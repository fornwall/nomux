//! PTY allocation and child spawn.
//!
//! What the child runs and why is `IMPLEMENTATION.md` § 6.1.1; the mechanics of the
//! PTY itself are § 6.1.

use std::env;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use nomux::WinSize;
use rustix::fs::{Mode, OFlags};
use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
use rustix::pty::{OpenptFlags, openpt, ptsname, unlockpt};
use rustix::termios::{Winsize, tcsetwinsize};

/// What the session's child needs to know at spawn.
#[derive(Debug)]
pub(crate) struct Spawn<'a> {
    /// Value for the child's `TERM`, taken from the creating `Hello`.
    pub term: &'a str,
    /// Initial dimensions, applied before the child can observe them.
    pub win: WinSize,
    /// Exported as `NOMUX_SESSION`.
    pub session_id: &'a str,
    /// Working directory for the child. The daemon itself has already moved to `/`
    /// (§ 6.2), so this must be passed explicitly or the shell would start there.
    pub cwd: &'a Path,
    /// `ssh-agent` socket to export as `SSH_AUTH_SOCK`, when forwarding is on.
    pub agent_sock: Option<&'a Path>,
}

/// How long the child's group has to act on `SIGHUP` before `SIGKILL` follows.
///
/// Named for the signal actually sent: `control.rs` has a `GRACE` of its own for the
/// different two seconds a *daemon* gets after `SIGTERM`.
const HANGUP_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// Interval between liveness checks while waiting out [`HANGUP_GRACE`].
const HANGUP_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

/// A running session: the PTY master plus the child holding its slave.
#[derive(Debug)]
pub(crate) struct Pty {
    master: OwnedFd,
    child: Child,
    /// The child's start time, read once at spawn — the other half of its identity, for
    /// [`Pty::pid_reissued`], which has what a `None` costs and why it is not the whole of
    /// the answer.
    started: Option<u64>,
}

impl Pty {
    /// Allocates a PTY and spawns the user's login shell on its slave.
    ///
    /// # Errors
    ///
    /// Propagates the PTY allocation, the slave `open` and the spawn.
    pub(crate) fn spawn(config: &Spawn<'_>) -> io::Result<Self> {
        // `CLOEXEC` on both ends, and what it keeps out of the child: § 6.1.
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)?;
        unlockpt(&master)?;
        let slave_path = ptsname(&master, Vec::new())?;

        // Non-blocking master (§ 6.1). The slave is a separate open and stays blocking,
        // as the child expects of its stdio.
        let flags = rustix::fs::fcntl_getfl(&master)?;
        rustix::fs::fcntl_setfl(&master, flags | OFlags::NONBLOCK)?;

        // As the `CString` `ptsname` returned: going through `OsStr` would strip the
        // terminator and have rustix copy the path back into a buffer to re-append it.
        let slave: OwnedFd = rustix::fs::open(
            slave_path.as_c_str(),
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let slave = File::from(slave);

        // Before the child can observe it, so its first prompt is laid out right.
        tcsetwinsize(&master, to_winsize(config.win))?;

        let (shell, argv0) = login_shell();
        let mut command = Command::new(&shell);
        command
            .arg0(&argv0)
            .current_dir(config.cwd)
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave.try_clone()?))
            .env("TERM", config.term)
            .env("NOMUX_SESSION", config.session_id);
        if let Some(sock) = config.agent_sock {
            // Overwrites whatever sshd forwarded, deliberately (§ 6.7).
            command.env("SSH_AUTH_SOCK", sock);
        }

        // Valid between fork and exec: `slave` outlives `spawn` in this frame, and
        // CLOEXEC only takes effect at exec.
        let slave_fd = slave.as_raw_fd();
        // Bound out here rather than written inside the `unsafe` block below, and
        // load-bearing for it: unsafe context reaches lexically into a closure body, so
        // the calls in here would need no block of their own for the lint to fire on.
        let pre_exec = move || {
            rustix::process::setsid()?;
            // SAFETY: `slave_fd` is open in the child, inherited across fork.
            let slave = unsafe { BorrowedFd::borrow_raw(slave_fd) };
            rustix::process::ioctl_tiocsctty(slave)?;
            // Every disposition this process may be *ignoring*, put back where a login
            // shell needs it. `exec` resets the handled ones and preserves the ignored
            // ones, so § 6.2's own SIGHUP would otherwise be shrugged off by the child
            // `terminate` sends it to — and, worse, ignored dispositions this daemon
            // never chose come the same way: POSIX has a non-interactive shell set
            // `SIGINT` and `SIGQUIT` to `SIG_IGN` around a background job, so
            // `nomux spawn work &` in a script would hand the user a session whose
            // shell, and everything it ever runs, silently ignores `Ctrl-\` for good.
            // The job-control three go with them, `Ctrl-Z` being the same loss.
            //
            // `SIGINT` and `SIGTERM` are absent because they are *handled* by the time
            // this runs (`startup::arm_stop_signals`), and exec resets a handler — the
            // half § 6.2 describes, and the reading of it that hid the rest. `SIGCHLD`
            // is absent on the same ground and matters most of the five that are not
            // here: `startup::arm_child_signal` handles it, and had it been *ignored*
            // instead the shell would carry that through exec into a session where the
            // kernel reaps its children out from under it and every `wait` it makes
            // fails `ECHILD` — job control with it.
            for signum in [
                libc::SIGHUP,
                libc::SIGQUIT,
                libc::SIGTSTP,
                libc::SIGTTIN,
                libc::SIGTTOU,
            ] {
                // SAFETY: `signal` is async-signal-safe and SIG_DFL is a valid handler
                // value.
                if unsafe { libc::signal(signum, libc::SIG_DFL) } == libc::SIG_ERR {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        };
        // SAFETY: the closure runs in the forked child before exec and must be
        // async-signal-safe. Every call in it is: POSIX lists `setsid` and `signal`
        // outright, and `ioctl` is a bare syscall — it has no userspace half to be
        // half-way through. Nothing here allocates, takes a lock, or touches the Rust
        // runtime.
        unsafe {
            command.pre_exec(pre_exec);
        }

        let child = command.spawn()?;
        // Read here, where the child is certainly still this pid: it is held unreaped
        // by the `Child` above, so an exit in the meantime leaves a zombie to read.
        let started = start_time(as_pid(child.id()));
        // Both the copy in this frame and the three `Stdio::from` took: std only
        // *borrows* an owned descriptor for the child, so `Command` holds all three
        // until it is itself dropped. § 6.1 has what a copy outliving this function
        // would cost.
        drop(command);
        drop(slave);
        Ok(Self {
            master,
            child,
            started,
        })
    }

    /// The PTY master, for reading output and writing input.
    #[must_use]
    pub(crate) fn master(&self) -> BorrowedFd<'_> {
        self.master.as_fd()
    }

    /// Applies new dimensions, which delivers `SIGWINCH` to the foreground group.
    pub(crate) fn resize(&self, win: WinSize) -> io::Result<()> {
        tcsetwinsize(&self.master, to_winsize(win))?;
        Ok(())
    }

    /// Nudges the child into repainting by resizing to one column narrower and
    /// back, delivering two `SIGWINCH`es.
    ///
    /// The gap-recovery repaint of `IMPLEMENTATION.md` § 4.3, which has what it does
    /// and does not reach, and why a one-column terminal is left without one: the master
    /// already holds `win` by the time a repaint is owed, so the lone resize left there
    /// is one the kernel short-circuits rather than signals.
    pub(crate) fn nudge_repaint(&self, win: WinSize) -> io::Result<()> {
        if win.cols > 1 {
            let narrower = WinSize {
                cols: win.cols - 1,
                ..win
            };
            self.resize(narrower)?;
        }
        self.resize(win)
    }

    /// Reaps the child if it has exited, without blocking.
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }

    /// Terminates everything the session started, then the child itself.
    ///
    /// Two reaches — the child's process group, then [`signal_session`]'s `/proc` walk over
    /// its session — because neither alone covers it, and in that order:
    /// `IMPLEMENTATION.md` § 6.5, which also has why every signal below is guarded by
    /// [`Pty::pid_reissued`].
    pub(crate) fn terminate(&mut self) {
        let raw = as_pid(self.child.id());
        if let Some(pid) = Pid::from_raw(raw)
            && !self.pid_reissued(raw)
        {
            // `group_alive` carries each probe's answer forward, so no signal below goes
            // to a group this has already watched go.
            let mut group_alive = rustix::process::test_kill_process_group(pid).is_ok();
            let mut settled = !group_alive && session_is_empty(raw);
            if !settled {
                reach(Reach::Group(pid), Signal::HUP);
                signal_session(raw, Signal::HUP);

                // Real grace, not a formality: checking microseconds after the signal
                // finds everything still running, so `SIGKILL` would follow at once and
                // no shell would run its exit trap. The condition is the session
                // emptying rather than the direct child exiting, which is satisfied the
                // moment it goes while the backgrounded grandchildren this exists to
                // collect are still running.
                let deadline = std::time::Instant::now() + HANGUP_GRACE;
                while std::time::Instant::now() < deadline {
                    // Reaped every pass, and not merely for tidiness: an unreaped
                    // zombie is still a member of its own process group, so
                    // `test_kill_process_group` answers `Ok` for it and the `&&`
                    // below short-circuits before the walk — which *does* filter
                    // zombies — is ever consulted.
                    let _ = self.child.try_wait();
                    group_alive = rustix::process::test_kill_process_group(pid).is_ok();
                    if !group_alive && session_is_empty(raw) {
                        settled = true;
                        break;
                    }
                    std::thread::sleep(HANGUP_POLL_INTERVAL);
                }
            }
            // The guard is asked again because the loop above can be what changes the
            // answer: its `try_wait` reaps the child, and reaping frees the number. The
            // two reaches are separately conditional because their conditions come
            // apart — a backgrounded job in a group of its own outlives the grace while
            // the *child's* group is already gone.
            if !settled && !self.pid_reissued(raw) {
                if group_alive {
                    reach(Reach::Group(pid), Signal::KILL);
                }
                signal_session(raw, Signal::KILL);
            }
        }
        drop(self.child.kill());
        drop(self.child.wait());
    }

    /// Whether `raw` has been handed to somebody else since the child was spawned (§ 6.5):
    /// a stranger who took the freed number and called `setsid` answers the liveness probe
    /// in [`Pty::terminate`] exactly as the child would have, and start times are not
    /// reissued with the pids they belong to.
    ///
    /// The two unknowns are not one unknown. A `/proc/<raw>` that cannot be read *now* is
    /// what a reaped shell with a surviving job leaves behind, and the start time taken at
    /// spawn still says whose the number was, so that is deliberately not a reissue.
    ///
    /// A missing start time from *spawn* is permanent — one `EMFILE` while the master, the
    /// slave and three dups were being opened — but permanent is not the same as no
    /// evidence. An unreaped child still owns its number, the zombie holding it until
    /// somebody waits, which is the fact [`Pty::terminate`]'s grace loop already leans on.
    /// So the child is asked, and only a *collected* one falls through to `true`: there the
    /// liveness probe is all that is left, which is exactly what a stranger holding a
    /// recycled pid satisfies, and the reach given up is over a child that has indeed gone.
    /// Answering on the failed read alone would have given up both reaches over a shell
    /// still running — § 6.5's orphan by the very route the walk exists to close.
    fn pid_reissued(&mut self, raw: i32) -> bool {
        let Some(ours) = self.started else {
            return !matches!(self.child.try_wait(), Ok(None));
        };
        start_time(raw).is_some_and(|now| ours != now)
    }
}

/// A pid as the signed number `/proc` and `kill(2)` are addressed with.
///
/// The conversion cannot fail: `pid_max` is capped at 2^22 by the kernel, so every pid
/// std hands back as a `u32` fits. Zero rather than three different fallbacks at the
/// three call sites, none of which could fire and each of which read as if it might —
/// and zero is the one value nothing here can act on, `Pid::from_raw` refusing it and
/// `/proc/0` never existing.
fn as_pid(id: u32) -> i32 {
    i32::try_from(id).unwrap_or(0)
}

/// The start time of the process holding `pid`, in clock ticks since boot.
///
/// Never read for its value: two of these are only ever compared.
fn start_time(pid: i32) -> Option<u64> {
    stat_start_time(&std::fs::read(format!("/proc/{pid}/stat")).ok()?)
}

/// Signals every live process still in session `sid`.
///
/// Individually, because a session is not something `kill(2)` addresses — its
/// negative-pid form means a process *group*, and the point here is precisely the
/// groups job control created that nobody is tracking.
///
/// Each member is pinned before its `stat` line is read and signalled through that pidfd.
/// Opening after the membership check would retain the same reuse window as a numeric
/// `kill(2)`; collecting numbers first would stretch it across the rest of the walk.
fn signal_session(sid: i32, signal: Signal) {
    walk_session(sid, true, |_, pinned| {
        // A missing pidfd is ambiguity, not licence to fall back to the number: on a
        // pre-5.3 kernel, under a restrictive seccomp profile, or after a racing exit,
        // signalling nothing is safer than reaching a process that inherited the number
        // between `/proc` and `kill(2)`. The child's own process-group reach above remains.
        if let Some(pidfd) = pinned {
            reach(Reach::Pinned(pidfd), signal);
        }
        true
    });
}

/// One stable destination for a signal this module sends.
#[derive(Clone, Copy)]
enum Reach<'a> {
    /// The direct child's process group, guarded by [`Pty::pid_reissued`].
    Group(Pid),
    /// A session member held across the `/proc` membership check.
    Pinned(&'a OwnedFd),
}

/// Sends one signal to a guarded process group or a pinned process.
///
/// This is the module's only door to a signal: nothing else in this file may call
/// `kill_process_group` or `pidfd_send_signal`, or a later path could reach a process
/// without `REACHES` recording it — the invariant the regression tests below rest on.
/// What they measure is the *decision* to signal, the only thing that can be: where a
/// guard skips, what it skips would have landed nowhere by construction.
///
/// The outcome is dropped throughout. A process that took the first signal and died answers
/// the second with `ESRCH`, which is this working rather than failing.
fn reach(target: Reach<'_>, signal: Signal) {
    #[cfg(test)]
    REACHES.with_borrow_mut(|sent| sent.push(signal));
    match target {
        Reach::Group(pid) => drop(rustix::process::kill_process_group(pid, signal)),
        Reach::Pinned(pidfd) => drop(pidfd_send_signal(pidfd, signal)),
    }
}

#[cfg(test)]
thread_local! {
    /// The signals [`reach`] has sent on this thread, in the order they went out.
    ///
    /// Per thread rather than process-wide, so the two tests that read it need nothing
    /// between them: [`Pty::terminate`] signals on the thread that called it, and two tests
    /// can share a thread only by running one after the other.
    static REACHES: std::cell::RefCell<Vec<Signal>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Walks `/proc` for the live processes in session `sid`, offering each to `visit` until
/// it answers `false`.
///
/// Signalling by a number read out of `/proc` goes very wrong when it goes wrong, so this is
/// deliberately narrow: `sid` is always a child this process forked, and this process is
/// excluded by pid whatever `/proc` says. Zombies are left out — signalling one does nothing,
/// and counting it would keep the caller's grace loop spinning for its whole budget over the
/// child it is about to reap.
///
/// With `pin` set, a pidfd is opened **before** the stat line that establishes membership and
/// borrowed into `visit`. The descriptor keeps the check and any signal about one process even
/// if it exits in between; a member that cannot be pinned is still visible to the emptiness
/// check, but is never safe to signal individually.
///
/// One path buffer and one read buffer for the whole walk, rather than a `format!` and a
/// `Vec` per process: [`Pty::terminate`]'s grace loop reaches here every
/// [`HANGUP_POLL_INTERVAL`] once the child's own group has gone, so on a busy host the
/// per-process pair would be tens of thousands of allocations inside a shutdown that has
/// [`HANGUP_GRACE`] to finish in.
fn walk_session(sid: i32, pin: bool, mut visit: impl FnMut(i32, Option<&OwnedFd>) -> bool) {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return;
    };
    let self_pid = as_pid(std::process::id());
    let mut path = PathBuf::from("/proc");
    let mut stat = Vec::with_capacity(1024);
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|name| name.parse::<i32>().ok()) else {
            continue;
        };
        if pid == self_pid {
            continue;
        }
        // Before the membership read below: opening it afterwards leaves the exact reuse
        // window this descriptor exists to close. Failure is carried as `None`; only the
        // signalling caller requires a hold, while `session_is_empty` still needs to see
        // members on kernels without pidfds.
        let pinned = pin
            .then(|| Pid::from_raw(pid).and_then(|pid| pidfd_open(pid, PidfdFlags::empty()).ok()))
            .flatten();
        path.push(&name);
        path.push("stat");
        stat.clear();
        let read = File::open(&path).and_then(|mut file| file.read_to_end(&mut stat));
        path.pop();
        path.pop();
        if read.is_err() {
            continue;
        }
        if stat_session(&stat).is_some_and(|(session, zombie)| session == sid && !zombie)
            && !visit(pid, pinned.as_ref())
        {
            return;
        }
    }
}

/// Whether nothing live is left in session `sid`.
///
/// The walk stops at the first member rather than reading every remaining
/// `/proc/<pid>/stat` to answer a question that one has already answered:
/// [`Pty::terminate`]'s grace loop asks this every [`HANGUP_POLL_INTERVAL`].
fn session_is_empty(sid: i32) -> bool {
    let mut empty = true;
    walk_session(sid, false, |_, _| {
        empty = false;
        false
    });
    empty
}

/// The fields of one `/proc/<pid>/stat` from the third onwards: state, ppid, pgrp,
/// session, and so on to the end.
///
/// Taken from the last `)` rather than by splitting from the left, and over bytes rather
/// than a `&str`, because field two is the executable's name in parentheses and the kernel
/// escapes only `\n` and `\\` in it. A name read naively drops its pid out of the walk —
/// after which [`Pty::terminate`] never signals it *and*, the walk being what decides the
/// session has settled, reports a clean shutdown over it.
/// `a_stat_line_parses_past_a_hostile_process_name` has the names that do it.
fn stat_tail(stat: &[u8]) -> Option<std::str::SplitWhitespace<'_>> {
    let close = stat.iter().rposition(|byte| *byte == b')')?;
    let rest = str::from_utf8(stat.get(close + 1..)?).ok()?;
    Some(rest.split_whitespace())
}

/// The session id and whether the process is a zombie, from one `/proc/<pid>/stat`.
fn stat_session(stat: &[u8]) -> Option<(i32, bool)> {
    let mut fields = stat_tail(stat)?;
    let state = fields.next()?;
    let session = fields.nth(2)?.parse().ok()?;
    Some((session, state == "Z"))
}

/// The start time, from one `/proc/<pid>/stat`: field 22 of the line, and the
/// twentieth of the tail [`stat_tail`] hands back.
fn stat_start_time(stat: &[u8]) -> Option<u64> {
    stat_tail(stat)?.nth(19)?.parse().ok()
}

const fn to_winsize(win: WinSize) -> Winsize {
    Winsize {
        ws_row: win.rows,
        ws_col: win.cols,
        ws_xpixel: win.xpixel,
        ws_ypixel: win.ypixel,
    }
}

/// Resolves the shell to run and the dash-prefixed `argv[0]` that makes it a login shell —
/// [`pick_shell`] has the choice, `IMPLEMENTATION.md` § 6.1.1 the leading `-`.
///
/// Nothing reads the password database behind it. sshd sets `$SHELL` from that database
/// itself, so what a lookup here answered for was a session started by something that
/// scrubbed the environment — and § 6.1.1 already has the directory-backed user, who has
/// no line in `/etc/passwd` to be found in, falling through to `/bin/sh`.
fn login_shell() -> (PathBuf, String) {
    pick_shell(env::var_os("SHELL").map(PathBuf::from))
}

/// The choice behind [`login_shell`], with the environment lifted out so it is testable
/// without mutating it — as [`pick_dir`] is for [`child_dir`].
///
/// Absolute rather than merely non-empty, which it subsumes: a program with no `/` in it
/// sends `Command` looking down `PATH` — and with `current_dir` set as well, std
/// documents the pair as ambiguous — so a `SHELL=bash` would run whatever a writable
/// `~/.local/bin` resolves it to.
fn pick_shell(shell: Option<PathBuf>) -> (PathBuf, String) {
    let shell = shell
        .filter(|value| value.is_absolute())
        .unwrap_or_else(|| PathBuf::from("/bin/sh"));
    let base = shell
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("sh")
        .to_owned();
    let argv0 = format!("-{base}");
    (shell, argv0)
}

/// Resolves the child's working directory, preferring `$HOME` the way sshd does.
///
/// `fallback` is the daemon's own directory from before it moved to `/`, i.e. the
/// directory the attaching connection was in. Neither existing leaves `/`, which is
/// always valid if never useful.
pub(crate) fn child_dir(fallback: Option<&Path>) -> PathBuf {
    let home = env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from);
    pick_dir(home.as_deref(), fallback)
}

/// The choice behind [`child_dir`], with the environment lifted out so it is
/// testable without mutating it.
fn pick_dir(home: Option<&Path>, fallback: Option<&Path>) -> PathBuf {
    [home, fallback]
        .into_iter()
        .flatten()
        .find(|dir| dir.is_dir())
        .map_or_else(|| PathBuf::from("/"), Path::to_path_buf)
}

/// Splits an `ExitStatus` into the wire representation of [`nomux::Frame::Exit`].
#[must_use]
pub(crate) fn exit_parts(status: std::process::ExitStatus) -> (i32, nomux::ExitKind) {
    use std::os::unix::process::ExitStatusExt;
    status.code().map_or_else(
        || (status.signal().unwrap_or(0), nomux::ExitKind::Signalled),
        |code| (code, nomux::ExitKind::Exited),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nbio::{ReadOutcome, read_or_eof};

    #[test]
    fn a_stat_line_parses_past_a_hostile_process_name() {
        let ordinary = b"42 (bash) S 1 42 42 34816 99 4194304 0 0";
        assert_eq!(stat_session(ordinary), Some((42, false)));

        // A name chosen to break a left-to-right split: it contains spaces, a
        // closing paren, and digits that would be read as the session id.
        let hostile = b"42 (evil) 1 2 3) S 1 42 7 34816 99 4194304 0 0";
        assert_eq!(
            stat_session(hostile),
            Some((7, false)),
            "the session must come from after the *last* paren"
        );

        // A `comm` the kernel does not escape and UTF-8 cannot hold: read as a string
        // the whole line is undecodable.
        let not_utf8 = b"42 (ba\xffsh) S 1 42 42 34816 99 4194304 0 0";
        assert_eq!(
            stat_session(not_utf8),
            Some((42, false)),
            "a name outside UTF-8 must not hide the process from the walk"
        );

        let zombie = b"42 (sh) Z 1 42 42 0 -1 4194304 0 0";
        assert_eq!(stat_session(zombie), Some((42, true)));

        assert_eq!(stat_session(b"truncated"), None);
        assert_eq!(
            stat_session(b"42 (sh) S 1"),
            None,
            "too few fields to answer"
        );
    }

    /// The start time is field 22, counted through the same tail, and a pid's
    /// identity now rests on this arithmetic being right.
    ///
    /// Pinned against the kernel rather than only against a line written here: this
    /// process's own `stat` is decoded both by the parser and by a plain left-to-right
    /// split, which is a valid reading for a `comm` of `nomux` and only for one.
    #[test]
    fn a_stat_line_gives_up_the_start_time_field() {
        let mine = std::fs::read("/proc/self/stat").expect("read this process's stat");
        let naive: Vec<&str> = str::from_utf8(&mine)
            .expect("this binary's own comm is ASCII")
            .split_whitespace()
            .collect();
        assert_eq!(
            stat_start_time(&mine)
                .map(|ticks| ticks.to_string())
                .as_deref(),
            naive.get(21).copied(),
            "the parser and a plain split must read the same field 22"
        );

        // The same hostile name the test above uses, with a full tail behind it:
        // state, ppid, pgrp, session, tty_nr, tpgid, flags, four faults, four
        // times, priority, nice, threads, itrealvalue, and then the start time.
        let hostile = b"42 (evil) 1 2 3) S 1 42 7 34816 99 4194304 0 0 0 0 \
                        0 0 0 0 20 0 1 0 987654321 4096";
        assert_eq!(stat_start_time(hostile), Some(987_654_321));
        assert_eq!(
            stat_session(hostile),
            Some((7, false)),
            "the two fields are read from one tail and must agree about where it starts"
        );

        assert_eq!(
            stat_start_time(b"42 (sh) S 1 42 42 0 -1 4194304 0 0"),
            None,
            "too few fields to answer"
        );
    }

    /// The daemon must never appear in the set it is about to signal, whatever
    /// `/proc` says.
    ///
    /// `getsid` is asked about *this* process, the one call it cannot fail for, rather
    /// than skipped on failure — which would report as a pass on every host where the
    /// walk was never run.
    #[test]
    fn the_walk_never_returns_this_process() {
        let sid = rustix::process::getsid(None)
            .expect("this process's own session id, which the kernel cannot refuse");
        let sid = Pid::as_raw(Some(sid));
        let members = session_members(sid);
        let self_pid = as_pid(std::process::id());
        assert!(
            !members.contains(&self_pid),
            "the reaper found itself among the reaped: {members:?}"
        );
    }

    /// The case the process-group kill cannot reach, and the reason for the `/proc`
    /// walk: a shell with job control gives each `&` job a process group of its own, so
    /// the only thing still holding them together is the session. `set -m` is what makes
    /// this test test something, and the `trap` closes the other way out.
    #[test]
    fn terminate_collects_a_backgrounded_job_in_its_own_process_group() {
        let mut pty = shell("terminate_test");

        let script = "set -m\n(trap '' HUP; sleep 30) &\necho NOMUX-JOB=$!\n";
        rustix::io::write(pty.master(), script.as_bytes()).expect("write the script");
        let job = read_marker(&pty, "NOMUX-JOB=").expect("the shell reported its job pid");
        assert!(
            !collected(job),
            "the job should be running before terminate"
        );

        pty.terminate();

        // `terminate` returns only once it has signalled, but the kernel's own
        // teardown and the reparenting reap are asynchronous, so the assertion is
        // on the job going away rather than on it having gone already.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline && !collected(job) {
            std::thread::sleep(HANGUP_POLL_INTERVAL);
        }
        assert!(
            collected(job),
            "a backgrounded job in its own process group outlived the session"
        );
    }

    /// The other side of that guard: a reaped child whose session is *not* empty
    /// still gets both reaches.
    ///
    /// What an ordinary exit leaves behind when the shell had a job running: the
    /// child's own group is empty and its pid dead, so a guard written on the group
    /// alone would skip and leave the job running under a clean shutdown — § 6.5's
    /// orphan by another route. The pid cannot have been reissued in this state, the
    /// kernel keeping one reserved for as long as anything names it as a session.
    #[test]
    fn terminate_still_collects_a_job_whose_shell_has_been_reaped() {
        let mut pty = shell("terminate_orphan");

        // `exit` twice, because a shell with job control may answer the first one
        // by pointing out that a job is still running and asking again — zsh does.
        // Where the first is taken the second is never read by anybody.
        let script = "set -m\n(trap '' HUP; sleep 30) &\necho NOMUX-JOB=$!\nexit\nexit\n";
        rustix::io::write(pty.master(), script.as_bytes()).expect("write the script");
        let job = read_marker(&pty, "NOMUX-JOB=").expect("the shell reported its job pid");

        assert!(reaped_within(&mut pty), "the shell never exited");
        assert!(
            !collected(job),
            "the job should outlive the shell that started it"
        );

        pty.terminate();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline && !collected(job) {
            std::thread::sleep(HANGUP_POLL_INTERVAL);
        }
        assert!(
            collected(job),
            "a job whose shell had already been reaped outlived the session"
        );
    }

    /// Regression: the two reaches go out while the pid is still the child's, and not
    /// once it is somebody else's.
    ///
    /// Three states in one test: the ordinary case, which keeps the two negatives from
    /// passing vacuously; an ordinary exit, which reaps the child and leaves nothing for
    /// either reach; and that same pid handed to somebody else, which the liveness probe
    /// cannot see. A reissued pid cannot be arranged, so the third state falsifies this
    /// side's half of the identity instead.
    ///
    /// Counted at [`reach`], which says why the decision to signal is the only thing there
    /// is to observe.
    #[test]
    fn terminate_signals_a_pid_only_while_it_is_still_the_childs() {
        // A live shell, whose session is emphatically not empty.
        let mut pty = shell("terminate_live");
        drop(reaches_since());
        pty.terminate();
        assert!(
            !reaches_since().is_empty(),
            "the ordinary case signalled nothing, so the two assertions below are about \
             an instrument that measures nothing"
        );

        // An ordinary exit, collected the way the daemon collects one — which is what
        // frees the pid both reaches are addressed to.
        let mut pty = shell("terminate_reaped");
        rustix::io::write(pty.master(), b"exit\n").expect("ask the shell to leave");
        assert!(reaped_within(&mut pty), "the shell never exited");
        let raw = as_pid(pty.child.id());
        let pid = Pid::from_raw(raw).expect("the reaped child's pid");
        // Deterministic rather than hopeful: a pid stays reserved while anything still
        // names it as a session.
        assert!(
            rustix::process::test_kill_process_group(pid).is_err() && session_is_empty(raw),
            "nothing of the session may be left, or this is the other case"
        );
        drop(reaches_since());
        pty.terminate();
        assert_eq!(
            reaches_since(),
            [],
            "terminate signalled a pid the kernel had already taken back"
        );

        // And a live session again, with the number no longer the child's. Everything the
        // probe can see says signal; only the start time says the process answering to it
        // is not the one this spawned.
        let mut pty = shell("terminate_reissued");
        let started = pty
            .started
            .expect("a start time for a child that is running");
        pty.started = Some(started.wrapping_add(1));
        drop(reaches_since());
        pty.terminate();
        assert_eq!(
            reaches_since(),
            [],
            "terminate signalled a pid that had been handed to somebody else"
        );
    }

    /// Regression: a shutdown over a child that has already gone ends with the session,
    /// rather than sitting out [`HANGUP_GRACE`] behind the child's own zombie.
    ///
    /// The child is left exited and *unreaped* — what the daemon holds between the poll that
    /// missed the exit and the one that would collect it, and the state [`Pty::terminate`]'s
    /// grace loop argues about. Delete the `try_wait` from that loop and the session never
    /// reads as settled: that one line is the whole of what this holds.
    ///
    /// The `SIGKILL` is the observation, not the half second: nothing is left alive to
    /// receive it, so the reach is the whole of the difference, and a wall clock would be
    /// measuring the machine as much as the shutdown. The `SIGHUP` that opens the shutdown
    /// goes out either way, and is what proves the instrument is reading anything at all.
    #[test]
    fn terminate_ends_a_settled_session_without_reaching_for_sigkill() {
        let mut pty = shell("terminate_quiet");
        let raw = as_pid(pty.child.id());
        let pid = Pid::from_raw(raw).expect("the child's pid");
        rustix::io::write(pty.master(), b"exit\n").expect("ask the shell to leave");

        // Watched through `/proc`, not through `try_wait`, which would perform the very
        // reap this is about and leave nothing to observe.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline && !collected(raw) {
            std::thread::sleep(HANGUP_POLL_INTERVAL);
        }
        assert!(collected(raw), "the shell never exited");
        assert!(
            rustix::process::test_kill_process_group(pid).is_ok(),
            "the zombie must still answer for its group, or the short-circuit this is \
             about cannot happen"
        );
        assert!(
            session_is_empty(raw),
            "the zombie must be all that is left, or the grace is owed either way"
        );

        drop(reaches_since());
        pty.terminate();
        let sent = reaches_since();
        assert!(
            sent.contains(&Signal::HUP),
            "the shutdown sent no SIGHUP, so the assertion below is about an instrument \
             that measures nothing: {sent:?}"
        );
        assert!(
            !sent.contains(&Signal::KILL),
            "terminate reached for SIGKILL over a session whose last member was the \
             zombie it had been handed to reap: {sent:?}"
        );
    }

    /// Every pid [`walk_session`] offers for `sid`, which nothing outside the tests
    /// collects: [`signal_session`] signals inside the walk and [`session_is_empty`] stops
    /// at the first member.
    fn session_members(sid: i32) -> Vec<i32> {
        let mut members = Vec::new();
        walk_session(sid, false, |pid, _| {
            members.push(pid);
            true
        });
        members
    }

    /// The signals [`reach`] has sent since this was last asked, and none from here on.
    fn reaches_since() -> Vec<Signal> {
        REACHES.with_borrow_mut(std::mem::take)
    }

    /// A shell on a PTY of its own, which is what the four tests around this
    /// terminate.
    fn shell(session_id: &str) -> Owned {
        Owned(Some(
            Pty::spawn(&Spawn {
                term: "dumb",
                win: WinSize {
                    cols: 80,
                    rows: 24,
                    xpixel: 0,
                    ypixel: 0,
                },
                session_id,
                cwd: Path::new("/tmp"),
                agent_sock: None,
            })
            .expect("spawn a shell on a pty"),
        ))
    }

    /// A [`Pty`] whose shell is collected however the test holding it ends.
    ///
    /// `Pty` has no `Drop` of its own and should not have one, the daemon tearing its
    /// session down through `terminate` in an order `shutdown` decides. But an `expect`
    /// firing before one of the tests below reaches `terminate` leaves a `dash` behind
    /// unwaited past the run, and the kill is the whole of what this closes: dropping
    /// the inner `Pty` hangs up the foreground group but does not *wait*. It
    /// deliberately does not walk the session — signalling by a raw pid after the child
    /// has been reaped is the hazard `Pty::pid_reissued` exists for.
    struct Owned(Option<Pty>);

    impl std::ops::Deref for Owned {
        type Target = Pty;

        fn deref(&self) -> &Pty {
            self.0.as_ref().expect("the pty is still held")
        }
    }

    impl std::ops::DerefMut for Owned {
        fn deref_mut(&mut self) -> &mut Pty {
            self.0.as_mut().expect("the pty is still held")
        }
    }

    impl Drop for Owned {
        fn drop(&mut self) {
            if let Some(pty) = self.0.as_mut() {
                drop(pty.child.kill());
                drop(pty.child.wait());
            }
        }
    }

    /// Collects the child once it goes, the way the daemon does at an ordinary exit —
    /// which is what frees its pid. `false` if it never left.
    fn reaped_within(pty: &mut Pty) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if pty.try_wait().expect("wait for the shell").is_some() {
                return true;
            }
            std::thread::sleep(HANGUP_POLL_INTERVAL);
        }
        false
    }

    /// Whether `pid` is gone, counting a zombie as gone: it has exited and is waiting on
    /// a parent that this test does not control.
    fn collected(pid: i32) -> bool {
        std::fs::read(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| stat_session(&stat))
            .is_none_or(|(_, zombie)| zombie)
    }

    /// Reads the PTY until `marker` is followed by a complete number.
    ///
    /// The terminal echoes input, so the literal `NOMUX-JOB=$!` arrives before the
    /// shell's answer. Requiring digits *and* something after them tells the echo from
    /// the reply, and keeps a number split across two reads from being taken half.
    fn read_marker(pty: &Pty, marker: &str) -> Option<i32> {
        let mut seen = String::new();
        let mut buf = [0u8; 4096];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            match read_or_eof(pty.master(), &mut buf) {
                ReadOutcome::Data(n) => seen.push_str(&String::from_utf8_lossy(&buf[..n])),
                ReadOutcome::WouldBlock => std::thread::sleep(HANGUP_POLL_INTERVAL),
                ReadOutcome::Eof => break,
                ReadOutcome::Failed(err) => panic!("read the PTY output: {err}"),
            }
            for (at, _) in seen.match_indices(marker) {
                let tail = &seen[at + marker.len()..];
                let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
                if !digits.is_empty()
                    && digits.len() < tail.len()
                    && let Ok(pid) = digits.parse()
                {
                    return Some(pid);
                }
            }
        }
        None
    }

    /// § 6.1.1's precedence, now that it is two steps: an absolute `$SHELL`, and `/bin/sh`
    /// for everything else. The refusals are the point rather than the happy path, and
    /// [`pick_shell`] has what a relative one would cost.
    #[test]
    fn login_shell_takes_an_absolute_path_and_falls_back_to_bin_sh() {
        assert_eq!(
            pick_shell(Some(PathBuf::from("/usr/bin/zsh"))),
            (PathBuf::from("/usr/bin/zsh"), "-zsh".to_owned()),
            "an absolute shell is run as a login shell of its own name"
        );
        for refused in ["bash", "", "./sh", "bin/../sh"] {
            assert_eq!(
                pick_shell(Some(PathBuf::from(refused))),
                (PathBuf::from("/bin/sh"), "-sh".to_owned()),
                "{refused:?} is not a path this may hand to `execve`"
            );
        }
        assert_eq!(
            pick_shell(None),
            (PathBuf::from("/bin/sh"), "-sh".to_owned()),
            "an environment with no `$SHELL` at all still gets a session"
        );
    }

    /// A shell that starts in `/` because `$HOME` was wrong is a visible
    /// regression, so every fallback step is pinned.
    #[test]
    fn child_dir_prefers_home_then_the_daemons_own_directory() {
        let home = Path::new("/tmp");
        let gone = Path::new("/nonexistent-nomux-home");
        assert_eq!(pick_dir(Some(home), Some(Path::new("/"))), home);
        assert_eq!(pick_dir(Some(gone), Some(Path::new("/"))), Path::new("/"));
        assert_eq!(pick_dir(Some(gone), Some(gone)), Path::new("/"));
        assert_eq!(pick_dir(None, Some(home)), home);
        assert_eq!(pick_dir(None, None), Path::new("/"));
    }
}
