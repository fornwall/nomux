//! PTY allocation and child spawn.
//!
//! What the child runs and why is `IMPLEMENTATION.md` § 6.1.1; the mechanics of the
//! PTY itself are § 6.1.

use std::env;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use nomux_proto::WinSize;
use rustix::fs::{Mode, OFlags};
use rustix::pty::{OpenptFlags, openpt, ptsname, unlockpt};
use rustix::termios::{Winsize, tcsetwinsize};

use crate::passwd;

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
/// Named for the signal actually sent: `control.rs` has a `TERM_GRACE` of its own for
/// the different two seconds a *daemon* gets after `SIGTERM`.
const HANGUP_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// Interval between liveness checks while waiting out [`HANGUP_GRACE`].
const HANGUP_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

/// A running session: the PTY master plus the child holding its slave.
#[derive(Debug)]
pub(crate) struct Pty {
    master: OwnedFd,
    child: Child,
    /// The child's start time, read once at spawn — the other half of its identity, for
    /// [`Pty::pid_reissued`]. `None` where `/proc` could not answer, read as "cannot
    /// tell" rather than as an answer.
    started: Option<u64>,
}

impl Pty {
    /// Allocates a PTY and spawns the user's login shell on its slave.
    ///
    /// # Errors
    ///
    /// Propagates failures from `openpt`, `unlockpt`, opening the slave, or spawning
    /// the shell.
    pub(crate) fn spawn(config: &Spawn<'_>) -> io::Result<Self> {
        // `CLOEXEC` on both ends, and what it keeps out of the child: § 6.1.
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)?;
        unlockpt(&master)?;
        let slave_path = ptsname(&master, Vec::new())?;

        // Non-blocking master (§ 6.1), so that a child which has stopped reading cannot
        // wedge the event loop; unwritten input waits in `pending_input` instead. The
        // slave is a separate open and stays blocking, as the child expects of its stdio.
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
            .env("NOMUX_SESSION", config.session_id)
            .env_remove("NOMUX_BOOTSTRAP");
        if let Some(sock) = config.agent_sock {
            // Overwrites whatever sshd forwarded, deliberately (§ 6.7).
            command.env("SSH_AUTH_SOCK", sock);
        }

        // Valid between fork and exec: `slave` outlives `spawn` in this frame, and
        // CLOEXEC only takes effect at exec.
        let slave_fd = slave.as_raw_fd();
        // Bound out here rather than written inside the `unsafe` block below, and
        // load-bearing for it: unsafe context reaches lexically into a closure body, so
        // every unsafe call in here would compile with no block of its own and
        // `undocumented_unsafe_blocks` would have nothing to fire on.
        let pre_exec = move || {
            rustix::process::setsid()?;
            // SAFETY: `slave_fd` is open in the child, inherited across fork.
            let slave = unsafe { BorrowedFd::borrow_raw(slave_fd) };
            rustix::process::ioctl_tiocsctty(slave)?;
            // The daemon ignores SIGHUP and an ignored disposition survives exec, so
            // the child would otherwise shrug off the one `terminate` sends first.
            // § 6.2 for why the handled signals need nothing here.
            //
            // SAFETY: `signal` is async-signal-safe and SIG_DFL is a valid handler
            // value.
            if unsafe { libc::signal(libc::SIGHUP, libc::SIG_DFL) } == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        };
        // SAFETY: the closure runs in the forked child before exec, so it must be
        // async-signal-safe. `setsid` and `ioctl_tiocsctty` are rustix on the
        // `linux_raw` backend every shipped target selects (`IMPLEMENTATION.md` § 8),
        // so they are inline syscalls and trivially reentrant whatever
        // signal-safety(7) says about the C functions of the same names.
        // `libc::signal` above is the one real libc call, and it *is* on that list.
        // Nothing allocates, takes a lock, or touches the Rust runtime.
        unsafe {
            command.pre_exec(pre_exec);
        }

        let child = command.spawn()?;
        // Read here, where the child is certainly still this pid: it is held unreaped
        // by the `Child` above, so an exit in the meantime leaves a zombie to read.
        let started = start_time(i32::try_from(child.id()).unwrap_or(0));
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
    ///
    /// # Errors
    ///
    /// Propagates `TIOCSWINSZ` failures.
    pub(crate) fn resize(&self, win: WinSize) -> io::Result<()> {
        tcsetwinsize(&self.master, to_winsize(win))?;
        Ok(())
    }

    /// Nudges the child into repainting by resizing to one column narrower and
    /// back, delivering two `SIGWINCH`es.
    ///
    /// The gap-recovery repaint of `IMPLEMENTATION.md` § 4.3, which has what it does
    /// and does not reach, and why a one-column terminal gets the second resize alone.
    ///
    /// # Errors
    ///
    /// Propagates `TIOCSWINSZ` failures.
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
    ///
    /// # Errors
    ///
    /// Propagates `waitpid` failures.
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }

    /// Terminates everything the session started, then the child itself.
    ///
    /// Two reaches — the child's process group, then [`session_members`]'s `/proc` walk
    /// over its session — because neither alone covers it, and in that order:
    /// `IMPLEMENTATION.md` § 6.5. What is left here is which reach each guard applies to.
    pub(crate) fn terminate(&mut self) {
        let raw = i32::try_from(self.child.id()).unwrap_or(0);
        if let Some(pid) = rustix::process::Pid::from_raw(raw)
            && !self.pid_reissued(raw)
        {
            // The same probe the `SIGKILL` escalation below is guarded by, one
            // signal earlier and for the same reason: an ordinary exit reaps the
            // child long before `shutdown` gets here, so by then there may be
            // nothing behind either reach. What it cannot ask is whether what it found
            // is *ours*, which is [`Pty::pid_reissued`], the other half of the same
            // guard. `group_alive` then carries the last probe's answer, so neither
            // signal below goes to a group this has already watched go.
            let mut group_alive = rustix::process::test_kill_process_group(pid).is_ok();
            let mut settled = !group_alive && session_members(raw).is_empty();
            if !settled {
                let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::HUP);
                signal_session(raw, rustix::process::Signal::HUP);

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
                    // below short-circuits before `session_members` — which *does*
                    // filter zombies — is ever consulted.
                    let _ = self.child.try_wait();
                    group_alive = rustix::process::test_kill_process_group(pid).is_ok();
                    if !group_alive && session_members(raw).is_empty() {
                        settled = true;
                        break;
                    }
                    std::thread::sleep(HANGUP_POLL_INTERVAL);
                }
            }
            // Only if something is still standing. The guard is asked a second time
            // because the loop above can be what makes the answer change — its
            // `try_wait` reaps the child, and reaping frees the number — and the two
            // reaches are separately conditional because their conditions come apart: a
            // backgrounded job in a group of its own outlives the grace while the
            // *child's* group is already gone.
            if !settled && !self.pid_reissued(raw) {
                if group_alive {
                    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
                }
                signal_session(raw, rustix::process::Signal::KILL);
            }
        }
        drop(self.child.kill());
        drop(self.child.wait());
    }

    /// Whether `raw` has been handed to somebody else since the child was spawned.
    ///
    /// The other half of [`Pty::terminate`]'s guard. The daemon reaps the child on
    /// every pass, so its number can be free for as long as the session then runs, and a
    /// stranger who took it and called `setsid` answers the liveness probe there exactly
    /// as the child would have. Start times are not reissued with the pids they belong
    /// to, which is what tells the two apart.
    ///
    /// Anything *unknown* is deliberately not a reissue: a missing `/proc/<raw>` is what
    /// a reaped shell with a surviving job leaves behind, an unreadable one arrives
    /// identically, and `terminate_still_collects_a_job_whose_shell_has_been_reaped`
    /// fails on reading either the other way.
    fn pid_reissued(&self, raw: i32) -> bool {
        matches!((self.started, start_time(raw)), (Some(ours), Some(now)) if ours != now)
    }
}

/// The start time of the process holding `pid`, in clock ticks since boot.
///
/// The other half of a pid's identity, and never read for its value: two of these are
/// only ever compared. Field 22, counted through the same fixed-width tail
/// [`stat_session`] reads.
fn start_time(pid: i32) -> Option<u64> {
    stat_start_time(&std::fs::read(format!("/proc/{pid}/stat")).ok()?)
}

/// Signals every live process still in session `sid`.
///
/// Individually, because a session is not something `kill(2)` addresses — its
/// negative-pid form means a process *group*, and the point here is precisely the
/// groups job control created that nobody is tracking.
fn signal_session(sid: i32, signal: rustix::process::Signal) {
    for member in session_members(sid) {
        if let Some(pid) = rustix::process::Pid::from_raw(member) {
            let _ = rustix::process::kill_process(pid, signal);
        }
    }
}

/// Pids of the live processes in session `sid`, from `/proc`.
///
/// Signalling by a number read out of `/proc` goes very wrong when it goes wrong, so
/// this is deliberately narrow: `sid` comes from a child this process forked, no pid is
/// returned unless its own `stat` line claims that session, and this process is
/// excluded by pid whatever `/proc` says. Zombies are left out — signalling one does
/// nothing, and counting it would keep the caller's grace loop spinning for its whole
/// budget over the child it is about to reap.
fn session_members(sid: i32) -> Vec<i32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let self_pid = i32::try_from(std::process::id()).unwrap_or(0);
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str()?.parse::<i32>().ok())
        .filter(|pid| *pid != self_pid)
        .filter(|pid| {
            std::fs::read(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|stat| stat_session(&stat))
                .is_some_and(|(session, zombie)| session == sid && !zombie)
        })
        .collect()
}

/// The fields of one `/proc/<pid>/stat` from the third onwards: state, ppid, pgrp,
/// session, and so on to the end.
///
/// Taken from the last `)` rather than by splitting from the left, and over bytes
/// rather than a `&str`, because field two is the executable's name in parentheses and
/// the kernel escapes only `\n` and `\\` in it: `foo bar) 1 2 3` and `ba<0xff>sh` are
/// both names somebody can choose, and either read naively drops its pid out of the
/// walk — after which [`Pty::terminate`] never signals it *and*, the walk being what
/// decides the session has settled, reports a clean shutdown over it.
/// `a_stat_line_parses_past_a_hostile_process_name` is both cases.
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

/// Resolves the shell to run and the dash-prefixed `argv[0]` that makes it a login
/// shell.
///
/// Precedence and the reason for the leading `-` are both `IMPLEMENTATION.md` § 6.1.1.
/// The password-database step matters for a session started by something that scrubs
/// the environment, where `$SHELL` is absent and `/bin/sh` would silently downgrade the
/// user's shell.
fn login_shell() -> (PathBuf, String) {
    let shell = env::var_os("SHELL")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| passwd::current().and_then(|entry| entry.shell))
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

/// Splits an `ExitStatus` into the wire representation of [`nomux_proto::Frame::Exit`].
#[must_use]
pub(crate) fn exit_parts(status: std::process::ExitStatus) -> (i32, nomux_proto::ExitKind) {
    use std::os::unix::process::ExitStatusExt;
    status.code().map_or_else(
        || {
            (
                status.signal().unwrap_or(0),
                nomux_proto::ExitKind::Signalled,
            )
        },
        |code| (code, nomux_proto::ExitKind::Exited),
    )
}

/// Outcome of one read from the PTY master.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Read {
    /// Bytes are available in the buffer.
    Data(usize),
    /// The last process holding the slave is gone.
    Eof,
    /// Nothing buffered right now. Distinct from [`Read::Eof`], which is the whole
    /// reason this is an enum: on a non-blocking master both arrive as an error
    /// return, and confusing `EAGAIN` for the end of the session would report the
    /// child as exited every time the poll set woke up spuriously.
    WouldBlock,
}

/// Reads from the PTY master.
///
/// When the last process holding the slave exits, Linux fails master reads with
/// `EIO` rather than returning 0. Callers want that to look like a clean EOF.
///
/// Nothing is propagated, which is why there is no `Result`: § 6.4.1 says a failing
/// client socket never leaves the event loop, and a PTY is not the one place a stray
/// errno may destroy the session (`Daemon::write_pty` carries the same argument for the
/// other direction). An errno this does not know is a master nothing can be read from,
/// so it arrives as the end of the session's *output* — and `Read::Eof` takes the
/// master out of the poll set, so nothing spins on it either.
pub(crate) fn read_pty(fd: BorrowedFd<'_>, buf: &mut [u8]) -> Read {
    match crate::nbio::read(fd, buf) {
        Ok(n) if n > 0 => Read::Data(n),
        Err(rustix::io::Errno::AGAIN) => Read::WouldBlock,
        Ok(_) | Err(_) => Read::Eof,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `comm` field is whatever the process called its executable, parentheses and
    /// spaces included, and the fields that matter here sit after it.
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

        // A `comm` the kernel does not escape and UTF-8 cannot hold. Read as a
        // string the whole line is undecodable, so this process would survive
        // `nomux kill` while the daemon reported a clean shutdown.
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
        let sid = rustix::process::Pid::as_raw(Some(sid));
        let members = session_members(sid);
        let self_pid = i32::try_from(std::process::id()).unwrap_or(0);
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

    /// Regression: the two reaches go out while the pid is still the child's, and
    /// not once it is somebody else's.
    ///
    /// Three states in one test because the observation is a process-wide flag: the
    /// ordinary case, which keeps the two negatives from passing vacuously; an ordinary
    /// exit, which reaps the child and leaves nothing for either reach; and that same
    /// pid handed to somebody else, which the liveness probe cannot see.
    ///
    /// Watched as the syscall rather than as its effect, which is the only thing that
    /// *can* be watched: where the guard skips, what it skips would have landed nowhere
    /// by construction. Nor can a reissued pid be arranged, so the third state
    /// falsifies this side's half of the identity instead. `SIGHUP` alone is trapped,
    /// because the `SIGKILL` `Child::kill` sends on the way out is not a reach.
    ///
    /// Trapping a syscall is not free of consequence for whoever made it: the kernel
    /// rolls the registers back before raising `SIGSYS`, so the call returns its own
    /// syscall number and rustix's debug assertion on a return value fires on it. Hence
    /// the `catch_unwind` around each of the three — the flag is set in the handler,
    /// before any of that.
    #[test]
    fn terminate_signals_a_pid_only_while_it_is_still_the_childs() {
        use std::sync::atomic::Ordering::Relaxed;

        // A live shell, whose session is emphatically not empty.
        let mut pty = shell("terminate_live");
        let raw = i32::try_from(pty.child.id()).unwrap_or(0);
        if !trap_hangups_of(raw) {
            // A host that will not take the filter cannot answer any of this, the
            // way `the_walk_never_returns_this_process` cannot without a session id.
            return;
        }
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pty.terminate()));
        assert!(
            SIGNALLED_A_FREED_PID.swap(false, Relaxed),
            "the ordinary case sent no SIGHUP, so the two assertions below are \
             about an instrument that measures nothing"
        );
        // Pinned rather than discarded, and it says something different in each
        // profile because the trap does. Where rustix's assertions are compiled in, the
        // trapped `kill` takes one with it, so what this pins is that the trap stopped
        // the call it was aimed at; where they are not, an unwind can only be somebody
        // else's and this refuses to swallow it.
        assert_eq!(
            unwound.is_err(),
            cfg!(debug_assertions),
            "a debug build must take rustix's assertion on the return value of the \
             syscall the filter rolled back, and a release build must not unwind \
             here at all"
        );
        // What `terminate` may not have got round to, having possibly left through
        // the trapped syscall rather than through its own end.
        drop(unwound);
        drop(pty.child.kill());
        drop(pty.child.wait());

        // An ordinary exit, collected the way the daemon collects one — which is
        // what frees the pid both reaches are addressed to.
        let mut pty = shell("terminate_reaped");
        rustix::io::write(pty.master(), b"exit\n").expect("ask the shell to leave");
        assert!(reaped_within(&mut pty), "the shell never exited");
        let raw = i32::try_from(pty.child.id()).unwrap_or(0);
        let pid = rustix::process::Pid::from_raw(raw).expect("the reaped child's pid");
        // Deterministic rather than hopeful, for the reason above: a pid stays
        // reserved while anything still names it.
        assert!(
            rustix::process::test_kill_process_group(pid).is_err()
                && session_members(raw).is_empty(),
            "nothing of the session may be left, or this is the other case"
        );
        assert!(trap_hangups_of(raw), "the filter was taken once already");
        // Caught here too, and for the opposite reason: a build that signals takes
        // rustix's assertion with it, and the failure worth reading is the flag below
        // rather than that one.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pty.terminate()));
        assert!(
            !SIGNALLED_A_FREED_PID.swap(false, Relaxed),
            "terminate signalled a pid the kernel had already taken back"
        );
        assert!(
            outcome.is_ok(),
            "terminate panicked with no signal behind it"
        );

        // And a live session again, with the number no longer the child's.
        // Everything the probe can see says signal; only the start time says the
        // process answering to it is not the one this spawned.
        let mut pty = shell("terminate_reissued");
        let raw = i32::try_from(pty.child.id()).unwrap_or(0);
        let started = pty
            .started
            .expect("a start time for a child that is running");
        pty.started = Some(started.wrapping_add(1));
        assert!(trap_hangups_of(raw), "the filter was taken twice already");
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pty.terminate()));
        assert!(
            !SIGNALLED_A_FREED_PID.load(Relaxed),
            "terminate signalled a pid that had been handed to somebody else"
        );
        assert!(
            outcome.is_ok(),
            "terminate panicked with no signal behind it"
        );
        // The child outlives a `terminate` that left early, either way.
        drop(pty.child.kill());
        drop(pty.child.wait());
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

    /// Set by [`note_sigsys`] when [`trap_hangups_of`] catches a reach going out.
    static SIGNALLED_A_FREED_PID: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    extern "C" fn note_sigsys(_signum: libc::c_int) {
        SIGNALLED_A_FREED_PID.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Traps every `SIGHUP` at `pid` or at its process group, so that issuing one
    /// sets [`SIGNALLED_A_FREED_PID`] instead of reaching the kernel. `false` where
    /// the filter was refused.
    ///
    /// `SIGHUP` because both reaches begin with one and nothing else does: the liveness
    /// probe sends signal 0, and the `SIGKILL` on the way out is not a reach.
    ///
    /// This thread's alone — no `TSYNC` flag — which keeps it off the rest of a `cargo
    /// test` run. It cannot be removed once installed, and is not. Installing a second
    /// is how one test watches three pids.
    fn trap_hangups_of(pid: i32) -> bool {
        // `struct seccomp_data`: the syscall number at 0, then the arguments from
        // 16, eight bytes each. Only the low half of an argument is loaded, which is
        // the whole of a pid and is where it sits on every little-endian target.
        const NUMBER: u32 = 0;
        const TARGET: u32 = 16;
        const SIGNAL: u32 = 24;

        let load = u16::try_from(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS).expect("a BPF opcode");
        let equals =
            u16::try_from(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K).expect("a BPF opcode");
        let answer = u16::try_from(libc::BPF_RET | libc::BPF_K).expect("a BPF opcode");
        let jump = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
        // Jump offsets count from the instruction after the one carrying them, so
        // both destinations are the last two entries: allow at 7, trap at 8.
        let mut filter = [
            jump(load, 0, 0, NUMBER),
            jump(
                equals,
                0,
                5,
                u32::try_from(libc::SYS_kill).expect("the kill syscall"),
            ),
            jump(load, 0, 0, SIGNAL),
            jump(
                equals,
                0,
                3,
                u32::try_from(libc::SIGHUP).expect("a signal number"),
            ),
            jump(load, 0, 0, TARGET),
            jump(equals, 2, 0, pid.cast_unsigned()),
            jump(equals, 1, 0, pid.wrapping_neg().cast_unsigned()),
            jump(answer, 0, 0, libc::SECCOMP_RET_ALLOW),
            jump(answer, 0, 0, libc::SECCOMP_RET_TRAP),
        ];

        // Before the filter, or the first trap is a core dump.
        //
        // SAFETY: `signal` with a handler that does nothing but store to an atomic,
        // which is async-signal-safe.
        unsafe { libc::signal(libc::SIGSYS, note_sigsys as *const () as libc::sighandler_t) };
        // SAFETY: `prctl` with `PR_SET_NO_NEW_PRIVS` takes no pointer arguments. It
        // is what lets an unprivileged process install the filter below.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return false;
        }
        let program = libc::sock_fprog {
            len: u16::try_from(filter.len()).expect("a filter of a few instructions"),
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: `seccomp` is handed a program whose length matches the array it
        // points at, both of which outlive the call.
        let installed = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0,
                std::ptr::from_ref(&program),
            )
        };
        installed == 0
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
            match read_pty(pty.master(), &mut buf) {
                Read::Data(n) => seen.push_str(&String::from_utf8_lossy(&buf[..n])),
                Read::WouldBlock => std::thread::sleep(HANGUP_POLL_INTERVAL),
                Read::Eof => break,
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
