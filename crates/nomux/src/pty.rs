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

use nomux_protocol::WinSize;
use rustix::fs::{Mode, OFlags};
use rustix::process::{
    Pid, PidfdFlags, Signal, WaitId, WaitIdOptions, pidfd_open, pidfd_send_signal, waitid,
};
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

/// Budget for each HUP/KILL session-cleanup phase. `control.rs` separately gives the
/// daemon two seconds after `SIGTERM`.
const HANGUP_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// Interval between liveness checks while waiting out [`HANGUP_GRACE`].
const HANGUP_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

/// A running session: the PTY master plus the child holding its slave.
#[derive(Debug)]
pub(crate) struct Pty {
    master: OwnedFd,
    child: Child,
    /// Whether the child's outcome has been read without collecting it.
    observed: bool,
    /// Whether shutdown has collected the child.
    reaped: bool,
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
        let max_signal = libc::SIGRTMAX();
        let pre_exec = move || {
            rustix::process::setsid()?;
            // SAFETY: `slave_fd` is open in the child, inherited across fork.
            let slave = unsafe { BorrowedFd::borrow_raw(slave_fd) };
            rustix::process::ioctl_tiocsctty(slave)?;
            // Exec preserves ignored dispositions. Give the login shell defaults rather
            // than a launcher's signal policy; skip the two uncatchable signals.
            for signum in 1..=max_signal {
                if !matches!(signum, libc::SIGKILL | libc::SIGSTOP) {
                    // SAFETY: `signal` is async-signal-safe and SIG_DFL is a valid handler.
                    unsafe { libc::signal(signum, libc::SIG_DFL) };
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
        // Both the copy in this frame and the three `Stdio::from` took: std only
        // *borrows* an owned descriptor for the child, so `Command` holds all three
        // until it is itself dropped. § 6.1 has what a copy outliving this function
        // would cost.
        drop(command);
        drop(slave);
        Ok(Self {
            master,
            child,
            observed: false,
            reaped: false,
        })
    }

    /// The PTY master, for reading output and writing input.
    #[must_use]
    pub(crate) fn master(&self) -> BorrowedFd<'_> {
        self.master.as_fd()
    }

    /// Applies new dimensions, which delivers `SIGWINCH` to the foreground group.
    pub(crate) fn resize(&self, win: WinSize) -> io::Result<()> {
        tcsetwinsize(&self.master, to_winsize(win)).map_err(Into::into)
    }

    pub(crate) const fn needs_observation(&self) -> bool {
        !self.observed
    }

    /// Nudges the child into repainting by resizing to one column narrower and back,
    /// delivering two `SIGWINCH`es — the gap-recovery repaint of `IMPLEMENTATION.md`
    /// § 4.3. A one-column terminal is left without one: the master already holds `win`,
    /// so the lone resize left is one the kernel short-circuits rather than signals.
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

    /// Observes the child's outcome without releasing its process identity.
    pub(crate) fn try_outcome(&mut self) -> io::Result<Option<(i32, nomux_protocol::ExitKind)>> {
        if self.observed || self.reaped {
            return Ok(None);
        }
        let raw = as_pid(self.child.id());
        let Some(pid) = Pid::from_raw(raw) else {
            return Err(io::Error::other("child pid is invalid"));
        };
        let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
        let status = loop {
            match waitid(WaitId::Pid(pid), options) {
                Err(err) if err == rustix::io::Errno::INTR => {}
                outcome => break outcome?,
            }
        };
        let Some(status) = status else {
            return Ok(None);
        };
        self.observed = true;
        let outcome = status.exit_status().map_or_else(
            || {
                (
                    status.terminating_signal().unwrap_or(0),
                    nomux_protocol::ExitKind::Signalled,
                )
            },
            |code| (code, nomux_protocol::ExitKind::Exited),
        );

        Ok(Some(outcome))
    }

    /// Terminates the child's process group and everything else in its session.
    pub(crate) fn terminate(&mut self) {
        let raw = as_pid(self.child.id());
        if let Some(pid) = Pid::from_raw(raw)
            && !self.reaped
        {
            let mut group_alive = rustix::process::test_kill_process_group(pid).is_ok();
            let deadline = std::time::Instant::now() + HANGUP_GRACE;
            let mut settled = session_is_empty(raw, Some(deadline));
            if !settled {
                if group_alive {
                    reach(Reach::Group(pid), Signal::HUP);
                }
                signal_session(raw, Signal::HUP, deadline);

                while std::time::Instant::now() < deadline {
                    group_alive = rustix::process::test_kill_process_group(pid).is_ok();
                    if session_is_empty(raw, Some(deadline)) {
                        settled = true;
                        break;
                    }
                    std::thread::sleep(HANGUP_POLL_INTERVAL);
                }
            }
            if !settled {
                if group_alive {
                    reach(Reach::Group(pid), Signal::KILL);
                }
                let deadline = std::time::Instant::now() + HANGUP_GRACE;
                loop {
                    signal_session(raw, Signal::KILL, deadline);
                    if session_is_empty(raw, Some(deadline))
                        || std::time::Instant::now() >= deadline
                    {
                        break;
                    }
                    std::thread::sleep(HANGUP_POLL_INTERVAL);
                }
            }
        }
        if !self.reaped {
            drop(self.child.kill());
            self.reaped = self.child.try_wait().is_ok_and(|status| status.is_some());
        }
    }
}

/// A pid as the signed number `/proc` and `kill(2)` are addressed with. The conversion
/// cannot fail — the kernel caps `pid_max` at 2^22 — and zero is the one fallback
/// nothing here can act on, `Pid::from_raw` refusing it and `/proc/0` never existing.
fn as_pid(id: u32) -> i32 {
    i32::try_from(id).unwrap_or(0)
}

/// Signals every live process still in session `sid`, individually: `kill(2)` has no
/// session form, and the point is precisely the groups job control created that nobody
/// is tracking. Each member is signalled through a pidfd that was confirmed to hold that
/// member ([`pinned_member`]), never through the number, or the reuse window a numeric
/// `kill(2)` has reopens.
fn signal_session(sid: i32, signal: Signal, deadline: std::time::Instant) {
    let _ = walk_session(Path::new(PROC), sid, true, Some(deadline), |_, pinned| {
        // A missing pidfd is ambiguity, not licence to fall back to the number:
        // signalling nothing is safer than reaching a process that inherited it. The
        // child's own process-group reach remains.
        if let Some(pidfd) = pinned {
            reach(Reach::Pinned(pidfd), signal);
        }
        true
    });
}

/// One stable destination for a signal this module sends.
#[derive(Clone, Copy)]
enum Reach<'a> {
    /// The direct child's process group, held by the live or zombie child.
    Group(Pid),
    /// A session member held across the `/proc` membership check.
    Pinned(&'a OwnedFd),
}

/// Sends one signal to a guarded process group or a pinned process — the module's only
/// door to a signal, or a later path could reach a process without `REACHES` recording
/// it, the invariant the regression tests below rest on. The outcome is dropped
/// throughout: `ESRCH` from a process the first signal killed is this working.
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

/// The process directory the walk below reads outside its own tests, which hand it one
/// whose entries they can make fail.
const PROC: &str = "/proc";

/// What one `/proc/<pid>/stat` read said about a process's membership of a session.
///
/// The three are kept apart the way § 6.6 keeps `/proc`'s three answers apart for `kill`,
/// and for the same reason: a `/proc` that lists a process and then refuses its line —
/// `hidepid=1`, `ProtectProc=noaccess`, or a daemon that has simply run out of
/// descriptors — must not have the members it withholds counted as members that are not
/// there.
enum Membership {
    /// Live, and in the session asked about.
    In,
    /// Answered for and not that: another session, a zombie, or a process that had
    /// already exited when its line was read.
    Out,
    /// No answer at all. Carried by the walk as incompleteness rather than as absence.
    Unseen,
}

/// Walks `root` — `/proc`, outside the tests below — for the live processes in session
/// `sid`, offering each to `visit` until it answers `false`.
///
/// Deliberately narrow: `sid` is always a child this process forked, this process is
/// excluded by pid whatever `/proc` says, and zombies are left out — signalling one does
/// nothing, and counting it would spin the caller's grace loop over the child it is
/// about to reap.
///
/// With `pin` set, the members and only the members are pinned, and their membership is
/// re-read behind the pidfd before they are offered to `visit` — [`pinned_member`] has why
/// that is as decisive as opening the descriptor first. It costs a second `stat` per
/// member, where pinning ahead of the question cost a pidfd for every process on the host:
/// a walk over a large process table has to finish inside [`HANGUP_GRACE`], and one that
/// runs out of it leaves the members it had not reached yet unsignalled. A member that
/// cannot be pinned is still visible to the emptiness check but never safe to signal.
/// One path and one read buffer for the whole walk: [`Pty::terminate`]'s grace loop
/// reaches here every [`HANGUP_POLL_INTERVAL`] inside [`HANGUP_GRACE`].
///
/// Returns whether the walk saw everything it looked at: `false` if `root` could not be
/// enumerated, if `deadline` passed, or if a process in it kept its `stat` from being read
/// ([`Membership::Unseen`]). A stopped visit is successful: the caller already learned
/// what it asked.
fn walk_session(
    root: &Path,
    sid: i32,
    pin: bool,
    deadline: Option<std::time::Instant>,
    mut visit: impl FnMut(i32, Option<&OwnedFd>) -> bool,
) -> bool {
    if deadline.is_some_and(|at| std::time::Instant::now() >= at) {
        return false;
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    let self_pid = as_pid(std::process::id());
    let mut path = root.to_path_buf();
    let mut stat = Vec::with_capacity(1024);
    let mut complete = true;
    for entry in entries {
        if deadline.is_some_and(|at| std::time::Instant::now() >= at) {
            return false;
        }
        let Ok(entry) = entry else {
            return false;
        };
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|name| name.parse::<i32>().ok()) else {
            continue;
        };
        if pid == self_pid {
            continue;
        }
        match membership(sid, &mut path, &name, &mut stat) {
            Membership::In => {}
            Membership::Out => continue,
            // The same rule the two refusals above follow, one process down: what the walk
            // could not look at is not something it may report the absence of.
            Membership::Unseen => {
                complete = false;
                continue;
            }
        }
        // Failure is carried as `None`; only the signalling caller requires a hold, while
        // `session_is_empty` still needs to see members on kernels without pidfds.
        let pinned = pin
            .then(|| pinned_member(sid, pid, &mut path, &name, &mut stat))
            .flatten();
        if !visit(pid, pinned.as_ref()) {
            return true;
        }
    }
    complete
}

/// What `<path>/<name>/stat` says about that process's membership of session `sid`, with
/// the path buffer and the read buffer borrowed from the walk and left as they were found.
fn membership(sid: i32, path: &mut PathBuf, name: &OsStr, stat: &mut Vec<u8>) -> Membership {
    path.push(name);
    path.push("stat");
    stat.clear();
    let read = File::open(&*path).and_then(|mut file| file.read_to_end(stat));
    path.pop();
    path.pop();
    match read {
        Ok(_) => stat_session(stat).map_or(Membership::Unseen, |(session, zombie)| {
            if session == sid && !zombie {
                Membership::In
            } else {
                Membership::Out
            }
        }),
        // A process that ended between the directory listing and this read is not a gap in
        // the evidence: it is gone, which is an answer. `ESRCH` says the same thing through
        // a `/proc` directory that outlived the task it named, and taken as anything else
        // it would leave every walk overlapping an unrelated exit — on a busy host, most of
        // them — reporting a session it could not settle.
        Err(err)
            if err.kind() == io::ErrorKind::NotFound || err.raw_os_error() == Some(libc::ESRCH) =>
        {
            Membership::Out
        }
        Err(_) => Membership::Unseen,
    }
}

/// A descriptor onto `pid` that has been shown to still hold a live member of session
/// `sid`, or `None`.
///
/// The pidfd is what makes the second read decisive, and why asking first and pinning
/// after closes the same window as pinning first: while the descriptor is held the kernel
/// cannot give the number to a new process, so from that moment `<path>/<pid>` is either
/// the pinned process or nothing at all. A pid recycled in the window before the pin
/// therefore answers as whatever it now is and is refused, and one that still answers
/// `sid` is a member of the very session being torn down — the session id itself cannot
/// have been recycled underneath, since [`Pty::terminate`] holds the leader's zombie
/// unreaped for exactly as long as it signals through that id.
fn pinned_member(
    sid: i32,
    pid: i32,
    path: &mut PathBuf,
    name: &OsStr,
    stat: &mut Vec<u8>,
) -> Option<OwnedFd> {
    let pidfd = Pid::from_raw(pid).and_then(|pid| pidfd_open(pid, PidfdFlags::empty()).ok())?;
    matches!(membership(sid, path, name, stat), Membership::In).then_some(pidfd)
}

/// Whether nothing live is left in session `sid`.
///
/// The walk stops at the first member rather than reading every remaining
/// `/proc/<pid>/stat` to answer a question that one has already answered:
/// [`Pty::terminate`]'s grace loop asks this every [`HANGUP_POLL_INTERVAL`]. An
/// incomplete walk answers false, the safe direction: it must not suppress the group reach
/// and final child kill on evidence it never obtained — and one `stat` it was refused is
/// that same failure at one process, which is precisely the shape a member hidden from the
/// daemon takes.
fn session_is_empty(sid: i32, deadline: Option<std::time::Instant>) -> bool {
    let mut empty = true;
    let scanned = walk_session(Path::new(PROC), sid, false, deadline, |_, _| {
        empty = false;
        false
    });
    scanned && empty
}

/// The fields of one `/proc/<pid>/stat` from the third onwards, taken from the last `)`
/// and over bytes: field two is the executable's name, the kernel escapes only `\n` and
/// `\\` in it, and a name read naively drops its pid out of the walk — never signalled,
/// and reported as a clean shutdown over.
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

const fn to_winsize(win: WinSize) -> Winsize {
    Winsize {
        ws_row: win.rows,
        ws_col: win.cols,
        ws_xpixel: win.xpixel,
        ws_ypixel: win.ypixel,
    }
}

/// Resolves the shell to run and the dash-prefixed `argv[0]` that makes it a login shell
/// (`IMPLEMENTATION.md` § 6.1.1). Nothing reads the password database behind `$SHELL`:
/// sshd sets it from that database itself, and § 6.1.1 has the directory-backed user
/// falling through to `/bin/sh`.
fn login_shell() -> (PathBuf, String) {
    pick_shell(env::var_os("SHELL").map(PathBuf::from))
}

/// The choice behind [`login_shell`], with the environment lifted out so it is testable
/// without mutating it — as [`pick_dir`] is for [`child_dir`]. Absolute rather than
/// merely non-empty: a program with no `/` sends `Command` looking down `PATH`, so a
/// `SHELL=bash` would run whatever a writable `~/.local/bin` resolves it to.
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
        .find(|dir| dir.is_absolute() && dir.is_dir())
        .map_or_else(|| PathBuf::from("/"), Path::to_path_buf)
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

    #[test]
    fn an_expired_session_walk_is_incomplete_not_empty() {
        let deadline = std::time::Instant::now();
        let mut visited = false;
        let proc = Path::new(PROC);
        assert!(!walk_session(proc, 0, false, Some(deadline), |_, _| {
            visited = true;
            true
        }));
        assert!(!visited);
        assert!(!session_is_empty(0, Some(deadline)));
    }

    /// A `stat` the walk was refused leaves the session unsettled, exactly as a `/proc` it
    /// could not enumerate does: this answer is the only thing that can tell
    /// [`Pty::terminate`] there is nothing left to `SIGHUP`, and the one process still
    /// holding the session — something the user left running under `sudo`, on a `/proc`
    /// mounted `hidepid=1` — is exactly the one whose line the daemon may not read. Taken
    /// as absence it skips both escalations and leaves that process behind.
    ///
    /// The unreadable `stat` is a directory rather than a file at mode `0`, which a suite
    /// running as root would read anyway. The readable ones around it are the other half:
    /// a walk that answered `false` for everything would pass this on an instrument that
    /// measures nothing.
    #[test]
    fn a_stat_the_walk_cannot_read_leaves_the_session_unsettled() {
        const SID: i32 = 4242;
        let root = crate::scratch::Scratch::new("pty-hidden-member");
        let plant = |pid: i32, session: i32| {
            let line = format!("{pid} (sh) S 1 {pid} {session} 34816 99 4194304 0 0");
            std::fs::write(root.dir(&pid.to_string()).join("stat"), line)
                .expect("plant a stat line");
        };
        let scan = |sid| {
            let mut members = Vec::new();
            let complete = walk_session(root.path(), sid, false, None, |pid, _| {
                members.push(pid);
                true
            });
            (complete, members)
        };

        plant(101, SID);
        plant(102, 999);
        // A process that left between the listing and the read: its directory is there and
        // its `stat` is not, which the walk has to tell from a `stat` it was refused.
        root.dir("103");
        assert_eq!(
            scan(SID),
            (true, vec![101]),
            "a walk that read every line it found is complete, and found the one member"
        );

        root.dir("104/stat");
        assert_eq!(
            scan(SID),
            (false, vec![101]),
            "a `stat` the walk could not read is a member it could not rule out"
        );
        assert_eq!(
            scan(7),
            (false, Vec::new()),
            "and a session whose every visible process belongs to somebody else is still \
             not one this may report as empty"
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

    /// An exited shell stays waitable while its background job needs the session id.
    #[test]
    fn terminate_collects_a_job_after_its_shell_exits() {
        let mut pty = shell("terminate_orphan");

        // `exit` twice, because a shell with job control may answer the first one
        // by pointing out that a job is still running and asking again — zsh does.
        // Where the first is taken the second is never read by anybody.
        let script = "set -m\n(trap '' HUP; sleep 30) &\necho NOMUX-JOB=$!\nexit\nexit\n";
        rustix::io::write(pty.master(), script.as_bytes()).expect("write the script");
        let job = read_marker(&pty, "NOMUX-JOB=").expect("the shell reported its job pid");
        let shell = as_pid(pty.child.id());

        assert!(outcome_within(&mut pty), "the shell never exited");
        assert!(
            std::fs::read(format!("/proc/{shell}/stat"))
                .ok()
                .and_then(|stat| stat_session(&stat))
                .is_some_and(|(_, zombie)| zombie),
            "the shell was reaped before its session was empty"
        );
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
            "a job whose shell had already exited outlived the session"
        );
    }

    /// A live session is signalled; an observed child alone is only collected.
    #[test]
    fn terminate_signals_only_a_live_session() {
        let mut pty = shell("terminate_live");
        drop(reaches_since());
        pty.terminate();
        assert!(
            !reaches_since().is_empty(),
            "the ordinary case signalled nothing, so the two assertions below are about \
             an instrument that measures nothing"
        );

        let mut pty = shell("terminate_reaped");
        rustix::io::write(pty.master(), b"exit\n").expect("ask the shell to leave");
        assert!(outcome_within(&mut pty), "the shell never exited");
        let raw = as_pid(pty.child.id());
        assert!(
            std::fs::read(format!("/proc/{raw}/stat"))
                .ok()
                .and_then(|stat| stat_session(&stat))
                .is_some_and(|(_, zombie)| zombie)
                && session_is_empty(raw, None),
            "the observed shell must reserve an otherwise empty session"
        );
        drop(reaches_since());
        pty.terminate();
        assert_eq!(
            reaches_since(),
            [],
            "terminate signalled a session with no live member"
        );
    }

    /// Regression: a shutdown over a child that has already gone ends with the session,
    /// rather than sitting out [`HANGUP_GRACE`] behind the child's own zombie. The child
    /// is left exited and *unreaped*: settlement must ignore that zombie without reaping
    /// it, since keeping it is what reserves the numeric session id until every signal
    /// addressed through that id has gone out.
    #[test]
    fn terminate_ends_a_settled_session_without_reaching_for_sigkill() {
        let mut pty = shell("terminate_quiet");
        let raw = as_pid(pty.child.id());
        let pid = Pid::from_raw(raw).expect("the child's pid");
        rustix::io::write(pty.master(), b"exit\n").expect("ask the shell to leave");

        // Watched through `/proc` without observing the outcome first.
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
            session_is_empty(raw, None),
            "the zombie must be all that is left, or the grace is owed either way"
        );

        drop(reaches_since());
        pty.terminate();
        let sent = reaches_since();
        assert_eq!(
            sent,
            [],
            "terminate signalled a session whose only member was the zombie it held \
             unreaped as an identity guard: {sent:?}"
        );
    }

    /// Every pid [`walk_session`] offers for `sid`, which nothing outside the tests
    /// collects: [`signal_session`] signals inside the walk and [`session_is_empty`] stops
    /// at the first member.
    fn session_members(sid: i32) -> Vec<i32> {
        let mut members = Vec::new();
        walk_session(Path::new(PROC), sid, false, None, |pid, _| {
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

    /// A [`Pty`] whose shell is collected however the test holding it ends: `Pty` has no
    /// `Drop` of its own, deliberately, and an `expect` firing before a test reaches
    /// `terminate` would leave a `dash` behind unwaited. Kill and wait only, no session
    /// walk.
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

    /// Observes the child once it exits. `false` if it never leaves.
    fn outcome_within(pty: &mut Pty) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if pty.try_outcome().expect("wait for the shell").is_some() {
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
        assert_eq!(pick_dir(Some(Path::new(".")), Some(home)), home);
        assert_eq!(pick_dir(None, Some(home)), home);
        assert_eq!(pick_dir(None, None), Path::new("/"));
    }
}
