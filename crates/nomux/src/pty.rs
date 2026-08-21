//! PTY allocation and child spawn.
//!
//! What the child runs and why is `IMPLEMENTATION.md` § 6.1.1; the mechanics of the
//! PTY itself are § 6.1.

use std::env;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::io::Read;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use nomux_protocol::WinSize;
use rustix::fs::{Mode, OFlags};
use rustix::process::{
    Pid, PidfdFlags, Signal, WaitId, WaitIdOptions, pidfd_open, pidfd_send_signal, waitid,
};
use rustix::pty::{OpenptFlags, openpt, ptsname, unlockpt};
use rustix::termios::{Winsize, tcsetwinsize};

use crate::exec::{self, Program};

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
///
/// The child is a bare pid and not a `std::process::Child`, `crate::exec` having the
/// argument. Nothing here reaps it: the zombie is what reserves the numeric session id for
/// as long as [`Pty::terminate`] signals through it, and § 6.5 leaves it to init.
#[derive(Debug)]
pub(crate) struct Pty {
    master: OwnedFd,
    child: Pid,
    /// Whether the child's outcome has been read without collecting it.
    observed: bool,
}

impl Pty {
    /// Allocates a PTY and spawns the user's login shell on its slave.
    ///
    /// # Errors
    ///
    /// Propagates the PTY allocation, the slave `open` and the spawn.
    pub(crate) fn spawn(config: &Spawn<'_>) -> io::Result<Self> {
        // `CLOEXEC` on both ends, and what it keeps out of the child: § 6.1.
        //
        // `NONBLOCK` is folded into the same open (the non-blocking master of § 6.1)
        // rather than set with an `fcntl` pair afterwards, which is two more syscalls and
        // two more error paths on the session-creation path. It leans on something
        // rustix does not document: on Linux `openpt` is a plain
        // `open("/dev/ptmx", flags)` and `OpenptFlags` carries a catch-all bit, so an
        // `O_*` it does not name reaches the kernel unchanged. A rustix bump could
        // silently drop the flag and leave the daemon blocking inside a PTY write, so
        // `a_pty_master_is_non_blocking_as_it_is_opened` reads the flag back rather than
        // trusting this. The slave is a separate open and stays blocking, as the child
        // expects of its stdio.
        let master = openpt(
            OpenptFlags::RDWR
                | OpenptFlags::NOCTTY
                | OpenptFlags::CLOEXEC
                | OpenptFlags::from_bits_retain(OFlags::NONBLOCK.bits()),
        )?;
        unlockpt(&master)?;
        let slave_path = ptsname(&master, Vec::new())?;

        // As the `CString` `ptsname` returned: going through `OsStr` would strip the
        // terminator and have rustix copy the path back into a buffer to re-append it.
        let slave: OwnedFd = rustix::fs::open(
            slave_path.as_c_str(),
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        // Before the child can observe it, so its first prompt is laid out right.
        tcsetwinsize(&master, to_winsize(config.win))?;

        // Everything the child will need, rendered here in the parent: between the fork
        // and the `execve` it may not allocate, and `crate::exec` has why that is stricter
        // than what `Command`'s `pre_exec` used to ask of the `setup` closure below.
        let (shell, argv0) = login_shell();
        let mut program = Program::new(&shell, argv0.as_bytes())?;
        // The daemon has moved to `/` (§ 6.2), so the child's directory is passed rather
        // than inherited or the shell would start there.
        program.current_dir(config.cwd)?;
        program.env("TERM", config.term.as_bytes())?;
        program.env("NOMUX_SESSION", config.session_id.as_bytes())?;
        if let Some(sock) = config.agent_sock {
            // Overwrites whatever sshd forwarded, deliberately (§ 6.7).
            program.env("SSH_AUTH_SOCK", sock.as_os_str().as_bytes())?;
        }

        // Read out here rather than in the child below, and load-bearing for it:
        // `SIGRTMAX()` is a libc *function* — on glibc one that consults a value the
        // runtime initialises — and the child may call nothing that is not
        // async-signal-safe. The loop it bounds runs there; the question is answered here.
        let max_signal = libc::SIGRTMAX();
        // The three descriptors the child is handed are all the slave, which
        // `crate::exec::spawn` places on 0, 1 and 2 for it. `CLOEXEC` on both ends of the
        // PTY (§ 6.1) is what keeps the master out of the child; these three cross because
        // `dup2` clears the flag on the copies it makes and on nothing else.
        let child = exec::spawn(&program, [slave.as_fd(); 3], &mut |[input, _, _]| {
            rustix::process::setsid()?;
            // SAFETY: `input` is this child's copy of the slave — open across the fork,
            // and already raised clear of the three numbers it is about to be placed on.
            let slave = unsafe { BorrowedFd::borrow_raw(input) };
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
        })?;
        // The daemon's own copy, let go of the moment the child holds one of its own —
        // § 6.1 has what one outliving this function would cost. `Command` used to keep
        // three of them until it was itself dropped, which is what the `drop` here
        // replaces.
        drop(slave);
        Ok(Self {
            master,
            child,
            observed: false,
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
        if self.observed {
            return Ok(None);
        }
        let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
        let status = loop {
            match waitid(WaitId::Pid(self.child), options) {
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
    ///
    /// Called exactly once, from `Daemon::shutdown`, which drops the `Pty` on the very
    /// next line — so this is deliberately *not* idempotent and guards against neither a
    /// second call nor a [`Pty::try_outcome`] after it. Nothing collects the child
    /// either: the daemon exits behind this, leaving the zombie to init, and the tests
    /// that hold a `Pty` past a `terminate` do their own `wait`.
    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "nothing here mutates the `Pty` now that the child is a bare pid, but \
                  every caller holds one by value and `let Some(mut pty) = …` would be an \
                  unused `mut` the moment this took `&self`"
    )]
    pub(crate) fn terminate(&mut self) {
        let pid = self.child;
        let raw = Pid::as_raw(Some(pid));
        let mut group_alive = rustix::process::test_kill_process_group(pid).is_ok();
        // A budget of the probe's own, and then a fresh one for the hangup phase
        // below, exactly as the `SIGKILL` phase takes for itself. Sharing one across
        // the three would spend the shell's grace on finding out whether it is owed
        // any: this probe is a whole `/proc` walk — three syscalls for every entry
        // ahead of the child in readdir order, tens of milliseconds on a busy host —
        // and one that used the budget up leaves [`walk_session`] bailing at its
        // first deadline check, so the `SIGHUP` walk below reaches nobody and every
        // session member in a process group of its own goes straight to `SIGKILL`.
        let mut settled = session_is_empty(raw, Some(std::time::Instant::now() + HANGUP_GRACE));
        let deadline = std::time::Instant::now() + HANGUP_GRACE;
        if !settled {
            if group_alive {
                reach(Reach::Group(pid), Signal::HUP);
                reach(Reach::Group(pid), Signal::CONT);
            }
            signal_session(raw, Signal::HUP, deadline);
            // `SIGCONT` behind every `SIGHUP`, as sshd and tmux both send it. A
            // stopped task is only woken by a signal whose *default* action is fatal,
            // so a job the user suspended with `Ctrl-Z` that installed a `SIGHUP`
            // handler — `vim`, `less`, `emacs -nw`, an inner shell — leaves the
            // signal merely queued and stays in state `T`: it counts as a live member
            // for the whole grace below and is then `SIGKILL`ed with its hangup path
            // never run, which for `vim` is the swapfile left orphaned. To anything
            // that was not stopped this is a no-op. The `SIGKILL` phase needs no
            // counterpart, `SIGKILL` being fatal by default and so waking a stopped
            // task itself.
            signal_session(raw, Signal::CONT, deadline);

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
                if session_is_empty(raw, Some(deadline)) || std::time::Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(HANGUP_POLL_INTERVAL);
            }
        }
        // The direct child, last and unconditionally, and deliberately not through
        // [`reach`]: `reach` is the door every *session* signal goes through so the tests
        // below can assert on what a settled session was sent, and this one is owed
        // whatever the walk concluded — a `SIGKILL` to a process that has already exited
        // is the `ESRCH` those tests must not see recorded. Safe against pid reuse for the
        // reason [`pinned_member`] gives: nothing has reaped this child.
        let _ = rustix::process::kill_process(pid, Signal::KILL);
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
    let _ = walk_session(
        Path::new(PROC),
        sid,
        true,
        Some(deadline),
        &mut |_, pinned| {
            // A missing pidfd is ambiguity, not licence to fall back to the number:
            // signalling nothing is safer than reaching a process that inherited it. The
            // child's own process-group reach remains.
            if let Some(pidfd) = pinned {
                reach(Reach::Pinned(pidfd), signal);
            }
            true
        },
    );
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
///
/// `visit` is taken as a trait object rather than by `impl FnMut`, which would give each
/// of the two callers a full copy of a body that reads a directory, pushes and pops a
/// `PathBuf` per entry and calls [`membership`] and [`pinned_member`]. This is the cold
/// teardown path — it runs once per session, against syscalls — so an indirect call per
/// process costs nothing measurable against the `.text` two copies cost.
fn walk_session(
    root: &Path,
    sid: i32,
    pin: bool,
    deadline: Option<std::time::Instant>,
    visit: &mut dyn FnMut(i32, Option<&OwnedFd>) -> bool,
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
    let scanned = walk_session(Path::new(PROC), sid, false, deadline, &mut |_, _| {
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
/// merely non-empty: `crate::exec` searches no `PATH` (its module doc has why), so a
/// program with no `/` is left to `execve` to resolve against the child's working
/// directory — and that directory is the user's own `$HOME`, which the child `chdir`s to
/// in the same breath. A `SHELL=bash` would run whatever `~/bash` happens to be.
fn pick_shell(shell: Option<PathBuf>) -> (PathBuf, String) {
    let shell = shell
        // Executable, not merely named, and for the reason [`pick_dir`] probes its
        // directory: an absolute `$SHELL` naming a binary that is gone or is not
        // executable propagates `ENOENT`/`EACCES` out of `execve`, and `daemon.rs`
        // answers a failed spawn with `ErrorCode::Internal` and stops — so a stale
        // `$SHELL` costs the user the session outright where § 6.1.1's precedence says
        // it should cost them nothing but `/bin/sh`. `access(2)` asks with the real ids,
        // which for this unprivileged, never-setuid daemon are the effective ones.
        //
        // `is_file` as well, because `access(X_OK)` alone is not the question being
        // asked: on a *directory* the execute bit means search permission, and it is set
        // on every directory this daemon can enter — so a `SHELL=/tmp` passes an `X_OK`
        // probe, reaches `execve`, and comes back `EACCES`, costing the session exactly
        // what the rest of this filter exists to prevent. `is_file` is `stat(2)` and
        // follows symlinks, and it answers *no* where the `stat` itself failed, which is
        // the fallback a `$SHELL` pointing at a dangling link deserves anyway.
        .filter(|value| {
            value.is_absolute()
                && value.is_file()
                && rustix::fs::access(value, rustix::fs::Access::EXEC_OK).is_ok()
        })
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
        // `is_dir` is `stat(2)`, which answers for a mode-`0000` directory as long as its
        // parent is searchable, while `chdir(2)` needs search permission on the directory
        // itself. Without the probe such a `$HOME` — one on an autofs or NFS mount
        // answering `EACCES`, one whose mode was tightened — reaches
        // `exec::Program::current_dir`, fails at the `chdir` the forked child issues just
        // before its `execve`, and comes back down that child's errno pipe as an `EACCES`
        // that `daemon.rs` answers with `ErrorCode::Internal`: the session
        // refuses to start rather than falling through to the next step of the
        // precedence, which is worse than `ssh`, and worse than the `/` this documents.
        .find(|dir| {
            dir.is_absolute()
                && dir.is_dir()
                && rustix::fs::access(*dir, rustix::fs::Access::EXEC_OK).is_ok()
        })
        .map_or_else(|| PathBuf::from("/"), Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::nbio::{ReadOutcome, read_or_eof};
    use crate::scratch::Scratch;

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
        assert!(!walk_session(
            proc,
            0,
            false,
            Some(deadline),
            &mut |_, _| {
                visited = true;
                true
            }
        ));
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
        let root = Scratch::new("pty-hidden-member");
        let plant = |pid: i32, session: i32| {
            let line = format!("{pid} (sh) S 1 {pid} {session} 34816 99 4194304 0 0");
            std::fs::write(root.dir(&pid.to_string()).join("stat"), line)
                .expect("plant a stat line");
        };
        let scan = |sid| {
            let mut members = Vec::new();
            let complete = walk_session(root.path(), sid, false, None, &mut |pid, _| {
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
        let shell = Pid::as_raw(Some(pty.child));

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
        let raw = Pid::as_raw(Some(pty.child));
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
        let raw = Pid::as_raw(Some(pty.child));
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
        walk_session(Path::new(PROC), sid, false, None, &mut |pid, _| {
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
                let _ = rustix::process::kill_process(pty.child, Signal::KILL);
                let _ = rustix::process::waitpid(
                    Some(pty.child),
                    rustix::process::WaitOptions::empty(),
                );
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

    /// § 6.1.1's precedence, now that it is two steps: an absolute `$SHELL` this may
    /// hand to `execve`, and `/bin/sh` for everything else. The refusals are the point
    /// rather than the happy path, and [`pick_shell`] has what a relative one would cost.
    ///
    /// The shell that *is* taken is planted here rather than named off the host —
    /// `/usr/bin/zsh` is not on every builder, and against a choice that now probes for
    /// executability an absent one would quietly test the fallback twice over.
    #[test]
    fn login_shell_takes_an_absolute_executable_and_falls_back_to_bin_sh() {
        let root = Scratch::new("pty-shell");
        let zsh = root.join("zsh");
        std::fs::write(&zsh, b"#!/bin/sh\n").expect("plant a shell");
        std::fs::set_permissions(&zsh, std::fs::Permissions::from_mode(0o755))
            .expect("make the planted shell executable");
        assert_eq!(
            pick_shell(Some(zsh.clone())),
            (zsh, "-zsh".to_owned()),
            "an absolute shell is run as a login shell of its own name"
        );

        // A `$SHELL` naming a file with no exec bit. Refused for a suite running as root
        // too: `X_OK` is the one access check root is not simply granted, needing some
        // execute bit to be set.
        let bare = root.join("bare");
        std::fs::write(&bare, b"#!/bin/sh\n").expect("plant a second shell");
        std::fs::set_permissions(&bare, std::fs::Permissions::from_mode(0o644))
            .expect("without an exec bit");

        let refusals = [
            PathBuf::from("bash"),
            PathBuf::new(),
            PathBuf::from("./sh"),
            PathBuf::from("bin/../sh"),
            // The three § 6.1.1's precedence used to lose the whole session over: an
            // absolute path is not a promise that `execve` will take it.
            root.join("no-such-shell"),
            bare,
            // A directory, which is the case `access(X_OK)` says *yes* to — its execute
            // bit is search permission — and which `execve` then refuses `EACCES`. The
            // one refusal here that the access check alone does not make.
            root.dir("a-directory"),
        ];
        for refused in refusals {
            assert_eq!(
                pick_shell(Some(refused.clone())),
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

    /// A `$HOME` that `stat` answers for and `chdir` would refuse falls through, rather
    /// than reaching the child's own `chdir` and costing the session altogether: the whole
    /// point of the fallback chain is a home that cannot be used, and an unenterable one
    /// is exactly that.
    #[test]
    fn child_dir_falls_through_a_home_it_could_not_enter() {
        let root = Scratch::new("pty-shut-home");
        let shut = root.dir("shut");
        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o000))
            .expect("shut the home directory");
        assert!(
            shut.is_dir(),
            "`stat` must still answer for it, or this measures nothing: it is the gap \
             between `stat` and `chdir` that is the trap"
        );

        if rustix::process::getuid().is_root() {
            // Root is granted search on every directory, so the trap cannot be laid for
            // a suite running as one — and a home it can enter is a home it should take.
            assert_eq!(pick_dir(Some(&shut), Some(Path::new("/tmp"))), shut);
            return;
        }
        assert_eq!(
            pick_dir(Some(&shut), Some(Path::new("/tmp"))),
            Path::new("/tmp"),
            "a home that cannot be entered must fall through to the connection's own \
             directory"
        );
        assert_eq!(
            pick_dir(Some(&shut), None),
            Path::new("/"),
            "and to `/` where there is nothing else, which is § 6.1.1's last step"
        );
    }

    /// The master's `O_NONBLOCK` is folded into the `openpt` rather than set afterwards,
    /// which leans on `OpenptFlags` passing an `O_*` bit it does not name straight
    /// through to Linux's `open("/dev/ptmx")`. That is not part of rustix's documented
    /// surface, so it is read back here: without it a rustix bump could leave the daemon
    /// blocking inside a write to a PTY whose reader has stopped, with nothing else in
    /// the suite failing.
    #[test]
    fn a_pty_master_is_non_blocking_as_it_is_opened() {
        let pty = shell("pty_nonblocking");
        let flags = rustix::fs::fcntl_getfl(pty.master()).expect("the master's status flags");
        assert!(
            flags.contains(OFlags::NONBLOCK),
            "the PTY master came back blocking: {flags:?}"
        );
    }

    /// Regression: a stopped job that *handles* `SIGHUP` must be woken to receive it.
    ///
    /// A `TASK_STOPPED` task is woken only by a signal whose *default* action is fatal, so
    /// a `SIGHUP` a process installed a handler for is merely queued against one the user
    /// suspended with `Ctrl-Z` — it stays in state `T`, counts as a live session member
    /// for the whole of [`HANGUP_GRACE`], and is then `SIGKILL`ed with its handler never
    /// run. The `SIGCONT` behind each `SIGHUP` is what closes that, and the marker file is
    /// how this test tells a handler that ran from a process that was killed.
    ///
    /// The job stops itself and is waited for, rather than being stopped from here: a
    /// `terminate` that arrived before the `kill -STOP` would pass on the ordinary path
    /// and prove nothing.
    #[test]
    fn terminate_wakes_a_stopped_job_so_its_hangup_handler_runs() {
        let root = Scratch::new("pty-stopped-hup");
        let marker = root.join("hung-up");
        let mut pty = shell("terminate_stopped");

        // `sh -c` rather than a subshell, so `$$` inside names the job itself and the
        // `kill` cannot reach the login shell.
        //
        // `set +m` — the job in the login shell's *own* process group — is what makes this
        // measure anything. POSIX has the kernel send `SIGHUP` *and `SIGCONT`* to a
        // process group that a process's exit leaves newly orphaned with a stopped member,
        // so a job in a group of its own is woken by the login shell dying whatever this
        // module does. The session leader's group is orphaned from birth, its parent being
        // this daemon in another session, so it never becomes *newly* orphaned and the
        // kernel never rescues it. Job control puts a `Ctrl-Z`ed job in a group of its own,
        // but only while the shell that owns it lives: a shell that handles `SIGHUP`
        // itself, or a nested one, leaves the real case looking exactly like this.
        let script = format!(
            "set +m\n/bin/sh -c 'trap \"echo hung-up > {marker}; exit 0\" HUP; \
             kill -STOP $$; sleep 30' &\necho NOMUX-JOB=$!\n",
            marker = marker.display()
        );
        rustix::io::write(pty.master(), script.as_bytes()).expect("write the script");
        let job = read_marker(&pty, "NOMUX-JOB=").expect("the shell reported its job pid");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline && !stopped(job) {
            std::thread::sleep(HANGUP_POLL_INTERVAL);
        }
        assert!(
            stopped(job),
            "the job never reached state `T`, so this test never met the case it is about"
        );

        pty.terminate();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline && !marker.exists() {
            std::thread::sleep(HANGUP_POLL_INTERVAL);
        }
        assert!(
            marker.exists(),
            "a stopped job that handles `SIGHUP` was killed rather than hung up: the \
             handler never ran"
        );
    }

    /// Whether `pid` is stopped — state `T`, the state a `SIGHUP` alone cannot leave.
    fn stopped(pid: i32) -> bool {
        let Ok(stat) = std::fs::read(format!("/proc/{pid}/stat")) else {
            return false;
        };
        stat_tail(&stat).and_then(|mut fields| fields.next()) == Some("T")
    }
}
