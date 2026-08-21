//! What the daemon does to itself before it is a daemon, and how it is asked to stop.
//!
//! `IMPLEMENTATION.md` § 6.2 for the detachment, § 6.5 for the stop signals.

use std::io;
use std::os::fd::{BorrowedFd, IntoRawFd, OwnedFd};
use std::sync::atomic::{AtomicI32, Ordering};

use rustix::fs::{Mode, OFlags};
use rustix::pipe::PipeFlags;

/// Signals that mean "stop", handled so that leaving runs `IMPLEMENTATION.md`
/// § 6.5's shutdown path instead of the default disposition. Armed where § 6.2 says.
const STOP_SIGNALS: [libc::c_int; 2] = [libc::SIGTERM, libc::SIGINT];

/// Write end of the self-pipe, as a raw descriptor because a signal handler may
/// neither allocate nor take a lock. `-1` until [`arm_stop_signals`] publishes it.
static STOP_PIPE: AtomicI32 = AtomicI32::new(-1);

/// The same for `SIGCHLD`, and deliberately not the same pipe. [`arm_child_signal`]
/// publishes it and has the argument.
static CHILD_PIPE: AtomicI32 = AtomicI32::new(-1);

/// The entirety of what happens in a signal handler: one byte down the self-pipe.
///
/// Non-blocking, so a full pipe cannot park the daemon inside a handler — and a write
/// it refuses is the message already waiting rather than a message lost. `errno` is not
/// perturbed either: rustix issues the syscall directly on the `linux_raw` backend every
/// shipped target selects.
fn note_signal(pipe: &AtomicI32) {
    let raw = pipe.load(Ordering::Relaxed);
    if raw >= 0 {
        // SAFETY: a write end is published once, before any handler can run, and then
        // deliberately never closed, so this descriptor number is valid for the rest of
        // the process's life and cannot have been reused.
        let fd = unsafe { BorrowedFd::borrow_raw(raw) };
        let _ = rustix::io::write(fd, b"\0");
    }
}

extern "C" fn note_stop_signal(_signum: libc::c_int) {
    note_signal(&STOP_PIPE);
}

extern "C" fn note_child_signal(_signum: libc::c_int) {
    note_signal(&CHILD_PIPE);
}

/// Closes every descriptor the daemon inherited except standard I/O and `keep`.
///
/// A daemon outlives the process that launched it, and its login shell is less trusted than
/// that launcher. Letting an arbitrary non-`CLOEXEC` descriptor cross either boundary can keep
/// a mount busy for a week, or hand the shell a file, socket or capability it was never meant to
/// have. This runs before the daemon opens anything of its own; `keep` is the spawn lock that is
/// deliberately handed across `exec` and validated immediately afterwards.
///
/// `close_range(2)` is the small, constant-time path on Linux 5.9 and later. Sessions still work
/// on older kernels, so `/proc/self/fd` is the fallback; procfs is already a project requirement
/// for process identity and shutdown.
pub(crate) fn close_inherited_descriptors(keep: Option<i32>) -> io::Result<()> {
    let keep = keep.and_then(|fd| u32::try_from(fd).ok());
    let closed = keep.map_or_else(
        || close_range(libc::STDERR_FILENO as u32 + 1, u32::MAX),
        |fd| {
            close_range(libc::STDERR_FILENO as u32 + 1, fd.saturating_sub(1))
                && close_range(fd.saturating_add(1), u32::MAX)
        },
    );
    if closed {
        return Ok(());
    }

    // Collect first: the directory iterator owns a descriptor that appears in its own
    // listing. Dropping it before the closes makes that entry an ordinary `EBADF`, and avoids
    // ending the scan part-way through by closing the descriptor it is reading from.
    let mut inherited = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        if fd > libc::STDERR_FILENO && keep != u32::try_from(fd).ok() {
            inherited.push(fd);
        }
    }
    for fd in inherited {
        // SAFETY: `fd` came from this process's descriptor directory. It may already be
        // closed (notably the directory iterator's own descriptor), which is harmless.
        unsafe {
            libc::close(fd);
        }
    }
    Ok(())
}

/// Closes one inclusive descriptor range, returning whether the kernel accepted it.
fn close_range(first: u32, last: u32) -> bool {
    if first > last {
        return true;
    }
    // SAFETY: `close_range` takes three integer values and touches no userspace memory.
    unsafe { libc::syscall(libc::SYS_close_range, first, last, 0) == 0 }
}

/// Routes [`STOP_SIGNALS`] into a descriptor the poll set can watch, and hands back
/// its read end.
///
/// A self-pipe rather than `signalfd`, which reports only *blocked* signals: reading one
/// would mean a process-wide `sigprocmask` that then has to survive the `exec` into the
/// session's child. rustix has no binding for it either.
pub(crate) fn arm_stop_signals() -> io::Result<OwnedFd> {
    // `CLOEXEC` so the session's child never inherits either end.
    let (read, write) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)?;
    // Leaked on purpose: a signal can arrive at any point up to process exit,
    // including after the `Daemon` has been dropped, and a handler holding a closed
    // descriptor would write its byte into whatever was opened next.
    STOP_PIPE.store(write.into_raw_fd(), Ordering::Relaxed);

    // `sighandler_t` is a pointer-wide integer, which a function item only reaches
    // by being laundered through one.
    let handler = note_stop_signal as *const () as libc::sighandler_t;
    for signum in STOP_SIGNALS {
        // SAFETY: `signal` on a single-threaded process with an async-signal-safe
        // handler, installed before any thread or child exists. `exec` resets
        // handled dispositions, so the session's child is unaffected. Unchecked
        // because `signal(2)` fails only on an invalid signum or on
        // `SIGKILL`/`SIGSTOP`, and [`STOP_SIGNALS`] is a constant that is neither.
        unsafe { libc::signal(signum, handler) };
    }

    // A disposition is nothing without delivery, and the mask is the half that survives
    // `exec`: with `SIGTERM` inherited blocked, the handlers above are never heard from and
    // `nomux kill` reaches `SIGKILL` with § 6.5's shutdown unrun. After the loop for § 6.2's
    // ordering rule. A pipe failure returns before this point, leaving a pending stop
    // signal blocked until startup has cleaned up what it published.
    //
    // Cleared whole rather than [`STOP_SIGNALS`] alone. The set this daemon inherited is
    // whatever the thing that started it happened to be holding — a relay's, an sshd's, a
    // shell that blocked something around the command — and none of it was chosen with a
    // process that idles for a week (§ 6.5) in mind. A blocked `SIGHUP` or `SIGQUIT` left
    // in place is one more signal that reaches the daemon as a pending bit nobody ever
    // reads, so the mask is emptied rather than trimmed to the signals this module knows
    // it wants.
    //
    // This is *this* process's mask and no child's. `crate::exec`'s child half issues the
    // same `sigemptyset`/`sigprocmask` pair of its own between its `fork` and its `execve`,
    // which is the complementary clear rather than a substitute for this one: that one
    // decides what the session's login shell starts life under, this one what the daemon
    // itself runs under from here to its shutdown — and every signal armed above is
    // delivered here.
    //
    // SAFETY: `sigemptyset` initialises the set this frame owns, which `sigprocmask` is then
    // handed along with a null pointer for the old mask it is not being asked for.
    // Single-threaded, so no other thread has a mask to disagree about.
    unsafe {
        let mut empty = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        libc::sigemptyset(empty.as_mut_ptr());
        libc::sigprocmask(libc::SIG_SETMASK, empty.as_ptr(), std::ptr::null_mut());
    }

    Ok(read)
}

/// Routes `SIGCHLD` into a descriptor of its own for the poll set, and hands back its
/// read end. What the daemon then does with it is `daemon.rs`'s `collect_outcome`.
///
/// A second pipe rather than a second byte down [`arm_stop_signals`]'s (§ 6.5), and handled
/// rather than ignored for the child's sake (§ 6.2, with `pty.rs` for the five dispositions
/// that do need putting back).
///
/// Called *before* [`arm_stop_signals`], which is the call that clears an inherited mask, so
/// § 6.2's rule about arming ahead of that clear is what fixes the order. `SIGCHLD` goes
/// first because it is the milder half to lose: its default is to ignore, so a gap here
/// drops a notification rather than the daemon.
pub(crate) fn arm_child_signal() -> io::Result<OwnedFd> {
    // `CLOEXEC` and the leaked write end are [`arm_stop_signals`]'s, for its reasons.
    let (read, write) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)?;
    CHILD_PIPE.store(write.into_raw_fd(), Ordering::Relaxed);

    // `SA_NOCLDSTOP` would keep a `Ctrl-Z`'d shell from delivering one of these, and is not
    // worth `sigaction` and a second spelling of this install: what it saves is a wakeup that
    // reads one byte and asks `waitpid` a question it answers `None` to.
    //
    // SAFETY: `signal` on a single-threaded process with an async-signal-safe handler,
    // installed before the session's child exists, and unchecked for [`arm_stop_signals`]'s
    // reason — `SIGCHLD` is neither invalid nor uncatchable.
    unsafe {
        libc::signal(
            libc::SIGCHLD,
            note_child_signal as *const () as libc::sighandler_t,
        );
    }
    Ok(read)
}

/// Puts the daemon in a POSIX session of its own *and* without a controlling terminal
/// (§ 6.2 for the order, the two shapes that need the fork, and the `SIGHUP` ignored ahead
/// of all of it).
///
/// This prevents a terminal or SSH-channel hangup from reaching the daemon, and is no
/// systemd claim: § 6.2 has what a `session-*.scope` still does at logout.
///
/// `TIOCNOTTY` would drop the terminal without a fork and is deliberately not used — § 6.2
/// delegates the argument here. Issued by a session leader it sends `SIGHUP` and `SIGCONT`
/// to the foreground process group, which in the case being fixed *is* this process, and it
/// strips the controlling terminal from every other process in the session too, which is not
/// this program's to take.
pub(crate) fn detach_from_controlling_terminal() -> io::Result<()> {
    // SAFETY: `signal` with SIG_IGN on a single-threaded process with no handler installed;
    // reset in the child before `exec` (`pty::Pty::spawn`), so it still dies on hangup.
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }

    let leads_session =
        rustix::process::getsid(None).is_ok_and(|sid| sid == rustix::process::getpid());
    if leads_session && !has_controlling_terminal() {
        return Ok(());
    }
    if rustix::process::setsid().is_ok() {
        return Ok(());
    }

    // SAFETY: this process is still single-threaded — no thread started and no child
    // spawned — so the copy holds no lock and no half-initialised runtime state.
    let forked = unsafe { libc::fork() };
    if forked < 0 {
        return Err(io::Error::last_os_error());
    }
    if forked > 0 {
        // SAFETY: the only correct exit for a forked parent. `exit` would run the atexit
        // handlers and flush the buffered stdio a second time, emitting whatever the child
        // has inherited and not yet written itself.
        unsafe { libc::_exit(0) }
    }
    rustix::process::setsid().map(|_| ()).map_err(Into::into)
}

/// Whether this process has a controlling terminal. `O_NOCTTY` so that asking never
/// acquires one — § 6.2 delegates the argument to [`terminal_behind`], which weighs the
/// errno a refused open came back with.
fn has_controlling_terminal() -> bool {
    match rustix::fs::open(
        "/dev/tty",
        OFlags::RDONLY | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(_) => true,
        Err(err) => terminal_behind(err),
    }
}

/// Whether a `/dev/tty` open that failed with `err` leaves a controlling terminal this
/// daemon might still be holding.
///
/// Three errnos settle it as a definite *no* and everything else stays conservative:
///
/// - `ENXIO` is the kernel's own answer for a process that has no controlling terminal,
///   which is what `/dev/tty` is a handle on.
/// - `ENOENT` is no such node, and `ENODEV` a `/dev` that carries no driver behind it: a
///   stripped container image or a hand-built chroot. `/dev/tty` is the *only* name for
///   the controlling terminal as such, so where it does not resolve there is nothing this
///   process could be holding by it and nothing a `setsid` here could hand back.
/// - Everything else — `EACCES` and `EPERM` from a restrictive device cgroup, `EMFILE`,
///   `EIO` — describes the asking rather than the answer, and stays *yes*.
///
/// The two missing-node errnos used to answer *yes* on the same "one wasted `fork`"
/// reasoning as the rest, and that reasoning was wrong about the cost. On the `spawn` path
/// the daemon has already been through `setsid` — `attach::spawn_daemon` issues one in the
/// `setup` closure `crate::exec::spawn` runs between its `fork` and its `execve` — so it
/// leads its session: the early return above is the only exit that avoids a `fork`, the
/// `setsid` below it fails `EPERM` for a process that already leads a *group*, and the
/// `fork` therefore happens on every single `spawn`. Its parent `_exit(0)`s, leaving a
/// process somebody has to collect: `attach::create` calls `crate::exec::reap_if_exited`
/// once publication is confirmed, which is a second guard and not a reason to fork anyway —
/// before it existed each session left one `<defunct>` process parented to a relay that
/// lives as long as the SSH session it serves, hours to days, accumulating towards
/// `RLIMIT_NPROC`. The grandchild daemon publishes its pidfile as usual, so `list` and
/// `kill` see nothing wrong either way.
///
/// Being wrong in the other direction still costs a session a keystroke can end, and the
/// host it would take is one that has a controlling terminal and no `/dev/tty` node naming
/// it — a `/dev` assembled by hand around a pty, where the `SIGHUP` ignored above is the
/// remaining guard.
const fn terminal_behind(err: rustix::io::Errno) -> bool {
    !matches!(
        err,
        rustix::io::Errno::NXIO | rustix::io::Errno::NOENT | rustix::io::Errno::NODEV
    )
}

/// Lets go of the directory the daemon inherited (§ 6.2), which would otherwise keep a
/// removable or network mount busy for [`crate::daemon`]'s whole idle life, a week (§ 6.5).
///
/// Called before the socket and pidfile publish, while a failure can still reach the caller.
///
/// The child does not follow. `pty::child_dir` captured where it starts before this ran.
///
/// # Errors
///
/// Propagates the `chdir`. `/` is searchable on any host that got this far — the run
/// directory, `/proc` and `/dev/log` were all resolved through it — so a refusal here
/// describes a host that is broken in ways a session would not survive either.
pub(crate) fn leave_startup_directory() -> io::Result<()> {
    rustix::process::chdir("/").map_err(Into::into)
}

/// Opens the `/dev/null` that [`silence_standard_descriptors`] will point stdio at.
///
/// Split from the redirection it feeds so the fallible open happens before publication (§ 6.2).
///
/// # Errors
///
/// Propagates the `open`, which is an unpopulated `/dev` or a descriptor limit reached at
/// exactly this moment.
pub(crate) fn open_null_device() -> io::Result<OwnedFd> {
    rustix::fs::open("/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty()).map_err(Into::into)
}

/// Points the three standard descriptors at `null`, retrying interrupted `dup2`s (§ 6.2).
///
/// These numbers were never free: std opens `/dev/null` onto any descriptor `main`
/// inherited closed, so no listener or pipe can be silenced accidentally. Stderr goes
/// last so any failure can still reach the launcher.
///
/// # Errors
///
/// Propagates a non-`EINTR` `dup2` failure.
pub(crate) fn silence_standard_descriptors(null: &OwnedFd) -> io::Result<()> {
    retry_intr(|| rustix::stdio::dup2_stdin(null))?;
    retry_intr(|| rustix::stdio::dup2_stdout(null))?;
    retry_intr(|| rustix::stdio::dup2_stderr(null))
}

fn retry_intr(mut op: impl FnMut() -> rustix::io::Result<()>) -> io::Result<()> {
    loop {
        match op() {
            Err(rustix::io::Errno::INTR) => {}
            result => return result.map_err(Into::into),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_operations_are_retried_but_other_errors_escape() {
        let mut calls = 0;
        retry_intr(|| {
            calls += 1;
            (calls > 1).then_some(()).ok_or(rustix::io::Errno::INTR)
        })
        .expect("retry an interruption");
        assert_eq!(calls, 2);
        assert_eq!(
            retry_intr(|| Err(rustix::io::Errno::BADF))
                .expect_err("propagate a permanent error")
                .raw_os_error(),
            Some(libc::EBADF)
        );
    }

    /// Regression: a `/dev/tty` that is not there at all is not a controlling terminal.
    ///
    /// Put to [`terminal_behind`](super::terminal_behind) rather than to
    /// [`has_controlling_terminal`](super::has_controlling_terminal), which answers about
    /// *this* process on *this* host: the suite runs where `/dev/tty` exists, and no test
    /// may unmount it out from under the machine it is running on.
    ///
    /// Read as "yes" — which is what a missing node used to be — every `spawn` on such a
    /// host forks and leaves the `_exit(0)`ed intermediate unreaped by
    /// `attach::create`, one zombie per session for the relay's whole life.
    #[test]
    fn only_an_errno_that_settles_the_question_denies_a_controlling_terminal() {
        for (err, describing) in [
            (
                rustix::io::Errno::NXIO,
                "this process has no controlling terminal",
            ),
            (
                rustix::io::Errno::NOENT,
                "there is no `/dev/tty` node to hold one by",
            ),
            (
                rustix::io::Errno::NODEV,
                "`/dev` carries no driver behind that name",
            ),
        ] {
            assert!(
                !terminal_behind(err),
                "{err} says {describing}, so there is nothing here to detach from and \
                 nothing to fork for"
            );
        }
        for (err, describing) in [
            (rustix::io::Errno::ACCESS, "a device cgroup"),
            (rustix::io::Errno::PERM, "a device cgroup"),
            (rustix::io::Errno::MFILE, "a descriptor limit"),
            (rustix::io::Errno::IO, "a driver that failed the open"),
        ] {
            assert!(
                terminal_behind(err),
                "{err} is {describing} refusing the *asking*, which establishes nothing \
                 about the terminal — and being wrong that way costs one `fork`, where \
                 being wrong the other way costs a session a keystroke can end"
            );
        }
    }
}
