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
    // Cleared whole rather than [`STOP_SIGNALS`] alone: `std` does not reset the mask across
    // `Command::spawn`, so whatever is blocked here is blocked in the session's login shell
    // for its whole life — a parent's `SIGTSTP` costs the child `Ctrl-Z` (`pty.rs`).
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
/// acquires one.
///
/// `ENXIO` is the only definite no — § 6.2 delegates the argument here. Anything else, such
/// as no `/dev/tty` node in a stripped container, is taken as yes: being wrong that way costs
/// one `fork`, and being wrong the other way costs a session a keystroke can end.
fn has_controlling_terminal() -> bool {
    match rustix::fs::open(
        "/dev/tty",
        OFlags::RDONLY | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(_) => true,
        Err(err) => err != rustix::io::Errno::NXIO,
    }
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

/// Points the three standard descriptors at `null`, last of all (§ 6.2).
///
/// Silent, and trivially so — [`open_null_device`] already proved the descriptor, and `dup2`
/// onto a valid one fails for nothing this process can cause.
///
/// What makes this safe is not the ordering, which cannot help: by here the socket is bound
/// and the stop pipe armed, and nothing below can tell an inherited terminal from a
/// descriptor of its own. It is that these three numbers were never free — std's runtime
/// opens `/dev/null` onto any of them `main` inherited closed, and aborts rather than start
/// without them, so the lowest number a `bind` here can be given is 3. Without that, § 6.2's
/// `nomux daemon x 0<&- 1>&- 2>&-` would land the listener on fd 1 for the `dup2`s below to
/// silence — an id claimed by a daemon nothing can ever reach. `tests/session.rs` starts one
/// that way and greets it.
pub(crate) fn silence_standard_descriptors(null: &OwnedFd) {
    let _ = rustix::stdio::dup2_stdin(null);
    let _ = rustix::stdio::dup2_stdout(null);
    let _ = rustix::stdio::dup2_stderr(null);
}
