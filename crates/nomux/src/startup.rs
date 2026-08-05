//! What the daemon does to itself before it is a daemon, and how it is asked to stop.
//!
//! `IMPLEMENTATION.md` § 6.2 for the detachment, § 6.5 for the stop signals.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, IntoRawFd, OwnedFd};
use std::sync::atomic::{AtomicI32, Ordering};

use rustix::fs::{Mode, OFlags};
use rustix::pipe::PipeFlags;

/// Signals that mean "stop", handled so that leaving runs `IMPLEMENTATION.md`
/// § 6.5's shutdown path instead of the default disposition. Armed where § 6.2 says.
const STOP_SIGNALS: [libc::c_int; 2] = [libc::SIGTERM, libc::SIGINT];

/// Write end of the self-pipe, as a raw descriptor because a signal handler may
/// neither allocate nor take a lock. `-1` until [`arm_stop_signals`] publishes it.
static STOP_PIPE: AtomicI32 = AtomicI32::new(-1);

/// The entirety of what happens in a signal handler: one byte down the self-pipe.
///
/// Async-signal-safety is the constraint that shapes this. `write(2)` is on the
/// permitted list, the descriptor is non-blocking so a filled pipe cannot park the
/// daemon inside a handler, and a refused write means a byte is already waiting —
/// the whole of the message. Nor can this perturb `errno`: rustix issues the syscall
/// directly on the `linux_raw` backend every shipped target selects.
extern "C" fn note_stop_signal(_signum: libc::c_int) {
    let raw = STOP_PIPE.load(Ordering::Relaxed);
    if raw >= 0 {
        // SAFETY: the write end is published once, before any handler can run, and
        // then deliberately never closed, so this descriptor number is valid for
        // the rest of the process's life and cannot have been reused.
        let fd = unsafe { BorrowedFd::borrow_raw(raw) };
        let _ = rustix::io::write(fd, b"\0");
    }
}

/// Routes [`STOP_SIGNALS`] into a descriptor the poll set can watch, and hands back
/// its read end. A self-pipe rather than `signalfd` for the reason
/// `IMPLEMENTATION.md` § 6.5 gives; rustix has no binding for it either.
///
/// # Errors
///
/// Fails only if the pipe cannot be created; installing the handlers cannot report
/// anything, for the reason the `SAFETY` note below gives.
pub(crate) fn arm_stop_signals() -> io::Result<OwnedFd> {
    // `CLOEXEC` so the session's child never inherits either end; `NONBLOCK` so the
    // handler above cannot block on the write.
    let (read, write) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)?;

    // The write end is leaked on purpose: a signal can arrive at any point up to
    // process exit, including after the `Daemon` has been dropped, and a handler
    // holding a closed descriptor would write its byte into whatever was opened next.
    STOP_PIPE.store(write.into_raw_fd(), Ordering::Relaxed);

    // `sighandler_t` is an integer wide enough for a pointer, and a function item
    // has to be laundered through one to reach it.
    let handler = note_stop_signal as *const () as libc::sighandler_t;
    for signum in STOP_SIGNALS {
        // SAFETY: `signal` on a single-threaded process with an async-signal-safe
        // handler, installed before any thread or child exists. `exec` resets
        // handled dispositions, so the session's child is unaffected.
        //
        // The result is not checked because there is nothing it can report:
        // `signal(2)` fails only on an invalid signum or on `SIGKILL`/`SIGSTOP`, and
        // [`STOP_SIGNALS`] is a compile-time constant that is neither.
        unsafe { libc::signal(signum, handler) };
    }
    Ok(read)
}

/// Puts the daemon in a session of its own *and* without a controlling terminal,
/// which is what lets it outlive the connection that started it
/// (`IMPLEMENTATION.md` § 6.2, which has the order, the two shapes that need the
/// fork, and why `SIGHUP` is ignored before any of it).
///
/// `TIOCNOTTY` would drop the terminal without a fork and is deliberately not used —
/// § 6.2 delegates the argument here. Issued by a session leader it sends `SIGHUP`
/// and `SIGCONT` to the foreground process group, which in the case being fixed *is*
/// this process, and it strips the controlling terminal from every other process in
/// the session too, which is not this program's to take.
///
/// Failures are not propagated. Sharing a session makes for a worse daemon, not a
/// broken one.
pub(crate) fn leave_login_session() {
    // SAFETY: `signal` with SIG_IGN on a single-threaded process with no handler
    // installed; the disposition is reset in the child before exec (see
    // `pty::Pty::spawn`) so the session's child still dies on hangup as it should.
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }

    let leads_session =
        rustix::process::getsid(None).is_ok_and(|sid| sid == rustix::process::getpid());
    if leads_session && !has_controlling_terminal() {
        return;
    }
    if rustix::process::setsid().is_ok() {
        return;
    }

    // SAFETY: this process is still single-threaded — no thread has been started
    // and no child spawned — so the copy the child gets holds no lock and no
    // half-initialised runtime state, and it is free to go on doing anything.
    let forked = unsafe { libc::fork() };
    if forked < 0 {
        return;
    }
    if forked > 0 {
        // SAFETY: the only correct exit for a forked parent. `exit` would run the
        // atexit handlers and flush the buffered stdio a second time, emitting
        // whatever the child has inherited and not yet written itself.
        unsafe { libc::_exit(0) }
    }
    let _ = rustix::process::setsid();
}

/// Whether this process has a controlling terminal.
///
/// Put to `/dev/tty` as § 6.2 requires, with `O_NOCTTY` so that asking never acquires
/// one.
///
/// `ENXIO` is the only definite no — § 6.2 delegates the argument here. Anything
/// else, such as no `/dev/tty` node in a stripped container, is taken as yes: being
/// wrong that way costs one `fork`, and being wrong the other way costs a session a
/// keystroke can end.
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

/// Cuts the daemon loose from the rest of the state it inherited: the working
/// directory and the standard descriptors (`IMPLEMENTATION.md` § 6.2).
///
/// Failures are not propagated: a daemon that cannot `chdir` still works, and the
/// mount it might pin is the cheaper of the two outcomes.
pub(crate) fn release_startup_state() {
    let _ = rustix::process::chdir("/");
    let _ = silence_stdio();
}

/// Points the three standard descriptors at `/dev/null`, last of all for the reason
/// § 6.2 gives. The `Result` chains the four calls rather than being handled.
fn silence_stdio() -> io::Result<()> {
    let null = rustix::fs::open("/dev/null", OFlags::RDWR, Mode::empty())?;
    rustix::stdio::dup2_stdin(&null)?;
    rustix::stdio::dup2_stdout(&null)?;
    rustix::stdio::dup2_stderr(&null)?;
    if null.as_raw_fd() <= libc::STDERR_FILENO {
        // Dropping it closes a standard descriptor, freeing it for the next `accept`.
        let _ = null.into_raw_fd();
    }
    Ok(())
}
