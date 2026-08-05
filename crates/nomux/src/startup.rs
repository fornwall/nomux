//! What the daemon does to itself before it is a daemon, and how it is asked to
//! stop.
//!
//! Two subjects, one property: both are about the *process* rather than about the
//! session, both run exactly once from `daemon::run`, and neither touches any
//! daemon state.
//!
//! `IMPLEMENTATION.md` § 6.2 for the detachment and § 6.5 for the stop signals.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, IntoRawFd, OwnedFd};
use std::sync::atomic::{AtomicI32, Ordering};

use rustix::fs::{Mode, OFlags};
use rustix::pipe::PipeFlags;

/// Signals that mean "stop", handled so that leaving runs the shutdown path
/// (`IMPLEMENTATION.md` § 6.5) instead of the default disposition; `SIGQUIT` is
/// deliberately left alone there, for the core dump it produces.
///
/// Armed right after § 6.2's detachment, which is the earliest point at which the
/// byte a handler writes cannot be inherited by a child that never received the
/// signal. Nothing is needed before it: the daemon holds no controlling terminal
/// for a keystroke to arrive through, and has no PTY, no child and no run files, so
/// dying there is indistinguishable from never having started.
const STOP_SIGNALS: [libc::c_int; 2] = [libc::SIGTERM, libc::SIGINT];

/// Write end of the self-pipe, as a raw descriptor because a signal handler may
/// neither allocate nor take a lock. `-1` until [`arm_stop_signals`] publishes it.
static STOP_PIPE: AtomicI32 = AtomicI32::new(-1);

/// The entirety of what happens in a signal handler: one byte down the self-pipe.
///
/// Async-signal-safety is the constraint that shapes this. `write(2)` is on the
/// permitted list, the descriptor is non-blocking so a pipe somebody has filled
/// cannot park the daemon inside a handler, and a refused write means a byte is
/// already waiting — which is the whole of the message. Nor can this perturb
/// `errno`: rustix issues the syscall directly on the `linux_raw` backend, which
/// every shipped target selects, and reports failure through its return value, so a
/// handler landing between a failing call in the main flow and that call's `errno`
/// read leaves it untouched.
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
/// its read end.
///
/// A self-pipe rather than `signalfd` for the reason `IMPLEMENTATION.md` § 6.5
/// gives; rustix has no binding for it either.
///
/// # Errors
///
/// Fails only if the pipe cannot be created. Installing the handlers cannot report
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
/// Both halves, not just the session: covering `SIGHUP` alone leaves every other
/// terminal-generated signal able to reach a daemon still in the foreground process
/// group, so Ctrl-C kills it and `Ctrl-\` dumps its core.
///
/// `TIOCNOTTY` would drop the terminal without a fork and is deliberately not used.
/// Issued by a session leader it sends `SIGHUP` and `SIGCONT` to the foreground
/// process group — which in the case being fixed *is* this process — and it strips
/// the controlling terminal from every other process in the session too, which is
/// not this program's to take.
///
/// Failures are not propagated. Sharing a session makes for a worse daemon, not a
/// broken one, and refusing to start would be the worse outcome of the two.
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
/// `/dev/tty` *is* that terminal, by definition, so opening it answers the question
/// whatever the daemon's own stdio has become — a pipe, a socket or `/dev/null` all
/// leave the terminal attached, so no amount of asking about fd 0 would do.
/// `O_NOCTTY` keeps § 6.2's rule that this binary never acquires one by opening it.
///
/// `ENXIO` is the kernel saying there is none, and is the only definite no. Anything
/// else — no `/dev/tty` node in a stripped container, a mode that refuses the open —
/// leaves the question unanswered, and unanswered is taken as yes. Being wrong that
/// way costs one `fork` on a host where the probe cannot work; being wrong the other
/// way costs a session that a keystroke can end.
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
/// Failures are not propagated. A daemon that cannot `chdir` still works; refusing
/// to start over it would be a worse outcome than the mount it might pin.
pub(crate) fn release_startup_state() {
    let _ = rustix::process::chdir("/");
    let _ = silence_stdio();
}

/// Points the three standard descriptors at `/dev/null`, last in the startup
/// sequence so that everything which can fail with a message worth reading has
/// already had its chance to write one (`IMPLEMENTATION.md` § 6.2).
///
/// The `Result` is here to chain the four calls, not to be handled: the only caller
/// discards it, because a daemon that could not reach `/dev/null` is a daemon that
/// writes where it should not, which is worse than a session but better than none.
fn silence_stdio() -> io::Result<()> {
    let null = rustix::fs::open("/dev/null", OFlags::RDWR, Mode::empty())?;
    rustix::stdio::dup2_stdin(&null)?;
    rustix::stdio::dup2_stdout(&null)?;
    rustix::stdio::dup2_stderr(&null)?;
    if null.as_raw_fd() <= libc::STDERR_FILENO {
        // Leaked on purpose, and only where `open` handed back one of the three it
        // was about to fill: it hands back the lowest free descriptor, and the
        // `dup2`s above have just left it as its own copy. Dropping it would close
        // it again and free that number for the next `openpt` or `accept` to claim,
        // after which everything written to what was believed to be `/dev/null`
        // lands in a PTY master or in the middle of a client's frame stream.
        //
        // Belt and braces rather than a live bug: std reopens a standard descriptor
        // it finds closed before `main` runs, so `nomux daemon <id> 1>&-` reaches
        // here with all three taken.
        let _ = null.into_raw_fd();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::fd::FromRawFd;

    use super::*;

    /// Regression: every standard descriptor is left *open* on `/dev/null`,
    /// including the one whose number `open` handed back.
    ///
    /// Freed by hand because nothing else can, which is the same reason this is a unit
    /// test: std reopens a standard descriptor it finds closed at startup, so no
    /// command line reaches [`silence_stdio`] with one free.
    ///
    /// In a child, because fds 0..=2 belong to the process rather than to this test and
    /// `cargo test` runs the other tests as threads in it. Freeing fd 0 hands its number
    /// to whichever of them allocates next — measured: `conn`'s socketpair came back as
    /// fd 0, was `dup2`ed onto `/dev/null` here, and failed with `ENOTSOCK` in a test
    /// that has nothing to do with startup — and pointing the *process's* stdout at
    /// `/dev/null` for that window swallowed whatever the harness was printing, so a run
    /// could fail with no failure list at all. A child's descriptor table is its own, so
    /// the whole of it is contained and the verdict comes back as an exit status.
    #[test]
    fn silencing_stdio_leaves_a_freed_descriptor_open_on_dev_null() {
        // Resolved before the fork, so the child does nothing but syscalls on
        // descriptors: what "is `/dev/null`" means to an `fstat`.
        let null = rustix::fs::stat("/dev/null")
            .expect("stat /dev/null")
            .st_rdev;

        // SAFETY: the child reaches only `close`, `open`, `dup2`, `fstat` and `_exit`,
        // every one of them async-signal-safe, so it never needs a lock that one of the
        // other threads of this process could have been holding at the fork.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork: {}", io::Error::last_os_error());
        if child == 0 {
            // SAFETY: fd 0 is this child's alone, and std's `Stdin` only borrows it.
            drop(unsafe { OwnedFd::from_raw_fd(libc::STDIN_FILENO) });
            // SAFETY: borrowed only for the `fstat` below, after `silence_stdio` has
            // filled the number; nothing here closes it.
            let stdin = unsafe { BorrowedFd::borrow_raw(libc::STDIN_FILENO) };
            let verdict = match silence_stdio().map(|()| rustix::fs::fstat(stdin)) {
                Ok(Ok(stat)) if stat.st_rdev == null => 0,
                // The descriptor `open` handed back was closed again, leaving fd 0 for
                // the next socket or PTY master to claim.
                Ok(Err(_)) => 1,
                Ok(Ok(_)) => 2,
                Err(_) => 3,
            };
            // SAFETY: the only correct exit for a forked child, which shares the
            // parent's atexit handlers and its buffered, half-written output.
            unsafe { libc::_exit(verdict) }
        }

        let mut status = 0;
        // SAFETY: `waitpid` writes only through `&mut status`, for the pid just forked.
        let waited = unsafe { libc::waitpid(child, &raw mut status, 0) };
        assert_eq!(waited, child, "waitpid: {}", io::Error::last_os_error());
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "fd 0 is open on /dev/null once stdio is silenced; the child said {status:#x} \
             (1: closed again, 2: some other file, 3: silence_stdio failed)"
        );
    }
}
