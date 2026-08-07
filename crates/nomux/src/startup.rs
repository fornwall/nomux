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

/// The entirety of what happens in a signal handler: one byte down the self-pipe.
///
/// Non-blocking, so a full pipe cannot park the daemon inside a handler — and a write
/// it refuses is the message already waiting rather than a message lost. `errno` is
/// not perturbed either: rustix issues the syscall directly on the `linux_raw` backend
/// every shipped target selects.
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
/// A self-pipe rather than `signalfd`, which reports only *blocked* signals: reading one
/// would mean a process-wide `sigprocmask` that then has to survive the `exec` into the
/// session's child. rustix has no binding for it either.
///
/// # Errors
///
/// Fails only if the pipe cannot be created.
pub(crate) fn arm_stop_signals() -> io::Result<OwnedFd> {
    // `CLOEXEC` so the session's child never inherits either end.
    let (read, write) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)?;

    // The write end is leaked on purpose: a signal can arrive at any point up to
    // process exit, including after the `Daemon` has been dropped, and a handler
    // holding a closed descriptor would write its byte into whatever was opened next.
    STOP_PIPE.store(write.into_raw_fd(), Ordering::Relaxed);

    // A disposition is nothing without delivery, and the mask is the half that survives
    // `exec`: a daemon started from a parent holding `SIGTERM` blocked — § 6.2's
    // `nomux daemon x 0<&- 1>&- 2>&-` typed into such a shell, a systemd unit, a test
    // harness — would install the handlers below and never hear from them. `nomux kill`
    // would then wait out its two-second grace and `SIGKILL`, so the shell would run no
    // exit trap and § 6.5's shutdown would not run at all. Nothing in this crate blocks
    // a signal, so there is nothing here to preserve.
    //
    // SAFETY: `sigemptyset` initialises the set this frame owns, and `sigprocmask` is
    // then handed that same initialised set and a null pointer for the old mask it is
    // not being asked for. Single-threaded, so no other thread has a mask to disagree
    // about.
    unsafe {
        let mut empty = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        libc::sigemptyset(empty.as_mut_ptr());
        libc::sigprocmask(libc::SIG_SETMASK, empty.as_ptr(), std::ptr::null_mut());
    }

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

/// Whether this process has a controlling terminal. `O_NOCTTY` so that asking never
/// acquires one.
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
/// directory, and then the standard descriptors, last of all for the reason
/// `IMPLEMENTATION.md` § 6.2 gives.
///
/// Failures are not propagated: a daemon that cannot `chdir` still works, and the
/// mount it might pin is the cheaper of the two outcomes; a daemon that cannot open
/// `/dev/null` keeps whatever it was handed, which is worse and still no reason to
/// refuse somebody a session.
///
/// What makes pointing the three at `/dev/null` safe is not the ordering, which cannot
/// help: by here the daemon has bound its socket and armed its stop pipe, and nothing
/// below can tell an inherited terminal from a descriptor of its own. It is that these
/// three numbers were never free — std's runtime opens `/dev/null` onto any of them that
/// `main` would have inherited closed, and aborts rather than starting without them, so
/// the lowest free number a `bind` here can be given is 3. Started as § 6.2's
/// `nomux daemon x 0<&- 1>&- 2>&-` without that, the listener would land on fd 1 and the
/// pipe's read end on fd 2, and the `dup2`s below would silence both — an id claimed by
/// a daemon nothing can ever reach. `tests/session.rs` starts one that way and greets it.
pub(crate) fn release_startup_state() {
    let _ = rustix::process::chdir("/");
    let Ok(null) = rustix::fs::open("/dev/null", OFlags::RDWR, Mode::empty()) else {
        return;
    };
    let _ = rustix::stdio::dup2_stdin(&null);
    let _ = rustix::stdio::dup2_stdout(&null);
    let _ = rustix::stdio::dup2_stderr(&null);
}
