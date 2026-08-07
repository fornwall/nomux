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
/// it refuses is the message already waiting rather than a message lost. `errno` is
/// not perturbed either: rustix issues the syscall directly on the `linux_raw` backend
/// every shipped target selects.
///
/// Taken as an argument rather than written out twice, so the safety argument below is
/// made once and both handlers are plainly the same three lines.
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

    // Strictly after the loop above: `exec` preserves pending signals as well as the
    // mask, so a parent holding `SIGTERM` blocked *and pending* delivers it the
    // instant this returns. Unblocking first would deliver it at `SIG_DFL` — the
    // daemon dying with `<id>.sock` bound, `<id>.pid` unwritten and § 6.5's shutdown
    // unrun, which is the failure this whole function exists to prevent.
    //
    // A disposition is nothing without delivery, and the mask is the half that survives
    // `exec`: a daemon started from a parent holding `SIGTERM` blocked — § 6.2's
    // `nomux daemon x 0<&- 1>&- 2>&-` typed into such a shell, a systemd unit, a test
    // harness — would install the handlers above and never hear from them. `nomux kill`
    // would then wait out its two-second grace and `SIGKILL`, so the shell would run no
    // exit trap and § 6.5's shutdown would not run at all.
    //
    // Cleared whole rather than unblocking [`STOP_SIGNALS`] alone, because the mask is
    // inherited twice over: `std` documents that it does *not* reset one across
    // `Command::spawn`, so whatever is blocked here is blocked in the session's login
    // shell for its whole life. Leaving a parent's blocked `SIGTSTP` in place would cost
    // the child `Ctrl-Z` exactly as an inherited `SIG_IGN` would (`pty.rs`), and that is
    // the larger of the two harms.
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

    Ok(read)
}

/// Routes `SIGCHLD` into a descriptor of its own for the poll set, and hands back its
/// read end. What the daemon then does with it is `daemon.rs`'s `collect_status`.
///
/// **A second pipe rather than a second byte down [`arm_stop_signals`]'s.** Telling the
/// two apart would have worked — one byte is one byte, and a pipe write of one is
/// atomic, so no handler could ever tear another's message. What sharing costs is the
/// stop pipe's licence never to be *read*: its byte is the last thing the loop will ever
/// want from that descriptor, where this one arrives afresh for every child that exits,
/// stops or continues, and a byte left in a pipe is a descriptor that stays readable and
/// a `poll` that returns at once on every pass for the rest of the session. So a shared
/// pipe would have to be drained every pass, and that drain would be handing the
/// shutdown decision bytes to classify — on the one path with no second chance, where a
/// stop misread as a child costs `nomux kill` its whole grace and the user's shell its
/// exit trap. Two descriptors and one more poll slot buy a `SIGCHLD` that cannot be read
/// as a stop by construction rather than by convention.
///
/// **Handled, never ignored, and that is what keeps the child clean.** `exec` resets a
/// handled disposition and preserves `SIG_IGN`, so `SIG_IGN` here — which on Linux also
/// means the kernel reaps children itself — would follow the login shell through `exec`
/// and leave every `wait` it ever makes failing `ECHILD`, job control included
/// (`IMPLEMENTATION.md` § 6.1, and `pty.rs` for the five that do need putting back). A
/// handler needs no reset in `pre_exec` for the same reason, and the window between the
/// `fork` and the `exec` is not one either: the copy has no children of its own to be
/// told about.
///
/// Called *before* [`arm_stop_signals`], which is the call that clears an inherited
/// signal mask — and which installs its own handlers ahead of doing so for the reason it
/// gives. The reason holds here as well as there: a blocked `SIGCHLD` is a handler that
/// never runs, and one blocked *and pending* is delivered the instant that mask clears,
/// so arming afterwards would miss it. What it costs is the milder half, `SIGCHLD`'s
/// default being to ignore — not a daemon that dies but a notification silently dropped,
/// and a dropped one is a reap nobody makes now that `collect_status` has stopped asking
/// on every pass.
///
/// # Errors
///
/// Fails only if the pipe cannot be created.
pub(crate) fn arm_child_signal() -> io::Result<OwnedFd> {
    // `CLOEXEC` and the leaked write end are [`arm_stop_signals`]'s, for its reasons.
    let (read, write) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)?;
    CHILD_PIPE.store(write.into_raw_fd(), Ordering::Relaxed);

    // `SA_NOCLDSTOP` would keep a `Ctrl-Z`'d shell from delivering one of these, and is
    // not worth `sigaction` and a second spelling of this install: what it saves is a
    // wakeup that reads one byte and asks `waitpid` a question it answers `None` to.
    //
    // SAFETY: `signal` on a single-threaded process with an async-signal-safe handler,
    // installed before the session's child exists. The result is not checked for
    // [`arm_stop_signals`]'s reason — `SIGCHLD` is neither invalid nor uncatchable.
    unsafe {
        libc::signal(
            libc::SIGCHLD,
            note_child_signal as *const () as libc::sighandler_t,
        );
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
