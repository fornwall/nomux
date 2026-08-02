//! What the daemon does to itself before it is a daemon, and how it is asked to
//! stop.
//!
//! Two subjects, one property: both are about the *process* rather than about the
//! session, both run exactly once from `daemon::run`, and neither touches any
//! daemon state. They live here rather than in `daemon.rs` because that is where
//! they were, sitting between `run` and the event loop — `setsid`, `/dev/tty` and
//! self-pipe lore that a reader who came for the § 6.4.1 ordering has to scroll
//! past, in the one file where the order things happen in is the subject.
//!
//! `IMPLEMENTATION.md` § 6.2 for the detachment and § 6.5 for the stop signals.

use std::io;
use std::os::fd::{BorrowedFd, IntoRawFd, OwnedFd};
use std::sync::atomic::{AtomicI32, Ordering};

use rustix::fs::{Mode, OFlags};
use rustix::pipe::PipeFlags;

/// Signals that mean "stop", handled so that leaving runs the shutdown path
/// (`IMPLEMENTATION.md` § 6.5) instead of the default disposition.
///
/// `SIGTERM` is what `nomux kill` sends (§ 6.6). `SIGINT` joins it because it is the
/// other signal a person sends by hand to mean stop, and a session is worth more
/// than the keystroke that ended it: taking the shutdown path collects the child's
/// process group and unlinks the run files, where the default disposition leaves
/// both behind.
///
/// It is not what protects the window before § 6.2 has finished detaching, and no
/// longer claims to be. Nothing is armed that early — the handlers go up right after
/// that detachment, which is the earliest point at which a byte written here cannot
/// be inherited by a child that never received the signal. What closes that window
/// instead is § 6.2 itself: once the daemon holds no controlling terminal, no
/// keystroke can reach it, and before that point it has no PTY, no child and no run
/// files, so dying there is indistinguishable from never having started.
///
/// `SIGQUIT` is deliberately left alone. Its default action is a core dump, which
/// is the only way left to get a snapshot out of a daemon that has wedged, and
/// `SIGKILL` already covers "go away now" for anyone who does not want one.
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
/// `errno`: rustix issues the syscall directly and reports failure through its
/// return value, so a handler landing between a failing call in the main flow and
/// that call's `errno` read leaves it untouched.
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
/// A self-pipe rather than `signalfd`, which reports only signals that are
/// *blocked* and so wants a process-wide `sigprocmask` — a mask that survives
/// `exec`, meaning `pty::Pty::spawn` would have to unblock it again in the child or
/// leave the user's shell permanently deaf to `SIGTERM`. rustix has no binding for
/// it either. Two descriptors and a one-line handler are the cheaper trade.
///
/// # Errors
///
/// Fails if the pipe cannot be created or a handler cannot be installed.
pub(crate) fn arm_stop_signals() -> io::Result<OwnedFd> {
    // `CLOEXEC` so the session's child never inherits either end; `NONBLOCK` so the
    // handler above cannot block on the write.
    let (read, write) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)?;

    // The write end is leaked on purpose. A signal can arrive at any point up to
    // process exit, including after the `Daemon` has been dropped, and a handler
    // holding a closed descriptor would write its byte into whatever was opened
    // next. One descriptor for the life of the process is the cheaper answer than
    // teaching the handler to be told.
    STOP_PIPE.store(write.into_raw_fd(), Ordering::Relaxed);

    // `sighandler_t` is an integer wide enough for a pointer, and a function item
    // has to be laundered through one to reach it.
    let handler = note_stop_signal as *const () as libc::sighandler_t;
    for (armed, signum) in STOP_SIGNALS.into_iter().enumerate() {
        // SAFETY: `signal` on a single-threaded process with an async-signal-safe
        // handler, installed before any thread or child exists. `exec` resets
        // handled dispositions, so the session's child is unaffected.
        if unsafe { libc::signal(signum, handler) } == libc::SIG_ERR {
            let err = io::Error::last_os_error();
            // Unwound rather than left half-installed. `run` answers this failure by
            // carrying on with no self-pipe, and the read end goes out of scope with
            // it — so a handler surviving here would write into a pipe nobody holds,
            // discard the `EPIPE` as "a byte is already waiting", and swallow the
            // signal. That is a daemon permanently deaf to `SIGTERM`, which is worse
            // than the default disposition this exists to improve on: the default at
            // least closes the master and hangs up the foreground group.
            for prior in STOP_SIGNALS.into_iter().take(armed) {
                // SAFETY: the same call, putting back the disposition the loop above
                // replaced.
                unsafe {
                    libc::signal(prior, libc::SIG_DFL);
                }
            }
            return Err(err);
        }
    }
    Ok(read)
}
/// Puts the daemon in a session of its own *and* without a controlling terminal,
/// which is what lets it outlive the connection that started it
/// (`IMPLEMENTATION.md` § 6.2).
///
/// Leading a session is not the property wanted, only half of it. A session leader
/// may still hold a controlling terminal, and `exec`ing the daemon *from* one lands
/// exactly there: `ssh -t host 'nomux daemon <id>'` produces it, because `bash -c`
/// with a single command `exec`s in place instead of forking. The daemon is then the
/// terminal's foreground process group for the session's whole life, so Ctrl-C kills
/// it and `Ctrl-\` dumps its core — `SIGHUP` was covered, terminal-generated signals
/// were not.
///
/// Hence both halves in the early return. Everything after it is unchanged and still
/// carries the weight: `setsid` leaves the caller a session leader with no
/// controlling terminal, which is the whole property, and it refuses with `EPERM`
/// for a process-group leader — a session leader being one by definition, so on the
/// ordinary path, where `attach::spawn_daemon` already called `setsid` between fork
/// and exec, calling it again looks exactly like a failure. Asking first is what
/// tells "already done" apart from "cannot be done", and it keeps that path
/// fork-free.
///
/// A genuine refusal means this process leads a process group somebody else made:
/// `nomux daemon <id>` typed at a shell with job control, or the `ssh -t` shape
/// above. Nothing can make a group leader a session leader, so the way out is a
/// child that is not one. The parent leaves through `_exit`, which is why this
/// happens before the pidfile is written — `nomux kill` must read the pid of the
/// process that survived rather than of the one that started.
///
/// `SIGHUP` is ignored first, before anything here can provoke one, and that is
/// load-bearing rather than tidy: when the parent leaves through `_exit` it is the
/// *session leader* of the terminal it was `exec`ed from, so the kernel hangs that
/// terminal up and delivers `SIGHUP` to its foreground process group — which the
/// forked child is still in for the few instructions before its own `setsid`. With
/// the disposition inherited as ignored the race cannot be lost; without it the
/// daemon dies during the very manoeuvre that was meant to save it, which is exactly
/// what it did the first time this was written.
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
/// without having to know which descriptor — if any — reaches it. That matters here:
/// the daemon's own stdio may already be a pipe, a socket or `/dev/null` and still
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
/// directory and the standard descriptors.
///
/// `IMPLEMENTATION.md` § 6.2. `SIGHUP` is not among them — it is ignored earlier,
/// in `leave_login_session`, because the detachment itself can provoke one.
/// `SIGPIPE` needs nothing: the Rust runtime ignores it at startup and restores it
/// for the child.
///
/// Failures are not propagated. A daemon that cannot `chdir` still works; refusing
/// to start over it would be a worse outcome than the mount it might pin.
pub(crate) fn release_startup_state() {
    let _ = rustix::process::chdir("/");
    let _ = silence_stdio();
}

/// Points the three standard descriptors at `/dev/null`.
///
/// Whatever started the daemon is still on the other end of them, and under
/// `attach` that is the SSH channel: holding it keeps a connection open that has
/// nothing left to carry, and a byte written to it — a failure to start, a
/// backtrace — arrives in the middle of the client's frame stream.
///
/// Late in the startup sequence on purpose: everything that can fail with a
/// message worth reading has already had its chance to write one.
///
/// The `Result` is here to chain the four calls, not to be handled: the only caller
/// discards it, because a daemon that could not reach `/dev/null` is a daemon that
/// writes where it should not, which is worse than a session but better than none.
fn silence_stdio() -> io::Result<()> {
    let null = rustix::fs::open("/dev/null", OFlags::RDWR, Mode::empty())?;
    rustix::stdio::dup2_stdin(&null)?;
    rustix::stdio::dup2_stdout(&null)?;
    rustix::stdio::dup2_stderr(&null)?;
    Ok(())
}
