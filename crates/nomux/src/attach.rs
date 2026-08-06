//! The relay behind `nomux spawn` and `nomux attach`.
//!
//! Deliberately dumb: it moves bytes between stdio and the session socket and never
//! parses a frame, so this side never needs a version bump (`IMPLEMENTATION.md` § 7).
//! It exists for hosts where the client cannot open a `direct-streamlocal` channel
//! straight to the socket.
//!
//! One relay, two ways in ([`Intent`]). Everything past the connection is shared.
//!
//! # The four refusals
//!
//! Both modes decide on one probe of the socket, and § 6.3 makes a `connect` that failed
//! for anything but a refusal evidence of nothing.
//!
//! | probe             | `attach`, wanting a session | `spawn`, wanting a free id |
//! |-------------------|-----------------------------|----------------------------|
//! | refused or absent | [`no_such_session`], 127    | start a daemon             |
//! | accepted          | relay to it                 | [`already_running`], 126   |
//! | neither           | [`unattachable`], 126       | [`may_be_running`], 126    |
//!
//! The last row is the wedged daemon: an `AF_UNIX` `connect` to a full backlog blocks
//! rather than being refused, so [`crate::rundir::connect_within`] gives up with `TimedOut`
//! over a socket somebody bound and stopped accepting on — evidence *of* a session, and
//! § 10's "no such session" had `DESIGN.md` § 7's client cache a live one as an id it had
//! got wrong. The two 126s keep separate kinds all the same: `AlreadyExists` answers a
//! question only the creating mode asks, so `attach` reports the `ResourceBusy` that
//! `control::hold_spawn_lock` gives the same state.

use std::collections::VecDeque;
use std::env;
use std::fs;
use std::io;
use std::net::Shutdown;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{ChildStderr, Command, Stdio};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags};
use rustix::pipe::SpliceFlags;

use crate::control::{Liveness, liveness};
use crate::rundir::{SessionPaths, check_run_dir, ensure_run_dir};

/// How long to wait for a freshly spawned daemon to bind its socket.
const SPAWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Delay between connect retries while waiting for the daemon.
const SPAWN_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// How long any one `connect` to the session socket waits out a full backlog.
///
/// [`crate::rundir::connect_within`] has why every `connect` here is bounded and this
/// one is not a plain `UnixStream::connect` (§ 6.3). Short, because the state it waits
/// out clears in one `accept` and this is on the path of every attach.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Delay between checks for the pidfile the daemon publishes just after its socket.
///
/// Shorter than [`SPAWN_POLL_INTERVAL`] because the window it covers is two
/// syscalls wide and is usually already over, while the wait itself is on the path
/// of every session creation.
const PUBLISH_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Largest transfer asked of `splice` in one call.
///
/// A pipe holds 64 KiB by default, so a larger request only comes back short while
/// a smaller one buys nothing but extra syscalls.
const SPLICE_CHUNK: usize = 64 * 1024;

/// Whether this invocation may bring the session into being — the whole of the
/// distinction between the two modes (`DESIGN.md` § 5.1).
#[derive(Clone, Copy)]
pub(crate) enum Intent<'a> {
    /// `nomux spawn <id>`: creates the session and attaches to it in one exec, and
    /// refuses an id something is already serving. Carries the label the new daemon is
    /// started with — a label belongs to the session rather than to the connection
    /// (§ 6.6), so this is the only mode with anywhere to put one.
    Create(Option<&'a str>),
    /// `nomux attach <id>`: relays to a session that exists, and refuses one that
    /// does not rather than quietly starting a second.
    Resume,
}

/// Reaches the session `session_id` names, per `intent`, and relays stdio to it.
///
/// # Errors
///
/// Fails if the session cannot be reached or created, or if relaying fails.
pub(crate) fn run(session_id: &str, intent: Intent<'_>) -> io::Result<()> {
    let paths = SessionPaths::new(session_id)?;
    let stream = match intent {
        Intent::Create(label) => create(&paths, label)?,
        Intent::Resume => resume(&paths)?,
    };
    relay(&stream)
}

/// Connects to a session that is already there, and refuses to invent one that is not.
fn resume(paths: &SessionPaths) -> io::Result<UnixStream> {
    // Checked and never created, which is `list` and `kill`'s rule (§ 6.3) and is
    // this mode's now that it creates nothing either. A directory that is not there
    // holds no session, which is the refusal below rather than a failure of its own.
    match check_run_dir(paths.dir()) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Err(no_such_session(paths)),
        Err(err) => return Err(err),
    }
    match liveness(&paths.socket(), CONNECT_TIMEOUT) {
        Liveness::Alive(stream) => Ok(stream),
        Liveness::Stale(_) => Err(no_such_session(paths)),
        Liveness::Unknown(err) => Err(unattachable(paths, &err)),
    }
}

/// `attach` on an id nothing is serving — never created here, or reaped, which are not
/// told apart because both want the same next command.
fn no_such_session(paths: &SessionPaths) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "no session {id}: nothing answers on {sock}. `nomux spawn {id}` starts one, \
             and `nomux list` says what this host is holding",
            id = paths.id(),
            sock = paths.socket().display(),
        ),
    )
}

/// `attach` on an id whose socket answered neither death nor life (the module's last row).
fn unattachable(paths: &SessionPaths, err: &io::Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::ResourceBusy,
        format!(
            "session {id} could not be joined: {sock} could not be probed, so that nothing \
             is serving it was never established: {err}. `nomux list` says what this host \
             is holding",
            id = paths.id(),
            sock = paths.socket().display(),
        ),
    )
}

/// `spawn` on an id something is already serving: the client's own state disagreeing with
/// the host's rather than a race to retry.
fn already_running(paths: &SessionPaths) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "session {id} already exists: something answers on {sock}. `nomux attach {id}` \
             joins it, and `nomux kill {id}` ends it",
            id = paths.id(),
            sock = paths.socket().display(),
        ),
    )
}

/// `spawn` on an id whose socket answered neither death nor life: [`already_running`]'s
/// kind on weaker evidence, `spawn` being allowed to create only an id it can say is free.
fn may_be_running(paths: &SessionPaths, err: &io::Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "session {id} may already exist: {sock} could not be probed, so that it is \
             free was never established: {err}. `nomux attach {id}` joins it if it is \
             there, and `nomux list` says what this host is holding",
            id = paths.id(),
            sock = paths.socket().display(),
        ),
    )
}

/// Creates the session under an exclusive lock, and refuses an id that answers.
///
/// The lock serialises concurrent spawns so two clients racing on the same id
/// produce one daemon, not two fighting over the socket path. It is held to the end
/// of the function rather than released after the spawn, because garbage collection
/// takes the same lock (`IMPLEMENTATION.md` § 6.6): while it is held, nothing can
/// unlink the socket this is waiting for.
fn create(paths: &SessionPaths, label: Option<&str>) -> io::Result<UnixStream> {
    // Before the lock and the probe below, not on the way to spawning a daemon. The
    // socket this is about to hand the user's keystrokes to is a *name* in the run
    // directory (§ 6.3), and where that directory is a symlink into somewhere another
    // user can write, the name is theirs to make: checking only when nothing answers
    // checks only the case where nothing was planted.
    ensure_run_dir(paths.dir())?;

    // A collector may unlink `<id>.lock` while this call is blocked on it, which
    // `rundir::SpawnLock` has: the lock that comes back is the one on the file now at
    // the path.
    let _spawn_lock = paths.lock_spawn()?;

    // Whether a failure gives `<id>.lock` back is that failure's own to say and cannot be
    // decided out here off the error: the two below that establish the id is nobody's
    // call [`released`] themselves, and every other way out leaves the name alone. It was
    // one release point for all of them, which is the shape that unlinked a run file of a
    // live session — an exit that established nothing was told it had established death.
    // Still under the lock wherever it lands, `_spawn_lock` outliving the call.
    spawn_and_join(paths, label)
}

/// The body of [`create`], as one call so that lock has a single owner.
fn spawn_and_join(paths: &SessionPaths, label: Option<&str>) -> io::Result<UnixStream> {
    let socket = paths.socket();
    // Once, and under the lock: another spawn may have created the session while we
    // waited for it, and the loser of that race is refused rather than handed the
    // winner's session — two tabs both told they created this one is exactly the
    // confusion the split exists to end.
    match liveness(&socket, CONNECT_TIMEOUT) {
        // Dropped on the spot, which costs the daemon a pending connection that
        // closes without greeting — the same nothing `list`'s probe costs it (§ 6.4).
        Liveness::Alive(_) => return Err(already_running(paths)),
        Liveness::Stale(_) => {}
        Liveness::Unknown(err) => return Err(may_be_running(paths, &err)),
    }

    let complaint = match spawn_daemon(paths.id(), label) {
        Ok(complaint) => complaint,
        // The one failure with nothing of anyone's behind it: no daemon was started, and
        // the probe above has just said nobody else is serving the id either, so the
        // name is this call's own to give back.
        Err(err) => return Err(released(paths, err)),
    };

    let deadline = Instant::now() + SPAWN_TIMEOUT;
    loop {
        match liveness(&socket, CONNECT_TIMEOUT) {
            Liveness::Alive(stream) => {
                await_publication(paths, deadline);
                return Ok(stream);
            }
            Liveness::Stale(_) => {
                if Instant::now() >= deadline {
                    let id = paths.id();
                    let complaint = daemon_complaint(complaint).map_or_else(
                        || format!("daemon for session {id} did not start"),
                        |said| format!("daemon for session {id} did not start: {said}"),
                    );
                    let refusal = io::Error::new(io::ErrorKind::TimedOut, complaint);
                    return Err(released(paths, refusal));
                }
                std::thread::sleep(SPAWN_POLL_INTERVAL);
            }
            // The daemon this call started may be the very thing that would not answer,
            // so this says as little about the id as the probe before the spawn did —
            // and the name is left alone for that reason rather than for the other one.
            Liveness::Unknown(err) => return Err(may_be_running(paths, &err)),
        }
    }
}

/// Gives back the `<id>.lock` this call created and hands `err` on, a leftover name being
/// one `session_id_of` counts as a session for § 6.3's ceiling.
///
/// Called from the two exits that established the id is nobody's and from nowhere else,
/// § 6.6 forbidding an exit that established neither death nor life to unlink over a live
/// session. Which exit it is cannot be read off the error, which is why this is a call
/// rather than a wrapper on every failure: the deadline above and
/// [`crate::rundir::connect_within`] both report `TimedOut`, one over a socket nothing ever
/// bound and one over a socket somebody bound and stopped accepting on.
fn released(paths: &SessionPaths, err: io::Error) -> io::Error {
    drop(fs::remove_file(paths.lock()));
    err
}

/// Keeps the spawn lock until the daemon this spawn started has published
/// `<id>.pid`.
///
/// This is what makes the lock mean what the rest of the layout assumes it means.
/// The daemon binds its socket before it writes the pidfile (§ 6.2), so a `connect`
/// that succeeds says the id is claimed and not that anything on disk says so yet —
/// and a `kill` taking the lock inside that window finds a live daemon and no pid,
/// which § 6.6 forbids it to unlink over.
///
/// Bounded by the caller's own deadline and never fatal: a daemon that never writes
/// one still gets its client, and `control::resolve` is what answers for it.
fn await_publication(paths: &SessionPaths, deadline: Instant) {
    // Built once. `SessionPaths::pid` allocates, and this loop runs every
    // millisecond for as long as the caller's deadline allows.
    let pid = paths.pid();
    while !pid.exists() && Instant::now() < deadline {
        std::thread::sleep(PUBLISH_POLL_INTERVAL);
    }
}

/// Starts the daemon detached from this process's session.
///
/// Both halves — `setsid` and `/dev/null` stdio — are the daemon's own job as of
/// `IMPLEMENTATION.md` § 6.2, and both are still done here because it cannot reach
/// either soon enough; that section has the two windows this closes.
fn spawn_daemon(session_id: &str, label: Option<&str>) -> io::Result<Option<ChildStderr>> {
    // The inode this process was loaded from, not the path it was loaded under, for two
    // reasons. A name is resolved again at exec, and what it resolves to by then belongs to
    // any uid that can write the install directory (`SECURITY.md`) — only that second exec
    // is closed, the first having run out of that directory, whose trust `DESIGN.md` § 8
    // leaves to the client. And the name need not resolve to this build at all: § 5.2
    // installs by `mv -f`, which unlinks the running inode without destroying it, so a
    // spawn parked in that window would otherwise lose its daemon to a concurrent upgrade
    // *of its own version*.
    let mut command = Command::new("/proc/self/exe");
    command
        // Keeps the real path in `ps`, off the very link named above, so a host with no
        // `/proc` still fails here rather than newly at the exec.
        // `control::names_daemon_for` skips `argv[0]` and reads neither spelling.
        .arg0(env::current_exe()?)
        .arg("daemon")
        .arg(session_id)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // A pipe rather than `/dev/null`, which is the only reason a failure to start
        // has a reason attached to it (§ 6.2).
        .stderr(Stdio::piped());
    if let Some(label) = label {
        // As two arguments, never `--label=<text>`: the label is free-form text
        // from a tab title and this way nothing has to be escaped.
        command.arg("--label").arg(label);
    }

    // Bound out here rather than written inside the `unsafe` block below, for the
    // reason `pty::Pty::spawn` gives at the same shape.
    let pre_exec = || -> io::Result<()> {
        rustix::process::setsid()?;
        Ok(())
    };
    // SAFETY: runs in the forked child before exec and must be async-signal-safe.
    // `setsid` is.
    unsafe {
        command.pre_exec(pre_exec);
    }
    command.spawn().map(|mut child| child.stderr.take())
}

/// Whatever the daemon managed to say before it stopped saying anything.
///
/// Read without waiting. This is only ever called once the daemon has already missed
/// its deadline, and one that is wedged with its stderr still open must not take the
/// relay down with it — a blocking read here would turn a five-second timeout into a
/// hang.
fn daemon_complaint(stderr: Option<ChildStderr>) -> Option<String> {
    let stderr = stderr?;
    let fd = stderr.as_fd();
    // Added to what is there rather than assigned over it: `fcntl_setfl` replaces the
    // whole status word, and every other site in the tree does the `getfl`-then-or.
    let flags = rustix::fs::fcntl_getfl(fd).ok()?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK).ok()?;
    let mut buf = [0u8; 512];
    // Through `nbio`, like every other read in the tree: a signal landing on this one
    // would report a daemon that explained itself as one that said nothing. `EAGAIN`
    // still falls through to `None`, which is what "it wrote nothing" means here.
    let read = crate::nbio::read(fd, &mut buf).ok()?;
    let text = String::from_utf8_lossy(buf.get(..read)?).into_owned();
    let line = text.lines().find(|line| !line.trim().is_empty())?.trim();
    // The daemon reached this through `main`'s reporter, which prefixes the binary's
    // own name. Keeping it would render as `nomux: ... : nomux: ...`.
    let line = line.strip_prefix("nomux: ").unwrap_or(line);
    // Escaped, like the pidfile bodies `control` quotes with `{:?}` and for the same
    // reason: this is another process's stderr on its way to a terminal, where the
    // `lines` above stops a second line being forged but not an `ESC ]0;` retitling
    // the window of whoever ran the attach.
    Some(line.escape_debug().collect())
}

/// Moves bytes between stdio and the socket until either side closes.
fn relay(stream: &UnixStream) -> io::Result<()> {
    // `SPLICE_F_NONBLOCK` governs the *pipe* end of a pair alone, so a splice into a socket
    // that is full parks the whole relay inside the kernel unless the socket itself is
    // non-blocking. Everything below already reads `EAGAIN` as "not now".
    stream.set_nonblocking(true)?;

    let stdin = io::stdin();
    let stdout = io::stdout();
    let stdin_fd = stdin.as_fd();
    let stdout_fd = stdout.as_fd();
    let sock_fd = stream.as_fd();

    let mut to_socket = Pump::default();
    let mut to_stdout = Pump::default();
    // One buffer for both directions, which never transfer within the same call, and
    // hoisted out of the loop: it is handed by reference to an opaque syscall wrapper,
    // so a fresh one per read is a memset nothing can elide — 32 KiB per keystroke.
    let mut chunk = [0u8; 16 * 1024];
    let mut stdin_open = true;
    let mut socket_open = true;
    // The only one of the three about a *destination*: the session's output having
    // nowhere left to go ends the loop the way the two above do.
    let mut stdout_open = true;

    while stdout_open && (socket_open || to_stdout.has_data()) {
        let mut stdin_flags = PollFlags::empty();
        stdin_flags.set(PollFlags::IN, stdin_open && to_socket.wants_source());
        let mut socket_flags = PollFlags::empty();
        socket_flags.set(PollFlags::IN, socket_open && to_stdout.wants_source());
        socket_flags.set(PollFlags::OUT, to_socket.wants_dest());
        let mut stdout_flags = PollFlags::empty();
        stdout_flags.set(PollFlags::OUT, to_stdout.wants_dest());
        // A fixed frame, seeded as `daemon::wait` seeds its slots and for its reasons.
        let mut fds: [PollFd<'_>; 3] =
            std::array::from_fn(|_| PollFd::from_borrowed_fd(sock_fd, PollFlags::empty()));
        let mut watched = 0;
        for (fd, flags) in [
            (stdin_fd, stdin_flags),
            (sock_fd, socket_flags),
            (stdout_fd, stdout_flags),
        ] {
            if !flags.is_empty()
                && let Some(slot) = fds.get_mut(watched)
            {
                *slot = PollFd::from_borrowed_fd(fd, flags);
                watched += 1;
            }
        }
        // Unreachable, [`Pump::wants_source`] being exactly `!wants_dest()`, and kept
        // because what it stands between is a `poll` on an empty set, which blocks
        // for ever.
        if watched == 0 {
            break;
        }

        // No deadline of our own: the relay lives exactly as long as the channel,
        // and every wakeup it can act on is a readiness event.
        match rustix::event::poll(fds.get_mut(..watched).unwrap_or(&mut []), None) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(err) => return Err(err.into()),
        }
        // Read back by position, which is safe only because the three masks that
        // decided whether each entry was taken are reused below rather than
        // recomputed: a `Pump` that changed state during `poll` cannot shift it.
        let mut events = fds.iter().map(PollFd::revents);
        let mut revents = |registered: bool| {
            if registered {
                events.next().unwrap_or_else(PollFlags::empty)
            } else {
                PollFlags::empty()
            }
        };
        let stdin_events = revents(!stdin_flags.is_empty());
        let socket_events = revents(!socket_flags.is_empty());
        let stdout_events = revents(!stdout_flags.is_empty());

        // `ERR` and `NVAL` alongside `HUP`, as `daemon::wait` has them: a source
        // reporting one of those alone would otherwise never be read, never be closed,
        // and spin in the poll set.
        let readable = PollFlags::IN | PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL;

        if stdin_events.intersects(readable)
            && !to_socket.transfer(stdin_fd, sock_fd, &mut chunk)?
        {
            stdin_open = false;
            // Half-close propagation (§ 7).
            drop(stream.shutdown(Shutdown::Write));
        }
        if socket_events.intersects(readable)
            && !to_stdout.transfer(sock_fd, stdout_fd, &mut chunk)?
        {
            socket_open = false;
        }
        // Speculative on a non-empty buffer as well as on `POLLOUT`, which stdout below
        // deliberately is not: this descriptor was made non-blocking at the top, so an
        // optimistic write costs at worst one `EAGAIN`. The answer is dropped rather
        // than read as an ending — an `EPIPE` towards the socket is a client that has
        // gone, and that same departure arrives as EOF from its *read* side above.
        if socket_events.contains(PollFlags::OUT) || to_socket.has_data() {
            let _ = to_socket.drain_to(sock_fd)?;
        }
        // `POLLOUT` is the only thing that clears `Pump::dest_full`, and a destination
        // whose reader has gone never reports it — a full pipe with no reader is not
        // writable, it is broken.
        if stdout_events.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) {
            stdout_open = false;
        } else if stdout_events.contains(PollFlags::OUT) {
            // Never speculatively, the way the socket above is drained: stdout is left
            // in the blocking mode it was inherited in and cannot safely be taken out
            // of it — it may be a terminal whose open file description the user's shell
            // shares — so a write it is not ready for parks the whole relay with the
            // other direction unserved. A socket-backed stdout reports itself writable
            // and then refuses, so its `EPIPE` here is the only way its death arrives.
            stdout_open = to_stdout.drain_to(stdout_fd)?;
        }
    }

    Ok(())
}

/// Reads once through `chunk` into `buf`. `false` means the source reached EOF.
fn copy_in(fd: BorrowedFd<'_>, buf: &mut VecDeque<u8>, chunk: &mut [u8]) -> io::Result<bool> {
    match crate::nbio::read(fd, chunk) {
        // Four shapes of one ending. A PTY-backed peer reports end of session as `EIO`
        // rather than 0; a socket peer that closed with bytes of *ours* still unread hands
        // over the last of its own and then answers `ECONNRESET` — the ordinary way a
        // session ends here (§ 4.1), and a failure here would cost the relay the exit
        // status § 10 gives a delivered `Exit` frame; and `ENOTCONN` where the connection
        // is already gone by the time the read lands.
        Ok(0)
        | Err(rustix::io::Errno::IO | rustix::io::Errno::CONNRESET | rustix::io::Errno::NOTCONN) => {
            Ok(false)
        }
        Ok(n) => {
            buf.extend(chunk.get(..n).unwrap_or(&[]));
            Ok(true)
        }
        // Nothing pending is not EOF: the peer is still there with nothing to say.
        Err(rustix::io::Errno::AGAIN) => Ok(true),
        Err(err) => Err(err.into()),
    }
}

/// What one `splice` attempt achieved.
#[derive(Debug)]
enum Spliced {
    /// Bytes handed over inside the kernel; 0 means the source is at EOF.
    Moved(usize),
    /// The destination would not take them yet. Neither an error nor EOF.
    Full,
    /// The kernel will not splice this pair — now or ever.
    Unusable,
    /// Something else went wrong, and it is about this moment rather than about the
    /// pair. The copying path meets the same condition on its own read.
    Failed,
}

/// Moves up to [`SPLICE_CHUNK`] bytes from `src` to `dst` without them ever
/// entering this process.
///
/// Whether `splice` works for a pair is a property of the host rather than of this code,
/// so it is discovered by trying: under sshd this process's stdio is a pipe on some builds
/// and a socket on others, and only a pair with a pipe in it can be spliced.
fn splice_once(src: BorrowedFd<'_>, dst: BorrowedFd<'_>) -> Spliced {
    let flags = SpliceFlags::MOVE | SpliceFlags::NONBLOCK;
    loop {
        return match rustix::pipe::splice(src, None, dst, None, SPLICE_CHUNK, flags) {
            Ok(moved) => Spliced::Moved(moved),
            Err(rustix::io::Errno::INTR) => continue,
            // Only ever reached with the source already reported readable, so this
            // is the destination refusing and never a source that had nothing.
            Err(rustix::io::Errno::AGAIN) => Spliced::Full,
            // `EINVAL` for a pair with neither end a pipe, `ENOSYS` for a kernel
            // without the call: the two that say something about the pair rather than
            // about the moment, and can therefore be believed for the rest of the run.
            Err(rustix::io::Errno::INVAL | rustix::io::Errno::NOSYS) => Spliced::Unusable,
            Err(_) => Spliced::Failed,
        };
    }
}

/// One direction of the relay, whose two paths cannot interleave: `splice` is attempted
/// only while `buf` below is empty, and never puts anything into it.
#[derive(Debug, Default)]
struct Pump {
    /// Bytes the destination would not take yet; only ever filled by the copying path.
    buf: VecDeque<u8>,
    /// Set for good the first time `splice` refuses the *pair* rather than the moment:
    /// neither reason it can refuse for can change while the relay runs, so retrying
    /// would buy a wasted syscall per wakeup for ever.
    splice_refused: bool,
    /// `splice` reported the destination full. Distinct from a non-empty buffer in
    /// that nothing is held here: it records only that the source must be left alone
    /// until the destination reports `POLLOUT`, re-reading it having nowhere to go.
    dest_full: bool,
}

impl Pump {
    /// Whether the source is worth polling: only with the destination caught up,
    /// so nothing can overtake bytes that are already owed to it.
    fn wants_source(&self) -> bool {
        !self.wants_dest()
    }

    /// Whether the destination is worth polling for writability.
    fn wants_dest(&self) -> bool {
        self.has_data() || self.dest_full
    }

    /// Whether anything is still held in userspace for the destination.
    fn has_data(&self) -> bool {
        !self.buf.is_empty()
    }

    /// Moves one batch from `src` towards `dst`. `false` means `src` reached EOF.
    ///
    /// Falling back within the same call keeps a host that cannot splice from losing
    /// a wakeup to the discovery.
    fn transfer(
        &mut self,
        src: BorrowedFd<'_>,
        dst: BorrowedFd<'_>,
        chunk: &mut [u8],
    ) -> io::Result<bool> {
        if !self.splice_refused && !self.has_data() {
            match splice_once(src, dst) {
                Spliced::Moved(moved) => return Ok(moved != 0),
                Spliced::Full => {
                    self.dest_full = true;
                    return Ok(true);
                }
                Spliced::Unusable => self.splice_refused = true,
                Spliced::Failed => {}
            }
        }
        copy_in(src, &mut self.buf, chunk)
    }

    /// Hands the destination whatever is owed it, and forgets that it was full.
    /// `false` means the destination has stopped reading.
    ///
    /// Clearing [`Pump::dest_full`] is sound from either of the two call sites: it
    /// only ever gates re-reading the source, and the write below is what establishes
    /// whether the destination has room.
    fn drain_to(&mut self, fd: BorrowedFd<'_>) -> io::Result<bool> {
        self.dest_full = false;
        match crate::nbio::drain_to(&mut self.buf, fd) {
            // `EPIPE` is `nbio`'s to report and each caller's to interpret: here it is
            // the destination's reader having gone — an ordinary ending rather than a
            // failure — so what was owed it is dropped and the answer comes back as
            // `false`. Which direction that ends is `relay`'s to say, not this
            // method's, and only one of the two stops the loop.
            Err(rustix::io::Errno::PIPE) => {
                self.buf.clear();
                Ok(false)
            }
            outcome => outcome.map(|()| true).map_err(Into::into),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write as _;

    use super::{ChildStderr, daemon_complaint};

    /// Reads back what a daemon writing `bytes` to its stderr would be reported as.
    ///
    /// The write end is dropped before the read: `daemon_complaint` never waits, so a
    /// pipe still open at the other end would answer `EAGAIN` and race the test.
    fn complaint_of(bytes: &[u8]) -> Option<String> {
        let (read, write) = rustix::pipe::pipe().unwrap();
        File::from(write).write_all(bytes).unwrap();
        daemon_complaint(Some(ChildStderr::from(read)))
    }

    #[test]
    fn a_complaint_cannot_drive_the_terminal_it_is_printed_to() {
        assert_eq!(
            complaint_of(b"nomux: \x1b]0;pwned\x07boom\nsecond line").as_deref(),
            Some("\\u{1b}]0;pwned\\u{7}boom"),
            "this reaches `main`'s `eprintln!` verbatim, so it must carry no escape \
             sequence — nor the daemon's own `nomux: `, nor a second line"
        );
    }

    #[test]
    fn a_legible_complaint_is_left_legible() {
        assert_eq!(
            complaint_of("nomux: /hëm/fornwall: permission denied".as_bytes()).as_deref(),
            Some("/hëm/fornwall: permission denied"),
            "escaping is for what a terminal acts on, not for every byte above ASCII"
        );
    }
}
