//! The relay behind `nomux spawn` and `nomux attach`.
//!
//! Deliberately dumb: it moves bytes between stdio and the session socket and never
//! parses a frame, so this side never needs a version bump (`IMPLEMENTATION.md` § 7).
//! It exists for hosts where the client cannot open a `direct-streamlocal` channel
//! straight to the socket.
//!
//! One relay, two ways in ([`Intent`]). Everything past the connection is shared.

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
use crate::rundir::SessionPaths;

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

/// Whether this invocation may bring the session into being.
///
/// The two modes are one relay and two answers to an id nothing is serving, which is
/// the whole of the distinction (`DESIGN.md` § 5.1): `spawn` creates it, `attach`
/// refuses.
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
    match paths.check_dir() {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Err(no_such_session(paths)),
        Err(err) => return Err(err),
    }
    match liveness(&paths.socket(), CONNECT_TIMEOUT) {
        Liveness::Alive(stream) => Ok(stream),
        Liveness::Stale(_) => Err(no_such_session(paths)),
        Liveness::Unknown(err) => Err(err),
    }
}

/// The refusal `attach` answers an id nothing is serving with.
///
/// Two states reach it and it deliberately does not tell them apart: an id that never
/// named a session here, and one whose session has been reaped. Neither is
/// recoverable from and both want the same next command, so the difference would be
/// resolution nobody can act on.
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

/// The refusal to create an id something is already serving.
///
/// `spawn` is the one mode that says what a session *is*, so meeting a live one is
/// the client's own state disagreeing with the host's rather than a race to retry —
/// and the repair is `attach`, which is the command this names.
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
    paths.ensure_dir()?;

    // A collector may unlink `<id>.lock` while this call is blocked on it, which
    // `rundir::SpawnLock` has: the lock that comes back is the one on the file now at
    // the path.
    let _spawn_lock = paths.lock_spawn()?;

    // One release point for every way the attempt can fail, so no exit path can forget
    // it. Still under the lock, `_spawn_lock` outliving this expression. `AlreadyExists`
    // is the one failure that leaves a session behind, where the name is that session's.
    spawn_and_join(paths, label).inspect_err(|err| {
        if err.kind() != io::ErrorKind::AlreadyExists {
            release_lock_name(paths);
        }
    })
}

/// The body of [`create`], as one fallible call so its lock has a single owner.
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
        Liveness::Unknown(err) => return Err(err),
    }

    let complaint = spawn_daemon(paths.id(), label)?;

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
                    return Err(io::Error::new(io::ErrorKind::TimedOut, complaint));
                }
                std::thread::sleep(SPAWN_POLL_INTERVAL);
            }
            Liveness::Unknown(err) => return Err(err),
        }
    }
}

/// Gives back the `<id>.lock` this call created, on the way out of a spawn that left no
/// session behind.
///
/// A leftover name is one `session_id_of` counts as a session, so without this every
/// spawn refused at § 6.3's ceiling would raise the count that refused it — and only
/// this process, still holding the lock, can undo that.
fn release_lock_name(paths: &SessionPaths) {
    drop(fs::remove_file(paths.lock()));
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
    let exe = env::current_exe()?;
    let mut command = Command::new(exe);
    command
        .arg("daemon")
        .arg(session_id)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // A pipe rather than `/dev/null`, which is the only reason a failure to start
        // has a reason attached to it: the daemon writes its diagnostics to stderr
        // until `release_startup_state` points the descriptor at `/dev/null` (§ 6.2),
        // and the pipe reaching end of file is itself the daemon reporting it got
        // past that point.
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
    // The socket has to be non-blocking for the `splice` path to be safe to take
    // (§ 7), and everything below already reads `EAGAIN` as "not now".
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
        // One mask per descriptor, empty where it is not worth watching this pass, and
        // read back below in the same order.
        let mut stdin_flags = PollFlags::empty();
        stdin_flags.set(PollFlags::IN, stdin_open && to_socket.wants_source());
        let mut socket_flags = PollFlags::empty();
        socket_flags.set(PollFlags::IN, socket_open && to_stdout.wants_source());
        socket_flags.set(PollFlags::OUT, to_socket.wants_dest());
        let mut stdout_flags = PollFlags::empty();
        stdout_flags.set(PollFlags::OUT, to_stdout.wants_dest());
        // A fixed frame rather than a `Vec`, which would be a heap allocation per
        // wakeup for a set of at most three. Seeded as `daemon::wait` seeds its slots:
        // `PollFd` has no vacant spelling, so the tail past `watched` carries a
        // descriptor of our own under an empty mask and is never shown to `poll`.
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
            // Propagate the half-close so the daemon sees our EOF while we keep
            // draining its output.
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
        // One of the two ways a dead stdout arrives: `POLLOUT` is the only thing that
        // clears `Pump::dest_full`, and a destination whose reader has gone never
        // reports it — a full pipe with no reader is not writable, it is broken.
        if stdout_events.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) {
            stdout_open = false;
        } else if stdout_events.contains(PollFlags::OUT) {
            // On `POLLOUT` alone, and never speculatively the way the socket above is
            // drained. Stdout is left in the blocking mode it was inherited in and
            // cannot safely be taken out of it — it may be a terminal whose open file
            // description the user's shell shares — so a write it is not ready for
            // parks the whole relay with the other direction unserved. Nothing is lost
            // by waiting, a non-empty buffer being what put stdout in the set.
            //
            // The `EPIPE` that write can return is the other of the two ways, and for
            // a socket-backed stdout it is the only one: that shape reports itself
            // writable and then refuses.
            stdout_open = to_stdout.drain_to(stdout_fd)?;
        }
    }

    Ok(())
}

/// Reads once through `chunk` into `buf`. `false` means the source reached EOF.
fn copy_in(fd: BorrowedFd<'_>, buf: &mut VecDeque<u8>, chunk: &mut [u8]) -> io::Result<bool> {
    match crate::nbio::read(fd, chunk) {
        // Four shapes of one ending. A PTY-backed peer reports end of session as
        // `EIO` rather than 0; a socket peer that closed with bytes of *ours* still
        // unread hands over the last of its own and then answers `ECONNRESET`, and
        // `ENOTCONN` where the connection is already gone by the time the read
        // lands.
        //
        // That middle one is the ordinary way a session ends here rather than an
        // exotic one — § 4.1, `write_client` and `shutdown` each leave input of ours
        // unread — and taken as a failure it costs the relay the exit status § 10
        // gives a delivered `Exit` frame.
        Ok(0)
        | Err(rustix::io::Errno::IO | rustix::io::Errno::CONNRESET | rustix::io::Errno::NOTCONN) => {
            Ok(false)
        }
        Ok(n) => {
            buf.extend(chunk.get(..n).unwrap_or(&[]));
            Ok(true)
        }
        // Nothing pending is not EOF; the peer is still there, it just had
        // nothing to say.
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
/// Whether `splice` works for a pair is a property of the host rather than of this
/// code (`IMPLEMENTATION.md` § 7), so it is discovered by trying — and only by the
/// two errors that are that same property.
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

/// One direction of the relay.
///
/// The two paths through it cannot interleave, which is `IMPLEMENTATION.md` § 7's:
/// `splice` is attempted only while the buffer is empty and never fills it.
#[derive(Debug, Default)]
struct Pump {
    /// Bytes the destination would not take yet. Only ever filled by the copying
    /// path.
    buf: VecDeque<u8>,
    /// Set for good the first time `splice` refuses the *pair* rather than the
    /// moment. Neither reason it can refuse for can change while the relay runs, and
    /// retrying would buy a wasted syscall per wakeup forever.
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
