//! What § 6.3 wants from `AF_UNIX` that `std` will not do.
//!
//! A `connect` that gives up rather than parking in a full backlog, the `SO_PEERCRED`
//! behind "one uid may have the session", and the [`Liveness`] every caller reads out of
//! that `connect`. Its own module because the run directory's business is names and
//! modes: `<id>.sock` is bound over there, at the one mode that has to be exact
//! ([`crate::rundir::bind_socket_private`]), and everything anyone does with a session
//! socket afterwards is here.
//!
//! Through `libc` rather than rustix, whose sockets sit behind a `net` feature § 8's
//! budget is why this crate does not enable.

use std::fmt;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

/// Longest path a unix socket can be bound to: `sun_path` is 108 bytes and holds a
/// terminator, so 107 is what is left — the figure std checks before it builds an address.
///
/// `pub(crate)` because `rundir::SessionPaths::new` refuses an id whose run files would
/// overrun it, rather than letting the `bind` discover that (§ 6.3).
pub(crate) const SUN_PATH_MAX: usize = 107;

/// Whether a failed `connect` to a session socket means nothing is listening there.
///
/// The one predicate behind every such decision in this binary, reached through
/// [`liveness`] alone, since § 6.3 requires the daemon's probe, its bind, `list` and `kill`
/// to agree. A socket file outlives the process that bound it, so `ECONNREFUSED` is a dead
/// daemon, and an absent name is that answer one syscall sooner. Anything else — `EACCES`,
/// a descriptor limit — is not evidence of death and must never license an unlink: § 6.3's
/// "`EACCES` is not staleness".
fn nothing_is_listening(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
    )
}

/// How long to wait between attempts at a `connect` refused for room rather than for want
/// of a listener. Short, because the state it waits out clears in one `accept`.
const PROBE_RETRY: Duration = Duration::from_millis(10);

/// Connects to the unix socket at `path`, giving up after `within` rather than parking in
/// the kernel.
///
/// Bounded because an `AF_UNIX` `connect` to a *full* backlog blocks rather than being
/// refused (§ 6.3), so a daemon that has stopped calling `accept` would park `list`, `kill`
/// and every attach on that id with nothing to end the wait — and § 6.6's escape hatch has
/// to answer on any host.
///
/// A sleep loop rather than a `poll`, which is what `AF_UNIX` requires: a stream socket
/// refused for room answers `EAGAIN` at once and registers nothing to wait on, staying in
/// `TCP_CLOSE`, where `poll` reports `POLLOUT | POLLHUP` immediately and for ever.
/// `SO_SNDTIMEO`, which the kernel *does* honour here, is a bound a kernel could stop
/// enforcing, and this is the surface that may not hang.
///
/// # Errors
///
/// Propagates the `connect`, so [`nothing_is_listening`] still divides a dead daemon from
/// everything else, and reports [`io::ErrorKind::TimedOut`] where the deadline ran out on a
/// backlog that never drained or on a call a signal kept from happening — neither death nor
/// an answer, and licence for no unlink. Which of the two it was is *in* that message,
/// because `kill` prints it back at a user as the whole of what is known (§ 6.6).
fn connect_within(path: &Path, within: Duration) -> io::Result<UnixStream> {
    let addr = unix_address(path)?;
    let deadline = Instant::now() + within;
    loop {
        // `EAGAIN` is the full backlog and `EINTR` a call that has not happened yet: the
        // two outcomes that say nothing about the listener, retried alike and carried
        // apart, because the timeout below reports a *state* and the two are different
        // ones. With `control`'s `LIST_PROBE` at zero there is exactly one attempt, so a
        // lone `EINTR` would otherwise be reported as a backlog nobody observed — which
        // `list` keeps a session on and `kill` quotes back inside its refusal. Only the
        // last outcome is kept, that being the one that ran the clock out.
        let unsettled = match connect_once(&addr) {
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                "its backlog is full, so whoever bound it has stopped accepting"
            }
            // Retried on the same deadline rather than for free: a signal storm would
            // otherwise spin here without a bound, and `list` probes with no deadline at
            // all to spend.
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                "the last attempt was interrupted by a signal before the kernel answered \
                 it, so nothing here reached whoever bound it"
            }
            // This caller has a user to answer, so the refusal is returned rather than
            // logged, and [`liveness`] reads it as [`Liveness::Unknown`]: a socket with an
            // owner is not a dead one, so it licenses no unlink.
            Ok(stream) => {
                if let Some(foreign) = foreign_peer(stream.as_fd()) {
                    return Err(foreign.refusal());
                }
                return Ok(stream);
            }
            Err(err) => return Err(err),
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            let ms = u64::try_from(within.as_millis()).unwrap_or(u64::MAX);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "{path} did not accept a connection within {ms}ms: {unsettled}",
                    path = path.display(),
                ),
            ));
        }
        thread::sleep(PROBE_RETRY.min(remaining));
    }
}

/// State of one session as seen from the run directory alone.
#[derive(Debug)]
pub(crate) enum Liveness {
    /// A daemon accepted this connection, so a process is serving the socket.
    Alive(UnixStream),
    /// Nothing is listening; the daemon died. Carries the errno, which is what says
    /// whether a socket file was left behind to replace.
    Stale(io::Error),
    /// The `connect` failed for a reason that is not death, carrying it.
    ///
    /// Answers as conservatively as [`Self::Alive`] for the *unlink*, and its opposite
    /// everywhere else, since only an accepted connection may escalate to `SIGKILL`.
    Unknown(io::Error),
}

/// Probes the socket, through [`connect_within`], which owns the argument for the
/// deadline and [`nothing_is_listening`], which owns what a failure means.
pub(crate) fn liveness(socket: &Path, within: Duration) -> Liveness {
    match connect_within(socket, within) {
        Ok(stream) => Liveness::Alive(stream),
        Err(err) if nothing_is_listening(&err) => Liveness::Stale(err),
        // Evidence of neither death nor life — see [`Liveness::Unknown`].
        Err(err) => Liveness::Unknown(err),
    }
}

/// One non-blocking `connect` to `addr`, and the stream if it took.
fn connect_once(addr: &libc::sockaddr_un) -> io::Result<UnixStream> {
    // SAFETY: `socket` takes three integers and returns a descriptor or -1. Nothing is
    // passed by reference, and the descriptor is owned from the next statement on.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is the descriptor the call above just returned and nothing else
    // holds, so this is its sole owner and the only thing that will close it.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: `connect` is given the address and length of a `sockaddr_un` that outlives
    // the call — [`widths::SOCKADDR_UN`] is that type's own size — on a descriptor `fd`
    // keeps open across it, and it writes nothing back through either.
    let connected = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            std::ptr::from_ref(addr).cast::<libc::sockaddr>(),
            widths::SOCKADDR_UN,
        )
    };
    if connected < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = UnixStream::from(fd);
    // The non-blocking flag belonged to the `connect` and not to the caller, every one
    // of which wants the ordinary blocking socket it asked for.
    stream.set_nonblocking(false)?;
    Ok(stream)
}

/// The `sockaddr_un` naming `path`.
///
/// By hand because std creates the socket inside its own `connect` and offers no way to set
/// a flag on one first, and rustix's would mean adding its `net` feature.
fn unix_address(path: &Path) -> io::Result<libc::sockaddr_un> {
    use std::os::unix::ffi::OsStrExt;

    let bytes = path.as_os_str().as_bytes();
    // Unreachable — `SessionPaths::new` refuses an id this would overrun (§ 6.3) — and
    // kept because the copy below is what it makes sound.
    if bytes.len() > SUN_PATH_MAX {
        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    let mut addr = libc::sockaddr_un {
        sun_family: widths::AF_UNIX,
        // One byte past [`SUN_PATH_MAX`], which is the terminator that bound is stated
        // against, and left zero so every shorter path is terminated by construction.
        sun_path: [0; SUN_PATH_MAX + 1],
    };
    // SAFETY: `bytes` is at most `SUN_PATH_MAX` long, checked just above, and
    // `sun_path` is one byte longer than that — so the copy stays inside the array and
    // cannot reach its last byte. The two regions belong to different objects.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            addr.sun_path.as_mut_ptr().cast::<u8>(),
            bytes.len(),
        );
    }
    Ok(addr)
}

/// Why the process at the other end of a session socket is not one this uid may speak to
/// (§ 6.3).
pub(crate) enum Foreign {
    /// Another user's uid.
    Uid(u32),
    /// A peer the kernel would not describe. A `getsockopt` that failed is evidence of
    /// nothing, and nothing is not a match.
    Unnamed(io::Error),
}

impl fmt::Display for Foreign {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uid(uid) => write!(formatter, "uid {uid}"),
            Self::Unnamed(err) => write!(formatter, "a uid this host would not report ({err})"),
        }
    }
}

impl Foreign {
    /// This refusal as an error for a caller that has somewhere to report it.
    ///
    /// `PermissionDenied` because that is what it is, and because [`nothing_is_listening`]
    /// must never read a socket that has an owner as a dead one (§ 6.3).
    pub(crate) fn refusal(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("bound by {self}, not by this user"),
        )
    }
}

/// Whether the peer at the other end of `peer` is somebody else, and so may not be heard at
/// all (§ 6.3); `Some` carries why, for the caller to report where it can.
///
/// Defence in depth behind the `0700` run directory and `0600` sockets (§ 6.3), for where
/// modes do not hold. Nothing is ever sent back to the refused peer.
/// uid 0 is turned away with everyone else: root has `/proc`, `setuid` and `ptrace`
/// whatever this answers.
fn foreign_peer(peer: BorrowedFd<'_>) -> Option<Foreign> {
    // The `getuid` § 6.3's run-directory check is written against, so that "this uid"
    // means one thing across the tree; nothing here is ever setuid, so the real uid it
    // answers with is also the one that owns the socket.
    let ours = rustix::process::getuid().as_raw();
    match peer_uid(peer) {
        Ok(uid) if uid == ours => None,
        Ok(uid) => Some(Foreign::Uid(uid)),
        Err(err) => Some(Foreign::Unnamed(err)),
    }
}

/// [`foreign_peer`] for the session's two listeners, whose refusal has no reader but syslog
/// (§ 11): `startup::silence_standard_descriptors` has already taken the daemon's stderr.
pub(crate) fn peer_is_ours(peer: BorrowedFd<'_>, id: &str) -> bool {
    let Some(foreign) = foreign_peer(peer) else {
        return true;
    };
    crate::sanitize::error(id, &format!("refused a connection from {foreign}"));
    false
}

/// The three fixed widths the socket calls here are handed: `AF_UNIX` in the field that
/// carries it, and the lengths of a `sockaddr_un` and a `ucred`. Constants because 1, 110
/// and 12 each fit the field they are written into, so the conversions these replace could
/// not fail and cost a branch and an error string apiece against § 8's budget.
#[expect(
    clippy::cast_possible_truncation,
    reason = "1, 110 and 12 each fit the field the cast writes them into"
)]
mod widths {
    pub(super) const AF_UNIX: libc::sa_family_t = libc::AF_UNIX as libc::sa_family_t;
    pub(super) const SOCKADDR_UN: libc::socklen_t =
        size_of::<libc::sockaddr_un>() as libc::socklen_t;
    pub(super) const UCRED: libc::socklen_t = size_of::<libc::ucred>() as libc::socklen_t;
}

/// The uid `SO_PEERCRED` reports for the process at the other end of `fd`.
fn peer_uid(fd: BorrowedFd<'_>) -> io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = widths::UCRED;
    // SAFETY: `getsockopt` is given a `ucred` to fill and a `socklen_t` holding that
    // type's own size, both owned by this frame and unaliased across the call, on a
    // descriptor the borrow keeps open for it.
    let asked = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut cred).cast::<libc::c_void>(),
            std::ptr::from_mut(&mut len),
        )
    };
    if asked != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What [`connect_within`] hands a caller that has a user to answer: the uid that
    /// actually owns the socket, and not the `EACCES` a `connect` refused by the
    /// directory's modes would have produced.
    ///
    /// Constructed rather than provoked — a socket owned by another uid needs a second
    /// uid, which the suite has no way to become — so this pins the two halves the
    /// relay's message is built out of: the sentence, and the kind
    /// `attach::resume_probe_class` reads to call the host unsafe rather than uncertain.
    /// The admitting direction is end to end in `tests/session.rs`:
    /// `a_connection_from_this_uid_is_admitted_and_reports_its_credentials`, and in every
    /// other test in the suite, a check that refused everybody taking no clients at all.
    #[test]
    fn a_socket_bound_by_another_user_is_refused_as_that_and_not_as_a_bare_errno() {
        let refusal = Foreign::Uid(4242).refusal();
        assert_eq!(refusal.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(refusal.to_string(), "bound by uid 4242, not by this user");

        let unnamed = Foreign::Unnamed(io::Error::from_raw_os_error(libc::ENOPROTOOPT)).refusal();
        assert!(
            unnamed.to_string().contains("would not report"),
            "a peer the kernel would not describe is refused as that too: {unnamed}"
        );
    }

    /// [`peer_uid`] against the only peer this process can produce on its own, where
    /// the answer is known: itself.
    ///
    /// It pins the call rather than the policy, and that is the half worth pinning. A
    /// wrong level, option or struct answers `Err` for every connection, which
    /// [`foreign_peer`] then refuses — a session socket that admits nobody, which is
    /// the realistic way this goes wrong.
    #[test]
    fn the_kernel_reports_the_uid_of_a_peer_this_process_owns() {
        let (ours, _theirs) = UnixStream::pair().expect("a socketpair");
        assert_eq!(
            peer_uid(ours.as_fd()).expect("SO_PEERCRED on a socketpair"),
            rustix::process::getuid().as_raw(),
            "both ends of a socketpair belong to the process that made it"
        );
    }
}
