//! Run-directory layout.
//!
//! This layout is the frozen contract described in `IMPLEMENTATION.md` § 6.6:
//! `list` and `kill` operate on it alone, never on the session protocol, so any
//! build can manage a daemon of any version. Filenames and permissions here may
//! never change.

use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::{env, fs, thread};

use rustix::fs::{FlockOperation, Mode, OFlags};

/// Permissions for the run directory: owner-only, since it holds the sockets that
/// grant access to live sessions.
const DIR_MODE: u32 = 0o700;

/// Permissions for every socket inside it.
const SOCKET_MODE: u32 = 0o600;

/// Permissions for the three plain files: the pidfile, the label and the spawn
/// lock.
///
/// Owner-only like everything else here, and exact for the same reason. The
/// directory already keeps other users out, so what this buys is not secrecy but a
/// mode that does not depend on the umask of whoever happened to create the file:
/// `<id>.lock` at `0400` is one that no *later* process can open for writing, and
/// the mutex the whole control surface rests on then belongs to nobody.
const FILE_MODE: u32 = 0o600;

/// How many times an acquirer will re-take the lock on finding that the file it
/// locked is no longer the file at the path. Each retry costs some other process a
/// whole collection, so a second is already a machine looping on `nomux list` rather
/// than a race being lost.
const LOCK_ATTEMPTS: usize = 2;

/// Runs `f` with the umask suppressed, so that a node created at `mode` is created
/// at exactly `mode`.
///
/// `mkdir(2)`, `bind(2)` and `open(2)` all subtract the caller's umask from the
/// mode they are given, which makes that argument an upper bound rather than a
/// request — and every mode in this module is exact. Creating and then `chmod`ing
/// would narrow the window rather than close it, and would `chmod` a path that is
/// being raced.
///
/// The umask is process-wide, and no shipped caller is multi-threaded or spawns a
/// process while it is in effect. `cargo test` is: `scratch::umask_lock` states that
/// and closes it, unlinked because both it and the line below are `#[cfg(test)]`.
fn with_umask<T>(mode: u32, f: impl FnOnce() -> T) -> T {
    #[cfg(test)]
    let _umask = crate::scratch::umask_lock();
    let previous = rustix::process::umask(Mode::from_bits_truncate(0o777 & !mode));
    let result = f();
    rustix::process::umask(previous);
    result
}

/// Replaces `path` with `body`, at exactly [`FILE_MODE`], in one `write`.
///
/// Removed first because a mode argument applies only to a file the call creates:
/// `O_TRUNC` onto one already at the path keeps whatever mode it arrived with, so
/// the suppression below would silently do nothing for the leftover of a previous
/// incarnation. Only the socket is cleared when a daemon rebinds an id, so such a
/// leftover is ordinary rather than exotic — and for `<id>.pid` the mode it keeps
/// can be one its own owner cannot read, which is a session `kill` will not touch.
///
/// One `write` rather than a `File` and a `writeln!`: `File` is unbuffered and
/// `format_args!` hands its pieces over one at a time, so a formatted pidfile would be
/// published three syscalls wide instead of the two `control::resolve` waits out.
fn write_private(path: &Path, body: &[u8]) -> io::Result<()> {
    drop(fs::remove_file(path));
    with_umask(FILE_MODE, || fs::write(path, body))
}

/// Binds a unix socket that is never, even briefly, more permissive than
/// [`SOCKET_MODE`] — [`with_umask`] is why that cannot be a `bind` and a `chmod`, and
/// a login with `umask 000` is what it would cost.
///
/// # Errors
///
/// Propagates bind failures.
pub(crate) fn bind_socket_private(path: &Path) -> io::Result<UnixListener> {
    with_umask(SOCKET_MODE, || UnixListener::bind(path))
}

/// Longest label written to `<id>.label`, in bytes, per the frozen layout.
const MAX_LABEL_LEN: usize = 256;

/// Longest `<id>.pid` body anything reads (§ 6.6), the rest of it room for whatever
/// whitespace a file repaired by hand carries. Bounded for [`read_prefix`]'s reason, and
/// beside [`MAX_LABEL_LEN`] because those are the two files read by hand.
///
/// `pub(crate)` because `control`'s refusal quotes it: a body that *reached* the bound is
/// a file to repair, and one that parsed and named nothing is not.
pub(crate) const MAX_PID_LEN: usize = 32;

/// Longest session id, in bytes (§ 6.3).
///
/// Not on the wire — § 2.2 keeps the id out of `Hello` — so it lives beside the layout
/// that turns one into a filename. `pub(crate)` because `control` sizes its
/// `/proc/<pid>/cmdline` prefix against it.
pub(crate) const MAX_SESSION_ID_LEN: usize = 64;

/// Longest path a unix socket can be bound to, in bytes.
///
/// `sun_path` is 108 bytes and holds a terminator, so 107 is what is left for the
/// path itself — the figure std checks before it will build the address at all.
const SUN_PATH_MAX: usize = 107;

/// Whether a failed `connect` to a session socket means nothing is listening there.
///
/// The one predicate behind every such decision in this binary, because § 6.3 is what
/// requires the daemon's probe, its bind, `list` and `kill` to agree. A socket file
/// outlives the process that bound it, so `ECONNREFUSED` is a dead daemon and a name
/// that is not there at all is the same answer one syscall sooner. Anything else —
/// `EACCES`, a descriptor limit — is not evidence of death and must never license an
/// unlink; § 6.3 puts that as "`EACCES` is not staleness".
pub(crate) fn nothing_is_listening(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
    )
}

/// How long to wait between attempts at a `connect` that was refused for room rather
/// than for want of a listener. Short against any deadline a caller sets, because the
/// state it waits out clears in one `accept`.
const PROBE_RETRY: Duration = Duration::from_millis(10);

/// Connects to the unix socket at `path`, giving up after `within` rather than
/// parking in the kernel.
///
/// The `connect` every mode here makes, because § 6.3 states the hazard and leaves no
/// mode out of it: an `AF_UNIX` `connect` to a listener whose backlog is *full* blocks
/// rather than being refused, so a daemon that has stopped calling `accept` parks
/// `list`, `kill` and every attach on that id inside the kernel with nothing to end the
/// wait — and § 6.6's escape hatch has to answer on any host.
///
/// The deadline is this loop rather than a `poll`, which is the shape a reader coming
/// from TCP will not expect and is what `AF_UNIX` requires: a stream socket whose
/// `connect` was refused for room answers `EAGAIN` at once and registers nothing to
/// wait on — it stays in `TCP_CLOSE`, where `poll` reports `POLLOUT | POLLHUP`
/// immediately and for ever. `SO_SNDTIMEO`, which the kernel *does* honour on a
/// blocking `connect` here, is not used either: a bound the kernel enforces is one a
/// kernel could stop enforcing, and this is the surface that may not hang.
///
/// # Errors
///
/// Propagates the `connect`, so [`nothing_is_listening`] still divides a dead daemon
/// from everything else, and reports [`io::ErrorKind::TimedOut`] for a backlog that
/// never drained — which is neither death nor an answer, and must license no unlink.
pub(crate) fn connect_within(path: &Path, within: Duration) -> io::Result<UnixStream> {
    let (addr, len) = unix_address(path)?;
    let deadline = Instant::now() + within;
    loop {
        match connect_once(&addr, len) {
            // `EAGAIN` is the full backlog and `EINTR` is a call that has not happened
            // yet: the two outcomes that say nothing about the listener, and so the
            // only two worth asking about again.
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            outcome => return outcome,
        }
        if Instant::now() >= deadline {
            // Narrowed before formatting: `as_millis` is a `u128`, and this is the only
            // one in the crate — printing it instantiates that `Display` on its own,
            // measured at 723 bytes of the § 8 budget for a message on a cold path.
            let ms = u64::try_from(within.as_millis()).unwrap_or(u64::MAX);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "{} did not accept a connection within {ms}ms: its backlog is full, \
                     so whoever bound it has stopped accepting",
                    path.display(),
                ),
            ));
        }
        thread::sleep(PROBE_RETRY);
    }
}

/// One non-blocking `connect` to `addr`, and the stream if it took.
fn connect_once(addr: &libc::sockaddr_un, len: libc::socklen_t) -> io::Result<UnixStream> {
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
    // SAFETY: `connect` is given the address and length of a `sockaddr_un` that
    // outlives the call — `len` is that type's own size — on a descriptor `fd` keeps
    // open across it, and it writes nothing back through either.
    let connected = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            std::ptr::from_ref(addr).cast::<libc::sockaddr>(),
            len,
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

/// The `sockaddr_un` naming `path`, and the length a `connect` is given for it.
///
/// By hand because std creates the socket inside its own `connect` and offers no way
/// to set a flag on one first, and rustix's would mean adding its `net` feature to a
/// crate that otherwise reaches sockets through `std` alone.
fn unix_address(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    use std::os::unix::ffi::OsStrExt;

    let (Ok(family), Ok(len)) = (
        libc::sa_family_t::try_from(libc::AF_UNIX),
        libc::socklen_t::try_from(size_of::<libc::sockaddr_un>()),
    ) else {
        return Err(io::Error::other(
            "AF_UNIX does not fit its own address type",
        ));
    };
    let bytes = path.as_os_str().as_bytes();
    // [`SessionPaths::new`] refuses an id this would overrun before any path is built
    // (§ 6.3); this is that bound where the address is actually formed, for the callers
    // that reach here with a path of their own.
    if bytes.len() > SUN_PATH_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is longer than the {SUN_PATH_MAX} bytes a unix socket path allows",
                path.display()
            ),
        ));
    }
    let mut addr = libc::sockaddr_un {
        sun_family: family,
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
    Ok((addr, len))
}

/// The value of environment variable `key`, but only where it names an **absolute**
/// path.
///
/// The rule every directory this binary takes from the environment obeys: a source
/// that does not name an absolute path is not a source, and an empty value is not
/// absolute either, so this is the whole of the check. `IMPLEMENTATION.md` § 6.3 has
/// why, and § 6.2 has the `chdir` that makes it matter.
pub(crate) fn absolute_env(key: &str) -> Option<std::ffi::OsString> {
    env::var_os(key).filter(|value| Path::new(value).is_absolute())
}

/// Resolves the run directory, preferring `XDG_RUNTIME_DIR`.
///
/// The precedence and the reason for each half are `IMPLEMENTATION.md` § 6.3's, as is
/// the rule [`absolute_env`] applies to every source.
///
/// # Errors
///
/// Fails when none of `XDG_RUNTIME_DIR`, `XDG_STATE_HOME` or `HOME` names an
/// absolute path.
pub(crate) fn run_dir() -> io::Result<PathBuf> {
    if let Some(dir) = absolute_env("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(dir).join("nomux"));
    }
    let state = absolute_env("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| absolute_env("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .ok_or_else(|| {
            io::Error::other(
                "none of XDG_RUNTIME_DIR, XDG_STATE_HOME or HOME names an absolute path",
            )
        })?;
    Ok(state.join("nomux/run"))
}

/// Creates `dir` if it is absent, and refuses it if it is not this user's alone.
///
/// Creating it is the easy half. It usually exists already, and that it exists says
/// nothing about *what* exists — [`check_run_dir`] is the other half and § 6.3 the
/// argument for it.
///
/// The check runs before the creation, so the ordinary case costs one `open` and
/// one `fstat`, and so a plain file sitting at the path is reported as what it is
/// rather than as an `EEXIST` naming nothing.
///
/// # Errors
///
/// Fails if the directory cannot be created, is not a directory, belongs to
/// somebody else, or is one other users can write to — a refusal § 6.3 makes hard
/// where the rest of this daemon degrades.
fn ensure_dir_at(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match check_run_dir(dir) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        settled => return settled,
    }
    // Suppressed for the parents `recursive` creates along the way as much as for the
    // directory itself ([`with_umask`]): left to a `umask 0500` this line would make a
    // run directory its owner cannot open, and the check below would then refuse what
    // it had just made.
    with_umask(DIR_MODE, || {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(dir)
    })?;
    // Checked again rather than trusted: `recursive` reports an existing directory
    // as success, so what this call created may be what another attach created a
    // moment earlier — or, where the parent is one somebody else can write to, what
    // they left there between the two checks.
    check_run_dir(dir)
}

/// Opens `dir` as itself and establishes that it belongs to this user alone.
///
/// `O_DIRECTORY` and `O_NOFOLLOW` do most of the work (§ 6.3), leaving this to decide
/// who owns the thing and who else may create names in it. That the file type is the
/// kernel's answer rather than a second `fstat` of ours is deliberate: a check that
/// could disagree with the descriptor it is meant to describe is worse than no check.
///
/// The descriptor is dropped at the end and the run files go on being opened by
/// path, which is a decision rather than an oversight: there is no `bindat(2)`, so
/// the two sockets that decide who a session is talking to must be resolved by name
/// whatever this function returns. `IMPLEMENTATION.md` § 6.3 gives the rest of that
/// argument. What is established is one link of the path rather than the whole of
/// it: nobody but this uid can put a name in *this* directory. Every component above
/// it is taken on trust, so a parent somebody else can write to is a run directory
/// they can replace outright — `DESIGN.md` § 8 states that gap rather than closing
/// it. Keeping the descriptor for the session's lifetime would also pin the
/// filesystem the daemon deliberately lets go of in § 6.2.
///
/// # Errors
///
/// Fails if `dir` is not a directory, is a symlink, belongs to another uid, is one
/// group or other can write to, or is in a mode its owner cannot open. A directory
/// that is simply absent arrives as [`io::ErrorKind::NotFound`], which the control
/// surface reads as an answer rather than a failure: no session was ever created here.
pub(crate) fn check_run_dir(dir: &Path) -> io::Result<()> {
    let fd = rustix::fs::open(
        dir,
        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|err| match err {
        // Linux answers `O_DIRECTORY | O_NOFOLLOW` on a symlink with `ENOTDIR` rather
        // than the `ELOOP` the manual page leads one to expect, so the two cases arrive
        // as one errno and telling them apart means asking again. Worth asking: "it is
        // a symlink" is the sentence that tells somebody what to do about it, and the
        // extra `lstat` is paid only on the way to failing.
        rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP => refuse(
            dir,
            io::ErrorKind::NotADirectory,
            match fs::symlink_metadata(dir) {
                Ok(meta) if meta.file_type().is_symlink() => "it is a symlink",
                _ => "it is not a directory",
            },
        ),
        // A mode with the owner's own read bit missing is the one loosening — or
        // tightening — that cannot be repaired (§ 6.3), and it is still a judgement
        // on the mode rather than on the syscall, so it is reported as one. The
        // `lstat` is paid only on the way to failing, and falls back where it is a
        // searchless parent rather than this directory that answered `EACCES`.
        rustix::io::Errno::ACCESS => match fs::symlink_metadata(dir) {
            // Somebody else's, at a mode that keeps us out. The uid is the whole
            // sentence — this is the § 8 threat, reachable with `XDG_RUNTIME_DIR`
            // pointed into a shared parent — and naming the mode instead would report
            // `0700`, the expected one, as the fault.
            Ok(meta) if meta.is_dir() && meta.uid() != rustix::process::getuid().as_raw() => {
                refuse(
                    dir,
                    io::ErrorKind::PermissionDenied,
                    &format!("it belongs to uid {}", meta.uid()),
                )
            }
            Ok(meta) if meta.is_dir() => refuse(
                dir,
                io::ErrorKind::PermissionDenied,
                &format!(
                    "mode {:o} does not let its owner open it",
                    meta.mode() & 0o7777
                ),
            ),
            _ => refuse_errno(dir, err, "it could not be opened"),
        },
        other => refuse_errno(dir, other, "it could not be opened"),
    })?;

    let stat =
        rustix::fs::fstat(&fd).map_err(|err| refuse_errno(dir, err, "it could not be examined"))?;
    if stat.st_uid != rustix::process::getuid().as_raw() {
        return Err(refuse(
            dir,
            io::ErrorKind::PermissionDenied,
            &format!("it belongs to uid {}", stat.st_uid),
        ));
    }

    // Write for group or other is the one loosening that is not repairable, and the
    // only one answered the way a wrong owner is (§ 6.3): tightening the directory
    // now does not un-plant what somebody left in it, so nothing inside is evidence
    // of anything any more.
    //
    // Every other mode is repaired to exactly [`DIR_MODE`], through the descriptor
    // already checked above, since § 6.3 states the mode as exact and says what each
    // of them costs. The one mode not reached here is one the owner cannot open at
    // all, which failed above with nothing to repair through.
    let mode = Mode::from_raw_mode(stat.st_mode);
    if mode.intersects(Mode::WGRP | Mode::WOTH) {
        return Err(refuse(
            dir,
            io::ErrorKind::PermissionDenied,
            &format!("mode {:o} lets other users create files in it", mode.bits()),
        ));
    }
    if mode != Mode::from_bits_truncate(DIR_MODE) {
        // Through the descriptor, never the path, which would reopen exactly the
        // hole the `O_NOFOLLOW` above closed.
        rustix::fs::fchmod(&fd, Mode::from_bits_truncate(DIR_MODE))
            .map_err(|err| refuse_errno(dir, err, "its mode could not be tightened"))?;
    }
    Ok(())
}

/// A refusal in the terms the user needs: which directory, what is wrong with it,
/// and what it was supposed to be. It reaches them as `nomux: ...` on stderr and is
/// the whole account they get, so it names the path even where the errno beneath it
/// names nothing at all.
fn refuse(dir: &Path, kind: io::ErrorKind, problem: &str) -> io::Error {
    io::Error::new(
        kind,
        format!(
            "run directory {}: {problem}; expected a directory owned by this user, mode {DIR_MODE:o}",
            dir.display()
        ),
    )
}

/// [`refuse`] for a failed syscall, keeping the kind the errno maps to so that a
/// caller matching on it still can.
fn refuse_errno(dir: &Path, err: rustix::io::Errno, problem: &str) -> io::Error {
    let err = io::Error::from(err);
    let kind = err.kind();
    refuse(dir, kind, &format!("{problem}: {err}"))
}

/// Returns whether `id` is usable as a session id.
///
/// Ids are minted by the client and used directly as filename components, so the
/// accepted set is deliberately narrow — 1..=64 bytes of `[A-Za-z0-9_-]`, never a
/// leading `-` (`IMPLEMENTATION.md` § 6.3) — which makes path traversal impossible by
/// construction rather than by escaping. The leading `-` is the command line's bound
/// rather than the filesystem's: `main` reads any argument beginning with one as an
/// option before a mode ever sees it, so an id that starts with `-` is one a
/// conforming client could mint and then never spawn, attach or kill — and the exit
/// code it would get says its command line was malformed rather than that its id was.
///
/// An invalid id is a hard error at both ends and is never sanitised: rewriting one
/// into a valid id would silently attach the user to the wrong session.
#[must_use]
fn is_valid_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_SESSION_ID_LEN
        && !id.starts_with('-')
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// The session a name in the run directory belongs to, if it belongs to one.
///
/// The inverse of [`SessionPaths::with_extension`], and the one rule by which anything
/// here learns an id from a directory rather than from a caller.
///
/// A glob rather than an enumeration, because § 6.6 freezes the five names it lists and
/// not the *set*: naming the extensions it knew made every future name a leak in every
/// binary already shipped — one file left behind per collected session, and an id whose
/// last remaining file is a name this build has never heard of is an id it never learns,
/// so the `kill` that would clear it can never be typed.
///
/// The id is what precedes the **first** `.`, which is not the same as a prefix:
/// `sess.sock` and `sess2.sock` are two sessions, and a match on `starts_with` would
/// have one of them collect the other's files. A name with no `.` at all is nobody's.
///
/// It is validated before it is handed back: every caller derives a path, a probe or a
/// signal from what this returns, and these bytes came out of a directory rather than
/// out of a client [`is_valid_session_id`] has already refused (§ 6.3).
pub(crate) fn session_id_of(path: &Path) -> Option<&str> {
    let (id, _extension) = path.file_name()?.to_str()?.split_once('.')?;
    is_valid_session_id(id).then_some(id)
}

/// Every distinct session id `dir` holds, and none at all where it cannot be read.
///
/// One entry per session, not per file (§ 6.6).
pub(crate) fn session_ids(dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut ids: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            session_id_of(&path).map(str::to_owned)
        })
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// The five names § 6.6 freezes for one session, and the id that finds whatever else
/// it has.
#[derive(Debug)]
pub(crate) struct SessionPaths {
    dir: PathBuf,
    id: String,
}

impl SessionPaths {
    /// Resolves the paths for `id`.
    ///
    /// # Errors
    ///
    /// Fails if `id` is not a valid session id, the run directory cannot be resolved,
    /// or the two together are too long to name a socket. Validation happens here
    /// rather than at each use so no caller can build a path from an unchecked id.
    pub(crate) fn new(id: &str) -> io::Result<Self> {
        if !is_valid_session_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid session id {id:?}: expected 1..=64 bytes of [A-Za-z0-9_-], \
                     not starting with -"
                ),
            ));
        }
        let dir = run_dir()?;
        // A valid id is not enough: `sun_path` is 108 bytes including its terminator,
        // and a 64-byte id under a deep enough run directory overruns it. Why that is
        // refused here rather than at the `bind`, and why against `.label` rather than
        // `.sock`, are both § 6.3's — what it buys this crate is that no `SessionPaths`
        // that exists can fail to build its own address.
        let longest = dir.as_os_str().len() + "/".len() + id.len() + ".label".len();
        if longest > SUN_PATH_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "session id {id:?} is too long for {}: the run files need {longest} bytes \
                     of the {SUN_PATH_MAX} a unix socket path allows",
                    dir.display()
                ),
            ));
        }
        Ok(Self {
            dir,
            id: id.to_owned(),
        })
    }

    /// The session id.
    #[must_use]
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Creates the run directory with owner-only permissions, and refuses one that
    /// is not this user's alone.
    ///
    /// # Errors
    ///
    /// See [`ensure_dir_at`], which is where the whole of this lives so that it can
    /// be tested against a directory of the test's choosing.
    pub(crate) fn ensure_dir(&self) -> io::Result<()> {
        ensure_dir_at(&self.dir)
    }

    /// Establishes the same property as [`Self::ensure_dir`] on a directory that is
    /// already there, creating nothing.
    ///
    /// For `kill`, which must not bring a run directory into existence as a side
    /// effect of being told to remove a session from it. It is the same property and
    /// not a weaker one, so a mode is repaired here exactly as [`check_run_dir`]
    /// repairs it anywhere else: § 6.3 states `0700` as the layout's rather than the
    /// user's, and a read-only path that left the directory at a mode every creating
    /// path tightens would only postpone the repair by one command.
    ///
    /// # Errors
    ///
    /// See [`check_run_dir`]. An absent directory arrives as
    /// [`io::ErrorKind::NotFound`], which is the answer "no such session" rather
    /// than a failure.
    pub(crate) fn check_dir(&self) -> io::Result<()> {
        check_run_dir(&self.dir)
    }

    fn with_extension(&self, extension: &str) -> PathBuf {
        self.dir.join(format!("{}.{extension}", self.id))
    }

    /// Unix socket the daemon listens on.
    #[must_use]
    pub(crate) fn socket(&self) -> PathBuf {
        self.with_extension("sock")
    }

    /// Daemon pid, ASCII, newline-terminated.
    #[must_use]
    pub(crate) fn pid(&self) -> PathBuf {
        self.with_extension("pid")
    }

    /// `flock` target serialising daemon spawn.
    #[must_use]
    pub(crate) fn lock(&self) -> PathBuf {
        self.with_extension("lock")
    }

    /// Advisory UTF-8 display label.
    #[must_use]
    pub(crate) fn label(&self) -> PathBuf {
        self.with_extension("label")
    }

    /// Writes the display label, if `label` has anything left after sanitising.
    ///
    /// Advisory throughout: a failure here costs `list` a column and nothing else, so
    /// the caller is expected to ignore the error rather than refuse a session over it.
    ///
    /// # Errors
    ///
    /// Propagates failures to create or write the file.
    pub(crate) fn write_label(&self, label: &str) -> io::Result<()> {
        let label = sanitize_label(label);
        if label.is_empty() {
            return Ok(());
        }
        write_private(&self.label(), label.as_bytes())
    }

    /// Records the pid `nomux kill` will signal, at a mode its owner can read back
    /// ([`write_private`]): `kill` refuses to unlink a live session whose pid it
    /// cannot read, correctly, so a pidfile left at `0266` by an odd umask is a
    /// session nobody can stop until somebody notices and `chmod`s it.
    ///
    /// The file is created and filled a syscall apart, which `control::kill` knows
    /// about: it waits out a zero-length pidfile rather than reporting the corrupt
    /// one it would otherwise see.
    ///
    /// [`parse_pid`] is the other half of this, and is in this module for that reason:
    /// the pidfile's *format* belongs to the frozen layout, as `<id>.label`'s does.
    pub(crate) fn write_pid(&self) -> io::Result<()> {
        write_private(&self.pid(), format!("{}\n", std::process::id()).as_bytes())
    }

    /// Removes the pidfile a previous incarnation of this id left behind.
    ///
    /// For the daemon, at the point where it has established that no live one is on
    /// the socket — `daemon::bind_socket` says why that is the moment. Absent is a
    /// state `control::resolve` already waits out; stale is the one it cannot tell
    /// from current.
    pub(crate) fn clear_pid(&self) {
        drop(fs::remove_file(self.pid()));
    }

    /// `ssh-agent` socket, served for a session created with
    /// [`nomux_proto::HELLO_AGENT_FORWARD`].
    #[must_use]
    pub(crate) fn agent(&self) -> PathBuf {
        self.with_extension("agent")
    }

    /// Takes the spawn lock, waiting for whoever holds it.
    ///
    /// # Errors
    ///
    /// Reports [`io::ErrorKind::ResourceBusy`] for the two ways a blocking
    /// [`Self::acquire`] comes back empty-handed. Neither is the caller's fault and
    /// neither says the lock is free, which is why the message names both rather than
    /// the first alone. A *host* that cannot provide the lock at all is still not an
    /// error — see [`SpawnLock`].
    pub(crate) fn lock_spawn(&self) -> io::Result<SpawnLock> {
        self.acquire(FlockOperation::LockExclusive).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ResourceBusy,
                format!(
                    "the spawn lock for session {} could not be taken: it kept being \
                     removed, or the descriptors and lock records it takes to hold one \
                     have run out",
                    self.id
                ),
            )
        })
    }

    /// Takes the spawn lock if it is free this instant, for callers with better
    /// things to do than wait.
    ///
    /// `None` is "not this time" and nothing more, in [`Self::acquire`]'s three
    /// readings. Everything that is a property of the *host* rather than of this moment
    /// comes back as a [`SpawnLock`] instead, which is where that policy is argued.
    pub(crate) fn try_lock_spawn(&self) -> Option<SpawnLock> {
        self.acquire(FlockOperation::NonBlockingLockExclusive)
    }

    /// Locks `<id>.lock` and confirms that what got locked is still that file.
    ///
    /// `None` is "not this time", in one of three readings the callers need not tell
    /// apart, since each answers all three the same way — wait, skip, or refuse:
    /// somebody else is holding the lock, the file at the path was replaced under this
    /// call more often than [`LOCK_ATTEMPTS`] allows for, or the descriptors and lock
    /// records it takes to ask have run out. [`SpawnLock::unavailable`] is kept for the
    /// failures [`no_lock_here`] names and for no others.
    fn acquire(&self, operation: FlockOperation) -> Option<SpawnLock> {
        let path = self.lock();
        for _ in 0..LOCK_ATTEMPTS {
            // At exactly [`FILE_MODE`], which is the constant this file is documented
            // around: a lock left at `0400` is a mutex every later process is shut
            // out of.
            let opened = with_umask(FILE_MODE, || {
                rustix::fs::open(
                    &path,
                    OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC,
                    Mode::from_bits_truncate(FILE_MODE),
                )
            });
            let fd = match opened {
                Ok(fd) => fd,
                // Only a failure of the *file* licenses proceeding without a lock, and
                // [`no_lock_here`] is the whole of that list.
                Err(err) => return no_lock_here(err).then(SpawnLock::unavailable),
            };
            loop {
                match rustix::fs::flock(&fd, operation) {
                    // A signal landing on a blocking `flock` is not an answer about
                    // the lock; ask again.
                    Err(rustix::io::Errno::INTR) => {}
                    Ok(()) => break,
                    // `ENOLCK` is `EMFILE`'s counterpart one syscall later, and has a
                    // second reading this cannot tell from it: a mount whose `flock`
                    // goes to a lock manager that is not answering says `ENOLCK` too,
                    // and that one *is* a host with no lock to give. Settled toward
                    // `None` because that is the reading that claims nothing —
                    // [`SpawnLock`] may only proceed where no other process here can be
                    // holding the lock, and out of lock records does not establish that.
                    Err(rustix::io::Errno::WOULDBLOCK | rustix::io::Errno::NOLCK) => return None,
                    // The same division as the `open` above, and the arm that carries
                    // it here is the filesystem which does not implement `flock` at all.
                    Err(err) => return no_lock_here(err).then(SpawnLock::unavailable),
                }
            }
            let lock = SpawnLock { fd: Some(fd) };
            if lock.locks_the_file_at(&path) {
                return Some(lock);
            }
            // Collection removed the file while this call was waiting for it, so what
            // is held now is an inode nobody else can reach ([`SpawnLock`]). Go back
            // for the file that is actually there.
        }
        None
    }

    /// Removes every file belonging to this session, ignoring absences.
    ///
    /// `lock` is never read: it is the caller's standing to remove `<id>.lock` along
    /// with the rest, which is [`SpawnLock`]'s argument and not this function's.
    ///
    /// # Errors
    ///
    /// The first failure that is not an absence, once every path has been tried.
    /// § 6.6 says why absence is success here and why anything else has to reach
    /// `kill` rather than be swallowed.
    pub(crate) fn unlink_all_locked(&self, _lock: &SpawnLock) -> io::Result<()> {
        // Every path is attempted before the first failure is returned: they are
        // independent, and stopping at one would leave the rest of a session behind.
        let mut failure = Ok(());
        for path in self.removal_order() {
            if let Err(err) = fs::remove_file(path)
                && err.kind() != io::ErrorKind::NotFound
                && failure.is_ok()
            {
                failure = Err(err);
            }
        }
        failure
    }

    /// Every `<id>.*` in the run directory, in the order [`Self::unlink_all_locked`]
    /// removes them.
    ///
    /// Split out so that the order can be asserted directly, rather than through a
    /// test that has to win a race against a live preemption to see anything.
    ///
    /// The four named files lead, and are attempted whatever the directory says: a
    /// `read_dir` this call could not make is not a session with nothing left to
    /// remove, and answering it with an empty list would turn the one failure § 6.6
    /// insists is reported — the unlink itself — into a silent success. What the scan
    /// adds is every *other* name sharing the id, which is [`session_id_of`]'s argument
    /// seen from the collecting end.
    fn removal_order(&self) -> Vec<PathBuf> {
        let lock = self.lock();
        let mut order = vec![self.socket(), self.pid(), self.label(), self.agent()];
        if let Ok(entries) = fs::read_dir(&self.dir) {
            for entry in entries.filter_map(Result::ok) {
                let path = entry.path();
                if session_id_of(&path) == Some(self.id.as_str())
                    && path != lock
                    && !order.contains(&path)
                {
                    order.push(path);
                }
            }
        }
        // `<id>.lock` last, and the ordering is load-bearing rather than tidy: the
        // instant that name is gone the caller's lock guards nothing ([`SpawnLock`]),
        // so the unlinks still to come here land on a session somebody else has
        // legitimately brought up in the meantime. Two of them are silent when that
        // happens — `<id>.label` costs the new session its column in `list`, and
        // `<id>.agent` is the live socket the child's `SSH_AUTH_SOCK` points at, so
        // its agent forwarding dies for the whole life of the session with nothing
        // said.
        order.push(lock);
        order
    }

    /// Removes every file belonging to this session, if the spawn lock is free.
    ///
    /// For the daemon's own shutdown, which holds nothing. An attach may be waiting on
    /// `<id>.lock` at this very moment — this daemon's exit is what it is about to
    /// discover — so the files are left alone rather than removed from under it. That
    /// costs little: the attach finds a socket whose `connect` is refused, which it
    /// already treats as stale and replaces. Waiting for the lock instead would park
    /// the daemon's exit behind that attach's spawn timeout.
    pub(crate) fn unlink_all(&self) {
        if let Some(lock) = self.try_lock_spawn() {
            drop(self.unlink_all_locked(&lock));
        }
    }
}

/// Whether `err` says the spawn lock cannot be taken by *anybody*, which is the only
/// reading [`SpawnLock::unavailable`]'s argument holds for.
///
/// A whitelist rather than "everything that is not a descriptor limit", because that
/// argument is about the *file* — a mode nobody can open, a uid nothing here may write
/// as, an `flock` the filesystem does not implement — and several errnos are about the
/// *moment* instead. `ENOSPC` and `EDQUOT` are the sharp case: they can only be met
/// where `<id>.lock` does not exist, which is precisely the collection race of § 6.3 —
/// another process holding a lock on the inode that has just been unlinked — so
/// answering "nobody can be holding this" there is how two spawners come to hold a
/// mutex each.
const fn no_lock_here(err: rustix::io::Errno) -> bool {
    use rustix::io::Errno;

    matches!(err, Errno::ACCESS | Errno::PERM | Errno::OPNOTSUPP)
}

/// A caller's exclusive standing on one session id: the right to spawn a daemon
/// into it, and to remove its files.
///
/// Normally that is an exclusive `flock` on `<id>.lock`, released when this is dropped.
/// It serialises two attaches racing to create the same session (`IMPLEMENTATION.md`
/// § 6.3) and — less obviously — either of them against the garbage collection of
/// § 6.6, which removes `<id>.lock` along with the rest of the session. Both must take
/// it, because a file that is unlinked while it is locked stops being a mutex at all:
/// the next process to ask creates a new file at the same path, locks that, and both
/// are then certain they hold the only lock there is.
///
/// It also stands for the *absence* of a lock, on a host that has none to give —
/// `<id>.lock` is at a mode nobody can open, or the filesystem rejects `flock` on it
/// outright. Proceeding without one there is deliberate: a lock this process cannot
/// obtain by any means is one no other process here can be holding either, since every
/// one of them reaches it through [`SessionPaths::acquire`], on the same file, under
/// the same uid — so refusing would buy nothing and would cost the § 6.6 escape hatch
/// its ability to collect a session that is genuinely dead. What that rests on is a
/// failure of the *file*, and [`no_lock_here`] is the list of errnos that are one.
#[derive(Debug)]
pub(crate) struct SpawnLock {
    /// The locked descriptor: `close(2)` on it is what releases the lock, so it is
    /// held for that. `None` where there was no lock to be had.
    fd: Option<OwnedFd>,
}

impl SpawnLock {
    /// The strongest claim available on a host that cannot lock at all.
    const fn unavailable() -> Self {
        Self { fd: None }
    }

    /// Whether this holds a lock on the file that is at `path` now.
    ///
    /// `flock` attaches to the inode rather than to the name, so this is the only
    /// way to tell a lock on the spawn mutex from a lock on what used to be it.
    /// Every failure — no lock at all, an unreadable descriptor, a path that is
    /// gone — answers "no", which is the safe direction: the caller goes round
    /// again instead of acting on a lock it may not hold. The first of those cannot
    /// arise from the one caller, and is still what reads `fd`, which is otherwise
    /// held only for its `Drop`.
    fn locks_the_file_at(&self, path: &Path) -> bool {
        let Some(fd) = self.fd.as_ref() else {
            return false;
        };
        let (Ok(held), Ok(named)) = (rustix::fs::fstat(fd), rustix::fs::stat(path)) else {
            return false;
        };
        held.st_dev == named.st_dev && held.st_ino == named.st_ino
    }
}

/// Drops every character that would let text say one thing and mean another once a
/// terminal draws it.
///
/// One function for both surfaces that print text somebody else chose, because both
/// are terminals: `list` writes a label to the operator's, and `crate::syslog` hands a
/// line to a journal that is read on one.
///
/// Dropped rather than escaped, so nothing supplied here can occupy width at all.
/// Most of category `Cf` is kept on purpose — ZWJ and ZWNJ are how Indic scripts and
/// emoji sequences are spelled — and what goes is the two classes [`is_deceptive`]
/// names, which are not text in that sense.
pub(crate) fn sanitize_text(text: &str) -> String {
    text.chars().filter(|ch| !is_deceptive(*ch)).collect()
}

/// Whether `ch` can make a run of text read as something other than its contents.
///
/// `char::is_control` is category `Cc` alone, and both additions here are `Cf`, so
/// every one of them passes it: the bidi overrides, one of which reverses the whole run
/// after it (the Trojan Source class), and the tag characters, which are a copy of
/// printable ASCII that renders as nothing. The two tests named for them run each.
const fn is_deceptive(ch: char) -> bool {
    ch.is_control()
        || matches!(ch,
            '\u{61c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
            | '\u{e0000}'..='\u{e007f}')
}

/// Trims a client-supplied label to what the frozen layout permits: one line of
/// printable UTF-8, at most [`MAX_LABEL_LEN`] bytes.
///
/// The label is a tab title chosen by a human, so it arrives with whatever they typed
/// in it — [`sanitize_text`] is what takes the `ESC ]0;` that would retitle the window
/// of whoever ran `list` back out. Truncation is at a character boundary, so the result
/// is always valid UTF-8.
pub(crate) fn sanitize_label(label: &str) -> String {
    let mut out = sanitize_text(label);
    out.truncate(out.floor_char_boundary(MAX_LABEL_LEN));
    out.trim().to_owned()
}

/// Reads a bounded prefix of the regular file at `path`, and hands back what arrived.
///
/// Both files the frozen control surface reads by hand come through here —
/// `<id>.label` and `<id>.pid` — and neither is read whole. The write side bounds
/// both; the read side cannot assume it did, for the same reason [`read_label`]
/// sanitizes what it finds: this is the frozen layout (§ 6.6), so the daemon that
/// wrote the file may be any version, and a stray shell redirect into the run
/// directory is not a daemon at all. `list` and `kill` are the escape hatch that has
/// to keep working on any host, which they would not if a file somebody left there
/// decided how much memory they faulted in — nor if it could park them in a syscall
/// with no end.
///
/// Nothing but a regular file is read from, and that is what makes one read enough: a
/// regular file hands back what was asked for or reaches its end, where a FIFO hands
/// back whatever its writer has delivered so far — `"327"` ahead of `"70419\n"` is a
/// prefix [`parse_pid`] cannot tell from a whole pidfile, and `kill` would signal 327.
/// The `fstat` is what refuses that; `O_NONBLOCK` keeps the `open` of such a file from
/// waiting for a writer that never comes, the refusal being a syscall later, and
/// `O_NOFOLLOW` keeps the name from resolving somewhere else entirely.
///
/// [`crate::nbio::read`] covers the signal that would otherwise cut the read short.
/// `File` with `Take` and `read_to_end` measured 1.6 KiB of machinery this binary
/// otherwise does not link, against the § 8 budget, for two files that cannot exceed
/// a few hundred bytes worth reading.
///
/// # Errors
///
/// Propagates the `open`, so a caller can tell a file that is absent from one it may
/// not read — which is the difference between a daemon that has not published yet
/// and one `kill` must refuse to touch. Anything at the path that is not a regular
/// file is [`io::ErrorKind::InvalidInput`], which is neither of those; it is worded
/// for the one caller that reports it, `control::running_but`, which names the path
/// ahead of it as [`refuse`] does.
pub(crate) fn read_prefix<'a>(path: &Path, buf: &'a mut [u8]) -> io::Result<&'a [u8]> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let stat = rustix::fs::fstat(&fd)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "it is not a regular file, so a read of it is a prefix rather than a body",
        ));
    }
    let read = crate::nbio::read(fd.as_fd(), buf)?;
    Ok(buf.get(..read).unwrap_or(&[]))
}

/// Reads a session's label, bounded by what the layout permits.
///
/// Anything unreadable is an empty label, invalid UTF-8 included: a listing that names
/// the session and its pid is worth more than one that fails over a decoration.
pub(crate) fn read_label(path: &Path) -> String {
    // One byte past the cap, so a label written at exactly [`MAX_LABEL_LEN`] still
    // arrives whole and a longer one is visibly over.
    let mut buf = [0u8; MAX_LABEL_LEN + 1];
    let body = read_prefix(path, &mut buf).unwrap_or(&[]);
    sanitize_label(str::from_utf8(body).unwrap_or(""))
}

/// The pidfile's on-disk contract (§ 6.6): what [`SessionPaths::write_pid`] puts there,
/// read back.
///
/// Here rather than beside the two modes that act on the number, because the *format* is
/// the frozen layout's. What stays with the caller is the policy: what to say when this,
/// the only witness § 6.6 has, cannot be believed.
///
/// Zero and negatives are refused rather than passed on: `kill(2)` reads those as a whole
/// process group and as every process the caller may signal, so a pidfile holding one is a
/// number that must never reach a signal.
///
/// A body that filled the reader's buffer is refused for the sharper reason § 6.6 gives —
/// it is the prefix of a file whose end was never seen, so a number still running at the
/// last byte is a truncation of somebody else's pid, and what the prefix cannot settle it
/// does not get to answer. The layout puts a pid and a newline there, eleven bytes at the
/// widest, so nothing legitimate reaches the bound.
pub(crate) fn parse_pid(body: &[u8]) -> Option<i32> {
    if body.len() >= MAX_PID_LEN {
        return None;
    }
    str::from_utf8(body)
        .ok()?
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|pid| *pid > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use crate::scratch::Scratch;

    /// The permission bits as they are on disk, never as the symlink pointing at it
    /// would report them.
    fn mode_of(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn a_run_directory_is_created_owner_only_and_then_accepted_as_it_stands() {
        let root = Scratch::new("rundir-new");
        let dir = root.join("nomux/run");

        ensure_dir_at(&dir).unwrap();
        assert_eq!(mode_of(&dir), DIR_MODE, "created owner-only");
        assert_eq!(
            mode_of(&root.join("nomux")),
            DIR_MODE,
            "and so is the parent it had to create on the way"
        );

        // The second call is the one every attach after the first makes.
        ensure_dir_at(&dir).unwrap();
        assert_eq!(mode_of(&dir), DIR_MODE);
    }

    /// Neither a symlink nor a plain file is a run directory, and the symlink is the
    /// one that mattered: anything that answers it by mode rather than by refusal
    /// resolves the path, and so tightens whatever it points at — another user's
    /// directory — before filling that with the session's sockets.
    #[test]
    fn a_symlink_or_a_file_in_place_of_the_run_directory_is_refused() {
        let root = Scratch::new("rundir-symlink");
        let target = root.dir("elsewhere");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o777)).unwrap();
        let dir = root.join("nomux");
        std::os::unix::fs::symlink(&target, &dir).unwrap();

        let err = ensure_dir_at(&dir).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotADirectory, "{err}");
        assert!(
            err.to_string().contains(&dir.display().to_string()),
            "the refusal must name the path: {err}"
        );
        assert!(
            err.to_string().contains("it is a symlink"),
            "and say which of the two it is: {err}"
        );
        assert_eq!(
            mode_of(&target),
            0o777,
            "the target's mode was never ours to change"
        );

        let file = root.join("file");
        fs::write(&file, b"").unwrap();
        let err = ensure_dir_at(&file).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotADirectory, "{err}");
        assert!(err.to_string().contains("it is not a directory"), "{err}");
    }

    /// Three answers for one field, separated by what can still be done about the
    /// mode: repaired wherever the owner can open the directory, refused where group
    /// or other can write to it, and refused where nobody can open it at all. The
    /// three loops below are those three answers; [`check_run_dir`] argues them.
    #[test]
    fn a_run_directory_mode_is_repaired_where_it_can_be_and_refused_where_it_cannot() {
        let root = Scratch::new("rundir-mode");
        let dir = root.join("nomux");
        ensure_dir_at(&dir).unwrap();

        for loose in [0o755, 0o750, 0o701, 0o600, 0o500, 0o400, 0o2700, 0o1700] {
            fs::set_permissions(&dir, fs::Permissions::from_mode(loose)).unwrap();
            assert_eq!(mode_of(&dir), loose, "the fixture must take");
            ensure_dir_at(&dir).unwrap();
            assert_eq!(mode_of(&dir), DIR_MODE, "mode {loose:o} should be repaired");
        }

        for shared in [0o770, 0o702] {
            fs::set_permissions(&dir, fs::Permissions::from_mode(shared)).unwrap();
            let err = ensure_dir_at(&dir).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
            assert!(
                err.to_string()
                    .contains("lets other users create files in it"),
                "the refusal must say which loosening it is: {err}"
            );
            assert_eq!(
                mode_of(&dir),
                shared,
                "mode {shared:o} is refused, not repaired"
            );
        }

        for shut in [0o300, 0o200, 0o000] {
            fs::set_permissions(&dir, fs::Permissions::from_mode(shut)).unwrap();
            let err = ensure_dir_at(&dir).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
            assert!(
                err.to_string()
                    .contains(&format!("mode {shut:o} does not let its owner open it")),
                "a refusal on the mode must be reported as one rather than as a \
                 failed syscall: {err}"
            );
            assert_eq!(mode_of(&dir), shut, "mode {shut:o} is left as it stands");
        }
    }

    /// The owner check needs no second uid and no mock as an ordinary user: every Linux
    /// host has readable directories belonging to root, and the check returns before
    /// anything is created or any mode changed — which is what makes the target being
    /// untouched an assertion here rather than a hope. As root it makes one instead of
    /// standing down, since standing down reports as a pass on the hosts CI runs on.
    #[test]
    fn a_run_directory_owned_by_another_uid_is_refused() {
        let us = rustix::process::getuid();
        let root = Scratch::new("rundir-uid");
        let theirs: PathBuf = if us.is_root() {
            let dir = root.dir("somebody-else");
            // `nobody` on every distribution this could run on, and it does not have
            // to exist as an account: the check compares numbers.
            rustix::fs::chown(
                &dir,
                Some(rustix::fs::Uid::from_raw(65_534)),
                Some(rustix::fs::Gid::from_raw(65_534)),
            )
            .expect("hand a directory of ours to another uid");
            dir
        } else {
            ["/usr/lib", "/usr", "/etc"]
                .into_iter()
                .map(Path::new)
                .find(|path| {
                    fs::metadata(path).is_ok_and(|meta| meta.is_dir() && meta.uid() != us.as_raw())
                })
                .unwrap_or_else(|| panic!("no readable directory of another uid to test against"))
                .to_path_buf()
        };

        let before = mode_of(&theirs);
        let err = ensure_dir_at(&theirs).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        assert!(err.to_string().contains("it belongs to uid"), "{err}");
        assert_eq!(
            mode_of(&theirs),
            before,
            "somebody else's directory was never ours to repair"
        );
    }

    /// A `SessionPaths` over a directory of the test's choosing, since
    /// [`SessionPaths::new`] resolves one from the environment and every assertion about
    /// *collection* is about what is in a directory rather than which one it is.
    fn paths_in(dir: &Path, id: &str) -> SessionPaths {
        SessionPaths {
            dir: dir.to_path_buf(),
            id: id.to_owned(),
        }
    }

    /// `<id>.lock` is removed last ([`SessionPaths::removal_order`]), over the whole
    /// `<id>.*` glob and not only over the five names — which is the half that could
    /// regress silently.
    #[test]
    fn the_spawn_lock_is_the_last_file_removed() {
        let root = Scratch::new("rundir-order");
        let dir = root.path();
        let paths = paths_in(dir, "tab_7");
        for name in ["tab_7.sock", "tab_7.pid", "tab_7.lock", "tab_7.quota"] {
            fs::write(dir.join(name), b"").unwrap();
        }

        let order = paths.removal_order();
        assert_eq!(
            order.last(),
            Some(&paths.lock()),
            "the lock must outlive every file it protects"
        );
        let mut distinct = order.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), order.len(), "nothing is removed twice");
        for named in [
            paths.socket(),
            paths.pid(),
            paths.label(),
            paths.agent(),
            paths.lock(),
        ] {
            assert!(
                order.contains(&named),
                "{} is still removed",
                named.display()
            );
        }
        assert!(
            order.contains(&dir.join("tab_7.quota")),
            "a name this build has never heard of is still this session's: {order:?}"
        );
    }

    /// The glob is what a *later* version's sixth file rests on, and the id it globs on
    /// is what keeps it off a neighbour's: everything under `tab_7.` goes and nothing
    /// else does, however much of the name it shares.
    #[test]
    fn collection_takes_every_name_this_id_has_and_no_neighbours() {
        let root = Scratch::new("rundir-glob");
        let dir = root.path();
        let mine = [
            "tab_7.sock",
            "tab_7.pid",
            "tab_7.lock",
            "tab_7.label",
            "tab_7.agent",
            // The sixth name, and a seventh with a suffix of its own.
            "tab_7.journal",
            "tab_7.ring.0",
        ];
        let theirs = [
            // A different session whose id merely begins the same way.
            "tab_72.sock",
            "tab_72.lock",
            // A name with no extension at all belongs to no session.
            "tab_7",
        ];
        for name in mine.into_iter().chain(theirs) {
            fs::write(dir.join(name), b"").unwrap();
        }

        paths_in(dir, "tab_7")
            .unlink_all_locked(&SpawnLock::unavailable())
            .unwrap();

        let mut left: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort_unstable();
        let mut expected: Vec<String> = theirs.iter().map(|name| (*name).to_owned()).collect();
        expected.sort_unstable();
        assert_eq!(left, expected, "collection reached past its own id");
    }

    /// A `read_dir` that fails is not a session with nothing left to remove: the glob
    /// made the list of paths depend on a directory scan, and a scan that came back
    /// empty would have `unlink_all_locked` remove nothing and report the success § 6.6
    /// says it may not report without establishing.
    #[test]
    fn a_directory_that_will_not_read_still_removes_the_names_it_knows() {
        let root = Scratch::new("rundir-unreadable");
        let dir = root.dir("shut");
        fs::write(dir.join("tab_7.sock"), b"").unwrap();
        // Searchable but not readable: the four named paths still resolve, and
        // `read_dir` does not.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o300)).unwrap();

        let paths = paths_in(&dir, "tab_7");
        assert!(
            fs::read_dir(&dir).is_err(),
            "the fixture must take, or this asserts nothing"
        );
        paths
            .unlink_all_locked(&SpawnLock::unavailable())
            .expect("the named files are removable whatever the scan could do");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            !dir.join("tab_7.sock").exists(),
            "the five named paths are attempted whatever the directory says"
        );
    }

    #[test]
    fn session_ids_accept_minted_forms() {
        assert!(is_valid_session_id("a"));
        assert!(is_valid_session_id("6f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8"));
        assert!(is_valid_session_id("tab_7"));
        assert!(is_valid_session_id(&"x".repeat(MAX_SESSION_ID_LEN)));
    }

    /// The leading `-` belongs with the traversal cases because it is the same kind of
    /// refusal: an id the filesystem would take and no command line can carry, so
    /// minting one mints a session nothing can ever reach.
    #[test]
    fn session_ids_reject_what_no_path_or_command_line_can_carry() {
        for id in [
            "",
            ".",
            "..",
            "/",
            "a/b",
            "../etc/passwd",
            "a.b",
            "a b",
            "a\0b",
            "-",
            "-abc123",
            "--label",
        ] {
            assert!(!is_valid_session_id(id), "should reject {id:?}");
        }
    }

    #[test]
    fn session_ids_reject_oversized_and_non_ascii() {
        assert!(!is_valid_session_id(&"x".repeat(MAX_SESSION_ID_LEN + 1)));
        assert!(!is_valid_session_id("café"));
        assert!(!is_valid_session_id("🦀"));
    }

    /// The bound held against the document rather than against itself.
    ///
    /// The three above pass at whatever value the constant happens to hold. It matters
    /// because the far end is a separate codebase built from the document, and § 6.3
    /// says "Both ends validate: the client before minting", so a re-tune here mints ids
    /// the daemon refuses. The number is written out by hand, since it has to come from
    /// the document rather than from the code under test.
    #[test]
    fn the_session_id_bound_is_the_one_the_document_gives() {
        assert_eq!(
            MAX_SESSION_ID_LEN, 64,
            "MAX_SESSION_ID_LEN is {MAX_SESSION_ID_LEN}, and IMPLEMENTATION.md § 6.3 caps a \
             session id at 64 bytes"
        );
    }

    /// The name-to-id rule, at the boundaries the glob turns on.
    #[test]
    fn a_run_file_names_the_session_it_belongs_to() {
        for (name, id) in [
            ("tab_7.sock", Some("tab_7")),
            ("tab_7.lock", Some("tab_7")),
            // The name this build has never heard of, which is the point of the glob.
            ("tab_7.whatever-comes-next", Some("tab_7")),
            // Up to the *first* dot: a neighbour is not a prefix.
            ("tab_72.sock", Some("tab_72")),
            ("tab_7.ring.0", Some("tab_7")),
            ("tab_7.", Some("tab_7")),
            // The name is what is read, wherever the entry was resolved from.
            ("/run/user/1000/nomux/tab_7.sock", Some("tab_7")),
            // No extension is no session.
            ("tab_7", None),
            // Ids the layout could never have written.
            (".hidden", None),
            ("..sock", None),
            ("has space.sock", None),
        ] {
            assert_eq!(
                session_id_of(Path::new(name)),
                id,
                "the session {name:?} belongs to"
            );
        }
        // Past the 64 bytes § 6.3 allows, which `is_valid_session_id` is what refuses.
        let long = format!("{}.sock", "x".repeat(65));
        assert_eq!(session_id_of(Path::new(&long)), None);
    }

    /// The pidfile's format, at the bound the refusal quotes.
    #[test]
    fn a_pidfile_body_parses_only_where_the_read_saw_all_of_it() {
        assert_eq!(parse_pid(b"1234\n"), Some(1234));
        assert_eq!(parse_pid(b"  1234  "), Some(1234));
        assert_eq!(parse_pid(b"0\n"), None);
        assert_eq!(parse_pid(b"-1\n"), None);
        assert_eq!(parse_pid(b"nonsense"), None);
        assert_eq!(parse_pid(b""), None);
        // The truncation this bound exists for: padded so the number straddles the end
        // of the read, the prefix is a smaller, plausible, live pid.
        let padded = format!("{}{}\n", " ".repeat(25), 32_770_419);
        assert_eq!(
            parse_pid(padded.get(..MAX_PID_LEN).unwrap().as_bytes()),
            None,
            "a prefix ending mid-number is not the number in the file"
        );
        assert_eq!(
            parse_pid(padded.as_bytes()),
            None,
            "and neither is a body that reached the bound at all"
        );
    }

    #[test]
    fn invalid_ids_are_refused_before_any_path_is_built() {
        for id in ["../etc/passwd", "a/b", "", "."] {
            let err = SessionPaths::new(id).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "id {id:?}");
        }
    }

    /// The frozen layout: five siblings in one directory, sharing the id as stem
    /// and differing only by extension. Asserted without mutating the process
    /// environment, so it stays valid under any test harness.
    #[test]
    fn paths_are_siblings_sharing_the_id_stem() {
        let paths = SessionPaths::new("tab_7").unwrap();
        let expected = [
            (paths.socket(), "sock"),
            (paths.pid(), "pid"),
            (paths.lock(), "lock"),
            (paths.label(), "label"),
            (paths.agent(), "agent"),
        ];
        let parent = paths.socket().parent().map(Path::to_path_buf).unwrap();
        assert!(parent.ends_with("nomux") || parent.ends_with("nomux/run"));

        for (path, extension) in expected {
            assert_eq!(path.parent().unwrap(), parent, "{extension} is a sibling");
            assert_eq!(path.file_stem().unwrap(), "tab_7");
            assert_eq!(path.extension().unwrap(), extension);
        }
    }

    #[test]
    fn labels_lose_control_characters_and_surrounding_space() {
        assert_eq!(sanitize_label("  build  "), "build");
        assert_eq!(sanitize_label("two\nlines"), "twolines");
        assert_eq!(sanitize_label("\u{1b}]0;pwned\u{7}"), "]0;pwned");
        assert_eq!(sanitize_label("\t\n"), "");
    }

    /// The bidi overrides are `Cf` rather than `Cc`, so they went straight through the
    /// filter above and out to the terminal `list` prints on — in a column the user
    /// reads to decide which session to kill.
    #[test]
    fn labels_lose_the_bidi_controls_that_are_not_control_characters() {
        assert_eq!(sanitize_label("build\u{202e}gnp."), "buildgnp.");
        for sneaky in [
            '\u{61c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}',
            '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        ] {
            assert!(
                !sneaky.is_control(),
                "{sneaky:?} would already be dropped, so it says nothing about this"
            );
            assert_eq!(
                sanitize_label(&format!("a{sneaky}b")),
                "ab",
                "{sneaky:?} reached the terminal"
            );
        }
        // Either side of the three ranges, so the filter is not simply eating `Cf`.
        // That it is not is the decision [`sanitize_text`] argues: ZWJ and ZWNJ are
        // `Cf` and are how correctly typed labels are spelled, so the line is drawn at
        // the classes that reorder or hide rather than around the category.
        assert_eq!(
            sanitize_label("\u{61b}a\u{2065}a\u{206a}"),
            "\u{61b}a\u{2065}a\u{206a}"
        );
        assert_eq!(sanitize_label("a\u{200d}b\u{200c}c"), "a\u{200d}b\u{200c}c");
    }

    /// U+E0020..=U+E007F encode printable ASCII in codepoints that render as nothing,
    /// so a label that `list` prints as `build` can carry an entire second string
    /// behind it — invisible in the listing and plainly there in whatever pastes it.
    #[test]
    fn labels_lose_the_tag_characters_that_render_as_nothing() {
        let hidden: String = " rm -rf ~"
            .chars()
            .filter_map(|ch| char::from_u32(0xE_0000 + u32::from(ch)))
            .collect();
        assert_eq!(hidden.chars().count(), 9, "the fixture must encode as tags");
        assert_eq!(sanitize_label(&format!("build{hidden}")), "build");

        for sneaky in ['\u{e0000}', '\u{e0001}', '\u{e0020}', '\u{e007f}'] {
            assert!(
                !sneaky.is_control(),
                "{sneaky:?} would already be dropped, so it says nothing about this"
            );
            assert_eq!(
                sanitize_label(&format!("a{sneaky}b")),
                "ab",
                "{sneaky:?} reached the terminal"
            );
        }
        // Either side of the block, for the same reason as above.
        assert_eq!(sanitize_label("\u{dffff}a\u{e0080}"), "\u{dffff}a\u{e0080}");
    }

    /// Truncation must not split a character, or `list` would print a replacement
    /// glyph for a label the user typed correctly.
    #[test]
    fn labels_are_truncated_on_a_character_boundary() {
        let long = "é".repeat(MAX_LABEL_LEN);
        let cut = sanitize_label(&long);
        assert_eq!(cut.len(), MAX_LABEL_LEN, "should fill the budget exactly");
        assert_eq!(cut.chars().count(), MAX_LABEL_LEN / 2);

        let odd = format!("{}€", "x".repeat(MAX_LABEL_LEN - 1));
        assert_eq!(sanitize_label(&odd).len(), MAX_LABEL_LEN - 1);
    }
}
