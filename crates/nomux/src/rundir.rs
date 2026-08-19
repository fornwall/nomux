//! Run-directory layout.
//!
//! This layout is the frozen contract described in `IMPLEMENTATION.md` § 6.6:
//! `list` and `kill` operate on it alone, never on the session protocol, so any
//! build can manage a daemon of any version. Filenames and permissions here may
//! never change.

use std::io::{self, Write as _};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::{env, fs};

use rustix::fs::{FlockOperation, Mode, OFlags};

use crate::sanitize::{MAX_LABEL_LEN, sanitize_label};
use crate::usock::SUN_PATH_MAX;

/// Permissions for the run directory: owner-only, since it holds the sockets that
/// grant access to live sessions.
const DIR_MODE: u32 = 0o700;

/// Permissions for every socket inside it.
const SOCKET_MODE: u32 = 0o600;

/// Permissions for the three plain files: the pidfile, the label and the spawn lock.
/// Exact rather than umask-derived: a `<id>.lock` its own uid cannot open later is one
/// nothing can lock, which [`SessionPaths::try_lock_spawn_or_refuse`] refuses outright.
const FILE_MODE: u32 = 0o600;

/// How many times an acquirer takes the lock before giving up — the first attempt and
/// one re-take, for finding that the file it locked is no longer the file at the path.
const LOCK_ATTEMPTS: usize = 2;
const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Runs `f` with the umask suppressed, so a node created at `mode` gets exactly `mode`.
///
/// `mkdir(2)`, `bind(2)` and `open(2)` subtract the caller's umask, making their mode
/// argument an upper bound rather than a request — and every mode in this module is exact.
/// Creating and then `chmod`ing would narrow the window rather than close it, on a path
/// that is being raced.
///
/// The umask is process-wide; no shipped caller is multi-threaded or spawns while it is in
/// effect, and `scratch::umask_lock` closes that for `cargo test`, which is.
fn with_umask<T>(mode: u32, f: impl FnOnce() -> T) -> T {
    #[cfg(test)]
    let _umask = crate::scratch::umask_lock();
    let previous = rustix::process::umask(Mode::from_bits_truncate(0o777 & !mode));
    let result = f();
    rustix::process::umask(previous);
    result
}

/// Replaces `path` with `body`, at exactly [`FILE_MODE`].
///
/// Removed first because `O_TRUNC` keeps an existing file's mode; created with `O_EXCL`
/// so a name planted between the two syscalls — by a *parent* this process does not own,
/// § 6.3's concession — is refused rather than written through, never retried. `write_all`,
/// so a body cut short is a failure and not a success that left a prefix ([`parse_pid`]).
fn write_private(path: &Path, body: &[u8]) -> io::Result<()> {
    drop(fs::remove_file(path));
    let file = with_umask(FILE_MODE, || {
        rustix::fs::open(
            path,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_bits_truncate(FILE_MODE),
        )
    })?;
    fs::File::from(file).write_all(body)
}

/// Binds a non-blocking unix socket at exactly [`SOCKET_MODE`].
pub(crate) fn bind_socket_private(path: &Path) -> io::Result<UnixListener> {
    let listener = with_umask(SOCKET_MODE, || UnixListener::bind(path))?;
    if let Err(err) = listener.set_nonblocking(true) {
        drop(listener);
        drop(fs::remove_file(path));
        return Err(err);
    }
    Ok(listener)
}

/// Longest `<id>.pid` body anything reads (§ 6.6). A pid and its newline are eleven
/// bytes at the widest, so a body reaching this bound is a file whose end was never
/// seen, which [`parse_pid`] refuses.
pub(crate) const MAX_PID_LEN: usize = 32;

/// Longest session id, in bytes (§ 6.3).
pub(crate) const MAX_SESSION_ID_LEN: usize = 64;

/// The longer of the two extensions this layout binds a socket at, `.sock` being the
/// other. What [`SessionPaths::in_dir`] measures an id against: only socket names are
/// under [`SUN_PATH_MAX`], so a longer plain-file name costs nothing.
const LONGEST_SOCKET_EXT: &str = ".agent";

/// The value of environment variable `key`, but only where it names an **absolute**
/// path — the rule every directory taken from the environment obeys (§ 6.3, and § 6.2
/// has the `chdir` that makes it matter). An empty value is not absolute either.
fn absolute_env(key: &str) -> Option<std::ffi::OsString> {
    env::var_os(key).filter(|value| Path::new(value).is_absolute())
}

/// Resolves the run directory, preferring persistent per-user state.
///
/// The precedence and the reason for each half are § 6.3's, as is the rule
/// [`absolute_env`] applies to every source.
pub(crate) fn run_dir() -> io::Result<PathBuf> {
    let state = absolute_env("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| absolute_env("HOME").map(|home| PathBuf::from(home).join(".local/state")));
    if let Some(state) = state {
        return Ok(state.join("nomux/run"));
    }
    // Last resort only. `pam_systemd` removes `$XDG_RUNTIME_DIR` after the final logout,
    // including every socket below it, so choosing it while a persistent home is available
    // makes an otherwise surviving daemon unreachable at exactly the reconnect nomux exists
    // to serve.
    absolute_env("XDG_RUNTIME_DIR")
        .map(|dir| PathBuf::from(dir).join("nomux"))
        .ok_or_else(|| {
            io::Error::other(
                "none of XDG_STATE_HOME, HOME or XDG_RUNTIME_DIR names an absolute path",
            )
        })
}

/// Creates `dir` if it is absent, and refuses it if it is not this user's alone
/// ([`check_run_dir`], which runs first so a plain file at the path is reported as what
/// it is rather than as an `EEXIST` naming nothing).
pub(crate) fn ensure_run_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if check_run_dir(dir)? {
        return Ok(());
    }
    // [`with_umask`] for the parents `recursive` creates along the way as much as for the
    // directory itself: under a `umask 0500` this would otherwise make a run directory
    // its owner cannot open, and the check below would refuse what it had just made.
    with_umask(DIR_MODE, || {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(dir)
    })?;
    // Checked again rather than trusted: `recursive` reports an existing directory as
    // success, and is willing to walk whatever appeared at a missing ancestor between
    // the two checks.
    if check_run_dir(dir)? {
        return Ok(());
    }
    Err(refuse(
        dir,
        io::ErrorKind::NotFound,
        "it was removed as it was created",
    ))
}

/// Refuses a run-directory path an untrusted user can redirect after it is checked.
///
/// § 6.3's ancestor rule, and the reason there is one: the later socket and file operations
/// are path-based, Linux having no `bindat(2)`, so a final directory at 0700 is insufficient
/// when another uid can rename an ancestor or replace one with a symlink between validation
/// and use. Missing components are allowed here — the sticky parent's own child among them,
/// there being no owner to weigh before the `mkdir` — because [`ensure_run_dir`] creates them
/// and then runs this check again before returning.
fn check_trusted_ancestors(dir: &Path) -> io::Result<()> {
    let us = rustix::process::getuid().as_raw();
    let mut child_owner = fs::symlink_metadata(dir)
        .ok()
        .map(|metadata| metadata.uid());
    let mut ancestor = dir.parent();
    while let Some(path) = ancestor {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.file_type().is_dir() {
                    return Err(refuse(
                        path,
                        io::ErrorKind::NotADirectory,
                        "an ancestor is not a real directory",
                    ));
                }
                let owner = metadata.uid();
                if owner != us && owner != 0 {
                    return Err(refuse(
                        path,
                        io::ErrorKind::PermissionDenied,
                        &format!("ancestor owner uid {owner} is neither this user nor root"),
                    ));
                }
                let mode = metadata.mode();
                // The sticky bit is the one safe shared-directory exception: only the
                // child owner, directory owner or root may rename the protected entry.
                // A child that is not there yet is nothing that rule can speak for —
                // refusing it made a run directory under sticky `/tmp` impossible to
                // *create* while an existing one was accepted. The atomic `mkdir` and
                // the re-check on the entry it leaves are what catch a lost race.
                let sticky_protects_child =
                    mode & 0o1000 != 0 && child_owner.is_none_or(|owner| owner == us || owner == 0);
                if mode & 0o022 != 0 && !sticky_protects_child {
                    return Err(refuse(
                        path,
                        io::ErrorKind::PermissionDenied,
                        &format!(
                            "ancestor mode {:o} lets other users redirect the run directory",
                            mode & 0o7777
                        ),
                    ));
                }
                child_owner = Some(owner);
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(io::Error::new(
                    err.kind(),
                    format!("{}: ancestor could not be examined: {err}", path.display()),
                ));
            }
        }
        ancestor = path.parent();
    }
    Ok(())
}

/// Answers whether `dir` is a run directory of this user's alone, opening it
/// (`O_DIRECTORY | O_NOFOLLOW`, § 6.3) to find out. `false` is simply absent: no session
/// was ever created here.
///
/// The descriptor is dropped at the end and the run files go on being opened by name
/// (§ 6.3): holding it would pin the filesystem § 6.2 lets go of, which is safe only
/// because [`check_trusted_ancestors`] first proves another uid cannot redirect the path.
///
/// # Errors
///
/// Anything that is not a directory of this user's alone, at a mode its owner can open
/// and nobody else can create in.
pub(crate) fn check_run_dir(dir: &Path) -> io::Result<bool> {
    check_trusted_ancestors(dir)?;
    let fd = match rustix::fs::open(
        dir,
        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        // A missing component anywhere along the path arrives here too, and is the same
        // answer: nothing this user put there is at that name.
        Err(rustix::io::Errno::NOENT) => return Ok(false),
        Err(err) => return Err(refuse_unopenable(dir, err)),
    };

    let stat =
        rustix::fs::fstat(&fd).map_err(|err| refuse_errno(dir, err, "it could not be examined"))?;
    if stat.st_uid != rustix::process::getuid().as_raw() {
        return Err(refuse(
            dir,
            io::ErrorKind::PermissionDenied,
            &format!("it belongs to uid {}", stat.st_uid),
        ));
    }

    // Write for group or other is the one loosening that is not repairable, and so the only
    // one answered the way a wrong owner is (§ 6.3): tightening now does not un-plant what
    // somebody left there, so nothing inside is evidence of anything any more. Every other
    // mode is repaired to exactly [`DIR_MODE`].
    let mode = Mode::from_raw_mode(stat.st_mode);
    if mode.intersects(Mode::WGRP | Mode::WOTH) {
        return Err(refuse(
            dir,
            io::ErrorKind::PermissionDenied,
            &format!("mode {:o} lets other users create files in it", mode.bits()),
        ));
    }
    if mode != Mode::from_bits_truncate(DIR_MODE) {
        // Through the descriptor, never the path, which would reopen exactly the hole the
        // `O_NOFOLLOW` above closed.
        rustix::fs::fchmod(&fd, Mode::from_bits_truncate(DIR_MODE))
            .map_err(|err| refuse_errno(dir, err, "its mode could not be tightened"))?;
    }
    Ok(true)
}

/// Why the `open` in [`check_run_dir`] would not give a descriptor. One symlink probe,
/// because Linux answers `O_DIRECTORY | O_NOFOLLOW` on a symlink with `ENOTDIR` rather
/// than `ELOOP`, and the symlink is the redirect worth naming (§ 6.3).
fn refuse_unopenable(dir: &Path, err: rustix::io::Errno) -> io::Error {
    match err {
        rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP => refuse(
            dir,
            io::ErrorKind::NotADirectory,
            if fs::symlink_metadata(dir).is_ok_and(|meta| meta.file_type().is_symlink()) {
                "it is a symlink"
            } else {
                "it is not a directory"
            },
        ),
        other => refuse_errno(dir, other, "it could not be opened"),
    }
}

/// A refusal in the terms the user needs. It reaches them as `nomux: ...` on stderr and is
/// the whole account they get, so it names the path even where the errno beneath names
/// nothing.
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
/// § 6.3 has the accepted set and both bounds behind it — one the filesystem's, one the
/// command line's, `main` reading any leading-`-` argument as an option. Never sanitised
/// into something valid: rewriting an id would silently attach the user to the wrong
/// session.
fn is_valid_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_SESSION_ID_LEN
        && !id.starts_with('-')
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// A run-directory name split into session id and extension: the id is what precedes the
/// **first** `.`, and a name with no `.` is nobody's. The one rule by which anything here
/// reads a filename (§ 6.6) — its two readers are [`session_id_of`] and
/// [`SessionPaths::removal_order`].
fn split_run_name(path: &Path) -> Option<(&str, &[u8])> {
    let name = path.file_name()?.as_bytes();
    let dot = name.iter().position(|byte| *byte == b'.')?;
    Some((str::from_utf8(name.get(..dot)?).ok()?, name.get(dot + 1..)?))
}

/// The session a name in the run directory belongs to, if it belongs to one — the inverse of
/// [`SessionPaths::with_extension`], and [`split_run_name`] without the extension.
///
/// Validated before it is handed back ([`is_valid_session_id`], § 6.3): every caller derives
/// a path, a probe or a signal from it, and these bytes came out of a directory.
pub(crate) fn session_id_of(path: &Path) -> Option<&str> {
    split_run_name(path)
        .map(|(id, _)| id)
        .filter(|id| is_valid_session_id(id))
}

/// Every distinct session id `dir` holds — one entry per session, not per file (§ 6.6).
///
/// Enumeration failures are propagated rather than turned into an empty or partial list.
/// An empty answer licenses `list` to report success and startup to admit another session;
/// either claim is false when the directory was not actually read to its end.
pub(crate) fn session_ids(dir: &Path) -> io::Result<Vec<String>> {
    let mut ids = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if let Some(id) = session_id_of(&path)
            && let Err(at) = ids.binary_search_by(|known: &String| known.as_str().cmp(id))
        {
            ids.insert(at, id.to_owned());
        }
    }
    Ok(ids)
}

/// The five names § 6.6 freezes for one session, and the id that finds whatever else it has.
#[derive(Debug)]
pub(crate) struct SessionPaths {
    dir: PathBuf,
    id: String,
}

impl SessionPaths {
    /// Resolves the paths for `id` in this user's run directory.
    ///
    /// # Errors
    ///
    /// [`Self::in_dir`]'s, plus a run directory that cannot be resolved at all.
    pub(crate) fn new(id: &str) -> io::Result<Self> {
        Self::in_dir(&run_dir()?, id)
    }

    /// Resolves the paths for `id` in `dir`, for a caller that already has the run
    /// directory.
    ///
    /// # Errors
    ///
    /// Fails if `id` is not a valid session id, or if the two together are too long to
    /// name a socket. Validated here rather than at each use, so no caller can build a
    /// path from an unchecked id.
    pub(crate) fn in_dir(dir: &Path, id: &str) -> io::Result<Self> {
        if !is_valid_session_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid session id {id:?}: expected 1..=64 bytes of [A-Za-z0-9_-], \
                     not starting with -"
                ),
            ));
        }
        // Refused here rather than at the `bind`, against the longest *socket* extension
        // (§ 6.3), so no `SessionPaths` that exists can fail to build either address.
        let longest = dir.as_os_str().len() + "/".len() + id.len() + LONGEST_SOCKET_EXT.len();
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
            dir: dir.to_path_buf(),
            id: id.to_owned(),
        })
    }

    /// The session id.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// The run directory these five names are in.
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    fn with_extension(&self, extension: &str) -> PathBuf {
        self.dir.join(format!("{}.{extension}", self.id))
    }

    /// Unix socket the daemon listens on.
    pub(crate) fn socket(&self) -> PathBuf {
        self.with_extension("sock")
    }

    /// Daemon pid, ASCII, newline-terminated.
    pub(crate) fn pid(&self) -> PathBuf {
        self.with_extension("pid")
    }

    /// `flock` target serialising daemon spawn.
    pub(crate) fn lock(&self) -> PathBuf {
        self.with_extension("lock")
    }

    /// Advisory UTF-8 display label.
    pub(crate) fn label(&self) -> PathBuf {
        self.with_extension("label")
    }

    /// Writes the display label, or removes it where `label` has nothing left after
    /// sanitising — `<id>.label` outlives what wrote it ([`Self::clear_label`]).
    ///
    /// Advisory: a failure costs `list` a column and nothing else, so the caller ignores
    /// it rather than refusing a session over a decoration.
    pub(crate) fn write_label(&self, label: &str) -> io::Result<()> {
        let label = sanitize_label(label);
        if label.is_empty() {
            self.clear_label();
            return Ok(());
        }
        write_private(&self.label(), label.as_bytes())
    }

    /// Records the pid `nomux kill` will signal, through [`write_private`].
    pub(crate) fn write_pid(&self) -> io::Result<()> {
        write_private(&self.pid(), format!("{}\n", std::process::id()).as_bytes())
    }

    /// Removes the pidfile a previous incarnation of this id left behind, as
    /// [`Self::clear_label`] does the label. Apart only because [`Self::write_label`]
    /// clears the second on its own; `daemon::bind_socket` calls both, at the point where
    /// it has established no live daemon is on the socket, and says why that is the
    /// moment. Absent is a state `control::resolve` waits out; stale is the one it cannot
    /// tell from current, and a stale label answers in `list` for whoever took the id
    /// over (§ 6.6).
    pub(crate) fn clear_pid(&self) {
        drop(fs::remove_file(self.pid()));
    }

    /// The label half of [`Self::clear_pid`].
    pub(crate) fn clear_label(&self) {
        drop(fs::remove_file(self.label()));
    }

    /// `ssh-agent` socket, served for a session created with
    /// [`nomux_protocol::Hello::agent_forward`].
    pub(crate) fn agent(&self) -> PathBuf {
        self.with_extension("agent")
    }

    /// Takes the spawn lock without letting a stuck creator block every later command.
    pub(crate) fn lock_spawn_until(&self, deadline: Instant) -> io::Result<SpawnLock> {
        loop {
            if let Some(lock) = self.try_lock_spawn_or_refuse()? {
                return Ok(lock);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::ResourceBusy,
                    format!("timed out waiting for session {}'s spawn lock", self.id),
                ));
            }
            std::thread::sleep(LOCK_POLL_INTERVAL);
        }
    }

    /// [`Self::try_lock_spawn_or_refuse`] for the two opportunistic collections, which
    /// have nobody to report a refusal to and answer every failure by touching nothing.
    /// Daemon startup deliberately does not use this lossy spelling: it must either own
    /// the lock or refuse the id.
    pub(crate) fn try_lock_spawn(&self) -> Option<SpawnLock> {
        self.try_lock_spawn_or_refuse().ok().flatten()
    }

    /// Locks `<id>.lock` if it is free this instant and confirms that what got locked is
    /// still that file — for callers with better things to do than wait.
    ///
    /// `Ok(None)` is "not this time" — held by somebody else, replaced more often than
    /// [`LOCK_ATTEMPTS`] allows for, or descriptors and lock records run out — all about
    /// the *moment*, and asking again is what they earn.
    ///
    /// # Errors
    ///
    /// The failures about the *file* and the *filesystem*, still there next time: a
    /// `<id>.lock` nothing can lock, one that is no regular file, and a run directory
    /// mounted read-only. None may be answered by going ahead ([`SpawnLock`]).
    pub(crate) fn try_lock_spawn_or_refuse(&self) -> io::Result<Option<SpawnLock>> {
        let path = self.lock();
        for _ in 0..LOCK_ATTEMPTS {
            // `RDONLY`: `flock(2)` needs no access mode, and asking for write would refuse
            // a `<id>.lock` left at 0400 by a second § 6.6 implementation. `NOFOLLOW`: a
            // symlink here would lock its target while `removal_order` unlinked the link.
            // `NONBLOCK`: a FIFO planted at the name must not park the open awaiting a
            // writer.
            let reading = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
            let opened = with_umask(FILE_MODE, || {
                match rustix::fs::open(
                    &path,
                    OFlags::CREATE | OFlags::EXCL | reading,
                    Mode::from_bits_truncate(FILE_MODE),
                ) {
                    Ok(fd) => Ok((fd, true)),
                    // Open the inode that won the create race; the
                    // [`SpawnLock::locks_the_file_at`] below rejects a replaced name.
                    Err(rustix::io::Errno::EXIST) => {
                        rustix::fs::open(&path, reading, Mode::empty()).map(|fd| (fd, false))
                    }
                    Err(err) => Err(err),
                }
            });
            let (fd, created_name) = match opened {
                Ok(opened) => opened,
                // `EROFS` means the name is absent and the mount will not create it — a
                // lock already sitting there still opens and locks.
                Err(rustix::io::Errno::ROFS) => return Err(self.read_only_lock(&path)),
                // A file no process of this uid can open is a mutex nobody can hold.
                Err(err @ (rustix::io::Errno::ACCESS | rustix::io::Errno::PERM)) => {
                    return Err(self.unlockable(&path, err));
                }
                // The nodes that refuse to open at all, and so never reach the file-type
                // check below that would have named them: `NOFOLLOW` answers a symlink
                // with `ELOOP`, sockfs has no `open` and answers `ENXIO`, and a `<id>.lock`
                // below something that is not a directory answers `ENOTDIR` on the create.
                // Each describes the name as it stands rather than this instant, so
                // `Ok(None)` would send every caller off to wait out a thing that does not
                // pass: `daemon::start` would call it contention, `control::kill` would
                // spin to its deadline, and the two collections would quietly do nothing.
                Err(
                    rustix::io::Errno::LOOP | rustix::io::Errno::NXIO | rustix::io::Errno::NOTDIR,
                ) => return Err(self.not_a_lock_file(&path)),
                // The opposite reading, and the same race the retry at the bottom of this
                // loop answers from the other side: collection unlinked `<id>.lock` between
                // the create that found it and the reopen, so the name is free now and one
                // more pass creates it. A run directory that is gone rather than a file
                // fails the same way twice and leaves by the `Ok(None)` below.
                Err(rustix::io::Errno::NOENT) => continue,
                // Everything else is about this attempt rather than about the file.
                Err(_) => return Ok(None),
            };
            let stat = rustix::fs::fstat(&fd).map_err(io::Error::from)?;
            if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                != rustix::fs::FileType::RegularFile
            {
                return Err(self.not_a_lock_file(&path));
            }
            loop {
                match rustix::fs::flock(&fd, FlockOperation::NonBlockingLockExclusive) {
                    // A signal landing on a blocking `flock` is not an answer; ask again.
                    Err(rustix::io::Errno::INTR) => {}
                    Ok(()) => break,
                    // `ENOLCK` (out of lock records) is a moment; settled toward the
                    // reading that claims nothing and costs one more attempt.
                    Err(rustix::io::Errno::WOULDBLOCK | rustix::io::Errno::NOLCK) => {
                        return Ok(None);
                    }
                    // No `flock` on this filesystem: the unopenable-file verdict.
                    Err(err @ rustix::io::Errno::OPNOTSUPP) => {
                        return Err(self.unlockable(&path, err));
                    }
                    Err(_) => return Ok(None),
                }
            }
            let lock = SpawnLock { fd, created_name };
            if lock.locks_the_file_at(&path) {
                return Ok(Some(lock));
            }
            // Collection removed the file while this call waited: the held inode is
            // unreachable ([`SpawnLock`]). Go round again.
        }
        Ok(None)
    }

    /// The refusal for a `<id>.lock` that cannot be locked by anybody — § 6.3's rule that
    /// nothing here proceeds without the lock, going ahead without one being how two
    /// daemons come to claim one id and unlink each other's live sessions. Apart from
    /// [`Self::read_only_lock`] because the repairs differ, which is what the message
    /// carries: a `chmod` versus pointing `XDG_RUNTIME_DIR` at a filesystem with `flock`.
    fn unlockable(&self, path: &Path, err: rustix::io::Errno) -> io::Error {
        let err = io::Error::from(err);
        io::Error::new(
            err.kind(),
            format!(
                "session {id}: spawn lock {path} cannot be held by anybody: {err}; \
                 chmod it, or point XDG_RUNTIME_DIR at a filesystem with flock",
                id = self.id,
                path = path.display(),
            ),
        )
    }

    /// The refusal for a run directory nothing can be created in, which is a fact about
    /// the mount rather than about locking ([`Self::unlockable`]): there is no session
    /// here to start and none to remove.
    fn read_only_lock(&self, path: &Path) -> io::Error {
        let err = io::Error::from(rustix::io::Errno::ROFS);
        io::Error::new(
            err.kind(),
            format!(
                "session {id}: spawn lock {path} could not be created: {err}; the run \
                 directory is on a read-only filesystem, so point it elsewhere",
                id = self.id,
                path = path.display(),
            ),
        )
    }

    /// Refuses a directory node that cannot serve as the spawn mutex.
    ///
    /// Opened non-blocking before this check, so a FIFO, device or socket cannot turn
    /// `spawn` and the `kill` escape hatch into an unbounded syscall.
    fn not_a_lock_file(&self, path: &Path) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "session {id}: spawn lock {path} is not a regular file",
                id = self.id,
                path = path.display(),
            ),
        )
    }

    /// Adopts the locked descriptor `spawn` inherited across its daemon exec.
    ///
    /// The descriptor is the capability proving startup authority. It is re-locked
    /// non-blocking (which succeeds on the inherited open-file description), checked
    /// against the current `<id>.lock` name, and put back under `CLOEXEC` before the
    /// login shell can be spawned.
    ///
    /// `raw` must be past `STDERR_FILENO`, which `main::parse_lock_fd` is where every
    /// caller gets it from: adopting a standard stream would close it on the way out.
    pub(crate) fn inherit_spawn_lock(&self, raw: i32) -> io::Result<SpawnLock> {
        // This number came from argv, including on a direct `nomux daemon` invocation.
        // Validate it before `OwnedFd::from_raw_fd`: constructing an `OwnedFd` for a
        // closed number violates its safety contract, and its drop is an I/O-safety abort
        // rather than the ordinary `EBADF` this malformed handoff earns. A raw `fcntl`
        // is the only way to ask without first claiming the descriptor is valid. Nothing
        // can close it between this check and the ownership transfer: startup is still
        // single-threaded and neither signal handler has been armed yet.
        //
        // SAFETY: `F_GETFD` takes no third argument, treats `raw` as a number only, and
        // mutates no memory. Failure is reported through errno below.
        if unsafe { libc::fcntl(raw, libc::F_GETFD) } == -1 {
            let err = io::Error::last_os_error();
            return Err(io::Error::new(
                err.kind(),
                format!(
                    "session {id}: --lock-fd {raw} is not an open descriptor for {path}: {err}",
                    id = self.id,
                    path = self.lock().display(),
                ),
            ));
        }
        // SAFETY: `spawn` cleared `CLOEXEC` on this owned descriptor in the forked
        // child and passed its number as an argument. This process has not opened or
        // closed anything since exec that could reuse it; the raw check above established
        // that a direct caller did pass an open descriptor; and taking ownership here makes
        // this the one value that closes the inherited copy.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
        let stat = rustix::fs::fstat(&fd).map_err(io::Error::from)?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
            return Err(self.not_a_lock_file(&self.lock()));
        }
        rustix::fs::flock(&fd, FlockOperation::NonBlockingLockExclusive)
            .map_err(io::Error::from)?;
        let lock = SpawnLock {
            fd,
            // The parent owns cleanup on a failed handoff. The daemon needs only the
            // authority, not a second and necessarily racy guess at who made the name.
            created_name: false,
        };
        if !lock.locks_the_file_at(&self.lock()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "session {}: inherited lock does not name {}",
                    self.id,
                    self.lock().display()
                ),
            ));
        }
        Ok(lock)
    }

    /// Gives `<id>.lock` back after a startup that failed before the session existed —
    /// but only where `lock` is the acquisition that created the name.
    ///
    /// The rule is [`SpawnLock::created_name`]'s and the one place it is applied: a name
    /// this call did not make may be a mutex another process still has standing on, and
    /// unlinking one is how two acquirers come to hold the only lock there is. Absence is
    /// the state this is reaching for, so nothing is reported.
    pub(crate) fn release_lock_name(&self, lock: &SpawnLock) {
        if lock.created_name {
            drop(fs::remove_file(self.lock()));
        }
    }

    /// Removes every file belonging to this session, ignoring absences. `lock` is never
    /// read: it is the caller's standing to remove `<id>.lock` with the rest
    /// ([`SpawnLock`]).
    ///
    /// # Errors
    ///
    /// The first failure that is not an absence, once every path has been tried, naming
    /// the session and the file — § 6.6 says why absence is success and why anything
    /// else has to reach `kill`.
    pub(crate) fn unlink_all_locked(&self, _lock: &SpawnLock) -> io::Result<()> {
        self.unlink_locked(true)
    }

    /// Removes published session files while leaving the spawn mutex named.
    pub(crate) fn unlink_published_locked(&self, _lock: &SpawnLock) -> io::Result<()> {
        self.unlink_locked(false)
    }

    fn unlink_locked(&self, include_lock: bool) -> io::Result<()> {
        let (order, mut failure) = self.removal_order();
        let count = order.len().saturating_sub(usize::from(!include_lock));
        for path in order.into_iter().take(count) {
            if let Err(err) = remove_node(&path)
                && err.kind() != io::ErrorKind::NotFound
                && failure.is_ok()
            {
                failure = Err(io::Error::new(
                    err.kind(),
                    format!(
                        "session {id}: {path} could not be removed: {err}",
                        id = self.id,
                        path = path.display(),
                    ),
                ));
            }
        }
        failure
    }

    /// Every `<id>.*` in the run directory, in the order [`Self::unlink_all_locked`]
    /// removes them, and whether the scan that found them completed. Split out so the
    /// order can be asserted directly.
    ///
    /// The named files lead and are attempted whatever the directory says: a `read_dir`
    /// this call could not make is not a session with nothing left to remove (§ 6.6), so
    /// the incomplete scan is reported beside the list rather than instead of it. The
    /// scan adds every *other* name sharing the id.
    fn removal_order(&self) -> (Vec<PathBuf>, io::Result<()>) {
        /// The extensions the named paths already cover.
        const ALREADY: [&[u8]; 5] = [b"sock", b"pid", b"label", b"agent", b"lock"];

        let mut order = vec![self.socket(), self.pid(), self.label(), self.agent()];
        let mut failure = Ok(());
        let scan_failure = |err: io::Error| {
            io::Error::new(
                err.kind(),
                format!(
                    "session {}: {} could not be scanned: {err}",
                    self.id,
                    self.dir.display()
                ),
            )
        };
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => Some(entries),
            Err(err) => {
                failure = Err(scan_failure(err));
                None
            }
        };
        for entry in entries.into_iter().flatten() {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    if failure.is_ok() {
                        failure = Err(scan_failure(err));
                    }
                    continue;
                }
            };
            let path = entry.path();
            if split_run_name(&path)
                .is_some_and(|(id, extension)| id == self.id && !ALREADY.contains(&extension))
            {
                order.push(path);
            }
        }
        // `<id>.lock` last (§ 6.3), load-bearing: unlinks after it would land on a
        // session somebody else has legitimately brought up.
        order.push(self.lock());
        (order, failure)
    }

    /// Removes every file belonging to this session, if the spawn lock can be had this
    /// instant — the daemon's own shutdown, which holds nothing and has nobody to report
    /// to. An attach waiting on `<id>.lock` finds a refused socket and replaces it as
    /// stale; waiting for it here would park the exit behind that attach's spawn timeout.
    pub(crate) fn unlink_all(&self) {
        if let Some(lock) = self.try_lock_spawn() {
            drop(self.unlink_all_locked(&lock));
        }
    }
}

/// Removes one run file, whatever kind of node somebody left at the name. A *directory*
/// there otherwise strands the id for good — every `kill` and collection fails on the
/// same `EISDIR` — and nothing this layout writes is one, so removing it is repair;
/// `remove_dir` still refuses a non-empty one.
fn remove_node(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(err) if err.kind() == io::ErrorKind::IsADirectory => fs::remove_dir(path),
        settled => settled,
    }
}

/// A caller's exclusive standing on one session id — an exclusive `flock` on
/// `<id>.lock`, released on drop, and never anything weaker: a host that cannot give one
/// gets a refusal ([`SessionPaths::try_lock_spawn_or_refuse`]).
///
/// Collection (§ 6.6) must take it as well as a spawn (§ 6.3), because **a file unlinked
/// while it is locked stops being a mutex**: the next process to ask creates a new file at
/// the same path, locks that, and both are then certain they hold the only lock there is.
#[derive(Debug)]
pub(crate) struct SpawnLock {
    /// The locked descriptor: `close(2)` on it releases the lock, so it is held for that.
    fd: OwnedFd,
    /// Whether this acquisition created the directory entry it locked, established
    /// atomically with `O_EXCL`: a startup failure may remove the name only then —
    /// otherwise it may be a stale mutex another process still has standing on. Read
    /// only by [`SessionPaths::release_lock_name`], which is that rule.
    created_name: bool,
}

impl SpawnLock {
    /// The descriptor whose open-file description carries this lock.
    ///
    /// `spawn` inherits this exact description into the daemon, so authority crosses
    /// the exec boundary without a release/reacquire window.
    pub(crate) fn raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    /// Whether this holds a lock on the file that is at `path` now — `flock` attaches to
    /// the inode rather than to the name ([`SpawnLock`]), so nothing else can tell a lock
    /// on the spawn mutex from a lock on what used to be it.
    ///
    /// Every failure answers "no", the safe direction: the caller goes round again rather
    /// than act on a lock it may not hold.
    fn locks_the_file_at(&self, path: &Path) -> bool {
        let (Ok(held), Ok(named)) = (rustix::fs::fstat(&self.fd), rustix::fs::stat(path)) else {
            return false;
        };
        held.st_dev == named.st_dev && held.st_ino == named.st_ino
    }
}

/// Reads a bounded prefix of the regular file at `path` (§ 6.6). The `open` and a
/// part-way read propagate, so a caller can tell an absent file from one it may not read.
///
/// Reads until the file ends or `buf` is full, so what comes back is a prefix of the
/// *file* rather than of one `read(2)` — § 6.3's fallback run directory is under `$HOME`,
/// which is NFS or FUSE often enough — and a body that reached the bound is exactly a
/// file with more in it ([`parse_pid`], `control::unidentified`).
///
/// A FIFO is refused rather than read short: it answers `EAGAIN` with no file end to
/// reach, and its `open` would wait for a writer. Anything that is not a regular file is
/// [`io::ErrorKind::InvalidData`] and never `InvalidInput`, which `main::report` scores
/// as § 10's 64 for an id that could never have named a session.
pub(crate) fn read_prefix<'a>(path: &Path, buf: &'a mut [u8]) -> io::Result<&'a [u8]> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let stat = rustix::fs::fstat(&fd)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "it is not a regular file, so a read of it is a prefix rather than a body",
        ));
    }
    let mut filled = 0;
    while filled < buf.len() {
        let read = crate::nbio::read(fd.as_fd(), buf.get_mut(filled..).unwrap_or(&mut []))?;
        if read == 0 {
            break;
        }
        // Clamped like every returned count in this tree: a count past what was asked for
        // would slice out of bounds, and this binary is built `panic = "abort"`.
        filled = filled.saturating_add(read).min(buf.len());
    }
    Ok(buf.get(..filled).unwrap_or(&[]))
}

/// Reads a session's label, bounded by what the layout permits.
///
/// Anything unreadable is an empty label: a listing that names the session and its pid is
/// worth more than one that fails over a decoration. Bad UTF-8 is replaced rather than
/// dropped, since a read cut at the bound can split a character — [`sanitize_label`] keeps
/// this daemon's own writes off that edge, but the file may be anybody's.
pub(crate) fn read_label(path: &Path) -> String {
    let mut buf = [0u8; MAX_LABEL_LEN];
    let body = read_prefix(path, &mut buf).unwrap_or(&[]);
    sanitize_label(&String::from_utf8_lossy(body))
}

/// The pidfile's on-disk contract (§ 6.6): what [`SessionPaths::write_pid`] puts there,
/// read back.
///
/// Zero and negatives are refused: `kill(2)` reads those as a process group and as every
/// process the caller may signal. The **newline is required**, and so is a body short of
/// [`MAX_PID_LEN`] — § 6.6 has why a pidfile cut off mid-number must never parse.
pub(crate) fn parse_pid(body: &[u8]) -> Option<i32> {
    if body.len() >= MAX_PID_LEN || !body.ends_with(b"\n") {
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
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use crate::scratch::{Scratch, mode_of};

    #[test]
    fn a_run_directory_is_created_owner_only_and_then_accepted_as_it_stands() {
        let root = Scratch::new("rundir-new");
        let dir = root.join("nomux/run");

        ensure_run_dir(&dir).unwrap();
        assert_eq!(mode_of(&dir), DIR_MODE, "created owner-only");
        assert_eq!(
            mode_of(&root.join("nomux")),
            DIR_MODE,
            "and so is the parent it had to create on the way"
        );

        // The second call is the one every attach after the first makes.
        ensure_run_dir(&dir).unwrap();
        assert_eq!(mode_of(&dir), DIR_MODE);
    }

    /// Checking only the final 0700 directory is a path race: another uid able to rename
    /// its parent can replace the checked name before a later bind or unlink follows it.
    #[test]
    fn a_run_directory_below_a_shared_ancestor_is_refused() {
        let root = Scratch::new("rundir-shared-parent");
        let shared = root.dir("shared");
        let dir = shared.join("private");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();

        let err = check_run_dir(&dir).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        assert!(
            err.to_string().contains("redirect the run directory"),
            "the refusal must explain why the final directory's mode is insufficient: {err}"
        );
        assert!(
            ensure_run_dir(&dir).is_err(),
            "creation and the read-only list/attach/kill check must share the refusal"
        );

        // Leave cleanup able to traverse the fixture even under a restrictive umask.
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// § 6.3's one shared-directory exception, taken where it used to fail: the entry a
    /// sticky parent protects has no owner to weigh until the `mkdir` makes it, and
    /// seeding the ancestor check from the missing one refused *creation* under `/tmp`,
    /// `/var/tmp` or `/dev/shm` while accepting a directory already there — a permanent
    /// 126 `unsafe-host` on every host whose `XDG_STATE_HOME` points into one, and one
    /// the client caches per host. The other fixtures pre-create the entry, which is
    /// exactly why they never saw it, so this one creates nothing.
    #[test]
    fn a_run_directory_is_created_under_a_sticky_parent_and_its_entry_is_still_weighed() {
        let root = Scratch::new("rundir-sticky");
        let shared = root.dir("shared");
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
        assert_eq!(mode_of(&shared), 0o1777, "the fixture must take");
        let dir = shared.join("nomux/run");

        ensure_run_dir(&dir).unwrap();
        assert_eq!(mode_of(&dir), DIR_MODE, "created owner-only");
        ensure_run_dir(&dir).unwrap();
        assert!(
            check_run_dir(&dir).unwrap(),
            "and the read-only check agrees"
        );

        // The sticky bit buys the entry nothing: the post-create check still governs it,
        // so a mode letting others create inside is refused exactly as under any parent.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        let err = ensure_run_dir(&dir).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        assert!(
            err.to_string()
                .contains("lets other users create files in it"),
            "{err}"
        );
        fs::set_permissions(&dir, fs::Permissions::from_mode(DIR_MODE)).unwrap();

        // A name somebody else planted first is refused rather than followed, which is
        // the answer to losing the `mkdir` race the leniency above allows.
        let planted = shared.join("planted");
        std::os::unix::fs::symlink(&dir, &planted).unwrap();
        let err = ensure_run_dir(&planted).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotADirectory, "{err}");
        assert!(err.to_string().contains("it is a symlink"), "{err}");

        // And an entry belonging to another uid — the race in its plainest form. Only
        // root can hand one away; as an ordinary user say so, since a silent skip is a
        // pass nobody can see.
        if rustix::process::getuid().is_root() {
            rustix::fs::chown(&dir, Some(rustix::fs::Uid::from_raw(65_534)), None)
                .expect("hand the created entry to another uid");
            let err = ensure_run_dir(&dir).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
            rustix::fs::chown(&dir, Some(rustix::process::getuid()), None)
                .expect("take it back, so the fixture can be removed");
        } else {
            eprintln!(
                "partially skipped: only root can give the created entry to another uid, \
                 so the planted symlink above stands for that half"
            );
        }

        // Leave cleanup able to traverse the fixture even under a restrictive umask.
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// Neither a symlink nor a plain file is a run directory, and the symlink is the one
    /// that matters: resolving it would tighten and then fill another user's directory.
    #[test]
    fn a_symlink_or_a_file_in_place_of_the_run_directory_is_refused() {
        let root = Scratch::new("rundir-symlink");
        let target = root.dir("elsewhere");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o777)).unwrap();
        let dir = root.join("nomux");
        std::os::unix::fs::symlink(&target, &dir).unwrap();

        let err = ensure_run_dir(&dir).unwrap_err();
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
        let err = ensure_run_dir(&file).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotADirectory, "{err}");
        assert!(err.to_string().contains("it is not a directory"), "{err}");
    }

    /// Three answers for one field, separated by what can still be done about the
    /// mode; the three loops below are those answers and [`check_run_dir`] argues them.
    #[test]
    fn a_run_directory_mode_is_repaired_where_it_can_be_and_refused_where_it_cannot() {
        let root = Scratch::new("rundir-mode");
        let dir = root.join("nomux");
        ensure_run_dir(&dir).unwrap();

        for loose in [0o755, 0o750, 0o701, 0o600, 0o500, 0o400, 0o2700, 0o1700] {
            fs::set_permissions(&dir, fs::Permissions::from_mode(loose)).unwrap();
            assert_eq!(mode_of(&dir), loose, "the fixture must take");
            ensure_run_dir(&dir).unwrap();
            assert_eq!(mode_of(&dir), DIR_MODE, "mode {loose:o} should be repaired");
        }

        for shared in [0o770, 0o702] {
            fs::set_permissions(&dir, fs::Permissions::from_mode(shared)).unwrap();
            let err = ensure_run_dir(&dir).unwrap_err();
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
            let err = ensure_run_dir(&dir).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
            assert!(
                err.to_string().contains("it could not be opened"),
                "a mode its owner cannot open is refused, naming the directory: {err}"
            );
            assert_eq!(mode_of(&dir), shut, "mode {shut:o} is left as it stands");
        }
    }

    /// As an ordinary user, a readable root-owned directory is the fixture; as root —
    /// where standing down would report as a pass on CI — one is made and chowned away.
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
        let err = ensure_run_dir(&theirs).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        assert!(err.to_string().contains("it belongs to uid"), "{err}");
        assert_eq!(
            mode_of(&theirs),
            before,
            "somebody else's directory was never ours to repair"
        );
    }

    /// `<id>.lock` is removed last ([`SessionPaths::removal_order`]), over the whole
    /// `<id>.*` glob and not only over the five names.
    #[test]
    fn the_spawn_lock_is_the_last_file_removed() {
        let root = Scratch::new("rundir-order");
        let dir = root.path();
        let paths = SessionPaths::in_dir(dir, "tab_7")
            .expect("a directory of the test's own naming a session");
        for name in ["tab_7.sock", "tab_7.pid", "tab_7.lock", "tab_7.quota"] {
            fs::write(dir.join(name), b"").unwrap();
        }

        let (order, scanned) = paths.removal_order();
        scanned.expect("scan the run directory");
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

    /// Everything under `tab_7.` goes and nothing else does, however much of the name a
    /// neighbour shares.
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
        let opaque = OsString::from_vec(b"tab_7.\xff".to_vec());
        fs::write(dir.join(&opaque), b"").expect("plant a non-UTF-8 session file");

        let paths = SessionPaths::in_dir(dir, "tab_7")
            .expect("a directory of the test's own naming a session");
        // The real standing rather than a stand-in: there is only one way to hold this
        // now, and it is the same call every collection makes.
        let lock = paths
            .try_lock_spawn()
            .expect("the spawn lock, in a directory of this test's own");
        paths.unlink_all_locked(&lock).unwrap();
        assert!(
            !dir.join(&opaque).exists(),
            "an opaque extension is still below the validated ASCII id"
        );

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

        let paths = SessionPaths::in_dir(&dir, "tab_7")
            .expect("a directory of the test's own naming a session");
        // Taken before the assertion below, and it is what says the mode is the
        // *scan* rather than everything: `0300` is searchable and writable, so
        // `<id>.lock` is created and locked exactly as it always is.
        let lock = paths
            .try_lock_spawn()
            .expect("a directory with no read permission is still one to take the lock in");
        assert!(
            fs::read_dir(&dir).is_err(),
            "the fixture must take, or this asserts nothing"
        );
        let err = paths
            .unlink_all_locked(&lock)
            .expect_err("an incomplete scan must be reported");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            !dir.join("tab_7.sock").exists(),
            "the five named paths are attempted whatever the directory says"
        );
    }

    /// A `<id>.lock` nothing can open is a session nothing can serialise, refused rather
    /// than proceeded past. Stands down as root, where a mode keeps nobody out of their
    /// own file — visibly, since a skip nobody can see is a pass.
    #[test]
    fn a_lock_nobody_can_open_is_refused_rather_than_proceeded_past() {
        if rustix::process::getuid().is_root() {
            eprintln!(
                "skipped as root: a mode keeps nobody out of their own lock file, so there \
                 is no unlockable lock to refuse"
            );
            return;
        }
        let root = Scratch::new("rundir-nolock");
        let paths = SessionPaths::in_dir(root.path(), "tab_7")
            .expect("a directory of the test's own naming a session");
        fs::write(paths.lock(), b"").unwrap();
        fs::set_permissions(paths.lock(), fs::Permissions::from_mode(0o000)).unwrap();

        let err = paths
            .try_lock_spawn_or_refuse()
            .expect_err("a lock that cannot be opened is not a lock that is merely busy");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        assert!(
            err.to_string().contains("cannot be held by anybody")
                && err.to_string().contains("tab_7.lock"),
            "the refusal must say that nothing can hold it and name the file, that being \
             the whole of what anyone can repair: {err}"
        );
        assert!(
            paths.try_lock_spawn().is_none(),
            "and the spelling with nobody to report to gives the id up rather than \
             inventing a standing it does not have"
        );
    }

    /// The nodes whose `open` fails outright, which the file-type check cannot answer
    /// because it never gets the descriptor to judge. They are as permanent as the FIFO
    /// that check does catch, and read as a moment instead they are worse than useless:
    /// `daemon::start` reports the id as one another process is starting, `control::kill`
    /// spins to its grace deadline and blames contention, and the two collections remove
    /// nothing and have nobody to say so to.
    #[test]
    fn a_lock_that_will_not_open_at_all_is_refused_rather_than_waited_out() {
        fn refuses(paths: &SessionPaths, planted: &str) {
            let err = paths
                .try_lock_spawn_or_refuse()
                .expect_err("a lock name that cannot be opened is not one that is busy");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{planted}: {err}");
            assert!(
                err.to_string().contains("session tab_7")
                    && err.to_string().contains("tab_7.lock")
                    && err.to_string().contains("is not a regular file"),
                "{planted}: the refusal must name the session and the file, and say what \
                 is wrong with it: {err}"
            );
            assert!(
                paths.try_lock_spawn().is_none(),
                "{planted}: the spelling with nobody to report to still takes no standing"
            );
        }

        let root = Scratch::new("rundir-lock-node");
        let paths = SessionPaths::in_dir(root.path(), "tab_7")
            .expect("a directory of the test's own naming a session");

        // `ELOOP`, from the `NOFOLLOW` that is there so a link cannot have the lock taken
        // on its target while `removal_order` unlinks the link itself.
        let target = root.join("elsewhere");
        fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, paths.lock()).unwrap();
        refuses(&paths, "a symlink");
        fs::remove_file(paths.lock()).unwrap();

        // `ENXIO`: sockfs implements no `open`, so a socket node yields no descriptor at
        // all rather than one `fstat` can turn away.
        let socket = UnixListener::bind(paths.lock()).expect("plant a socket at the lock name");
        refuses(&paths, "a socket");
        drop(socket);
        fs::remove_file(paths.lock()).unwrap();

        // `ENOTDIR`, which arrives on the create rather than the reopen: the run
        // directory is a plain file, so no name below it can ever resolve.
        let file = root.join("notdir");
        fs::write(&file, b"").unwrap();
        let below = SessionPaths::in_dir(&file, "tab_7").expect("resolve paths below a plain file");
        refuses(&below, "a name below a plain file");
    }

    /// A startup that failed gives back only the `<id>.lock` it made itself. Both callers
    /// — `daemon::start` on a refused ring or bind, and `attach::create` on a launcher
    /// that started nothing — reach the rule through [`SessionPaths::release_lock_name`],
    /// and the second of the two used to remove the name whoever it was. Unlinking a
    /// mutex somebody else created is how two acquirers come to hold the only lock there
    /// is, so the distinction is the whole of what this function is.
    #[test]
    fn only_the_acquisition_that_made_the_lock_name_gives_it_back() {
        let root = Scratch::new("rundir-lock-name");
        let paths = SessionPaths::in_dir(root.path(), "tab_7").expect("resolve paths");

        let made = paths.try_lock_spawn().expect("create and hold the lock");
        paths.release_lock_name(&made);
        assert!(
            !paths.lock().exists(),
            "the acquisition that created the name is the one that may take it away"
        );
        drop(made);

        // Somebody else's `<id>.lock`, which this acquisition finds rather than creates.
        fs::write(paths.lock(), b"").expect("plant a lock file");
        let found = paths.try_lock_spawn().expect("hold the planted lock");
        paths.release_lock_name(&found);
        assert!(
            paths.lock().exists(),
            "a name this acquisition did not make may be a mutex another process still \
             has standing on, so a failed startup leaves it exactly where it is"
        );
    }

    /// A `--lock-fd` this daemon cannot adopt is a bad *descriptor* and never a bad id:
    /// § 10 reserves [`io::ErrorKind::InvalidInput`] to [`SessionPaths::in_dir`], since
    /// `main::report` scores it as the 64 a client caches as its own typo. It also has to
    /// say what it was refusing, as every other refusal here does: this one reached the
    /// user as a bare `Bad file descriptor` naming neither the session nor the file.
    #[test]
    fn a_malformed_lock_fd_is_never_reported_as_a_malformed_id() {
        let root = Scratch::new("rundir-inherit");
        let paths = SessionPaths::in_dir(root.path(), "tab_7").expect("resolve paths");

        let err = paths
            .inherit_spawn_lock(i32::MAX)
            .expect_err("a closed number is no capability");
        assert_ne!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
        let text = err.to_string();
        assert!(
            text.contains("session tab_7")
                && text.contains("tab_7.lock")
                && text.contains(&format!("os error {}", libc::EBADF)),
            "the refusal must name the session, the file it was for, and the errno: {err}"
        );
    }

    #[test]
    fn waiting_for_a_held_spawn_lock_is_bounded() {
        let root = Scratch::new("rundir-lock-timeout");
        let paths = SessionPaths::in_dir(root.path(), "tab_7").expect("resolve paths");
        let held = paths.try_lock_spawn().expect("hold the lock");

        let err = paths
            .lock_spawn_until(Instant::now() + Duration::from_millis(20))
            .expect_err("a held lock must time out");
        assert_eq!(err.kind(), io::ErrorKind::ResourceBusy);

        drop(held);
        paths
            .lock_spawn_until(Instant::now() + Duration::from_secs(1))
            .expect("take the released lock");
    }

    /// The leading `-` belongs with the traversal cases because it is the same kind of
    /// refusal: an id the filesystem would take and no command line can carry, so
    /// minting one mints a session nothing can ever reach.
    #[test]
    fn session_ids_take_the_minted_forms_and_nothing_a_path_or_argv_could_not_carry() {
        for (id, valid) in [
            ("a", true),
            ("6f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8", true),
            ("tab_7", true),
            ("", false),
            (".", false),
            ("..", false),
            ("/", false),
            ("a/b", false),
            ("../etc/passwd", false),
            ("a.b", false),
            ("a b", false),
            ("a\0b", false),
            ("-", false),
            ("-abc123", false),
            ("--label", false),
            ("café", false),
            ("🦀", false),
        ] {
            assert_eq!(is_valid_session_id(id), valid, "id {id:?}");
        }
        assert!(is_valid_session_id(&"x".repeat(MAX_SESSION_ID_LEN)));
        assert!(!is_valid_session_id(&"x".repeat(MAX_SESSION_ID_LEN + 1)));
    }

    #[test]
    fn session_ids_are_sorted_and_deduplicated() {
        let root = Scratch::new("rundir-session-ids");
        for name in ["z.pid", "a.sock", "z.label", "m.agent", "a.lock", "invalid"] {
            fs::write(root.join(name), []).unwrap();
        }
        assert_eq!(session_ids(root.path()).unwrap(), ["a", "m", "z"]);
    }

    /// The bound held against the document rather than against itself: the client is a
    /// separate codebase built from § 6.3, so a re-tune here mints ids the daemon
    /// refuses.
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
        let opaque = PathBuf::from(OsString::from_vec(b"tab_7.\xff".to_vec()));
        assert_eq!(
            session_id_of(&opaque),
            Some("tab_7"),
            "only the id has to be UTF-8; an opaque suffix must not escape its cleanup"
        );
    }

    /// The pidfile's format, at the bound the refusal quotes and at the newline that says
    /// the file ends where the number does.
    #[test]
    fn a_pidfile_body_parses_only_where_the_read_saw_all_of_it() {
        assert_eq!(parse_pid(b"1234\n"), Some(1234));
        assert_eq!(parse_pid(b" 1234 \n"), Some(1234));
        assert_eq!(parse_pid(b"0\n"), None);
        assert_eq!(parse_pid(b"-1\n"), None);
        assert_eq!(parse_pid(b"nonsense\n"), None);
        assert_eq!(parse_pid(b""), None);
        // The short write, which is the same hazard as the truncated read one file
        // shorter: `"3277"` of `"32770419\n"` is a smaller, plausible, live pid, and the
        // missing newline is the whole of what tells it from a pidfile.
        assert_eq!(parse_pid(b"3277"), None);
        assert_eq!(parse_pid(b"  1234  "), None);
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

    /// Something that is not a regular file is refused as bad *data*, never as bad
    /// input: `main::report` scores [`io::ErrorKind::InvalidInput`] as § 10's 64, which
    /// a client caches as its own typo — and the id here is perfectly good.
    #[test]
    fn a_run_file_that_is_not_a_regular_file_is_not_a_usage_error() {
        let root = Scratch::new("rundir-fifo");
        let path = root.join("pid");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &path,
            rustix::fs::FileType::Fifo,
            Mode::from_bits_truncate(FILE_MODE),
            0,
        )
        .expect("plant a FIFO where a run file should be");
        let mut buf = [0u8; MAX_PID_LEN];
        let err = read_prefix(&path, &mut buf).expect_err("a FIFO is no run file");
        assert_eq!(
            err.kind(),
            io::ErrorKind::InvalidData,
            "an unreadable run file is not an id the client should stop retrying"
        );
    }

    /// A body longer than one `read(2)` still arrives whole: nothing lost, doubled or
    /// transposed on its way into the buffer.
    #[test]
    fn a_body_longer_than_one_read_still_arrives_whole() {
        let root = Scratch::new("rundir-longbody");
        let path = root.join("body");
        // Not a repeated byte: a chunk lost, doubled or delivered out of order would
        // pass a comparison against one of those.
        let written: Vec<u8> = (0..64u32 * 1024)
            .map(|n| u8::try_from(n % 251).unwrap())
            .collect();
        fs::write(&path, &written).unwrap();
        let mut buf = vec![0u8; written.len() + 1];
        assert_eq!(
            read_prefix(&path, &mut buf).unwrap(),
            written,
            "the file must arrive exactly as it was written"
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

    /// § 6.3's concession about a *parent* this process does not own: a name still at
    /// the path when `O_EXCL` decides is refused with `EEXIST`, never written through.
    /// A directory stands in for the raced plant, being the one node
    /// [`write_private`]'s leading unlink cannot clear.
    #[test]
    fn a_name_planted_at_the_pidfile_is_refused_rather_than_written_through() {
        let root = Scratch::new("rundir-plant");
        let paths = SessionPaths::in_dir(root.path(), "tab_7")
            .expect("a directory of the test's own naming a session");
        fs::create_dir(paths.pid()).unwrap();

        let err = paths.write_pid().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{err}");

        fs::remove_dir(paths.pid()).unwrap();
        paths.write_pid().unwrap();
        assert_eq!(
            fs::read(paths.pid()).unwrap(),
            format!("{}\n", std::process::id()).into_bytes(),
            "the ordinary write still lands once the name is clear"
        );
        assert_eq!(mode_of(&paths.pid()), FILE_MODE, "at the frozen mode");
    }
}
