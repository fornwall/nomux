//! Run-directory layout.
//!
//! This layout is the frozen contract described in `IMPLEMENTATION.md` § 6.6:
//! `list` and `kill` operate on it alone, never on the session protocol, so any
//! build can manage a daemon of any version. Filenames and permissions here may
//! never change.

use std::io::{self, Write as _};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
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
///
/// Owner-only like everything else here, and exact for the same reason. The directory
/// already keeps other users out, so what this buys is not secrecy but a mode that does not
/// depend on the umask of whoever created the file: a `<id>.lock` no *later* process can
/// open is one [`no_lock_here`] answers true for, and the mutex the whole control surface
/// rests on then belongs to nobody.
const FILE_MODE: u32 = 0o600;

/// How many times an acquirer will re-take the lock on finding that the file it locked is
/// no longer the file at the path. Each retry costs some other process a whole
/// collection, so a second is already a machine looping on `nomux list`.
const LOCK_ATTEMPTS: usize = 2;

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

/// Replaces `path` with `body`, at exactly [`FILE_MODE`], in one `write`.
///
/// Removed first because a mode argument applies only to a file the call creates: `O_TRUNC`
/// onto one already there keeps the mode it arrived with, and for `<id>.pid` that mode can
/// be one its own owner cannot read, which is a session `kill` will not touch.
///
/// *Created* rather than opened, `O_EXCL` refusing a symlink at the name outright: the
/// removal above opens a window in which a *parent* this process does not own — § 6.3's,
/// there being no `bindat(2)` — can plant one, and a create that followed it would write
/// the pidfile into whatever it named. The `EEXIST` that flag introduces is refused rather
/// than retried, since the only legitimate writer of these names is the daemon holding the
/// id and looping would race whoever is planting rather than win.
fn write_private(path: &Path, body: &[u8]) -> io::Result<()> {
    drop(fs::remove_file(path));
    // The unlink above and the create below are two syscalls on one name, so the test for
    // losing that race has to be forced inside the window.
    #[cfg(test)]
    tests::plant_in_the_window(path);
    let file = with_umask(FILE_MODE, || {
        rustix::fs::open(
            path,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_bits_truncate(FILE_MODE),
        )
    })?;
    fs::File::from(file).write_all(body)
}

/// Binds a unix socket at exactly [`SOCKET_MODE`], never briefly wider ([`with_umask`]).
pub(crate) fn bind_socket_private(path: &Path) -> io::Result<UnixListener> {
    with_umask(SOCKET_MODE, || UnixListener::bind(path))
}

/// Longest `<id>.pid` body anything reads (§ 6.6), the slack past a pid and a newline
/// being room for whatever whitespace a file repaired by hand carries. What a body that
/// reaches it means is [`parse_pid`]'s; `pub(crate)` because `control`'s refusal quotes
/// the number.
pub(crate) const MAX_PID_LEN: usize = 32;

/// Longest session id, in bytes (§ 6.3).
///
/// Beside the layout that turns one into a filename rather than on the wire, which § 2.2
/// keeps the id out of. `pub(crate)` because `control` sizes its `/proc/<pid>/cmdline`
/// prefix against it.
pub(crate) const MAX_SESSION_ID_LEN: usize = 64;

/// The value of environment variable `key`, but only where it names an **absolute**
/// path.
///
/// The rule every directory this binary takes from the environment obeys: a source that
/// does not name an absolute path is not a source, and an empty value is not absolute
/// either. § 6.3 has why, and § 6.2 has the `chdir` that makes it matter.
fn absolute_env(key: &str) -> Option<std::ffi::OsString> {
    env::var_os(key).filter(|value| Path::new(value).is_absolute())
}

/// Resolves the run directory, preferring `XDG_RUNTIME_DIR`.
///
/// The precedence and the reason for each half are § 6.3's, as is the rule
/// [`absolute_env`] applies to every source.
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
/// That it exists says nothing about *what* exists, which is [`check_run_dir`]'s half.
/// That check runs first, so the ordinary case costs one `open` and one `fstat`, and a
/// plain file at the path is reported as what it is rather than as an `EEXIST` naming
/// nothing.
pub(crate) fn ensure_run_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match check_run_dir(dir) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        settled => return settled,
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
    // success, so what this "created" may be another attach's — or, under a parent
    // somebody else can write to, what they left there between the two checks.
    check_run_dir(dir)
}

/// Opens `dir` as itself and establishes that it belongs to this user alone.
///
/// `O_DIRECTORY` and `O_NOFOLLOW` do most of the work (§ 6.3), leaving this the owner and
/// who else may create names in it. The file type is the kernel's answer rather than a
/// second `fstat` of ours, which could disagree with the descriptor it describes.
///
/// The descriptor is dropped at the end and the run files go on being opened by name
/// (§ 6.3), deliberately: holding it would pin the filesystem § 6.2 lets go of. What is
/// established is one link — nobody but this uid can put a name in *this* directory — and
/// every component above it is trusted, a gap `DESIGN.md` § 8 states rather than closes.
///
/// # Errors
///
/// Fails if `dir` is not a directory, is a symlink, belongs to another uid, is one group
/// or other can write to, or is in a mode its owner cannot open. Simply absent arrives as
/// [`io::ErrorKind::NotFound`], which the control surface reads as an answer rather than a
/// failure: no session was ever created here.
pub(crate) fn check_run_dir(dir: &Path) -> io::Result<()> {
    let fd = rustix::fs::open(
        dir,
        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|err| match err {
        // Linux answers `O_DIRECTORY | O_NOFOLLOW` on a symlink with `ENOTDIR` rather than
        // the `ELOOP` the manual page leads one to expect, so telling the two apart means
        // asking again — worth an `lstat` paid only on the way to failing, since "it is a
        // symlink" is the sentence that tells somebody what to do about it.
        rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP => refuse(
            dir,
            io::ErrorKind::NotADirectory,
            match fs::symlink_metadata(dir) {
                Ok(meta) if meta.file_type().is_symlink() => "it is a symlink",
                _ => "it is not a directory",
            },
        ),
        // A mode its own owner cannot open is the one tightening that cannot be repaired
        // (§ 6.3), and is a judgement on the mode rather than on the syscall, so it is
        // reported as one. The fallback arm is a searchless parent rather than this
        // directory having answered `EACCES`.
        rustix::io::Errno::ACCESS => match fs::symlink_metadata(dir) {
            // Somebody else's, at a mode that keeps us out: the § 8 threat, reachable with
            // `XDG_RUNTIME_DIR` pointed into a shared parent. The uid is the whole
            // sentence — naming the mode would report `0700`, the expected one, as the
            // fault.
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
    Ok(())
}

/// A refusal in the terms the user needs: which directory, what is wrong with it, and what
/// it was supposed to be. It reaches them as `nomux: ...` on stderr and is the whole
/// account they get, so it names the path even where the errno beneath names nothing.
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

/// The session a name in the run directory belongs to, if it belongs to one.
///
/// The inverse of [`SessionPaths::with_extension`], and the one rule by which anything here
/// learns an id from a directory rather than from a caller — the glob § 6.6 rests growth on,
/// so the id is what precedes the **first** `.` and a name with no `.` is nobody's.
///
/// Validated before it is handed back ([`is_valid_session_id`], § 6.3): every caller derives
/// a path, a probe or a signal from it, and these bytes came out of a directory.
pub(crate) fn session_id_of(path: &Path) -> Option<&str> {
    let (id, _extension) = path.file_name()?.to_str()?.split_once('.')?;
    is_valid_session_id(id).then_some(id)
}

/// Every distinct session id `dir` holds — one entry per session, not per file (§ 6.6) —
/// and none at all where it cannot be read.
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

/// The five names § 6.6 freezes for one session, and the id that finds whatever else it has.
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
    /// Fails if `id` is not a valid session id, the run directory cannot be resolved, or
    /// the two together are too long to name a socket. Validated here rather than at each
    /// use, so no caller can build a path from an unchecked id.
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
        // A valid id is not enough: a 64-byte one under a deep enough run directory
        // overruns `SUN_PATH_MAX`. Refused here rather than at the `bind`, and against the
        // longest name rather than `.sock` (§ 6.3), so no `SessionPaths` that exists can
        // fail to build its own address.
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

    /// Writes the display label, if `label` has anything left after sanitising.
    ///
    /// Advisory throughout: a failure here costs `list` a column and nothing else, so the
    /// caller is expected to ignore it rather than refuse a session over a decoration.
    pub(crate) fn write_label(&self, label: &str) -> io::Result<()> {
        let label = sanitize_label(label);
        if label.is_empty() {
            return Ok(());
        }
        write_private(&self.label(), label.as_bytes())
    }

    /// Records the pid `nomux kill` will signal, through [`write_private`] so its owner can
    /// read it back: `kill` correctly refuses to unlink a live session whose pid it cannot
    /// read. The file is created and filled a syscall apart, which `control::resolve` knows
    /// about, and [`parse_pid`] is the other half of the format.
    pub(crate) fn write_pid(&self) -> io::Result<()> {
        write_private(&self.pid(), format!("{}\n", std::process::id()).as_bytes())
    }

    /// Removes the pidfile a previous incarnation of this id left behind.
    ///
    /// For the daemon, at the point where it has established that no live one is on the
    /// socket — `daemon::bind_socket` says why that is the moment. Absent is a state
    /// `control::resolve` already waits out; stale is the one it cannot tell from current.
    pub(crate) fn clear_pid(&self) {
        drop(fs::remove_file(self.pid()));
    }

    /// `ssh-agent` socket, served for a session created with
    /// [`nomux::HELLO_AGENT_FORWARD`].
    pub(crate) fn agent(&self) -> PathBuf {
        self.with_extension("agent")
    }

    /// Takes the spawn lock, waiting for whoever holds it.
    ///
    /// # Errors
    ///
    /// Reports [`io::ErrorKind::ResourceBusy`] for the two ways a blocking
    /// [`Self::acquire`] comes back empty-handed, naming both because neither says the
    /// lock is free. A *host* that cannot provide the lock at all is not an error
    /// ([`SpawnLock`]).
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

    /// Takes the spawn lock if it is free this instant, for callers with better things to
    /// do than wait. `None` is [`Self::acquire`]'s "not this time" and nothing more.
    pub(crate) fn try_lock_spawn(&self) -> Option<SpawnLock> {
        self.acquire(FlockOperation::NonBlockingLockExclusive)
    }

    /// Locks `<id>.lock` and confirms that what got locked is still that file.
    ///
    /// `None` is "not this time", in one of three readings the callers need not tell apart,
    /// since each answers all three the same way — wait, skip, or refuse: somebody else
    /// holds the lock, the file at the path was replaced more often than [`LOCK_ATTEMPTS`]
    /// allows for, or the descriptors and lock records it takes to ask have run out.
    /// [`SpawnLock::unavailable`] is kept for the failures [`no_lock_here`] names.
    fn acquire(&self, operation: FlockOperation) -> Option<SpawnLock> {
        let path = self.lock();
        for _ in 0..LOCK_ATTEMPTS {
            // At exactly [`FILE_MODE`], for the reason that constant gives, and `RDONLY`
            // because `flock(2)` needs no particular access mode: nothing reads or writes
            // this descriptor, and asking for write would make a `<id>.lock` left at `0400`
            // — which § 6.6 invites a second implementation of `list` and `kill` to leave —
            // one [`no_lock_here`] answers true for, after which every nomux process
            // proceeds unlocked. This narrows that to modes no implementation can lock.
            //
            // `NOFOLLOW` as every other name in this directory is opened: a symlink here
            // would be locked at its target while [`removal_order`] unlinked the link,
            // leaving the mutex on an inode nothing else resolves to. `ELOOP` is not in
            // [`no_lock_here`], so that refusal reads as "not this time" rather than as
            // licence to proceed unlocked.
            let opened = with_umask(FILE_MODE, || {
                rustix::fs::open(
                    &path,
                    OFlags::CREATE | OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::from_bits_truncate(FILE_MODE),
                )
            });
            let fd = match opened {
                Ok(fd) => fd,
                Err(err) => return no_lock_here(err).then(SpawnLock::unavailable),
            };
            loop {
                match rustix::fs::flock(&fd, operation) {
                    // A signal landing on a blocking `flock` is not an answer; ask again.
                    Err(rustix::io::Errno::INTR) => {}
                    Ok(()) => break,
                    // `ENOLCK` has two readings this cannot tell apart: out of lock records,
                    // and a mount whose lock manager is not answering — a host with no lock
                    // to give. Settled toward `None`, the reading that claims nothing, since
                    // [`SpawnLock`] may only proceed where no other process here can be
                    // holding the lock.
                    Err(rustix::io::Errno::WOULDBLOCK | rustix::io::Errno::NOLCK) => return None,
                    // The same division as the `open` above; the arm that carries it here is
                    // a filesystem that does not implement `flock` at all.
                    Err(err) => return no_lock_here(err).then(SpawnLock::unavailable),
                }
            }
            let lock = SpawnLock { fd: Some(fd) };
            if lock.locks_the_file_at(&path) {
                return Some(lock);
            }
            // Collection removed the file while this call waited for it, so what is held
            // is an inode nobody else can reach ([`SpawnLock`]). Go round again.
        }
        None
    }

    /// Removes every file belonging to this session, ignoring absences.
    ///
    /// `lock` is never read: it is the caller's standing to remove `<id>.lock` along with
    /// the rest ([`SpawnLock`]).
    ///
    /// # Errors
    ///
    /// The first failure that is not an absence, once every path has been tried. § 6.6
    /// says why absence is success here and why anything else has to reach `kill`.
    pub(crate) fn unlink_all_locked(&self, _lock: &SpawnLock) -> io::Result<()> {
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
    /// Split out so the order can be asserted directly, rather than through a test that has
    /// to win a race against a live preemption to see anything.
    ///
    /// The four named files lead, and are attempted whatever the directory says: a
    /// `read_dir` this call could not make is not a session with nothing left to remove, and
    /// an empty list would turn the one failure § 6.6 insists is reported — the unlink
    /// itself — into a silent success. The scan adds every *other* name sharing the id
    /// ([`session_id_of`]).
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
        // `<id>.lock` last (§ 6.3), and the ordering is load-bearing: the unlinks still to
        // come would land on a session somebody else has legitimately brought up — and
        // silently, for `<id>.label` and for the `<id>.agent` socket the child's
        // `SSH_AUTH_SOCK` still points at.
        order.push(lock);
        order
    }

    /// Removes every file belonging to this session, if the spawn lock is free.
    ///
    /// For the daemon's own shutdown, which holds nothing. An attach may be waiting on
    /// `<id>.lock` right now — this exit is what it is about to discover — so the files are
    /// left to it, which costs little: it finds a socket whose `connect` is refused and
    /// replaces it as stale. Waiting for the lock would park the exit behind that attach's
    /// spawn timeout.
    pub(crate) fn unlink_all(&self) {
        if let Some(lock) = self.try_lock_spawn() {
            drop(self.unlink_all_locked(&lock));
        }
    }
}

/// Whether `err` says the spawn lock cannot be taken by *anybody* — the only reading
/// [`SpawnLock::unavailable`]'s argument holds for.
///
/// A whitelist rather than "everything that is not a descriptor limit", because that
/// argument is about the *file* while several errnos are about the *moment*. `ENOSPC` and
/// `EDQUOT` are the sharp case: they can only be met where `<id>.lock` does not exist,
/// which is precisely the collection race of § 6.3 — another process holding a lock on
/// the inode just unlinked — so answering "nobody can be holding this" there is how two
/// spawners come to hold a mutex each.
const fn no_lock_here(err: rustix::io::Errno) -> bool {
    use rustix::io::Errno;

    matches!(err, Errno::ACCESS | Errno::PERM | Errno::OPNOTSUPP)
}

/// A caller's exclusive standing on one session id: the right to spawn a daemon into it,
/// and to remove its files.
///
/// Normally an exclusive `flock` on `<id>.lock`, released when this is dropped. Collection
/// (§ 6.6) must take it as well as a spawn (§ 6.3), because **a file unlinked while it is
/// locked stops being a mutex**: the next process to ask creates a new file at the same
/// path, locks that, and both are then certain they hold the only lock there is.
///
/// It also stands for the *absence* of a lock, on a host that has none to give.
/// Proceeding without one is § 6.3's last rule, and it holds only because every acquirer
/// reaches the lock through [`SessionPaths::acquire`], on the same file, under the same
/// uid; [`no_lock_here`] is the list of errnos that are a failure of the *file* in that
/// sense.
#[derive(Debug)]
pub(crate) struct SpawnLock {
    /// The locked descriptor: `close(2)` on it releases the lock, so it is held for that.
    /// `None` where there was no lock to be had.
    fd: Option<OwnedFd>,
}

impl SpawnLock {
    /// The strongest claim available on a host that cannot lock at all.
    const fn unavailable() -> Self {
        Self { fd: None }
    }

    /// Whether this holds a lock on the file that is at `path` now — `flock` attaches to
    /// the inode rather than to the name ([`SpawnLock`]), so nothing else can tell a lock
    /// on the spawn mutex from a lock on what used to be it.
    ///
    /// Every failure answers "no", the safe direction: the caller goes round again rather
    /// than act on a lock it may not hold.
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

/// Reads a bounded prefix of the regular file at `path`, and hands back what arrived.
///
/// Both files the frozen control surface reads by hand come through here (§ 6.6). The write
/// side bounds both; the read side cannot assume it did, the daemon that wrote either being
/// any version and a stray shell redirect into the run directory not a daemon at all.
///
/// Read until the file ends or `buf` is full, so what comes back is a prefix of the *file*
/// rather than of one `read(2)`. That a regular file hands back everything asked for is a
/// property of local filesystems and not of the call: § 6.3's fallback run directory is
/// under `$HOME`, which is NFS or FUSE often enough, and `"3277"` out of `"32770419\n"` is a
/// smaller, plausible, **live** pid that `kill` would signal. Looping also makes the reading
/// [`parse_pid`] and `control::unidentified` put on a full buffer exact: a body that reached
/// the bound is a file with more in it, and nothing else now is.
///
/// A FIFO is refused rather than read short: it hands back whatever its writer has delivered
/// so far and then answers `EAGAIN`, so the loop above would deliver `327` for `kill` to
/// signal. `O_NONBLOCK` also keeps the `open` of one from waiting for a writer that never
/// comes; `O_NOFOLLOW` keeps the name from resolving somewhere else.
///
/// # Errors
///
/// Propagates the `open`, so a caller can tell a file that is absent from one it may not
/// read — the difference between a daemon that has not published yet and one `kill` must
/// refuse to touch. Propagates a read that failed part-way for the same reason. Anything
/// that is not a regular file is [`io::ErrorKind::InvalidData`] and never `InvalidInput`,
/// which `main::report` scores as § 10's 64 for an id that could never have named a
/// session.
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

/// The pidfile's on-disk contract (§ 6.6): what [`SessionPaths::write_pid`] puts there, read
/// back. Here because the *format* is the frozen layout's; what to say about a witness that
/// cannot be believed stays with the two modes that act on the number.
///
/// Zero and negatives are refused: `kill(2)` reads those as a whole process group and as
/// every process the caller may signal. A body that reached [`MAX_PID_LEN`] is refused for
/// § 6.6's asymmetry — it is the prefix of a file whose end was never seen. The layout puts
/// a pid and a newline there, eleven bytes at the widest, so nothing legitimate reaches it.
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
    use std::cell::Cell;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use crate::scratch::{Scratch, mode_of};

    thread_local! {
        /// Where a symlink is to be planted at the name [`write_private`] has just
        /// unlinked, and nowhere if there is none. Per thread, because `cargo test` runs
        /// this crate's unit tests as threads of one process and nothing else may see
        /// the fault.
        static PLANT_ONCE: Cell<Option<PathBuf>> = const { Cell::new(None) };
    }

    /// What a parent this process does not own can do inside the window between the
    /// unlink and the create, forced into it because it cannot be scheduled there.
    /// Called from [`write_private`], which says why it has to be.
    pub(super) fn plant_in_the_window(path: &Path) {
        if let Some(target) = PLANT_ONCE.take() {
            std::os::unix::fs::symlink(target, path).unwrap();
        }
    }

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
        let err = ensure_run_dir(&theirs).unwrap_err();
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

    /// Something that is not a regular file is refused as bad *data*, never as bad input.
    ///
    /// `main::report` scores [`io::ErrorKind::InvalidInput`] as § 10's 64, which a client
    /// caches as its own typo — and the id here is perfectly good. `control::refuse`
    /// happens to rewrap this before it can reach `report`, so the exit code is right
    /// today by way of a caller rather than at the source; this pins the source.
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

    /// A body longer than one `read(2)` still arrives whole.
    ///
    /// The first half is an ordinary file, where what the loop must not do is lose,
    /// duplicate or transpose anything on its way into the buffer. The second is a
    /// genuinely short read, which nothing this test can mount will produce: procfs serves
    /// `smaps` out of a one-page `seq_file` buffer, so a `read` that asked for more comes
    /// back at the page with the rest of the file still there — [`read_prefix`] has why
    /// that shape is the whole reason there is a loop.
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

        // Stood down from visibly rather than silently, at either of the two ways a host
        // can fail to serve one in pieces: a skip nobody can see is a pass.
        let smaps = Path::new("/proc/self/smaps");
        let Ok(fd) = rustix::fs::open(smaps, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        else {
            eprintln!(
                "skipped: this host has no {}, so nothing here hands back a regular file in pieces",
                smaps.display()
            );
            return;
        };
        let mut once = vec![0u8; 1 << 20];
        let first = crate::nbio::read(fd.as_fd(), &mut once).expect("one read of it");
        let more = crate::nbio::read(fd.as_fd(), &mut once).expect("a second read of it");
        drop(fd);
        if more == 0 {
            eprintln!(
                "skipped: {} came back whole in one read of {first} bytes, so this host \
                 cannot show what the loop is for",
                smaps.display()
            );
            return;
        }

        let mut buf = vec![0u8; 1 << 20];
        let bound = buf.len();
        let body = read_prefix(smaps, &mut buf).expect("read the whole of it");
        assert!(
            body.len() > first,
            "the body stopped where one read did, at {} bytes of a file with more in it",
            body.len()
        );
        assert!(
            body.len() < bound,
            "the read filled the buffer, so it says nothing about reaching the end"
        );
        assert_eq!(
            body.last(),
            Some(&b'\n'),
            "and it ended where the kernel had finished a line rather than mid-record"
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

    /// § 6.3's concession about a *parent* this process does not own: a name planted
    /// between [`write_private`]'s unlink and its create is refused, never written
    /// through. Following it put this session's pid wherever the symlink pointed —
    /// under this uid, so a mode elsewhere was no defence.
    ///
    /// The ordinary path is asserted behind it, because the flag that closes the window
    /// is also the one that would refuse every honest write: what is left at the name
    /// after the refusal is the plant, and rewriting over that is the leftover the
    /// unlink exists for.
    #[test]
    fn a_name_planted_in_the_write_window_is_refused_rather_than_written_through() {
        let root = Scratch::new("rundir-plant");
        let dir = root.path();
        let paths = paths_in(dir, "tab_7");
        let theirs = dir.join("elsewhere");
        fs::write(&theirs, b"theirs").unwrap();

        PLANT_ONCE.set(Some(theirs.clone()));
        let err = paths.write_pid().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{err}");
        assert_eq!(
            fs::read(&theirs).unwrap(),
            b"theirs",
            "the file the plant pointed at was never this session's to write"
        );

        paths.write_pid().unwrap();
        assert_eq!(
            fs::read(paths.pid()).unwrap(),
            format!("{}\n", std::process::id()).into_bytes(),
            "and the pidfile is this process's own, over the plant"
        );
        assert_eq!(mode_of(&paths.pid()), FILE_MODE, "at the frozen mode");
    }
}
