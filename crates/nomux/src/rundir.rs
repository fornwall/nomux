//! Run-directory layout.
//!
//! This layout is the frozen contract described in `IMPLEMENTATION.md` § 6.6:
//! `list` and `kill` operate on it alone, never on the session protocol, so any
//! build can manage a daemon of any version. Filenames and permissions here may
//! never change.

use std::io::{self, Write as _};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
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
/// open is one nothing can lock, and [`SessionPaths::acquire`] refuses the id outright
/// rather than serve a session behind a mutex that is not one.
const FILE_MODE: u32 = 0o600;

/// How many times an acquirer takes the lock before giving up — the first attempt and one
/// re-take, for finding that the file it locked is no longer the file at the path. Each
/// re-take costs some other process a whole collection, so a second one is already a
/// machine looping on `nomux list`.
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

/// Replaces `path` with `body`, at exactly [`FILE_MODE`].
///
/// `write_all` rather than one `write(2)`, which promises to deliver everything or fail
/// rather than to be a single call — so a body cut short is a *failure* here, and never a
/// success that left a prefix. The prefix is still on disk, which is [`parse_pid`]'s half.
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

/// Longest `<id>.pid` body anything reads (§ 6.6). A pid and its newline are eleven bytes
/// at the widest, so the slack is what makes reaching this bound evidence in itself — of a
/// file whose end was never seen, which [`parse_pid`] refuses rather than reads a prefix of.
pub(crate) const MAX_PID_LEN: usize = 32;

/// Longest session id, in bytes (§ 6.3).
///
/// Beside the layout that turns one into a filename rather than on the wire, which § 2.2
/// keeps the id out of.
pub(crate) const MAX_SESSION_ID_LEN: usize = 64;

/// The longer of the two extensions this layout binds a socket at, `.sock` being the other.
///
/// What [`SessionPaths::in_dir`] measures an id against, since only these two names are ever
/// addresses: `<id>.pid`, `<id>.label` and `<id>.lock` are plain files under no
/// [`SUN_PATH_MAX`] bound at all. Measuring against one of those would let the sixth name
/// § 6.6 invites tighten the id ceiling for nothing — or, were that name a socket with a
/// longer extension, silently overrun it.
const LONGEST_SOCKET_EXT: &str = ".agent";

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
    // success, so what this "created" may be another attach's — or, under a parent
    // somebody else can write to, what they left there between the two checks. Absent
    // even now is the one place where that is a failure rather than an answer: this
    // function owes its caller a directory, and there is none.
    if check_run_dir(dir)? {
        return Ok(());
    }
    Err(refuse(
        dir,
        io::ErrorKind::NotFound,
        "it was removed as it was created",
    ))
}

/// Answers whether `dir` is a run directory of this user's alone, opening it to find out.
///
/// `false` is simply absent, which every caller reads as the question already settled:
/// no session was ever created here.
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
/// Anything that is not a directory of this user's alone, at a mode its owner can open and
/// nobody else can create in — the arms below are the distinctions.
pub(crate) fn check_run_dir(dir: &Path) -> io::Result<bool> {
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
            &not_this_users(stat.st_uid),
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

/// Why the `open` in [`check_run_dir`] would not give a descriptor, in terms of the
/// directory rather than of the syscall — one `symlink_metadata`, paid only on the way out,
/// because the errno alone does not separate states a user would act on differently.
///
/// Linux answers `O_DIRECTORY | O_NOFOLLOW` on a symlink with `ENOTDIR` and not the `ELOOP`
/// the manual page leads one to expect, so both share an arm. `EACCES` covers both somebody
/// else's directory — § 8's threat, reachable with `XDG_RUNTIME_DIR` pointed into a shared
/// parent — and a mode its own owner cannot open, the one loosening § 6.3 will not repair.
/// Past those the errno is a searchless *parent*, not this directory answering anything.
fn refuse_unopenable(dir: &Path, err: rustix::io::Errno) -> io::Error {
    let meta = fs::symlink_metadata(dir).ok();
    match err {
        rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP => refuse(
            dir,
            io::ErrorKind::NotADirectory,
            if meta.is_some_and(|meta| meta.file_type().is_symlink()) {
                "it is a symlink"
            } else {
                "it is not a directory"
            },
        ),
        rustix::io::Errno::ACCESS => match meta.filter(fs::Metadata::is_dir) {
            Some(meta) if meta.uid() != rustix::process::getuid().as_raw() => refuse(
                dir,
                io::ErrorKind::PermissionDenied,
                &not_this_users(meta.uid()),
            ),
            Some(meta) => refuse(
                dir,
                io::ErrorKind::PermissionDenied,
                &format!(
                    "mode {:o} does not let its owner open it",
                    meta.mode() & 0o7777
                ),
            ),
            None => refuse_errno(dir, err, "it could not be opened"),
        },
        other => refuse_errno(dir, other, "it could not be opened"),
    }
}

/// The one sentence for a directory of somebody else's, wherever [`check_run_dir`] finds
/// that out — the `EACCES` on the way in, or the `fstat` of what it did open. The uid is
/// the whole of it: naming the mode would report `0700`, the expected one, as the fault.
fn not_this_users(uid: u32) -> String {
    format!("it belongs to uid {uid}")
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

/// A name in the run directory split into the session it belongs to and the extension saying
/// which of that session's files it is: the id is what precedes the **first** `.`, and a name
/// with no `.` is nobody's.
///
/// The one rule by which anything here reads a filename, and the glob § 6.6 rests growth on.
/// Spelt twice it stops being one rule, which is how a sixth filename comes to be found by
/// discovery and missed by collection — the two readers are [`session_id_of`] and
/// [`SessionPaths::removal_order`], and only the second wants the extension.
fn split_run_name(path: &Path) -> Option<(&str, &str)> {
    path.file_name()?.to_str()?.split_once('.')
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
    /// Resolves the paths for `id` in this user's run directory.
    ///
    /// # Errors
    ///
    /// [`Self::in_dir`]'s, plus a run directory that cannot be resolved at all.
    pub(crate) fn new(id: &str) -> io::Result<Self> {
        Self::in_dir(&run_dir()?, id)
    }

    /// Resolves the paths for `id` in `dir`.
    ///
    /// For a caller that already has the run directory — `control::list` resolves it once
    /// and then reaches every session through here, rather than paying two `getenv`s and a
    /// `PathBuf` per entry to be handed back the directory it is reading.
    ///
    /// # Errors
    ///
    /// Fails if `id` is not a valid session id, or if the two together are too long to name
    /// a socket. Validated here rather than at each use, so no caller can build a path from
    /// an unchecked id.
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
        // A valid id is not enough: a 64-byte one under a deep enough run directory
        // overruns `SUN_PATH_MAX`. Refused here rather than at the `bind`, and against the
        // longest *socket* rather than `.sock` alone (§ 6.3), so no `SessionPaths` that
        // exists can fail to build either of its addresses ([`LONGEST_SOCKET_EXT`]).
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
    /// sanitising.
    ///
    /// Advisory throughout: a failure here costs `list` a column and nothing else, so the
    /// caller is expected to ignore it rather than refuse a session over a decoration. The
    /// *removal* is what a label reduced to nothing has to mean, `<id>.label` being a file
    /// that outlives what wrote it ([`Self::clear_label`]).
    pub(crate) fn write_label(&self, label: &str) -> io::Result<()> {
        let label = sanitize_label(label);
        if label.is_empty() {
            self.clear_label();
            return Ok(());
        }
        write_private(&self.label(), label.as_bytes())
    }

    /// Records the pid `nomux kill` will signal, through [`write_private`] so its owner can
    /// read it back: `kill` correctly refuses to unlink a live session whose pid it cannot
    /// read. The file is created and filled a syscall apart, which `control::resolve` knows
    /// about, and [`parse_pid`] is the other half of the format.
    ///
    /// The label goes first because this is the one call every incarnation of an id makes
    /// and [`Self::write_label`] is not: `daemon::publish` writes the pid here and the
    /// label, where there is one, straight after — so an id restarted without `--label`
    /// stops carrying the last one's ([`Self::clear_label`]).
    pub(crate) fn write_pid(&self) -> io::Result<()> {
        self.clear_label();
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

    /// Removes the label a previous incarnation of this id left behind.
    ///
    /// Beside [`Self::clear_pid`] and for its reason, on the other file § 6.6 has `list`
    /// print. Nothing else ever removes one: `<id>.label` is written when a session is
    /// created and read by every `list` after, so a session started over the files of one
    /// that was killed outright inherited the dead session's name — in the column a human
    /// reads to decide what to kill.
    pub(crate) fn clear_label(&self) {
        drop(fs::remove_file(self.label()));
    }

    /// `ssh-agent` socket, served for a session created with
    /// [`nomux::Hello::agent_forward`].
    pub(crate) fn agent(&self) -> PathBuf {
        self.with_extension("agent")
    }

    /// Takes the spawn lock, waiting for whoever holds it. [`Self::acquire`]'s refusals, and
    /// its `Ok(None)` as [`io::ErrorKind::ResourceBusy`]: a caller that has already waited
    /// and still came back empty has not been told the lock is free.
    pub(crate) fn lock_spawn(&self) -> io::Result<SpawnLock> {
        self.acquire(FlockOperation::LockExclusive)?.ok_or_else(|| {
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

    /// Takes the spawn lock if it is free this instant, for callers with better things to do
    /// than wait — [`Self::acquire`] unchanged, `Ok(None)` and both refusals.
    pub(crate) fn try_lock_spawn_or_refuse(&self) -> io::Result<Option<SpawnLock>> {
        self.acquire(FlockOperation::NonBlockingLockExclusive)
    }

    /// [`Self::try_lock_spawn_or_refuse`] for the two opportunistic collections, which
    /// have nobody to report a refusal to and answer every failure by touching nothing.
    /// Daemon startup deliberately does not use this lossy spelling: it must either own
    /// the lock or refuse the id.
    pub(crate) fn try_lock_spawn(&self) -> Option<SpawnLock> {
        self.try_lock_spawn_or_refuse().ok().flatten()
    }

    /// Locks `<id>.lock` and confirms that what got locked is still that file.
    ///
    /// `Ok(None)` is "not this time", in three readings no caller tells apart because each
    /// answers all three alike, by waiting, skipping or refusing: somebody else holds the
    /// lock, the file at the path was replaced more often than [`LOCK_ATTEMPTS`] allows for,
    /// or the descriptors and lock records it takes to ask have run out. Every one is about
    /// the *moment*, and asking again is what they earn.
    ///
    /// # Errors
    ///
    /// The two failures about the *file* and the *filesystem* rather than the moment, and so
    /// still there next time: a `<id>.lock` nothing can lock, and a run directory mounted
    /// read-only. Neither may be answered by going ahead ([`SpawnLock`]).
    fn acquire(&self, operation: FlockOperation) -> io::Result<Option<SpawnLock>> {
        let path = self.lock();
        for _ in 0..LOCK_ATTEMPTS {
            // At exactly [`FILE_MODE`], for the reason that constant gives, and `RDONLY`
            // because `flock(2)` needs no particular access mode: nothing reads or writes
            // this descriptor, and asking for write would make a `<id>.lock` left at `0400`
            // — which § 6.6 invites a second implementation of `list` and `kill` to leave —
            // a file this refuses outright, where `RDONLY` takes it and locks it.
            //
            // `NOFOLLOW` as every other name in this directory is opened: a symlink here
            // would be locked at its target while [`removal_order`] unlinked the link,
            // leaving the mutex on an inode nothing else resolves to. `ELOOP` is not one of
            // the two refusals below, so that reads as "not this time" — a name somebody is
            // in the middle of replacing — rather than as a verdict on the host.
            // `NONBLOCK` is inert for regular files and load-bearing for a FIFO planted
            // at this name: opening its read end without a writer otherwise sleeps before
            // any caller's lock deadline can begin to help.
            let reading = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
            let opened = with_umask(FILE_MODE, || {
                match rustix::fs::open(
                    &path,
                    OFlags::CREATE | OFlags::EXCL | reading,
                    Mode::from_bits_truncate(FILE_MODE),
                ) {
                    Ok(fd) => Ok((fd, true)),
                    // Open the inode that won the create race. Keeping this as a second
                    // lookup is intentional: [`SpawnLock::locks_the_file_at`] below
                    // rejects it if a collector replaces the name between the two.
                    Err(rustix::io::Errno::EXIST) => {
                        rustix::fs::open(&path, reading, Mode::empty()).map(|fd| (fd, false))
                    }
                    Err(err) => Err(err),
                }
            });
            let (fd, created_name) = match opened {
                Ok(opened) => opened,
                // `EROFS` here means the name is *absent* and the mount will not create it,
                // never that a `<id>.lock` already sitting there was refused for the flag:
                // the kernel drops `O_CREAT` when it cannot take the write and reports the
                // refusal only once the lookup comes back negative, so a lock on a read-only
                // mount still opens and locks. A fact about the filesystem, and a different
                // sentence from the one below.
                Err(rustix::io::Errno::ROFS) => return Err(self.read_only_lock(&path)),
                // A file no process of this uid can open is one no process can lock, so
                // there is no mutex at this name for anybody.
                Err(err @ (rustix::io::Errno::ACCESS | rustix::io::Errno::PERM)) => {
                    return Err(self.unlockable(&path, err));
                }
                // Everything else — a descriptor limit, a full disk, a symlink somebody is
                // replacing — is about this attempt rather than about the file.
                Err(_) => return Ok(None),
            };
            let stat = rustix::fs::fstat(&fd).map_err(io::Error::from)?;
            if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                != rustix::fs::FileType::RegularFile
            {
                return Err(self.not_a_lock_file(&path));
            }
            loop {
                match rustix::fs::flock(&fd, operation) {
                    // A signal landing on a blocking `flock` is not an answer; ask again.
                    Err(rustix::io::Errno::INTR) => {}
                    Ok(()) => break,
                    // `ENOLCK` has two readings this cannot tell apart: out of lock records,
                    // and a mount whose lock manager is not answering. Settled toward
                    // `Ok(None)`, the reading that claims nothing and costs the caller one
                    // more attempt, since the first of the two is a moment and passes.
                    Err(rustix::io::Errno::WOULDBLOCK | rustix::io::Errno::NOLCK) => {
                        return Ok(None);
                    }
                    // A filesystem that does not implement `flock` at all, which is the
                    // same verdict as an unopenable file and gets the same sentence.
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
            // Collection removed the file while this call waited for it, so what is held
            // is an inode nobody else can reach ([`SpawnLock`]). Go round again.
        }
        Ok(None)
    }

    /// The refusal for a `<id>.lock` that cannot be locked by anybody — § 6.3's rule that
    /// nothing here proceeds without the lock, in the words the user needs.
    ///
    /// Named apart from [`Self::read_only_lock`] because the repairs are nothing alike: a
    /// mode is one `chmod` away, and a filesystem with no `flock` is a run directory to
    /// point somewhere else with `XDG_RUNTIME_DIR`.
    fn unlockable(&self, path: &Path, err: rustix::io::Errno) -> io::Error {
        let err = io::Error::from(err);
        io::Error::new(
            err.kind(),
            format!(
                "the spawn lock for session {id} cannot be held by anybody: {path}: {err}; \
                 this filesystem cannot serialise session startup, and going ahead without \
                 the lock is how two daemons come to claim one id and unlink each other's \
                 live sessions",
                id = self.id,
                path = path.display(),
            ),
        )
    }

    /// The refusal for a run directory nothing can be created in, which is a fact about the
    /// mount rather than about locking ([`Self::unlockable`]).
    fn read_only_lock(&self, path: &Path) -> io::Error {
        let err = io::Error::from(rustix::io::Errno::ROFS);
        io::Error::new(
            err.kind(),
            format!(
                "the spawn lock for session {id} could not be created: {path}: {err}; the \
                 run directory is on a read-only filesystem, so there is no session here to \
                 start and none to remove",
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
    pub(crate) fn inherit_spawn_lock(&self, raw: i32) -> io::Result<SpawnLock> {
        if raw <= libc::STDERR_FILENO {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "inherited spawn-lock descriptor is not usable",
            ));
        }
        // SAFETY: `spawn` cleared `CLOEXEC` on this owned descriptor in the forked
        // child and passed its number as an argument. This process has not opened or
        // closed anything since exec that could reuse it, and taking ownership here
        // makes this the one value that closes the inherited copy.
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

    /// Removes every file belonging to this session, ignoring absences.
    ///
    /// `lock` is never read: it is the caller's standing to remove `<id>.lock` along with
    /// the rest ([`SpawnLock`]).
    ///
    /// # Errors
    ///
    /// The first failure that is not an absence, once every path has been tried, named the
    /// way every other refusal in this module is: which session, and which of its files.
    /// The bare errno reached `kill` as `nomux: Is a directory (os error 21)`, which says
    /// neither. § 6.6 says why absence is success here and why anything else has to reach
    /// `kill`.
    pub(crate) fn unlink_all_locked(&self, _lock: &SpawnLock) -> io::Result<()> {
        let mut failure = Ok(());
        for path in self.removal_order() {
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
    /// removes them.
    ///
    /// Split out so the order can be asserted directly, rather than through a test that has
    /// to win a race against a live preemption to see anything.
    ///
    /// The four named files lead, and are attempted whatever the directory says: a
    /// `read_dir` this call could not make is not a session with nothing left to remove, and
    /// an empty list would turn the one failure § 6.6 insists is reported — the unlink
    /// itself — into a silent success. The scan adds every *other* name sharing the id.
    fn removal_order(&self) -> Vec<PathBuf> {
        /// The extensions the five named paths already cover. Every entry the scan looks at
        /// is in one directory under one id, so the extension alone tells two of them apart
        /// — a name is placed by one comparison against this rather than by a search of the
        /// list built so far, and every `kill`, `list` sweep and daemon exit runs this.
        const ALREADY: [&str; 5] = ["sock", "pid", "label", "agent", "lock"];

        let mut order = vec![self.socket(), self.pid(), self.label(), self.agent()];
        if let Ok(entries) = fs::read_dir(&self.dir) {
            order.extend(entries.filter_map(Result::ok).filter_map(|entry| {
                let path = entry.path();
                // [`session_id_of`] validates because it learns an id from the directory;
                // this compares against one checked when the `SessionPaths` was built, so
                // the rule alone is what it needs.
                let mine = split_run_name(&path)
                    .is_some_and(|(id, extension)| id == self.id && !ALREADY.contains(&extension));
                mine.then_some(path)
            }));
        }
        // `<id>.lock` last (§ 6.3), and the ordering is load-bearing: the unlinks still to
        // come would land on a session somebody else has legitimately brought up — and
        // silently, for `<id>.label` and for the `<id>.agent` socket the child's
        // `SSH_AUTH_SOCK` still points at.
        order.push(self.lock());
        order
    }

    /// Removes every file belonging to this session, if the spawn lock can be had this
    /// instant.
    ///
    /// For the daemon's own shutdown, which holds nothing. An attach may be waiting on
    /// `<id>.lock` right now — this exit is what it is about to discover — so the files are
    /// left to it, which costs little: it finds a socket whose `connect` is refused and
    /// replaces it as stale. Waiting for the lock would park the exit behind that attach's
    /// spawn timeout, and a host that can give no lock at all leaves them the same way, an
    /// exit having nobody to report that to ([`Self::try_lock_spawn`]).
    pub(crate) fn unlink_all(&self) {
        if let Some(lock) = self.try_lock_spawn() {
            drop(self.unlink_all_locked(&lock));
        }
    }
}

/// Removes one run file, whatever kind of node somebody left at the name.
///
/// A *directory* at one of these names strands the id for good otherwise, and `<id>.sock`
/// is the one that bites: `connect` answers `ECONNREFUSED`, which § 6.6 reads as stale, so
/// every `list` sweeps the entry, every `kill` fails on the same `EISDIR`, and
/// `daemon::bind_socket`'s own removal fails identically — leaving an id nothing can create,
/// collect or name again. Nothing this layout writes is a directory, so removing one is
/// repair rather than licence, and `remove_dir` still refuses a non-empty one.
fn remove_node(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(err) if err.kind() == io::ErrorKind::IsADirectory => fs::remove_dir(path),
        settled => settled,
    }
}

/// A caller's exclusive standing on one session id: the right to spawn a daemon into it,
/// and to remove its files.
///
/// An exclusive `flock` on `<id>.lock`, released when this is dropped, and never anything
/// weaker — a host that cannot give one gets a refusal ([`SessionPaths::acquire`]) rather
/// than a caller that holds nothing and proceeds as though it did. Every argument in this
/// module and in `control` that rests on the mutex therefore rests on it without a caveat.
///
/// Collection (§ 6.6) must take it as well as a spawn (§ 6.3), because **a file unlinked
/// while it is locked stops being a mutex**: the next process to ask creates a new file at
/// the same path, locks that, and both are then certain they hold the only lock there is.
#[derive(Debug)]
pub(crate) struct SpawnLock {
    /// The locked descriptor: `close(2)` on it releases the lock, so it is held for that.
    fd: OwnedFd,
    /// Whether this acquisition created the directory entry it locked.
    ///
    /// Established atomically with `O_EXCL`, rather than by an `exists` check before
    /// the open. A startup failure may remove the name only in this case; otherwise it
    /// may be a stale mutex another process still has standing on.
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

    /// Whether taking this lock created its directory entry.
    pub(crate) const fn created_name(&self) -> bool {
        self.created_name
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

/// Reads a bounded prefix of the regular file at `path`, and hands back what arrived.
///
/// Both files the frozen control surface reads by hand come through here (§ 6.6). The write
/// side bounds both; the read side cannot assume it did, the daemon that wrote either being
/// any version and a stray shell redirect into the run directory not a daemon at all. The
/// `open` and a part-way read propagate, so a caller can tell an absent file from one it may
/// not read — a daemon that has not published yet from one `kill` must refuse to touch.
///
/// Read until the file ends or `buf` is full, so what comes back is a prefix of the *file*
/// rather than of one `read(2)`. That a regular file hands back everything asked for is a
/// property of local filesystems and not of the call — § 6.3's fallback run directory is
/// under `$HOME`, which is NFS or FUSE often enough. Looping also makes the reading
/// [`parse_pid`] and `control::unidentified` put on a full buffer exact: a body that reached
/// the bound is a file with more in it, and nothing else now is.
///
/// A FIFO is refused rather than read short: it hands back whatever its writer has delivered
/// so far and then answers `EAGAIN`, which is that same partial pid with no end to the file
/// to reach. `O_NONBLOCK` also keeps the `open` of one from waiting for a writer that never
/// comes; `O_NOFOLLOW` keeps the name from resolving somewhere else. Anything that is not a
/// regular file is [`io::ErrorKind::InvalidData`] and never `InvalidInput`, which
/// `main::report` scores as § 10's 64 for an id that could never have named a session.
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
/// every process the caller may signal.
///
/// The **newline is required**, being what says the file ends where the number does. A body
/// without one is a pid that was cut off somewhere, and a cut-off pid is not a smaller
/// question than a wrong one: `"3277"` out of `"32770419\n"` is a shorter, entirely
/// plausible, *live* number that `kill` would go on to signal. Two things produce one —
/// a write that ran out of room part-way ([`write_private`]), and a second implementation
/// of § 6.6 that has not finished writing — and neither announces itself. A body that
/// reached [`MAX_PID_LEN`] is refused for that same asymmetry one bound further out; blanks
/// around the number are still taken, which costs nothing once the newline has said the
/// file is whole.
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

    /// `<id>.lock` is removed last ([`SessionPaths::removal_order`]), over the whole
    /// `<id>.*` glob and not only over the five names — which is the half that could
    /// regress silently.
    #[test]
    fn the_spawn_lock_is_the_last_file_removed() {
        let root = Scratch::new("rundir-order");
        let dir = root.path();
        let paths = SessionPaths::in_dir(dir, "tab_7")
            .expect("a directory of the test's own naming a session");
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

        let paths = SessionPaths::in_dir(dir, "tab_7")
            .expect("a directory of the test's own naming a session");
        // The real standing rather than a stand-in: there is only one way to hold this
        // now, and it is the same call every collection makes.
        let lock = paths
            .try_lock_spawn()
            .expect("the spawn lock, in a directory of this test's own");
        paths.unlink_all_locked(&lock).unwrap();

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
        paths
            .unlink_all_locked(&lock)
            .expect("the named files are removable whatever the scan could do");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            !dir.join("tab_7.sock").exists(),
            "the five named paths are attempted whatever the directory says"
        );
    }

    /// A `<id>.lock` nothing can open is a session nothing can serialise, and that is
    /// refused rather than proceeded past.
    ///
    /// What this replaces let a caller holding no lock act as though it held one, which is
    /// two spawners each certain they have the only lock there is — and each entitled to
    /// unlink the other's *live* session. The refusal names the file, since the whole of
    /// the repair is a `chmod`.
    ///
    /// Stands down as root, where a mode keeps nobody out of their own file and the open
    /// simply succeeds. The reason is printed rather than swallowed: a skip nobody can see
    /// is a pass.
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

    /// The bound held against the document rather than against itself.
    ///
    /// The table above passes at whatever value the constant happens to hold. It matters
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
        let paths = SessionPaths::in_dir(dir, "tab_7")
            .expect("a directory of the test's own naming a session");
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
