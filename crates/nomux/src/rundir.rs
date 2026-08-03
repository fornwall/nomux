//! Run-directory layout.
//!
//! This layout is the frozen contract described in `IMPLEMENTATION.md` § 6.6:
//! `list` and `kill` operate on it alone, never on the session protocol, so any
//! build can manage a daemon of any version. Filenames and permissions here may
//! never change.

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::{env, fs};

use nomux_proto::is_valid_session_id;
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
/// locked is no longer the file at the path.
///
/// Each retry costs some other process a whole collection, so more than one or
/// two means a machine looping on `nomux list` rather than a race being lost; the
/// cap is only here so that such a machine cannot spin an attach forever.
const LOCK_ATTEMPTS: usize = 8;

/// Runs `f` with the umask suppressed, so that a node created at `mode` is created
/// at exactly `mode`.
///
/// `mkdir(2)`, `bind(2)` and `open(2)` all subtract the caller's umask from the
/// mode they are given, which makes that argument an upper bound rather than a
/// request — and every mode in this module is exact. Creating and then `chmod`ing
/// would narrow the window rather than close it, and would `chmod` a path that is
/// being raced.
///
/// The umask is process-wide, but nothing here is multi-threaded and no caller
/// spawns a process while it is in effect.
fn with_umask<T>(mode: u32, f: impl FnOnce() -> T) -> T {
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
/// `format_args!` hands its pieces over one at a time, so a formatted pidfile is
/// published three syscalls wide instead of the two `control::resolve` is written
/// against.
fn write_private(path: &Path, body: &[u8]) -> io::Result<()> {
    drop(fs::remove_file(path));
    with_umask(FILE_MODE, || fs::write(path, body))
}

/// Binds a unix socket that is never, even briefly, more permissive than
/// [`SOCKET_MODE`].
///
/// `bind(2)` creates the node with `0777 & ~umask`, so binding and then `chmod`ing
/// leaves a window — a login with `umask 000` publishes a world-connectable socket
/// for the length of one syscall.
///
/// # Errors
///
/// Propagates bind failures.
pub(crate) fn bind_socket_private(path: &Path) -> io::Result<UnixListener> {
    with_umask(SOCKET_MODE, || UnixListener::bind(path))
}

/// Longest label written to `<id>.label`, in bytes, per the frozen layout.
const MAX_LABEL_LEN: usize = 256;

/// Longest path a unix socket can be bound to, in bytes.
///
/// `sun_path` is 108 bytes and holds a terminator, so 107 is what is left for the
/// path itself — the figure std checks before it will build the address at all.
const SUN_PATH_MAX: usize = 107;

/// Resolves the run directory, preferring `XDG_RUNTIME_DIR`.
///
/// `XDG_RUNTIME_DIR` is tmpfs and cleared on last logout unless lingering is
/// enabled, so the fallback under `XDG_STATE_HOME` is what makes a session outlive
/// a logout on hosts without linger.
///
/// Each source must be *absolute*, which the XDG specification requires anyway and
/// which this daemon needs for a reason of its own: the resolved directory is held
/// in a [`SessionPaths`] for the session's whole life, and § 6.2 moves the daemon
/// to `/` partway through it. A relative path would therefore mean one directory
/// while the daemon was starting and another one afterwards — the socket bound in
/// the caller's working directory, the agent socket and the cleanup on exit
/// looking for it under the root. Refused rather than half-honoured; an empty
/// value is not absolute either, so this is the whole of the check.
///
/// # Errors
///
/// Fails when none of `XDG_RUNTIME_DIR`, `XDG_STATE_HOME` or `HOME` names an
/// absolute path.
pub(crate) fn run_dir() -> io::Result<PathBuf> {
    let absolute = |value: &std::ffi::OsString| Path::new(value).is_absolute();
    if let Some(dir) = env::var_os("XDG_RUNTIME_DIR").filter(absolute) {
        return Ok(PathBuf::from(dir).join("nomux"));
    }
    let state = env::var_os("XDG_STATE_HOME")
        .filter(absolute)
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("HOME")
                .filter(absolute)
                .map(|home| PathBuf::from(home).join(".local/state"))
        })
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
/// nothing about *what* exists: `$XDG_RUNTIME_DIR/nomux` may be a symlink into a
/// directory another user owns, in which case every file the caller is about to
/// make there — a socket that carries the session, the pidfile, the spawn lock — is
/// made somewhere that user chose and can replace.
///
/// The check runs before the creation, so the ordinary case costs one `open` and
/// one `fstat`, and so a plain file sitting at the path is reported as what it is
/// rather than as an `EEXIST` naming nothing.
///
/// # Errors
///
/// Fails if the directory cannot be created, is not a directory, belongs to
/// somebody else, or is one other users can write to. Loud on purpose: the rest of
/// this daemon degrades rather than refuses, but a run directory that is not what
/// it claims to be is not somewhere to start a session.
fn ensure_dir_at(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match check_run_dir(dir) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        settled => return settled,
    }
    // Suppressed for the parents `recursive` creates along the way as much as for
    // the directory itself — [`with_umask`] says why every mode here has to be
    // exact. Left to a `umask 0500` this line would make a run directory its owner
    // cannot open, and the check below would then refuse what it had just made.
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
/// `O_DIRECTORY` and `O_NOFOLLOW` do most of the work: between them the kernel
/// refuses anything that is not a directory, and refuses a symlink instead of
/// following it, so what is left to decide here is who owns the thing and who else
/// may create names in it. That the file type is the kernel's answer rather than a
/// second `fstat` of ours is deliberate — a check that could disagree with the
/// descriptor it is meant to describe is worse than no check.
///
/// The descriptor is dropped at the end and the run files go on being opened by
/// path, which is a decision rather than an oversight: there is no `bindat(2)`, so
/// the two sockets that decide who a session is talking to must be resolved by name
/// whatever this function returns. `IMPLEMENTATION.md` § 6.3 gives the rest of that
/// argument, and the *parent* it leaves open. What closes the part that can be
/// closed is the property established here: in a directory this user owns and
/// nobody else can write to, this user's own processes are the only ones that can
/// put a name in it, which is what makes every path built on it safe to resolve.
/// Keeping the descriptor for the session's lifetime would also pin the filesystem
/// the daemon deliberately lets go of in § 6.2.
///
/// # Errors
///
/// Fails if `dir` is not a directory, is a symlink, belongs to another uid, is one
/// group or other can write to, or is in a mode its owner cannot open. A directory
/// that is simply absent arrives as [`io::ErrorKind::NotFound`], which the control
/// surface reads as an answer rather than a failure: no session has ever been
/// created here.
pub(crate) fn check_run_dir(dir: &Path) -> io::Result<()> {
    let fd = rustix::fs::open(
        dir,
        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|err| match err {
        // Linux answers `O_DIRECTORY | O_NOFOLLOW` on a symlink with `ENOTDIR`
        // rather than the `ELOOP` the manual page leads one to expect — the link is
        // not a directory, and that is the check it fails first — so the two cases
        // arrive as one errno and telling them apart means asking again. Worth
        // asking: "it is a symlink" is the sentence that tells somebody what to do
        // about it, and the extra `lstat` is paid only on the way to failing.
        rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP => refuse(
            dir,
            io::ErrorKind::NotADirectory,
            match fs::symlink_metadata(dir) {
                Ok(meta) if meta.file_type().is_symlink() => "it is a symlink",
                _ => "it is not a directory",
            },
        ),
        // A mode with the owner's own read bit missing is the one loosening — or
        // tightening — that cannot be repaired the way the rest are: `open` fails,
        // so there is no descriptor to `fchmod` through, and a `chmod` by name
        // would resolve a path this function exists to stop resolving twice. It is
        // still a judgement on the mode rather than on the syscall, so it is
        // reported as one; the `lstat` is paid only on the way to failing, and
        // falls back where it is a searchless parent rather than this directory
        // that answered `EACCES`.
        rustix::io::Errno::ACCESS => match fs::symlink_metadata(dir) {
            // Somebody else's, at a mode that keeps us out. The uid is the whole
            // sentence — this is the § 8 threat, reachable with `XDG_RUNTIME_DIR`
            // pointed into a shared parent — and naming the mode instead would
            // report `0700`, the expected one, as the fault. The `fstat` route
            // below says it the same way, and only ever reaches directories this
            // user can already open.
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
    // only one answered the way a wrong owner is. Whoever had it could have left a
    // socket of their own at a session id this process is about to connect to, and
    // tightening the directory now does not un-plant it — nothing inside is evidence
    // of anything any more.
    //
    // Every other mode is repaired to exactly [`DIR_MODE`], through the descriptor
    // already checked above — spare bits, owner bits that are missing rather than
    // spare, and `setgid` or `sticky` alike, since § 6.3 states the mode as exact
    // and says what each of them costs. The one mode not reached here is one the
    // owner cannot open at all, which failed above with nothing to repair through.
    let mode = Mode::from_raw_mode(stat.st_mode);
    if mode.intersects(Mode::WGRP | Mode::WOTH) {
        return Err(refuse(
            dir,
            io::ErrorKind::PermissionDenied,
            &format!("mode {:o} lets other users create files in it", mode.bits()),
        ));
    }
    if mode != Mode::from_bits_truncate(DIR_MODE) {
        // Through the descriptor, never the path: a `chmod` by name resolves it
        // again, and would reopen exactly the hole the `O_NOFOLLOW` above closed.
        rustix::fs::fchmod(&fd, Mode::from_bits_truncate(DIR_MODE))
            .map_err(|err| refuse_errno(dir, err, "its mode could not be tightened"))?;
    }
    Ok(())
}

/// A refusal in the terms the user needs: which directory, what is wrong with it,
/// and what it was supposed to be.
///
/// This reaches them as `nomux: ...` on stderr and is the whole account they get of
/// why a session would not start, so it names the path even where the errno beneath
/// it names nothing at all.
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

/// The five paths belonging to one session.
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
    /// Fails if `id` is not a valid session id, the run directory cannot be
    /// resolved, or the two together are too long to name a socket. Validation
    /// happens here rather than at each use so no caller can build a path from an
    /// unchecked id.
    pub(crate) fn new(id: &str) -> io::Result<Self> {
        if !is_valid_session_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid session id {id:?}: expected 1..=64 bytes of [A-Za-z0-9_-]"),
            ));
        }
        let dir = run_dir()?;
        // A valid id is not enough: `sun_path` is 108 bytes including its
        // terminator, and a 64-byte id under a deep enough run directory overruns
        // it. Refused here, where both halves are known, because the alternative is
        // finding out at `bind` — and the failure that follows is not a session
        // that did not start but one that can never exist, while `list` and `kill`
        // read the unbindable address as a *live* session whose files they must not
        // unlink. That leaves a `<id>.lock` behind on every attempt, from the very
        // command whose job is to collect it.
        //
        // Bounded against `.label`, the longest of the five, so a `.sock` path is a
        // byte shorter still — which is what lets `control::liveness` read every
        // `connect` failure it is not told about as a live session rather than as an
        // address that can never be formed. Both `list` and `kill` reach that code
        // only through this constructor, so no `SessionPaths` that exists can fail
        // to build its own socket address.
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
    /// be tested against a directory of the test's choosing rather than against
    /// whatever `XDG_RUNTIME_DIR` says on the machine running it.
    pub(crate) fn ensure_dir(&self) -> io::Result<()> {
        ensure_dir_at(&self.dir)
    }

    /// Establishes the same property as [`Self::ensure_dir`] without creating
    /// anything.
    ///
    /// For `kill`, which must not bring a run directory into existence as a side
    /// effect of being told to remove a session from it.
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
    fn lock(&self) -> PathBuf {
        self.with_extension("lock")
    }

    /// Advisory UTF-8 display label.
    #[must_use]
    pub(crate) fn label(&self) -> PathBuf {
        self.with_extension("label")
    }

    /// Writes the display label, if `label` has anything left after sanitising.
    ///
    /// Advisory throughout: a failure here costs `list` a column and nothing else,
    /// so the caller is expected to ignore the error rather than refuse a session
    /// over it.
    ///
    /// # Errors
    ///
    /// Propagates failures to create or write the file.
    pub(crate) fn write_label(&self, label: &str) -> io::Result<()> {
        let label = sanitize_label(label);
        if label.is_empty() {
            return Ok(());
        }
        // Left to the umask this would be `0666` minus it, which under the ordinary
        // one publishes the label at `0644` and under `umask 0400` leaves it
        // unreadable to the `list` that is its only consumer.
        write_private(&self.label(), label.as_bytes())
    }

    /// Records the pid `nomux kill` will signal, at a mode its owner can read back.
    ///
    /// Left to the umask this file is whatever `0666` minus it comes to, which under
    /// `umask 0400` is `0266` — a pidfile its own owner cannot read. `kill` refuses
    /// to unlink a live session whose pid it cannot read, correctly, so the session
    /// would be unkillable until somebody noticed and `chmod`ed it. The directory is
    /// `0700` either way; this is about the file staying legible to the process that
    /// has to act on it.
    ///
    /// The file is created and filled a syscall apart, which `control::kill` knows
    /// about: it waits out a zero-length pidfile rather than reporting the corrupt
    /// one it would otherwise see.
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
    /// Reports [`io::ErrorKind::ResourceBusy`] if the file at that path was
    /// replaced under this one more often than [`LOCK_ATTEMPTS`] allows for. A
    /// host that cannot provide the lock at all is not an error — see
    /// [`SpawnLock`].
    pub(crate) fn lock_spawn(&self) -> io::Result<SpawnLock> {
        self.acquire(FlockOperation::LockExclusive).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ResourceBusy,
                format!("the spawn lock for session {} kept being removed", self.id),
            )
        })
    }

    /// Takes the spawn lock if it is free this instant, for callers with better
    /// things to do than wait.
    ///
    /// `None` means one thing only: somebody else is holding it. Everything that
    /// is not a refusal by another process comes back as a [`SpawnLock`], which is
    /// the whole of the policy — a caller that skipped on every failure would skip
    /// on a lock file it cannot open, and `list` would then stop collecting dead
    /// sessions on that host without ever saying why.
    pub(crate) fn try_lock_spawn(&self) -> Option<SpawnLock> {
        self.acquire(FlockOperation::NonBlockingLockExclusive)
    }

    /// Locks `<id>.lock` and confirms that what got locked is still that file.
    ///
    /// `None` is "not this time": either somebody else is holding the lock, or the
    /// file at the path was replaced under this call more often than
    /// [`LOCK_ATTEMPTS`] allows for. Every other way this can fail to produce a lock
    /// hands back [`SpawnLock::unavailable`] instead. The two readings need not be
    /// told apart, because every caller answers them the same way — wait, skip, or
    /// refuse — and `lock_spawn` uses the blocking operation, so *its* `None` can
    /// only ever be the second.
    fn acquire(&self, operation: FlockOperation) -> Option<SpawnLock> {
        let path = self.lock();
        for _ in 0..LOCK_ATTEMPTS {
            // Created at exactly [`FILE_MODE`] like the other two plain files, and
            // this is the one that constant is documented around: a lock left at
            // `0400` is one no later `open(O_RDWR)` can have, so the mutex the
            // `list` and `kill` that clean up after anything rest on is lost to
            // every process that comes after.
            let opened = with_umask(FILE_MODE, || {
                rustix::fs::open(
                    &path,
                    OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC,
                    Mode::from_bits_truncate(FILE_MODE),
                )
            });
            let Ok(fd) = opened else {
                return Some(SpawnLock::unavailable());
            };
            loop {
                match rustix::fs::flock(&fd, operation) {
                    // A signal landing on a blocking `flock` is not an answer about
                    // the lock; ask again.
                    Err(rustix::io::Errno::INTR) => {}
                    Ok(()) => break,
                    Err(rustix::io::Errno::WOULDBLOCK) => return None,
                    Err(_) => return Some(SpawnLock::unavailable()),
                }
            }
            let lock = SpawnLock { fd: Some(fd) };
            if lock.locks_the_file_at(&path) {
                return Some(lock);
            }
            // Collection removed the file while this call was waiting for it, so
            // what is held now is an inode nobody else can reach. Whoever asks
            // next creates a fresh file at the path and locks that instead, and
            // the two of them then hold one mutex each. Go back for the file that
            // is actually there.
        }
        None
    }

    /// Removes every file belonging to this session, ignoring absences.
    ///
    /// `lock` is never read: it is the caller's standing to remove `<id>.lock`
    /// along with the rest. Collection that skipped the lock would pull the spawn
    /// mutex out from under an attach that is using it (`IMPLEMENTATION.md`
    /// § 6.3), and could unlink the socket of a session that came up while the
    /// decision to collect was being made.
    ///
    /// # Errors
    ///
    /// The first failure that is not an absence, once every path has been tried.
    /// Absence is success — the five go in one order, and a collection is often
    /// finishing one that was interrupted — but anything else has to reach `kill`,
    /// whose exit status is the caller's only account of whether the session went.
    /// Reporting nothing here is how a read-only run directory, an `EIO` or an
    /// immutable `<id>.lock` becomes a `kill` that exits 0 having removed nothing,
    /// and a `<id>.lock` left behind is a session `list` rediscovers and tries to
    /// collect on every run from then on.
    pub(crate) fn unlink_all_locked(&self, _lock: &SpawnLock) -> io::Result<()> {
        // Every path is attempted before the first failure is returned: they are
        // independent, and stopping at one would leave the rest of a session behind
        // over a file that was already the exception.
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

    /// The five paths, in the order [`Self::unlink_all_locked`] removes them.
    ///
    /// Split out so that the order can be asserted directly, rather than through a
    /// test that has to win a race against a live preemption to see anything.
    fn removal_order(&self) -> [PathBuf; 5] {
        // `<id>.lock` last, and the ordering is load-bearing rather than tidy.
        // `flock` holds an *inode*: the instant that name is gone the caller's lock
        // guards nothing, the next acquirer creates a fresh file at the path and
        // legitimately locks that — and the unlinks still to come here then land on
        // a session somebody else brought up in the meantime, whose owner is
        // certain it holds the only lock there is. Two of the four are silent when
        // that happens: `<id>.label` costs the new session its column in `list`,
        // and `<id>.agent` is the live socket the child's `SSH_AUTH_SOCK` points
        // at, so its agent forwarding dies for the whole life of the session with
        // nothing said.
        [
            self.socket(),
            self.pid(),
            self.label(),
            self.agent(),
            self.lock(),
        ]
    }

    /// Removes every file belonging to this session, if the spawn lock is free.
    ///
    /// For the daemon's own shutdown, which holds nothing. An attach may be
    /// waiting on `<id>.lock` at this very moment — this daemon's exit is what it
    /// is about to discover — so the files are left alone rather than removed from
    /// under it. That costs little: the attach finds a socket whose `connect` is
    /// refused, which it already treats as stale and replaces, and the next `list`
    /// collects whatever is left over. Waiting for the lock instead would park the
    /// daemon's exit behind that attach's spawn timeout.
    pub(crate) fn unlink_all(&self) {
        if let Some(lock) = self.try_lock_spawn() {
            drop(self.unlink_all_locked(&lock));
        }
    }
}

/// A caller's exclusive standing on one session id: the right to spawn a daemon
/// into it, and to remove its files.
///
/// Normally that is an exclusive `flock` on `<id>.lock`, released when this is
/// dropped. It serialises two attaches racing to create the same session
/// (`IMPLEMENTATION.md` § 6.3) and — less obviously — either of them against the
/// garbage collection of § 6.6, which removes `<id>.lock` along with the rest of
/// the session. Both must take it, because a file that is unlinked while it is
/// locked stops being a mutex at all: the next process to ask creates a new file
/// at the same path, locks that, and both are then certain they hold the only
/// lock there is.
///
/// It also stands for the *absence* of a lock, on a host that has none to give —
/// `<id>.lock` cannot be opened, or the filesystem does not implement `flock`, or
/// the run directory is read-only or over quota. Proceeding without one there is
/// deliberate, and § 6.3 gives the argument: a lock this process cannot obtain by
/// any means is one no other process here can be holding either, since every one of
/// them reaches it through [`SessionPaths::acquire`], on the same file, under the
/// same uid — so refusing would buy nothing and would cost the § 6.6 escape hatch
/// its ability to collect a session that is genuinely dead.
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
    /// again instead of acting on a lock it may not hold.
    ///
    /// The first of those cannot arise from the one caller, which has just locked
    /// the descriptor it is asking about. It is still what reads `fd`, and the
    /// field is otherwise held only for its `Drop`.
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

/// Trims a client-supplied label to what the frozen layout permits: one line of
/// printable UTF-8, at most [`MAX_LABEL_LEN`] bytes.
///
/// The label is a tab title chosen by a human, so it arrives with whatever they
/// typed in it. Control characters are dropped rather than escaped — `list` writes
/// this straight to a terminal, and a label carrying `ESC ]0;` would retitle the
/// window of whoever ran it. Truncation is at a character boundary, so the result
/// is always valid UTF-8.
pub(crate) fn sanitize_label(label: &str) -> String {
    let mut out: String = label.chars().filter(|ch| !ch.is_control()).collect();
    out.truncate(out.floor_char_boundary(MAX_LABEL_LEN));
    out.trim().to_owned()
}

/// Reads a bounded prefix of `path`, and hands back what arrived.
///
/// Both files the frozen control surface reads by hand come through here —
/// `<id>.label` and `<id>.pid` — and neither is read whole. The write side bounds
/// both; the read side cannot assume it did, for the same reason [`read_label`]
/// sanitizes what it finds: this is the frozen layout (§ 6.6), so the daemon that
/// wrote the file may be any version, and a stray shell redirect into the run
/// directory is not a daemon at all. `list` and `kill` are the escape hatch that has
/// to keep working on any host, which they would not if a file somebody left there
/// decided how much memory they faulted in — nor if it could park them in a syscall
/// with no end. `O_NONBLOCK` is what turns a FIFO at either path into an `EAGAIN`
/// rather than an `open` that waits for a writer that never comes, and `O_NOFOLLOW`
/// keeps the name from resolving somewhere else entirely.
///
/// One read is enough — a regular file returns what was asked for or reaches the end
/// — and [`crate::nbio::read`] covers the signal that would otherwise cut it short.
/// `File` with `Take` and `read_to_end` measured 1.6 KiB of machinery this binary
/// otherwise does not link, against the § 8 budget, for two files that cannot exceed
/// a few hundred bytes worth reading.
///
/// # Errors
///
/// Propagates the `open`, so a caller can tell a file that is absent from one it may
/// not read — which is the difference between a daemon that has not published yet
/// and one `kill` must refuse to touch. A FIFO nobody is writing to is neither: it
/// opens, reads nothing, and comes back empty, which is what any other file holding
/// no session data comes back as.
pub(crate) fn read_prefix<'a>(path: &Path, buf: &'a mut [u8]) -> io::Result<&'a [u8]> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let read = match crate::nbio::read(fd.as_fd(), buf) {
        Err(rustix::io::Errno::AGAIN) => 0,
        outcome => outcome?,
    };
    Ok(buf.get(..read).unwrap_or(&[]))
}

/// Reads a session's label, bounded by what the layout permits.
///
/// Anything unreadable is an empty label. A listing that names the session and its
/// pid is worth more than one that fails over a decoration. Invalid UTF-8 is an
/// empty label rather than a repaired one, which is what reading it as a `String`
/// always did.
pub(crate) fn read_label(path: &Path) -> String {
    // One byte past the cap, so a label written at exactly [`MAX_LABEL_LEN`] still
    // arrives whole and a longer one is visibly over.
    let mut buf = [0u8; MAX_LABEL_LEN + 1];
    let body = read_prefix(path, &mut buf).unwrap_or(&[]);
    sanitize_label(str::from_utf8(body).unwrap_or(""))
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
        let target = root.join("elsewhere");
        fs::create_dir_all(&target).unwrap();
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

    /// The owner check needs no second uid and no mock as an ordinary user: every
    /// Linux host has readable directories belonging to root, and the check returns
    /// before anything is created or any mode changed — which is what makes the
    /// target being untouched an assertion here rather than a hope.
    ///
    /// As root it does need one, and it makes one rather than standing down. The
    /// early `return` this used to take reports as a pass, so on a host where the
    /// suite runs as root — a container, which is where CI usually is — the check
    /// went entirely unexercised and said so nowhere. A directory of this test's own
    /// handed to another uid asks exactly the same question of exactly the same
    /// branch, and root is the one user who can arrange it.
    #[test]
    fn a_run_directory_owned_by_another_uid_is_refused() {
        let us = rustix::process::getuid();
        let root = Scratch::new("rundir-uid");
        let theirs: PathBuf = if us.is_root() {
            let dir = root.join("somebody-else");
            fs::create_dir_all(&dir).unwrap();
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

    /// `<id>.lock` is removed last, which is a correctness property rather than a
    /// tidy one — [`SessionPaths::removal_order`] says why, and this is the
    /// assertion that keeps it true.
    #[test]
    fn the_spawn_lock_is_the_last_file_removed() {
        let paths = SessionPaths::new("tab_7").unwrap();
        let order = paths.removal_order();
        assert_eq!(
            order.last(),
            Some(&paths.lock()),
            "the lock must outlive the four files it protects"
        );
        let mut distinct: Vec<_> = order.iter().collect();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), 5, "all five files are still removed");
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
