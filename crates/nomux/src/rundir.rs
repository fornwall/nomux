//! Run-directory layout.
//!
//! This layout is the frozen contract described in `IMPLEMENTATION.md` § 6.6:
//! `list` and `kill` operate on it alone, never on the session protocol, so any
//! build can manage a daemon of any version. Filenames and permissions here may
//! never change.

use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::{env, fs};

use nomux_proto::is_valid_session_id;
use rustix::fs::{FlockOperation, Mode, OFlags};

/// Permissions for the run directory: owner-only, since it holds the sockets that
/// grant access to live sessions.
pub(crate) const DIR_MODE: u32 = 0o700;

/// Permissions for every socket inside it.
pub(crate) const SOCKET_MODE: u32 = 0o600;

/// Binds a unix socket that is never, even briefly, more permissive than
/// [`SOCKET_MODE`].
///
/// `bind(2)` creates the node with `0777 & ~umask`, so binding and then `chmod`ing
/// leaves a window — a login with `umask 000` publishes a world-connectable socket
/// for the length of one syscall. Setting the umask around the bind closes it
/// instead of narrowing it, and avoids `chmod`ing a path that is being raced.
///
/// The umask is process-wide, but the daemon is single-threaded and spawns nothing
/// while this is in effect.
///
/// # Errors
///
/// Propagates bind failures.
pub(crate) fn bind_socket_private(path: &Path) -> io::Result<UnixListener> {
    let previous = rustix::process::umask(Mode::from_bits_truncate(0o777 & !SOCKET_MODE));
    let listener = UnixListener::bind(path);
    rustix::process::umask(previous);
    listener
}

/// Longest label written to `<id>.label`, in bytes, per the frozen layout.
pub(crate) const MAX_LABEL_LEN: usize = 256;

/// Resolves the run directory, preferring `XDG_RUNTIME_DIR`.
///
/// `XDG_RUNTIME_DIR` is tmpfs and cleared on last logout unless lingering is
/// enabled, so the fallback under `XDG_STATE_HOME` is what makes a session outlive
/// a logout on hosts without linger.
///
/// # Errors
///
/// Fails when none of `XDG_RUNTIME_DIR`, `XDG_STATE_HOME` or `HOME` is set.
pub(crate) fn run_dir() -> io::Result<PathBuf> {
    if let Some(dir) = env::var_os("XDG_RUNTIME_DIR").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(dir).join("nomux"));
    }
    let state = env::var_os("XDG_STATE_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .ok_or_else(|| {
            io::Error::other("none of XDG_RUNTIME_DIR, XDG_STATE_HOME or HOME is set")
        })?;
    Ok(state.join("nomux/run"))
}

/// The five paths belonging to one session.
#[derive(Debug, Clone)]
pub(crate) struct SessionPaths {
    dir: PathBuf,
    id: String,
}

impl SessionPaths {
    /// Resolves the paths for `id`.
    ///
    /// # Errors
    ///
    /// Fails if `id` is not a valid session id, or the run directory cannot be
    /// resolved. Validation happens here rather than at each use so no caller can
    /// build a path from an unchecked id.
    pub(crate) fn new(id: &str) -> io::Result<Self> {
        if !is_valid_session_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid session id {id:?}: expected 1..=64 bytes of [A-Za-z0-9_-]"),
            ));
        }
        Ok(Self {
            dir: run_dir()?,
            id: id.to_owned(),
        })
    }

    /// The session id.
    #[must_use]
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Creates the run directory with owner-only permissions.
    ///
    /// # Errors
    ///
    /// Fails if the directory cannot be created or its mode cannot be set.
    pub(crate) fn ensure_dir(&self) -> io::Result<()> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(&self.dir)?;
        // `recursive` skips the mode on an existing directory, so tighten it here
        // in case an earlier version or a umask left it more permissive.
        fs::set_permissions(&self.dir, fs::Permissions::from_mode(DIR_MODE))
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
        fs::write(self.label(), label.as_bytes())
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
    /// Propagates failures to create or lock `<id>.lock`, and reports
    /// [`io::ErrorKind::ResourceBusy`] if the file at that path was replaced under
    /// this one more often than [`LOCK_ATTEMPTS`] allows for.
    pub(crate) fn lock_spawn(&self) -> io::Result<SpawnLock> {
        self.acquire(FlockOperation::LockExclusive)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ResourceBusy,
                format!("the spawn lock for session {} kept being removed", self.id),
            )
        })
    }

    /// Takes the spawn lock if it is free this instant, for callers with better
    /// things to do than wait. `Ok(None)` means it was not granted.
    ///
    /// # Errors
    ///
    /// Propagates failures to create or open `<id>.lock`. A run directory that
    /// does not exist arrives as [`io::ErrorKind::NotFound`], which is not a
    /// failure so much as an answer: there is no session there to collect.
    pub(crate) fn try_lock_spawn(&self) -> io::Result<Option<SpawnLock>> {
        self.acquire(FlockOperation::NonBlockingLockExclusive)
    }

    /// Locks `<id>.lock` and confirms that what got locked is still that file.
    fn acquire(&self, operation: FlockOperation) -> io::Result<Option<SpawnLock>> {
        let path = self.lock();
        for _ in 0..LOCK_ATTEMPTS {
            let fd = rustix::fs::open(
                &path,
                OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )?;
            match rustix::fs::flock(&fd, operation) {
                Ok(()) => {}
                Err(rustix::io::Errno::WOULDBLOCK) => return Ok(None),
                Err(err) => return Err(err.into()),
            }
            let lock = SpawnLock { fd };
            if lock.is_file_at(&path) {
                return Ok(Some(lock));
            }
            // Collection removed the file while this call was waiting for it, so
            // what is held now is an inode nobody else can reach. Whoever asks
            // next creates a fresh file at the path and locks that instead, and
            // the two of them then hold one mutex each. Go back for the file that
            // is actually there.
        }
        Ok(None)
    }

    /// Removes every file belonging to this session, ignoring absences.
    ///
    /// `lock` is never read: it is the proof that the caller holds `<id>.lock`,
    /// which is what makes removing that file safe. Collection that skipped the
    /// lock would pull the spawn mutex out from under an attach that is using it
    /// (`IMPLEMENTATION.md` § 6.3), and could unlink the socket of a session that
    /// came up while the decision to collect was being made.
    pub(crate) fn unlink_all_locked(&self, _lock: &SpawnLock) {
        for path in [
            self.socket(),
            self.pid(),
            self.lock(),
            self.label(),
            self.agent(),
        ] {
            drop(fs::remove_file(path));
        }
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
        if let Ok(Some(lock)) = self.try_lock_spawn() {
            self.unlink_all_locked(&lock);
        }
    }
}

/// How many times an acquirer will re-take the lock on finding that the file it
/// locked is no longer the file at the path.
///
/// Each retry costs some other process a whole collection, so more than one or
/// two means a machine looping on `nomux list` rather than a race being lost; the
/// cap is only here so that such a machine cannot spin an attach forever.
const LOCK_ATTEMPTS: usize = 8;

/// An exclusive hold on a session's `<id>.lock`, released when this is dropped.
///
/// It serialises two attaches racing to create the same session
/// (`IMPLEMENTATION.md` § 6.3) and — less obviously — either of them against the
/// garbage collection of § 6.6, which removes `<id>.lock` along with the rest of
/// the session. Both must take it, because a file that is unlinked while it is
/// locked stops being a mutex at all: the next process to ask creates a new file
/// at the same path, locks that, and both are then certain they hold the only
/// lock there is.
#[derive(Debug)]
pub(crate) struct SpawnLock {
    /// Held only for the `flock` it carries; `close(2)` is what releases it.
    fd: OwnedFd,
}

impl SpawnLock {
    /// Whether the locked descriptor is still the file at `path`.
    ///
    /// `flock` attaches to the inode rather than to the name, so this is the only
    /// way to tell a lock on the spawn mutex from a lock on what used to be it.
    /// Either failure — an unreadable descriptor, a path that is gone — answers
    /// "no", which is the safe direction: the caller goes round again instead of
    /// acting on a lock it may not hold.
    fn is_file_at(&self, path: &Path) -> bool {
        let (Ok(held), Ok(named)) = (rustix::fs::fstat(&self.fd), rustix::fs::stat(path)) else {
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
    let mut out = String::new();
    for ch in label.chars().filter(|ch| !ch.is_control()) {
        if out.len() + ch.len_utf8() > MAX_LABEL_LEN {
            break;
        }
        out.push(ch);
    }
    out.trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

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
