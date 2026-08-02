//! Run-directory layout.
//!
//! This layout is the frozen contract described in `IMPLEMENTATION.md` § 6.6:
//! `list` and `kill` operate on it alone, never on the session protocol, so any
//! build can manage a daemon of any version. Filenames and permissions here may
//! never change.

use std::io;
use std::path::PathBuf;
use std::{env, fs};

use nomux_proto::is_valid_session_id;

/// Permissions for the run directory: owner-only, since it holds the sockets that
/// grant access to live sessions.
pub(crate) const DIR_MODE: u32 = 0o700;

/// Permissions for every socket inside it.
pub(crate) const SOCKET_MODE: u32 = 0o600;

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

    /// `ssh-agent` socket, once agent forwarding is implemented.
    #[must_use]
    pub(crate) fn agent(&self) -> PathBuf {
        self.with_extension("agent")
    }

    /// Removes every file belonging to this session, ignoring absences.
    pub(crate) fn unlink_all(&self) {
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
}
