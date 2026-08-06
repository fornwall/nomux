//! Whether this session survives the user's last logout.
//!
//! `IMPLEMENTATION.md` § 6.2 has the rest. What it does not say is why nothing here can
//! do more than report: `KillUserProcesses=yes` kills every process in the user's
//! *slice* at logout, daemon included, and no amount of double-forking evades it.

use std::fs;
use std::io;
use std::path::Path;

use nomux::Linger;

use crate::passwd;

/// Present exactly when `systemd` is the running init.
const SYSTEMD_MARKER: &str = "/run/systemd/system";

/// Directory holding one empty file per lingering user.
const LINGER_DIR: &str = "/var/lib/systemd/linger";

/// Reports whether this user's processes outlive their session.
///
/// Two file lookups rather than `loginctl show-user -p Linger`, which is a D-Bus round
/// trip: on a bus that is wedged it blocks for its full 25-second timeout, and this runs
/// on the daemon's startup path, with the client that asked for the session waiting.
pub(crate) fn detect() -> Linger {
    if !Path::new(SYSTEMD_MARKER).is_dir() {
        // No `logind`, so nothing kills the daemon at logout and nothing to warn about.
        return Linger::Unknown;
    }
    let Some(user) = username() else {
        return Linger::Unknown;
    };
    state_of(Path::new(LINGER_DIR), &user)
}

/// Classifies one user's linger marker (`IMPLEMENTATION.md` § 6.2).
///
/// `logind` creates `LINGER_DIR` lazily, so a host where nobody lingers has no directory
/// at all and the whole lookup, not just the file, comes back `NotFound`.
fn state_of(dir: &Path, user: &str) -> Linger {
    match fs::metadata(dir.join(user)) {
        Ok(_) => Linger::Enabled,
        Err(err) if err.kind() == io::ErrorKind::NotFound => Linger::Disabled,
        Err(_) => Linger::Unknown,
    }
}

/// The login name, used as a filename component under [`LINGER_DIR`].
///
/// `IMPLEMENTATION.md` § 6.2 has the source order and the refusals. The environment is a
/// fallback rather than a peer: directory-backed accounts have no line in `/etc/passwd`.
///
/// Empty, `/`, NUL, `.` and `..` are refused because this name is joined onto a system
/// directory and `$USER` is the environment's to set: anything but a single component
/// asks about a path other than the one [`LINGER_DIR`] holds.
fn username() -> Option<String> {
    passwd::current()
        .map(|entry| entry.name)
        .or_else(|| {
            std::env::var("USER")
                .or_else(|_| std::env::var("LOGNAME"))
                .ok()
        })
        .filter(|name| {
            !name.is_empty()
                && !name.contains('/')
                && !name.contains('\0')
                && name != "."
                && name != ".."
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::scratch::Scratch;

    #[test]
    fn a_marker_file_means_enabled_and_its_absence_means_disabled() {
        let dir = Scratch::new("linger");
        fs::write(dir.join("lingerer"), "").unwrap();

        assert_eq!(state_of(dir.path(), "lingerer"), Linger::Enabled);
        assert_eq!(state_of(dir.path(), "someone_else"), Linger::Disabled);
    }

    /// Asked under a scratch directory that does exist, so the absence being asked
    /// about is `LINGER_DIR` itself rather than `$TMPDIR` — and so the guard has
    /// something to collect either way.
    #[test]
    fn a_missing_directory_is_disabled_not_unknown() {
        let root = Scratch::new("linger-absent");
        assert_eq!(
            state_of(&root.join("never-created"), "anyone"),
            Linger::Disabled
        );
    }
}
