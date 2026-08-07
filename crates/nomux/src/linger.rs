//! The user's advisory systemd linger-marker state.
//!
//! `IMPLEMENTATION.md` § 6.2 has the rest. Enabling linger keeps the user manager alive;
//! it does not move this daemon out of the SSH `session-*.scope`. Nothing here therefore
//! claims that the current session survives logout.

use std::fs;
use std::io;
use std::path::Path;

use nomux::Linger;

/// Present exactly when `systemd` is the running init.
const SYSTEMD_MARKER: &str = "/run/systemd/system";

/// Directory holding one empty file per lingering user.
const LINGER_DIR: &str = "/var/lib/systemd/linger";

/// Reports whether systemd's linger marker is present for this user.
///
/// Two file lookups rather than `loginctl show-user -p Linger`, which is a D-Bus round
/// trip: on a bus that is wedged it blocks for its full 25-second timeout, and this runs
/// with the client that asked for the session waiting on the answer.
///
/// Called per greeting rather than once at startup, and cheap enough to be: the marker can
/// change while a session exists. It is useful to a future user-manager-backed launcher,
/// but is not evidence that this session-scoped process has escaped logout policy.
pub(crate) fn detect() -> Linger {
    if !Path::new(SYSTEMD_MARKER).is_dir() {
        // No systemd classification is available; another init may still impose policy.
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
/// `$USER`, then `$LOGNAME`, and nothing else. The password database used to sit in front
/// of them and could never decide anything: [`detect`] answers `Unknown` without asking
/// unless [`SYSTEMD_MARKER`] is there, and a host running `logind` is one where PAM has
/// set both variables — so it bought a second parse of `/etc/passwd` per session and no
/// answer that these two did not already give.
///
/// Empty, `/`, NUL, `.` and `..` are refused because this name is joined onto a system
/// directory and `$USER` is the environment's to set: anything but a single component
/// asks about a path other than the one [`LINGER_DIR`] holds. Asked of each source in
/// turn rather than of the answer, so a `$USER` that fails it falls through to `$LOGNAME`
/// as the stated order implies, rather than ending the lookup.
fn username() -> Option<String> {
    ["USER", "LOGNAME"]
        .into_iter()
        .filter_map(|variable| std::env::var(variable).ok())
        .find(|name| {
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
