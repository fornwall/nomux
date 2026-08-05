//! Whether this session survives the user's last logout.
//!
//! `IMPLEMENTATION.md` § 6.2 has most of it: why `loginctl enable-linger` is the only
//! fix and the user's to run, why the two files below are read instead of asking
//! `loginctl`, and what the marker's absence means. What it does not say is the
//! mechanism, and the mechanism is what rules out doing anything here rather than
//! reporting: `KillUserProcesses=yes` kills every process in the user's *slice* at
//! logout, daemon included, and no amount of double-forking evades it.
//!
//! [`username`] has the order the last two sources are consulted in.

use std::fs;
use std::io;
use std::path::Path;

use nomux_proto::Linger;

use crate::passwd;

/// Present exactly when `systemd` is the running init.
const SYSTEMD_MARKER: &str = "/run/systemd/system";

/// Directory holding one empty file per lingering user.
const LINGER_DIR: &str = "/var/lib/systemd/linger";

/// Reports whether this user's processes outlive their session.
pub(crate) fn detect() -> Linger {
    if !Path::new(SYSTEMD_MARKER).is_dir() {
        // No `logind`, so nothing kills the daemon at logout and there is nothing
        // for the client to warn about.
        return Linger::Unknown;
    }
    let Some(user) = username() else {
        return Linger::Unknown;
    };
    state_of(Path::new(LINGER_DIR), &user)
}

/// Classifies one user's linger marker.
///
/// Absence is the answer rather than a failure (`IMPLEMENTATION.md` § 6.2), and
/// `logind` creates `LINGER_DIR` lazily, so a host where nobody lingers has no
/// directory at all. Only a lookup that fails for some *other* reason — a permission
/// change, a bind mount over the path — is unknown.
fn state_of(dir: &Path, user: &str) -> Linger {
    match fs::metadata(dir.join(user)) {
        Ok(_) => Linger::Enabled,
        Err(err) if err.kind() == io::ErrorKind::NotFound => Linger::Disabled,
        Err(_) => Linger::Unknown,
    }
}

/// The login name, used as a filename component under [`LINGER_DIR`].
///
/// The password database first, because it is authoritative and cannot contain a
/// name that is not this user's; `$USER` second, for directory-backed accounts that
/// have no line in `/etc/passwd`. Anything usable as a path traversal is refused
/// outright — the value is joined onto a system directory.
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

    /// A host where no one has ever enabled lingering has no directory, which is
    /// still a definite "off" rather than an unknown.
    ///
    /// Under a scratch directory that does exist, so the absence being asked about
    /// is `LINGER_DIR` itself rather than `$TMPDIR` — and so the guard has something
    /// to collect either way.
    #[test]
    fn a_missing_directory_is_disabled_not_unknown() {
        let root = Scratch::new("linger-absent");
        assert_eq!(
            state_of(&root.join("never-created"), "anyone"),
            Linger::Disabled
        );
    }
}
