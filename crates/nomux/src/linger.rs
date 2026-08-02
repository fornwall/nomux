//! Whether this session survives the user's last logout.
//!
//! `systemd-logind` with `KillUserProcesses=yes` kills every process in the user's
//! slice at logout, daemon included, and no amount of double-forking evades it
//! (`IMPLEMENTATION.md` § 6.2). The only fix is `loginctl enable-linger`, which is
//! the user's to run. So the daemon detects the state, reports it in `HelloOk`, and
//! does nothing else about it.
//!
//! Detection is two `stat` calls rather than the `loginctl show-user -p Linger`
//! the design sketches, because this runs on the path that starts a session:
//! `loginctl` is a D-Bus round trip that can block for its full 25-second timeout
//! on a busy or broken bus, which would outlast the client's spawn deadline and
//! turn "linger is off" into "the session would not start". The files below are
//! what `logind` itself reads, so the answer is the same one `loginctl` prints.

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
/// Absence is the answer, not a failure: `logind` creates `LINGER_DIR` lazily, so
/// a host where nobody lingers has no directory at all. Only a lookup that fails
/// for a reason *other* than absence — a permission change, a bind mount over the
/// path — is genuinely unknown, and reporting `Disabled` there would make the
/// client warn about a session that is in fact safe.
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
/// name that is not this user's; `$USER` second, for directory-backed accounts
/// that have no line in `/etc/passwd`. Anything usable as a path traversal is
/// refused outright — the value would be joined onto a system directory, and a
/// nonsense answer is better than an interesting one.
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

    /// A scratch directory of this process's own, so concurrent test binaries do
    /// not share one.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("nomux-{}-{name}", std::process::id()));
        drop(fs::remove_dir_all(&dir));
        dir
    }

    #[test]
    fn a_marker_file_means_enabled_and_its_absence_means_disabled() {
        let dir = scratch("linger");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("lingerer"), "").unwrap();

        assert_eq!(state_of(&dir, "lingerer"), Linger::Enabled);
        assert_eq!(state_of(&dir, "someone_else"), Linger::Disabled);
        drop(fs::remove_dir_all(&dir));
    }

    /// A host where no one has ever enabled lingering has no directory, which is
    /// still a definite "off" rather than an unknown.
    #[test]
    fn a_missing_directory_is_disabled_not_unknown() {
        assert_eq!(
            state_of(&scratch("linger-absent"), "anyone"),
            Linger::Disabled
        );
    }
}
