//! Scratch directories for the unit tests inside this binary.
//!
//! Entirely `#[cfg(test)]`, so none of it is compiled into a shipped build.
//!
//! The integration tests get `CARGO_TARGET_TMPDIR` and a run root of their own
//! (`tests/harness/mod.rs`). Cargo sets that variable for integration tests and
//! benches only — measured, not assumed: `option_env!` reads `None` from here — so
//! the unit tests in `src/` have nowhere but the developer's ambient `$TMPDIR`,
//! shared with everything else on the host. Both halves of the harness's naming
//! argument are therefore load-bearing here.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Mode a directory has to be in before it can be removed: readable to list, and
/// executable to reach what is listed.
const REMOVABLE: u32 = 0o700;

/// Serialises everything in this process whose result depends on the umask.
///
/// `rundir::with_umask` sets a process-wide umask for the length of one call, which
/// was sound while nothing in the crate was multi-threaded. `cargo test` is: two of
/// those calls interleave and the second restores the *first's* mask, leaving the
/// process at `0177` for good. `cargo nextest` gives each test a process and never
/// sees it.
///
/// Held by `with_umask` and by every directory this module creates, which is the
/// whole of what a test process creates whose mode it does not set itself.
///
/// Poisoning is ignored: a taker that panicked was a failing assertion, not a broken
/// lock, and refusing everyone after it would turn one red test into all of them.
pub(crate) fn umask_lock() -> MutexGuard<'static, ()> {
    static UMASK: Mutex<()> = Mutex::new(());
    UMASK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The permission bits as they are on disk, never as a symlink pointing at the file would
/// report them.
pub(crate) fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

/// Creates `dir` and every parent it needs, under [`umask_lock`].
fn create_dir(dir: &Path) {
    let _umask = umask_lock();
    fs::create_dir_all(dir).expect("create a scratch directory");
}

/// A directory of this process's own, emptied and removed however the test ends.
///
/// On drop rather than at the end of the test body, which is the whole point: an
/// assertion that fires is exactly the case that used to leave one behind.
pub(crate) struct Scratch(PathBuf);

impl Scratch {
    /// An empty scratch directory named for `name` and for this process.
    ///
    /// The wipe on the way in stays even though the name carries this process's pid,
    /// for the reason the integration harness gives: pids are reused.
    pub(crate) fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("nomux-{}-{name}", std::process::id()));
        make_removable(&dir);
        drop(fs::remove_dir_all(&dir));
        create_dir(&dir);
        Self(dir)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    pub(crate) fn join(&self, tail: &str) -> PathBuf {
        self.0.join(tail)
    }

    /// A directory at `tail`, created the way the root was: a bare
    /// `fs::create_dir_all` in a test body is what [`umask_lock`] exists to stop.
    pub(crate) fn dir(&self, tail: &str) -> PathBuf {
        let path = self.join(tail);
        create_dir(&path);
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        make_removable(&self.0);
        drop(fs::remove_dir_all(&self.0));
    }
}

/// Puts `dir` and every directory under it back into a mode that can be removed.
///
/// The mode tests deliberately leave directories nobody can open, including their
/// owner, and `remove_dir_all` has to read a directory to empty it.
///
/// Symlinks are not followed, which is the same promise `ensure_dir_at` makes. The
/// recursion gets that from `read_dir`; the entry point has to buy it, because
/// `set_permissions` is `chmod(2)`, which follows, and Linux has no `lchmod`. Both
/// callers hand this a path somebody else may have replaced, so without the check a
/// link planted at one of those names is a `chmod` of whatever it points at —
/// successful as root, which `rundir`'s tests treat as a supported way to run this
/// suite.
fn make_removable(dir: &Path) {
    // `symlink_metadata`, so the answer is about the name rather than about what it
    // resolves to.
    if !fs::symlink_metadata(dir).is_ok_and(|meta| meta.is_dir()) {
        return;
    }
    drop(fs::set_permissions(
        dir,
        fs::Permissions::from_mode(REMOVABLE),
    ));
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            make_removable(&entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both directions of the guard at the top of [`make_removable`], because either
    /// one alone is a fault: a `chmod` that follows a link is somebody else's file at
    /// [`REMOVABLE`], and a guard that turns any of them away is a scratch directory
    /// left behind on every run that fails.
    #[test]
    fn make_removable_repairs_a_directory_and_does_not_follow_a_link_to_one() {
        let root = Scratch::new("scratch-make-removable");

        let victim = root.join("victim");
        fs::write(&victim, b"not ours to chmod").expect("plant a file of somebody's");
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).expect("at its own mode");
        let link = root.join("link");
        std::os::unix::fs::symlink(&victim, &link).expect("plant a link where a run dir goes");

        // A real directory, shut the way the mode tests leave one, from the inside
        // out since the outer has to be open to create the inner.
        let nested = root.dir("dir/nested");
        let dir = root.join("dir");
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o300)).expect("shut the inner");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o300)).expect("shut the outer");

        make_removable(&link);
        make_removable(&dir);

        assert_eq!(
            mode_of(&victim),
            0o644,
            "the mode belongs to what the link points at, which this was never asked \
             to touch"
        );
        assert_eq!(mode_of(&dir), REMOVABLE, "a directory of ours is repaired");
        assert_eq!(
            mode_of(&nested),
            REMOVABLE,
            "and so is one under it, or `remove_dir_all` cannot empty the parent"
        );
    }
}
