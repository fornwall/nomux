//! Scratch directories for the unit tests inside this binary.
//!
//! Entirely `#[cfg(test)]`, so none of it is compiled into a shipped build.
//!
//! The integration tests get `CARGO_TARGET_TMPDIR` and a run root of their own
//! (`tests/harness/mod.rs`). Cargo sets that variable for integration tests and
//! benches only — measured, not assumed: `option_env!` reads `None` from here — so
//! the unit tests in `src/` have nowhere but `env::temp_dir()`, which is the
//! developer's ambient `$TMPDIR` shared with everything else on the host. That
//! makes both halves of the harness's naming argument load-bearing here rather than
//! merely tidy, and neither of them was done.
//!
//! What that cost, measured before this existed: `/tmp/nomux-226959-rundir-symlink`
//! and `/tmp/nomux-615195-rundir-mode` were still there a day after the run that
//! made them, because the cleanup sat on the success path and those runs had
//! failed. The second was left at mode `d-wx------`, which its own owner cannot
//! open — and which `remove_dir_all` therefore cannot empty either, so it would
//! have survived any amount of tidying up that did not know to repair it first.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Mode a directory has to be in before it can be removed: readable to list, and
/// executable to reach what is listed.
const REMOVABLE: u32 = 0o700;

/// A directory of this process's own, emptied and removed however the test ends.
///
/// On drop rather than at the end of the test body, which is the whole point: an
/// assertion that fires is exactly the case that used to leave one behind.
pub(crate) struct Scratch(PathBuf);

impl Scratch {
    /// An empty scratch directory named for `name` and for this process.
    ///
    /// The wipe on the way in stays even though the name carries this process's pid,
    /// for the reason the integration harness gives: pids are reused, and a run that
    /// crashed hard between the sweep and here leaves its directory behind.
    pub(crate) fn new(name: &str) -> Self {
        sweep_finished_runs();
        let dir = std::env::temp_dir().join(format!("nomux-{}-{name}", std::process::id()));
        make_removable(&dir);
        drop(fs::remove_dir_all(&dir));
        fs::create_dir_all(&dir).expect("create a scratch directory");
        Self(dir)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    pub(crate) fn join(&self, tail: &str) -> PathBuf {
        self.0.join(tail)
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
/// owner, and `remove_dir_all` has to read a directory to empty it. Restoring here
/// rather than at the end of the test body is what makes it happen on the path that
/// matters — the one where an assertion has already fired.
///
/// Symlinks are not followed: `read_dir` reports a link's own type, so a link
/// planted in place of a run directory is removed as the link it is and whatever it
/// points at is left alone. Which is the same promise `ensure_dir_at` makes, and it
/// would be an odd thing for the test's own cleanup to break.
///
/// The recursion got that from `read_dir` for nothing; the entry point has to buy it,
/// because `set_permissions` is `chmod(2)`, which follows, and Linux has no `lchmod`
/// to reach for instead. Both callers hand this a path somebody else may have replaced
/// — `Scratch::new` under a shared sticky `/tmp`, and `sweep_finished_runs` over every
/// `nomux-<dead-pid>-*` entry it finds there — so without the check a link planted at
/// one of those names is a `chmod` of whatever it points at. As an ordinary user that
/// fails `EPERM` on somebody else's file; as root, which `rundir`'s tests treat as a
/// supported way to run this suite, it succeeds.
fn make_removable(dir: &Path) {
    // `symlink_metadata`, so the answer is about the name rather than about what it
    // resolves to — and anything that is not a directory of ours has neither a mode
    // worth repairing nor entries to recurse into.
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

/// Removes the scratch directories of test processes that have exited.
///
/// The pid in the name is what lets two runs proceed at once, and it is equally
/// what stops a run from reusing what the last one left. A directory goes only once
/// `/proc` says its process is gone — a live pid is either this one or a run in
/// flight, and taking either away is the exact fault the naming exists to prevent.
fn sweep_finished_runs() {
    let temp = std::env::temp_dir();
    let Ok(entries) = fs::read_dir(&temp) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let owner = name
            .to_string_lossy()
            .strip_prefix("nomux-")
            .and_then(|tail| tail.split_once('-'))
            .and_then(|(pid, _)| pid.parse::<u32>().ok());
        if owner.is_some_and(|pid| !Path::new(&format!("/proc/{pid}")).exists()) {
            let path = entry.path();
            make_removable(&path);
            drop(fs::remove_dir_all(&path));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The permission bits as they are on disk, never as a symlink pointing at the
    /// file would report them.
    fn mode_of(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    /// Both directions of the guard at the top of [`make_removable`], because either
    /// one alone is a fault: a `chmod` that follows a link is somebody else's file at
    /// [`REMOVABLE`], and a guard that turns any of them away is a scratch directory
    /// left behind on every run that fails.
    ///
    /// The recursion gets the first half from `read_dir`, which reports a link's own
    /// type. The entry point cannot: `set_permissions` is `chmod(2)`, which follows,
    /// and both callers hand it a path somebody else may have replaced — `Scratch::new`
    /// under a shared sticky `/tmp`, and [`sweep_finished_runs`] over every
    /// `nomux-<dead-pid>-*` name it finds there.
    #[test]
    fn make_removable_repairs_a_directory_and_does_not_follow_a_link_to_one() {
        let root = Scratch::new("scratch-make-removable");

        let victim = root.join("victim");
        fs::write(&victim, b"not ours to chmod").expect("plant a file of somebody's");
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).expect("at its own mode");
        let link = root.join("link");
        std::os::unix::fs::symlink(&victim, &link).expect("plant a link where a run dir goes");

        // A real directory, shut the way the mode tests leave one — and shut from the
        // inside out, since the outer one has to be open to create the inner.
        let dir = root.join("dir");
        let nested = dir.join("nested");
        fs::create_dir_all(&nested).expect("create a directory and one under it");
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
