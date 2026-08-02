//! The frozen control surface: `list` and `kill`.
//!
//! These must work against a daemon of *any* version, including one older than
//! the binary running them, because they are the escape hatch that makes the N-1
//! codec policy safe (`DESIGN.md` § 6.4). So the contract here is the on-disk
//! layout — never a protocol frame, never `PROTOCOL_VERSION`.

use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};
use std::{fs, thread};

use crate::rundir::{SessionPaths, SpawnLock, run_dir, sanitize_label};

/// How long a terminated daemon has to exit before it is killed outright.
const TERM_GRACE: Duration = Duration::from_secs(2);

/// Interval between liveness checks while waiting out `TERM_GRACE`.
const REAP_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// How long `kill` waits for the spawn lock before giving up on the session.
///
/// Long enough for a healthy spawn — a `fork`, an `exec` and a `bind` — and for
/// any collection, which is five `unlink`s, so the ordinary race is simply won
/// rather than reported. Deliberately shorter than the five seconds an attach
/// spends waiting for a daemon that never starts: past that point telling the
/// caller is worth more than going on waiting.
const SPAWN_LOCK_GRACE: Duration = Duration::from_secs(2);

/// State of one session as seen from the run directory alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Liveness {
    /// A daemon accepted a connection.
    Alive,
    /// The socket exists but nothing is listening; the daemon died.
    Stale,
}

/// Prints one line per live session: id, pid and label.
///
/// # Errors
///
/// Fails if the run directory cannot be read. A missing directory is not an
/// error — it simply means no session has ever been created.
pub(crate) fn list() -> io::Result<()> {
    let dir = run_dir()?;
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };

    let mut ids: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| session_id_of(&entry.path()))
        .collect();
    ids.sort_unstable();

    let stdout = io::stdout();
    let mut out = stdout.lock();
    for id in ids {
        let Ok(paths) = SessionPaths::new(&id) else {
            continue;
        };
        match liveness(&paths) {
            Liveness::Stale => collect(&paths),
            Liveness::Alive => {
                let pid = read_pid(&paths).map_or_else(|| "?".to_owned(), |pid| pid.to_string());
                // Sanitised on read as well as on write. The file is sanitised
                // going in, but this is the frozen layout (§ 6.6): the daemon that
                // wrote it may be any version, and the bytes land on the terminal
                // of whoever ran `list`. A label carrying `ESC ]0;` would retitle
                // their window.
                let label = sanitize_label(&fs::read_to_string(paths.label()).unwrap_or_default());
                writeln!(out, "{id}\t{pid}\t{label}")?;
            }
        }
    }
    Ok(())
}

/// Terminates a session and removes its run files.
///
/// # Errors
///
/// Fails if the session id is invalid, or if the spawn lock could not be taken
/// within [`SPAWN_LOCK_GRACE`] — see [`hold_spawn_lock`]. A session that is
/// already gone is not an error — the postcondition is "no such session", which
/// already holds.
pub(crate) fn kill(session_id: &str) -> io::Result<()> {
    let paths = SessionPaths::new(session_id)?;
    // Held from here to the end of the function. Nothing can spawn into this id
    // while it is held (§ 6.3), which is what keeps the two halves of this
    // operation talking about the same session: without it, an attach that starts
    // a fresh daemon between the signal below and the unlink that follows loses
    // its socket to a kill it was never the target of.
    let Some(lock) = hold_spawn_lock(&paths)? else {
        return Ok(());
    };
    // Liveness first, and only then the pid. A daemon that died without unlinking —
    // `SIGKILL`, an OOM kill, a crash — leaves its pidfile behind, and the kernel
    // reuses pids, so signalling one read off disk without checking is how `nomux
    // kill` ends up terminating an unrelated process of the user's. The socket is
    // the authority on whether the daemon is still there.
    if liveness(&paths) == Liveness::Stale {
        paths.unlink_all_locked(&lock);
        return Ok(());
    }
    let Some(pid) = read_pid(&paths) else {
        paths.unlink_all_locked(&lock);
        return Ok(());
    };
    let Some(pid) = rustix::process::Pid::from_raw(pid) else {
        paths.unlink_all_locked(&lock);
        return Ok(());
    };

    let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);

    let deadline = Instant::now() + TERM_GRACE;
    while Instant::now() < deadline {
        if liveness(&paths) == Liveness::Stale {
            paths.unlink_all_locked(&lock);
            return Ok(());
        }
        thread::sleep(REAP_POLL_INTERVAL);
    }

    let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
    paths.unlink_all_locked(&lock);
    Ok(())
}

/// Takes the spawn lock for the whole of a `kill`, waiting briefly for it.
///
/// `Ok(None)` means there is no run directory to lock in, and therefore no
/// session: the postcondition holds without anything being done.
///
/// The wait is what makes `kill` *win* a race against the attach creating this
/// session rather than merely lose one: the holder releases as soon as its daemon
/// answers, and that daemon is then killed on the next line like any other. It is
/// bounded rather than a blocking `flock` because this is the frozen control
/// surface — a process that has stopped while holding the lock is not a reason
/// for `kill` to hang forever.
///
/// # Errors
///
/// Reports [`io::ErrorKind::ResourceBusy`] when the lock is still held at the
/// deadline. Returning success there would make `kill` claim a postcondition it
/// did not establish — the session is still on disk and about to be listed again
/// — and the exit status is all the caller has to go on.
fn hold_spawn_lock(paths: &SessionPaths) -> io::Result<Option<SpawnLock>> {
    let deadline = Instant::now() + SPAWN_LOCK_GRACE;
    loop {
        match paths.try_lock_spawn() {
            Ok(Some(lock)) => return Ok(Some(lock)),
            Ok(None) if Instant::now() >= deadline => {
                return Err(io::Error::new(
                    io::ErrorKind::ResourceBusy,
                    format!(
                        "session {} is being started or removed by another process",
                        paths.id()
                    ),
                ));
            }
            Ok(None) => thread::sleep(REAP_POLL_INTERVAL),
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        }
    }
}

/// Removes a dead session's files, or leaves them to whoever comes next.
///
/// The probe that got us here is a hint rather than a verdict. `<id>.lock` is the
/// mutex an attach holds across creating a session (§ 6.3) and is itself one of
/// the files removed below, so an entry that looked stale a moment ago may be one
/// an attach is in the middle of bringing up — and taking that mutex out from
/// under it is how two attaches end up each holding a lock of their own. So
/// collection takes the same lock, and gives up rather than waits: a session
/// somebody is starting is not garbage, `list` is a snapshot either way, and the
/// entry is collectable for as long as it stays dead.
///
/// Liveness is then decided again under the lock, which is the only place the
/// answer cannot change between being read and being acted on.
fn collect(paths: &SessionPaths) {
    let Ok(Some(lock)) = paths.try_lock_spawn() else {
        return;
    };
    if liveness(paths) == Liveness::Stale {
        paths.unlink_all_locked(&lock);
    }
}

/// Extracts a session id from a `*.sock` path, ignoring anything else.
fn session_id_of(path: &Path) -> Option<String> {
    if path.extension()? != "sock" {
        return None;
    }
    Some(path.file_stem()?.to_str()?.to_owned())
}

/// Probes the socket. A refused connection means the daemon is gone; the socket
/// file outlives the process that bound it.
fn liveness(paths: &SessionPaths) -> Liveness {
    match UnixStream::connect(paths.socket()) {
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) =>
        {
            Liveness::Stale
        }
        // A successful connect obviously means alive; so does anything else, such
        // as EACCES, which is not evidence of death. Never unlink on a guess.
        _ => Liveness::Alive,
    }
}

fn read_pid(paths: &SessionPaths) -> Option<i32> {
    fs::read_to_string(paths.pid())
        .ok()?
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|pid| *pid > 0)
}
