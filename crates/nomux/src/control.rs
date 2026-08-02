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

use crate::rundir::{SessionPaths, run_dir, sanitize_label};

/// How long a terminated daemon has to exit before it is killed outright.
const TERM_GRACE: Duration = Duration::from_secs(2);

/// Interval between liveness checks while waiting out `TERM_GRACE`.
const REAP_POLL_INTERVAL: Duration = Duration::from_millis(25);

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
            Liveness::Stale => paths.unlink_all(),
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
/// Fails if the session id is invalid. A session that is already gone is not an
/// error — the postcondition is "no such session", which already holds.
pub(crate) fn kill(session_id: &str) -> io::Result<()> {
    let paths = SessionPaths::new(session_id)?;
    // Liveness first, and only then the pid. A daemon that died without unlinking —
    // `SIGKILL`, an OOM kill, a crash — leaves its pidfile behind, and the kernel
    // reuses pids, so signalling one read off disk without checking is how `nomux
    // kill` ends up terminating an unrelated process of the user's. The socket is
    // the authority on whether the daemon is still there.
    if liveness(&paths) == Liveness::Stale {
        paths.unlink_all();
        return Ok(());
    }
    let Some(pid) = read_pid(&paths) else {
        paths.unlink_all();
        return Ok(());
    };
    let Some(pid) = rustix::process::Pid::from_raw(pid) else {
        paths.unlink_all();
        return Ok(());
    };

    let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);

    let deadline = Instant::now() + TERM_GRACE;
    while Instant::now() < deadline {
        if liveness(&paths) == Liveness::Stale {
            paths.unlink_all();
            return Ok(());
        }
        thread::sleep(REAP_POLL_INTERVAL);
    }

    let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
    paths.unlink_all();
    Ok(())
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
