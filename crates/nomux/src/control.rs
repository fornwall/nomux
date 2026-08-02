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

use crate::rundir::{SessionPaths, SpawnLock, check_run_dir, run_dir, sanitize_label};

/// How long a terminated daemon has to exit before it is killed outright.
const TERM_GRACE: Duration = Duration::from_secs(2);

/// How often to look again while waiting any of the three graces out.
///
/// One interval for all of them, rather than three tuned separately: each is a
/// wait on another process reaching a point of its own — exiting, dropping the
/// spawn lock, publishing a pidfile — and none of the three has a reason to be
/// noticed sooner than the others.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// How long `kill` waits for the spawn lock before giving up on the session.
///
/// Long enough for a healthy spawn — a `fork`, an `exec` and a `bind` — and for
/// any collection, which is five `unlink`s, so the ordinary race is simply won
/// rather than reported. Deliberately shorter than the five seconds an attach
/// spends waiting for a daemon that never starts: past that point telling the
/// caller is worth more than going on waiting.
const SPAWN_LOCK_GRACE: Duration = Duration::from_secs(2);

/// How long `kill` waits for a live daemon to publish `<id>.pid`.
///
/// The daemon binds its socket — which is what makes it answer as alive — before
/// it writes the pidfile (§ 6.2), so a `kill` that lands inside that window finds a
/// session that is unmistakably there and no pid to signal. `attach` holds the spawn
/// lock until the pidfile exists, which covers most of it — but only most: the file
/// is created empty and filled a syscall later, and `attach` lets go at the first
/// half. So the window is reachable from the ordinary spawn as well as from a daemon
/// somebody started by hand, and both halves of it — no file, and a file with nothing
/// in it — are waited out here. Waiting turns a spurious failure into the ordinary
/// answer;
/// bounded, because a socket that answers with no pidfile behind it may equally be
/// a daemon that died mid-publish, and this is the escape hatch — it does not hang.
const PUBLISH_GRACE: Duration = Duration::from_secs(2);

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
/// Turns the § 6.3 run-directory check into "is there one?" rather than an error to
/// be matched.
///
/// Both modes have to make that check before they trust any name inside the
/// directory, and both treat its absence as the question already answered: `list`
/// prints nothing, `kill` finds its postcondition already holding. Written out at
/// each site it was a five-line `match` per call — and `list` made two of them, for
/// two different reasons, which left a reader unable to tell which was load-bearing.
fn present(checked: io::Result<()>) -> io::Result<bool> {
    match checked {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

pub(crate) fn list() -> io::Result<()> {
    let dir = run_dir()?;
    // The same check every other path makes before it trusts this directory
    // (§ 6.3), and `list` needs it as much as any: it builds five paths per entry,
    // connects to one of them, and writes another straight to the caller's
    // terminal. Where `$XDG_RUNTIME_DIR/nomux` is a symlink into a directory
    // somebody else can write to, every one of those is a name they chose.
    //
    // Checked and never created: being asked what sessions exist must not be what
    // brings the place they would live into existence.
    if !present(check_run_dir(&dir))? {
        return Ok(());
    }
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        // Not the same absence as the one above, which is the ordinary "this host
        // has never run a session". The check has just opened this directory and
        // succeeded, so reaching here means it went away in between — a race, not a
        // state. Answered the same way because the answer is the same.
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
/// Fails if the session id is invalid, if the run directory is not this user's
/// alone (§ 6.3), if the spawn lock could not be taken within [`SPAWN_LOCK_GRACE`]
/// — see [`hold_spawn_lock`] — or if the session is alive but will not say which
/// process it is (see [`resolve`]). A session that is already gone is not an error
/// — the postcondition is "no such session", which already holds.
pub(crate) fn kill(session_id: &str) -> io::Result<()> {
    let paths = SessionPaths::new(session_id)?;
    // The same check `list` makes, and this is where it bites hardest: the two
    // things below are reading a pid out of a file and sending it a signal, and in
    // a run directory somebody else can write to, that number is theirs. Checked
    // rather than ensured — `kill` has no business creating a run directory.
    // Nowhere for the session to be is the postcondition already holding.
    if !present(paths.check_dir())? {
        return Ok(());
    }
    // Held from here to the end of the function. Nothing can spawn into this id
    // while it is held (§ 6.3), which is what keeps the two halves of this
    // operation talking about the same session: without it, an attach that starts
    // a fresh daemon between the signal below and the unlink that follows loses
    // its socket to a kill it was never the target of.
    let lock = hold_spawn_lock(&paths)?;
    let pid = match resolve(&paths)? {
        Target::Gone => {
            paths.unlink_all_locked(&lock);
            return Ok(());
        }
        Target::Daemon(pid) => pid,
    };

    let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);

    let deadline = Instant::now() + TERM_GRACE;
    while Instant::now() < deadline {
        if liveness(&paths) == Liveness::Stale {
            paths.unlink_all_locked(&lock);
            return Ok(());
        }
        thread::sleep(POLL_INTERVAL);
    }

    let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
    paths.unlink_all_locked(&lock);
    Ok(())
}

/// Takes the spawn lock for the whole of a `kill`, waiting briefly for it.
///
/// The wait is what makes `kill` *win* a race against the attach creating this
/// session rather than merely lose one: the holder releases once its daemon has
/// answered and published its pid, and that daemon is then killed on the next line
/// like any other. It is bounded rather than a blocking `flock` because this is the
/// frozen control surface — a process that has stopped while holding the lock is
/// not a reason for `kill` to hang forever.
///
/// [`SPAWN_LOCK_GRACE`] is deliberately shorter than the five seconds an attach
/// spends waiting for a daemon that never starts, so the one case this reports on a
/// session that no longer exists is an attach still parked on that timeout. Telling
/// the caller is worth more there than going on waiting: the attach is about to
/// fail, and its own failure is the better account of what happened.
///
/// # Errors
///
/// Reports [`io::ErrorKind::ResourceBusy`] when the lock is still held at the
/// deadline. Returning success there would make `kill` claim a postcondition it
/// did not establish — the session is still on disk and about to be listed again
/// — and the exit status is all the caller has to go on.
fn hold_spawn_lock(paths: &SessionPaths) -> io::Result<SpawnLock> {
    let deadline = Instant::now() + SPAWN_LOCK_GRACE;
    loop {
        if let Some(lock) = paths.try_lock_spawn() {
            return Ok(lock);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                format!(
                    "session {} is being started or removed by another process",
                    paths.id()
                ),
            ));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// What a locked session turns out to be.
#[derive(Debug)]
enum Target {
    /// Nothing is listening: the files are all that is left, and collectable.
    Gone,
    /// A daemon answered its socket and published this pid.
    Daemon(rustix::process::Pid),
}

/// Decides which of the two a locked session is.
///
/// Liveness first, and only then the pid. A daemon that died without unlinking —
/// `SIGKILL`, an OOM kill, a crash — leaves its pidfile behind, and the kernel
/// reuses pids, so signalling one read off disk without checking is how `nomux
/// kill` ends up terminating an unrelated process of the user's. The socket is the
/// authority on whether the daemon is still there.
///
/// The other direction is the one that had to be repaired: a socket that answers
/// and a pid that cannot be read is an **error**, never a "no such session". The
/// version this supersedes unlinked all five files there and exited 0, which took
/// the socket away from a daemon still holding the user's shell — the session then
/// answered nothing, appeared in no listing, and the next attach bound a second
/// daemon over the same id. There is exactly one benign reason for that state,
/// which is the daemon's own bind-to-publish window, so a *missing* pidfile is
/// waited out for [`PUBLISH_GRACE`] and anything else — a mode that hides it, a
/// body that is not a pid — is reported at once, since waiting cannot change it.
///
/// # Errors
///
/// Reports the reason a live session's pid could not be read.
fn resolve(paths: &SessionPaths) -> io::Result<Target> {
    let deadline = Instant::now() + PUBLISH_GRACE;
    loop {
        if liveness(paths) == Liveness::Stale {
            return Ok(Target::Gone);
        }
        let waiting_on = match fs::read_to_string(paths.pid()) {
            Ok(body) if !body.trim().is_empty() => {
                return parse_pid(&body)
                    .and_then(rustix::process::Pid::from_raw)
                    .map(Target::Daemon)
                    .ok_or_else(|| unreadable(paths, &format!("it holds {body:?}")));
            }
            // Present but empty is the same window one syscall later, and is
            // therefore waited out rather than reported. `SessionPaths::write_pid`
            // publishes in
            // two steps — `File::create`, which leaves a zero-length file, then the
            // `writeln!` that fills it — so a reader can land between them. Nor is
            // this only the hand-started case: `attach` releases the spawn lock as
            // soon as the path *exists*, which the empty file already satisfies, so
            // the ordinary spawn reaches it too. Reported as an error it refused to
            // kill a session that was in perfect health and about to finish starting.
            Ok(_) => "it was created but never written",
            Err(err) if err.kind() == io::ErrorKind::NotFound => "it never appeared",
            Err(err) => return Err(unreadable(paths, &err.to_string())),
        };
        if Instant::now() >= deadline {
            return Err(unreadable(paths, waiting_on));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// The refusal to touch a live session whose pid is not knowable.
///
/// It names the pidfile because that is the one thing the user can repair, and it
/// says what was *not* done, since "kill failed" reads like "the session is still
/// running" — which is exactly right here, and is the point.
fn unreadable(paths: &SessionPaths, problem: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "session {id} is running, but {pid}: {problem}; leaving it alone rather \
             than unlinking a live session's files",
            id = paths.id(),
            pid = paths.pid().display(),
        ),
    )
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
///
/// `None` from [`SessionPaths::try_lock_spawn`] means that and nothing else —
/// somebody holds it. A host that cannot lock at all hands back a claim anyway and
/// collection goes ahead, which is the point: an entry that stopped being
/// collectable because of the mutex protecting it would be a garbage collector that
/// leaks under exactly the conditions it exists for.
fn collect(paths: &SessionPaths) {
    let Some(lock) = paths.try_lock_spawn() else {
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

/// Reads what a session published as its pid, or nothing if it cannot be had.
///
/// `list` uses this, where any failure prints the same `?`. [`resolve`] keeps the
/// body instead, because a live session whose pid will not parse is the one case
/// that must be reported rather than shrugged off.
fn read_pid(paths: &SessionPaths) -> Option<i32> {
    parse_pid(&fs::read_to_string(paths.pid()).ok()?)
}

/// The pidfile's on-disk contract (§ 6.6), in the one place both readers share.
///
/// Zero and negatives are refused rather than passed on. `kill(2)` reads those as
/// a whole process group and as every process the caller may signal, so a pidfile
/// holding one is a number that must never reach a signal — and a daemon whose
/// pidfile says `0` is not a daemon this can identify.
fn parse_pid(body: &str) -> Option<i32> {
    body.trim().parse::<i32>().ok().filter(|pid| *pid > 0)
}
