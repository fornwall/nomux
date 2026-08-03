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

use crate::rundir::{SessionPaths, SpawnLock, check_run_dir, read_label, read_prefix, run_dir};

/// How long a terminated daemon has to exit before it is killed outright.
const TERM_GRACE: Duration = Duration::from_secs(2);

/// How long a killed daemon has to actually go before `kill` concludes that the
/// signal never reached whatever is serving the socket.
///
/// Nothing survives `SIGKILL`, so this is not a grace in the sense the one above
/// is: an ordinary daemon is gone within microseconds of it and the wait is never
/// observed. What it bounds is the case where the pid being signalled is *not* the
/// process behind the socket — a stale pidfile whose number the kernel has since
/// reissued — where the two signals landed on a stranger and the session is still
/// running. Half a second is far beyond how long dying takes and far short of
/// making the failure slow to report.
const KILL_GRACE: Duration = Duration::from_millis(500);

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
/// The daemon binds its socket — which is what makes it answer as alive — before it
/// writes the pidfile (§ 6.2), so a `kill` that lands inside that window finds a
/// session that is unmistakably there and no pid to signal. `attach` holds the spawn
/// lock only until the path *exists*, which the empty file left by the first half of
/// publishing already satisfies, so the ordinary spawn reaches that window as well as
/// a daemon somebody started by hand. Both halves of it — no file, and a file with
/// nothing in it — are waited out here, which turns a spurious failure into the
/// ordinary answer. Bounded, because a socket that answers with no pidfile behind it
/// may equally be a daemon that died mid-publish, and this is the escape hatch — it
/// does not hang.
const PUBLISH_GRACE: Duration = Duration::from_secs(2);

/// Longest `<id>.pid` body this reads.
///
/// The layout says a pid in ASCII and a newline (§ 6.6), which is eleven bytes at
/// the widest a pid can be; the rest is room for whatever whitespace a file repaired
/// by hand carries. Bounded at all for [`read_prefix`]'s reason: what somebody left
/// at that path does not get to decide how much memory the escape hatch faults in.
const MAX_PID_LEN: usize = 32;

/// State of one session as seen from the run directory alone.
#[derive(Debug)]
enum Liveness {
    /// A daemon accepted a connection, which is handed over with the answer: that
    /// connection is what ties a pid to this socket (see [`daemon_of`]).
    ///
    /// `None` where liveness was concluded from something *other* than an accepted
    /// connection — see [`liveness`] — and so with nothing to ask.
    Alive(Option<UnixStream>),
    /// The socket exists but nothing is listening; the daemon died.
    Stale,
}

/// Turns the § 6.3 run-directory check into "is there one?" rather than an error to
/// be matched.
///
/// Both modes have to make that check before they trust any name inside the
/// directory, and both treat its absence as the question already answered: `list`
/// prints nothing, `kill` finds its postcondition already holding.
fn present(checked: io::Result<()>) -> io::Result<bool> {
    match checked {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

/// Prints one line per live session: id, pid and label.
///
/// A reader that closes stdout early — `nomux list | head` — ends the listing rather
/// than failing it. The Rust runtime ignores `SIGPIPE` (§ 6.2 depends on that), so
/// the write comes back `EPIPE` instead of ending the process, and § 10 already reads
/// a closed stdout as a clean end for `attach`. What it does *not* end is the sweep:
/// the ids are already in hand, so finishing it costs one `connect` and at most five
/// `unlink`s per dead session and leaves nothing behind, where returning early would
/// make `head` the reason a stale session survived.
///
/// # Errors
///
/// Fails if the run directory cannot be read. A missing directory is not an
/// error — it simply means no session has ever been created.
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
    // One entry per session, not per file: five names lead to the same id.
    ids.dedup();

    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut listening = true;
    for id in ids {
        let Ok(paths) = SessionPaths::new(&id) else {
            continue;
        };
        match liveness(&paths) {
            Liveness::Stale => collect(&paths),
            // Nowhere left to print to, and the arm above is the whole reason the
            // loop goes on anyway.
            Liveness::Alive(_) if !listening => {}
            Liveness::Alive(_) => {
                let pid = read_pid(&paths).map_or_else(|| "?".to_owned(), |pid| pid.to_string());
                // Sanitised on read as well as on write. The file is sanitised
                // going in, but this is the frozen layout (§ 6.6): the daemon that
                // wrote it may be any version, and the bytes land on the terminal
                // of whoever ran `list`. A label carrying `ESC ]0;` would retitle
                // their window.
                let label = read_label(&paths.label());
                match writeln!(out, "{id}\t{pid}\t{label}") {
                    Err(err) if err.kind() == io::ErrorKind::BrokenPipe => listening = false,
                    outcome => outcome?,
                }
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
/// — see [`hold_spawn_lock`] — if the session is alive but will not say which
/// process it is (see [`resolve`]), or if it goes on answering after both signals,
/// which means the pid it published is not the process serving it. A session that
/// is already gone is not an error — the postcondition is "no such session", which
/// already holds.
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
    if let Target::Daemon(pid) = resolve(&paths)? {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
        // Liveness first, deadline second, so a daemon that let go on the last
        // interval is not signalled again: the pid it published is reusable the
        // moment it is reaped, and `SIGKILL` is the one signal nothing survives.
        let mut deadline = Instant::now() + TERM_GRACE;
        let mut killed = false;
        while matches!(liveness(&paths), Liveness::Alive(_)) {
            if Instant::now() >= deadline {
                // Still answering after `SIGKILL`, which nothing survives — so the
                // pid that was signalled is not the process serving this socket, and
                // the two signals went to a stranger. [`resolve`] takes that pid from
                // the socket wherever the socket will name one, which leaves the
                // pidfile fallback as the way this is still reachable. The unlink
                // below is unconditional, so without this it would take a live
                // session's socket with it, which is the one thing § 6.6 promises
                // never happens. Refused instead, the same way `resolve` refuses a
                // session it cannot identify.
                if killed {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "session {id} is still answering after SIGTERM and SIGKILL to \
                             pid {pid}, so that pid is not the process serving it; leaving \
                             it alone rather than unlinking a live session's files",
                            id = paths.id(),
                            pid = pid.as_raw_nonzero(),
                        ),
                    ));
                }
                let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
                killed = true;
                deadline = Instant::now() + KILL_GRACE;
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
    // The one *successful* exit from the locked region, and so the one place the
    // files go: a session that was already gone, one that stopped on `SIGTERM` and
    // one that had to be killed all leave the same nothing behind. Every other exit
    // is a `?` or a `return` above, and none of them unlinks anything — § 6.6 keeps
    // all five files whenever `kill` cannot establish that the session is dead.
    paths.unlink_all_locked(&lock)
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
/// It is the authority on *which* process it is, too, wherever it will say: the
/// connection that just answered carries the pid in [`daemon_of`], and nothing at a
/// filename can forge that. `<id>.pid` is what is left when it will not — the
/// bind-to-publish window has no file yet, and § 6.2's fork leaves a socket whose
/// creator is gone and an heir only the file names — so the file is read second and
/// believed only there.
///
/// The other direction is § 6.6's rule that a live session's files are never
/// unlinked: a socket that answers and no pid to be had either way is an **error**,
/// never a "no such session". There is exactly one benign reason for that state,
/// which is the daemon's own bind-to-publish window, so a *missing* pidfile is
/// waited out for [`PUBLISH_GRACE`] and anything else — a mode that hides it, a
/// body that is not a pid — is reported at once, since waiting cannot change it.
///
/// # Errors
///
/// Reports the reason a live session's pid could not be had.
fn resolve(paths: &SessionPaths) -> io::Result<Target> {
    let deadline = Instant::now() + PUBLISH_GRACE;
    loop {
        let Liveness::Alive(answered) = liveness(paths) else {
            return Ok(Target::Gone);
        };
        if let Some(pid) = answered.as_ref().and_then(daemon_of) {
            return Ok(Target::Daemon(pid));
        }
        let mut buf = [0u8; MAX_PID_LEN];
        let waiting_on = match read_prefix(&paths.pid(), &mut buf) {
            Ok(body) if !body.trim_ascii().is_empty() => {
                return parse_pid(body)
                    .and_then(rustix::process::Pid::from_raw)
                    .map(Target::Daemon)
                    .ok_or_else(|| {
                        let body = String::from_utf8_lossy(body);
                        unreadable(paths, &format!("it holds {body:?}"))
                    });
            }
            // Present but empty is the same window one syscall later, and is therefore
            // waited out rather than reported: `SessionPaths::write_pid` publishes in
            // two steps — a `File::create` that leaves a zero-length file, then the one
            // `write` that fills it — so a reader can land between them. Reported as an
            // error it refused to kill a session in perfect health.
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

/// The daemon behind a connection that answered: the process that called `listen`.
///
/// `SO_PEERCRED` on the *client* side of a unix socket reports the credentials the
/// kernel recorded for the listening socket, which it takes at `listen(2)` from the
/// process performing it. So this is the one number on this surface that is tied to
/// the socket rather than to a name in a directory — a stale `<id>.pid`, or one a
/// user repaired by hand, cannot make it point anywhere.
///
/// `None` where that process no longer exists, which is not a formality: § 6.2's
/// interactive path binds the socket and *then* forks, so a daemon that had to detach
/// that way is an heir serving a socket its exited parent created, and the parent's
/// number is exactly the reissuable one this exists to stop signalling. The pidfile,
/// written after that fork by the process that survived it, is the only account of
/// the heir — so an answer of `None` sends [`resolve`] there rather than at a stranger.
fn daemon_of(answered: &UnixStream) -> Option<rustix::process::Pid> {
    let creator = rustix::net::sockopt::socket_peercred(answered).ok()?.pid;
    rustix::process::test_kill_process(creator)
        .is_ok()
        .then_some(creator)
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
/// The probe that got us here is a hint rather than a verdict, so collection takes
/// `<id>.lock` and decides liveness again under it — the only place the answer cannot
/// change between being read and being acted on (§ 6.6). It gives up rather than
/// waits, because that lock is also the mutex an attach holds across creating a
/// session (§ 6.3) and is itself one of the files removed below: taking it out from
/// under an attach is how two of them end up each holding a lock of their own, and
/// the entry stays collectable for as long as it stays dead.
///
/// `None` from [`SessionPaths::try_lock_spawn`] means somebody holds it and nothing
/// else. A host that cannot lock at all hands back a claim anyway and collection goes
/// ahead, per § 6.3: an entry that stopped being collectable because of the mutex
/// protecting it would be a garbage collector that leaks under exactly the conditions
/// it exists for.
fn collect(paths: &SessionPaths) {
    let Some(lock) = paths.try_lock_spawn() else {
        return;
    };
    if matches!(liveness(paths), Liveness::Stale) {
        // Ignored, unlike `kill`: this is opportunistic tidying behind a `list`,
        // with no caller waiting on an answer and nothing lost by trying again.
        drop(paths.unlink_all_locked(&lock));
    }
}

/// Extracts a session id from any of the five run-file names (§ 6.6).
///
/// Every name, not just `<id>.sock`: the socket is the first file
/// [`SessionPaths::unlink_all_locked`] removes, so a collection interrupted partway
/// through leaves the other four behind — and keying discovery on the socket alone
/// makes exactly that wreckage invisible. It would never be listed, so its id could
/// never be learned, so the `kill` that would clear it could never be typed. Under
/// the `$XDG_STATE_HOME` fallback, which exists so sessions outlive a logout, the
/// litter outlives it too.
///
/// A live session contributes several names and is folded back to one entry by the
/// `dedup` in [`list`]. What decides a session's fate is still the probe under the
/// spawn lock in [`collect`], never the name that led us to it.
fn session_id_of(path: &Path) -> Option<String> {
    const EXTENSIONS: [&str; 5] = ["sock", "pid", "lock", "label", "agent"];
    let extension = path.extension()?.to_str()?;
    if !EXTENSIONS.contains(&extension) {
        return None;
    }
    Some(path.file_stem()?.to_str()?.to_owned())
}

/// Probes the socket. A refused connection means the daemon is gone; the socket
/// file outlives the process that bound it.
///
/// The connection is handed back rather than dropped, because it is evidence about
/// more than liveness: [`daemon_of`] reads the daemon's own pid off it.
fn liveness(paths: &SessionPaths) -> Liveness {
    match UnixStream::connect(paths.socket()) {
        Ok(answered) => Liveness::Alive(Some(answered)),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) =>
        {
            Liveness::Stale
        }
        // Anything else — `EACCES`, a descriptor limit — is not evidence of death
        // either, so it is alive with nothing to ask. Never unlink on a guess.
        Err(_) => Liveness::Alive(None),
    }
}

/// Reads what a session published as its pid, or nothing if it cannot be had.
///
/// `list` uses this, where any failure prints the same `?`. [`resolve`] keeps the
/// body instead, because a live session whose pid will not parse is the one case
/// that must be reported rather than shrugged off.
fn read_pid(paths: &SessionPaths) -> Option<i32> {
    let mut buf = [0u8; MAX_PID_LEN];
    parse_pid(read_prefix(&paths.pid(), &mut buf).ok()?)
}

/// The pidfile's on-disk contract (§ 6.6), in the one place both readers share.
///
/// Zero and negatives are refused rather than passed on. `kill(2)` reads those as
/// a whole process group and as every process the caller may signal, so a pidfile
/// holding one is a number that must never reach a signal — and a daemon whose
/// pidfile says `0` is not a daemon this can identify.
fn parse_pid(body: &[u8]) -> Option<i32> {
    str::from_utf8(body)
        .ok()?
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|pid| *pid > 0)
}
