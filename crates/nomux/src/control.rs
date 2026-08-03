//! The frozen control surface: `list` and `kill`.
//!
//! These must work against a daemon of *any* version, including one older than
//! the binary running them, because they are the escape hatch that makes the N-1
//! codec policy safe (`DESIGN.md` § 6.4). So the contract here is the on-disk
//! layout — never a protocol frame, never `PROTOCOL_VERSION`.

use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::{fs, thread};

use nomux_proto::MAX_SESSION_ID_LEN;

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

/// Longest `/proc/<pid>/cmdline` prefix [`is_daemon_for`] reads.
///
/// Sized to hold the three arguments that identify a daemon and no more of the command
/// line than that: `argv[0]`, whose bound is the kernel's `PATH_MAX` rather than
/// anything this program picks — `attach` starts the daemon from `env::current_exe()`
/// resolved, and § 5.2 installs under a directory the *client* names — then the mode,
/// then an id of at most [`MAX_SESSION_ID_LEN`], with a NUL after each.
///
/// It is deliberately *not* sized for the whole command line, because the whole
/// command line has no bound: `--label <text>` follows the id and reaches `attach`
/// verbatim, so a caller can make it any length it likes. Nothing past the id is read
/// as anything but padding — [`is_daemon_for`] decides on the arguments it saw the end
/// of — which is what keeps a label out of the question rather than in front of it.
/// Stack rather than text, on a path that runs at most twice per `kill`.
const MAX_CMDLINE_LEN: usize = PATH_MAX + 1 + "daemon".len() + 1 + MAX_SESSION_ID_LEN + 1;

/// The kernel's longest path, which is what bounds a resolved `argv[0]`.
const PATH_MAX: usize = 4096;

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

    // One entry per session, not per file: five names lead to the same id (§ 6.6).
    //
    // Folded by a scan of what is already here rather than by sorting and `dedup`ing,
    // which is a size decision and not a taste one: `sort_unstable` on a `String`
    // instantiates a quicksort and its insertion-sort fallback, and taking it out of
    // the binary was worth 3 KiB of the § 8 budget on every target.
    //
    // What it costs back is quadratic in the number of *distinct* ids — measured at
    // 0.26 s of CPU for 5 000 and 3.35 s for 20 000, against 0.06 s and 0.32 s for the
    // sort. That is a real trade and not a rounding error, and it is taken because a
    // run directory in that state is one this very call empties: every id in it that
    // is not answering is collected below, so the cost is paid once and the directory
    // that would charge it again does not survive the pass. Eight sessions is what a
    // client mints, five files is what one leaves, and forty names is where this ends
    // on any host that is not already the pathology.
    //
    // Nothing downstream is owed an order: § 6.6 states what a listing contains and
    // never what sequence it arrives in, and no caller in or out of this tree reads it
    // by position.
    let mut ids: Vec<String> = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        if let Some(id) = session_id_of(&entry.path())
            && !ids.contains(&id)
        {
            ids.push(id);
        }
    }

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
            Liveness::Alive(answered) => {
                // The same two witnesses `kill` signals on, weighed the same way, so
                // the number a user reads here is the number that would be acted on —
                // including the tie-break, which is the case this column matters in.
                // A session whose `<id>.pid` no longer names its daemon printed the
                // stale number, and `kill` refusing to choose *for* the user is what
                // sends them here to choose themselves: it must not be the one place
                // that hands back a stranger's pid to signal by hand. Where the two
                // cannot be reconciled there is no number to print, and `?` says so.
                let pid = chosen(
                    &paths,
                    answered.as_ref().and_then(daemon_of),
                    read_pid(&paths).and_then(extant),
                )
                .map_or_else(|| "?".to_owned(), |pid| pid.as_raw_nonzero().to_string());
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
/// process it is, if its two witnesses name two live processes and neither of them
/// is this session's daemon (both are [`resolve`]), if it goes on answering after
/// both signals, which means the pid that was signalled is not the process serving
/// it, or if one of the five files will not go once it has stopped — the one refusal
/// here that is not about establishing anything, since the session really did end
/// (see [`SessionPaths::unlink_all_locked`]). A session that is already gone is not
/// an error — the postcondition is "no such session", which already holds.
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
/// It says *which* process it is, too, wherever it will: the connection that just
/// answered carries the pid in [`daemon_of`], and nothing at a filename can forge
/// that.
///
/// Both sources are consulted rather than one preferred outright, because each is
/// the only account of a state the other cannot describe. The socket names nobody
/// during the bind-to-publish window, or where a `connect` failed for a reason that
/// is not death, or where the peer is in a pid namespace this process cannot see
/// (see [`peer_pid`]) — and `<id>.pid` is what is left there. The *file* names the
/// wrong process where a dead daemon's number outlived it and the kernel handed that
/// number to somebody else. Neither is the senior witness: § 6.2 forks *after* the
/// bind, so on a daemon built before that changed the socket names the half that
/// left and the file names the half that serves.
///
/// So each is discarded when it names no process at all, which settles both of the
/// ordinary shapes, and a disagreement that survives that is put to [`serving`],
/// which asks the two candidates what they are rather than inferring it. Only where
/// *that* cannot answer is the session refused, exactly as a pid that cannot be read
/// is refused.
///
/// The other direction is § 6.6's rule that a live session's files are never
/// unlinked: a socket that answers and no pid to be had either way is an **error**,
/// never a "no such session". There is exactly one benign reason for that state,
/// which is the daemon's own bind-to-publish window, so a pidfile that is *missing
/// or still empty* is waited out for [`PUBLISH_GRACE`] — even when the socket has
/// already named somebody, since a second witness one interval away is worth more
/// than the interval — and anything else is settled at once, since waiting cannot
/// change it.
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
        let named = answered.as_ref().and_then(daemon_of);
        let mut buf = [0u8; MAX_PID_LEN];
        let waiting_on = match read_prefix(&paths.pid(), &mut buf) {
            Ok(body) if !body.trim_ascii().is_empty() => {
                let filed = parse_pid(body).and_then(extant);
                return chosen(paths, named, filed)
                    .map(Target::Daemon)
                    .ok_or_else(|| {
                        // Nothing came back, so either there was no witness at all or the
                        // two could not be reconciled — and the two read very differently
                        // to whoever has to act on them.
                        match (named, filed) {
                            (Some(named), Some(filed)) => disagreement(paths, named, filed),
                            _ => unreadable(paths, &unusable(body)),
                        }
                    });
            }
            // Present but empty is the same window one syscall later, and is therefore
            // waited out rather than reported: `SessionPaths::write_pid` publishes in
            // two steps — a `File::create` that leaves a zero-length file, then the one
            // `write` that fills it — so a reader can land between them. Reported as an
            // error it refused to kill a session in perfect health.
            Ok(_) => "it was created but never written",
            Err(err) if err.kind() == io::ErrorKind::NotFound => "it never appeared",
            // Unreadable is not the publish window and never becomes it, so it is
            // settled now: on the socket's word where there is one, and refused where
            // there is not.
            Err(err) => return decided(paths, named, &err.to_string()),
        };
        if Instant::now() >= deadline {
            return decided(paths, named, waiting_on);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// What a live session comes to when `<id>.pid` will not say: the socket's word, or
/// a refusal carrying `problem`.
fn decided(
    paths: &SessionPaths,
    named: Option<rustix::process::Pid>,
    problem: &str,
) -> io::Result<Target> {
    named.map_or_else(
        || Err(unreadable(paths, problem)),
        |pid| Ok(Target::Daemon(pid)),
    )
}

/// The daemon behind a connection that answered: the process that called `listen`.
///
/// `SO_PEERCRED` on the *client* side of a unix socket reports the credentials the
/// kernel recorded for the listening socket, which it takes at `listen(2)` from the
/// process performing it. So this is the one number on this surface that is tied to
/// the socket rather than to a name in a directory — a stale `<id>.pid`, or one a
/// user repaired by hand, cannot make it point anywhere.
fn daemon_of(answered: &UnixStream) -> Option<rustix::process::Pid> {
    extant(peer_pid(answered)?)
}

/// The pid the kernel recorded for whoever called `listen` on `answered`, or nothing
/// where it will not say.
///
/// Through `libc` rather than through rustix's `socket_peercred`, and not by
/// preference: that function fills a `MaybeUninit<UCred>` straight from the syscall
/// and `assume_init`s it, and `UCred::pid` is a `NonZeroI32`. The kernel writes
/// **zero** into that field for a peer whose pid does not map into the caller's pid
/// namespace — `pid_vnr` on an unmappable pid — which is an invalid niche and so
/// undefined behaviour rather than an error, in the one binary that is the escape
/// hatch and is built `panic = "abort"`. `nomux list` inside a container that shares
/// the run directory with a daemon started outside it reaches exactly that, and it
/// was reproduced with `unshare --user --pid --fork` before this was written.
///
/// So zero is read here as an answer, and the right one: a number that names no
/// process *in this namespace* is not a number to signal, and the pidfile — which
/// the daemon wrote in its own namespace and which means nothing here either — is
/// left to [`resolve`] to refuse. The `libc` call costs nothing the binary did not
/// already link, and takes rustix's `net` feature back out with it.
fn peer_pid(answered: &UnixStream) -> Option<i32> {
    use std::os::fd::AsRawFd;

    let mut peer = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = libc::socklen_t::try_from(size_of::<libc::ucred>()).ok()?;
    // SAFETY: `getsockopt` is given the address and length of a `ucred` that outlives
    // the call, on a descriptor the borrow above keeps open for it, and it writes at
    // most `len` bytes into it. Both are read back only on a zero return, and the
    // length it reports is checked before the value is used.
    let got = unsafe {
        libc::getsockopt(
            answered.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut peer).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    (got == 0 && usize::try_from(len) == Ok(size_of::<libc::ucred>()) && peer.pid > 0)
        .then_some(peer.pid)
}

/// A number that still names a process this user may signal, or nothing.
///
/// Both accounts of a session's identity come through here, and it is what makes
/// them comparable: a number naming nothing is not evidence, so it neither gets
/// signalled nor contradicts the other source. It cannot tell a reissued number from
/// the original — nothing available here can — which is why the disagreement of two
/// *live* numbers is refused rather than guessed at.
fn extant(pid: i32) -> Option<rustix::process::Pid> {
    let pid = rustix::process::Pid::from_raw(pid)?;
    rustix::process::test_kill_process(pid)
        .is_ok()
        .then_some(pid)
}

/// The pid two witnesses come to, where they come to one.
///
/// Shared by both modes so that the number `list` prints is the number `kill` would
/// signal — including in the case that most needs it, since `kill` deliberately
/// recommends no repair for an unreconciled session and a user who wants to act then
/// asks `list` what to signal. A column that answered from the file alone would hand
/// them the stranger's.
fn chosen(
    paths: &SessionPaths,
    named: Option<rustix::process::Pid>,
    filed: Option<rustix::process::Pid>,
) -> Option<rustix::process::Pid> {
    match (named, filed) {
        (Some(named), Some(filed)) if named != filed => serving(paths, named, filed),
        (Some(pid), _) | (None, Some(pid)) => Some(pid),
        (None, None) => None,
    }
}

/// Which of two live candidates is this session's daemon, where that can be settled.
///
/// The two witnesses disagree only when a number has been reissued, and from outside
/// the two ways that happens look identical: the socket names an exited creator whose
/// number came round again — § 6.2 forks *after* the bind, so a daemon built before
/// that changed is served by the heir the pidfile names — or the file holds a dead
/// daemon's number that now belongs to a stranger while the socket names the live one.
/// Guessing between them signals somebody's process either way, so the tie is settled
/// by asking each candidate what it *is*: this session's daemon runs `nomux daemon
/// <id>`, and no reissued number wears that by accident.
///
/// Both wearing it is § 6.2's fork and nothing else — one image, two halves — and
/// there the file is the answer by construction, since `write_pid` runs after the fork
/// in the half that survives it. Neither wearing it is not a tie to break, and neither
/// is a candidate that could not be *asked*: both refuse. Those two are kept apart in
/// [`is_daemon_for`] rather than folded together, because "it is not the daemon" and
/// "I could not tell" differ in the direction they are wrong — the first, said of a
/// daemon, is what strands a healthy session.
///
/// This identifies the process rather than the *fd*, which is the stronger question
/// and the more expensive one — `/proc/<pid>/fd` carries a socket's `sockfs` inode,
/// which no `stat` of the path yields, so matching them means parsing `/proc/net/unix`
/// as well, on the one surface that has to keep working on any host. What is bought
/// with the cheaper question is every shape the tree can produce; what is given up is
/// a second `nomux daemon <id>` that is not this one, which the bind in § 6.3 already
/// makes unreachable while the first still answers.
fn serving(
    paths: &SessionPaths,
    named: rustix::process::Pid,
    filed: rustix::process::Pid,
) -> Option<rustix::process::Pid> {
    match (
        is_daemon_for(named, paths.id()),
        is_daemon_for(filed, paths.id()),
    ) {
        (_, Some(true)) => Some(filed),
        (Some(true), Some(false)) => Some(named),
        _ => None,
    }
}

/// Whether `pid` is a `nomux daemon <id>` process, where that can be established.
///
/// The command line rather than the executable's name: `attach` spawns the daemon as
/// `<exe> daemon <id>` (`attach::spawn_daemon`) and § 6.2 documents the same words
/// typed by hand, so the mode and the id are two arguments whatever the binary is
/// called or where it was installed — which matters, since § 5.2 installs it under a
/// version-stamped name. Both are required: a relay is `<exe> attach <id>` and would
/// otherwise answer to this.
///
/// `None` is "could not tell", and keeping it apart from `Some(false)` is the whole
/// reason this returns an `Option`. A false *positive* is unreachable — a truncated
/// last argument cannot equal both `daemon` and the id — but a false *negative* is
/// how a healthy daemon becomes invisible, and an invisible daemon is a session
/// [`serving`] refuses to identify for as long as it runs. So a read that cannot see
/// what it needs says so, exactly as [`parse_pid`] does of a pidfile that runs past
/// its own bound.
///
/// What it needs is the two words, not the whole command line, and the difference is
/// the reason a session with a long `--label` is still killable: the label follows the
/// id and arrives at `attach` verbatim, so a command line has no length this could be
/// sized against. Finding the pair is therefore an answer whether or not the read
/// reached the end, and only *failing* to find it leaves the truncation to decide.
fn is_daemon_for(pid: rustix::process::Pid, id: &str) -> Option<bool> {
    let mut buf = [0u8; MAX_CMDLINE_LEN];
    let cmdline = PathBuf::from(format!("/proc/{}/cmdline", pid.as_raw_nonzero()));
    let body = read_prefix(&cmdline, &mut buf).ok()?;
    // Every argv element is NUL-*terminated*, so everything up to the last NUL is
    // arguments this read saw the end of and whatever follows it is a tail. Comparing
    // the tail would be comparing half a word.
    let whole = body
        .iter()
        .rposition(|byte| *byte == 0)
        .and_then(|end| body.get(..end))
        .unwrap_or(&[]);
    // Compared as whole arguments, so an id that is a prefix of another session's is a
    // different session — and the id is looked for *after* the mode, which is the order
    // `<exe> daemon <id>` puts them in.
    let mut args = whole.split(|byte| *byte == 0);
    if args.any(|arg| arg == b"daemon") && args.any(|arg| arg == id.as_bytes()) {
        return Some(true);
    }
    // Not there — which is only news if the read saw everything there was.
    (body.len() < MAX_CMDLINE_LEN).then_some(false)
}

/// The refusal to act when neither live candidate is this session's daemon.
///
/// It prints both numbers and what each of them came from, because that is the whole
/// of what is known and the user is the only one who can look further. It recommends
/// nothing: the repair that suggests itself — remove the pidfile and let the socket
/// decide — is the catastrophic one exactly half the time, since the number the
/// socket carries is the one that may have been reissued.
fn disagreement(
    paths: &SessionPaths,
    named: rustix::process::Pid,
    filed: rustix::process::Pid,
) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "session {id} is running, but its socket names pid {named} and {pid} names \
             pid {filed}, and neither is a `nomux daemon {id}` process; leaving it alone \
             rather than signalling the wrong one",
            id = paths.id(),
            pid = paths.pid().display(),
            named = named.as_raw_nonzero(),
            filed = filed.as_raw_nonzero(),
        ),
    )
}

/// What is wrong with a pidfile body that yielded no pid, in the terms of the repair.
///
/// The two are not the same fault and do not read the same way: a body that reached
/// the bound holds what may be a perfectly good number with the end of it unread, so
/// quoting it alone would show the user a pid and call it unusable.
fn unusable(body: &[u8]) -> String {
    let quoted = String::from_utf8_lossy(body);
    if body.len() >= MAX_PID_LEN {
        format!(
            "it runs past the {MAX_PID_LEN} bytes a pidfile may be, so any number in it \
             is cut off rather than read; it begins {quoted:?}"
        )
    } else {
        format!("it holds {quoted:?}")
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
/// scan in [`list`]. What decides a session's fate is still the probe under the
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
///
/// A body that filled the reader's buffer is refused for a sharper reason: it is a
/// prefix of a file whose end was never seen, so a number still running at the last
/// byte is a *truncation* — `" "*25 + "32770419\n"` comes back as 3277041, which is
/// not the pid in the file and may well be somebody else's. Reading less than the
/// whole file is what keeps `list` off a planted gigabyte ([`MAX_PID_LEN`]), and this
/// is the other half of that bargain: what the prefix does not settle, it does not
/// get to answer. The layout puts a pid and a newline in this file, which is eleven
/// bytes at the widest; nothing legitimate reaches the bound. [`read_label`] is
/// deliberately not symmetric — truncating a decoration costs a column, truncating a
/// number costs somebody else's process.
fn parse_pid(body: &[u8]) -> Option<i32> {
    if body.len() >= MAX_PID_LEN {
        return None;
    }
    str::from_utf8(body)
        .ok()?
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|pid| *pid > 0)
}
