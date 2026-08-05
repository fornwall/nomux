//! The frozen control surface: `list` and `kill` (§ 6.6).
//!
//! These must work against a daemon of *any* version, including one older than the
//! binary running them, because they are the escape hatch that makes the N-1 codec
//! policy safe (`DESIGN.md` § 6.4). So the contract here is the on-disk layout — never
//! a protocol frame, never `PROTOCOL_VERSION`.

use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::{fs, thread};

use rustix::process::{Pid, Signal, kill_process, test_kill_process};

use crate::rundir::{
    MAX_PID_LEN, MAX_SESSION_ID_LEN, SessionPaths, SpawnLock, check_run_dir, connect_within,
    nothing_is_listening, parse_pid, read_label, read_prefix, run_dir, session_id_of,
};

/// How long a probe of a session socket waits for an answer.
///
/// Bounded at all because an `AF_UNIX` `connect` to a full backlog blocks rather than being
/// refused (§ 6.3), so a daemon that stopped calling `accept` would park the one surface
/// that must work on any host. Two seconds, the budget every other wait here is given.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a terminated daemon has to exit before it is killed outright.
const TERM_GRACE: Duration = Duration::from_secs(2);

/// How long a killed daemon has to actually go before `kill` concludes that the signal
/// never reached whatever is serving the socket.
///
/// Nothing survives `SIGKILL`, so this is never observed of an ordinary daemon. What it
/// bounds is the case where the pid signalled is *not* the process behind the socket.
const KILL_GRACE: Duration = Duration::from_millis(500);

/// How often to look again while waiting any of the graces out. One interval for all of
/// them: each waits on another process reaching a point of its own.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// How long `kill` waits for the spawn lock before giving up (see [`hold_spawn_lock`]).
const SPAWN_LOCK_GRACE: Duration = Duration::from_secs(2);

/// How long `kill` waits for a live daemon to publish `<id>.pid` (§ 6.6): the daemon binds
/// its socket before it writes the pidfile (§ 6.2), so a `kill` landing in that window
/// finds a session unmistakably there and no pid to signal. Bounded, because a socket
/// answering with no pidfile behind it may be a daemon that died mid-publish.
const PUBLISH_GRACE: Duration = Duration::from_secs(2);

/// Longest `/proc/<pid>/cmdline` prefix [`is_daemon_for`] reads: `argv[0]`, bounded by the
/// kernel's [`PATH_MAX`] rather than by anything this program picks, then the mode, then an
/// id of at most [`MAX_SESSION_ID_LEN`], with a NUL after each. Deliberately *not* sized
/// for the whole command line, which has no bound — `--label <text>` follows the id and
/// reaches `attach` verbatim, and nothing past it is read as anything but padding.
const MAX_CMDLINE_LEN: usize = PATH_MAX + 1 + "daemon".len() + 1 + MAX_SESSION_ID_LEN + 1;

/// The kernel's longest path, which is what bounds a resolved `argv[0]`.
const PATH_MAX: usize = 4096;

/// State of one session as seen from the run directory alone.
#[derive(Debug)]
enum Liveness {
    /// A daemon accepted a connection, which is handed over with the answer: that
    /// connection is what ties a pid to this socket (see [`daemon_of`]).
    Alive(UnixStream),
    /// The socket exists but nothing is listening; the daemon died.
    Stale,
    /// The `connect` failed for a reason that is not death, carrying it.
    ///
    /// Kept apart from [`Self::Alive`] because only one of the two is evidence. For the
    /// *unlink* they are the same conservative answer — § 6.3's "`EACCES` is not
    /// staleness". Everywhere else they are opposites: an accepted connection proves a
    /// process is serving this socket, while an `EACCES`, a descriptor limit or an
    /// undrained backlog proves nothing, so only the first may escalate to `SIGKILL` or
    /// call a session still answering.
    Unknown(io::Error),
}

/// Turns the § 6.3 run-directory check into "is there one?" rather than an error to be
/// matched. Both modes read its absence as the question already answered: `list` prints
/// nothing, `kill` finds its postcondition already holding.
fn present(checked: io::Result<()>) -> io::Result<bool> {
    match checked {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

/// Prints one line per live session: id, pid and label.
///
/// A reader that closes stdout early — `nomux list | head` — ends the listing rather than
/// failing it: the Rust runtime ignores `SIGPIPE`, so the write comes back `EPIPE`, and
/// § 10 already reads a closed stdout as a clean end. What it does *not* end is the sweep,
/// since the ids are in hand and returning early would make `head` the reason a stale
/// session survived.
///
/// # Errors
///
/// Fails if the run directory cannot be read. A missing directory is not an error — no
/// session has ever been created.
pub(crate) fn list() -> io::Result<()> {
    let dir = run_dir()?;
    // § 6.3, before any name in this directory is trusted: `list` builds five paths per
    // entry, connects to one and writes another to the caller's terminal. Checked and never
    // created — being asked what sessions exist must not create the place they would live.
    if !present(check_run_dir(&dir))? {
        return Ok(());
    }
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        // Not the absence above: the check has just opened this directory, so this is a
        // race rather than a state. Same answer either way.
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };

    // One entry per session, not per file: every name under `<id>.` leads to the same
    // id (§ 6.6), and the socket is the *first* one collection removes — so keying
    // discovery on it alone would make an interrupted collection invisible, never
    // listed, and so beyond the `kill` that would clear it.
    //
    // Folded by a scan rather than by sorting and `dedup`ing, which is a size decision:
    // `sort_unstable` on a `String` instantiates a quicksort and its insertion-sort
    // fallback, and taking it out was worth 3 KiB of the § 8 budget on every target. What
    // it costs back is quadratic in the number of *distinct* ids — measured at 0.26 s of
    // CPU for 5 000 and 3.35 s for 20 000, against 0.06 s and 0.32 s for the sort — and is
    // paid at most once, since every id in such a directory that is not answering is
    // collected below. Nothing downstream is owed an order.
    let mut ids: Vec<String> = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if let Some(id) = session_id_of(&path)
            && !ids.iter().any(|known| known == id)
        {
            ids.push(id.to_owned());
        }
    }

    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut listening = true;
    for id in ids {
        let Ok(paths) = SessionPaths::new(&id) else {
            continue;
        };
        let answered = match liveness(&paths) {
            Liveness::Stale => {
                collect(&paths);
                continue;
            }
            Liveness::Alive(answered) => Some(answered),
            // Live, since only death collects (§ 6.3), and with nothing to ask.
            Liveness::Unknown(_) => None,
        };
        // Nowhere left to print to, and the arm above is the whole reason the loop goes
        // on anyway.
        if !listening {
            continue;
        }
        // The same two witnesses `kill` signals on, weighed the same way ([`chosen`]),
        // because § 6.6 has the number a user reads be the number that would be acted on:
        // `kill` refuses to choose where they cannot be reconciled and sends the user here
        // to choose themselves, so this must not be the one place that hands back a
        // stranger's pid. Every failure to read prints that same `?`, where [`resolve`]
        // keeps the body and reports on it.
        let mut buf = [0u8; MAX_PID_LEN];
        let filed = read_prefix(&paths.pid(), &mut buf).ok().and_then(parse_pid);
        let pid = chosen(
            &paths,
            answered.as_ref().and_then(daemon_of),
            filed.and_then(extant),
        )
        .map_or_else(|| "?".to_owned(), |pid| pid.as_raw_nonzero().to_string());
        // Sanitised on read as well as on write: the daemon that wrote it may be any
        // version (§ 6.6), and a label carrying `ESC ]0;` would retitle the terminal of
        // whoever ran `list`.
        let label = read_label(&paths.label());
        match writeln!(out, "{id}\t{pid}\t{label}") {
            Err(err) if err.kind() == io::ErrorKind::BrokenPipe => listening = false,
            outcome => outcome?,
        }
    }
    Ok(())
}

/// Terminates a session and removes its run files.
///
/// # Errors
///
/// Fails on an invalid session id, on a run directory that is not this user's alone
/// (§ 6.3), and on the five states § 6.6 lists behind a non-zero `kill`. Two more come
/// from the probe rather than from the session — a socket this process could not reach
/// at all ([`unprobeable`]), and an id a daemon claimed while this call held the lock
/// ([`bound_since`]). A session that is already gone is not an error: the postcondition
/// is "no such session", which already holds.
pub(crate) fn kill(session_id: &str) -> io::Result<()> {
    let paths = SessionPaths::new(session_id)?;
    // The same check `list` makes, and this is where it bites hardest: what follows
    // reads a pid out of a file and signals it, and in a run directory somebody else can
    // write to, that number is theirs. Checked, never created.
    if !present(paths.check_dir())? {
        return Ok(());
    }
    // Held from here to the end of the function, since no *attach* can spawn into this id
    // while it is held (§ 6.3): without it, one that starts a fresh daemon between the
    // signal below and the unlink that follows loses its socket to a kill it was never the
    // target of. What the lock does not exclude is a daemon started by hand, which is why
    // the unlink probes again rather than trusting this.
    let lock = hold_spawn_lock(&paths)?;
    if let Some(pid) = resolve(&paths)? {
        let _ = kill_process(pid, Signal::TERM);
        // Liveness first, deadline second, so a daemon that let go on the last interval
        // is not signalled again: the pid it published is reusable the moment it is
        // reaped, and `SIGKILL` is the one signal nothing survives.
        let mut deadline = Instant::now() + TERM_GRACE;
        let mut killed = false;
        loop {
            match liveness(&paths) {
                Liveness::Stale => break,
                Liveness::Alive(_) => {}
                // A probe that never reached the socket answers nothing about the daemon,
                // so it may neither be waited out nor escalated on: the `SIGKILL` below
                // would go to a number nothing here ties to this session, and the refusal
                // beside it would call a session answering unheard from.
                Liveness::Unknown(err) => return Err(unprobeable(&paths, &err)),
            }
            if Instant::now() >= deadline {
                // Still answering after `SIGKILL`, which nothing survives — so the pid
                // signalled is not the process serving this socket and both signals went
                // to a stranger. Refused rather than unlinked, and reachable only from the
                // arm above that accepted a connection, which makes every clause true.
                if killed {
                    return Err(refuse(format!(
                        "session {id} is still answering after SIGTERM and SIGKILL to \
                         pid {pid}, so that pid is not the process serving it; leaving \
                         it alone rather than unlinking a live session's files",
                        id = paths.id(),
                        pid = pid.as_raw_nonzero(),
                    )));
                }
                let _ = kill_process(pid, Signal::KILL);
                killed = true;
                deadline = Instant::now() + KILL_GRACE;
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
    // Probed once more, under the lock and immediately before the unlink, because that is
    // the only point at which the answer cannot change between being read and being acted
    // on (§ 6.6) — where [`collect`] also decides, and the two must agree.
    //
    // What it closes is the daemon somebody started by hand, which § 6.3 lets proceed
    // *without* the spawn lock when it cannot take one: it can bind and publish inside this
    // locked region, after everything above concluded the id was free. Unlinking on that
    // answer takes its socket away without stopping it — a session answering nothing, in no
    // listing, unreachable by the `kill` that would clear it, holding a PTY until the reap.
    match liveness(&paths) {
        // The one *successful* exit from the locked region, and so the one place the
        // files go: already gone, stopped on `SIGTERM`, and killed outright all leave
        // the same nothing behind.
        Liveness::Stale => paths.unlink_all_locked(&lock),
        Liveness::Alive(_) => Err(bound_since(&paths)),
        Liveness::Unknown(err) => Err(unprobeable(&paths, &err)),
    }
}

/// Takes the spawn lock for the whole of a `kill`, waiting briefly for it.
///
/// The wait is what makes `kill` *win* a race against the attach creating this session
/// rather than merely lose one: the holder releases once its daemon has answered and
/// published its pid, and that daemon is then killed like any other. Bounded rather than a
/// blocking `flock` because a process that stopped holding it is not a reason for the
/// escape hatch to hang forever.
///
/// # Errors
///
/// Reports [`io::ErrorKind::ResourceBusy`] when the lock is still held at the deadline,
/// rather than claim a postcondition it did not establish.
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

/// Which process a locked session's daemon is, or `None` where nothing is listening and
/// the files are all that is left.
///
/// Liveness first, and only then the pid: a daemon that died without unlinking leaves its
/// pidfile behind and the kernel reuses pids, so signalling a number read off disk
/// unchecked is how `nomux kill` terminates an unrelated process of the user's. The socket
/// is the authority on whether the daemon is still there, [`daemon_of`] makes it name
/// *which* process that is, and [`chosen`] weighs the two. A live session neither
/// identifies is refused rather than reported as gone.
///
/// # Errors
///
/// Reports the reason a live session's pid could not be had.
fn resolve(paths: &SessionPaths) -> io::Result<Option<Pid>> {
    let deadline = Instant::now() + PUBLISH_GRACE;
    loop {
        let answered = match liveness(paths) {
            Liveness::Stale => return Ok(None),
            Liveness::Alive(answered) => Some(answered),
            // Alive as far as anything here can establish, and with no socket witness.
            Liveness::Unknown(_) => None,
        };
        let named = answered.as_ref().and_then(daemon_of);
        let mut buf = [0u8; MAX_PID_LEN];
        let waiting_on = match read_prefix(&paths.pid(), &mut buf) {
            Ok(body) if !body.trim_ascii().is_empty() => {
                let filed = parse_pid(body).and_then(extant);
                return chosen(paths, named, filed)
                    .map(Some)
                    .ok_or_else(|| unidentified(paths, named, filed, body));
            }
            // Present but empty is the same window one syscall later, so it is waited
            // out too: `SessionPaths::write_pid` creates the file and fills it in two
            // steps, and a reader can land between them.
            Ok(_) => "it was created but never written",
            Err(err) if err.kind() == io::ErrorKind::NotFound => "it never appeared",
            // Unreadable is not the publish window and never becomes it, so it is
            // settled now, like the deadline below: on the socket's word where there is
            // one, and refused where there is not.
            Err(err) => {
                return named
                    .map(Some)
                    .ok_or_else(|| running_but(paths, &err.to_string()));
            }
        };
        if Instant::now() >= deadline {
            return named
                .map(Some)
                .ok_or_else(|| running_but(paths, waiting_on));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// The pid two witnesses come to, where they come to one.
///
/// Shared by both modes, so the number `list` prints is the number `kill` would signal —
/// which matters most in the case `kill` refuses, since it recommends no repair there and
/// a user who wants to act asks `list` what to signal.
///
/// The arms below are § 6.6's weighing, which is deliberately not symmetric and is stated
/// there in full: read that bullet before changing this match. Both distinctions
/// [`is_daemon_for`] draws are load-bearing in it — a positive "it is not" against "could
/// not tell", and a lone file witness, which is what a pid namespace this process cannot
/// see produces (see [`daemon_of`]), against one with a rival.
///
/// It asks what a process *is*, not which holds the *fd*: matching a `sockfs` inode would
/// mean parsing `/proc/net/unix` on the surface that has to keep working anywhere, and
/// what that gives up — a second `nomux daemon <id>` that is not this one — § 6.3's bind
/// already makes unreachable.
fn chosen(paths: &SessionPaths, named: Option<Pid>, filed: Option<Pid>) -> Option<Pid> {
    let id = paths.id();
    match (named, filed) {
        (Some(named), Some(filed)) if named != filed => {
            match (is_daemon_for(named, id), is_daemon_for(filed, id)) {
                (_, Some(true)) => Some(filed),
                (Some(true), Some(false)) => Some(named),
                _ => None,
            }
        }
        (Some(pid), _) => Some(pid),
        (None, Some(pid)) => (is_daemon_for(pid, id) != Some(false)).then_some(pid),
        (None, None) => None,
    }
}

/// The daemon behind a connection that answered: the process that called `listen`, where
/// the kernel will say and the number still names something live.
///
/// `SO_PEERCRED` on the *client* side reports the credentials the kernel recorded for the
/// listening socket at `listen(2)`, which is what ties this number to the socket rather
/// than to a name in a directory (§ 6.6).
///
/// Through `libc` rather than through rustix's `socket_peercred`, and not by preference:
/// that function fills a `MaybeUninit<UCred>` straight from the syscall and
/// `assume_init`s it, and `UCred::pid` is a `NonZeroI32`. The kernel writes **zero**
/// into that field for a peer whose pid does not map into the caller's pid namespace —
/// `pid_vnr` on an unmappable pid — which is an invalid niche and so undefined behaviour
/// rather than an error, in the one binary that is the escape hatch and is built
/// `panic = "abort"`. `nomux list` inside a container that shares the run directory with
/// a daemon started outside it reaches exactly that, and it was reproduced with
/// `unshare --user --pid --fork` before this was written.
///
/// So zero is read here as an answer, and the right one: a number that names no process
/// *in this namespace* is not a number to signal, and the pidfile — written in the
/// daemon's namespace and meaning nothing here either — is left to [`resolve`] to refuse.
fn daemon_of(answered: &UnixStream) -> Option<Pid> {
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
    if got != 0 || usize::try_from(len) != Ok(size_of::<libc::ucred>()) || peer.pid <= 0 {
        return None;
    }
    extant(peer.pid)
}

/// A number that still names a process this user may signal, or nothing.
///
/// Both accounts of a session's identity come through here, which is what makes them
/// comparable: a number naming nothing is not evidence, so it neither gets signalled nor
/// contradicts the other. It cannot tell a reissued number from the original, which is why
/// [`chosen`] asks [`is_daemon_for`] rather than guess between two live ones.
fn extant(pid: i32) -> Option<Pid> {
    let pid = Pid::from_raw(pid)?;
    test_kill_process(pid).is_ok().then_some(pid)
}

/// Whether `pid` is a `nomux daemon <id>` process, where that can be established.
///
/// The command line rather than the executable's name, since § 5.2 installs under a
/// version-stamped one: `spawn` starts the daemon as `<exe> daemon <id>` and § 6.2
/// documents the same words typed by hand. Both are required — a relay is
/// `<exe> spawn <id>` or `<exe> attach <id>` and would otherwise answer to this.
///
/// `None` is "could not tell", and keeping it apart from `Some(false)` is the whole reason
/// this returns an `Option`: a false *negative* makes a healthy daemon invisible, and an
/// invisible daemon is a session [`chosen`] refuses to identify for as long as it runs. So
/// finding the pair is an answer whether or not the read reached the end — which keeps a
/// session with a long `--label` killable — and only *failing* to find it leaves the
/// truncation to decide.
fn is_daemon_for(pid: Pid, id: &str) -> Option<bool> {
    let mut buf = [0u8; MAX_CMDLINE_LEN];
    let cmdline = PathBuf::from(format!("/proc/{}/cmdline", pid.as_raw_nonzero()));
    let body = read_prefix(&cmdline, &mut buf).ok()?;
    // Every argv element is NUL-*terminated*, so everything up to the last NUL is
    // arguments this read saw the end of and whatever follows is a tail. Comparing the
    // tail would be comparing half a word.
    let whole = body
        .iter()
        .rposition(|byte| *byte == 0)
        .and_then(|end| body.get(..end))
        .unwrap_or(&[]);
    if names_daemon_for(whole, id) {
        return Some(true);
    }
    // Not there — which is only news if the read saw everything there was.
    (body.len() < MAX_CMDLINE_LEN).then_some(false)
}

/// Whether a NUL-separated command line is `<exe> daemon <id>`, however it was spelled.
///
/// Parsed the way [`main::parse_session_args`](crate::main) parses it, rather than
/// searched. A search answers to any command line that merely *contains* both words, and
/// `--label` puts caller-supplied text into that same argv: `daemon A --label B` would
/// be B's daemon as well as A's, and `spawn --label daemon Z` would be Z's — the process
/// class § 6.6 names as excluded, which is now the two relay modes rather than one. So
/// the id is compared positionally, and `--label` is accepted in either position and
/// either spelling, because the real parser accepts it there and a daemon started that
/// way round is still the daemon.
///
/// Read against whatever `/proc` holds rather than against what this build can produce,
/// which is why an `attach --label` still parses here after `main` stopped accepting
/// one: the command line on the far side of that read may be any version's.
fn names_daemon_for(whole: &[u8], id: &str) -> bool {
    let mut args = whole.split(|byte| *byte == 0);
    args.next();
    if args.next() != Some(b"daemon".as_slice()) {
        return false;
    }
    let mut session = None;
    while let Some(arg) = args.next() {
        if arg == b"--label" {
            // The value is the next argument, and must not be read as the id.
            args.next();
        } else if !arg.starts_with(b"--label=") && !arg.starts_with(b"-") {
            session.get_or_insert(arg);
        }
    }
    session == Some(id.as_bytes())
}

/// The shape every refusal here takes: something in the run directory said what this
/// call would not act on, which is [`io::ErrorKind::InvalidData`] and § 10's code for it.
fn refuse(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// The refusal to touch a live session whose pid is not knowable.
///
/// It names the pidfile because that is the one thing the user can repair, and it says
/// what was *not* done, since "kill failed" reads like "the session is still running" —
/// which is exactly right here, and is the point.
fn running_but(paths: &SessionPaths, problem: &str) -> io::Error {
    refuse(format!(
        "session {id} is running, but {pid}: {problem}; leaving it alone rather than \
         unlinking a live session's files",
        id = paths.id(),
        pid = paths.pid().display(),
    ))
}

/// Why [`chosen`] came back with nothing over a session that is answering.
///
/// The four read very differently to whoever has to act on them, and only the last is a
/// file to repair. Two live candidates get both numbers, where each came from, what
/// `/proc` said about each, and no recommendation, for § 6.6's reason. A lone file witness
/// positively ruled out is about the pid rather than the file. A body that reached the
/// bound holds what may be a good number with its end unread, so quoting it would show the
/// user a pid and call it unusable. A body that parsed and named nothing is the daemon
/// that died without unlinking, where the file is exactly what its author meant it to be.
fn unidentified(
    paths: &SessionPaths,
    named: Option<Pid>,
    filed: Option<Pid>,
    body: &[u8],
) -> io::Error {
    let quoted = String::from_utf8_lossy(body);
    let problem = match (named, filed) {
        (Some(named), Some(filed)) => {
            return refuse(format!(
                "session {id} is running, but its socket names pid {named_pid} and {pid} \
                 names pid {filed_pid}, and which of them is the `nomux daemon {id}` \
                 process was not established: {named_says}, and {filed_says}; leaving it \
                 alone rather than signalling the wrong one",
                id = paths.id(),
                pid = paths.pid().display(),
                named_pid = named.as_raw_nonzero(),
                filed_pid = filed.as_raw_nonzero(),
                named_says = told_of(named, paths.id()),
                filed_says = told_of(filed, paths.id()),
            ));
        }
        (_, Some(filed)) => format!(
            "it names pid {filed}, which is not a `nomux daemon {id}` process",
            filed = filed.as_raw_nonzero(),
            id = paths.id(),
        ),
        _ if body.len() >= MAX_PID_LEN => format!(
            "it runs past the {MAX_PID_LEN} bytes a pidfile may be, so any number in it \
             is cut off rather than read; it begins {quoted:?}"
        ),
        _ => parse_pid(body).map_or_else(
            || format!("it holds {quoted:?}"),
            |pid| format!("pid {pid} names no process this user can signal"),
        ),
    };
    running_but(paths, &problem)
}

/// What `/proc` said about one of two rival candidates, in the words the refusal is
/// entitled to use.
///
/// The sentence this replaces said "neither is a `nomux daemon <id>` process", and that
/// branch is reached on an [`is_daemon_for`] that answered `None` as readily as on one that
/// answered `Some(false)`: a `/proc/<pid>/cmdline` that would not open, or one whose
/// command line ran past the buffer, for either candidate. § 6.6 keeps "it is not the
/// daemon" and "I could not tell" apart precisely because acting on the first when only
/// the second was established is what strands a healthy session — and a refusal is not
/// exempt from the distinction it refuses on. So each candidate is reported as what was
/// found out about it, and the clause in front of them says only that the pair was not
/// settled, which is the whole of what [`chosen`] establishes here.
///
/// Asked again rather than threaded down from [`chosen`], which costs two bounded reads on
/// a path that is already refusing: what the message then reports is a reading of its own,
/// consistent with itself whatever raced it.
fn told_of(pid: Pid, id: &str) -> String {
    let verdict = is_daemon_for(pid, id);
    let pid = pid.as_raw_nonzero();
    match verdict {
        Some(true) => format!("{pid} is one"),
        Some(false) => format!("{pid} is not one"),
        None => format!("/proc would not say what {pid} is"),
    }
}

/// The refusal to decide a session's fate on a probe that never reached it.
///
/// § 6.3 makes an `EACCES`, a descriptor limit and an undrained backlog evidence of
/// neither death nor life, so none may license an unlink and none may be built into a
/// refusal that says a session is *answering*. Naming the errno is the whole of what is
/// known, and the useful half: each is repairable from outside.
fn unprobeable(paths: &SessionPaths, problem: &io::Error) -> io::Error {
    refuse(format!(
        "session {id}: {sock} could not be probed, so whether it has stopped was never \
         established: {problem}; leaving its files alone rather than unlinking what \
         may be a live session",
        id = paths.id(),
        sock = paths.socket().display(),
    ))
}

/// The refusal to collect a session that answered again under the lock.
///
/// Rare by construction and reported rather than swallowed, because it reads two ways: a
/// daemon that bound the id inside this locked region is a live session to leave alone,
/// and it is also this `kill` having been overtaken by a spawn. Running the command again
/// is the whole of the repair, and exit status is all the caller has to go on.
fn bound_since(paths: &SessionPaths) -> io::Error {
    io::Error::new(
        io::ErrorKind::AddrInUse,
        format!(
            "session {id} is answering on {sock} again: a daemon has bound the id since \
             this kill established it was gone, so those files are its own and not this \
             call's to remove",
            id = paths.id(),
            sock = paths.socket().display(),
        ),
    )
}

/// Removes a dead session's files, or leaves them to whoever comes next.
///
/// The probe that got us here is a hint rather than a verdict, so collection takes
/// `<id>.lock` and decides liveness again under it (§ 6.6). It gives up rather than waits,
/// because that lock is also the mutex an attach holds across creating a session, and the
/// entry stays collectable for as long as it stays dead.
fn collect(paths: &SessionPaths) {
    let Some(lock) = paths.try_lock_spawn() else {
        return;
    };
    if matches!(liveness(paths), Liveness::Stale) {
        // Ignored, unlike `kill`: this is opportunistic tidying behind a `list`, with no
        // caller waiting on an answer and nothing lost by trying again.
        drop(paths.unlink_all_locked(&lock));
    }
}

/// Probes the socket. A refused connection means the daemon is gone; the socket file
/// outlives the process that bound it.
///
/// The connection is handed back rather than dropped, because it is evidence about more
/// than liveness: [`daemon_of`] reads the daemon's own pid off it. Through
/// [`connect_within`] because § 6.3 has a full backlog block a `connect` rather than refuse
/// it, and `UnixStream::connect` has no deadline.
fn liveness(paths: &SessionPaths) -> Liveness {
    match connect_within(&paths.socket(), PROBE_TIMEOUT) {
        Ok(answered) => Liveness::Alive(answered),
        Err(err) if nothing_is_listening(&err) => Liveness::Stale,
        // Not evidence of death, per the predicate above, and not evidence of life
        // either — see [`Liveness::Unknown`], which is the whole of the difference.
        Err(err) => Liveness::Unknown(err),
    }
}

#[cfg(test)]
mod tests {
    use super::names_daemon_for;

    /// Joins argv the way `/proc/<pid>/cmdline` presents it, minus the trailing NUL
    /// that [`is_daemon_for`](super::is_daemon_for) has already trimmed.
    fn cmdline(args: &[&str]) -> Vec<u8> {
        args.join("\0").into_bytes()
    }

    /// Regression: a label is not an id, however much it looks like one in argv.
    ///
    /// The predicate used to *search* for `daemon` and then for the id anywhere after
    /// it, so a session labelled with a sibling's id answered for both — and `kill` on
    /// the sibling signalled this daemon. The collision needs no attacker, a label
    /// equal to some other tab's id does it, but a client mints both.
    #[test]
    fn a_label_never_stands_in_for_the_id() {
        for (argv, describing) in [
            (vec!["nomux", "daemon", "one", "--label", "two"], "after"),
            (vec!["nomux", "daemon", "--label", "two", "one"], "before"),
            (vec!["nomux", "daemon", "--label=two", "one"], "joined"),
        ] {
            let whole = cmdline(&argv);
            assert!(
                names_daemon_for(&whole, "one"),
                "a daemon with its label {describing} the id is still `one`'s: {argv:?}"
            );
            assert!(
                !names_daemon_for(&whole, "two"),
                "a label {describing} the id made this daemon `two`'s as well: {argv:?}"
            );
        }
    }

    /// The process class § 6.6 names as excluded: a relay wearing the mode word as a
    /// label answered for the id it was relaying to.
    ///
    /// Both relay modes, since the split made `spawn` a second one — and the `attach
    /// --label` forms stay because this reads `/proc`, where a command line from any
    /// version may be found, rather than what this build's `main` will accept.
    #[test]
    fn a_relay_is_not_the_daemon_whatever_its_label_says() {
        for argv in [
            vec!["nomux", "attach", "--label", "daemon", "one"],
            vec!["nomux", "attach", "one", "--label", "daemon"],
            vec!["nomux", "attach", "one"],
            vec!["nomux", "spawn", "--label", "daemon", "one"],
            vec!["nomux", "spawn", "one", "--label", "daemon"],
            vec!["nomux", "spawn", "one"],
        ] {
            assert!(
                !names_daemon_for(&cmdline(&argv), "one"),
                "a relay was taken for the daemon it spawned: {argv:?}"
            );
        }
    }

    /// The ordinary shapes still resolve, including the hand-typed one § 6.2 documents.
    #[test]
    fn the_plain_command_lines_still_name_their_session() {
        assert!(names_daemon_for(
            &cmdline(&["nomux", "daemon", "one"]),
            "one"
        ));
        assert!(names_daemon_for(
            &cmdline(&["/opt/nomux-0.2.0", "daemon", "one"]),
            "one"
        ));
        // Whole arguments, so one id is never a prefix of another.
        assert!(!names_daemon_for(
            &cmdline(&["nomux", "daemon", "one0"]),
            "one"
        ));
        assert!(!names_daemon_for(&cmdline(&["nomux", "daemon"]), "one"));
        assert!(!names_daemon_for(&[], "one"));
    }
}
