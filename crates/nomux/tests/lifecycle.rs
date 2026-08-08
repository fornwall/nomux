//! What a session's processes do at their two ends.
//!
//! Starting: the id a daemon claims and the spawn lock it holds while claiming it
//! (`IMPLEMENTATION.md` § 6.3), the detachment from whoever launched it (§ 6.2), and
//! a child that inherits nothing but its stdio. Ending: the exit status the client is
//! owed and when it arrives (§ 6.5, § 10), the reaping of everything the session
//! leaves behind it — including the child an unknown outcome has already spoken
//! for — and the shutdown a signal or an idle deadline sets off.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "the allow-*-in-tests settings in clippy.toml reach `#[test]` bodies \
              and `#[cfg(test)]` modules, not the helpers an integration test crate \
              keeps beside them"
)]

mod harness;

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nomux_protocol::{Frame, FrameType, RESUME_FROM_START};

use harness::{
    Client, Cue, FRAME_PATIENCE, Flock, HeldLock, Reaper, Rng, SETTLE, SPIN_WINDOW, Session,
    Spawned, StatField, control, control_with_shell, cpu_ticks, daemon_reaper, entries,
    leads_a_process_group, nomux_with_shell, poll_by, poll_until, process_alive, process_state,
    run_root, stat_field, still_serving, succeeded, wait_for, wait_until_flock, wedge_socket,
};

/// How long a test that waits on a second process reaching a window may spend waiting,
/// across every wait it makes.
///
/// One figure per test rather than one per wait, for `harness::poll_by`'s reason. Above
/// [`SETTLE`], which bounds one wait for this process's own filesystem to catch up,
/// because what the two spawn-lock tests at the end of this file wait for is another
/// process arriving somewhere under whatever load the rest of the suite is applying.
const PATIENCE: Duration = Duration::from_secs(30);

/// A child that was killed is reported as `Signalled` carrying the signal, not as a
/// process that returned one (`IMPLEMENTATION.md` § 10).
///
/// The whole of the `128+n` convention rests on telling those two apart, and it is
/// the client that applies it: a shell killed by `SIGKILL` has to reach the user as
/// 137 rather than as a program that chose to exit 9, and the only thing carrying
/// that distinction across the wire is this one byte.
///
/// This client stays attached, unlike
/// [`a_session_whose_child_has_exited_keeps_its_files_and_its_status_with_nobody_attached`],
/// so what it pins is the frame the daemon builds on the pass that collects the
/// status — which makes it the place to pin `since_terminal_closed_secs` at zero. That
/// field is how a client tells a shell that has just finished from one that finished
/// while the laptop was shut (§ 6.5), and only a client that watched the exit happen
/// can say what the answer must be. A daemon that stamped the frame when it *built*
/// it rather than measuring from the end of file would pass every reattach test in
/// this file and still tell every live client that its shell had exited some time ago.
///
/// `kill -9 $$` rather than a signal from outside, because `$$` is the shell the
/// daemon is watching and `kill` is a builtin of it: no second process to find, and
/// nothing to race.
#[test]
fn a_child_killed_by_a_signal_is_reported_as_signalled_rather_than_as_a_status() {
    let (_session, mut client, _) = Session::attached("exit_signalled");

    client.input(0, b"kill -9 $$\n");

    let replay = replay_to_the_exit(&mut client);

    assert_eq!(
        (replay.status, replay.kind),
        (9, nomux_protocol::ExitKind::Signalled),
        "a child killed by SIGKILL must arrive as the signal that killed it, not as \
         a status a process chose"
    );
    // Whole seconds, so this is not a tight bound wearing a loose one: the daemon
    // collects the status on the pass that finds `waitpid` ready, microseconds after
    // the end of file it measures from, and a whole second would have to pass before
    // this could read as anything but zero.
    assert_eq!(
        replay.since_terminal_closed_secs, 0,
        "the client that watched the exit happen was told the shell had been gone \
         for {} s, so the field measures something other than the end of file",
        replay.since_terminal_closed_secs
    );
}

/// Regression: the status is turned into a frame on the pass that collects it, not
/// on whatever pass happens to wake up next.
///
/// `pump_output` is the only place the `Exit` frame is built, and `collect_outcome`
/// used to run at the top of `event_loop` — one whole iteration earlier.
/// `poll_timeout` carries a wakeup at `OUTCOME_GRACE` only while the outcome is still
/// outstanding, so the pass that finally collected one no longer qualified for it,
/// and by then the master had already left the poll set with the child.
///
/// A session outlives its child on the idle rule alone (§ 6.5), and nothing between
/// the exit and that deadline wakes the daemon: with the master out of the poll set,
/// `SIGCHLD` at its default disposition and no client traffic, the next wakeup is
/// `IDLE_TICK` — an hour away. The user is left holding a session whose shell has
/// finished, with no status and no reason given, until they type something at it.
///
/// Driven down the `OUTCOME_GRACE` path rather than through an ordinary `exit`, which
/// reaches the same bug only when `waitpid` is not ready at PTY end of file — a coin
/// toss rather than a test. A child that closes the terminal *without* exiting reaches
/// it every time: the master reports end of file at once, and `waitpid` has nothing to
/// give up because the process is still there, so the status can only come from the
/// two-second unknown-outcome deadline in `collect_outcome`.
///
/// `exec <command>` rather than bare redirections, because redirecting 0, 1 and 2 away
/// from the slave does not take the last descriptor onto it: an interactive shell
/// keeps one more for job control — `/dev/tty` on fd 10, under the `dash` this suite
/// pins as `SHELL` — and the master goes on waiting. Replacing the process closes that
/// one, since it is close-on-exec.
#[test]
fn an_unknown_outcome_is_sent_on_the_pass_that_decides_it() {
    /// Comfortably above the two-second `OUTCOME_GRACE`, and nowhere near the hour the
    /// regression misses this by: large enough not to fail a fork, an exec and a poll
    /// pass under nextest's full-core parallelism, and small enough to be a bound.
    const BOUND: Duration = Duration::from_secs(10);

    let (_session, mut client, ok) = Session::attached("outcome_unknown");

    // The marker is the last thing the child writes, and the `exec` on its heels is
    // what closes the terminal — so the clock below starts within one shell statement
    // of the end of file the daemon reacts to. The process it leaves behind is alive
    // for far longer than this test runs, which is what leaves `waitpid` with nothing
    // to report and forces the explicit unknown outcome.
    client.make_ready(
        "-echo",
        Some("exec sleep 300 0</dev/null 1>/dev/null 2>/dev/null"),
        ok.resume_from,
    );
    let began = Instant::now();

    // `replay_to_the_exit`'s own patience is far above `BOUND`, so what decides this
    // test is still the measurement below — the wait only replaces a hang with a
    // sentence.
    let replay = replay_to_the_exit(&mut client);
    let elapsed = began.elapsed();

    assert_eq!(
        replay.status, 0,
        "a child that closed the terminal without exiting has no status of its own"
    );
    assert_eq!(
        replay.kind,
        nomux_protocol::ExitKind::Unknown,
        "closing the terminal is not evidence that the child exited successfully"
    );
    assert!(
        elapsed < BOUND,
        "the Exit frame took {elapsed:?}: the status was collected at the two-second \
         grace and then held for a pass that never came, which is a terminal that \
         hangs until its user types at it on every exit `waitpid` is not ready for"
    );
}

/// A shell that exits behind a live job remains waitable, reserving the session id until
/// shutdown. Its outcome is known but not reported while the job holds the terminal.
#[test]
fn an_exited_shell_reserves_its_live_background_session() {
    let (session, mut client, ok) = Session::attached("zombie_shell");
    let shell = shell_of(&session);
    let ready = client.make_ready("-echo", None, ok.resume_from);

    // The job outlives the shell and keeps the slave open, so the master never
    // reports end of file and the daemon is never told the child has gone.
    client.input(ready.in_offset, b"sleep 300 & exit\n");
    assert!(
        poll_until(SETTLE, || !process_alive(shell)),
        "the shell never exited"
    );

    assert_eq!(
        process_state(shell),
        Some('Z'),
        "the shell was reaped early"
    );

    client.send(&Frame::Ping);
    drop(client.next_of(FrameType::Pong));

    // The job still has the terminal, and `Session` drops its daemon with `SIGKILL`,
    // which runs none of § 6.5's collection — so the `sleep` would outlive this test
    // by five minutes. Asking the daemon to stop is what collects it.
    let raw = session.child.id();
    let daemon = rustix::process::Pid::from_raw(raw.cast_signed()).expect("the daemon's own pid");
    rustix::process::kill_process(daemon, rustix::process::Signal::TERM)
        .expect("signal the daemon");
    assert!(
        poll_until(SETTLE, || !process_alive(raw)),
        "the signalled daemon never exited, so the job it was collecting is still \
         running"
    );
}

/// A child answered for as unknown stays waitable until session shutdown.
///
/// The other half of [`an_exited_shell_reserves_its_live_background_session`]: this child
/// closes its terminal, receives an unknown outcome, then exits on cue. `SIGCHLD` still
/// drives outcome observation, but the child remains waitable as the session's identity.
#[test]
fn a_child_that_exits_after_an_unknown_outcome_keeps_its_identity() {
    let (session, mut client, ok) = Session::attached("zombie_synth");
    let child = shell_of(&session);
    let cue = Cue::new(&session.root);

    client.make_ready(
        "-echo",
        Some("exec sh -c 'read go < cue' 0</dev/null 1>/dev/null 2>/dev/null"),
        ok.resume_from,
    );
    // Two seconds of `OUTCOME_GRACE` later, and the daemon has told this client that the
    // transcript ended without a known outcome while the child still waits below.
    drop(client.next_of(FrameType::Exit));

    cue.release();
    assert!(
        poll_until(SETTLE, || !process_alive(child)),
        "the child never took the cue and exited, so nothing below is about a status \
         that outlived its process"
    );

    assert_eq!(
        process_state(child),
        Some('Z'),
        "the daemon released pid {child} before session shutdown"
    );
}

/// The child must not inherit a handle to its own PTY master.
///
/// Everything the user runs in the session would otherwise hold a writable
/// descriptor onto the master: anything that walks `/proc/self/fd`, or writes to a
/// descriptor it did not open, could inject output into the stream or read the
/// user's keystrokes.
#[test]
fn the_child_inherits_only_its_stdio() {
    let (session, mut client, _ok) = Session::attached("fds");
    // The shell is up once it has run a line, which is what is looked for below.
    still_serving(&mut client, "NOMUX-SPAWNED");

    let shell = shell_of(&session);
    let mut terminals = Vec::new();
    for entry in fs::read_dir(format!("/proc/{shell}/fd")).expect("read the shell's fds") {
        let entry = entry.expect("fd entry");
        let target = fs::read_link(entry.path()).unwrap_or_default();
        let target = target.to_string_lossy().into_owned();
        assert!(
            !target.contains("ptmx"),
            "the child inherited the PTY master as fd {:?}",
            entry.file_name()
        );
        if target.starts_with("/dev/pts/") {
            terminals.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    terminals.sort();
    assert_eq!(
        terminals,
        ["0", "1", "2"],
        "the child should hold the slave exactly three times, as its stdio"
    );
}

/// The rest of what `Pty::spawn` puts into the child (§ 6.1): a login shell's
/// `argv[0]`, the terminal the client named, and the session's own id.
///
/// Of the five it sets, only `SSH_AUTH_SOCK` was ever checked. Losing `.arg0()`
/// silently stops `~/.profile` being read for every user, and losing `TERM` breaks
/// every full-screen program. The format string is echoed by the line discipline
/// unexpanded, so only the child's own answer can satisfy the read.
#[test]
fn the_child_is_a_login_shell_told_its_terminal_and_its_session() {
    let (session, mut client, ok) = Session::attached("spawn_env");
    client.input(
        0,
        b"printf 'NOMUX-SPAWN[%s|%s|%s]' \"$0\" \"$TERM\" \"$NOMUX_SESSION\"\n",
    );
    client.read_until(
        &format!("NOMUX-SPAWN[-sh|xterm-256color|{}]", session.id),
        ok.resume_from,
    );
}

/// The pid of the shell `session` is running.
///
/// Waited for rather than looked up once: a session is up when its daemon answers,
/// which is one fork before the shell exists, so a single walk of `/proc` is a race
/// every caller here would lose occasionally and blame on something else.
fn shell_of(session: &Session) -> u32 {
    let daemon = session.child.id();
    let mut shell = None;
    assert!(
        poll_until(SETTLE, || {
            shell = child_of(daemon);
            shell.is_some()
        }),
        "the daemon never started a shell"
    );
    shell.expect("the shell the wait above returned for")
}

/// The pid of `parent`'s first child, from `/proc`.
fn child_of(parent: u32) -> Option<u32> {
    let entries = fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|name| name.parse::<u32>().ok()) else {
            continue;
        };
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        let parent_of_pid = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .and_then(|value| value.trim().parse::<u32>().ok());
        if parent_of_pid == Some(parent) {
            return Some(pid);
        }
    }
    None
}

/// A child that exits while the daemon is still holding input it never read must not
/// take its own last words with it.
///
/// Guards the consequence rather than one line of the cause. `write_pty` used to
/// answer an `EIO` from the master by recording the exit, and recording the exit is
/// what takes the master out of the poll set, since `Daemon::watches` keeps it only
/// while `terminal_closed_at` is `None`. From that moment the master is never read again, so
/// everything the child wrote on its way out past the one read of that same pass was
/// dropped with no `Gap` to say so, which is the one thing § 9 forbids outright. The
/// exit belongs to `read_pty`, which reaches `Read::Eof` only once the master is dry.
///
/// The `EIO` itself cannot be provoked on Linux: writing to a master whose slave has
/// closed succeeds, and a master reports the departure on its read side only. So what
/// is pinned is the invariant rather than the line — the state in which an early exit
/// would cost output, composed exactly and asserted byte for byte.
///
/// Composing it needs three things at once. The master has to be holding output nobody
/// has read, and a daemon keeps up with a child effortlessly. `pending_input` has to be
/// non-empty, since the daemon asks for `POLLOUT` only while something is queued. And
/// the master has to still be *writable*, which rules out the queue
/// [`reconnecting_does_not_raise_the_input_ceiling`] builds: input that reached the cap
/// got there by filling the terminal, and a full terminal never reports `POLLOUT`
/// again.
///
/// So the daemon is stopped while all three are arranged around it — the only way to
/// hold a single-threaded event loop still long enough to compose a state it would
/// otherwise pass through in microseconds. Every step is then a condition: the child
/// has burst and exited (`/proc` says so), the whole burst is in the terminal's buffer
/// (it fits, so the child never blocked on a daemon that was not running), and the
/// keystroke is in the socket waiting to be read.
#[test]
fn a_child_that_exits_with_input_still_queued_delivers_its_last_output_in_full() {
    /// Bounded on both sides by the line discipline: a read of the master is handed
    /// 4095 bytes however large a buffer it offers, and a single write into an empty
    /// terminal is taken up to 11776 before the writer has to wait for a reader. So
    /// the burst is more than the couple of reads a daemon gets in before it could
    /// notice the exit — without which there would be nothing left to lose — and less
    /// than what the child can hand over in one go without waiting on a daemon that is
    /// not running, which it would otherwise do for ever.
    const BURST: usize = 10 * 1024;
    /// Room for the burst several times over. A `Gap` here would be the ring being
    /// tight rather than the master leaving the poll set, and the assertions below
    /// have to be able to tell those apart.
    const RING: usize = 4 << 20;

    let session = Session::start_with_ring("last_words", RING);

    // Written where the child can reach it — the shell starts in this directory — and
    // compared byte for byte at the far end, so a burst that arrives short, doubled or
    // out of order fails on the byte rather than on the total.
    let burst = Rng::new(0x1a57_0207).bytes(BURST);
    fs::write(session.root.join("burst"), &burst).expect("write what the child will emit");
    let cue = Cue::new(&session.root);

    let mut client = session.connect();
    let ok = client.hello(RESUME_FROM_START);
    // `-echo` so the keystroke below is not echoed into the stream being compared, and
    // `raw` so the line discipline neither mangles it nor throws it away — which is
    // what makes it reach `pending_input` rather than the floor.
    let ready = client.make_ready(
        "raw -echo",
        Some("read cue < cue; cat burst; exit 9"),
        ok.resume_from,
    );
    let shell = shell_of(&session);

    let daemon = rustix::process::Pid::from_raw(session.child.id().cast_signed())
        .expect("the daemon's own pid");
    rustix::process::kill_process(daemon, rustix::process::Signal::STOP).expect("stop the daemon");
    assert!(
        poll_until(SETTLE, || process_state(session.child.id()) == Some('T')),
        "the daemon never stopped, so what follows is a race rather than a setup"
    );

    cue.release();

    // The whole burst is in the terminal's buffer by the time this comes back, and
    // nothing but the master's read side can ever produce it again. A child that has
    // exited but not been collected is a zombie, which is one of the two states this
    // reads as gone — the daemon that would reap it is stopped.
    assert!(
        poll_until(SETTLE, || !process_alive(shell)),
        "the child never finished its burst and left"
    );

    // A keystroke the child is never going to read, waiting in the socket for a daemon
    // that has not run since the terminal it belongs to lost its far end.
    client.input(ready.in_offset, b"x");

    rustix::process::kill_process(daemon, rustix::process::Signal::CONT)
        .expect("let the daemon go");

    let mut seen: Vec<u8> = Vec::new();
    let mut offset = ready.offset;
    let deadline = Instant::now() + FRAME_PATIENCE;
    let awaiting = "the child's last output and the exit behind it";
    let ended = loop {
        let (ty, payload) = client.frame_before(deadline, awaiting).unwrap_or_else(|| {
            panic!(
                "only {} of the {BURST} bytes the child wrote on its way out arrived, \
                 and no Exit behind them",
                seen.len()
            )
        });
        match Frame::decode(ty, &payload).expect("decode frame") {
            Frame::Output { offset: at, data } => {
                assert_eq!(
                    at,
                    offset,
                    "the child's last output must arrive unbroken: this frame opens {} \
                     bytes from where the stream stood",
                    at.abs_diff(offset)
                );
                offset += data.len() as u64;
                seen.extend_from_slice(data);
            }
            Frame::Exit {
                status,
                kind,
                since_terminal_closed_secs: _,
            } => break (status, kind),
            Frame::InputAck { .. } | Frame::Pong => {}
            other => panic!("unexpected {other:?} while collecting the child's last output"),
        }
    };

    assert_eq!(
        ended,
        (9, nomux_protocol::ExitKind::Exited),
        "the child's own status must survive the exit its queued input interrupted"
    );
    assert!(
        seen.len() >= BURST,
        "only {} bytes arrived before the Exit, out of the {BURST} the child wrote on \
         its way out",
        seen.len()
    );
    assert_eq!(
        &seen[seen.len() - BURST..],
        &burst[..],
        "the child's last {BURST} bytes are not what it wrote"
    );
}

/// The daemon must not hold the directory it was started in — that pins a mount
/// for the life of the session — while the shell must still start where sshd
/// would have started it.
#[test]
fn the_daemon_releases_its_working_directory_but_the_shell_does_not() {
    let (session, mut client, ok) = Session::attached("cwd");

    let cwd = fs::read_link(format!("/proc/{}/cwd", session.child.id())).expect("read daemon cwd");
    assert_eq!(
        cwd,
        Path::new("/"),
        "daemon still holds a working directory"
    );

    client.input(0, b"pwd\n");
    let home = session.root.to_str().expect("utf-8 root");
    client.read_until(home, ok.resume_from);
}

/// § 6.2's detachment, on the path that needs a fork.
///
/// [`leads_a_process_group`] is what forces the `EPERM` only a fork can answer: a
/// test that starts a plain daemon goes on passing with `detach_from_login_session`
/// moved to after `write_pidfile`, so it guards nothing.
///
/// The daemon that survives is in nobody's process group and is nobody's child, so
/// `wait` collects the process that started and nothing else — it has to be reaped
/// through `nomux kill`, before the assertions rather than after them.
#[test]
fn a_daemon_that_leads_a_process_group_detaches_by_forking() {
    let root = run_root("fork");
    let mut command = nomux_with_shell(&root, &["daemon", "grouped"]);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    leads_a_process_group(&mut command);
    let mut starter = Spawned::spawn(&mut command);
    let original_pid = starter.id();

    let pid_file = root.join("nomux/run").join("grouped.pid");
    wait_for(&root.join("nomux/run").join("grouped.sock"));
    wait_for(&pid_file);

    // Bounded rather than a bare `wait`: if the fork never happened then the process
    // started here *is* the daemon, and waiting on it would hang the suite instead of
    // failing an assertion.
    let starter_exited = poll_until(SETTLE, || !starter.is_running());

    // `recorded` outlives the wait because the assertions below are about the pid the
    // last look found, whether or not it ever satisfied the condition.
    let mut recorded = None;
    poll_until(SETTLE, || {
        recorded = fs::read_to_string(&pid_file)
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok());
        recorded.is_some_and(has_detached)
    });

    // Everything read before anything is collected, so a failing assertion cannot
    // leave a session behind.
    let detachment = recorded.map(detachment_of).unwrap_or_default();
    let alive = recorded.is_some_and(process_alive);
    let killed = control(&root, &["kill", "grouped"]);
    drop(starter);

    assert!(
        starter_exited,
        "the process that started never left, so nothing forked"
    );
    // The other half of what the pidfile is for, and the one case where it outranks
    // the socket: `control::daemon_of` takes the pid off the connection, and the
    // process that made this socket is the one that `_exit`ed above. A number the
    // kernel has already reclaimed is not an identity, so `kill` falls back to the
    // file the survivor wrote — without which this session could not be stopped at
    // all, which is the fault the assertion below names from the other side.
    succeeded(
        &killed,
        "kill could not stop a daemon that had to fork to detach",
    );
    assert_ne!(
        recorded,
        Some(original_pid),
        "the pidfile names the process that started, which has since exited — \
         `nomux kill` would signal nobody"
    );
    assert!(
        alive,
        "no live daemon behind the pidfile: it names {recorded:?}"
    );
    assert_detached(&detachment, recorded);
}

/// Regression: a spawn whose socket cannot be bound leaves nothing behind.
///
/// The bind is the first way out of the locked region — a full disk, a descriptor
/// shortage, a quota, a name planted where `<id>.sock` goes. It returned through `?`,
/// past the removal, leaving the 0-byte `<id>.lock` `try_lock_spawn` had just created:
/// a session `nomux list` reports and the next daemon reads as one that is there, until
/// something collects it.
///
/// The lever is a directory where the socket goes, which needs no fault injection and
/// fails the daemon on its own path: `connect` to a name that is not a socket is refused,
/// which is the whole of what § 6.6 means by stale, and the removal that answer licenses
/// comes back `EISDIR`. What is asserted is the directory rather than the five names,
/// since the property is that a refusal touched nothing at all.
#[test]
fn a_spawn_whose_socket_cannot_be_bound_leaves_no_lock_behind() {
    let root = run_root("bind_lock");
    let dir = root.join("nomux/run");
    fs::create_dir_all(&dir).expect("create the run directory");
    fs::create_dir(dir.join("wedged.sock")).expect("plant a name no bind can take");
    let before = entries(&dir);

    let refused = control_with_shell(&root, &["daemon", "wedged"]);

    let complaint = harness::stderr(&refused);
    assert_eq!(
        refused.status.code(),
        Some(1),
        "a daemon claimed an id whose socket it could not bind: {complaint:?}"
    );
    assert_eq!(
        entries(&dir),
        before,
        "the refused spawn left files behind, and a bare `<id>.lock` is one that both \
         `list` and the next daemon read as a session that is there: {complaint:?}"
    );
}

/// A stop signal the daemon inherited already pending must reach § 6.5's shutdown, not
/// the default disposition.
///
/// `exec` preserves a blocked signal *and* a pending one, so the daemon starts owing a
/// `SIGTERM` it has not heard yet, and `startup::arm_stop_signals` decides which of two
/// things happens when it clears the mask. Handlers installed first: the byte goes down
/// the stop pipe and leaving unlinks the run files. The mask cleared first: `SIG_DFL`
/// kills the process between `bind_socket` and the event loop, and `<id>.sock` and
/// `<id>.lock` are left for the next daemon and for `list` to read as a live session.
///
/// The directory is what is asserted, rather than the exit status: both orders end the
/// process, and only one of them ends it having tidied up.
#[test]
fn a_daemon_that_inherits_a_pending_stop_signal_still_runs_its_shutdown() {
    let root = run_root("pending_term");
    let dir = root.join("nomux/run");
    fs::create_dir_all(&dir).expect("create the run directory");
    let before = entries(&dir);

    let mut command = nomux_with_shell(&root, &["daemon", "pending"]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    arrives_with_a_stop_signal_pending(&mut command);
    let finished = harness::collect(&mut command);

    let complaint = harness::stderr(&finished);
    assert_eq!(
        entries(&dir),
        before,
        "a daemon that inherited a pending SIGTERM left its run files behind, so the mask \
         was cleared before the handlers were installed and the signal landed on SIG_DFL \
         with the socket already bound: {complaint:?}"
    );
}

/// Hands what `command` starts a `SIGTERM` that is blocked *and already pending*, the
/// state `exec` preserves and § 6.2's arming has to survive.
///
/// A shell holding the signal blocked, a systemd unit, a harness — the daemon inherits
/// both halves, and the pending one is delivered the instant anything clears the mask.
/// `startup::arm_stop_signals` therefore has to install the handlers *before* it
/// unblocks: the other order delivers this signal at `SIG_DFL` with the socket already
/// bound, killing the daemon where it stands with § 6.5's shutdown unrun.
fn arrives_with_a_stop_signal_pending(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    // SAFETY: the closure runs in the forked child before exec, so it must be
    // async-signal-safe. `sigemptyset`, `sigaddset`, `sigprocmask` and `raise` all are,
    // and nothing here allocates or takes a lock.
    unsafe {
        command.pre_exec(|| {
            let mut set = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
            if libc::sigemptyset(set.as_mut_ptr()) != 0
                || libc::sigaddset(set.as_mut_ptr(), libc::SIGTERM) != 0
                || libc::sigprocmask(libc::SIG_BLOCK, set.as_ptr(), std::ptr::null_mut()) != 0
                // Blocked first, so this makes it pending rather than fatal.
                || libc::raise(libc::SIGTERM) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// The other side of that scrub, and why it cannot be unconditional: a daemon refused
/// because a live session already holds the id must leave that session's `<id>.lock`
/// alone.
///
/// The refusal arrives at the same place by the same route — the bind, this time
/// answering `AddrInUse` because the probe found somebody listening — but the lock this
/// daemon took on its way in is the *live* session's, created when that daemon claimed
/// the id and outliving it for the whole session. Removed, it stops being a mutex at all
/// (`rundir::SpawnLock`): the next `spawn` and the next `kill` each create a file at the
/// same path, lock that, and are both certain they hold the only lock there is.
///
/// Green against the defect as well as against the fix, which is the point of it: it is
/// the fix that could break this, and nothing else in the suite would notice.
#[test]
fn a_daemon_refused_by_a_live_session_leaves_that_session_its_lock() {
    let session = Session::start("dup_id");
    let lock = session
        .root
        .join("nomux/run")
        .join(format!("{}.lock", session.id));
    assert!(
        lock.exists(),
        "the live session left no spawn lock, so nothing below is about one"
    );

    let refused = control_with_shell(&session.root, &["daemon", &session.id]);

    let complaint = harness::stderr(&refused);
    assert_eq!(
        refused.status.code(),
        Some(1),
        "a second daemon took an id a live session is answering on: {complaint:?}"
    );
    assert!(
        complaint.contains("already running"),
        "the refusal must be the live session's, or this says nothing about the arm it \
         is written for: {complaint:?}"
    );
    assert!(
        lock.exists(),
        "the refused daemon removed the live session's spawn lock, which leaves § 6.3's \
         serialisation with nothing to serialise on: {complaint:?}"
    );

    // And the session it collided with is untouched by the collision.
    let mut client = session.connect();
    client.hello(RESUME_FROM_START);
    still_serving(&mut client, "NOMUX-AFTER-DUP");
}

/// A spawn whose lock is collected while it waits goes back for the file that is now
/// at the path.
///
/// This is the half of the fix that is not "take the lock first": `flock` attaches
/// to the inode, so a spawn that was blocked on a lock file somebody unlinked
/// wakes up holding a lock nobody else can see. The next spawn creates a fresh
/// file at the same path, locks that, and both start a daemon for one session.
///
/// `spawn` rather than `attach` because creating is what takes this lock at all
/// (§ 6.3): `attach` connects to a session that is already there and never reaches
/// the region under test.
///
#[test]
fn a_spawn_re_takes_a_spawn_lock_that_was_collected() {
    let deadline = Instant::now() + PATIENCE;
    let root = run_root("collected_lock");
    let dir = root.join("nomux/run");
    fs::create_dir_all(&dir).expect("create the run directory");
    let lock_path = dir.join("collected.lock");
    let lock = HeldLock::take(&lock_path);
    let held = lock.metadata().expect("stat the held lock");
    let orphan = held.ino();

    let mut relay = Spawned::spawn(
        nomux_with_shell(&root, &["spawn", "collected"])
            .env("NOMUX_RING_BYTES", "65536")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    );

    thread::sleep(SPIN_WINDOW);
    assert!(
        relay.is_running() && !dir.join("collected.sock").exists(),
        "spawn did not remain pending behind the held lock on inode {orphan}"
    );

    // Exactly what collection used to do to a lock in use.
    fs::remove_file(&lock_path).expect("unlink the lock");
    drop(lock);

    let socket = dir.join("collected.sock");
    assert!(
        poll_by(deadline, || socket.exists()),
        "the spawn never brought up a socket for the session"
    );
    // Nothing collects this session by an explicit `nomux kill`, and the guard has to
    // cover the failing assertion below too.
    let (_pid, _reaper) = daemon_reaper(&root, "collected");

    assert!(
        lock_path.exists(),
        "the session came up without the spawn lock the layout promises, so the \
         spawn started it holding an unlinked inode"
    );
}

/// Regression: a daemon holds `<id>.lock` across claiming its id, so nothing can
/// collect the session it is in the middle of publishing.
///
/// `spawn` holds that lock from before the fork until `<id>.pid` exists (§ 6.3) and
/// `list` and `kill` take it before they unlink anything (§ 6.6) — but a `nomux daemon
/// <id>` started by hand, which § 6.2 is written for, took nothing at all. A `list`
/// that had already probed the stale socket then unlinked the socket and pidfile this
/// daemon had bound in between, and through `kill` the same interleaving exits 0
/// reporting no such session while a daemon holds the user's shell.
///
/// The window is three syscalls wide, so it is held open rather than waited for:
/// `bind_socket` probes the socket before it touches anything, and a `connect` to a
/// listener whose backlog is full blocks, so [`wedge_socket`] parks the daemon inside
/// the region under test for as long as this test likes.
#[test]
fn a_daemon_holds_the_spawn_lock_while_it_claims_the_id() {
    let deadline = Instant::now() + PATIENCE;
    let root = run_root("claimed_lock");
    let dir = root.join("nomux/run");
    fs::create_dir_all(&dir).expect("create the run directory");
    // Created here so the wait below has an inode to name; the daemon opens this same
    // path, and `SpawnLock` checks that what it locked is still the file at it.
    let lock = fs::File::create(dir.join("claimed.lock")).expect("create the spawn lock");
    let lock = lock.metadata().expect("stat the spawn lock");

    let _wedged = wedge_socket(&dir.join("claimed.sock"));

    let _daemon = Spawned::spawn(
        nomux_with_shell(&root, &["daemon", "claimed"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    );

    wait_until_flock(
        Flock::Granted,
        lock.dev(),
        lock.ino(),
        "the daemon took the spawn lock before it went near the socket",
        deadline,
    );
}

/// A direct daemon start cannot turn somebody else's locked, stale id into a live
/// session.
///
/// The lock is the authority to replace a stale socket, not merely a courtesy around
/// publication. Proceeding after a nonblocking lock attempt failed let two daemons both
/// believe they could claim one id: the second could unlink the first one's socket in
/// the narrow interval before its listener began answering. A stale socket forces the
/// replacement arm here without needing that timing window; the held lock must stop the
/// daemon before it changes any name.
#[test]
fn a_direct_daemon_refuses_an_id_whose_spawn_lock_is_held() {
    let deadline = Instant::now() + PATIENCE;
    let root = run_root("contended_direct_lock");
    let dir = root.join("nomux/run");
    fs::create_dir_all(&dir).expect("create the run directory");
    let socket = dir.join("contended.sock");
    drop(UnixListener::bind(&socket).expect("plant a stale session socket"));
    let socket_before = fs::metadata(&socket).expect("stat the stale socket").ino();
    let held = HeldLock::take(&dir.join("contended.lock"));
    let lock_before = held.metadata().expect("stat the held lock").ino();

    let mut daemon = Spawned::spawn(
        nomux_with_shell(&root, &["daemon", "contended"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    assert!(
        poll_by(deadline, || !daemon.is_running()),
        "a direct daemon waited for, or proceeded without, somebody else's spawn lock"
    );
    let refused = daemon
        .into_exited()
        .wait_with_output()
        .expect("collect the refused daemon");

    assert_eq!(
        refused.status.code(),
        Some(1),
        "a daemon claimed an id without the spawn lock: {:?}",
        harness::stderr(&refused)
    );
    assert!(
        harness::stderr(&refused).contains("being started or removed"),
        "the refusal did not identify the held startup authority: {:?}",
        harness::stderr(&refused)
    );
    assert_eq!(
        fs::metadata(&socket)
            .expect("the stale socket survived")
            .ino(),
        socket_before,
        "the refused daemon replaced a socket without owning the spawn lock"
    );
    assert_eq!(
        fs::metadata(dir.join("contended.lock"))
            .expect("the held lock survived")
            .ino(),
        lock_before,
        "the refused daemon replaced somebody else's lock name"
    );
}

/// Whether `pid` has finished detaching itself (§ 6.2): a session of its own, and
/// nothing left of the stdio it was handed.
///
/// The same two halves [`assert_detached`] reports, through the same
/// [`detachment_of`], so the wait and the assertion behind it cannot disagree.
fn has_detached(pid: u32) -> bool {
    let (leads_session, stdio) = detachment_of(pid);
    leads_session == Some(pid) && stdio_is_silenced(&stdio)
}

/// What `/proc` says about `pid`'s detachment, as the session it leads and the three
/// descriptors it holds.
///
/// Read out and handed back rather than asserted on the spot, because both halves
/// have to be in hand *before* the caller collects the daemon: `/proc` has nothing to
/// say about a process that is gone, and a failing assertion must not be the thing
/// that leaves a session behind.
fn detachment_of(pid: u32) -> (Option<u32>, Vec<PathBuf>) {
    let stdio = (0..3)
        .map(|fd| fs::read_link(format!("/proc/{pid}/fd/{fd}")).unwrap_or_default())
        .collect();
    (stat_field(pid, StatField::Session), stdio)
}

/// The two halves of § 6.2, as [`detachment_of`] found them for the forked child.
fn assert_detached(found: &(Option<u32>, Vec<PathBuf>), pid: Option<u32>) {
    let (leads_session, stdio) = found;
    assert_eq!(
        *leads_session, pid,
        "the forked child stayed in the session it was started in, so a hangup \
         reaches it"
    );
    assert!(
        stdio_is_silenced(stdio),
        "the forked child still holds the descriptors it was handed: {stdio:?}"
    );
}

/// Whether all three point at `/dev/null`, which is where detaching puts them. Takes
/// what [`detachment_of`] read rather than a pid, for the reason given there.
fn stdio_is_silenced(targets: &[PathBuf]) -> bool {
    targets.iter().all(|path| path == Path::new("/dev/null"))
}

/// A daemon spawned by a connection that died mid-handshake must reap itself — and a
/// session somebody has actually used must not.
///
/// Every reaping rule is only checked when `poll` returns, so this is really a test
/// that a wakeup is armed for the 30-second first-attach deadline rather than only
/// for the hour-long backstop. Waiting out that deadline is the only way to observe
/// it from outside, which is why this is `#[ignore]`d: 30 seconds is unreasonable
/// in a suite that otherwise finishes in two, and CI runs it with
/// `--run-ignored all`.
///
/// Both halves, because `Daemon::detach_deadline` is a *choice* — 30 seconds where no
/// PTY was ever started, seven days once one was — and the rule was the untested one
/// of the two. A regression returning `FIRST_ATTACH_TIMEOUT` for both would reap
/// every real user's session half a minute after they shut their laptop, and nothing
/// in the suite would go red: the timeout half would pass, being what the regression
/// does everywhere. The other branch rides along at no cost in wall clock, since the
/// wait is the same wait.
#[test]
#[ignore = "waits out the 30-second first-attach timeout; run in CI, not on every commit"]
fn a_daemon_nobody_ever_attaches_to_reaps_itself() {
    // The seven-day branch is set up first so that under the regression its thirty
    // seconds are up no later than the other session's. That ordering is not enough on
    // its own — the two are within a hundred milliseconds of each other — so the
    // assertion at the end asks for a margin instead.
    let (greeted, client, _) = Session::attached("attached_once");
    // The limit is consulted only while there is nobody attached, so a session still
    // holding its client would satisfy the assertion below by never having been asked
    // the question. The `Hello` that has just been answered is what makes this the
    // seven-day branch: it is what started the PTY.
    drop(client);
    let detached_at = Instant::now();

    let unattached = Session::start("unattached");

    assert!(
        poll_until(Duration::from_secs(45), || !unattached.socket.exists()),
        "daemon outlived its first-attach timeout"
    );

    // Stated rather than reasoned about: the wait above cannot end before the
    // unattached daemon's own 30 seconds are up, and this session was detached before
    // that daemon existed — so by here it has been clientless for longer than the
    // deadline it must not be holding.
    assert!(
        detached_at.elapsed() > Duration::from_secs(30),
        "the unattached daemon went in {:?}, which is short of the first-attach \
         timeout — so nothing below says anything about the limit this session is on",
        detached_at.elapsed()
    );
    // "Still here three seconds from now" rather than "here at this instant", which is
    // what makes this falsifiable: only a margin tells a session on the seven-day limit
    // from one on the thirty-second limit that has not got round to it yet.
    //
    // Answering, not merely present: the socket file outlives the process that bound
    // it, so a daemon that died without unlinking would leave one behind. A bare
    // `connect` is not an attach (§ 6.4) and costs this session nothing.
    let reaped = poll_until(Duration::from_secs(3), || {
        !greeted.socket.exists() || UnixStream::connect(&greeted.socket).is_err()
    });
    assert!(
        !reaped,
        "a session that was attached to and then detached was reaped on the \
         first-attach deadline, so closing a laptop for half a minute now costs the \
         user their shell"
    );
}

/// A session whose child has exited and whose client has left is still there — still
/// holding its run files, still answering, and still able to say what happened.
///
/// § 6.5's lifetime rule stated from outside: a session is reaped on `last_detach +
/// IDLE_TIMEOUT` and on nothing else, so a child that finishes is not a second
/// deadline beside it. It used to be one — five seconds measured from the end of
/// file — and what that cost is what this exists to keep from coming back: a build
/// that finished while the laptop was shut took the session, the run files and the
/// status with it, and left the user unable to tell that from an id that had never
/// named anything. Knowing how a job that has already run turned out is most of why
/// anybody leaves one running.
///
/// The status is distinctive because the alternative is not: `exit 0` is what the
/// daemon reports as unknown for a child it never got a status for (`collect_outcome`), so a
/// session that had lost the real one would still answer plausibly.
///
/// The order the two halves arrive in is pinned here as well, for the client that has
/// no way to ask again: `pump_output` sends the `Exit` only once `sent_through` has
/// reached the end of the ring, and it is decided afresh for every connection —
/// `on_hello` rewinds `sent_through` to where this client resumes and `terminal_end_sent`
/// starts false on every takeover. A client that was handed the status first closes
/// the tab on it and loses the whole transcript, including whatever the shell said on
/// its way out; [`replay_to_the_exit`] stops at the `Exit`, so output queued behind it
/// is output the marker assertion below never sees.
#[test]
fn a_session_whose_child_has_exited_keeps_its_files_and_its_status_with_nobody_attached() {
    /// How long the session is left with no client and no child before anything at
    /// all is asked of it.
    ///
    /// Past the five seconds a daemon used to allow itself after its child exited, and
    /// the one wall-clock wait in this suite that cannot be replaced by a condition:
    /// what is under test is a deadline that is *not* there, and the only way to see
    /// one of those is to outlast the one that used to be. Six rather than five and a
    /// bit, because the clock the daemon would have measured starts at the end of file
    /// it reports and this one starts at `/proc` agreeing the child has gone.
    const UNATTENDED: Duration = Duration::from_secs(6);
    /// Five ticks is 50 ms of processor time against the half second [`SPIN_WINDOW`]
    /// covers: a tenth of a core, unreachable by a daemon that is asleep.
    const TOLERATED: u64 = 5;

    let (session, mut client, _) = Session::attached("outlives_child");
    let shell = shell_of(&session);
    let daemon = session.child.id();

    // The client leaves before the shell does, which is the case the old window was
    // written for and the one this rule has to answer without it: nobody is watching
    // when the status is collected, so the daemon is holding it for a client that has
    // not arrived. The ack first, or the RST a close over unread bytes provokes takes
    // the command with it rather than running it (`Client::wait_for_input_ack`).
    let command = b"printf NOMUX-LAST-WORD; exit 7\n";
    client.input(0, command);
    client.wait_for_input_ack(command.len() as u64);
    drop(client);

    assert!(
        poll_until(SETTLE, || !process_alive(shell)),
        "the child never exited, so the wait below is about a session that still has \
         one and says nothing about what happens to a session that does not"
    );
    // Measured inside the wait rather than beside it, so it costs nothing: this is
    // exactly the state `Daemon::watches` drops the PTY master for, and without that
    // filter the master reports `POLLHUP` every pass until the idle timeout.
    let burned = cpu_ticks(daemon);
    thread::sleep(UNATTENDED.saturating_sub(SPIN_WINDOW));

    assert!(
        burned <= TOLERATED,
        "the daemon burned {burned} clock ticks in {SPIN_WINDOW:?} with its child gone \
         and nobody attached, which is a core per finished session for up to seven days"
    );
    assert!(
        process_alive(daemon),
        "the daemon left {UNATTENDED:?} after its child did, so a session outlives \
         its shell by a deadline of its own rather than by the idle rule"
    );
    let pid_file = session.pid_file();
    assert!(
        pid_file.exists() && session.socket.exists(),
        "the session took its run files with it {UNATTENDED:?} after its child \
         exited, so `list` no longer knows it is there: socket={} pid={}",
        session.socket.exists(),
        pid_file.exists()
    );

    // The point of holding all that: the session is not merely present, it is still
    // the same session, and it still owes this client both halves of the ending.
    let mut client = session.connect();
    let resumed = client.hello(RESUME_FROM_START);
    let replay = replay_to_the_exit(&mut client);
    assert_eq!(
        (replay.status, replay.kind),
        (7, nomux_protocol::ExitKind::Exited),
        "the child's own status must survive being held for {UNATTENDED:?} with \
         nobody to give it to"
    );
    assert!(
        replay.output.contains("NOMUX-LAST-WORD"),
        "the exit status arrived ahead of the child's last words, or they were \
         dropped while the session waited: {:?} (resumed from {})",
        replay.output,
        resumed.resume_from
    );
    // The other half of what `since_terminal_closed_secs` is for, and the half only a delay can
    // establish: a client arriving late is told *how* late, so a shell that finished
    // days ago is not presented as one that just did. Compared against one less than
    // the wait, since the field counts whole seconds from an end of file that
    // preceded it.
    assert!(
        u64::from(replay.since_terminal_closed_secs) + 1 >= UNATTENDED.as_secs(),
        "a client reattaching {UNATTENDED:?} after the exit was told the child had \
         been gone for {} s, so the field is stamped when the frame is built rather \
         than measured from the end of file",
        replay.since_terminal_closed_secs
    );
}

/// What a client reattaching to a session whose child has gone is owed: everything
/// the child wrote, and the fate behind it.
struct Replay {
    /// The child's output, from where this client resumed to the exit.
    output: String,
    /// Exit status, or the signal number when `kind` is `Signalled`.
    status: i32,
    /// How the child terminated.
    kind: nomux_protocol::ExitKind,
    /// Whole seconds the daemon says have passed since the child let go of the
    /// terminal.
    since_terminal_closed_secs: u32,
}

/// Reads a reattached client's replay up to and including the exit.
///
/// The ordering promise of § 6.5 is carried by the *shape* of this loop rather than
/// by a line in its caller: the `Exit` ends it, so anything the child wrote that the
/// daemon queued behind the status is output this never collects — and the caller
/// then finds its marker missing rather than finding a passing test that read the
/// frames in whatever order they came.
fn replay_to_the_exit(client: &mut Client) -> Replay {
    let mut seen = Vec::new();
    let deadline = Instant::now() + FRAME_PATIENCE;
    let awaiting = "the child's last output and then its exit status";
    loop {
        let (ty, payload) = client.frame_before(deadline, awaiting).unwrap_or_else(|| {
            panic!(
                "the exit status never arrived; {} bytes of output before it: {:?}",
                seen.len(),
                String::from_utf8_lossy(&seen)
            )
        });
        match Frame::decode(ty, &payload).expect("decode") {
            Frame::Output { data, .. } => seen.extend_from_slice(data),
            Frame::Exit {
                status,
                kind,
                since_terminal_closed_secs,
            } => {
                return Replay {
                    output: String::from_utf8_lossy(&seen).into_owned(),
                    status,
                    kind,
                    since_terminal_closed_secs,
                };
            }
            Frame::InputAck { .. } | Frame::Gap { .. } | Frame::Pong => {}
            other => panic!("unexpected {other:?} while awaiting {awaiting}"),
        }
    }
}

/// `SIGTERM` must leave through the shutdown path, not the default disposition.
///
/// Without a handler the daemon died where it stood, so `Pty::terminate` never ran —
/// and closing the PTY master hides that for the ordinary case, because the kernel
/// delivers `SIGHUP` to the foreground process group on the way out. What it does not
/// cover is [`background_ignoring_sighup`]'s process, which only a real shutdown path
/// collects.
#[test]
fn a_signalled_daemon_collects_a_process_that_ignores_sighup() {
    let (session, mut client, ok) = Session::attached("sigterm");

    let (orphan, _collected) = background_ignoring_sighup(&mut client, ok.resume_from);
    assert!(
        process_alive(orphan),
        "the backgrounded process was gone before the session ended"
    );
    let shell = shell_of(&session);
    assert_eq!(
        stat_field(orphan, StatField::ProcessGroup),
        Some(shell),
        "this shell kept job control on, so nothing here is testing reaping"
    );

    let daemon = rustix::process::Pid::from_raw(session.child.id().cast_signed())
        .expect("the daemon's own pid");
    // Signalled directly rather than through `nomux kill`, which unlinks the run
    // files itself and would answer the question for the daemon.
    rustix::process::kill_process(daemon, rustix::process::Signal::TERM)
        .expect("signal the daemon");

    // `shutdown` unlinks what the session published on its way out, so the files
    // outliving the process is the visible symptom of a shutdown that did not run to
    // completion — `list` then reports a session nobody can attach to until something
    // else garbage-collects it. Both files, because either one left behind is that
    // symptom, and the message names both rather than the first to be looked at.
    //
    // Inside the two seconds `nomux kill` allows before `SIGKILL`, with room for a
    // loaded machine: an overrun there is this same bug wearing a hat.
    let pid_file = session.pid_file();
    assert!(
        poll_until(SETTLE, || !pid_file.exists() && !session.socket.exists()),
        "run files outlived the signalled daemon: socket={} pid={}",
        session.socket.exists(),
        pid_file.exists()
    );

    assert!(
        poll_until(SETTLE, || !process_alive(orphan)),
        "pid {orphan} outlived the session it was backgrounded in"
    );
}

/// Backgrounds a process the session's own hangup cannot collect, and hands back its
/// pid and a guard for it.
///
/// `trap '' HUP` before the fork, because an *ignored* disposition is inherited
/// through `exec` where a trapped one is reset — which is what puts this process
/// beyond the `SIGHUP` the kernel delivers to the foreground group when the PTY
/// master closes, and so makes it the case that only a real shutdown path collects.
///
/// `set +m` is what puts it where reaping can see it at all: an interactive shell
/// gives every job a process group of its own and nothing in the session signals
/// those, while with job control off the job stays in the shell's group, which is
/// what `Pty::terminate` signals and what a script's background processes do anyway.
///
/// The marker trails the pid so that seeing it proves the digits already arrived, and
/// the arithmetic is `harness::READY_MARKER`'s — without it the echo of the command
/// would match first, carrying `$!` unexpanded.
///
/// The [`Reaper`] comes back with it because the process is deliberately in nobody's
/// reach: if an assertion fires, `sleep 300` outlives the whole suite.
fn background_ignoring_sighup(client: &mut Client, from: u64) -> (u32, Reaper) {
    client.input(
        0,
        b"set +m; trap '' HUP; sleep 300 & echo \"$!-NOMUX-ORPHAN-$((6*7))\"\n",
    );
    let (seen, _) = client.read_until("-NOMUX-ORPHAN-42", from);
    let orphan = trailing_pid(&seen, "-NOMUX-ORPHAN-42")
        .unwrap_or_else(|| panic!("no background pid in the transcript: {seen:?}"));
    (orphan, Reaper(orphan))
}

/// The run of digits immediately before `marker`, as a pid.
fn trailing_pid(transcript: &str, marker: &str) -> Option<u32> {
    let (head, _) = transcript.rsplit_once(marker)?;
    let reversed: String = head
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect();
    reversed.chars().rev().collect::<String>().parse().ok()
}
