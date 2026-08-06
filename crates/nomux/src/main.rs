//! `nomux` — persistent PTY sessions that survive SSH disconnects.
//!
//! One binary, several modes (see `DESIGN.md` § 4):
//!
//! - `daemon` owns the PTY master, the child process and the output ring buffer.
//! - `spawn` and `attach` are one dumb byte relay between stdio and the daemon's
//!   unix socket, differing only in whether they may create the session.
//! - `list` and `kill` are the frozen, version-independent control surface.

mod agent;
mod attach;
mod conn;
mod control;
mod daemon;
mod linger;
mod nbio;
mod passwd;
mod pty;
mod ring;
mod rundir;
#[cfg(test)]
mod scratch;
mod startup;
mod syslog;

use std::env;
use std::ffi::OsString;
use std::process::ExitCode;

/// `EX_USAGE`: malformed invocation. The one code borrowed from `sysexits.h`, and
/// the only one shared by every mode — `IMPLEMENTATION.md` § 10 has both tables and
/// says why the rest of that range is left alone.
const EXIT_USAGE: u8 = 64;
/// The session is there but this mode cannot have it: `spawn` found the id already
/// taken, or `attach` found a session it could not join. The shell's "found but not
/// executable", for the reason § 10 gives.
const EXIT_UNATTACHABLE: u8 = 126;
/// No such session — `attach` on an id nothing answers for, or a `spawn` whose daemon
/// never started. The shell's "not found", for the reason above.
const EXIT_NO_SESSION: u8 = 127;

const USAGE: &str = "\
usage: nomux <mode> [session-id] [--label <text>]

modes:
  daemon <session-id>   Own a PTY session (normally spawned by `spawn`)
  spawn <session-id>    Create a session and relay stdio to it; fails if it exists
  attach <session-id>   Relay stdio to an existing session; fails if it does not

control surface (frozen across versions, see IMPLEMENTATION.md 6.6):
  list                  List sessions in the run directory
  kill <session-id>     Terminate a session and unlink its run files

options:
  --label <text>        Display name for `list`, recorded when the session is created
  --version, -V         Print version and protocol revision
  --help, -h            Print this usage
";

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let Some(mode) = args.next() else {
        return usage_error(None);
    };

    match mode.to_str() {
        Some(word @ "list") => only(args, word, || report(control::list(), false)),
        Some(word @ ("--version" | "-V")) => only(args, word, || {
            println!(
                "nomux {} (protocol {})",
                env!("CARGO_PKG_VERSION"),
                nomux::PROTOCOL_VERSION
            );
            ExitCode::SUCCESS
        }),
        Some(word @ ("--help" | "-h")) => only(args, word, || {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }),
        Some(word @ "daemon") => run_session_mode(Mode::Daemon, word, args),
        Some(word @ "spawn") => run_session_mode(Mode::Spawn, word, args),
        Some(word @ "attach") => run_session_mode(Mode::Attach, word, args),
        Some(word @ "kill") => run_session_mode(Mode::Kill, word, args),
        _ => usage_error(Some(&format!("unknown mode `{}`", mode.display()))),
    }
}

/// Refuses arguments to a mode that takes none.
fn only(mut args: impl Iterator<Item = OsString>, word: &str, run: fn() -> ExitCode) -> ExitCode {
    if let Some(extra) = args.next() {
        return usage_error(Some(&format!(
            "`{word}` takes no arguments, got `{}`",
            extra.display()
        )));
    }
    run()
}

/// Prints `message` where there is one, then the usage, and reports `EX_USAGE`.
///
/// Every way to misuse the command line ends here, so what a usage error consists of
/// is decided once.
fn usage_error(message: Option<&str>) -> ExitCode {
    if let Some(message) = message {
        // Escaped here rather than at each of the five places one is built: what all
        // of them quote is a word from `argv`, on its way to a terminal that would
        // act on an `ESC ]0;` in it. `escape_debug` leaves printable UTF-8 alone, so
        // an argument in any language still reads as what was typed.
        eprintln!("nomux: {}\n", message.escape_debug());
    }
    eprint!("{USAGE}");
    ExitCode::from(EXIT_USAGE)
}

/// The four modes that take a session id.
///
/// An enum rather than the `&str` `main` matched on, so that the dispatch below is
/// exhaustive and a fifth mode cannot silently fall into a catch-all arm.
#[derive(Clone, Copy)]
enum Mode {
    Daemon,
    Spawn,
    Attach,
    Kill,
}

/// Dispatches the modes that take a session id. `word` is the one `main` matched on.
fn run_session_mode(mode: Mode, word: &str, args: impl Iterator<Item = OsString>) -> ExitCode {
    let (session, label) = match parse_session_args(args) {
        Ok(parsed) => parsed,
        Err(message) => return usage_error(Some(&message)),
    };
    let Some(session) = session else {
        return usage_error(Some(&format!("`{word}` requires a session id")));
    };
    // Refused rather than dropped on the floor: a `--label` on `attach` is a caller
    // that still believes `attach` might create the session. `kill` parses and ignores
    // one, `IMPLEMENTATION.md` § 6.6 having frozen what it accepts.
    if matches!(mode, Mode::Attach) && label.is_some() {
        return usage_error(Some(
            "`attach` takes no `--label`: a label is recorded when the session is \
             created, which `spawn` does",
        ));
    }

    match mode {
        Mode::Daemon => report(daemon::run(&session, label.as_deref()), false),
        Mode::Spawn => report(
            attach::run(&session, attach::Intent::Create(label.as_deref())),
            true,
        ),
        Mode::Attach => report(attach::run(&session, attach::Intent::Resume), true),
        Mode::Kill => report(control::kill(&session), false),
    }
}

/// Splits a session-mode command line into its id and optional label.
///
/// Deliberately minimal — no argument parser, no abbreviations, no `--` handling.
/// The only caller is the client, which builds this command line itself.
fn parse_session_args(
    mut args: impl Iterator<Item = OsString>,
) -> Result<(Option<String>, Option<String>), String> {
    let mut session = None;
    let mut label = None;

    while let Some(arg) = args.next() {
        let text = arg
            .to_str()
            .ok_or_else(|| format!("argument `{}` must be valid UTF-8", arg.display()))?;
        let value = match text.split_once('=') {
            Some(("--label", value)) => value.to_owned(),
            _ if text == "--label" => args
                .next()
                .ok_or_else(|| "`--label` requires a value".to_owned())?
                .to_str()
                .ok_or_else(|| "label must be valid UTF-8".to_owned())?
                .to_owned(),
            _ if text.starts_with('-') => return Err(format!("unknown option `{text}`")),
            _ if session.is_none() => {
                session = Some(text.to_owned());
                continue;
            }
            _ => return Err(format!("unexpected argument `{text}`")),
        };
        if label.replace(value).is_some() {
            return Err("`--label` is given once: a second would replace the first".to_owned());
        }
    }
    Ok((session, label))
}

/// Maps a fallible operation onto an exit code, reporting failure on stderr.
///
/// Both of `IMPLEMENTATION.md` § 10's tables, which are one table. Every mode gives
/// `InvalidInput` `EX_USAGE`: [`rundir::SessionPaths::new`] is the only place the crate
/// *constructs* one, so it means an id that could never have named a session rather than
/// an operation that failed — a distinction the client acts on, caching "unattachable"
/// per host and otherwise caching its own typo. That makes this kind a reserved word
/// here: an `EINVAL` from anywhere would decode to it and be reported as the user's
/// spelling, which is why a run file that cannot be read is `InvalidData`
/// ([`rundir::read_prefix`]) and why `Hello.term` is refused for an interior NUL before
/// it can reach `Command::env`. `relay` selects § 10's other table, the one `spawn` and
/// `attach` are scored against.
fn report(result: std::io::Result<()>, relay: bool) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("nomux: {err}");
            let kind = err.kind();
            ExitCode::from(if kind == std::io::ErrorKind::InvalidInput {
                EXIT_USAGE
            } else if !relay {
                1
            } else if matches!(
                kind,
                // `NotFound` is the session `attach` refused to invent; `TimedOut` is a
                // daemon `spawn` started that never bound — the same "not found",
                // reached by waiting. The other wait that runs out is a `connect` to a
                // socket somebody bound and stopped accepting on, which is a session
                // and not a missing one; that this line cannot tell the two apart is
                // why both modes rename it first, through `attach::may_be_running` and
                // `attach::unattachable`, and never leave it as `TimedOut`.
                std::io::ErrorKind::NotFound | std::io::ErrorKind::TimedOut
            ) {
                EXIT_NO_SESSION
            } else {
                EXIT_UNATTACHABLE
            })
        }
    }
}
