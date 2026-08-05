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
/// The session is there but this mode cannot have it. The shell's "found but not
/// executable", applied to a session, since these are what a client runs over an
/// exec channel: `spawn` found the id already taken, or `attach` found a session it
/// could not join.
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
  --label <text>        Display name for `list`, recorded when the session is
                        created, so `daemon` and `spawn` take it and `attach` does
                        not. Advisory: ids are opaque, so this is what makes an
                        orphaned session recognisable to a human.
  --version, -V         Print version and protocol revision
  --help, -h            Print this usage
";

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let Some(mode) = args.next() else {
        return usage_error(None);
    };

    match mode.to_str() {
        Some(word @ "list") => only(args, word, || report(control::list())),
        Some(word @ ("--version" | "-V")) => only(args, word, || {
            println!(
                "nomux {} (protocol {})",
                env!("CARGO_PKG_VERSION"),
                nomux_proto::PROTOCOL_VERSION
            );
            ExitCode::SUCCESS
        }),
        Some(word @ ("--help" | "-h")) => only(args, word, || {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }),
        Some("daemon") => run_session_mode(Mode::Daemon, args),
        Some("spawn") => run_session_mode(Mode::Spawn, args),
        Some("attach") => run_session_mode(Mode::Attach, args),
        Some("kill") => run_session_mode(Mode::Kill, args),
        _ => usage_error(Some(&format!("unknown mode `{}`", mode.display()))),
    }
}

/// Runs a mode that takes no arguments, refusing any that were passed.
///
/// The caller is the client, which builds these command lines itself, so an
/// argument dropped on the floor is a bug it has no way to be told about — and the
/// session modes already reject one they do not understand.
///
/// `run` is a plain `fn` pointer rather than a generic so that the four modes share
/// a single instantiation, which the § 8 size budget cares about and this does not.
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
/// Every way to misuse the command line ends here, so what a usage error consists
/// of — the message, the usage, and 64 — is decided once.
fn usage_error(message: Option<&str>) -> ExitCode {
    if let Some(message) = message {
        // Escaped here rather than at each of the five places one is built, because
        // what every one of them quotes is a word from `argv` — text nothing validated,
        // on its way to a terminal that would act on an `ESC ]0;` in it. `escape_debug`
        // leaves printable UTF-8 alone, so an argument in any language still reads as
        // what was typed.
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

impl Mode {
    /// The word the user typed, for diagnostics.
    const fn name(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::Spawn => "spawn",
            Self::Attach => "attach",
            Self::Kill => "kill",
        }
    }
}

/// Dispatches the modes that take a session id.
fn run_session_mode(mode: Mode, args: impl Iterator<Item = OsString>) -> ExitCode {
    let (session, label) = match parse_session_args(args) {
        Ok(parsed) => parsed,
        Err(message) => return usage_error(Some(&message)),
    };
    let Some(session) = session else {
        return usage_error(Some(&format!("`{}` requires a session id", mode.name())));
    };
    // The label is recorded when the session is created (`IMPLEMENTATION.md` § 6.6),
    // so it belongs to the two modes that create one. Refused rather than dropped on
    // the floor: a `--label` on `attach` is a caller that still believes `attach`
    // might create the session, which is the confusion this split exists to end, and
    // silence would leave it believing it. `kill` goes on parsing and ignoring one,
    // because what the frozen escape hatch accepts is not this change's to narrow.
    if matches!(mode, Mode::Attach) && label.is_some() {
        return usage_error(Some(
            "`attach` takes no `--label`: a label is recorded when the session is \
             created, which `spawn` does",
        ));
    }

    match mode {
        Mode::Daemon => report(daemon::run(&session, label.as_deref())),
        Mode::Spawn => relayed(attach::run(
            &session,
            attach::Intent::Create,
            label.as_deref(),
        )),
        Mode::Attach => relayed(attach::run(&session, attach::Intent::Resume, None)),
        Mode::Kill => report(control::kill(&session)),
    }
}

/// Maps the relay's fate onto an exit code, per `IMPLEMENTATION.md` § 10.
///
/// Shared by `spawn` and `attach` because the table is one table: the two differ in
/// which errors they can produce, never in what a given one means. `NotFound` is the
/// session `attach` refused to invent and `TimedOut` is the daemon `spawn` could not
/// start — the same "not found", one about a session and one about bringing it into
/// being — while `AlreadyExists` is the id `spawn` found taken, which falls to the
/// catch-all beside the permission and protocol refusals that were always there.
fn relayed(result: std::io::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("nomux: {err}");
            ExitCode::from(match err.kind() {
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::NotFound => EXIT_NO_SESSION,
                // A rejected session id is a malformed command line, not a session
                // that resisted attaching: the id could never have named one. § 10
                // gives that `EX_USAGE`, and the distinction is the client's to act
                // on — it caches "unattachable" per host and would otherwise cache it
                // off its own typo.
                std::io::ErrorKind::InvalidInput => EXIT_USAGE,
                _ => EXIT_UNATTACHABLE,
            })
        }
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
        match text.split_once('=') {
            Some(("--label", value)) => label = Some(value.to_owned()),
            _ if text == "--label" => {
                label = Some(
                    args.next()
                        .ok_or_else(|| "`--label` requires a value".to_owned())?
                        .to_str()
                        .ok_or_else(|| "label must be valid UTF-8".to_owned())?
                        .to_owned(),
                );
            }
            _ if text.starts_with('-') => return Err(format!("unknown option `{text}`")),
            _ if session.is_none() => session = Some(text.to_owned()),
            _ => return Err(format!("unexpected argument `{text}`")),
        }
    }
    Ok((session, label))
}

/// Maps a fallible operation onto an exit code, reporting failure on stderr.
///
/// The whole of the `daemon`, `list` and `kill` table in `IMPLEMENTATION.md` § 10,
/// including why the last row is deliberately coarse.
///
/// `InvalidInput` is `EX_USAGE` here for the reason the `attach` arm above gives:
/// [`rundir::SessionPaths::new`] is the crate's only source of it, so it always means
/// a session id that could never have named a session, rather than an operation that
/// failed.
fn report(result: std::io::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("nomux: {err}");
            ExitCode::from(if err.kind() == std::io::ErrorKind::InvalidInput {
                EXIT_USAGE
            } else {
                1
            })
        }
    }
}
