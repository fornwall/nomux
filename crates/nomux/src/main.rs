//! `nomux` — persistent PTY sessions that survive SSH disconnects.
//!
//! One binary, several modes (see `DESIGN.md` § 4):
//!
//! - `daemon` owns the PTY master, the child process and the output ring buffer.
//! - `attach` is a dumb byte relay between stdio and the daemon's unix socket.
//! - `probe` reports the information the client needs to bootstrap this host.
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
mod startup;

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

/// `EX_USAGE`: malformed invocation.
const EXIT_USAGE: u8 = 64;
/// Session exists but is unattachable.
const EXIT_UNATTACHABLE: u8 = 126;
/// No such session, and it could not be started.
const EXIT_NO_SESSION: u8 = 127;

const USAGE: &str = "\
usage: nomux <mode> [session-id] [--label <text>]

modes:
  daemon <session-id>   Own a PTY session (normally spawned by `attach`)
  attach <session-id>   Relay stdio to a session, spawning it if absent
  probe                 Report OS, architecture and install path

control surface (frozen across versions, see IMPLEMENTATION.md 6.6):
  list                  List sessions in the run directory
  kill <session-id>     Terminate a session and unlink its run files

options:
  --label <text>        Display name for `list`, recorded when the session is
                        created. Advisory: ids are opaque, so this is what makes
                        an orphaned session recognisable to a human.
  --version, -V         Print version and protocol revision
  --help, -h            Print this usage
";

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let Some(mode) = args.next() else {
        eprint!("{USAGE}");
        return ExitCode::from(EXIT_USAGE);
    };

    match mode.to_str() {
        Some("probe") => {
            print_probe();
            ExitCode::SUCCESS
        }
        Some("list") => report(control::list()),
        Some("--version" | "-V") => {
            println!(
                "nomux {} (protocol {})",
                env!("CARGO_PKG_VERSION"),
                nomux_proto::PROTOCOL_VERSION
            );
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some("daemon") => run_session_mode(Mode::Daemon, args),
        Some("attach") => run_session_mode(Mode::Attach, args),
        Some("kill") => run_session_mode(Mode::Kill, args),
        _ => {
            eprint!("{USAGE}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

/// The three modes that take a session id.
///
/// An enum rather than the `&str` `main` matched on, so that the dispatch below is
/// exhaustive. Spelled as a string it needed a catch-all arm, which `kill` was
/// reached through — and a fourth mode added to `main` would then have become
/// `kill` silently, since the lint wall denies the `unreachable!` that would
/// otherwise have caught it.
#[derive(Clone, Copy)]
enum Mode {
    Daemon,
    Attach,
    Kill,
}

impl Mode {
    /// The word the user typed, for diagnostics.
    const fn name(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::Attach => "attach",
            Self::Kill => "kill",
        }
    }
}

/// Dispatches the modes that take a session id.
fn run_session_mode(mode: Mode, args: impl Iterator<Item = OsString>) -> ExitCode {
    let (session, label) = match parse_session_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("nomux: {message}\n");
            eprint!("{USAGE}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let Some(session) = session else {
        eprintln!("nomux: `{}` requires a session id\n", mode.name());
        eprint!("{USAGE}");
        return ExitCode::from(EXIT_USAGE);
    };

    match mode {
        Mode::Daemon => report(daemon::run(&session, label.as_deref())),
        Mode::Attach => match attach::run(&session, label.as_deref()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("nomux: {err}");
                ExitCode::from(match err.kind() {
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::NotFound => EXIT_NO_SESSION,
                    // A rejected session id is a malformed command line, not a
                    // session that resisted attaching: the id could never have named
                    // one. § 10 gives that `EX_USAGE`, and the distinction is the
                    // client's to act on — it caches "unattachable" per host and
                    // would otherwise cache it off its own typo.
                    std::io::ErrorKind::InvalidInput => EXIT_USAGE,
                    _ => EXIT_UNATTACHABLE,
                })
            }
        },
        Mode::Kill => report(control::kill(&session)),
    }
}

/// Splits a session-mode command line into its id and optional label.
///
/// Deliberately minimal — no argument parser, no abbreviations, no `--` handling.
/// The only caller is the client, which builds this command line itself.
fn parse_session_args(
    args: impl Iterator<Item = OsString>,
) -> Result<(Option<String>, Option<String>), String> {
    let mut session = None;
    let mut label = None;
    let mut args = args;

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
fn report(result: std::io::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("nomux: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Emits the bootstrap line the client parses in `IMPLEMENTATION.md` § 5.1.
///
/// The architecture reported is this binary's own compile-time target, which is
/// what the client actually needs to confirm: that the uploaded artifact runs here.
///
/// So the vocabulary is Rust's and *not* `uname`'s — lowercase `linux`, and `arm`
/// where `uname -m` says `armv7l`. The shell probe in § 5.1 runs before any binary
/// exists and necessarily uses `uname`; this one describes the artifact rather than
/// the host. Same prefix, two vocabularies, on purpose.
fn print_probe() {
    println!(
        "NOMUX-BOOTSTRAP {} {} {}",
        env::consts::OS,
        env::consts::ARCH,
        install_dir().display()
    );
}

/// Resolves the install directory, matching the shell precedence in
/// `IMPLEMENTATION.md` § 5.
fn install_dir() -> PathBuf {
    let base = env::var_os("XDG_DATA_HOME")
        .filter(|dir| !dir.is_empty())
        .map_or_else(
            || {
                let home = env::var_os("HOME").unwrap_or_else(|| OsString::from("."));
                let mut path = PathBuf::from(home);
                path.push(".local/share");
                path
            },
            PathBuf::from,
        );
    base.join("nomux")
}
