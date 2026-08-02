//! `nomux` — persistent PTY sessions that survive SSH disconnects.
//!
//! One binary, several modes (see `DESIGN.md` § 4):
//!
//! - `daemon` owns the PTY master, the child process and the output ring buffer.
//! - `attach` is a dumb byte relay between stdio and the daemon's unix socket.
//! - `probe` reports the information the client needs to bootstrap this host.
//! - `list` and `kill` are the frozen, version-independent control surface.

mod attach;
mod conn;
mod control;
mod daemon;
mod pty;
mod ring;
mod rundir;

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
usage: nomux <mode> [session-id]

modes:
  daemon <session-id>   Own a PTY session (normally spawned by `attach`)
  attach <session-id>   Relay stdio to a session, spawning it if absent
  probe                 Report OS, architecture and install path

control surface (frozen across versions, see IMPLEMENTATION.md 6.6):
  list                  List sessions in the run directory
  kill <session-id>     Terminate a session and unlink its run files

  --version             Print version and protocol revision
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
        Some(mode @ ("daemon" | "attach" | "kill")) => run_session_mode(mode, args.next()),
        _ => {
            eprint!("{USAGE}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

/// Dispatches the modes that take a session id.
fn run_session_mode(mode: &str, session: Option<OsString>) -> ExitCode {
    let Some(session) = session else {
        eprintln!("nomux: `{mode}` requires a session id\n");
        eprint!("{USAGE}");
        return ExitCode::from(EXIT_USAGE);
    };
    let Some(session) = session.to_str() else {
        eprintln!("nomux: session id must be valid UTF-8");
        return ExitCode::from(EXIT_USAGE);
    };

    match mode {
        "daemon" => report(daemon::run(session, daemon::ring_capacity())),
        "attach" => match attach::run(session) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("nomux: {err}");
                ExitCode::from(match err.kind() {
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::NotFound => EXIT_NO_SESSION,
                    _ => EXIT_UNATTACHABLE,
                })
            }
        },
        _ => report(control::kill(session)),
    }
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
