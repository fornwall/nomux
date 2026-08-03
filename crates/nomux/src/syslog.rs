//! Best-effort syslog, for the half of the daemon's life that has nowhere else to
//! write.
//!
//! `startup::silence_stdio` points the daemon's three descriptors at `/dev/null`,
//! correctly: under `attach` they are the SSH channel carrying the client's frame
//! stream, and a diagnostic written there would land in the middle of it. From that
//! moment the daemon has no terminal, and a process with no terminal is what syslog
//! is for.
//!
//! A datagram to `/dev/log`, which is the whole implementation. That path is the
//! traditional socket and also what `systemd-journald` provides for compatibility,
//! so one code path reaches journald, rsyslog and busybox alike — and reaching it
//! costs no new dependency, no new port and no privilege the daemon does not
//! already have.
//!
//! What is *not* here is as deliberate as what is. Nothing this module sends carries
//! PTY bytes or a session's `--label`: the label is free-form text from a tab title,
//! and syslog is a host-wide sink that root and often an `adm` group can read, so a
//! session whose entire footprint is otherwise `0600` inside a `0700` directory would
//! be announcing itself by name. Session ids are opaque and go out; labels stay in
//! the run directory.
//!
//! It does not cover an abort. The shipping build is `-Cpanic=immediate-abort` and
//! `strip = "symbols"` (`IMPLEMENTATION.md` § 8), so an allocation failure produces
//! no message for anything to forward. That case still belongs to the `SIGQUIT` core
//! § 6.5 preserves.

use std::os::unix::net::UnixDatagram;

/// The socket every syslog implementation on Linux offers, and the one
/// `systemd-journald` keeps for compatibility.
const SOCKET: &str = "/dev/log";

/// `LOG_USER`, the facility for a message from an ordinary program.
const FACILITY_USER: u8 = 1;

/// Severities, from RFC 5424 § 6.2.1. Only the two the daemon has a use for.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Severity {
    /// Something failed. The session may not exist, or may not have survived.
    Error = 3,
    /// A session began or ended in the ordinary way.
    Info = 6,
}

/// Sends one line, and never reports whether it arrived.
///
/// Every failure is swallowed on purpose. A host may have no syslog at all — a
/// minimal container being the ordinary case — and a daemon that declined to start
/// because it could not describe itself would be worse than one nobody can diagnose.
/// This is the same trade `silence_stdio` makes with its discarded `Result`.
///
/// No timestamp and no hostname, which is a choice rather than an omission: rendering
/// an RFC 3164 timestamp means local time, local time means a timezone database, and
/// that is real weight against the § 8 budget to restate something the collector
/// stamps anyway from the moment it receives the datagram. `journald`, `rsyslog` and
/// `busybox syslogd` all fill both in for a message that carries neither.
pub(crate) fn send(severity: Severity, message: &str) {
    let priority = FACILITY_USER * 8 + severity as u8;
    let line = format!(
        "<{priority}>nomux[{pid}]: {message}",
        pid = std::process::id(),
        message = sanitize(message),
    );
    if let Ok(socket) = UnixDatagram::unbound() {
        // A full collector must not park the daemon inside a `send`. Dropping the
        // line is the right answer to a log nobody is draining.
        let _ = socket.set_nonblocking(true);
        let _ = socket.send_to(line.as_bytes(), SOCKET);
    }
}

/// Reports a failure, identified by the session it belongs to.
pub(crate) fn error(session_id: &str, message: &str) {
    send(Severity::Error, &format!("session {session_id}: {message}"));
}

/// Reports something ordinary in a session's life.
pub(crate) fn info(session_id: &str, message: &str) {
    send(Severity::Info, &format!("session {session_id}: {message}"));
}

/// Flattens anything that would let a message forge a second one.
///
/// Applied to the whole assembled line, which is what makes it enough: the text
/// beside a session id is usually an `io::Error` carrying a path somebody else
/// chose, and the id itself is not always validated either — `daemon::run` reports
/// a startup failure before anything has looked at its argument, so a malformed id
/// reaches here verbatim. A newline in a datagram is how one log line becomes two,
/// the second one saying whatever its author wanted it to.
fn sanitize(message: &str) -> String {
    message
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{FACILITY_USER, Severity, sanitize};

    #[test]
    fn control_characters_cannot_forge_a_second_line() {
        assert_eq!(
            sanitize("one\nfeb 30 host sshd[1]: two\r\tthree"),
            "one feb 30 host sshd[1]: two  three",
            "a newline in a message is how one datagram becomes two log entries"
        );
    }

    #[test]
    fn priorities_are_the_rfc_5424_numbers() {
        assert_eq!(
            FACILITY_USER * 8 + Severity::Error as u8,
            11,
            "user.err is the priority every collector files as a failure"
        );
        assert_eq!(
            FACILITY_USER * 8 + Severity::Info as u8,
            14,
            "user.info is the priority for the ordinary lifecycle events"
        );
    }
}
