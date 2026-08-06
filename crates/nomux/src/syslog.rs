//! Best-effort syslog, for the half of the daemon's life that has nowhere else to
//! write: `startup::silence_stdio` has pointed the daemon's three descriptors at
//! `/dev/null` (`IMPLEMENTATION.md` § 11, which also has what is never logged and why
//! an abort stays silent).
//!
//! One datagram to `/dev/log` is the whole implementation: journald, rsyslog and
//! busybox all offer that socket, at no new dependency.

use std::os::unix::net::UnixDatagram;

const SOCKET: &str = "/dev/log";

/// Sends one line, and never reports whether it arrived.
///
/// `priority` is RFC 5424 § 6.2.1's `facility * 8 + severity`: 11 is `user.err` and
/// 14 is `user.info`, the two § 11 names.
///
/// Every failure is swallowed on purpose. A host may have no syslog at all — a
/// minimal container being the ordinary case — and a daemon that declined to start
/// because it could not describe itself would be worse than one nobody can diagnose.
/// This is the same trade `silence_stdio` makes with its discarded `Result`.
///
/// No timestamp and no hostname, which is a choice rather than an omission: an
/// RFC 3164 timestamp means local time, local time means a timezone database, and
/// that is real weight against the § 8 budget to restate what the collector stamps
/// anyway — `journald`, `rsyslog` and `busybox syslogd` all fill both in.
fn send(priority: u8, session_id: &str, message: &str) {
    // Filtered by the function `list` filters a label with, over the whole assembled
    // line: the text beside a session id is usually an `io::Error` carrying a run
    // directory somebody else chose, and the id is not always validated either —
    // `daemon::run` reports a startup failure before anything has looked at its
    // argument. A newline in a datagram is how one log line becomes two.
    let line = crate::rundir::sanitize_text(&format!(
        "<{priority}>nomux[{pid}]: session {session_id}: {message}",
        pid = std::process::id(),
    ));
    if let Ok(socket) = UnixDatagram::unbound() {
        // A full collector must not park the daemon inside a `send`. Dropping the
        // line is the right answer to a log nobody is draining.
        let _ = socket.set_nonblocking(true);
        let _ = socket.send_to(line.as_bytes(), SOCKET);
    }
}

/// Reports a failure, identified by the session it belongs to.
pub(crate) fn error(session_id: &str, message: &str) {
    send(11, session_id, message);
}

/// Reports something ordinary in a session's life.
pub(crate) fn info(session_id: &str, message: &str) {
    send(14, session_id, message);
}

#[cfg(test)]
mod tests {
    use crate::rundir::{sanitize_label, sanitize_text};

    #[test]
    fn control_characters_cannot_forge_a_second_line() {
        assert_eq!(
            sanitize_text("one\nfeb 30 host sshd[1]: two\r\tthree"),
            "onefeb 30 host sshd[1]: twothree",
            "a newline in a message is how one datagram becomes two log entries"
        );
    }

    /// The listing and the journal are both read on a terminal, so a line bound for
    /// one has to be filtered exactly as a label bound for the other is.
    #[test]
    fn a_log_line_is_filtered_exactly_as_a_label_is() {
        for message in [
            "session bad\u{202e}dne: started",
            "session x: run directory /run/user/1000/\u{e0041}\u{e0042}: it is a symlink",
            "one\nfeb 30 host sshd[1]: two",
            "\u{1b}]0;pwned\u{7}",
        ] {
            assert_eq!(
                sanitize_text(message),
                sanitize_label(message),
                "one hazard, one filter: {message:?}"
            );
        }
    }
}
