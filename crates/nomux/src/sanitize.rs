//! One filter over text somebody else chose, and the journal that is the daemon's only
//! voice once `startup::silence_standard_descriptors` has pointed its three descriptors at
//! `/dev/null`.
//!
//! The two live here together because the journal *is* one of the filter's two surfaces
//! — [`sanitize_text`] has that argument, and `IMPLEMENTATION.md` § 11 has what is never
//! logged and why an abort stays silent. One datagram to `/dev/log` is the whole of the
//! logging: journald, rsyslog and busybox all offer that socket, at no new dependency.

use std::os::unix::net::UnixDatagram;

/// Longest label written to `<id>.label`, in bytes, per the frozen layout (§ 6.6).
///
/// `pub(crate)` because [`crate::rundir::read_label`] sizes the buffer it reads one back
/// into against the same bound the write side truncates to.
pub(crate) const MAX_LABEL_LEN: usize = 256;

/// Where a syslog daemon listens, on every implementation this can expect to meet.
const SOCKET: &str = "/dev/log";

/// Longest datagram [`send`] hands to [`SOCKET`]: RFC 5424 § 6.1 obliges every receiver to
/// take 480 octets and asks for 2048, so past here a collector was free to cut anyway.
/// Bounded at all because the id in a line can still be argv's, and a datagram over
/// `SO_SNDBUF` is an `EMSGSIZE` swallowed with the rest — losing the one line that would
/// have explained the refusal.
const MAX_LINE_LEN: usize = 2048;

/// Drops every character that would let text say one thing and mean another once a terminal
/// draws it.
///
/// One function for both surfaces that print text somebody else chose, because both are
/// terminals (§ 11): `list` writes a label to the operator's, [`send`] a line to a journal.
/// Dropped rather than escaped, so nothing supplied here can occupy width at all.
pub(crate) fn sanitize_text(text: &str) -> String {
    text.chars().filter(|ch| !is_deceptive(*ch)).collect()
}

/// Whether `ch` can forge terminal layout or render invisibly. ZWJ and ZWNJ are retained
/// because they are part of ordinary emoji and Indic text. The Hangul fillers draw nothing
/// while occupying a cell, which `trim` does not take back and no tab title reaches by
/// accident.
const fn is_deceptive(ch: char) -> bool {
    ch.is_control()
        || matches!(ch,
            '\u{ad}' | '\u{61c}' | '\u{115f}'..='\u{1160}' | '\u{180e}' | '\u{200b}'
            | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}' | '\u{3164}' | '\u{ffa0}' | '\u{feff}'
            | '\u{e0000}'..='\u{e007f}')
}

/// Trims a client-supplied label to what the frozen layout permits: one line of printable
/// UTF-8, at most [`MAX_LABEL_LEN`] bytes.
///
/// A tab title chosen by a human, so it arrives with whatever they typed — [`sanitize_text`]
/// takes back out the `ESC ]0;` that would retitle the window of whoever ran `list`.
pub(crate) fn sanitize_label(label: &str) -> String {
    let mut out = sanitize_text(label);
    out.truncate(out.floor_char_boundary(MAX_LABEL_LEN));
    out.trim().to_owned()
}

/// Assembles the bounded line [`send`] writes, filtered over the whole of it rather than
/// over the message alone (§ 11): the text beside a session id is usually an `io::Error`
/// carrying a run directory somebody else chose, and the id is not always validated either
/// — `daemon::run` reports a startup failure before anything has looked at its argument.
fn format_line(priority: u8, session_id: &str, message: &str) -> String {
    let mut line = sanitize_text(&format!(
        "<{priority}>nomux[{pid}]: session {session_id}: {message}",
        pid = std::process::id(),
    ));
    line.truncate(line.floor_char_boundary(MAX_LINE_LEN));
    line
}

/// Sends one line to the journal, and never reports whether it arrived.
///
/// `priority` is RFC 5424 § 6.2.1's `facility * 8 + severity`: 11 is `user.err` and
/// 14 is `user.info`, the two § 11 names.
///
/// Every failure is swallowed on purpose. A host may have no syslog at all — a
/// minimal container being the ordinary case — and a daemon that declined to start
/// because it could not describe itself would be worse than one nobody can diagnose.
///
/// No timestamp and no hostname: an RFC 3164 timestamp is local time, so it would mean
/// carrying a timezone database to restate what every collector stamps anyway.
fn send(priority: u8, session_id: &str, message: &str) {
    let line = format_line(priority, session_id, message);
    if let Ok(socket) = UnixDatagram::unbound() {
        // A full collector must not park the daemon inside a `send`. Dropping the
        // line is the right answer to a log nobody is draining.
        if socket.set_nonblocking(true).is_ok() {
            let _ = socket.send_to(line.as_bytes(), SOCKET);
        }
    }
}

pub(crate) fn error(session_id: &str, message: &str) {
    send(11, session_id, message);
}

pub(crate) fn info(session_id: &str, message: &str) {
    send(14, session_id, message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_lose_control_characters_and_surrounding_space() {
        assert_eq!(sanitize_label("  build  "), "build");
        assert_eq!(sanitize_label("two\nlines"), "twolines");
        assert_eq!(sanitize_label("\u{1b}]0;pwned\u{7}"), "]0;pwned");
        assert_eq!(sanitize_label("\t\n"), "");
    }

    #[test]
    fn deceptive_non_controls_are_removed() {
        assert_eq!(sanitize_label("build\u{202e}gnp."), "buildgnp.");
        for sneaky in [
            '\u{61c}',
            '\u{200e}',
            '\u{200f}',
            '\u{202a}',
            '\u{202b}',
            '\u{202c}',
            '\u{202d}',
            '\u{202e}',
            '\u{2066}',
            '\u{2067}',
            '\u{2068}',
            '\u{2069}',
            '\u{ad}',
            '\u{180e}',
            '\u{200b}',
            '\u{2060}',
            '\u{2061}',
            '\u{2062}',
            '\u{2063}',
            '\u{2064}',
            '\u{115f}',
            '\u{1160}',
            '\u{3164}',
            '\u{ffa0}',
            '\u{feff}',
            '\u{e0000}',
            '\u{e0001}',
            '\u{e0020}',
            '\u{e007f}',
        ] {
            assert!(
                !sneaky.is_control(),
                "{sneaky:?} would already be dropped, so it says nothing about this"
            );
            assert_eq!(
                sanitize_label(&format!("a{sneaky}b")),
                "ab",
                "{sneaky:?} reached the terminal"
            );
        }
        assert_eq!(sanitize_label("bu\u{200b}ild"), sanitize_label("build"));

        let hidden: String = " rm -rf ~"
            .chars()
            .filter_map(|ch| char::from_u32(0xE_0000 + u32::from(ch)))
            .collect();
        assert_eq!(hidden.chars().count(), 9, "the fixture must encode as tags");
        assert_eq!(sanitize_label(&format!("build{hidden}")), "build");

        assert_eq!(
            sanitize_label("\u{61b}a\u{2065}a\u{2070}"),
            "\u{61b}a\u{2065}a\u{2070}"
        );
        assert_eq!(sanitize_label("a\u{200c}\u{200d}b"), "a\u{200c}\u{200d}b");
        assert_eq!(sanitize_label("a\u{205f}b\u{2065}c"), "a\u{205f}b\u{2065}c");
        assert_eq!(sanitize_label("\u{dffff}a\u{e0080}"), "\u{dffff}a\u{e0080}");
    }

    /// `trim` takes back whitespace, but a Hangul filler is not whitespace and draws
    /// nothing, so without the filter a label rendering as blank cells would reach `list`
    /// as a name — and one appended to a real label would pass for it.
    #[test]
    fn a_label_that_draws_nothing_is_no_label() {
        assert_eq!(sanitize_label("\u{3164}\u{115f} \u{ffa0}"), "");
        assert_eq!(sanitize_label("build\u{3164}"), sanitize_label("build"));
    }

    /// Truncation must not split a character, or `list` would print a replacement
    /// glyph for a label the user typed correctly.
    #[test]
    fn labels_are_truncated_on_a_character_boundary() {
        let long = "é".repeat(MAX_LABEL_LEN);
        let cut = sanitize_label(&long);
        assert_eq!(cut.len(), MAX_LABEL_LEN, "should fill the budget exactly");
        assert_eq!(cut.chars().count(), MAX_LABEL_LEN / 2);

        let odd = format!("{}€", "x".repeat(MAX_LABEL_LEN - 1));
        assert_eq!(sanitize_label(&odd).len(), MAX_LABEL_LEN - 1);
    }

    #[test]
    fn deceptive_characters_cannot_forge_layout() {
        assert_eq!(
            sanitize_text("one\nfeb 30 host sshd[1]: two\r\tthree\u{2028}four\u{2029}five"),
            "onefeb 30 host sshd[1]: twothreefourfive",
            "a newline in a message is how one datagram becomes two log entries"
        );
    }

    /// The journal's half of [`sanitize_text`]'s argument, asserted rather than argued:
    /// what a log line loses is exactly what a label loses.
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

    /// Everything a receiver has one of: no RFC 5424 header is emitted, so the priority and
    /// the `tag[pid]:` are the whole of the framing — and both sit ahead of anything a
    /// caller supplied, which is why a cut taken off the tail cannot damage them.
    fn framing() -> String {
        format!("<11>nomux[{}]: session ", std::process::id())
    }

    /// A line that fits comes through byte for byte, or the bound would be quietly eating
    /// the diagnostics it exists to deliver.
    #[test]
    fn an_ordinary_line_is_not_truncated() {
        assert_eq!(
            format_line(11, "build", "run directory /run/user/1000: it is a symlink"),
            format!(
                "{}build: run directory /run/user/1000: it is a symlink",
                framing()
            )
        );
        assert_eq!(
            format_line(14, "build", "started"),
            format!("<14>nomux[{}]: session build: started", std::process::id())
        );
    }

    /// The reachable oversize, and the whole reason for [`MAX_LINE_LEN`]: `daemon::run`
    /// reports a bad session id before anything has looked at its length, and the
    /// `io::Error` beside it quotes the id as well — so one argv element at Linux's
    /// `MAX_ARG_STRLEN` assembles twice its own size. Unbounded that is a datagram past
    /// `wmem_default`, refused with `EMSGSIZE` and swallowed like every other failure here,
    /// which loses the one line that would have said why the daemon declined to start.
    #[test]
    fn an_argv_sized_session_id_still_fits_one_datagram() {
        let huge = "x".repeat(128 * 1024);
        let line = format_line(11, &huge, &format!("invalid session id {huge:?}"));
        assert_eq!(line.len(), MAX_LINE_LEN, "the bound is over the whole line");
        assert!(
            line.starts_with(&framing()),
            "the framing must survive the cut"
        );
    }

    /// `String::truncate` panics on a split codepoint rather than yielding invalid UTF-8, so
    /// what can be shown is the cut walking back off one: with a three-byte character laid
    /// across the bound, the line lands short by exactly the bytes of it that were inside.
    #[test]
    fn the_bound_is_taken_on_a_character_boundary() {
        for (inside, len, last) in [
            (3, MAX_LINE_LEN, '€'),
            (2, MAX_LINE_LEN - 2, 'x'),
            (1, MAX_LINE_LEN - 1, 'x'),
        ] {
            let id = "x".repeat(MAX_LINE_LEN - framing().len() - inside) + &"€".repeat(4);
            let line = format_line(11, &id, "started");
            assert_eq!(line.len(), len, "{inside} of three bytes inside the bound");
            assert_eq!(
                line.chars().next_back(),
                Some(last),
                "cut inside a character"
            );
        }
    }

    /// Filtered first and cut second, which is the only order that leaves the bound
    /// measuring what a receiver will actually see: the other spends the budget on
    /// characters that are about to be dropped anyway, and drops the tail that says what
    /// went wrong to pay for them.
    #[test]
    fn the_line_is_filtered_before_it_is_cut() {
        let id = format!("{}build", "\u{7}".repeat(MAX_LINE_LEN));
        assert_eq!(
            format_line(11, &id, "started"),
            format!("{}build: started", framing())
        );
    }
}
