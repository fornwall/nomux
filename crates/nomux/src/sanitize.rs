//! One filter over text somebody else chose, and the journal that is the daemon's only
//! voice once `startup::release_startup_state` has pointed its three descriptors at
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

/// Whether `ch` can make a run of text read as something other than its contents.
///
/// `char::is_control` is category `Cc` alone, and every addition here is `Cf`, so all of
/// them pass it: the bidi overrides, one of which reverses the whole run after it (the
/// Trojan Source class); the tag characters, a copy of printable ASCII that renders as
/// nothing; and the zero-width spellings — a byte-order mark, a zero-width space, the
/// invisible operators, a Mongolian vowel separator, the deprecated shaping selectors —
/// which occupy no width at all, so two labels carrying different ones draw identically
/// in the column a human reads to decide what to kill.
///
/// The intent is narrow: invisible `Cf` goes, *except* § 6.6's ZWJ and ZWNJ (U+200C and
/// U+200D), with U+200B sitting directly beside them while being none of that. Spelled as a
/// named set rather than as that sentence because std has no general-category test to write
/// it with, so a codepoint missing from the set is a gap rather than a decision.
const fn is_deceptive(ch: char) -> bool {
    ch.is_control()
        || matches!(ch,
            '\u{61c}' | '\u{180e}' | '\u{200b}' | '\u{200e}' | '\u{200f}'
            | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{206a}'..='\u{206f}'
            | '\u{2066}'..='\u{2069}' | '\u{feff}' | '\u{e0000}'..='\u{e007f}')
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
    // Filtered over the whole assembled line rather than over the message alone (§ 11): the
    // text beside a session id is usually an `io::Error` carrying a run directory somebody
    // else chose, and the id is not always validated either — `daemon::run` reports a
    // startup failure before anything has looked at its argument.
    let mut line = sanitize_text(&format!(
        "<{priority}>nomux[{pid}]: session {session_id}: {message}",
        pid = std::process::id(),
    ));
    line.truncate(line.floor_char_boundary(MAX_LINE_LEN));
    if let Ok(socket) = UnixDatagram::unbound() {
        // A full collector must not park the daemon inside a `send`. Dropping the
        // line is the right answer to a log nobody is draining.
        let _ = socket.set_nonblocking(true);
        let _ = socket.send_to(line.as_bytes(), SOCKET);
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

    /// The bidi overrides are `Cf` rather than `Cc`, so they went straight through the
    /// filter above and out to the terminal `list` prints on — in a column the user
    /// reads to decide which session to kill.
    #[test]
    fn labels_lose_the_bidi_controls_that_are_not_control_characters() {
        assert_eq!(sanitize_label("build\u{202e}gnp."), "buildgnp.");
        for sneaky in [
            '\u{61c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}',
            '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
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
        // Either side of the ranges, so the filter is not simply eating `Cf` — the line
        // [`is_deceptive`] draws, and why it is drawn there.
        assert_eq!(
            sanitize_label("\u{61b}a\u{2065}a\u{2070}"),
            "\u{61b}a\u{2065}a\u{2070}"
        );
        assert_eq!(sanitize_label("a\u{200d}b\u{200c}c"), "a\u{200d}b\u{200c}c");
    }

    /// The invisible `Cf` codepoints that are neither bidi nor tags, and the reason
    /// `is_control` cannot be the whole filter: they occupy no width, so two sessions
    /// whose labels differ by one of them are two rows a human cannot tell apart in the
    /// listing they choose from.
    #[test]
    fn labels_lose_the_zero_width_characters_that_occupy_no_column() {
        for sneaky in [
            '\u{180e}', '\u{200b}', '\u{2060}', '\u{2061}', '\u{2062}', '\u{2063}', '\u{2064}',
            '\u{feff}',
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
        // The whole of what that buys, stated as the collision it closes.
        assert_eq!(sanitize_label("bu\u{200b}ild"), sanitize_label("build"));

        // And the deliberate exception, one codepoint away from U+200B: ZWJ and ZWNJ
        // spell Indic scripts and emoji sequences, and a label is a human's own text.
        assert_eq!(sanitize_label("a\u{200c}\u{200d}b"), "a\u{200c}\u{200d}b");
        // Either side of the invisible operators, for the reason above: U+205F is a
        // space that occupies one and U+2065 is unassigned.
        assert_eq!(sanitize_label("a\u{205f}b\u{2065}c"), "a\u{205f}b\u{2065}c");
    }

    /// U+E0020..=U+E007F encode printable ASCII in codepoints that render as nothing,
    /// so a label that `list` prints as `build` can carry an entire second string
    /// behind it — invisible in the listing and plainly there in whatever pastes it.
    #[test]
    fn labels_lose_the_tag_characters_that_render_as_nothing() {
        let hidden: String = " rm -rf ~"
            .chars()
            .filter_map(|ch| char::from_u32(0xE_0000 + u32::from(ch)))
            .collect();
        assert_eq!(hidden.chars().count(), 9, "the fixture must encode as tags");
        assert_eq!(sanitize_label(&format!("build{hidden}")), "build");

        for sneaky in ['\u{e0000}', '\u{e0001}', '\u{e0020}', '\u{e007f}'] {
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
        // Either side of the block, for the same reason as above.
        assert_eq!(sanitize_label("\u{dffff}a\u{e0080}"), "\u{dffff}a\u{e0080}");
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
    fn control_characters_cannot_forge_a_second_line() {
        assert_eq!(
            sanitize_text("one\nfeb 30 host sshd[1]: two\r\tthree"),
            "onefeb 30 host sshd[1]: twothree",
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
}
