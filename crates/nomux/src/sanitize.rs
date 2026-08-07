//! One filter over text somebody else chose, for the two surfaces that draw it.
//!
//! Its own module because neither of those surfaces is the run directory: `list` prints
//! a `<id>.label` on the operator's terminal, and [`crate::syslog`] hands a datagram to
//! a journal read on one (§ 11). Both are terminals, so a hazard closed for either has
//! to be closed for both, which is what one function for both is here to make true.

/// Longest label written to `<id>.label`, in bytes, per the frozen layout (§ 6.6).
///
/// `pub(crate)` because [`crate::rundir::read_label`] sizes the buffer it reads one back
/// into against the same bound the write side truncates to.
pub(crate) const MAX_LABEL_LEN: usize = 256;

/// Drops every character that would let text say one thing and mean another once a terminal
/// draws it.
///
/// One function for both surfaces that print text somebody else chose, because both are
/// terminals: `list` writes a label to the operator's, and `crate::syslog` hands a line to a
/// journal read on one. Dropped rather than escaped, so nothing supplied here can occupy
/// width at all. Most of category `Cf` is kept on purpose — ZWJ and ZWNJ are how Indic
/// scripts and emoji sequences are spelled — and what goes is [`is_deceptive`]'s two
/// classes.
pub(crate) fn sanitize_text(text: &str) -> String {
    text.chars().filter(|ch| !is_deceptive(*ch)).collect()
}

/// Whether `ch` can make a run of text read as something other than its contents.
///
/// `char::is_control` is category `Cc` alone, and both additions here are `Cf`, so every one
/// of them passes it: the bidi overrides, one of which reverses the whole run after it (the
/// Trojan Source class), and the tag characters, a copy of printable ASCII that renders as
/// nothing.
const fn is_deceptive(ch: char) -> bool {
    ch.is_control()
        || matches!(ch,
            '\u{61c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
            | '\u{e0000}'..='\u{e007f}')
}

/// Trims a client-supplied label to what the frozen layout permits: one line of printable
/// UTF-8, at most [`MAX_LABEL_LEN`] bytes.
///
/// A tab title chosen by a human, so it arrives with whatever they typed — [`sanitize_text`]
/// takes back out the `ESC ]0;` that would retitle the window of whoever ran `list`.
/// Truncation is at a character boundary, so the result is always valid UTF-8.
pub(crate) fn sanitize_label(label: &str) -> String {
    let mut out = sanitize_text(label);
    out.truncate(out.floor_char_boundary(MAX_LABEL_LEN));
    out.trim().to_owned()
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
        // Either side of the three ranges, so the filter is not simply eating `Cf` —
        // the line [`sanitize_text`] draws, and why it is drawn there.
        assert_eq!(
            sanitize_label("\u{61b}a\u{2065}a\u{206a}"),
            "\u{61b}a\u{2065}a\u{206a}"
        );
        assert_eq!(sanitize_label("a\u{200d}b\u{200c}c"), "a\u{200d}b\u{200c}c");
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
}
