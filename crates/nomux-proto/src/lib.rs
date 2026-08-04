//! Wire protocol for nomux.
//!
//! Spoken end-to-end between the client and the session daemon; the `attach` relay
//! is transparent to it. See `IMPLEMENTATION.md` § 2 for the frame tables.
//!
//! A private protocol with no stability guarantee: [`PROTOCOL_VERSION`] exists to
//! fail fast on a mismatched peer rather than to negotiate (`IMPLEMENTATION.md` § 2).

#![forbid(unsafe_code)]

mod frame;

pub use frame::{
    ErrorCode, ExitKind, Frame, HELLO_AGENT_FORWARD, HELLO_REPAINT_CTRL_L, Hello, HelloOk, Linger,
    RESUME_FROM_START, WinSize,
};

/// Protocol revision. Bumped on any wire change, including compatible ones.
///
/// Revision 2 gave both flag fields meaning: agent forwarding and repaint policy
/// in `Hello`, linger state and agent status in `HelloOk`. Revision 3 took
/// `Hello.in_offset` back out, the daemon never having read it — `DESIGN.md` § 10
/// owns why it was there and is where it comes back.
///
/// The number itself is pinned against `IMPLEMENTATION.md` § 2.2 by
/// `the_frozen_numbers_are_the_ones_the_document_gives`. The handshake vectors spell
/// it out as a literal rather than symbolically, and
/// `the_handshake_vectors_are_written_at_the_revision_this_build_speaks` is what
/// holds those two together — so a bump has to move the constant, the vectors and the
/// document, in that order of complaint.
pub const PROTOCOL_VERSION: u16 = 3;

/// Fixed frame header size, so reads are a two-stage `read_exact`.
pub const HEADER_LEN: usize = 4;

/// Largest permitted payload. Bounds the peer's ability to force an allocation.
pub const MAX_PAYLOAD: u32 = 256 * 1024;

// A discriminant list is written down once, and everything mechanically derived
// from it — the enum, both directions of the conversion, and the `ALL` the suites
// sweep — is generated from it, so the four cannot drift apart. `Frame::decode`
// matches on `FrameType` exhaustively, so a variant added to the list stops the
// build until the payload side has learnt to read one; a hand-written `from_byte`
// ending in a catch-all `_ => None` stops nothing, and leaves an end that can
// *send* the new frame but never *receives* one.
//
// `IMPLEMENTATION.md` § 2.3 applies the same closed-set rule to `Error.code`,
// `Exit.kind` and the linger field, so those go through this macro too rather than
// through three more hand-written matches — see `frame.rs`. Hence the parameters:
// the sets differ in their repr and in what the two accessors are called. The
// encode direction is a cast, which is why each list's numbers are declared as real
// discriminants under `#[repr($repr)]` rather than as the arms of a second match
// that could disagree with the first.
macro_rules! wire_enum {
    (
        $(#[$enum_meta:meta])*
        $name:ident: $repr:ident, $as_fn:ident / $from_fn:ident,
        $($(#[$variant_meta:meta])* $variant:ident = $value:literal,)+
    ) => {
        $(#[$enum_meta])*
        #[repr($repr)]
        pub enum $name {
            $($(#[$variant_meta])* $variant = $value,)+
        }

        impl $name {
            /// Every variant, in wire order.
            ///
            /// Public because the crate's integration tests sweep it, and a test that
            /// has to be told about a new variant is a test that will eventually not
            /// be told about one.
            pub const ALL: [Self; [$(Self::$variant),+].len()] = [$(Self::$variant),+];

            /// Returns the wire discriminant.
            #[must_use]
            pub const fn $as_fn(self) -> $repr {
                self as $repr
            }

            /// Parses a wire discriminant, returning `None` if unrecognised.
            #[must_use]
            pub const fn $from_fn(value: $repr) -> Option<Self> {
                match value {
                    $($value => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
}
pub(crate) use wire_enum;

wire_enum! {
    /// Frame discriminant.
    ///
    /// Exhaustive on purpose: both endpoints are built from this repository, so an
    /// unrecognised variant is a bug rather than a forward-compatibility case.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    FrameType: u8, as_byte / from_byte,
    /// Client opens a session, carrying its resume offsets and window size.
    Hello = 0x01,
    /// Daemon accepts, reporting where output will resume from.
    HelloOk = 0x02,
    /// Client keystrokes, at an absolute offset in the input stream.
    Input = 0x03,
    /// Daemon confirms input it has taken ownership of, and will never re-apply.
    InputAck = 0x04,
    /// PTY output, at an absolute offset in the output stream.
    Output = 0x05,
    /// Client confirms output consumed. Advisory; never trims the ring.
    OutputAck = 0x06,
    /// Window size change, applied via `TIOCSWINSZ`.
    Resize = 0x07,
    /// Output was discarded by ring overflow; the stream is discontinuous.
    Gap = 0x08,
    /// The child process terminated.
    Exit = 0x09,
    /// Client leaves without terminating the session.
    Detach = 0x0a,
    /// Liveness probe.
    Ping = 0x0b,
    /// Liveness response, echoing the nonce.
    Pong = 0x0c,
    /// Daemon-side failure; the connection closes after this.
    Error = 0x0d,
    /// A process connected to the session's agent socket; open a peer channel.
    AgentOpen = 0x0e,
    /// Opaque `ssh-agent` protocol bytes for one agent channel.
    AgentData = 0x0f,
    /// One agent channel is finished, in either direction.
    AgentClose = 0x10,
}

/// Maximum session id length, in bytes.
pub const MAX_SESSION_ID_LEN: usize = 64;

/// Maximum concurrent agent channels per session.
///
/// `ssh-agent` exchanges are short and serial in practice; the cap bounds what a
/// runaway child can force the daemon and client to track.
pub const MAX_AGENT_CHANNELS: u32 = 8;

/// Returns whether `id` is usable as a session id.
///
/// Ids are minted by the client and used directly as filename components, so the
/// accepted set is deliberately narrow — 1..=64 bytes of `[A-Za-z0-9_-]`
/// (`IMPLEMENTATION.md` § 6.3) — which makes path traversal impossible by
/// construction rather than by escaping. An invalid id is a hard error at both ends
/// and is never sanitised: rewriting one into a valid id would silently attach the
/// user to the wrong session.
///
/// # Examples
///
/// ```
/// use nomux_proto::is_valid_session_id;
///
/// assert!(is_valid_session_id("6f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8"));
/// assert!(!is_valid_session_id("../etc/passwd"));
/// assert!(!is_valid_session_id(""));
/// ```
#[must_use]
pub fn is_valid_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_SESSION_ID_LEN
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// A decoded frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Frame discriminant.
    pub ty: FrameType,
    /// Payload length in bytes, guaranteed `<= MAX_PAYLOAD`.
    pub len: u32,
}

/// A malformed frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoError {
    /// Discriminant is not a known [`FrameType`].
    UnknownFrameType(u8),
    /// Declared length exceeds [`MAX_PAYLOAD`].
    PayloadTooLarge(u32),
    /// Payload ended before the frame's fixed fields were complete.
    Truncated,
    /// Payload continued past the end of a fixed-size frame.
    TrailingBytes,
    /// Structurally intact but semantically invalid.
    Malformed(&'static str),
}

impl core::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::UnknownFrameType(byte) => write!(f, "unknown frame type {byte:#04x}"),
            Self::PayloadTooLarge(len) => {
                write!(f, "payload of {len} bytes exceeds maximum of {MAX_PAYLOAD}")
            }
            Self::Truncated => f.write_str("frame payload is truncated"),
            Self::TrailingBytes => f.write_str("frame payload has trailing bytes"),
            Self::Malformed(what) => write!(f, "malformed frame: {what}"),
        }
    }
}

impl core::error::Error for ProtoError {}

/// Encodes a frame header.
///
/// # Errors
///
/// [`ProtoError::PayloadTooLarge`] if `len` exceeds [`MAX_PAYLOAD`].
pub const fn encode_header(ty: FrameType, len: u32) -> Result<[u8; HEADER_LEN], ProtoError> {
    if len > MAX_PAYLOAD {
        return Err(ProtoError::PayloadTooLarge(len));
    }
    // `len <= MAX_PAYLOAD` fits in 24 bits, so the high byte is always zero.
    let [_, a, b, c] = len.to_be_bytes();
    Ok([ty.as_byte(), a, b, c])
}

/// Decodes a frame header.
///
/// # Errors
///
/// [`ProtoError::UnknownFrameType`] for an unrecognised discriminant, or
/// [`ProtoError::PayloadTooLarge`] if the declared length exceeds [`MAX_PAYLOAD`].
///
/// # Examples
///
/// ```
/// use nomux_proto::{FrameType, Header, decode_header, encode_header};
///
/// let bytes = encode_header(FrameType::Output, 4096)?;
/// assert_eq!(bytes, [0x05, 0x00, 0x10, 0x00]);
/// assert_eq!(
///     decode_header(&bytes)?,
///     Header { ty: FrameType::Output, len: 4096 }
/// );
/// # Ok::<(), nomux_proto::ProtoError>(())
/// ```
pub fn decode_header(bytes: &[u8; HEADER_LEN]) -> Result<Header, ProtoError> {
    let [ty, a, b, c] = *bytes;
    let ty = FrameType::from_byte(ty).ok_or(ProtoError::UnknownFrameType(ty))?;
    let len = u32::from_be_bytes([0, a, b, c]);
    if len > MAX_PAYLOAD {
        return Err(ProtoError::PayloadTooLarge(len));
    }
    Ok(Header { ty, len })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips() {
        for ty in FrameType::ALL {
            for len in [0, 1, 255, 256, 65_535, MAX_PAYLOAD] {
                let encoded = encode_header(ty, len).unwrap();
                assert_eq!(decode_header(&encoded).unwrap(), Header { ty, len });
            }
        }
    }

    #[test]
    fn oversized_payload_is_rejected() {
        assert_eq!(
            encode_header(FrameType::Output, MAX_PAYLOAD + 1),
            Err(ProtoError::PayloadTooLarge(MAX_PAYLOAD + 1))
        );
        // 0x00_04_00_01 == MAX_PAYLOAD + 1, encoded by hand since the encoder refuses.
        assert_eq!(
            decode_header(&[FrameType::Output.as_byte(), 0x04, 0x00, 0x01]),
            Err(ProtoError::PayloadTooLarge(MAX_PAYLOAD + 1))
        );
    }

    #[test]
    fn session_ids_accept_minted_forms() {
        assert!(is_valid_session_id("a"));
        assert!(is_valid_session_id("6f1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8"));
        assert!(is_valid_session_id("tab_7"));
        assert!(is_valid_session_id(&"x".repeat(MAX_SESSION_ID_LEN)));
    }

    #[test]
    fn session_ids_reject_path_traversal() {
        for id in [
            "",
            ".",
            "..",
            "/",
            "a/b",
            "../etc/passwd",
            "a.b",
            "a b",
            "a\0b",
        ] {
            assert!(!is_valid_session_id(id), "should reject {id:?}");
        }
    }

    #[test]
    fn session_ids_reject_oversized_and_non_ascii() {
        assert!(!is_valid_session_id(&"x".repeat(MAX_SESSION_ID_LEN + 1)));
        assert!(!is_valid_session_id("café"));
        assert!(!is_valid_session_id("🦀"));
    }

    #[test]
    fn unknown_frame_type_is_rejected() {
        assert_eq!(
            decode_header(&[0x00, 0, 0, 0]),
            Err(ProtoError::UnknownFrameType(0x00))
        );
        assert_eq!(
            decode_header(&[0xff, 0, 0, 0]),
            Err(ProtoError::UnknownFrameType(0xff))
        );
    }
}
