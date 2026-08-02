//! Wire protocol for nomux.
//!
//! Spoken end-to-end between the client and the session daemon; the `attach` relay
//! is transparent to it. See `IMPLEMENTATION.md` § 2 for the frame tables.
//!
//! Client and daemon ship as one unit and are versioned in lockstep, so this is a
//! private protocol with no stability guarantee. [`PROTOCOL_VERSION`] exists to
//! *fail fast* on the one mismatch that can genuinely occur — a live session held
//! by a daemon from an older client — not to negotiate.

#![forbid(unsafe_code)]

mod frame;

pub use frame::{ErrorCode, ExitKind, Frame, Hello, HelloOk, RESUME_FROM_START, WinSize};

/// Protocol revision. Bumped on any wire change, including compatible ones.
pub const PROTOCOL_VERSION: u16 = 1;

/// Fixed frame header size, so reads are a two-stage `read_exact`.
pub const HEADER_LEN: usize = 4;

/// Largest permitted payload. Bounds the peer's ability to force an allocation.
pub const MAX_PAYLOAD: u32 = 256 * 1024;

/// Frame discriminant.
///
/// Exhaustive on purpose: both endpoints are built from this repository, so an
/// unrecognised variant is a bug rather than a forward-compatibility case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    /// Client opens a session, carrying its resume offsets and window size.
    Hello = 0x01,
    /// Daemon accepts, reporting where output will resume from.
    HelloOk = 0x02,
    /// Client keystrokes, at an absolute offset in the input stream.
    Input = 0x03,
    /// Daemon confirms input durably written to the PTY master.
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

impl FrameType {
    /// Returns the wire discriminant.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Parses a wire discriminant, returning `None` if unrecognised.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Hello),
            0x02 => Some(Self::HelloOk),
            0x03 => Some(Self::Input),
            0x04 => Some(Self::InputAck),
            0x05 => Some(Self::Output),
            0x06 => Some(Self::OutputAck),
            0x07 => Some(Self::Resize),
            0x08 => Some(Self::Gap),
            0x09 => Some(Self::Exit),
            0x0a => Some(Self::Detach),
            0x0b => Some(Self::Ping),
            0x0c => Some(Self::Pong),
            0x0d => Some(Self::Error),
            0x0e => Some(Self::AgentOpen),
            0x0f => Some(Self::AgentData),
            0x10 => Some(Self::AgentClose),
            _ => None,
        }
    }
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
/// Ids are minted by the client and used directly as filename components in the run
/// directory, so the accepted set is deliberately narrow: 1..=64 bytes of
/// `[A-Za-z0-9_-]`. This rejects `.`, `..`, `/`, NUL, empty and all non-ASCII, which
/// makes path traversal impossible by construction rather than by escaping.
///
/// Both ends validate — the client before minting, the daemon before use. An invalid
/// id is always a hard error; sanitising one into a valid id would silently attach
/// the user to the wrong session.
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

    const ALL: [FrameType; 16] = [
        FrameType::Hello,
        FrameType::HelloOk,
        FrameType::Input,
        FrameType::InputAck,
        FrameType::Output,
        FrameType::OutputAck,
        FrameType::Resize,
        FrameType::Gap,
        FrameType::Exit,
        FrameType::Detach,
        FrameType::Ping,
        FrameType::Pong,
        FrameType::Error,
        FrameType::AgentOpen,
        FrameType::AgentData,
        FrameType::AgentClose,
    ];

    #[test]
    fn header_round_trips() {
        for ty in ALL {
            for len in [0, 1, 255, 256, 65_535, MAX_PAYLOAD] {
                let encoded = encode_header(ty, len).unwrap();
                assert_eq!(decode_header(&encoded).unwrap(), Header { ty, len });
            }
        }
    }

    #[test]
    fn discriminants_round_trip() {
        for ty in ALL {
            assert_eq!(FrameType::from_byte(ty.as_byte()), Some(ty));
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
