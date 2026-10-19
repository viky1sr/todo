//! Pure-Rust Zstandard codec following RFC 8878 (`0xFD2FB528` frames).
//!
//! Ported from the format description and the reference C implementation vendored in
//! `vendor/zstd` (which remains available as a differential-test oracle via the `zstd`
//! crate). No C code is executed by this module.
//!
//! Scope:
//! - Decoder: full frame format (raw/RLE/compressed blocks, Huffman and treeless literals,
//!   predefined/RLE/FSE/repeat sequence tables, repeat offsets, content checksum,
//!   skippable frames, concatenated frames). Dictionaries are rejected.
//! - Encoder: hash-chain LZ77 + Huffman literals + FSE sequences in one standard frame
//!   with content size and XXH64 checksum. Output is deterministic for a given
//!   `(data, level)` but is **not** byte-identical to libzstd.

pub mod bitstream;
pub mod block;
pub mod frame;
pub mod fse;
pub mod huffman;
pub mod lz77;
pub mod xxhash;

use std::fmt;

/// Zstandard frame magic number (little-endian on the wire: `28 B5 2F FD`).
pub const ZSTD_MAGIC: u32 = 0xFD2F_B528;
/// Maximum decompressed size of a single block (RFC 8878 §3.1.1.2.4).
pub const BLOCK_SIZE_MAX: usize = 128 * 1024;
/// Minimum compression level accepted by [`compress`].
pub const MIN_LEVEL: i32 = 1;
/// Maximum compression level accepted by [`compress`].
pub const MAX_LEVEL: i32 = 22;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// Input ended before a structure was complete.
    Truncated(&'static str),
    /// Magic number is neither a Zstandard nor a skippable frame.
    BadMagic(u32),
    /// Reserved bit set or unsupported header field.
    BadFrameHeader(&'static str),
    /// Frame needs a dictionary, which this implementation does not support.
    DictionaryUnsupported(u32),
    /// Malformed block, literals, sequences or entropy table.
    Corrupted(&'static str),
    /// XXH64 content checksum does not match.
    ChecksumMismatch { expected: u32, actual: u32 },
    /// Declared frame content size does not match decoded output.
    ContentSizeMismatch { declared: u64, actual: u64 },
    /// Output would exceed the caller-provided limit.
    OutputLimitExceeded(usize),
    /// Input larger than the encoder supports.
    InputTooLarge(usize),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated(what) => write!(f, "truncated input: {what}"),
            Self::BadMagic(m) => write!(f, "unknown frame magic 0x{m:08X}"),
            Self::BadFrameHeader(what) => write!(f, "invalid frame header: {what}"),
            Self::DictionaryUnsupported(id) => {
                write!(f, "dictionary {id} required but unsupported")
            }
            Self::Corrupted(what) => write!(f, "corrupted data: {what}"),
            Self::ChecksumMismatch { expected, actual } => write!(
                f,
                "content checksum mismatch: expected 0x{expected:08X}, got 0x{actual:08X}"
            ),
            Self::ContentSizeMismatch { declared, actual } => write!(
                f,
                "frame content size mismatch: declared {declared}, decoded {actual}"
            ),
            Self::OutputLimitExceeded(limit) => {
                write!(f, "decompressed output exceeds limit of {limit} bytes")
            }
            Self::InputTooLarge(len) => write!(f, "input of {len} bytes is too large"),
        }
    }
}

impl std::error::Error for CoreError {}

pub type Result<T> = std::result::Result<T, CoreError>;

/// Compress `data` into one standard Zstandard frame (content size + XXH64 checksum).
///
/// `level` is clamped to `MIN_LEVEL..=MAX_LEVEL`.
pub fn compress(data: &[u8], level: i32) -> Result<Vec<u8>> {
    frame::compress_frame(data, level.clamp(MIN_LEVEL, MAX_LEVEL))
}

/// Decompress all (possibly concatenated) Zstandard/skippable frames in `data`.
///
/// Uses no output limit beyond available memory; prefer [`decompress_with_limit`] for
/// untrusted input.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    decompress_with_limit(data, usize::MAX)
}

/// Decompress with a hard cap on the total number of output bytes.
pub fn decompress_with_limit(data: &[u8], max_output: usize) -> Result<Vec<u8>> {
    frame::decompress_frames(data, max_output)
}
