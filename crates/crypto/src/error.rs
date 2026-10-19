//! Error type for the `todo-crypto` crate.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Tag verification failed; no plaintext is released.
    AuthenticationFailed,
    /// Key is neither 16 nor 32 bytes (AES-128/AES-256, or the master key of a
    /// [`crate::CryptoMode`]).
    InvalidKeyLength(usize),
    /// Plaintext/ciphertext or AAD exceeds the algorithm limit (RFC 8452: 2^36 bytes).
    DataTooLarge,
    /// POLYVAL segment size must be a non-zero multiple of 16 bytes (one POLYVAL block).
    InvalidSegmentSize(usize),
    /// Sequential, parallel, and/or upstream outputs differ (an implementation bug).
    EquivalenceMismatch(String),
    /// The upstream `aes-gcm-siv` oracle returned an error.
    Upstream,
    /// Authentication tag has the wrong length for the selected crypto mode.
    InvalidTagLength { expected: usize, actual: usize },
    /// Ciphertext is too short for the selected crypto mode (e.g. missing inner cascade tag).
    CiphertextTooShort,
    /// Unknown crypto mode name or wire identifier.
    UnknownCryptoMode(String),
    /// Subkey derivation (HKDF-SHA256) failed.
    KeyDerivation,
    /// STREAM chunk size outside
    /// [`crate::crypto_mode::MIN_STREAM_CHUNK_SIZE`]..=[`crate::crypto_mode::MAX_STREAM_CHUNK_SIZE`].
    InvalidStreamChunkSize(usize),
    /// The crypto mode does not support STREAM chunking (AES-GCM-SIV is always one
    /// message with segment-parallel POLYVAL).
    StreamChunkingUnsupported(crate::CryptoMode),
    /// Ciphertext length is not a valid STREAM layout for the mode and chunk size.
    MalformedStreamCiphertext,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationFailed => {
                write!(f, "AEAD authentication tag verification failed")
            }
            Self::InvalidKeyLength(len) => {
                write!(f, "invalid key length {len}: expected 16 or 32 bytes")
            }
            Self::DataTooLarge => {
                write!(f, "input exceeds the size limit of the selected algorithm")
            }
            Self::InvalidSegmentSize(size) => write!(
                f,
                "invalid POLYVAL segment size {size}: must be a non-zero multiple of 16 bytes"
            ),
            Self::EquivalenceMismatch(msg) => write!(f, "equivalence check failed: {msg}"),
            Self::Upstream => write!(f, "upstream aes-gcm-siv oracle returned an error"),
            Self::InvalidTagLength { expected, actual } => write!(
                f,
                "invalid tag length {actual}: expected {expected} bytes for this crypto mode"
            ),
            Self::CiphertextTooShort => write!(f, "ciphertext too short for this crypto mode"),
            Self::UnknownCryptoMode(name) => write!(f, "unknown crypto mode {name:?}"),
            Self::KeyDerivation => write!(f, "HKDF-SHA256 subkey derivation failed"),
            Self::InvalidStreamChunkSize(size) => write!(
                f,
                "invalid STREAM chunk size {size}: must be between {} and {} bytes",
                crate::crypto_mode::MIN_STREAM_CHUNK_SIZE,
                crate::crypto_mode::MAX_STREAM_CHUNK_SIZE
            ),
            Self::StreamChunkingUnsupported(mode) => {
                write!(f, "crypto mode {mode} does not support STREAM chunking")
            }
            Self::MalformedStreamCiphertext => write!(
                f,
                "ciphertext length is not a valid STREAM layout for this mode and chunk size"
            ),
        }
    }
}

impl std::error::Error for CryptoError {}
