//! Error type for the IPFS layer.

use crate::cid::Cid;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpfsError {
    /// A CID, multibase string, varint or multihash is malformed or non-canonical.
    InvalidCid(String),
    /// The multihash function is valid but not supported for local verification.
    UnsupportedHash(u64),
    /// Block bytes do not hash to the digest in their CID.
    DigestMismatch { cid: Cid },
    /// The backend reported a different CID than the one computed locally.
    CidMismatch { expected: Cid, actual: Cid },
    /// Block larger than [`crate::MAX_BLOCK_SIZE`] (or another configured limit).
    BlockTooLarge { size: usize, limit: usize },
    /// The block is not present in the backend.
    NotFound(Cid),
    /// Manifest is malformed, non-canonical or inconsistent with its blocks.
    InvalidManifest(String),
    /// Declared/actual object size exceeds the configured bound.
    ObjectTooLarge { size: u64, limit: u64 },
    /// The backend cannot perform this operation (e.g. `put` on a read-only gateway).
    Unsupported(&'static str),
    /// Transport or HTTP-level failure talking to a live backend.
    Transport(String),
    /// The backend answered with an error.
    Backend { status: u16, message: String },
    /// Internal failure (e.g. a blocking task panicked).
    Internal(String),
}

impl fmt::Display for IpfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCid(e) => write!(f, "invalid CID: {e}"),
            Self::UnsupportedHash(code) => {
                write!(f, "unsupported multihash function 0x{code:x}")
            }
            Self::DigestMismatch { cid } => write!(f, "block content does not match CID {cid}"),
            Self::CidMismatch { expected, actual } => {
                write!(f, "backend returned CID {actual}, expected {expected}")
            }
            Self::BlockTooLarge { size, limit } => {
                write!(f, "block of {size} B exceeds limit {limit} B")
            }
            Self::NotFound(cid) => write!(f, "block not found: {cid}"),
            Self::InvalidManifest(e) => write!(f, "invalid manifest: {e}"),
            Self::ObjectTooLarge { size, limit } => {
                write!(f, "object of {size} B exceeds limit {limit} B")
            }
            Self::Unsupported(op) => write!(f, "operation not supported by backend: {op}"),
            Self::Transport(e) => write!(f, "transport error: {e}"),
            Self::Backend { status, message } => write!(f, "backend error {status}: {message}"),
            Self::Internal(e) => write!(f, "internal error: {e}"),
        }
    }
}

impl std::error::Error for IpfsError {}
