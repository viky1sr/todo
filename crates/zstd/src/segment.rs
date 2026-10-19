//! Zstandard Independent Segment Data Structures and Framing.
//!
//! Encapsulates self-contained, independent compressed chunks with metadata.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Magic 4-byte header identifying an independent segment frame: "ZSTX"
pub const SEGMENT_MAGIC: [u8; 4] = [0x5A, 0x53, 0x54, 0x58];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZstdError {
    CompressionFailed(String),
    DecompressionFailed(String),
    CorruptedSegment(String),
    InvalidHeader,
}

impl fmt::Display for ZstdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompressionFailed(msg) => write!(f, "Zstandard compression error: {msg}"),
            Self::DecompressionFailed(msg) => write!(f, "Zstandard decompression error: {msg}"),
            Self::CorruptedSegment(msg) => write!(f, "Corrupted segment: {msg}"),
            Self::InvalidHeader => write!(f, "Invalid segment magic header"),
        }
    }
}

impl std::error::Error for ZstdError {}

/// A self-contained, independent Zstandard compressed segment.
///
/// Can be compressed, decompressed, encrypted, and verified completely independently
/// of any other segment in the stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZstdSegment {
    pub segment_id: u32,
    pub is_last: bool,
    pub uncompressed_size: usize,
    pub compressed_data: Vec<u8>,
}

impl ZstdSegment {
    /// Serialize segment into a binary framed byte buffer.
    ///
    /// Framing layout:
    /// - Magic (4 bytes): "ZSTX"
    /// - segment_id (4 bytes LE)
    /// - is_last (1 byte)
    /// - uncompressed_size (4 bytes LE)
    /// - compressed_size (4 bytes LE)
    /// - payload: compressed_data
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(17 + self.compressed_data.len());
        buf.extend_from_slice(&SEGMENT_MAGIC);
        buf.extend_from_slice(&self.segment_id.to_le_bytes());
        buf.push(if self.is_last { 1 } else { 0 });
        buf.extend_from_slice(&(self.uncompressed_size as u32).to_le_bytes());
        buf.extend_from_slice(&(self.compressed_data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.compressed_data);
        buf
    }

    /// Parse a binary framed byte buffer back into a ZstdSegment.
    pub fn from_bytes(slice: &[u8]) -> Result<Self, ZstdError> {
        if slice.len() < 17 {
            return Err(ZstdError::CorruptedSegment("Frame too short".to_string()));
        }
        if slice[..4] != SEGMENT_MAGIC {
            return Err(ZstdError::InvalidHeader);
        }

        let read_u32 = |offset: usize| {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&slice[offset..offset + 4]);
            u32::from_le_bytes(bytes)
        };
        let segment_id = read_u32(4);
        let is_last = slice[8] != 0;
        let uncompressed_size = read_u32(9) as usize;
        let compressed_size = read_u32(13) as usize;

        if slice.len() < 17 + compressed_size {
            return Err(ZstdError::CorruptedSegment(
                "Truncated compressed payload".to_string(),
            ));
        }

        let compressed_data = slice[17..17 + compressed_size].to_vec();

        Ok(Self {
            segment_id,
            is_last,
            uncompressed_size,
            compressed_data,
        })
    }
}
