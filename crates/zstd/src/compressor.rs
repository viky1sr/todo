//! Parallel and Streaming Zstandard Segmentation Engine.
//!
//! Handles segmenting input data into independent chunks and compressing/decompressing
//! concurrently across CPU cores using Rayon.
//!
//! Each segment payload is a standard Zstandard frame (`0xFD2FB528`) produced by the
//! pure-Rust codec in [`crate::core`]; [`ZstdSegment::to_bytes`] wraps it in a `ZSTX`
//! container: `[ZSTX header][standard Zstd frame]`.

use crate::core;
use crate::segment::{ZstdError, ZstdSegment};
use rayon::prelude::*;

/// Default independent segment size: 256 KB.
pub const DEFAULT_SEGMENT_SIZE: usize = 256 * 1024;

/// Default compression level (3 offers high compression speed and good ratio).
pub const DEFAULT_COMPRESSION_LEVEL: i32 = 3;

fn compress_chunk(chunk: &[u8], level: i32) -> Result<Vec<u8>, ZstdError> {
    core::compress(chunk, level).map_err(|e| ZstdError::CompressionFailed(e.to_string()))
}

/// Decode one segment with its declared size as the hard output cap.
fn decompress_segment(seg: &ZstdSegment) -> Result<Vec<u8>, ZstdError> {
    let out = core::decompress_with_limit(&seg.compressed_data, seg.uncompressed_size)
        .map_err(|e| ZstdError::DecompressionFailed(e.to_string()))?;
    if out.len() != seg.uncompressed_size {
        return Err(ZstdError::CorruptedSegment(
            "Decompressed size mismatch".to_string(),
        ));
    }
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct ZstdSegmenter {
    pub segment_size: usize,
    pub compression_level: i32,
}

impl Default for ZstdSegmenter {
    fn default() -> Self {
        Self {
            segment_size: DEFAULT_SEGMENT_SIZE,
            compression_level: DEFAULT_COMPRESSION_LEVEL,
        }
    }
}

impl ZstdSegmenter {
    pub fn new(segment_size: usize, compression_level: i32) -> Self {
        Self {
            segment_size: segment_size.max(4096),
            compression_level: compression_level.clamp(1, 22),
        }
    }

    /// Compress arbitrary data into a series of independent Zstandard segments in parallel.
    pub fn compress_segments_parallel(&self, data: &[u8]) -> Result<Vec<ZstdSegment>, ZstdError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let chunks: Vec<(usize, &[u8])> = data.chunks(self.segment_size).enumerate().collect();
        let total_chunks = chunks.len();
        let level = self.compression_level;

        chunks
            .into_par_iter()
            .map(|(idx, chunk)| {
                let is_last = idx == total_chunks - 1;
                let compressed_data = compress_chunk(chunk, level)?;

                Ok(ZstdSegment {
                    segment_id: idx as u32,
                    is_last,
                    uncompressed_size: chunk.len(),
                    compressed_data,
                })
            })
            .collect()
    }

    /// Sequential compression into independent segments for baseline benchmarking.
    pub fn compress_segments_sequential(&self, data: &[u8]) -> Result<Vec<ZstdSegment>, ZstdError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let chunks: Vec<&[u8]> = data.chunks(self.segment_size).collect();
        let total_chunks = chunks.len();
        let mut segments = Vec::with_capacity(total_chunks);

        for (idx, chunk) in chunks.into_iter().enumerate() {
            let is_last = idx == total_chunks - 1;
            let compressed_data = compress_chunk(chunk, self.compression_level)?;

            segments.push(ZstdSegment {
                segment_id: idx as u32,
                is_last,
                uncompressed_size: chunk.len(),
                compressed_data,
            });
        }

        Ok(segments)
    }

    /// Decompress a series of independent Zstandard segments in parallel.
    pub fn decompress_segments_parallel(
        &self,
        segments: &[ZstdSegment],
    ) -> Result<Vec<u8>, ZstdError> {
        if segments.is_empty() {
            return Ok(Vec::new());
        }

        // Validate segments ordering
        for (i, seg) in segments.iter().enumerate() {
            if seg.segment_id != i as u32 {
                return Err(ZstdError::CorruptedSegment(format!(
                    "Out of order segment: expected {}, got {}",
                    i, seg.segment_id
                )));
            }
        }

        let decompressed_chunks: Result<Vec<Vec<u8>>, ZstdError> =
            segments.par_iter().map(decompress_segment).collect();

        let chunks = decompressed_chunks?;
        let total_uncompressed_len: usize = chunks.iter().map(|c| c.len()).sum();
        let mut result = Vec::with_capacity(total_uncompressed_len);
        for chunk in chunks {
            result.extend_from_slice(&chunk);
        }

        Ok(result)
    }

    /// Decompress a series of independent segments sequentially.
    pub fn decompress_segments_sequential(
        &self,
        segments: &[ZstdSegment],
    ) -> Result<Vec<u8>, ZstdError> {
        let mut result = Vec::new();
        for seg in segments {
            result.extend_from_slice(&decompress_segment(seg)?);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_parallel_independent_segments() {
        let segmenter = ZstdSegmenter::new(32 * 1024, 3);
        let original_data: Vec<u8> = (0..200 * 1024).map(|i| (i * 13 % 256) as u8).collect();

        let segments = segmenter
            .compress_segments_parallel(&original_data)
            .unwrap();
        assert!(
            segments.len() >= 6,
            "Expected at least 6 independent segments"
        );

        let decompressed = segmenter.decompress_segments_parallel(&segments).unwrap();
        assert_eq!(
            original_data, decompressed,
            "Lossless decompression match failed!"
        );
    }
}
