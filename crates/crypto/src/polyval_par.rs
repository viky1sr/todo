//! Segment-parallel evaluation and composition of standard POLYVAL (RFC 8452 § 3).
//!
//! This is an *execution strategy* for the unmodified POLYVAL function, not a new hash.
//! The byte stream is split into ordered segments of `segment_size` bytes (a multiple of
//! 16, so only the final segment can contain a partial POLYVAL block). Each segment is
//! hashed independently from the zero state. Segment states are then combined with the
//! associative ordered-concatenation operator from `gf128`.
//!
//! The primary thesis path uses an **ordered parallel tree reduction**, reducing the
//! composition critical depth from O(m) to O(log m) for `m` segment states while
//! preserving the exact byte order. A linear reducer is retained as an experimental
//! baseline so the contribution of tree composition can be measured independently from
//! parallel local hashing.
//!
//! Because segment boundaries are multiples of 16 bytes, zero-padding occurs at exactly
//! the same final partial block as in the sequential computation. Therefore the output is
//! bit-identical to [`crate::polyval_seq::polyval_sequential`].

use crate::error::CryptoError;
use crate::gf128::{PolyvalPart, dot_pow};
use crate::polyval_seq::{polyval_part_sequential, polyval_part_sequential_with_power};
use polyval::hazmat::FieldElement;
use rayon::prelude::*;

/// Default POLYVAL segment size: 64 KiB (4096 blocks).
pub const DEFAULT_POLYVAL_SEGMENT_SIZE: usize = 64 * 1024;

/// POLYVAL block size in bytes.
pub const POLYVAL_BLOCK_SIZE: usize = 16;

/// Small sequential leaf used by the fused divide-and-conquer tree. This avoids spawning
/// Rayon work for every individual segment while keeping tree depth logarithmic.
const TREE_LEAF_SEGMENTS: usize = 8;

/// Reject segment sizes that would place zero-padding in the middle of the stream.
pub fn validate_segment_size(segment_size: usize) -> Result<(), CryptoError> {
    if segment_size == 0 || !segment_size.is_multiple_of(POLYVAL_BLOCK_SIZE) {
        return Err(CryptoError::InvalidSegmentSize(segment_size));
    }
    Ok(())
}

/// Number of POLYVAL segments `data_len` bytes are split into.
pub fn segment_count(data_len: usize, segment_size: usize) -> usize {
    data_len.div_ceil(segment_size.max(1))
}

/// Ordered linear composition baseline: local segment hashing is parallel, but the
/// segment states are composed from left to right on one thread.
pub fn polyval_parallel_linear_reduce(
    h_key: &[u8; 16],
    data: &[u8],
    segment_size: usize,
) -> Result<[u8; 16], CryptoError> {
    validate_segment_size(segment_size)?;
    Ok(polyval_part_parallel_linear(h_key, data, segment_size)
        .hash
        .into())
}

/// Primary thesis implementation: local segment hashing and ordered composition are both
/// parallel. The ordered tree reducer preserves concatenation order because the combine
/// operator is associative but not commutative.
pub fn polyval_parallel(
    h_key: &[u8; 16],
    data: &[u8],
    segment_size: usize,
) -> Result<[u8; 16], CryptoError> {
    validate_segment_size(segment_size)?;
    Ok(polyval_part_parallel(h_key, data, segment_size).hash.into())
}

fn local_parts(h_key: &[u8; 16], data: &[u8], segment_size: usize) -> Vec<PolyvalPart> {
    let h = FieldElement::from(*h_key);
    let full_blocks = (segment_size / POLYVAL_BLOCK_SIZE) as u64;
    let full_power = dot_pow(h, full_blocks);

    data.par_chunks(segment_size)
        .map(|segment| {
            if segment.len() == segment_size {
                polyval_part_sequential_with_power(h_key, segment, full_blocks, full_power)
            } else {
                polyval_part_sequential(h_key, segment)
            }
        })
        .collect()
}

/// Old execution shape retained as a measurement baseline:
/// parallel local hashes + sequential ordered fold.
pub(crate) fn polyval_part_parallel_linear(
    h_key: &[u8; 16],
    data: &[u8],
    segment_size: usize,
) -> PolyvalPart {
    debug_assert!(validate_segment_size(segment_size).is_ok());

    if data.len() <= segment_size {
        return polyval_part_sequential(h_key, data);
    }

    local_parts(h_key, data, segment_size)
        .into_iter()
        .fold(PolyvalPart::empty(), |acc, part| acc.combine(part))
}

fn segment_part(
    h_key: &[u8; 16],
    segment: &[u8],
    segment_size: usize,
    full_blocks: u64,
    full_power: FieldElement,
) -> PolyvalPart {
    if segment.len() == segment_size {
        polyval_part_sequential_with_power(h_key, segment, full_blocks, full_power)
    } else {
        polyval_part_sequential(h_key, segment)
    }
}

/// Fused ordered divide-and-conquer evaluation. Unlike the measurement baseline, the primary
/// path does not first materialize one `PolyvalPart` per segment. Each leaf hashes a small run
/// of adjacent segments and the recursion composes left before right, preserving the exact
/// concatenation order required by RFC 8452.
fn reduce_data_ordered(
    h_key: &[u8; 16],
    data: &[u8],
    segment_size: usize,
    full_blocks: u64,
    full_power: FieldElement,
) -> PolyvalPart {
    let segments = segment_count(data.len(), segment_size);
    if segments == 0 {
        return PolyvalPart::empty();
    }
    if segments <= TREE_LEAF_SEGMENTS {
        return data.chunks(segment_size).fold(PolyvalPart::empty(), |acc, segment| {
            acc.combine(segment_part(
                h_key,
                segment,
                segment_size,
                full_blocks,
                full_power,
            ))
        });
    }

    // Split only on a segment boundary. Therefore a partial final POLYVAL block can occur only
    // in the right-most subtree, exactly as in the sequential byte stream.
    let left_segments = segments / 2;
    let split = left_segments * segment_size;
    let (left_data, right_data) = data.split_at(split);
    let (left, right) = rayon::join(
        || {
            reduce_data_ordered(
                h_key,
                left_data,
                segment_size,
                full_blocks,
                full_power,
            )
        },
        || {
            reduce_data_ordered(
                h_key,
                right_data,
                segment_size,
                full_blocks,
                full_power,
            )
        },
    );
    left.combine(right)
}

/// Caller must have validated `segment_size`.
pub(crate) fn polyval_part_parallel(
    h_key: &[u8; 16],
    data: &[u8],
    segment_size: usize,
) -> PolyvalPart {
    debug_assert!(validate_segment_size(segment_size).is_ok());

    if data.len() <= segment_size {
        return polyval_part_sequential(h_key, data);
    }

    let h = FieldElement::from(*h_key);
    let full_blocks = (segment_size / POLYVAL_BLOCK_SIZE) as u64;
    let full_power = dot_pow(h, full_blocks);
    reduce_data_ordered(
        h_key,
        data,
        segment_size,
        full_blocks,
        full_power,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::polyval_seq::polyval_sequential;

    #[test]
    fn rejects_invalid_segment_sizes() {
        let h = [0x42u8; 16];
        for bad in [0usize, 1, 15, 17, 100, 65_535] {
            assert_eq!(
                polyval_parallel(&h, &[0u8; 64], bad),
                Err(CryptoError::InvalidSegmentSize(bad))
            );
            assert_eq!(
                polyval_parallel_linear_reduce(&h, &[0u8; 64], bad),
                Err(CryptoError::InvalidSegmentSize(bad))
            );
        }
    }

    #[test]
    fn tree_and_linear_reducers_match_sequential_across_boundaries() {
        let h = [0x42u8; 16];
        for seg in [16usize, 32, 48, 1024] {
            for len in [
                0usize,
                1,
                15,
                16,
                17,
                seg - 1,
                seg,
                seg + 1,
                3 * seg + 5,
                10_000,
            ] {
                let data: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
                let expected = polyval_sequential(&h, &data);
                assert_eq!(
                    polyval_parallel(&h, &data, seg),
                    Ok(expected),
                    "tree len={len} seg={seg}"
                );
                assert_eq!(
                    polyval_parallel_linear_reduce(&h, &data, seg),
                    Ok(expected),
                    "linear len={len} seg={seg}"
                );
            }
        }
    }

    #[test]
    fn ordered_tree_handles_odd_segment_count() {
        let h = [0x93u8; 16];
        let seg = 64usize;
        let data: Vec<u8> = (0..(5 * seg + 7)).map(|i| (i * 11 % 251) as u8).collect();
        assert_eq!(
            polyval_parallel(&h, &data, seg).unwrap(),
            polyval_sequential(&h, &data)
        );
    }

    #[test]
    fn fused_tree_matches_linear_for_many_segments() {
        let h = [0x5au8; 16];
        let seg = 16usize;
        let data: Vec<u8> = (0..(257 * seg + 13))
            .map(|i| (i.wrapping_mul(73) % 251) as u8)
            .collect();
        assert_eq!(
            polyval_parallel(&h, &data, seg),
            polyval_parallel_linear_reduce(&h, &data, seg)
        );
        assert_eq!(
            polyval_parallel(&h, &data, seg).unwrap(),
            polyval_sequential(&h, &data)
        );
    }
}
