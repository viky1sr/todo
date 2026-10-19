//! Adaptive choice between sequential and segment-parallel POLYVAL execution.
//!
//! Because every segment size that is a non-zero multiple of 16 bytes yields output
//! bit-identical to the sequential computation (see `docs/PROOF_PARALLEL_POLYVAL.md`),
//! the POLYVAL segmentation is purely a scheduling decision: it is **not** part of the message
//! format, is not authenticated, and the decrypting side may choose a different plan.
//!
//! The plan depends on the actual (compressed) payload length and the number of Rayon
//! worker threads available at call time:
//!
//! * fewer than 2 threads, or payload below [`SegmentationPolicy::min_parallel_bytes`]
//!   -> sequential fallback (Rayon dispatch and the GF(2^128) merge would dominate);
//! * otherwise the payload is split into about `threads * segments_per_thread` segments,
//!   clamped to `[min_segment_bytes, max_segment_bytes]` and rounded up to 16 bytes;
//!   if that still yields a single segment, fall back to sequential.
//!
//! The default threshold is an engineering default, not a measured optimum; calibrate it
//! per machine with the `crypto-only` size sweep of `thesis_bench`.

use crate::aes_gcm_siv_par::{
    AesGcmSivOutput, aes_gcm_siv_decrypt_polyval_parallel, aes_gcm_siv_decrypt_sequential,
    aes_gcm_siv_encrypt_polyval_parallel, aes_gcm_siv_encrypt_sequential,
};
use crate::error::CryptoError;
use crate::polyval_par::{POLYVAL_BLOCK_SIZE, polyval_parallel, segment_count};
use crate::polyval_seq::polyval_sequential;
use serde::{Deserialize, Serialize};

/// Thresholds for [`plan_segments`]. All byte sizes refer to the AEAD payload
/// (the compressed plaintext in the Zstd pipeline).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentationPolicy {
    /// Payloads shorter than this are processed sequentially.
    pub min_parallel_bytes: usize,
    /// Lower bound on the segment size (multiple of 16).
    pub min_segment_bytes: usize,
    /// Upper bound on the segment size (multiple of 16).
    pub max_segment_bytes: usize,
    /// Target number of segments per worker thread (load balancing on hybrid CPUs).
    pub segments_per_thread: usize,
}

impl SegmentationPolicy {
    pub const DEFAULT: Self = Self {
        min_parallel_bytes: 512 * 1024,
        min_segment_bytes: 16 * 1024,
        max_segment_bytes: 1024 * 1024,
        segments_per_thread: 4,
    };

    /// Check that the bounds are non-zero multiples of 16 and ordered.
    pub fn validate(&self) -> Result<(), CryptoError> {
        for size in [self.min_segment_bytes, self.max_segment_bytes] {
            if size == 0 || !size.is_multiple_of(POLYVAL_BLOCK_SIZE) {
                return Err(CryptoError::InvalidSegmentSize(size));
            }
        }
        if self.min_segment_bytes > self.max_segment_bytes || self.segments_per_thread == 0 {
            return Err(CryptoError::InvalidSegmentSize(self.min_segment_bytes));
        }
        Ok(())
    }
}

impl Default for SegmentationPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why the sequential path was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackReason {
    /// Only one Rayon worker thread is available.
    SingleThread,
    /// Payload shorter than `min_parallel_bytes`.
    BelowThreshold,
    /// The clamped segment size covers the whole payload.
    SingleSegment,
    /// Sequential execution was requested explicitly.
    Forced,
}

/// Execution plan for one AES-GCM-SIV message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "execution", rename_all = "snake_case")]
pub enum SegmentPlan {
    Sequential {
        reason: FallbackReason,
    },
    Parallel {
        segment_bytes: usize,
        /// Number of compressed-payload POLYVAL segments. AAD remains sequential.
        segments: usize,
    },
}

impl SegmentPlan {
    /// Fixed segment size (no fallback). `segment_bytes` must be a multiple of 16.
    pub fn fixed(payload_len: usize, segment_bytes: usize) -> Self {
        Self::Parallel {
            segment_bytes,
            segments: segment_count(payload_len, segment_bytes),
        }
    }

    pub fn is_parallel(&self) -> bool {
        matches!(self, Self::Parallel { segments, .. } if *segments > 1)
    }

    /// Payload segments actually processed (1 for the sequential path, 0 for empty input).
    pub fn executed_segments(&self, payload_len: usize) -> usize {
        match *self {
            Self::Sequential { .. } => usize::from(payload_len > 0),
            Self::Parallel { segments, .. } => segments,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Sequential {
                reason: FallbackReason::Forced,
            } => "sequential",
            Self::Sequential { .. } => "sequential-fallback",
            Self::Parallel { segments, .. } if *segments <= 1 => "single-segment",
            Self::Parallel { .. } => "parallel",
        }
    }
}

/// Choose an execution plan for a payload of `payload_len` bytes on `threads` workers.
pub fn plan_segments(
    policy: &SegmentationPolicy,
    payload_len: usize,
    threads: usize,
) -> Result<SegmentPlan, CryptoError> {
    policy.validate()?;
    if threads < 2 {
        return Ok(SegmentPlan::Sequential {
            reason: FallbackReason::SingleThread,
        });
    }
    if payload_len < policy.min_parallel_bytes {
        return Ok(SegmentPlan::Sequential {
            reason: FallbackReason::BelowThreshold,
        });
    }
    let target = threads.saturating_mul(policy.segments_per_thread).max(1);
    let segment_bytes = payload_len
        .div_ceil(target)
        .next_multiple_of(POLYVAL_BLOCK_SIZE)
        .clamp(policy.min_segment_bytes, policy.max_segment_bytes);
    let segments = segment_count(payload_len, segment_bytes);
    if segments < 2 {
        return Ok(SegmentPlan::Sequential {
            reason: FallbackReason::SingleSegment,
        });
    }
    Ok(SegmentPlan::Parallel {
        segment_bytes,
        segments,
    })
}

/// [`plan_segments`] with the current Rayon thread count.
pub fn plan_for_current_pool(
    policy: &SegmentationPolicy,
    payload_len: usize,
) -> Result<SegmentPlan, CryptoError> {
    plan_segments(policy, payload_len, rayon::current_num_threads())
}

/// Encrypt according to `plan`. Output is identical for every plan.
pub fn aes_gcm_siv_encrypt_planned(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    plan: &SegmentPlan,
) -> Result<AesGcmSivOutput, CryptoError> {
    match *plan {
        SegmentPlan::Sequential { .. } => {
            aes_gcm_siv_encrypt_sequential(key, nonce, aad, plaintext)
        }
        SegmentPlan::Parallel { segment_bytes, .. } => {
            aes_gcm_siv_encrypt_polyval_parallel(key, nonce, aad, plaintext, segment_bytes)
        }
    }
}

/// Verify and decrypt according to `plan`; plaintext is released only after the tag
/// verifies.
pub fn aes_gcm_siv_decrypt_planned(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
    plan: &SegmentPlan,
) -> Result<Vec<u8>, CryptoError> {
    match *plan {
        SegmentPlan::Sequential { .. } => {
            aes_gcm_siv_decrypt_sequential(key, nonce, aad, ciphertext, tag)
        }
        SegmentPlan::Parallel { segment_bytes, .. } => {
            aes_gcm_siv_decrypt_polyval_parallel(key, nonce, aad, ciphertext, tag, segment_bytes)
        }
    }
}

/// POLYVAL over `pad16(data)` according to `plan`.
pub fn polyval_planned(
    h_key: &[u8; 16],
    data: &[u8],
    plan: &SegmentPlan,
) -> Result<[u8; 16], CryptoError> {
    match *plan {
        SegmentPlan::Sequential { .. } => Ok(polyval_sequential(h_key, data)),
        SegmentPlan::Parallel { segment_bytes, .. } => polyval_parallel(h_key, data, segment_bytes),
    }
}

/// Plan for the current pool, then encrypt. Returns the plan for reporting.
pub fn aes_gcm_siv_encrypt_adaptive(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    policy: &SegmentationPolicy,
) -> Result<(AesGcmSivOutput, SegmentPlan), CryptoError> {
    let plan = plan_for_current_pool(policy, plaintext.len())?;
    Ok((
        aes_gcm_siv_encrypt_planned(key, nonce, aad, plaintext, &plan)?,
        plan,
    ))
}

/// Plan for the current pool, then verify and decrypt.
pub fn aes_gcm_siv_decrypt_adaptive(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
    policy: &SegmentationPolicy,
) -> Result<(Vec<u8>, SegmentPlan), CryptoError> {
    let plan = plan_for_current_pool(policy, ciphertext.len())?;
    Ok((
        aes_gcm_siv_decrypt_planned(key, nonce, aad, ciphertext, tag, &plan)?,
        plan,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle::aes_gcm_siv_encrypt_upstream;

    const KIB: usize = 1024;
    const MIB: usize = 1024 * KIB;

    #[test]
    fn fallback_reasons() {
        let p = SegmentationPolicy::DEFAULT;
        assert_eq!(
            plan_segments(&p, 64 * MIB, 1).unwrap(),
            SegmentPlan::Sequential {
                reason: FallbackReason::SingleThread
            }
        );
        assert_eq!(
            plan_segments(&p, 3936, 12).unwrap(),
            SegmentPlan::Sequential {
                reason: FallbackReason::BelowThreshold
            }
        );
        let wide = SegmentationPolicy {
            min_parallel_bytes: 0,
            min_segment_bytes: MIB,
            ..p
        };
        assert_eq!(
            plan_segments(&wide, 600 * KIB, 12).unwrap(),
            SegmentPlan::Sequential {
                reason: FallbackReason::SingleSegment
            }
        );
    }

    #[test]
    fn parallel_plans_are_aligned_bounded_and_cover_payload() {
        let p = SegmentationPolicy::DEFAULT;
        for threads in [2usize, 3, 4, 8, 12, 64] {
            for len in [512 * KIB, 512 * KIB + 1, 4 * MIB + 17, 64 * MIB, 300 * MIB] {
                let plan = plan_segments(&p, len, threads).unwrap();
                let SegmentPlan::Parallel {
                    segment_bytes,
                    segments,
                } = plan
                else {
                    panic!("expected parallel plan for len={len} threads={threads}");
                };
                assert!(segment_bytes.is_multiple_of(16));
                assert!((p.min_segment_bytes..=p.max_segment_bytes).contains(&segment_bytes));
                assert!(segments >= 2);
                assert!(segments * segment_bytes >= len);
                assert!((segments - 1) * segment_bytes < len);
            }
        }
    }

    #[test]
    fn invalid_policies_are_rejected() {
        let p = SegmentationPolicy::DEFAULT;
        for bad in [
            SegmentationPolicy {
                min_segment_bytes: 0,
                ..p
            },
            SegmentationPolicy {
                max_segment_bytes: 1000,
                ..p
            },
            SegmentationPolicy {
                min_segment_bytes: 2 * MIB,
                ..p
            },
            SegmentationPolicy {
                segments_per_thread: 0,
                ..p
            },
        ] {
            assert!(plan_segments(&bad, MIB, 4).is_err());
        }
    }

    #[test]
    fn every_plan_matches_upstream() {
        let key = [0x61u8; 32];
        let nonce = [0x0cu8; 12];
        let aad = b"adaptive";
        let pt: Vec<u8> = (0..(MIB + 33)).map(|i| (i * 7 % 253) as u8).collect();
        let up = aes_gcm_siv_encrypt_upstream(&key, &nonce, aad, &pt).unwrap();
        let small = SegmentationPolicy {
            min_parallel_bytes: 0,
            ..SegmentationPolicy::DEFAULT
        };
        let plans = [
            SegmentPlan::Sequential {
                reason: FallbackReason::Forced,
            },
            plan_segments(&SegmentationPolicy::DEFAULT, pt.len(), 12).unwrap(),
            plan_segments(&small, pt.len(), 3).unwrap(),
            SegmentPlan::fixed(pt.len(), 16),
        ];
        for plan in plans {
            let out = aes_gcm_siv_encrypt_planned(&key, &nonce, aad, &pt, &plan).unwrap();
            assert_eq!(out, up, "{plan:?}");
            let dec =
                aes_gcm_siv_decrypt_planned(&key, &nonce, aad, &out.ciphertext, &out.tag, &plan);
            assert_eq!(dec.unwrap(), pt);
        }
    }
}
