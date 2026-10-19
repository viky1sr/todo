//! Compress-then-encrypt pipeline: Zstandard frame(s) + one AEAD message.
//!
//! The encryption is selected by [`CryptoMode`] (`crypto_mode`): AES-GCM-SIV (default,
//! primary thesis mode), XChaCha20 (unauthenticated baseline), XChaCha20-Poly1305,
//! Ascon-AEAD128, AEGIS-256, or the XChaCha20-Poly1305 + AEGIS-256 cascade. By default
//! every mode encrypts the **same** compressed stream as one message; only AES-GCM-SIV
//! uses the segment-parallel POLYVAL plan. Non-AES modes can instead be sealed as
//! parallel STREAM chunks ([`StreamCryptoPipeline::with_stream_chunking`], format
//! version 3). See `todo_crypto::crypto_mode` for key derivation and STREAM.
//!
//! # Data flow
//!
//! 1. Compression, selected by [`CompressionMode`]:
//!    * [`CompressionMode::SingleFrame`]: the whole input is one stateful Zstandard frame
//!      (primary thesis configuration; best ratio, compression is not parallel).
//!    * [`CompressionMode::IndependentFrames`]: the input is split into chunks of
//!      `compression_segment_size` bytes, each compressed **independently** as a standard
//!      Zstandard frame (RFC 8878), optionally in parallel. Independence costs some
//!      compression ratio (comparison baseline).
//! 2. The frames are concatenated in order. RFC 8878 allows a stream to consist of
//!    multiple consecutive frames, so the result is itself a valid Zstandard stream.
//! 3. The compressed stream is encrypted as **one** AES-GCM-SIV message (one key, one
//!    nonce, one tag). POLYVAL/CTR scheduling is chosen per message by
//!    [`SegmentationStrategy`] from the **compressed** length: adaptive segmentation with
//!    a sequential fallback when the compressed output is too small to benefit.
//!
//! # Segment mapping
//!
//! *Zstd frames* and *POLYVAL segments* (16-byte-aligned slices of the concatenated
//! compressed stream) are independent: POLYVAL segment `j` covers stream bytes
//! `[j*S, (j+1)*S)` regardless of where frames begin or end. The POLYVAL segmentation is
//! not part of the format: every plan yields the same ciphertext and tag, so the
//! decrypting side plans independently.
//!
//! # Associated data (application format, not a change to AES-GCM-SIV)
//!
//! The segment metadata needed for parallel decompression is authenticated by passing
//! it as the standard AEAD AAD. Version 1 (AES-GCM-SIV only, unchanged format):
//!
//! ```text
//! magic "ZSGS" (4) || version u8 = 1 || segment_count u64 LE
//!   || segment_count * (compressed_size u64 LE || uncompressed_size u64 LE)
//! ```
//!
//! Version 2 (all other modes, one message) additionally binds the mode identifier:
//!
//! ```text
//! magic "ZSGS" (4) || version u8 = 2 || crypto_mode_id u8 || segment_count u64 LE || ...
//! ```
//!
//! Version 3 (non-AES modes, STREAM chunks) also binds the AEAD chunk size:
//!
//! ```text
//! magic "ZSGS" (4) || version u8 = 3 || crypto_mode_id u8 || chunk_size u32 LE
//!   || segment_count u64 LE || ...
//! ```
//!
//! Every STREAM chunk `i` is sealed with `AAD_i = AAD || crypto_mode_id || i u64 LE ||
//! is_last u8` and a nonce containing `i` and `is_last`, so reordered, duplicated,
//! dropped, appended or spliced chunks fail authentication. AEAD chunk `i` covers
//! compressed-stream bytes `[i*chunk_size, (i+1)*chunk_size)`, independent of Zstandard
//! frame boundaries. All chunks are verified before anything is decompressed.
//!
//! The serialized stream is `AAD || ciphertext_len u64 LE || ciphertext || tag`, where
//! the tag length is fixed by the mode (0, 16 or 32 bytes); for version 3 `ciphertext`
//! holds the chunks with their embedded tags and `tag` is the final chunk's tag.
//!
//! This is a design assumption of the experiment.
//!
//! # Limitation: compression side channel
//!
//! AES-GCM-SIV does not hide the ciphertext length, and here the per-frame compressed
//! sizes are even sent in the clear (authenticated, not encrypted). Compress-then-encrypt
//! therefore leaks information about the plaintext through lengths (cf. CRIME/BREACH).
//! Segmentation is a performance measure only and is **not** a mitigation. The pipeline
//! must not be used where an attacker can inject chosen data next to secrets.

use crate::compressor::ZstdSegmenter;
use crate::segment::ZstdError;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{Duration, Instant};
use todo_crypto::{
    CryptoError, CryptoMode, DEFAULT_POLYVAL_SEGMENT_SIZE, FallbackReason, SegmentPlan,
    SegmentationPolicy, TagEquivalenceReport, assert_aes_gcm_siv_equivalence, crypto_mode,
    plan_for_current_pool, validate_segment_size,
};

/// Magic prefix of the AAD / serialized sealed stream.
pub const SEALED_STREAM_MAGIC: [u8; 4] = *b"ZSGS";

/// Sealed stream format version for [`CryptoMode::AesGcmSiv`] (format unchanged).
pub const SEALED_STREAM_VERSION: u8 = 1;

/// Sealed stream format version for every other [`CryptoMode`] (mode id in the AAD).
pub const SEALED_STREAM_VERSION_MULTI_MODE: u8 = 2;

/// Sealed stream format version for STREAM-chunked non-AES modes (mode id and chunk size
/// in the AAD).
pub const SEALED_STREAM_VERSION_STREAM: u8 = 3;

/// Format version used for `mode` as one message.
pub fn sealed_stream_version(mode: CryptoMode) -> u8 {
    if mode == CryptoMode::AesGcmSiv {
        SEALED_STREAM_VERSION
    } else {
        SEALED_STREAM_VERSION_MULTI_MODE
    }
}

/// Default upper bound on the total decompressed size accepted by
/// [`StreamCryptoPipeline::decrypt_and_decompress`] (decompression-bomb protection).
///
/// The declared sizes are authenticated, but anyone holding the key (e.g. a REST client
/// that supplies its own key) can declare arbitrary sizes, so the bound is enforced
/// before any decryption or allocation.
pub const DEFAULT_MAX_DECOMPRESSED_SIZE: usize = 1 << 30;

const HEADER_LEN: usize = 4 + 1 + 8;
const DESCRIPTOR_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineError {
    Zstd(ZstdError),
    Crypto(CryptoError),
    VerificationMismatch(String),
    MalformedStream(String),
    DecompressedSizeLimitExceeded {
        declared: usize,
        limit: usize,
    },
    /// The sealed stream uses a different crypto mode than the pipeline expects.
    CryptoModeMismatch {
        expected: CryptoMode,
        found: CryptoMode,
    },
}

impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zstd(e) => write!(f, "Zstandard error: {e}"),
            Self::Crypto(e) => write!(f, "cryptographic error: {e}"),
            Self::VerificationMismatch(e) => write!(f, "verification mismatch: {e}"),
            Self::MalformedStream(e) => write!(f, "malformed sealed stream: {e}"),
            Self::DecompressedSizeLimitExceeded { declared, limit } => write!(
                f,
                "declared decompressed size {declared} B exceeds limit {limit} B"
            ),
            Self::CryptoModeMismatch { expected, found } => write!(
                f,
                "crypto mode mismatch: expected {expected}, sealed stream uses {found}"
            ),
        }
    }
}

impl std::error::Error for PipelineError {}

impl From<ZstdError> for PipelineError {
    fn from(e: ZstdError) -> Self {
        Self::Zstd(e)
    }
}

impl From<CryptoError> for PipelineError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

/// Sizes of one independent Zstandard frame inside the compressed stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentDescriptor {
    pub compressed_size: u64,
    pub uncompressed_size: u64,
}

/// Output of [`StreamCryptoPipeline::compress_and_encrypt`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedStream {
    pub version: u8,
    /// Encryption mode; bound to the AAD for format version 2, implied by version 1.
    #[serde(default)]
    pub crypto_mode: CryptoMode,
    /// Authenticated (via AAD) but not encrypted.
    pub segments: Vec<SegmentDescriptor>,
    /// Ciphertext of the concatenated Zstandard frames (cascade: includes the inner tag).
    pub ciphertext: Vec<u8>,
    /// Detached tag, [`CryptoMode::tag_len`] bytes (empty for unauthenticated XChaCha20).
    /// For STREAM (version 3) this is the final chunk's tag.
    pub tag: Vec<u8>,
    /// AEAD STREAM chunk size (version 3 only; bound to the AAD).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_chunk_size: Option<u32>,
}

fn encode_aad(
    version: u8,
    mode: CryptoMode,
    stream_chunk_size: Option<u32>,
    segments: &[SegmentDescriptor],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_LEN + 5 + segments.len() * DESCRIPTOR_LEN);
    aad.extend_from_slice(&SEALED_STREAM_MAGIC);
    aad.push(version);
    if version >= SEALED_STREAM_VERSION_MULTI_MODE {
        aad.push(mode.id());
    }
    if version == SEALED_STREAM_VERSION_STREAM {
        aad.extend_from_slice(&stream_chunk_size.unwrap_or(0).to_le_bytes());
    }
    aad.extend_from_slice(&(segments.len() as u64).to_le_bytes());
    for seg in segments {
        aad.extend_from_slice(&seg.compressed_size.to_le_bytes());
        aad.extend_from_slice(&seg.uncompressed_size.to_le_bytes());
    }
    aad
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], PipelineError> {
        if self.buf.len() < n {
            return Err(PipelineError::MalformedStream("truncated input".into()));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32, PipelineError> {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, PipelineError> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(bytes))
    }
}

fn to_usize(v: u64) -> Result<usize, PipelineError> {
    usize::try_from(v).map_err(|_| PipelineError::MalformedStream("size overflows usize".into()))
}

impl SealedStream {
    /// The AAD bound to this stream's ciphertext.
    pub fn associated_data(&self) -> Vec<u8> {
        encode_aad(
            self.version,
            self.crypto_mode,
            self.stream_chunk_size,
            &self.segments,
        )
    }

    /// Check that version, mode, chunk size and tag length are mutually consistent.
    pub fn validate_header(&self) -> Result<(), PipelineError> {
        match self.version {
            SEALED_STREAM_VERSION | SEALED_STREAM_VERSION_MULTI_MODE => {
                if self.version != sealed_stream_version(self.crypto_mode) {
                    return Err(PipelineError::MalformedStream(format!(
                        "version {} does not match crypto mode {}",
                        self.version, self.crypto_mode
                    )));
                }
                if self.stream_chunk_size.is_some() {
                    return Err(PipelineError::MalformedStream(format!(
                        "version {} has no STREAM chunk size",
                        self.version
                    )));
                }
            }
            SEALED_STREAM_VERSION_STREAM => {
                let size = self.stream_chunk_size.ok_or_else(|| {
                    PipelineError::MalformedStream("version 3 requires a STREAM chunk size".into())
                })?;
                crypto_mode::validate_stream_chunk_size(self.crypto_mode, size as usize)
                    .map_err(|e| PipelineError::MalformedStream(e.to_string()))?;
            }
            v => {
                return Err(PipelineError::MalformedStream(format!(
                    "unsupported version {v}"
                )));
            }
        }
        if self.tag.len() != self.crypto_mode.tag_len() {
            return Err(PipelineError::MalformedStream(format!(
                "tag length {} does not match crypto mode {} ({} B)",
                self.tag.len(),
                self.crypto_mode,
                self.crypto_mode.tag_len()
            )));
        }
        Ok(())
    }

    /// Length of the encrypted compressed payload (ciphertext minus cascade/STREAM
    /// overhead). Requires a valid header.
    pub fn payload_len(&self) -> Result<usize, PipelineError> {
        Ok(match self.stream_chunk_size {
            Some(size) => crypto_mode::stream_payload_len(
                self.crypto_mode,
                self.ciphertext.len(),
                size as usize,
            )?,
            None => self
                .ciphertext
                .len()
                .checked_sub(self.crypto_mode.ciphertext_expansion())
                .ok_or(PipelineError::Crypto(CryptoError::CiphertextTooShort))?,
        })
    }

    /// Number of AEAD messages/chunks (1 unless STREAM-chunked).
    pub fn aead_chunks(&self) -> Result<usize, PipelineError> {
        Ok(match self.stream_chunk_size {
            Some(size) => crypto_mode::stream_chunk_count(self.payload_len()?, size as usize),
            None => 1,
        })
    }

    /// Serialize as `AAD || ciphertext_len u64 LE || ciphertext || tag`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.associated_data();
        out.reserve(8 + self.ciphertext.len() + self.tag.len());
        out.extend_from_slice(&(self.ciphertext.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.tag);
        out
    }

    /// Parse the format written by [`SealedStream::to_bytes`]. This only checks
    /// structure; authenticity is checked on decryption.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PipelineError> {
        let mut r = Reader { buf: bytes };
        if r.take(4)? != SEALED_STREAM_MAGIC {
            return Err(PipelineError::MalformedStream("bad magic".into()));
        }
        let version = r.take(1)?[0];
        let (crypto_mode, stream_chunk_size) = match version {
            SEALED_STREAM_VERSION => (CryptoMode::AesGcmSiv, None),
            SEALED_STREAM_VERSION_MULTI_MODE | SEALED_STREAM_VERSION_STREAM => {
                let mode = CryptoMode::from_id(r.take(1)?[0])?;
                if mode == CryptoMode::AesGcmSiv {
                    return Err(PipelineError::MalformedStream(
                        "aes-gcm-siv must use format version 1".into(),
                    ));
                }
                let chunk = if version == SEALED_STREAM_VERSION_STREAM {
                    let size = r.u32()?;
                    crypto_mode::validate_stream_chunk_size(mode, size as usize)
                        .map_err(|e| PipelineError::MalformedStream(e.to_string()))?;
                    Some(size)
                } else {
                    None
                };
                (mode, chunk)
            }
            _ => {
                return Err(PipelineError::MalformedStream(format!(
                    "unsupported version {version}"
                )));
            }
        };
        let count = to_usize(r.u64()?)?;
        if count > r.buf.len() / DESCRIPTOR_LEN {
            return Err(PipelineError::MalformedStream(
                "segment count too large".into(),
            ));
        }
        let segments = (0..count)
            .map(|_| {
                Ok(SegmentDescriptor {
                    compressed_size: r.u64()?,
                    uncompressed_size: r.u64()?,
                })
            })
            .collect::<Result<Vec<_>, PipelineError>>()?;
        let ct_len = to_usize(r.u64()?)?;
        let ciphertext = r.take(ct_len)?.to_vec();
        let tag = r.take(crypto_mode.tag_len())?.to_vec();
        if !r.buf.is_empty() {
            return Err(PipelineError::MalformedStream("trailing bytes".into()));
        }
        Ok(Self {
            version,
            crypto_mode,
            segments,
            ciphertext,
            tag,
            stream_chunk_size,
        })
    }
}

/// Check that the declared frame sizes are consistent with the ciphertext length and that
/// the declared decompressed total does not exceed `max_decompressed_size`.
/// Returns the total decompressed size.
fn validate_layout(
    stream_len: usize,
    segments: &[SegmentDescriptor],
    max_decompressed_size: usize,
) -> Result<usize, PipelineError> {
    let mut compressed_total = 0usize;
    let mut uncompressed_total = 0usize;
    for seg in segments {
        let overflow = || PipelineError::MalformedStream("segment sizes overflow".into());
        compressed_total = compressed_total
            .checked_add(to_usize(seg.compressed_size)?)
            .ok_or_else(overflow)?;
        uncompressed_total = uncompressed_total
            .checked_add(to_usize(seg.uncompressed_size)?)
            .ok_or_else(overflow)?;
    }
    if compressed_total != stream_len {
        return Err(PipelineError::MalformedStream(
            "segment sizes do not match ciphertext length".into(),
        ));
    }
    if uncompressed_total > max_decompressed_size {
        return Err(PipelineError::DecompressedSizeLimitExceeded {
            declared: uncompressed_total,
            limit: max_decompressed_size,
        });
    }
    Ok(uncompressed_total)
}

fn decompress_frame(src: &[u8], dst: &mut [u8]) -> Result<(), ZstdError> {
    let expected = dst.len();
    let written = zstd::bulk::decompress_to_buffer(src, dst)
        .map_err(|e| ZstdError::DecompressionFailed(e.to_string()))?;
    if written != expected {
        return Err(ZstdError::CorruptedSegment(
            "decompressed size mismatch".into(),
        ));
    }
    Ok(())
}

/// Decompress consecutive frames directly into one buffer (in parallel if requested).
/// Each frame writes into a slice of exactly its declared size, so no frame can expand
/// beyond the bound checked by [`validate_layout`].
fn decompress_frames(
    stream: &[u8],
    segments: &[SegmentDescriptor],
    max_decompressed_size: usize,
    parallel: bool,
) -> Result<Vec<u8>, PipelineError> {
    let uncompressed_total = validate_layout(stream.len(), segments, max_decompressed_size)?;
    let mut output = vec![0u8; uncompressed_total];
    let mut jobs = Vec::with_capacity(segments.len());
    let (mut src_rest, mut dst_rest) = (stream, output.as_mut_slice());
    for seg in segments {
        // Both conversions were checked above.
        let (src, s) = src_rest.split_at(seg.compressed_size as usize);
        let (dst, d) = dst_rest.split_at_mut(seg.uncompressed_size as usize);
        jobs.push((src, dst));
        (src_rest, dst_rest) = (s, d);
    }

    if parallel && jobs.len() > 1 {
        jobs.into_par_iter()
            .try_for_each(|(src, dst)| decompress_frame(src, dst))?;
    } else {
        jobs.into_iter()
            .try_for_each(|(src, dst)| decompress_frame(src, dst))?;
    }
    Ok(output)
}

/// How the input is turned into Zstandard frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompressionMode {
    /// One stateful frame over the whole input (primary thesis configuration).
    SingleFrame,
    /// Independent frames of `ZstdSegmenter::segment_size` input bytes (baseline).
    IndependentFrames,
}

impl CompressionMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::SingleFrame => "single-frame",
            Self::IndependentFrames => "independent-frames",
        }
    }
}

/// How POLYVAL/CTR work for the single AES-GCM-SIV message is scheduled. All strategies
/// produce identical ciphertext and tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentationStrategy {
    /// Always sequential (baseline arm).
    Sequential,
    /// Fixed segment size (multiple of 16), no fallback.
    Fixed(usize),
    /// Segment size derived from the compressed length and thread count, with a
    /// sequential fallback for small payloads.
    Adaptive(SegmentationPolicy),
}

impl Default for SegmentationStrategy {
    fn default() -> Self {
        Self::Adaptive(SegmentationPolicy::DEFAULT)
    }
}

impl SegmentationStrategy {
    pub fn validate(&self) -> Result<(), CryptoError> {
        match self {
            Self::Sequential => Ok(()),
            Self::Fixed(size) => validate_segment_size(*size),
            Self::Adaptive(policy) => policy.validate(),
        }
    }

    /// Plan for a payload of `payload_len` bytes on the current Rayon pool.
    pub fn plan(&self, payload_len: usize) -> Result<SegmentPlan, CryptoError> {
        match self {
            Self::Sequential => Ok(SegmentPlan::Sequential {
                reason: FallbackReason::Forced,
            }),
            Self::Fixed(size) => {
                validate_segment_size(*size)?;
                Ok(SegmentPlan::fixed(payload_len, *size))
            }
            Self::Adaptive(policy) => plan_for_current_pool(policy, payload_len),
        }
    }
}

/// Stage measurements of [`StreamCryptoPipeline::compress_and_encrypt_with_metrics`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SealMetrics {
    pub crypto_mode: CryptoMode,
    pub compression_mode: CompressionMode,
    pub zstd_frames: usize,
    pub original_bytes: usize,
    /// AEAD payload length (= POLYVAL message length for AES-GCM-SIV).
    pub compressed_bytes: usize,
    pub aad_bytes: usize,
    pub plan: SegmentPlan,
    /// STREAM chunk size, `None` for one AEAD message.
    pub stream_chunk_size: Option<usize>,
    /// AEAD messages/chunks sealed (1 unless STREAM-chunked).
    pub aead_chunks: usize,
    pub compression: Duration,
    /// AES-GCM-SIV: planning + POLYVAL + tag + CTR. Other modes: KDF + AEAD/stream.
    pub encryption: Duration,
}

/// Stage measurements of [`StreamCryptoPipeline::decrypt_and_decompress_with_metrics`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct OpenMetrics {
    pub crypto_mode: CryptoMode,
    pub plan: SegmentPlan,
    pub stream_chunk_size: Option<usize>,
    pub aead_chunks: usize,
    /// AES-GCM-SIV: planning + CTR + POLYVAL + constant-time tag check. Other modes:
    /// KDF + decryption + tag check(s).
    pub decryption: Duration,
    pub decompression: Duration,
}

/// Pipeline report for the evaluation chapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineVerificationReport {
    pub crypto_mode: CryptoMode,
    /// False only for the unauthenticated XChaCha20 baseline.
    pub authenticated: bool,
    pub tag_size_bytes: usize,
    /// Ciphertext + tag bytes minus compressed bytes.
    pub crypto_overhead_bytes: usize,
    pub original_size_bytes: usize,
    pub compressed_size_bytes: usize,
    /// Size when the whole input is compressed as one frame (no segmentation).
    pub single_frame_compressed_size_bytes: usize,
    pub compression_ratio_percent: f64,
    pub single_frame_compression_ratio_percent: f64,
    pub compression_mode: CompressionMode,
    /// Input bytes per frame (`None` for [`CompressionMode::SingleFrame`]).
    pub compression_segment_size: Option<usize>,
    pub zstd_frames: usize,
    /// Plan actually used for encryption.
    pub encryption_plan: SegmentPlan,
    /// `None` when the sequential path was used.
    pub polyval_segment_size: Option<usize>,
    /// POLYVAL segments of the compressed payload actually executed (0 for modes
    /// without POLYVAL).
    pub num_polyval_segments: usize,
    /// True iff more than one POLYVAL segment was executed in parallel.
    pub parallel_path_exercised: bool,
    /// STREAM chunk size of non-AES modes (`None`: one AEAD message).
    pub stream_chunk_size: Option<usize>,
    /// AEAD messages/chunks (1 unless STREAM-chunked).
    pub aead_chunks: usize,
    /// True iff more than one STREAM chunk was sealed on the Rayon pool.
    pub stream_parallel_exercised: bool,
    /// Two swapped equal-sized STREAM chunks were rejected (`None` if not applicable:
    /// fewer than 3 chunks or unauthenticated mode).
    pub chunk_transposition_rejected: Option<bool>,
    /// Dropping the final STREAM chunk was rejected (`None` if fewer than 2 chunks or
    /// unauthenticated mode).
    pub chunk_truncation_rejected: Option<bool>,
    pub aad_size_bytes: usize,
    /// Sequential vs. parallel vs. upstream AES-GCM-SIV over the actual compressed stream
    /// (`None` for other crypto modes: they are different formats).
    pub aes_gcm_siv_equivalence: Option<TagEquivalenceReport>,
    /// Re-encryption with identical inputs reproduced ciphertext and tag.
    pub deterministic_reencryption: bool,
    /// A flipped ciphertext bit was rejected (`None` if not applicable: unauthenticated
    /// mode or empty ciphertext).
    pub tamper_rejected: Option<bool>,
    /// The concatenated frames decode with a plain (multi-frame) Zstandard decoder.
    pub standard_zstd_decoder_roundtrip: bool,
    pub pipeline_roundtrip_verified: bool,
    pub compression_time_micros: f64,
    pub encryption_time_micros: f64,
    pub decryption_time_micros: f64,
    pub decompression_time_micros: f64,
    /// Original MiB / (compression + encryption) time, single run.
    pub total_pipeline_throughput_mib_s: f64,
}

pub struct StreamCryptoPipeline {
    pub segmenter: ZstdSegmenter,
    crypto_mode: CryptoMode,
    compression_mode: CompressionMode,
    frame_parallelism: bool,
    segmentation: SegmentationStrategy,
    stream_chunk_size: Option<usize>,
    max_decompressed_size: usize,
}

/// Independent frames (parallel), adaptive POLYVAL segmentation.
impl Default for StreamCryptoPipeline {
    fn default() -> Self {
        Self {
            segmenter: ZstdSegmenter::default(),
            crypto_mode: CryptoMode::AesGcmSiv,
            compression_mode: CompressionMode::IndependentFrames,
            frame_parallelism: true,
            segmentation: SegmentationStrategy::default(),
            stream_chunk_size: None,
            max_decompressed_size: DEFAULT_MAX_DECOMPRESSED_SIZE,
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl StreamCryptoPipeline {
    /// Independent frames with a fixed POLYVAL segment size.
    /// `polyval_segment_size` must be a non-zero multiple of 16 bytes.
    pub fn new(
        compression_segment_size: usize,
        compression_level: i32,
        polyval_segment_size: usize,
    ) -> Result<Self, PipelineError> {
        validate_segment_size(polyval_segment_size)?;
        Ok(Self {
            segmenter: ZstdSegmenter::new(compression_segment_size, compression_level),
            segmentation: SegmentationStrategy::Fixed(polyval_segment_size),
            ..Self::default()
        })
    }

    /// One stateful Zstandard frame and adaptive POLYVAL segmentation.
    pub fn single_frame(compression_level: i32) -> Self {
        let mut pipeline = Self::default();
        pipeline.segmenter.compression_level = compression_level.clamp(1, 22);
        pipeline.compression_mode = CompressionMode::SingleFrame;
        pipeline
    }

    pub fn with_compression_mode(mut self, mode: CompressionMode) -> Self {
        self.compression_mode = mode;
        self
    }

    /// Select the encryption mode (default [`CryptoMode::AesGcmSiv`]). Decryption only
    /// accepts sealed streams of this mode.
    pub fn with_crypto_mode(mut self, mode: CryptoMode) -> Self {
        self.crypto_mode = mode;
        self
    }

    pub fn crypto_mode(&self) -> CryptoMode {
        self.crypto_mode
    }

    /// Compress/decompress independent frames on the Rayon pool (default `true`).
    pub fn with_frame_parallelism(mut self, parallel: bool) -> Self {
        self.frame_parallelism = parallel;
        self
    }

    pub fn with_segmentation(
        mut self,
        segmentation: SegmentationStrategy,
    ) -> Result<Self, PipelineError> {
        segmentation.validate()?;
        self.segmentation = segmentation;
        Ok(self)
    }

    /// Seal non-AES modes as parallel STREAM chunks of `chunk_size` compressed bytes
    /// (format version 3), or as one AEAD message (`None`, default). Chunks run on the
    /// Rayon pool unless the segmentation strategy is [`SegmentationStrategy::Sequential`]
    /// (same output either way). AES-GCM-SIV rejects chunking at encryption time.
    /// Decryption accepts both formats; the chunk size is read from the authenticated
    /// header.
    pub fn with_stream_chunking(
        mut self,
        chunk_size: Option<usize>,
    ) -> Result<Self, PipelineError> {
        if let Some(size) = chunk_size
            && !(todo_crypto::MIN_STREAM_CHUNK_SIZE..=todo_crypto::MAX_STREAM_CHUNK_SIZE)
                .contains(&size)
        {
            return Err(CryptoError::InvalidStreamChunkSize(size).into());
        }
        self.stream_chunk_size = chunk_size;
        Ok(self)
    }

    pub fn stream_chunk_size(&self) -> Option<usize> {
        self.stream_chunk_size
    }

    /// Whether STREAM chunks are processed on the Rayon pool.
    fn stream_parallel(&self) -> bool {
        self.segmentation != SegmentationStrategy::Sequential
    }

    /// Override the decompression-bomb bound (default [`DEFAULT_MAX_DECOMPRESSED_SIZE`]).
    pub fn with_max_decompressed_size(mut self, limit: usize) -> Self {
        self.max_decompressed_size = limit;
        self
    }

    pub fn compression_mode(&self) -> CompressionMode {
        self.compression_mode
    }

    pub fn segmentation(&self) -> SegmentationStrategy {
        self.segmentation
    }

    pub fn max_decompressed_size(&self) -> usize {
        self.max_decompressed_size
    }

    /// Execution plan for a payload of `payload_len` bytes: the configured POLYVAL
    /// segmentation for AES-GCM-SIV, [`FallbackReason::NotApplicable`] otherwise.
    fn plan_for(&self, payload_len: usize) -> Result<SegmentPlan, CryptoError> {
        if self.crypto_mode.uses_polyval_segmentation() {
            self.segmentation.plan(payload_len)
        } else {
            Ok(SegmentPlan::Sequential {
                reason: FallbackReason::NotApplicable,
            })
        }
    }

    /// Compress `data` into frame descriptors and the concatenated compressed stream.
    pub fn compress(
        &self,
        data: &[u8],
    ) -> Result<(Vec<SegmentDescriptor>, Vec<u8>), PipelineError> {
        if data.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        if self.compression_mode == CompressionMode::SingleFrame {
            let stream = zstd::bulk::compress(data, self.segmenter.compression_level)
                .map_err(|e| ZstdError::CompressionFailed(e.to_string()))?;
            let descriptor = SegmentDescriptor {
                compressed_size: stream.len() as u64,
                uncompressed_size: data.len() as u64,
            };
            return Ok((vec![descriptor], stream));
        }

        let frames = if self.frame_parallelism {
            self.segmenter.compress_segments_parallel(data)?
        } else {
            self.segmenter.compress_segments_sequential(data)?
        };
        let total: usize = frames.iter().map(|f| f.compressed_data.len()).sum();
        let mut stream = Vec::with_capacity(total);
        let descriptors = frames
            .iter()
            .map(|f| {
                stream.extend_from_slice(&f.compressed_data);
                SegmentDescriptor {
                    compressed_size: f.compressed_data.len() as u64,
                    uncompressed_size: f.uncompressed_size as u64,
                }
            })
            .collect();
        Ok((descriptors, stream))
    }

    /// Compression, then one encryption of the compressed stream with the selected
    /// [`CryptoMode`].
    ///
    /// The caller is responsible for never reusing `nonce` with the same `key`.
    pub fn compress_and_encrypt(
        &self,
        data: &[u8],
        key: &[u8],
        nonce: &[u8; 12],
    ) -> Result<SealedStream, PipelineError> {
        Ok(self.compress_and_encrypt_with_metrics(data, key, nonce)?.0)
    }

    /// [`Self::compress_and_encrypt`] with per-stage timings and the encryption plan.
    pub fn compress_and_encrypt_with_metrics(
        &self,
        data: &[u8],
        key: &[u8],
        nonce: &[u8; 12],
    ) -> Result<(SealedStream, SealMetrics), PipelineError> {
        let start = Instant::now();
        let (segments, stream) = self.compress(data)?;
        let compressed_at = Instant::now();
        let mode = self.crypto_mode;
        let plan = self.plan_for(stream.len())?;
        let (version, wire_chunk) = match self.stream_chunk_size {
            Some(size) => {
                crypto_mode::validate_stream_chunk_size(mode, size)?;
                (SEALED_STREAM_VERSION_STREAM, Some(size as u32))
            }
            None => (sealed_stream_version(mode), None),
        };
        let aad = encode_aad(version, mode, wire_chunk, &segments);
        let out = match self.stream_chunk_size {
            Some(size) => crypto_mode::seal_stream(
                mode,
                key,
                nonce,
                &aad,
                &stream,
                size,
                self.stream_parallel(),
            )?,
            None => crypto_mode::seal(mode, key, nonce, &aad, &stream, &plan)?,
        };
        let encrypted_at = Instant::now();
        let aead_chunks = self.stream_chunk_size.map_or(1, |size| {
            crypto_mode::stream_chunk_count(stream.len(), size)
        });

        let metrics = SealMetrics {
            crypto_mode: mode,
            compression_mode: self.compression_mode,
            zstd_frames: segments.len(),
            original_bytes: data.len(),
            compressed_bytes: stream.len(),
            aad_bytes: aad.len(),
            plan,
            stream_chunk_size: self.stream_chunk_size,
            aead_chunks,
            compression: compressed_at - start,
            encryption: encrypted_at - compressed_at,
        };
        let sealed = SealedStream {
            version,
            crypto_mode: mode,
            segments,
            ciphertext: out.ciphertext,
            tag: out.tag,
            stream_chunk_size: wire_chunk,
        };
        Ok((sealed, metrics))
    }

    /// Check the declared layout and size bound, verify and decrypt (tag checked before
    /// anything is decompressed), then decompress the frames.
    pub fn decrypt_and_decompress(
        &self,
        sealed: &SealedStream,
        key: &[u8],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>, PipelineError> {
        Ok(self
            .decrypt_and_decompress_with_metrics(sealed, key, nonce)?
            .0)
    }

    /// [`Self::decrypt_and_decompress`] with per-stage timings and the decryption plan.
    pub fn decrypt_and_decompress_with_metrics(
        &self,
        sealed: &SealedStream,
        key: &[u8],
        nonce: &[u8; 12],
    ) -> Result<(Vec<u8>, OpenMetrics), PipelineError> {
        sealed.validate_header()?;
        if sealed.crypto_mode != self.crypto_mode {
            return Err(PipelineError::CryptoModeMismatch {
                expected: self.crypto_mode,
                found: sealed.crypto_mode,
            });
        }
        let payload_len = sealed.payload_len()?;
        validate_layout(payload_len, &sealed.segments, self.max_decompressed_size)?;
        let start = Instant::now();
        let plan = self.plan_for(payload_len)?;
        let aad = sealed.associated_data();
        let stream = match sealed.stream_chunk_size {
            Some(size) => crypto_mode::open_stream(
                sealed.crypto_mode,
                key,
                nonce,
                &aad,
                &sealed.ciphertext,
                &sealed.tag,
                size as usize,
                self.stream_parallel(),
            )?,
            None => crypto_mode::open(
                sealed.crypto_mode,
                key,
                nonce,
                &aad,
                &sealed.ciphertext,
                &sealed.tag,
                &plan,
            )?,
        };
        let decrypted_at = Instant::now();
        let output = decompress_frames(
            &stream,
            &sealed.segments,
            self.max_decompressed_size,
            self.frame_parallelism,
        )?;
        let metrics = OpenMetrics {
            crypto_mode: sealed.crypto_mode,
            plan,
            stream_chunk_size: sealed.stream_chunk_size.map(|s| s as usize),
            aead_chunks: sealed.aead_chunks()?,
            decryption: decrypted_at - start,
            decompression: decrypted_at.elapsed(),
        };
        Ok((output, metrics))
    }

    /// For an authenticated STREAM-sealed stream: swap chunks 0 and 1 (needs >= 3 chunks,
    /// so both are full-sized) and drop the final chunk (needs >= 2 chunks, chunk `n-2`
    /// becomes the claimed final chunk). Both must fail authentication.
    fn check_stream_attacks(
        &self,
        sealed: &SealedStream,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
    ) -> Result<(Option<bool>, Option<bool>), PipelineError> {
        let (Some(size), true) = (
            sealed.stream_chunk_size,
            sealed.crypto_mode.is_authenticated(),
        ) else {
            return Ok((None, None));
        };
        let (mode, size) = (sealed.crypto_mode, size as usize);
        let n = sealed.aead_chunks()?;
        let slot = size + mode.overhead();
        let rejected = |ct: &[u8], tag: &[u8]| {
            matches!(
                crypto_mode::open_stream(mode, key, nonce, aad, ct, tag, size, true),
                Err(CryptoError::AuthenticationFailed)
            )
        };
        let transposition = (n >= 3).then(|| {
            let mut ct = sealed.ciphertext.clone();
            let (first, rest) = ct.split_at_mut(slot);
            first.swap_with_slice(&mut rest[..slot]);
            rejected(&ct, &sealed.tag)
        });
        let truncation = (n >= 2).then(|| {
            let body_end = (n - 2) * slot + size + mode.ciphertext_expansion();
            let ct = &sealed.ciphertext[..body_end];
            let tag = &sealed.ciphertext[body_end..body_end + mode.tag_len()];
            rejected(ct, tag)
        });
        if transposition == Some(false) || truncation == Some(false) {
            return Err(PipelineError::VerificationMismatch(
                "reordered or truncated STREAM chunks were not rejected".into(),
            ));
        }
        Ok((transposition, truncation))
    }

    /// Run the full pipeline once and check: (1) for AES-GCM-SIV, sequential, parallel
    /// and upstream agree on the real compressed stream and AAD, and the plan actually
    /// used produces the same tag; for every mode, re-encryption is deterministic and
    /// (authenticated modes) a flipped ciphertext bit is rejected, (2) the frames decode
    /// with a standard Zstandard decoder, (3) the round trip is lossless.
    pub fn verify_pipeline_with_tag_proof(
        &self,
        data: &[u8],
        key: &[u8],
        nonce: &[u8; 12],
    ) -> Result<PipelineVerificationReport, PipelineError> {
        let (sealed, seal) = self.compress_and_encrypt_with_metrics(data, key, nonce)?;
        let (_, stream) = self.compress(data)?;
        let mode = self.crypto_mode;

        let single_frame = zstd::bulk::compress(data, self.segmenter.compression_level)
            .map_err(|e| ZstdError::CompressionFailed(e.to_string()))?;
        let standard_decoded = zstd::stream::decode_all(stream.as_slice())
            .map_err(|e| ZstdError::DecompressionFailed(e.to_string()))?;
        if standard_decoded != data {
            return Err(PipelineError::VerificationMismatch(
                "standard Zstandard decoder output differs from input".into(),
            ));
        }

        let aad = sealed.associated_data();
        let equivalence = if mode == CryptoMode::AesGcmSiv {
            // Exercise the parallel code path even if the plan fell back to sequential.
            let eq_segment = match seal.plan {
                SegmentPlan::Parallel { segment_bytes, .. } => segment_bytes,
                SegmentPlan::Sequential { .. } => DEFAULT_POLYVAL_SEGMENT_SIZE,
            };
            let eq = assert_aes_gcm_siv_equivalence(key, nonce, &aad, &stream, eq_segment)?;
            if hex(&sealed.tag) != eq.sequential_tag_hex {
                return Err(PipelineError::VerificationMismatch(
                    "tag of the executed plan differs from the sequential tag".into(),
                ));
            }
            Some(eq)
        } else {
            None
        };

        let reseal = match self.stream_chunk_size {
            Some(size) => crypto_mode::seal_stream(mode, key, nonce, &aad, &stream, size, false)?,
            None => crypto_mode::seal(mode, key, nonce, &aad, &stream, &seal.plan)?,
        };
        if reseal.ciphertext != sealed.ciphertext || reseal.tag != sealed.tag {
            return Err(PipelineError::VerificationMismatch(
                "re-encryption with identical inputs differs".into(),
            ));
        }

        let tamper_rejected = if mode.is_authenticated() && !sealed.ciphertext.is_empty() {
            let mut tampered = sealed.clone();
            let mid = tampered.ciphertext.len() / 2;
            tampered.ciphertext[mid] ^= 0x01;
            let rejected = matches!(
                self.decrypt_and_decompress(&tampered, key, nonce),
                Err(PipelineError::Crypto(CryptoError::AuthenticationFailed))
            );
            if !rejected {
                return Err(PipelineError::VerificationMismatch(
                    "tampered ciphertext was not rejected".into(),
                ));
            }
            Some(true)
        } else {
            None
        };

        let (chunk_transposition_rejected, chunk_truncation_rejected) =
            self.check_stream_attacks(&sealed, key, nonce, &aad)?;

        let (recovered, open) = self.decrypt_and_decompress_with_metrics(&sealed, key, nonce)?;
        if recovered != data {
            return Err(PipelineError::VerificationMismatch(
                "recovered data differs from input".into(),
            ));
        }

        let pct = |n: usize| n as f64 / data.len().max(1) as f64 * 100.0;
        let total = seal.compression + seal.encryption;
        let mib = data.len() as f64 / (1024.0 * 1024.0);
        let micros = |d: Duration| d.as_secs_f64() * 1e6;
        Ok(PipelineVerificationReport {
            crypto_mode: mode,
            authenticated: mode.is_authenticated(),
            tag_size_bytes: sealed.tag.len(),
            crypto_overhead_bytes: sealed.ciphertext.len() + sealed.tag.len() - stream.len(),
            original_size_bytes: data.len(),
            compressed_size_bytes: stream.len(),
            single_frame_compressed_size_bytes: single_frame.len(),
            compression_ratio_percent: pct(stream.len()),
            single_frame_compression_ratio_percent: pct(single_frame.len()),
            compression_mode: self.compression_mode,
            compression_segment_size: (self.compression_mode == CompressionMode::IndependentFrames)
                .then_some(self.segmenter.segment_size),
            zstd_frames: seal.zstd_frames,
            encryption_plan: seal.plan,
            polyval_segment_size: match seal.plan {
                SegmentPlan::Parallel { segment_bytes, .. } => Some(segment_bytes),
                SegmentPlan::Sequential { .. } => None,
            },
            num_polyval_segments: if mode.uses_polyval_segmentation() {
                seal.plan.executed_segments(stream.len())
            } else {
                0
            },
            parallel_path_exercised: seal.plan.is_parallel(),
            stream_chunk_size: seal.stream_chunk_size,
            aead_chunks: seal.aead_chunks,
            stream_parallel_exercised: seal.stream_chunk_size.is_some()
                && seal.aead_chunks > 1
                && self.stream_parallel(),
            chunk_transposition_rejected,
            chunk_truncation_rejected,
            aad_size_bytes: aad.len(),
            aes_gcm_siv_equivalence: equivalence,
            deterministic_reencryption: true,
            tamper_rejected,
            standard_zstd_decoder_roundtrip: true,
            pipeline_roundtrip_verified: true,
            compression_time_micros: micros(seal.compression),
            encryption_time_micros: micros(seal.encryption),
            decryption_time_micros: micros(open.decryption),
            decompression_time_micros: micros(open.decompression),
            total_pipeline_throughput_mib_s: if total.is_zero() {
                0.0
            } else {
                mib / total.as_secs_f64()
            },
        })
    }
}
