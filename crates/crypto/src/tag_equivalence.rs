//! Empirical equivalence checks: sequential vs. segment-parallel (vs. upstream) outputs.
//!
//! Each check runs every implementation once on the same input, requires byte-for-byte
//! identical output, and records single-shot wall-clock timings. The timings are
//! indicative only; use the criterion benchmarks (`cargo bench -p todo-crypto`, release
//! profile) for performance claims.

use crate::aes_gcm_siv_par::{
    aes_gcm_siv_encrypt_polyval_parallel, aes_gcm_siv_encrypt_sequential,
};
use crate::error::CryptoError;
use crate::oracle::aes_gcm_siv_encrypt_upstream;
use crate::polyval_par::{polyval_parallel, segment_count, validate_segment_size};
use crate::polyval_seq::polyval_sequential;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagEquivalenceReport {
    pub algorithm: String,
    pub data_size_bytes: usize,
    pub aad_size_bytes: usize,
    pub segment_size_bytes: usize,
    pub num_segments: usize,
    pub rayon_threads: usize,
    pub sequential_tag_hex: String,
    pub parallel_tag_hex: String,
    /// Tag from the upstream `aes-gcm-siv` crate (AES-GCM-SIV checks only).
    pub upstream_tag_hex: Option<String>,
    /// True iff all compared outputs (tags and, for AES-GCM-SIV, ciphertexts) are identical.
    pub is_bit_identical: bool,
    pub sequential_latency_micros: f64,
    pub parallel_latency_micros: f64,
    pub upstream_latency_micros: Option<f64>,
    /// `T_seq / T_par` (single run).
    pub speedup_ratio: f64,
    pub throughput_seq_mib_per_sec: f64,
    pub throughput_par_mib_per_sec: f64,
}

fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let out = f();
    (out, start.elapsed())
}

fn micros(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

fn mib_per_sec(bytes: usize, d: Duration) -> f64 {
    let secs = d.as_secs_f64();
    if secs > 0.0 {
        bytes as f64 / (1024.0 * 1024.0) / secs
    } else {
        0.0
    }
}

pub(crate) fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Check `polyval_parallel == polyval_sequential` on `data`.
///
/// Returns [`CryptoError::EquivalenceMismatch`] if the tags differ.
pub fn assert_polyval_equivalence(
    h_key: &[u8; 16],
    data: &[u8],
    segment_size: usize,
) -> Result<TagEquivalenceReport, CryptoError> {
    validate_segment_size(segment_size)?;
    let (seq_tag, seq_t) = timed(|| polyval_sequential(h_key, data));
    let (par_tag, par_t) = timed(|| polyval_parallel(h_key, data, segment_size));
    let par_tag = par_tag?;

    if seq_tag != par_tag {
        return Err(CryptoError::EquivalenceMismatch(format!(
            "POLYVAL sequential {} != parallel {}",
            hex_encode(&seq_tag),
            hex_encode(&par_tag)
        )));
    }

    Ok(TagEquivalenceReport {
        algorithm: "POLYVAL (RFC 8452)".to_string(),
        data_size_bytes: data.len(),
        aad_size_bytes: 0,
        segment_size_bytes: segment_size,
        num_segments: segment_count(data.len(), segment_size),
        rayon_threads: rayon::current_num_threads(),
        sequential_tag_hex: hex_encode(&seq_tag),
        parallel_tag_hex: hex_encode(&par_tag),
        upstream_tag_hex: None,
        is_bit_identical: true,
        sequential_latency_micros: micros(seq_t),
        parallel_latency_micros: micros(par_t),
        upstream_latency_micros: None,
        speedup_ratio: if par_t.is_zero() {
            1.0
        } else {
            seq_t.as_secs_f64() / par_t.as_secs_f64()
        },
        throughput_seq_mib_per_sec: mib_per_sec(data.len(), seq_t),
        throughput_par_mib_per_sec: mib_per_sec(data.len(), par_t),
    })
}

/// Check that sequential, segment-parallel and upstream AES-GCM-SIV produce identical
/// ciphertexts and tags.
pub fn assert_aes_gcm_siv_equivalence(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    segment_size: usize,
) -> Result<TagEquivalenceReport, CryptoError> {
    validate_segment_size(segment_size)?;
    let (seq, seq_t) = timed(|| aes_gcm_siv_encrypt_sequential(key, nonce, aad, plaintext));
    let (par, par_t) =
        timed(|| aes_gcm_siv_encrypt_polyval_parallel(key, nonce, aad, plaintext, segment_size));
    let (up, up_t) = timed(|| aes_gcm_siv_encrypt_upstream(key, nonce, aad, plaintext));
    let (seq, par, up) = (seq?, par?, up?);

    for (name, other) in [("parallel", &par), ("upstream", &up)] {
        if other.tag != seq.tag {
            return Err(CryptoError::EquivalenceMismatch(format!(
                "AES-GCM-SIV tag: sequential {} != {name} {}",
                hex_encode(&seq.tag),
                hex_encode(&other.tag)
            )));
        }
        if other.ciphertext != seq.ciphertext {
            return Err(CryptoError::EquivalenceMismatch(format!(
                "AES-GCM-SIV ciphertext: sequential != {name}"
            )));
        }
    }

    Ok(TagEquivalenceReport {
        algorithm: "AES-GCM-SIV (RFC 8452)".to_string(),
        data_size_bytes: plaintext.len(),
        aad_size_bytes: aad.len(),
        segment_size_bytes: segment_size,
        num_segments: segment_count(plaintext.len(), segment_size),
        rayon_threads: rayon::current_num_threads(),
        sequential_tag_hex: hex_encode(&seq.tag),
        parallel_tag_hex: hex_encode(&par.tag),
        upstream_tag_hex: Some(hex_encode(&up.tag)),
        is_bit_identical: true,
        sequential_latency_micros: micros(seq_t),
        parallel_latency_micros: micros(par_t),
        upstream_latency_micros: Some(micros(up_t)),
        speedup_ratio: if par_t.is_zero() {
            1.0
        } else {
            seq_t.as_secs_f64() / par_t.as_secs_f64()
        },
        throughput_seq_mib_per_sec: mib_per_sec(plaintext.len(), seq_t),
        throughput_par_mib_per_sec: mib_per_sec(plaintext.len(), par_t),
    })
}
