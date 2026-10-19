//! Lightweight wall-clock measurements for the evaluation binary and REST endpoint.
//!
//! These are quick, indicative numbers. Thesis results should come from the criterion
//! benchmarks (`cargo bench -p todo-crypto`) built with the release profile, together
//! with the [`EnvironmentInfo`] of the machine.

use crate::error::CryptoError;
use crate::polyval_par::{polyval_parallel, validate_segment_size};
use crate::polyval_seq::polyval_sequential;
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub payload_size_bytes: usize,
    pub payload_size_label: String,
    pub segment_size_bytes: usize,
    pub rayon_threads: usize,
    pub iterations: usize,
    pub seq_latency_avg_micros: f64,
    pub par_latency_avg_micros: f64,
    pub seq_throughput_mib_s: f64,
    pub par_throughput_mib_s: f64,
    /// `T_seq / T_par`.
    pub speedup_ratio: f64,
    /// `speedup / rayon_threads`.
    pub parallel_efficiency: f64,
    pub tag_equivalence_passed: bool,
}

/// Machine and build information to report alongside measurements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentInfo {
    pub os: String,
    pub arch: String,
    pub logical_cpus: usize,
    pub rayon_threads: usize,
    /// Relevant CPU features detected at runtime (e.g. `pclmulqdq`, `aes`).
    pub cpu_features: Vec<String>,
    pub rustc_version: String,
    pub build_profile: String,
}

impl EnvironmentInfo {
    pub fn detect() -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            logical_cpus: std::thread::available_parallelism().map_or(1, |n| n.get()),
            rayon_threads: rayon::current_num_threads(),
            cpu_features: detect_cpu_features(),
            rustc_version: env!("TODO_CRYPTO_RUSTC_VERSION").to_string(),
            build_profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            }
            .to_string(),
        }
    }
}

fn detect_cpu_features() -> Vec<String> {
    #[allow(unused_mut)]
    let mut features = Vec::new();
    #[cfg(target_arch = "x86_64")]
    {
        for (name, on) in [
            (
                "pclmulqdq",
                std::arch::is_x86_feature_detected!("pclmulqdq"),
            ),
            ("aes", std::arch::is_x86_feature_detected!("aes")),
            ("avx2", std::arch::is_x86_feature_detected!("avx2")),
            (
                "vpclmulqdq",
                std::arch::is_x86_feature_detected!("vpclmulqdq"),
            ),
            ("vaes", std::arch::is_x86_feature_detected!("vaes")),
        ] {
            if on {
                features.push(name.to_string());
            }
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // On aarch64 the Rust `aes` feature covers both AES and PMULL instructions.
        if std::arch::is_aarch64_feature_detected!("aes") {
            features.push("aes+pmull".to_string());
        }
    }
    features
}

/// Average sequential vs. parallel POLYVAL latency over `iterations` runs (after one
/// warm-up run each).
pub fn benchmark_polyval(
    data: &[u8],
    segment_size: usize,
    iterations: usize,
) -> Result<BenchmarkResult, CryptoError> {
    validate_segment_size(segment_size)?;
    let h_key = [0x3du8; 16];
    let iters = iterations.max(1);

    let _ = polyval_sequential(&h_key, data);
    let _ = polyval_parallel(&h_key, data, segment_size)?;

    let start = Instant::now();
    let mut seq_tag = [0u8; 16];
    for _ in 0..iters {
        seq_tag = polyval_sequential(std::hint::black_box(&h_key), std::hint::black_box(data));
    }
    let seq_elapsed = start.elapsed();

    let start = Instant::now();
    let mut par_tag = [0u8; 16];
    for _ in 0..iters {
        par_tag = polyval_parallel(
            std::hint::black_box(&h_key),
            std::hint::black_box(data),
            segment_size,
        )?;
    }
    let par_elapsed = start.elapsed();

    let seq_secs = seq_elapsed.as_secs_f64() / iters as f64;
    let par_secs = par_elapsed.as_secs_f64() / iters as f64;
    let mib = data.len() as f64 / (1024.0 * 1024.0);
    let speedup = if par_secs > 0.0 {
        seq_secs / par_secs
    } else {
        1.0
    };
    let threads = rayon::current_num_threads();

    let label = if data.len() >= 1024 * 1024 {
        format!("{:.1} MiB", mib)
    } else {
        format!("{:.1} KiB", data.len() as f64 / 1024.0)
    };

    Ok(BenchmarkResult {
        payload_size_bytes: data.len(),
        payload_size_label: label,
        segment_size_bytes: segment_size,
        rayon_threads: threads,
        iterations: iters,
        seq_latency_avg_micros: seq_secs * 1e6,
        par_latency_avg_micros: par_secs * 1e6,
        seq_throughput_mib_s: if seq_secs > 0.0 { mib / seq_secs } else { 0.0 },
        par_throughput_mib_s: if par_secs > 0.0 { mib / par_secs } else { 0.0 },
        speedup_ratio: speedup,
        parallel_efficiency: speedup / threads.max(1) as f64,
        tag_equivalence_passed: seq_tag == par_tag,
    })
}

/// Run [`benchmark_polyval`] over 64 KiB, 256 KiB, 1 MiB, 4 MiB and 16 MiB payloads.
pub fn run_standard_suite(segment_size: usize) -> Result<Vec<BenchmarkResult>, CryptoError> {
    [
        64 * 1024,
        256 * 1024,
        1024 * 1024,
        4 * 1024 * 1024,
        16 * 1024 * 1024,
    ]
    .iter()
    .map(|&size| {
        let data: Vec<u8> = (0..size).map(|i| (i * 47 % 256) as u8).collect();
        benchmark_polyval(&data, segment_size, 5)
    })
    .collect()
}
