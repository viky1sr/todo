//! Crypto-only criterion benchmarks of every selectable `crypto_mode` (no Zstd).
//! Run with the release profile: `cargo bench -p todo-crypto --bench crypto_modes_benchmark`.
//!
//! Groups:
//! - `crypto_mode/seal`: encryption incl. HKDF subkey derivation (non-AES modes) and, for
//!   AES-GCM-SIV, the sequential plan and a fixed 64 KiB segment-parallel plan.
//! - `crypto_mode/open`: verification + decryption of the same messages.
//! - `crypto_mode/stream_seal`, `crypto_mode/stream_open`: non-AES modes as STREAM chunks
//!   of 64 KiB, sequential vs. Rayon-parallel (identical output). The 64 KiB message has
//!   one chunk, so no parallel speedup can be claimed there.
//!
//! Outputs are checked to round-trip before timing. Modes other than AES-GCM-SIV are
//! different formats: compare throughput, never tags. Keep these numbers separate from
//! end-to-end (compression + encryption) measurements.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use todo_crypto::{
    CryptoMode, DEFAULT_POLYVAL_SEGMENT_SIZE, EnvironmentInfo, FallbackReason, SegmentPlan,
    crypto_mode,
};

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
const KEY: [u8; 32] = [0x3a; 32];
const NONCE: [u8; 12] = [0x91; 12];
const AAD: &[u8] = b"ZSGS benchmark header";

fn payload(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i * 17 % 251) as u8).collect()
}

fn arms(size: usize) -> Vec<(String, CryptoMode, SegmentPlan)> {
    let seq = SegmentPlan::Sequential {
        reason: FallbackReason::Forced,
    };
    let mut arms = Vec::new();
    for mode in CryptoMode::ALL {
        if mode == CryptoMode::AesGcmSiv {
            arms.push(("aes-gcm-siv/sequential".to_string(), mode, seq));
            arms.push((
                "aes-gcm-siv/parallel-64k".to_string(),
                mode,
                SegmentPlan::fixed(size, DEFAULT_POLYVAL_SEGMENT_SIZE),
            ));
        } else {
            let na = SegmentPlan::Sequential {
                reason: FallbackReason::NotApplicable,
            };
            arms.push((mode.label().to_string(), mode, na));
        }
    }
    arms
}

fn bench_crypto_modes(c: &mut Criterion) {
    eprintln!("{:?}", EnvironmentInfo::detect());
    let mut seal_group = c.benchmark_group("crypto_mode/seal");
    for size in [64 * KIB, MIB, 16 * MIB] {
        let data = payload(size);
        seal_group.throughput(Throughput::Bytes(size as u64));
        for (name, mode, plan) in arms(size) {
            let sealed = crypto_mode::seal(mode, &KEY, &NONCE, AAD, &data, &plan).unwrap();
            let opened = crypto_mode::open(
                mode,
                &KEY,
                &NONCE,
                AAD,
                &sealed.ciphertext,
                &sealed.tag,
                &plan,
            )
            .unwrap();
            assert_eq!(opened, data, "{name}: roundtrip failed before timing");
            seal_group.bench_with_input(BenchmarkId::new(name, size), &data, |b, d| {
                b.iter(|| crypto_mode::seal(mode, &KEY, &NONCE, AAD, black_box(d), &plan).unwrap());
            });
        }
    }
    seal_group.finish();

    let mut open_group = c.benchmark_group("crypto_mode/open");
    for size in [64 * KIB, MIB, 16 * MIB] {
        let data = payload(size);
        open_group.throughput(Throughput::Bytes(size as u64));
        for (name, mode, plan) in arms(size) {
            let sealed = crypto_mode::seal(mode, &KEY, &NONCE, AAD, &data, &plan).unwrap();
            open_group.bench_with_input(BenchmarkId::new(name, size), &sealed, |b, s| {
                b.iter(|| {
                    crypto_mode::open(
                        mode,
                        &KEY,
                        &NONCE,
                        AAD,
                        black_box(&s.ciphertext),
                        &s.tag,
                        &plan,
                    )
                    .unwrap()
                });
            });
        }
    }
    open_group.finish();

    const STREAM_CHUNK: usize = 64 * KIB;
    let stream_modes = || {
        CryptoMode::ALL
            .into_iter()
            .filter(|m| *m != CryptoMode::AesGcmSiv)
    };
    let mut stream_seal = c.benchmark_group("crypto_mode/stream_seal");
    for size in [64 * KIB, MIB, 16 * MIB] {
        let data = payload(size);
        stream_seal.throughput(Throughput::Bytes(size as u64));
        for mode in stream_modes() {
            let seq = crypto_mode::seal_stream(mode, &KEY, &NONCE, AAD, &data, STREAM_CHUNK, false)
                .unwrap();
            let par = crypto_mode::seal_stream(mode, &KEY, &NONCE, AAD, &data, STREAM_CHUNK, true)
                .unwrap();
            assert_eq!(seq, par, "{mode}: sequential != parallel STREAM");
            for (arm, parallel) in [("sequential", false), ("parallel", true)] {
                let name = format!("{}/stream-64k-{arm}", mode.label());
                stream_seal.bench_with_input(BenchmarkId::new(name, size), &data, |b, d| {
                    b.iter(|| {
                        crypto_mode::seal_stream(
                            mode,
                            &KEY,
                            &NONCE,
                            AAD,
                            black_box(d),
                            STREAM_CHUNK,
                            parallel,
                        )
                        .unwrap()
                    });
                });
            }
        }
    }
    stream_seal.finish();

    let mut stream_open = c.benchmark_group("crypto_mode/stream_open");
    for size in [64 * KIB, MIB, 16 * MIB] {
        let data = payload(size);
        stream_open.throughput(Throughput::Bytes(size as u64));
        for mode in stream_modes() {
            let s = crypto_mode::seal_stream(mode, &KEY, &NONCE, AAD, &data, STREAM_CHUNK, true)
                .unwrap();
            for (arm, parallel) in [("sequential", false), ("parallel", true)] {
                let opened = crypto_mode::open_stream(
                    mode,
                    &KEY,
                    &NONCE,
                    AAD,
                    &s.ciphertext,
                    &s.tag,
                    STREAM_CHUNK,
                    parallel,
                )
                .unwrap();
                assert_eq!(
                    opened, data,
                    "{mode}: STREAM roundtrip failed before timing"
                );
                let name = format!("{}/stream-64k-{arm}", mode.label());
                stream_open.bench_with_input(BenchmarkId::new(name, size), &s, |b, s| {
                    b.iter(|| {
                        crypto_mode::open_stream(
                            mode,
                            &KEY,
                            &NONCE,
                            AAD,
                            black_box(&s.ciphertext),
                            &s.tag,
                            STREAM_CHUNK,
                            parallel,
                        )
                        .unwrap()
                    });
                });
            }
        }
    }
    stream_open.finish();
}

criterion_group!(benches, bench_crypto_modes);
criterion_main!(benches);
