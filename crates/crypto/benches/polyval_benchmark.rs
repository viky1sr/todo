//! Criterion benchmarks. Always run with the release profile:
//! `cargo bench -p todo-crypto` (optionally `RAYON_NUM_THREADS=n`).
//!
//! Groups:
//! - `polyval/size`: sequential vs. parallel-local/linear-reduce vs. parallel-tree.
//! - `polyval/segment_size`: tree POLYVAL on 16 MiB across segment sizes.
//! - `polyval/threads`: tree POLYVAL on 16 MiB with 1, 2, 4, ... threads.
//! - `aes_gcm_siv/encrypt`: upstream plus SS, PS, SP and PP execution modes.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use todo_crypto::{
    DEFAULT_POLYVAL_SEGMENT_SIZE, EnvironmentInfo, aes_gcm_siv_encrypt_ctr_parallel,
    aes_gcm_siv_encrypt_parallel, aes_gcm_siv_encrypt_polyval_parallel,
    aes_gcm_siv_encrypt_sequential, aes_gcm_siv_encrypt_upstream, polyval_parallel,
    polyval_parallel_linear_reduce, polyval_sequential,
};

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

fn payload(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i * 17 % 251) as u8).collect()
}

fn bench_polyval_size(c: &mut Criterion) {
    eprintln!("{:?}", EnvironmentInfo::detect());
    let mut group = c.benchmark_group("polyval/size");
    let h = [0x5cu8; 16];
    for size in [64 * KIB, 256 * KIB, MIB, 4 * MIB, 16 * MIB] {
        let data = payload(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("sequential", size), &data, |b, d| {
            b.iter(|| polyval_sequential(black_box(&h), black_box(d)));
        });
        group.bench_with_input(
            BenchmarkId::new("parallel_local_linear_reduce", size),
            &data,
            |b, d| {
                b.iter(|| {
                    polyval_parallel_linear_reduce(
                        black_box(&h),
                        black_box(d),
                        DEFAULT_POLYVAL_SEGMENT_SIZE,
                    )
                });
            },
        );
        group.bench_with_input(BenchmarkId::new("parallel_tree", size), &data, |b, d| {
            b.iter(|| polyval_parallel(black_box(&h), black_box(d), DEFAULT_POLYVAL_SEGMENT_SIZE));
        });
    }
    group.finish();
}

fn bench_polyval_segment_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("polyval/segment_size");
    let h = [0x5cu8; 16];
    let data = payload(16 * MIB);
    group.throughput(Throughput::Bytes(data.len() as u64));
    for segment in [16 * KIB, 64 * KIB, 256 * KIB, MIB, 4 * MIB, 16 * MIB] {
        group.bench_with_input(BenchmarkId::from_parameter(segment), &segment, |b, &s| {
            b.iter(|| polyval_parallel(black_box(&h), black_box(&data), s));
        });
    }
    group.finish();
}

fn bench_polyval_threads(c: &mut Criterion) {
    let mut group = c.benchmark_group("polyval/threads");
    let h = [0x5cu8; 16];
    let data = payload(16 * MIB);
    group.throughput(Throughput::Bytes(data.len() as u64));
    let max = std::thread::available_parallelism().map_or(1, |n| n.get());
    let mut threads = 1;
    while threads <= max {
        let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(threads).build() else {
            break;
        };
        group.bench_with_input(BenchmarkId::from_parameter(threads), &threads, |b, _| {
            b.iter(|| {
                pool.install(|| {
                    polyval_parallel(
                        black_box(&h),
                        black_box(&data),
                        DEFAULT_POLYVAL_SEGMENT_SIZE,
                    )
                })
            });
        });
        threads *= 2;
    }
    group.finish();
}

fn bench_aes_gcm_siv(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm_siv/encrypt");
    let key = [0x2au8; 16];
    let nonce = [0x7bu8; 12];
    let aad = b"benchmark header";
    for size in [256 * KIB, MIB, 4 * MIB, 16 * MIB] {
        let pt = payload(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("SS", size), &pt, |b, pt| {
            b.iter(|| aes_gcm_siv_encrypt_sequential(&key, &nonce, aad, black_box(pt)));
        });
        group.bench_with_input(
            BenchmarkId::new("PS_polyval_parallel", size),
            &pt,
            |b, pt| {
                b.iter(|| {
                    aes_gcm_siv_encrypt_polyval_parallel(
                        &key,
                        &nonce,
                        aad,
                        black_box(pt),
                        DEFAULT_POLYVAL_SEGMENT_SIZE,
                    )
                });
            },
        );
        group.bench_with_input(BenchmarkId::new("SP_ctr_parallel", size), &pt, |b, pt| {
            b.iter(|| {
                aes_gcm_siv_encrypt_ctr_parallel(
                    &key,
                    &nonce,
                    aad,
                    black_box(pt),
                    DEFAULT_POLYVAL_SEGMENT_SIZE,
                )
            });
        });
        group.bench_with_input(BenchmarkId::new("PP_both_parallel", size), &pt, |b, pt| {
            b.iter(|| {
                aes_gcm_siv_encrypt_parallel(
                    &key,
                    &nonce,
                    aad,
                    black_box(pt),
                    DEFAULT_POLYVAL_SEGMENT_SIZE,
                )
            });
        });
        group.bench_with_input(BenchmarkId::new("upstream", size), &pt, |b, pt| {
            b.iter(|| aes_gcm_siv_encrypt_upstream(&key, &nonce, aad, black_box(pt)));
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_polyval_size,
    bench_polyval_segment_size,
    bench_polyval_threads,
    bench_aes_gcm_siv
);
criterion_main!(benches);
