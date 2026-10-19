//! End-to-end pipeline tests whose *compressed* output spans many POLYVAL segments,
//! plus the sequential fallback for small compressed outputs.

use todo_crypto::{
    CryptoError, FallbackReason, SegmentPlan, SegmentationPolicy, aes_gcm_siv_decrypt_upstream,
    aes_gcm_siv_encrypt_upstream,
};
use todo_zstd::{CompressionMode, PipelineError, SegmentationStrategy, StreamCryptoPipeline};

const KEY: [u8; 32] = [0x6b; 32];
const NONCE: [u8; 12] = [0x2e; 12];
const MIB: usize = 1024 * 1024;

fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        out.extend_from_slice(&(z ^ (z >> 31)).to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Alternating 64 KiB blocks of random and highly repetitive bytes.
fn mixed_bytes(len: usize, seed: u64) -> Vec<u8> {
    let random = random_bytes(len, seed);
    random
        .chunks(64 * 1024)
        .enumerate()
        .flat_map(|(i, c)| {
            if i % 2 == 0 {
                c.to_vec()
            } else {
                vec![b'A'; c.len()]
            }
        })
        .collect()
}

fn pool(threads: usize) -> rayon::ThreadPool {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .unwrap()
}

fn single_frame(strategy: SegmentationStrategy) -> StreamCryptoPipeline {
    StreamCryptoPipeline::single_frame(3)
        .with_segmentation(strategy)
        .unwrap()
}

#[test]
fn incompressible_single_frame_exercises_many_polyval_segments() {
    let data = random_bytes(4 * MIB + 13, 1);
    let report = pool(4).install(|| {
        StreamCryptoPipeline::single_frame(3)
            .verify_pipeline_with_tag_proof(&data, &KEY, &NONCE)
            .unwrap()
    });
    assert_eq!(report.zstd_frames, 1);
    assert!(report.compressed_size_bytes > 4 * MIB);
    assert!(report.parallel_path_exercised);
    assert!(
        report.num_polyval_segments >= 8,
        "segments = {}",
        report.num_polyval_segments
    );
    let eq = report.aes_gcm_siv_equivalence.as_ref().unwrap();
    assert!(eq.is_bit_identical);
    assert_eq!(
        eq.upstream_tag_hex.as_deref(),
        Some(eq.parallel_tag_hex.as_str())
    );
    assert!(report.pipeline_roundtrip_verified);
}

#[test]
fn mixed_entropy_single_frame_is_multi_segment_and_matches_upstream() {
    let data = mixed_bytes(8 * MIB, 2);
    let pipeline = single_frame(SegmentationStrategy::default());
    let (sealed, metrics) = pool(6)
        .install(|| pipeline.compress_and_encrypt_with_metrics(&data, &KEY, &NONCE))
        .unwrap();
    assert!(metrics.compressed_bytes < data.len());
    assert!(metrics.plan.executed_segments(metrics.compressed_bytes) > 1);

    let stream = aes_gcm_siv_decrypt_upstream(
        &KEY,
        &NONCE,
        &sealed.associated_data(),
        &sealed.ciphertext,
        sealed.tag.as_slice().try_into().unwrap(),
    )
    .unwrap();
    let upstream =
        aes_gcm_siv_encrypt_upstream(&KEY, &NONCE, &sealed.associated_data(), &stream).unwrap();
    assert_eq!(upstream.tag.as_slice(), sealed.tag.as_slice());
    assert_eq!(upstream.ciphertext, sealed.ciphertext);
    assert_eq!(zstd::stream::decode_all(stream.as_slice()).unwrap(), data);
}

#[test]
fn highly_compressible_input_falls_back_to_sequential() {
    // The 4 MiB pattern that compresses to a few KiB (one segment in earlier runs).
    let data: Vec<u8> = (0..4 * MIB)
        .map(|i| if i % 8 == 0 { (i % 256) as u8 } else { 0x42 })
        .collect();
    let report = pool(12).install(|| {
        StreamCryptoPipeline::single_frame(3)
            .verify_pipeline_with_tag_proof(&data, &KEY, &NONCE)
            .unwrap()
    });
    assert!(report.compressed_size_bytes < SegmentationPolicy::DEFAULT.min_parallel_bytes);
    assert_eq!(
        report.encryption_plan,
        SegmentPlan::Sequential {
            reason: FallbackReason::BelowThreshold
        }
    );
    assert!(!report.parallel_path_exercised);
    assert_eq!(report.num_polyval_segments, 1);
    assert!(report.aes_gcm_siv_equivalence.unwrap().is_bit_identical);
}

#[test]
fn single_thread_pool_falls_back_to_sequential() {
    let data = random_bytes(2 * MIB, 3);
    let (_, metrics) = pool(1)
        .install(|| {
            single_frame(SegmentationStrategy::default())
                .compress_and_encrypt_with_metrics(&data, &KEY, &NONCE)
        })
        .unwrap();
    assert_eq!(
        metrics.plan,
        SegmentPlan::Sequential {
            reason: FallbackReason::SingleThread
        }
    );
}

#[test]
fn all_strategies_and_thread_counts_produce_identical_sealed_streams() {
    let data = mixed_bytes(3 * MIB + 7, 4);
    let strategies = [
        SegmentationStrategy::Sequential,
        SegmentationStrategy::Fixed(16),
        SegmentationStrategy::Fixed(48),
        SegmentationStrategy::Fixed(64 * 1024),
        SegmentationStrategy::default(),
    ];
    let reference = single_frame(SegmentationStrategy::Sequential)
        .compress_and_encrypt(&data, &KEY, &NONCE)
        .unwrap();
    for threads in [1usize, 2, 3, 8] {
        for strategy in strategies {
            let sealed = pool(threads)
                .install(|| single_frame(strategy).compress_and_encrypt(&data, &KEY, &NONCE))
                .unwrap();
            assert_eq!(sealed, reference, "{strategy:?} threads={threads}");
            // The decrypting side plans independently of the encrypting side.
            for other in strategies {
                let recovered = pool(threads)
                    .install(|| single_frame(other).decrypt_and_decompress(&sealed, &KEY, &NONCE))
                    .unwrap();
                assert_eq!(recovered, data);
            }
        }
    }
}

#[test]
fn independent_frames_sequential_and_parallel_compression_agree() {
    let data = mixed_bytes(2 * MIB, 5);
    let base = || {
        StreamCryptoPipeline::new(128 * 1024, 3, 16 * 1024)
            .unwrap()
            .with_compression_mode(CompressionMode::IndependentFrames)
    };
    let seq = base()
        .with_frame_parallelism(false)
        .with_segmentation(SegmentationStrategy::Sequential)
        .unwrap()
        .compress_and_encrypt(&data, &KEY, &NONCE)
        .unwrap();
    let par = base()
        .with_segmentation(SegmentationStrategy::default())
        .unwrap()
        .compress_and_encrypt(&data, &KEY, &NONCE)
        .unwrap();
    assert_eq!(seq, par);
    assert_eq!(seq.segments.len(), 16);
}

#[test]
fn tampering_inside_a_middle_segment_is_rejected() {
    let data = random_bytes(4 * MIB, 6);
    let pipeline = single_frame(SegmentationStrategy::Fixed(64 * 1024));
    let mut sealed = pipeline.compress_and_encrypt(&data, &KEY, &NONCE).unwrap();
    let mid = sealed.ciphertext.len() / 2 + 5;
    sealed.ciphertext[mid] ^= 0x01;
    assert_eq!(
        pool(4).install(|| pipeline.decrypt_and_decompress(&sealed, &KEY, &NONCE)),
        Err(PipelineError::Crypto(CryptoError::AuthenticationFailed))
    );
}

#[test]
fn invalid_strategies_are_rejected() {
    assert!(
        StreamCryptoPipeline::single_frame(3)
            .with_segmentation(SegmentationStrategy::Fixed(100))
            .is_err()
    );
    let bad = SegmentationPolicy {
        min_segment_bytes: 0,
        ..SegmentationPolicy::DEFAULT
    };
    assert!(
        StreamCryptoPipeline::single_frame(3)
            .with_segmentation(SegmentationStrategy::Adaptive(bad))
            .is_err()
    );
}
