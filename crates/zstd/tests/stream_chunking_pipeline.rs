//! STREAM-chunked (format version 3) non-AES modes through the Zstd pipeline:
//! chunk index / final flag binding against transposition and truncation.

use todo_crypto::{CryptoError, CryptoMode, MIN_STREAM_CHUNK_SIZE, SegmentationPolicy};
use todo_zstd::{
    CompressionMode, PipelineError, SEALED_STREAM_VERSION_MULTI_MODE, SEALED_STREAM_VERSION_STREAM,
    SealedStream, SegmentationStrategy, StreamCryptoPipeline,
};

const KEY: [u8; 32] = [0x5au8; 32];
const NONCE: [u8; 12] = [0xa5u8; 12];
const CHUNK: usize = 4096;

/// Mostly incompressible bytes (xorshift) with some repetition, so the compressed stream
/// spans several AEAD chunks.
fn sample(len: usize) -> Vec<u8> {
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    (0..len)
        .map(|i| {
            if i % 4 == 0 {
                b'z'
            } else {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            }
        })
        .collect()
}

fn stream_modes() -> impl Iterator<Item = CryptoMode> {
    CryptoMode::ALL
        .into_iter()
        .filter(|m| *m != CryptoMode::AesGcmSiv)
}

fn chunked(mode: CryptoMode, compression: CompressionMode) -> StreamCryptoPipeline {
    StreamCryptoPipeline::single_frame(3)
        .with_compression_mode(compression)
        .with_crypto_mode(mode)
        .with_stream_chunking(Some(CHUNK))
        .unwrap()
}

/// Byte length of one full chunk slot (ciphertext + embedded tag) in `sealed.ciphertext`.
fn slot(mode: CryptoMode) -> usize {
    CHUNK + mode.overhead()
}

#[test]
fn chunked_modes_roundtrip_and_serialize() {
    for mode in stream_modes() {
        for compression in [
            CompressionMode::SingleFrame,
            CompressionMode::IndependentFrames,
        ] {
            let pipeline = chunked(mode, compression);
            for len in [0, 1, 100, 40_000] {
                let data = sample(len);
                let (sealed, metrics) = pipeline
                    .compress_and_encrypt_with_metrics(&data, &KEY, &NONCE)
                    .unwrap();
                assert_eq!(sealed.version, SEALED_STREAM_VERSION_STREAM);
                assert_eq!(sealed.stream_chunk_size, Some(CHUNK as u32));
                assert_eq!(sealed.tag.len(), mode.tag_len());
                assert_eq!(metrics.aead_chunks, sealed.aead_chunks().unwrap());
                assert_eq!(
                    metrics.aead_chunks,
                    metrics.compressed_bytes.div_ceil(CHUNK).max(1)
                );
                let parsed = SealedStream::from_bytes(&sealed.to_bytes()).unwrap();
                assert_eq!(parsed, sealed);
                let json = serde_json::to_string(&sealed).unwrap();
                assert_eq!(serde_json::from_str::<SealedStream>(&json).unwrap(), sealed);
                let (out, open) = pipeline
                    .decrypt_and_decompress_with_metrics(&parsed, &KEY, &NONCE)
                    .unwrap();
                assert_eq!(out, data, "{mode} {compression:?} len {len}");
                assert_eq!(open.aead_chunks, metrics.aead_chunks);
                if len == 40_000 {
                    assert!(metrics.aead_chunks >= 3, "{mode}: {metrics:?}");
                }
            }
        }
    }
}

#[test]
fn chunk_boundaries_are_independent_of_zstd_frames() {
    let data = sample(100_000);
    let pipeline = StreamCryptoPipeline::new(16 * 1024, 3, 4096)
        .unwrap()
        .with_crypto_mode(CryptoMode::Aegis256)
        .with_stream_chunking(Some(CHUNK))
        .unwrap();
    let (sealed, m) = pipeline
        .compress_and_encrypt_with_metrics(&data, &KEY, &NONCE)
        .unwrap();
    // 7 frames of 16 KiB input vs. ~19 AEAD chunks of 4 KiB compressed bytes.
    assert_eq!(m.zstd_frames, 7);
    assert_eq!(m.aead_chunks, m.compressed_bytes.div_ceil(CHUNK));
    assert_ne!(m.aead_chunks, m.zstd_frames);
    // At least one frame boundary falls inside an AEAD chunk.
    let frame_ends: Vec<u64> = sealed
        .segments
        .iter()
        .scan(0u64, |end, seg| {
            *end += seg.compressed_size;
            Some(*end)
        })
        .collect();
    assert!(
        frame_ends
            .iter()
            .any(|e| !(*e as usize).is_multiple_of(CHUNK))
    );
    assert_eq!(
        pipeline
            .decrypt_and_decompress(&sealed, &KEY, &NONCE)
            .unwrap(),
        data
    );
}

#[test]
fn parallel_and_sequential_chunking_are_identical_and_interoperable() {
    let data = sample(60_000);
    for mode in stream_modes() {
        let par = chunked(mode, CompressionMode::SingleFrame)
            .with_segmentation(SegmentationStrategy::Adaptive(SegmentationPolicy::DEFAULT))
            .unwrap();
        let seq = chunked(mode, CompressionMode::SingleFrame)
            .with_segmentation(SegmentationStrategy::Sequential)
            .unwrap();
        let a = par.compress_and_encrypt(&data, &KEY, &NONCE).unwrap();
        let b = seq.compress_and_encrypt(&data, &KEY, &NONCE).unwrap();
        assert_eq!(a, b, "{mode}");
        assert_eq!(seq.decrypt_and_decompress(&a, &KEY, &NONCE).unwrap(), data);
        // A whole-message pipeline of the same mode reads the chunk size from the
        // authenticated header, and vice versa.
        let whole = StreamCryptoPipeline::single_frame(3).with_crypto_mode(mode);
        assert_eq!(
            whole.decrypt_and_decompress(&a, &KEY, &NONCE).unwrap(),
            data
        );
        let w = whole.compress_and_encrypt(&data, &KEY, &NONCE).unwrap();
        assert_eq!(w.version, SEALED_STREAM_VERSION_MULTI_MODE);
        assert_eq!(par.decrypt_and_decompress(&w, &KEY, &NONCE).unwrap(), data);
    }
}

#[test]
fn configuration_errors() {
    let aes = StreamCryptoPipeline::single_frame(3)
        .with_stream_chunking(Some(CHUNK))
        .unwrap();
    assert_eq!(
        aes.compress_and_encrypt(b"data", &KEY, &NONCE),
        Err(PipelineError::Crypto(
            CryptoError::StreamChunkingUnsupported(CryptoMode::AesGcmSiv)
        ))
    );
    for bad in [0, MIN_STREAM_CHUNK_SIZE - 1] {
        assert!(matches!(
            StreamCryptoPipeline::single_frame(3).with_stream_chunking(Some(bad)),
            Err(PipelineError::Crypto(CryptoError::InvalidStreamChunkSize(
                _
            )))
        ));
    }
    // AES-GCM-SIV JSON is unchanged (no chunk field).
    let sealed = StreamCryptoPipeline::single_frame(3)
        .compress_and_encrypt(b"data", &KEY, &NONCE)
        .unwrap();
    assert!(
        !serde_json::to_string(&sealed)
            .unwrap()
            .contains("stream_chunk_size")
    );
}

#[test]
fn transposition_duplication_and_truncation_are_rejected() {
    let data = sample(40_000);
    for mode in stream_modes().filter(|m| m.is_authenticated()) {
        let pipeline = chunked(mode, CompressionMode::SingleFrame);
        let sealed = pipeline.compress_and_encrypt(&data, &KEY, &NONCE).unwrap();
        let n = sealed.aead_chunks().unwrap();
        assert!(n >= 3);
        let s = slot(mode);
        let auth_failed = |st: &SealedStream| {
            matches!(
                pipeline.decrypt_and_decompress(st, &KEY, &NONCE),
                Err(PipelineError::Crypto(CryptoError::AuthenticationFailed))
            )
        };

        // Swap chunk slots 0 and 1 (each with its own valid tag).
        let mut swapped = sealed.clone();
        let (a, rest) = swapped.ciphertext.split_at_mut(s);
        a.swap_with_slice(&mut rest[..s]);
        assert!(auth_failed(&swapped), "{mode}: transposition accepted");

        // Duplicate chunk 0 into slot 1.
        let mut dup = sealed.clone();
        let first = dup.ciphertext[..s].to_vec();
        dup.ciphertext[s..2 * s].copy_from_slice(&first);
        assert!(auth_failed(&dup), "{mode}: duplication accepted");

        // Truncation: drop the final chunk; chunk n-2 claims to be final. The declared
        // frame sizes are adjusted too, so only the cryptographic check can catch it.
        let mut truncated = sealed.clone();
        let end = (n - 2) * s + CHUNK + mode.ciphertext_expansion();
        truncated.tag = truncated.ciphertext[end..end + mode.tag_len()].to_vec();
        truncated.ciphertext.truncate(end);
        let removed = sealed.payload_len().unwrap() - truncated.payload_len().unwrap();
        truncated.segments[0].compressed_size -= removed as u64;
        assert!(auth_failed(&truncated), "{mode}: truncation accepted");

        // Header relabelling: another valid chunk size, or v3 -> v2.
        let mut relabel = sealed.clone();
        relabel.stream_chunk_size = Some(2 * CHUNK as u32);
        assert!(
            pipeline
                .decrypt_and_decompress(&relabel, &KEY, &NONCE)
                .is_err()
        );
        let mut downgraded = sealed.clone();
        downgraded.version = SEALED_STREAM_VERSION_MULTI_MODE;
        downgraded.stream_chunk_size = None;
        assert!(
            pipeline
                .decrypt_and_decompress(&downgraded, &KEY, &NONCE)
                .is_err()
        );

        assert_eq!(
            pipeline
                .decrypt_and_decompress(&sealed, &KEY, &NONCE)
                .unwrap(),
            data
        );
    }
}

#[test]
fn malformed_version_3_headers_are_rejected() {
    let pipeline = chunked(CryptoMode::AsconAead128, CompressionMode::SingleFrame);
    let sealed = pipeline
        .compress_and_encrypt(&sample(10_000), &KEY, &NONCE)
        .unwrap();
    let bytes = sealed.to_bytes();
    // magic(4) || version(1) || mode(1) || chunk_size u32 LE at offset 6.
    let mut bad = bytes.clone();
    bad[6..10].copy_from_slice(&16u32.to_le_bytes());
    assert!(matches!(
        SealedStream::from_bytes(&bad),
        Err(PipelineError::MalformedStream(_))
    ));
    let mut missing = sealed.clone();
    missing.stream_chunk_size = None;
    assert!(matches!(
        missing.validate_header(),
        Err(PipelineError::MalformedStream(_))
    ));
    let mut v2_with_chunk = sealed.clone();
    v2_with_chunk.version = SEALED_STREAM_VERSION_MULTI_MODE;
    assert!(matches!(
        v2_with_chunk.validate_header(),
        Err(PipelineError::MalformedStream(_))
    ));
}

#[test]
fn verification_report_proves_chunk_order_and_final_flag() {
    let data = sample(50_000);
    for mode in stream_modes() {
        let report = chunked(mode, CompressionMode::SingleFrame)
            .verify_pipeline_with_tag_proof(&data, &KEY, &NONCE)
            .unwrap();
        assert_eq!(report.stream_chunk_size, Some(CHUNK));
        assert!(report.aead_chunks >= 3);
        assert!(report.stream_parallel_exercised);
        assert!(report.pipeline_roundtrip_verified);
        if mode.is_authenticated() {
            assert_eq!(report.chunk_transposition_rejected, Some(true), "{mode}");
            assert_eq!(report.chunk_truncation_rejected, Some(true), "{mode}");
            assert_eq!(report.tamper_rejected, Some(true));
        } else {
            assert_eq!(report.chunk_transposition_rejected, None);
            assert_eq!(report.chunk_truncation_rejected, None);
        }
    }
    let whole = StreamCryptoPipeline::single_frame(3)
        .with_crypto_mode(CryptoMode::Aegis256)
        .verify_pipeline_with_tag_proof(&data, &KEY, &NONCE)
        .unwrap();
    assert_eq!(whole.aead_chunks, 1);
    assert!(!whole.stream_parallel_exercised);
    assert_eq!(whole.chunk_transposition_rejected, None);
}
