use todo_crypto::CryptoError;
use todo_zstd::{PipelineError, SealedStream, StreamCryptoPipeline, ZstdSegment};

const KEY: [u8; 16] = [0x88; 16];
const NONCE: [u8; 12] = [0x55; 12];

fn sample(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| if i % 4 == 0 { (i % 251) as u8 } else { 0x5a })
        .collect()
}

#[test]
fn end_to_end_pipeline_with_tag_equivalence() {
    let pipeline = StreamCryptoPipeline::new(64 * 1024, 3, 16 * 1024).unwrap();
    let data = sample(1024 * 1024);

    let report = pipeline
        .verify_pipeline_with_tag_proof(&data, &KEY, &NONCE)
        .unwrap();

    assert!(report.pipeline_roundtrip_verified);
    assert!(report.standard_zstd_decoder_roundtrip);
    let eq = report.aes_gcm_siv_equivalence.as_ref().unwrap();
    assert!(eq.is_bit_identical);
    assert_eq!(eq.sequential_tag_hex, eq.parallel_tag_hex);
    assert_eq!(
        eq.upstream_tag_hex.as_deref(),
        Some(eq.parallel_tag_hex.as_str())
    );
    assert_eq!(report.zstd_frames, 16);
    assert!(report.compression_ratio_percent < 100.0);
    assert!(report.single_frame_compressed_size_bytes <= report.compressed_size_bytes);
}

#[test]
fn roundtrip_various_sizes() {
    let pipeline = StreamCryptoPipeline::new(4096, 3, 32).unwrap();
    for len in [0usize, 1, 15, 16, 17, 4095, 4096, 4097, 50_000] {
        let data = sample(len);
        let sealed = pipeline.compress_and_encrypt(&data, &KEY, &NONCE).unwrap();
        assert_eq!(sealed.segments.len(), len.div_ceil(4096));
        assert_eq!(
            pipeline
                .decrypt_and_decompress(&sealed, &KEY, &NONCE)
                .unwrap(),
            data
        );

        let parsed = SealedStream::from_bytes(&sealed.to_bytes()).unwrap();
        assert_eq!(parsed, sealed);
    }
}

#[test]
fn concatenated_frames_are_a_standard_zstd_stream() {
    let pipeline = StreamCryptoPipeline::new(8192, 3, 64).unwrap();
    let data = sample(100_000);
    let sealed = pipeline.compress_and_encrypt(&data, &KEY, &NONCE).unwrap();
    let stream = todo_crypto::aes_gcm_siv_decrypt_upstream(
        &KEY,
        &NONCE,
        &sealed.associated_data(),
        &sealed.ciphertext,
        sealed.tag.as_slice().try_into().unwrap(),
    )
    .unwrap();
    assert_eq!(zstd::stream::decode_all(stream.as_slice()).unwrap(), data);
}

#[test]
fn tampering_is_detected_before_decompression() {
    let pipeline = StreamCryptoPipeline::new(4096, 3, 64).unwrap();
    let data = sample(20_000);
    let sealed = pipeline.compress_and_encrypt(&data, &KEY, &NONCE).unwrap();
    let auth_failed = Err(PipelineError::Crypto(CryptoError::AuthenticationFailed));

    let mut s = sealed.clone();
    s.ciphertext[0] ^= 1;
    assert_eq!(
        pipeline.decrypt_and_decompress(&s, &KEY, &NONCE),
        auth_failed
    );

    let mut s = sealed.clone();
    s.segments.swap(0, 1);
    assert_eq!(
        pipeline.decrypt_and_decompress(&s, &KEY, &NONCE),
        auth_failed
    );

    // Dropping a descriptor breaks the declared layout, which is rejected even earlier.
    let mut s = sealed.clone();
    s.segments.pop();
    assert!(matches!(
        pipeline.decrypt_and_decompress(&s, &KEY, &NONCE),
        Err(PipelineError::MalformedStream(_))
    ));

    let mut s = sealed.clone();
    s.segments[0].uncompressed_size += 1;
    assert_eq!(
        pipeline.decrypt_and_decompress(&s, &KEY, &NONCE),
        auth_failed
    );

    let mut s = sealed;
    s.tag[15] ^= 0x01;
    assert_eq!(
        pipeline.decrypt_and_decompress(&s, &KEY, &NONCE),
        auth_failed
    );
}

#[test]
fn rejects_invalid_polyval_segment_size() {
    assert!(matches!(
        StreamCryptoPipeline::new(4096, 3, 1000),
        Err(PipelineError::Crypto(CryptoError::InvalidSegmentSize(1000)))
    ));
}

#[test]
fn malformed_serialized_stream_is_rejected() {
    assert!(SealedStream::from_bytes(b"").is_err());
    assert!(SealedStream::from_bytes(b"XXXX\x01").is_err());
    let pipeline = StreamCryptoPipeline::default();
    let mut bytes = pipeline
        .compress_and_encrypt(b"hello", &KEY, &NONCE)
        .unwrap()
        .to_bytes();
    bytes.push(0);
    assert!(SealedStream::from_bytes(&bytes).is_err());
}

#[test]
fn segment_framing_serde() {
    let seg = ZstdSegment {
        segment_id: 42,
        is_last: true,
        uncompressed_size: 131_072,
        compressed_data: vec![0x11, 0x22, 0x33, 0x44, 0x55],
    };
    assert_eq!(ZstdSegment::from_bytes(&seg.to_bytes()).unwrap(), seg);
}
