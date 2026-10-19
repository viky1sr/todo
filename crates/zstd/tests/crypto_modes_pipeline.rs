//! Pipeline tests for the selectable `crypto_mode`.

use todo_crypto::{CryptoError, CryptoMode, FallbackReason, SegmentPlan};
use todo_zstd::{
    CompressionMode, PipelineError, SEALED_STREAM_VERSION, SEALED_STREAM_VERSION_MULTI_MODE,
    SealedStream, StreamCryptoPipeline,
};

const KEY: [u8; 32] = [0x6bu8; 32];
const NONCE: [u8; 12] = [0x3cu8; 12];

fn sample(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| {
            if i % 7 == 0 {
                (i % 251) as u8
            } else {
                b'a' + (i % 5) as u8
            }
        })
        .collect()
}

fn pipelines(mode: CryptoMode) -> [StreamCryptoPipeline; 2] {
    [
        StreamCryptoPipeline::single_frame(3).with_crypto_mode(mode),
        StreamCryptoPipeline::new(16 * 1024, 3, 4096)
            .unwrap()
            .with_compression_mode(CompressionMode::IndependentFrames)
            .with_crypto_mode(mode),
    ]
}

#[test]
fn every_mode_roundtrips_and_serializes() {
    for mode in CryptoMode::ALL {
        for pipeline in pipelines(mode) {
            for len in [0, 1, 17, 100_000] {
                let data = sample(len);
                let sealed = pipeline.compress_and_encrypt(&data, &KEY, &NONCE).unwrap();
                assert_eq!(sealed.crypto_mode, mode);
                assert_eq!(sealed.tag.len(), mode.tag_len());
                let expected_version = if mode == CryptoMode::AesGcmSiv {
                    SEALED_STREAM_VERSION
                } else {
                    SEALED_STREAM_VERSION_MULTI_MODE
                };
                assert_eq!(sealed.version, expected_version);

                let parsed = SealedStream::from_bytes(&sealed.to_bytes()).unwrap();
                assert_eq!(parsed, sealed);
                let json = serde_json::to_string(&sealed).unwrap();
                assert_eq!(serde_json::from_str::<SealedStream>(&json).unwrap(), sealed);

                let out = pipeline
                    .decrypt_and_decompress(&parsed, &KEY, &NONCE)
                    .unwrap();
                assert_eq!(out, data, "{mode} len {len}");
            }
        }
    }
}

#[test]
fn aes_gcm_siv_keeps_version_1_wire_format() {
    let data = sample(5000);
    let sealed = StreamCryptoPipeline::single_frame(3)
        .compress_and_encrypt(&data, &KEY, &NONCE)
        .unwrap();
    let bytes = sealed.to_bytes();
    assert_eq!(&bytes[..5], b"ZSGS\x01");
    // segment_count follows the version byte directly (no mode byte in v1).
    assert_eq!(&bytes[5..13], &1u64.to_le_bytes());
    // Legacy JSON without `crypto_mode` still parses as AES-GCM-SIV.
    let mut v = serde_json::to_value(&sealed).unwrap();
    v.as_object_mut().unwrap().remove("crypto_mode");
    let legacy: SealedStream = serde_json::from_value(v).unwrap();
    assert_eq!(legacy.crypto_mode, CryptoMode::AesGcmSiv);
    assert_eq!(
        StreamCryptoPipeline::default()
            .decrypt_and_decompress(&legacy, &KEY, &NONCE)
            .unwrap(),
        data
    );
}

#[test]
fn mode_byte_is_authenticated() {
    let data = sample(4000);
    let sealed = StreamCryptoPipeline::single_frame(3)
        .with_crypto_mode(CryptoMode::XChaCha20Poly1305)
        .compress_and_encrypt(&data, &KEY, &NONCE)
        .unwrap();
    let mut bytes = sealed.to_bytes();
    assert_eq!(bytes[4], SEALED_STREAM_VERSION_MULTI_MODE);
    assert_eq!(bytes[5], CryptoMode::XChaCha20Poly1305.id());
    // Relabel as Ascon-AEAD128 (same tag length): parses, but authentication fails.
    bytes[5] = CryptoMode::AsconAead128.id();
    let relabeled = SealedStream::from_bytes(&bytes).unwrap();
    assert_eq!(
        StreamCryptoPipeline::single_frame(3)
            .with_crypto_mode(CryptoMode::AsconAead128)
            .decrypt_and_decompress(&relabeled, &KEY, &NONCE),
        Err(PipelineError::Crypto(CryptoError::AuthenticationFailed))
    );
    // v2 header claiming AES-GCM-SIV is rejected as malformed.
    bytes[5] = CryptoMode::AesGcmSiv.id();
    assert!(matches!(
        SealedStream::from_bytes(&bytes),
        Err(PipelineError::MalformedStream(_))
    ));
    bytes[5] = 0xee;
    assert!(matches!(
        SealedStream::from_bytes(&bytes),
        Err(PipelineError::Crypto(CryptoError::UnknownCryptoMode(_)))
    ));
}

#[test]
fn pipeline_rejects_other_modes_and_inconsistent_headers() {
    let data = sample(3000);
    let sealed = StreamCryptoPipeline::single_frame(3)
        .with_crypto_mode(CryptoMode::Aegis256)
        .compress_and_encrypt(&data, &KEY, &NONCE)
        .unwrap();
    assert_eq!(
        StreamCryptoPipeline::single_frame(3).decrypt_and_decompress(&sealed, &KEY, &NONCE),
        Err(PipelineError::CryptoModeMismatch {
            expected: CryptoMode::AesGcmSiv,
            found: CryptoMode::Aegis256
        })
    );
    // An attacker relabelling a stream as unauthenticated XChaCha20 is refused by a
    // pipeline configured for an authenticated mode.
    let mut downgrade = sealed.clone();
    downgrade.crypto_mode = CryptoMode::XChaCha20;
    downgrade.tag.clear();
    assert!(matches!(
        StreamCryptoPipeline::single_frame(3)
            .with_crypto_mode(CryptoMode::Aegis256)
            .decrypt_and_decompress(&downgrade, &KEY, &NONCE),
        Err(PipelineError::CryptoModeMismatch { .. })
    ));

    let aegis = StreamCryptoPipeline::single_frame(3).with_crypto_mode(CryptoMode::Aegis256);
    let mut short_tag = sealed.clone();
    short_tag.tag.truncate(16);
    assert!(matches!(
        aegis.decrypt_and_decompress(&short_tag, &KEY, &NONCE),
        Err(PipelineError::MalformedStream(_))
    ));
    let mut wrong_version = sealed.clone();
    wrong_version.version = SEALED_STREAM_VERSION;
    assert!(matches!(
        aegis.decrypt_and_decompress(&wrong_version, &KEY, &NONCE),
        Err(PipelineError::MalformedStream(_))
    ));
    let mut tampered = sealed;
    tampered.segments[0].uncompressed_size -= 1;
    assert_eq!(
        aegis.decrypt_and_decompress(&tampered, &KEY, &NONCE),
        Err(PipelineError::Crypto(CryptoError::AuthenticationFailed))
    );
}

#[test]
fn cascade_layout_and_decompression_limit() {
    let data = sample(50_000);
    let pipeline = StreamCryptoPipeline::single_frame(3)
        .with_crypto_mode(CryptoMode::CascadeXChaCha20Poly1305Aegis256);
    let (sealed, metrics) = pipeline
        .compress_and_encrypt_with_metrics(&data, &KEY, &NONCE)
        .unwrap();
    assert_eq!(sealed.ciphertext.len(), metrics.compressed_bytes + 16);
    assert_eq!(sealed.tag.len(), 32);
    assert_eq!(
        metrics.plan,
        SegmentPlan::Sequential {
            reason: FallbackReason::NotApplicable
        }
    );
    let limited = StreamCryptoPipeline::single_frame(3)
        .with_crypto_mode(CryptoMode::CascadeXChaCha20Poly1305Aegis256)
        .with_max_decompressed_size(1000);
    assert!(matches!(
        limited.decrypt_and_decompress(&sealed, &KEY, &NONCE),
        Err(PipelineError::DecompressedSizeLimitExceeded { .. })
    ));
}

#[test]
fn verification_report_per_mode() {
    let data = sample(300_000);
    for mode in CryptoMode::ALL {
        let r = StreamCryptoPipeline::single_frame(3)
            .with_crypto_mode(mode)
            .verify_pipeline_with_tag_proof(&data, &KEY, &NONCE)
            .unwrap();
        assert_eq!(r.crypto_mode, mode);
        assert_eq!(r.authenticated, mode.is_authenticated());
        assert_eq!(r.tag_size_bytes, mode.tag_len());
        assert_eq!(r.crypto_overhead_bytes, mode.overhead());
        assert!(r.pipeline_roundtrip_verified && r.deterministic_reencryption);
        if mode == CryptoMode::AesGcmSiv {
            assert!(r.aes_gcm_siv_equivalence.unwrap().is_bit_identical);
        } else {
            assert!(r.aes_gcm_siv_equivalence.is_none());
            assert!(!r.parallel_path_exercised);
        }
        assert_eq!(
            r.tamper_rejected,
            mode.is_authenticated().then_some(true),
            "{mode}"
        );
    }
}
