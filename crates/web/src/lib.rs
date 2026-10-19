//! Web console (Askama pages + same-origin API server) and web-facing helpers for
//! verification and client-side recovery.

pub mod pages;
pub mod server;

use serde::{Deserialize, Serialize};
use todo_crypto::{CryptoError, assert_polyval_equivalence};
use todo_zstd::{PipelineError, SealedStream, StreamCryptoPipeline};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebPipelineResponse {
    pub success: bool,
    pub message: String,
    pub payload_bytes: usize,
    pub tag_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebEquivalenceResponse {
    pub verified: bool,
    pub sequential_tag: String,
    pub parallel_tag: String,
    pub speedup: f64,
}

/// Check sequential vs. segment-parallel POLYVAL on `data` with a fixed test key.
pub fn verify_web_equivalence(
    data: &[u8],
    segment_size: usize,
) -> Result<WebEquivalenceResponse, CryptoError> {
    let h_key = [0x5cu8; 16];
    let report = assert_polyval_equivalence(&h_key, data, segment_size)?;
    Ok(WebEquivalenceResponse {
        verified: report.is_bit_identical,
        sequential_tag: report.sequential_tag_hex,
        parallel_tag: report.parallel_tag_hex,
        speedup: report.speedup_ratio,
    })
}

/// Verify, decrypt and decompress a sealed stream using the authenticated crypto mode
/// recorded in it. Streams of the unauthenticated `xchacha20` mode are refused
/// ([`PipelineError::CryptoModeMismatch`]).
pub fn web_decrypt_and_decompress(
    sealed: &SealedStream,
    key: &[u8],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, PipelineError> {
    let mut pipeline = StreamCryptoPipeline::default();
    if sealed.crypto_mode.is_authenticated() {
        pipeline = pipeline.with_crypto_mode(sealed.crypto_mode);
    }
    pipeline.decrypt_and_decompress(sealed, key, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_verification_and_pipeline() {
        let data = b"Testing Web/WASM payload verification for AES-GCM-SIV and Zstandard";
        let res = verify_web_equivalence(data, 16).unwrap();
        assert!(res.verified);
        assert_eq!(res.sequential_tag, res.parallel_tag);

        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let sealed = StreamCryptoPipeline::default()
            .compress_and_encrypt(data, &key, &nonce)
            .unwrap();
        assert_eq!(
            web_decrypt_and_decompress(&sealed, &key, &nonce).unwrap(),
            data
        );

        for mode in todo_crypto::CryptoMode::ALL {
            let sealed = StreamCryptoPipeline::default()
                .with_crypto_mode(mode)
                .compress_and_encrypt(data, &key, &nonce)
                .unwrap();
            let res = web_decrypt_and_decompress(&sealed, &key, &nonce);
            if mode.is_authenticated() {
                assert_eq!(res.unwrap(), data);
            } else {
                assert!(matches!(res, Err(PipelineError::CryptoModeMismatch { .. })));
            }
        }
    }
}
