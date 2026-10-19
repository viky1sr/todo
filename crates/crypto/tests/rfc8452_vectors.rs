//! All RFC 8452 Appendix C test vectors against every implementation in this crate.

mod common;

use common::rfc8452_vectors::RFC8452_VECTORS;
use todo_crypto::{
    CryptoError, aes_gcm_siv_decrypt_ctr_parallel, aes_gcm_siv_decrypt_parallel,
    aes_gcm_siv_decrypt_polyval_parallel, aes_gcm_siv_decrypt_sequential,
    aes_gcm_siv_decrypt_upstream, aes_gcm_siv_encrypt_ctr_parallel,
    aes_gcm_siv_encrypt_parallel, aes_gcm_siv_encrypt_polyval_parallel,
    aes_gcm_siv_encrypt_sequential,
    aes_gcm_siv_encrypt_upstream, build_polyval_record, derive_keys, polyval_parallel,
    polyval_sequential,
};

const SEGMENT_SIZES: [usize; 3] = [16, 32, 48];

#[test]
fn vector_count() {
    // C.1: 24 vectors, C.2: 24 vectors, C.3: 2 vectors.
    assert_eq!(RFC8452_VECTORS.len(), 50);
}

#[test]
fn key_derivation_and_polyval() {
    for (i, v) in RFC8452_VECTORS.iter().enumerate() {
        let keys = derive_keys(v.key, &v.nonce).unwrap();
        assert_eq!(keys.auth_key, v.auth_key, "auth key, {} #{i}", v.section);

        let record = build_polyval_record(v.aad, v.plaintext);
        assert_eq!(record, v.polyval_input, "POLYVAL input, {} #{i}", v.section);
        assert_eq!(polyval_sequential(&v.auth_key, &record), v.polyval_result);
        for seg in SEGMENT_SIZES {
            assert_eq!(
                polyval_parallel(&v.auth_key, &record, seg).unwrap(),
                v.polyval_result,
                "parallel POLYVAL seg={seg}, {} #{i}",
                v.section
            );
        }
    }
}

#[test]
fn encryption_matches_rfc() {
    for (i, v) in RFC8452_VECTORS.iter().enumerate() {
        let (expected_ct, expected_tag) = v.result.split_at(v.plaintext.len());

        let mut outputs = vec![
            (
                "sequential",
                aes_gcm_siv_encrypt_sequential(v.key, &v.nonce, v.aad, v.plaintext),
            ),
            (
                "upstream",
                aes_gcm_siv_encrypt_upstream(v.key, &v.nonce, v.aad, v.plaintext),
            ),
        ];
        for seg in SEGMENT_SIZES {
            outputs.push((
                "PS_polyval_parallel",
                aes_gcm_siv_encrypt_polyval_parallel(
                    v.key,
                    &v.nonce,
                    v.aad,
                    v.plaintext,
                    seg,
                ),
            ));
            outputs.push((
                "SP_ctr_parallel",
                aes_gcm_siv_encrypt_ctr_parallel(v.key, &v.nonce, v.aad, v.plaintext, seg),
            ));
            outputs.push((
                "PP_both_parallel",
                aes_gcm_siv_encrypt_parallel(v.key, &v.nonce, v.aad, v.plaintext, seg),
            ));
        }
        for (name, out) in outputs {
            let out = out.unwrap();
            assert_eq!(out.tag, v.tag, "{name} tag, {} #{i}", v.section);
            assert_eq!(out.tag.as_slice(), expected_tag);
            assert_eq!(out.ciphertext, expected_ct, "{name} ct, {} #{i}", v.section);
        }
    }
}

#[test]
fn decryption_matches_rfc_and_rejects_tampering() {
    for v in RFC8452_VECTORS {
        let (ct, tag) = v.result.split_at(v.plaintext.len());
        let tag: [u8; 16] = tag.try_into().unwrap();

        assert_eq!(
            aes_gcm_siv_decrypt_sequential(v.key, &v.nonce, v.aad, ct, &tag).unwrap(),
            v.plaintext
        );
        assert_eq!(
            aes_gcm_siv_decrypt_upstream(v.key, &v.nonce, v.aad, ct, &tag).unwrap(),
            v.plaintext
        );
        for seg in SEGMENT_SIZES {
            assert_eq!(
                aes_gcm_siv_decrypt_polyval_parallel(
                    v.key,
                    &v.nonce,
                    v.aad,
                    ct,
                    &tag,
                    seg,
                )
                .unwrap(),
                v.plaintext
            );
            assert_eq!(
                aes_gcm_siv_decrypt_ctr_parallel(v.key, &v.nonce, v.aad, ct, &tag, seg).unwrap(),
                v.plaintext
            );
            assert_eq!(
                aes_gcm_siv_decrypt_parallel(v.key, &v.nonce, v.aad, ct, &tag, seg).unwrap(),
                v.plaintext
            );
        }

        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        assert_eq!(
            aes_gcm_siv_decrypt_polyval_parallel(v.key, &v.nonce, v.aad, ct, &bad_tag, 16),
            Err(CryptoError::AuthenticationFailed)
        );
        if !ct.is_empty() {
            let mut bad_ct = ct.to_vec();
            bad_ct[ct.len() - 1] ^= 0x80;
            assert_eq!(
                aes_gcm_siv_decrypt_polyval_parallel(
                    v.key,
                    &v.nonce,
                    v.aad,
                    &bad_ct,
                    &tag,
                    16,
                ),
                Err(CryptoError::AuthenticationFailed)
            );
        }
    }
}
