//! In-place AES-GCM-SIV (used for memory-mapped files) must be byte-identical to the
//! copying implementation, the RFC 8452 vectors and upstream `aes-gcm-siv`.

mod common;

use common::rfc8452_vectors::RFC8452_VECTORS;
use todo_crypto::{
    CryptoError, FallbackReason, SegmentPlan, aes_gcm_siv_decrypt_in_place_planned,
    aes_gcm_siv_decrypt_in_place_polyval_parallel, aes_gcm_siv_decrypt_in_place_sequential,
    aes_gcm_siv_decrypt_upstream, aes_gcm_siv_encrypt_in_place_planned,
    aes_gcm_siv_encrypt_in_place_polyval_parallel, aes_gcm_siv_encrypt_in_place_sequential,
    aes_gcm_siv_encrypt_upstream,
};

#[test]
fn rfc8452_vectors_in_place() {
    for (i, v) in RFC8452_VECTORS.iter().enumerate() {
        let (expected_ct, expected_tag) = v.result.split_at(v.result.len() - 16);
        let mut buf = v.plaintext.to_vec();
        let tag =
            aes_gcm_siv_encrypt_in_place_sequential(v.key, &v.nonce, v.aad, &mut buf).unwrap();
        assert_eq!(
            (buf.as_slice(), &tag[..]),
            (expected_ct, expected_tag),
            "seq {} #{i}",
            v.section
        );
        for seg in [16, 32, 48] {
            let mut buf = v.plaintext.to_vec();
            let tag = aes_gcm_siv_encrypt_in_place_polyval_parallel(
                v.key, &v.nonce, v.aad, &mut buf, seg,
            )
            .unwrap();
            assert_eq!(
                (buf.as_slice(), &tag[..]),
                (expected_ct, expected_tag),
                "par seg={seg} {} #{i}",
                v.section
            );
        }
    }
}

#[test]
fn in_place_matches_upstream_on_edge_lengths() {
    let nonce = [0x5au8; 12];
    let aad = b"ZSGS\x01 authenticated header";
    for key in [vec![0x11u8; 16], vec![0x22u8; 32]] {
        for len in [0usize, 1, 15, 16, 17, 31, 33, 4095, 4096, 4097, 70_001] {
            let pt: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            let up = aes_gcm_siv_encrypt_upstream(&key, &nonce, aad, &pt).unwrap();
            let plans = [
                SegmentPlan::Sequential {
                    reason: FallbackReason::Forced,
                },
                SegmentPlan::fixed(len, 16),
                SegmentPlan::fixed(len, 4096),
            ];
            for plan in plans {
                let mut buf = pt.clone();
                let tag = aes_gcm_siv_encrypt_in_place_planned(&key, &nonce, aad, &mut buf, &plan)
                    .unwrap();
                assert_eq!(buf, up.ciphertext, "len={len} plan={plan:?}");
                assert_eq!(tag, up.tag, "len={len} plan={plan:?}");
                let back = aes_gcm_siv_decrypt_upstream(&key, &nonce, aad, &buf, &tag).unwrap();
                assert_eq!(back, pt);
            }
        }
    }
}

#[test]
fn rfc8452_vectors_decrypt_in_place() {
    for (i, v) in RFC8452_VECTORS.iter().enumerate() {
        let (ct, tag) = v.result.split_at(v.result.len() - 16);
        let tag: [u8; 16] = tag.try_into().unwrap();
        let mut buf = ct.to_vec();
        aes_gcm_siv_decrypt_in_place_sequential(v.key, &v.nonce, v.aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, v.plaintext, "seq {} #{i}", v.section);
        for seg in [16, 32, 48] {
            let mut buf = ct.to_vec();
            aes_gcm_siv_decrypt_in_place_polyval_parallel(
                v.key, &v.nonce, v.aad, &mut buf, &tag, seg,
            )
            .unwrap();
            assert_eq!(buf, v.plaintext, "par seg={seg} {} #{i}", v.section);
        }
    }
}

/// (ciphertext, nonce, AAD, tag)
type Case<'a> = (&'a [u8], [u8; 12], &'a [u8], [u8; 16]);

#[test]
fn decrypt_in_place_rejects_tampering_and_zeroes_buffer() {
    let key = [0x33u8; 32];
    let nonce = [0x44u8; 12];
    let aad = b"header";
    let pt: Vec<u8> = (0..70_001).map(|i| (i * 7 + 1) as u8).collect();
    let up = aes_gcm_siv_encrypt_upstream(&key, &nonce, aad, &pt).unwrap();
    let plans = [
        SegmentPlan::Sequential {
            reason: FallbackReason::Forced,
        },
        SegmentPlan::fixed(pt.len(), 4096),
    ];
    for plan in plans {
        let mut buf = up.ciphertext.clone();
        aes_gcm_siv_decrypt_in_place_planned(&key, &nonce, aad, &mut buf, &up.tag, &plan).unwrap();
        assert_eq!(buf, pt);

        let mut bad_tag = up.tag;
        bad_tag[0] ^= 1;
        let mut bad_nonce = nonce;
        bad_nonce[11] ^= 1;
        let mut bad_ct = up.ciphertext.clone();
        bad_ct[40_000] ^= 0x80;
        let cases: [Case; 4] = [
            (&bad_ct, nonce, aad, up.tag),
            (&up.ciphertext, nonce, aad, bad_tag),
            (&up.ciphertext, nonce, b"headeR", up.tag),
            (&up.ciphertext, bad_nonce, aad, up.tag),
        ];
        for (ct, n, a, t) in cases {
            let mut buf = ct.to_vec();
            assert_eq!(
                aes_gcm_siv_decrypt_in_place_planned(&key, &n, a, &mut buf, &t, &plan),
                Err(CryptoError::AuthenticationFailed)
            );
            assert!(
                buf.iter().all(|&b| b == 0),
                "unauthenticated plaintext left"
            );
        }
    }
}
