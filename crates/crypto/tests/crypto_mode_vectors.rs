//! Known-answer and negative tests for the selectable `crypto_mode` variants.
//!
//! Sources of the published vectors:
//! - XChaCha20 / XChaCha20-Poly1305: draft-irtf-cfrg-xchacha-03, Appendix A.2 / A.3.1.
//! - Ascon-AEAD128: reference implementation KAT `LWC_AEAD_KAT_128_128.txt`
//!   (github.com/ascon/ascon-c, commit fdfca408), counts 1, 17, 34, 545, 1089.
//! - AEGIS-256: draft-irtf-cfrg-aegis-aead, Appendix A (test vectors 1–9, 256-bit tags).

use hex_literal::hex;
use todo_crypto::crypto_mode::{
    self, aegis256_open_in_place, aegis256_seal_in_place, ascon_aead128_open_in_place,
    ascon_aead128_seal_in_place, xchacha20_apply_keystream, xchacha20poly1305_open_in_place,
    xchacha20poly1305_seal_in_place,
};
use todo_crypto::{
    CryptoError, CryptoMode, FallbackReason, SegmentPlan, aes_gcm_siv_encrypt_upstream,
};

const XC_KEY: [u8; 32] = hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");

#[test]
fn xchacha20_draft_a2_vector() {
    let iv = hex!("404142434445464748494a4b4c4d4e4f5051525354555658");
    let plaintext = hex!(
        "5468652064686f6c65202870726f6e6f756e6365642022646f6c652229206973"
        "20616c736f206b6e6f776e2061732074686520417369617469632077696c6420"
        "646f672c2072656420646f672c20616e642077686973746c696e6720646f672e"
        "2049742069732061626f7574207468652073697a65206f662061204765726d61"
        "6e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061"
        "206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c"
        "757369766520616e6420736b696c6c6564206a756d70657220697320636c6173"
        "736966696564207769746820776f6c7665732c20636f796f7465732c206a6163"
        "6b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d6963"
        "2066616d696c792043616e696461652e"
    );
    let ciphertext = hex!(
        "7d0a2e6b7f7c65a236542630294e063b7ab9b555a5d5149aa21e4ae1e4fbce87"
        "ecc8e08a8b5e350abe622b2ffa617b202cfad72032a3037e76ffdcdc4376ee05"
        "3a190d7e46ca1de04144850381b9cb29f051915386b8a710b8ac4d027b8b050f"
        "7cba5854e028d564e453b8a968824173fc16488b8970cac828f11ae53cabd201"
        "12f87107df24ee6183d2274fe4c8b1485534ef2c5fbc1ec24bfc3663efaa08bc"
        "047d29d25043532db8391a8a3d776bf4372a6955827ccb0cdd4af403a7ce4c63"
        "d595c75a43e045f0cce1f29c8b93bd65afc5974922f214a40b7c402cdb91ae73"
        "c0b63615cdad0480680f16515a7ace9d39236464328a37743ffc28f4ddb324f4"
        "d0f5bbdc270c65b1749a6efff1fbaa09536175ccd29fb9e6057b307320d31683"
        "8a9c71f70b5b5907a66f7ea49aadc409"
    );
    // The draft's vector starts at block counter 1: skip the first 64 keystream bytes.
    let mut buf = vec![0u8; 64];
    buf.extend_from_slice(&plaintext);
    xchacha20_apply_keystream(&XC_KEY, &iv, &mut buf).unwrap();
    assert_eq!(&buf[64..], &ciphertext[..]);
}

#[test]
fn xchacha20poly1305_draft_a31_vector() {
    let nonce = hex!("404142434445464748494a4b4c4d4e4f5051525354555657");
    let aad = hex!("50515253c0c1c2c3c4c5c6c7");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let ciphertext = hex!(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
        "21f9664c97637da9768812f615c68b13b52e"
    );
    let tag = hex!("c0875924c1c7987947deafd8780acf49");

    let mut buf = plaintext.to_vec();
    let got = xchacha20poly1305_seal_in_place(&XC_KEY, &nonce, &aad, &mut buf).unwrap();
    assert_eq!(buf, ciphertext);
    assert_eq!(got, tag);

    xchacha20poly1305_open_in_place(&XC_KEY, &nonce, &aad, &mut buf, &tag).unwrap();
    assert_eq!(buf, plaintext);

    let mut bad = ciphertext.to_vec();
    bad[0] ^= 1;
    assert_eq!(
        xchacha20poly1305_open_in_place(&XC_KEY, &nonce, &aad, &mut bad, &tag),
        Err(CryptoError::AuthenticationFailed)
    );
    assert!(
        bad.iter().all(|&b| b == 0),
        "buffer must be wiped on failure"
    );
}

#[test]
fn ascon_aead128_reference_kats() {
    let key = hex!("000102030405060708090A0B0C0D0E0F");
    let nonce = hex!("101112131415161718191A1B1C1D1E1F");
    // (PT, AD, CT || TAG)
    let cases: [(&[u8], &[u8], &[u8]); 5] = [
        (b"", b"", &hex!("4F9C278211BEC9316BF68F46EE8B2EC6")),
        (
            b"",
            &hex!("303132333435363738393A3B3C3D3E3F"),
            &hex!("E4230CDB8330EE9DC0CFD7C7B346E6DC"),
        ),
        (
            &hex!("20"),
            b"",
            &hex!("E8DD576ABA1CD3E6FC704DE02AEDB79588"),
        ),
        (
            &hex!("202122232425262728292A2B2C2D2E2F"),
            &hex!("303132333435363738393A3B3C3D3E3F"),
            &hex!("6373EBB28BE97C9BAC090CF399C13EF13ABFC0D209E8F4844C90814D13F32C59"),
        ),
        (
            &hex!("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"),
            &hex!("303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F"),
            &hex!(
                "CB34D04660A66DBFBE9C856601F5B8AA51A499B55AC8F7FBEFBC331A613EE9CD"
                "FD191750A47F211C0A15ED28173D7CAA"
            ),
        ),
    ];
    for (pt, ad, expected) in cases {
        let mut buf = pt.to_vec();
        let tag = ascon_aead128_seal_in_place(&key, &nonce, ad, &mut buf).unwrap();
        buf.extend_from_slice(&tag);
        assert_eq!(
            buf,
            expected,
            "Ascon-AEAD128 KAT mismatch for |PT|={}",
            pt.len()
        );

        let (ct, t) = expected.split_at(pt.len());
        let mut dec = ct.to_vec();
        ascon_aead128_open_in_place(&key, &nonce, ad, &mut dec, t.try_into().unwrap()).unwrap();
        assert_eq!(dec, pt);

        let mut bad_tag: [u8; 16] = t.try_into().unwrap();
        bad_tag[15] ^= 1;
        let mut dec = ct.to_vec();
        assert_eq!(
            ascon_aead128_open_in_place(&key, &nonce, ad, &mut dec, &bad_tag),
            Err(CryptoError::AuthenticationFailed)
        );
    }
}

/// (AD, MSG, CT, TAG256)
type AegisCase<'a> = (&'a [u8], &'a [u8], &'a [u8], [u8; 32]);
/// (key, nonce, AD, CT, TAG256)
type AegisNegative<'a> = (&'a [u8; 32], &'a [u8; 32], &'a [u8], &'a [u8], &'a [u8; 32]);

#[test]
fn aegis256_draft_vectors() {
    let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
    let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
    // (AD, MSG, CT, TAG256): test vectors 1-5.
    let cases: [AegisCase; 5] = [
        (
            b"",
            &[0u8; 16],
            &hex!("754fc3d8c973246dcc6d741412a4b236"),
            hex!("1181a1d18091082bf0266f66297d167d2e68b845f61a3b0527d31fc7b7b89f13"),
        ),
        (
            b"",
            b"",
            b"",
            hex!("6a348c930adbd654896e1666aad67de989ea75ebaa2b82fb588977b1ffec864a"),
        ),
        (
            &hex!("0001020304050607"),
            &hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            &hex!("f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711"),
            hex!("b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a"),
        ),
        (
            &hex!("0001020304050607"),
            &hex!("000102030405060708090a0b0c0d"),
            &hex!("f373079ed84b2709faee37358458"),
            hex!("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9"),
        ),
        (
            &hex!(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829"
            ),
            &hex!(
                "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
            ),
            &hex!(
                "57754a7d09963e7c787583a2e7b859bb24fa1e04d49fd550b2511a358e3bca252a9b1b8b30cc4a67"
            ),
            hex!("a3aca270c006094d71c20e6910b5161c0826df233d08919a566ec2c05990f734"),
        ),
    ];
    for (ad, msg, ct, tag) in cases {
        let mut buf = msg.to_vec();
        assert_eq!(aegis256_seal_in_place(&key, &nonce, ad, &mut buf), tag);
        assert_eq!(buf, ct);
        aegis256_open_in_place(&key, &nonce, ad, &mut buf, &tag).unwrap();
        assert_eq!(buf, msg);
    }

    // Test vectors 6-9: must fail verification.
    let ad = hex!("0001020304050607");
    let ct = hex!("f373079ed84b2709faee37358458");
    let tag = hex!("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9");
    let mut bad_ct = ct;
    bad_ct[13] ^= 1;
    let mut bad_ad = ad;
    bad_ad[7] ^= 0x0f;
    let mut bad_tag = tag;
    bad_tag[31] ^= 0x09;
    let negatives: [AegisNegative; 4] = [
        (&nonce, &key, &ad, &ct, &tag), // key and nonce swapped
        (&key, &nonce, &ad, &bad_ct, &tag),
        (&key, &nonce, &bad_ad, &ct, &tag),
        (&key, &nonce, &ad, &ct, &bad_tag),
    ];
    for (k, n, a, c, t) in negatives {
        let mut buf = c.to_vec();
        assert_eq!(
            aegis256_open_in_place(k, n, a, &mut buf, t),
            Err(CryptoError::AuthenticationFailed)
        );
        assert!(buf.iter().all(|&b| b == 0));
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 + 7) as u8).collect()
}

const SEQ: SegmentPlan = SegmentPlan::Sequential {
    reason: FallbackReason::NotApplicable,
};

#[test]
fn every_mode_roundtrips_and_reports_sizes() {
    let nonce = [0x24u8; 12];
    let aad = b"ZSGS header";
    for key_len in [16, 32] {
        let key = vec![0x5au8; key_len];
        for mode in CryptoMode::ALL {
            for len in [0, 1, 15, 16, 17, 31, 32, 33, 4096, 65_537] {
                let pt = pattern(len);
                let sealed = crypto_mode::seal(mode, &key, &nonce, aad, &pt, &SEQ).unwrap();
                assert_eq!(sealed.tag.len(), mode.tag_len(), "{mode}");
                assert_eq!(
                    sealed.ciphertext.len(),
                    len + mode.ciphertext_expansion(),
                    "{mode}"
                );
                if len >= 16 {
                    assert_ne!(&sealed.ciphertext[..16], &pt[..16], "{mode} must encrypt");
                }
                // Deterministic for identical (key, nonce, aad, pt).
                let again = crypto_mode::seal(mode, &key, &nonce, aad, &pt, &SEQ).unwrap();
                assert_eq!(sealed, again, "{mode}");
                let opened = crypto_mode::open(
                    mode,
                    &key,
                    &nonce,
                    aad,
                    &sealed.ciphertext,
                    &sealed.tag,
                    &SEQ,
                )
                .unwrap();
                assert_eq!(opened, pt, "{mode} len {len}");
            }
        }
    }
}

#[test]
fn aes_gcm_siv_mode_is_byte_identical_to_upstream() {
    let key = [0x3au8; 32];
    let nonce = [0x91u8; 12];
    let aad = b"Auth Header";
    let pt = pattern(200_000);
    let upstream = aes_gcm_siv_encrypt_upstream(&key, &nonce, aad, &pt).unwrap();
    for plan in [SEQ, SegmentPlan::fixed(pt.len(), 4096)] {
        let sealed =
            crypto_mode::seal(CryptoMode::AesGcmSiv, &key, &nonce, aad, &pt, &plan).unwrap();
        assert_eq!(sealed.ciphertext, upstream.ciphertext);
        assert_eq!(sealed.tag, upstream.tag.to_vec());
    }
}

#[test]
fn modes_are_independent_and_key_separated() {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let pt = pattern(1024);
    let outputs: Vec<_> = CryptoMode::ALL
        .iter()
        .map(|&m| crypto_mode::seal(m, &key, &nonce, b"", &pt, &SEQ).unwrap())
        .collect();
    for i in 0..outputs.len() {
        for j in i + 1..outputs.len() {
            assert_ne!(
                outputs[i].ciphertext[..1024],
                outputs[j].ciphertext[..1024],
                "{} vs {}",
                CryptoMode::ALL[i],
                CryptoMode::ALL[j]
            );
        }
    }
    // The cascade outer layer is not plain AEGIS-256 under the same master key.
    let aegis = &outputs[4];
    let cascade = &outputs[5];
    assert_ne!(aegis.tag, cascade.tag);
}

#[test]
fn authenticated_modes_reject_tampering_without_releasing_plaintext() {
    let key = [0x42u8; 32];
    let nonce = [0x07u8; 12];
    let aad = b"metadata";
    let pt = pattern(3000);
    for mode in CryptoMode::ALL.into_iter().filter(|m| m.is_authenticated()) {
        let s = crypto_mode::seal(mode, &key, &nonce, aad, &pt, &SEQ).unwrap();
        let open = |k: &[u8], n: &[u8; 12], a: &[u8], c: &[u8], t: &[u8]| {
            crypto_mode::open(mode, k, n, a, c, t, &SEQ)
        };
        let auth_failed = Err(CryptoError::AuthenticationFailed);

        let mut c = s.ciphertext.clone();
        c[1500] ^= 0x80;
        assert_eq!(
            open(&key, &nonce, aad, &c, &s.tag),
            auth_failed,
            "{mode} ct"
        );
        let last = s.ciphertext.len() - 1;
        let mut c = s.ciphertext.clone();
        c[last] ^= 1;
        assert_eq!(
            open(&key, &nonce, aad, &c, &s.tag),
            auth_failed,
            "{mode} ct tail"
        );
        let mut t = s.tag.clone();
        t[0] ^= 1;
        assert_eq!(
            open(&key, &nonce, aad, &s.ciphertext, &t),
            auth_failed,
            "{mode} tag"
        );
        assert_eq!(
            open(&key, &nonce, b"metadatA", &s.ciphertext, &s.tag),
            auth_failed,
            "{mode} aad"
        );
        let mut n = nonce;
        n[11] ^= 1;
        assert_eq!(
            open(&key, &n, aad, &s.ciphertext, &s.tag),
            auth_failed,
            "{mode} nonce"
        );
        let mut k = key;
        k[0] ^= 1;
        assert_eq!(
            open(&k, &nonce, aad, &s.ciphertext, &s.tag),
            auth_failed,
            "{mode} key"
        );
        // Truncated ciphertext.
        assert!(open(&key, &nonce, aad, &s.ciphertext[..last], &s.tag).is_err());
        // Wrong tag length.
        assert_eq!(
            open(&key, &nonce, aad, &s.ciphertext, &s.tag[1..]),
            Err(CryptoError::InvalidTagLength {
                expected: mode.tag_len(),
                actual: mode.tag_len() - 1
            })
        );
    }
}

#[test]
fn cascade_requires_both_layers() {
    let key = [0x99u8; 16];
    let nonce = [0x01u8; 12];
    let mode = CryptoMode::CascadeXChaCha20Poly1305Aegis256;
    let s = crypto_mode::seal(mode, &key, &nonce, b"", b"", &SEQ).unwrap();
    assert_eq!(
        s.ciphertext.len(),
        16,
        "empty message still carries the inner tag"
    );
    assert_eq!(
        crypto_mode::open(mode, &key, &nonce, b"", &s.ciphertext[..15], &s.tag, &SEQ),
        Err(CryptoError::CiphertextTooShort)
    );
}

#[test]
fn xchacha20_is_unauthenticated_and_malleable() {
    let key = [0x10u8; 32];
    let nonce = [0x20u8; 12];
    let mode = CryptoMode::XChaCha20;
    assert!(!mode.is_authenticated());
    let pt = b"transfer 100".to_vec();
    let mut s = crypto_mode::seal(mode, &key, &nonce, b"", &pt, &SEQ).unwrap();
    assert!(s.tag.is_empty());
    // Bit flips pass through undetected: this mode must never be the default.
    s.ciphertext[9] ^= b'1' ^ b'9';
    let out = crypto_mode::open(mode, &key, &nonce, b"", &s.ciphertext, &s.tag, &SEQ).unwrap();
    assert_eq!(out, b"transfer 900");
    assert_eq!(CryptoMode::default(), CryptoMode::AesGcmSiv);
}

#[test]
fn invalid_master_key_lengths_are_rejected() {
    for mode in CryptoMode::ALL {
        for len in [0, 15, 24, 33] {
            assert_eq!(
                crypto_mode::seal(mode, &vec![0; len], &[0; 12], b"", b"x", &SEQ),
                Err(CryptoError::InvalidKeyLength(len)),
                "{mode}"
            );
        }
    }
}
