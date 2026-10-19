//! Empirical equivalence: tree-POLYVAL and all AES-GCM-SIV execution modes match the
//! sequential baseline and upstream `aes-gcm-siv` implementation.

mod common;

use common::SplitMix64;
use todo_crypto::{
    CryptoError, aes_gcm_siv_decrypt_ctr_parallel, aes_gcm_siv_decrypt_parallel,
    aes_gcm_siv_decrypt_polyval_parallel, aes_gcm_siv_decrypt_upstream,
    aes_gcm_siv_encrypt_ctr_parallel, aes_gcm_siv_encrypt_parallel,
    aes_gcm_siv_encrypt_polyval_parallel, aes_gcm_siv_encrypt_sequential,
    aes_gcm_siv_encrypt_upstream, assert_aes_gcm_siv_equivalence, assert_polyval_equivalence,
    polyval_parallel, polyval_parallel_linear_reduce, polyval_sequential,
};

const KEYS: [&[u8]; 2] = [&[0x4f; 16], &[0xa7; 32]];
const NONCE: [u8; 12] = [0x1b; 12];

fn edge_lengths(segment: usize) -> Vec<usize> {
    vec![
        0,
        1,
        15,
        16,
        17,
        segment - 1,
        segment,
        segment + 1,
        2 * segment,
        5 * segment + 7,
    ]
}

/// Encrypts with SS/PS/SP/PP/upstream, checks equality and every parallel decryption path.
fn check_all(key: &[u8], aad: &[u8], pt: &[u8], segment: usize) {
    let ss = aes_gcm_siv_encrypt_sequential(key, &NONCE, aad, pt).unwrap();
    let ps = aes_gcm_siv_encrypt_polyval_parallel(key, &NONCE, aad, pt, segment).unwrap();
    let sp = aes_gcm_siv_encrypt_ctr_parallel(key, &NONCE, aad, pt, segment).unwrap();
    let pp = aes_gcm_siv_encrypt_parallel(key, &NONCE, aad, pt, segment).unwrap();
    let up = aes_gcm_siv_encrypt_upstream(key, &NONCE, aad, pt).unwrap();
    let ctx = format!(
        "key={} aad={} pt={} seg={segment}",
        key.len(),
        aad.len(),
        pt.len()
    );

    assert_eq!(ss, up, "SS vs upstream: {ctx}");
    assert_eq!(ps, up, "PS vs upstream: {ctx}");
    assert_eq!(sp, up, "SP vs upstream: {ctx}");
    assert_eq!(pp, up, "PP vs upstream: {ctx}");

    let ps_dec = aes_gcm_siv_decrypt_polyval_parallel(
        key,
        &NONCE,
        aad,
        &ps.ciphertext,
        &ps.tag,
        segment,
    )
    .unwrap();
    let sp_dec = aes_gcm_siv_decrypt_ctr_parallel(
        key,
        &NONCE,
        aad,
        &sp.ciphertext,
        &sp.tag,
        segment,
    )
    .unwrap();
    let pp_dec = aes_gcm_siv_decrypt_parallel(
        key,
        &NONCE,
        aad,
        &pp.ciphertext,
        &pp.tag,
        segment,
    )
    .unwrap();
    assert_eq!(ps_dec, pt, "PS decrypt: {ctx}");
    assert_eq!(sp_dec, pt, "SP decrypt: {ctx}");
    assert_eq!(pp_dec, pt, "PP decrypt: {ctx}");
}

#[test]
fn edge_cases_all_implementations_agree() {
    for key in KEYS {
        for segment in [16usize, 64, 4096] {
            for len in edge_lengths(segment) {
                let pt: Vec<u8> = (0..len).map(|i| (i * 73 % 256) as u8).collect();
                for aad in [&b""[..], b"x", &[0x33; 16], &[0x44; 33]] {
                    check_all(key, aad, &pt, segment);
                }
            }
        }
    }
}

#[test]
fn aad_spanning_multiple_segments_stays_sequential_but_equivalent() {
    let aad = vec![0x5a; 10_000];
    let pt = vec![0xc3; 7_777];
    for key in KEYS {
        check_all(key, &aad, &pt, 64);
    }
}

#[test]
fn invalid_segment_sizes_are_rejected() {
    for bad in [0usize, 1, 15, 17, 100, 1000] {
        let err = Err(CryptoError::InvalidSegmentSize(bad));
        assert_eq!(polyval_parallel(&[1; 16], b"data", bad), err);
        assert_eq!(polyval_parallel_linear_reduce(&[1; 16], b"data", bad), err);
        assert_eq!(
            aes_gcm_siv_encrypt_polyval_parallel(KEYS[0], &NONCE, b"", b"data", bad)
                .map(|_| ()),
            err.map(|_: [u8; 16]| ())
        );
        assert!(assert_polyval_equivalence(&[1; 16], b"data", bad).is_err());
    }
}

#[test]
fn randomized_equivalence() {
    let mut rng = SplitMix64(0x5EED_2026);
    for _ in 0..300 {
        let key_len = if rng.below(2) == 0 { 16 } else { 32 };
        let key = rng.bytes(key_len);
        let nonce: [u8; 12] = rng.bytes(12).try_into().unwrap();
        let aad_len = rng.below(200);
        let aad = rng.bytes(aad_len);
        let pt_len = rng.below(64 * 1024);
        let pt = rng.bytes(pt_len);
        let segment = 16 * (1 + rng.below(512));

        let h: [u8; 16] = rng.bytes(16).try_into().unwrap();
        let expected_poly = polyval_sequential(&h, &pt);
        assert_eq!(polyval_parallel(&h, &pt, segment).unwrap(), expected_poly);
        assert_eq!(
            polyval_parallel_linear_reduce(&h, &pt, segment).unwrap(),
            expected_poly
        );

        let up = aes_gcm_siv_encrypt_upstream(&key, &nonce, &aad, &pt).unwrap();
        let ps = aes_gcm_siv_encrypt_polyval_parallel(&key, &nonce, &aad, &pt, segment).unwrap();
        let sp = aes_gcm_siv_encrypt_ctr_parallel(&key, &nonce, &aad, &pt, segment).unwrap();
        let pp = aes_gcm_siv_encrypt_parallel(&key, &nonce, &aad, &pt, segment).unwrap();
        assert_eq!(ps, up, "PS pt={} seg={segment}", pt.len());
        assert_eq!(sp, up, "SP pt={} seg={segment}", pt.len());
        assert_eq!(pp, up, "PP pt={} seg={segment}", pt.len());

        let dec = aes_gcm_siv_decrypt_upstream(&key, &nonce, &aad, &ps.ciphertext, &ps.tag)
            .unwrap();
        assert_eq!(dec, pt);
    }
}

#[test]
fn large_input_equivalence() {
    let mut rng = SplitMix64(42);
    let pt = rng.bytes(32 * 1024 * 1024 + 5);
    let aad = b"large input";
    for segment in [64 * 1024, 1024 * 1024] {
        let report = assert_aes_gcm_siv_equivalence(KEYS[0], &NONCE, aad, &pt, segment).unwrap();
        assert!(report.is_bit_identical);
        assert_eq!(
            report.upstream_tag_hex.as_deref(),
            Some(report.parallel_tag_hex.as_str())
        );
    }
}

#[test]
fn polyval_equivalence_report() {
    let h_key = [0x9au8; 16];
    for size in [1024usize, 16_384, 65_536, 262_144, 1_048_576 + 3] {
        let data: Vec<u8> = (0..size).map(|i| (i * 41 % 256) as u8).collect();
        for segment in [16 * 1024, 32 * 1024, 64 * 1024] {
            let report = assert_polyval_equivalence(&h_key, &data, segment).unwrap();
            assert!(report.is_bit_identical);
            assert_eq!(report.sequential_tag_hex, report.parallel_tag_hex);
            assert_eq!(report.num_segments, size.div_ceil(segment));
        }
    }
}
