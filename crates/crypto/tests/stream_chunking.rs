//! STREAM chunking for non-AES crypto modes: round trip, parallel == sequential, and
//! rejection of chunk transposition, duplication, truncation, extension and splicing.

use todo_crypto::crypto_mode::{
    open_stream, seal_stream, stream_chunk_count, stream_ciphertext_len, stream_payload_len,
    validate_stream_chunk_size,
};
use todo_crypto::{CryptoError, CryptoMode, MAX_STREAM_CHUNK_SIZE, MIN_STREAM_CHUNK_SIZE};

const CHUNK: usize = MIN_STREAM_CHUNK_SIZE;
const KEY: [u8; 32] = [0x42; 32];
const NONCE: [u8; 12] = [0x24; 12];
const AAD: &[u8] = b"ZSGS stream header";

fn stream_modes() -> impl Iterator<Item = CryptoMode> {
    CryptoMode::ALL
        .into_iter()
        .filter(|m| *m != CryptoMode::AesGcmSiv)
}

fn authenticated_stream_modes() -> impl Iterator<Item = CryptoMode> {
    stream_modes().filter(|m| m.is_authenticated())
}

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 + 7) as u8).collect()
}

/// Split a STREAM payload into per-chunk `(ct_i, tag_i)` (detached final tag attached).
fn chunks(mode: CryptoMode, ct: &[u8], tag: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let payload = stream_payload_len(mode, ct.len(), CHUNK).unwrap();
    let n = stream_chunk_count(payload, CHUNK);
    let (exp, tl) = (mode.ciphertext_expansion(), mode.tag_len());
    let mut rest = ct;
    let mut remaining = payload;
    let mut out = Vec::new();
    for i in 0..n {
        let len = remaining.min(CHUNK) + exp;
        remaining -= remaining.min(CHUNK);
        let (c, r) = rest.split_at(len);
        let (t, r) = if i == n - 1 { (tag, r) } else { r.split_at(tl) };
        out.push((c.to_vec(), t.to_vec()));
        rest = r;
    }
    out
}

/// Inverse of [`chunks`]: serialize chunks, detaching the last tag.
fn join(chunks: &[(Vec<u8>, Vec<u8>)]) -> (Vec<u8>, Vec<u8>) {
    let mut ct = Vec::new();
    for (i, (c, t)) in chunks.iter().enumerate() {
        ct.extend_from_slice(c);
        if i + 1 < chunks.len() {
            ct.extend_from_slice(t);
        }
    }
    (ct, chunks.last().unwrap().1.clone())
}

fn open(mode: CryptoMode, ct: &[u8], tag: &[u8]) -> Result<Vec<u8>, CryptoError> {
    open_stream(mode, &KEY, &NONCE, AAD, ct, tag, CHUNK, true)
}

#[test]
fn roundtrip_layout_and_parallel_equals_sequential() {
    for mode in stream_modes() {
        for key in [&KEY[..], &KEY[..16]] {
            for len in [
                0,
                1,
                CHUNK - 1,
                CHUNK,
                CHUNK + 1,
                5 * CHUNK,
                5 * CHUNK + 7,
                64 * CHUNK + 3,
            ] {
                let pt = data(len);
                let par = seal_stream(mode, key, &NONCE, AAD, &pt, CHUNK, true).unwrap();
                let seq = seal_stream(mode, key, &NONCE, AAD, &pt, CHUNK, false).unwrap();
                assert_eq!(par, seq, "{mode} len {len}: parallel != sequential");
                assert_eq!(par.tag.len(), mode.tag_len());
                assert_eq!(
                    par.ciphertext.len(),
                    stream_ciphertext_len(mode, len, CHUNK),
                    "{mode} len {len}"
                );
                assert_eq!(
                    stream_payload_len(mode, par.ciphertext.len(), CHUNK).unwrap(),
                    len
                );
                for parallel in [true, false] {
                    let out = open_stream(
                        mode,
                        key,
                        &NONCE,
                        AAD,
                        &par.ciphertext,
                        &par.tag,
                        CHUNK,
                        parallel,
                    )
                    .unwrap();
                    assert_eq!(out, pt, "{mode} len {len}");
                }
            }
        }
    }
}

#[test]
fn stream_format_differs_from_whole_message_format() {
    // Domain separation: STREAM chunks use different subkeys than one-message mode.
    let pt = data(100);
    let plan = todo_crypto::SegmentPlan::Sequential {
        reason: todo_crypto::FallbackReason::NotApplicable,
    };
    for mode in stream_modes() {
        let whole = todo_crypto::crypto_mode::seal(mode, &KEY, &NONCE, AAD, &pt, &plan).unwrap();
        let chunked = seal_stream(mode, &KEY, &NONCE, AAD, &pt, CHUNK, true).unwrap();
        assert_eq!(whole.ciphertext.len(), chunked.ciphertext.len());
        assert_ne!(whole.ciphertext, chunked.ciphertext, "{mode}");
    }
}

#[test]
fn configuration_is_validated() {
    assert_eq!(
        validate_stream_chunk_size(CryptoMode::AesGcmSiv, CHUNK),
        Err(CryptoError::StreamChunkingUnsupported(
            CryptoMode::AesGcmSiv
        ))
    );
    for bad in [0, MIN_STREAM_CHUNK_SIZE - 1, MAX_STREAM_CHUNK_SIZE + 1] {
        assert_eq!(
            validate_stream_chunk_size(CryptoMode::Aegis256, bad),
            Err(CryptoError::InvalidStreamChunkSize(bad))
        );
    }
    assert!(seal_stream(CryptoMode::AesGcmSiv, &KEY, &NONCE, AAD, b"x", CHUNK, true).is_err());
    assert_eq!(
        seal_stream(
            CryptoMode::Aegis256,
            &KEY[..20],
            &NONCE,
            AAD,
            b"x",
            CHUNK,
            true
        ),
        Err(CryptoError::InvalidKeyLength(20))
    );
    // Ciphertext lengths that fall inside a tag slot are not a valid layout.
    let mode = CryptoMode::XChaCha20Poly1305;
    assert_eq!(
        stream_payload_len(mode, CHUNK + 1, CHUNK),
        Err(CryptoError::MalformedStreamCiphertext)
    );
    let sealed = seal_stream(mode, &KEY, &NONCE, AAD, &data(10), CHUNK, true).unwrap();
    assert!(matches!(
        open(mode, &sealed.ciphertext, &sealed.tag[..15]),
        Err(CryptoError::InvalidTagLength { .. })
    ));
}

#[test]
fn transposition_and_duplication_are_rejected() {
    let pt = data(4 * CHUNK + 100);
    for mode in authenticated_stream_modes() {
        let s = seal_stream(mode, &KEY, &NONCE, AAD, &pt, CHUNK, true).unwrap();
        let original = chunks(mode, &s.ciphertext, &s.tag);
        assert_eq!(original.len(), 5);
        assert_eq!(join(&original), (s.ciphertext.clone(), s.tag.clone()));

        // Swap two equal-sized chunks (with their tags): each tag is still valid for its
        // own bytes, but index i is bound in nonce and AAD.
        for (a, b) in [(0, 1), (1, 3), (0, 3)] {
            let mut swapped = original.clone();
            swapped.swap(a, b);
            let (ct, tag) = join(&swapped);
            assert_eq!(
                open(mode, &ct, &tag),
                Err(CryptoError::AuthenticationFailed),
                "{mode}: swap {a}<->{b} accepted"
            );
        }
        // Duplicate chunk 0 over chunk 1.
        let mut dup = original.clone();
        dup[1] = dup[0].clone();
        let (ct, tag) = join(&dup);
        assert_eq!(
            open(mode, &ct, &tag),
            Err(CryptoError::AuthenticationFailed)
        );
    }
}

#[test]
fn truncation_and_extension_are_rejected_even_under_nonce_reuse() {
    // Worst case for the final flag: the attacker holds a short and a long message
    // sealed with the SAME key and nonce (nonce misuse) sharing a prefix.
    let long_pt = data(5 * CHUNK);
    let short_pt = long_pt[..3 * CHUNK].to_vec();
    for mode in authenticated_stream_modes() {
        let long = seal_stream(mode, &KEY, &NONCE, AAD, &long_pt, CHUNK, true).unwrap();
        let short = seal_stream(mode, &KEY, &NONCE, AAD, &short_pt, CHUNK, true).unwrap();
        let long_chunks = chunks(mode, &long.ciphertext, &long.tag);
        let short_chunks = chunks(mode, &short.ciphertext, &short.tag);
        // Non-final chunks of a shared prefix are identical; the final one differs.
        assert_eq!(long_chunks[..2], short_chunks[..2]);
        assert_ne!(long_chunks[2], short_chunks[2]);

        // Truncation: drop the final chunks of the long message.
        for keep in 1..long_chunks.len() {
            let (ct, tag) = join(&long_chunks[..keep]);
            assert_eq!(
                open(mode, &ct, &tag),
                Err(CryptoError::AuthenticationFailed),
                "{mode}: truncation to {keep} chunks accepted"
            );
        }
        // Extension: append chunks after the short message's final chunk.
        let mut extended = short_chunks.clone();
        extended.extend_from_slice(&long_chunks[3..]);
        let (ct, tag) = join(&extended);
        assert_eq!(
            open(mode, &ct, &tag),
            Err(CryptoError::AuthenticationFailed)
        );
        // Sanity: the genuine streams still open.
        assert_eq!(open(mode, &long.ciphertext, &long.tag).unwrap(), long_pt);
        assert_eq!(open(mode, &short.ciphertext, &short.tag).unwrap(), short_pt);
    }
}

#[test]
fn splicing_aad_chunk_size_and_bit_flips_are_rejected() {
    let pt = data(3 * CHUNK + 5);
    for mode in authenticated_stream_modes() {
        let s = seal_stream(mode, &KEY, &NONCE, AAD, &pt, CHUNK, true).unwrap();
        let original = chunks(mode, &s.ciphertext, &s.tag);

        // Chunk 1 taken from a message under another nonce (same position and length).
        let mut other_nonce = NONCE;
        other_nonce[11] ^= 1;
        let other = seal_stream(mode, &KEY, &other_nonce, AAD, &pt, CHUNK, true).unwrap();
        let mut spliced = original.clone();
        spliced[1] = chunks(mode, &other.ciphertext, &other.tag)[1].clone();
        let (ct, tag) = join(&spliced);
        assert_eq!(
            open(mode, &ct, &tag),
            Err(CryptoError::AuthenticationFailed)
        );

        // Different stream AAD (header) or different chunk size.
        assert_eq!(
            open_stream(
                mode,
                &KEY,
                &NONCE,
                b"other",
                &s.ciphertext,
                &s.tag,
                CHUNK,
                true
            ),
            Err(CryptoError::AuthenticationFailed)
        );
        assert!(
            open_stream(
                mode,
                &KEY,
                &NONCE,
                AAD,
                &s.ciphertext,
                &s.tag,
                CHUNK * 2,
                true
            )
            .is_err()
        );

        // One flipped bit anywhere (ciphertext, embedded tags, detached tag).
        for pos in [0, CHUNK, s.ciphertext.len() / 2, s.ciphertext.len() - 1] {
            let mut ct = s.ciphertext.clone();
            ct[pos] ^= 0x80;
            assert_eq!(
                open(mode, &ct, &s.tag),
                Err(CryptoError::AuthenticationFailed),
                "{mode}: flip at {pos}"
            );
        }
        let mut tag = s.tag.clone();
        tag[0] ^= 1;
        assert_eq!(
            open(mode, &s.ciphertext, &tag),
            Err(CryptoError::AuthenticationFailed)
        );
    }
}

#[test]
fn unauthenticated_xchacha20_does_not_detect_transposition() {
    // Documents the baseline: without a tag, chunk swaps go undetected (output garbled).
    let mode = CryptoMode::XChaCha20;
    let pt = data(3 * CHUNK);
    let s = seal_stream(mode, &KEY, &NONCE, AAD, &pt, CHUNK, true).unwrap();
    let mut c = chunks(mode, &s.ciphertext, &s.tag);
    c.swap(0, 1);
    let (ct, tag) = join(&c);
    let out = open(mode, &ct, &tag).expect("no authentication in xchacha20");
    assert_ne!(out, pt);
}
