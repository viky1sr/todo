//! AES-GCM-SIV (RFC 8452) with independently selectable POLYVAL and CTR execution.
//!
//! The cryptographic algorithm is unchanged: key derivation, POLYVAL input ordering,
//! tag computation, and 32-bit little-endian CTR follow RFC 8452. The thesis variable is
//! the scheduling of POLYVAL over the compressed payload:
//!
//! * SS: sequential POLYVAL + sequential CTR (reference baseline)
//! * PS: **parallel POLYVAL composition + sequential CTR** (primary thesis method)
//! * SP: sequential POLYVAL + parallel CTR (control experiment)
//! * PP: parallel POLYVAL composition + parallel CTR (end-to-end optimized variant)
//!
//! AAD and the final length block remain sequential in the PS/PP POLYVAL path; only the
//! message bytes (the Zstandard-compressed payload in the pipeline) are segmented. This
//! isolates the research variable and avoids attributing AAD parallelism to the proposed
//! method.
//!
//! Every mode must be bit-identical to the sequential reference and upstream
//! `aes-gcm-siv` implementation. AES-GCM-SIV remains a two-pass encryption construction:
//! the tag is computed over plaintext before CTR encryption can start.

use crate::error::CryptoError;
use crate::polyval_par::{polyval_part_parallel, validate_segment_size};
use crate::polyval_seq::polyval_part_sequential;
use aes::{Aes128, Aes256};
use cipher::consts::U16;
use cipher::{
    Block, BlockCipherEncrypt, BlockSizeUser, InnerIvInit, KeyInit, StreamCipher, StreamCipherSeek,
};
use ctr::{Ctr32LE, CtrCore};
use ctutils::CtEq;
use polyval::Polyval;
use rayon::prelude::*;
use universal_hash::UniversalHash;

/// Maximum plaintext length in bytes (RFC 8452 § 6: P_MAX = 2^36).
pub const P_MAX: u64 = 1 << 36;

/// Maximum AAD length in bytes (RFC 8452 § 6: A_MAX = 2^36).
pub const A_MAX: u64 = 1 << 36;

/// Ciphertext (without tag) and the 16-byte tag.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AesGcmSivOutput {
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
}

/// Per-nonce keys derived as in RFC 8452 § 4.
#[derive(Clone)]
pub struct DerivedKeys {
    /// Message-authentication key (POLYVAL key H).
    pub auth_key: [u8; 16],
    enc_key: EncKey,
}

#[derive(Clone)]
enum EncKey {
    Aes128([u8; 16]),
    Aes256([u8; 32]),
}

impl DerivedKeys {
    /// Message-encryption key (16 bytes for AES-128, 32 bytes for AES-256).
    pub fn enc_key(&self) -> &[u8] {
        match &self.enc_key {
            EncKey::Aes128(k) => k,
            EncKey::Aes256(k) => k,
        }
    }
}

#[derive(Clone, Copy)]
enum Exec {
    Sequential,
    Parallel(usize),
}

#[derive(Clone, Copy)]
struct ExecutionPlan {
    polyval: Exec,
    ctr: Exec,
}

impl ExecutionPlan {
    const SS: Self = Self {
        polyval: Exec::Sequential,
        ctr: Exec::Sequential,
    };

    fn ps(segment_size: usize) -> Self {
        Self {
            polyval: Exec::Parallel(segment_size),
            ctr: Exec::Sequential,
        }
    }

    fn sp(segment_size: usize) -> Self {
        Self {
            polyval: Exec::Sequential,
            ctr: Exec::Parallel(segment_size),
        }
    }

    fn pp(segment_size: usize) -> Self {
        Self {
            polyval: Exec::Parallel(segment_size),
            ctr: Exec::Parallel(segment_size),
        }
    }
}

/// Derive the per-nonce authentication and encryption keys (RFC 8452 § 4).
pub fn derive_keys(key: &[u8], nonce: &[u8; 12]) -> Result<DerivedKeys, CryptoError> {
    match <[u8; 16]>::try_from(key) {
        Ok(k) => {
            let mut material = [0u8; 32];
            derive_key_material(&Aes128::new(&k.into()), nonce, &mut material);
            let (auth, enc) = material.split_at(16);
            return Ok(DerivedKeys {
                auth_key: to_array(auth),
                enc_key: EncKey::Aes128(to_array(enc)),
            });
        }
        Err(_) if key.len() != 32 => return Err(CryptoError::InvalidKeyLength(key.len())),
        Err(_) => {}
    }
    let k: [u8; 32] = to_array(key);
    let mut material = [0u8; 48];
    derive_key_material(&Aes256::new(&k.into()), nonce, &mut material);
    let (auth, enc) = material.split_at(16);
    Ok(DerivedKeys {
        auth_key: to_array(auth),
        enc_key: EncKey::Aes256(to_array(enc)),
    })
}

fn to_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    out
}

/// Encrypt blocks `LE32(counter) || nonce` for counter = 0, 1, ... and keep the first
/// 8 bytes of each output block.
fn derive_key_material<C>(key_generating_key: &C, nonce: &[u8; 12], out: &mut [u8])
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
{
    for (counter, chunk) in (0u32..).zip(out.chunks_mut(8)) {
        let mut block = Block::<C>::default();
        block[..4].copy_from_slice(&counter.to_le_bytes());
        block[4..].copy_from_slice(nonce);
        key_generating_key.encrypt_block(&mut block);
        chunk.copy_from_slice(&block[..8]);
    }
}

/// The final POLYVAL block: `LE64(bitlen(A)) || LE64(bitlen(P))`.
fn length_block(aad_len: usize, msg_len: usize) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[..8].copy_from_slice(&((aad_len as u64) * 8).to_le_bytes());
    block[8..].copy_from_slice(&((msg_len as u64) * 8).to_le_bytes());
    block
}

/// The full POLYVAL input `pad16(A) || pad16(P) || length block` (RFC 8452 § 4).
///
/// Materialising it copies the message; it is provided for inspection and tests only.
pub fn build_polyval_record(aad: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(aad.len() + msg.len() + 48);
    record.extend_from_slice(aad);
    record.resize(aad.len().next_multiple_of(16), 0);
    record.extend_from_slice(msg);
    record.resize(
        record.len() + (msg.len().next_multiple_of(16) - msg.len()),
        0,
    );
    record.extend_from_slice(&length_block(aad.len(), msg.len()));
    record
}

/// POLYVAL over the RFC 8452 record without materialising it.
///
/// In the parallel mode only `msg` is segmented. AAD and the length block remain
/// sequential so the experiment isolates parallel composition on the compressed stream.
fn polyval_record(auth_key: &[u8; 16], aad: &[u8], msg: &[u8], exec: Exec) -> [u8; 16] {
    let len_block = length_block(aad.len(), msg.len());
    match exec {
        Exec::Sequential => {
            let mut poly = Polyval::new(&polyval::Key::from(*auth_key));
            poly.update_padded(aad);
            poly.update_padded(msg);
            poly.update(&[polyval::Block::from(len_block)]);
            poly.finalize().into()
        }
        Exec::Parallel(segment_size) => {
            let aad_part = polyval_part_sequential(auth_key, aad);
            let msg_part = polyval_part_parallel(auth_key, msg, segment_size);
            let len_part = polyval_part_sequential(auth_key, &len_block);
            aad_part.combine(msg_part).combine(len_part).hash.into()
        }
    }
}

/// Tag = AES_enc(POLYVAL result XOR nonce, with the MSB of byte 15 cleared).
fn compute_tag<C>(enc: &C, polyval_out: [u8; 16], nonce: &[u8; 12]) -> [u8; 16]
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
{
    let mut s = polyval_out;
    for (b, n) in s.iter_mut().zip(nonce) {
        *b ^= n;
    }
    s[15] &= 0x7f;
    let mut block = Block::<C>::from(s);
    enc.encrypt_block(&mut block);
    block.into()
}

/// AES-CTR with a 32-bit little-endian wrapping counter, initial block = tag | 0x80 in
/// byte 15 (RFC 8452 § 4). Applied in place.
fn apply_ctr<C>(enc: &C, tag: &[u8; 16], buf: &mut [u8], exec: Exec) -> Result<(), CryptoError>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16> + Clone + Sync,
{
    let mut iv = *tag;
    iv[15] |= 0x80;
    let iv = Block::<C>::from(iv);
    let new_ctr = || Ctr32LE::<C>::from_core(CtrCore::inner_iv_init(enc.clone(), &iv));

    match exec {
        Exec::Sequential => new_ctr()
            .try_apply_keystream(buf)
            .map_err(|_| CryptoError::DataTooLarge),
        Exec::Parallel(segment_size) => {
            buf.par_chunks_mut(segment_size)
                .enumerate()
                .try_for_each(|(idx, segment)| {
                    let mut ctr = new_ctr();
                    ctr.try_seek((idx as u64) * (segment_size as u64))
                        .map_err(|_| CryptoError::DataTooLarge)?;
                    ctr.try_apply_keystream(segment)
                        .map_err(|_| CryptoError::DataTooLarge)
                })
        }
    }
}

/// RFC 8452 § 6 input limits. `msg_len` is the plaintext length, or the ciphertext
/// length without the 16-byte tag (equivalent to `C_MAX = 2^36 + 16`).
fn check_length_limits(aad_len: u64, msg_len: u64) -> Result<(), CryptoError> {
    if msg_len > P_MAX || aad_len > A_MAX {
        return Err(CryptoError::DataTooLarge);
    }
    Ok(())
}

fn check_lengths(aad: &[u8], msg: &[u8]) -> Result<(), CryptoError> {
    check_length_limits(aad.len() as u64, msg.len() as u64)
}

fn seal<C>(
    enc: &C,
    keys: &DerivedKeys,
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    plan: ExecutionPlan,
) -> Result<AesGcmSivOutput, CryptoError>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16> + Clone + Sync,
{
    // Pass 1: tag over the plaintext. Pass 2: CTR keyed by the tag.
    let s = polyval_record(&keys.auth_key, aad, plaintext, plan.polyval);
    let tag = compute_tag(enc, s, nonce);
    let mut ciphertext = plaintext.to_vec();
    apply_ctr(enc, &tag, &mut ciphertext, plan.ctr)?;
    Ok(AesGcmSivOutput { ciphertext, tag })
}

/// [`seal`] without the copy: `buffer` holds the plaintext on entry and the ciphertext on
/// return (e.g. a memory-mapped file). Same two passes, same output.
fn seal_in_place<C>(
    enc: &C,
    keys: &DerivedKeys,
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
    plan: ExecutionPlan,
) -> Result<[u8; 16], CryptoError>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16> + Clone + Sync,
{
    let s = polyval_record(&keys.auth_key, aad, buffer, plan.polyval);
    let tag = compute_tag(enc, s, nonce);
    apply_ctr(enc, &tag, buffer, plan.ctr)?;
    Ok(tag)
}

/// [`open`] without the copy: `buffer` holds the ciphertext on entry and the plaintext
/// only if the tag verifies; on failure it is zeroed (never unauthenticated plaintext).
fn open_in_place<C>(
    enc: &C,
    keys: &DerivedKeys,
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; 16],
    plan: ExecutionPlan,
) -> Result<(), CryptoError>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16> + Clone + Sync,
{
    apply_ctr(enc, tag, buffer, plan.ctr)?;
    let s = polyval_record(&keys.auth_key, aad, buffer, plan.polyval);
    let expected = compute_tag(enc, s, nonce);
    if expected.ct_eq(tag).to_bool() {
        Ok(())
    } else {
        buffer.fill(0);
        Err(CryptoError::AuthenticationFailed)
    }
}

fn open<C>(
    enc: &C,
    keys: &DerivedKeys,
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
    plan: ExecutionPlan,
) -> Result<Vec<u8>, CryptoError>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16> + Clone + Sync,
{
    let mut plaintext = ciphertext.to_vec();
    apply_ctr(enc, tag, &mut plaintext, plan.ctr)?;
    let s = polyval_record(&keys.auth_key, aad, &plaintext, plan.polyval);
    let expected = compute_tag(enc, s, nonce);

    if expected.ct_eq(tag).to_bool() {
        Ok(plaintext)
    } else {
        // Never release unauthenticated plaintext.
        plaintext.fill(0);
        Err(CryptoError::AuthenticationFailed)
    }
}

fn encrypt_impl(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    plan: ExecutionPlan,
) -> Result<AesGcmSivOutput, CryptoError> {
    check_lengths(aad, plaintext)?;
    let keys = derive_keys(key, nonce)?;
    match &keys.enc_key {
        EncKey::Aes128(k) => seal(
            &Aes128::new(&(*k).into()),
            &keys,
            nonce,
            aad,
            plaintext,
            plan,
        ),
        EncKey::Aes256(k) => seal(
            &Aes256::new(&(*k).into()),
            &keys,
            nonce,
            aad,
            plaintext,
            plan,
        ),
    }
}

fn encrypt_in_place_impl(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
    plan: ExecutionPlan,
) -> Result<[u8; 16], CryptoError> {
    check_lengths(aad, buffer)?;
    let keys = derive_keys(key, nonce)?;
    match &keys.enc_key {
        EncKey::Aes128(k) => {
            seal_in_place(&Aes128::new(&(*k).into()), &keys, nonce, aad, buffer, plan)
        }
        EncKey::Aes256(k) => {
            seal_in_place(&Aes256::new(&(*k).into()), &keys, nonce, aad, buffer, plan)
        }
    }
}

/// In-place SS baseline: `buffer` (plaintext) is overwritten with the ciphertext; returns
/// the tag. Output identical to [`aes_gcm_siv_encrypt_sequential`].
pub fn aes_gcm_siv_encrypt_in_place_sequential(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<[u8; 16], CryptoError> {
    encrypt_in_place_impl(key, nonce, aad, buffer, ExecutionPlan::SS)
}

/// In-place PS (parallel POLYVAL, sequential CTR). Output identical to
/// [`aes_gcm_siv_encrypt_polyval_parallel`].
pub fn aes_gcm_siv_encrypt_in_place_polyval_parallel(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
    segment_size: usize,
) -> Result<[u8; 16], CryptoError> {
    validate_segment_size(segment_size)?;
    encrypt_in_place_impl(key, nonce, aad, buffer, ExecutionPlan::ps(segment_size))
}

fn decrypt_in_place_impl(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; 16],
    plan: ExecutionPlan,
) -> Result<(), CryptoError> {
    check_lengths(aad, buffer)?;
    let keys = derive_keys(key, nonce)?;
    match &keys.enc_key {
        EncKey::Aes128(k) => open_in_place(
            &Aes128::new(&(*k).into()),
            &keys,
            nonce,
            aad,
            buffer,
            tag,
            plan,
        ),
        EncKey::Aes256(k) => open_in_place(
            &Aes256::new(&(*k).into()),
            &keys,
            nonce,
            aad,
            buffer,
            tag,
            plan,
        ),
    }
}

/// In-place SS decryption: on success `buffer` holds the plaintext; on tag mismatch it is
/// zeroed and [`CryptoError::AuthenticationFailed`] is returned.
pub fn aes_gcm_siv_decrypt_in_place_sequential(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), CryptoError> {
    decrypt_in_place_impl(key, nonce, aad, buffer, tag, ExecutionPlan::SS)
}

/// In-place PS decryption (sequential CTR, parallel POLYVAL verification); same
/// failure semantics as [`aes_gcm_siv_decrypt_in_place_sequential`].
pub fn aes_gcm_siv_decrypt_in_place_polyval_parallel(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; 16],
    segment_size: usize,
) -> Result<(), CryptoError> {
    validate_segment_size(segment_size)?;
    decrypt_in_place_impl(
        key,
        nonce,
        aad,
        buffer,
        tag,
        ExecutionPlan::ps(segment_size),
    )
}

fn decrypt_impl(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
    plan: ExecutionPlan,
) -> Result<Vec<u8>, CryptoError> {
    check_lengths(aad, ciphertext)?;
    let keys = derive_keys(key, nonce)?;
    match &keys.enc_key {
        EncKey::Aes128(k) => open(
            &Aes128::new(&(*k).into()),
            &keys,
            nonce,
            aad,
            ciphertext,
            tag,
            plan,
        ),
        EncKey::Aes256(k) => open(
            &Aes256::new(&(*k).into()),
            &keys,
            nonce,
            aad,
            ciphertext,
            tag,
            plan,
        ),
    }
}

/// SS baseline: sequential POLYVAL + sequential CTR.
pub fn aes_gcm_siv_encrypt_sequential(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<AesGcmSivOutput, CryptoError> {
    encrypt_impl(key, nonce, aad, plaintext, ExecutionPlan::SS)
}

/// PS primary thesis method: parallel POLYVAL tree composition + sequential CTR.
pub fn aes_gcm_siv_encrypt_polyval_parallel(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    segment_size: usize,
) -> Result<AesGcmSivOutput, CryptoError> {
    validate_segment_size(segment_size)?;
    encrypt_impl(key, nonce, aad, plaintext, ExecutionPlan::ps(segment_size))
}

/// SP control experiment: sequential POLYVAL + parallel CTR.
pub fn aes_gcm_siv_encrypt_ctr_parallel(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    segment_size: usize,
) -> Result<AesGcmSivOutput, CryptoError> {
    validate_segment_size(segment_size)?;
    encrypt_impl(key, nonce, aad, plaintext, ExecutionPlan::sp(segment_size))
}

/// PP optimized variant: parallel POLYVAL tree composition + parallel CTR.
///
/// Kept under the original API name for backwards compatibility with existing callers.
pub fn aes_gcm_siv_encrypt_parallel(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    segment_size: usize,
) -> Result<AesGcmSivOutput, CryptoError> {
    validate_segment_size(segment_size)?;
    encrypt_impl(key, nonce, aad, plaintext, ExecutionPlan::pp(segment_size))
}

/// SS baseline decryption.
pub fn aes_gcm_siv_decrypt_sequential(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, CryptoError> {
    decrypt_impl(key, nonce, aad, ciphertext, tag, ExecutionPlan::SS)
}

/// PS primary thesis method decryption: sequential CTR + parallel POLYVAL verification.
pub fn aes_gcm_siv_decrypt_polyval_parallel(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
    segment_size: usize,
) -> Result<Vec<u8>, CryptoError> {
    validate_segment_size(segment_size)?;
    decrypt_impl(
        key,
        nonce,
        aad,
        ciphertext,
        tag,
        ExecutionPlan::ps(segment_size),
    )
}

/// SP control experiment decryption: parallel CTR + sequential POLYVAL verification.
pub fn aes_gcm_siv_decrypt_ctr_parallel(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
    segment_size: usize,
) -> Result<Vec<u8>, CryptoError> {
    validate_segment_size(segment_size)?;
    decrypt_impl(
        key,
        nonce,
        aad,
        ciphertext,
        tag,
        ExecutionPlan::sp(segment_size),
    )
}

/// PP optimized variant decryption. Kept under the original API name for compatibility.
pub fn aes_gcm_siv_decrypt_parallel(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
    segment_size: usize,
) -> Result<Vec<u8>, CryptoError> {
    validate_segment_size(segment_size)?;
    decrypt_impl(
        key,
        nonce,
        aad,
        ciphertext,
        tag,
        ExecutionPlan::pp(segment_size),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn rfc8452_c1_16_byte_plaintext_all_execution_modes() {
        let key = hex!("01000000000000000000000000000000");
        let nonce = hex!("030000000000000000000000");
        let plaintext = hex!("01000000000000000000000000000000");
        let expected_ct = hex!("743f7c8077ab25f8624e2e948579cf77");
        let expected_tag = hex!("303aaf90f6fe21199c6068577437a0c4");

        let outputs = [
            aes_gcm_siv_encrypt_sequential(&key, &nonce, b"", &plaintext).unwrap(),
            aes_gcm_siv_encrypt_polyval_parallel(&key, &nonce, b"", &plaintext, 16).unwrap(),
            aes_gcm_siv_encrypt_ctr_parallel(&key, &nonce, b"", &plaintext, 16).unwrap(),
            aes_gcm_siv_encrypt_parallel(&key, &nonce, b"", &plaintext, 16).unwrap(),
        ];
        for out in outputs {
            assert_eq!(out.ciphertext, expected_ct);
            assert_eq!(out.tag, expected_tag);
        }
    }

    #[test]
    fn same_nonce_different_messages_still_roundtrip() {
        // Deliberate nonce reuse to exercise RFC 8452 behaviour; never do this in practice.
        let key = [0x5au8; 16];
        let nonce = [0x12u8; 12];
        let aad = b"header";
        let pt1 = b"Transaction #1: Transfer $100 to Alice";
        let pt2 = b"Transaction #2: Transfer $900 to Bob";

        let out1 = aes_gcm_siv_encrypt_polyval_parallel(&key, &nonce, aad, pt1, 16).unwrap();
        let out2 = aes_gcm_siv_encrypt_polyval_parallel(&key, &nonce, aad, pt2, 16).unwrap();
        assert_ne!(out1.tag, out2.tag);

        let r1 = aes_gcm_siv_decrypt_polyval_parallel(
            &key,
            &nonce,
            aad,
            &out1.ciphertext,
            &out1.tag,
            16,
        );
        let r2 = aes_gcm_siv_decrypt_polyval_parallel(
            &key,
            &nonce,
            aad,
            &out2.ciphertext,
            &out2.tag,
            16,
        );
        assert_eq!(r1.unwrap(), pt1);
        assert_eq!(r2.unwrap(), pt2);
    }

    #[test]
    fn rfc8452_length_limits_are_enforced() {
        assert_eq!(P_MAX, 1 << 36);
        assert_eq!(A_MAX, 1 << 36);
        assert_eq!(check_length_limits(A_MAX, P_MAX), Ok(()));
        assert_eq!(
            check_length_limits(0, P_MAX + 1),
            Err(CryptoError::DataTooLarge)
        );
        assert_eq!(
            check_length_limits(A_MAX + 1, 0),
            Err(CryptoError::DataTooLarge)
        );
    }

    #[test]
    fn rejects_bad_parameters() {
        let nonce = [0u8; 12];
        assert_eq!(
            aes_gcm_siv_encrypt_sequential(&[0u8; 24], &nonce, b"", b"x"),
            Err(CryptoError::InvalidKeyLength(24))
        );
        assert_eq!(
            aes_gcm_siv_encrypt_polyval_parallel(&[0u8; 16], &nonce, b"", b"x", 24),
            Err(CryptoError::InvalidSegmentSize(24))
        );
        assert_eq!(
            aes_gcm_siv_encrypt_parallel(&[0u8; 16], &nonce, b"", b"x", 24),
            Err(CryptoError::InvalidSegmentSize(24))
        );
    }
}
