//! Reference oracle: the upstream RustCrypto `aes-gcm-siv` crate.
//!
//! Used only to cross-check the sequential and parallel implementations in this crate.

use crate::aes_gcm_siv_par::AesGcmSivOutput;
use crate::error::CryptoError;
use aes_gcm_siv::aead::{AeadInOut, KeyInit};
use aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv, Nonce, Tag};

fn seal<A>(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<AesGcmSivOutput, CryptoError>
where
    A: AeadInOut
        + KeyInit
        + aes_gcm_siv::AeadCore<NonceSize = cipher::consts::U12, TagSize = cipher::consts::U16>,
{
    let cipher = A::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength(key.len()))?;
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&Nonce::from(*nonce), aad, ciphertext.as_mut_slice().into())
        .map_err(|_| CryptoError::Upstream)?;
    Ok(AesGcmSivOutput {
        ciphertext,
        tag: tag.into(),
    })
}

fn open<A>(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, CryptoError>
where
    A: AeadInOut
        + KeyInit
        + aes_gcm_siv::AeadCore<NonceSize = cipher::consts::U12, TagSize = cipher::consts::U16>,
{
    let cipher = A::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength(key.len()))?;
    let mut plaintext = ciphertext.to_vec();
    cipher
        .decrypt_inout_detached(
            &Nonce::from(*nonce),
            aad,
            plaintext.as_mut_slice().into(),
            &Tag::from(*tag),
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    Ok(plaintext)
}

/// Encrypt with upstream `aes-gcm-siv` (AES-128 or AES-256 chosen by key length).
pub fn aes_gcm_siv_encrypt_upstream(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<AesGcmSivOutput, CryptoError> {
    match key.len() {
        16 => seal::<Aes128GcmSiv>(key, nonce, aad, plaintext),
        32 => seal::<Aes256GcmSiv>(key, nonce, aad, plaintext),
        other => Err(CryptoError::InvalidKeyLength(other)),
    }
}

/// Decrypt with upstream `aes-gcm-siv`.
pub fn aes_gcm_siv_decrypt_upstream(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, CryptoError> {
    match key.len() {
        16 => open::<Aes128GcmSiv>(key, nonce, aad, ciphertext, tag),
        32 => open::<Aes256GcmSiv>(key, nonce, aad, ciphertext, tag),
        other => Err(CryptoError::InvalidKeyLength(other)),
    }
}
