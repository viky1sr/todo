//! Selectable encryption modes (`crypto_mode`) for the compress-then-encrypt pipeline.
//!
//! [`CryptoMode::AesGcmSiv`] is the primary thesis mode and is executed by the existing
//! sequential/segment-parallel RFC 8452 implementation with the caller's key and 96-bit
//! nonce **unchanged**, so its output stays byte-identical to upstream `aes-gcm-siv`.
//!
//! The other modes are separate experiment variants (different formats, never compared
//! tag-for-tag with AES-GCM-SIV). They only wrap audited implementations:
//!
//! | Mode | Primitive | Implementation | Tag |
//! |---|---|---|---|
//! | `xchacha20` | XChaCha20 stream cipher (draft-irtf-cfrg-xchacha) | RustCrypto `chacha20` | none (**unauthenticated**) |
//! | `xchacha20-poly1305` | XChaCha20-Poly1305 AEAD | RustCrypto `chacha20poly1305` | 16 B |
//! | `ascon-aead128` | Ascon-AEAD128 (NIST SP 800-232) | RustCrypto `ascon-aead` | 16 B |
//! | `aegis-256` | AEGIS-256 (draft-irtf-cfrg-aegis-aead) | `aegis` (libaegis) | 32 B |
//! | `cascade-xchacha20poly1305-aegis256` | XChaCha20-Poly1305 inside AEGIS-256 | both above | 16 B inner + 32 B outer |
//!
//! # Subkey and nonce derivation (application design, not part of any standard)
//!
//! The pipeline API takes a 16- or 32-byte master key and a 12-byte nonce. For every
//! non-AES-GCM-SIV mode the primitive key and nonce are derived with HKDF-SHA256
//! (RFC 5869):
//!
//! ```text
//! PRK = HKDF-Extract(salt = "todo-crypto/crypto-mode/v1", IKM = master_key)
//! OKM = HKDF-Expand(PRK, info = "todo-crypto/v1" || 0x00 || mode_label || 0x00
//!                                || role || 0x00 || nonce12, L = key_len + nonce_len)
//! key || nonce = OKM
//! ```
//!
//! `role` is `"single"`, or `"inner"`/`"outer"` for the cascade, so every mode and every
//! cascade layer uses an independent key (domain separation; the same master key used
//! with two modes never shares a primitive key). The derived nonce is a deterministic
//! function of `(master_key, nonce12)`: **the caller must still never reuse `nonce12`
//! with the same master key**. With a 16-byte master key the effective security of the
//! 256-bit-key modes is bounded by 128 bits.
//!
//! # Cascade
//!
//! `inner = XChaCha20-Poly1305(k1, n1, aad, P)` (ciphertext || 16-byte tag), then
//! `outer = AEGIS-256(k2, n2, aad, inner)` with a 32-byte tag. Decryption verifies the
//! outer tag, then the inner tag; plaintext is returned only after **both** succeed.
//! The cascade has no new security proof here: it is defence in depth, secure if at least
//! one layer is (independent keys), at the cost of throughput — which is what the
//! experiment measures.
//!
//! # STREAM chunking (parallel non-AES modes)
//!
//! Optionally ([`seal_stream`] / [`open_stream`]) a non-AES mode splits the payload into
//! chunks of `chunk_size` bytes that are sealed **independently and in parallel** with the
//! STREAM construction (Hoang, Reyhanitabar, Rogaway, Vizár, "Online
//! Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance", CRYPTO 2015). Chunk
//! `i` of `n` (always `n >= 1`; an empty payload is one empty final chunk) uses
//!
//! ```text
//! key, base_nonce = HKDF(..., role = "stream" | "stream-inner" | "stream-outer", nonce12)
//! nonce_i = base_nonce[..len-5] || u32 BE i || last_i      (last_i = 1 iff i == n-1)
//! aad_i   = stream_aad || crypto_mode_id u8 || i u64 LE || last_i u8
//! ```
//!
//! Index and final flag are in the nonce (STREAM; also makes every chunk nonce unique
//! under the per-message key) **and** in the AAD (explicit binding). Consequences, each
//! covered by tests: swapping/duplicating chunks (transposition), dropping the final
//! chunk(s) (truncation), appending chunks after the final one (extension), and splicing
//! chunks from another message all fail authentication. Wire layout:
//!
//! ```text
//! ciphertext = (ct_0 || tag_0) || ... || (ct_{n-2} || tag_{n-2}) || ct_{n-1}
//! tag        = tag_{n-1}                (detached, CryptoMode::tag_len bytes)
//! ```
//!
//! where `ct_i` includes the 16-byte inner tag for the cascade. Unlike online
//! decryption, [`open_stream`] verifies **every** chunk before returning anything; on any
//! failure the whole output buffer is zeroized. STREAM chunk boundaries are boundaries of
//! the AEAD payload (the compressed stream), unrelated to Zstandard frames. For the
//! unauthenticated XChaCha20 baseline, chunking adds no integrity at all.
//!
//! # XChaCha20 without authentication
//!
//! Plain XChaCha20 has no tag: ciphertext is malleable and decryption cannot detect
//! tampering or a wrong key. It exists as a baseline that quantifies the cost of
//! authentication. Its "decryption" output is **not authenticated**; callers must opt in
//! explicitly (see `todo-zstd`/`todo-rest`).

use crate::adaptive::{
    FallbackReason, SegmentPlan, aes_gcm_siv_decrypt_planned, aes_gcm_siv_encrypt_planned,
};
use crate::error::CryptoError;
use aegis::aegis256::Aegis256;
use ascon_aead::AsconAead128;
use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;
use std::str::FromStr;
use zeroize::{Zeroize, Zeroizing};

/// HKDF-Extract salt for all derived modes.
pub const CRYPTO_MODE_KDF_SALT: &[u8] = b"todo-crypto/crypto-mode/v1";
const KDF_INFO_PREFIX: &[u8] = b"todo-crypto/v1";

/// AEGIS-256 tag length used by this crate (256-bit tag, the stronger of the two options
/// of draft-irtf-cfrg-aegis-aead).
pub const AEGIS256_TAG_LEN: usize = 32;
/// XChaCha20-Poly1305 / Ascon-AEAD128 / AES-GCM-SIV tag length.
pub const TAG_LEN_128: usize = 16;

/// Encryption mode applied to the (compressed) payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum CryptoMode {
    /// AES-GCM-SIV (RFC 8452), primary thesis mode with segment-parallel POLYVAL.
    #[default]
    #[serde(rename = "aes-gcm-siv")]
    AesGcmSiv,
    /// XChaCha20 stream cipher only. **Unauthenticated** baseline.
    #[serde(rename = "xchacha20")]
    XChaCha20,
    /// XChaCha20-Poly1305 AEAD.
    #[serde(rename = "xchacha20-poly1305")]
    XChaCha20Poly1305,
    /// Ascon-AEAD128 (NIST SP 800-232).
    #[serde(rename = "ascon-aead128")]
    AsconAead128,
    /// AEGIS-256 with a 256-bit tag.
    #[serde(rename = "aegis-256")]
    Aegis256,
    /// XChaCha20-Poly1305 (inner) cascaded with AEGIS-256 (outer), independent subkeys.
    #[serde(rename = "cascade-xchacha20poly1305-aegis256")]
    CascadeXChaCha20Poly1305Aegis256,
}

impl CryptoMode {
    pub const ALL: [CryptoMode; 6] = [
        Self::AesGcmSiv,
        Self::XChaCha20,
        Self::XChaCha20Poly1305,
        Self::AsconAead128,
        Self::Aegis256,
        Self::CascadeXChaCha20Poly1305Aegis256,
    ];

    /// Canonical name (also the serde / REST / CLI value).
    pub fn label(self) -> &'static str {
        match self {
            Self::AesGcmSiv => "aes-gcm-siv",
            Self::XChaCha20 => "xchacha20",
            Self::XChaCha20Poly1305 => "xchacha20-poly1305",
            Self::AsconAead128 => "ascon-aead128",
            Self::Aegis256 => "aegis-256",
            Self::CascadeXChaCha20Poly1305Aegis256 => "cascade-xchacha20poly1305-aegis256",
        }
    }

    /// Stable wire identifier stored in the sealed-stream header.
    pub fn id(self) -> u8 {
        match self {
            Self::AesGcmSiv => 1,
            Self::XChaCha20 => 2,
            Self::XChaCha20Poly1305 => 3,
            Self::AsconAead128 => 4,
            Self::Aegis256 => 5,
            Self::CascadeXChaCha20Poly1305Aegis256 => 6,
        }
    }

    pub fn from_id(id: u8) -> Result<Self, CryptoError> {
        Self::ALL
            .into_iter()
            .find(|m| m.id() == id)
            .ok_or_else(|| CryptoError::UnknownCryptoMode(format!("id {id}")))
    }

    /// Whether decryption verifies a tag before returning plaintext.
    pub fn is_authenticated(self) -> bool {
        !matches!(self, Self::XChaCha20)
    }

    /// Length of the detached (outer) tag.
    pub fn tag_len(self) -> usize {
        match self {
            Self::XChaCha20 => 0,
            Self::AesGcmSiv | Self::XChaCha20Poly1305 | Self::AsconAead128 => TAG_LEN_128,
            Self::Aegis256 | Self::CascadeXChaCha20Poly1305Aegis256 => AEGIS256_TAG_LEN,
        }
    }

    /// Bytes by which the ciphertext is longer than the plaintext (cascade: inner tag).
    pub fn ciphertext_expansion(self) -> usize {
        match self {
            Self::CascadeXChaCha20Poly1305Aegis256 => TAG_LEN_128,
            _ => 0,
        }
    }

    /// Total per-message overhead (expansion + detached tag).
    pub fn overhead(self) -> usize {
        self.ciphertext_expansion() + self.tag_len()
    }

    /// Only AES-GCM-SIV uses POLYVAL and therefore the segment-parallel plan.
    pub fn uses_polyval_segmentation(self) -> bool {
        matches!(self, Self::AesGcmSiv)
    }

    /// Human-readable description of the primitive(s).
    pub fn description(self) -> &'static str {
        match self {
            Self::AesGcmSiv => "AES-GCM-SIV (RFC 8452), segment-parallel POLYVAL",
            Self::XChaCha20 => "XChaCha20 stream cipher, UNAUTHENTICATED baseline",
            Self::XChaCha20Poly1305 => "XChaCha20-Poly1305 AEAD",
            Self::AsconAead128 => "Ascon-AEAD128 (NIST SP 800-232)",
            Self::Aegis256 => "AEGIS-256 AEAD, 256-bit tag",
            Self::CascadeXChaCha20Poly1305Aegis256 => {
                "cascade: XChaCha20-Poly1305 (inner) + AEGIS-256 (outer), independent subkeys"
            }
        }
    }
}

impl fmt::Display for CryptoMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl FromStr for CryptoMode {
    type Err = CryptoError;

    /// Accepts the canonical label plus common aliases (case-insensitive, `_` = `-`).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let norm = s.trim().to_ascii_lowercase().replace('_', "-");
        Ok(match norm.as_str() {
            "aes-gcm-siv" | "aesgcmsiv" | "aes" => Self::AesGcmSiv,
            "xchacha20" | "xchacha" => Self::XChaCha20,
            "xchacha20-poly1305" | "xchacha20poly1305" => Self::XChaCha20Poly1305,
            "ascon-aead128" | "ascon" | "ascon128" | "ascon-128" => Self::AsconAead128,
            "aegis-256" | "aegis256" | "aegis" => Self::Aegis256,
            "cascade-xchacha20poly1305-aegis256"
            | "cascade"
            | "aegis-cascade"
            | "aegis256-cascade" => Self::CascadeXChaCha20Poly1305Aegis256,
            _ => return Err(CryptoError::UnknownCryptoMode(s.to_string())),
        })
    }
}

/// Output of [`seal`]: ciphertext and detached (outer) tag of length [`CryptoMode::tag_len`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedPayload {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

fn check_master_key(key: &[u8]) -> Result<(), CryptoError> {
    match key.len() {
        16 | 32 => Ok(()),
        n => Err(CryptoError::InvalidKeyLength(n)),
    }
}

/// HKDF-SHA256 derivation of `K` key bytes and `N` nonce bytes (see module docs).
fn derive<const K: usize, const N: usize>(
    mode: CryptoMode,
    role: &str,
    master_key: &[u8],
    nonce: &[u8; 12],
) -> Result<(Zeroizing<[u8; K]>, [u8; N]), CryptoError> {
    let mut info = Vec::with_capacity(KDF_INFO_PREFIX.len() + 64);
    info.extend_from_slice(KDF_INFO_PREFIX);
    info.push(0);
    info.extend_from_slice(mode.label().as_bytes());
    info.push(0);
    info.extend_from_slice(role.as_bytes());
    info.push(0);
    info.extend_from_slice(nonce);

    let hk = Hkdf::<Sha256>::new(Some(CRYPTO_MODE_KDF_SALT), master_key);
    let mut okm = Zeroizing::new(vec![0u8; K + N]);
    hk.expand(&info, &mut okm)
        .map_err(|_| CryptoError::KeyDerivation)?;
    let mut key = Zeroizing::new([0u8; K]);
    key.copy_from_slice(&okm[..K]);
    let mut derived_nonce = [0u8; N];
    derived_nonce.copy_from_slice(&okm[K..]);
    Ok((key, derived_nonce))
}

// ---- Primitive layer (exact key/nonce sizes; checked against published test vectors) ----

/// XChaCha20 keystream XOR (block counter starts at 0). Encryption = decryption.
pub fn xchacha20_apply_keystream(
    key: &[u8; 32],
    nonce: &[u8; 24],
    buf: &mut [u8],
) -> Result<(), CryptoError> {
    let mut cipher = XChaCha20::new(key.into(), nonce.into());
    cipher
        .try_apply_keystream(buf)
        .map_err(|_| CryptoError::DataTooLarge)
}

/// XChaCha20-Poly1305 in-place encryption; returns the 16-byte tag.
pub fn xchacha20poly1305_seal_in_place(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; 16], CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let tag = cipher
        .encrypt_inout_detached(nonce.into(), aad, buf.into())
        .map_err(|_| CryptoError::DataTooLarge)?;
    Ok(tag.into())
}

/// XChaCha20-Poly1305 in-place decryption. On failure `buf` is zeroized.
pub fn xchacha20poly1305_open_in_place(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt_inout_detached(nonce.into(), aad, (&mut *buf).into(), tag.into())
        .map_err(|_| {
            buf.zeroize();
            CryptoError::AuthenticationFailed
        })
}

/// Ascon-AEAD128 (SP 800-232) in-place encryption; returns the 16-byte tag.
pub fn ascon_aead128_seal_in_place(
    key: &[u8; 16],
    nonce: &[u8; 16],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; 16], CryptoError> {
    let cipher = AsconAead128::new(key.into());
    let tag = cipher
        .encrypt_inout_detached(nonce.into(), aad, buf.into())
        .map_err(|_| CryptoError::DataTooLarge)?;
    Ok(tag.into())
}

/// Ascon-AEAD128 in-place decryption. On failure `buf` is zeroized.
pub fn ascon_aead128_open_in_place(
    key: &[u8; 16],
    nonce: &[u8; 16],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), CryptoError> {
    let cipher = AsconAead128::new(key.into());
    cipher
        .decrypt_inout_detached(nonce.into(), aad, (&mut *buf).into(), tag.into())
        .map_err(|_| {
            buf.zeroize();
            CryptoError::AuthenticationFailed
        })
}

/// AEGIS-256 in-place encryption; returns the 32-byte tag.
pub fn aegis256_seal_in_place(
    key: &[u8; 32],
    nonce: &[u8; 32],
    aad: &[u8],
    buf: &mut [u8],
) -> [u8; AEGIS256_TAG_LEN] {
    Aegis256::<AEGIS256_TAG_LEN>::new(key, nonce).encrypt_in_place(buf, aad)
}

/// AEGIS-256 in-place decryption. On failure `buf` is zeroized.
pub fn aegis256_open_in_place(
    key: &[u8; 32],
    nonce: &[u8; 32],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; AEGIS256_TAG_LEN],
) -> Result<(), CryptoError> {
    Aegis256::<AEGIS256_TAG_LEN>::new(key, nonce)
        .decrypt_in_place(buf, tag, aad)
        .map_err(|_| {
            buf.zeroize();
            CryptoError::AuthenticationFailed
        })
}

// ---- Mode layer (master key + 12-byte nonce) ----

/// Encrypt `plaintext` with `mode`. `plan` is only used by [`CryptoMode::AesGcmSiv`]
/// (POLYVAL segmentation); other modes ignore it.
///
/// The caller is responsible for never reusing `nonce` with the same `key`.
pub fn seal(
    mode: CryptoMode,
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    plan: &SegmentPlan,
) -> Result<SealedPayload, CryptoError> {
    check_master_key(key)?;
    match mode {
        CryptoMode::AesGcmSiv => {
            let out = aes_gcm_siv_encrypt_planned(key, nonce, aad, plaintext, plan)?;
            Ok(SealedPayload {
                ciphertext: out.ciphertext,
                tag: out.tag.to_vec(),
            })
        }
        CryptoMode::XChaCha20 => {
            let (k, n) = derive::<32, 24>(mode, "single", key, nonce)?;
            let mut buf = plaintext.to_vec();
            xchacha20_apply_keystream(&k, &n, &mut buf)?;
            Ok(SealedPayload {
                ciphertext: buf,
                tag: Vec::new(),
            })
        }
        CryptoMode::XChaCha20Poly1305 => {
            let (k, n) = derive::<32, 24>(mode, "single", key, nonce)?;
            let mut buf = plaintext.to_vec();
            let tag = xchacha20poly1305_seal_in_place(&k, &n, aad, &mut buf)?;
            Ok(SealedPayload {
                ciphertext: buf,
                tag: tag.to_vec(),
            })
        }
        CryptoMode::AsconAead128 => {
            let (k, n) = derive::<16, 16>(mode, "single", key, nonce)?;
            let mut buf = plaintext.to_vec();
            let tag = ascon_aead128_seal_in_place(&k, &n, aad, &mut buf)?;
            Ok(SealedPayload {
                ciphertext: buf,
                tag: tag.to_vec(),
            })
        }
        CryptoMode::Aegis256 => {
            let (k, n) = derive::<32, 32>(mode, "single", key, nonce)?;
            let mut buf = plaintext.to_vec();
            let tag = aegis256_seal_in_place(&k, &n, aad, &mut buf);
            Ok(SealedPayload {
                ciphertext: buf,
                tag: tag.to_vec(),
            })
        }
        CryptoMode::CascadeXChaCha20Poly1305Aegis256 => {
            let (k1, n1) = derive::<32, 24>(mode, "inner", key, nonce)?;
            let (k2, n2) = derive::<32, 32>(mode, "outer", key, nonce)?;
            let mut buf = Vec::with_capacity(plaintext.len() + TAG_LEN_128);
            buf.extend_from_slice(plaintext);
            let inner_tag = xchacha20poly1305_seal_in_place(&k1, &n1, aad, &mut buf)?;
            buf.extend_from_slice(&inner_tag);
            let tag = aegis256_seal_in_place(&k2, &n2, aad, &mut buf);
            Ok(SealedPayload {
                ciphertext: buf,
                tag: tag.to_vec(),
            })
        }
    }
}

/// Decrypt and verify. For authenticated modes no plaintext is returned unless every tag
/// verifies (constant-time comparison inside the underlying implementations). For
/// [`CryptoMode::XChaCha20`] the output is **not authenticated**.
pub fn open(
    mode: CryptoMode,
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    plan: &SegmentPlan,
) -> Result<Vec<u8>, CryptoError> {
    check_master_key(key)?;
    if tag.len() != mode.tag_len() {
        return Err(CryptoError::InvalidTagLength {
            expected: mode.tag_len(),
            actual: tag.len(),
        });
    }
    if ciphertext.len() < mode.ciphertext_expansion() {
        return Err(CryptoError::CiphertextTooShort);
    }
    let tag16 = || -> [u8; 16] { tag.try_into().expect("length checked above") };
    let tag32 = || -> [u8; 32] { tag.try_into().expect("length checked above") };
    match mode {
        CryptoMode::AesGcmSiv => {
            aes_gcm_siv_decrypt_planned(key, nonce, aad, ciphertext, &tag16(), plan)
        }
        CryptoMode::XChaCha20 => {
            let (k, n) = derive::<32, 24>(mode, "single", key, nonce)?;
            let mut buf = ciphertext.to_vec();
            xchacha20_apply_keystream(&k, &n, &mut buf)?;
            Ok(buf)
        }
        CryptoMode::XChaCha20Poly1305 => {
            let (k, n) = derive::<32, 24>(mode, "single", key, nonce)?;
            let mut buf = ciphertext.to_vec();
            xchacha20poly1305_open_in_place(&k, &n, aad, &mut buf, &tag16())?;
            Ok(buf)
        }
        CryptoMode::AsconAead128 => {
            let (k, n) = derive::<16, 16>(mode, "single", key, nonce)?;
            let mut buf = ciphertext.to_vec();
            ascon_aead128_open_in_place(&k, &n, aad, &mut buf, &tag16())?;
            Ok(buf)
        }
        CryptoMode::Aegis256 => {
            let (k, n) = derive::<32, 32>(mode, "single", key, nonce)?;
            let mut buf = ciphertext.to_vec();
            aegis256_open_in_place(&k, &n, aad, &mut buf, &tag32())?;
            Ok(buf)
        }
        CryptoMode::CascadeXChaCha20Poly1305Aegis256 => {
            let (k1, n1) = derive::<32, 24>(mode, "inner", key, nonce)?;
            let (k2, n2) = derive::<32, 32>(mode, "outer", key, nonce)?;
            let mut buf = ciphertext.to_vec();
            aegis256_open_in_place(&k2, &n2, aad, &mut buf, &tag32())?;
            let split = buf.len() - TAG_LEN_128;
            let mut inner_tag = [0u8; 16];
            inner_tag.copy_from_slice(&buf[split..]);
            buf.truncate(split);
            xchacha20poly1305_open_in_place(&k1, &n1, aad, &mut buf, &inner_tag)?;
            Ok(buf)
        }
    }
}

// ---- STREAM chunking (non-AES modes only) ----

/// Smallest accepted STREAM chunk size (bounds per-chunk tag overhead and chunk count).
pub const MIN_STREAM_CHUNK_SIZE: usize = 1024;
/// Largest accepted STREAM chunk size (fits the `u32` wire field).
pub const MAX_STREAM_CHUNK_SIZE: usize = 1 << 30;
/// Nonce suffix replaced per chunk: `u32 BE index || last flag`.
pub const STREAM_NONCE_SUFFIX_LEN: usize = 5;
const MAX_STREAM_CHUNKS: u64 = 1 << 32;

/// Check that `mode` supports STREAM chunking and `chunk_size` is in range.
pub fn validate_stream_chunk_size(mode: CryptoMode, chunk_size: usize) -> Result<(), CryptoError> {
    if mode == CryptoMode::AesGcmSiv {
        return Err(CryptoError::StreamChunkingUnsupported(mode));
    }
    if !(MIN_STREAM_CHUNK_SIZE..=MAX_STREAM_CHUNK_SIZE).contains(&chunk_size) {
        return Err(CryptoError::InvalidStreamChunkSize(chunk_size));
    }
    Ok(())
}

/// Number of STREAM chunks for `payload_len` bytes (at least 1).
pub fn stream_chunk_count(payload_len: usize, chunk_size: usize) -> usize {
    payload_len.div_ceil(chunk_size).max(1)
}

/// Length of the STREAM `ciphertext` field (detached final tag excluded).
pub fn stream_ciphertext_len(mode: CryptoMode, payload_len: usize, chunk_size: usize) -> usize {
    payload_len + stream_chunk_count(payload_len, chunk_size) * mode.overhead() - mode.tag_len()
}

/// Inverse of [`stream_ciphertext_len`]: the payload length, or an error if
/// `ciphertext_len` is not a valid layout.
pub fn stream_payload_len(
    mode: CryptoMode,
    ciphertext_len: usize,
    chunk_size: usize,
) -> Result<usize, CryptoError> {
    validate_stream_chunk_size(mode, chunk_size)?;
    let rest = ciphertext_len
        .checked_sub(mode.ciphertext_expansion())
        .ok_or(CryptoError::CiphertextTooShort)?;
    if rest == 0 {
        return Ok(0);
    }
    // `rest` = full_chunks * (chunk_size + overhead) + last_len, 1 <= last_len <= chunk_size.
    let slot = chunk_size + mode.overhead();
    let full_chunks = (rest - 1) / slot;
    let last_len = rest - full_chunks * slot;
    if last_len > chunk_size {
        return Err(CryptoError::MalformedStreamCiphertext);
    }
    let payload = full_chunks * chunk_size + last_len;
    if (stream_chunk_count(payload, chunk_size) as u64) > MAX_STREAM_CHUNKS {
        return Err(CryptoError::DataTooLarge);
    }
    Ok(payload)
}

/// `base[..N-5] || u32 BE index || last` (STREAM nonce of chunk `index`).
pub fn stream_chunk_nonce<const N: usize>(base: &[u8; N], index: u32, last: bool) -> [u8; N] {
    let mut nonce = *base;
    nonce[N - STREAM_NONCE_SUFFIX_LEN..N - 1].copy_from_slice(&index.to_be_bytes());
    nonce[N - 1] = u8::from(last);
    nonce
}

/// `stream_aad || crypto_mode_id || index u64 LE || last u8` (AAD of chunk `index`).
pub fn stream_chunk_aad(stream_aad: &[u8], mode: CryptoMode, index: u64, last: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(stream_aad.len() + 10);
    aad.extend_from_slice(stream_aad);
    aad.push(mode.id());
    aad.extend_from_slice(&index.to_le_bytes());
    aad.push(u8::from(last));
    aad
}

/// Per-message STREAM keys (derived once, shared read-only by all chunk jobs).
enum StreamKeys {
    XChaCha20(Zeroizing<[u8; 32]>, [u8; 24]),
    XChaCha20Poly1305(Zeroizing<[u8; 32]>, [u8; 24]),
    Ascon(Zeroizing<[u8; 16]>, [u8; 16]),
    Aegis(Zeroizing<[u8; 32]>, [u8; 32]),
    Cascade {
        inner: (Zeroizing<[u8; 32]>, [u8; 24]),
        outer: (Zeroizing<[u8; 32]>, [u8; 32]),
    },
}

impl StreamKeys {
    fn derive(mode: CryptoMode, key: &[u8], nonce: &[u8; 12]) -> Result<Self, CryptoError> {
        check_master_key(key)?;
        Ok(match mode {
            CryptoMode::AesGcmSiv => return Err(CryptoError::StreamChunkingUnsupported(mode)),
            CryptoMode::XChaCha20 => {
                let (k, n) = derive::<32, 24>(mode, "stream", key, nonce)?;
                Self::XChaCha20(k, n)
            }
            CryptoMode::XChaCha20Poly1305 => {
                let (k, n) = derive::<32, 24>(mode, "stream", key, nonce)?;
                Self::XChaCha20Poly1305(k, n)
            }
            CryptoMode::AsconAead128 => {
                let (k, n) = derive::<16, 16>(mode, "stream", key, nonce)?;
                Self::Ascon(k, n)
            }
            CryptoMode::Aegis256 => {
                let (k, n) = derive::<32, 32>(mode, "stream", key, nonce)?;
                Self::Aegis(k, n)
            }
            CryptoMode::CascadeXChaCha20Poly1305Aegis256 => Self::Cascade {
                inner: derive::<32, 24>(mode, "stream-inner", key, nonce)?,
                outer: derive::<32, 32>(mode, "stream-outer", key, nonce)?,
            },
        })
    }

    /// Seal one chunk in place. `buf` = plaintext followed by `ciphertext_expansion` spare
    /// bytes (cascade inner tag). Returns the chunk tag.
    fn seal_chunk(
        &self,
        index: u32,
        last: bool,
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Ok(match self {
            Self::XChaCha20(k, n) => {
                xchacha20_apply_keystream(k, &stream_chunk_nonce(n, index, last), buf)?;
                Vec::new()
            }
            Self::XChaCha20Poly1305(k, n) => {
                let nonce = stream_chunk_nonce(n, index, last);
                xchacha20poly1305_seal_in_place(k, &nonce, aad, buf)?.to_vec()
            }
            Self::Ascon(k, n) => {
                let nonce = stream_chunk_nonce(n, index, last);
                ascon_aead128_seal_in_place(k, &nonce, aad, buf)?.to_vec()
            }
            Self::Aegis(k, n) => {
                aegis256_seal_in_place(k, &stream_chunk_nonce(n, index, last), aad, buf).to_vec()
            }
            Self::Cascade { inner, outer } => {
                let split = buf.len() - TAG_LEN_128;
                let n1 = stream_chunk_nonce(&inner.1, index, last);
                let inner_tag =
                    xchacha20poly1305_seal_in_place(&inner.0, &n1, aad, &mut buf[..split])?;
                buf[split..].copy_from_slice(&inner_tag);
                let n2 = stream_chunk_nonce(&outer.1, index, last);
                aegis256_seal_in_place(&outer.0, &n2, aad, buf).to_vec()
            }
        })
    }

    /// Verify and decrypt one chunk in place (`buf` = chunk ciphertext incl. expansion).
    /// Afterwards the plaintext is `buf[..buf.len() - ciphertext_expansion]`.
    fn open_chunk(
        &self,
        index: u32,
        last: bool,
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        let tag16 = || -> Result<[u8; 16], CryptoError> {
            tag.try_into()
                .map_err(|_| CryptoError::AuthenticationFailed)
        };
        let tag32 = || -> Result<[u8; 32], CryptoError> {
            tag.try_into()
                .map_err(|_| CryptoError::AuthenticationFailed)
        };
        match self {
            Self::XChaCha20(k, n) => {
                xchacha20_apply_keystream(k, &stream_chunk_nonce(n, index, last), buf)
            }
            Self::XChaCha20Poly1305(k, n) => {
                let nonce = stream_chunk_nonce(n, index, last);
                xchacha20poly1305_open_in_place(k, &nonce, aad, buf, &tag16()?)
            }
            Self::Ascon(k, n) => {
                let nonce = stream_chunk_nonce(n, index, last);
                ascon_aead128_open_in_place(k, &nonce, aad, buf, &tag16()?)
            }
            Self::Aegis(k, n) => {
                let nonce = stream_chunk_nonce(n, index, last);
                aegis256_open_in_place(k, &nonce, aad, buf, &tag32()?)
            }
            Self::Cascade { inner, outer } => {
                let n2 = stream_chunk_nonce(&outer.1, index, last);
                aegis256_open_in_place(&outer.0, &n2, aad, buf, &tag32()?)?;
                let split = buf.len() - TAG_LEN_128;
                let (body, inner_tag) = buf.split_at_mut(split);
                let inner_tag: [u8; 16] = (&*inner_tag).try_into().expect("16-byte split");
                let n1 = stream_chunk_nonce(&inner.1, index, last);
                xchacha20poly1305_open_in_place(&inner.0, &n1, aad, body, &inner_tag)
                    .inspect_err(|_| buf.zeroize())
            }
        }
    }
}

fn run_jobs<T: Send>(
    jobs: Vec<T>,
    parallel: bool,
    f: impl Fn(T) -> Result<(), CryptoError> + Sync + Send,
) -> Result<(), CryptoError> {
    if parallel && jobs.len() > 1 {
        use rayon::prelude::*;
        jobs.into_par_iter().try_for_each(f)
    } else {
        jobs.into_iter().try_for_each(f)
    }
}

/// STREAM-chunked encryption (see module docs). Chunks are sealed on the Rayon pool when
/// `parallel` is true; the output is identical either way.
///
/// The caller is responsible for never reusing `nonce` with the same `key`.
pub fn seal_stream(
    mode: CryptoMode,
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    chunk_size: usize,
    parallel: bool,
) -> Result<SealedPayload, CryptoError> {
    validate_stream_chunk_size(mode, chunk_size)?;
    let keys = StreamKeys::derive(mode, key, nonce)?;
    let n = stream_chunk_count(plaintext.len(), chunk_size);
    if (n as u64) > MAX_STREAM_CHUNKS {
        return Err(CryptoError::DataTooLarge);
    }
    let (exp, tag_len) = (mode.ciphertext_expansion(), mode.tag_len());
    let mut ciphertext = vec![0u8; plaintext.len() + n * (exp + tag_len)];

    let mut jobs = Vec::with_capacity(n);
    let mut rest = ciphertext.as_mut_slice();
    for (i, pt) in (0..n).zip(plaintext.chunks(chunk_size).chain(std::iter::once(&[][..]))) {
        let (slot, tail) = rest.split_at_mut(pt.len() + exp + tag_len);
        rest = tail;
        jobs.push((i, pt, slot));
    }
    run_jobs(jobs, parallel, |(i, pt, slot)| {
        let last = i == n - 1;
        let chunk_aad = stream_chunk_aad(aad, mode, i as u64, last);
        let (body, tag_slot) = slot.split_at_mut(pt.len() + exp);
        body[..pt.len()].copy_from_slice(pt);
        let tag = keys.seal_chunk(i as u32, last, &chunk_aad, body)?;
        tag_slot.copy_from_slice(&tag);
        Ok(())
    })?;
    // The final chunk's tag is detached (it becomes the stream's `tag` field).
    let tag = ciphertext.split_off(ciphertext.len() - tag_len);
    Ok(SealedPayload { ciphertext, tag })
}

/// Verify and decrypt a [`seal_stream`] payload. Every chunk is verified before anything
/// is returned; on any failure the output is zeroized and
/// [`CryptoError::AuthenticationFailed`] is returned. XChaCha20 output is **not**
/// authenticated.
#[allow(clippy::too_many_arguments)]
pub fn open_stream(
    mode: CryptoMode,
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    chunk_size: usize,
    parallel: bool,
) -> Result<Vec<u8>, CryptoError> {
    if tag.len() != mode.tag_len() {
        return Err(CryptoError::InvalidTagLength {
            expected: mode.tag_len(),
            actual: tag.len(),
        });
    }
    let payload_len = stream_payload_len(mode, ciphertext.len(), chunk_size)?;
    let keys = StreamKeys::derive(mode, key, nonce)?;
    let n = stream_chunk_count(payload_len, chunk_size);
    let (exp, tag_len) = (mode.ciphertext_expansion(), mode.tag_len());

    let mut output = vec![0u8; payload_len];
    let mut jobs = Vec::with_capacity(n);
    let (mut src, mut dst) = (ciphertext, output.as_mut_slice());
    for i in 0..n {
        let pt_len = dst.len().min(chunk_size);
        let last = i == n - 1;
        let (ct, s) = src.split_at(pt_len + exp);
        let (chunk_tag, s) = if last { (tag, s) } else { s.split_at(tag_len) };
        let (out, d) = dst.split_at_mut(pt_len);
        jobs.push((i, ct, chunk_tag, out));
        (src, dst) = (s, d);
    }
    debug_assert!(src.is_empty());

    let result = run_jobs(jobs, parallel, |(i, ct, chunk_tag, out)| {
        let last = i == n - 1;
        let chunk_aad = stream_chunk_aad(aad, mode, i as u64, last);
        if exp == 0 {
            out.copy_from_slice(ct);
            keys.open_chunk(i as u32, last, &chunk_aad, out, chunk_tag)
        } else {
            let mut buf = Zeroizing::new(ct.to_vec());
            keys.open_chunk(i as u32, last, &chunk_aad, &mut buf, chunk_tag)?;
            out.copy_from_slice(&buf[..out.len()]);
            Ok(())
        }
    });
    if let Err(e) = result {
        output.zeroize();
        return Err(e);
    }
    Ok(output)
}

/// The plan used for `mode`: modes without POLYVAL report
/// [`FallbackReason::NotApplicable`].
pub fn plan_for_mode(mode: CryptoMode, aes_plan: SegmentPlan) -> SegmentPlan {
    if mode.uses_polyval_segmentation() {
        aes_plan
    } else {
        SegmentPlan::Sequential {
            reason: FallbackReason::NotApplicable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_ids_and_parsing_roundtrip() {
        for mode in CryptoMode::ALL {
            assert_eq!(CryptoMode::from_id(mode.id()).unwrap(), mode);
            assert_eq!(mode.label().parse::<CryptoMode>().unwrap(), mode);
            let json = serde_json::to_string(&mode).unwrap();
            assert_eq!(json, format!("\"{}\"", mode.label()));
        }
        assert_eq!(
            "AEGIS_Cascade".parse::<CryptoMode>().unwrap(),
            CryptoMode::CascadeXChaCha20Poly1305Aegis256
        );
        assert!("rot13".parse::<CryptoMode>().is_err());
        assert!(CryptoMode::from_id(0).is_err());
    }

    #[test]
    fn stream_chunks_follow_documented_nonce_and_aad() {
        // Recompute every chunk with the primitive and the documented nonce/AAD formula.
        let (key, nonce, aad) = ([3u8; 32], [5u8; 12], b"hdr".as_slice());
        let pt: Vec<u8> = (0..2 * MIN_STREAM_CHUNK_SIZE + 9)
            .map(|i| i as u8)
            .collect();
        let mode = CryptoMode::XChaCha20Poly1305;
        let s = seal_stream(mode, &key, &nonce, aad, &pt, MIN_STREAM_CHUNK_SIZE, true).unwrap();
        let (k, base) = derive::<32, 24>(mode, "stream", &key, &nonce).unwrap();
        let mut expected = Vec::new();
        let n = 3;
        for (i, chunk) in pt.chunks(MIN_STREAM_CHUNK_SIZE).enumerate() {
            let last = i == n - 1;
            let mut cn = base;
            cn[19..23].copy_from_slice(&(i as u32).to_be_bytes());
            cn[23] = u8::from(last);
            assert_eq!(cn, stream_chunk_nonce(&base, i as u32, last));
            let mut caad = aad.to_vec();
            caad.push(mode.id());
            caad.extend_from_slice(&(i as u64).to_le_bytes());
            caad.push(u8::from(last));
            let mut buf = chunk.to_vec();
            let tag = xchacha20poly1305_seal_in_place(&k, &cn, &caad, &mut buf).unwrap();
            expected.extend_from_slice(&buf);
            expected.extend_from_slice(&tag);
        }
        let tag = expected.split_off(expected.len() - TAG_LEN_128);
        assert_eq!(s.ciphertext, expected);
        assert_eq!(s.tag, tag);

        let mut nonces = std::collections::HashSet::new();
        for i in [0u32, 1, 255, 256, u32::MAX] {
            for last in [false, true] {
                assert!(nonces.insert(stream_chunk_nonce(&[9u8; 16], i, last)));
            }
        }
    }

    #[test]
    fn derived_keys_are_domain_separated() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let (a, _) = derive::<32, 24>(CryptoMode::XChaCha20, "single", &key, &nonce).unwrap();
        let (b, _) =
            derive::<32, 24>(CryptoMode::XChaCha20Poly1305, "single", &key, &nonce).unwrap();
        let (c, _) = derive::<32, 24>(
            CryptoMode::CascadeXChaCha20Poly1305Aegis256,
            "inner",
            &key,
            &nonce,
        )
        .unwrap();
        let (d, _) = derive::<32, 32>(
            CryptoMode::CascadeXChaCha20Poly1305Aegis256,
            "outer",
            &key,
            &nonce,
        )
        .unwrap();
        assert_ne!(*a, *b);
        assert_ne!(*b, *c);
        assert_ne!(*c, *d);
        let mut other_nonce = nonce;
        other_nonce[0] ^= 1;
        let (e, _) =
            derive::<32, 24>(CryptoMode::XChaCha20Poly1305, "single", &key, &other_nonce).unwrap();
        assert_ne!(*b, *e);
    }
}
