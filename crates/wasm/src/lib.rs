//! `todo-wasm`: In-browser WebAssembly module for IPFS verified-fetch,
//! multihash block verification, DAG-JSON manifest parsing, and client-side
//! AES-256-GCM-SIV decryption + Zstandard decompression.

use serde::{Deserialize, Serialize};
use std::str::FromStr;
use todo_crypto::aes_gcm_siv_decrypt_sequential;
use todo_ipfs::block::Block;
use todo_ipfs::cid::{Cid, codec};
use todo_ipfs::manifest::{self, ObjectManifest};
use todo_zstd::pipeline::SealedStream;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestJsBlock {
    pub cid: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestJs {
    pub schema: String,
    pub object_id: String,
    pub total_size: u64,
    pub blocks: Vec<ManifestJsBlock>,
}

/// Decode a hex string into raw bytes.
pub fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err("hex string length must be even".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|e| format!("invalid hex char at {i}: {e}"))?;
        out.push(byte);
    }
    Ok(out)
}

/// Encode bytes into lowercase hex string.
pub fn encode_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct WasmCidVerifier;

impl WasmCidVerifier {
    /// Re-compute cryptographic multihash of `raw_bytes` and verify against `cid_str`.
    /// Returns `Ok(true)` if valid, `Ok(false)` if digest mismatch (tampering detected),
    /// or `Err` if CID format is invalid.
    pub fn verify_block(raw_bytes: &[u8], cid_str: &str) -> Result<bool, String> {
        let cid = Cid::from_str(cid_str.trim()).map_err(|e| e.to_string())?;
        match cid.verify(raw_bytes) {
            Ok(_) => Ok(true),
            Err(todo_ipfs::IpfsError::DigestMismatch { .. }) => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Parse and validate a DAG-JSON manifest block (`todo-ipfs/object-manifest/v1`).
    pub fn parse_manifest(dag_json: &[u8]) -> Result<ManifestJs, String> {
        let block = Block::new(codec::DAG_JSON, dag_json.to_vec()).map_err(|e| e.to_string())?;
        let manifest = ObjectManifest::decode(&block).map_err(|e| e.to_string())?;
        let blocks = manifest
            .blocks()
            .iter()
            .map(|b| ManifestJsBlock {
                cid: b.cid.to_string(),
                size: b.size,
            })
            .collect();
        Ok(ManifestJs {
            schema: manifest::MANIFEST_SCHEMA.to_string(),
            object_id: manifest.object_id().to_string(),
            total_size: manifest.total_size(),
            blocks,
        })
    }

    /// Parse manifest and return as JSON string.
    pub fn parse_manifest_json(dag_json: &[u8]) -> Result<String, String> {
        let manifest = Self::parse_manifest(dag_json)?;
        serde_json::to_string(&manifest).map_err(|e| e.to_string())
    }

    /// Concatenate ordered chunks into a single byte vector.
    pub fn reassemble_blocks(chunks: &[&[u8]]) -> Vec<u8> {
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        let mut out = Vec::with_capacity(total);
        for chunk in chunks {
            out.extend_from_slice(chunk);
        }
        out
    }

    /// Decrypt AES-256-GCM-SIV ciphertext and decompress Zstandard payload.
    /// Fails closed (releasing zero plaintext) if authentication tag fails.
    pub fn decrypt_and_decompress(
        ciphertext_payload: &[u8],
        key_hex: &str,
        nonce_hex: &str,
    ) -> Result<Vec<u8>, String> {
        let key_bytes = decode_hex(key_hex)?;
        if key_bytes.len() != 32 {
            return Err("key must be exactly 32 bytes (64 hex characters)".into());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);

        let nonce_bytes = decode_hex(nonce_hex)?;
        if nonce_bytes.len() != 12 {
            return Err("nonce must be exactly 12 bytes (24 hex characters)".into());
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes);

        if ciphertext_payload.starts_with(b"ZSGS") {
            let sealed = SealedStream::from_bytes(ciphertext_payload)
                .map_err(|e| format!("sealed stream decode error: {e}"))?;
            let aad = sealed.associated_data();
            let mut tag = [0u8; 16];
            if sealed.tag.len() != 16 {
                return Err("invalid tag length in sealed stream".into());
            }
            tag.copy_from_slice(&sealed.tag);
            let compressed =
                aes_gcm_siv_decrypt_sequential(&key, &nonce, &aad, &sealed.ciphertext, &tag)
                    .map_err(|e| format!("AEAD tag verification failed: {e}"))?;
            todo_zstd::core::decompress_with_limit(&compressed, 64 * 1024 * 1024)
                .map_err(|e| format!("Zstd decompression failed: {e}"))
        } else {
            if ciphertext_payload.len() < 16 {
                return Err("ciphertext payload too short (must include 16-byte tag)".into());
            }
            let ct_len = ciphertext_payload.len() - 16;
            let ct = &ciphertext_payload[..ct_len];
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&ciphertext_payload[ct_len..]);
            let decrypted = aes_gcm_siv_decrypt_sequential(&key, &nonce, b"", ct, &tag)
                .map_err(|e| format!("AEAD tag verification failed: {e}"))?;
            if decrypted.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
                todo_zstd::core::decompress_with_limit(&decrypted, 64 * 1024 * 1024)
                    .map_err(|e| format!("Zstd decompression failed: {e}"))
            } else {
                Ok(decrypted)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// C-ABI Low-Level WASM Memory Exports
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn todo_wasm_alloc(size: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Frees memory allocated by `todo_wasm_alloc`.
///
/// # Safety
/// Caller must ensure `ptr` was allocated by `todo_wasm_alloc` and `size` matches the capacity.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn todo_wasm_free(ptr: *mut u8, size: usize) {
    if !ptr.is_null() && size > 0 {
        unsafe {
            drop(Vec::from_raw_parts(ptr, size, size));
        }
    }
}

/// Verify a raw block against a CID string.
/// Returns:
///   1 = Valid (digest matches CID)
///   0 = Digest mismatch (tampering detected)
///  -1 = Invalid CID format / parse error
///
/// # Safety
/// Caller must pass valid pointers `data_ptr` of length `data_len` and `cid_ptr` of length `cid_len`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn todo_wasm_verify_block(
    data_ptr: *const u8,
    data_len: usize,
    cid_ptr: *const u8,
    cid_len: usize,
) -> i32 {
    if data_ptr.is_null() || cid_ptr.is_null() {
        return -1;
    }
    let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
    let cid_bytes = unsafe { std::slice::from_raw_parts(cid_ptr, cid_len) };
    let cid_str = match std::str::from_utf8(cid_bytes) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    match WasmCidVerifier::verify_block(data, cid_str) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}

/// Parse a DAG-JSON manifest. Writes JSON string output into allocated memory.
/// Returns length of JSON string on success, or -1 on error.
///
/// # Safety
/// Caller must pass valid `data_ptr` of length `data_len` and non-null pointers `out_ptr_buf`, `out_len_buf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn todo_wasm_parse_manifest(
    data_ptr: *const u8,
    data_len: usize,
    out_ptr_buf: *mut *mut u8,
    out_len_buf: *mut usize,
) -> i32 {
    if data_ptr.is_null() || out_ptr_buf.is_null() || out_len_buf.is_null() {
        return -1;
    }
    let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
    match WasmCidVerifier::parse_manifest_json(data) {
        Ok(json_str) => {
            let bytes = json_str.into_bytes();
            let len = bytes.len();
            let ptr = bytes.as_ptr() as *mut u8;
            std::mem::forget(bytes);
            unsafe {
                *out_ptr_buf = ptr;
                *out_len_buf = len;
            }
            len as i32
        }
        Err(_) => -1,
    }
}

/// Decrypt AES-256-GCM-SIV ciphertext and decompress Zstandard payload.
/// Returns output byte length on success, or negative status on failure.
///
/// # Safety
/// Caller must pass valid pointers for ciphertext, key hex, and nonce hex, plus output pointer/length buffers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn todo_wasm_decrypt_decompress(
    ct_ptr: *const u8,
    ct_len: usize,
    key_ptr: *const u8,
    key_len: usize,
    nonce_ptr: *const u8,
    nonce_len: usize,
    out_ptr_buf: *mut *mut u8,
    out_len_buf: *mut usize,
) -> i32 {
    if ct_ptr.is_null()
        || key_ptr.is_null()
        || nonce_ptr.is_null()
        || out_ptr_buf.is_null()
        || out_len_buf.is_null()
    {
        return -1;
    }
    let ct = unsafe { std::slice::from_raw_parts(ct_ptr, ct_len) };
    let key_bytes = unsafe { std::slice::from_raw_parts(key_ptr, key_len) };
    let nonce_bytes = unsafe { std::slice::from_raw_parts(nonce_ptr, nonce_len) };
    let key_str = match std::str::from_utf8(key_bytes) {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let nonce_str = match std::str::from_utf8(nonce_bytes) {
        Ok(s) => s,
        Err(_) => return -3,
    };

    match WasmCidVerifier::decrypt_and_decompress(ct, key_str, nonce_str) {
        Ok(plaintext) => {
            let len = plaintext.len();
            let ptr = plaintext.as_ptr() as *mut u8;
            std::mem::forget(plaintext);
            unsafe {
                *out_ptr_buf = ptr;
                *out_len_buf = len;
            }
            len as i32
        }
        Err(_) => -4,
    }
}
