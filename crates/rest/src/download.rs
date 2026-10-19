//! Verified download: `GET /api/v1/objects/{cid}?nonce=<24 hex>`.
//!
//! ```text
//! IPFS ObjectStore (every block re-hashed against its CID) -> private temp file
//!   -> mutable memmap2 -> parse sealed stream v1 header (bounds/size checks)
//!   -> AES-GCM-SIV in place: CTR + POLYVAL + constant-time tag check
//!        tag mismatch -> buffer zeroed, 422, nothing sent
//!   -> only then: decompress each Zstd frame (output bounded by the authenticated
//!      declared size) into a second temp file
//!   -> HTTP 200 + Content-Length + file stream
//! ```
//!
//! The response status and length are decided only after authentication and complete
//! decompression, so a client never receives unauthenticated or partial plaintext under
//! a 200. The key is the server-side `TODO_UPLOAD_KEY_HEX`; the nonce is the one
//! returned by the upload (format version 1 does not store it).
//!
//! **No authorization:** CID and nonce are not secrets, so anyone who can reach this
//! route and knows both can download the plaintext. Put the service behind
//! authentication before exposing it.

use crate::upload::{ObjectError, SPOOL_BUFFER, TAG_LEN, TempFile, decode_hex};
use crate::{RestServiceController, run_blocking};
use memmap2::MmapOptions;
use std::fs::File;
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use todo_crypto::{CryptoError, SegmentPlan};
use todo_ipfs::Cid;
use todo_zstd::{SEALED_STREAM_MAGIC, SEALED_STREAM_VERSION, SegmentationStrategy};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// `GET` prefix; everything after it (up to `?`) is the root CID.
pub const OBJECTS_PREFIX: &str = "/api/v1/objects/";

/// `magic || version || segment_count`.
const FIXED_HEADER: usize = 4 + 1 + 8;
const DESCRIPTOR_LEN: usize = 16;

/// Decrypted, decompressed object ready to be streamed.
pub struct DownloadedObject {
    file: TempFile,
    pub len: u64,
    pub root: Cid,
    /// Manifest object id (`[A-Za-z0-9._-]`, safe for `Content-Disposition`).
    pub filename: String,
    pub plan: SegmentPlan,
    pub fetch: Duration,
    pub decrypt: Duration,
    pub decompress: Duration,
}

impl DownloadedObject {
    /// Response headers specific to the download (status line and generic headers are
    /// the caller's).
    pub fn headers(&self) -> String {
        format!(
            "Content-Type: application/octet-stream\r\nContent-Length: {}\r\n\
Content-Disposition: attachment; filename=\"{}\"\r\nX-Root-Cid: {}\r\n\
X-Encryption-Plan: {}\r\nServer-Timing: fetch;dur={:.3}, decrypt;dur={:.3}, decompress;dur={:.3}\r\n\
X-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\n",
            self.len,
            self.filename,
            self.root,
            self.plan.label(),
            self.fetch.as_secs_f64() * 1e3,
            self.decrypt.as_secs_f64() * 1e3,
            self.decompress.as_secs_f64() * 1e3,
        )
    }

    /// Stream the plaintext to `out`.
    pub async fn write_body<W: AsyncWrite + Unpin>(&self, out: &mut W) -> io::Result<()> {
        let mut file = tokio::fs::File::from_std(self.file.file.try_clone()?);
        tokio::io::AsyncSeekExt::seek(&mut file, SeekFrom::Start(0)).await?;
        let mut body = file.take(self.len);
        let copied = tokio::io::copy(&mut body, out).await?;
        if copied != self.len {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short file"));
        }
        out.flush().await
    }
}

/// `Some((cid, query))` if `target` (path with optional `?query`) is a download path.
pub fn parse_target(target: &str) -> Option<(&str, &str)> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let cid = path.strip_prefix(OBJECTS_PREFIX)?;
    (!cid.is_empty() && !cid.contains('/')).then_some((cid, query))
}

/// `Ok(None)` when the query has no `nonce=`; a present but malformed value is an error.
fn nonce_from_query(query: &str) -> Result<Option<[u8; 12]>, ObjectError> {
    let Some(value) = query.split('&').find_map(|kv| kv.strip_prefix("nonce=")) else {
        return Ok(None);
    };
    decode_hex(value)
        .and_then(|n| <[u8; 12]>::try_from(n).ok())
        .map(Some)
        .ok_or_else(|| ObjectError::new(400, "nonce must be 24 hex digits"))
}

/// Fetch, verify, decrypt and decompress the object at `target`
/// (`/api/v1/objects/{cid}?nonce=...`).
pub async fn prepare_download(
    controller: &RestServiceController,
    target: &str,
    authorization: Option<&str>,
) -> Result<DownloadedObject, ObjectError> {
    prepare_download_as(controller, target, authorization, None).await
}

/// [`prepare_download`] for a caller whose session the front end already verified
/// (`session_user = Some(id)` skips the bearer-token check).
pub async fn prepare_download_as(
    controller: &RestServiceController,
    target: &str,
    authorization: Option<&str>,
    session_user: Option<u64>,
) -> Result<DownloadedObject, ObjectError> {
    prepare_download_with(controller, target, authorization, session_user, None).await
}

/// [`prepare_download_as`] with a nonce from a server-side metadata store, used when the
/// query has no `nonce=`. A nonce in the query takes precedence (a wrong one simply
/// fails tag verification).
pub async fn prepare_download_with(
    controller: &RestServiceController,
    target: &str,
    authorization: Option<&str>,
    session_user: Option<u64>,
    stored_nonce: Option<[u8; 12]>,
) -> Result<DownloadedObject, ObjectError> {
    let Some(cfg) = controller.upload_config() else {
        return Err(ObjectError::new(
            503,
            "object service disabled: server has no TODO_UPLOAD_KEY_HEX",
        ));
    };
    if session_user.is_none() {
        cfg.authorize(authorization)?;
    }
    let (cid, query) = parse_target(target).ok_or_else(|| ObjectError::new(404, "not found"))?;
    let root: Cid = cid
        .parse()
        .map_err(|e: todo_ipfs::IpfsError| ObjectError::new(400, e.to_string()))?;
    let nonce = nonce_from_query(query)?
        .or(stored_nonce)
        .ok_or_else(|| ObjectError::new(400, "query parameter nonce=<24 hex digits> required"))?;
    let _permit = Arc::clone(&cfg.permits)
        .try_acquire_owned()
        .map_err(|_| ObjectError::new(429, "too many concurrent object transfers"))?;

    let t0 = Instant::now();
    let sealed = TempFile::create(&cfg.temp_dir, "fetch")
        .map_err(|e| ObjectError::internal("create temp file", e))?;
    let manifest = {
        let std_file = sealed
            .file
            .try_clone()
            .map_err(|e| ObjectError::internal("fetch", e))?;
        let mut out =
            tokio::io::BufWriter::with_capacity(SPOOL_BUFFER, tokio::fs::File::from_std(std_file));
        controller
            .ipfs_store()
            .write_object_to(&root, &mut out)
            .await?
    };
    let fetch = t0.elapsed();

    let key = zeroize::Zeroizing::new(cfg.key.to_vec());
    let temp_dir = cfg.temp_dir.clone();
    let limit = cfg.max_upload_bytes;
    let opened =
        run_blocking(move || open_file(&sealed.file, &temp_dir, &key, &nonce, limit)).await??;

    Ok(DownloadedObject {
        file: opened.file,
        len: opened.len,
        root,
        filename: manifest.object_id().to_string(),
        plan: opened.plan,
        fetch,
        decrypt: opened.decrypt,
        decompress: opened.decompress,
    })
}

pub(crate) struct OpenedFile {
    pub(crate) file: TempFile,
    pub(crate) len: u64,
    pub(crate) plan: SegmentPlan,
    pub(crate) decrypt: Duration,
    pub(crate) decompress: Duration,
}

fn malformed(msg: &str) -> ObjectError {
    ObjectError::new(422, format!("malformed sealed object: {msg}"))
}

fn u64_at(buf: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(buf[at..at + 8].try_into().expect("8 bytes"))
}

/// Verify and decrypt a sealed stream (format version 1, AES-GCM-SIV) stored in
/// `sealed`, in place, then decompress it into a new temp file. Plaintext is produced
/// only after the tag verifies. CPU/IO-bound: call from a blocking context.
pub(crate) fn open_file(
    sealed: &File,
    temp_dir: &Path,
    key: &[u8],
    nonce: &[u8; 12],
    max_decompressed: u64,
) -> Result<OpenedFile, ObjectError> {
    let total = sealed
        .metadata()
        .map_err(|e| ObjectError::internal("stat", e))?
        .len();
    let total = usize::try_from(total).map_err(|_| ObjectError::new(413, "object too large"))?;
    if total < FIXED_HEADER + 8 + TAG_LEN {
        return Err(malformed("truncated"));
    }
    // SAFETY: `sealed` is a private (0600, O_EXCL, unlinked on Unix) temp file written
    // by this process; nothing else resizes or modifies it while mapped.
    let mut map = unsafe { MmapOptions::new().len(total).map_mut(sealed) }
        .map_err(|e| ObjectError::internal("mmap", e))?;

    if map[..4] != SEALED_STREAM_MAGIC {
        return Err(malformed("bad magic"));
    }
    if map[4] != SEALED_STREAM_VERSION {
        return Err(ObjectError::new(
            422,
            "unsupported sealed format (only version 1 / AES-GCM-SIV)",
        ));
    }
    let count = usize::try_from(u64_at(&map, 5)).map_err(|_| malformed("segment count"))?;
    if count > (total - FIXED_HEADER) / DESCRIPTOR_LEN {
        return Err(malformed("segment count too large"));
    }
    let aad_len = FIXED_HEADER + count * DESCRIPTOR_LEN;
    let header_len = aad_len + 8;
    if total < header_len + TAG_LEN {
        return Err(malformed("truncated"));
    }
    let ct_len = u64_at(&map, aad_len);
    if ct_len != (total - header_len - TAG_LEN) as u64 {
        return Err(malformed("ciphertext length mismatch"));
    }
    let mut frames = Vec::with_capacity(count);
    let (mut compressed_sum, mut uncompressed_sum) = (0u64, 0u64);
    for i in 0..count {
        let at = FIXED_HEADER + i * DESCRIPTOR_LEN;
        let (c, u) = (u64_at(&map, at), u64_at(&map, at + 8));
        compressed_sum = compressed_sum
            .checked_add(c)
            .ok_or_else(|| malformed("size overflow"))?;
        uncompressed_sum = uncompressed_sum
            .checked_add(u)
            .ok_or_else(|| malformed("size overflow"))?;
        frames.push((c as usize, u));
    }
    if compressed_sum != ct_len {
        return Err(malformed("frame sizes do not match ciphertext length"));
    }
    if uncompressed_sum > max_decompressed {
        return Err(ObjectError::new(
            413,
            format!("declared size {uncompressed_sum} B exceeds limit {max_decompressed} B"),
        ));
    }

    let aad = map[..aad_len].to_vec();
    let tag: [u8; 16] = map[total - TAG_LEN..].try_into().expect("16 bytes");
    let ct_end = total - TAG_LEN;
    let plan = SegmentationStrategy::default()
        .plan(ct_end - header_len)
        .map_err(|e| ObjectError::internal("plan", e))?;

    let start = Instant::now();
    match todo_crypto::aes_gcm_siv_decrypt_in_place_planned(
        key,
        nonce,
        &aad,
        &mut map[header_len..ct_end],
        &tag,
        &plan,
    ) {
        Ok(()) => {}
        Err(CryptoError::AuthenticationFailed) => {
            return Err(ObjectError::new(
                422,
                "authentication failed: wrong nonce/key or tampered object",
            ));
        }
        Err(e) => return Err(ObjectError::internal("decrypt", e)),
    }
    let decrypt = start.elapsed();

    // Authenticated from here on.
    let start = Instant::now();
    let plain = TempFile::create(temp_dir, "plain")
        .map_err(|e| ObjectError::internal("create temp file", e))?;
    {
        let mut out = BufWriter::with_capacity(SPOOL_BUFFER, &plain.file);
        let mut src = &map[header_len..ct_end];
        for (compressed, declared) in frames {
            let (frame, rest) = src.split_at(compressed);
            src = rest;
            let mut dec = zstd::stream::read::Decoder::with_buffer(frame)
                .map_err(|e| ObjectError::internal("zstd init", e))?
                .single_frame();
            // Read at most one byte past the declared size to detect overlong frames.
            let written = io::copy(&mut io::Read::take(&mut dec, declared + 1), &mut out)
                .map_err(|_| ObjectError::new(422, "corrupt compressed payload"))?;
            if written != declared {
                return Err(ObjectError::new(
                    422,
                    "decompressed size does not match the authenticated header",
                ));
            }
        }
        out.flush().map_err(|e| ObjectError::internal("write", e))?;
    }
    let mut f = &plain.file;
    f.seek(SeekFrom::Start(0))
        .map_err(|e| ObjectError::internal("seek", e))?;
    Ok(OpenedFile {
        file: plain,
        len: uncompressed_sum,
        plan,
        decrypt,
        decompress: start.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upload::seal_file;

    const KEY: [u8; 16] = [0x24; 16];

    fn dir() -> std::path::PathBuf {
        std::env::temp_dir()
    }

    fn sealed_bytes(data: &[u8]) -> (Vec<u8>, [u8; 12]) {
        let src = TempFile::create(&dir(), "test-src").unwrap();
        (&src.file).write_all(data).unwrap();
        let sealed = seal_file(&src.file, &dir(), &KEY, 3).unwrap();
        (sealed.bytes.to_vec(), sealed.nonce)
    }

    fn open_bytes(bytes: &[u8], nonce: &[u8; 12], limit: u64) -> Result<Vec<u8>, ObjectError> {
        let f = TempFile::create(&dir(), "test-sealed").unwrap();
        (&f.file).write_all(bytes).unwrap();
        let opened = open_file(&f.file, &dir(), &KEY, nonce, limit)?;
        let mut out = Vec::new();
        io::Read::read_to_end(&mut &opened.file.file, &mut out).unwrap();
        assert_eq!(out.len() as u64, opened.len);
        Ok(out)
    }

    #[test]
    fn roundtrip_and_rejections() {
        let data = b"verified before release\n".repeat(40_000);
        let (bytes, nonce) = sealed_bytes(&data);
        assert_eq!(open_bytes(&bytes, &nonce, u64::MAX).unwrap(), data);

        let aad_len = FIXED_HEADER + DESCRIPTOR_LEN;
        let n = bytes.len();
        // (byte offset to flip, expected status)
        for (at, status) in [
            (aad_len + 8 + 5, 422), // ciphertext
            (n - 1, 422),           // tag
            (aad_len - 1, 422),     // declared uncompressed size (AAD)
            (0, 422),               // magic
        ] {
            let mut bad = bytes.clone();
            bad[at] ^= 0x01;
            let err = open_bytes(&bad, &nonce, u64::MAX).unwrap_err();
            assert_eq!(err.status, status, "flip at {at}: {err:?}");
        }
        let mut wrong_nonce = nonce;
        wrong_nonce[0] ^= 1;
        assert_eq!(
            open_bytes(&bytes, &wrong_nonce, u64::MAX)
                .unwrap_err()
                .status,
            422
        );
        assert_eq!(
            open_bytes(&bytes, &nonce, data.len() as u64 - 1)
                .unwrap_err()
                .status,
            413
        );
        assert_eq!(
            open_bytes(&bytes[..n - 1], &nonce, u64::MAX)
                .unwrap_err()
                .status,
            422
        );
        assert_eq!(
            open_bytes(&bytes[..10], &nonce, u64::MAX)
                .unwrap_err()
                .status,
            422
        );
    }

    #[test]
    fn target_and_nonce_parsing() {
        assert_eq!(
            parse_target("/api/v1/objects/bafy?nonce=00"),
            Some(("bafy", "nonce=00"))
        );
        assert_eq!(parse_target("/api/v1/objects/"), None);
        assert_eq!(parse_target("/api/v1/objects/a/b"), None);
        assert_eq!(parse_target("/api/v1/other"), None);
        assert_eq!(
            nonce_from_query("x=1&nonce=000102030405060708090a0b").unwrap(),
            Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
        );
        assert!(nonce_from_query("nonce=0001").is_err());
        assert!(nonce_from_query("nonce=").is_err());
        assert_eq!(nonce_from_query("").unwrap(), None);
    }
}
