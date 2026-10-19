//! Large-file upload: `POST /api/v1/objects/upload`.
//!
//! ```text
//! raw request body (Content-Length, application/octet-stream)
//!   -> private temporary file (bounded, never fully in RAM)
//!   -> read-only memmap2 -> one stateful Zstandard frame (streamed into the sealed file)
//!   -> mutable memmap2 of the sealed file -> AES-GCM-SIV in place, ONE message / ONE tag
//!      (POLYVAL plan chosen from the compressed length; may fall back to sequential)
//!   -> sealed stream (format version 1, identical to `SealedStream::to_bytes`)
//!   -> IPFS ObjectStore (raw blocks + DAG-JSON manifest, pinned) -> root CID
//! ```
//!
//! The body is the file itself (no multipart): browsers stream it with
//! `fetch(url, { method: "POST", body: file })`, and the server needs no boundary parser.
//!
//! Keys stay on the server: the AES-GCM-SIV key comes from `TODO_UPLOAD_KEY_HEX` and a
//! fresh random 96-bit nonce is drawn per upload (returned, it is not secret). The
//! sealed bytes can be recovered with `POST /api/v1/ipfs/fetch` by a holder of that key.
//!
//! Access control: with `TODO_API_TOKEN` set, upload and download require
//! `Authorization: Bearer <token>` (checked before any body byte is read or any block is
//! fetched; only a SHA-256 verifier of the token is kept, compared in constant time).
//! Without a token the routes are open, which the binaries only allow on a loopback
//! listener ([`crate::RestServiceController::check_exposure`]).
//!
//! Temporary files are created `0600` with `O_EXCL` in `TODO_UPLOAD_TMPDIR` and, on Unix,
//! unlinked immediately after creation, so they disappear when the handle is dropped,
//! including after a crash. This is *not* secure erasure: blocks may persist on SSDs,
//! copy-on-write or journaling filesystems; use an encrypted volume or tmpfs (with
//! enough RAM) for the temp directory if that matters.

use crate::{RestError, RestServiceController, run_blocking};
use memmap2::{Mmap, MmapOptions};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fmt;
use std::future::Future;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use todo_crypto::{CryptoMode, SegmentPlan};
use todo_ipfs::{BackendKind, Cid, IpfsError};
use todo_zstd::{SEALED_STREAM_VERSION, SealedStream, SegmentDescriptor, SegmentationStrategy};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

pub const UPLOAD_ROUTE: &str = "/api/v1/objects/upload";

/// Default bound on the uploaded (plaintext) size.
pub const DEFAULT_MAX_UPLOAD_BYTES: u64 = 512 * 1024 * 1024;

/// Hard upper bound: the sealed object must fit the IPFS object-store limit.
pub const MAX_UPLOAD_BYTES_LIMIT: u64 = todo_ipfs::DEFAULT_MAX_OBJECT_SIZE - (1 << 20);

pub const DEFAULT_MAX_CONCURRENT_UPLOADS: usize = 2;
pub const DEFAULT_UPLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_COMPRESSION_LEVEL: i32 = 3;
pub(crate) const SPOOL_BUFFER: usize = 1 << 20;
pub(crate) const TAG_LEN: usize = 16;
/// Bounds on `TODO_API_TOKEN` (characters; a random 32-byte token is 43 base64url chars).
pub const MIN_API_TOKEN_LEN: usize = 32;
pub const MAX_API_TOKEN_LEN: usize = 512;

/// Server-side configuration of the object upload/download routes. The key never
/// leaves this struct.
pub struct UploadConfig {
    pub(crate) key: Zeroizing<Vec<u8>>,
    /// Also the bound on decompressed downloads.
    pub max_upload_bytes: u64,
    pub temp_dir: PathBuf,
    pub compression_level: i32,
    pub idle_timeout: Duration,
    pub(crate) permits: Arc<Semaphore>,
    /// SHA-256 of the bearer token; `None` = routes are unauthenticated.
    api_token_sha256: Option<[u8; 32]>,
}

impl fmt::Debug for UploadConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadConfig")
            .field("key", &"<redacted>")
            .field("max_upload_bytes", &self.max_upload_bytes)
            .field("temp_dir", &self.temp_dir)
            .field("compression_level", &self.compression_level)
            .field("idle_timeout", &self.idle_timeout)
            .field("api_token", &self.api_token_sha256.map(|_| "<redacted>"))
            .finish()
    }
}

impl UploadConfig {
    /// `key`: 16 or 32 bytes (AES-128/256-GCM-SIV).
    /// Whether `candidate` equals the object key (startup key-separation check only).
    pub fn uses_key(&self, candidate: &[u8]) -> bool {
        self.key[..] == *candidate
    }

    pub fn new(key: &[u8]) -> Result<Self, RestError> {
        if key.len() != 16 && key.len() != 32 {
            return Err(RestError::BadRequest(
                "upload key must be 16 or 32 bytes".into(),
            ));
        }
        Ok(Self {
            key: Zeroizing::new(key.to_vec()),
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
            temp_dir: std::env::temp_dir(),
            compression_level: DEFAULT_COMPRESSION_LEVEL,
            idle_timeout: DEFAULT_UPLOAD_IDLE_TIMEOUT,
            permits: Arc::new(Semaphore::new(DEFAULT_MAX_CONCURRENT_UPLOADS)),
            api_token_sha256: None,
        })
    }

    /// Require `Authorization: Bearer <token>` on the object routes. The token must be
    /// [`MIN_API_TOKEN_LEN`]..=[`MAX_API_TOKEN_LEN`] RFC 6750 `b64token` characters
    /// (`A-Z a-z 0-9 - . _ ~ + /`, trailing `=`); generate it randomly, e.g.
    /// `openssl rand -base64 32`.
    pub fn with_api_token(mut self, token: &str) -> Result<Self, RestError> {
        let body = token.trim_end_matches('=');
        let valid = (MIN_API_TOKEN_LEN..=MAX_API_TOKEN_LEN).contains(&token.len())
            && !body.is_empty()
            && body
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b));
        if !valid {
            return Err(RestError::BadRequest(format!(
                "API token must be {MIN_API_TOKEN_LEN}..={MAX_API_TOKEN_LEN} base64/base64url characters"
            )));
        }
        self.api_token_sha256 = Some(Sha256::digest(token.as_bytes()).into());
        Ok(self)
    }

    pub fn requires_token(&self) -> bool {
        self.api_token_sha256.is_some()
    }

    /// Check an `Authorization` header value. Always `Ok` when no token is configured.
    pub fn authorize(&self, authorization: Option<&str>) -> Result<(), ObjectError> {
        let Some(expected) = &self.api_token_sha256 else {
            return Ok(());
        };
        let presented = authorization.and_then(|v| {
            let (scheme, token) = v.trim().split_once(' ')?;
            scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
        });
        // Hashing first makes the comparison independent of the presented length.
        let ok = presented.is_some_and(|t| {
            let got: [u8; 32] = Sha256::digest(t.as_bytes()).into();
            got.iter()
                .zip(expected)
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
        });
        if ok {
            Ok(())
        } else {
            Err(ObjectError::new(401, "missing or invalid bearer token"))
        }
    }

    pub fn with_max_upload_bytes(mut self, limit: u64) -> Result<Self, RestError> {
        if limit == 0 || limit > MAX_UPLOAD_BYTES_LIMIT {
            return Err(RestError::BadRequest(format!(
                "max upload size must be 1..={MAX_UPLOAD_BYTES_LIMIT} bytes"
            )));
        }
        self.max_upload_bytes = limit;
        Ok(self)
    }

    pub fn with_temp_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.temp_dir = dir.into();
        self
    }

    pub fn with_compression_level(mut self, level: i32) -> Result<Self, RestError> {
        if !(1..=22).contains(&level) {
            return Err(RestError::BadRequest(
                "compression level must be 1..=22".into(),
            ));
        }
        self.compression_level = level;
        Ok(self)
    }

    pub fn with_max_concurrent(mut self, n: usize) -> Result<Self, RestError> {
        if n == 0 {
            return Err(RestError::BadRequest(
                "max concurrent uploads must be >= 1".into(),
            ));
        }
        self.permits = Arc::new(Semaphore::new(n));
        Ok(self)
    }

    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// `None` when `TODO_UPLOAD_KEY_HEX` is unset (upload disabled). Optional:
    /// `TODO_API_TOKEN`, `TODO_UPLOAD_MAX_BYTES`, `TODO_UPLOAD_TMPDIR`,
    /// `TODO_UPLOAD_MAX_CONCURRENT`, `TODO_UPLOAD_ZSTD_LEVEL`. The key and token may
    /// instead be given as owner-only files via `TODO_UPLOAD_KEY_HEX_FILE` /
    /// `TODO_API_TOKEN_FILE` ([`todo_database::secrets`]).
    pub fn from_env() -> Result<Option<Self>, RestError> {
        let Some(key_hex) =
            todo_database::secrets::read_secret("TODO_UPLOAD_KEY_HEX").map_err(cfg_err)?
        else {
            return Ok(None);
        };
        let key = Zeroizing::new(
            decode_hex(key_hex.trim())
                .ok_or_else(|| RestError::BadRequest("TODO_UPLOAD_KEY_HEX must be hex".into()))?,
        );
        drop(key_hex);
        let mut cfg = Self::new(&key)?;
        let env_num = |name: &str| -> Result<Option<u64>, RestError> {
            std::env::var(name)
                .ok()
                .map(|v| {
                    v.trim()
                        .parse()
                        .map_err(|_| RestError::BadRequest(format!("{name} must be a number")))
                })
                .transpose()
        };
        if let Some(v) = env_num("TODO_UPLOAD_MAX_BYTES")? {
            cfg = cfg.with_max_upload_bytes(v)?;
        }
        if let Some(v) = env_num("TODO_UPLOAD_MAX_CONCURRENT")? {
            cfg = cfg.with_max_concurrent(usize::try_from(v).unwrap_or(usize::MAX))?;
        }
        if let Some(v) = env_num("TODO_UPLOAD_ZSTD_LEVEL")? {
            cfg = cfg.with_compression_level(i32::try_from(v).unwrap_or(0))?;
        }
        if let Ok(dir) = std::env::var("TODO_UPLOAD_TMPDIR") {
            cfg = cfg.with_temp_dir(dir);
        }
        if let Some(token) =
            todo_database::secrets::read_secret("TODO_API_TOKEN").map_err(cfg_err)?
        {
            cfg = cfg
                .with_api_token(token.trim())
                .map_err(|_| RestError::BadRequest(format!(
                    "TODO_API_TOKEN must be {MIN_API_TOKEN_LEN}..={MAX_API_TOKEN_LEN} base64/base64url characters"
                )))?;
        }
        Ok(Some(cfg))
    }
}

fn cfg_err(e: todo_database::ConfigError) -> RestError {
    RestError::BadRequest(e.0)
}

/// Request headers relevant to an upload, as parsed by the HTTP front end.
#[derive(Default, Clone)]
pub struct UploadHeaders {
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
    /// `X-Object-Id`; generated when absent.
    pub object_id: Option<String>,
    pub chunked: bool,
    /// Raw `Authorization` header value (redacted in `Debug`).
    pub authorization: Option<Zeroizing<String>>,
    /// User id of a session already verified by the front end (`todo-web` login). When
    /// set, the bearer-token check is skipped.
    pub session_user: Option<u64>,
}

impl fmt::Debug for UploadHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadHeaders")
            .field("content_length", &self.content_length)
            .field("content_type", &self.content_type)
            .field("object_id", &self.object_id)
            .field("chunked", &self.chunked)
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "<redacted>"),
            )
            .field("session_user", &self.session_user)
            .finish()
    }
}

/// HTTP status + safe client message for the object upload/download routes. Internal
/// details (paths, OS errors) are logged server-side only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectError {
    pub status: u16,
    pub message: String,
}

impl ObjectError {
    pub(crate) fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub(crate) fn internal(context: &str, e: impl fmt::Display) -> Self {
        eprintln!("upload: {context}: {e}");
        Self::new(500, format!("internal error ({context})"))
    }
}

impl From<RestError> for ObjectError {
    fn from(e: RestError) -> Self {
        match e {
            RestError::Storage(e) => e.into(),
            other => Self::internal("pipeline", other),
        }
    }
}

impl From<IpfsError> for ObjectError {
    fn from(e: IpfsError) -> Self {
        match e {
            IpfsError::ObjectTooLarge { .. } => Self::new(413, e.to_string()),
            IpfsError::InvalidManifest(_) | IpfsError::InvalidCid(_) => {
                Self::new(400, e.to_string())
            }
            IpfsError::NotFound(_) => Self::new(404, "object not found"),
            IpfsError::DigestMismatch { .. } | IpfsError::CidMismatch { .. } => {
                eprintln!("upload: IPFS integrity: {e}");
                Self::new(502, "IPFS returned data that does not match its CID")
            }
            IpfsError::Unsupported("put on a read-only gateway") => Self::new(
                503,
                "IPFS backend is read-only; object publishing requires a Kubo RPC backend",
            ),
            IpfsError::Transport(_) | IpfsError::Backend { .. } | IpfsError::Unsupported(_) => {
                eprintln!("upload: IPFS backend: {e}");
                Self::new(502, "IPFS backend unavailable or rejected the object")
            }
            other => Self::internal("ipfs", other),
        }
    }
}

/// A private temporary file, removed on drop (on Unix: unlinked right after creation).
pub(crate) struct TempFile {
    pub(crate) file: File,
    path: Option<PathBuf>,
}

impl TempFile {
    pub(crate) fn create(dir: &Path, label: &str) -> io::Result<Self> {
        ensure_temp_dir(dir)?;
        let mut rnd = [0u8; 16];
        getrandom::fill(&mut rnd).map_err(io::Error::other)?;
        let path = dir.join(format!(".todo-upload-{label}-{}", encode_hex(&rnd)));
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&path)?;
        #[cfg(unix)]
        {
            std::fs::remove_file(&path)?;
            Ok(Self { file, path: None })
        }
        #[cfg(not(unix))]
        Ok(Self {
            file,
            path: Some(path),
        })
    }
}

/// Create a configured upload spool directory on first use and reject a path that is
/// not a directory.  `TODO_UPLOAD_TMPDIR` is intentionally allowed to name a new
/// directory so a fresh deployment does not turn its first upload into ENOENT.
fn ensure_temp_dir(dir: &Path) -> io::Result<()> {
    match std::fs::metadata(dir) {
        Ok(metadata) if metadata.is_dir() => return Ok(()),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "upload temporary path is not a directory",
            ));
        }
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        Err(_) => {}
    }

    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Only tighten a directory created above; never alter an administrator's
        // pre-existing directory permissions.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let metadata = std::fs::metadata(dir)?;
    if metadata.is_dir() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "upload temporary path is not a directory",
        ))
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Result of [`seal_file`]: the sealed file mapped read-only plus metrics.
pub struct SealedFile {
    /// Keeps the (unlinked) sealed file alive as long as the map.
    _file: TempFile,
    pub bytes: Mmap,
    pub original_bytes: u64,
    pub compressed_bytes: u64,
    pub plan: SegmentPlan,
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub compression: Duration,
    pub encryption: Duration,
}

impl AsRef<[u8]> for SealedFile {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Compress `plain` (one stateful Zstandard frame) and encrypt the compressed bytes as
/// **one** AES-GCM-SIV message, writing a format-version-1 sealed stream to a new
/// temporary file in `temp_dir`. CPU/IO-bound: call from a blocking context.
///
/// File layout (identical to [`SealedStream::to_bytes`]):
/// `AAD || ciphertext_len u64 LE || ciphertext || tag`, with
/// `AAD = "ZSGS" || 1 || 1 u64 || compressed_size u64 || uncompressed_size u64`.
pub fn seal_file(
    plain: &File,
    temp_dir: &Path,
    key: &[u8],
    compression_level: i32,
) -> Result<SealedFile, ObjectError> {
    let original_bytes = plain
        .metadata()
        .map_err(|e| ObjectError::internal("stat", e))?
        .len();
    if original_bytes == 0 {
        return Err(ObjectError::new(400, "empty upload"));
    }
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|e| ObjectError::internal("nonce", e))?;

    // SAFETY: `plain` is a private (0600, O_EXCL, unlinked on Unix) temporary file that
    // this process finished writing; nothing truncates or modifies it while mapped.
    let plain_map = unsafe { Mmap::map(plain) }.map_err(|e| ObjectError::internal("mmap", e))?;
    let sealed = TempFile::create(temp_dir, "sealed")
        .map_err(|e| ObjectError::internal("create sealed file", e))?;

    let header_len = header_for(0, 0).len() as u64 + 8;
    let start = Instant::now();
    let compressed_bytes = {
        let mut out = &sealed.file;
        out.seek(SeekFrom::Start(header_len))
            .map_err(|e| ObjectError::internal("seek", e))?;
        let writer = BufWriter::with_capacity(SPOOL_BUFFER, out);
        let mut enc = zstd::stream::Encoder::new(writer, compression_level)
            .map_err(|e| ObjectError::internal("zstd init", e))?;
        enc.include_contentsize(true)
            .and_then(|_| enc.set_pledged_src_size(Some(original_bytes)))
            .map_err(|e| ObjectError::internal("zstd config", e))?;
        enc.write_all(&plain_map)
            .map_err(|e| ObjectError::internal("compress", e))?;
        let mut writer = enc
            .finish()
            .map_err(|e| ObjectError::internal("compress", e))?;
        writer
            .flush()
            .map_err(|e| ObjectError::internal("compress flush", e))?;
        drop(writer);
        let end = out
            .stream_position()
            .map_err(|e| ObjectError::internal("seek", e))?;
        end - header_len
    };
    drop(plain_map);
    let compression = start.elapsed();

    let aad = header_for(compressed_bytes, original_bytes);
    let total = header_len + compressed_bytes + TAG_LEN as u64;
    sealed
        .file
        .set_len(total)
        .map_err(|e| ObjectError::internal("resize", e))?;
    let total = usize::try_from(total).map_err(|_| ObjectError::new(413, "object too large"))?;
    let header_len = header_len as usize;
    let ct_end = total - TAG_LEN;

    let start = Instant::now();
    // SAFETY: as above; the sealed file is private to this process and its length is
    // fixed (`set_len`) before mapping.
    let mut map = unsafe { MmapOptions::new().len(total).map_mut(&sealed.file) }
        .map_err(|e| ObjectError::internal("mmap", e))?;
    map[..aad.len()].copy_from_slice(&aad);
    map[aad.len()..header_len].copy_from_slice(&compressed_bytes.to_le_bytes());
    let plan = SegmentationStrategy::default()
        .plan(ct_end - header_len)
        .map_err(|e| ObjectError::internal("plan", e))?;
    let tag = todo_crypto::aes_gcm_siv_encrypt_in_place_planned(
        key,
        &nonce,
        &aad,
        &mut map[header_len..ct_end],
        &plan,
    )
    .map_err(|e| ObjectError::internal("encrypt", e))?;
    map[ct_end..].copy_from_slice(&tag);
    let encryption = start.elapsed();
    let bytes = map
        .make_read_only()
        .map_err(|e| ObjectError::internal("mmap", e))?;

    Ok(SealedFile {
        _file: sealed,
        bytes,
        original_bytes,
        compressed_bytes,
        plan,
        nonce,
        tag,
        compression,
        encryption,
    })
}

/// Canonical version-1 AAD for one Zstandard frame (built by `todo-zstd` itself so the
/// format cannot drift).
fn header_for(compressed: u64, uncompressed: u64) -> Vec<u8> {
    SealedStream {
        version: SEALED_STREAM_VERSION,
        crypto_mode: CryptoMode::AesGcmSiv,
        segments: vec![SegmentDescriptor {
            compressed_size: compressed,
            uncompressed_size: uncompressed,
        }],
        ciphertext: Vec::new(),
        tag: Vec::new(),
        stream_chunk_size: None,
    }
    .associated_data()
}

fn is_octet_stream(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|ct| ct.split(';').next())
        .is_some_and(|ct| ct.trim().eq_ignore_ascii_case("application/octet-stream"))
}

/// Stream exactly `len` body bytes (`prefix` = bytes already read with the headers)
/// into `file`, with an idle timeout per read.
async fn spool<R: AsyncRead + Unpin>(
    file: &File,
    prefix: &[u8],
    reader: &mut R,
    len: u64,
    idle: Duration,
) -> Result<(), ObjectError> {
    let std_file = file
        .try_clone()
        .map_err(|e| ObjectError::internal("spool", e))?;
    let mut out =
        tokio::io::BufWriter::with_capacity(SPOOL_BUFFER, tokio::fs::File::from_std(std_file));
    let first = prefix.len().min(usize::try_from(len).unwrap_or(usize::MAX));
    out.write_all(&prefix[..first])
        .await
        .map_err(|e| ObjectError::internal("spool", e))?;
    let mut remaining = len - first as u64;
    let mut buf = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let want = buf
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let n = match tokio::time::timeout(idle, reader.read(&mut buf[..want])).await {
            Err(_) => return Err(ObjectError::new(408, "upload stalled (idle timeout)")),
            Ok(Err(_)) | Ok(Ok(0)) => {
                return Err(ObjectError::new(400, "body shorter than Content-Length"));
            }
            Ok(Ok(n)) => n,
        };
        out.write_all(&buf[..n])
            .await
            .map_err(|e| ObjectError::internal("spool", e))?;
        remaining -= n as u64;
    }
    out.flush()
        .await
        .map_err(|e| ObjectError::internal("spool", e))?;
    buf.fill(0);
    Ok(())
}

/// Structured result of a successful upload (what a metadata store needs) plus the JSON
/// response body.
#[derive(Debug, Clone)]
pub struct UploadReceipt {
    pub object_id: String,
    pub root: Cid,
    pub backend: BackendKind,
    pub crypto_mode: CryptoMode,
    pub sealed_format_version: u8,
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub original_bytes: u64,
    pub compressed_bytes: u64,
    pub sealed_bytes: u64,
    pub plan: SegmentPlan,
    pub json: Value,
}

/// Async hook used by the production web layer to durably persist the deterministic
/// root and public sealed-object metadata after staging but before the recursive pin.
/// Returning `Err(())` leaves staged blocks unpinned/GC-eligible and fails the upload.
pub type UploadLifecycleFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), ()>> + Send + 'a>>;

pub trait UploadLifecycle: Send + Sync {
    fn before_publish<'a>(&'a self, receipt: &'a UploadReceipt) -> UploadLifecycleFuture<'a>;
}

/// Ensure a validated object id exists before body processing. Front ends use this to
/// reserve a durable generation in the journal before the upload starts.
fn resolved_object_id(current: Option<&str>) -> Result<String, ObjectError> {
    let object_id = match current {
        Some(id) => id.to_owned(),
        None => {
            let mut rnd = [0u8; 8];
            getrandom::fill(&mut rnd).map_err(|e| ObjectError::internal("id", e))?;
            format!("upload-{}", encode_hex(&rnd))
        }
    };
    todo_ipfs::manifest::validate_object_id(&object_id)?;
    Ok(object_id)
}

pub fn ensure_object_id(headers: &mut UploadHeaders) -> Result<String, ObjectError> {
    let object_id = resolved_object_id(headers.object_id.as_deref())?;
    headers.object_id = Some(object_id.clone());
    Ok(object_id)
}

/// Validate, spool, seal and publish one upload. Returns `(status, JSON body)`.
pub async fn handle_upload<R: AsyncRead + Unpin>(
    controller: &RestServiceController,
    headers: &UploadHeaders,
    prefix: &[u8],
    reader: &mut R,
) -> (u16, Value) {
    match upload_object(controller, headers, prefix, reader).await {
        Ok(r) => (200, r.json),
        Err(e) => (e.status, json!({ "status": "error", "error": e.message })),
    }
}

/// [`handle_upload`] returning the structured [`UploadReceipt`].
pub async fn upload_object<R: AsyncRead + Unpin>(
    controller: &RestServiceController,
    headers: &UploadHeaders,
    prefix: &[u8],
    reader: &mut R,
) -> Result<UploadReceipt, ObjectError> {
    upload_object_with_lifecycle(controller, headers, prefix, reader, None).await
}

/// Journal-aware upload used by the production web layer. The lifecycle hook executes
/// after all IPFS blocks + root manifest are staged and before the recursive pin.
pub async fn upload_object_with_lifecycle<R: AsyncRead + Unpin>(
    controller: &RestServiceController,
    headers: &UploadHeaders,
    prefix: &[u8],
    reader: &mut R,
    lifecycle: Option<&dyn UploadLifecycle>,
) -> Result<UploadReceipt, ObjectError> {
    let Some(cfg) = controller.upload_config() else {
        return Err(ObjectError::new(
            503,
            "upload disabled: server has no TODO_UPLOAD_KEY_HEX",
        ));
    };
    if headers.session_user.is_none() {
        cfg.authorize(headers.authorization.as_deref().map(String::as_str))?;
    }
    if headers.chunked {
        return Err(ObjectError::new(411, "chunked bodies are not supported"));
    }
    let len = headers
        .content_length
        .ok_or_else(|| ObjectError::new(411, "Content-Length required"))?;
    if !is_octet_stream(headers.content_type.as_deref()) {
        return Err(ObjectError::new(
            415,
            "Content-Type must be application/octet-stream",
        ));
    }
    if len == 0 {
        return Err(ObjectError::new(400, "empty upload"));
    }
    if len > cfg.max_upload_bytes {
        return Err(ObjectError::new(
            413,
            format!("upload exceeds {} bytes", cfg.max_upload_bytes),
        ));
    }
    let object_id = resolved_object_id(headers.object_id.as_deref())?;
    let _permit = Arc::clone(&cfg.permits)
        .try_acquire_owned()
        .map_err(|_| ObjectError::new(429, "too many concurrent uploads"))?;

    let t0 = Instant::now();
    let plain = TempFile::create(&cfg.temp_dir, "plain")
        .map_err(|e| ObjectError::internal("create temp file", e))?;
    spool(&plain.file, prefix, reader, len, cfg.idle_timeout).await?;
    let receive = t0.elapsed();

    let key = Zeroizing::new(cfg.key.to_vec());
    let temp_dir = cfg.temp_dir.clone();
    let level = cfg.compression_level;
    let sealed = run_blocking(move || {
        let sealed = seal_file(&plain.file, &temp_dir, &key, level);
        // Drop (and on non-Unix delete) the plaintext spool as soon as it is sealed.
        drop(plain);
        sealed
    })
    .await??;

    let summary = json!({
        "original_size_bytes": sealed.original_bytes,
        "compressed_size_bytes": sealed.compressed_bytes,
        "sealed_size_bytes": sealed.bytes.len(),
        "num_polyval_segments": sealed.plan.executed_segments(sealed.compressed_bytes as usize),
        "parallel_path_exercised": sealed.plan.is_parallel(),
        "encryption_plan": sealed.plan,
        "nonce_hex": encode_hex(&sealed.nonce),
        "tag_hex": encode_hex(&sealed.tag),
        "compression_ms": ms(sealed.compression),
        "encryption_ms": ms(sealed.encryption),
    });
    let (nonce, tag, plan) = (sealed.nonce, sealed.tag, sealed.plan);
    let (original_bytes, compressed_bytes) = (sealed.original_bytes, sealed.compressed_bytes);
    let sealed_bytes = sealed.bytes.len() as u64;
    let t1 = Instant::now();
    let staged = controller
        .ipfs_store()
        .stage_object(&object_id, sealed)
        .await?;

    let mut out = json!({
        "status": "success",
        "ipfs_cid": staged.root,
        "backend": staged.backend,
        "backend_label": staged.backend.label(),
        "object_id": object_id,
        "ipfs_blocks": staged.manifest.blocks().len(),
        "crypto_mode": CryptoMode::AesGcmSiv,
        "sealed_format_version": SEALED_STREAM_VERSION,
        "compression_mode": "single-frame",
        "zstd_frames": 1,
        "aead_messages": 1,
        "key_source": "server (TODO_UPLOAD_KEY_HEX)",
        "receive_ms": ms(receive),
        "timing_note": "single run, wall clock; not a benchmark",
    });
    if let (Value::Object(o), Value::Object(s)) = (&mut out, summary) {
        o.extend(s);
    }
    let mut receipt = UploadReceipt {
        object_id,
        root: staged.root.clone(),
        backend: staged.backend,
        crypto_mode: CryptoMode::AesGcmSiv,
        sealed_format_version: SEALED_STREAM_VERSION,
        nonce,
        tag,
        original_bytes,
        compressed_bytes,
        sealed_bytes,
        plan,
        json: out,
    };

    if let Some(lifecycle) = lifecycle {
        lifecycle
            .before_publish(&receipt)
            .await
            .map_err(|()| ObjectError::new(503, "upload journal unavailable before publish"))?;
    }

    let published = controller.ipfs_store().commit_staged(staged).await?;
    let publish = t1.elapsed();
    debug_assert_eq!(published.root, receipt.root);
    if let Some(o) = receipt.json.as_object_mut() {
        o.insert("publish_ms".into(), json!(ms(publish)));
    }
    Ok(receipt)
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

pub(crate) fn encode_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    let nibble = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    pairs
        .iter()
        .map(|[hi, lo]| Some(nibble(*hi)? << 4 | nibble(*lo)?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::ObjectError;
    use todo_ipfs::IpfsError;

    #[test]
    fn read_only_gateway_publish_error_is_actionable() {
        let error = ObjectError::from(IpfsError::Unsupported("put on a read-only gateway"));
        assert_eq!(error.status, 503);
        assert_eq!(
            error.message,
            "IPFS backend is read-only; object publishing requires a Kubo RPC backend"
        );
    }
}
