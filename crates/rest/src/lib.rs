//! `todo-rest`: REST service layer over the compression/encryption pipeline and IPFS.
//!
//! CPU-bound work (compression, AES-GCM-SIV, benchmarks) is executed on Tokio's blocking
//! pool (`spawn_blocking`), which in turn uses Rayon; async tasks only do I/O.

pub mod download;
pub mod server;
pub mod tls;
pub mod upload;

pub use download::{
    DownloadedObject, OBJECTS_PREFIX, prepare_download, prepare_download_as, prepare_download_with,
};
pub use upload::{ObjectError, UPLOAD_ROUTE, UploadConfig, UploadHeaders, UploadReceipt};

use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use todo_crypto::{
    CryptoError, TagEquivalenceReport, assert_aes_gcm_siv_equivalence, assert_polyval_equivalence,
};
use todo_crypto::{CryptoMode, SegmentationPolicy};
use todo_ipfs::{BackendKind, Cid, IpfsBackend, IpfsError, ObjectManifest, ObjectStore};
use todo_zstd::{
    CompressionMode, PipelineError, PipelineVerificationReport, SealedStream, SegmentationStrategy,
    StreamCryptoPipeline,
};

/// Upper bound on payloads accepted by the verification endpoint (it runs the
/// pipeline several times and holds multiple copies in memory).
pub const MAX_VERIFY_PAYLOAD: usize = 16 * 1024 * 1024;

/// Size of the raw IPFS blocks a serialized sealed stream is split into.
pub const IPFS_BLOCK_SIZE: usize = todo_ipfs::DEFAULT_CHUNK_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestError {
    BadRequest(String),
    /// Admission control rejected expensive work before it entered Rayon/spawn_blocking.
    Busy(&'static str),
    Pipeline(PipelineError),
    Crypto(CryptoError),
    Storage(IpfsError),
    Internal(String),
}

impl fmt::Display for RestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRequest(e) => write!(f, "bad request: {e}"),
            Self::Busy(e) => write!(f, "service busy: {e}"),
            Self::Pipeline(e) => write!(f, "{e}"),
            Self::Crypto(e) => write!(f, "{e}"),
            Self::Storage(e) => write!(f, "storage error: {e}"),
            Self::Internal(e) => write!(f, "internal error: {e}"),
        }
    }
}

impl std::error::Error for RestError {}

impl From<PipelineError> for RestError {
    fn from(e: PipelineError) -> Self {
        Self::Pipeline(e)
    }
}

impl From<IpfsError> for RestError {
    fn from(e: IpfsError) -> Self {
        Self::Storage(e)
    }
}

impl From<CryptoError> for RestError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineProcessRequest {
    pub data: Vec<u8>,
    pub key: Vec<u8>,
    pub nonce: [u8; 12],
    pub segment_size: Option<usize>,
    pub compression_level: Option<i32>,
    pub polyval_segment_size: Option<usize>,
    /// Encryption mode (see [`CryptoMode`]); default `aes-gcm-siv`.
    #[serde(default)]
    pub crypto_mode: Option<String>,
    /// Non-AES modes only: seal as parallel STREAM chunks of this many compressed bytes
    /// (format version 3). Default: one AEAD message.
    #[serde(default)]
    pub stream_chunk_size: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineProcessResponse {
    pub success: bool,
    pub total_segments: usize,
    pub sealed: SealedStream,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineRecoverRequest {
    pub sealed: SealedStream,
    pub key: Vec<u8>,
    pub nonce: [u8; 12],
    /// Expected encryption mode. If absent, the (authenticated) mode recorded in the
    /// sealed stream is used; the unauthenticated `xchacha20` mode must be named
    /// explicitly.
    #[serde(default)]
    pub crypto_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineRecoverResponse {
    pub success: bool,
    pub recovered_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineVerifyRequest {
    pub data: Vec<u8>,
    pub key: Vec<u8>,
    pub nonce: [u8; 12],
    pub compression_level: Option<i32>,
    pub compression_mode: Option<String>,
    pub frame_size: Option<usize>,
    pub segmentation: Option<String>,
    pub polyval_segment_size: Option<usize>,
    #[serde(default)]
    pub crypto_mode: Option<String>,
    #[serde(default)]
    pub stream_chunk_size: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivalenceVerifyRequest {
    pub data: Vec<u8>,
    pub segment_size: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecentralizedPublishRequest {
    pub stream_id: String,
    pub data: Vec<u8>,
    pub key: Vec<u8>,
    pub nonce: [u8; 12],
    #[serde(default)]
    pub crypto_mode: Option<String>,
    #[serde(default)]
    pub stream_chunk_size: Option<usize>,
}

/// One entry of [`crypto_mode_catalog`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoModeInfo {
    pub crypto_mode: CryptoMode,
    pub id: u8,
    pub description: String,
    pub authenticated: bool,
    pub tag_size_bytes: usize,
    pub overhead_bytes: usize,
    pub parallel_polyval: bool,
    /// Supports parallel STREAM chunking (`stream_chunk_size`).
    pub stream_chunking: bool,
    pub is_default: bool,
}

/// Every selectable `crypto_mode` with its properties.
pub fn crypto_mode_catalog() -> Vec<CryptoModeInfo> {
    CryptoMode::ALL
        .into_iter()
        .map(|m| CryptoModeInfo {
            crypto_mode: m,
            id: m.id(),
            description: m.description().to_string(),
            authenticated: m.is_authenticated(),
            tag_size_bytes: m.tag_len(),
            overhead_bytes: m.overhead(),
            parallel_polyval: m.uses_polyval_segmentation(),
            stream_chunking: m != CryptoMode::AesGcmSiv,
            is_default: m == CryptoMode::default(),
        })
        .collect()
}

/// Parse an optional `crypto_mode` name; `None` selects the default (AES-GCM-SIV).
pub fn parse_crypto_mode(name: Option<&str>) -> Result<CryptoMode, RestError> {
    name.map_or(Ok(CryptoMode::default()), |n| {
        n.parse().map_err(|e: CryptoError| {
            let valid: Vec<_> = CryptoMode::ALL.iter().map(|m| m.label()).collect();
            RestError::BadRequest(format!("{e}; valid: {}", valid.join(", ")))
        })
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecentralizedPublishResponse {
    pub success: bool,
    /// Which backend stored the object; `mock` results say nothing about IPFS.
    pub backend: BackendKind,
    pub backend_label: String,
    /// DAG-JSON manifest CID: the trust anchor needed to fetch the object.
    pub root_cid: Cid,
    pub manifest: ObjectManifest,
}

/// Run CPU-bound work off the async executor.
pub async fn run_blocking<T, F>(f: F) -> Result<T, RestError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| RestError::Internal(e.to_string()))
}

/// Research pipeline calls can each fan out across the Rayon pool. Keep only one admitted
/// job by default to avoid CPU oversubscription; object transfers have a separate limit.
pub const DEFAULT_MAX_CONCURRENT_COMPUTE_JOBS: usize = 1;

#[derive(Clone)]
pub struct RestServiceController {
    ipfs: Arc<ObjectStore<IpfsBackend>>,
    upload: Option<Arc<UploadConfig>>,
    compute_permits: Arc<Semaphore>,
}

impl Default for RestServiceController {
    fn default() -> Self {
        Self::new()
    }
}

impl RestServiceController {
    /// Controller backed by the in-memory **mock** IPFS store.
    pub fn new() -> Self {
        Self::with_ipfs_backend(IpfsBackend::mock())
    }

    pub fn with_ipfs_backend(backend: IpfsBackend) -> Self {
        Self {
            ipfs: Arc::new(ObjectStore::new(backend)),
            upload: None,
            compute_permits: Arc::new(Semaphore::new(DEFAULT_MAX_CONCURRENT_COMPUTE_JOBS)),
        }
    }

    /// Enable `POST /api/v1/objects/upload` with a server-side key.
    pub fn with_upload_config(mut self, config: UploadConfig) -> Self {
        self.upload = Some(Arc::new(config));
        self
    }

    /// Backend from `TODO_IPFS_BACKEND` (`mock` default, `kubo`, `gateway`) and
    /// `TODO_IPFS_URL`; uploads enabled iff `TODO_UPLOAD_KEY_HEX` is set (see
    /// [`UploadConfig::from_env`]).
    pub fn from_env() -> Result<Self, RestError> {
        let mut controller = Self::with_ipfs_backend(IpfsBackend::from_env()?);
        if let Some(cfg) = UploadConfig::from_env()? {
            controller = controller.with_upload_config(cfg);
        }
        Ok(controller)
    }

    /// Non-blocking admission for CPU-heavy research endpoints. Rejecting early keeps
    /// authenticated bursts from building an unbounded spawn_blocking/Rayon backlog.
    pub(crate) fn try_compute_permit(&self) -> Result<OwnedSemaphorePermit, RestError> {
        Arc::clone(&self.compute_permits)
            .try_acquire_owned()
            .map_err(|_| RestError::Busy("too many concurrent compute jobs"))
    }

    pub fn upload_config(&self) -> Option<&UploadConfig> {
        self.upload.as_deref()
    }

    /// Fail closed: object routes decrypt with the server key and the research API can
    /// consume substantial CPU/storage, so without `TODO_API_TOKEN` the service may only
    /// be served on a loopback address.
    pub fn check_exposure(&self, addr: std::net::SocketAddr) -> Result<(), RestError> {
        match self.upload_config() {
            Some(cfg) if !cfg.requires_token() && !addr.ip().is_loopback() => {
                Err(RestError::BadRequest(format!(
                    "refusing to serve protected routes on non-loopback {addr} without \
TODO_API_TOKEN (set a token or bind to 127.0.0.1/::1)"
                )))
            }
            _ => Ok(()),
        }
    }

    pub fn ipfs_store(&self) -> &ObjectStore<IpfsBackend> {
        &self.ipfs
    }

    pub fn ipfs_backend(&self) -> BackendKind {
        use todo_ipfs::BlockStore;
        self.ipfs.store().kind()
    }

    /// Independent Zstandard compression + one encryption with the selected
    /// `crypto_mode` (default: segment-parallel AES-GCM-SIV).
    /// CPU-bound: call from a blocking context.
    pub fn process_pipeline(
        &self,
        req: PipelineProcessRequest,
    ) -> Result<PipelineProcessResponse, RestError> {
        let mode = parse_crypto_mode(req.crypto_mode.as_deref())?;
        let pipeline = StreamCryptoPipeline::new(
            req.segment_size.unwrap_or(64 * 1024),
            req.compression_level.unwrap_or(3),
            req.polyval_segment_size
                .unwrap_or(todo_crypto::DEFAULT_POLYVAL_SEGMENT_SIZE),
        )?
        .with_crypto_mode(mode)
        .with_stream_chunking(req.stream_chunk_size)?;
        let sealed = pipeline.compress_and_encrypt(&req.data, &req.key, &req.nonce)?;
        Ok(PipelineProcessResponse {
            success: true,
            total_segments: sealed.segments.len(),
            sealed,
        })
    }

    /// Verify, decrypt and decompress. CPU-bound: call from a blocking context.
    pub fn recover_pipeline(
        &self,
        req: PipelineRecoverRequest,
    ) -> Result<PipelineRecoverResponse, RestError> {
        let mode = match req.crypto_mode.as_deref() {
            Some(name) => parse_crypto_mode(Some(name))?,
            None if req.sealed.crypto_mode.is_authenticated() => req.sealed.crypto_mode,
            None => {
                return Err(RestError::BadRequest(format!(
                    "sealed stream uses unauthenticated crypto_mode {}; name it explicitly to accept unauthenticated output",
                    req.sealed.crypto_mode
                )));
            }
        };
        let recovered_data = StreamCryptoPipeline::default()
            .with_crypto_mode(mode)
            .decrypt_and_decompress(&req.sealed, &req.key, &req.nonce)?;
        Ok(PipelineRecoverResponse {
            success: true,
            recovered_data,
        })
    }

    /// Full pipeline run with correctness checks (sequential = parallel = upstream tag,
    /// standard Zstd decode, lossless round trip) and stage metrics.
    /// CPU-bound: call from a blocking context.
    pub fn verify_pipeline(
        &self,
        req: PipelineVerifyRequest,
    ) -> Result<PipelineVerificationReport, RestError> {
        if req.data.len() > MAX_VERIFY_PAYLOAD {
            return Err(RestError::BadRequest(format!(
                "payload exceeds {MAX_VERIFY_PAYLOAD} bytes"
            )));
        }
        let mode = parse_crypto_mode(req.crypto_mode.as_deref())?;
        let level = req.compression_level.unwrap_or(3);
        if !(1..=22).contains(&level) {
            return Err(RestError::BadRequest(
                "compression_level must be 1..=22".into(),
            ));
        }
        let segmentation = match req.segmentation.as_deref().unwrap_or("adaptive") {
            "adaptive" => SegmentationStrategy::Adaptive(SegmentationPolicy::DEFAULT),
            "sequential" => SegmentationStrategy::Sequential,
            "fixed" => SegmentationStrategy::Fixed(
                req.polyval_segment_size
                    .unwrap_or(todo_crypto::DEFAULT_POLYVAL_SEGMENT_SIZE),
            ),
            other => {
                return Err(RestError::BadRequest(format!(
                    "unknown segmentation {other:?}"
                )));
            }
        };
        let pipeline = match req.compression_mode.as_deref().unwrap_or("single-frame") {
            "single-frame" => StreamCryptoPipeline::single_frame(level),
            "independent-frames" => {
                let frame = req.frame_size.unwrap_or(64 * 1024);
                if !(1024..=16 * 1024 * 1024).contains(&frame) {
                    return Err(RestError::BadRequest(
                        "frame_size must be 1 KiB..=16 MiB".into(),
                    ));
                }
                StreamCryptoPipeline::new(frame, level, 16)?
                    .with_compression_mode(CompressionMode::IndependentFrames)
            }
            other => {
                return Err(RestError::BadRequest(format!(
                    "unknown compression_mode {other:?}"
                )));
            }
        }
        .with_segmentation(segmentation)?
        .with_crypto_mode(mode)
        .with_stream_chunking(req.stream_chunk_size)?;
        Ok(pipeline.verify_pipeline_with_tag_proof(&req.data, &req.key, &req.nonce)?)
    }

    /// Sequential vs. parallel POLYVAL on `req.data` with a fixed test key.
    pub fn verify_equivalence(
        &self,
        req: EquivalenceVerifyRequest,
    ) -> Result<TagEquivalenceReport, RestError> {
        let h_key = [0x7au8; 16];
        Ok(assert_polyval_equivalence(
            &h_key,
            &req.data,
            req.segment_size.unwrap_or(16 * 1024),
        )?)
    }

    /// Sequential vs. parallel vs. upstream AES-GCM-SIV.
    pub fn verify_aes_gcm_siv_equivalence(
        &self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
        segment_size: Option<usize>,
    ) -> Result<TagEquivalenceReport, RestError> {
        Ok(assert_aes_gcm_siv_equivalence(
            key,
            nonce,
            aad,
            plaintext,
            segment_size.unwrap_or(16 * 1024),
        )?)
    }

    /// Compress + encrypt (on the blocking pool), then store the serialized sealed stream
    /// as [`IPFS_BLOCK_SIZE`] raw blocks plus a DAG-JSON manifest, pinned by root CID.
    /// Only ciphertext leaves this process.
    pub async fn publish_to_ipfs(
        &self,
        req: DecentralizedPublishRequest,
    ) -> Result<DecentralizedPublishResponse, RestError> {
        let DecentralizedPublishRequest {
            stream_id,
            data,
            key,
            nonce,
            crypto_mode,
            stream_chunk_size,
        } = req;
        let mode = parse_crypto_mode(crypto_mode.as_deref())?;
        let sealed = run_blocking(move || {
            StreamCryptoPipeline::default()
                .with_crypto_mode(mode)
                .with_stream_chunking(stream_chunk_size)?
                .compress_and_encrypt(&data, &key, &nonce)
        })
        .await??;

        let published = self.ipfs.put_object(&stream_id, sealed.to_bytes()).await?;
        Ok(DecentralizedPublishResponse {
            success: true,
            backend: published.backend,
            backend_label: published.backend.label().to_string(),
            root_cid: published.root,
            manifest: published.manifest,
        })
    }

    /// Fetch a sealed stream by trusted root CID. Blocks are verified against their CIDs
    /// here; the AEAD tag is still checked on recovery.
    pub async fn fetch_from_ipfs(&self, root: &Cid) -> Result<SealedStream, RestError> {
        let (_, bytes) = self.ipfs.get_object(root).await?;
        Ok(SealedStream::from_bytes(&bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rest_controller_end_to_end() {
        let controller = RestServiceController::new();
        let key = vec![0x11u8; 16];
        let nonce = [0x22u8; 12];
        let raw_data = b"Hello, research REST service for parallel AES-GCM-SIV!".to_vec();

        let proc_resp = controller
            .process_pipeline(PipelineProcessRequest {
                data: raw_data.clone(),
                key: key.clone(),
                nonce,
                segment_size: Some(16 * 1024),
                compression_level: Some(3),
                polyval_segment_size: Some(64),
                crypto_mode: None,
                stream_chunk_size: None,
            })
            .unwrap();
        assert!(proc_resp.success);
        assert_eq!(proc_resp.total_segments, 1);

        let rec_resp = controller
            .recover_pipeline(PipelineRecoverRequest {
                sealed: proc_resp.sealed,
                key: key.clone(),
                nonce,
                crypto_mode: None,
            })
            .unwrap();
        assert_eq!(rec_resp.recovered_data, raw_data);

        let eq_resp = controller
            .verify_equivalence(EquivalenceVerifyRequest {
                data: raw_data.clone(),
                segment_size: Some(16),
            })
            .unwrap();
        assert!(eq_resp.is_bit_identical);

        let ipfs_resp = controller
            .publish_to_ipfs(DecentralizedPublishRequest {
                stream_id: "stream-test-42".to_string(),
                data: raw_data.clone(),
                key: key.clone(),
                nonce,
                crypto_mode: None,
                stream_chunk_size: None,
            })
            .await
            .unwrap();
        assert_eq!(ipfs_resp.backend, BackendKind::Mock);
        assert!(!ipfs_resp.manifest.blocks().is_empty());

        let sealed = controller
            .fetch_from_ipfs(&ipfs_resp.root_cid)
            .await
            .unwrap();
        let rec = controller
            .recover_pipeline(PipelineRecoverRequest {
                sealed,
                key,
                nonce,
                crypto_mode: None,
            })
            .unwrap();
        assert_eq!(rec.recovered_data, raw_data);
    }

    #[tokio::test]
    async fn every_crypto_mode_roundtrips_through_rest_and_ipfs() {
        let controller = RestServiceController::new();
        let key = vec![0x5cu8; 32];
        let nonce = [0x33u8; 12];
        let data = b"crypto_mode selection through REST + IPFS mock".repeat(50);
        for info in crypto_mode_catalog() {
            let mode = info.crypto_mode;
            let processed = controller
                .process_pipeline(PipelineProcessRequest {
                    data: data.clone(),
                    key: key.clone(),
                    nonce,
                    segment_size: None,
                    compression_level: None,
                    polyval_segment_size: None,
                    crypto_mode: Some(mode.label().to_string()),
                    stream_chunk_size: None,
                })
                .unwrap();
            assert_eq!(processed.sealed.crypto_mode, mode);
            assert_eq!(processed.sealed.tag.len(), mode.tag_len());

            let explicit = Some(mode.label().to_string());
            let rec = controller
                .recover_pipeline(PipelineRecoverRequest {
                    sealed: processed.sealed.clone(),
                    key: key.clone(),
                    nonce,
                    crypto_mode: explicit.clone(),
                })
                .unwrap();
            assert_eq!(rec.recovered_data, data, "{mode}");

            let implicit = controller.recover_pipeline(PipelineRecoverRequest {
                sealed: processed.sealed,
                key: key.clone(),
                nonce,
                crypto_mode: None,
            });
            if mode.is_authenticated() {
                assert_eq!(implicit.unwrap().recovered_data, data);
            } else {
                assert!(matches!(implicit, Err(RestError::BadRequest(_))));
            }

            let published = controller
                .publish_to_ipfs(DecentralizedPublishRequest {
                    stream_id: format!("mode-{mode}"),
                    data: data.clone(),
                    key: key.clone(),
                    nonce,
                    crypto_mode: explicit.clone(),
                    stream_chunk_size: None,
                })
                .await
                .unwrap();
            let sealed = controller
                .fetch_from_ipfs(&published.root_cid)
                .await
                .unwrap();
            assert_eq!(sealed.crypto_mode, mode);
            let rec = controller
                .recover_pipeline(PipelineRecoverRequest {
                    sealed,
                    key: key.clone(),
                    nonce,
                    crypto_mode: explicit,
                })
                .unwrap();
            assert_eq!(rec.recovered_data, data);
        }
    }

    #[test]
    fn crypto_mode_mismatch_and_unknown_mode_are_rejected() {
        let controller = RestServiceController::new();
        let processed = controller
            .process_pipeline(PipelineProcessRequest {
                data: b"abc".to_vec(),
                key: vec![1; 16],
                nonce: [2; 12],
                segment_size: None,
                compression_level: None,
                polyval_segment_size: None,
                crypto_mode: Some("aegis-256".into()),
                stream_chunk_size: None,
            })
            .unwrap();
        let res = controller.recover_pipeline(PipelineRecoverRequest {
            sealed: processed.sealed,
            key: vec![1; 16],
            nonce: [2; 12],
            crypto_mode: Some("xchacha20".into()),
        });
        assert!(matches!(
            res,
            Err(RestError::Pipeline(
                PipelineError::CryptoModeMismatch { .. }
            ))
        ));
        assert!(matches!(
            parse_crypto_mode(Some("des")),
            Err(RestError::BadRequest(_))
        ));
    }

    #[test]
    fn stream_chunking_through_rest() {
        let controller = RestServiceController::new();
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let data: Vec<u8> = (0..60_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        let request = |mode: &str, chunk| PipelineProcessRequest {
            data: data.clone(),
            key: vec![9; 32],
            nonce: [4; 12],
            segment_size: None,
            compression_level: None,
            polyval_segment_size: None,
            crypto_mode: Some(mode.into()),
            stream_chunk_size: chunk,
        };
        let processed = controller
            .process_pipeline(request("ascon-aead128", Some(4096)))
            .unwrap();
        assert_eq!(
            processed.sealed.version,
            todo_zstd::SEALED_STREAM_VERSION_STREAM
        );
        assert!(processed.sealed.aead_chunks().unwrap() >= 3);
        let recovered = controller
            .recover_pipeline(PipelineRecoverRequest {
                sealed: processed.sealed.clone(),
                key: vec![9; 32],
                nonce: [4; 12],
                crypto_mode: None,
            })
            .unwrap();
        assert_eq!(recovered.recovered_data, data);

        let mut swapped = processed.sealed;
        let slot = 4096 + CryptoMode::AsconAead128.overhead();
        let (a, rest) = swapped.ciphertext.split_at_mut(slot);
        a.swap_with_slice(&mut rest[..slot]);
        assert!(matches!(
            controller.recover_pipeline(PipelineRecoverRequest {
                sealed: swapped,
                key: vec![9; 32],
                nonce: [4; 12],
                crypto_mode: None,
            }),
            Err(RestError::Pipeline(PipelineError::Crypto(
                CryptoError::AuthenticationFailed
            )))
        ));

        for (mode, chunk) in [("aes-gcm-siv", 4096), ("aegis-256", 16)] {
            assert!(matches!(
                controller.process_pipeline(request(mode, Some(chunk))),
                Err(RestError::Pipeline(PipelineError::Crypto(_)))
            ));
        }
    }

    #[test]
    fn invalid_polyval_segment_size_is_rejected() {
        let res = RestServiceController::new().process_pipeline(PipelineProcessRequest {
            data: vec![1, 2, 3],
            key: vec![0; 16],
            nonce: [0; 12],
            segment_size: None,
            compression_level: None,
            polyval_segment_size: Some(10),
            crypto_mode: None,
            stream_chunk_size: None,
        });
        assert!(matches!(res, Err(RestError::Pipeline(_))));
    }
}
