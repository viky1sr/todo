//! Minimal HTTP/1.1 REST server on Tokio.
//!
//! The async tasks only handle socket I/O; all CPU-bound work is dispatched to the
//! blocking pool via [`run_blocking`].

use crate::download::OBJECTS_PREFIX;
use crate::tls::{HANDSHAKE_TIMEOUT, TlsAcceptor};
use crate::{
    DecentralizedPublishRequest, EquivalenceVerifyRequest, PipelineProcessRequest,
    PipelineRecoverRequest, PipelineVerifyRequest, RestError, RestServiceController, UPLOAD_ROUTE,
    UploadHeaders, crypto_mode_catalog, download, run_blocking, upload,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use todo_ipfs::IpfsError;
use todo_zstd::{PipelineError, SealedStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiProcessPayload {
    pub data_utf8: Option<String>,
    pub data_hex: Option<String>,
    pub key_hex: String,
    pub nonce_hex: String,
    pub segment_size: Option<usize>,
    pub compression_level: Option<i32>,
    pub polyval_segment_size: Option<usize>,
    /// See `GET /api/v1/crypto-modes`; default `aes-gcm-siv`.
    pub crypto_mode: Option<String>,
    /// Non-AES modes: parallel STREAM chunk size in bytes (default: one AEAD message).
    pub stream_chunk_size: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiRecoverPayload {
    pub sealed: SealedStream,
    pub key_hex: String,
    pub nonce_hex: String,
    /// Expected mode; required to accept the unauthenticated `xchacha20` mode.
    pub crypto_mode: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiVerifyPayload {
    pub data_utf8: Option<String>,
    pub data_hex: Option<String>,
    pub segment_size: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiIpfsPayload {
    pub stream_id: String,
    pub data_utf8: Option<String>,
    pub data_hex: Option<String>,
    pub key_hex: String,
    pub nonce_hex: String,
    pub crypto_mode: Option<String>,
    pub stream_chunk_size: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiVerifyPipelinePayload {
    pub data_utf8: Option<String>,
    pub data_hex: Option<String>,
    pub key_hex: String,
    pub nonce_hex: String,
    pub compression_level: Option<i32>,
    /// `single-frame` (default) or `independent-frames`.
    pub compression_mode: Option<String>,
    /// Input bytes per frame for `independent-frames`.
    pub frame_size: Option<usize>,
    /// `adaptive` (default), `sequential` or `fixed`.
    pub segmentation: Option<String>,
    /// POLYVAL segment size for `fixed`.
    pub polyval_segment_size: Option<usize>,
    pub crypto_mode: Option<String>,
    /// Non-AES modes: parallel STREAM chunk size in bytes.
    pub stream_chunk_size: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiIpfsFetchPayload {
    pub root_cid: String,
    pub key_hex: String,
    pub nonce_hex: String,
    pub crypto_mode: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
    pub rust_edition: &'static str,
}

pub struct RestApiServer {
    pub host: String,
    pub port: u16,
    controller: Arc<RestServiceController>,
    tls: Option<TlsAcceptor>,
}

impl RestApiServer {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            controller: Arc::new(RestServiceController::new()),
            tls: None,
        }
    }

    /// Serve HTTPS (TLS 1.3 only, see [`crate::tls`]) instead of plain HTTP.
    pub fn with_tls(mut self, acceptor: TlsAcceptor) -> Self {
        self.tls = Some(acceptor);
        self
    }

    pub fn with_controller(host: &str, port: u16, controller: RestServiceController) -> Self {
        Self {
            host: host.to_string(),
            port,
            controller: Arc::new(controller),
            tls: None,
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = format!("{}:{}", self.host, self.port);
        let listener = TcpListener::bind(&addr).await?;
        let local = listener.local_addr()?;
        self.controller.check_exposure(local)?;
        let scheme = if self.tls.is_some() { "https" } else { "http" };
        println!("REST API listening on {scheme}://{addr}");
        if self.tls.is_some() {
            println!("  TLS 1.3 only (rustls/aws-lc-rs)");
        }
        if let Some(w) = crate::tls::plaintext_exposure_warning(local, self.tls.is_some()) {
            eprintln!("{w}");
        }
        println!("  GET  /api/v1/health");
        println!("  GET  /api/v1/benchmark");
        println!("  GET  /api/v1/crypto-modes");
        println!("  POST /api/v1/pipeline/process");
        println!("  POST /api/v1/pipeline/recover");
        println!("  POST /api/v1/pipeline/verify");
        println!("  POST /api/v1/verify-equivalence");
        println!("  POST /api/v1/ipfs/fetch");
        println!(
            "  POST /api/v1/ipfs/publish   [IPFS backend: {}]",
            self.controller.ipfs_backend().label()
        );
        println!("  GET  {OBJECTS_PREFIX}{{cid}}?nonce=<hex>");
        println!(
            "  POST {UPLOAD_ROUTE}   [{}]",
            match self.controller.upload_config() {
                Some(cfg) if cfg.requires_token() => "enabled, bearer token required",
                Some(_) => "enabled, NO authentication (loopback only)",
                None => "disabled: set TODO_UPLOAD_KEY_HEX",
            }
        );

        serve_with(listener, Arc::clone(&self.controller), self.tls.clone()).await
    }
}

/// Accept plain-HTTP connections on `listener` forever, one task per connection.
pub async fn serve(
    listener: TcpListener,
    controller: Arc<RestServiceController>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    serve_with(listener, controller, None).await
}

/// Like [`serve`], with a TLS handshake (bounded by [`HANDSHAKE_TIMEOUT`]) first when
/// `tls` is set. Failed handshakes are dropped silently.
pub async fn serve_with(
    listener: TcpListener,
    controller: Arc<RestServiceController>,
    tls: Option<TlsAcceptor>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let connections = Arc::new(Semaphore::new(DEFAULT_MAX_CONCURRENT_CONNECTIONS));
    loop {
        // Acquire before accept so the number of live connection tasks is bounded. Excess
        // clients remain in the kernel listen backlog instead of allocating Tokio tasks.
        let permit = Arc::clone(&connections).acquire_owned().await?;
        let (socket, _) = listener.accept().await?;
        let controller = Arc::clone(&controller);
        let tls = tls.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let result = match tls {
                None => handle_connection(socket, controller).await,
                Some(acceptor) => {
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(socket)).await {
                        Ok(Ok(stream)) => handle_connection(stream, controller).await,
                        _ => return,
                    }
                }
            };
            if let Err(e) = result {
                eprintln!("connection error: {e}");
            }
        });
    }
}

pub fn status_of(err: &RestError) -> u16 {
    match err {
        RestError::Busy(_) => 429,
        RestError::BadRequest(_)
        | RestError::Crypto(_)
        | RestError::Pipeline(PipelineError::Crypto(_))
        | RestError::Pipeline(PipelineError::MalformedStream(_))
        | RestError::Pipeline(PipelineError::CryptoModeMismatch { .. })
        | RestError::Storage(IpfsError::InvalidCid(_) | IpfsError::InvalidManifest(_)) => 400,
        RestError::Storage(IpfsError::NotFound(_)) => 404,
        _ => 500,
    }
}

fn to_json<T: Serialize>(value: &T) -> Result<Value, RestError> {
    serde_json::to_value(value).map_err(|e| RestError::Internal(e.to_string()))
}

fn parse<T: for<'de> Deserialize<'de>>(body: &str) -> Result<T, RestError> {
    serde_json::from_str(body).map_err(|e| RestError::BadRequest(format!("JSON parse error: {e}")))
}

fn parse_key_nonce(key_hex: &str, nonce_hex: &str) -> Result<(Vec<u8>, [u8; 12]), RestError> {
    let key = decode_hex(key_hex)
        .filter(|k| k.len() == 16 || k.len() == 32)
        .ok_or_else(|| RestError::BadRequest("key must be 16 or 32 bytes of hex".into()))?;
    let nonce = decode_hex(nonce_hex)
        .and_then(|n| <[u8; 12]>::try_from(n).ok())
        .ok_or_else(|| RestError::BadRequest("nonce must be 12 bytes of hex".into()))?;
    Ok((key, nonce))
}

async fn route(
    method: &str,
    path: &str,
    body: &str,
    controller: Arc<RestServiceController>,
) -> Result<Value, RestError> {
    match (method, path) {
        ("GET", "/api/v1/health") => to_json(&HealthResponse {
            status: "ok",
            service: "parallel-aes-gcm-siv-zstd-rest-api",
            version: env!("CARGO_PKG_VERSION"),
            rust_edition: "2024",
        }),
        ("GET", "/api/v1/benchmark") => {
            let results = run_blocking(|| {
                todo_crypto::run_standard_suite(todo_crypto::DEFAULT_POLYVAL_SEGMENT_SIZE)
            })
            .await??;
            to_json(&results)
        }
        ("GET", "/api/v1/crypto-modes") => to_json(&crypto_mode_catalog()),
        ("POST", "/api/v1/pipeline/process") => {
            let p: ApiProcessPayload = parse(body)?;
            let data = extract_data(p.data_utf8, p.data_hex)?;
            let (key, nonce) = parse_key_nonce(&p.key_hex, &p.nonce_hex)?;
            let req = PipelineProcessRequest {
                data,
                key,
                nonce,
                segment_size: p.segment_size,
                compression_level: p.compression_level,
                polyval_segment_size: p.polyval_segment_size,
                crypto_mode: p.crypto_mode,
                stream_chunk_size: p.stream_chunk_size,
            };
            let res = run_blocking(move || controller.process_pipeline(req)).await??;
            to_json(&res)
        }
        ("POST", "/api/v1/pipeline/recover") => {
            let p: ApiRecoverPayload = parse(body)?;
            let (key, nonce) = parse_key_nonce(&p.key_hex, &p.nonce_hex)?;
            let req = PipelineRecoverRequest {
                sealed: p.sealed,
                key,
                nonce,
                crypto_mode: p.crypto_mode,
            };
            let res = run_blocking(move || controller.recover_pipeline(req)).await??;
            Ok(json!({
                "success": true,
                "recovered_size_bytes": res.recovered_data.len(),
                "recovered_utf8": String::from_utf8(res.recovered_data.clone()).ok(),
                "recovered_hex": encode_hex(&res.recovered_data),
            }))
        }
        ("POST", "/api/v1/pipeline/verify") => {
            let p: ApiVerifyPipelinePayload = parse(body)?;
            let data = extract_data(p.data_utf8, p.data_hex)?;
            let (key, nonce) = parse_key_nonce(&p.key_hex, &p.nonce_hex)?;
            let req = PipelineVerifyRequest {
                data,
                key,
                nonce,
                compression_level: p.compression_level,
                compression_mode: p.compression_mode,
                frame_size: p.frame_size,
                segmentation: p.segmentation,
                polyval_segment_size: p.polyval_segment_size,
                crypto_mode: p.crypto_mode,
                stream_chunk_size: p.stream_chunk_size,
            };
            let res = run_blocking(move || controller.verify_pipeline(req)).await??;
            to_json(&res)
        }
        ("POST", "/api/v1/verify-equivalence") => {
            let p: ApiVerifyPayload = parse(body)?;
            let req = EquivalenceVerifyRequest {
                data: extract_data(p.data_utf8, p.data_hex)?,
                segment_size: p.segment_size,
            };
            let res = run_blocking(move || controller.verify_equivalence(req)).await??;
            to_json(&res)
        }
        ("POST", "/api/v1/ipfs/publish") => {
            let p: ApiIpfsPayload = parse(body)?;
            let data = extract_data(p.data_utf8, p.data_hex)?;
            let (key, nonce) = parse_key_nonce(&p.key_hex, &p.nonce_hex)?;
            let res = controller
                .publish_to_ipfs(DecentralizedPublishRequest {
                    stream_id: p.stream_id,
                    data,
                    key,
                    nonce,
                    crypto_mode: p.crypto_mode,
                    stream_chunk_size: p.stream_chunk_size,
                })
                .await?;
            to_json(&res)
        }
        ("POST", "/api/v1/ipfs/fetch") => {
            let p: ApiIpfsFetchPayload = parse(body)?;
            let root = p
                .root_cid
                .parse()
                .map_err(|e: IpfsError| RestError::BadRequest(e.to_string()))?;
            let (key, nonce) = parse_key_nonce(&p.key_hex, &p.nonce_hex)?;
            let sealed = controller.fetch_from_ipfs(&root).await?;
            let req = PipelineRecoverRequest {
                sealed,
                key,
                nonce,
                crypto_mode: p.crypto_mode,
            };
            let res = run_blocking(move || controller.recover_pipeline(req)).await??;
            Ok(json!({
                "success": true,
                "root_cid": root,
                "recovered_size_bytes": res.recovered_data.len(),
                "recovered_utf8": String::from_utf8(res.recovered_data.clone()).ok(),
                "recovered_hex": encode_hex(&res.recovered_data),
            }))
        }
        _ => Err(RestError::BadRequest("route not found".into())),
    }
}

/// Every API route as `(method, path)`.
pub const API_ROUTES: &[(&str, &str)] = &[
    ("GET", "/api/v1/health"),
    ("GET", "/api/v1/benchmark"),
    ("GET", "/api/v1/crypto-modes"),
    ("POST", "/api/v1/pipeline/process"),
    ("POST", "/api/v1/pipeline/recover"),
    ("POST", "/api/v1/pipeline/verify"),
    ("POST", "/api/v1/verify-equivalence"),
    ("POST", "/api/v1/ipfs/publish"),
    ("POST", "/api/v1/ipfs/fetch"),
];

/// Route one API request; returns the HTTP status and JSON body. Shared with the web
/// front-end server so both expose identical API semantics.
pub async fn dispatch(
    method: &str,
    path: &str,
    body: &str,
    controller: Arc<RestServiceController>,
) -> (u16, Value) {
    if !API_ROUTES.contains(&(method, path)) {
        return (404, json!({ "error": "route not found" }));
    }
    let _compute_permit = if api_route_requires_compute(method, path) {
        match controller.try_compute_permit() {
            Ok(permit) => Some(permit),
            Err(e) => return (status_of(&e), json!({ "error": e.to_string() })),
        }
    } else {
        None
    };
    match route(method, path, body, controller).await {
        Ok(v) => (200, v),
        Err(e) => (status_of(&e), json!({ "error": e.to_string() })),
    }
}

/// Upper bound on concurrently accepted connections. This bounds socket/task memory even
/// when clients connect and then stop sending bytes.
pub const DEFAULT_MAX_CONCURRENT_CONNECTIONS: usize = 256;
/// Whole-request deadline for receiving HTTP headers (slowloris protection).
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Whole-request deadline for receiving a buffered JSON body. Object uploads have their own
/// streaming idle timeout and do not use this value.
pub const JSON_BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Upper bound on request headers.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
/// Upper bound on JSON request bodies (the upload route streams to disk instead).
pub const MAX_JSON_BODY_BYTES: usize = 12 * 1024 * 1024;

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Public discovery endpoints remain unauthenticated. All CPU/storage-affecting REST API
/// routes require the same bearer token as object transfer routes when a token is configured.
fn api_route_requires_auth(method: &str, path: &str) -> bool {
    API_ROUTES.contains(&(method, path))
        && !matches!(
            (method, path),
            ("GET", "/api/v1/health") | ("GET", "/api/v1/crypto-modes")
        )
}

fn api_route_requires_compute(method: &str, path: &str) -> bool {
    api_route_requires_auth(method, path)
}

async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    controller: Arc<RestServiceController>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buffer = Vec::with_capacity(8192);
    let mut chunk = vec![0u8; 65536];
    let header_deadline = tokio::time::Instant::now() + HEADER_READ_TIMEOUT;
    let header_end = loop {
        if let Some(pos) = find_header_end(&buffer) {
            if pos + 4 > MAX_HEADER_BYTES {
                return write_json(&mut stream, 431, &json!({ "error": "headers too large" })).await;
            }
            break pos;
        }
        if buffer.len() >= MAX_HEADER_BYTES {
            return write_json(&mut stream, 431, &json!({ "error": "headers too large" })).await;
        }
        let n = match tokio::time::timeout_at(header_deadline, stream.read(&mut chunk)).await {
            Ok(read) => read?,
            Err(_) => {
                return write_json(&mut stream, 408, &json!({ "error": "request header timeout" }))
                    .await;
            }
        };
        if n == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&chunk[..n]);
    };

    let head = match std::str::from_utf8(&buffer[..header_end]) {
        Ok(head) => head,
        Err(_) => return write_json(&mut stream, 400, &json!({ "error": "invalid header" })).await,
    };
    let mut lines = head.split("\r\n");
    let mut parts = lines.next().unwrap_or("").split_whitespace();
    let (Some(method), Some(path), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
        return write_json(&mut stream, 400, &json!({ "error": "malformed request line" })).await;
    };
    if parts.next().is_some() || !version.starts_with("HTTP/1.") || !path.starts_with('/') {
        return write_json(&mut stream, 400, &json!({ "error": "unsupported request" })).await;
    }
    let method = method.to_string();
    let path = path.to_string();

    let mut headers = UploadHeaders::default();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return write_json(&mut stream, 400, &json!({ "error": "malformed header" })).await;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => {
                if headers.content_length.is_some() {
                    return write_json(
                        &mut stream,
                        400,
                        &json!({ "error": "duplicate Content-Length" }),
                    )
                    .await;
                }
                match value.parse() {
                    Ok(n) => headers.content_length = Some(n),
                    Err(_) => {
                        let body = json!({ "error": "invalid Content-Length" });
                        return write_json(&mut stream, 400, &body).await;
                    }
                }
            }
            "transfer-encoding" => headers.chunked = true,
            "content-type" => headers.content_type = Some(value.to_string()),
            "x-object-id" => headers.object_id = Some(value.to_string()),
            "authorization" => headers.authorization = Some(Zeroizing::new(value.to_string())),
            _ => {}
        }
    }

    if method == "OPTIONS" {
        let response = "HTTP/1.1 204 No Content\r\n\
Access-Control-Allow-Origin: *\r\n\
Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
Access-Control-Allow-Headers: Content-Type, X-Object-Id, Authorization\r\n\
Content-Length: 0\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;
        return Ok(());
    }
    if headers.chunked {
        return write_json(
            &mut stream,
            411,
            &json!({ "error": "Transfer-Encoding is not supported; send Content-Length" }),
        )
        .await;
    }

    if method == "GET" && download::parse_target(&path).is_some() {
        let auth = headers.authorization.as_deref().map(String::as_str);
        return match download::prepare_download(&controller, &path, auth).await {
            // No Access-Control-Allow-Origin: other origins must not read plaintext.
            Ok(obj) => {
                let head = format!(
                    "HTTP/1.1 200 OK\r\n{}Connection: close\r\n\r\n",
                    obj.headers()
                );
                stream.write_all(head.as_bytes()).await?;
                obj.write_body(&mut stream).await?;
                stream.flush().await?;
                let _ = stream.shutdown().await;
                Ok(())
            }
            Err(e) => {
                let body = json!({ "status": "error", "error": e.message });
                write_json(&mut stream, e.status, &body).await
            }
        };
    }

    let prefix = &buffer[header_end + 4..];
    if method == "POST" && path == UPLOAD_ROUTE {
        let (status, body) =
            upload::handle_upload(&controller, &headers, prefix, &mut stream).await;
        return write_json(&mut stream, status, &body).await;
    }

    if method == "POST" && API_ROUTES.contains(&(method.as_str(), path.as_str())) {
        if headers.content_length.is_none() {
            return write_json(&mut stream, 411, &json!({ "error": "Content-Length required" }))
                .await;
        }
        let is_json = headers
            .content_type
            .as_deref()
            .and_then(|ct| ct.split(';').next())
            .is_some_and(|ct| ct.trim().eq_ignore_ascii_case("application/json"));
        if !is_json {
            return write_json(
                &mut stream,
                415,
                &json!({ "error": "Content-Type must be application/json" }),
            )
            .await;
        }
    }

    if api_route_requires_auth(&method, &path)
        && let Some(cfg) = controller.upload_config()
    {
        let auth = headers.authorization.as_deref().map(String::as_str);
        if let Err(e) = cfg.authorize(auth) {
            return write_json(
                &mut stream,
                e.status,
                &json!({ "status": "error", "error": e.message }),
            )
            .await;
        }
    }

    let len = usize::try_from(headers.content_length.unwrap_or(0)).unwrap_or(usize::MAX);
    if len > MAX_JSON_BODY_BYTES {
        return write_json(
            &mut stream,
            413,
            &json!({ "error": "request body too large" }),
        )
        .await;
    }
    let mut body = prefix[..prefix.len().min(len)].to_vec();
    let body_deadline = tokio::time::Instant::now() + JSON_BODY_READ_TIMEOUT;
    while body.len() < len {
        let want = (len - body.len()).min(chunk.len());
        let n = match tokio::time::timeout_at(body_deadline, stream.read(&mut chunk[..want])).await {
            Ok(read) => read?,
            Err(_) => {
                return write_json(&mut stream, 408, &json!({ "error": "request body timeout" }))
                    .await;
            }
        };
        if n == 0 {
            return write_json(&mut stream, 400, &json!({ "error": "truncated request body" }))
                .await;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8_lossy(&body);

    let (status_code, json_response) = dispatch(&method, &path, &body, controller).await;
    write_json(&mut stream, status_code, &json_response).await
}

async fn write_json<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status_code: u16,
    value: &Value,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let json_response = value.to_string();
    let status_text = match status_code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };

    let challenge = if status_code == 401 {
        "WWW-Authenticate: Bearer\r\n"
    } else {
        ""
    };
    let response = format!(
        "HTTP/1.1 {status_code} {status_text}\r\n{challenge}\
Content-Type: application/json\r\n\
Access-Control-Allow-Origin: *\r\n\
Content-Length: {}\r\n\
Connection: close\r\n\r\n{json_response}",
        json_response.len(),
    );
    stream.write_all(response.as_bytes()).await?;
    // Flush (TLS buffers records) and close the write side (TLS close_notify).
    stream.flush().await?;
    let _ = stream.shutdown().await;
    Ok(())
}

fn extract_data(utf8: Option<String>, hex: Option<String>) -> Result<Vec<u8>, RestError> {
    match (hex, utf8) {
        (Some(h), _) => {
            decode_hex(&h).ok_or_else(|| RestError::BadRequest("invalid data_hex".into()))
        }
        (None, Some(u)) => Ok(u.into_bytes()),
        (None, None) => Ok(Vec::new()),
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = s.trim().as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    let nibble = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    pairs
        .iter()
        .map(|[hi, lo]| Some(nibble(*hi)? << 4 | nibble(*lo)?))
        .collect()
}

fn encode_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use todo_crypto::CryptoError;

    #[test]
    fn hex_roundtrip_and_rejects_garbage() {
        assert_eq!(decode_hex("00ff10"), Some(vec![0x00, 0xff, 0x10]));
        assert_eq!(decode_hex("0"), None);
        assert_eq!(decode_hex("zz"), None);
        assert_eq!(decode_hex("é"), None);
        assert_eq!(encode_hex(&[0xab, 0x01]), "ab01");
    }

    #[test]
    fn auth_failure_is_client_error() {
        let e = RestError::Pipeline(PipelineError::Crypto(CryptoError::AuthenticationFailed));
        assert_eq!(status_of(&e), 400);
    }

    #[test]
    fn only_safe_discovery_routes_are_public() {
        assert!(!api_route_requires_auth("GET", "/api/v1/health"));
        assert!(!api_route_requires_auth("GET", "/api/v1/crypto-modes"));
        assert!(api_route_requires_auth("GET", "/api/v1/benchmark"));
        assert!(api_route_requires_auth("POST", "/api/v1/pipeline/process"));
        assert!(api_route_requires_auth("POST", "/api/v1/ipfs/publish"));
        assert!(!api_route_requires_auth("GET", "/not-an-api-route"));
        assert!(!api_route_requires_compute("GET", "/api/v1/health"));
        assert!(api_route_requires_compute("GET", "/api/v1/benchmark"));
        assert!(api_route_requires_compute("POST", "/api/v1/pipeline/verify"));
    }
}
