//! Same-origin web server: Askama pages, embedded static assets and the `/api/v1/*`
//! routes of `todo-rest` (via [`todo_rest::server::dispatch`]).
//!
//! Hardening: bounded headers/body, read timeouts, strict CSP (no inline script/style),
//! `nosniff`, no framing, `no-store` on pages and API responses. POST `/api/*` requires
//! `Content-Type: application/json` and a same-origin `Origin` (when sent), so a foreign
//! page cannot trigger API calls with a simple cross-site form post. Exception:
//! `POST /api/v1/objects/upload` takes a raw `application/octet-stream` body (same-origin
//! check still applies) that is streamed to disk by `todo_rest::upload` instead of being
//! buffered. Only the object routes are access-controlled (`TODO_API_TOKEN`); bind to
//! loopback or put the console behind an authenticating proxy.
//!
//! Accounts (optional, [`WebApp::with_auth`]): `POST /api/v1/auth/login`, `POST
//! /api/v1/auth/logout`, `GET /api/v1/auth/me` and the `/account` page. A login sets an
//! `HttpOnly; SameSite=Strict` session cookie (`__Host-todo_sid; Secure` over HTTPS,
//! `todo_sid` over plain HTTP) holding a random 256-bit token; the server keeps only its
//! SHA-256 in Redis ([`todo_database::sessions`]). With accounts enabled, the object routes
//! accept a valid session; otherwise the bearer token (if configured) is required, and
//! without a token configured an anonymous caller gets 401. Login is rate-limited per
//! peer IP and per username (the peer is the TCP peer: put no proxy in front without
//! adapting this).
//!
//! [`serve_with`] optionally terminates TLS 1.3 in-process ([`todo_rest::tls`]); HTTPS
//! responses add `Strict-Transport-Security`.
//!
//! Compression ([`negotiate`], [`encode_response`]): `Content-Encoding: zstd` (preferred,
//! window ≤ 8 MiB per RFC 9659) or `gzip`, only for successful HTML pages and static
//! assets. API JSON, decrypted downloads and error pages are never compressed: they may
//! mix secrets with attacker-influenced input (BREACH-style length oracle).

use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use askama::Template;
use rukubo::Rukubo;
use serde_json::json;
use todo_database::accounts::{AccountDirectory, AccountError};
use todo_database::objects::{CatalogError, NewObject, ObjectCatalog};
use todo_database::sessions::{Session, SessionStore};
use todo_rest::server::dispatch;
use todo_rest::tls::{HANDSHAKE_TIMEOUT, TlsAcceptor};
use todo_rest::{ObjectError, RestServiceController, UPLOAD_ROUTE, UploadHeaders, UploadReceipt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

use crate::pages;

/// Maximum request body (a 4 MiB input hex-encoded plus JSON framing).
pub const MAX_BODY_BYTES: usize = 12 * 1024 * 1024;
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Sent on HTTPS responses only (RFC 6797: ignored over plain HTTP anyway).
const HSTS: &str = "Strict-Transport-Security: max-age=31536000\r\n";

const CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval' 'sha256-WMsi5gjKAFuJxSHnxEDr/gSOE2WlyQUdtTrcYklgQ4Q='; script-src-elem 'self'; style-src 'self'; img-src 'self' data:; \
connect-src 'self' http://127.0.0.1:8080 http://localhost:8080 https://trustless-gateway.link https://ipfs.io https://dweb.link https://cloudflare-ipfs.com; \
font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

const APP_CSS: &str = include_str!("../static/app.css");
const APP_JS: &str = include_str!("../static/app.js");
const THEME_JS: &str = include_str!("../static/theme.js");
const FAVICON_SVG: &str = include_str!("../static/favicon.svg");
const SW_JS: &str = include_str!("../static/sw.js");
const TODO_WASM: &[u8] = include_bytes!("../static/wasm/todo_wasm.wasm");

/// Session cookie names: the `__Host-` prefix (requires `Secure`, `Path=/`, no `Domain`)
/// is used over HTTPS only, since browsers refuse `Secure` cookies on plain HTTP.
pub const SESSION_COOKIE_TLS: &str = "__Host-todo_sid";
pub const SESSION_COOKIE_PLAIN: &str = "todo_sid";

/// A secret request/response value: zeroized on drop, redacted in `Debug`.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SecretValue(pub Zeroizing<String>);

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl SecretValue {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Login/session services; see the module docs.
pub struct WebAuth {
    pub accounts: Arc<dyn AccountDirectory>,
    pub sessions: Arc<SessionStore>,
}

/// Bodies smaller than this are sent as-is (headers/frame overhead dominates).
pub const MIN_COMPRESS_BYTES: usize = 256;
/// Rendered pages: fast levels (per request). Static assets: compressed once, max levels.
const PAGE_ZSTD_LEVEL: i32 = 3;
const PAGE_GZIP_LEVEL: u32 = 6;
const ASSET_ZSTD_LEVEL: i32 = todo_zstd::content_encoding::HTTP_MAX_LEVEL;
const ASSET_GZIP_LEVEL: u32 = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentCoding {
    Identity,
    Gzip,
    Zstd,
}

impl ContentCoding {
    pub fn token(self) -> Option<&'static str> {
        match self {
            Self::Identity => None,
            Self::Gzip => Some("gzip"),
            Self::Zstd => Some("zstd"),
        }
    }
}

/// Pick a coding from `Accept-Encoding` (RFC 9110 §12.5.3): highest q wins, zstd on ties,
/// `q=0` excludes, `*` covers unlisted codings. No header → identity.
pub fn negotiate(accept_encoding: Option<&str>) -> ContentCoding {
    let Some(header) = accept_encoding else {
        return ContentCoding::Identity;
    };
    let (mut zstd, mut gzip, mut star) = (None, None, None);
    for item in header.split(',') {
        let mut parts = item.split(';');
        let name = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let mut q = 1.0f32;
        for param in parts {
            if let Some((k, v)) = param.split_once('=')
                && k.trim().eq_ignore_ascii_case("q")
            {
                q = v.trim().parse::<f32>().unwrap_or(0.0).clamp(0.0, 1.0);
            }
        }
        match name.as_str() {
            "zstd" => zstd = Some(q),
            "gzip" | "x-gzip" => gzip = Some(q),
            "*" => star = Some(q),
            _ => {}
        }
    }
    let zstd = zstd.or(star).unwrap_or(0.0);
    let gzip = gzip.or(star).unwrap_or(0.0);
    if zstd > 0.0 && zstd >= gzip {
        ContentCoding::Zstd
    } else if gzip > 0.0 {
        ContentCoding::Gzip
    } else {
        ContentCoding::Identity
    }
}

fn compressible(r: &Response, path: &str) -> bool {
    !path.starts_with("/api/")
        && r.status == 200
        && r.content_encoding.is_none()
        && ["text/html", "text/css", "text/javascript", "image/svg+xml"]
            .iter()
            .any(|t| r.content_type.starts_with(t))
}

fn encode(data: &[u8], coding: ContentCoding, asset: bool) -> std::io::Result<Vec<u8>> {
    match coding {
        ContentCoding::Identity => Ok(data.to_vec()),
        ContentCoding::Zstd => {
            let level = if asset {
                ASSET_ZSTD_LEVEL
            } else {
                PAGE_ZSTD_LEVEL
            };
            todo_zstd::content_encoding::encode_http_zstd(data, level)
        }
        ContentCoding::Gzip => {
            let level = if asset {
                ASSET_GZIP_LEVEL
            } else {
                PAGE_GZIP_LEVEL
            };
            let mut enc =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(level));
            enc.write_all(data)?;
            enc.finish()
        }
    }
}

/// Embedded assets are compressed once per coding (keyed by their static address).
type AssetCache = Mutex<HashMap<(usize, ContentCoding), Option<Arc<[u8]>>>>;
static ASSET_CACHE: LazyLock<AssetCache> = LazyLock::new(Default::default);

/// Apply the negotiated coding to an eligible response (see module docs); otherwise a
/// no-op. Encoded bodies that are not smaller are discarded. Adds `Vary` when eligible.
pub fn encode_response(r: &mut Response, path: &str, coding: ContentCoding) {
    if !compressible(r, path) {
        return;
    }
    r.vary_encoding = true;
    let Some(token) = coding.token() else { return };
    if r.body.len() < MIN_COMPRESS_BYTES {
        return;
    }
    let encoded: Option<Arc<[u8]>> = match r.static_body {
        Some(src) => {
            let key = (src.as_ptr() as usize, coding);
            let mut cache = ASSET_CACHE.lock().unwrap_or_else(|e| e.into_inner());
            cache
                .entry(key)
                .or_insert_with(|| encode(src.as_bytes(), coding, true).ok().map(Arc::from))
                .clone()
        }
        None => encode(&r.body, coding, false).ok().map(Arc::from),
    };
    if let Some(body) = encoded.filter(|b| b.len() < r.body.len()) {
        r.body = body.to_vec();
        r.content_encoding = Some(token);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub cache_control: &'static str,
    pub body: Vec<u8>,
    /// `Content-Encoding` token of `body`, if encoded.
    pub content_encoding: Option<&'static str>,
    /// Send `Vary: Accept-Encoding` (representation depends on the request).
    pub vary_encoding: bool,
    /// Full `Set-Cookie` value (may carry a session token).
    pub set_cookie: Option<SecretValue>,
    /// `Location` header for redirects.
    pub location: Option<String>,
    pub service_worker_allowed: bool,
    static_body: Option<&'static str>,
}

impl Response {
    fn html(status: u16, body: String) -> Self {
        Self {
            status,
            content_type: "text/html; charset=utf-8",
            cache_control: "no-store",
            body: body.into_bytes(),
            content_encoding: None,
            vary_encoding: false,
            set_cookie: None,
            location: None,
            service_worker_allowed: false,
            static_body: None,
        }
    }

    fn json(status: u16, value: serde_json::Value) -> Self {
        Self {
            status,
            content_type: "application/json; charset=utf-8",
            cache_control: "no-store",
            body: value.to_string().into_bytes(),
            content_encoding: None,
            vary_encoding: false,
            set_cookie: None,
            location: None,
            service_worker_allowed: false,
            static_body: None,
        }
    }

    fn asset(content_type: &'static str, body: &'static str) -> Self {
        Self {
            status: 200,
            content_type,
            cache_control: "public, max-age=31536000, immutable",
            body: body.as_bytes().to_vec(),
            content_encoding: None,
            vary_encoding: false,
            set_cookie: None,
            location: None,
            service_worker_allowed: false,
            static_body: Some(body),
        }
    }

    fn binary_asset(content_type: &'static str, bytes: &'static [u8]) -> Self {
        Self {
            status: 200,
            content_type,
            cache_control: "public, max-age=31536000, immutable",
            body: bytes.to_vec(),
            content_encoding: None,
            vary_encoding: false,
            set_cookie: None,
            location: None,
            service_worker_allowed: false,
            static_body: None,
        }
    }

    fn service_worker(body: &'static str) -> Self {
        Self {
            status: 200,
            content_type: "application/javascript; charset=utf-8",
            cache_control: "no-cache",
            body: body.as_bytes().to_vec(),
            content_encoding: None,
            vary_encoding: false,
            set_cookie: None,
            location: None,
            service_worker_allowed: true,
            static_body: Some(body),
        }
    }

    pub fn redirect(location: &str) -> Self {
        Self {
            status: 302,
            content_type: "text/plain; charset=utf-8",
            cache_control: "no-store",
            body: Vec::new(),
            content_encoding: None,
            vary_encoding: false,
            set_cookie: None,
            location: Some(location.to_string()),
            service_worker_allowed: false,
            static_body: None,
        }
    }

    fn error(status: u16, message: &str) -> Self {
        Self::json(status, json!({ "error": message }))
    }
}

/// Minimal parsed request (headers already validated).
#[derive(Debug, Default)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub origin: Option<String>,
    pub content_type: Option<String>,
    /// Raw query string (without `?`), if any.
    pub query: Option<String>,
    pub accept_encoding: Option<String>,
    /// Session cookie value for the cookie name matching `tls`.
    pub session_cookie: Option<SecretValue>,
    /// TCP peer address (login rate limiting).
    pub peer_ip: Option<IpAddr>,
    /// Request arrived over TLS.
    pub tls: bool,
    pub body: Vec<u8>,
}

fn sanitize_next(next: Option<&str>) -> Option<String> {
    let next = next?.trim();
    if next.starts_with('/') && !next.starts_with("//") && !next.contains('\\') {
        Some(next.to_string())
    } else {
        None
    }
}

fn query_param<'a>(query: Option<&'a str>, key: &str) -> Option<&'a str> {
    let query = query?;
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        if let Some(k) = parts.next()
            && k == key
        {
            return parts.next();
        }
    }
    None
}

pub struct WebApp {
    controller: Arc<RestServiceController>,
    auth: Option<WebAuth>,
    catalog: Option<Arc<dyn ObjectCatalog>>,
    rukubo: Option<Arc<Rukubo>>,
}

impl WebApp {
    pub fn new(controller: Arc<RestServiceController>) -> Self {
        Self {
            controller,
            auth: None,
            catalog: None,
            rukubo: None,
        }
    }

    pub fn with_auth(mut self, auth: WebAuth) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Layer 4 object metadata store. Only used for session users, so it has an effect
    /// only together with [`WebApp::with_auth`].
    pub fn with_catalog(mut self, catalog: Arc<dyn ObjectCatalog>) -> Self {
        self.catalog = Some(catalog);
        self
    }

    /// Attach the Rust-owned private Kubo supervisor. Its controls remain admin-only.
    pub fn with_rukubo(mut self, rukubo: Arc<Rukubo>) -> Self {
        self.rukubo = Some(rukubo);
        self
    }

    pub fn auth_enabled(&self) -> bool {
        self.auth.is_some()
    }

    pub fn catalog_enabled(&self) -> bool {
        self.auth.is_some() && self.catalog.is_some()
    }

    /// Records a session user's upload. Without a catalog (or for token clients) the
    /// response is unchanged and the client must keep CID + nonce itself.
    async fn finish_upload(
        &self,
        user: Option<u64>,
        receipt: Result<UploadReceipt, ObjectError>,
    ) -> Response {
        let mut receipt = match receipt {
            Ok(r) => r,
            Err(e) => {
                return Response::json(e.status, json!({ "status": "error", "error": e.message }));
            }
        };
        let (Some(owner_id), Some(catalog)) = (user, self.catalog_for_sessions()) else {
            return Response::json(200, receipt.json);
        };
        let row = NewObject {
            owner_id,
            object_id: receipt.object_id.clone(),
            root_cid: receipt.root.to_string(),
            backend: json_str(&receipt.backend),
            crypto_mode: json_str(&receipt.crypto_mode),
            sealed_format_version: receipt.sealed_format_version,
            nonce: receipt.nonce,
            tag: receipt.tag,
            original_size: receipt.original_bytes,
            compressed_size: receipt.compressed_bytes,
            sealed_size: receipt.sealed_bytes,
            encryption_plan: serde_json::to_value(receipt.plan).unwrap_or_default(),
        };
        match catalog.record(&row).await {
            Ok(id) => {
                if let Some(o) = receipt.json.as_object_mut() {
                    o.insert("metadata_id".into(), json!(id));
                    o.insert("metadata_store".into(), json!(catalog.kind()));
                }
                Response::json(200, receipt.json)
            }
            Err(e) => {
                // The ciphertext is already in IPFS; without a row it is unreachable for
                // this user (it stays encrypted). Report instead of pretending success.
                eprintln!("catalog: record {}: {e}", row.root_cid);
                Response::json(
                    503,
                    json!({ "status": "error", "error": "metadata store unavailable; object not recorded" }),
                )
            }
        }
    }

    fn catalog_for_sessions(&self) -> Option<&Arc<dyn ObjectCatalog>> {
        self.auth.as_ref().and(self.catalog.as_ref())
    }

    /// Stored nonce for a session user's download, enforcing ownership.
    /// `Ok(None)` = no catalog/no session (legacy: nonce from the query).
    #[allow(clippy::result_large_err)]
    async fn owned_nonce(
        &self,
        user: Option<u64>,
        path: &str,
    ) -> Result<Option<[u8; 12]>, Response> {
        let (Some(owner_id), Some(catalog)) = (user, self.catalog_for_sessions()) else {
            return Ok(None);
        };
        let not_found = || {
            Response::json(
                404,
                json!({ "status": "error", "error": "object not found for this account" }),
            )
        };
        let Some((cid, _)) = todo_rest::download::parse_target(path) else {
            return Err(not_found());
        };
        let Ok(cid) = cid.parse::<todo_ipfs::Cid>() else {
            return Err(Response::json(
                400,
                json!({ "status": "error", "error": "invalid CID" }),
            ));
        };
        match catalog.find(owner_id, &cid.to_string()).await {
            Ok(Some(row)) => Ok(Some(row.object.nonce)),
            Ok(None) => Err(not_found()),
            Err(e) => Err(catalog_error(e)),
        }
    }

    async fn list_objects(&self, req: &Request) -> Response {
        if req.method != "GET" {
            return Response::error(405, "method not allowed");
        }
        let Some(catalog) = self.catalog_for_sessions() else {
            return Response::json(
                503,
                json!({ "status": "error", "error": "object metadata store not configured" }),
            );
        };
        let Some(session) = self.session(req).await else {
            return Response::json(401, json!({ "status": "error", "error": "login required" }));
        };
        match catalog.list(session.user_id, 100).await {
            Ok(rows) => Response::json(
                200,
                json!({
                    "status": "ok",
                    "objects": rows.iter().map(|r| r.to_json()).collect::<Vec<_>>(),
                }),
            ),
            Err(e) => catalog_error(e),
        }
    }

    /// Valid session of the request, if any (store errors count as "no session").
    pub async fn session(&self, req: &Request) -> Option<Session> {
        let auth = self.auth.as_ref()?;
        let token = req.session_cookie.as_ref()?;
        auth.sessions.get(token.as_str()).await.ok().flatten()
    }

    /// Object-route access decision for a request without a verified bearer token:
    /// `Ok(Some(uid))` = session user, `Ok(None)` = defer to the bearer check in
    /// `todo-rest`, `Err` = login required.
    #[allow(clippy::result_large_err)]
    async fn object_access(&self, req: &Request) -> Result<Option<u64>, Response> {
        if self.auth.is_none() {
            return Ok(None);
        }
        if let Some(s) = self.session(req).await {
            return Ok(Some(s.user_id));
        }
        let token_configured = self
            .controller
            .upload_config()
            .is_some_and(todo_rest::UploadConfig::requires_token);
        if token_configured || self.controller.upload_config().is_none() {
            Ok(None)
        } else {
            Err(Response::json(
                401,
                json!({ "status": "error", "error": "login required" }),
            ))
        }
    }

    pub fn controller(&self) -> &Arc<RestServiceController> {
        &self.controller
    }

    pub async fn handle(&self, req: &Request) -> Response {
        let backend = self.controller.ipfs_backend();
        let path = req.path.as_str();

        if path.starts_with("/api/") {
            return self.handle_api(req).await;
        }
        if req.method != "GET" && req.method != "HEAD" {
            return Response::error(405, "method not allowed");
        }

        let token_configured = self
            .controller
            .upload_config()
            .is_some_and(todo_rest::UploadConfig::requires_token);

        let session = self.session(req).await;
        if self.auth_enabled() {
            if session.is_none() {
                if path == "/login" {
                    let next = sanitize_next(query_param(req.query.as_deref(), "next"));
                    return match pages::login(backend, next).render() {
                        Ok(html) => Response::html(200, html),
                        Err(_) => Response::error(500, "template rendering failed"),
                    };
                }
                let redirect_to_login = match path {
                    "/" | "/status" | "/dashboard" | "/account" | "/settings" | "/storage"
                    | "/explore" | "/peers" | "/diagnostics" | "/pipeline" | "/equivalence"
                    | "/rukubo" | "/benchmark" | "/research" | "/production" => true,
                    "/files" | "/vault" => !token_configured,
                    _ => false,
                };
                if redirect_to_login {
                    let next_query = if path == "/" || path == "/status" || path == "/dashboard" {
                        String::new()
                    } else {
                        format!("?next={path}")
                    };
                    return Response::redirect(&format!("/login{next_query}"));
                }
            } else if path == "/login" {
                let next = sanitize_next(query_param(req.query.as_deref(), "next"))
                    .unwrap_or_else(|| "/status".to_string());
                return Response::redirect(&next);
            }
        }

        let rendered = match path {
            "/" | "/status" | "/dashboard" | "/production" => pages::status(
                backend,
                self.auth_enabled(),
                self.catalog_enabled(),
                session.as_ref(),
            )
            .render(),
            "/files" | "/vault" => pages::files(
                backend,
                self.controller.upload_config(),
                self.auth_enabled(),
                self.catalog_enabled(),
                session.as_ref(),
            )
            .render(),
            "/explore" | "/storage" => pages::explore(backend).render(),
            "/peers" => pages::peers(backend).render(),
            "/settings" => pages::settings(backend, self.auth_enabled(), session.as_ref()).render(),
            "/diagnostics" => pages::diagnostics(backend).render(),
            "/pipeline" => pages::pipeline(backend).render(),
            "/equivalence" => pages::equivalence(backend).render(),
            "/benchmark" => pages::benchmark(backend).render(),
            "/research" => pages::research(backend).render(),
            "/rukubo" => {
                let Some(rukubo) = &self.rukubo else {
                    return Response::error(404, "not found");
                };
                let Some(session) = session.as_ref() else {
                    return Response::redirect("/login?next=/rukubo");
                };
                if session.role.as_str() != "admin" {
                    return Response::error(403, "administrator access required");
                }
                match rukubo.status() {
                    Ok(status) => pages::rukubo(backend, status).render(),
                    Err(_) => return Response::error(503, "private Kubo status unavailable"),
                }
            }
            "/account" => pages::account(backend, self.auth_enabled(), session.as_ref()).render(),
            "/login" => {
                let next = sanitize_next(query_param(req.query.as_deref(), "next"));
                pages::login(backend, next).render()
            }
            "/sw.js" => return Response::service_worker(SW_JS),
            "/static/app.css" => return Response::asset("text/css; charset=utf-8", APP_CSS),
            "/static/app.js" => {
                return Response::asset("text/javascript; charset=utf-8", APP_JS);
            }
            "/static/theme.js" => {
                return Response::asset("text/javascript; charset=utf-8", THEME_JS);
            }
            "/static/favicon.svg" | "/favicon.ico" => {
                return Response::asset("image/svg+xml", FAVICON_SVG);
            }
            "/static/wasm/todo_wasm.wasm" | "/static/wasm/todo-wasm.wasm" => {
                return Response::binary_asset("application/wasm", TODO_WASM);
            }
            _ => {
                return match pages::not_found(backend, path).render() {
                    Ok(html) => Response::html(404, html),
                    Err(_) => Response::error(404, "not found"),
                };
            }
        };
        match rendered {
            Ok(html) => Response::html(200, html),
            Err(_) => Response::error(500, "template rendering failed"),
        }
    }

    async fn handle_api(&self, req: &Request) -> Response {
        if req.method == "POST" {
            let is_json = req
                .content_type
                .as_deref()
                .map(|ct| {
                    ct.split(';')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .eq_ignore_ascii_case("application/json")
                })
                .unwrap_or(false);
            if !is_json {
                return Response::error(415, "Content-Type must be application/json");
            }
            if !same_origin(req.origin.as_deref(), req.host.as_deref()) {
                return Response::error(403, "cross-origin request rejected");
            }
        }
        if req.path.starts_with(AUTH_PREFIX) {
            return self.handle_auth(req).await;
        }
        if req.path.starts_with("/api/v1/rukubo/") {
            return self.handle_rukubo(req).await;
        }
        if req.path == VAULT_OBJECTS_ROUTE {
            return self.list_objects(req).await;
        }
        let Ok(body) = std::str::from_utf8(&req.body) else {
            return Response::error(400, "body must be UTF-8 JSON");
        };
        let (status, value) =
            dispatch(&req.method, &req.path, body, Arc::clone(&self.controller)).await;
        Response::json(status, value)
    }

    async fn handle_rukubo(&self, req: &Request) -> Response {
        let Some(rukubo) = &self.rukubo else {
            return Response::json(404, json!({ "status": "error", "error": "not found" }));
        };
        let Some(session) = self.session(req).await else {
            return Response::json(401, json!({ "status": "error", "error": "login required" }));
        };
        if session.role.as_str() != "admin" {
            return Response::json(
                403,
                json!({ "status": "error", "error": "administrator access required" }),
            );
        }
        let result = match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/api/v1/rukubo/status") => rukubo.status(),
            ("POST", "/api/v1/rukubo/start") => rukubo.start(),
            _ => return Response::json(404, json!({ "status": "error", "error": "not found" })),
        };
        match result {
            Ok(status) => Response::json(
                200,
                json!({
                    "status": "ok", "running": status.running, "managed_pid": status.managed_pid,
                    "repository": status.repository,
                }),
            ),
            Err(_) => Response::json(
                503,
                json!({ "status": "error", "error": "private Kubo unavailable" }),
            ),
        }
    }
}

const AUTH_PREFIX: &str = "/api/v1/auth/";
/// `GET`: the logged-in user's objects from the metadata store (newest first).
pub const VAULT_OBJECTS_ROUTE: &str = "/api/v1/vault/objects";

fn json_str<T: serde::Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

fn catalog_error(e: CatalogError) -> Response {
    eprintln!("catalog: {e}");
    Response::json(
        503,
        json!({ "status": "error", "error": "metadata store unavailable" }),
    )
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let (chunks, _) = s.as_bytes().as_chunks::<2>();
    let mut out = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

#[derive(serde::Deserialize)]
struct LoginRequest {
    username: String,
    password: Zeroizing<String>,
}

#[derive(serde::Deserialize)]
struct EncryptedLoginPayload {
    #[serde(default)]
    #[allow(dead_code)]
    encrypted: bool,
    key: String,
    iv: String,
    ciphertext: String,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum LoginBody {
    Plain(LoginRequest),
    Encrypted(EncryptedLoginPayload),
}

#[derive(serde::Deserialize)]
struct DecryptedLogin {
    username: String,
    password: Zeroizing<String>,
    #[serde(default)]
    #[allow(dead_code)]
    timestamp: Option<u64>,
}

fn session_cookie_name(tls: bool) -> &'static str {
    if tls {
        SESSION_COOKIE_TLS
    } else {
        SESSION_COOKIE_PLAIN
    }
}

fn session_set_cookie(tls: bool, token: &str, max_age: u64) -> SecretValue {
    let secure = if tls { "; Secure" } else { "" };
    SecretValue(Zeroizing::new(format!(
        "{}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}",
        session_cookie_name(tls)
    )))
}

fn auth_error(status: u16, message: &str) -> Response {
    Response::json(status, json!({ "status": "error", "error": message }))
}

impl WebApp {
    async fn handle_auth(&self, req: &Request) -> Response {
        let Some(auth) = &self.auth else {
            return auth_error(503, "accounts are not configured on this server");
        };
        let route = &req.path[AUTH_PREFIX.len()..];
        match (req.method.as_str(), route) {
            ("POST", "login") => self.login(auth, req).await,
            ("POST", "logout") => {
                if let Some(token) = &req.session_cookie
                    && auth.sessions.destroy(token.as_str()).await.is_err()
                {
                    return auth_error(503, "session store unavailable");
                }
                let mut r = Response::json(200, json!({ "status": "ok" }));
                r.set_cookie = Some(session_set_cookie(req.tls, "", 0));
                r
            }
            ("GET", "me") => {
                let Some(session) = self.session(req).await else {
                    return auth_error(401, "not logged in");
                };
                match auth.accounts.profile(session.user_id).await {
                    Ok(Some(p)) => Response::json(
                        200,
                        json!({
                            "status": "ok",
                            "username": p.username,
                            "role": p.role,
                            "email": p.email.as_deref(),
                            "national_id": p.national_id.as_deref(),
                            "created_at_unix": p.created_at_unix,
                            "session_created_unix": session.created_unix,
                        }),
                    ),
                    Ok(None) => auth_error(401, "account no longer exists"),
                    Err(AccountError::PiiIntegrity) => {
                        auth_error(500, "encrypted profile data failed authentication")
                    }
                    Err(_) => auth_error(503, "account store unavailable"),
                }
            }
            (_, "login" | "logout" | "me") => auth_error(405, "method not allowed"),
            _ => auth_error(404, "not found"),
        }
    }

    async fn login(&self, auth: &WebAuth, req: &Request) -> Response {
        // serde_json errors can quote input; never echo them.
        let Ok(body) = serde_json::from_slice::<LoginBody>(&req.body) else {
            return auth_error(
                400,
                "expected {\"username\": ..., \"password\": ...} or encrypted payload envelope",
            );
        };
        let (username, password) = match body {
            LoginBody::Plain(req) => (req.username, req.password),
            LoginBody::Encrypted(enc) => {
                let Some(key_bytes) = decode_hex(&enc.key) else {
                    return auth_error(400, "invalid encrypted payload key encoding");
                };
                let Some(iv_bytes) = decode_hex(&enc.iv) else {
                    return auth_error(400, "invalid encrypted payload iv encoding");
                };
                let Some(ct_bytes) = decode_hex(&enc.ciphertext) else {
                    return auth_error(400, "invalid encrypted payload ciphertext encoding");
                };
                let Ok(key): Result<[u8; 32], _> = key_bytes.try_into() else {
                    return auth_error(400, "invalid key length for encrypted envelope");
                };
                let Ok(iv): Result<[u8; 16], _> = iv_bytes.try_into() else {
                    return auth_error(400, "invalid iv length for encrypted envelope");
                };
                let Ok(plain_bytes) = todo_crypto::decrypt_aes_ctr_payload(&key, &iv, &ct_bytes)
                else {
                    return auth_error(400, "failed to decrypt payload envelope");
                };
                let Ok(decrypted) = serde_json::from_slice::<DecryptedLogin>(&plain_bytes) else {
                    return auth_error(400, "invalid decrypted credential format");
                };
                (decrypted.username, decrypted.password)
            }
        };
        let ip = req
            .peer_ip
            .map_or_else(|| "unknown".to_string(), |ip| ip.to_string());
        match auth.sessions.login_allowed(&ip, &username).await {
            Ok(true) => {}
            Ok(false) => return auth_error(429, "too many failed logins; try again later"),
            Err(_) => return auth_error(503, "session store unavailable"),
        }
        let user = match auth.accounts.authenticate(&username, &password).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                let _ = auth.sessions.record_failure(&ip, &username).await;
                return auth_error(401, "invalid username or password");
            }
            Err(_) => return auth_error(503, "account store unavailable"),
        };
        let _ = auth.sessions.clear_user_failures(&username).await;
        // New token on every login (no session fixation); drop the previous one.
        if let Some(old) = &req.session_cookie {
            let _ = auth.sessions.destroy(old.as_str()).await;
        }
        let token = match auth.sessions.create(&user).await {
            Ok(t) => t,
            Err(_) => return auth_error(503, "session store unavailable"),
        };
        let max_age = auth.sessions.policy().absolute_ttl.as_secs();
        let mut r = Response::json(
            200,
            json!({ "status": "ok", "username": user.username, "role": user.role }),
        );
        r.set_cookie = Some(session_set_cookie(req.tls, token.as_str(), max_age));
        r
    }
}

/// Value of cookie `name` from a `Cookie` header (`a=b; c=d`).
fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|pair| {
        let (k, v) = pair.trim().split_once('=')?;
        (k == name).then_some(v.trim())
    })
}

/// `true` when no `Origin` was sent (same-origin GET / non-browser client) or its
/// authority equals `Host`.
fn same_origin(origin: Option<&str>, host: Option<&str>) -> bool {
    let Some(origin) = origin else { return true };
    let Some(host) = host else { return false };
    let authority = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"));
    authority.is_some_and(|a| a.eq_ignore_ascii_case(host))
}

/// Accept plain-HTTP connections forever, one task per connection.
pub async fn serve(listener: TcpListener, app: Arc<WebApp>) -> std::io::Result<()> {
    serve_with(listener, app, None).await
}

/// Like [`serve`], with a TLS handshake (bounded by [`HANDSHAKE_TIMEOUT`]) first when
/// `tls` is set. Failed handshakes are dropped silently.
pub async fn serve_with(
    listener: TcpListener,
    app: Arc<WebApp>,
    tls: Option<TlsAcceptor>,
) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let app = Arc::clone(&app);
        let tls = tls.clone();
        let peer = Some(peer.ip());
        tokio::spawn(async move {
            match tls {
                None => {
                    let _ = handle_connection(stream, app, "", peer).await;
                }
                Some(acceptor) => {
                    if let Ok(Ok(stream)) =
                        tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await
                    {
                        let _ = handle_connection(stream, app, HSTS, peer).await;
                    }
                }
            }
        });
    }
}

enum ReadError {
    Respond(Response),
    Io,
}

enum Incoming {
    /// The raw `Authorization` value is kept out of `Request` (which derives `Debug`).
    Full(Request, Option<zeroize::Zeroizing<String>>),
    /// `POST /api/v1/objects/upload`: headers parsed, body (minus `prefix`) still on the
    /// socket, to be streamed to disk by `todo_rest::upload`.
    Upload {
        req: Request,
        headers: UploadHeaders,
        prefix: Vec<u8>,
    },
}

/// `extra` = additional response header lines (HSTS on HTTPS, which also marks the
/// connection as TLS for cookie handling).
async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    app: Arc<WebApp>,
    extra: &str,
    peer_ip: Option<IpAddr>,
) -> std::io::Result<()> {
    let tls = !extra.is_empty();
    let read = tokio::time::timeout(READ_TIMEOUT, read_request(&mut stream, tls, peer_ip)).await;
    let response = match read {
        Err(_) => Response::error(408, "request timeout"),
        Ok(Err(ReadError::Io)) => return Ok(()),
        Ok(Err(ReadError::Respond(r))) => r,
        Ok(Ok(Incoming::Upload {
            req,
            mut headers,
            prefix,
        })) => {
            if !same_origin(req.origin.as_deref(), req.host.as_deref()) {
                Response::error(403, "cross-origin request rejected")
            } else {
                match app.object_access(&req).await {
                    Err(r) => r,
                    Ok(user) => {
                        headers.session_user = user;
                        let receipt = todo_rest::upload::upload_object(
                            app.controller(),
                            &headers,
                            &prefix,
                            &mut stream,
                        )
                        .await;
                        app.finish_upload(user, receipt).await
                    }
                }
            }
        }
        Ok(Ok(Incoming::Full(req, auth)))
            if req.method == "GET" && todo_rest::download::parse_target(&req.path).is_some() =>
        {
            let target = match &req.query {
                Some(q) => format!("{}?{q}", req.path),
                None => req.path.clone(),
            };
            let auth = auth.as_deref().map(String::as_str);
            let access = match app.object_access(&req).await {
                Ok(user) => app.owned_nonce(user, &req.path).await.map(|n| (user, n)),
                Err(r) => Err(r),
            };
            match access {
                Err(r) => r,
                Ok((user, stored_nonce)) => {
                    match todo_rest::prepare_download_with(
                        app.controller(),
                        &target,
                        auth,
                        user,
                        stored_nonce,
                    )
                    .await
                    {
                        Ok(obj) => return write_download(&mut stream, &obj, extra).await,
                        Err(e) => Response::json(
                            e.status,
                            json!({ "status": "error", "error": e.message }),
                        ),
                    }
                }
            }
        }
        Ok(Ok(Incoming::Full(req, _))) => {
            let mut r = app.handle(&req).await;
            encode_response(&mut r, &req.path, negotiate(req.accept_encoding.as_deref()));
            if req.method == "HEAD" {
                return write_response(&mut stream, &r, Some(r.body.len()), extra).await;
            }
            r
        }
    };
    write_response(&mut stream, &response, None, extra).await
}

#[allow(clippy::result_large_err)]
async fn read_request<S: AsyncRead + Unpin>(
    stream: &mut S,
    tls: bool,
    peer_ip: Option<IpAddr>,
) -> Result<Incoming, ReadError> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 8192];
    let header_end = loop {
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(ReadError::Respond(Response::error(
                431,
                "request headers too large",
            )));
        }
        let n = stream.read(&mut chunk).await.map_err(|_| ReadError::Io)?;
        if n == 0 {
            return Err(ReadError::Io);
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let bad = |msg: &str| ReadError::Respond(Response::error(400, msg));
    let head = std::str::from_utf8(&buf[..header_end]).map_err(|_| bad("invalid header"))?;
    let mut lines = head.split("\r\n");
    let mut parts = lines.next().unwrap_or("").split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(bad("malformed request line"));
    };
    if !version.starts_with("HTTP/1.") || !target.starts_with('/') {
        return Err(bad("unsupported request"));
    }
    let target = target.split('#').next().unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));

    let mut req = Request {
        method: method.to_string(),
        path: path.to_string(),
        query: (!query.is_empty()).then(|| query.to_string()),
        tls,
        peer_ip,
        ..Request::default()
    };
    let mut content_length = 0usize;
    let mut upload = UploadHeaders::default();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(bad("malformed header"));
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => {
                let n: u64 = value.parse().map_err(|_| bad("invalid Content-Length"))?;
                upload.content_length = Some(n);
                content_length = usize::try_from(n).unwrap_or(usize::MAX);
            }
            "transfer-encoding" => {
                return Err(ReadError::Respond(Response::error(
                    411,
                    "chunked bodies are not supported; send Content-Length",
                )));
            }
            "host" => req.host = Some(value.to_string()),
            "origin" => req.origin = Some(value.to_string()),
            "accept-encoding" => req.accept_encoding = Some(value.to_string()),
            "cookie" => {
                if let Some(v) = cookie_value(value, session_cookie_name(tls)) {
                    req.session_cookie = Some(SecretValue(Zeroizing::new(v.to_string())));
                }
            }
            "content-type" => req.content_type = Some(value.to_string()),
            "x-object-id" => upload.object_id = Some(value.to_string()),
            "authorization" => {
                upload.authorization = Some(zeroize::Zeroizing::new(value.to_string()));
            }
            _ => {}
        }
    }
    if req.method == "POST" && req.path == UPLOAD_ROUTE {
        upload.content_type = req.content_type.clone();
        let prefix = buf.split_off(header_end + 4);
        return Ok(Incoming::Upload {
            req,
            headers: upload,
            prefix,
        });
    }
    if content_length > MAX_BODY_BYTES {
        return Err(ReadError::Respond(Response::error(
            413,
            "request body too large",
        )));
    }

    let mut body = buf.split_off(header_end + 4);
    if body.len() > content_length {
        body.truncate(content_length);
    }
    body.reserve(content_length - body.len());
    while body.len() < content_length {
        let want = (content_length - body.len()).min(chunk.len());
        let n = stream
            .read(&mut chunk[..want])
            .await
            .map_err(|_| ReadError::Io)?;
        if n == 0 {
            return Err(ReadError::Io);
        }
        body.extend_from_slice(&chunk[..n]);
    }
    req.body = body;
    Ok(Incoming::Full(req, upload.authorization))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        302 => "Found",
        303 => "See Other",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
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
    }
}

/// 200 response streaming a verified, decrypted object (security headers as for every
/// response; `Content-Disposition: attachment` so it is never rendered inline).
async fn write_download<S: AsyncWrite + Unpin>(
    stream: &mut S,
    obj: &todo_rest::DownloadedObject,
    extra: &str,
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 200 OK\r\n{extra}{}Content-Security-Policy: {CSP}\r\nX-Frame-Options: DENY\r\n\
Referrer-Policy: no-referrer\r\nCross-Origin-Resource-Policy: same-origin\r\nConnection: close\r\n\r\n",
        obj.headers()
    );
    stream.write_all(header.as_bytes()).await?;
    obj.write_body(stream).await?;
    stream.flush().await?;
    stream.shutdown().await
}

/// `head_len = Some(n)` writes headers for a HEAD request without a body.
async fn write_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    r: &Response,
    head_len: Option<usize>,
    extra: &str,
) -> std::io::Result<()> {
    let len = head_len.unwrap_or(r.body.len());
    let challenge = if r.status == 401 {
        "WWW-Authenticate: Bearer\r\n"
    } else {
        ""
    };
    let loc = match &r.location {
        Some(l) => format!("Location: {l}\r\n"),
        None => String::new(),
    };
    let coding = match r.content_encoding {
        Some(token) => format!("Content-Encoding: {token}\r\n"),
        None => String::new(),
    };
    let vary = if r.vary_encoding {
        "Vary: Accept-Encoding\r\n"
    } else {
        ""
    };
    let cookie = match &r.set_cookie {
        Some(c) => Zeroizing::new(format!("Set-Cookie: {}\r\n", c.as_str())),
        None => Zeroizing::new(String::new()),
    };
    let cookie = cookie.as_str();
    let sw_hdr = if r.service_worker_allowed {
        "Service-Worker-Allowed: /\r\n"
    } else {
        ""
    };
    let header = Zeroizing::new(format!(
        "HTTP/1.1 {} {}\r\n{extra}{loc}{challenge}{coding}{vary}{cookie}{sw_hdr}Content-Type: {}\r\nContent-Length: {len}\r\nCache-Control: {}\r\n\
Content-Security-Policy: {CSP}\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n\
Referrer-Policy: no-referrer\r\nCross-Origin-Opener-Policy: same-origin\r\n\
Cross-Origin-Resource-Policy: same-origin\r\n\
Permissions-Policy: camera=(), microphone=(), geolocation=()\r\nConnection: close\r\n\r\n",
        r.status,
        reason(r.status),
        r.content_type,
        r.cache_control,
    ));
    stream.write_all(header.as_bytes()).await?;
    if head_len.is_none() {
        stream.write_all(&r.body).await?;
    }
    stream.flush().await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_cookie_attributes_and_parsing() {
        let tls = session_set_cookie(true, "ab", 60);
        assert_eq!(
            tls.as_str(),
            "__Host-todo_sid=ab; Path=/; HttpOnly; SameSite=Strict; Max-Age=60; Secure"
        );
        let plain = session_set_cookie(false, "ab", 60);
        assert_eq!(
            plain.as_str(),
            "todo_sid=ab; Path=/; HttpOnly; SameSite=Strict; Max-Age=60"
        );
        assert_eq!(format!("{tls:?}"), "<redacted>");
        let h = "theme=dark; todo_sid=abc ; __Host-todo_sid=def";
        assert_eq!(cookie_value(h, "todo_sid"), Some("abc"));
        assert_eq!(cookie_value(h, "__Host-todo_sid"), Some("def"));
        assert_eq!(cookie_value(h, "sid"), None);
        assert_eq!(cookie_value("xtodo_sid=1", "todo_sid"), None);
    }

    #[test]
    fn same_origin_rules() {
        assert!(same_origin(None, Some("127.0.0.1:8000")));
        assert!(same_origin(
            Some("http://127.0.0.1:8000"),
            Some("127.0.0.1:8000")
        ));
        assert!(!same_origin(
            Some("http://evil.example"),
            Some("127.0.0.1:8000")
        ));
        assert!(!same_origin(Some("null"), Some("127.0.0.1:8000")));
        assert!(!same_origin(Some("http://127.0.0.1:8000"), None));
    }

    #[test]
    fn header_end_detection() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(14));
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n"), None);
    }
}
