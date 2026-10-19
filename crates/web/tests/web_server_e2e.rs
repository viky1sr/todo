//! End-to-end tests of the web server over a real TCP socket (mock IPFS backend).

use std::sync::Arc;

use serde_json::{Value, json};
use todo_rest::RestServiceController;
use todo_web::server::{MAX_BODY_BYTES, WebApp, serve};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn start() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let app = Arc::new(WebApp::new(Arc::new(RestServiceController::new())));
    tokio::spawn(serve(listener, app));
    addr
}

struct Reply {
    status: u16,
    headers: String,
    body: String,
}

async fn raw(addr: &str, request: Vec<u8>) -> Reply {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(&request).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let split_pos = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("valid HTTP header boundary");
    let head = String::from_utf8(buf[..split_pos].to_vec()).unwrap();
    let body = String::from_utf8_lossy(&buf[split_pos + 4..]).to_string();
    Reply {
        status: head[9..12].parse().unwrap(),
        headers: head.to_ascii_lowercase(),
        body,
    }
}

async fn get(addr: &str, path: &str) -> Reply {
    raw(
        addr,
        format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n\r\n").into_bytes(),
    )
    .await
}

async fn post(addr: &str, path: &str, body: &Value, extra: &str) -> Reply {
    let body = body.to_string();
    raw(
        addr,
        format!(
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
    )
    .await
}

const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const NONCE: &str = "0c0b0a090807060504030201";

#[tokio::test]
async fn pages_render_with_security_headers() {
    let addr = start().await;
    for (path, needle) in [
        ("/", "Invarian yang dijaga"),
        ("/status", "Node Overview"),
        ("/dashboard", "Node Overview"),
        ("/production", "Node Overview"),
        ("/login", "id=\"login-form\""),
        ("/files", "Vault nonaktif"),
        ("/vault", "Vault nonaktif"),
        ("/explore", "MOCK (in-memory, not IPFS)"),
        ("/storage", "MOCK (in-memory, not IPFS)"),
        ("/peers", "Private Swarm"),
        ("/settings", "Pengaturan Sistem"),
        ("/diagnostics", "Pusat Diagnostik &amp; Verifikasi"),
        ("/pipeline", "Jalankan &amp; verifikasi"),
        ("/equivalence", "Ekuivalensi POLYVAL"),
        ("/benchmark", "crypto-only"),
        ("/research", "Research Workspace"),
        ("/account", "Akun nonaktif"),
    ] {
        let r = get(&addr, path).await;
        assert_eq!(r.status, 200, "{path}");
        assert!(r.body.contains(needle), "{path} missing {needle:?}");
        assert!(r.headers.contains("content-type: text/html"));
        assert!(
            r.headers
                .contains("content-security-policy: default-src 'none'")
        );
        assert!(r.headers.contains("x-content-type-options: nosniff"));
        assert!(r.headers.contains("cache-control: no-store"));
    }
    let r = get(&addr, "/pipeline?x=1").await;
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn static_assets_and_not_found() {
    let addr = start().await;
    let css = get(&addr, "/static/app.css").await;
    assert_eq!(css.status, 200);
    assert!(css.headers.contains("content-type: text/css"));
    assert!(css.body.contains("--sky-500"));
    let js = get(&addr, "/static/app.js").await;
    assert!(js.headers.contains("content-type: text/javascript"));
    assert!(!js.body.contains(".innerHTML"));
    let missing = get(&addr, "/nope").await;
    assert_eq!(missing.status, 404);
    assert!(missing.body.contains("Halaman tidak ditemukan"));
    let api_missing = get(&addr, "/api/v1/nope").await;
    assert_eq!(api_missing.status, 404);
}

#[tokio::test]
async fn api_is_served_same_origin() {
    let addr = start().await;
    let health = get(&addr, "/api/v1/health").await;
    assert_eq!(health.status, 200);
    assert!(health.headers.contains("application/json"));
    let v: Value = serde_json::from_str(&health.body).unwrap();
    assert_eq!(v["status"], "ok");

    let body = json!({ "data_utf8": "langit ".repeat(500), "key_hex": KEY, "nonce_hex": NONCE });
    let r = post(&addr, "/api/v1/pipeline/verify", &body, "").await;
    assert_eq!(r.status, 200, "{}", r.body);
    let v: Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["aes_gcm_siv_equivalence"]["is_bit_identical"], true);
    assert_eq!(v["pipeline_roundtrip_verified"], true);
    assert_eq!(v["parallel_path_exercised"], false);
    assert_eq!(v["num_polyval_segments"], 1);
}

#[tokio::test]
async fn pipeline_verify_parallel_path_with_fixed_segments() {
    let addr = start().await;
    // Pseudo-random bytes stay large after compression, so >1 POLYVAL segment runs.
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let data: Vec<u8> = (0..512 * 1024)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
    let body = json!({
        "data_hex": hex, "key_hex": KEY, "nonce_hex": NONCE,
        "segmentation": "fixed", "polyval_segment_size": 65536,
        "compression_mode": "independent-frames", "frame_size": 131072
    });
    let r = post(&addr, "/api/v1/pipeline/verify", &body, "").await;
    assert_eq!(r.status, 200, "{}", r.body);
    let v: Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["aes_gcm_siv_equivalence"]["is_bit_identical"], true);
    assert_eq!(v["parallel_path_exercised"], true);
    assert!(v["num_polyval_segments"].as_u64().unwrap() > 1);
    assert_eq!(v["zstd_frames"], 4);

    let bad =
        json!({ "data_utf8": "x", "key_hex": KEY, "nonce_hex": NONCE, "segmentation": "bogus" });
    assert_eq!(
        post(&addr, "/api/v1/pipeline/verify", &bad, "")
            .await
            .status,
        400
    );
}

#[tokio::test]
async fn tampered_stream_is_rejected_without_plaintext() {
    let addr = start().await;
    let body = json!({ "data_utf8": "rahasia ".repeat(64), "key_hex": KEY, "nonce_hex": NONCE });
    let r = post(&addr, "/api/v1/pipeline/process", &body, "").await;
    assert_eq!(r.status, 200);
    let mut sealed: Value = serde_json::from_str::<Value>(&r.body).unwrap()["sealed"].clone();
    let c = sealed["ciphertext"][0].as_u64().unwrap();
    sealed["ciphertext"][0] = json!(c ^ 1);
    let r = post(
        &addr,
        "/api/v1/pipeline/recover",
        &json!({ "sealed": sealed, "key_hex": KEY, "nonce_hex": NONCE }),
        "",
    )
    .await;
    assert_eq!(r.status, 400);
    assert!(!r.body.contains("rahasia"));
    assert!(!r.body.contains("recovered"));
}

#[tokio::test]
async fn ipfs_publish_fetch_through_web() {
    let addr = start().await;
    let body = json!({ "stream_id": "web-e2e", "data_utf8": "awan biru", "key_hex": KEY, "nonce_hex": NONCE });
    let r = post(&addr, "/api/v1/ipfs/publish", &body, "").await;
    assert_eq!(r.status, 200, "{}", r.body);
    let v: Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["backend"], "mock");
    let root = v["root_cid"].as_str().unwrap().to_string();
    let r = post(
        &addr,
        "/api/v1/ipfs/fetch",
        &json!({ "root_cid": root, "key_hex": KEY, "nonce_hex": NONCE }),
        "",
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let v: Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["recovered_utf8"], "awan biru");
}

#[tokio::test]
async fn request_hardening() {
    let addr = start().await;
    // Simple cross-site form posts (non-JSON content type) are refused.
    let r = raw(
        &addr,
        format!("POST /api/v1/ipfs/publish HTTP/1.1\r\nHost: {addr}\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{{}}").into_bytes(),
    )
    .await;
    assert_eq!(r.status, 415);
    // Foreign Origin is refused.
    let r = post(
        &addr,
        "/api/v1/verify-equivalence",
        &json!({ "data_utf8": "x" }),
        "Origin: http://evil.example\r\n",
    )
    .await;
    assert_eq!(r.status, 403);
    // Same Origin is accepted.
    let r = post(
        &addr,
        "/api/v1/verify-equivalence",
        &json!({ "data_utf8": "abc" }),
        &format!("Origin: http://{addr}\r\n"),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    // Oversized body is refused before it is read.
    let r = raw(
        &addr,
        format!(
            "POST /api/v1/pipeline/verify HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        )
        .into_bytes(),
    )
    .await;
    assert_eq!(r.status, 413);
    // Chunked encoding is refused.
    let r = raw(
        &addr,
        format!("POST /api/v1/health HTTP/1.1\r\nHost: {addr}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n").into_bytes(),
    )
    .await;
    assert_eq!(r.status, 411);
    // Pages reject non-GET methods.
    let r = raw(
        &addr,
        format!("DELETE / HTTP/1.1\r\nHost: {addr}\r\n\r\n").into_bytes(),
    )
    .await;
    assert_eq!(r.status, 405);
}

#[tokio::test]
async fn large_body_across_many_reads() {
    let addr = start().await;
    // ~2 MiB hex body, larger than any single socket read.
    let data = vec![0x42u8; 1024 * 1024];
    let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
    let body = json!({ "data_hex": hex, "key_hex": KEY, "nonce_hex": NONCE });
    let r = post(&addr, "/api/v1/pipeline/verify", &body, "").await;
    assert_eq!(r.status, 200, "{}", &r.body[..r.body.len().min(200)]);
    let v: Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(v["original_size_bytes"], 1024 * 1024);
}

/// The browser flow of the Secure Vault page: raw upload (same origin) → verified download.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secure_vault_upload_and_verified_download() {
    let tmp = std::env::temp_dir().join(format!("todo-web-vault-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let cfg = todo_rest::UploadConfig::new(&[0x42; 32])
        .unwrap()
        .with_temp_dir(&tmp);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let controller = RestServiceController::new().with_upload_config(cfg);
    tokio::spawn(serve(listener, Arc::new(WebApp::new(Arc::new(controller)))));

    let page = get(&addr, "/vault").await;
    assert_eq!(page.status, 200);
    assert!(!page.body.contains("Vault nonaktif"));
    assert!(page.body.contains("id=\"vault-upload\""));

    let data = "baris laporan rahasia\n".repeat(50_000);
    let upload = |origin: String| {
        format!(
            "POST /api/v1/objects/upload HTTP/1.1\r\nHost: {addr}\r\nOrigin: {origin}\r\n\
Content-Type: application/octet-stream\r\nX-Object-Id: laporan.txt\r\nContent-Length: {}\r\n\r\n{data}",
            data.len()
        )
        .into_bytes()
    };
    let r = raw(&addr, upload(format!("http://{addr}"))).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let v: Value = serde_json::from_str(&r.body).unwrap();
    let (cid, nonce) = (
        v["ipfs_cid"].as_str().unwrap(),
        v["nonce_hex"].as_str().unwrap(),
    );

    let r = get(&addr, &format!("/api/v1/objects/{cid}?nonce={nonce}")).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, data);
    assert!(
        r.headers
            .contains("content-disposition: attachment; filename=\"laporan.txt\"")
    );
    assert!(
        r.headers
            .contains("content-security-policy: default-src 'none'")
    );
    assert!(r.headers.contains("x-frame-options: deny"));

    let flipped = format!(
        "{}{}",
        &nonce[..23],
        if nonce.ends_with('0') { '1' } else { '0' }
    );
    let r = get(&addr, &format!("/api/v1/objects/{cid}?nonce={flipped}")).await;
    assert_eq!(r.status, 422);
    assert!(!r.body.contains("baris laporan"));

    let mut cross = upload("http://evil.example".into());
    cross.truncate(cross.len() - data.len());
    assert_eq!(raw(&addr, cross).await.status, 403);

    assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 0);
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secure_vault_requires_bearer_token_when_configured() {
    const TOKEN: &str = "dmF1bHQtdG9rZW4tZm9yLXRlc3RzLTAxMjM0NTY3ODk";
    let tmp = std::env::temp_dir().join(format!("todo-web-vault-auth-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let cfg = todo_rest::UploadConfig::new(&[0x42; 16])
        .unwrap()
        .with_temp_dir(&tmp)
        .with_api_token(TOKEN)
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let controller = RestServiceController::new().with_upload_config(cfg);
    tokio::spawn(serve(listener, Arc::new(WebApp::new(Arc::new(controller)))));

    let page = get(&addr, "/vault").await;
    assert!(page.body.contains("id=\"vault-token\""));
    assert!(!page.body.contains(TOKEN));

    let data = "isi rahasia\n".repeat(1000);
    let upload = |auth: &str, body: &str| {
        format!(
            "POST /api/v1/objects/upload HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\n\
Content-Type: application/octet-stream\r\n{auth}Content-Length: {}\r\n\r\n{body}",
            data.len()
        )
        .into_bytes()
    };
    let r = raw(&addr, upload("", "")).await;
    assert_eq!(r.status, 401);
    assert!(r.headers.contains("www-authenticate: bearer"));

    let auth = format!("Authorization: Bearer {TOKEN}\r\n");
    let r = raw(&addr, upload(&auth, &data)).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let v: Value = serde_json::from_str(&r.body).unwrap();
    let target = format!(
        "/api/v1/objects/{}?nonce={}",
        v["ipfs_cid"].as_str().unwrap(),
        v["nonce_hex"].as_str().unwrap()
    );
    assert_eq!(get(&addr, &target).await.status, 401);
    let r = raw(
        &addr,
        format!("GET {target} HTTP/1.1\r\nHost: {addr}\r\n{auth}\r\n").into_bytes(),
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, data);
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_pages_send_hsts_and_upload_works_same_origin() {
    use rustls::pki_types::ServerName;
    let dir = std::env::temp_dir().join(format!("todo-web-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert, ck.cert.pem()).unwrap();
    std::fs::write(&key, ck.signing_key.serialize_pem()).unwrap();
    let acceptor = todo_rest::tls::acceptor(&cert, &key).unwrap();

    let cfg = todo_rest::UploadConfig::new(&[0x42; 16])
        .unwrap()
        .with_temp_dir(&dir);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let controller = RestServiceController::new().with_upload_config(cfg);
    let app = Arc::new(WebApp::new(Arc::new(controller)));
    tokio::spawn(todo_web::server::serve_with(listener, app, Some(acceptor)));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ck.cert.der().clone()).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    let send = |req: Vec<u8>| {
        let connector = connector.clone();
        async move {
            let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let name = ServerName::try_from("localhost").unwrap();
            let mut s = connector.connect(name, tcp).await.unwrap();
            s.write_all(&req).await.unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.unwrap();
            let text = String::from_utf8(buf).unwrap();
            let (head, body) = text.split_once("\r\n\r\n").unwrap();
            (head.to_ascii_lowercase(), body.to_string())
        }
    };
    let host = format!("localhost:{port}");

    let (head, body) =
        send(format!("GET /vault HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes()).await;
    assert!(head.starts_with("http/1.1 200"));
    assert!(head.contains("strict-transport-security: max-age=31536000"));
    assert!(body.contains("id=\"vault-upload\""));

    let data = "via https\n".repeat(5000);
    let (head, body) = send(
        format!(
            "POST /api/v1/objects/upload HTTP/1.1\r\nHost: {host}\r\nOrigin: https://{host}\r\n\
Content-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n{data}",
            data.len()
        )
        .into_bytes(),
    )
    .await;
    assert!(head.starts_with("http/1.1 200"), "{head}\n{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    let (head, body) = send(
        format!(
            "GET /api/v1/objects/{}?nonce={} HTTP/1.1\r\nHost: {host}\r\n\r\n",
            v["ipfs_cid"].as_str().unwrap(),
            v["nonce_hex"].as_str().unwrap()
        )
        .into_bytes(),
    )
    .await;
    assert!(head.starts_with("http/1.1 200"));
    assert!(head.contains("strict-transport-security"));
    assert_eq!(body, data);

    // Plain HTTP pages carry no HSTS.
    let plain = start().await;
    assert!(
        !get(&plain, "/")
            .await
            .headers
            .contains("strict-transport-security")
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn service_worker_and_wasm_assets() {
    let addr = start().await;

    // Service Worker route
    let sw = get(&addr, "/sw.js").await;
    assert_eq!(sw.status, 200);
    assert!(sw.headers.contains("content-type: application/javascript"));
    assert!(sw.headers.contains("service-worker-allowed: /"));
    assert!(sw.body.contains("SW_VERSION"));
    assert!(sw.headers.contains("content-security-policy"));
    assert!(sw.headers.contains("'wasm-unsafe-eval'"));

    // WASM binary route
    let wasm = raw(
        &addr,
        b"GET /static/wasm/todo_wasm.wasm HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".to_vec(),
    )
    .await;
    assert_eq!(wasm.status, 200);
    assert!(wasm.headers.contains("content-type: application/wasm"));
}

#[tokio::test]
async fn csp_includes_whitelisted_script_hash() {
    let addr = start().await;
    let res = get(&addr, "/login").await;
    assert_eq!(res.status, 200);
    assert!(
        res.headers
            .contains("sha256-wmsi5gjkafujxshnxedr/gsoe2wlyqudttrcyklgq4q=")
    );
    assert!(res.headers.contains("script-src-elem 'self'"));
    assert!(res.body.contains("method=\"post\""));
    assert!(res.body.contains("action=\"/api/v1/auth/login\""));
}

#[tokio::test]
async fn theme_script_with_version_query_is_served_under_the_strict_csp() {
    let addr = start().await;
    let page = get(&addr, "/login").await;
    assert_eq!(page.status, 200);
    assert!(page.headers.contains("script-src 'self'"));
    assert!(page.headers.contains("script-src-elem 'self'"));

    let theme = get(&addr, "/static/theme.js?v=0.1.0").await;
    assert_eq!(theme.status, 200);
    assert!(theme.headers.contains("content-type: text/javascript"));
    assert!(theme.body.contains("skycipher-theme"));
}
