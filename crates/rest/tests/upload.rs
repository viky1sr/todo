//! `POST /api/v1/objects/upload`: temp file -> memmap2 -> single-frame Zstd -> one
//! AES-GCM-SIV message (in place) -> IPFS (mock) -> CID.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value;
use todo_crypto::{CryptoError, aes_gcm_siv_decrypt_upstream, aes_gcm_siv_encrypt_upstream};
use todo_rest::upload::{UploadConfig, seal_file};
use todo_rest::{PipelineRecoverRequest, RestServiceController, UPLOAD_ROUTE};
use todo_zstd::{PipelineError, SealedStream, StreamCryptoPipeline};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const KEY: [u8; 32] = [0x42; 32];

fn temp_dir(name: &str) -> PathBuf {
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).unwrap();
    let hex: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let dir = std::env::temp_dir().join(format!("todo-upload-test-{name}-{hex}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Deterministic, poorly compressible bytes (xorshift), so the compressed payload is
/// large enough for the adaptive plan to go parallel.
fn noise(len: usize, mut x: u64) -> Vec<u8> {
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn leftover_temp_files(dir: &PathBuf) -> usize {
    std::fs::read_dir(dir)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".todo-upload-")
        })
        .count()
}

#[test]
fn sealed_file_matches_upstream_and_roundtrips() {
    let dir = temp_dir("seal");
    for (name, data) in [
        ("noise", noise(3 * 1024 * 1024 + 7, 0x9e3779b97f4a7c15)),
        ("text", b"compressible line\n".repeat(50_000)),
        ("one", vec![0xab]),
    ] {
        let path = dir.join(name);
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&data)
            .unwrap();
        let plain = std::fs::File::open(&path).unwrap();
        let sealed = seal_file(&plain, &dir, &KEY, 3).unwrap();
        assert_eq!(sealed.original_bytes, data.len() as u64);

        let stream = SealedStream::from_bytes(&sealed.bytes).unwrap();
        assert_eq!(stream.version, 1);
        assert_eq!(stream.segments.len(), 1, "one Zstd frame");
        assert_eq!(stream.tag, sealed.tag, "one tag");
        assert_eq!(stream.ciphertext.len() as u64, sealed.compressed_bytes);
        assert_eq!(stream.to_bytes(), sealed.bytes.to_vec(), "canonical format");

        // Oracle: upstream aes-gcm-siv over the same AAD and compressed bytes.
        let aad = stream.associated_data();
        let compressed = aes_gcm_siv_decrypt_upstream(
            &KEY,
            &sealed.nonce,
            &aad,
            &stream.ciphertext,
            &sealed.tag,
        )
        .unwrap();
        let upstream =
            aes_gcm_siv_encrypt_upstream(&KEY, &sealed.nonce, &aad, &compressed).unwrap();
        assert_eq!(upstream.ciphertext, stream.ciphertext, "{name}");
        assert_eq!(upstream.tag, sealed.tag, "{name}");
        assert_eq!(zstd::decode_all(&compressed[..]).unwrap(), data, "{name}");

        let recovered = StreamCryptoPipeline::default()
            .decrypt_and_decompress(&stream, &KEY, &sealed.nonce)
            .unwrap();
        assert_eq!(recovered, data, "{name}");

        if name == "noise" && rayon::current_num_threads() >= 2 {
            assert!(sealed.plan.is_parallel(), "plan {:?}", sealed.plan);
        }
        if name == "one" {
            assert!(!sealed.plan.is_parallel());
        }

        let mut tampered = stream.clone();
        tampered.ciphertext[0] ^= 1;
        assert_eq!(
            StreamCryptoPipeline::default().decrypt_and_decompress(&tampered, &KEY, &sealed.nonce),
            Err(PipelineError::Crypto(CryptoError::AuthenticationFailed))
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn seal_file_creates_missing_temp_dir() {
    let root = temp_dir("missing-temp-dir");
    let missing = root.join("spool");
    let input = root.join("input");
    std::fs::write(&input, b"create the configured spool directory").unwrap();

    let sealed = seal_file(&std::fs::File::open(&input).unwrap(), &missing, &KEY, 3).unwrap();
    assert!(missing.is_dir());
    drop(sealed);
    assert_eq!(leftover_temp_files(&missing), 0);

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn nonces_are_fresh_per_upload() {
    let dir = temp_dir("nonce");
    let path = dir.join("p");
    std::fs::write(&path, b"same input").unwrap();
    let a = seal_file(&std::fs::File::open(&path).unwrap(), &dir, &KEY, 3).unwrap();
    let b = seal_file(&std::fs::File::open(&path).unwrap(), &dir, &KEY, 3).unwrap();
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.tag, b.tag);
    drop((a, b));
    std::fs::remove_dir_all(&dir).unwrap();
}

async fn start(
    controller: RestServiceController,
) -> (std::net::SocketAddr, Arc<RestServiceController>) {
    let controller = Arc::new(controller);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(todo_rest::server::serve(listener, Arc::clone(&controller)));
    (addr, controller)
}

async fn post(addr: std::net::SocketAddr, headers: &str, body: &[u8]) -> (u16, Value) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let head = format!("POST {UPLOAD_ROUTE} HTTP/1.1\r\nHost: test\r\n{headers}\r\n");
    s.write_all(head.as_bytes()).await.unwrap();
    // A rejected request may be answered (and closed) before the body is sent.
    for part in body.chunks(100_000) {
        if s.write_all(part).await.is_err() {
            break;
        }
    }
    let mut resp = Vec::new();
    let _ = s.read_to_end(&mut resp).await;
    let text = String::from_utf8_lossy(&resp);
    let status = text[9..12].parse().unwrap();
    let json = text.split_once("\r\n\r\n").unwrap().1;
    (status, serde_json::from_str(json).unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_upload_end_to_end_with_mock_ipfs() {
    let dir = temp_dir("http");
    std::fs::remove_dir(&dir).unwrap();
    let cfg = UploadConfig::new(&KEY)
        .unwrap()
        .with_temp_dir(&dir)
        .with_max_upload_bytes(4 * 1024 * 1024)
        .unwrap();
    let (addr, controller) = start(RestServiceController::new().with_upload_config(cfg)).await;

    let data = noise(1_500_000, 7);
    let headers = format!(
        "Content-Type: application/octet-stream\r\nContent-Length: {}\r\nX-Object-Id: thesis-doc.pdf\r\n",
        data.len()
    );
    let (status, v) = post(addr, &headers, &data).await;
    assert_eq!(status, 200, "{v}");
    assert!(
        dir.is_dir(),
        "configured temporary directory is created on demand"
    );
    assert_eq!(v["status"], "success");
    assert_eq!(v["object_id"], "thesis-doc.pdf");
    assert_eq!(v["backend"], "mock");
    assert_eq!(v["aead_messages"], 1);
    assert_eq!(v["original_size_bytes"], data.len());
    assert!(v.to_string().find(&"42".repeat(32)).is_none(), "key leaked");

    let cid: todo_ipfs::Cid = v["ipfs_cid"].as_str().unwrap().parse().unwrap();
    let nonce_hex = v["nonce_hex"].as_str().unwrap();
    let nonce: [u8; 12] = (0..12)
        .map(|i| u8::from_str_radix(&nonce_hex[2 * i..2 * i + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let sealed = controller.fetch_from_ipfs(&cid).await.unwrap();
    assert_eq!(
        sealed.to_bytes().len() as u64,
        v["sealed_size_bytes"].as_u64().unwrap()
    );
    let rec = controller
        .recover_pipeline(PipelineRecoverRequest {
            sealed,
            key: KEY.to_vec(),
            nonce,
            crypto_mode: None,
        })
        .unwrap();
    assert_eq!(rec.recovered_data, data);
    assert_eq!(leftover_temp_files(&dir), 0, "temp files must not persist");

    // Error statuses.
    let n = data.len();
    let cases = [
        (
            format!("Content-Type: text/plain\r\nContent-Length: {n}\r\n"),
            415,
        ),
        (
            "Content-Type: application/octet-stream\r\n".to_string(),
            411,
        ),
        (
            "Content-Type: application/octet-stream\r\nContent-Length: 0\r\n".to_string(),
            400,
        ),
        (
            "Content-Type: application/octet-stream\r\nContent-Length: 99999999\r\n".to_string(),
            413,
        ),
        (
            format!(
                "Content-Type: application/octet-stream\r\nContent-Length: {n}\r\nX-Object-Id: ../x\r\n"
            ),
            400,
        ),
    ];
    for (headers, expected) in cases {
        // Rejected before the body is read; sending none avoids a TCP reset racing the
        // response.
        let (status, v) = post(addr, &headers, &[]).await;
        assert_eq!(status, expected, "{headers:?} -> {v}");
        assert_eq!(v["status"], "error");
    }
    // Truncated body.
    let headers = format!(
        "Content-Type: application/octet-stream\r\nContent-Length: {}\r\n",
        n + 10
    );
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("POST {UPLOAD_ROUTE} HTTP/1.1\r\nHost: t\r\n{headers}\r\n").as_bytes())
        .await
        .unwrap();
    s.write_all(&data).await.unwrap();
    s.shutdown().await.unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
    assert_eq!(leftover_temp_files(&dir), 0);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn upload_disabled_without_key() {
    let (addr, _) = start(RestServiceController::new()).await;
    let (status, v) = post(
        addr,
        "Content-Type: application/octet-stream\r\nContent-Length: 3\r\n",
        b"abc",
    )
    .await;
    assert_eq!(status, 503, "{v}");
}

#[test]
fn config_validation_and_redaction() {
    assert!(UploadConfig::new(&[0u8; 20]).is_err());
    let cfg = UploadConfig::new(&KEY).unwrap();
    assert!(!format!("{cfg:?}").contains("42, 42"));
    assert!(
        UploadConfig::new(&KEY)
            .unwrap()
            .with_max_upload_bytes(0)
            .is_err()
    );
    assert!(
        UploadConfig::new(&KEY)
            .unwrap()
            .with_max_upload_bytes(u64::MAX)
            .is_err()
    );
}

async fn get(addr: std::net::SocketAddr, target: &str) -> (u16, String, Vec<u8>) {
    get_with(addr, target, "").await
}

async fn get_with(addr: std::net::SocketAddr, target: &str, extra: &str) -> (u16, String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("GET {target} HTTP/1.1\r\nHost: test\r\n{extra}\r\n").as_bytes())
        .await
        .unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).await.unwrap();
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8(resp[..split].to_vec()).unwrap();
    let status = head[9..12].parse().unwrap();
    (status, head, resp[split + 4..].to_vec())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_download_verifies_before_release() {
    let dir = temp_dir("download");
    let cfg = UploadConfig::new(&KEY).unwrap().with_temp_dir(&dir);
    let (addr, controller) = start(RestServiceController::new().with_upload_config(cfg)).await;

    let data = noise(1_200_000, 99);
    let headers = format!(
        "Content-Type: application/octet-stream\r\nContent-Length: {}\r\nX-Object-Id: report.bin\r\n",
        data.len()
    );
    let (status, v) = post(addr, &headers, &data).await;
    assert_eq!(status, 200, "{v}");
    let cid = v["ipfs_cid"].as_str().unwrap().to_string();
    let nonce = v["nonce_hex"].as_str().unwrap().to_string();

    let (status, head, body) = get(addr, &format!("/api/v1/objects/{cid}?nonce={nonce}")).await;
    assert_eq!(status, 200, "{head}");
    assert_eq!(body, data);
    assert!(head.contains(&format!("Content-Length: {}", data.len())));
    assert!(head.contains("filename=\"report.bin\""));
    assert!(!head.contains("Access-Control-Allow-Origin"));

    // Wrong nonce: tag fails, no plaintext.
    let mut wrong = nonce.clone().into_bytes();
    wrong[0] = if wrong[0] == b'0' { b'1' } else { b'0' };
    let wrong = String::from_utf8(wrong).unwrap();
    let (status, _, body) = get(addr, &format!("/api/v1/objects/{cid}?nonce={wrong}")).await;
    assert_eq!(status, 422);
    let err: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err["status"], "error");
    assert!(body.len() < 200, "error body must not contain data");

    let unknown = todo_ipfs::Block::raw(b"never stored".to_vec()).unwrap();
    let missing = todo_ipfs::ObjectManifest::new(
        "x",
        vec![todo_ipfs::BlockLink {
            cid: unknown.cid().clone(),
            size: 12,
        }],
    )
    .unwrap()
    .to_block()
    .unwrap();
    for (target, expected) in [
        (format!("/api/v1/objects/{cid}"), 400),
        (format!("/api/v1/objects/{cid}?nonce=zz"), 400),
        (format!("/api/v1/objects/not-a-cid?nonce={nonce}"), 400),
        (
            format!("/api/v1/objects/{}?nonce={nonce}", missing.cid()),
            404,
        ),
    ] {
        let (status, head, _) = get(addr, &target).await;
        assert_eq!(status, expected, "{target}: {head}");
    }

    // Objects published through /ipfs/publish (independent frames, same v1 format) are
    // downloadable too when sealed with the server key.
    let text = b"multi-frame object ".repeat(20_000);
    let published = controller
        .publish_to_ipfs(todo_rest::DecentralizedPublishRequest {
            stream_id: "multi".into(),
            data: text.clone(),
            key: KEY.to_vec(),
            nonce: [7; 12],
            crypto_mode: None,
            stream_chunk_size: None,
        })
        .await
        .unwrap();
    let (status, _, body) = get(
        addr,
        &format!(
            "/api/v1/objects/{}?nonce={}",
            published.root_cid,
            "07".repeat(12)
        ),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, text);

    // Other crypto modes use other formats: rejected, not misparsed.
    let published = controller
        .publish_to_ipfs(todo_rest::DecentralizedPublishRequest {
            stream_id: "aegis".into(),
            data: text.clone(),
            key: KEY.to_vec(),
            nonce: [8; 12],
            crypto_mode: Some("aegis-256".into()),
            stream_chunk_size: None,
        })
        .await
        .unwrap();
    let (status, _, _) = get(
        addr,
        &format!(
            "/api/v1/objects/{}?nonce={}",
            published.root_cid,
            "08".repeat(12)
        ),
    )
    .await;
    assert_eq!(status, 422);

    assert_eq!(leftover_temp_files(&dir), 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn download_disabled_without_key() {
    let (addr, _) = start(RestServiceController::new()).await;
    let (status, _, _) = get(
        addr,
        "/api/v1/objects/bafkqaaa?nonce=000000000000000000000000",
    )
    .await;
    assert_eq!(status, 503);
}

const TOKEN: &str = "Zm9vYmFyLXRlc3QtdG9rZW4tMDEyMzQ1Njc4OWFiY2RlZg";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bearer_token_guards_upload_and_download() {
    let dir = temp_dir("auth");
    let cfg = UploadConfig::new(&KEY)
        .unwrap()
        .with_temp_dir(&dir)
        .with_api_token(TOKEN)
        .unwrap();
    let (addr, _) = start(RestServiceController::new().with_upload_config(cfg)).await;
    let data = noise(200_000, 5);
    let base = format!(
        "Content-Type: application/octet-stream\r\nContent-Length: {}\r\n",
        data.len()
    );

    // Rejected before the body is read (no body sent, see `post`).
    for auth in [
        String::new(),
        "Authorization: Bearer wrong-token-0123456789abcdef0123456789\r\n".into(),
        format!("Authorization: Basic {TOKEN}\r\n"),
        format!("Authorization: Bearer {TOKEN}x\r\n"),
    ] {
        let (status, v) = post(addr, &format!("{base}{auth}"), &[]).await;
        assert_eq!(status, 401, "{auth:?}: {v}");
        assert!(!v.to_string().contains(TOKEN));
    }

    let ok = format!("Authorization: bearer {TOKEN}\r\n");
    let (status, v) = post(addr, &format!("{base}{ok}"), &data).await;
    assert_eq!(status, 200, "{v}");
    let target = format!(
        "/api/v1/objects/{}?nonce={}",
        v["ipfs_cid"].as_str().unwrap(),
        v["nonce_hex"].as_str().unwrap()
    );

    let (status, head, body) = get(addr, &target).await;
    assert_eq!(status, 401);
    assert!(head.contains("WWW-Authenticate: Bearer"));
    assert!(body.len() < 200);
    let (status, _, _) = get_with(addr, &target, "Authorization: Bearer nope\r\n").await;
    assert_eq!(status, 401);
    let (status, _, body) = get_with(addr, &target, &ok).await;
    assert_eq!(status, 200);
    assert_eq!(body, data);

    assert_eq!(leftover_temp_files(&dir), 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn api_token_validation_redaction_and_exposure() {
    let base = || UploadConfig::new(&KEY).unwrap();
    for bad in [
        "short",
        &"a".repeat(31),
        &"a".repeat(513),
        "contains space 0123456789abcdef0123456789",
        "header\r\ninjection-0123456789abcdef012345",
        "================================",
    ] {
        assert!(base().with_api_token(bad).is_err(), "{bad:?}");
    }
    let cfg = base().with_api_token(TOKEN).unwrap();
    assert!(cfg.requires_token());
    assert!(cfg.authorize(Some(&format!("Bearer {TOKEN}"))).is_ok());
    assert!(cfg.authorize(Some(&format!("BEARER  {TOKEN} "))).is_ok());
    for bad in [
        None,
        Some(""),
        Some("Bearer"),
        Some(TOKEN),
        Some("Bearer x"),
    ] {
        assert_eq!(cfg.authorize(bad).unwrap_err().status, 401, "{bad:?}");
    }
    assert!(base().authorize(None).is_ok());
    assert!(!format!("{cfg:?}").contains(TOKEN));
    let headers = todo_rest::UploadHeaders {
        authorization: Some(zeroize::Zeroizing::new(format!("Bearer {TOKEN}"))),
        ..Default::default()
    };
    assert!(!format!("{headers:?}").contains(TOKEN));

    let any: std::net::SocketAddr = "0.0.0.0:80".parse().unwrap();
    let lo4: std::net::SocketAddr = "127.0.0.1:80".parse().unwrap();
    let lo6: std::net::SocketAddr = "[::1]:80".parse().unwrap();
    let open = RestServiceController::new().with_upload_config(base());
    assert!(open.check_exposure(lo4).is_ok());
    assert!(open.check_exposure(lo6).is_ok());
    assert!(open.check_exposure(any).is_err());
    let guarded = RestServiceController::new().with_upload_config(cfg);
    assert!(guarded.check_exposure(any).is_ok());
    assert!(RestServiceController::new().check_exposure(any).is_ok());
}
