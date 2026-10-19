//! Layer 1: `Content-Encoding` negotiation over a real socket (mock IPFS backend).

use std::io::Read;
use std::sync::Arc;

use todo_rest::RestServiceController;
use todo_web::server::{ContentCoding, WebApp, negotiate, serve};
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
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }

    fn decoded(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self.header("content-encoding") {
            None => out.clone_from(&self.body),
            Some("zstd") => {
                let mut d = zstd::stream::Decoder::new(&self.body[..]).unwrap();
                d.window_log_max(23).unwrap();
                d.read_to_end(&mut out).unwrap();
            }
            Some("gzip") => {
                flate2::read::GzDecoder::new(&self.body[..])
                    .read_to_end(&mut out)
                    .unwrap();
            }
            Some(other) => panic!("unexpected coding {other}"),
        }
        out
    }
}

async fn request(addr: &str, method: &str, path: &str, accept: Option<&str>, body: &str) -> Reply {
    let accept = accept
        .map(|a| format!("Accept-Encoding: {a}\r\n"))
        .unwrap_or_default();
    let extra = if body.is_empty() {
        String::new()
    } else {
        format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        )
    };
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(
        format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\n{accept}{extra}\r\n{body}").as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let headers = String::from_utf8(buf[..end].to_vec()).unwrap();
    let status = headers[9..12].parse().unwrap();
    let body = buf[end + 4..].to_vec();
    let reply = Reply {
        status,
        headers,
        body,
    };
    if method != "HEAD" {
        let len: usize = reply.header("content-length").unwrap().parse().unwrap();
        assert_eq!(len, reply.body.len());
    }
    reply
}

#[test]
fn accept_encoding_negotiation() {
    use ContentCoding::*;
    for (header, want) in [
        (None, Identity),
        (Some(""), Identity),
        (Some("identity"), Identity),
        (Some("gzip"), Gzip),
        (Some("GZIP"), Gzip),
        (Some("x-gzip"), Gzip),
        (Some("zstd"), Zstd),
        (Some("gzip, deflate, br, zstd"), Zstd),
        (Some("zstd;q=0.5, gzip"), Gzip),
        (Some("zstd;q=0, gzip;q=0.1"), Gzip),
        (Some("zstd;q=0, gzip;q=0"), Identity),
        (Some("*"), Zstd),
        (Some("*;q=0.2, zstd;q=0"), Gzip),
        (Some("br"), Identity),
        (Some("gzip;q=bogus, zstd;q=0"), Identity),
    ] {
        assert_eq!(negotiate(header), want, "{header:?}");
    }
}

#[tokio::test]
async fn pages_and_assets_are_compressed_and_decode_identically() {
    let addr = start().await;
    for path in [
        "/",
        "/vault",
        "/pipeline",
        "/static/app.js",
        "/static/app.css",
        "/static/favicon.svg",
    ] {
        let plain = request(&addr, "GET", path, None, "").await;
        assert_eq!(plain.status, 200, "{path}");
        assert_eq!(plain.header("content-encoding"), None);
        assert_eq!(plain.header("vary"), Some("Accept-Encoding"), "{path}");
        let mut sizes = vec![plain.body.len()];
        for (accept, token) in [("gzip", "gzip"), ("gzip, deflate, br, zstd", "zstd")] {
            let r = request(&addr, "GET", path, Some(accept), "").await;
            assert_eq!(r.status, 200);
            assert_eq!(r.header("content-encoding"), Some(token), "{path} {accept}");
            assert_eq!(r.header("vary"), Some("Accept-Encoding"));
            assert!(r.header("content-security-policy").is_some());
            assert_eq!(r.decoded(), plain.body, "{path} {token}");
            assert!(r.body.len() < plain.body.len());
            sizes.push(r.body.len());
            // Second request hits the asset cache; bytes must be stable.
            let again = request(&addr, "GET", path, Some(accept), "").await;
            if path.starts_with("/static/") {
                assert_eq!(again.body, r.body);
            }
            // HEAD advertises the encoded length without a body.
            let head = request(&addr, "HEAD", path, Some(accept), "").await;
            assert!(head.body.is_empty());
            assert_eq!(head.header("content-encoding"), Some(token));
            assert_eq!(
                head.header("content-length").unwrap(),
                r.body.len().to_string()
            );
        }
        println!(
            "{path}: identity {} gzip {} zstd {}",
            sizes[0], sizes[1], sizes[2]
        );
    }
}

#[tokio::test]
async fn api_errors_and_reflected_pages_are_never_compressed() {
    let addr = start().await;
    let api = request(&addr, "GET", "/api/v1/health", Some("zstd, gzip"), "").await;
    assert_eq!(api.header("content-encoding"), None);
    assert_eq!(api.header("vary"), None);

    // Pipeline JSON echoes caller-supplied data: must stay uncompressed (BREACH).
    let body = format!(
        r#"{{"plaintext":"{}","key_hex":"{}","nonce_hex":"{}"}}"#,
        "a".repeat(4096),
        "00".repeat(32),
        "00".repeat(12)
    );
    let api = request(
        &addr,
        "POST",
        "/api/v1/pipeline/process",
        Some("zstd, gzip"),
        &body,
    )
    .await;
    assert_eq!(api.header("content-encoding"), None);

    // 404 page reflects the requested path.
    let nf = request(
        &addr,
        "GET",
        &format!("/{}", "x".repeat(600)),
        Some("zstd"),
        "",
    )
    .await;
    assert_eq!(nf.status, 404);
    assert_eq!(nf.header("content-encoding"), None);

    // Explicit refusal is honoured.
    let r = request(&addr, "GET", "/", Some("zstd;q=0, gzip;q=0"), "").await;
    assert_eq!(r.header("content-encoding"), None);
}
