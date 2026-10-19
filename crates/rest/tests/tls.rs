//! In-process TLS: TLS 1.3 only, object routes over HTTPS, configuration errors.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;
use todo_rest::server::serve_with;
use todo_rest::{RestServiceController, UploadConfig, tls};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

const TOKEN: &str = "dGxzLXRlc3QtdG9rZW4tMDEyMzQ1Njc4OWFiY2RlZmdo";

struct Pki {
    dir: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    der: CertificateDer<'static>,
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn make_pki(tag: &str) -> Pki {
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).unwrap();
    let dir = std::env::temp_dir().join(format!(
        "todo-rest-tls-{tag}-{}",
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert, ck.cert.pem()).unwrap();
    std::fs::write(&key, ck.signing_key.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    Pki {
        dir,
        cert,
        key,
        der: ck.cert.der().clone(),
    }
}

fn client(
    der: &CertificateDer<'static>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.add(der.clone()).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsConnector::from(Arc::new(cfg))
}

async fn start(controller: RestServiceController, cert: &Path, key: &Path) -> std::net::SocketAddr {
    let acceptor = tls::acceptor(cert, key).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_with(listener, Arc::new(controller), Some(acceptor)));
    addr
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    request: &[u8],
) -> (u16, String, Vec<u8>) {
    s.write_all(request).await.unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).await.unwrap();
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8(resp[..split].to_vec()).unwrap();
    (
        head[9..12].parse().unwrap(),
        head,
        resp[split + 4..].to_vec(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_tls13_only_with_object_routes() {
    let pki = make_pki("e2e");
    let tmp = pki.dir.join("spool");
    std::fs::create_dir_all(&tmp).unwrap();
    let cfg = UploadConfig::new(&[0x11; 32])
        .unwrap()
        .with_temp_dir(&tmp)
        .with_api_token(TOKEN)
        .unwrap();
    let addr = start(
        RestServiceController::new().with_upload_config(cfg),
        &pki.cert,
        &pki.key,
    )
    .await;
    let name = ServerName::try_from("localhost").unwrap();
    let tls13 = client(&pki.der, &[&rustls::version::TLS13]);

    // TLS 1.3 negotiated, ALPN http/1.1, plain JSON route works.
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut s = tls13.connect(name.clone(), tcp).await.unwrap();
    let conn = s.get_ref().1;
    assert_eq!(
        conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(conn.alpn_protocol(), Some(&b"http/1.1"[..]));
    let (status, _, _) = exchange(
        &mut s,
        b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200);

    // Upload (2 MiB, many TLS records) and verified download over HTTPS with the token.
    let data: Vec<u8> = (0..2_000_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let mut req = format!(
        "POST /api/v1/objects/upload HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\
Content-Type: application/octet-stream\r\nX-Object-Id: tls.bin\r\nContent-Length: {}\r\n\r\n",
        data.len()
    )
    .into_bytes();
    req.extend_from_slice(&data);
    let mut s = tls13
        .connect(name.clone(), TcpStream::connect(addr).await.unwrap())
        .await
        .unwrap();
    let (status, _, body) = exchange(&mut s, &req).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let v: Value = serde_json::from_slice(&body).unwrap();
    let get = format!(
        "GET /api/v1/objects/{}?nonce={} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\r\n",
        v["ipfs_cid"].as_str().unwrap(),
        v["nonce_hex"].as_str().unwrap()
    );
    let mut s = tls13
        .connect(name.clone(), TcpStream::connect(addr).await.unwrap())
        .await
        .unwrap();
    let (status, head, body) = exchange(&mut s, get.as_bytes()).await;
    assert_eq!(status, 200, "{head}");
    assert_eq!(body, data);
    assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 0);

    // A TLS 1.2-only client cannot connect.
    let tls12 = client(&pki.der, &[&rustls::version::TLS12]);
    let tcp = TcpStream::connect(addr).await.unwrap();
    assert!(tls12.connect(name.clone(), tcp).await.is_err());

    // Plain HTTP on the TLS port never gets an HTTP response.
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ =
        tokio::time::timeout(std::time::Duration::from_secs(5), tcp.read_to_end(&mut buf)).await;
    assert!(!buf.starts_with(b"HTTP/"));

    // A client that does not trust the certificate fails.
    let other = make_pki("other");
    let tcp = TcpStream::connect(addr).await.unwrap();
    assert!(
        client(&other.der, &[&rustls::version::TLS13])
            .connect(name, tcp)
            .await
            .is_err()
    );
}

#[test]
fn tls_configuration_errors() {
    let a = make_pki("cfg-a");
    let b = make_pki("cfg-b");
    assert!(tls::server_config(&a.cert, &a.key).is_ok());
    // Mismatched certificate and key.
    assert!(tls::server_config(&a.cert, &b.key).is_err());
    // Missing files, empty certificate file, key given as certificate.
    let missing = a.dir.join("missing.pem");
    assert!(tls::server_config(&missing, &a.key).is_err());
    assert!(tls::server_config(&a.cert, &missing).is_err());
    let empty = a.dir.join("empty.pem");
    std::fs::write(&empty, "").unwrap();
    assert!(tls::server_config(&empty, &a.key).is_err());
    let err = tls::server_config(&a.key, &a.key).unwrap_err().to_string();
    let key_pem = std::fs::read_to_string(&a.key).unwrap();
    let key_body = key_pem.lines().nth(1).unwrap();
    assert!(!err.contains(key_body), "error must not echo key material");

    let any: std::net::SocketAddr = "0.0.0.0:443".parse().unwrap();
    let lo: std::net::SocketAddr = "127.0.0.1:80".parse().unwrap();
    assert!(tls::plaintext_exposure_warning(any, false).is_some());
    assert!(tls::plaintext_exposure_warning(any, true).is_none());
    assert!(tls::plaintext_exposure_warning(lo, false).is_none());
}
