use std::time::Duration;
use todo_rest::server::RestApiServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const PORT: u16 = 18088;

async fn request(method: &str, path: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", PORT)).await.unwrap();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut res = Vec::new();
    stream.read_to_end(&mut res).await.unwrap();
    String::from_utf8_lossy(&res).to_string()
}

fn json_body(response: &str) -> serde_json::Value {
    let body = response.split("\r\n\r\n").nth(1).unwrap();
    serde_json::from_str(body).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn rest_server_http_endpoints_e2e() {
    let server = RestApiServer::new("127.0.0.1", PORT);
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let res = request("GET", "/api/v1/health", "").await;
    assert!(res.contains("HTTP/1.1 200 OK"));
    assert!(res.contains(r#""status":"ok""#));

    let res = request(
        "POST",
        "/api/v1/verify-equivalence",
        r#"{"data_utf8":"Tag equivalence check across HTTP","segment_size":16}"#,
    )
    .await;
    assert!(res.contains("HTTP/1.1 200 OK"), "{res}");
    assert!(res.contains(r#""is_bit_identical":true"#));

    let res = request(
        "POST",
        "/api/v1/pipeline/process",
        r#"{
            "data_utf8": "End-to-end data pipeline streaming test payload",
            "key_hex": "0102030405060708090a0b0c0d0e0f10",
            "nonce_hex": "0102030405060708090a0b0c",
            "segment_size": 16384,
            "compression_level": 3,
            "polyval_segment_size": 64
        }"#,
    )
    .await;
    assert!(res.contains("HTTP/1.1 200 OK"), "{res}");
    let processed = json_body(&res);
    assert_eq!(processed["success"], true);

    let recover_body = serde_json::json!({
        "sealed": processed["sealed"],
        "key_hex": "0102030405060708090a0b0c0d0e0f10",
        "nonce_hex": "0102030405060708090a0b0c",
    })
    .to_string();
    let res = request("POST", "/api/v1/pipeline/recover", &recover_body).await;
    assert!(res.contains("HTTP/1.1 200 OK"), "{res}");
    assert_eq!(
        json_body(&res)["recovered_utf8"],
        "End-to-end data pipeline streaming test payload"
    );

    let wrong_key_body = recover_body.replace(
        "0102030405060708090a0b0c0d0e0f10",
        "ff02030405060708090a0b0c0d0e0f10",
    );
    let res = request("POST", "/api/v1/pipeline/recover", &wrong_key_body).await;
    assert!(res.contains("HTTP/1.1 400 Bad Request"), "{res}");
    assert!(res.contains("authentication"));

    let res = request(
        "POST",
        "/api/v1/ipfs/publish",
        r#"{
            "stream_id": "http-stream-alpha",
            "data_utf8": "Decentralized IPFS pinning test record",
            "key_hex": "0102030405060708090a0b0c0d0e0f10",
            "nonce_hex": "0102030405060708090a0b0c"
        }"#,
    )
    .await;
    assert!(res.contains("HTTP/1.1 200 OK"), "{res}");
    let published = json_body(&res);
    assert_eq!(published["backend"], "mock");
    let root = published["root_cid"].as_str().unwrap().to_string();
    // CIDv1, dag-json, sha2-256, base32: always starts with "baguqeera".
    assert!(root.starts_with("baguqeera"), "{root}");
    assert!(root.parse::<todo_ipfs::Cid>().is_ok());

    let fetch = |root: &str, key: &str| {
        serde_json::json!({
            "root_cid": root,
            "key_hex": key,
            "nonce_hex": "0102030405060708090a0b0c",
        })
        .to_string()
    };
    let key = "0102030405060708090a0b0c0d0e0f10";
    let res = request("POST", "/api/v1/ipfs/fetch", &fetch(&root, key)).await;
    assert!(res.contains("HTTP/1.1 200 OK"), "{res}");
    assert_eq!(
        json_body(&res)["recovered_utf8"],
        "Decentralized IPFS pinning test record"
    );

    let wrong_key = "ff02030405060708090a0b0c0d0e0f10";
    let res = request("POST", "/api/v1/ipfs/fetch", &fetch(&root, wrong_key)).await;
    assert!(res.contains("HTTP/1.1 400 Bad Request"), "{res}");
    assert!(!res.contains("Decentralized IPFS"), "{res}");

    let res = request(
        "POST",
        "/api/v1/ipfs/fetch",
        &fetch("bafybeigf7b969b0912a860600000073", key),
    )
    .await;
    assert!(res.contains("HTTP/1.1 400 Bad Request"), "{res}");

    let absent = todo_ipfs::Cid::sha2_256(todo_ipfs::cid::codec::DAG_JSON, b"absent");
    let res = request(
        "POST",
        "/api/v1/ipfs/fetch",
        &fetch(&absent.to_string(), key),
    )
    .await;
    assert!(res.contains("HTTP/1.1 404 Not Found"), "{res}");

    let res = request("GET", "/api/v1/nope", "").await;
    assert!(res.contains("HTTP/1.1 404 Not Found"));
}
