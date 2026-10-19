//! Live Layer 2 + Layer 4 over a real socket: Redis sessions and the PostgreSQL object
//! catalog (accounts from the in-memory directory; MariaDB has its own live test).
//! Ignored by default:
//!
//! ```sh
//! TODO_TEST_REDIS_URL=redis://127.0.0.1:6379/15 \
//! TODO_TEST_POSTGRES_URL=postgres://todo_app@127.0.0.1:5432/todo_test \
//! TODO_TEST_POSTGRES_PASSWORD_FILE=~/.config/todo/secrets/postgres_password \
//!   cargo test -p todo-web --test live_stack -- --ignored
//! ```

use std::path::Path;
use std::sync::Arc;

use serde_json::Value;
use todo_database::accounts::{MemoryDirectory, NewUser, PiiCipher, Role};
use todo_database::objects::{ObjectCatalog, PgCatalog, postgres_options};
use todo_database::secrets::read_secret_file;
use todo_database::sessions::{SessionPolicy, SessionStore, redis_connection_info};
use todo_rest::{RestServiceController, UploadConfig};
use todo_web::server::{WebApp, WebAuth, serve};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

const PASSWORD: &str = "correct horse battery";

async fn raw(addr: &str, request: String) -> (u16, String, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8(buf).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    (
        head[9..12].parse().unwrap(),
        head.to_string(),
        body.to_string(),
    )
}

async fn get(addr: &str, path: &str, cookie: &str) -> (u16, String) {
    let (status, _, body) = raw(
        addr,
        format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{cookie}\r\n"),
    )
    .await;
    (status, body)
}

async fn login(addr: &str, user: &str) -> String {
    let body = format!(r#"{{"username":"{user}","password":"{PASSWORD}"}}"#);
    let (status, head, resp) = raw(
        addr,
        format!(
            "POST /api/v1/auth/login HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\n\
Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
    .await;
    assert_eq!(status, 200, "{resp}");
    let set = head
        .lines()
        .find_map(|l| l.strip_prefix("Set-Cookie: "))
        .unwrap();
    format!("Cookie: {}\r\n", set.split(';').next().unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs live Redis + PostgreSQL (TODO_TEST_REDIS_URL, TODO_TEST_POSTGRES_URL)"]
async fn redis_sessions_and_postgres_catalog_end_to_end() {
    let redis_url = std::env::var("TODO_TEST_REDIS_URL").expect("TODO_TEST_REDIS_URL");
    let pg_url = std::env::var("TODO_TEST_POSTGRES_URL").expect("TODO_TEST_POSTGRES_URL");
    assert!(
        pg_url.contains("todo_test"),
        "refusing to run outside todo_test"
    );
    let pg_pw = std::env::var("TODO_TEST_POSTGRES_PASSWORD_FILE")
        .ok()
        .map(|p| read_secret_file(Path::new(&p), "TODO_TEST_POSTGRES_PASSWORD_FILE").unwrap());

    let catalog = PgCatalog::connect(
        postgres_options(&pg_url, pg_pw.as_deref().map(String::as_str)).unwrap(),
    )
    .await
    .unwrap();
    catalog.migrate().await.unwrap();
    let catalog = Arc::new(catalog);
    let sessions = SessionStore::redis(
        redis_connection_info(&redis_url, None).unwrap(),
        SessionPolicy::default(),
    )
    .await
    .unwrap();

    // Rows are keyed by a fresh random CID and deleted at the end of the run.
    let dir = MemoryDirectory::new(PiiCipher::new(&[0x11; 32]).unwrap()).unwrap();
    let suffix = std::process::id();
    for name in ["owner", "other"] {
        dir.create_user(NewUser {
            username: format!("{name}{suffix}"),
            password: Zeroizing::new(PASSWORD.into()),
            role: Role::User,
            email: None,
            national_id: None,
        })
        .unwrap();
    }

    let tmp = std::env::temp_dir().join(format!("todo-web-live-{suffix}"));
    std::fs::create_dir_all(&tmp).unwrap();
    let cfg = UploadConfig::new(&[0x42; 32]).unwrap().with_temp_dir(&tmp);
    let controller = RestServiceController::new().with_upload_config(cfg);
    let app = WebApp::new(Arc::new(controller))
        .with_auth(WebAuth {
            accounts: Arc::new(dir),
            sessions: Arc::new(sessions),
        })
        .with_catalog(Arc::clone(&catalog) as Arc<dyn ObjectCatalog>);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(serve(listener, Arc::new(app)));

    let owner = login(&addr, &format!("owner{suffix}")).await;
    let data = "arsip live postgres\n".repeat(50_000);
    let (status, _, body) = raw(
        &addr,
        format!(
            "POST /api/v1/objects/upload HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\n\
Content-Type: application/octet-stream\r\nX-Object-Id: live.txt\r\n{owner}Content-Length: {}\r\n\r\n{data}",
            data.len()
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let up: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(up["metadata_store"], "postgresql");
    let cid = up["ipfs_cid"].as_str().unwrap().to_string();

    let (status, body) = get(&addr, "/api/v1/vault/objects", &owner).await;
    assert_eq!(status, 200, "{body}");
    let list: Value = serde_json::from_str(&body).unwrap();
    let row = list["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["ipfs_cid"] == cid.as_str())
        .expect("uploaded row listed")
        .clone();
    assert_eq!(row["nonce_hex"], up["nonce_hex"]);
    assert_eq!(row["encryption_plan"], up["encryption_plan"]);

    let (status, body) = get(&addr, &format!("/api/v1/objects/{cid}"), &owner).await;
    assert_eq!(status, 200);
    assert_eq!(body, data);
    let other = login(&addr, &format!("other{suffix}")).await;
    let (status, _) = get(&addr, &format!("/api/v1/objects/{cid}"), &other).await;
    assert_eq!(status, 404);

    sqlx::query("DELETE FROM objects WHERE root_cid = $1")
        .bind(&cid)
        .execute(catalog.pool())
        .await
        .unwrap();
    assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 0);
    std::fs::remove_dir_all(&tmp).unwrap();
}
