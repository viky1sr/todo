//! Layer 2/3 over a real socket: login, session cookie, profile with decrypted PII,
//! rate limiting, logout and session-authorised object routes. Uses the in-memory
//! account directory, session store and object catalog (same hashing/PII/validation code
//! paths as MariaDB/Redis/PostgreSQL).

use std::sync::Arc;

use serde_json::{Value, json};
use todo_database::accounts::{MemoryDirectory, NewUser, PiiCipher, Role};
use todo_database::objects::{MemoryCatalog, ObjectCatalog};
use todo_database::sessions::{SessionPolicy, SessionStore};
use todo_rest::{RestServiceController, UploadConfig};
use todo_web::server::{WebApp, WebAuth, serve};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

const PASSWORD: &str = "correct horse battery";
const TOKEN: &str = "dmF1bHQtdG9rZW4tZm9yLXRlc3RzLTAxMjM0NTY3ODk";

struct Reply {
    status: u16,
    headers: String,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap()
    }
}

async fn raw(addr: &str, request: String) -> Reply {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8(buf).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    Reply {
        status: head[9..12].parse().unwrap(),
        headers: head.to_string(),
        body: body.to_string(),
    }
}

async fn get(addr: &str, path: &str, extra: &str) -> Reply {
    raw(
        addr,
        format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{extra}\r\n"),
    )
    .await
}

async fn post(addr: &str, path: &str, body: &Value, extra: &str) -> Reply {
    let body = body.to_string();
    raw(
        addr,
        format!(
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\n\
Content-Type: application/json\r\n{extra}Content-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
    .await
}

fn directory() -> MemoryDirectory {
    let dir = MemoryDirectory::new(PiiCipher::new(&[0x11; 32]).unwrap()).unwrap();
    dir.create_user(NewUser {
        username: "budi".into(),
        password: Zeroizing::new(PASSWORD.into()),
        role: Role::Admin,
        email: Some(Zeroizing::new("budi@example.co.id".into())),
        national_id: Some(Zeroizing::new("3201234567890123".into())),
    })
    .unwrap();
    dir.create_user(NewUser {
        username: "siti".into(),
        password: Zeroizing::new(PASSWORD.into()),
        role: Role::User,
        email: None,
        national_id: None,
    })
    .unwrap();
    dir
}

async fn start(upload: Option<UploadConfig>, auth: bool) -> String {
    start_with_catalog(upload, auth, None).await
}

async fn start_with_catalog(
    upload: Option<UploadConfig>,
    auth: bool,
    catalog: Option<Arc<MemoryCatalog>>,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let mut controller = RestServiceController::new();
    if let Some(cfg) = upload {
        controller = controller.with_upload_config(cfg);
    }
    let mut app = WebApp::new(Arc::new(controller));
    if auth {
        app = app.with_auth(WebAuth {
            accounts: Arc::new(directory()),
            sessions: Arc::new(SessionStore::memory(SessionPolicy::default())),
        });
    }
    if let Some(c) = catalog {
        app = app.with_catalog(c);
    }
    tokio::spawn(serve(listener, Arc::new(app)));
    addr
}

/// `Cookie:` header line for the session set by a successful login.
async fn login(addr: &str, user: &str) -> String {
    let r = post(
        addr,
        "/api/v1/auth/login",
        &json!({ "username": user, "password": PASSWORD }),
        "",
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let set = r.header("set-cookie").unwrap();
    let pair = set.split(';').next().unwrap();
    format!("Cookie: theme=dark; {pair}\r\n")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_profile_logout_flow() {
    let addr = start(None, true).await;

    // Unauthenticated access to /account or other protected routes redirects to /login?next=...
    let redirect = get(&addr, "/account", "").await;
    assert_eq!(redirect.status, 302);
    assert_eq!(redirect.header("location"), Some("/login?next=/account"));

    for path in ["/status", "/settings", "/peers", "/diagnostics", "/explore"] {
        let r = get(&addr, path, "").await;
        assert_eq!(r.status, 302, "{path}");
        let expected_loc = if path == "/status" {
            "/login".to_string()
        } else {
            format!("/login?next={path}")
        };
        assert_eq!(r.header("location"), Some(expected_loc.as_str()), "{path}");
    }

    let page = get(&addr, "/login", "").await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("id=\"login-form\""));

    // Wrong password and unknown user: same generic 401, no cookie.
    for (u, p) in [("budi", "wrong password!!"), ("nobody", PASSWORD)] {
        let r = post(
            &addr,
            "/api/v1/auth/login",
            &json!({ "username": u, "password": p }),
            "",
        )
        .await;
        assert_eq!(r.status, 401);
        assert_eq!(r.json()["error"], "invalid username or password");
        assert!(r.header("set-cookie").is_none());
    }

    let r = post(
        &addr,
        "/api/v1/auth/login",
        &json!({ "username": "BUDI", "password": PASSWORD }),
        "",
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["role"], "admin");
    assert!(!r.body.contains(PASSWORD));
    let set = r.header("set-cookie").unwrap().to_string();
    assert!(set.starts_with("todo_sid="), "{set}");
    for attr in ["Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=43200"] {
        assert!(set.contains(attr), "{set}");
    }
    assert!(
        !set.contains("Secure"),
        "plain HTTP must not mark the cookie Secure"
    );
    let token = set.split(';').next().unwrap()["todo_sid=".len()..].to_string();
    assert_eq!(token.len(), 64);
    let cookie = format!("Cookie: todo_sid={token}\r\n");

    // Profile: PII decrypted server-side, never compressed, no-store.
    let me = get(
        &addr,
        "/api/v1/auth/me",
        &format!("{cookie}Accept-Encoding: zstd, gzip\r\n"),
    )
    .await;
    assert_eq!(me.status, 200, "{}", me.body);
    let v = me.json();
    assert_eq!(v["username"], "budi");
    assert_eq!(v["email"], "budi@example.co.id");
    assert_eq!(v["national_id"], "3201234567890123");
    assert!(me.header("content-encoding").is_none());
    assert_eq!(me.header("cache-control"), Some("no-store"));

    // The page shows the user but no PII (PII only via the JSON endpoint).
    let page = get(&addr, "/account", &cookie).await;
    assert!(page.body.contains("id=\"account-profile\""));
    assert!(page.body.contains("budi"));
    assert!(!page.body.contains("3201234567890123"));
    assert!(!page.body.contains("budi@example.co.id"));

    assert_eq!(get(&addr, "/api/v1/auth/me", "").await.status, 401);
    let bogus = format!("Cookie: todo_sid={}\r\n", "f".repeat(64));
    assert_eq!(get(&addr, "/api/v1/auth/me", &bogus).await.status, 401);
    // The TLS cookie name is ignored on a plain-HTTP connection.
    let wrong_name = format!("Cookie: __Host-todo_sid={token}\r\n");
    assert_eq!(get(&addr, "/api/v1/auth/me", &wrong_name).await.status, 401);

    // A second login issues a new token and revokes the presented one.
    let r = post(
        &addr,
        "/api/v1/auth/login",
        &json!({ "username": "budi", "password": PASSWORD }),
        &cookie,
    )
    .await;
    let set2 = r.header("set-cookie").unwrap();
    assert!(!set2.contains(&token));
    assert_eq!(get(&addr, "/api/v1/auth/me", &cookie).await.status, 401);
    let cookie2 = format!("Cookie: {}\r\n", set2.split(';').next().unwrap());

    let out = post(&addr, "/api/v1/auth/logout", &json!({}), &cookie2).await;
    assert_eq!(out.status, 200);
    let cleared = out.header("set-cookie").unwrap();
    assert!(cleared.starts_with("todo_sid=;") && cleared.contains("Max-Age=0"));
    assert_eq!(get(&addr, "/api/v1/auth/me", &cookie2).await.status, 401);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_csrf_validation_and_rate_limit() {
    let addr = start(None, true).await;
    let body = json!({ "username": "siti", "password": PASSWORD }).to_string();

    // Cross-site form posts are refused: wrong content type or foreign Origin.
    let text_plain = raw(
        &addr,
        format!(
            "POST /api/v1/auth/login HTTP/1.1\r\nHost: {addr}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
    .await;
    assert_eq!(text_plain.status, 415);
    let foreign = raw(
        &addr,
        format!(
            "POST /api/v1/auth/login HTTP/1.1\r\nHost: {addr}\r\nOrigin: https://evil.example\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
    .await;
    assert_eq!(foreign.status, 403);
    assert!(foreign.header("set-cookie").is_none());

    let bad = post(&addr, "/api/v1/auth/login", &json!({ "user": "x" }), "").await;
    assert_eq!(bad.status, 400);
    assert_eq!(get(&addr, "/api/v1/auth/login", "").await.status, 405);
    assert_eq!(get(&addr, "/api/v1/auth/nope", "").await.status, 404);

    // 5 failures lock the username (even the right password), not other users.
    for _ in 0..5 {
        let r = post(
            &addr,
            "/api/v1/auth/login",
            &json!({ "username": "siti", "password": "wrong password!!" }),
            "",
        )
        .await;
        assert_eq!(r.status, 401);
    }
    let locked = post(
        &addr,
        "/api/v1/auth/login",
        &json!({ "username": "siti", "password": PASSWORD }),
        "",
    )
    .await;
    assert_eq!(locked.status, 429);
    assert!(locked.header("set-cookie").is_none());
    login(&addr, "budi").await;
}

#[tokio::test]
async fn auth_routes_without_accounts_are_503() {
    let addr = start(None, false).await;
    let r = post(
        &addr,
        "/api/v1/auth/login",
        &json!({ "username": "budi", "password": PASSWORD }),
        "",
    )
    .await;
    assert_eq!(r.status, 503);
    let page = get(&addr, "/account", "").await;
    assert!(page.body.contains("Akun nonaktif"));
}

fn upload_request(addr: &str, data: &str, extra: &str) -> String {
    format!(
        "POST /api/v1/objects/upload HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\n\
Content-Type: application/octet-stream\r\nX-Object-Id: arsip.txt\r\n{extra}Content-Length: {}\r\n\r\n{data}",
        data.len()
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn object_routes_accept_session_or_token() {
    let tmp = std::env::temp_dir().join(format!("todo-web-session-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let data = "arsip final bersegel\n".repeat(20_000);

    // Accounts on, no API token: anonymous callers must log in.
    let cfg = UploadConfig::new(&[0x42; 32]).unwrap().with_temp_dir(&tmp);
    let addr = start(Some(cfg), true).await;
    let vault = get(&addr, "/vault", "").await;
    assert_eq!(vault.status, 302);
    assert_eq!(vault.header("location"), Some("/login?next=/vault"));
    // Rejected before the body is read: send headers only (avoids an RST race).
    let mut anon = upload_request(&addr, &data, "");
    anon.truncate(anon.len() - data.len());
    let r = raw(&addr, anon).await;
    assert_eq!(r.status, 401);
    assert_eq!(r.json()["error"], "login required");

    let cookie = login(&addr, "siti").await;
    let vault = get(&addr, "/vault", &cookie).await;
    assert!(vault.body.contains("masuk sebagai <strong>siti</strong>"));
    assert!(!vault.body.contains("id=\"vault-token\""));
    let r = raw(&addr, upload_request(&addr, &data, &cookie)).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let v = r.json();
    let (cid, nonce) = (
        v["ipfs_cid"].as_str().unwrap(),
        v["nonce_hex"].as_str().unwrap(),
    );
    let path = format!("/api/v1/objects/{cid}?nonce={nonce}");
    let r = get(&addr, &path, &cookie).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, data);
    assert_eq!(get(&addr, &path, "").await.status, 401);

    let out = post(&addr, "/api/v1/auth/logout", &json!({}), &cookie).await;
    assert_eq!(out.status, 200);
    assert_eq!(get(&addr, &path, &cookie).await.status, 401);

    // Accounts on + API token: either credential works, neither is refused.
    let cfg = UploadConfig::new(&[0x42; 32])
        .unwrap()
        .with_temp_dir(&tmp)
        .with_api_token(TOKEN)
        .unwrap();
    let addr = start(Some(cfg), true).await;
    let vault = get(&addr, "/vault", "").await;
    assert!(vault.body.contains("id=\"vault-token\""));
    let bearer = format!("Authorization: Bearer {TOKEN}\r\n");
    let r = raw(&addr, upload_request(&addr, &data, &bearer)).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let v = r.json();
    let path = format!(
        "/api/v1/objects/{}?nonce={}",
        v["ipfs_cid"].as_str().unwrap(),
        v["nonce_hex"].as_str().unwrap()
    );
    assert_eq!(get(&addr, &path, &bearer).await.status, 200);
    let cookie = login(&addr, "budi").await;
    assert_eq!(get(&addr, &path, &cookie).await.status, 200);
    assert_eq!(get(&addr, &path, "").await.status, 401);

    assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 0);
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catalog_records_uploads_and_scopes_downloads_to_owner() {
    let tmp = std::env::temp_dir().join(format!("todo-web-catalog-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let data = "dokumen milik siti\n".repeat(30_000);
    let catalog = Arc::new(MemoryCatalog::new());
    let cfg = UploadConfig::new(&[0x42; 32]).unwrap().with_temp_dir(&tmp);
    let addr = start_with_catalog(Some(cfg), true, Some(Arc::clone(&catalog))).await;

    assert_eq!(get(&addr, "/api/v1/vault/objects", "").await.status, 401);
    let siti = login(&addr, "siti").await;
    let page = get(&addr, "/vault", &siti).await;
    assert!(page.body.contains("data-catalog"));
    assert!(page.body.contains("Objek saya"));

    let r = raw(&addr, upload_request(&addr, &data, &siti)).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let up = r.json();
    assert_eq!(up["metadata_store"], "memory");
    let cid = up["ipfs_cid"].as_str().unwrap().to_string();
    let nonce = up["nonce_hex"].as_str().unwrap().to_string();

    let list = get(&addr, "/api/v1/vault/objects", &siti).await;
    assert_eq!(list.status, 200, "{}", list.body);
    assert_eq!(list.header("cache-control"), Some("no-store"));
    let rows = list.json()["objects"].as_array().unwrap().clone();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["ipfs_cid"], cid.as_str());
    assert_eq!(rows[0]["nonce_hex"], nonce.as_str());
    assert_eq!(rows[0]["tag_hex"], up["tag_hex"]);
    assert_eq!(rows[0]["object_id"], "arsip.txt");
    assert_eq!(rows[0]["original_size_bytes"], data.len());

    // Owner: no nonce needed (stored server-side); a wrong nonce still fails the tag.
    let r = get(&addr, &format!("/api/v1/objects/{cid}"), &siti).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, data);
    let mut bad = nonce.clone().into_bytes();
    bad[23] = if bad[23] == b'0' { b'1' } else { b'0' };
    let bad = String::from_utf8(bad).unwrap();
    let r = get(&addr, &format!("/api/v1/objects/{cid}?nonce={bad}"), &siti).await;
    assert_eq!(r.status, 422, "{}", r.body);
    assert!(!r.body.contains("dokumen milik siti"));

    // Another user: neither listing nor download, even with the correct nonce.
    let budi = login(&addr, "budi").await;
    let list = get(&addr, "/api/v1/vault/objects", &budi).await;
    assert_eq!(list.json()["objects"].as_array().unwrap().len(), 0);
    for path in [
        format!("/api/v1/objects/{cid}"),
        format!("/api/v1/objects/{cid}?nonce={nonce}"),
    ] {
        let r = get(&addr, &path, &budi).await;
        assert_eq!(r.status, 404, "{}", r.body);
        assert_eq!(r.json()["error"], "object not found for this account");
    }
    assert_eq!(
        get(&addr, &format!("/api/v1/objects/{cid}"), "")
            .await
            .status,
        401
    );
    let r = get(&addr, "/api/v1/objects/not-a-cid", &siti).await;
    assert_eq!(r.status, 400);
    let r = post(&addr, "/api/v1/vault/objects", &json!({}), &siti).await;
    assert_eq!(r.status, 405);

    let owner = catalog.list(2, 10).await.unwrap();
    assert_eq!(owner.len(), 1, "siti is user 2 in the directory");
    assert!(catalog.list(1, 10).await.unwrap().is_empty());

    // Without a catalog the listing route reports it is not configured.
    let addr = start(
        Some(UploadConfig::new(&[0x42; 32]).unwrap().with_temp_dir(&tmp)),
        true,
    )
    .await;
    let siti = login(&addr, "siti").await;
    assert_eq!(get(&addr, "/api/v1/vault/objects", &siti).await.status, 503);

    assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 0);
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_login_payload_envelope() {
    let addr = start(None, true).await;
    let key = [0x55u8; 32];
    let iv = [0x77u8; 16];
    let plain =
        json!({ "username": "siti", "password": PASSWORD, "timestamp": 1234567890u64 }).to_string();
    let ct = todo_crypto::decrypt_aes_ctr_payload(&key, &iv, plain.as_bytes()).unwrap();
    let to_hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
    let enc_body = json!({
        "encrypted": true,
        "key": to_hex(&key),
        "iv": to_hex(&iv),
        "ciphertext": to_hex(&ct),
    });
    let r = post(&addr, "/api/v1/auth/login", &enc_body, "").await;
    assert_eq!(
        r.status, 200,
        "encrypted payload login failed: {:?}",
        r.body
    );
    assert_eq!(r.json()["username"], "siti");
    assert_eq!(r.json()["role"], "user");
    assert!(r.header("set-cookie").is_some());
}
