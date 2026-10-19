//! `todo-web`: Askama web console for the parallel AES-GCM-SIV + Zstd + IPFS pipeline.
//!
//! `WEB_HOST` (default `127.0.0.1`), `WEB_PORT` (default `8000`),
//! `TODO_IPFS_BACKEND=mock|kubo|gateway`, `TODO_IPFS_URL=<endpoint>`,
//! `TODO_UPLOAD_KEY_HEX`, `TODO_API_TOKEN` (required for the object routes off loopback),
//! `TODO_TLS_CERT` + `TODO_TLS_KEY` (PEM; enables HTTPS, TLS 1.3 only).
//! Accounts (both or neither): `TODO_MARIADB_URL` + `TODO_MARIADB_PASSWORD_FILE` +
//! `TODO_PII_KEY_HEX_FILE`, and `TODO_REDIS_URL` (+ `TODO_REDIS_PASSWORD_FILE`); MariaDB
//! migrations are applied at startup. Object metadata (needs accounts):
//! `TODO_POSTGRES_URL` + `TODO_POSTGRES_PASSWORD_FILE`, PostgreSQL migrations applied at
//! startup. Secrets: see `config/todo.env.example`.

use rukubo::Rukubo;
use std::env;
use std::sync::Arc;

use todo_rest::RestServiceController;
use todo_web::server::{WebApp, WebAuth, serve_with};

async fn auth_from_env(
    controller: &RestServiceController,
) -> Result<Option<WebAuth>, Box<dyn std::error::Error + Send + Sync>> {
    let upload = controller.upload_config();
    let accounts =
        todo_database::accounts::accounts_from_env(|k| upload.is_some_and(|u| u.uses_key(k)))
            .await?;
    let sessions = todo_database::sessions::SessionStore::from_env().await?;
    match (accounts, sessions) {
        (None, None) => Ok(None),
        (Some(accounts), Some(sessions)) => {
            accounts.migrate().await?;
            Ok(Some(WebAuth {
                accounts: Arc::new(accounts),
                sessions: Arc::new(sessions),
            }))
        }
        _ => Err("accounts need both TODO_MARIADB_URL and TODO_REDIS_URL".into()),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = todo_database::config::init_config_env();
    let host = env::var("WEB_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("WEB_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8000);

    let controller = Arc::new(RestServiceController::from_env()?);
    let rukubo = Arc::new(Rukubo::from_env()?);
    if controller.ipfs_backend() == todo_ipfs::BackendKind::Mock {
        return Err(
            "production todo-web requires live IPFS (TODO_IPFS_BACKEND=kubo|gateway and TODO_IPFS_URL); mock backend is prohibited in production"
                .into(),
        );
    }
    if controller.upload_config().is_none() {
        return Err(
            "production todo-web requires upload configuration (TODO_UPLOAD_KEY_HEX or TODO_UPLOAD_KEY_HEX_FILE)"
                .into(),
        );
    }
    let tls = todo_rest::tls::acceptor_from_env()?;
    let backend = controller.ipfs_backend();
    let listener = tokio::net::TcpListener::bind((host.as_str(), port)).await?;
    let addr = listener.local_addr()?;
    let auth = match auth_from_env(&controller).await? {
        Some(a) => a,
        None => {
            return Err(
                "production todo-web requires MariaDB accounts and Redis sessions (TODO_MARIADB_URL, TODO_REDIS_URL)"
                    .into(),
            );
        }
    };
    let catalog = match todo_database::objects::catalog_from_env().await? {
        Some(c) => {
            c.migrate().await?;
            c
        }
        None => {
            return Err(
                "production todo-web requires PostgreSQL object catalog (TODO_POSTGRES_URL)".into(),
            );
        }
    };

    let scheme = if tls.is_some() { "https" } else { "http" };
    println!("todo-web listening on {scheme}://{addr}");
    if tls.is_some() {
        println!("TLS 1.3 only (rustls/aws-lc-rs)");
    }
    println!("IPFS backend: {}", backend.label());
    println!(
        "Accounts: MariaDB + Redis sessions (idle {}s, absolute {}s)",
        auth.sessions.policy().idle_ttl.as_secs(),
        auth.sessions.policy().absolute_ttl.as_secs()
    );
    println!("Object metadata: PostgreSQL (owner-scoped downloads, server-side nonce)");
    if !addr.ip().is_loopback() && tls.is_none() {
        eprintln!("warning: non-loopback bind without TLS; all traffic is unencrypted plaintext");
    }
    if let Some(w) = todo_rest::tls::plaintext_exposure_warning(addr, tls.is_some()) {
        eprintln!("{w}");
    }
    let app = WebApp::new(controller)
        .with_auth(auth)
        .with_catalog(Arc::new(catalog))
        .with_rukubo(rukubo);
    serve_with(listener, Arc::new(app), tls).await?;
    Ok(())
}
