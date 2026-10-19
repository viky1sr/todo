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
use std::time::Duration;

use todo_database::objects::{ObjectCatalog, PgCatalog, UploadState};
use todo_ipfs::{IpfsError, StagedObject};
use todo_rest::RestServiceController;
use todo_web::server::{WebApp, WebAuth, serve_with};

const RECOVERY_BATCH: u32 = 100;
const RECOVERY_INTERVAL: Duration = Duration::from_secs(30);

fn backend_name(kind: todo_ipfs::BackendKind) -> &'static str {
    match kind {
        todo_ipfs::BackendKind::Mock => "mock",
        todo_ipfs::BackendKind::KuboRpc => "kubo_rpc",
        todo_ipfs::BackendKind::TrustlessGateway => "trustless_gateway",
    }
}

async fn abort_recovery_object(
    catalog: &PgCatalog,
    controller: &RestServiceController,
    transaction_id: &str,
    root: Option<&todo_ipfs::Cid>,
    reason: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(root) = root {
        let _ = controller.ipfs_store().unpin_object(root).await;
    }
    catalog.abort_upload(transaction_id, reason).await?;
    Ok(())
}

/// Resolve lifecycle records left by a previous process before the listener starts.
/// `PUBLISHING` is safe to finish because complete metadata + deterministic root were
/// journaled before the recursive pin. `WRITING` is aborted only after its database
/// lease expires; a live uploader renews that lease, so another instance cannot reclaim it.
async fn reconcile_upload_journal(
    catalog: &PgCatalog,
    controller: &RestServiceController,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let current_backend = backend_name(controller.ipfs_backend());
    let mut recovered = 0usize;

    loop {
        let pending = catalog.pending_uploads(RECOVERY_BATCH).await?;
        if pending.is_empty() {
            break;
        }

        for transaction in pending {
            match transaction.state {
                UploadState::Writing => {
                    // Re-check expiry atomically. The uploader may have renewed or moved
                    // to PUBLISHING after our SELECT. Never abort based on a stale scan.
                    let _ = catalog
                        .abort_expired_writing(
                            &transaction.transaction_id,
                            "expired_writer_lease",
                        )
                        .await?;
                }
                UploadState::Publishing => {
                    let object = transaction.object.as_ref().ok_or_else(|| {
                        format!(
                            "publishing transaction {} has no object metadata",
                            transaction.transaction_id
                        )
                    })?;
                    if object.backend != current_backend {
                        return Err(format!(
                            "pending transaction {} belongs to backend {}, current backend is {}; restore the original backend before recovery",
                            transaction.transaction_id, object.backend, current_backend
                        )
                        .into());
                    }
                    let root = object
                        .root_cid
                        .parse::<todo_ipfs::Cid>()
                        .map_err(|e| format!("invalid journal root {}: {e}", object.root_cid))?;
                    let mut sink = tokio::io::sink();
                    let manifest = match controller
                        .ipfs_store()
                        .write_object_to(&root, &mut sink)
                        .await
                    {
                        Ok(manifest) => manifest,
                        Err(IpfsError::NotFound(_)) => {
                            abort_recovery_object(
                                catalog,
                                controller,
                                &transaction.transaction_id,
                                Some(&root),
                                "staged_root_missing_after_restart",
                            )
                            .await?;
                            continue;
                        }
                        Err(
                            IpfsError::DigestMismatch { .. }
                            | IpfsError::CidMismatch { .. }
                            | IpfsError::InvalidManifest(_),
                        ) => {
                            abort_recovery_object(
                                catalog,
                                controller,
                                &transaction.transaction_id,
                                Some(&root),
                                "staged_root_failed_integrity",
                            )
                            .await?;
                            continue;
                        }
                        Err(e) => {
                            return Err(format!(
                                "cannot verify pending transaction {}: {e}",
                                transaction.transaction_id
                            )
                            .into());
                        }
                    };
                    if manifest.object_id() != object.object_id
                        || manifest.total_size() != object.sealed_size
                    {
                        abort_recovery_object(
                            catalog,
                            controller,
                            &transaction.transaction_id,
                            Some(&root),
                            "staged_manifest_metadata_mismatch",
                        )
                        .await?;
                        continue;
                    }

                    controller
                        .ipfs_store()
                        .commit_staged(StagedObject {
                            root,
                            manifest,
                            backend: controller.ipfs_backend(),
                        })
                        .await?;
                    catalog.commit_upload(&transaction.transaction_id).await?;
                    recovered = recovered.saturating_add(1);
                }
                UploadState::Committed | UploadState::Aborted => {
                    // The query never returns terminal states. Keep the branch explicit
                    // so adding a new state cannot silently alter recovery semantics.
                }
            }
        }
    }

    Ok(recovered)
}

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
    todo_database::config::init_config_env()?;
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
    let catalog = Arc::new(match todo_database::objects::catalog_from_env().await? {
        Some(c) => {
            c.migrate().await?;
            c
        }
        None => {
            return Err(
                "production todo-web requires PostgreSQL object catalog (TODO_POSTGRES_URL)".into(),
            );
        }
    });
    let recovered = reconcile_upload_journal(&catalog, &controller).await?;

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
    println!("Object metadata: PostgreSQL (generation journal + owner-scoped downloads)");
    if recovered > 0 {
        println!("Recovered {recovered} interrupted object upload transaction(s)");
    }
    if !addr.ip().is_loopback() && tls.is_none() {
        eprintln!("warning: non-loopback bind without TLS; all traffic is unencrypted plaintext");
    }
    if let Some(w) = todo_rest::tls::plaintext_exposure_warning(addr, tls.is_some()) {
        eprintln!("{w}");
    }
    // Continue reconciliation while the service is alive. This covers an instance dying
    // while peers remain healthy: expired WRITING leases and deterministic PUBLISHING
    // records do not require a whole-cluster restart to make progress.
    {
        let recovery_catalog = Arc::clone(&catalog);
        let recovery_controller = Arc::clone(&controller);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(RECOVERY_INTERVAL);
            interval.tick().await; // initial reconciliation already completed above
            loop {
                interval.tick().await;
                match reconcile_upload_journal(&recovery_catalog, &recovery_controller).await {
                    Ok(0) => {}
                    Ok(count) => {
                        eprintln!(
                            "recovery: reconciled {count} interrupted object upload transaction(s)"
                        );
                    }
                    Err(e) => {
                        eprintln!("recovery: periodic object reconciliation failed: {e}");
                    }
                }
            }
        });
    }

    let app = WebApp::new(controller)
        .with_auth(auth)
        .with_catalog(catalog)
        .with_rukubo(rukubo);
    serve_with(listener, Arc::new(app), tls).await?;
    Ok(())
}
