//! Optional in-process TLS for todo-rest and todo-web (rustls, aws-lc-rs provider — the
//! same provider `reqwest` already uses for the IPFS client).
//!
//! Only TLS 1.3 is offered (`ServerConfig` is built with `TLS13` as the sole protocol
//! version, so TLS 1.2 clients fail the handshake), ALPN `http/1.1`, no client
//! certificates. Certificate chain and private key are PEM files given by
//! `TODO_TLS_CERT` / `TODO_TLS_KEY`; both or neither must be set.
//!
//! TLS protects the request (plaintext upload, bearer token) on the wire; it does not
//! change the AEAD format, which still protects data at rest.

use crate::RestError;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
pub use tokio_rustls::TlsAcceptor;

/// Bound on the TLS handshake of one connection (slow or silent clients are dropped).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// TLS 1.3-only server configuration from PEM files. Error messages name the file but
/// never include key material.
pub fn server_config(cert_pem: &Path, key_pem: &Path) -> Result<Arc<ServerConfig>, RestError> {
    let bad = |what: &str, path: &Path, e: &dyn std::fmt::Display| {
        RestError::BadRequest(format!("TLS {what} {}: {e}", path.display()))
    };
    let certs = CertificateDer::pem_file_iter(cert_pem)
        .map_err(|e| bad("certificate file", cert_pem, &e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| bad("certificate file", cert_pem, &e))?;
    if certs.is_empty() {
        return Err(bad("certificate file", cert_pem, &"no CERTIFICATE block"));
    }
    warn_if_key_readable_by_others(key_pem);
    let key =
        PrivateKeyDer::from_pem_file(key_pem).map_err(|e| bad("private key file", key_pem, &e))?;

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| RestError::BadRequest(format!("TLS configuration: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| RestError::BadRequest(format!("TLS certificate/key: {e}")))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub fn acceptor(cert_pem: &Path, key_pem: &Path) -> Result<TlsAcceptor, RestError> {
    Ok(TlsAcceptor::from(server_config(cert_pem, key_pem)?))
}

/// `None` when neither `TODO_TLS_CERT` nor `TODO_TLS_KEY` is set (plain HTTP).
pub fn acceptor_from_env() -> Result<Option<TlsAcceptor>, RestError> {
    match (
        std::env::var_os("TODO_TLS_CERT"),
        std::env::var_os("TODO_TLS_KEY"),
    ) {
        (None, None) => Ok(None),
        (Some(cert), Some(key)) => acceptor(Path::new(&cert), Path::new(&key)).map(Some),
        _ => Err(RestError::BadRequest(
            "set both TODO_TLS_CERT and TODO_TLS_KEY (PEM files) or neither".into(),
        )),
    }
}

/// Startup warning for deployments that expose plaintext HTTP beyond loopback.
pub fn plaintext_exposure_warning(addr: std::net::SocketAddr, tls: bool) -> Option<&'static str> {
    (!tls && !addr.ip().is_loopback()).then_some(
        "warning: plain HTTP on a non-loopback address; uploads, downloads and the bearer \
token cross the network unencrypted (set TODO_TLS_CERT/TODO_TLS_KEY or terminate TLS at a \
reverse proxy)",
    )
}

#[cfg(unix)]
fn warn_if_key_readable_by_others(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path)
        && meta.permissions().mode() & 0o077 != 0
    {
        eprintln!(
            "warning: TLS private key {} is accessible by group/others (chmod 600)",
            path.display()
        );
    }
}

#[cfg(not(unix))]
fn warn_if_key_readable_by_others(_: &Path) {}
