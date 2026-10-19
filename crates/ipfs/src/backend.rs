//! One enum over all backends, so heterogeneous replicas share a type.

use crate::block::{BackendKind, Block, BlockStore};
use crate::cid::Cid;
use crate::error::IpfsError;
use crate::gateway::TrustlessGateway;
use crate::kubo::KuboRpcClient;
use crate::memory::MemoryBlockStore;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

#[derive(Clone)]
pub enum IpfsBackend {
    Mock(MemoryBlockStore),
    Kubo(KuboRpcClient),
    Gateway(TrustlessGateway),
}

impl IpfsBackend {
    pub fn mock() -> Self {
        Self::Mock(MemoryBlockStore::new())
    }

    /// Build from a backend name (`mock`, `kubo`, `gateway`) and an optional URL.
    pub fn from_config(kind: &str, url: Option<&str>) -> Result<Self, IpfsError> {
        match kind {
            "mock" => Ok(Self::mock()),
            "kubo" => Ok(Self::Kubo(KuboRpcClient::new(
                url.unwrap_or(crate::kubo::DEFAULT_KUBO_API),
            )?)),
            "gateway" => Ok(Self::Gateway(TrustlessGateway::new(url.ok_or_else(
                || IpfsError::Transport("gateway backend requires a URL".into()),
            )?)?)),
            other => Err(IpfsError::Transport(format!(
                "unknown IPFS backend {other:?} (expected mock, kubo or gateway)"
            ))),
        }
    }

    /// Read `TODO_IPFS_BACKEND` (default `mock`) and `TODO_IPFS_URL`.
    pub fn from_env() -> Result<Self, IpfsError> {
        let kind = std::env::var("TODO_IPFS_BACKEND").unwrap_or_else(|_| "mock".into());
        let url = std::env::var("TODO_IPFS_URL").ok();
        if kind == "kubo" {
            return Self::kubo_from_env(url.as_deref());
        }
        Self::from_config(&kind, url.as_deref())
    }

    fn kubo_from_env(url: Option<&str>) -> Result<Self, IpfsError> {
        let url = url.unwrap_or(crate::kubo::DEFAULT_KUBO_API);
        let production = matches!(
            std::env::var("TODO_ENV").as_deref(),
            Ok("production" | "prod")
        );
        let remote = private_kubo_endpoint(url, production)?;
        let authorization = read_rpc_authorization()?;
        if production && remote {
            if !url.starts_with("https://") {
                return Err(IpfsError::Transport(
                    "production Kubo RPC on LAN/Wi-Fi must use https; use loopback for a local node".into(),
                ));
            }
            if authorization.is_none() {
                return Err(IpfsError::Transport(
                    "production Kubo RPC on LAN/Wi-Fi requires TODO_IPFS_RPC_AUTHORIZATION_FILE"
                        .into(),
                ));
            }
        }
        let local_only = match std::env::var("TODO_IPFS_LOCAL_ONLY") {
            Ok(value) => match value.trim() {
                "true" | "1" => true,
                "false" | "0" => false,
                _ => {
                    return Err(IpfsError::Transport(
                        "TODO_IPFS_LOCAL_ONLY must be true or false".into(),
                    ));
                }
            },
            Err(_) => true,
        };
        let mut client = KuboRpcClient::new(url)?.with_local_only(local_only);
        if let Some(value) = authorization {
            client = client.with_authorization(value);
        }
        Ok(Self::Kubo(client))
    }
}

/// True for a private LAN/Wi-Fi endpoint, false for loopback. In production public
/// addresses and hostnames are rejected: DNS cannot prove that an arbitrary name stays
/// on a private network.
fn private_kubo_endpoint(url: &str, production: bool) -> Result<bool, IpfsError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| IpfsError::Transport(format!("invalid Kubo RPC URL: {e}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| IpfsError::Transport("Kubo RPC URL has no host".into()))?;
    let host = host.trim_matches(['[', ']']);
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    if loopback || !production {
        return Ok(!loopback);
    }
    let private = host.parse::<IpAddr>().is_ok_and(is_private_lan_ip);
    if !private {
        return Err(IpfsError::Transport(
            "production Kubo RPC must use a loopback or literal private LAN/Wi-Fi IP address"
                .into(),
        ));
    }
    Ok(true)
}

fn is_private_lan_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_link_local()
                || ip == Ipv4Addr::new(100, 64, 0, 0)
                || (ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
        }
        IpAddr::V6(ip) => {
            ip.is_unique_local() || ip.is_unicast_link_local() || ip == Ipv6Addr::LOCALHOST
        }
    }
}

/// An HTTP Authorization header value for a TLS-terminating private RPC proxy. It is
/// deliberately file-only: process environments expose secrets through container and
/// process inspection. Kubo itself must stay on loopback behind that proxy.
fn read_rpc_authorization() -> Result<Option<String>, IpfsError> {
    let Ok(path) = std::env::var("TODO_IPFS_RPC_AUTHORIZATION_FILE") else {
        return Ok(None);
    };
    let path = Path::new(&path);
    let meta = std::fs::metadata(path)
        .map_err(|_| IpfsError::Transport("cannot read TODO_IPFS_RPC_AUTHORIZATION_FILE".into()))?;
    if !meta.is_file() || meta.len() > 4096 {
        return Err(IpfsError::Transport(
            "TODO_IPFS_RPC_AUTHORIZATION_FILE must be a regular file no larger than 4 KiB".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(IpfsError::Transport(
                "TODO_IPFS_RPC_AUTHORIZATION_FILE must be owner-only (chmod 400 or 600)".into(),
            ));
        }
    }
    let value = std::fs::read_to_string(path)
        .map_err(|_| IpfsError::Transport("cannot read TODO_IPFS_RPC_AUTHORIZATION_FILE".into()))?;
    let value = value.trim();
    if value.is_empty() || value.contains('\r') || value.contains('\n') {
        return Err(IpfsError::Transport(
            "TODO_IPFS_RPC_AUTHORIZATION_FILE must contain one non-empty header value".into(),
        ));
    }
    Ok(Some(value.to_owned()))
}

macro_rules! delegate {
    ($self:ident, $s:ident => $call:expr) => {
        match $self {
            IpfsBackend::Mock($s) => $call,
            IpfsBackend::Kubo($s) => $call,
            IpfsBackend::Gateway($s) => $call,
        }
    };
}

impl BlockStore for IpfsBackend {
    fn kind(&self) -> BackendKind {
        delegate!(self, s => s.kind())
    }

    async fn put_block(&self, block: &Block) -> Result<(), IpfsError> {
        delegate!(self, s => s.put_block(block).await)
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Vec<u8>, IpfsError> {
        delegate!(self, s => s.get_raw(cid).await)
    }

    async fn has_block(&self, cid: &Cid) -> Result<bool, IpfsError> {
        delegate!(self, s => s.has_block(cid).await)
    }

    async fn remove_block(&self, cid: &Cid) -> Result<(), IpfsError> {
        delegate!(self, s => s.remove_block(cid).await)
    }

    async fn pin(&self, cid: &Cid, recursive: bool) -> Result<(), IpfsError> {
        delegate!(self, s => s.pin(cid, recursive).await)
    }

    async fn unpin(&self, cid: &Cid, recursive: bool) -> Result<(), IpfsError> {
        delegate!(self, s => s.unpin(cid, recursive).await)
    }
}

#[cfg(test)]
mod tests {
    use super::private_kubo_endpoint;

    #[test]
    fn production_kubo_endpoint_is_loopback_or_private_ip() {
        assert!(!private_kubo_endpoint("http://127.0.0.1:5001", true).unwrap());
        assert!(private_kubo_endpoint("https://192.168.1.20:5443", true).unwrap());
        assert!(private_kubo_endpoint("https://[fd12::20]:5443", true).unwrap());
        assert!(private_kubo_endpoint("https://198.51.100.10:5443", true).is_err());
        assert!(private_kubo_endpoint("https://kubo.example:5443", true).is_err());
    }

    #[test]
    fn development_can_use_an_explicit_remote_endpoint() {
        assert!(private_kubo_endpoint("http://kubo.test:5001", false).unwrap());
    }
}
