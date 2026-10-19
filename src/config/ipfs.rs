//! IPFS backend selection (`TODO_IPFS_BACKEND`, `TODO_IPFS_URL`).

use std::fmt;

use super::{ConfigError, Lookup, plain, reject_url_password};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpfsKind {
    /// In-process memory map: not IPFS, lost on restart.
    Mock,
    /// Live Kubo node, HTTP RPC API.
    Kubo,
    /// Read-only trustless HTTP gateway.
    Gateway,
}

impl IpfsKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::Kubo => "kubo",
            Self::Gateway => "gateway",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpfsConfig {
    pub kind: IpfsKind,
    pub url: Option<String>,
}

impl IpfsConfig {
    pub(super) fn load(env: Lookup<'_>) -> Result<Self, ConfigError> {
        let kind = match plain(env, "TODO_IPFS_BACKEND").as_deref() {
            None | Some("mock") => IpfsKind::Mock,
            Some("kubo") => IpfsKind::Kubo,
            Some("gateway") => IpfsKind::Gateway,
            Some(_) => {
                return Err(ConfigError(
                    "TODO_IPFS_BACKEND must be mock, kubo or gateway".into(),
                ));
            }
        };
        let url = plain(env, "TODO_IPFS_URL");
        if let Some(u) = &url {
            if !(u.starts_with("http://") || u.starts_with("https://")) {
                return Err(ConfigError("TODO_IPFS_URL must be http(s)://...".into()));
            }
            reject_url_password("TODO_IPFS_URL", u)?;
        }
        if kind == IpfsKind::Gateway && url.is_none() {
            return Err(ConfigError(
                "TODO_IPFS_BACKEND=gateway requires TODO_IPFS_URL".into(),
            ));
        }
        let config = Self { kind, url };
        config
            .backend()
            .map_err(|e| ConfigError(format!("TODO_IPFS_URL: {e}")))?;
        Ok(config)
    }

    /// The `todo-ipfs` backend (no network access happens here).
    pub fn backend(&self) -> Result<todo_ipfs::IpfsBackend, todo_ipfs::IpfsError> {
        todo_ipfs::IpfsBackend::from_config(self.kind.as_str(), self.url.as_deref())
    }
}

impl fmt::Display for IpfsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.kind, &self.url) {
            (IpfsKind::Mock, _) => f.write_str("mock (in-memory, NOT IPFS)"),
            (IpfsKind::Kubo, None) => {
                write!(f, "kubo {} (default)", todo_ipfs::kubo::DEFAULT_KUBO_API)
            }
            (k, Some(u)) => write!(f, "{} {u}", k.as_str()),
            (k, None) => f.write_str(k.as_str()),
        }
    }
}
