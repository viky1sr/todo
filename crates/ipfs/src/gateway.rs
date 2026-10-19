//! Read-only backend: an IPFS HTTP gateway in trustless mode
//! (https://specs.ipfs.tech/http-gateways/trustless-gateway/), i.e.
//! `GET /ipfs/{cid}?format=raw` with `Accept: application/vnd.ipld.raw`.
//!
//! The gateway is not trusted: every block is re-hashed by [`BlockStore::get_block`].

use crate::block::{BackendKind, Block, BlockStore, MAX_BLOCK_SIZE};
use crate::cid::Cid;
use crate::error::IpfsError;
use crate::http::{error_message, normalize_base_url, read_limited, transport};
use std::time::Duration;

const RAW_BLOCK_MIME: &str = "application/vnd.ipld.raw";

#[derive(Clone)]
pub struct TrustlessGateway {
    http: reqwest::Client,
    base: String,
}

impl TrustlessGateway {
    /// `base` is the gateway origin, e.g. `http://127.0.0.1:8080` or `https://ipfs.io`.
    pub fn new(base: &str) -> Result<Self, IpfsError> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(transport)?;
        Ok(Self {
            http,
            base: normalize_base_url(base)?,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    fn url(&self, cid: &Cid) -> String {
        format!("{}/ipfs/{cid}?format=raw", self.base)
    }
}

impl BlockStore for TrustlessGateway {
    fn kind(&self) -> BackendKind {
        BackendKind::TrustlessGateway
    }

    async fn put_block(&self, _block: &Block) -> Result<(), IpfsError> {
        Err(IpfsError::Unsupported("put on a read-only gateway"))
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Vec<u8>, IpfsError> {
        let resp = self
            .http
            .get(self.url(cid))
            .header(reqwest::header::ACCEPT, RAW_BLOCK_MIME)
            .send()
            .await
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => read_limited(resp, MAX_BLOCK_SIZE).await,
            404 => Err(IpfsError::NotFound(cid.clone())),
            status => Err(IpfsError::Backend {
                status,
                message: error_message(resp).await,
            }),
        }
    }

    /// Whether the gateway can serve the block (it may fetch it from the network).
    async fn has_block(&self, cid: &Cid) -> Result<bool, IpfsError> {
        let resp = self
            .http
            .head(self.url(cid))
            .header(reqwest::header::ACCEPT, RAW_BLOCK_MIME)
            .send()
            .await
            .map_err(transport)?;
        match resp.status().as_u16() {
            200 => Ok(true),
            404 => Ok(false),
            status => Err(IpfsError::Backend {
                status,
                message: "HEAD request failed".into(),
            }),
        }
    }

    async fn remove_block(&self, _cid: &Cid) -> Result<(), IpfsError> {
        Err(IpfsError::Unsupported("remove on a read-only gateway"))
    }

    async fn pin(&self, _cid: &Cid, _recursive: bool) -> Result<(), IpfsError> {
        Err(IpfsError::Unsupported("pin on a read-only gateway"))
    }

    async fn unpin(&self, _cid: &Cid, _recursive: bool) -> Result<(), IpfsError> {
        Err(IpfsError::Unsupported("unpin on a read-only gateway"))
    }
}
