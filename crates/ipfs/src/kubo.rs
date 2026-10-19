//! Live backend: a Kubo node via its HTTP RPC API
//! (https://docs.ipfs.tech/reference/kubo/rpc/).
//!
//! Endpoints used (all `POST`): `version`, `id`, `block/put`, `block/get`, `block/stat`,
//! `block/rm`, `pin/add`, `pin/rm`. The RPC API grants full node control: expose it only
//! on loopback or behind authentication (`API.Authorizations`), never publicly.
//!
//! Blocks written to a node connected to the public network are announced and can be
//! fetched by anyone who knows the CID. Store ciphertext only; sizes and CIDs leak.

use crate::block::{BackendKind, Block, BlockStore, MAX_BLOCK_SIZE};
use crate::cid::{Cid, codec};
use crate::error::IpfsError;
use crate::http::{MAX_RPC_RESPONSE, error_message, normalize_base_url, read_limited, transport};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const DEFAULT_KUBO_API: &str = "http://127.0.0.1:5001";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    pub peer_id: String,
    pub agent_version: String,
}

#[derive(Clone)]
pub struct KuboRpcClient {
    http: reqwest::Client,
    base: String,
    authorization: Option<String>,
    local_only: bool,
}

impl KuboRpcClient {
    /// `base` is the RPC API root, e.g. [`DEFAULT_KUBO_API`].
    pub fn new(base: &str) -> Result<Self, IpfsError> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(transport)?;
        Ok(Self {
            http,
            base: normalize_base_url(base)?,
            authorization: None,
            local_only: true,
        })
    }

    /// Value for the `Authorization` header (e.g. `Bearer <token>`), matching the node's
    /// `API.Authorizations` config. Never logged.
    pub fn with_authorization(mut self, value: impl Into<String>) -> Self {
        self.authorization = Some(value.into());
        self
    }

    /// When `true` (default) reads are answered from the node's local blockstore only
    /// (`offline=true`), which is what replica audits need. When `false` the node may
    /// fetch missing blocks from the IPFS network.
    pub fn with_local_only(mut self, local_only: bool) -> Self {
        self.local_only = local_only;
        self
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    fn request(&self, path: &str, query: &[(&str, String)]) -> reqwest::RequestBuilder {
        let mut req = self
            .http
            .post(format!("{}/api/v0/{path}", self.base))
            .query(query);
        if let Some(auth) = &self.authorization {
            req = req.header(reqwest::header::AUTHORIZATION, auth);
        }
        req
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<reqwest::Response, IpfsError> {
        let resp = req.send().await.map_err(transport)?;
        if resp.status().is_success() {
            return Ok(resp);
        }
        let status = resp.status().as_u16();
        Err(IpfsError::Backend {
            status,
            message: error_message(resp).await,
        })
    }

    async fn call_json(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<serde_json::Value, IpfsError> {
        let resp = self.send(self.request(path, query)).await?;
        let body = read_limited(resp, MAX_RPC_RESPONSE).await?;
        // Some endpoints stream newline-delimited JSON; the last object is the result.
        let last = body
            .split(|&b| b == b'\n')
            .rfind(|line| !line.iter().all(u8::is_ascii_whitespace))
            .unwrap_or(&[]);
        serde_json::from_slice(last)
            .map_err(|e| IpfsError::Transport(format!("invalid RPC response: {e}")))
    }

    fn offline_flag(&self) -> Vec<(&'static str, String)> {
        if self.local_only {
            vec![("offline", "true".into())]
        } else {
            Vec::new()
        }
    }

    pub async fn version(&self) -> Result<String, IpfsError> {
        let v = self.call_json("version", &[]).await?;
        Ok(v["Version"].as_str().unwrap_or_default().to_string())
    }

    pub async fn node_info(&self) -> Result<NodeInfo, IpfsError> {
        let v = self.call_json("id", &[]).await?;
        Ok(NodeInfo {
            peer_id: v["ID"].as_str().unwrap_or_default().to_string(),
            agent_version: v["AgentVersion"].as_str().unwrap_or_default().to_string(),
        })
    }
}

fn is_not_found(err: &IpfsError) -> bool {
    matches!(err, IpfsError::Backend { message, .. }
        if message.contains("not found") || message.contains("could not find"))
}

impl BlockStore for KuboRpcClient {
    fn kind(&self) -> BackendKind {
        BackendKind::KuboRpc
    }

    async fn put_block(&self, block: &Block) -> Result<(), IpfsError> {
        let codec_name = codec::name(block.cid().codec())
            .ok_or(IpfsError::Unsupported("block/put with this codec"))?;
        let part = reqwest::multipart::Part::bytes(block.data().to_vec()).file_name("block");
        let form = reqwest::multipart::Form::new().part("file", part);
        let query = [
            ("cid-codec", codec_name.to_string()),
            ("mhtype", "sha2-256".into()),
            ("mhlen", "32".into()),
            ("pin", "false".into()),
        ];
        let v = self.call_json_multipart("block/put", &query, form).await?;
        let actual: Cid = v["Key"]
            .as_str()
            .ok_or_else(|| IpfsError::Transport("block/put: missing Key".into()))?
            .parse()?;
        if actual.to_v1() != block.cid().to_v1() {
            return Err(IpfsError::CidMismatch {
                expected: block.cid().clone(),
                actual,
            });
        }
        Ok(())
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Vec<u8>, IpfsError> {
        let mut query = vec![("arg", cid.to_string())];
        query.extend(self.offline_flag());
        match self.send(self.request("block/get", &query)).await {
            Ok(resp) => read_limited(resp, MAX_BLOCK_SIZE).await,
            Err(e) if is_not_found(&e) => Err(IpfsError::NotFound(cid.clone())),
            Err(e) => Err(e),
        }
    }

    async fn has_block(&self, cid: &Cid) -> Result<bool, IpfsError> {
        let query = [("arg", cid.to_string()), ("offline", "true".into())];
        match self.call_json("block/stat", &query).await {
            Ok(_) => Ok(true),
            Err(e) if is_not_found(&e) => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn remove_block(&self, cid: &Cid) -> Result<(), IpfsError> {
        let query = [("arg", cid.to_string()), ("force", "true".into())];
        let v = self.call_json("block/rm", &query).await?;
        match v["Error"].as_str() {
            Some(msg) if !msg.is_empty() => Err(IpfsError::Backend {
                status: 200,
                message: msg.to_string(),
            }),
            _ => Ok(()),
        }
    }

    async fn pin(&self, cid: &Cid, recursive: bool) -> Result<(), IpfsError> {
        let query = [
            ("arg", cid.to_string()),
            ("recursive", recursive.to_string()),
        ];
        self.call_json("pin/add", &query).await.map(drop)
    }

    async fn unpin(&self, cid: &Cid, recursive: bool) -> Result<(), IpfsError> {
        let query = [
            ("arg", cid.to_string()),
            ("recursive", recursive.to_string()),
        ];
        self.call_json("pin/rm", &query).await.map(drop)
    }
}

impl KuboRpcClient {
    async fn call_json_multipart(
        &self,
        path: &str,
        query: &[(&str, String)],
        form: reqwest::multipart::Form,
    ) -> Result<serde_json::Value, IpfsError> {
        let resp = self.send(self.request(path, query).multipart(form)).await?;
        let body = read_limited(resp, MAX_RPC_RESPONSE).await?;
        serde_json::from_slice(&body)
            .map_err(|e| IpfsError::Transport(format!("invalid RPC response: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_base_urls() {
        assert!(KuboRpcClient::new("ftp://127.0.0.1:5001").is_err());
        assert!(KuboRpcClient::new("not a url").is_err());
        assert!(KuboRpcClient::new("http://127.0.0.1:5001/?x=1").is_err());
        let c = KuboRpcClient::new("http://127.0.0.1:5001/").unwrap();
        assert_eq!(c.base_url(), "http://127.0.0.1:5001");
    }
}
