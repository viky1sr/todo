//! IPFS blocks and the backend-independent block-store contract.

use crate::cid::{Cid, codec};
use crate::error::IpfsError;
use serde::{Deserialize, Serialize};
use std::future::Future;

/// Largest block this crate writes or accepts. IPFS implementations interoperate
/// reliably only for blocks up to 1 MiB (Bitswap's hard limit is 2 MiB).
pub const MAX_BLOCK_SIZE: usize = 1024 * 1024;

/// Default chunk size, equal to Kubo's default `size-262144` chunker.
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// A block whose bytes are known to hash to its CID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    cid: Cid,
    data: Vec<u8>,
}

impl Block {
    /// Build a sha2-256 CIDv1 block with `codec`.
    pub fn new(codec: u64, data: Vec<u8>) -> Result<Self, IpfsError> {
        check_size(data.len())?;
        Ok(Self {
            cid: Cid::sha2_256(codec, &data),
            data,
        })
    }

    pub fn raw(data: Vec<u8>) -> Result<Self, IpfsError> {
        Self::new(codec::RAW, data)
    }

    /// Accept untrusted bytes only if they hash to `cid`.
    pub fn verified(cid: Cid, data: Vec<u8>) -> Result<Self, IpfsError> {
        check_size(data.len())?;
        cid.verify(&data)?;
        Ok(Self { cid, data })
    }

    pub fn cid(&self) -> &Cid {
        &self.cid
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

fn check_size(size: usize) -> Result<(), IpfsError> {
    if size > MAX_BLOCK_SIZE {
        return Err(IpfsError::BlockTooLarge {
            size,
            limit: MAX_BLOCK_SIZE,
        });
    }
    Ok(())
}

/// Which kind of backend served a request. Results from [`BackendKind::Mock`] say
/// nothing about interoperability with real IPFS nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    /// In-process memory map (testing/benchmarks only).
    Mock,
    /// Live Kubo node via its HTTP RPC API.
    KuboRpc,
    /// Read-only trustless HTTP gateway.
    TrustlessGateway,
}

impl BackendKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Mock => "MOCK (in-memory, not IPFS)",
            Self::KuboRpc => "Kubo RPC (live IPFS)",
            Self::TrustlessGateway => "trustless gateway (live IPFS, read-only)",
        }
    }
}

/// Block storage backend. Backends are untrusted: [`BlockStore::get_block`] always
/// re-hashes the returned bytes, and `put_block` implementations must check the CID the
/// backend reports.
pub trait BlockStore: Send + Sync {
    fn kind(&self) -> BackendKind;

    /// Store `block`. Must be idempotent.
    fn put_block(&self, block: &Block) -> impl Future<Output = Result<(), IpfsError>> + Send;

    /// Fetch bytes for `cid` without verification. Returns [`IpfsError::NotFound`] if
    /// absent and must not return more than [`MAX_BLOCK_SIZE`] bytes.
    fn get_raw(&self, cid: &Cid) -> impl Future<Output = Result<Vec<u8>, IpfsError>> + Send;

    /// Whether the block is stored locally by the backend (no network fetch).
    fn has_block(&self, cid: &Cid) -> impl Future<Output = Result<bool, IpfsError>> + Send;

    /// Remove a (possibly corrupted) local copy so it can be rewritten.
    fn remove_block(&self, cid: &Cid) -> impl Future<Output = Result<(), IpfsError>> + Send;

    /// Pin `cid`; `recursive` also pins every block linked from it.
    fn pin(&self, cid: &Cid, recursive: bool)
    -> impl Future<Output = Result<(), IpfsError>> + Send;

    fn unpin(
        &self,
        cid: &Cid,
        recursive: bool,
    ) -> impl Future<Output = Result<(), IpfsError>> + Send;

    /// Fetch and verify a block against its CID.
    fn get_block(&self, cid: &Cid) -> impl Future<Output = Result<Block, IpfsError>> + Send {
        async move {
            let data = self.get_raw(cid).await?;
            Block::verified(cid.clone(), data)
        }
    }
}
