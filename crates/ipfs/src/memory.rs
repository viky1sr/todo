//! In-memory [`BlockStore`] for tests and benchmarks. It computes real CIDs, but it is
//! **not** an IPFS node: no networking, no interoperability evidence.

use crate::block::{BackendKind, Block, BlockStore};
use crate::cid::{Cid, codec};
use crate::error::IpfsError;
use crate::manifest::ObjectManifest;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Default)]
struct State {
    blocks: HashMap<Cid, Vec<u8>>,
    pins: HashSet<(Cid, bool)>,
    offline: bool,
}

/// Cloning shares the same storage.
#[derive(Clone, Default)]
pub struct MemoryBlockStore {
    state: Arc<RwLock<State>>,
}

impl MemoryBlockStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn len(&self) -> usize {
        self.state.read().await.blocks.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    pub async fn is_pinned(&self, cid: &Cid, recursive: bool) -> bool {
        self.state
            .read()
            .await
            .pins
            .contains(&(cid.to_v1(), recursive))
    }

    /// Fault injection: overwrite the stored bytes for `cid` without changing its key.
    pub async fn tamper_block(&self, cid: &Cid, data: Vec<u8>) {
        self.state.write().await.blocks.insert(cid.to_v1(), data);
    }

    /// Fault injection: drop a block.
    pub async fn drop_block(&self, cid: &Cid) {
        self.state.write().await.blocks.remove(&cid.to_v1());
    }

    /// Fault injection: make every operation fail with a transport error.
    pub async fn set_offline(&self, offline: bool) {
        self.state.write().await.offline = offline;
    }

    async fn check_online(&self) -> Result<(), IpfsError> {
        if self.state.read().await.offline {
            return Err(IpfsError::Transport("mock store is offline".into()));
        }
        Ok(())
    }
}

impl BlockStore for MemoryBlockStore {
    fn kind(&self) -> BackendKind {
        BackendKind::Mock
    }

    async fn put_block(&self, block: &Block) -> Result<(), IpfsError> {
        self.check_online().await?;
        self.state
            .write()
            .await
            .blocks
            .insert(block.cid().to_v1(), block.data().to_vec());
        Ok(())
    }

    async fn get_raw(&self, cid: &Cid) -> Result<Vec<u8>, IpfsError> {
        self.check_online().await?;
        self.state
            .read()
            .await
            .blocks
            .get(&cid.to_v1())
            .cloned()
            .ok_or_else(|| IpfsError::NotFound(cid.clone()))
    }

    async fn has_block(&self, cid: &Cid) -> Result<bool, IpfsError> {
        self.check_online().await?;
        Ok(self.state.read().await.blocks.contains_key(&cid.to_v1()))
    }

    async fn remove_block(&self, cid: &Cid) -> Result<(), IpfsError> {
        self.check_online().await?;
        self.state.write().await.blocks.remove(&cid.to_v1());
        Ok(())
    }

    /// Like Kubo, a recursive pin requires the whole DAG to be present and valid. Only
    /// this crate's DAG-JSON manifests are traversed.
    async fn pin(&self, cid: &Cid, recursive: bool) -> Result<(), IpfsError> {
        let root = self.get_block(cid).await?;
        if recursive && cid.codec() == codec::DAG_JSON {
            let manifest = ObjectManifest::decode(&root)?;
            for link in manifest.blocks() {
                self.get_block(&link.cid).await?;
            }
        }
        self.state
            .write()
            .await
            .pins
            .insert((cid.to_v1(), recursive));
        Ok(())
    }

    async fn unpin(&self, cid: &Cid, recursive: bool) -> Result<(), IpfsError> {
        self.check_online().await?;
        self.state
            .write()
            .await
            .pins
            .remove(&(cid.to_v1(), recursive));
        Ok(())
    }
}
