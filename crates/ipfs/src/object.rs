//! Chunked objects: raw blocks + a DAG-JSON manifest whose CID is the object root.

use crate::block::{BackendKind, Block, BlockStore, DEFAULT_CHUNK_SIZE, MAX_BLOCK_SIZE};
use crate::cid::{Cid, codec};
use crate::error::IpfsError;
use crate::manifest::{BlockLink, ObjectManifest, validate_object_id};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Default bound on object size for reads and writes (1 GiB).
pub const DEFAULT_MAX_OBJECT_SIZE: u64 = 1 << 30;

/// Blocks hashed and stored per batch in [`ObjectStore::put_object`] (4 MiB at the
/// default chunk size).
pub const PUT_BATCH_BLOCKS: usize = 16;

/// Object whose blocks and root manifest exist in the backend but are not recursively
/// pinned yet. This is the durability boundary used by the production upload journal:
/// persist `root` + metadata first, then call [`ObjectStore::commit_staged`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedObject {
    pub root: Cid,
    pub manifest: ObjectManifest,
    pub backend: BackendKind,
}

/// Result of publishing an object. `root` is the trust anchor callers must keep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedObject {
    pub root: Cid,
    pub manifest: ObjectManifest,
    pub backend: BackendKind,
}

pub struct ObjectStore<S> {
    store: S,
    chunk_size: usize,
    max_object_size: u64,
}

impl<S: BlockStore> ObjectStore<S> {
    pub fn new(store: S) -> Self {
        Self {
            store,
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_object_size: DEFAULT_MAX_OBJECT_SIZE,
        }
    }

    pub fn with_chunk_size(mut self, chunk_size: usize) -> Result<Self, IpfsError> {
        if chunk_size == 0 || chunk_size > MAX_BLOCK_SIZE {
            return Err(IpfsError::BlockTooLarge {
                size: chunk_size,
                limit: MAX_BLOCK_SIZE,
            });
        }
        self.chunk_size = chunk_size;
        Ok(self)
    }

    pub fn with_max_object_size(mut self, limit: u64) -> Self {
        self.max_object_size = limit;
        self
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    pub fn max_object_size(&self) -> u64 {
        self.max_object_size
    }

    /// Chunk, hash and store an object plus its root manifest, but do **not** recursively
    /// pin the root yet. Unpinned blocks are staging data and remain GC-eligible.
    ///
    /// Production callers should durably journal [`StagedObject::root`] and the public
    /// sealed-object metadata before [`Self::commit_staged`]. This ordering closes the
    /// crash window between an IPFS pin and the PostgreSQL metadata commit.
    pub async fn stage_object<D>(
        &self,
        object_id: &str,
        data: D,
    ) -> Result<StagedObject, IpfsError>
    where
        D: AsRef<[u8]> + Send + Sync + 'static,
    {
        validate_object_id(object_id)?;
        let size = data.as_ref().len() as u64;
        if size > self.max_object_size {
            return Err(IpfsError::ObjectTooLarge {
                size,
                limit: self.max_object_size,
            });
        }
        let chunk_size = self.chunk_size;
        let data = Arc::new(data);
        let chunks = (*data).as_ref().len().div_ceil(chunk_size);
        let mut links = Vec::with_capacity(chunks);
        for first in (0..chunks).step_by(PUT_BATCH_BLOCKS) {
            let data = Arc::clone(&data);
            // Hashing is CPU work; keep it off the async executor.
            let blocks = tokio::task::spawn_blocking(move || {
                let bytes: &[u8] = (*data).as_ref();
                bytes
                    .chunks(chunk_size)
                    .skip(first)
                    .take(PUT_BATCH_BLOCKS)
                    .map(|c| Block::raw(c.to_vec()))
                    .collect::<Result<Vec<_>, _>>()
            })
            .await
            .map_err(|e| IpfsError::Internal(e.to_string()))??;
            for block in &blocks {
                self.store.put_block(block).await?;
                links.push(BlockLink {
                    cid: block.cid().clone(),
                    size: block.data().len() as u64,
                });
            }
        }
        let manifest = ObjectManifest::new(object_id, links)?;
        let root_block = manifest.to_block()?;
        self.store.put_block(&root_block).await?;

        Ok(StagedObject {
            root: root_block.cid().clone(),
            manifest,
            backend: self.store.kind(),
        })
    }

    /// Atomically publish a staged root according to the backend's recursive-pin
    /// semantics. The operation is idempotent for content-addressed backends.
    pub async fn commit_staged(
        &self,
        staged: StagedObject,
    ) -> Result<PublishedObject, IpfsError> {
        // Re-read the complete DAG before making it durable/visible. `write_object_to`
        // verifies the root CID, every child CID and every declared child size while
        // streaming into a sink, so a missing/corrupt staged chunk cannot be pinned as
        // a committed object. The sealed bytes are never materialized here.
        let mut sink = tokio::io::sink();
        let manifest = self.write_object_to(&staged.root, &mut sink).await?;
        if manifest != staged.manifest {
            return Err(IpfsError::InvalidManifest(
                "staged root manifest changed before commit".into(),
            ));
        }
        self.store.pin(&staged.root, true).await?;
        Ok(PublishedObject {
            root: staged.root,
            manifest,
            backend: staged.backend,
        })
    }

    /// Convenience path for non-journal callers: stage and immediately commit.
    pub async fn put_object<D>(
        &self,
        object_id: &str,
        data: D,
    ) -> Result<PublishedObject, IpfsError>
    where
        D: AsRef<[u8]> + Send + Sync + 'static,
    {
        let staged = self.stage_object(object_id, data).await?;
        self.commit_staged(staged).await
    }

    /// Fetch and verify the manifest for a trusted `root`.
    pub async fn get_manifest(&self, root: &Cid) -> Result<ObjectManifest, IpfsError> {
        fetch_manifest(&self.store, root, self.max_object_size).await
    }

    /// Fetch an object by trusted root CID. Every block is verified against its CID and
    /// declared size before the bytes are returned.
    pub async fn get_object(&self, root: &Cid) -> Result<(ObjectManifest, Vec<u8>), IpfsError> {
        let mut data = Vec::new();
        let manifest = self.write_object_to(root, &mut data).await?;
        Ok((manifest, data))
    }

    /// Like [`Self::get_object`], but writes the verified blocks to `out` one at a time
    /// (e.g. a temporary file), so only one block is held in memory. On error, `out` may
    /// contain a verified prefix of the object and must be discarded.
    pub async fn write_object_to<W>(
        &self,
        root: &Cid,
        out: &mut W,
    ) -> Result<ObjectManifest, IpfsError>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;
        let manifest = self.get_manifest(root).await?;
        for link in manifest.blocks() {
            let block = self.store.get_block(&link.cid).await?;
            if block.data().len() as u64 != link.size {
                return Err(IpfsError::InvalidManifest(format!(
                    "chunk {} is {} B, manifest declares {} B",
                    link.cid,
                    block.data().len(),
                    link.size
                )));
            }
            out.write_all(block.data())
                .await
                .map_err(|e| IpfsError::Internal(format!("write: {e}")))?;
        }
        out.flush()
            .await
            .map_err(|e| IpfsError::Internal(format!("write: {e}")))?;
        Ok(manifest)
    }

    /// Remove the recursive pin on `root` (blocks become eligible for GC on real nodes).
    pub async fn unpin_object(&self, root: &Cid) -> Result<(), IpfsError> {
        self.store.unpin(root, true).await
    }
}

pub(crate) async fn fetch_manifest<S: BlockStore>(
    store: &S,
    root: &Cid,
    max_object_size: u64,
) -> Result<ObjectManifest, IpfsError> {
    if root.codec() != codec::DAG_JSON {
        return Err(IpfsError::InvalidManifest(format!(
            "root {root} is not a DAG-JSON manifest"
        )));
    }
    let manifest = ObjectManifest::decode(&store.get_block(root).await?)?;
    check_object_size(&manifest, max_object_size)?;
    Ok(manifest)
}

pub(crate) fn check_object_size(manifest: &ObjectManifest, limit: u64) -> Result<(), IpfsError> {
    if manifest.total_size() > limit {
        return Err(IpfsError::ObjectTooLarge {
            size: manifest.total_size(),
            limit,
        });
    }
    Ok(())
}
