//! Replica audit and repair for objects addressed by a trusted root CID.
//!
//! Repair copies **byte-identical** blocks: a block is written to a replica only after
//! it was fetched from another replica and re-hashed against its CID, and the write is
//! accepted only after reading it back and verifying it again. Nothing is re-encrypted
//! or re-chunked, so the root CID never changes. The root CID is the trust anchor; this
//! module does not authenticate who published it.

use crate::block::{BackendKind, Block, BlockStore};
use crate::cid::Cid;
use crate::error::IpfsError;
use crate::object::{DEFAULT_MAX_OBJECT_SIZE, fetch_manifest};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockStatus {
    Healthy,
    Missing,
    /// Bytes present but they do not hash to the CID (or exceed the block limit).
    Corrupted,
    /// The replica could not be queried.
    Unreachable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectHealth {
    /// Every replica holds every block.
    Healthy,
    /// Every block has at least one healthy copy, but some replica is missing data.
    Degraded,
    /// Some block (or the manifest) has no verifiable copy anywhere.
    Unrecoverable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaAudit {
    pub replica: String,
    pub backend: BackendKind,
    /// Aligned with [`AuditReport::cids`].
    pub blocks: Vec<BlockStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReport {
    pub root: Cid,
    /// Root (manifest) first, then the distinct chunk CIDs in manifest order. Only the
    /// root is listed if no replica holds a verifiable manifest.
    pub cids: Vec<Cid>,
    pub replicas: Vec<ReplicaAudit>,
    pub health: ObjectHealth,
    pub unrecoverable: Vec<Cid>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RepairKind {
    RewriteBlock { cid: Cid, previous: BlockStatus },
    PinRoot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", content = "detail", rename_all = "snake_case")]
pub enum RepairOutcome {
    Verified,
    Failed(String),
    Skipped(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairAction {
    pub replica: String,
    pub kind: RepairKind,
    pub outcome: RepairOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairReport {
    pub before: AuditReport,
    pub actions: Vec<RepairAction>,
    pub after: AuditReport,
}

pub struct ReplicaSet<S> {
    replicas: Vec<(String, S)>,
    max_object_size: u64,
}

async fn probe<S: BlockStore>(store: &S, cid: &Cid) -> BlockStatus {
    match store.get_raw(cid).await {
        Ok(data) => match Block::verified(cid.clone(), data) {
            Ok(_) => BlockStatus::Healthy,
            Err(_) => BlockStatus::Corrupted,
        },
        Err(IpfsError::NotFound(_)) => BlockStatus::Missing,
        Err(IpfsError::BlockTooLarge { .. }) => BlockStatus::Corrupted,
        Err(_) => BlockStatus::Unreachable,
    }
}

impl<S: BlockStore> ReplicaSet<S> {
    pub fn new(replicas: Vec<(String, S)>) -> Self {
        Self {
            replicas,
            max_object_size: DEFAULT_MAX_OBJECT_SIZE,
        }
    }

    pub fn with_max_object_size(mut self, limit: u64) -> Self {
        self.max_object_size = limit;
        self
    }

    pub fn replicas(&self) -> &[(String, S)] {
        &self.replicas
    }

    /// Inspect every replica for every block of the object rooted at `root`.
    pub async fn audit(&self, root: &Cid) -> AuditReport {
        let mut cids = vec![root.clone()];
        let mut manifest_found = false;
        for (_, store) in &self.replicas {
            if let Ok(manifest) = fetch_manifest(store, root, self.max_object_size).await {
                manifest_found = true;
                let mut seen = HashSet::from([root.clone()]);
                cids.extend(
                    manifest
                        .blocks()
                        .iter()
                        .filter(|l| seen.insert(l.cid.clone()))
                        .map(|l| l.cid.clone()),
                );
                break;
            }
        }

        let mut replicas = Vec::with_capacity(self.replicas.len());
        for (name, store) in &self.replicas {
            let mut blocks = Vec::with_capacity(cids.len());
            for cid in &cids {
                blocks.push(probe(store, cid).await);
            }
            replicas.push(ReplicaAudit {
                replica: name.clone(),
                backend: store.kind(),
                blocks,
            });
        }

        let healthy_somewhere = |i: usize| {
            replicas
                .iter()
                .any(|r: &ReplicaAudit| r.blocks[i] == BlockStatus::Healthy)
        };
        let mut unrecoverable: Vec<Cid> = (0..cids.len())
            .filter(|&i| !healthy_somewhere(i))
            .map(|i| cids[i].clone())
            .collect();
        // Without a manifest the chunk list is unknown, so the object is unrecoverable
        // even if the root block itself looks healthy (e.g. it failed to decode).
        if !manifest_found && unrecoverable.is_empty() {
            unrecoverable.push(root.clone());
        }
        let all_healthy = replicas
            .iter()
            .all(|r| r.blocks.iter().all(|&s| s == BlockStatus::Healthy));
        let health = if !unrecoverable.is_empty() || self.replicas.is_empty() {
            ObjectHealth::Unrecoverable
        } else if all_healthy {
            ObjectHealth::Healthy
        } else {
            ObjectHealth::Degraded
        };

        AuditReport {
            root: root.clone(),
            cids,
            replicas,
            health,
            unrecoverable,
        }
    }

    /// Audit, rewrite missing/corrupted blocks from verified copies, re-pin the root on
    /// repaired replicas, and audit again. Blocks without a verified source are left
    /// alone and reported as unrecoverable.
    pub async fn repair(&self, root: &Cid) -> RepairReport {
        let before = self.audit(root).await;
        let mut actions = Vec::new();
        let mut touched = vec![false; self.replicas.len()];

        for (i, cid) in before.cids.iter().enumerate() {
            if before.unrecoverable.contains(cid) {
                continue;
            }
            let sources: Vec<usize> = (0..self.replicas.len())
                .filter(|&r| before.replicas[r].blocks[i] == BlockStatus::Healthy)
                .collect();
            let mut verified: Option<Block> = None;
            for (r, audit) in before.replicas.iter().enumerate() {
                let previous = audit.blocks[i];
                if previous == BlockStatus::Healthy {
                    continue;
                }
                let kind = RepairKind::RewriteBlock {
                    cid: cid.clone(),
                    previous,
                };
                let outcome = if previous == BlockStatus::Unreachable {
                    RepairOutcome::Skipped("replica unreachable".into())
                } else {
                    if verified.is_none() {
                        verified = self.fetch_verified(&sources, cid).await;
                    }
                    match &verified {
                        None => RepairOutcome::Failed("no verified source copy".into()),
                        Some(block) => {
                            touched[r] = true;
                            self.rewrite(&self.replicas[r].1, block, previous).await
                        }
                    }
                };
                actions.push(RepairAction {
                    replica: audit.replica.clone(),
                    kind,
                    outcome,
                });
            }
        }

        for (r, (name, store)) in self.replicas.iter().enumerate() {
            if !touched[r] {
                continue;
            }
            let outcome = match store.pin(root, true).await {
                Ok(()) => RepairOutcome::Verified,
                Err(IpfsError::Unsupported(op)) => RepairOutcome::Skipped(op.into()),
                Err(e) => RepairOutcome::Failed(e.to_string()),
            };
            actions.push(RepairAction {
                replica: name.clone(),
                kind: RepairKind::PinRoot,
                outcome,
            });
        }

        let after = self.audit(root).await;
        RepairReport {
            before,
            actions,
            after,
        }
    }

    async fn fetch_verified(&self, sources: &[usize], cid: &Cid) -> Option<Block> {
        for &r in sources {
            if let Ok(block) = self.replicas[r].1.get_block(cid).await {
                return Some(block);
            }
        }
        None
    }

    async fn rewrite(&self, target: &S, block: &Block, previous: BlockStatus) -> RepairOutcome {
        if previous == BlockStatus::Corrupted
            && let Err(e) = target.remove_block(block.cid()).await
        {
            return RepairOutcome::Failed(format!("remove corrupted copy: {e}"));
        }
        if let Err(e) = target.put_block(block).await {
            return match e {
                IpfsError::Unsupported(op) => RepairOutcome::Skipped(op.into()),
                e => RepairOutcome::Failed(format!("write: {e}")),
            };
        }
        match target.get_block(block.cid()).await {
            Ok(_) => RepairOutcome::Verified,
            Err(e) => RepairOutcome::Failed(format!("read-back verification: {e}")),
        }
    }
}
