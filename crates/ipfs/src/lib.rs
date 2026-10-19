//! `todo-ipfs`: content-addressed storage of encrypted objects following the IPFS
//! specifications.
//!
//! * [`cid`]: CIDv0/CIDv1, multihash, multicodec (strict parsing, canonical encoding).
//! * [`block`]: blocks verified against their CID and the backend-neutral
//!   [`BlockStore`] contract. Backends are untrusted; every read is re-hashed.
//! * [`manifest`]: DAG-JSON object manifest whose CID is the object root.
//! * [`object`]: chunking objects into raw blocks and reassembling them by root CID.
//! * [`replica`]: audit and byte-identical repair across several stores.
//! * Backends: [`kubo::KuboRpcClient`] (live node, read/write),
//!   [`gateway::TrustlessGateway`] (live, read-only) and [`memory::MemoryBlockStore`]
//!   (in-process **mock**; computes real CIDs but proves nothing about interoperability).
//!
//! This crate stores bytes; it does not encrypt them. Callers must store ciphertext and
//! still verify the AEAD tag after retrieval: a CID proves the bytes match a root, not
//! who produced them.

#[cfg(not(target_arch = "wasm32"))]
pub mod backend;
pub mod block;
pub mod cid;
pub mod error;
#[cfg(not(target_arch = "wasm32"))]
pub mod gateway;
#[cfg(not(target_arch = "wasm32"))]
mod http;
#[cfg(not(target_arch = "wasm32"))]
pub mod kubo;
#[cfg(not(target_arch = "wasm32"))]
pub mod managed_kubo;
pub mod manifest;
#[cfg(not(target_arch = "wasm32"))]
pub mod memory;
mod multibase;
#[cfg(not(target_arch = "wasm32"))]
pub mod object;
#[cfg(not(target_arch = "wasm32"))]
pub mod replica;
mod varint;

#[cfg(not(target_arch = "wasm32"))]
pub use backend::IpfsBackend;
pub use block::{BackendKind, Block, BlockStore, DEFAULT_CHUNK_SIZE, MAX_BLOCK_SIZE};
pub use cid::{Cid, CidVersion, Multihash};
pub use error::IpfsError;
#[cfg(not(target_arch = "wasm32"))]
pub use gateway::TrustlessGateway;
#[cfg(not(target_arch = "wasm32"))]
pub use kubo::{DEFAULT_KUBO_API, KuboRpcClient, NodeInfo};
#[cfg(not(target_arch = "wasm32"))]
pub use managed_kubo::ManagedKubo;
pub use manifest::{BlockLink, MANIFEST_SCHEMA, ObjectManifest};
#[cfg(not(target_arch = "wasm32"))]
pub use memory::MemoryBlockStore;
#[cfg(not(target_arch = "wasm32"))]
pub use object::{DEFAULT_MAX_OBJECT_SIZE, ObjectStore, PublishedObject};
#[cfg(not(target_arch = "wasm32"))]
pub use replica::{
    AuditReport, BlockStatus, ObjectHealth, RepairAction, RepairKind, RepairOutcome, RepairReport,
    ReplicaAudit, ReplicaSet,
};
