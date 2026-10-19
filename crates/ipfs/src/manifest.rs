//! Object manifest stored as a DAG-JSON block (multicodec `0x0129`).
//!
//! ```json
//! {"blocks":[{"cid":{"/":"bafkrei..."},"size":262144},...],
//!  "object_id":"stream-001","schema":"todo-ipfs/object-manifest/v1","total_size":300000}
//! ```
//!
//! Encoding is canonical DAG-JSON (keys sorted bytewise, no whitespace, links as
//! `{"/": "<cid>"}`), so IPFS nodes can traverse it (e.g. Kubo recursive pinning) and the
//! root CID commits to every chunk CID, size and order. The root CID gives integrity
//! only relative to a trusted root; it does not authenticate who published it, and it
//! does not replace the AEAD tag of the stored ciphertext.

use crate::block::{Block, MAX_BLOCK_SIZE};
use crate::cid::{Cid, CidVersion, codec, hash};
use crate::error::IpfsError;
use serde::{Deserialize, Serialize};
use std::fmt::Write;

pub const MANIFEST_SCHEMA: &str = "todo-ipfs/object-manifest/v1";

/// Maximum length of an object identifier.
pub const MAX_OBJECT_ID_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockLink {
    pub cid: Cid,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectManifest {
    object_id: String,
    total_size: u64,
    blocks: Vec<BlockLink>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireLink {
    #[serde(rename = "/")]
    link: Cid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBlock {
    cid: WireLink,
    size: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireManifest {
    blocks: Vec<WireBlock>,
    object_id: String,
    schema: String,
    total_size: u64,
}

/// Object IDs are stored in public metadata: restrict to `[A-Za-z0-9._-]{1,128}`.
pub fn validate_object_id(id: &str) -> Result<(), IpfsError> {
    let ok = !id.is_empty()
        && id.len() <= MAX_OBJECT_ID_LEN
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(IpfsError::InvalidManifest(format!(
            "object id must match [A-Za-z0-9._-]{{1,{MAX_OBJECT_ID_LEN}}}"
        )))
    }
}

fn invalid(msg: impl Into<String>) -> IpfsError {
    IpfsError::InvalidManifest(msg.into())
}

impl ObjectManifest {
    pub fn new(object_id: &str, blocks: Vec<BlockLink>) -> Result<Self, IpfsError> {
        validate_object_id(object_id)?;
        let mut total_size = 0u64;
        for link in &blocks {
            if link.cid.version() != CidVersion::V1
                || link.cid.codec() != codec::RAW
                || link.cid.hash().code() != hash::SHA2_256
            {
                return Err(invalid(format!(
                    "chunk {} must be a CIDv1 raw sha2-256 block",
                    link.cid
                )));
            }
            if link.size == 0 || link.size > MAX_BLOCK_SIZE as u64 {
                return Err(invalid(format!("chunk size {} out of range", link.size)));
            }
            total_size = total_size
                .checked_add(link.size)
                .ok_or_else(|| invalid("total size overflow"))?;
        }
        Ok(Self {
            object_id: object_id.to_string(),
            total_size,
            blocks,
        })
    }

    pub fn object_id(&self) -> &str {
        &self.object_id
    }

    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    pub fn blocks(&self) -> &[BlockLink] {
        &self.blocks
    }

    /// Canonical DAG-JSON bytes.
    pub fn to_dag_json(&self) -> Vec<u8> {
        let mut out = String::with_capacity(96 + self.blocks.len() * 90);
        out.push_str("{\"blocks\":[");
        for (i, link) in self.blocks.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                "{{\"cid\":{{\"/\":\"{}\"}},\"size\":{}}}",
                link.cid, link.size
            );
        }
        // object_id is restricted to characters that need no JSON escaping.
        let _ = write!(
            out,
            "],\"object_id\":\"{}\",\"schema\":\"{MANIFEST_SCHEMA}\",\"total_size\":{}}}",
            self.object_id, self.total_size
        );
        out.into_bytes()
    }

    pub fn to_block(&self) -> Result<Block, IpfsError> {
        Block::new(codec::DAG_JSON, self.to_dag_json())
    }

    /// Decode a verified manifest block; rejects non-canonical encodings.
    pub fn decode(block: &Block) -> Result<Self, IpfsError> {
        if block.cid().codec() != codec::DAG_JSON {
            return Err(invalid(format!(
                "root {} is not a DAG-JSON block",
                block.cid()
            )));
        }
        let wire: WireManifest = serde_json::from_slice(block.data())
            .map_err(|e| invalid(format!("malformed DAG-JSON: {e}")))?;
        if wire.schema != MANIFEST_SCHEMA {
            return Err(invalid(format!("unsupported schema {:?}", wire.schema)));
        }
        let manifest = Self::new(
            &wire.object_id,
            wire.blocks
                .into_iter()
                .map(|b| BlockLink {
                    cid: b.cid.link,
                    size: b.size,
                })
                .collect(),
        )?;
        if manifest.total_size != wire.total_size {
            return Err(invalid("total_size does not equal the sum of chunk sizes"));
        }
        if manifest.to_dag_json() != block.data() {
            return Err(invalid("non-canonical DAG-JSON encoding"));
        }
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ObjectManifest {
        let a = Block::raw(b"hello ".to_vec()).unwrap();
        let b = Block::raw(b"world".to_vec()).unwrap();
        ObjectManifest::new(
            "stream-001",
            vec![
                BlockLink {
                    cid: a.cid().clone(),
                    size: 6,
                },
                BlockLink {
                    cid: b.cid().clone(),
                    size: 5,
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn canonical_roundtrip() {
        let m = sample();
        let block = m.to_block().unwrap();
        assert_eq!(block.cid().codec(), codec::DAG_JSON);
        assert_eq!(ObjectManifest::decode(&block).unwrap(), m);
        // Generic JSON parsers see the same document with sorted keys.
        let v: serde_json::Value = serde_json::from_slice(block.data()).unwrap();
        assert_eq!(v["total_size"], 11);
        assert_eq!(serde_json::to_vec(&v).unwrap(), block.data());
    }

    #[test]
    fn rejects_bad_manifests() {
        let good = String::from_utf8(sample().to_dag_json()).unwrap();
        let cases = [
            good.replace("\"total_size\":11", "\"total_size\":12"),
            good.replace("v1", "v2"),
            good.replace(":", ": "),
            good.replace("\"size\":5", "\"size\":0"),
            good.replace("}", ",\"extra\":1}"),
            good.replace("stream-001", "../etc"),
            "not json".to_string(),
        ];
        for bad in cases {
            let block = Block::new(codec::DAG_JSON, bad.clone().into_bytes()).unwrap();
            assert!(ObjectManifest::decode(&block).is_err(), "accepted {bad}");
        }
        let raw = Block::raw(good.into_bytes()).unwrap();
        assert!(ObjectManifest::decode(&raw).is_err());
    }

    #[test]
    fn object_id_validation() {
        assert!(validate_object_id("a.b_c-1").is_ok());
        for bad in ["", "a/b", "a b", "é", &"x".repeat(129)] {
            assert!(validate_object_id(bad).is_err(), "{bad:?}");
        }
    }
}
