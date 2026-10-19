//! Object store against the in-memory backend (MOCK: no IPFS interoperability claim).

use todo_ipfs::cid::codec;
use todo_ipfs::{BackendKind, Block, BlockStore, Cid, IpfsError, MemoryBlockStore, ObjectStore};

fn data(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

#[tokio::test]
async fn roundtrip_across_chunk_boundaries() {
    let chunk = 1024;
    let store = ObjectStore::new(MemoryBlockStore::new())
        .with_chunk_size(chunk)
        .unwrap();
    for len in [0, 1, chunk - 1, chunk, chunk + 1, 5 * chunk + 7] {
        let payload = data(len, 3);
        let published = store.put_object("obj-1", payload.clone()).await.unwrap();
        assert_eq!(published.backend, BackendKind::Mock);
        assert_eq!(published.root.codec(), codec::DAG_JSON);
        assert_eq!(published.manifest.total_size(), len as u64);
        assert_eq!(published.manifest.blocks().len(), len.div_ceil(chunk));
        // Root CID is the CID of the canonical manifest bytes.
        assert_eq!(
            published.root,
            Cid::sha2_256(codec::DAG_JSON, &published.manifest.to_dag_json())
        );
        let (manifest, out) = store.get_object(&published.root).await.unwrap();
        assert_eq!(manifest, published.manifest);
        assert_eq!(out, payload, "len={len}");
        assert!(store.store().is_pinned(&published.root, true).await);
    }
}

#[tokio::test]
async fn content_addressing_is_deterministic_and_deduplicates() {
    let store = ObjectStore::new(MemoryBlockStore::new())
        .with_chunk_size(16)
        .unwrap();
    let payload = [vec![7u8; 16], vec![7u8; 16], vec![9u8; 16]].concat();
    let a = store.put_object("same", payload.clone()).await.unwrap();
    let b = store.put_object("same", payload).await.unwrap();
    assert_eq!(a.root, b.root);
    assert_eq!(a.manifest.blocks()[0].cid, a.manifest.blocks()[1].cid);
    // 2 distinct chunks + 1 manifest.
    assert_eq!(store.store().len().await, 3);
    let other = store.put_object("other-id", vec![7u8; 48]).await.unwrap();
    assert_ne!(other.root, a.root);
}

#[tokio::test]
async fn tampered_or_missing_blocks_are_rejected() {
    let backend = MemoryBlockStore::new();
    let store = ObjectStore::new(backend.clone())
        .with_chunk_size(64)
        .unwrap();
    let published = store.put_object("victim", data(300, 1)).await.unwrap();
    let chunk = published.manifest.blocks()[2].cid.clone();

    backend.tamper_block(&chunk, vec![0u8; 64]).await;
    assert_eq!(
        store.get_object(&published.root).await.unwrap_err(),
        IpfsError::DigestMismatch { cid: chunk.clone() }
    );

    backend.drop_block(&chunk).await;
    assert_eq!(
        store.get_object(&published.root).await.unwrap_err(),
        IpfsError::NotFound(chunk)
    );

    // Tampering with the manifest is detected through the root CID.
    backend.tamper_block(&published.root, b"{}".to_vec()).await;
    assert!(matches!(
        store.get_object(&published.root).await,
        Err(IpfsError::DigestMismatch { .. })
    ));
}

#[tokio::test]
async fn limits_and_validation() {
    let store = ObjectStore::new(MemoryBlockStore::new()).with_max_object_size(100);
    assert!(matches!(
        store.put_object("big", vec![0; 101]).await,
        Err(IpfsError::ObjectTooLarge {
            size: 101,
            limit: 100
        })
    ));
    assert!(matches!(
        store.put_object("../escape", vec![1]).await,
        Err(IpfsError::InvalidManifest(_))
    ));
    assert!(
        ObjectStore::new(MemoryBlockStore::new())
            .with_chunk_size(2 * 1024 * 1024)
            .is_err()
    );

    // A manifest declaring more than the reader's limit is refused before any chunk fetch.
    let writer = ObjectStore::new(MemoryBlockStore::new());
    let published = writer.put_object("x", vec![5; 200]).await.unwrap();
    let reader = ObjectStore::new(writer.store().clone()).with_max_object_size(100);
    assert!(matches!(
        reader.get_object(&published.root).await,
        Err(IpfsError::ObjectTooLarge {
            size: 200,
            limit: 100
        })
    ));

    // A raw block is not a manifest root.
    let raw = Block::raw(b"abc".to_vec()).unwrap();
    writer.store().put_block(&raw).await.unwrap();
    assert!(matches!(
        writer.get_object(raw.cid()).await,
        Err(IpfsError::InvalidManifest(_))
    ));
}

#[tokio::test]
async fn recursive_pin_requires_complete_dag_and_unpin_works() {
    let backend = MemoryBlockStore::new();
    let store = ObjectStore::new(backend.clone())
        .with_chunk_size(32)
        .unwrap();
    let published = store.put_object("pinned", data(100, 2)).await.unwrap();
    store.unpin_object(&published.root).await.unwrap();
    assert!(!backend.is_pinned(&published.root, true).await);

    backend
        .drop_block(&published.manifest.blocks()[0].cid)
        .await;
    assert!(matches!(
        backend.pin(&published.root, true).await,
        Err(IpfsError::NotFound(_))
    ));
}

#[test]
fn block_size_limit() {
    assert!(Block::raw(vec![0; todo_ipfs::MAX_BLOCK_SIZE]).is_ok());
    assert!(matches!(
        Block::raw(vec![0; todo_ipfs::MAX_BLOCK_SIZE + 1]),
        Err(IpfsError::BlockTooLarge { .. })
    ));
}
