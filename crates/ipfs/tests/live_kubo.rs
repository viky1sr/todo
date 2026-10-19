//! Live interoperability tests against a real Kubo node. Not run by default:
//!
//! ```text
//! TODO_IPFS_KUBO_API=http://127.0.0.1:5001 \
//! TODO_IPFS_GATEWAY=http://127.0.0.1:8080 \
//!   cargo test -p todo-ipfs --test live_kubo -- --ignored --test-threads=1
//! ```
//!
//! `TODO_IPFS_GATEWAY` is optional. Use a disposable node: the test writes, unpins and
//! removes blocks.

use todo_ipfs::cid::codec;
use todo_ipfs::{
    BackendKind, Block, BlockStatus, BlockStore, Cid, IpfsBackend, KuboRpcClient, MemoryBlockStore,
    ObjectHealth, ObjectStore, RepairOutcome, ReplicaSet, TrustlessGateway,
};

fn kubo() -> KuboRpcClient {
    let url = std::env::var("TODO_IPFS_KUBO_API").expect("set TODO_IPFS_KUBO_API");
    KuboRpcClient::new(&url).unwrap()
}

fn payload(len: usize) -> Vec<u8> {
    // Seeded per run so stale state from earlier runs cannot mask failures.
    let mut x = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
        | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

#[tokio::test]
#[ignore = "requires a live Kubo node (TODO_IPFS_KUBO_API)"]
async fn kubo_computes_identical_cids() {
    let node = kubo();
    let info = node.node_info().await.unwrap();
    assert!(!info.peer_id.is_empty());
    println!(
        "Kubo {} peer {}",
        node.version().await.unwrap(),
        info.peer_id
    );

    let hello = Block::raw(b"hello world".to_vec()).unwrap();
    node.put_block(&hello).await.unwrap();
    assert_eq!(
        hello.cid().to_string(),
        "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e"
    );
    assert!(node.has_block(hello.cid()).await.unwrap());
    assert_eq!(node.get_block(hello.cid()).await.unwrap(), hello);

    let absent = Cid::sha2_256(codec::RAW, &payload(64));
    assert!(!node.has_block(&absent).await.unwrap());
    assert!(matches!(
        node.get_raw(&absent).await,
        Err(todo_ipfs::IpfsError::NotFound(_))
    ));
}

#[tokio::test]
#[ignore = "requires a live Kubo node (TODO_IPFS_KUBO_API)"]
async fn kubo_object_roundtrip_with_recursive_pin() {
    let store = ObjectStore::new(kubo());
    let data = payload(3 * 256 * 1024 + 123);
    let published = store.put_object("live-object", data.clone()).await.unwrap();
    assert_eq!(published.backend, BackendKind::KuboRpc);
    assert_eq!(published.manifest.blocks().len(), 4);
    let (_, out) = store.get_object(&published.root).await.unwrap();
    assert_eq!(out, data);
    println!("root {}", published.root);

    if let Ok(url) = std::env::var("TODO_IPFS_GATEWAY") {
        let gateway = ObjectStore::new(TrustlessGateway::new(&url).unwrap());
        let (_, via_gateway) = gateway.get_object(&published.root).await.unwrap();
        assert_eq!(via_gateway, data);
    }
    store.unpin_object(&published.root).await.unwrap();
}

#[tokio::test]
#[ignore = "requires a live Kubo node (TODO_IPFS_KUBO_API)"]
async fn kubo_replica_is_repaired_from_verified_copy() {
    let node = kubo();
    let mock = MemoryBlockStore::new();
    let data = payload(600 * 1024);
    let live = ObjectStore::new(node.clone())
        .put_object("live-repair", data.clone())
        .await
        .unwrap();
    let copy = ObjectStore::new(mock.clone())
        .put_object("live-repair", data.clone())
        .await
        .unwrap();
    assert_eq!(live.root, copy.root);

    // Simulate loss on the live node.
    let lost = live.manifest.blocks()[1].cid.clone();
    node.unpin(&live.root, true).await.unwrap();
    node.remove_block(&lost).await.unwrap();
    assert!(!node.has_block(&lost).await.unwrap());

    let set = ReplicaSet::new(vec![
        ("kubo".to_string(), IpfsBackend::Kubo(node.clone())),
        ("mock".to_string(), IpfsBackend::Mock(mock)),
    ]);
    let report = set.repair(&live.root).await;
    let i = report.before.cids.iter().position(|c| *c == lost).unwrap();
    assert_eq!(report.before.replicas[0].blocks[i], BlockStatus::Missing);
    assert!(
        report
            .actions
            .iter()
            .all(|a| a.outcome == RepairOutcome::Verified),
        "{:?}",
        report.actions
    );
    assert_eq!(report.after.health, ObjectHealth::Healthy);
    let (_, out) = ObjectStore::new(node.clone())
        .get_object(&live.root)
        .await
        .unwrap();
    assert_eq!(out, data);
    node.unpin(&live.root, true).await.unwrap();
}
