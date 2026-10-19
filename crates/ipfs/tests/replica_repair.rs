//! Replica audit and byte-identical repair (MOCK replicas with fault injection).

use todo_ipfs::{
    BlockStatus, Cid, IpfsBackend, MemoryBlockStore, ObjectHealth, ObjectStore, RepairKind,
    RepairOutcome, ReplicaSet, TrustlessGateway,
};

fn replicas(n: usize) -> Vec<MemoryBlockStore> {
    (0..n).map(|_| MemoryBlockStore::new()).collect()
}

fn set(stores: &[MemoryBlockStore]) -> ReplicaSet<MemoryBlockStore> {
    ReplicaSet::new(
        stores
            .iter()
            .enumerate()
            .map(|(i, s)| (format!("replica-{i}"), s.clone()))
            .collect(),
    )
}

/// Publish the same object to every store; returns root and chunk CIDs.
async fn publish_everywhere(stores: &[MemoryBlockStore], payload: &[u8]) -> (Cid, Vec<Cid>) {
    let mut root: Option<Cid> = None;
    let mut chunks = Vec::new();
    for s in stores {
        let p = ObjectStore::new(s.clone())
            .with_chunk_size(64)
            .unwrap()
            .put_object("replicated", payload.to_vec())
            .await
            .unwrap();
        chunks = p.manifest.blocks().iter().map(|l| l.cid.clone()).collect();
        assert!(root.as_ref().is_none_or(|r| *r == p.root));
        root = Some(p.root);
    }
    (root.unwrap(), chunks)
}

#[tokio::test]
async fn healthy_object_needs_no_repair() {
    let stores = replicas(3);
    let (root, _) = publish_everywhere(&stores, &[1u8; 200]).await;
    let report = set(&stores).repair(&root).await;
    assert_eq!(report.before.health, ObjectHealth::Healthy);
    assert!(report.actions.is_empty());
    assert_eq!(report.after.health, ObjectHealth::Healthy);
}

#[tokio::test]
async fn repairs_missing_and_corrupted_blocks_from_verified_copies() {
    let stores = replicas(3);
    let payload: Vec<u8> = (0..500u32).map(|i| (i * 7) as u8).collect();
    let (root, chunks) = publish_everywhere(&stores, &payload).await;

    stores[0].tamper_block(&chunks[1], vec![0xee; 64]).await;
    stores[1].drop_block(&chunks[3]).await;
    stores[1].drop_block(&root).await;
    stores[2].tamper_block(&chunks[3], vec![0xaa; 64]).await;

    let report = set(&stores).repair(&root).await;
    assert_eq!(report.before.health, ObjectHealth::Degraded);
    let status = |r: usize, cid: &Cid| {
        let i = report.before.cids.iter().position(|c| c == cid).unwrap();
        report.before.replicas[r].blocks[i]
    };
    assert_eq!(status(0, &chunks[1]), BlockStatus::Corrupted);
    assert_eq!(status(1, &chunks[3]), BlockStatus::Missing);
    assert_eq!(status(1, &root), BlockStatus::Missing);
    assert_eq!(status(2, &chunks[3]), BlockStatus::Corrupted);

    let rewrites = report
        .actions
        .iter()
        .filter(|a| matches!(a.kind, RepairKind::RewriteBlock { .. }))
        .count();
    assert_eq!(rewrites, 4);
    assert!(
        report
            .actions
            .iter()
            .all(|a| a.outcome == RepairOutcome::Verified),
        "{:?}",
        report.actions
    );
    assert_eq!(report.after.health, ObjectHealth::Healthy);

    // Every replica now serves the original bytes under the unchanged root.
    for s in &stores {
        let (_, out) = ObjectStore::new(s.clone()).get_object(&root).await.unwrap();
        assert_eq!(out, payload);
        assert!(s.is_pinned(&root, true).await);
    }
}

#[tokio::test]
async fn never_fabricates_recovery_when_all_copies_are_bad() {
    let stores = replicas(2);
    let payload: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
    let (root, chunks) = publish_everywhere(&stores, &payload).await;
    stores[0].tamper_block(&chunks[0], vec![1; 64]).await;
    stores[1].drop_block(&chunks[0]).await;
    // A different chunk is repairable and must still be repaired.
    stores[1].drop_block(&chunks[2]).await;

    let report = set(&stores).repair(&root).await;
    assert_eq!(report.before.health, ObjectHealth::Unrecoverable);
    assert_eq!(report.before.unrecoverable, vec![chunks[0].clone()]);
    assert!(report.actions.iter().all(|a| match &a.kind {
        RepairKind::RewriteBlock { cid, .. } => *cid != chunks[0],
        RepairKind::PinRoot => true,
    }));
    assert!(report.actions.iter().any(|a| matches!(
        &a.kind,
        RepairKind::RewriteBlock { cid, .. } if *cid == chunks[2]
    ) && a.outcome == RepairOutcome::Verified));
    assert_eq!(report.after.health, ObjectHealth::Unrecoverable);
    assert_eq!(report.after.unrecoverable, vec![chunks[0].clone()]);
    assert!(
        ObjectStore::new(stores[1].clone())
            .get_object(&root)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn missing_manifest_everywhere_is_unrecoverable() {
    let stores = replicas(2);
    let (root, _) = publish_everywhere(&stores, &[4u8; 100]).await;
    for s in &stores {
        s.drop_block(&root).await;
    }
    let report = set(&stores).repair(&root).await;
    assert_eq!(report.after.health, ObjectHealth::Unrecoverable);
    assert_eq!(report.after.cids, vec![root.clone()]);
    assert!(report.actions.is_empty());
}

#[tokio::test]
async fn unreachable_replica_is_skipped_not_reported_repaired() {
    let stores = replicas(2);
    let (root, _) = publish_everywhere(&stores, &[5u8; 100]).await;
    stores[1].set_offline(true).await;
    let report = set(&stores).repair(&root).await;
    assert_eq!(
        report.before.replicas[1].blocks[0],
        BlockStatus::Unreachable
    );
    assert!(!report.actions.is_empty());
    assert!(
        report
            .actions
            .iter()
            .all(|a| a.replica == "replica-1" && matches!(a.outcome, RepairOutcome::Skipped(_)))
    );
    assert_eq!(report.after.health, ObjectHealth::Degraded);
}

#[tokio::test]
async fn unreachable_gateway_is_reported_not_repaired() {
    let mock = MemoryBlockStore::new();
    let published = ObjectStore::new(mock.clone())
        .put_object("gw", vec![6u8; 10])
        .await
        .unwrap();
    // Nothing listens on port 9 (discard), so the gateway is unreachable.
    let gateway = TrustlessGateway::new("http://127.0.0.1:9").unwrap();
    let set = ReplicaSet::new(vec![
        ("mock".into(), IpfsBackend::Mock(mock)),
        ("gateway".into(), IpfsBackend::Gateway(gateway)),
    ]);
    let report = set.repair(&published.root).await;
    assert_eq!(
        report.before.replicas[1].blocks[0],
        BlockStatus::Unreachable
    );
    assert_eq!(report.after.health, ObjectHealth::Degraded);
    assert!(
        report
            .actions
            .iter()
            .all(|a| matches!(a.outcome, RepairOutcome::Skipped(_)))
    );
}
