//! Live PostgreSQL test (ignored by default):
//!
//! ```text
//! TODO_TEST_POSTGRES_URL=postgres://todo_app@127.0.0.1:5432/todo_test \
//! TODO_TEST_POSTGRES_PASSWORD_FILE=~/.config/todo/secrets/postgres_password \
//!   cargo test -p todo-database --test objects_postgres -- --ignored
//! ```

use serde_json::json;
use todo_database::objects::{CatalogError, NewObject, ObjectCatalog, PgCatalog, postgres_options};
use todo_database::secrets::read_secret_file;

async fn catalog() -> PgCatalog {
    let url = std::env::var("TODO_TEST_POSTGRES_URL").expect("TODO_TEST_POSTGRES_URL");
    assert!(
        url.contains("todo_test"),
        "refusing to run outside todo_test"
    );
    let pw = std::env::var("TODO_TEST_POSTGRES_PASSWORD_FILE")
        .ok()
        .map(|p| {
            read_secret_file(std::path::Path::new(&p), "TODO_TEST_POSTGRES_PASSWORD_FILE")
                .expect("password file")
        });
    let opts = postgres_options(&url, pw.as_deref().map(String::as_str)).expect("options");
    let c = PgCatalog::connect(opts).await.expect("connect");
    c.migrate().await.expect("migrate");
    c
}

fn rand_u64() -> u64 {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).unwrap();
    u64::from_le_bytes(b) >> 20
}

fn object(owner_id: u64, tag: u8) -> NewObject {
    NewObject {
        owner_id,
        object_id: format!("doc-{tag}.pdf"),
        root_cid: format!("bafytest{owner_id:x}x{tag}"),
        backend: "mock".into(),
        crypto_mode: "aes-gcm-siv".into(),
        sealed_format_version: 1,
        nonce: [tag; 12],
        tag: [tag ^ 0xff; 16],
        original_size: 10_000,
        compressed_size: 3_000,
        sealed_size: 3_061,
        encryption_plan: json!({"execution": "parallel", "segment_bytes": 1024, "segments": 3}),
    }
}

#[tokio::test]
#[ignore]
async fn record_list_find_owner_scoped() {
    let c = catalog().await;
    let (alice, bob) = (rand_u64() + 1, rand_u64() + 2);
    let a1 = object(alice, 1);
    let a2 = object(alice, 2);
    let b1 = object(bob, 3);
    let id1 = c.record(&a1).await.unwrap();
    let id2 = c.record(&a2).await.unwrap();
    c.record(&b1).await.unwrap();
    assert!(id2 > id1);
    assert!(matches!(c.record(&a1).await, Err(CatalogError::Duplicate)));

    let list = c.list(alice, 50).await.unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].object, a2, "newest first, round-trips exactly");
    assert_eq!(list[1].object, a1);
    assert!(list[0].created_unix > 1_700_000_000);

    let found = c.find(alice, &a1.root_cid).await.unwrap().unwrap();
    assert_eq!(found.id, id1);
    assert_eq!(found.object.nonce, [1; 12]);
    assert!(c.find(bob, &a1.root_cid).await.unwrap().is_none());
    assert!(c.find(alice, "bafynothere00").await.unwrap().is_none());

    // The schema enforces the same rules even if application validation is bypassed.
    let bad = sqlx::query(
        "INSERT INTO objects (owner_id, object_id, root_cid, backend, crypto_mode, \
         sealed_format_version, nonce, tag, original_size, compressed_size, sealed_size, \
         encryption_plan) VALUES (1, '../x', 'bafybadbadbad', 'mock', 'aes-gcm-siv', 1, \
         '\\x00'::bytea, '\\x00'::bytea, 1, 1, 2, '{}'::jsonb)",
    )
    .execute(c.pool())
    .await;
    assert!(bad.is_err(), "CHECK constraints must reject bad rows");

    sqlx::query("DELETE FROM objects WHERE owner_id = ANY($1)")
        .bind(vec![alice as i64, bob as i64])
        .execute(c.pool())
        .await
        .unwrap();
}
