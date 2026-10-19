//! Live Redis tests for Layer 2 sessions. Ignored by default; run with
//!
//! ```sh
//! TODO_TEST_REDIS_URL=redis://127.0.0.1:6379/15 \
//! cargo test -p todo-database --test sessions_redis -- --ignored
//! ```

use std::time::Duration;

use redis::AsyncCommands;
use todo_database::accounts::{AuthenticatedUser, Role};
use todo_database::secrets::read_secret;
use todo_database::sessions::{SessionPolicy, SessionStore, redis_connection_info};

fn info() -> redis::ConnectionInfo {
    let url = std::env::var("TODO_TEST_REDIS_URL").expect("TODO_TEST_REDIS_URL");
    let pw = read_secret("TODO_TEST_REDIS_PASSWORD").unwrap();
    redis_connection_info(&url, pw.as_deref().map(String::as_str)).unwrap()
}

#[tokio::test]
#[ignore = "needs a live Redis (TODO_TEST_REDIS_URL)"]
async fn redis_sessions_ttl_hashing_and_rate_limit() {
    let policy = SessionPolicy {
        idle_ttl: Duration::from_secs(2),
        max_failures_per_user: 3,
        ..SessionPolicy::default()
    };
    let store = SessionStore::redis(info(), policy).await.unwrap();
    let user = AuthenticatedUser {
        id: 42,
        username: format!("redis-test-{}", std::process::id()),
        role: Role::Admin,
    };
    let token = store.create(&user).await.unwrap();
    let s = store.get(token.as_str()).await.unwrap().unwrap();
    assert_eq!((s.user_id, s.role), (42, Role::Admin));

    // Only SHA-256(token) is stored; the raw token never appears as key or value.
    let client = redis::Client::open(info()).unwrap();
    let mut conn = client.get_multiplexed_async_connection().await.unwrap();
    let keys: Vec<String> = conn.keys("todo:v1:sess:*").await.unwrap();
    assert!(!keys.is_empty());
    assert!(keys.iter().all(|k| !k.contains(token.as_str())));
    for k in &keys {
        let v: String = conn.get(k).await.unwrap_or_default();
        assert!(!v.contains(token.as_str()));
    }
    let ttl: i64 = redis::cmd("TTL")
        .arg(&keys[0])
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!((1..=2).contains(&ttl), "ttl {ttl}");

    // Sliding idle TTL: touched sessions survive, untouched ones expire.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(store.get(token.as_str()).await.unwrap().is_some());
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(store.get(token.as_str()).await.unwrap().is_some());
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(store.get(token.as_str()).await.unwrap().is_none());

    let t2 = store.create(&user).await.unwrap();
    store.destroy(t2.as_str()).await.unwrap();
    assert!(store.get(t2.as_str()).await.unwrap().is_none());

    let ip = format!("192.0.2.{}", std::process::id() % 250);
    for _ in 0..3 {
        assert!(store.login_allowed(&ip, &user.username).await.unwrap());
        store.record_failure(&ip, &user.username).await.unwrap();
    }
    assert!(
        !store
            .login_allowed("198.51.100.1", &user.username)
            .await
            .unwrap()
    );
    store.clear_user_failures(&user.username).await.unwrap();
    assert!(store.login_allowed(&ip, &user.username).await.unwrap());
    let ip_keys: Vec<String> = conn
        .keys(format!("todo:v1:login-fail:ip:{ip}"))
        .await
        .unwrap();
    let ttl: i64 = redis::cmd("TTL")
        .arg(&ip_keys[0])
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!(ttl > 0 && ttl <= 900);
    let _: usize = conn.del(&ip_keys[0]).await.unwrap();
}
