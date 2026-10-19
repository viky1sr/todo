//! Live MariaDB tests for Layer 3 accounts. Ignored by default; run with
//!
//! ```sh
//! TODO_TEST_MARIADB_URL='mysql://todo_app@localhost/todo_test?socket=/run/mysqld/mysqld.sock' \
//! TODO_TEST_MARIADB_PASSWORD_FILE=~/.config/todo/secrets/mariadb_password \
//! cargo test -p todo-database --test accounts_mariadb -- --ignored
//! ```

use std::path::Path;

use sqlx::Row;
use todo_database::accounts::{AccountError, NewUser, PiiCipher, Role, UserStore, mariadb_options};
use todo_database::secrets::read_secret_file;
use zeroize::Zeroizing;

async fn store() -> UserStore {
    let url = std::env::var("TODO_TEST_MARIADB_URL").expect("TODO_TEST_MARIADB_URL");
    assert!(
        url.contains("todo_test"),
        "tests must use the todo_test database"
    );
    let pw = std::env::var("TODO_TEST_MARIADB_PASSWORD_FILE")
        .ok()
        .map(|p| read_secret_file(Path::new(&p), "TODO_TEST_MARIADB_PASSWORD_FILE").unwrap());
    let opts = mariadb_options(&url, pw.as_deref().map(String::as_str)).unwrap();
    let store = UserStore::connect(opts, PiiCipher::new(&[0x5a; 32]).unwrap())
        .await
        .unwrap();
    store.migrate().await.unwrap();
    store
}

fn unique(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    format!("{prefix}{}{nanos}", std::process::id())
}

fn new_user(username: &str, email: Option<&str>, nik: Option<&str>) -> NewUser {
    NewUser {
        username: username.into(),
        password: Zeroizing::new("correct horse battery".into()),
        role: Role::User,
        email: email.map(|e| Zeroizing::new(e.into())),
        national_id: nik.map(|n| Zeroizing::new(n.into())),
    }
}

#[tokio::test]
#[ignore = "needs a live MariaDB (TODO_TEST_MARIADB_URL)"]
async fn users_argon2id_and_encrypted_pii() {
    let store = store().await;
    let name = unique("budi");
    let id = store
        .create_user(new_user(
            &name.to_uppercase(),
            Some("budi@example.co.id"),
            Some("3201234567890123"),
        ))
        .await
        .unwrap();

    // Stored bytes: Argon2id PHC + ciphertext only.
    let row = sqlx::query(
        "SELECT username, password_hash, email_enc, national_id_enc FROM users WHERE id = ?",
    )
    .bind(id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("username"), name);
    assert!(
        row.get::<String, _>("password_hash")
            .starts_with("$argon2id$")
    );
    let email_enc: Vec<u8> = row.get("email_enc");
    let nik_enc: Vec<u8> = row.get("national_id_enc");
    assert_eq!(email_enc[0], 1);
    assert!(!email_enc.windows(4).any(|w| w == b"budi"));
    assert!(!nik_enc.windows(6).any(|w| w == b"320123"));

    // Login: case-insensitive username, wrong password and unknown user both None.
    let ok = store
        .authenticate(&name.to_uppercase(), "correct horse battery")
        .await
        .unwrap()
        .unwrap();
    assert_eq!((ok.id, ok.role), (id, Role::User));
    assert!(
        store
            .authenticate(&name, "wrong password!!")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .authenticate("nobody-here", "correct horse battery")
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.authenticate("x", "y").await.unwrap().is_none());

    let p = store.profile(id).await.unwrap().unwrap();
    assert_eq!(
        p.email.as_deref().map(String::as_str),
        Some("budi@example.co.id")
    );
    assert_eq!(
        p.national_id.as_deref().map(String::as_str),
        Some("3201234567890123")
    );
    assert!(p.created_at_unix > 1_700_000_000);
    assert!(store.profile(u64::MAX).await.unwrap().is_none());

    // Duplicate username (after normalisation).
    assert!(matches!(
        store.create_user(new_user(&name, None, None)).await,
        Err(AccountError::DuplicateUsername)
    ));
    assert!(matches!(
        store.create_user(new_user("ab", None, None)).await,
        Err(AccountError::Invalid(_))
    ));

    // Moving a valid blob to another row or column is detected (AAD binding).
    let other = store
        .create_user(new_user(&unique("siti"), Some("siti@example.co.id"), None))
        .await
        .unwrap();
    sqlx::query("UPDATE users SET email_enc = ? WHERE id = ?")
        .bind(&email_enc)
        .bind(other)
        .execute(store.pool())
        .await
        .unwrap();
    assert!(matches!(
        store.profile(other).await,
        Err(AccountError::PiiIntegrity)
    ));
    sqlx::query("UPDATE users SET email_enc = ? WHERE id = ?")
        .bind(&nik_enc)
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();
    assert!(matches!(
        store.profile(id).await,
        Err(AccountError::PiiIntegrity)
    ));

    sqlx::query("DELETE FROM users WHERE id IN (?, ?)")
        .bind(id)
        .bind(other)
        .execute(store.pool())
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "needs a live MariaDB (TODO_TEST_MARIADB_URL)"]
async fn users_seed_idempotency_and_auth() {
    let store = store().await;

    // Apply seed first time
    store.seed().await.unwrap();

    // Verify seeded user and admin accounts authenticate
    let user_auth = store
        .authenticate("user", "correct horse battery")
        .await
        .unwrap();
    assert!(user_auth.is_some(), "user account must authenticate");

    let admin_auth = store
        .authenticate("admin", "correct horse battery")
        .await
        .unwrap();
    assert!(admin_auth.is_some(), "admin account must authenticate");

    // Re-apply seed to verify idempotency (zero errors on duplicate keys)
    store.seed().await.unwrap();

    // Verify accounts still authenticate after idempotent re-seed
    let user_auth2 = store
        .authenticate("user", "correct horse battery")
        .await
        .unwrap();
    assert!(user_auth2.is_some());
    let admin_auth2 = store
        .authenticate("admin", "correct horse battery")
        .await
        .unwrap();
    assert!(admin_auth2.is_some());
}
