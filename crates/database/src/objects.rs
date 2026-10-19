//! Layer 4: metadata of sealed objects in PostgreSQL.
//!
//! One row per uploaded object: owner (MariaDB `users.id`), object id (download file
//! name), root CID, backend, AEAD parameters (nonce, tag; public values) and sizes /
//! encryption plan. No plaintext and no key is stored here. Downloads by a logged-in
//! user are authorized by `(owner_id, root_cid)` and use the stored nonce, so the
//! client no longer has to keep it.
//!
//! Connection: `TODO_POSTGRES_URL` without a password, plus
//! `TODO_POSTGRES_PASSWORD_FILE` (owner-only file, see [`crate::secrets`]).

use std::fmt;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions, PgRow};
use sqlx::types::Json;
use sqlx::{ConnectOptions, Row};
use zeroize::Zeroizing;

use crate::ConfigError;
use crate::accounts::BoxFuture;
use crate::secrets::read_secret;

/// Embedded PostgreSQL migrations (`crates/database/migrations/postgres`).
pub static POSTGRES_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("migrations/postgres");

/// Upper bound of rows returned by one listing.
pub const MAX_LIST: u32 = 200;

#[derive(Debug)]
pub enum CatalogError {
    Invalid(&'static str),
    /// The root CID is already recorded.
    Duplicate,
    Database(sqlx::Error),
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(m) => write!(f, "invalid object metadata: {m}"),
            Self::Duplicate => f.write_str("object already recorded"),
            Self::Database(e) => write!(f, "database error: {e}"),
        }
    }
}

impl std::error::Error for CatalogError {}

impl From<sqlx::Error> for CatalogError {
    fn from(e: sqlx::Error) -> Self {
        if let sqlx::Error::Database(db) = &e
            && db.is_unique_violation()
        {
            return Self::Duplicate;
        }
        Self::Database(e)
    }
}

/// Metadata of a freshly uploaded object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewObject {
    pub owner_id: u64,
    pub object_id: String,
    pub root_cid: String,
    /// `BackendKind` in snake_case (`mock`, `kubo_rpc`, ...).
    pub backend: String,
    pub crypto_mode: String,
    pub sealed_format_version: u8,
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub original_size: u64,
    pub compressed_size: u64,
    pub sealed_size: u64,
    /// Serialized `SegmentPlan` (JSON object).
    pub encryption_plan: Value,
}

/// A stored row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRecord {
    pub id: i64,
    pub created_unix: i64,
    pub object: NewObject,
}

impl ObjectRecord {
    /// JSON for the owner's listing (nonce/tag are public AEAD parameters).
    pub fn to_json(&self) -> Value {
        let o = &self.object;
        json!({
            "id": self.id,
            "object_id": o.object_id,
            "ipfs_cid": o.root_cid,
            "backend": o.backend,
            "crypto_mode": o.crypto_mode,
            "sealed_format_version": o.sealed_format_version,
            "nonce_hex": hex(&o.nonce),
            "tag_hex": hex(&o.tag),
            "original_size_bytes": o.original_size,
            "compressed_size_bytes": o.compressed_size,
            "sealed_size_bytes": o.sealed_size,
            "encryption_plan": o.encryption_plan,
            "created_at_unix": self.created_unix,
        })
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn is_object_id(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn to_i64(v: u64, what: &'static str) -> Result<i64, CatalogError> {
    i64::try_from(v).map_err(|_| CatalogError::Invalid(what))
}

/// Mirrors the CHECK constraints of the migration, so the in-memory catalog behaves
/// like PostgreSQL and bad input fails before reaching the database.
pub fn validate(o: &NewObject) -> Result<(), CatalogError> {
    if o.owner_id == 0 {
        return Err(CatalogError::Invalid("owner_id"));
    }
    to_i64(o.owner_id, "owner_id")?;
    if !is_object_id(&o.object_id) {
        return Err(CatalogError::Invalid("object_id"));
    }
    if !(8..=128).contains(&o.root_cid.len())
        || !o.root_cid.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err(CatalogError::Invalid("root_cid"));
    }
    if !(1..=32).contains(&o.backend.len())
        || !o
            .backend
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'_')
    {
        return Err(CatalogError::Invalid("backend"));
    }
    if !(1..=32).contains(&o.crypto_mode.len()) {
        return Err(CatalogError::Invalid("crypto_mode"));
    }
    if o.sealed_format_version == 0 {
        return Err(CatalogError::Invalid("sealed_format_version"));
    }
    if o.original_size == 0 || o.compressed_size == 0 || o.sealed_size <= o.compressed_size {
        return Err(CatalogError::Invalid("sizes"));
    }
    to_i64(o.original_size, "original_size")?;
    to_i64(o.sealed_size, "sealed_size")?;
    if !o.encryption_plan.is_object() {
        return Err(CatalogError::Invalid("encryption_plan"));
    }
    Ok(())
}

/// Object metadata store used by the web layer (PostgreSQL or in-memory fake).
pub trait ObjectCatalog: Send + Sync {
    /// Store label reported to clients (`postgresql`, `memory`).
    fn kind(&self) -> &'static str;
    /// Insert a row; returns its id.
    fn record<'a>(&'a self, object: &'a NewObject) -> BoxFuture<'a, Result<i64, CatalogError>>;
    /// Newest first, at most `limit` (capped at [`MAX_LIST`]).
    fn list(
        &self,
        owner_id: u64,
        limit: u32,
    ) -> BoxFuture<'_, Result<Vec<ObjectRecord>, CatalogError>>;
    /// The owner's row for `root_cid`; `None` if absent or owned by someone else.
    fn find<'a>(
        &'a self,
        owner_id: u64,
        root_cid: &'a str,
    ) -> BoxFuture<'a, Result<Option<ObjectRecord>, CatalogError>>;
}

/// Connection options from `TODO_POSTGRES_URL` + `TODO_POSTGRES_PASSWORD(_FILE)`.
/// `Ok(None)` when the URL is unset (metadata store disabled).
pub fn postgres_options_from_env() -> Result<Option<PgConnectOptions>, ConfigError> {
    let Ok(url) = std::env::var("TODO_POSTGRES_URL") else {
        return Ok(None);
    };
    let url = Zeroizing::new(url);
    let password = read_secret("TODO_POSTGRES_PASSWORD")?;
    postgres_options(&url, password.as_deref().map(String::as_str)).map(Some)
}

/// A password embedded in the URL is rejected (it would leak through `ps`, history and
/// logs); use the password (file) variable instead.
pub fn postgres_options(
    url: &str,
    password: Option<&str>,
) -> Result<PgConnectOptions, ConfigError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| ConfigError("TODO_POSTGRES_URL must be postgres://...".into()))?;
    if scheme != "postgres" && scheme != "postgresql" {
        return Err(ConfigError(
            "TODO_POSTGRES_URL must be postgres://...".into(),
        ));
    }
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    let has_url_password = authority
        .rsplit_once('@')
        .is_some_and(|(userinfo, _)| userinfo.contains(':'));
    let has_query_password = rest
        .split_once('?')
        .is_some_and(|(_, q)| q.split('&').any(|kv| kv.starts_with("password=")));
    if has_url_password || has_query_password {
        return Err(ConfigError(
            "TODO_POSTGRES_URL must not contain a password; use TODO_POSTGRES_PASSWORD_FILE".into(),
        ));
    }
    let url = format!("postgres://{rest}");
    let mut opts = PgConnectOptions::from_str(&url)
        .map_err(|_| ConfigError("TODO_POSTGRES_URL is not a valid URL".into()))?
        .application_name("todo")
        .disable_statement_logging();
    if let Some(pw) = password {
        opts = opts.password(pw);
    }
    Ok(opts)
}

/// Catalog from the environment: `None` when `TODO_POSTGRES_URL` is unset.
pub async fn catalog_from_env() -> Result<Option<PgCatalog>, ConfigError> {
    let Some(opts) = postgres_options_from_env()? else {
        return Ok(None);
    };
    PgCatalog::connect(opts)
        .await
        .map(Some)
        .map_err(|e| ConfigError(format!("PostgreSQL: {e}")))
}

pub struct PgCatalog {
    pool: PgPool,
}

const SELECT_COLUMNS: &str = "id, owner_id, object_id, root_cid, backend, crypto_mode, \
sealed_format_version, nonce, tag, original_size, compressed_size, sealed_size, \
encryption_plan, floor(extract(epoch FROM created_at))::BIGINT AS created_unix";

impl PgCatalog {
    pub async fn connect(opts: PgConnectOptions) -> Result<Self, CatalogError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(opts)
            .await?;
        Ok(Self { pool })
    }

    pub fn with_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<(), CatalogError> {
        POSTGRES_MIGRATOR
            .run(&self.pool)
            .await
            .map_err(|e| CatalogError::Database(e.into()))
    }
}

fn from_row(row: &PgRow) -> Result<ObjectRecord, CatalogError> {
    let bad = |what| CatalogError::Invalid(what);
    let u = |v: i64, what| u64::try_from(v).map_err(|_| bad(what));
    let nonce: Vec<u8> = row.try_get("nonce")?;
    let tag: Vec<u8> = row.try_get("tag")?;
    let version: i16 = row.try_get("sealed_format_version")?;
    let Json(plan): Json<Value> = row.try_get("encryption_plan")?;
    Ok(ObjectRecord {
        id: row.try_get("id")?,
        created_unix: row.try_get("created_unix")?,
        object: NewObject {
            owner_id: u(row.try_get("owner_id")?, "owner_id")?,
            object_id: row.try_get("object_id")?,
            root_cid: row.try_get("root_cid")?,
            backend: row.try_get("backend")?,
            crypto_mode: row.try_get("crypto_mode")?,
            sealed_format_version: u8::try_from(version).map_err(|_| bad("version"))?,
            nonce: nonce.try_into().map_err(|_| bad("nonce"))?,
            tag: tag.try_into().map_err(|_| bad("tag"))?,
            original_size: u(row.try_get("original_size")?, "original_size")?,
            compressed_size: u(row.try_get("compressed_size")?, "compressed_size")?,
            sealed_size: u(row.try_get("sealed_size")?, "sealed_size")?,
            encryption_plan: plan,
        },
    })
}

impl ObjectCatalog for PgCatalog {
    fn kind(&self) -> &'static str {
        "postgresql"
    }

    fn record<'a>(&'a self, o: &'a NewObject) -> BoxFuture<'a, Result<i64, CatalogError>> {
        Box::pin(async move {
            validate(o)?;
            let id: i64 = sqlx::query_scalar(
                "INSERT INTO objects (owner_id, object_id, root_cid, backend, crypto_mode, \
                 sealed_format_version, nonce, tag, original_size, compressed_size, \
                 sealed_size, encryption_plan) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id",
            )
            .bind(to_i64(o.owner_id, "owner_id")?)
            .bind(&o.object_id)
            .bind(&o.root_cid)
            .bind(&o.backend)
            .bind(&o.crypto_mode)
            .bind(i16::from(o.sealed_format_version))
            .bind(&o.nonce[..])
            .bind(&o.tag[..])
            .bind(to_i64(o.original_size, "original_size")?)
            .bind(to_i64(o.compressed_size, "compressed_size")?)
            .bind(to_i64(o.sealed_size, "sealed_size")?)
            .bind(Json(&o.encryption_plan))
            .fetch_one(&self.pool)
            .await?;
            Ok(id)
        })
    }

    fn list(
        &self,
        owner_id: u64,
        limit: u32,
    ) -> BoxFuture<'_, Result<Vec<ObjectRecord>, CatalogError>> {
        Box::pin(async move {
            let owner = to_i64(owner_id, "owner_id")?;
            let sql = format!(
                "SELECT {SELECT_COLUMNS} FROM objects WHERE owner_id = $1 \
                 ORDER BY id DESC LIMIT $2"
            );
            let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(owner)
                .bind(i64::from(limit.min(MAX_LIST)))
                .fetch_all(&self.pool)
                .await?;
            rows.iter().map(from_row).collect()
        })
    }

    fn find<'a>(
        &'a self,
        owner_id: u64,
        root_cid: &'a str,
    ) -> BoxFuture<'a, Result<Option<ObjectRecord>, CatalogError>> {
        Box::pin(async move {
            let owner = to_i64(owner_id, "owner_id")?;
            let sql = format!(
                "SELECT {SELECT_COLUMNS} FROM objects WHERE owner_id = $1 AND root_cid = $2"
            );
            let row = sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(owner)
                .bind(root_cid)
                .fetch_optional(&self.pool)
                .await?;
            row.as_ref().map(from_row).transpose()
        })
    }
}

/// In-memory catalog with the same validation and uniqueness rules (tests, demos).
#[derive(Default)]
pub struct MemoryCatalog {
    rows: Mutex<Vec<ObjectRecord>>,
}

impl MemoryCatalog {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ObjectCatalog for MemoryCatalog {
    fn kind(&self) -> &'static str {
        "memory"
    }

    fn record<'a>(&'a self, o: &'a NewObject) -> BoxFuture<'a, Result<i64, CatalogError>> {
        Box::pin(async move {
            validate(o)?;
            let mut rows = self.rows.lock().unwrap_or_else(|e| e.into_inner());
            if rows.iter().any(|r| r.object.root_cid == o.root_cid) {
                return Err(CatalogError::Duplicate);
            }
            let id = rows.len() as i64 + 1;
            let created_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64);
            rows.push(ObjectRecord {
                id,
                created_unix,
                object: o.clone(),
            });
            Ok(id)
        })
    }

    fn list(
        &self,
        owner_id: u64,
        limit: u32,
    ) -> BoxFuture<'_, Result<Vec<ObjectRecord>, CatalogError>> {
        Box::pin(async move {
            let rows = self.rows.lock().unwrap_or_else(|e| e.into_inner());
            Ok(rows
                .iter()
                .rev()
                .filter(|r| r.object.owner_id == owner_id)
                .take(limit.min(MAX_LIST) as usize)
                .cloned()
                .collect())
        })
    }

    fn find<'a>(
        &'a self,
        owner_id: u64,
        root_cid: &'a str,
    ) -> BoxFuture<'a, Result<Option<ObjectRecord>, CatalogError>> {
        Box::pin(async move {
            let rows = self.rows.lock().unwrap_or_else(|e| e.into_inner());
            Ok(rows
                .iter()
                .find(|r| r.object.owner_id == owner_id && r.object.root_cid == root_cid)
                .cloned())
        })
    }
}

#[cfg(test)]
pub(crate) fn sample(owner_id: u64, cid: &str) -> NewObject {
    NewObject {
        owner_id,
        object_id: "report.pdf".into(),
        root_cid: cid.into(),
        backend: "mock".into(),
        crypto_mode: "aes-gcm-siv".into(),
        sealed_format_version: 1,
        nonce: [7; 12],
        tag: [9; 16],
        original_size: 1000,
        compressed_size: 400,
        sealed_size: 461,
        encryption_plan: json!({"execution": "sequential", "reason": "below_threshold"}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_mirrors_schema() {
        let ok = sample(
            1,
            "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        );
        assert!(validate(&ok).is_ok());
        let cases: [fn(&mut NewObject); 8] = [
            |o| o.owner_id = 0,
            |o| o.object_id = "../etc".into(),
            |o| o.root_cid = "short".into(),
            |o| o.root_cid = "bafy/../x".into(),
            |o| o.backend = "Kubo RPC".into(),
            |o| o.sealed_size = o.compressed_size,
            |o| o.original_size = u64::MAX,
            |o| o.encryption_plan = json!("x"),
        ];
        for f in cases {
            let mut o = ok.clone();
            f(&mut o);
            assert!(
                matches!(validate(&o), Err(CatalogError::Invalid(_))),
                "{o:?}"
            );
        }
    }

    #[tokio::test]
    async fn memory_catalog_is_owner_scoped() {
        let c = MemoryCatalog::new();
        let a = sample(1, "bafyaaaaaaaaaaaa");
        let b = sample(2, "bafybbbbbbbbbbbb");
        assert_eq!(c.record(&a).await.unwrap(), 1);
        assert_eq!(c.record(&b).await.unwrap(), 2);
        assert!(matches!(c.record(&a).await, Err(CatalogError::Duplicate)));
        assert_eq!(c.list(1, 10).await.unwrap().len(), 1);
        assert!(c.find(1, "bafybbbbbbbbbbbb").await.unwrap().is_none());
        let r = c.find(2, "bafybbbbbbbbbbbb").await.unwrap().unwrap();
        assert_eq!(r.to_json()["nonce_hex"], "070707070707070707070707");
    }

    #[test]
    fn postgres_url_rules() {
        assert!(postgres_options("postgres://todo_app@127.0.0.1/todo", Some("x")).is_ok());
        assert!(postgres_options("postgresql://todo_app@127.0.0.1:5432/todo", None).is_ok());
        assert!(postgres_options("postgres://todo_app:pw@127.0.0.1/todo", None).is_err());
        assert!(postgres_options("postgres://todo_app@h/todo?password=pw", None).is_err());
        assert!(postgres_options("mysql://todo_app@127.0.0.1/todo", None).is_err());
        assert!(postgres_options("127.0.0.1/todo", None).is_err());
    }
}
