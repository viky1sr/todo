//! Layer 4: durable metadata and upload lifecycle of sealed objects in PostgreSQL.
//!
//! Production uploads use a journal-backed state machine:
//! `WRITING -> PUBLISHING -> COMMITTED`. The journal is updated with the deterministic
//! IPFS root and complete public object metadata **before** the recursive pin is made
//! visible. If the process dies after that point, startup reconciliation can verify the
//! root, re-pin it idempotently and finish the PostgreSQL commit. `ABORTED` is terminal.
//!
//! The immutable object row carries `(owner_id, object_id, generation)`. Repair of a
//! byte-identical replica never creates a new generation; a new upload/version does.
//! No plaintext or encryption key is stored here.

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

/// Upper bound of rows returned by one listing or recovery scan.
pub const MAX_LIST: u32 = 200;
pub const MAX_RECOVERY: u32 = 200;
/// Writer leases prevent one instance from aborting another instance's live upload.
pub const MIN_UPLOAD_LEASE_SECS: u64 = 30;
pub const MAX_UPLOAD_LEASE_SECS: u64 = 60 * 60;

#[derive(Debug)]
pub enum CatalogError {
    Invalid(&'static str),
    /// A unique object root, generation or active upload already exists.
    Duplicate,
    Database(sqlx::Error),
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(m) => write!(f, "invalid object metadata: {m}"),
            Self::Duplicate => f.write_str("object or upload transaction already exists"),
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

/// Canonical lifecycle of an immutable object generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectState {
    Committed,
    Healthy,
    Degraded,
    Suspect,
    Corrupted,
    Repairing,
    Unrecoverable,
}

impl ObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Suspect => "suspect",
            Self::Corrupted => "corrupted",
            Self::Repairing => "repairing",
            Self::Unrecoverable => "unrecoverable",
        }
    }

    fn from_db(value: &str) -> Result<Self, CatalogError> {
        match value {
            "committed" => Ok(Self::Committed),
            "healthy" => Ok(Self::Healthy),
            "degraded" => Ok(Self::Degraded),
            "suspect" => Ok(Self::Suspect),
            "corrupted" => Ok(Self::Corrupted),
            "repairing" => Ok(Self::Repairing),
            "unrecoverable" => Ok(Self::Unrecoverable),
            _ => Err(CatalogError::Invalid("object state")),
        }
    }
}

/// Durable upload-journal state. Only `Writing` and `Publishing` need startup recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadState {
    Writing,
    Publishing,
    Committed,
    Aborted,
}

impl UploadState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Writing => "writing",
            Self::Publishing => "publishing",
            Self::Committed => "committed",
            Self::Aborted => "aborted",
        }
    }

    fn from_db(value: &str) -> Result<Self, CatalogError> {
        match value {
            "writing" => Ok(Self::Writing),
            "publishing" => Ok(Self::Publishing),
            "committed" => Ok(Self::Committed),
            "aborted" => Ok(Self::Aborted),
            _ => Err(CatalogError::Invalid("upload state")),
        }
    }
}

/// Metadata of a sealed immutable object generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewObject {
    pub owner_id: u64,
    pub object_id: String,
    /// Monotonic per `(owner_id, object_id)`. `repair != versioning`.
    pub generation: u64,
    pub state: ObjectState,
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

/// One durable upload transaction. `object` is present from `Publishing` onward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadTransaction {
    pub transaction_id: String,
    pub owner_id: u64,
    pub object_id: String,
    pub generation: u64,
    pub state: UploadState,
    pub object: Option<NewObject>,
    /// Writer lease. A `WRITING` transaction is recoverable only after this instant.
    pub lease_expires_unix: i64,
    pub updated_unix: i64,
}

/// A stored immutable object row.
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
            "generation": o.generation,
            "state": o.state.as_str(),
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

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn lease_deadline(lease_seconds: u64) -> Result<i64, CatalogError> {
    if !(MIN_UPLOAD_LEASE_SECS..=MAX_UPLOAD_LEASE_SECS).contains(&lease_seconds) {
        return Err(CatalogError::Invalid("upload lease"));
    }
    let lease = i64::try_from(lease_seconds).map_err(|_| CatalogError::Invalid("upload lease"))?;
    unix_now()
        .checked_add(lease)
        .ok_or(CatalogError::Invalid("upload lease"))
}

fn new_transaction_id() -> Result<String, CatalogError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| CatalogError::Invalid("transaction entropy"))?;
    Ok(hex(&bytes))
}

fn safe_error_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '\0'))
        .take(256)
        .collect()
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
    if o.generation == 0 {
        return Err(CatalogError::Invalid("generation"));
    }
    to_i64(o.generation, "generation")?;
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
    to_i64(o.compressed_size, "compressed_size")?;
    to_i64(o.sealed_size, "sealed_size")?;
    if !o.encryption_plan.is_object() {
        return Err(CatalogError::Invalid("encryption_plan"));
    }
    Ok(())
}

/// Object metadata + lifecycle store used by the web layer (PostgreSQL or in-memory).
pub trait ObjectCatalog: Send + Sync {
    /// Store label reported to clients (`postgresql`, `memory`).
    fn kind(&self) -> &'static str;

    /// Legacy/direct insert path. Production web uploads should use the journal methods.
    fn record<'a>(&'a self, object: &'a NewObject) -> BoxFuture<'a, Result<i64, CatalogError>>;

    /// Reserve the next generation and persist `WRITING` before durable publication.
    fn begin_upload<'a>(
        &'a self,
        owner_id: u64,
        object_id: &'a str,
        lease_seconds: u64,
    ) -> BoxFuture<'a, Result<UploadTransaction, CatalogError>>;

    /// Extend the lease of a live `WRITING` transaction. A failed heartbeat causes the
    /// uploader to stop before publication, so another instance can safely recover it.
    fn renew_upload_lease<'a>(
        &'a self,
        transaction_id: &'a str,
        lease_seconds: u64,
    ) -> BoxFuture<'a, Result<(), CatalogError>>;

    /// Persist the deterministic root + complete public metadata and transition to
    /// `PUBLISHING`. Call this before the recursive IPFS pin.
    fn mark_publishing<'a>(
        &'a self,
        transaction_id: &'a str,
        object: &'a NewObject,
    ) -> BoxFuture<'a, Result<(), CatalogError>>;

    /// Atomically create the immutable object row and mark the journal `COMMITTED`.
    /// Idempotent for an already committed transaction.
    fn commit_upload<'a>(
        &'a self,
        transaction_id: &'a str,
    ) -> BoxFuture<'a, Result<i64, CatalogError>>;

    /// Abort only a definitely pre-publish writer. Returns `false` if it already advanced
    /// to `PUBLISHING`/terminal state, which preserves ambiguous successful journal writes.
    fn abort_writing<'a>(
        &'a self,
        transaction_id: &'a str,
        reason: &'a str,
    ) -> BoxFuture<'a, Result<bool, CatalogError>>;

    /// Terminal rollback marker for recovery/integrity decisions that are allowed to
    /// abort either `WRITING` or `PUBLISHING`.
    fn abort_upload<'a>(
        &'a self,
        transaction_id: &'a str,
        reason: &'a str,
    ) -> BoxFuture<'a, Result<(), CatalogError>>;

    /// Compare-and-set recovery for an expired writer lease. Returns `false` if the
    /// uploader renewed its lease or advanced state after the recovery scan.
    fn abort_expired_writing<'a>(
        &'a self,
        transaction_id: &'a str,
        reason: &'a str,
    ) -> BoxFuture<'a, Result<bool, CatalogError>>;

    /// Active journal entries left by a previous process, oldest first.
    fn pending_uploads(
        &self,
        limit: u32,
    ) -> BoxFuture<'_, Result<Vec<UploadTransaction>, CatalogError>>;

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

const SELECT_COLUMNS: &str = "id, owner_id, object_id, generation, state, root_cid, backend, crypto_mode, \
sealed_format_version, nonce, tag, original_size, compressed_size, sealed_size, \
encryption_plan, floor(extract(epoch FROM created_at))::BIGINT AS created_unix";

const TX_SELECT_COLUMNS: &str = "transaction_id, owner_id, object_id, generation, state, root_cid, backend, \
crypto_mode, sealed_format_version, nonce, tag, original_size, compressed_size, sealed_size, \
encryption_plan, floor(extract(epoch FROM lease_expires_at))::BIGINT AS lease_expires_unix, \
floor(extract(epoch FROM updated_at))::BIGINT AS updated_unix";

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
    let state: String = row.try_get("state")?;
    Ok(ObjectRecord {
        id: row.try_get("id")?,
        created_unix: row.try_get("created_unix")?,
        object: NewObject {
            owner_id: u(row.try_get("owner_id")?, "owner_id")?,
            object_id: row.try_get("object_id")?,
            generation: u(row.try_get("generation")?, "generation")?,
            state: ObjectState::from_db(&state)?,
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

fn transaction_from_row(row: &PgRow) -> Result<UploadTransaction, CatalogError> {
    let bad = |what| CatalogError::Invalid(what);
    let u = |v: i64, what| u64::try_from(v).map_err(|_| bad(what));
    let owner_id = u(row.try_get("owner_id")?, "owner_id")?;
    let object_id: String = row.try_get("object_id")?;
    let generation = u(row.try_get("generation")?, "generation")?;
    let state_text: String = row.try_get("state")?;
    let state = UploadState::from_db(&state_text)?;
    let root_cid: Option<String> = row.try_get("root_cid")?;

    let object = match root_cid {
        None => None,
        Some(root_cid) => {
            let backend: Option<String> = row.try_get("backend")?;
            let crypto_mode: Option<String> = row.try_get("crypto_mode")?;
            let version: Option<i16> = row.try_get("sealed_format_version")?;
            let nonce: Option<Vec<u8>> = row.try_get("nonce")?;
            let tag: Option<Vec<u8>> = row.try_get("tag")?;
            let original: Option<i64> = row.try_get("original_size")?;
            let compressed: Option<i64> = row.try_get("compressed_size")?;
            let sealed: Option<i64> = row.try_get("sealed_size")?;
            let plan: Option<Json<Value>> = row.try_get("encryption_plan")?;
            Some(NewObject {
                owner_id,
                object_id: object_id.clone(),
                generation,
                state: ObjectState::Healthy,
                root_cid,
                backend: backend.ok_or_else(|| bad("transaction backend"))?,
                crypto_mode: crypto_mode.ok_or_else(|| bad("transaction crypto_mode"))?,
                sealed_format_version: u8::try_from(
                    version.ok_or_else(|| bad("transaction version"))?,
                )
                .map_err(|_| bad("transaction version"))?,
                nonce: nonce
                    .ok_or_else(|| bad("transaction nonce"))?
                    .try_into()
                    .map_err(|_| bad("transaction nonce"))?,
                tag: tag
                    .ok_or_else(|| bad("transaction tag"))?
                    .try_into()
                    .map_err(|_| bad("transaction tag"))?,
                original_size: u(
                    original.ok_or_else(|| bad("transaction original_size"))?,
                    "original_size",
                )?,
                compressed_size: u(
                    compressed.ok_or_else(|| bad("transaction compressed_size"))?,
                    "compressed_size",
                )?,
                sealed_size: u(
                    sealed.ok_or_else(|| bad("transaction sealed_size"))?,
                    "sealed_size",
                )?,
                encryption_plan: plan
                    .ok_or_else(|| bad("transaction encryption_plan"))?
                    .0,
            })
        }
    };

    Ok(UploadTransaction {
        transaction_id: row.try_get("transaction_id")?,
        owner_id,
        object_id,
        generation,
        state,
        object,
        lease_expires_unix: row.try_get("lease_expires_unix")?,
        updated_unix: row.try_get("updated_unix")?,
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
                "INSERT INTO objects (owner_id, object_id, generation, state, root_cid, backend, crypto_mode, \
                 sealed_format_version, nonce, tag, original_size, compressed_size, sealed_size, encryption_plan) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING id",
            )
            .bind(to_i64(o.owner_id, "owner_id")?)
            .bind(&o.object_id)
            .bind(to_i64(o.generation, "generation")?)
            .bind(o.state.as_str())
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

    fn begin_upload<'a>(
        &'a self,
        owner_id: u64,
        object_id: &'a str,
        lease_seconds: u64,
    ) -> BoxFuture<'a, Result<UploadTransaction, CatalogError>> {
        Box::pin(async move {
            if owner_id == 0 || !is_object_id(object_id) {
                return Err(CatalogError::Invalid("upload identity"));
            }
            let lease_deadline = lease_deadline(lease_seconds)?;
            let owner = to_i64(owner_id, "owner_id")?;
            let transaction_id = new_transaction_id()?;
            let mut tx = self.pool.begin().await?;

            // Serialize generation reservation for this logical object without locking
            // unrelated objects. `hashtextextended` returns a deterministic BIGINT key.
            let _ = sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, $2))")
                .bind(object_id)
                .bind(owner)
                .fetch_optional(&mut *tx)
                .await?;

            // A different instance may have died without restarting the cluster. Reclaim
            // only a writer whose lease is still expired while we hold the per-object
            // advisory lock. Aborted generations remain in history and are never reused.
            sqlx::query(
                "UPDATE object_upload_transactions \
                 SET state = 'aborted', last_error = 'expired_writer_lease_reclaimed_on_begin', \
                     updated_at = now() \
                 WHERE owner_id = $1 AND object_id = $2 AND state = 'writing' \
                   AND lease_expires_at <= now()",
            )
            .bind(owner)
            .bind(object_id)
            .execute(&mut *tx)
            .await?;

            let generation: i64 = sqlx::query_scalar(
                "SELECT GREATEST(\
                    COALESCE((SELECT MAX(generation) FROM objects WHERE owner_id = $1 AND object_id = $2), 0), \
                    COALESCE((SELECT MAX(generation) FROM object_upload_transactions WHERE owner_id = $1 AND object_id = $2), 0)\
                 ) + 1",
            )
            .bind(owner)
            .bind(object_id)
            .fetch_one(&mut *tx)
            .await?;

            sqlx::query(
                "INSERT INTO object_upload_transactions \
                 (transaction_id, owner_id, object_id, generation, state, lease_expires_at) \
                 VALUES ($1, $2, $3, $4, 'writing', to_timestamp($5))",
            )
            .bind(&transaction_id)
            .bind(owner)
            .bind(object_id)
            .bind(generation)
            .bind(lease_deadline)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;

            Ok(UploadTransaction {
                transaction_id,
                owner_id,
                object_id: object_id.to_owned(),
                generation: u64::try_from(generation)
                    .map_err(|_| CatalogError::Invalid("generation"))?,
                state: UploadState::Writing,
                object: None,
                lease_expires_unix: lease_deadline,
                updated_unix: unix_now(),
            })
        })
    }

    fn renew_upload_lease<'a>(
        &'a self,
        transaction_id: &'a str,
        lease_seconds: u64,
    ) -> BoxFuture<'a, Result<(), CatalogError>> {
        Box::pin(async move {
            let lease_deadline = lease_deadline(lease_seconds)?;
            let changed = sqlx::query(
                "UPDATE object_upload_transactions \
                 SET lease_expires_at = to_timestamp($2), updated_at = now() \
                 WHERE transaction_id = $1 AND state = 'writing'",
            )
            .bind(transaction_id)
            .bind(lease_deadline)
            .execute(&self.pool)
            .await?;
            if changed.rows_affected() == 1 {
                Ok(())
            } else {
                Err(CatalogError::Invalid("upload lease renewal"))
            }
        })
    }

    fn mark_publishing<'a>(
        &'a self,
        transaction_id: &'a str,
        o: &'a NewObject,
    ) -> BoxFuture<'a, Result<(), CatalogError>> {
        Box::pin(async move {
            validate(o)?;
            let result = sqlx::query(
                "UPDATE object_upload_transactions SET \
                    state = 'publishing', root_cid = $2, backend = $3, crypto_mode = $4, \
                    sealed_format_version = $5, nonce = $6, tag = $7, original_size = $8, \
                    compressed_size = $9, sealed_size = $10, encryption_plan = $11, \
                    last_error = NULL, updated_at = now() \
                 WHERE transaction_id = $1 AND owner_id = $12 AND object_id = $13 AND generation = $14 \
                   AND state IN ('writing', 'publishing')",
            )
            .bind(transaction_id)
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
            .bind(to_i64(o.owner_id, "owner_id")?)
            .bind(&o.object_id)
            .bind(to_i64(o.generation, "generation")?)
            .execute(&self.pool)
            .await?;
            if result.rows_affected() == 1 {
                Ok(())
            } else {
                Err(CatalogError::Invalid("upload transition to publishing"))
            }
        })
    }

    fn commit_upload<'a>(
        &'a self,
        transaction_id: &'a str,
    ) -> BoxFuture<'a, Result<i64, CatalogError>> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await?;
            let state: Option<String> = sqlx::query_scalar(
                "SELECT state FROM object_upload_transactions WHERE transaction_id = $1 FOR UPDATE",
            )
            .bind(transaction_id)
            .fetch_optional(&mut *tx)
            .await?;
            let state = state.ok_or(CatalogError::Invalid("unknown upload transaction"))?;

            if state == "committed" {
                let id: Option<i64> =
                    sqlx::query_scalar("SELECT id FROM objects WHERE transaction_id = $1")
                        .bind(transaction_id)
                        .fetch_optional(&mut *tx)
                        .await?;
                tx.commit().await?;
                return id.ok_or(CatalogError::Invalid("committed upload missing object row"));
            }
            if state != "publishing" {
                return Err(CatalogError::Invalid("upload is not publishing"));
            }

            let id: i64 = sqlx::query_scalar(
                "INSERT INTO objects \
                 (owner_id, object_id, generation, state, root_cid, backend, crypto_mode, \
                  sealed_format_version, nonce, tag, original_size, compressed_size, sealed_size, \
                  encryption_plan, transaction_id) \
                 SELECT owner_id, object_id, generation, 'healthy', root_cid, backend, crypto_mode, \
                        sealed_format_version, nonce, tag, original_size, compressed_size, sealed_size, \
                        encryption_plan, transaction_id \
                 FROM object_upload_transactions \
                 WHERE transaction_id = $1 AND state = 'publishing' \
                 RETURNING id",
            )
            .bind(transaction_id)
            .fetch_one(&mut *tx)
            .await?;

            let changed = sqlx::query(
                "UPDATE object_upload_transactions \
                 SET state = 'committed', last_error = NULL, updated_at = now() \
                 WHERE transaction_id = $1 AND state = 'publishing'",
            )
            .bind(transaction_id)
            .execute(&mut *tx)
            .await?;
            if changed.rows_affected() != 1 {
                return Err(CatalogError::Invalid("upload commit transition"));
            }
            tx.commit().await?;
            Ok(id)
        })
    }

    fn abort_writing<'a>(
        &'a self,
        transaction_id: &'a str,
        reason: &'a str,
    ) -> BoxFuture<'a, Result<bool, CatalogError>> {
        Box::pin(async move {
            let reason = safe_error_reason(reason);
            let changed = sqlx::query(
                "UPDATE object_upload_transactions \
                 SET state = 'aborted', last_error = $2, updated_at = now() \
                 WHERE transaction_id = $1 AND state = 'writing'",
            )
            .bind(transaction_id)
            .bind(reason)
            .execute(&self.pool)
            .await?;
            Ok(changed.rows_affected() == 1)
        })
    }

    fn abort_upload<'a>(
        &'a self,
        transaction_id: &'a str,
        reason: &'a str,
    ) -> BoxFuture<'a, Result<(), CatalogError>> {
        Box::pin(async move {
            let reason = safe_error_reason(reason);
            sqlx::query(
                "UPDATE object_upload_transactions \
                 SET state = 'aborted', last_error = $2, updated_at = now() \
                 WHERE transaction_id = $1 AND state IN ('writing', 'publishing')",
            )
            .bind(transaction_id)
            .bind(reason)
            .execute(&self.pool)
            .await?;
            Ok(())
        })
    }

    fn abort_expired_writing<'a>(
        &'a self,
        transaction_id: &'a str,
        reason: &'a str,
    ) -> BoxFuture<'a, Result<bool, CatalogError>> {
        Box::pin(async move {
            let reason = safe_error_reason(reason);
            let changed = sqlx::query(
                "UPDATE object_upload_transactions \
                 SET state = 'aborted', last_error = $2, updated_at = now() \
                 WHERE transaction_id = $1 AND state = 'writing' AND lease_expires_at <= now()",
            )
            .bind(transaction_id)
            .bind(reason)
            .execute(&self.pool)
            .await?;
            Ok(changed.rows_affected() == 1)
        })
    }

    fn pending_uploads(
        &self,
        limit: u32,
    ) -> BoxFuture<'_, Result<Vec<UploadTransaction>, CatalogError>> {
        Box::pin(async move {
            let sql = format!(
                "SELECT {TX_SELECT_COLUMNS} FROM object_upload_transactions \
                 WHERE state = 'publishing' \
                    OR (state = 'writing' AND lease_expires_at <= now()) \
                 ORDER BY updated_at ASC, transaction_id ASC LIMIT $1"
            );
            let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(i64::from(limit.min(MAX_RECOVERY)))
                .fetch_all(&self.pool)
                .await?;
            rows.iter().map(transaction_from_row).collect()
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

#[derive(Default)]
pub struct MemoryCatalog {
    rows: Mutex<Vec<ObjectRecord>>,
    transactions: Mutex<Vec<UploadTransaction>>,
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
            if rows.iter().any(|r| {
                (r.object.owner_id == o.owner_id && r.object.root_cid == o.root_cid)
                    || (r.object.owner_id == o.owner_id
                        && r.object.object_id == o.object_id
                        && r.object.generation == o.generation)
            }) {
                return Err(CatalogError::Duplicate);
            }
            let id = rows.len() as i64 + 1;
            rows.push(ObjectRecord {
                id,
                created_unix: unix_now(),
                object: o.clone(),
            });
            Ok(id)
        })
    }

    fn begin_upload<'a>(
        &'a self,
        owner_id: u64,
        object_id: &'a str,
        lease_seconds: u64,
    ) -> BoxFuture<'a, Result<UploadTransaction, CatalogError>> {
        Box::pin(async move {
            if owner_id == 0 || !is_object_id(object_id) {
                return Err(CatalogError::Invalid("upload identity"));
            }
            let lease_expires_unix = lease_deadline(lease_seconds)?;
            let now = unix_now();
            let mut transactions = self.transactions.lock().unwrap_or_else(|e| e.into_inner());
            for tx in transactions.iter_mut().filter(|t| {
                t.owner_id == owner_id
                    && t.object_id == object_id
                    && t.state == UploadState::Writing
                    && t.lease_expires_unix <= now
            }) {
                tx.state = UploadState::Aborted;
                tx.updated_unix = now;
            }
            if transactions.iter().any(|t| {
                t.owner_id == owner_id
                    && t.object_id == object_id
                    && matches!(t.state, UploadState::Writing | UploadState::Publishing)
            }) {
                return Err(CatalogError::Duplicate);
            }
            let rows = self.rows.lock().unwrap_or_else(|e| e.into_inner());
            let max_row = rows
                .iter()
                .filter(|r| r.object.owner_id == owner_id && r.object.object_id == object_id)
                .map(|r| r.object.generation)
                .max()
                .unwrap_or(0);
            let max_tx = transactions
                .iter()
                .filter(|t| t.owner_id == owner_id && t.object_id == object_id)
                .map(|t| t.generation)
                .max()
                .unwrap_or(0);
            drop(rows);
            let generation = max_row
                .max(max_tx)
                .checked_add(1)
                .ok_or(CatalogError::Invalid("generation overflow"))?;
            let tx = UploadTransaction {
                transaction_id: new_transaction_id()?,
                owner_id,
                object_id: object_id.to_owned(),
                generation,
                state: UploadState::Writing,
                object: None,
                lease_expires_unix,
                updated_unix: unix_now(),
            };
            transactions.push(tx.clone());
            Ok(tx)
        })
    }

    fn renew_upload_lease<'a>(
        &'a self,
        transaction_id: &'a str,
        lease_seconds: u64,
    ) -> BoxFuture<'a, Result<(), CatalogError>> {
        Box::pin(async move {
            let lease_expires_unix = lease_deadline(lease_seconds)?;
            let mut transactions = self.transactions.lock().unwrap_or_else(|e| e.into_inner());
            let tx = transactions
                .iter_mut()
                .find(|t| t.transaction_id == transaction_id)
                .ok_or(CatalogError::Invalid("unknown upload transaction"))?;
            if tx.state != UploadState::Writing {
                return Err(CatalogError::Invalid("upload lease renewal"));
            }
            tx.lease_expires_unix = lease_expires_unix;
            tx.updated_unix = unix_now();
            Ok(())
        })
    }

    fn mark_publishing<'a>(
        &'a self,
        transaction_id: &'a str,
        o: &'a NewObject,
    ) -> BoxFuture<'a, Result<(), CatalogError>> {
        Box::pin(async move {
            validate(o)?;
            let mut transactions = self.transactions.lock().unwrap_or_else(|e| e.into_inner());
            let tx = transactions
                .iter_mut()
                .find(|t| t.transaction_id == transaction_id)
                .ok_or(CatalogError::Invalid("unknown upload transaction"))?;
            if tx.owner_id != o.owner_id
                || tx.object_id != o.object_id
                || tx.generation != o.generation
                || !matches!(tx.state, UploadState::Writing | UploadState::Publishing)
            {
                return Err(CatalogError::Invalid("upload transition to publishing"));
            }
            tx.state = UploadState::Publishing;
            tx.object = Some(o.clone());
            tx.updated_unix = unix_now();
            Ok(())
        })
    }

    fn commit_upload<'a>(
        &'a self,
        transaction_id: &'a str,
    ) -> BoxFuture<'a, Result<i64, CatalogError>> {
        Box::pin(async move {
            let mut transactions = self.transactions.lock().unwrap_or_else(|e| e.into_inner());
            let tx = transactions
                .iter_mut()
                .find(|t| t.transaction_id == transaction_id)
                .ok_or(CatalogError::Invalid("unknown upload transaction"))?;
            if tx.state == UploadState::Committed {
                let rows = self.rows.lock().unwrap_or_else(|e| e.into_inner());
                return rows
                    .iter()
                    .find(|r| {
                        r.object.owner_id == tx.owner_id
                            && r.object.object_id == tx.object_id
                            && r.object.generation == tx.generation
                    })
                    .map(|r| r.id)
                    .ok_or(CatalogError::Invalid("committed upload missing object row"));
            }
            if tx.state != UploadState::Publishing {
                return Err(CatalogError::Invalid("upload is not publishing"));
            }
            let object = tx
                .object
                .clone()
                .ok_or(CatalogError::Invalid("publishing metadata"))?;
            let mut rows = self.rows.lock().unwrap_or_else(|e| e.into_inner());
            if rows.iter().any(|r| {
                (r.object.owner_id == object.owner_id && r.object.root_cid == object.root_cid)
                    || (r.object.owner_id == object.owner_id
                        && r.object.object_id == object.object_id
                        && r.object.generation == object.generation)
            }) {
                return Err(CatalogError::Duplicate);
            }
            let id = rows.len() as i64 + 1;
            rows.push(ObjectRecord {
                id,
                created_unix: unix_now(),
                object,
            });
            tx.state = UploadState::Committed;
            tx.updated_unix = unix_now();
            Ok(id)
        })
    }

    fn abort_writing<'a>(
        &'a self,
        transaction_id: &'a str,
        reason: &'a str,
    ) -> BoxFuture<'a, Result<bool, CatalogError>> {
        Box::pin(async move {
            let mut transactions = self.transactions.lock().unwrap_or_else(|e| e.into_inner());
            let Some(tx) = transactions
                .iter_mut()
                .find(|t| t.transaction_id == transaction_id)
            else {
                return Ok(false);
            };
            if tx.state != UploadState::Writing {
                return Ok(false);
            }
            let _reason = safe_error_reason(reason);
            tx.state = UploadState::Aborted;
            tx.updated_unix = unix_now();
            Ok(true)
        })
    }

    fn abort_upload<'a>(
        &'a self,
        transaction_id: &'a str,
        _reason: &'a str,
    ) -> BoxFuture<'a, Result<(), CatalogError>> {
        Box::pin(async move {
            let mut transactions = self.transactions.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(tx) = transactions
                .iter_mut()
                .find(|t| t.transaction_id == transaction_id)
                && matches!(tx.state, UploadState::Writing | UploadState::Publishing)
            {
                tx.state = UploadState::Aborted;
                tx.updated_unix = unix_now();
            }
            Ok(())
        })
    }

    fn abort_expired_writing<'a>(
        &'a self,
        transaction_id: &'a str,
        reason: &'a str,
    ) -> BoxFuture<'a, Result<bool, CatalogError>> {
        Box::pin(async move {
            let now = unix_now();
            let mut transactions = self.transactions.lock().unwrap_or_else(|e| e.into_inner());
            let Some(tx) = transactions
                .iter_mut()
                .find(|t| t.transaction_id == transaction_id)
            else {
                return Ok(false);
            };
            if tx.state != UploadState::Writing || tx.lease_expires_unix > now {
                return Ok(false);
            }
            tx.state = UploadState::Aborted;
            tx.updated_unix = now;
            let _ = safe_error_reason(reason);
            Ok(true)
        })
    }

    fn pending_uploads(
        &self,
        limit: u32,
    ) -> BoxFuture<'_, Result<Vec<UploadTransaction>, CatalogError>> {
        Box::pin(async move {
            let now = unix_now();
            let transactions = self.transactions.lock().unwrap_or_else(|e| e.into_inner());
            let mut pending: Vec<_> = transactions
                .iter()
                .filter(|t| {
                    t.state == UploadState::Publishing
                        || (t.state == UploadState::Writing && t.lease_expires_unix <= now)
                })
                .cloned()
                .collect();
            pending.sort_by_key(|t| (t.updated_unix, t.transaction_id.clone()));
            pending.truncate(limit.min(MAX_RECOVERY) as usize);
            Ok(pending)
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
        generation: 1,
        state: ObjectState::Healthy,
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
        let cases: [fn(&mut NewObject); 9] = [
            |o| o.owner_id = 0,
            |o| o.object_id = "../etc".into(),
            |o| o.generation = 0,
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
    async fn memory_catalog_journal_is_generation_aware_and_idempotent() {
        let c = MemoryCatalog::new();
        let tx1 = c.begin_upload(1, "report.pdf", 120).await.unwrap();
        assert_eq!(tx1.generation, 1);
        assert!(matches!(
            c.begin_upload(1, "report.pdf", 120).await,
            Err(CatalogError::Duplicate)
        ));

        let mut object = sample(1, "bafyaaaaaaaaaaaa");
        object.generation = tx1.generation;
        c.mark_publishing(&tx1.transaction_id, &object)
            .await
            .unwrap();
        assert!(
            !c.abort_writing(&tx1.transaction_id, "ambiguous_mark_publishing")
                .await
                .unwrap(),
            "pre-publish cleanup must never roll back a transaction that already reached PUBLISHING"
        );
        let pending = c.pending_uploads(10).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].state, UploadState::Publishing);
        let id = c.commit_upload(&tx1.transaction_id).await.unwrap();
        assert_eq!(c.commit_upload(&tx1.transaction_id).await.unwrap(), id);
        assert!(c.pending_uploads(10).await.unwrap().is_empty());

        let tx2 = c.begin_upload(1, "report.pdf", 120).await.unwrap();
        assert_eq!(tx2.generation, 2);
        c.abort_upload(&tx2.transaction_id, "client disconnected")
            .await
            .unwrap();
        let tx3 = c.begin_upload(1, "report.pdf", 120).await.unwrap();
        assert_eq!(tx3.generation, 3, "aborted generations are never reused");
        assert!(c.pending_uploads(10).await.unwrap().is_empty());

        // Recovery only reclaims an actually expired writer lease. Renewal wins over
        // a stale scan and therefore must keep the transaction active.
        c.renew_upload_lease(&tx3.transaction_id, 120)
            .await
            .unwrap();
        assert!(!c
            .abort_expired_writing(&tx3.transaction_id, "must_not_reclaim")
            .await
            .unwrap());
        {
            let mut transactions = c.transactions.lock().unwrap_or_else(|e| e.into_inner());
            let tx = transactions
                .iter_mut()
                .find(|t| t.transaction_id == tx3.transaction_id)
                .unwrap();
            tx.lease_expires_unix = unix_now() - 1;
        }
        let pending = c.pending_uploads(10).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].transaction_id, tx3.transaction_id);
        assert!(c
            .abort_expired_writing(&tx3.transaction_id, "expired_test_lease")
            .await
            .unwrap());

        let tx4 = c.begin_upload(1, "report.pdf", 120).await.unwrap();
        assert_eq!(tx4.generation, 4);
        {
            let mut transactions = c.transactions.lock().unwrap_or_else(|e| e.into_inner());
            let tx = transactions
                .iter_mut()
                .find(|t| t.transaction_id == tx4.transaction_id)
                .unwrap();
            tx.lease_expires_unix = unix_now() - 1;
        }
        let tx5 = c.begin_upload(1, "report.pdf", 120).await.unwrap();
        assert_eq!(
            tx5.generation, 5,
            "begin_upload must reclaim an expired writer without reusing its generation"
        );
        assert!(matches!(
            c.begin_upload(1, "bad-lease", 1).await,
            Err(CatalogError::Invalid("upload lease"))
        ));
    }

    #[tokio::test]
    async fn memory_catalog_is_owner_scoped() {
        let c = MemoryCatalog::new();
        let a = sample(1, "bafyaaaaaaaaaaaa");
        let b = sample(2, "bafybbbbbbbbbbbb");
        let same_root_other_owner = sample(3, "bafyaaaaaaaaaaaa");
        assert_eq!(c.record(&a).await.unwrap(), 1);
        assert_eq!(c.record(&b).await.unwrap(), 2);
        assert_eq!(c.record(&same_root_other_owner).await.unwrap(), 3);
        assert!(matches!(c.record(&a).await, Err(CatalogError::Duplicate)));
        assert_eq!(c.list(1, 10).await.unwrap().len(), 1);
        assert!(c.find(1, "bafybbbbbbbbbbbb").await.unwrap().is_none());
        let r = c.find(2, "bafybbbbbbbbbbbb").await.unwrap().unwrap();
        assert_eq!(r.to_json()["nonce_hex"], "070707070707070707070707");
        assert_eq!(r.to_json()["generation"], 1);
        assert_eq!(r.to_json()["state"], "healthy");
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
