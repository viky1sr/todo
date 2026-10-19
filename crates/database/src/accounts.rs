//! Layer 3: user accounts in MariaDB.
//!
//! - Passwords: Argon2id (RFC 9106) PHC strings, m = 19 MiB, t = 2, p = 1 (OWASP
//!   minimum), hashed/verified on the blocking pool. Unknown usernames are verified
//!   against a dummy hash so response time does not reveal which accounts exist.
//! - PII (email, national ID / NIK): sealed with the project's AES-256-GCM-SIV
//!   (`todo_crypto::aes_gcm_siv_encrypt_sequential`, single message, one tag) under a
//!   dedicated key (`TODO_PII_KEY_HEX`, distinct from the object key). Stored layout
//!   `0x01 || nonce(12) || ciphertext || tag(16)`; AAD binds table, column and user id,
//!   so swapping blobs between rows or columns fails authentication.
//! - Connection: `TODO_MARIADB_URL` without a password, plus
//!   `TODO_MARIADB_PASSWORD_FILE` (owner-only file, see [`crate::secrets`]).

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use sqlx::mysql::{MySqlConnectOptions, MySqlPool, MySqlPoolOptions};
use sqlx::{ConnectOptions, Row};
use zeroize::Zeroizing;

use crate::ConfigError;
use crate::secrets::read_secret;

/// Embedded MariaDB migrations (`crates/rest/migrations/mariadb`).
pub static MARIADB_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("migrations/mariadb");

pub const PII_FORMAT_V1: u8 = 1;
const PII_NONCE_LEN: usize = 12;
const PII_TAG_LEN: usize = 16;
pub const MAX_PII_BYTES: usize = 254;

pub const ARGON2_M_KIB: u32 = 19 * 1024;
pub const ARGON2_T: u32 = 2;
pub const ARGON2_P: u32 = 1;
pub const MIN_PASSWORD_CHARS: usize = 12;
pub const MAX_PASSWORD_CHARS: usize = 128;

#[derive(Debug)]
pub enum AccountError {
    /// Input rejected; message is safe to show (never contains the input).
    Invalid(&'static str),
    DuplicateUsername,
    /// PII blob failed authentication (tampered, moved or wrong key).
    PiiIntegrity,
    Database(String),
    Internal(String),
}

impl std::fmt::Display for AccountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) => write!(f, "invalid input: {m}"),
            Self::DuplicateUsername => f.write_str("username already exists"),
            Self::PiiIntegrity => f.write_str("encrypted PII failed authentication"),
            Self::Database(m) => write!(f, "database error: {m}"),
            Self::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

impl std::error::Error for AccountError {}

impl From<sqlx::Error> for AccountError {
    fn from(e: sqlx::Error) -> Self {
        if e.as_database_error()
            .is_some_and(|d| d.is_unique_violation())
        {
            return Self::DuplicateUsername;
        }
        Self::Database(e.to_string())
    }
}

impl From<sqlx::migrate::MigrateError> for AccountError {
    fn from(e: sqlx::migrate::MigrateError) -> Self {
        Self::Database(e.to_string())
    }
}

// ---------------------------------------------------------------------------------------
// PII encryption
// ---------------------------------------------------------------------------------------

/// AES-256-GCM-SIV sealing of PII columns, bound to (table, column, row id).
pub struct PiiCipher {
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for PiiCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PiiCipher(<redacted>)")
    }
}

impl PiiCipher {
    pub fn new(key: &[u8]) -> Result<Self, ConfigError> {
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| ConfigError("PII key must be 32 bytes".into()))?;
        Ok(Self {
            key: Zeroizing::new(key),
        })
    }

    /// `TODO_PII_KEY_HEX` or `TODO_PII_KEY_HEX_FILE` (64 hex chars); `None` if unset.
    pub fn from_env() -> Result<Option<Self>, ConfigError> {
        let Some(hex) = read_secret("TODO_PII_KEY_HEX")? else {
            return Ok(None);
        };
        let key = Zeroizing::new(
            crate::decode_hex(&hex)
                .ok_or_else(|| ConfigError("TODO_PII_KEY_HEX must be hex".into()))?,
        );
        Self::new(&key).map(Some)
    }

    fn aad(table: &str, column: &str, row_id: u64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(32 + table.len() + column.len());
        aad.extend_from_slice(b"todo/pii/v1\0");
        aad.extend_from_slice(table.as_bytes());
        aad.push(0);
        aad.extend_from_slice(column.as_bytes());
        aad.push(0);
        aad.extend_from_slice(&row_id.to_be_bytes());
        aad
    }

    pub fn seal(
        &self,
        table: &str,
        column: &str,
        row_id: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AccountError> {
        let mut nonce = [0u8; PII_NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|e| AccountError::Internal(e.to_string()))?;
        let out = todo_crypto::aes_gcm_siv_encrypt_sequential(
            &self.key[..],
            &nonce,
            &Self::aad(table, column, row_id),
            plaintext,
        )
        .map_err(|e| AccountError::Internal(e.to_string()))?;
        let mut blob = Vec::with_capacity(1 + PII_NONCE_LEN + out.ciphertext.len() + PII_TAG_LEN);
        blob.push(PII_FORMAT_V1);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&out.ciphertext);
        blob.extend_from_slice(&out.tag);
        Ok(blob)
    }

    /// Plaintext is returned only after the tag verifies.
    pub fn open(
        &self,
        table: &str,
        column: &str,
        row_id: u64,
        blob: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AccountError> {
        if blob.len() < 1 + PII_NONCE_LEN + PII_TAG_LEN || blob[0] != PII_FORMAT_V1 {
            return Err(AccountError::PiiIntegrity);
        }
        let nonce: [u8; PII_NONCE_LEN] = blob[1..1 + PII_NONCE_LEN].try_into().unwrap();
        let (ct, tag) =
            blob[1 + PII_NONCE_LEN..].split_at(blob.len() - 1 - PII_NONCE_LEN - PII_TAG_LEN);
        let tag: [u8; PII_TAG_LEN] = tag.try_into().unwrap();
        todo_crypto::aes_gcm_siv_decrypt_sequential(
            &self.key[..],
            &nonce,
            &Self::aad(table, column, row_id),
            ct,
            &tag,
        )
        .map(Zeroizing::new)
        .map_err(|_| AccountError::PiiIntegrity)
    }
}

// ---------------------------------------------------------------------------------------
// Passwords and input validation
// ---------------------------------------------------------------------------------------

fn argon2() -> Argon2<'static> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, None).expect("valid Argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Argon2id PHC string with a random 128-bit salt (CPU-heavy: call off the async runtime).
pub fn hash_password(password: &str) -> Result<String, AccountError> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| AccountError::Internal(e.to_string()))?;
    let salt = SaltString::encode_b64(&salt).map_err(|e| AccountError::Internal(e.to_string()))?;
    argon2()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AccountError::Internal(e.to_string()))
}

/// Constant-time verification against a stored PHC string; malformed hashes fail.
pub fn verify_password(password: &str, phc: &str) -> bool {
    PasswordHash::new(phc).is_ok_and(|h| argon2().verify_password(password.as_bytes(), &h).is_ok())
}

/// Lowercase ASCII `[a-z0-9._-]`, 3..=32 characters, starting with a letter or digit.
pub fn normalize_username(raw: &str) -> Result<String, AccountError> {
    let u = raw.trim().to_ascii_lowercase();
    let ok = (3..=32).contains(&u.len())
        && u.starts_with(|c: char| c.is_ascii_alphanumeric())
        && u.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(u)
    } else {
        Err(AccountError::Invalid(
            "username must be 3-32 chars of a-z, 0-9, '.', '_', '-'",
        ))
    }
}

pub fn validate_password(password: &str) -> Result<(), AccountError> {
    let n = password.chars().count();
    if !(MIN_PASSWORD_CHARS..=MAX_PASSWORD_CHARS).contains(&n) {
        return Err(AccountError::Invalid("password must be 12-128 characters"));
    }
    if password.chars().any(char::is_control) {
        return Err(AccountError::Invalid(
            "password must not contain control characters",
        ));
    }
    Ok(())
}

pub fn validate_email(email: &str) -> Result<(), AccountError> {
    let ok = email.len() <= MAX_PII_BYTES
        && email.split_once('@').is_some_and(|(l, d)| {
            !l.is_empty() && d.contains('.') && !d.starts_with('.') && !d.ends_with('.')
        })
        && !email.chars().any(|c| c.is_whitespace() || c.is_control());
    if ok {
        Ok(())
    } else {
        Err(AccountError::Invalid("email is not valid"))
    }
}

/// Indonesian NIK: exactly 16 digits.
pub fn validate_national_id(nik: &str) -> Result<(), AccountError> {
    if nik.len() == 16 && nik.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(AccountError::Invalid("national ID (NIK) must be 16 digits"))
    }
}

// ---------------------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Admin => "admin",
        }
    }

    fn parse(s: &str) -> Result<Self, AccountError> {
        match s {
            "user" => Ok(Self::User),
            "admin" => Ok(Self::Admin),
            _ => Err(AccountError::Internal("unknown role in database".into())),
        }
    }
}

/// Input for [`UserStore::create_user`]. Secrets are zeroized on drop.
#[derive(serde::Deserialize)]
pub struct NewUser {
    pub username: String,
    pub password: Zeroizing<String>,
    #[serde(default = "default_role")]
    pub role: Role,
    #[serde(default)]
    pub email: Option<Zeroizing<String>>,
    #[serde(default)]
    pub national_id: Option<Zeroizing<String>>,
}

fn default_role() -> Role {
    Role::User
}

impl std::fmt::Debug for NewUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewUser")
            .field("username", &self.username)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedUser {
    pub id: u64,
    pub username: String,
    pub role: Role,
}

/// Decrypted profile (PII present only after successful tag verification).
pub struct UserProfile {
    pub id: u64,
    pub username: String,
    pub role: Role,
    pub email: Option<Zeroizing<String>>,
    pub national_id: Option<Zeroizing<String>>,
    pub created_at_unix: i64,
}

impl std::fmt::Debug for UserProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserProfile")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

/// Connection options from `TODO_MARIADB_URL` + `TODO_MARIADB_PASSWORD(_FILE)`.
/// `Ok(None)` when the URL is unset (accounts disabled).
pub fn mariadb_options_from_env() -> Result<Option<MySqlConnectOptions>, ConfigError> {
    let Ok(url) = std::env::var("TODO_MARIADB_URL") else {
        return Ok(None);
    };
    let url = Zeroizing::new(url);
    let password = read_secret("TODO_MARIADB_PASSWORD")?;
    mariadb_options(&url, password.as_deref().map(String::as_str)).map(Some)
}

/// A password embedded in the URL is rejected: it would leak through `ps`, shell history
/// and logs. Use the password (file) variable instead.
pub fn mariadb_options(
    url: &str,
    password: Option<&str>,
) -> Result<MySqlConnectOptions, ConfigError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| ConfigError("TODO_MARIADB_URL must be mysql://...".into()))?;
    if scheme != "mysql" && scheme != "mariadb" {
        return Err(ConfigError("TODO_MARIADB_URL must be mysql://...".into()));
    }
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    if authority
        .rsplit_once('@')
        .is_some_and(|(userinfo, _)| userinfo.contains(':'))
    {
        return Err(ConfigError(
            "TODO_MARIADB_URL must not contain a password; use TODO_MARIADB_PASSWORD_FILE".into(),
        ));
    }
    let url = format!("mysql://{rest}");
    let mut opts = MySqlConnectOptions::from_str(&url)
        .map_err(|_| ConfigError("TODO_MARIADB_URL is not a valid URL".into()))?
        .charset("utf8mb4")
        .disable_statement_logging();
    if let Some(pw) = password {
        opts = opts.password(pw);
    }
    Ok(opts)
}

/// Accounts from the environment: `None` when `TODO_MARIADB_URL` is unset. Requires a
/// PII key for which `is_reserved_key` is false, e.g. different from the object upload
/// key (key separation).
pub async fn accounts_from_env(
    is_reserved_key: impl Fn(&[u8]) -> bool,
) -> Result<Option<UserStore>, ConfigError> {
    let Some(opts) = mariadb_options_from_env()? else {
        return Ok(None);
    };
    let pii = PiiCipher::from_env()?
        .ok_or_else(|| ConfigError("TODO_MARIADB_URL requires TODO_PII_KEY_HEX(_FILE)".into()))?;
    if is_reserved_key(&pii.key[..]) {
        return Err(ConfigError(
            "TODO_PII_KEY_HEX must differ from TODO_UPLOAD_KEY_HEX".into(),
        ));
    }
    UserStore::connect(opts, pii)
        .await
        .map(Some)
        .map_err(|e| ConfigError(format!("MariaDB: {e}")))
}

pub struct UserStore {
    pool: MySqlPool,
    pii: Arc<PiiCipher>,
    dummy_hash: String,
}

impl std::fmt::Debug for UserStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UserStore")
    }
}

impl UserStore {
    pub async fn connect(opts: MySqlConnectOptions, pii: PiiCipher) -> Result<Self, AccountError> {
        let pool = MySqlPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(opts)
            .await?;
        Self::with_pool(pool, pii).await
    }

    pub async fn with_pool(pool: MySqlPool, pii: PiiCipher) -> Result<Self, AccountError> {
        let dummy_hash = tokio::task::spawn_blocking(|| hash_password("dummy-password-for-timing"))
            .await
            .map_err(|e| AccountError::Internal(e.to_string()))??;
        Ok(Self {
            pool,
            pii: Arc::new(pii),
            dummy_hash,
        })
    }

    pub fn pool(&self) -> &MySqlPool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<(), AccountError> {
        MARIADB_MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    /// Embedded MariaDB seed SQL (`crates/database/seeds/mariadb/0001_seed_users.sql`).
    pub const SEED_USERS_SQL: &'static str = include_str!("../seeds/mariadb/0001_seed_users.sql");

    /// Applies idempotent user seed data to the MariaDB `users` table.
    pub async fn seed(&self) -> Result<(), AccountError> {
        sqlx::raw_sql(Self::SEED_USERS_SQL)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Validates input, hashes the password, inserts the row and then seals PII under
    /// the new row id, all in one transaction.
    pub async fn create_user(&self, new: NewUser) -> Result<u64, AccountError> {
        let username = normalize_username(&new.username)?;
        validate_password(&new.password)?;
        if let Some(e) = &new.email {
            validate_email(e)?;
        }
        if let Some(n) = &new.national_id {
            validate_national_id(n)?;
        }
        let password = new.password.clone();
        let hash = tokio::task::spawn_blocking(move || hash_password(&password))
            .await
            .map_err(|e| AccountError::Internal(e.to_string()))??;

        let mut tx = self.pool.begin().await?;
        let id = sqlx::query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)")
            .bind(&username)
            .bind(&hash)
            .bind(new.role.as_str())
            .execute(&mut *tx)
            .await?
            .last_insert_id();
        let seal = |column: &str, v: &Option<Zeroizing<String>>| {
            v.as_ref()
                .map(|v| self.pii.seal("users", column, id, v.as_bytes()))
                .transpose()
        };
        let email = seal("email", &new.email)?;
        let national_id = seal("national_id", &new.national_id)?;
        sqlx::query("UPDATE users SET email_enc = ?, national_id_enc = ? WHERE id = ?")
            .bind(email)
            .bind(national_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// `Ok(None)` for an unknown user or wrong password (indistinguishable to callers).
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<AuthenticatedUser>, AccountError> {
        let row = match normalize_username(username) {
            Ok(u) => {
                sqlx::query(
                    "SELECT id, username, CAST(role AS CHAR) AS role, password_hash \
                 FROM users WHERE username = ?",
                )
                .bind(u)
                .fetch_optional(&self.pool)
                .await?
            }
            Err(_) => None,
        };
        let (user, phc) = match &row {
            Some(r) => (
                Some(AuthenticatedUser {
                    id: r.try_get("id")?,
                    username: r.try_get("username")?,
                    role: Role::parse(r.try_get::<&str, _>("role")?)?,
                }),
                r.try_get::<String, _>("password_hash")?,
            ),
            None => (None, self.dummy_hash.clone()),
        };
        let password = Zeroizing::new(password.to_string());
        let ok = tokio::task::spawn_blocking(move || verify_password(&password, &phc))
            .await
            .map_err(|e| AccountError::Internal(e.to_string()))?;
        Ok(user.filter(|_| ok))
    }

    pub async fn profile(&self, id: u64) -> Result<Option<UserProfile>, AccountError> {
        let Some(r) = sqlx::query(
            "SELECT id, username, CAST(role AS CHAR) AS role, email_enc, national_id_enc, \
             CAST(UNIX_TIMESTAMP(created_at) AS SIGNED) AS created FROM users WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };
        let open = |column: &str, blob: Option<Vec<u8>>| -> Result<_, AccountError> {
            blob.map(|b| {
                let pt = self.pii.open("users", column, id, &b)?;
                String::from_utf8(pt.to_vec())
                    .map(Zeroizing::new)
                    .map_err(|_| AccountError::PiiIntegrity)
            })
            .transpose()
        };
        Ok(Some(UserProfile {
            id,
            username: r.try_get("username")?,
            role: Role::parse(r.try_get::<&str, _>("role")?)?,
            email: open("email", r.try_get("email_enc")?)?,
            national_id: open("national_id", r.try_get("national_id_enc")?)?,
            created_at_unix: r.try_get("created")?,
        }))
    }
}

// ---------------------------------------------------------------------------------------
// Directory abstraction (lets the web layer run against MariaDB or an in-memory fake)
// ---------------------------------------------------------------------------------------

pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Read side of the account store used by login/session handling.
pub trait AccountDirectory: Send + Sync {
    fn authenticate<'a>(
        &'a self,
        username: &'a str,
        password: &'a str,
    ) -> BoxFuture<'a, Result<Option<AuthenticatedUser>, AccountError>>;

    fn profile(&self, id: u64) -> BoxFuture<'_, Result<Option<UserProfile>, AccountError>>;
}

impl AccountDirectory for UserStore {
    fn authenticate<'a>(
        &'a self,
        username: &'a str,
        password: &'a str,
    ) -> BoxFuture<'a, Result<Option<AuthenticatedUser>, AccountError>> {
        Box::pin(UserStore::authenticate(self, username, password))
    }

    fn profile(&self, id: u64) -> BoxFuture<'_, Result<Option<UserProfile>, AccountError>> {
        Box::pin(UserStore::profile(self, id))
    }
}

struct MemoryUser {
    user: AuthenticatedUser,
    password_hash: String,
    email_enc: Option<Vec<u8>>,
    national_id_enc: Option<Vec<u8>>,
}

/// Non-persistent directory with the same hashing/PII sealing as [`UserStore`]
/// (tests and offline demos only).
pub struct MemoryDirectory {
    pii: PiiCipher,
    users: std::sync::Mutex<Vec<MemoryUser>>,
    dummy_hash: String,
}

impl MemoryDirectory {
    pub fn new(pii: PiiCipher) -> Result<Self, AccountError> {
        Ok(Self {
            pii,
            users: std::sync::Mutex::new(Vec::new()),
            dummy_hash: hash_password("dummy-password-for-timing")?,
        })
    }

    /// Blocking (Argon2id); call from sync code or `spawn_blocking`.
    pub fn create_user(&self, new: NewUser) -> Result<u64, AccountError> {
        let username = normalize_username(&new.username)?;
        validate_password(&new.password)?;
        if let Some(e) = &new.email {
            validate_email(e)?;
        }
        if let Some(n) = &new.national_id {
            validate_national_id(n)?;
        }
        let password_hash = hash_password(&new.password)?;
        let mut users = self.users.lock().unwrap_or_else(|e| e.into_inner());
        if users.iter().any(|u| u.user.username == username) {
            return Err(AccountError::DuplicateUsername);
        }
        let id = users.len() as u64 + 1;
        let seal = |column: &str, v: &Option<Zeroizing<String>>| {
            v.as_ref()
                .map(|v| self.pii.seal("users", column, id, v.as_bytes()))
                .transpose()
        };
        let email_enc = seal("email", &new.email)?;
        let national_id_enc = seal("national_id", &new.national_id)?;
        users.push(MemoryUser {
            user: AuthenticatedUser {
                id,
                username,
                role: new.role,
            },
            password_hash,
            email_enc,
            national_id_enc,
        });
        Ok(id)
    }
}

impl AccountDirectory for MemoryDirectory {
    fn authenticate<'a>(
        &'a self,
        username: &'a str,
        password: &'a str,
    ) -> BoxFuture<'a, Result<Option<AuthenticatedUser>, AccountError>> {
        Box::pin(async move {
            let found = normalize_username(username).ok().and_then(|u| {
                let users = self.users.lock().unwrap_or_else(|e| e.into_inner());
                users
                    .iter()
                    .find(|m| m.user.username == u)
                    .map(|m| (m.user.clone(), m.password_hash.clone()))
            });
            let (user, phc) = match found {
                Some((u, h)) => (Some(u), h),
                None => (None, self.dummy_hash.clone()),
            };
            let password = Zeroizing::new(password.to_string());
            let ok = tokio::task::spawn_blocking(move || verify_password(&password, &phc))
                .await
                .map_err(|e| AccountError::Internal(e.to_string()))?;
            Ok(user.filter(|_| ok))
        })
    }

    fn profile(&self, id: u64) -> BoxFuture<'_, Result<Option<UserProfile>, AccountError>> {
        Box::pin(async move {
            let users = self.users.lock().unwrap_or_else(|e| e.into_inner());
            let Some(m) = users.iter().find(|m| m.user.id == id) else {
                return Ok(None);
            };
            let open = |column: &str, blob: &Option<Vec<u8>>| -> Result<_, AccountError> {
                blob.as_ref()
                    .map(|b| {
                        let pt = self.pii.open("users", column, id, b)?;
                        String::from_utf8(pt.to_vec())
                            .map(Zeroizing::new)
                            .map_err(|_| AccountError::PiiIntegrity)
                    })
                    .transpose()
            };
            Ok(Some(UserProfile {
                id,
                username: m.user.username.clone(),
                role: m.user.role,
                email: open("email", &m.email_enc)?,
                national_id: open("national_id", &m.national_id_enc)?,
                created_at_unix: 0,
            }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pii_roundtrip_binding_and_tamper() {
        let c = PiiCipher::new(&[7u8; 32]).unwrap();
        let blob = c.seal("users", "email", 42, b"budi@example.com").unwrap();
        assert_eq!(blob[0], PII_FORMAT_V1);
        assert_eq!(blob.len(), 1 + 12 + 16 + 16);
        assert!(!blob.windows(4).any(|w| w == b"budi"));
        assert_eq!(
            &c.open("users", "email", 42, &blob).unwrap()[..],
            b"budi@example.com"
        );
        // Bound to row, column, table and key.
        assert!(c.open("users", "email", 43, &blob).is_err());
        assert!(c.open("users", "national_id", 42, &blob).is_err());
        assert!(c.open("admins", "email", 42, &blob).is_err());
        assert!(
            PiiCipher::new(&[8u8; 32])
                .unwrap()
                .open("users", "email", 42, &blob)
                .is_err()
        );
        for i in 0..blob.len() {
            let mut t = blob.clone();
            t[i] ^= 1;
            assert!(c.open("users", "email", 42, &t).is_err(), "byte {i}");
        }
        assert!(c.open("users", "email", 42, &blob[..20]).is_err());
        // Random nonce: same value seals differently.
        assert_ne!(
            blob,
            c.seal("users", "email", 42, b"budi@example.com").unwrap()
        );
        assert!(PiiCipher::new(&[0u8; 16]).is_err());
        assert_eq!(format!("{c:?}"), "PiiCipher(<redacted>)");
    }

    #[test]
    fn pii_matches_upstream_aes_gcm_siv() {
        let key = [3u8; 32];
        let c = PiiCipher::new(&key).unwrap();
        let blob = c
            .seal("users", "national_id", 9, b"3201234567890123")
            .unwrap();
        let nonce: [u8; 12] = blob[1..13].try_into().unwrap();
        let up = todo_crypto::aes_gcm_siv_encrypt_upstream(
            &key,
            &nonce,
            &PiiCipher::aad("users", "national_id", 9),
            b"3201234567890123",
        )
        .unwrap();
        assert_eq!(&blob[13..blob.len() - 16], &up.ciphertext[..]);
        assert_eq!(&blob[blob.len() - 16..], &up.tag[..]);
    }

    #[test]
    fn argon2id_hash_and_verify() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{h}");
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("correct horse batterY", &h));
        assert!(!verify_password("x", "not-a-phc"));
        assert_ne!(h, hash_password("correct horse battery").unwrap());
    }

    #[test]
    fn input_validation() {
        assert_eq!(normalize_username("  Budi.S ").unwrap(), "budi.s");
        for bad in ["ab", "-budi", "bu di", "budi@x", "ü-user", &"a".repeat(33)] {
            assert!(normalize_username(bad).is_err(), "{bad}");
        }
        assert!(validate_password("short").is_err());
        assert!(validate_password("twelve chars").is_ok());
        assert!(validate_password("twelve\nchars!").is_err());
        assert!(validate_password(&"x".repeat(129)).is_err());
        assert!(validate_email("budi@example.co.id").is_ok());
        for bad in ["budi", "@x.id", "budi@x", "bu di@x.id", "budi@.x"] {
            assert!(validate_email(bad).is_err(), "{bad}");
        }
        assert!(validate_national_id("3201234567890123").is_ok());
        assert!(validate_national_id("320123456789012").is_err());
        assert!(validate_national_id("32012345678901a3").is_err());
    }

    #[test]
    fn seed_sql_argon2id_hashes_valid() {
        assert!(UserStore::SEED_USERS_SQL.contains("INSERT INTO users"));
        assert!(UserStore::SEED_USERS_SQL.contains("ON DUPLICATE KEY UPDATE"));
        assert!(UserStore::SEED_USERS_SQL.contains("'user'"));
        assert!(UserStore::SEED_USERS_SQL.contains("'admin'"));

        // Extract and verify PHC hashes in the seed file
        for line in UserStore::SEED_USERS_SQL.lines() {
            if let Some(start) = line.find("$argon2id$") {
                let rest = &line[start..];
                let hash = rest.split('\'').next().unwrap();
                assert!(
                    verify_password("correct horse battery", hash),
                    "hash in seed failed verification: {hash}"
                );
            }
        }
    }

    #[test]
    fn mariadb_url_rules() {
        assert!(
            mariadb_options(
                "mysql://todo_app@localhost/todo?socket=/run/mysqld/mysqld.sock",
                Some("pw")
            )
            .is_ok()
        );
        assert!(mariadb_options("mariadb://todo_app@127.0.0.1:3306/todo", None).is_ok());
        let err = mariadb_options("mysql://todo_app:secret@localhost/todo", None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("must not contain a password") && !err.contains("secret@"));
        assert!(mariadb_options("postgres://x@y/z", None).is_err());
        assert!(mariadb_options("localhost/todo", None).is_err());
    }
}
