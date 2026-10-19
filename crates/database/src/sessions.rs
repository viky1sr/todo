//! Layer 2: server-side login sessions (Redis) and login rate limiting.
//!
//! - Token: 256 random bits (64 hex chars), sent to the browser only in an `HttpOnly`
//!   cookie. Redis stores `SHA-256(token)` as the key, so a Redis dump does not yield
//!   usable cookies. No cookie encryption is needed: the cookie carries no data.
//! - Lifetime: sliding idle TTL (`GETEX … EX idle` on each use) plus an absolute cap
//!   checked against the creation time.
//! - Rate limit: failed logins counted per client IP and per username in a fixed window
//!   (`INCR` + `EXPIRE … NX`); successful login clears the username counter.
//! - Connection: `TODO_REDIS_URL` (no password inside), `TODO_REDIS_PASSWORD(_FILE)`.
//!
//! [`SessionStore::memory`] is a single-process backend for tests/demos only.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use redis::aio::ConnectionManager;
use redis::{AsyncCommands, IntoConnectionInfo};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::ConfigError;
use crate::accounts::{AuthenticatedUser, Role};
use crate::secrets::read_secret;

pub const SESSION_TOKEN_HEX_LEN: usize = 64;
const KEY_PREFIX: &str = "todo:v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPolicy {
    pub idle_ttl: Duration,
    pub absolute_ttl: Duration,
    pub max_failures_per_ip: u32,
    pub max_failures_per_user: u32,
    pub failure_window: Duration,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            idle_ttl: Duration::from_secs(30 * 60),
            absolute_ttl: Duration::from_secs(12 * 3600),
            max_failures_per_ip: 20,
            max_failures_per_user: 5,
            failure_window: Duration::from_secs(15 * 60),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub user_id: u64,
    pub username: String,
    pub role: Role,
    pub created_unix: u64,
}

#[derive(Debug)]
pub struct SessionError(pub String);

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "session store error: {}", self.0)
    }
}

impl std::error::Error for SessionError {}

impl From<redis::RedisError> for SessionError {
    fn from(e: redis::RedisError) -> Self {
        Self(e.to_string())
    }
}

/// Opaque session token (redacted in `Debug`, zeroized on drop).
pub struct SessionToken(Zeroizing<String>);

impl SessionToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionToken(<redacted>)")
    }
}

#[derive(Default)]
struct MemoryState {
    values: HashMap<String, (String, Instant)>,
    counters: HashMap<String, (u32, Instant)>,
}

enum Backend {
    Redis(ConnectionManager),
    Memory(Mutex<MemoryState>),
}

pub struct SessionStore {
    backend: Backend,
    policy: SessionPolicy,
}

impl std::fmt::Debug for SessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self.backend {
            Backend::Redis(_) => "redis",
            Backend::Memory(_) => "memory",
        };
        f.debug_struct("SessionStore")
            .field("backend", &kind)
            .field("policy", &self.policy)
            .finish()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn session_key(token: &str) -> String {
    format!(
        "{KEY_PREFIX}:sess:{}",
        hex(&Sha256::digest(token.as_bytes()))
    )
}

fn ip_key(ip: &str) -> String {
    format!("{KEY_PREFIX}:login-fail:ip:{ip}")
}

fn user_key(username: &str) -> String {
    let u = username.trim().to_ascii_lowercase();
    format!(
        "{KEY_PREFIX}:login-fail:user:{}",
        hex(&Sha256::digest(u.as_bytes()))
    )
}

fn valid_token(token: &str) -> bool {
    token.len() == SESSION_TOKEN_HEX_LEN
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `redis://host[:port][/db]` or `rediss://…`; a password inside the URL is rejected.
pub fn redis_connection_info(
    url: &str,
    password: Option<&str>,
) -> Result<redis::ConnectionInfo, ConfigError> {
    let rest = url
        .strip_prefix("redis://")
        .or_else(|| url.strip_prefix("rediss://"))
        .or_else(|| url.strip_prefix("redis+unix://"))
        .ok_or_else(|| ConfigError("TODO_REDIS_URL must be redis://...".into()))?;
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    if authority
        .rsplit_once('@')
        .is_some_and(|(userinfo, _)| userinfo.contains(':'))
    {
        return Err(ConfigError(
            "TODO_REDIS_URL must not contain a password; use TODO_REDIS_PASSWORD_FILE".into(),
        ));
    }
    let info = url
        .into_connection_info()
        .map_err(|_| ConfigError("TODO_REDIS_URL is not a valid Redis URL".into()))?;
    Ok(match password {
        Some(pw) => {
            let settings = info.redis_settings().clone().set_password(pw);
            info.set_redis_settings(settings)
        }
        None => info,
    })
}

impl SessionStore {
    /// Single-process, non-persistent backend (tests/demo only).
    pub fn memory(policy: SessionPolicy) -> Self {
        Self {
            backend: Backend::Memory(Mutex::new(MemoryState::default())),
            policy,
        }
    }

    pub async fn redis(
        info: redis::ConnectionInfo,
        policy: SessionPolicy,
    ) -> Result<Self, ConfigError> {
        let client = redis::Client::open(info).map_err(|e| ConfigError(format!("Redis: {e}")))?;
        let mut conn = tokio::time::timeout(Duration::from_secs(5), ConnectionManager::new(client))
            .await
            .map_err(|_| ConfigError("Redis: connection timed out".into()))?
            .map_err(|e| ConfigError(format!("Redis: {e}")))?;
        let _: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .map_err(|e| ConfigError(format!("Redis: {e}")))?;
        Ok(Self {
            backend: Backend::Redis(conn),
            policy,
        })
    }

    /// `None` when `TODO_REDIS_URL` is unset. Optional `TODO_SESSION_IDLE_SECS`,
    /// `TODO_SESSION_ABSOLUTE_SECS`.
    pub async fn from_env() -> Result<Option<Self>, ConfigError> {
        let Ok(url) = std::env::var("TODO_REDIS_URL") else {
            return Ok(None);
        };
        let password = read_secret("TODO_REDIS_PASSWORD")?;
        let info = redis_connection_info(&url, password.as_deref().map(String::as_str))?;
        let mut policy = SessionPolicy::default();
        let secs = |name: &str| -> Result<Option<Duration>, ConfigError> {
            std::env::var(name)
                .ok()
                .map(|v| match v.trim().parse::<u64>() {
                    Ok(n) if (60..=30 * 86400).contains(&n) => Ok(Duration::from_secs(n)),
                    _ => Err(ConfigError(format!("{name} must be 60..=2592000 seconds"))),
                })
                .transpose()
        };
        if let Some(d) = secs("TODO_SESSION_IDLE_SECS")? {
            policy.idle_ttl = d;
        }
        if let Some(d) = secs("TODO_SESSION_ABSOLUTE_SECS")? {
            policy.absolute_ttl = d;
        }
        if policy.idle_ttl > policy.absolute_ttl {
            return Err(ConfigError(
                "TODO_SESSION_IDLE_SECS must not exceed TODO_SESSION_ABSOLUTE_SECS".into(),
            ));
        }
        Self::redis(info, policy).await.map(Some)
    }

    pub fn policy(&self) -> SessionPolicy {
        self.policy
    }

    /// New random session for `user` (call on every successful login: no fixation).
    pub async fn create(&self, user: &AuthenticatedUser) -> Result<SessionToken, SessionError> {
        let mut raw = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut raw[..]).map_err(|e| SessionError(e.to_string()))?;
        let token = SessionToken(Zeroizing::new(hex(&raw[..])));
        let session = Session {
            user_id: user.id,
            username: user.username.clone(),
            role: user.role,
            created_unix: now_unix(),
        };
        let value = serde_json::to_string(&session).map_err(|e| SessionError(e.to_string()))?;
        let key = session_key(token.as_str());
        let idle = self.policy.idle_ttl;
        match &self.backend {
            Backend::Redis(conn) => {
                let mut conn = conn.clone();
                let created: Option<String> = redis::cmd("SET")
                    .arg(&key)
                    .arg(&value)
                    .arg("EX")
                    .arg(idle.as_secs())
                    .arg("NX")
                    .query_async(&mut conn)
                    .await?;
                if created.is_none() {
                    return Err(SessionError("session id collision".into()));
                }
            }
            Backend::Memory(m) => {
                let mut m = m.lock().unwrap_or_else(|e| e.into_inner());
                m.values.insert(key, (value, Instant::now() + idle));
            }
        }
        Ok(token)
    }

    /// Valid session for `token`, refreshing the idle TTL; `None` if unknown, malformed,
    /// idle-expired or past the absolute lifetime.
    pub async fn get(&self, token: &str) -> Result<Option<Session>, SessionError> {
        if !valid_token(token) {
            return Ok(None);
        }
        let key = session_key(token);
        let idle = self.policy.idle_ttl;
        let value: Option<String> = match &self.backend {
            Backend::Redis(conn) => {
                let mut conn = conn.clone();
                redis::cmd("GETEX")
                    .arg(&key)
                    .arg("EX")
                    .arg(idle.as_secs())
                    .query_async(&mut conn)
                    .await?
            }
            Backend::Memory(m) => {
                let mut m = m.lock().unwrap_or_else(|e| e.into_inner());
                let now = Instant::now();
                match m.values.get_mut(&key) {
                    Some((v, exp)) if *exp > now => {
                        *exp = now + idle;
                        Some(v.clone())
                    }
                    Some(_) => {
                        m.values.remove(&key);
                        None
                    }
                    None => None,
                }
            }
        };
        let Some(session) = value.and_then(|v| serde_json::from_str::<Session>(&v).ok()) else {
            return Ok(None);
        };
        if now_unix().saturating_sub(session.created_unix) >= self.policy.absolute_ttl.as_secs() {
            self.destroy(token).await?;
            return Ok(None);
        }
        Ok(Some(session))
    }

    pub async fn destroy(&self, token: &str) -> Result<(), SessionError> {
        if !valid_token(token) {
            return Ok(());
        }
        self.delete(&session_key(token)).await
    }

    async fn delete(&self, key: &str) -> Result<(), SessionError> {
        match &self.backend {
            Backend::Redis(conn) => {
                let mut conn = conn.clone();
                let _: usize = conn.del(key).await?;
            }
            Backend::Memory(m) => {
                let mut m = m.lock().unwrap_or_else(|e| e.into_inner());
                m.values.remove(key);
                m.counters.remove(key);
            }
        }
        Ok(())
    }

    async fn counter(&self, key: &str) -> Result<u32, SessionError> {
        Ok(match &self.backend {
            Backend::Redis(conn) => {
                let mut conn = conn.clone();
                let v: Option<u32> = conn.get(key).await?;
                v.unwrap_or(0)
            }
            Backend::Memory(m) => {
                let m = m.lock().unwrap_or_else(|e| e.into_inner());
                m.counters
                    .get(key)
                    .filter(|(_, exp)| *exp > Instant::now())
                    .map_or(0, |(n, _)| *n)
            }
        })
    }

    async fn bump(&self, key: &str) -> Result<(), SessionError> {
        let window = self.policy.failure_window;
        match &self.backend {
            Backend::Redis(conn) => {
                let mut conn = conn.clone();
                let _: () = redis::pipe()
                    .atomic()
                    .cmd("INCR")
                    .arg(key)
                    .ignore()
                    .cmd("EXPIRE")
                    .arg(key)
                    .arg(window.as_secs())
                    .arg("NX")
                    .ignore()
                    .query_async(&mut conn)
                    .await?;
            }
            Backend::Memory(m) => {
                let mut m = m.lock().unwrap_or_else(|e| e.into_inner());
                let now = Instant::now();
                let entry = m
                    .counters
                    .entry(key.to_string())
                    .or_insert((0, now + window));
                if entry.1 <= now {
                    *entry = (0, now + window);
                }
                entry.0 += 1;
            }
        }
        Ok(())
    }

    /// `false` when the IP or the username exceeded its failure budget in the window.
    pub async fn login_allowed(&self, ip: &str, username: &str) -> Result<bool, SessionError> {
        Ok(
            self.counter(&ip_key(ip)).await? < self.policy.max_failures_per_ip
                && self.counter(&user_key(username)).await? < self.policy.max_failures_per_user,
        )
    }

    pub async fn record_failure(&self, ip: &str, username: &str) -> Result<(), SessionError> {
        self.bump(&ip_key(ip)).await?;
        self.bump(&user_key(username)).await
    }

    pub async fn clear_user_failures(&self, username: &str) -> Result<(), SessionError> {
        self.delete(&user_key(username)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> AuthenticatedUser {
        AuthenticatedUser {
            id: 7,
            username: "budi".into(),
            role: Role::User,
        }
    }

    #[tokio::test]
    async fn memory_sessions_and_rate_limit() {
        let store = SessionStore::memory(SessionPolicy::default());
        let t = store.create(&user()).await.unwrap();
        assert_eq!(t.as_str().len(), 64);
        assert_eq!(format!("{t:?}"), "SessionToken(<redacted>)");
        let s = store.get(t.as_str()).await.unwrap().unwrap();
        assert_eq!((s.user_id, s.username.as_str()), (7, "budi"));
        let t2 = store.create(&user()).await.unwrap();
        assert_ne!(t.as_str(), t2.as_str());
        assert!(store.get(&"0".repeat(64)).await.unwrap().is_none());
        assert!(store.get("short").await.unwrap().is_none());
        assert!(
            store
                .get(&t.as_str().to_uppercase())
                .await
                .unwrap()
                .is_none()
        );
        store.destroy(t.as_str()).await.unwrap();
        assert!(store.get(t.as_str()).await.unwrap().is_none());
        assert!(store.get(t2.as_str()).await.unwrap().is_some());

        for _ in 0..5 {
            assert!(store.login_allowed("10.0.0.1", "Budi").await.unwrap());
            store.record_failure("10.0.0.1", "Budi").await.unwrap();
        }
        assert!(!store.login_allowed("10.0.0.2", "budi").await.unwrap());
        assert!(store.login_allowed("10.0.0.1", "siti").await.unwrap());
        store.clear_user_failures("BUDI").await.unwrap();
        assert!(store.login_allowed("10.0.0.1", "budi").await.unwrap());
    }

    #[tokio::test]
    async fn idle_and_absolute_expiry() {
        let store = SessionStore::memory(SessionPolicy {
            idle_ttl: Duration::from_millis(50),
            ..SessionPolicy::default()
        });
        let t = store.create(&user()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(store.get(t.as_str()).await.unwrap().is_none());

        let store = SessionStore::memory(SessionPolicy {
            absolute_ttl: Duration::ZERO,
            ..SessionPolicy::default()
        });
        let t = store.create(&user()).await.unwrap();
        assert!(store.get(t.as_str()).await.unwrap().is_none());
    }

    #[test]
    fn redis_url_rules() {
        assert!(redis_connection_info("redis://127.0.0.1:6379/0", Some("pw")).is_ok());
        assert!(redis_connection_info("redis://todo@127.0.0.1:6379/0", None).is_ok());
        let e = redis_connection_info("redis://todo:hunter2@127.0.0.1/0", None).unwrap_err();
        assert!(e.0.contains("must not contain a password") && !e.0.contains("hunter2"));
        assert!(redis_connection_info("http://127.0.0.1", None).is_err());
        let info = redis_connection_info("redis://127.0.0.1/2", Some("pw")).unwrap();
        assert_eq!(info.redis_settings().password(), Some("pw"));
    }

    #[test]
    fn keys_do_not_contain_token_or_username() {
        let token = "ab".repeat(32);
        assert!(!session_key(&token).contains(&token));
        assert!(!user_key("budi").contains("budi"));
        assert_eq!(user_key("Budi "), user_key("budi"));
    }
}
