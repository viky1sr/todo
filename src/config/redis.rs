//! Layer 2 sessions: `TODO_REDIS_URL` (no password) + `TODO_REDIS_PASSWORD(_FILE)`,
//! `TODO_SESSION_IDLE_SECS`, `TODO_SESSION_ABSOLUTE_SECS`.

use std::fmt;
use std::time::Duration;

use todo_database::sessions::SessionPolicy;

use super::mariadb::password;
use super::{
    ConfigError, Environment, Lookup, Secret, number, plain, read_secret, reject_url_password,
};

const TTL_RANGE: std::ops::RangeInclusive<u64> = 60..=30 * 86_400;

#[derive(Debug)]
pub struct RedisConfig {
    /// Password-free URL, safe to print.
    pub url: String,
    pub password: Option<Secret>,
    pub policy: SessionPolicy,
}

impl RedisConfig {
    pub(super) fn load(env: Lookup<'_>, mode: Environment) -> Result<Option<Self>, ConfigError> {
        let Some(url) = plain(env, "TODO_REDIS_URL") else {
            return Ok(None);
        };
        reject_url_password("TODO_REDIS_URL", &url)?;
        let mut policy = SessionPolicy::default();
        let ttl = |name: &str| -> Result<Option<Duration>, ConfigError> {
            match number::<u64>(env, name)? {
                None => Ok(None),
                Some(n) if TTL_RANGE.contains(&n) => Ok(Some(Duration::from_secs(n))),
                Some(_) => Err(ConfigError(format!("{name} must be 60..=2592000 seconds"))),
            }
        };
        if let Some(d) = ttl("TODO_SESSION_IDLE_SECS")? {
            policy.idle_ttl = d;
        }
        if let Some(d) = ttl("TODO_SESSION_ABSOLUTE_SECS")? {
            policy.absolute_ttl = d;
        }
        if policy.idle_ttl > policy.absolute_ttl {
            return Err(ConfigError(
                "TODO_SESSION_IDLE_SECS must not exceed TODO_SESSION_ABSOLUTE_SECS".into(),
            ));
        }
        let config = Self {
            url,
            password: read_secret(env, "TODO_REDIS_PASSWORD", mode)?,
            policy,
        };
        config.connection_info()?;
        Ok(Some(config))
    }

    /// Redis connection info (no connection is opened).
    pub fn connection_info(&self) -> Result<::redis::ConnectionInfo, ConfigError> {
        todo_database::sessions::redis_connection_info(
            &self.url,
            password(&self.password, "Redis")?,
        )
    }
}

impl fmt::Display for RedisConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} password={} session idle={}s absolute={}s",
            self.url,
            super::opt_secret(&self.password),
            self.policy.idle_ttl.as_secs(),
            self.policy.absolute_ttl.as_secs()
        )
    }
}
