//! Layer 4 object metadata: `TODO_POSTGRES_URL` (no password) +
//! `TODO_POSTGRES_PASSWORD(_FILE)`.

use std::fmt;

use super::mariadb::password;
use super::{ConfigError, Environment, Lookup, Secret, plain, read_secret, reject_url_password};

#[derive(Debug)]
pub struct PgsqlConfig {
    /// Password-free URL, safe to print.
    pub url: String,
    pub password: Option<Secret>,
}

impl PgsqlConfig {
    pub(super) fn load(env: Lookup<'_>, mode: Environment) -> Result<Option<Self>, ConfigError> {
        let Some(url) = plain(env, "TODO_POSTGRES_URL") else {
            return Ok(None);
        };
        reject_url_password("TODO_POSTGRES_URL", &url)?;
        let config = Self {
            url,
            password: read_secret(env, "TODO_POSTGRES_PASSWORD", mode)?,
        };
        config.connect_options()?;
        Ok(Some(config))
    }

    /// sqlx options with statement logging disabled (no connection is opened).
    pub fn connect_options(&self) -> Result<sqlx::postgres::PgConnectOptions, ConfigError> {
        todo_database::objects::postgres_options(&self.url, password(&self.password, "PostgreSQL")?)
    }
}

impl fmt::Display for PgsqlConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} password={}",
            self.url,
            super::opt_secret(&self.password)
        )
    }
}
