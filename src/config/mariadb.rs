//! Layer 3 accounts: `TODO_MARIADB_URL` (no password) + `TODO_MARIADB_PASSWORD(_FILE)`.

use std::fmt;

use super::{ConfigError, Environment, Lookup, Secret, plain, read_secret, reject_url_password};

#[derive(Debug)]
pub struct MariaDbConfig {
    /// Password-free URL, safe to print.
    pub url: String,
    pub password: Option<Secret>,
}

impl MariaDbConfig {
    pub(super) fn load(env: Lookup<'_>, mode: Environment) -> Result<Option<Self>, ConfigError> {
        let Some(url) = plain(env, "TODO_MARIADB_URL") else {
            return Ok(None);
        };
        reject_url_password("TODO_MARIADB_URL", &url)?;
        let config = Self {
            url,
            password: read_secret(env, "TODO_MARIADB_PASSWORD", mode)?,
        };
        config.connect_options()?;
        Ok(Some(config))
    }

    /// sqlx options with statement logging disabled (no connection is opened).
    pub fn connect_options(&self) -> Result<sqlx::mysql::MySqlConnectOptions, ConfigError> {
        todo_database::accounts::mariadb_options(&self.url, password(&self.password, "MariaDB")?)
    }
}

pub(super) fn password<'a>(
    secret: &'a Option<Secret>,
    what: &str,
) -> Result<Option<&'a str>, ConfigError> {
    secret
        .as_ref()
        .map(|s| {
            s.expose_str()
                .ok_or_else(|| ConfigError(format!("{what} password must be UTF-8")))
        })
        .transpose()
}

impl fmt::Display for MariaDbConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} password={}",
            self.url,
            super::opt_secret(&self.password)
        )
    }
}
