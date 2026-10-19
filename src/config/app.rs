//! HTTP front ends, TLS, object keys and upload limits.

use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;

use super::{ConfigError, Environment, Lookup, Secret, number, plain, read_hex_key, read_secret};

/// PEM files for in-process TLS 1.3 (`TODO_TLS_CERT`, `TODO_TLS_KEY`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Optional overrides; `None` keeps the `todo-rest` defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UploadLimits {
    pub max_bytes: Option<u64>,
    pub max_concurrent: Option<usize>,
    pub zstd_level: Option<i32>,
    pub temp_dir: Option<PathBuf>,
}

impl fmt::Display for UploadLimits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = |v: Option<String>| v.unwrap_or_else(|| "default".into());
        write!(
            f,
            "max_bytes={} max_concurrent={} zstd_level={} tmpdir={}",
            d(self.max_bytes.map(|v| v.to_string())),
            d(self.max_concurrent.map(|v| v.to_string())),
            d(self.zstd_level.map(|v| v.to_string())),
            d(self.temp_dir.as_ref().map(|p| p.display().to_string())),
        )
    }
}

#[derive(Debug)]
pub struct AppConfig {
    pub web_host: String,
    pub web_port: u16,
    pub rest_host: String,
    pub rest_port: u16,
    pub tls: Option<TlsPaths>,
    /// Object key (AES-128/256-GCM-SIV), 16 or 32 bytes.
    pub upload_key: Option<Secret>,
    /// Bearer token for the object routes.
    pub api_token: Option<Secret>,
    /// PII column key (AES-256-GCM-SIV), 32 bytes, distinct from the object key.
    pub pii_key: Option<Secret>,
    pub limits: UploadLimits,
}

impl AppConfig {
    pub(super) fn load(env: Lookup<'_>, mode: Environment) -> Result<Self, ConfigError> {
        let tls = match (plain(env, "TODO_TLS_CERT"), plain(env, "TODO_TLS_KEY")) {
            (None, None) => None,
            (Some(cert), Some(key)) => Some(TlsPaths {
                cert: cert.into(),
                key: key.into(),
            }),
            _ => {
                return Err(ConfigError(
                    "set both TODO_TLS_CERT and TODO_TLS_KEY (PEM files) or neither".into(),
                ));
            }
        };
        let config = Self {
            web_host: plain(env, "WEB_HOST").unwrap_or_else(|| "127.0.0.1".into()),
            web_port: number(env, "WEB_PORT")?.unwrap_or(8000),
            rest_host: plain(env, "REST_HOST").unwrap_or_else(|| "127.0.0.1".into()),
            // Kubo's loopback-only gateway uses 8080 by default.
            rest_port: number(env, "REST_PORT")?.unwrap_or(8001),
            tls,
            upload_key: read_hex_key(env, "TODO_UPLOAD_KEY_HEX", mode, &[16, 32])?,
            api_token: read_secret(env, "TODO_API_TOKEN", mode)?,
            pii_key: read_hex_key(env, "TODO_PII_KEY_HEX", mode, &[32])?,
            limits: UploadLimits {
                max_bytes: number(env, "TODO_UPLOAD_MAX_BYTES")?,
                max_concurrent: number(env, "TODO_UPLOAD_MAX_CONCURRENT")?,
                zstd_level: number(env, "TODO_UPLOAD_ZSTD_LEVEL")?,
                temp_dir: plain(env, "TODO_UPLOAD_TMPDIR").map(PathBuf::from),
            },
        };
        if config.upload_key.is_none() && config.api_token.is_some() {
            return Err(ConfigError(
                "TODO_API_TOKEN is set but TODO_UPLOAD_KEY_HEX is not".into(),
            ));
        }
        // Validate ranges with the same code that will use them.
        drop(config.upload_config()?);
        Ok(config)
    }

    pub fn web_host_is_loopback(&self) -> bool {
        self.web_host == "localhost"
            || self
                .web_host
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    }

    /// `todo-rest` upload configuration; `None` when no object key is set.
    pub fn upload_config(&self) -> Result<Option<todo_rest::UploadConfig>, ConfigError> {
        let Some(key) = &self.upload_key else {
            return Ok(None);
        };
        let err = |e: todo_rest::RestError| ConfigError(e.to_string());
        let mut cfg = todo_rest::UploadConfig::new(key.expose()).map_err(err)?;
        let l = &self.limits;
        if let Some(v) = l.max_bytes {
            cfg = cfg.with_max_upload_bytes(v).map_err(err)?;
        }
        if let Some(v) = l.max_concurrent {
            cfg = cfg.with_max_concurrent(v).map_err(err)?;
        }
        if let Some(v) = l.zstd_level {
            cfg = cfg.with_compression_level(v).map_err(err)?;
        }
        if let Some(dir) = &l.temp_dir {
            cfg = cfg.with_temp_dir(dir);
        }
        if let Some(token) = &self.api_token {
            let token = token
                .expose_str()
                .ok_or_else(|| ConfigError("TODO_API_TOKEN must be text".into()))?;
            cfg = cfg.with_api_token(token).map_err(|_| {
                ConfigError(format!(
                    "TODO_API_TOKEN must be {}..={} base64/base64url characters",
                    todo_rest::upload::MIN_API_TOKEN_LEN,
                    todo_rest::upload::MAX_API_TOKEN_LEN
                ))
            })?;
        }
        Ok(Some(cfg))
    }
}
