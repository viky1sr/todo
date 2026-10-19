//! TOML configuration loader for workspace services.
//!
//! Loads non-secret settings and secret file paths from `config/*.toml` (or
//! `TODO_CONFIG_TOML_DIR`) and applies them to the process environment if not already set.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::ConfigError;

const MAX_TOML_BYTES: u64 = 64 * 1024;

/// `(file, dotted key, environment variable)`.
const KEYS: &[(&str, &str, &str)] = &[
    ("app.toml", "environment", "TODO_ENV"),
    ("app.toml", "web.host", "WEB_HOST"),
    ("app.toml", "web.port", "WEB_PORT"),
    ("app.toml", "rest.host", "REST_HOST"),
    ("app.toml", "rest.port", "REST_PORT"),
    ("app.toml", "tls.cert", "TODO_TLS_CERT"),
    ("app.toml", "tls.key", "TODO_TLS_KEY"),
    (
        "app.toml",
        "upload.key_hex_file",
        "TODO_UPLOAD_KEY_HEX_FILE",
    ),
    ("app.toml", "upload.api_token_file", "TODO_API_TOKEN_FILE"),
    ("app.toml", "upload.max_bytes", "TODO_UPLOAD_MAX_BYTES"),
    (
        "app.toml",
        "upload.max_concurrent",
        "TODO_UPLOAD_MAX_CONCURRENT",
    ),
    ("app.toml", "upload.zstd_level", "TODO_UPLOAD_ZSTD_LEVEL"),
    ("app.toml", "upload.temp_dir", "TODO_UPLOAD_TMPDIR"),
    ("app.toml", "pii.key_hex_file", "TODO_PII_KEY_HEX_FILE"),
    ("ipfs.toml", "backend", "TODO_IPFS_BACKEND"),
    ("ipfs.toml", "url", "TODO_IPFS_URL"),
    (
        "ipfs.toml",
        "rpc_authorization_file",
        "TODO_IPFS_RPC_AUTHORIZATION_FILE",
    ),
    ("ipfs.toml", "local_only", "TODO_IPFS_LOCAL_ONLY"),
    ("ipfs.toml", "rukubo.repo_dir", "TODO_KUBO_REPO"),
    ("ipfs.toml", "rukubo.binary", "TODO_KUBO_BIN"),
    ("mariadb.toml", "url", "TODO_MARIADB_URL"),
    (
        "mariadb.toml",
        "password_file",
        "TODO_MARIADB_PASSWORD_FILE",
    ),
    ("pgsql.toml", "url", "TODO_POSTGRES_URL"),
    ("pgsql.toml", "password_file", "TODO_POSTGRES_PASSWORD_FILE"),
    ("redis.toml", "url", "TODO_REDIS_URL"),
    ("redis.toml", "password_file", "TODO_REDIS_PASSWORD_FILE"),
    ("redis.toml", "session.idle_secs", "TODO_SESSION_IDLE_SECS"),
    (
        "redis.toml",
        "session.absolute_secs",
        "TODO_SESSION_ABSOLUTE_SECS",
    ),
];

const FILES: [&str; 5] = [
    "app.toml",
    "ipfs.toml",
    "mariadb.toml",
    "pgsql.toml",
    "redis.toml",
];

/// Leaf names that would carry a secret value instead of a path.
const SECRET_VALUE_KEYS: [&str; 7] = [
    "password",
    "key",
    "key_hex",
    "api_token",
    "token",
    "secret",
    "pii_key",
];

/// Values loaded from the TOML files, keyed by environment variable name.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TomlLayer {
    pub dir: Option<PathBuf>,
    pub files: Vec<String>,
    pub values: HashMap<&'static str, String>,
}

impl TomlLayer {
    pub fn get(&self, env_name: &str) -> Option<String> {
        self.values.get(env_name).cloned()
    }

    /// Load every known file present in `dir` (missing files are skipped).
    pub fn load(dir: &Path) -> Result<Self, ConfigError> {
        if !dir.is_dir() {
            return Err(ConfigError(format!(
                "TODO_CONFIG_TOML_DIR {} is not a directory",
                dir.display()
            )));
        }
        let mut layer = Self {
            dir: Some(dir.to_path_buf()),
            ..Self::default()
        };
        for file in FILES {
            let path = dir.join(file);
            if !path.exists() {
                continue;
            }
            let text = read_config_file(&path)?;
            let table: toml::Table = text.parse().map_err(|e: toml::de::Error| {
                ConfigError(format!("{}: invalid TOML: {}", path.display(), e.message()))
            })?;
            layer.insert(file, "", &table)?;
            layer.files.push(file.to_string());
        }
        Ok(layer)
    }

    fn insert(&mut self, file: &str, prefix: &str, table: &toml::Table) -> Result<(), ConfigError> {
        for (k, v) in table {
            let key = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{prefix}.{k}")
            };
            let known = KEYS.iter().any(|(f, k, _)| *f == file && *k == key);
            // `tls.key` is a PEM path; any other bare `key`/`password`/... is a secret value.
            if !known
                && SECRET_VALUE_KEYS.contains(&k.as_str())
                && !matches!(v, toml::Value::Table(_))
            {
                return Err(ConfigError(format!(
                    "{file}: `{key}` would store a secret in the config file; put the value in \
                     an owner-only file (e.g. a Docker secret) and set `{key}_file`"
                )));
            }
            let text = match v {
                toml::Value::Table(t) => {
                    self.insert(file, &key, t)?;
                    continue;
                }
                toml::Value::String(s) => s.clone(),
                toml::Value::Integer(i) => i.to_string(),
                _ => {
                    return Err(ConfigError(format!(
                        "{file}: `{key}` must be a string or an integer"
                    )));
                }
            };
            let Some((_, _, env)) = KEYS.iter().find(|(f, k, _)| *f == file && *k == key) else {
                return Err(ConfigError(format!("{file}: unknown key `{key}`")));
            };
            self.values.insert(env, text);
        }
        Ok(())
    }
}

/// Automatically loads `./config/*.toml` or `TODO_CONFIG_TOML_DIR` and populates
/// missing environment variables into the current process.
pub fn init_config_env() -> Result<TomlLayer, ConfigError> {
    let dir = match std::env::var("TODO_CONFIG_TOML_DIR") {
        Ok(dir) => Some(PathBuf::from(dir)),
        Err(_) if Path::new("config").is_dir() => Some(PathBuf::from("config")),
        Err(_) => None,
    };
    if let Some(dir) = dir {
        let layer = TomlLayer::load(&dir)?;
        for (&env_name, val) in &layer.values {
            if std::env::var(env_name).is_err() {
                // SAFETY: Executed during early single-threaded application startup before spawning worker threads.
                unsafe {
                    std::env::set_var(env_name, val);
                }
            }
        }
        Ok(layer)
    } else {
        Ok(TomlLayer::default())
    }
}

#[cfg(unix)]
fn check_mode(path: &Path, meta: &std::fs::Metadata) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;
    if meta.permissions().mode() & 0o022 != 0 {
        return Err(ConfigError(format!(
            "{} must not be writable by group/others (chmod 644 or 640)",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_mode(_: &Path, _: &std::fs::Metadata) -> Result<(), ConfigError> {
    Ok(())
}

fn read_config_file(path: &Path) -> Result<String, ConfigError> {
    let bad = |m: &str| ConfigError(format!("{}: {m}", path.display()));
    let meta = std::fs::metadata(path).map_err(|_| bad("cannot read"))?;
    if !meta.is_file() {
        return Err(bad("not a regular file"));
    }
    if meta.len() > MAX_TOML_BYTES {
        return Err(bad("larger than 64 KiB"));
    }
    check_mode(path, &meta)?;
    std::fs::read_to_string(path).map_err(|_| bad("cannot read as UTF-8"))
}
