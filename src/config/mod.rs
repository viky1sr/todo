//! Runtime configuration for the whole stack (web/REST, IPFS, MariaDB, PostgreSQL, Redis),
//! safe to print in container logs (Docker, Portainer) and careful with secrets in memory.
//!
//! **Console/logs.** [`Secret`] has no `Display`/`Debug`/`Serialize` that reveals its
//! value: it prints `<redacted; file:/run/secrets/x>`. No length, no hash (a stable hash
//! of a password in a log would allow offline guessing). URLs never contain passwords
//! (rejected at load), so [`Config`]'s `Display` report can be logged as is.
//!
//! **Sources.** Non-secret settings and *paths* of secret files come from TOML files in
//! `TODO_CONFIG_TOML_DIR` (default `./config`, see [`TomlLayer`]); any environment
//! variable overrides the TOML value. Secret *values* are never accepted in TOML.
//!
//! **Docker/Portainer.** Container environment variables are shown by `docker inspect`
//! and in Portainer's container view, and stay readable in `/proc/<pid>/environ`. In
//! `TODO_ENV=production` every secret must therefore come from a file (`NAME_FILE`,
//! e.g. a Docker secret under `/run/secrets/`); `NAME=<value>` is refused. Secret files
//! must be regular, owner-only (`0400`/`0600`) and ≤ 4 KiB.
//!
//! **Memory.** Secret bytes live in one exact-size heap buffer that is zeroized on drop,
//! is never cloned, and is `mlock`ed (best effort) so it is not swapped out.
//! [`harden_process`] disables core dumps and marks the process non-dumpable, which also
//! makes `/proc/<pid>/{environ,mem}` unreadable for other processes of the same user.

mod app;
mod ipfs;
mod layer;
mod mariadb;
mod pgsql;
mod redis;

use std::fmt;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

pub use app::{AppConfig, TlsPaths, UploadLimits};
pub use ipfs::{IpfsConfig, IpfsKind};
pub use layer::TomlLayer;
pub use mariadb::MariaDbConfig;
pub use pgsql::PgsqlConfig;
pub use redis::RedisConfig;
pub use todo_database::ConfigError;

/// Variable lookup (`std::env::var` in production, a map in tests).
pub type Lookup<'a> = &'a dyn Fn(&str) -> Option<String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Development,
    Production,
}

impl Environment {
    fn parse(value: Option<&str>) -> Result<Self, ConfigError> {
        match value.map(str::trim) {
            None | Some("") | Some("development") | Some("dev") => Ok(Self::Development),
            Some("production") | Some("prod") => Ok(Self::Production),
            Some(_) => Err(ConfigError(
                "TODO_ENV must be development or production".into(),
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Production => "production",
        }
    }
}

/// Where a secret came from (printed instead of the value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretSource {
    File(PathBuf),
    /// Plain environment variable (development only).
    Env(String),
}

impl fmt::Display for SecretSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(p) => write!(f, "file:{}", p.display()),
            Self::Env(name) => write!(f, "env:{name}"),
        }
    }
}

/// A secret value: zeroized on drop, never cloned, never printed.
pub struct Secret {
    bytes: Zeroizing<Vec<u8>>,
    source: SecretSource,
    locked: bool,
}

impl Secret {
    fn new(bytes: Zeroizing<Vec<u8>>, source: SecretSource) -> Self {
        let locked = lock_memory(&bytes);
        Self {
            bytes,
            source,
            locked,
        }
    }

    /// The raw value. Keep the borrow short; never log it.
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    /// The value as text (passwords, tokens); `None` for binary keys.
    pub fn expose_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.bytes).ok()
    }

    pub fn source(&self) -> &SecretSource {
        &self.source
    }

    /// Whether the buffer is `mlock`ed (not swappable).
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Constant-time equality (no early exit on the first differing byte).
    pub fn ct_eq(&self, other: &Secret) -> bool {
        let (a, b) = (self.expose(), other.expose());
        a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted; {}>", self.source)
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Best-effort `mlock` of a secret buffer. The pages are left locked after the buffer
/// is zeroized and freed (`munlock` could unlock a page still holding another secret).
#[cfg(unix)]
fn lock_memory(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    // SAFETY: `buf` is a valid, live allocation of `buf.len()` bytes; mlock only changes
    // paging behaviour of the pages containing it and does not access the memory.
    unsafe { libc::mlock(buf.as_ptr().cast(), buf.len()) == 0 }
}

#[cfg(not(unix))]
fn lock_memory(_: &[u8]) -> bool {
    false
}

/// Result of [`harden_process`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Hardening {
    pub core_dumps_disabled: bool,
    pub non_dumpable: bool,
}

/// Disable core dumps (`RLIMIT_CORE = 0`) and set `PR_SET_DUMPABLE = 0` (Linux), so
/// secrets cannot end up in a core file and other same-user processes cannot read this
/// process's memory or environment. Call once, before loading secrets.
pub fn harden_process() -> Hardening {
    #[cfg(target_os = "linux")]
    {
        let rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: plain syscalls with valid arguments; no memory is shared with the kernel
        // beyond the `rl` struct, which outlives the call.
        unsafe {
            Hardening {
                core_dumps_disabled: libc::setrlimit(libc::RLIMIT_CORE, &rl) == 0,
                non_dumpable: libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0,
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    Hardening::default()
}

/// Read secret `name` from `NAME_FILE` (preferred) or `NAME`.
fn read_secret(
    env: Lookup<'_>,
    name: &str,
    mode: Environment,
) -> Result<Option<Secret>, ConfigError> {
    let file_var = format!("{name}_FILE");
    let value = env(name).map(Zeroizing::new);
    match (env(&file_var), value) {
        (Some(_), Some(_)) => Err(ConfigError(format!(
            "set only one of {name} and {file_var}"
        ))),
        (Some(path), None) => {
            let path = PathBuf::from(path);
            let text = todo_database::secrets::read_secret_file(Path::new(&path), &file_var)?;
            Ok(Some(Secret::new(
                Zeroizing::new(text.as_bytes().to_vec()),
                SecretSource::File(path),
            )))
        }
        (None, Some(_)) if mode == Environment::Production => Err(ConfigError(format!(
            "{name} is set as a plain environment variable, which docker inspect/Portainer \
             display; in production use {file_var} (e.g. a Docker secret in /run/secrets)"
        ))),
        (None, Some(value)) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(ConfigError(format!("{name} is empty")));
            }
            Ok(Some(Secret::new(
                Zeroizing::new(trimmed.as_bytes().to_vec()),
                SecretSource::Env(name.to_string()),
            )))
        }
        (None, None) => Ok(None),
    }
}

/// Read a hex-encoded key secret and decode it; `lens` = allowed key sizes in bytes.
fn read_hex_key(
    env: Lookup<'_>,
    name: &str,
    mode: Environment,
    lens: &[usize],
) -> Result<Option<Secret>, ConfigError> {
    let Some(text) = read_secret(env, name, mode)? else {
        return Ok(None);
    };
    let bad = || {
        let sizes: Vec<String> = lens.iter().map(|n| (n * 2).to_string()).collect();
        ConfigError(format!("{name} must be {} hex digits", sizes.join(" or ")))
    };
    let decoded = text
        .expose_str()
        .and_then(todo_database::decode_hex)
        .map(Zeroizing::new)
        .ok_or_else(bad)?;
    if !lens.contains(&decoded.len()) {
        return Err(bad());
    }
    Ok(Some(Secret::new(decoded, text.source.clone())))
}

fn plain(env: Lookup<'_>, name: &str) -> Option<String> {
    env(name)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn number<T: std::str::FromStr>(env: Lookup<'_>, name: &str) -> Result<Option<T>, ConfigError> {
    plain(env, name)
        .map(|v| {
            v.parse()
                .map_err(|_| ConfigError(format!("{name} must be a number")))
        })
        .transpose()
}

/// Rejects credentials embedded in a URL (`user:pass@` or `?password=`): they would be
/// printed by every tool that shows the environment or the configuration.
fn reject_url_password(name: &str, url: &str) -> Result<(), ConfigError> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let userinfo_pw = authority
        .rsplit_once('@')
        .is_some_and(|(userinfo, _)| userinfo.contains(':'));
    let query_pw = rest.split_once('?').is_some_and(|(_, q)| {
        q.split('&').any(|kv| {
            let key = kv.split('=').next().unwrap_or("").to_ascii_lowercase();
            matches!(key.as_str(), "password" | "pass" | "pwd" | "token")
        })
    });
    if userinfo_pw || query_pw {
        return Err(ConfigError(format!(
            "{name} must not contain a password; use the matching *_PASSWORD_FILE"
        )));
    }
    Ok(())
}

/// The complete configuration. `Display` renders a redacted multi-line report.
#[derive(Debug)]
pub struct Config {
    pub environment: Environment,
    pub app: AppConfig,
    pub ipfs: IpfsConfig,
    pub mariadb: Option<MariaDbConfig>,
    pub pgsql: Option<PgsqlConfig>,
    pub redis: Option<RedisConfig>,
    /// TOML files that were read (empty when none).
    pub toml: TomlLayer,
    /// Non-fatal findings, safe to log.
    pub warnings: Vec<String>,
}

impl Config {
    /// Load from `TODO_CONFIG_TOML_DIR` (or `./config` if present) overridden by the
    /// process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        let env = |name: &str| std::env::var(name).ok();
        let toml = match env("TODO_CONFIG_TOML_DIR") {
            Some(dir) => TomlLayer::load(Path::new(&dir))?,
            None if Path::new("config").is_dir() => TomlLayer::load(Path::new("config"))?,
            None => TomlLayer::default(),
        };
        Self::load_layered(&env, toml)
    }

    /// Environment over TOML.
    pub fn load_layered(env: Lookup<'_>, toml: TomlLayer) -> Result<Self, ConfigError> {
        let mut config = Self::load(&|name| env(name).or_else(|| toml.get(name)))?;
        config.toml = toml;
        Ok(config)
    }

    /// Load and validate from one lookup; errors name the variable, never its value.
    pub fn load(env: Lookup<'_>) -> Result<Self, ConfigError> {
        let environment = Environment::parse(env("TODO_ENV").as_deref())?;
        let app = AppConfig::load(env, environment)?;
        let ipfs = IpfsConfig::load(env)?;
        let mariadb = MariaDbConfig::load(env, environment)?;
        let pgsql = PgsqlConfig::load(env, environment)?;
        let redis = RedisConfig::load(env, environment)?;

        if mariadb.is_some() != redis.is_some() {
            return Err(ConfigError(
                "accounts need both TODO_MARIADB_URL and TODO_REDIS_URL (or neither)".into(),
            ));
        }
        if mariadb.is_some() && app.pii_key.is_none() {
            return Err(ConfigError(
                "TODO_MARIADB_URL requires TODO_PII_KEY_HEX(_FILE)".into(),
            ));
        }
        if pgsql.is_some() && mariadb.is_none() {
            return Err(ConfigError(
                "TODO_POSTGRES_URL needs accounts (TODO_MARIADB_URL + TODO_REDIS_URL)".into(),
            ));
        }
        if let (Some(pii), Some(upload)) = (&app.pii_key, &app.upload_key)
            && pii.ct_eq(upload)
        {
            return Err(ConfigError(
                "TODO_PII_KEY_HEX must differ from TODO_UPLOAD_KEY_HEX".into(),
            ));
        }

        let mut config = Self {
            environment,
            app,
            ipfs,
            mariadb,
            pgsql,
            redis,
            toml: TomlLayer::default(),
            warnings: Vec::new(),
        };
        config.warnings = config.collect_warnings();
        Ok(config)
    }

    fn secrets(&self) -> impl Iterator<Item = &Secret> {
        [
            self.app.upload_key.as_ref(),
            self.app.api_token.as_ref(),
            self.app.pii_key.as_ref(),
            self.mariadb.as_ref().and_then(|m| m.password.as_ref()),
            self.pgsql.as_ref().and_then(|p| p.password.as_ref()),
            self.redis.as_ref().and_then(|r| r.password.as_ref()),
        ]
        .into_iter()
        .flatten()
    }

    fn collect_warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        let from_env: Vec<&str> = self
            .secrets()
            .filter_map(|s| match s.source() {
                SecretSource::Env(name) => Some(name.as_str()),
                SecretSource::File(_) => None,
            })
            .collect();
        if !from_env.is_empty() {
            w.push(format!(
                "secrets from plain environment variables ({}) are visible in docker \
                 inspect/Portainer; use *_FILE",
                from_env.join(", ")
            ));
        }
        if self.secrets().any(|s| !s.is_locked()) {
            w.push(
                "some secret buffers could not be mlocked (RLIMIT_MEMLOCK); they may be \
                 swapped to disk"
                    .into(),
            );
        }
        if self.ipfs.kind == IpfsKind::Mock && self.app.upload_key.is_some() {
            w.push(
                "IPFS backend is MOCK (in-memory, not IPFS): objects are lost on restart".into(),
            );
        }
        if self.app.tls.is_none() && !self.app.web_host_is_loopback() {
            w.push(format!(
                "WEB_HOST {} is not loopback and TLS is off: terminate TLS at a reverse proxy",
                self.app.web_host
            ));
        }
        if self.app.upload_key.is_some()
            && self.app.api_token.is_none()
            && self.mariadb.is_none()
            && !self.app.web_host_is_loopback()
        {
            w.push("object routes have no authentication and the bind is not loopback; todo-web will refuse to start".into());
        }
        if self.redis.as_ref().is_some_and(|r| r.password.is_none()) {
            w.push(
                "Redis without password/ACL (set requirepass and TODO_REDIS_PASSWORD_FILE)".into(),
            );
        }
        w
    }
}

fn on_off(b: bool) -> &'static str {
    if b { "on" } else { "off" }
}

fn opt_secret(s: &Option<Secret>) -> String {
    s.as_ref()
        .map_or_else(|| "not set".into(), |s| s.to_string())
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a = &self.app;
        writeln!(
            f,
            "todo configuration (environment={})",
            self.environment.as_str()
        )?;
        match &self.toml.dir {
            Some(dir) if !self.toml.files.is_empty() => writeln!(
                f,
                "  sources        env over toml {} ({})",
                dir.display(),
                self.toml.files.join(", ")
            )?,
            _ => writeln!(f, "  sources        env")?,
        }
        writeln!(f, "  web            {}:{}", a.web_host, a.web_port)?;
        writeln!(f, "  rest           {}:{}", a.rest_host, a.rest_port)?;
        match &a.tls {
            Some(t) => writeln!(
                f,
                "  tls            on (cert={}, key={})",
                t.cert.display(),
                t.key.display()
            )?,
            None => writeln!(f, "  tls            off")?,
        }
        writeln!(f, "  upload key     {}", opt_secret(&a.upload_key))?;
        writeln!(f, "  api token      {}", opt_secret(&a.api_token))?;
        writeln!(f, "  pii key        {}", opt_secret(&a.pii_key))?;
        writeln!(f, "  upload limits  {}", a.limits)?;
        writeln!(f, "  ipfs           {}", self.ipfs)?;
        match &self.mariadb {
            Some(m) => writeln!(f, "  mariadb        {m}")?,
            None => writeln!(f, "  mariadb        disabled")?,
        }
        match &self.redis {
            Some(r) => writeln!(f, "  redis          {r}")?,
            None => writeln!(f, "  redis          disabled")?,
        }
        match &self.pgsql {
            Some(p) => writeln!(f, "  postgresql     {p}")?,
            None => writeln!(f, "  postgresql     disabled")?,
        }
        let locked = self.secrets().filter(|s| s.is_locked()).count();
        writeln!(
            f,
            "  memory         {} secret(s), {locked} mlocked, zeroized on drop",
            self.secrets().count()
        )?;
        for w in &self.warnings {
            writeln!(f, "  warning: {w}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Hardening {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "core dumps disabled: {}, non-dumpable: {}",
            on_off(self.core_dumps_disabled),
            on_off(self.non_dumpable)
        )
    }
}

#[cfg(test)]
pub(crate) mod tests;
