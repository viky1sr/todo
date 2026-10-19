use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::*;

const UPLOAD: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const PII: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
const TOKEN: &str = "c2VjcmV0LXRva2VuLWZvci1jb25maWctdGVzdHMtMDEyMw";
const DB_PW: &str = "Sup3r-Secret-Db-Passw0rd";

struct Env(HashMap<String, String>);

impl Env {
    fn new(pairs: &[(&str, &str)]) -> Self {
        Self(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    fn load(&self) -> Result<Config, ConfigError> {
        Config::load(&|k| self.0.get(k).cloned())
    }
}

struct SecretDir(PathBuf);

impl SecretDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("todo-config-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn write(&self, name: &str, value: &str, mode: u32) -> String {
        use std::os::unix::fs::PermissionsExt;
        let p = self.0.join(name);
        std::fs::write(&p, format!("{value}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p.display().to_string()
    }
}

impl Drop for SecretDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn assert_no_secret(text: &str) {
    for s in [UPLOAD, PII, TOKEN, DB_PW, "c2VjcmV0", "0011223344"] {
        assert!(!text.contains(s), "secret leaked into output:\n{text}");
    }
}

#[test]
fn defaults_without_secrets() {
    let c = Env::new(&[]).load().unwrap();
    assert_eq!(c.environment, Environment::Development);
    assert_eq!(
        (c.app.web_host.as_str(), c.app.web_port),
        ("127.0.0.1", 8000)
    );
    assert_eq!(c.app.rest_port, 8001);
    assert_eq!(c.ipfs.kind, IpfsKind::Mock);
    assert!(c.app.upload_key.is_none() && c.mariadb.is_none());
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
    assert!(c.to_string().contains("upload key     not set"));
}

#[test]
fn development_env_secrets_are_redacted_and_warned() {
    let c = Env::new(&[
        ("TODO_UPLOAD_KEY_HEX", UPLOAD),
        ("TODO_API_TOKEN", TOKEN),
        ("TODO_PII_KEY_HEX", PII),
        ("TODO_MARIADB_URL", "mysql://todo_app@localhost/todo"),
        ("TODO_MARIADB_PASSWORD", DB_PW),
        ("TODO_REDIS_URL", "redis://127.0.0.1:6379/0"),
    ])
    .load()
    .unwrap();
    assert_eq!(c.app.upload_key.as_ref().unwrap().expose().len(), 32);
    assert_eq!(
        c.mariadb
            .as_ref()
            .unwrap()
            .password
            .as_ref()
            .unwrap()
            .expose_str(),
        Some(DB_PW)
    );
    let shown = format!("{c}\n{c:?}");
    assert_no_secret(&shown);
    assert!(shown.contains("<redacted; env:TODO_MARIADB_PASSWORD>"));
    assert!(c.warnings.iter().any(|w| w.contains("docker inspect")));
    assert!(
        c.warnings
            .iter()
            .any(|w| w.contains("Redis without password"))
    );
    assert!(c.app.upload_config().unwrap().unwrap().requires_token());
    assert!(c.mariadb.as_ref().unwrap().connect_options().is_ok());
    assert!(c.redis.as_ref().unwrap().connection_info().is_ok());
}

#[test]
fn production_refuses_plain_env_secrets_without_echoing_them() {
    let dir = SecretDir::new("prod-env");
    let upload = dir.write("upload_key_hex", UPLOAD, 0o600);
    for (name, value) in [
        ("TODO_UPLOAD_KEY_HEX", UPLOAD),
        ("TODO_API_TOKEN", TOKEN),
        ("TODO_PII_KEY_HEX", PII),
    ] {
        let mut pairs = vec![("TODO_ENV", "production"), (name, value)];
        if name == "TODO_API_TOKEN" {
            pairs.push(("TODO_UPLOAD_KEY_HEX_FILE", &upload));
        }
        let err = Env::new(&pairs).load().unwrap_err().to_string();
        assert_no_secret(&err);
        assert!(err.contains(&format!("{name}_FILE")), "{err}");
        assert!(err.contains("Portainer"), "{err}");
    }
}

#[test]
fn production_with_docker_style_secret_files() {
    let dir = SecretDir::new("prod");
    let upload = dir.write("upload_key_hex", UPLOAD, 0o400);
    let pii = dir.write("pii_key_hex", PII, 0o600);
    let token = dir.write("api_token", TOKEN, 0o600);
    let maria = dir.write("mariadb_password", DB_PW, 0o600);
    let pg = dir.write("postgres_password", DB_PW, 0o600);
    let redis = dir.write("redis_password", DB_PW, 0o600);
    let c = Env::new(&[
        ("TODO_ENV", "production"),
        ("WEB_HOST", "0.0.0.0"),
        ("TODO_TLS_CERT", "/run/secrets/tls_cert.pem"),
        ("TODO_TLS_KEY", "/run/secrets/tls_key.pem"),
        ("TODO_UPLOAD_KEY_HEX_FILE", &upload),
        ("TODO_PII_KEY_HEX_FILE", &pii),
        ("TODO_API_TOKEN_FILE", &token),
        ("TODO_MARIADB_URL", "mysql://todo_app@db/todo"),
        ("TODO_MARIADB_PASSWORD_FILE", &maria),
        ("TODO_POSTGRES_URL", "postgres://todo_app@pg:5432/todo"),
        ("TODO_POSTGRES_PASSWORD_FILE", &pg),
        ("TODO_REDIS_URL", "redis://cache:6379/0"),
        ("TODO_REDIS_PASSWORD_FILE", &redis),
        ("TODO_IPFS_BACKEND", "kubo"),
        ("TODO_IPFS_URL", "http://ipfs:5001"),
        ("TODO_SESSION_IDLE_SECS", "600"),
    ])
    .load()
    .unwrap();
    let shown = format!("{c}\n{c:?}");
    assert_no_secret(&shown);
    assert!(
        shown.contains(&format!("<redacted; file:{upload}>")),
        "{shown}"
    );
    assert!(shown.contains("postgres://todo_app@pg:5432/todo"));
    assert!(shown.contains("idle=600s"));
    assert!(
        !c.warnings
            .iter()
            .any(|w| w.contains("docker inspect") || w.contains("TLS")),
        "{:?}",
        c.warnings
    );
    assert!(c.pgsql.as_ref().unwrap().connect_options().is_ok());
    assert!(c.ipfs.backend().is_ok());
}

#[test]
fn secret_files_must_be_owner_only_and_exclusive() {
    let dir = SecretDir::new("perm");
    let open = dir.write("upload_key_hex", UPLOAD, 0o644);
    let err = Env::new(&[("TODO_UPLOAD_KEY_HEX_FILE", &open)])
        .load()
        .unwrap_err();
    assert!(err.0.contains("chmod 600"), "{err}");
    let ok = dir.write("upload_key_ok", UPLOAD, 0o600);
    let err = Env::new(&[
        ("TODO_UPLOAD_KEY_HEX_FILE", &ok),
        ("TODO_UPLOAD_KEY_HEX", UPLOAD),
    ])
    .load()
    .unwrap_err();
    assert!(err.0.contains("only one of"), "{err}");
    assert_no_secret(&err.0);
}

#[test]
fn urls_with_passwords_are_rejected() {
    for (name, url) in [
        (
            "TODO_MARIADB_URL",
            "mysql://todo_app:hunter2@localhost/todo",
        ),
        (
            "TODO_POSTGRES_URL",
            "postgres://todo_app@pg/todo?password=hunter2",
        ),
        ("TODO_REDIS_URL", "redis://:hunter2@cache:6379/0"),
        ("TODO_IPFS_URL", "https://user:hunter2@ipfs.example"),
    ] {
        let err = Env::new(&[(name, url)]).load().unwrap_err();
        assert!(!err.0.contains("hunter2"), "{err}");
        assert!(err.0.contains(name) || err.0.contains("password"), "{err}");
    }
}

#[test]
fn cross_rules_and_key_validation() {
    let e = |pairs: &[(&str, &str)]| Env::new(pairs).load().unwrap_err().0;
    assert!(e(&[("TODO_UPLOAD_KEY_HEX", "abcd")]).contains("32 or 64 hex"));
    assert!(
        e(&[
            ("TODO_PII_KEY_HEX", UPLOAD),
            ("TODO_UPLOAD_KEY_HEX", UPLOAD)
        ])
        .contains("must differ")
    );
    assert!(e(&[("TODO_MARIADB_URL", "mysql://a@h/todo")]).contains("both"));
    assert!(
        e(&[
            ("TODO_MARIADB_URL", "mysql://a@h/todo"),
            ("TODO_REDIS_URL", "redis://h:6379/0")
        ])
        .contains("TODO_PII_KEY_HEX")
    );
    assert!(e(&[("TODO_POSTGRES_URL", "postgres://a@h/todo")]).contains("needs accounts"));
    assert!(e(&[("TODO_API_TOKEN", TOKEN)]).contains("TODO_UPLOAD_KEY_HEX"));
    assert!(
        e(&[("TODO_UPLOAD_KEY_HEX", UPLOAD), ("TODO_API_TOKEN", "short")])
            .contains("TODO_API_TOKEN must be")
    );
    assert!(
        !e(&[
            ("TODO_UPLOAD_KEY_HEX", UPLOAD),
            ("TODO_UPLOAD_ZSTD_LEVEL", "99")
        ])
        .is_empty()
    );
    assert!(e(&[("TODO_TLS_CERT", "/c.pem")]).contains("both"));
    assert!(e(&[("TODO_ENV", "staging")]).contains("TODO_ENV"));
    assert!(e(&[("TODO_IPFS_BACKEND", "gateway")]).contains("TODO_IPFS_URL"));
    assert!(e(&[("WEB_PORT", "http")]).contains("WEB_PORT"));
    assert!(
        e(&[
            ("TODO_REDIS_URL", "redis://h/0"),
            ("TODO_MARIADB_URL", "mysql://a@h/todo"),
            ("TODO_PII_KEY_HEX", PII),
            ("TODO_SESSION_IDLE_SECS", "7200"),
            ("TODO_SESSION_ABSOLUTE_SECS", "3600"),
        ])
        .contains("must not exceed")
    );
}

#[test]
fn secret_is_never_formatted_and_compares_in_constant_time() {
    let a = Secret::new(
        Zeroizing::new(b"value-one".to_vec()),
        SecretSource::Env("A".into()),
    );
    let b = Secret::new(
        Zeroizing::new(b"value-one".to_vec()),
        SecretSource::File(Path::new("/run/secrets/b").into()),
    );
    let c = Secret::new(
        Zeroizing::new(b"value-two".to_vec()),
        SecretSource::Env("C".into()),
    );
    assert!(a.ct_eq(&b) && !a.ct_eq(&c));
    assert_eq!(format!("{a}"), "<redacted; env:A>");
    assert_eq!(format!("{b:?}"), "<redacted; file:/run/secrets/b>");
    assert_eq!(
        format!("{:#?}", Some(&c)),
        "Some(\n    <redacted; env:C>,\n)"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn process_hardening_applies() {
    let h = harden_process();
    assert!(h.core_dumps_disabled && h.non_dumpable, "{h}");
}

#[test]
fn toml_files_hold_settings_and_secret_paths_env_overrides() {
    let dir = SecretDir::new("toml");
    let upload = dir.write("upload_key_hex", UPLOAD, 0o600);
    let pg = dir.write("postgres_password", DB_PW, 0o600);
    let maria = dir.write("mariadb_password", DB_PW, 0o600);
    let pii = dir.write("pii_key_hex", PII, 0o600);
    dir.write(
        "app.toml",
        &format!(
            "environment = \"production\"\n[web]\nhost = \"0.0.0.0\"\nport = 9000\n\
             [upload]\nkey_hex_file = \"{upload}\"\nmax_bytes = 1048576\n\
             [pii]\nkey_hex_file = \"{pii}\"\n"
        ),
        0o644,
    );
    dir.write(
        "ipfs.toml",
        "backend = \"kubo\"\nurl = \"http://ipfs:5001\"\n",
        0o644,
    );
    dir.write(
        "mariadb.toml",
        &format!("url = \"mysql://todo_app@db/todo\"\npassword_file = \"{maria}\"\n"),
        0o640,
    );
    dir.write(
        "pgsql.toml",
        &format!("url = \"postgres://todo_app@pg/todo\"\npassword_file = \"{pg}\"\n"),
        0o644,
    );
    dir.write(
        "redis.toml",
        "url = \"redis://cache:6379/0\"\n[session]\nidle_secs = 900\n",
        0o644,
    );
    let layer = TomlLayer::load(&dir.0).unwrap();
    assert_eq!(layer.files.len(), 5);
    let env = Env::new(&[("WEB_PORT", "9443")]);
    let c = Config::load_layered(&|k| env.0.get(k).cloned(), layer).unwrap();
    assert_eq!(c.environment, Environment::Production);
    assert_eq!((c.app.web_host.as_str(), c.app.web_port), ("0.0.0.0", 9443));
    assert_eq!(c.app.limits.max_bytes, Some(1 << 20));
    assert_eq!(c.ipfs.kind, IpfsKind::Kubo);
    assert_eq!(c.redis.as_ref().unwrap().policy.idle_ttl.as_secs(), 900);
    assert_eq!(
        c.pgsql
            .as_ref()
            .unwrap()
            .password
            .as_ref()
            .unwrap()
            .expose_str(),
        Some(DB_PW)
    );
    let shown = format!("{c}\n{c:?}");
    assert_no_secret(&shown);
    assert!(shown.contains("env over toml"), "{shown}");
}

#[test]
fn toml_rejects_secret_values_unknown_keys_and_loose_permissions() {
    let cases = [
        (
            "mariadb.toml",
            "password = \"x\"\n",
            "secret in the config file",
        ),
        (
            "app.toml",
            "[upload]\nkey_hex = \"00\"\n",
            "secret in the config file",
        ),
        (
            "app.toml",
            "[upload]\napi_token = \"x\"\n",
            "secret in the config file",
        ),
        ("redis.toml", "uri = \"redis://h\"\n", "unknown key `uri`"),
        ("app.toml", "[web]\nport = true\n", "string or an integer"),
        ("ipfs.toml", "backend = ", "invalid TOML"),
    ];
    for (i, (file, body, expect)) in cases.into_iter().enumerate() {
        let dir = SecretDir::new(&format!("toml-bad{i}"));
        dir.write(file, body, 0o644);
        let err = TomlLayer::load(&dir.0).unwrap_err().0;
        assert!(err.contains(expect), "{file}: {err}");
        assert!(!err.contains("\"x\""), "{err}");
    }
    let dir = SecretDir::new("toml-mode");
    dir.write("app.toml", "[web]\nport = 1\n", 0o666);
    assert!(TomlLayer::load(&dir.0).unwrap_err().0.contains("writable"));
    assert!(TomlLayer::load(Path::new("/nonexistent-todo-config")).is_err());
}

#[test]
fn repo_toml_files_are_active_and_valid() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("config");
    let active = TomlLayer::load(&repo).unwrap();
    assert_eq!(active.files.len(), 5);
    assert_eq!(active.get("TODO_ENV").as_deref(), Some("production"));
    assert_eq!(active.get("TODO_IPFS_BACKEND").as_deref(), Some("kubo"));
    assert_eq!(
        active.get("TODO_IPFS_URL").as_deref(),
        Some("http://127.0.0.1:5001")
    );
    assert_eq!(
        active.get("TODO_MARIADB_URL").as_deref(),
        Some("mysql://visry@localhost:3306/todo")
    );
    assert_eq!(
        active.get("TODO_POSTGRES_URL").as_deref(),
        Some("postgres://visry@localhost:5432/todo")
    );
    assert_eq!(
        active.get("TODO_REDIS_URL").as_deref(),
        Some("redis://127.0.0.1:6379/0")
    );
    let cfg = Config::load_layered(&|_| None, active).unwrap();
    assert_eq!(cfg.environment, Environment::Production);
    assert_eq!(cfg.ipfs.kind, IpfsKind::Kubo);
}
