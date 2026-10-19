//! Askama page models. Templates live in `crates/web/templates/` and are compiled into
//! the binary; all interactivity is in `static/app.js` (no inline scripts, see the CSP in
//! [`crate::server`]).

use askama::Template;
use todo_crypto::{DEFAULT_POLYVAL_SEGMENT_SIZE, SegmentationPolicy};
use todo_ipfs::{BackendKind, DEFAULT_CHUNK_SIZE};
use todo_zstd::pipeline::DEFAULT_MAX_DECOMPRESSED_SIZE;

/// Largest raw input the browser UI sends (hex-encoded it fits in [`crate::server::MAX_BODY_BYTES`]).
pub const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;
/// Largest input for the tamper demo (its sealed JSON is sent back to the server).
pub const MAX_TAMPER_INPUT_BYTES: usize = 1024 * 1024;

/// Data shared by every page (header, navigation, footer).
#[derive(Debug, Clone)]
pub struct Shell {
    pub active: &'static str,
    pub version: &'static str,
    pub build_profile: &'static str,
    pub backend_kind: &'static str,
    pub backend_label: &'static str,
    pub backend_live: bool,
}

impl Shell {
    pub fn new(active: &'static str, backend: BackendKind) -> Self {
        Self {
            active,
            version: env!("CARGO_PKG_VERSION"),
            build_profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
            backend_kind: match backend {
                BackendKind::Mock => "mock",
                BackendKind::KuboRpc => "kubo",
                BackendKind::TrustlessGateway => "gateway",
            },
            backend_label: backend.label(),
            backend_live: backend != BackendKind::Mock,
        }
    }

    pub fn is_debug(&self) -> bool {
        self.build_profile == "debug"
    }
}

#[derive(Template)]
#[template(path = "production/overview.html")]
pub struct DashboardPage {
    pub shell: Shell,
    pub session_user: Option<String>,
    pub session_role: &'static str,
    pub rayon_threads: usize,
    pub logical_cpus: usize,
    pub polyval_default_segment: String,
    pub min_parallel: String,
    pub adaptive_segment_range: String,
    pub max_decompressed: String,
    pub accounts_enabled: bool,
    pub catalog_enabled: bool,
}

#[derive(Template)]
#[template(path = "research/pipeline.html")]
pub struct PipelinePage {
    pub shell: Shell,
    pub max_input_bytes: usize,
    pub max_input: String,
    pub max_tamper_bytes: usize,
    pub min_parallel: String,
    pub rayon_threads: usize,
}

#[derive(Template)]
#[template(path = "research/equivalence.html")]
pub struct EquivalencePage {
    pub shell: Shell,
    pub max_input_bytes: usize,
    pub rayon_threads: usize,
}

#[derive(Template)]
#[template(path = "research/benchmark.html")]
pub struct BenchmarkPage {
    pub shell: Shell,
    pub rayon_threads: usize,
    pub logical_cpus: usize,
}

#[derive(Template)]
#[template(path = "research/overview.html")]
pub struct ResearchPage {
    pub shell: Shell,
    pub rayon_threads: usize,
    pub logical_cpus: usize,
    pub max_input: String,
}

#[derive(Template)]
#[template(path = "production/explorer.html")]
pub struct StoragePage {
    pub shell: Shell,
    pub block_size: String,
    pub max_input_bytes: usize,
    pub max_input: String,
}

#[derive(Template)]
#[template(path = "production/node_control.html")]
pub struct RukuboPage {
    pub shell: Shell,
    pub running: bool,
    pub repository: String,
    pub managed_pid: Option<u32>,
}

pub fn rukubo(backend: BackendKind, status: rukubo::RukuboStatus) -> RukuboPage {
    RukuboPage {
        shell: Shell::new("rukubo", backend),
        running: status.running,
        repository: status.repository,
        managed_pid: status.managed_pid,
    }
}

#[derive(Template)]
#[template(path = "production/objects.html")]
pub struct VaultPage {
    pub shell: Shell,
    pub upload_enabled: bool,
    /// Bearer-token card shown (token configured and no session).
    pub auth_required: bool,
    /// Accounts enabled and no session: object routes need a login.
    pub login_required: bool,
    /// Logged-in username (session cookie), if any.
    pub session_user: Option<String>,
    /// Object list comes from the server-side metadata store (Layer 4) for this user.
    pub persistent_list: bool,
    pub max_upload_bytes: u64,
    pub max_upload: String,
}

#[derive(Template)]
#[template(path = "not_found.html")]
pub struct NotFoundPage {
    pub shell: Shell,
    pub path: String,
}

fn logical_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Binary-prefixed size, e.g. `64 KiB`, `1.5 MiB`.
pub fn human_bytes(bytes: usize) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 || value.fract() == 0.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn dashboard(
    backend: BackendKind,
    accounts_enabled: bool,
    catalog_enabled: bool,
    session: Option<&todo_database::sessions::Session>,
) -> DashboardPage {
    let policy = SegmentationPolicy::DEFAULT;
    DashboardPage {
        shell: Shell::new("dashboard", backend),
        session_user: session.map(|s| s.username.clone()),
        session_role: session.map_or("", |s| s.role.as_str()),
        rayon_threads: rayon::current_num_threads(),
        logical_cpus: logical_cpus(),
        polyval_default_segment: human_bytes(DEFAULT_POLYVAL_SEGMENT_SIZE),
        min_parallel: human_bytes(policy.min_parallel_bytes),
        adaptive_segment_range: format!(
            "{} – {}",
            human_bytes(policy.min_segment_bytes),
            human_bytes(policy.max_segment_bytes)
        ),
        max_decompressed: human_bytes(DEFAULT_MAX_DECOMPRESSED_SIZE),
        accounts_enabled,
        catalog_enabled,
    }
}

pub fn pipeline(backend: BackendKind) -> PipelinePage {
    PipelinePage {
        shell: Shell::new("pipeline", backend),
        max_input_bytes: MAX_INPUT_BYTES,
        max_input: human_bytes(MAX_INPUT_BYTES),
        max_tamper_bytes: MAX_TAMPER_INPUT_BYTES,
        min_parallel: human_bytes(SegmentationPolicy::DEFAULT.min_parallel_bytes),
        rayon_threads: rayon::current_num_threads(),
    }
}

pub fn equivalence(backend: BackendKind) -> EquivalencePage {
    EquivalencePage {
        shell: Shell::new("equivalence", backend),
        max_input_bytes: MAX_INPUT_BYTES,
        rayon_threads: rayon::current_num_threads(),
    }
}

pub fn benchmark(backend: BackendKind) -> BenchmarkPage {
    BenchmarkPage {
        shell: Shell::new("benchmark", backend),
        rayon_threads: rayon::current_num_threads(),
        logical_cpus: logical_cpus(),
    }
}

pub fn research(backend: BackendKind) -> ResearchPage {
    ResearchPage {
        shell: Shell::new("research", backend),
        rayon_threads: rayon::current_num_threads(),
        logical_cpus: logical_cpus(),
        max_input: human_bytes(MAX_INPUT_BYTES),
    }
}

pub fn storage(backend: BackendKind) -> StoragePage {
    StoragePage {
        shell: Shell::new("storage", backend),
        block_size: human_bytes(DEFAULT_CHUNK_SIZE),
        max_input_bytes: MAX_INPUT_BYTES,
        max_input: human_bytes(MAX_INPUT_BYTES),
    }
}

/// `upload` is the server's upload/download configuration, `None` when no key is set.
pub fn vault(
    backend: BackendKind,
    upload: Option<&todo_rest::UploadConfig>,
    accounts_enabled: bool,
    catalog_enabled: bool,
    session: Option<&todo_database::sessions::Session>,
) -> VaultPage {
    let max = upload.map_or(todo_rest::upload::DEFAULT_MAX_UPLOAD_BYTES, |c| {
        c.max_upload_bytes
    });
    let token = upload.is_some_and(todo_rest::UploadConfig::requires_token);
    VaultPage {
        shell: Shell::new("vault", backend),
        upload_enabled: upload.is_some(),
        auth_required: token && session.is_none(),
        login_required: accounts_enabled && session.is_none() && !token,
        session_user: session.map(|s| s.username.clone()),
        persistent_list: catalog_enabled && session.is_some(),
        max_upload_bytes: max,
        max_upload: human_bytes(usize::try_from(max).unwrap_or(usize::MAX)),
    }
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginPage {
    pub shell: Shell,
    pub next: Option<String>,
}

pub fn login(backend: BackendKind, next: Option<String>) -> LoginPage {
    LoginPage {
        shell: Shell::new("login", backend),
        next,
    }
}

#[derive(Template)]
#[template(path = "account.html")]
pub struct AccountPage {
    pub shell: Shell,
    pub accounts_enabled: bool,
    pub username: Option<String>,
    pub role: &'static str,
}

/// Login form, or (with a session) the profile view whose PII is fetched by `app.js`
/// from `GET /api/v1/auth/me`, so the compressed page never contains secrets.
pub fn account(
    backend: BackendKind,
    accounts_enabled: bool,
    session: Option<&todo_database::sessions::Session>,
) -> AccountPage {
    AccountPage {
        shell: Shell::new("account", backend),
        accounts_enabled,
        username: session.map(|s| s.username.clone()),
        role: session.map_or("", |s| s.role.as_str()),
    }
}

pub fn status(
    backend: BackendKind,
    accounts_enabled: bool,
    catalog_enabled: bool,
    session: Option<&todo_database::sessions::Session>,
) -> DashboardPage {
    let mut page = dashboard(backend, accounts_enabled, catalog_enabled, session);
    page.shell.active = "status";
    page
}

pub fn files(
    backend: BackendKind,
    upload: Option<&todo_rest::UploadConfig>,
    accounts_enabled: bool,
    catalog_enabled: bool,
    session: Option<&todo_database::sessions::Session>,
) -> VaultPage {
    let mut page = vault(backend, upload, accounts_enabled, catalog_enabled, session);
    page.shell.active = "files";
    page
}

pub fn explore(backend: BackendKind) -> StoragePage {
    let mut page = storage(backend);
    page.shell.active = "explore";
    page
}

#[derive(Template)]
#[template(path = "production/swarm.html")]
pub struct PeersPage {
    pub shell: Shell,
    pub backend_kind: &'static str,
    pub backend_live: bool,
}

pub fn peers(backend: BackendKind) -> PeersPage {
    PeersPage {
        shell: Shell::new("peers", backend),
        backend_kind: match backend {
            BackendKind::Mock => "mock",
            BackendKind::KuboRpc => "kubo",
            BackendKind::TrustlessGateway => "gateway",
        },
        backend_live: backend != BackendKind::Mock,
    }
}

#[derive(Template)]
#[template(path = "production/settings.html")]
pub struct SettingsPage {
    pub shell: Shell,
    pub accounts_enabled: bool,
    pub username: Option<String>,
    pub role: &'static str,
    pub rayon_threads: usize,
    pub logical_cpus: usize,
    pub polyval_default_segment: String,
    pub min_parallel: String,
    pub adaptive_segment_range: String,
    pub max_decompressed: String,
}

pub fn settings(
    backend: BackendKind,
    accounts_enabled: bool,
    session: Option<&todo_database::sessions::Session>,
) -> SettingsPage {
    let policy = SegmentationPolicy::DEFAULT;
    SettingsPage {
        shell: Shell::new("settings", backend),
        accounts_enabled,
        username: session.map(|s| s.username.clone()),
        role: session.map_or("", |s| s.role.as_str()),
        rayon_threads: rayon::current_num_threads(),
        logical_cpus: logical_cpus(),
        polyval_default_segment: human_bytes(DEFAULT_POLYVAL_SEGMENT_SIZE),
        min_parallel: human_bytes(policy.min_parallel_bytes),
        adaptive_segment_range: format!(
            "{} – {}",
            human_bytes(policy.min_segment_bytes),
            human_bytes(policy.max_segment_bytes)
        ),
        max_decompressed: human_bytes(DEFAULT_MAX_DECOMPRESSED_SIZE),
    }
}

#[derive(Template)]
#[template(path = "research/diagnostics.html")]
pub struct DiagnosticsPage {
    pub shell: Shell,
    pub max_input_bytes: usize,
    pub max_input: String,
    pub max_tamper_bytes: usize,
    pub min_parallel: String,
    pub rayon_threads: usize,
    pub logical_cpus: usize,
}

pub fn diagnostics(backend: BackendKind) -> DiagnosticsPage {
    DiagnosticsPage {
        shell: Shell::new("diagnostics", backend),
        max_input_bytes: MAX_INPUT_BYTES,
        max_input: human_bytes(MAX_INPUT_BYTES),
        max_tamper_bytes: MAX_TAMPER_INPUT_BYTES,
        min_parallel: human_bytes(SegmentationPolicy::DEFAULT.min_parallel_bytes),
        rayon_threads: rayon::current_num_threads(),
        logical_cpus: logical_cpus(),
    }
}

pub fn not_found(backend: BackendKind, path: &str) -> NotFoundPage {
    NotFoundPage {
        shell: Shell::new("", backend),
        path: path.chars().take(200).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_bytes_formats_binary_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(64 * 1024), "64 KiB");
        assert_eq!(human_bytes(4 * 1024 * 1024), "4 MiB");
    }

    #[test]
    fn every_page_renders_with_shell_and_badge() {
        for backend in [BackendKind::Mock, BackendKind::KuboRpc] {
            let pages = [
                dashboard(backend, true, true, None).render().unwrap(),
                status(backend, true, true, None).render().unwrap(),
                login(backend, None).render().unwrap(),
                pipeline(backend).render().unwrap(),
                equivalence(backend).render().unwrap(),
                benchmark(backend).render().unwrap(),
                research(backend).render().unwrap(),
                storage(backend).render().unwrap(),
                explore(backend).render().unwrap(),
                vault(backend, None, false, false, None).render().unwrap(),
                files(backend, None, false, false, None).render().unwrap(),
                peers(backend).render().unwrap(),
                settings(backend, false, None).render().unwrap(),
                settings(backend, true, None).render().unwrap(),
                diagnostics(backend).render().unwrap(),
                account(backend, false, None).render().unwrap(),
                account(backend, true, None).render().unwrap(),
                not_found(backend, "/missing").render().unwrap(),
            ];
            for html in &pages {
                assert!(html.starts_with("<!doctype html>"));
                assert!(html.contains("/static/app.css"));
                assert!(html.contains(backend.label()));
                assert!(!html.contains("<script>"), "inline scripts violate the CSP");
                assert!(!html.contains(" style=\""), "inline styles violate the CSP");
            }
        }
    }

    #[test]
    fn login_disables_credential_autocomplete() {
        let html = login(BackendKind::Mock, None).render().unwrap();
        assert!(html.contains(
            "id=\"login-form\" method=\"post\" action=\"/api/v1/auth/login\" autocomplete=\"off\""
        ));
        assert!(html.contains("name=\"username\" id=\"username\" autocomplete=\"off\""));
        assert!(html.contains("name=\"password\" id=\"password\" autocomplete=\"off\""));
    }

    #[test]
    fn mock_badge_is_labelled_as_not_ipfs() {
        let html = storage(BackendKind::Mock).render().unwrap();
        assert!(html.contains("MOCK (in-memory, not IPFS)"));
        assert!(html.contains("badge-mock"));
        let live = storage(BackendKind::KuboRpc).render().unwrap();
        assert!(live.contains("badge-live"));
    }

    #[test]
    fn vault_reflects_upload_config() {
        let off = vault(BackendKind::Mock, None, false, false, None)
            .render()
            .unwrap();
        assert!(off.contains("Vault nonaktif"));
        assert!(off.contains("disabled"));
        let cfg = todo_rest::UploadConfig::new(&[1; 16])
            .unwrap()
            .with_max_upload_bytes(8 << 20)
            .unwrap();
        let on = vault(BackendKind::Mock, Some(&cfg), false, false, None)
            .render()
            .unwrap();
        assert!(!on.contains("Vault nonaktif"));
        assert!(on.contains("data-max-input=\"8388608\""));
        assert!(on.contains("8 MiB"));
        assert!(
            !on.contains("01010101010101010101010101010101"),
            "key must never render"
        );
        assert!(!on.contains("id=\"vault-token\""));
        let token = "t0ken-for-tests-0123456789abcdefghij";
        let cfg = todo_rest::UploadConfig::new(&[1; 16])
            .unwrap()
            .with_api_token(token)
            .unwrap();
        let auth = vault(BackendKind::Mock, Some(&cfg), false, false, None)
            .render()
            .unwrap();
        assert!(auth.contains("id=\"vault-token\""));
        assert!(!auth.contains(token), "token must never render");
    }

    #[test]
    fn vault_session_and_catalog_modes() {
        use todo_database::accounts::Role;
        use todo_database::sessions::Session;
        let cfg = todo_rest::UploadConfig::new(&[1; 16]).unwrap();
        let session = Session {
            user_id: 7,
            username: "siti".into(),
            role: Role::User,
            created_unix: 1,
        };
        let login = vault(BackendKind::Mock, Some(&cfg), true, true, None)
            .render()
            .unwrap();
        assert!(login.contains("<a href=\"/account\">"));
        assert!(!login.contains("data-catalog"), "list needs a session");
        let mine = vault(BackendKind::Mock, Some(&cfg), true, true, Some(&session))
            .render()
            .unwrap();
        assert!(mine.contains("<strong>siti</strong>"));
        assert!(mine.contains("id=\"vault-list\" data-catalog"));
        assert!(mine.contains("Objek saya"));
        assert!(
            !mine.contains("name=\"nonce_hex\" autocomplete=\"off\" spellcheck=\"false\" required")
        );
        let memory = vault(BackendKind::Mock, Some(&cfg), true, false, Some(&session))
            .render()
            .unwrap();
        assert!(!memory.contains("data-catalog"));
        assert!(memory.contains("Objek sesi ini"));
    }

    #[test]
    fn not_found_escapes_path() {
        let html = not_found(BackendKind::Mock, "/<script>alert(1)</script>")
            .render()
            .unwrap();
        assert!(!html.contains("<script>alert(1)"));
        assert!(html.contains("&#60;script&#62;") || html.contains("&lt;script&gt;"));
    }
}
