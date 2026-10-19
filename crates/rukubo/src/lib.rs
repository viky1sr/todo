//! `rukubo`: Rust-owned lifecycle control for an existing Kubo binary.
//!
//! Kubo remains the IPFS implementation. This crate gives the Rust application a
//! narrowly scoped supervisor for one dedicated private repository; it does not expose
//! Kubo's unauthenticated WebUI or administrative RPC to the browser.

use std::process::Child;
use std::sync::{Arc, Mutex};
use std::{fs, path::Path, thread, time::Duration};

pub use todo_ipfs::ManagedKubo;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RukuboStatus {
    pub running: bool,
    pub managed_pid: Option<u32>,
    pub repository: String,
}

/// Starts Kubo only after `ManagedKubo` has installed private-repository safeguards.
/// A single supervisor instance is shared by the authenticated web console.
#[derive(Clone)]
pub struct Rukubo {
    kubo: ManagedKubo,
    child: Arc<Mutex<Option<Child>>>,
}

impl Rukubo {
    /// Resolve settings from explicit environment variables first, then from the
    /// non-secret `config/ipfs.toml` in the current workspace.  The latter lets the
    /// release binary be started directly without manually exporting variables.
    pub fn from_env() -> Result<Self, todo_ipfs::IpfsError> {
        if std::env::var_os("TODO_KUBO_REPO").is_some() {
            return Ok(Self::new(ManagedKubo::from_env()?));
        }
        let config_dir = std::env::var_os("TODO_CONFIG_TOML_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| "config".into());
        let config = config_dir.join("ipfs.toml");
        let (repo, binary) = kubo_from_toml(&config)?;
        Ok(Self::new(ManagedKubo::new(binary, repo)?))
    }

    pub fn new(kubo: ManagedKubo) -> Self {
        Self {
            kubo,
            child: Arc::new(Mutex::new(None)),
        }
    }

    /// Idempotently initialize the dedicated private repository, then spawn Kubo as a
    /// Rust child. If a Kubo daemon already serves this dedicated repo, it is reused.
    pub fn start(&self) -> Result<RukuboStatus, todo_ipfs::IpfsError> {
        let mut child = self.child.lock().map_err(|_| {
            todo_ipfs::IpfsError::Internal("rukubo process lock is poisoned".into())
        })?;
        if let Some(existing) = child.as_mut() {
            if existing
                .try_wait()
                .map_err(|_| {
                    todo_ipfs::IpfsError::Transport("cannot inspect managed Kubo process".into())
                })?
                .is_none()
            {
                return Ok(self.status_locked(Some(existing.id())));
            }
            *child = None;
        }
        if self.kubo.is_running() {
            return Ok(self.status_locked(None));
        }
        self.kubo.initialize_private()?;
        let spawned = self.kubo.spawn()?;
        let pid = spawned.id();
        *child = Some(spawned);
        Ok(self.status_locked(Some(pid)))
    }

    pub fn status(&self) -> Result<RukuboStatus, todo_ipfs::IpfsError> {
        let mut child = self.child.lock().map_err(|_| {
            todo_ipfs::IpfsError::Internal("rukubo process lock is poisoned".into())
        })?;
        if let Some(existing) = child.as_mut() {
            if existing
                .try_wait()
                .map_err(|_| {
                    todo_ipfs::IpfsError::Transport("cannot inspect managed Kubo process".into())
                })?
                .is_none()
            {
                return Ok(self.status_locked(Some(existing.id())));
            }
            *child = None;
        }
        Ok(self.status_locked(None))
    }

    /// Gracefully stop only the Kubo daemon reachable through this manager's
    /// loopback RPC. The shutdown is confirmed before this method returns.
    pub fn stop(&self) -> Result<RukuboStatus, todo_ipfs::IpfsError> {
        let mut child = self.child.lock().map_err(|_| {
            todo_ipfs::IpfsError::Internal("rukubo process lock is poisoned".into())
        })?;
        if !self.kubo.is_running() {
            *child = None;
            return Ok(self.status_locked(None));
        }
        self.kubo.stop()?;
        for _ in 0..30 {
            if !self.kubo.is_running() {
                if let Some(existing) = child.as_mut() {
                    let _ = existing.try_wait();
                }
                *child = None;
                return Ok(self.status_locked(None));
            }
            thread::sleep(Duration::from_millis(100));
        }
        Err(todo_ipfs::IpfsError::Transport(
            "managed Kubo did not stop within 3 seconds".into(),
        ))
    }

    /// Stop the current daemon cleanly, then initialize and start it again.
    pub fn restart(&self) -> Result<RukuboStatus, todo_ipfs::IpfsError> {
        self.stop()?;
        self.start()
    }

    fn status_locked(&self, managed_pid: Option<u32>) -> RukuboStatus {
        RukuboStatus {
            running: managed_pid.is_some() || self.kubo.is_running(),
            managed_pid,
            repository: self.kubo.repo().display().to_string(),
        }
    }
}

fn kubo_from_toml(path: &Path) -> Result<(String, String), todo_ipfs::IpfsError> {
    let text = fs::read_to_string(path).map_err(|_| {
        todo_ipfs::IpfsError::Transport(format!(
            "TODO_KUBO_REPO is unset and {} cannot be read; run from the workspace, set TODO_CONFIG_TOML_DIR, or set TODO_KUBO_REPO",
            path.display()
        ))
    })?;
    let value: toml::Table = text.parse().map_err(|error: toml::de::Error| {
        todo_ipfs::IpfsError::Transport(format!("{} is not valid TOML: {error}", path.display()))
    })?;
    let rukubo = value
        .get("rukubo")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| {
            todo_ipfs::IpfsError::Transport(format!("{} is missing [rukubo]", path.display()))
        })?;
    let repo = rukubo
        .get("repo_dir")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| {
            todo_ipfs::IpfsError::Transport(format!(
                "{} is missing rukubo.repo_dir",
                path.display()
            ))
        })?;
    let binary = std::env::var("TODO_KUBO_BIN")
        .ok()
        .or_else(|| {
            rukubo
                .get("binary")
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "/usr/local/bin/ipfs".into());
    Ok((repo.to_owned(), binary))
}

#[cfg(test)]
mod tests {
    use super::kubo_from_toml;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_TEST_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn reads_private_manager_paths_from_toml() {
        let directory = std::env::temp_dir().join(format!(
            "rukubo-config-test-{}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).expect("temporary directory");
        let config = directory.join("ipfs.toml");
        fs::write(
            &config,
            "[rukubo]\nrepo_dir = \"/var/lib/rukubo\"\nbinary = \"/usr/local/bin/ipfs\"\n",
        )
        .expect("config write");
        assert_eq!(
            kubo_from_toml(&config).expect("config parse"),
            ("/var/lib/rukubo".into(), "/usr/local/bin/ipfs".into())
        );
        fs::remove_dir_all(directory).expect("temporary directory cleanup");
    }
}
