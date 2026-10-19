//! Lifecycle manager for an existing Kubo binary, owned by the Rust application.
//!
//! This is deliberately not an IPFS reimplementation. It creates a dedicated private
//! Kubo repository, keeps its administrative RPC and gateway on loopback, removes the
//! public bootstrap list, and starts `ipfs daemon` as a child process. Kubo peers still
//! use TCP/UDP port 4001 on a private LAN/Wi-Fi; every node in that swarm needs the same
//! `swarm.key` (copied out-of-band with owner-only permissions).

use crate::IpfsError;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};

const DEFAULT_KUBO_BIN: &str = "/usr/local/bin/ipfs";
const SWARM_KEY_HEADER: &str = "/key/swarm/psk/1.0.0/\n/base16/\n";
const LOOPBACK_API: &str = "/ip4/127.0.0.1/tcp/5001";
const LOOPBACK_GATEWAY: &str = "/ip4/127.0.0.1/tcp/8080";

/// A Kubo process controlled by Rust. The Kubo repository is always explicit, so the
/// manager cannot silently alter a user's default `~/.ipfs` repository.
#[derive(Debug, Clone)]
pub struct ManagedKubo {
    binary: PathBuf,
    repo: PathBuf,
}

impl ManagedKubo {
    /// The binary must be an absolute regular-file path. `repo` is where Kubo stores its
    /// private identity and swarm key; do not put it in a source repository.
    pub fn new(binary: impl Into<PathBuf>, repo: impl Into<PathBuf>) -> Result<Self, IpfsError> {
        let binary = binary.into();
        let repo = repo.into();
        if !binary.is_absolute() || !fs::metadata(&binary).is_ok_and(|m| m.is_file()) {
            return Err(IpfsError::Transport(
                "Kubo binary must be an existing absolute regular-file path".into(),
            ));
        }
        if !repo.is_absolute() {
            return Err(IpfsError::Transport(
                "managed Kubo repository must be an absolute path".into(),
            ));
        }
        Ok(Self { binary, repo })
    }

    /// Read `TODO_KUBO_BIN` (default `/usr/local/bin/ipfs`) and the required
    /// `TODO_KUBO_REPO`. The required repository variable prevents accidental use of
    /// a pre-existing default Kubo installation.
    pub fn from_env() -> Result<Self, IpfsError> {
        let binary = std::env::var_os("TODO_KUBO_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_KUBO_BIN));
        let repo = std::env::var_os("TODO_KUBO_REPO").ok_or_else(|| {
            IpfsError::Transport("TODO_KUBO_REPO is required for managed Kubo".into())
        })?;
        Self::new(binary, PathBuf::from(repo))
    }

    pub fn repo(&self) -> &Path {
        &self.repo
    }

    /// Initialize and harden the dedicated private repository. It is idempotent: an
    /// existing identity and swarm key are never replaced. The bootstrap list is cleared
    /// on every call so this node does not discover public IPFS peers.
    pub fn initialize_private(&self) -> Result<(), IpfsError> {
        if !self.repo.join("config").is_file() {
            fs::create_dir_all(&self.repo).map_err(|_| {
                IpfsError::Transport("cannot create managed Kubo repository".into())
            })?;
            set_owner_only_dir(&self.repo)?;
            self.run_kubo(["init"])?;
        }
        set_owner_only_dir(&self.repo)?;
        let swarm_key = self.repo.join("swarm.key");
        if !swarm_key.exists() {
            let mut key = [0u8; 32];
            getrandom::fill(&mut key).map_err(|_| {
                IpfsError::Transport("cannot generate private Kubo swarm key".into())
            })?;
            write_owner_only(
                &swarm_key,
                format!("{SWARM_KEY_HEADER}{}\n", hex(&key)).as_bytes(),
            )?;
        }
        self.run_kubo(["bootstrap", "rm", "--all"])?;
        // Kubo 0.43 enables mainnet AutoConf by default; private swarms must not contact
        // that service and Kubo refuses to start while it remains enabled.
        self.run_kubo(["config", "--bool", "AutoConf.Enabled", "false"])?;
        self.run_kubo(["config", "--bool", "AutoTLS.Enabled", "false"])?;
        // Avoid Kubo's `auto` routing mode, which enables public HTTP IPNI defaults.
        self.run_kubo(["config", "Routing.Type", "dht"])?;
        self.run_kubo(["config", "Addresses.API", LOOPBACK_API])?;
        self.run_kubo(["config", "Addresses.Gateway", LOOPBACK_GATEWAY])?;
        Ok(())
    }

    /// Run the private Kubo daemon in the foreground as a Rust-owned child process.
    /// The caller controls its lifetime; no detached process or shell is used.
    pub fn run(&self) -> Result<ExitStatus, IpfsError> {
        self.spawn()?
            .wait()
            .map_err(|_| IpfsError::Transport("cannot start managed Kubo daemon".into()))
    }

    /// Spawn the private daemon for an application supervisor. The returned child must
    /// stay owned by that supervisor; this method never detaches a background process.
    pub fn spawn(&self) -> Result<Child, IpfsError> {
        self.initialize_private()?;
        Command::new(&self.binary)
            .arg("daemon")
            .env("IPFS_PATH", &self.repo)
            .spawn()
            .map_err(|_| IpfsError::Transport("cannot start managed Kubo daemon".into()))
    }

    /// Runs a small, read-only RPC command against the managed repository's API address.
    pub fn is_running(&self) -> bool {
        Command::new(&self.binary)
            .args([
                OsStr::new("--api"),
                OsStr::new(LOOPBACK_API),
                OsStr::new("id"),
            ])
            .env("IPFS_PATH", &self.repo)
            .output()
            .is_ok_and(|out| out.status.success())
    }

    /// Gracefully stop the daemon through its loopback-only administrative RPC.
    /// This never sends a signal to a process selected by name or PID.
    pub fn stop(&self) -> Result<(), IpfsError> {
        if !self.is_running() {
            return Ok(());
        }
        let status = Command::new(&self.binary)
            .args([
                OsStr::new("--api"),
                OsStr::new(LOOPBACK_API),
                OsStr::new("shutdown"),
            ])
            .env("IPFS_PATH", &self.repo)
            .status()
            .map_err(|_| IpfsError::Transport("cannot request managed Kubo shutdown".into()))?;
        if status.success() {
            Ok(())
        } else {
            Err(IpfsError::Transport(
                "managed Kubo refused graceful shutdown; inspect its private service log".into(),
            ))
        }
    }

    fn run_kubo<I, S>(&self, args: I) -> Result<(), IpfsError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let status = Command::new(&self.binary)
            .args(args)
            .env("IPFS_PATH", &self.repo)
            .status()
            .map_err(|_| IpfsError::Transport("cannot execute managed Kubo command".into()))?;
        if status.success() {
            Ok(())
        } else {
            Err(IpfsError::Transport(
                "managed Kubo command failed; inspect its private service log".into(),
            ))
        }
    }
}

#[cfg(unix)]
fn set_owner_only_dir(path: &Path) -> Result<(), IpfsError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| IpfsError::Transport("cannot protect managed Kubo repository".into()))
}

#[cfg(not(unix))]
fn set_owner_only_dir(_: &Path) -> Result<(), IpfsError> {
    Ok(())
}

fn write_owner_only(path: &Path, data: &[u8]) -> Result<(), IpfsError> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| IpfsError::Transport("cannot create private Kubo swarm key".into()))?;
    file.write_all(data)
        .map_err(|_| IpfsError::Transport("cannot write private Kubo swarm key".into()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::ManagedKubo;

    #[test]
    fn manager_refuses_relative_or_missing_paths() {
        assert!(ManagedKubo::new("ipfs", "/tmp/private-kubo").is_err());
        assert!(ManagedKubo::new("/usr/local/bin/ipfs", "relative").is_err());
    }
}
