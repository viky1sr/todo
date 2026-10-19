//! Records the compiler version for benchmark environment reports.

use std::process::Command;

fn main() {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let version = Command::new(rustc)
        .arg("-V")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_else(|| "unknown".to_string());
    println!(
        "cargo:rustc-env=TODO_CRYPTO_RUSTC_VERSION={}",
        version.trim()
    );
    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-changed=build.rs");
}
