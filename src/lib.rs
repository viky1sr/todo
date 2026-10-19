//! Parallel AES-GCM-SIV & Zstandard Research Pipeline Workspace.
//!
//! Language: Rust 2024 Edition (rustc 1.99 minimum).
//! Modular Cargo Workspace separating pure cryptography, compression, decentralized storage,
//! web integration, and REST service exposure.

pub mod config;
pub mod datasets;

pub use todo_crypto as crypto;
pub use todo_ipfs as ipfs;
pub use todo_rest as rest;
pub use todo_web as web;
pub use todo_zstd as zstd;
