//! Persistence layer of the workspace.
//!
//! - [`secrets`]: owner-only secret files / environment variables.
//! - [`accounts`]: Layer 3 user accounts in MariaDB (Argon2id passwords, PII sealed with
//!   `todo-crypto` AES-256-GCM-SIV), embedded sqlx migrations in `migrations/mariadb`.
//! - [`sessions`]: Layer 2 login sessions and login rate limiting in Redis.
//! - [`objects`]: Layer 4 generation-aware object metadata plus a durable upload lifecycle
//!   journal in PostgreSQL, embedded sqlx migrations in `migrations/postgres`.

pub mod accounts;
pub mod config;
pub mod objects;
pub mod secrets;
pub mod sessions;

use std::fmt;

/// Configuration/connection error; messages never contain secret values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Lower/upper-case hex without separators; `None` on odd length or a non-hex digit.
pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn hex() {
        assert_eq!(super::decode_hex("00aBff"), Some(vec![0, 0xab, 0xff]));
        assert_eq!(super::decode_hex("abc"), None);
        assert_eq!(super::decode_hex("zz"), None);
        assert_eq!(super::decode_hex("+1"), None);
    }
}
