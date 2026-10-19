//! Secret loading from the environment without putting secrets in the repository.
//!
//! For a secret `NAME`, `NAME_FILE=<path>` is preferred: the file must be a regular file
//! readable by the owner only (mode `0600`/`0400`), so it is never world/group readable.
//! `NAME=<value>` is accepted for development. Setting both is an error. Trailing
//! whitespace/newline is stripped. Values are returned in [`Zeroizing`] buffers and are
//! never included in error messages.

use std::path::Path;

use zeroize::Zeroizing;

use crate::ConfigError;

/// Largest accepted secret file (keys, passwords and tokens are tiny).
const MAX_SECRET_FILE_BYTES: u64 = 4096;

/// `Ok(None)` when neither `NAME_FILE` nor `NAME` is set.
pub fn read_secret(name: &str) -> Result<Option<Zeroizing<String>>, ConfigError> {
    let file_var = format!("{name}_FILE");
    let from_file = std::env::var_os(&file_var);
    let from_env = std::env::var(name).ok().map(Zeroizing::new);
    match (from_file, from_env) {
        (Some(_), Some(_)) => Err(ConfigError(format!(
            "set only one of {name} and {file_var}"
        ))),
        (Some(path), None) => read_secret_file(Path::new(&path), &file_var).map(Some),
        (None, Some(value)) => non_empty(trimmed(value), name).map(Some),
        (None, None) => Ok(None),
    }
}

/// Reads a secret file, enforcing owner-only permissions and a size bound.
pub fn read_secret_file(path: &Path, what: &str) -> Result<Zeroizing<String>, ConfigError> {
    let bad = |msg: &str| ConfigError(format!("{what}: {msg}"));
    let meta = std::fs::metadata(path).map_err(|_| bad("cannot read secret file"))?;
    if !meta.is_file() {
        return Err(bad("secret path is not a regular file"));
    }
    if meta.len() > MAX_SECRET_FILE_BYTES {
        return Err(bad("secret file too large"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(bad(
                "secret file must not be group/world accessible (chmod 600)",
            ));
        }
    }
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|_| bad("cannot read secret file"))?);
    let text = std::str::from_utf8(&bytes).map_err(|_| bad("secret file is not UTF-8"))?;
    non_empty(trimmed(Zeroizing::new(text.to_string())), what)
}

fn trimmed(value: Zeroizing<String>) -> Zeroizing<String> {
    Zeroizing::new(value.trim().to_string())
}

fn non_empty(value: Zeroizing<String>, what: &str) -> Result<Zeroizing<String>, ConfigError> {
    if value.is_empty() {
        return Err(ConfigError(format!("{what} is empty")));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn secret_file_permissions_and_content() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("todo-secret-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s");
        std::fs::write(&path, "  hunter2-secret\n").unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = read_secret_file(&path, "X_FILE").unwrap_err().to_string();
        assert!(err.contains("chmod 600"), "{err}");
        assert!(!err.contains("hunter2"));

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_secret_file(&path, "X_FILE").unwrap().as_str(),
            "hunter2-secret"
        );

        std::fs::write(&path, "\n \n").unwrap();
        assert!(read_secret_file(&path, "X_FILE").is_err());
        std::fs::write(&path, vec![b'a'; 5000]).unwrap();
        assert!(read_secret_file(&path, "X_FILE").is_err());
        assert!(read_secret_file(&dir, "X_FILE").is_err());
        assert!(read_secret_file(&dir.join("missing"), "X_FILE").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
