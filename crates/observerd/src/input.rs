// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;
use std::fs::OpenOptions;
use std::io::{BufReader, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub fn read_json<T: DeserializeOwned>(path: &Path, max_bytes: u64) -> Result<T> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open JSON input {}", path.display()))?;
    let before = file
        .metadata()
        .with_context(|| format!("inspect JSON input {}", path.display()))?;
    if !before.file_type().is_file() || before.nlink() != 1 {
        bail!(
            "JSON input {} must be a singly linked regular file",
            path.display()
        );
    }
    if before.len() > max_bytes {
        bail!(
            "JSON input {} exceeds its {max_bytes}-byte limit",
            path.display()
        );
    }
    let capacity = usize::try_from(before.len()).context("JSON input size is not representable")?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut reader = BufReader::new(file);
    reader
        .by_ref()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("read JSON input {}", path.display()))?;
    let after = reader
        .get_ref()
        .metadata()
        .with_context(|| format!("reinspect JSON input {}", path.display()))?;
    if bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        bail!("JSON input {} changed while it was read", path.display());
    }
    serde_json::from_slice(&bytes).with_context(|| format!("parse JSON input {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn rejects_hardlinked_trust_input() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "bpf-observer-input-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let first = directory.join("scope.json");
        let second = directory.join("scope-alias.json");
        fs::write(&first, b"{}\n").unwrap();
        fs::hard_link(&first, &second).unwrap();

        let result = read_json::<serde_json::Value>(&first, 1024);

        let _ = fs::remove_file(&second);
        let _ = fs::remove_file(&first);
        let _ = fs::remove_dir(&directory);
        assert!(result.is_err());
    }
}
