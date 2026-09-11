// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{anyhow, Context, Result};
use bpf_observer_schema::EnvironmentFingerprint;
use sha2::{Digest, Sha256};
use std::ffi::CStr;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_unix_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

pub fn new_run_id() -> Result<String> {
    let value = fs::read_to_string("/proc/sys/kernel/random/uuid")
        .context("read kernel-generated run UUID")?;
    let value = value.trim();
    if value.len() != 36 {
        return Err(anyhow!("kernel returned malformed UUID: {value:?}"));
    }
    Ok(value.to_string())
}

pub fn boot_id() -> Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("read boot ID")?
        .trim()
        .to_string())
}

pub fn kernel_release() -> Result<String> {
    let mut value = unsafe { std::mem::zeroed::<libc::utsname>() };
    if unsafe { libc::uname(&mut value) } != 0 {
        return Err(std::io::Error::last_os_error()).context("uname");
    }
    Ok(unsafe { CStr::from_ptr(value.release.as_ptr()) }
        .to_string_lossy()
        .into_owned())
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let file = File::open(path).with_context(|| format!("open {} for hashing", path.display()))?;
    sha256_reader(BufReader::new(file))
        .with_context(|| format!("hash contents of {}", path.display()))
}

/// Stable measurement of an executable used by the authenticated harness
/// binding. Opening with `O_NOFOLLOW`, requiring one regular-file link, and
/// comparing inode/timestamps around the read prevents a path substitution or
/// concurrent rewrite from being silently authorized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileMeasurement {
    pub sha256: String,
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

pub fn measure_regular_file(path: &Path) -> Result<FileMeasurement> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open {} for stable measurement", path.display()))?;
    let before = file
        .metadata()
        .with_context(|| format!("inspect {} before measurement", path.display()))?;
    if !before.file_type().is_file() || before.nlink() != 1 {
        anyhow::bail!(
            "authenticated executable {} must be a singly linked regular file",
            path.display()
        );
    }
    let (sha256, bytes_read) = sha256_reader_counted(&mut file)
        .with_context(|| format!("measure executable {}", path.display()))?;
    let after = file
        .metadata()
        .with_context(|| format!("inspect {} after measurement", path.display()))?;
    let state = |metadata: &fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    if bytes_read != before.len() || state(&before) != state(&after) {
        anyhow::bail!("authenticated executable changed while it was measured");
    }
    Ok(FileMeasurement {
        sha256,
        dev: after.dev(),
        ino: after.ino(),
        len: after.len(),
        mtime: after.mtime(),
        mtime_nsec: after.mtime_nsec(),
        ctime: after.ctime(),
        ctime_nsec: after.ctime_nsec(),
    })
}

pub fn sha256_reader(mut reader: impl Read) -> Result<String> {
    Ok(sha256_reader_counted(&mut reader)?.0)
}

pub fn sha256_reader_counted(mut reader: impl Read) -> Result<(String, u64)> {
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut bytes_read = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read
            .checked_add(read as u64)
            .context("SHA-256 input length overflow")?;
        hash.update(&buffer[..read]);
    }
    Ok((format!("{:x}", hash.finalize()), bytes_read))
}

pub fn fingerprint(recorder_object_sha256: Option<String>) -> Result<EnvironmentFingerprint> {
    let btf = Path::new("/sys/kernel/btf/vmlinux");
    Ok(EnvironmentFingerprint {
        kernel_release: kernel_release()?,
        boot_id: boot_id()?,
        observer_version: env!("CARGO_PKG_VERSION").into(),
        recorder_object_sha256,
        kernel_btf_sha256: if btf.exists() {
            Some(sha256_file(btf)?)
        } else {
            None
        },
        source_commit: option_env!("BPF_OBSERVER_SOURCE_COMMIT").map(str::to_string),
        observer_executable_sha256: None,
        workload_executable_sha256: None,
        harness_kernel_identity: None,
        harness_policy_id: None,
        harness_policy_sha256: None,
        harness_public_key_fingerprint_sha256: None,
    })
}
