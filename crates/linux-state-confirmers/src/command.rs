// SPDX-License-Identifier: GPL-2.0-only

use crate::schema::{NamespaceTarget, NetworkNormalization};
use crate::RetainedNamespace;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const TOOL_HASH_BUFFER_BYTES: usize = 64 * 1024;
const HARD_MAX_TOOL_BYTES: u64 = 256 * 1024 * 1024;
const STDERR_CAPTURE_BYTES: u64 = 64 * 1024;

pub(crate) struct CommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub output_exceeded: bool,
    pub stderr_exceeded: bool,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub tool_sha256: String,
    pub tool_object_identity_sha256: String,
    pub tool_changed_during_run: bool,
}

pub(crate) fn run_json_command(
    binary: &Path,
    expected_sha256: &str,
    args: &[&str],
    namespace: &NamespaceTarget,
    retained: Option<&RetainedNamespace>,
    max_output_bytes: u64,
    deadline: Instant,
) -> Result<CommandOutput> {
    let mut anchored = open_tool(binary)?;
    let metadata_before = anchored.metadata().context("fstat anchored collector")?;
    let identity_before = hash_open_tool(&mut anchored)?;
    if identity_before != expected_sha256 {
        bail!(
            "collector {} SHA-256 {} does not match scope-bound {}",
            binary.display(),
            identity_before,
            expected_sha256
        );
    }
    let exec_fd = unsafe { libc::dup(anchored.as_raw_fd()) };
    if exec_fd < 0 {
        return Err(io::Error::last_os_error()).context("duplicate anchored collector FD");
    }
    let exec_file = unsafe { File::from_raw_fd(exec_fd) };
    if unsafe { libc::fcntl(exec_fd, libc::F_SETFD, 0) } != 0 {
        return Err(io::Error::last_os_error()).context("make anchored collector FD inheritable");
    }
    let executable = format!("/proc/self/fd/{exec_fd}");
    let mut command = Command::new(executable);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("LC_ALL", "C");

    let namespace_file = if let Some(retained) = retained {
        retained.verify()?;
        if retained.inode() != namespace.expected_namespace_inode {
            bail!("retained network namespace does not match command scope");
        }
        Some(
            retained
                .file()
                .try_clone()
                .context("clone retained network namespace FD")?,
        )
    } else if namespace.pid == 0 {
        None
    } else {
        let path = format!("/proc/{}/ns/net", namespace.pid);
        let file =
            File::open(&path).with_context(|| format!("open target network namespace {path}"))?;
        let inode = file
            .metadata()
            .context("inspect target network namespace")?
            .ino();
        if inode != namespace.expected_namespace_inode {
            bail!(
                "network namespace identity mismatch: observed {inode}, expected {}",
                namespace.expected_namespace_inode
            );
        }
        Some(file)
    };
    // Only the child changes namespaces. It also owns a fresh process group so
    // timeout cleanup kills collector descendants and closes their pipes.
    unsafe {
        command.pre_exec(move || {
            let _keep_exec_fd_alive = &exec_file;
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if let Some(file) = namespace_file.as_ref() {
                if libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("execute trusted collector {}", binary.display()))?;
    let stdout = child
        .stdout
        .take()
        .context("collector stdout pipe missing")?;
    let stderr = child
        .stderr
        .take()
        .context("collector stderr pipe missing")?;
    let stdout_reader = thread::spawn(move || drain_bounded(stdout, max_output_bytes));
    let stderr_reader = thread::spawn(move || drain_bounded(stderr, STDERR_CAPTURE_BYTES));

    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().context("wait for network collector")? {
            break status;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            let pid = child.id();
            if pid <= i32::MAX as u32 {
                unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
            }
            let _ = child.kill();
            break child.wait().context("reap timed-out network collector")?;
        }
        thread::sleep(Duration::from_millis(2));
    };

    let (stdout, output_exceeded) = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("collector stdout reader panicked"))??;
    let (stderr, stderr_exceeded) = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("collector stderr reader panicked"))??;
    let metadata_after = anchored.metadata().context("re-fstat anchored collector")?;
    let identity_after = hash_open_tool(&mut anchored)?;
    Ok(CommandOutput {
        stdout,
        stderr,
        output_exceeded,
        stderr_exceeded,
        exit_code: status.code(),
        timed_out,
        tool_sha256: identity_before.clone(),
        tool_object_identity_sha256: metadata_identity_sha256(&metadata_before),
        tool_changed_during_run: identity_before != identity_after
            || tool_metadata_identity(&metadata_before) != tool_metadata_identity(&metadata_after),
    })
}

fn drain_bounded<R: Read>(mut reader: R, maximum: u64) -> io::Result<(Vec<u8>, bool)> {
    let mut captured = Vec::new();
    let mut exceeded = false;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = maximum.saturating_sub(captured.len() as u64) as usize;
        let retain = read.min(remaining);
        captured.extend_from_slice(&buffer[..retain]);
        if retain < read {
            exceeded = true;
        }
    }
    Ok((captured, exceeded))
}

fn open_tool(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open anchored collector {}", path.display()))?;
    let metadata = file.metadata().context("fstat collector")?;
    if !metadata.is_file() {
        bail!("collector {} is not a regular file", path.display());
    }
    if metadata.nlink() != 1 {
        bail!(
            "collector {} must have exactly one hard link",
            path.display()
        );
    }
    let mode = metadata.permissions().mode();
    if mode & 0o111 == 0 {
        bail!("collector {} is not executable", path.display());
    }
    if metadata.uid() != 0 || mode & 0o022 != 0 {
        bail!(
            "collector {} must be root-owned and not group/other writable",
            path.display()
        );
    }
    if metadata.len() == 0 || metadata.len() > HARD_MAX_TOOL_BYTES {
        bail!("collector binary size is outside the hard bound");
    }
    let mut magic_file = file
        .try_clone()
        .context("clone collector FD for ELF check")?;
    let mut magic = [0_u8; 4];
    magic_file
        .read_exact(&mut magic)
        .context("read collector ELF identity")?;
    if magic != [0x7f, b'E', b'L', b'F'] {
        bail!(
            "collector {} must be an ELF binary; script interpreters are not scope-bound",
            path.display()
        );
    }
    Ok(file)
}

/// Resolve the digest which must be copied into a `NetworkScope`. This uses
/// the same no-follow, single-link, executable regular-file checks as capture.
pub fn trusted_collector_sha256(path: &Path) -> Result<String> {
    let mut file = open_tool(path)?;
    hash_open_tool(&mut file)
}

fn hash_open_tool(file: &mut File) -> Result<String> {
    file.seek(SeekFrom::Start(0))
        .context("rewind collector binary")?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; TOOL_HASH_BUFFER_BYTES];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer).context("hash collector binary")?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > HARD_MAX_TOOL_BYTES {
            bail!("collector binary changed beyond the hard size bound while hashing");
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn tool_metadata_identity(metadata: &Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.size(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn metadata_identity_sha256(metadata: &Metadata) -> String {
    let identity = tool_metadata_identity(metadata);
    hex::encode(Sha256::digest(
        format!(
            "{}:{}:{}:{}:{}:{}:{}",
            identity.0, identity.1, identity.2, identity.3, identity.4, identity.5, identity.6
        )
        .as_bytes(),
    ))
}

pub(crate) fn canonical_json(
    bytes: &[u8],
    collector_key: &str,
    normalization: NetworkNormalization,
) -> Result<Vec<u8>> {
    let mut value: serde_json::Value =
        serde_json::from_slice(bytes).context("parse collector JSON")?;
    match normalization {
        NetworkNormalization::ConfigurationOnlyV1 => {
            normalize_configuration_value(&mut value, collector_key, None);
            sort_unordered_top_level(&mut value, collector_key)?;
        }
    }
    serde_json::to_vec(&value).context("serialize canonical collector JSON")
}

fn sort_unordered_top_level(value: &mut serde_json::Value, collector: &str) -> Result<()> {
    let unordered_set = collector == "ip/address"
        || collector == "tc/qdisc"
        || collector.starts_with("tc/class/")
        || collector.starts_with("tc/filter/");
    if !unordered_set {
        return Ok(());
    }
    // These objects carry their semantic identity/ordering in fields such as
    // ifindex, parent, handle, chain and preference; iproute2 does not promise
    // a stable enumeration order for the outer list. Sort only that outer
    // object set. Route/rule lists are deliberately excluded because equal
    // priority insertion order can affect selection. Nested address and
    // multipath arrays stay ordered, and nft stays ordered because chain/rule
    // order is packet-processing configuration.
    let serde_json::Value::Array(values) = value else {
        bail!("unordered ip/tc collector JSON must be a top-level array");
    };
    let mut keyed = values
        .drain(..)
        .map(|value| {
            let key = serde_json::to_vec(&value).context("serialize normalized network element")?;
            Ok((key, value))
        })
        .collect::<Result<Vec<_>>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    values.extend(keyed.into_iter().map(|(_, value)| value));
    Ok(())
}

fn normalize_configuration_value(
    value: &mut serde_json::Value,
    collector_key: &str,
    parent_key: Option<&str>,
) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                normalize_configuration_value(value, collector_key, parent_key);
            }
        }
        serde_json::Value::Object(fields) => {
            fields.retain(|key, _| !volatile_network_field(collector_key, parent_key, key));
            for (key, value) in fields {
                normalize_configuration_value(value, collector_key, Some(key));
            }
        }
        _ => {}
    }
}

fn volatile_network_field(collector: &str, parent: Option<&str>, field: &str) -> bool {
    if collector == "ip/address" {
        return matches!(
            field,
            "stats"
                | "stats64"
                | "valid_life_time"
                | "preferred_life_time"
                | "valid_lft"
                | "preferred_lft"
                | "cstamp"
                | "tstamp"
        );
    }
    if collector.starts_with("ip/route/") {
        return matches!(field, "expires" | "age" | "lastuse" | "used");
    }
    if collector.starts_with("tc/") {
        return matches!(
            field,
            "stats"
                | "stats2"
                | "xstats"
                | "bytes"
                | "packets"
                | "drops"
                | "overlimits"
                | "requeues"
                | "backlog"
                | "qlen"
                | "lastuse"
                | "used"
        );
    }
    if collector == "nft/ruleset" {
        return matches!(field, "expires" | "handle")
            || (parent == Some("counter") && matches!(field, "packets" | "bytes"))
            || (parent == Some("quota") && field == "used");
    }
    false
}
