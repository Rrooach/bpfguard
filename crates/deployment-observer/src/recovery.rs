// SPDX-License-Identifier: GPL-2.0-only

//! Strict, shell-free execution of an externally supplied recovery helper.
//!
//! This module records whether the configured helper itself ran successfully.
//! It deliberately does not claim that the observed Linux state was restored;
//! that conclusion belongs to the independent A/B/C endpoint comparators.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Component, Path};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::barrier::RootFreezeBarrier;
use crate::report::IdentityAssessment;

pub const RECOVERY_EVIDENCE_SCHEMA_VERSION: u32 = 1;

const MAX_ID_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 4096;
const MAX_ARG_COUNT: usize = 256;
const MAX_ARG_BYTES: usize = 16 * 1024;
const MAX_TOTAL_ARG_BYTES: usize = 128 * 1024;
const MAX_TIMEOUT_MS: u64 = 60 * 60 * 1000;
const MAX_OUTPUT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const TERMINATION_GRACE: Duration = Duration::from_millis(250);
const OUTPUT_DRAIN_GRACE: Duration = Duration::from_millis(250);
const MAX_ERROR_BYTES: usize = 4096;
const MAX_FORBIDDEN_CGROUPS: usize = 256;
const CGROUPFS_ROOT: &str = "/sys/fs/cgroup";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryConfig {
    pub checkpoint_id: String,
    pub recovery_id: String,
    pub executable_path: String,
    pub expected_sha256: String,
    /// Arguments after argv[0]. The executable path is always argv[0].
    #[serde(default)]
    pub argv: Vec<String>,
    pub timeout_ms: u64,
    /// Per-stream capture bound. All observed bytes are still hashed.
    pub max_output_bytes: u64,
}

impl RecoveryConfig {
    pub fn validate(&self) -> Result<()> {
        self.validate_schema()
    }

    pub fn validate_schema(&self) -> Result<()> {
        validate_id(&self.checkpoint_id, "checkpoint_id")?;
        validate_id(&self.recovery_id, "recovery_id")?;
        validate_absolute_path(&self.executable_path, "recovery executable")?;
        validate_sha256(&self.expected_sha256, "expected recovery executable")?;
        if self.argv.len() > MAX_ARG_COUNT {
            bail!("recovery argv contains more than {MAX_ARG_COUNT} arguments");
        }
        let mut total = 0_usize;
        for argument in &self.argv {
            let bytes = argument.as_bytes();
            if bytes.len() > MAX_ARG_BYTES || bytes.contains(&0) {
                bail!("recovery argv contains an oversized argument or NUL byte");
            }
            total = total
                .checked_add(bytes.len())
                .context("recovery argv byte count overflow")?;
        }
        if total > MAX_TOTAL_ARG_BYTES {
            bail!("recovery argv exceeds the {MAX_TOTAL_ARG_BYTES}-byte aggregate bound");
        }
        if self.timeout_ms == 0 || self.timeout_ms > MAX_TIMEOUT_MS {
            bail!("recovery timeout_ms must be in 1..={MAX_TIMEOUT_MS}");
        }
        if self.max_output_bytes == 0 || self.max_output_bytes > MAX_OUTPUT_BYTES {
            bail!("recovery max_output_bytes must be in 1..={MAX_OUTPUT_BYTES}");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenCgroupIdentity {
    /// Canonical cgroup-v2 path, relative to the cgroup filesystem namespace
    /// but beginning with `/` (for example `/agent/session-1`).
    pub cgroup_path: String,
    pub cgroup_id: u64,
}

impl ForbiddenCgroupIdentity {
    pub fn validate(&self) -> Result<()> {
        validate_cgroup_path(&self.cgroup_path)?;
        if self.cgroup_id == 0 {
            bail!("forbidden target cgroup ID must be nonzero");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableIdentity {
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
    pub size_bytes: u64,
    pub mtime_seconds: i64,
    pub mtime_nanoseconds: i64,
    pub ctime_seconds: i64,
    pub ctime_nanoseconds: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HelperCgroupIdentity {
    pub cgroup_path: String,
    pub cgroup_id: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedOutputEvidence {
    /// A binary-safe bounded prefix of the stream.
    pub captured_prefix_bytes_hex: String,
    pub captured_bytes: u64,
    pub observed_bytes: u64,
    /// SHA-256 of every byte read. If `stream_closed` is false, this is only
    /// the digest of the observed prefix and must not be treated as complete.
    pub sha256: String,
    pub truncated: bool,
    pub stream_closed: bool,
}

/// Observer-owned target-Linux identity at one recovery boundary. The helper
/// success predicate is intentionally independent of this state evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryEnvironmentIdentity {
    pub boot_id: String,
    pub barrier: RootFreezeBarrier,
    pub identity_assessment: IdentityAssessment,
}

impl CapturedOutputEvidence {
    fn empty() -> Self {
        Self {
            captured_prefix_bytes_hex: String::new(),
            captured_bytes: 0,
            observed_bytes: 0,
            sha256: hex::encode(Sha256::digest([])),
            truncated: false,
            stream_closed: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryEvidence {
    pub schema_version: u32,
    pub mechanism: String,
    pub checkpoint_id: String,
    pub recovery_id: String,
    pub executable_path: String,
    pub argv: Vec<String>,
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
    pub expected_executable_sha256: String,
    pub executable_sha256_before: Option<String>,
    pub executable_sha256_after: Option<String>,
    pub executable_identity_before: Option<ExecutableIdentity>,
    pub executable_identity_after: Option<ExecutableIdentity>,
    pub executable_identity_stable: Option<bool>,
    pub attempt_started_unix_ns: u128,
    pub command_started_unix_ns: Option<u128>,
    pub ended_unix_ns: u128,
    pub command_duration_ns: Option<u64>,
    /// B-side frozen target identity immediately before the external helper.
    /// The coordinator binds this to the separately committed B artifacts.
    #[serde(default)]
    pub before_environment: Option<RecoveryEnvironmentIdentity>,
    /// Fresh target identity after helper exit and before snapshot C.
    #[serde(default)]
    pub after_environment: Option<RecoveryEnvironmentIdentity>,
    pub helper_pid: Option<u32>,
    pub process_group_id: Option<u32>,
    pub helper_start_cgroup: Option<HelperCgroupIdentity>,
    pub forbidden_target_cgroups: Vec<ForbiddenCgroupIdentity>,
    pub helper_outside_forbidden_cgroups_at_start: Option<bool>,
    /// This is intentionally explicit: generic Linux process groups cannot
    /// prove that a privileged helper never migrated cgroup or escaped by
    /// creating a new session after it was resumed.
    pub containment_evidence_model: String,
    pub exit_code: Option<i32>,
    pub termination_signal: Option<i32>,
    pub timed_out: bool,
    pub term_sent_to_process_group: bool,
    pub kill_sent_to_process_group: bool,
    pub process_group_empty_after_wait: Option<bool>,
    pub stdout: CapturedOutputEvidence,
    pub stderr: CapturedOutputEvidence,
    pub success: bool,
    pub error_reason: Option<String>,
}

impl RecoveryEvidence {
    fn new(config: &RecoveryConfig, forbidden: &[ForbiddenCgroupIdentity]) -> Result<Self> {
        Ok(Self {
            schema_version: RECOVERY_EVIDENCE_SCHEMA_VERSION,
            mechanism: "DIRECT_EXEC_NO_SHELL".to_owned(),
            checkpoint_id: config.checkpoint_id.clone(),
            recovery_id: config.recovery_id.clone(),
            executable_path: config.executable_path.clone(),
            argv: config.argv.clone(),
            timeout_ms: config.timeout_ms,
            max_output_bytes: config.max_output_bytes,
            expected_executable_sha256: config.expected_sha256.clone(),
            executable_sha256_before: None,
            executable_sha256_after: None,
            executable_identity_before: None,
            executable_identity_after: None,
            executable_identity_stable: None,
            attempt_started_unix_ns: unix_ns()?,
            command_started_unix_ns: None,
            ended_unix_ns: 0,
            command_duration_ns: None,
            before_environment: None,
            after_environment: None,
            helper_pid: None,
            process_group_id: None,
            helper_start_cgroup: None,
            forbidden_target_cgroups: forbidden.to_vec(),
            helper_outside_forbidden_cgroups_at_start: None,
            containment_evidence_model:
                "STARTUP_CGROUP_AND_PROCESS_GROUP_ONLY; POST_EXEC_CGROUP_MIGRATION_NOT_EXCLUDED"
                    .to_owned(),
            exit_code: None,
            termination_signal: None,
            timed_out: false,
            term_sent_to_process_group: false,
            kill_sent_to_process_group: false,
            process_group_empty_after_wait: None,
            stdout: CapturedOutputEvidence::empty(),
            stderr: CapturedOutputEvidence::empty(),
            success: false,
            error_reason: None,
        })
    }
}

/// Execute a content-bound recovery helper without invoking a shell.
///
/// Configuration-schema errors are returned as `Err`. Once the schema and
/// forbidden-cgroup identities are accepted, operational failures (including
/// a bad digest, unsafe permissions, spawn failure, nonzero exit, signal, or
/// timeout) are returned as a `RecoveryEvidence` value with `success == false`.
pub fn execute(
    config: &RecoveryConfig,
    forbidden_cgroups: &[ForbiddenCgroupIdentity],
) -> Result<RecoveryEvidence> {
    config.validate_schema()?;
    validate_forbidden_cgroups(forbidden_cgroups)?;
    let mut evidence = RecoveryEvidence::new(config, forbidden_cgroups)?;

    let mut executable = match PreparedExecutable::open(&config.executable_path) {
        Ok(value) => value,
        Err(error) => {
            append_error(
                &mut evidence.error_reason,
                format!("executable preflight: {error:#}"),
            );
            finish_evidence(&mut evidence, None);
            return Ok(evidence);
        }
    };
    evidence.executable_sha256_before = Some(executable.sha256.clone());
    evidence.executable_identity_before = Some(executable.identity.clone());
    if executable.sha256 != config.expected_sha256 {
        append_error(
            &mut evidence.error_reason,
            "recovery executable SHA-256 does not match the configured digest".to_owned(),
        );
    } else if let Err(error) = run_helper(config, forbidden_cgroups, &mut executable, &mut evidence)
    {
        append_error(
            &mut evidence.error_reason,
            format!("helper execution: {error:#}"),
        );
    }

    let opened_file_stable = match executable.rehash() {
        Ok((identity, digest)) => {
            let stable = evidence.executable_identity_before.as_ref() == Some(&identity)
                && evidence.executable_sha256_before.as_ref() == Some(&digest)
                && digest == config.expected_sha256;
            if !stable {
                append_error(
                    &mut evidence.error_reason,
                    "opened recovery executable changed during execution".to_owned(),
                );
            }
            stable
        }
        Err(error) => {
            append_error(
                &mut evidence.error_reason,
                format!("rehash opened recovery executable: {error:#}"),
            );
            false
        }
    };

    let pathname_stable = match PreparedExecutable::open(&config.executable_path) {
        Ok(mut path_after) => match path_after.rehash() {
            Ok((identity, digest)) => {
                let path_stable = evidence.executable_identity_before.as_ref() == Some(&identity)
                    && evidence.executable_sha256_before.as_ref() == Some(&digest)
                    && digest == config.expected_sha256;
                evidence.executable_identity_after = Some(identity);
                evidence.executable_sha256_after = Some(digest);
                if !path_stable {
                    append_error(
                        &mut evidence.error_reason,
                        "recovery executable pathname was replaced during execution".to_owned(),
                    );
                }
                path_stable
            }
            Err(error) => {
                append_error(
                    &mut evidence.error_reason,
                    format!("rehash recovery executable pathname: {error:#}"),
                );
                false
            }
        },
        Err(error) => {
            append_error(
                &mut evidence.error_reason,
                format!("reopen recovery executable pathname: {error:#}"),
            );
            false
        }
    };
    evidence.executable_identity_stable = Some(opened_file_stable && pathname_stable);

    if evidence.command_started_unix_ns.is_some() {
        if evidence.timed_out {
            append_error(
                &mut evidence.error_reason,
                "recovery command timed out".to_owned(),
            );
        } else if let Some(code) = evidence.exit_code {
            if code != 0 {
                append_error(
                    &mut evidence.error_reason,
                    format!("recovery command exited with status {code}"),
                );
            }
        } else if let Some(signal) = evidence.termination_signal {
            append_error(
                &mut evidence.error_reason,
                format!("recovery command terminated by signal {signal}"),
            );
        } else {
            append_error(
                &mut evidence.error_reason,
                "recovery command has no terminal wait status".to_owned(),
            );
        }
    }
    if !evidence.stdout.stream_closed || !evidence.stderr.stream_closed {
        append_error(
            &mut evidence.error_reason,
            "recovery output stream remained open after the helper leader exited".to_owned(),
        );
    }

    let success = evidence.command_started_unix_ns.is_some()
        && evidence.exit_code == Some(0)
        && evidence.termination_signal.is_none()
        && !evidence.timed_out
        && evidence.helper_outside_forbidden_cgroups_at_start == Some(true)
        && evidence.process_group_empty_after_wait == Some(true)
        && evidence.executable_identity_stable == Some(true)
        && evidence.stdout.stream_closed
        && evidence.stderr.stream_closed
        && evidence.error_reason.is_none();
    evidence.success = success;
    finish_evidence(&mut evidence, None);
    Ok(evidence)
}

struct PreparedExecutable {
    file: File,
    identity: ExecutableIdentity,
    sha256: String,
}

impl PreparedExecutable {
    fn open(path: &str) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("open recovery executable {path}"))?;
        let (identity, sha256) = inspect_and_hash(&mut file)?;
        Ok(Self {
            file,
            identity,
            sha256,
        })
    }

    fn rehash(&mut self) -> Result<(ExecutableIdentity, String)> {
        inspect_and_hash(&mut self.file)
    }
}

fn inspect_and_hash(file: &mut File) -> Result<(ExecutableIdentity, String)> {
    let before = file.metadata().context("stat recovery executable")?;
    if !before.file_type().is_file() || before.nlink() != 1 {
        bail!("recovery executable is not a singly-linked regular file");
    }
    if before.mode() & 0o022 != 0 {
        bail!("recovery executable is group- or world-writable");
    }
    if before.mode() & 0o111 == 0 {
        bail!("recovery executable has no execute bit");
    }
    if before.len() > MAX_EXECUTABLE_BYTES {
        bail!("recovery executable exceeds the {MAX_EXECUTABLE_BYTES}-byte hash bound");
    }
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut size = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .context("executable size overflow")?;
        hasher.update(&buffer[..count]);
    }
    let after = file.metadata().context("re-stat recovery executable")?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.mode() != after.mode()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
        || before.nlink() != after.nlink()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || size != before.len()
    {
        bail!("recovery executable changed while it was hashed");
    }
    file.seek(SeekFrom::Start(0))?;
    Ok((
        ExecutableIdentity {
            device: before.dev(),
            inode: before.ino(),
            mode: before.mode(),
            uid: before.uid(),
            gid: before.gid(),
            nlink: before.nlink(),
            size_bytes: before.len(),
            mtime_seconds: before.mtime(),
            mtime_nanoseconds: before.mtime_nsec(),
            ctime_seconds: before.ctime(),
            ctime_nanoseconds: before.ctime_nsec(),
        },
        hex::encode(hasher.finalize()),
    ))
}

fn run_helper(
    config: &RecoveryConfig,
    forbidden: &[ForbiddenCgroupIdentity],
    executable: &mut PreparedExecutable,
    evidence: &mut RecoveryEvidence,
) -> Result<()> {
    let argv_storage = build_argv(config)?;
    let mut argv = argv_storage
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    argv.push(std::ptr::null());
    let environment_storage = build_environment()?;
    let mut environment = environment_storage
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    environment.push(std::ptr::null());

    let stdout_pipe = Pipe::new(false)?;
    let stderr_pipe = Pipe::new(false)?;
    let exec_error_pipe = Pipe::new(true)?;
    set_nonblocking(stdout_pipe.read.as_raw_fd())?;
    set_nonblocking(stderr_pipe.read.as_raw_fd())?;
    let dev_null = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/dev/null")
        .context("open /dev/null for recovery stdin")?;

    set_cloexec(executable.file.as_raw_fd(), false)?;
    // SAFETY: the child branch below performs only async-signal-safe libc
    // operations using storage fully prepared before fork, then execs or exits.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let error = std::io::Error::last_os_error();
        let _ = set_cloexec(executable.file.as_raw_fd(), true);
        return Err(error).context("fork recovery helper");
    }
    if pid == 0 {
        child_exec(
            executable.file.as_raw_fd(),
            &argv,
            &environment,
            dev_null.as_raw_fd(),
            stdout_pipe.read.as_raw_fd(),
            stdout_pipe.write.as_raw_fd(),
            stderr_pipe.read.as_raw_fd(),
            stderr_pipe.write.as_raw_fd(),
            exec_error_pipe.read.as_raw_fd(),
            exec_error_pipe.write.as_raw_fd(),
        );
    }
    let mut guard = ChildGuard::new(pid);
    evidence.helper_pid = Some(pid as u32);
    set_cloexec(executable.file.as_raw_fd(), true)
        .context("restore close-on-exec on recovery executable")?;
    drop(stdout_pipe.write);
    drop(stderr_pipe.write);
    drop(exec_error_pipe.write);
    drop(dev_null);

    let stopped = wait_for_initial_stop(pid)?;
    if !stopped {
        guard.leader_reaped = true;
        evidence.process_group_empty_after_wait = Some(!process_group_exists(pid));
        bail!("recovery helper exited before its startup cgroup could be checked");
    }
    let pgid = unsafe { libc::getpgid(pid) };
    if pgid != pid {
        bail!("recovery helper did not enter the required private process group");
    }
    evidence.process_group_id = Some(pgid as u32);

    let membership = read_helper_cgroup(pid)?;
    let outside = !forbidden.iter().any(|target| {
        membership.cgroup_id == target.cgroup_id
            || cgroup_is_within(&membership.cgroup_path, &target.cgroup_path)
    });
    evidence.helper_start_cgroup = Some(membership);
    evidence.helper_outside_forbidden_cgroups_at_start = Some(outside);
    if !outside {
        bail!("recovery helper startup cgroup overlaps an observed target cgroup");
    }

    let mut stdout = CaptureState::new(stdout_pipe.read, config.max_output_bytes)?;
    let mut stderr = CaptureState::new(stderr_pipe.read, config.max_output_bytes)?;
    let mut exec_error = SmallNonblockingRead::new(exec_error_pipe.read);
    if unsafe { libc::kill(pid, libc::SIGCONT) } != 0 {
        bail!(
            "resume stopped recovery helper: {}",
            std::io::Error::last_os_error()
        );
    }
    let command_started = Instant::now();
    evidence.command_started_unix_ns = Some(unix_ns()?);

    let timeout = Duration::from_millis(config.timeout_ms);
    let mut wait_status = None;
    loop {
        stdout.drain()?;
        stderr.drain()?;
        exec_error.drain()?;
        if let Some(status) = try_wait(pid)? {
            wait_status = Some(status);
            guard.leader_reaped = true;
            break;
        }
        if command_started.elapsed() >= timeout {
            evidence.timed_out = true;
            signal_group(pid, libc::SIGTERM)?;
            evidence.term_sent_to_process_group = true;
            let grace_started = Instant::now();
            while grace_started.elapsed() < TERMINATION_GRACE {
                stdout.drain()?;
                stderr.drain()?;
                exec_error.drain()?;
                if let Some(status) = try_wait(pid)? {
                    wait_status = Some(status);
                    guard.leader_reaped = true;
                    break;
                }
                thread::sleep(POLL_INTERVAL);
            }
            if process_group_exists(pid) || wait_status.is_none() {
                signal_group_best_effort(pid, libc::SIGKILL);
                signal_pid_best_effort(pid, libc::SIGKILL);
                evidence.kill_sent_to_process_group = true;
            }
            if wait_status.is_none() {
                let status = wait_blocking(pid)?;
                wait_status = Some(status);
                guard.leader_reaped = true;
            }
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }

    let status = wait_status.context("recovery helper wait status is absent")?;
    record_wait_status(status, evidence);
    evidence.command_duration_ns = Some(duration_ns(command_started.elapsed())?);

    if process_group_exists(pid) {
        signal_group_best_effort(pid, libc::SIGTERM);
        evidence.term_sent_to_process_group = true;
        let started = Instant::now();
        while started.elapsed() < TERMINATION_GRACE && process_group_exists(pid) {
            stdout.drain()?;
            stderr.drain()?;
            exec_error.drain()?;
            thread::sleep(POLL_INTERVAL);
        }
        if process_group_exists(pid) {
            signal_group_best_effort(pid, libc::SIGKILL);
            evidence.kill_sent_to_process_group = true;
            append_error(
                &mut evidence.error_reason,
                "recovery helper process group remained populated after leader exit".to_owned(),
            );
        }
    }
    let group_wait_started = Instant::now();
    while group_wait_started.elapsed() < TERMINATION_GRACE && process_group_exists(pid) {
        thread::sleep(POLL_INTERVAL);
    }
    evidence.process_group_empty_after_wait = Some(!process_group_exists(pid));
    if evidence.process_group_empty_after_wait != Some(true) {
        append_error(
            &mut evidence.error_reason,
            "recovery helper process group could not be proven empty".to_owned(),
        );
    }

    let drain_started = Instant::now();
    while drain_started.elapsed() < OUTPUT_DRAIN_GRACE
        && (!stdout.closed || !stderr.closed || !exec_error.closed)
    {
        stdout.drain()?;
        stderr.drain()?;
        exec_error.drain()?;
        if !stdout.closed || !stderr.closed || !exec_error.closed {
            thread::sleep(POLL_INTERVAL);
        }
    }
    evidence.stdout = stdout.finish();
    evidence.stderr = stderr.finish();
    if let Some(error) = exec_error.decode_error()? {
        append_error(&mut evidence.error_reason, error);
    }
    guard.disarm();
    Ok(())
}

fn build_argv(config: &RecoveryConfig) -> Result<Vec<CString>> {
    std::iter::once(config.executable_path.as_str())
        .chain(config.argv.iter().map(String::as_str))
        .map(|value| CString::new(value.as_bytes()).context("recovery argv contains NUL"))
        .collect()
}

fn build_environment() -> Result<Vec<CString>> {
    std::env::vars_os()
        .map(|(key, value)| {
            let mut bytes = key.as_os_str().as_bytes().to_vec();
            bytes.push(b'=');
            bytes.extend_from_slice(value.as_os_str().as_bytes());
            CString::new(bytes).context("inherited recovery environment contains NUL")
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn child_exec(
    executable_fd: RawFd,
    argv: &[*const libc::c_char],
    environment: &[*const libc::c_char],
    dev_null_fd: RawFd,
    stdout_read_fd: RawFd,
    stdout_write_fd: RawFd,
    stderr_read_fd: RawFd,
    stderr_write_fd: RawFd,
    exec_error_read_fd: RawFd,
    exec_error_write_fd: RawFd,
) -> ! {
    unsafe {
        libc::close(stdout_read_fd);
        libc::close(stderr_read_fd);
        libc::close(exec_error_read_fd);
        if libc::dup2(dev_null_fd, libc::STDIN_FILENO) < 0 {
            child_fail(exec_error_write_fd, 1);
        }
        if libc::dup2(stdout_write_fd, libc::STDOUT_FILENO) < 0 {
            child_fail(exec_error_write_fd, 2);
        }
        if libc::dup2(stderr_write_fd, libc::STDERR_FILENO) < 0 {
            child_fail(exec_error_write_fd, 3);
        }
        libc::close(dev_null_fd);
        libc::close(stdout_write_fd);
        libc::close(stderr_write_fd);
        if libc::setpgid(0, 0) != 0 {
            child_fail(exec_error_write_fd, 4);
        }
        if libc::raise(libc::SIGSTOP) != 0 {
            child_fail(exec_error_write_fd, 5);
        }
        libc::fexecve(executable_fd, argv.as_ptr(), environment.as_ptr());
        child_fail(exec_error_write_fd, 6);
    }
}

unsafe fn child_fail(error_fd: RawFd, stage: i32) -> ! {
    let errno = *libc::__errno_location();
    let message = [stage, errno];
    libc::write(
        error_fd,
        message.as_ptr().cast(),
        std::mem::size_of_val(&message),
    );
    libc::_exit(127)
}

struct Pipe {
    read: File,
    write: File,
}

impl Pipe {
    fn new(nonblocking: bool) -> Result<Self> {
        let mut descriptors = [-1_i32; 2];
        let mut flags = libc::O_CLOEXEC;
        if nonblocking {
            flags |= libc::O_NONBLOCK;
        }
        if unsafe { libc::pipe2(descriptors.as_mut_ptr(), flags) } != 0 {
            return Err(std::io::Error::last_os_error()).context("create recovery evidence pipe");
        }
        // SAFETY: pipe2 returned two newly owned file descriptors.
        Ok(unsafe {
            Self {
                read: File::from_raw_fd(descriptors[0]),
                write: File::from_raw_fd(descriptors[1]),
            }
        })
    }
}

struct CaptureState {
    file: File,
    captured: Vec<u8>,
    observed: u64,
    hasher: Sha256,
    limit: usize,
    closed: bool,
}

impl CaptureState {
    fn new(file: File, limit: u64) -> Result<Self> {
        Ok(Self {
            file,
            captured: Vec::new(),
            observed: 0,
            hasher: Sha256::new(),
            limit: usize::try_from(limit).context("output capture bound exceeds usize")?,
            closed: false,
        })
    }

    fn drain(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        let mut budget = 256 * 1024_usize;
        let mut buffer = [0_u8; 16 * 1024];
        while budget > 0 {
            match self.file.read(&mut buffer) {
                Ok(0) => {
                    self.closed = true;
                    break;
                }
                Ok(count) => {
                    budget = budget.saturating_sub(count);
                    self.observed = self
                        .observed
                        .checked_add(count as u64)
                        .context("recovery output byte count overflow")?;
                    self.hasher.update(&buffer[..count]);
                    let remaining = self.limit.saturating_sub(self.captured.len());
                    self.captured
                        .extend_from_slice(&buffer[..count.min(remaining)]);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error).context("read recovery output pipe"),
            }
        }
        Ok(())
    }

    fn finish(self) -> CapturedOutputEvidence {
        let captured_bytes = self.captured.len() as u64;
        CapturedOutputEvidence {
            captured_prefix_bytes_hex: hex::encode(self.captured),
            captured_bytes,
            observed_bytes: self.observed,
            sha256: hex::encode(self.hasher.finalize()),
            truncated: captured_bytes < self.observed || !self.closed,
            stream_closed: self.closed,
        }
    }
}

struct SmallNonblockingRead {
    file: File,
    bytes: Vec<u8>,
    closed: bool,
}

impl SmallNonblockingRead {
    fn new(file: File) -> Self {
        Self {
            file,
            bytes: Vec::new(),
            closed: false,
        }
    }

    fn drain(&mut self) -> Result<()> {
        let mut buffer = [0_u8; 32];
        loop {
            match self.file.read(&mut buffer) {
                Ok(0) => {
                    self.closed = true;
                    return Ok(());
                }
                Ok(count) => {
                    if self.bytes.len() + count > 64 {
                        bail!("recovery exec-error pipe exceeded its fixed bound");
                    }
                    self.bytes.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error).context("read recovery exec-error pipe"),
            }
        }
    }

    fn decode_error(&self) -> Result<Option<String>> {
        if self.bytes.is_empty() {
            if self.closed {
                return Ok(None);
            }
            return Ok(Some(
                "recovery exec status pipe did not reach EOF".to_owned(),
            ));
        }
        if self.bytes.len() != 2 * std::mem::size_of::<i32>() {
            bail!("recovery exec-error record has an invalid size");
        }
        let stage = i32::from_ne_bytes(self.bytes[0..4].try_into().unwrap());
        let errno = i32::from_ne_bytes(self.bytes[4..8].try_into().unwrap());
        Ok(Some(format!(
            "recovery child setup/exec failed at stage {stage}: {}",
            std::io::Error::from_raw_os_error(errno)
        )))
    }
}

struct ChildGuard {
    pid: libc::pid_t,
    leader_reaped: bool,
    armed: bool,
}

impl ChildGuard {
    fn new(pid: libc::pid_t) -> Self {
        Self {
            pid,
            leader_reaped: false,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        signal_group_best_effort(self.pid, libc::SIGKILL);
        signal_pid_best_effort(self.pid, libc::SIGKILL);
        if !self.leader_reaped {
            unsafe {
                let mut status = 0_i32;
                while libc::waitpid(self.pid, &mut status, 0) < 0
                    && std::io::Error::last_os_error().kind() == ErrorKind::Interrupted
                {
                }
            }
        }
    }
}

fn wait_for_initial_stop(pid: libc::pid_t) -> Result<bool> {
    loop {
        let mut status = 0_i32;
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
        if result == pid {
            if libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP {
                return Ok(true);
            }
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                return Ok(false);
            }
            bail!("recovery helper produced an unexpected initial wait status");
        }
        if result < 0 && std::io::Error::last_os_error().kind() == ErrorKind::Interrupted {
            continue;
        }
        return Err(std::io::Error::last_os_error()).context("wait for stopped recovery helper");
    }
}

fn try_wait(pid: libc::pid_t) -> Result<Option<i32>> {
    loop {
        let mut status = 0_i32;
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result == pid {
            return Ok(Some(status));
        }
        if result == 0 {
            return Ok(None);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == ErrorKind::Interrupted {
            continue;
        }
        return Err(error).context("poll recovery helper wait status");
    }
}

fn wait_blocking(pid: libc::pid_t) -> Result<i32> {
    loop {
        let mut status = 0_i32;
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result == pid {
            return Ok(status);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == ErrorKind::Interrupted {
            continue;
        }
        return Err(error).context("wait for terminated recovery helper");
    }
}

fn record_wait_status(status: i32, evidence: &mut RecoveryEvidence) {
    if libc::WIFEXITED(status) {
        evidence.exit_code = Some(libc::WEXITSTATUS(status));
    } else if libc::WIFSIGNALED(status) {
        evidence.termination_signal = Some(libc::WTERMSIG(status));
    }
}

fn signal_group(pid: libc::pid_t, signal: i32) -> Result<()> {
    if unsafe { libc::kill(-pid, signal) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(error).with_context(|| format!("send signal {signal} to recovery process group"))
}

fn signal_group_best_effort(pid: libc::pid_t, signal: i32) {
    unsafe {
        libc::kill(-pid, signal);
    }
}

fn signal_pid_best_effort(pid: libc::pid_t, signal: i32) {
    unsafe {
        libc::kill(pid, signal);
    }
}

fn process_group_exists(pid: libc::pid_t) -> bool {
    if unsafe { libc::kill(-pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn read_helper_cgroup(pid: libc::pid_t) -> Result<HelperCgroupIdentity> {
    let path = format!("/proc/{pid}/cgroup");
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .with_context(|| format!("open recovery helper cgroup membership {path}"))?;
    let mut bytes = Vec::new();
    file.by_ref().take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 {
        bail!("recovery helper cgroup membership exceeds its bound");
    }
    let text =
        String::from_utf8(bytes).context("recovery helper cgroup membership is not UTF-8")?;
    let mut unified = None;
    for line in text.lines() {
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields.next().context("cgroup line lacks hierarchy")?;
        let controllers = fields.next().context("cgroup line lacks controllers")?;
        let member_path = fields.next().context("cgroup line lacks path")?;
        if hierarchy == "0"
            && controllers.is_empty()
            && unified.replace(member_path.to_owned()).is_some()
        {
            bail!("recovery helper has duplicate unified cgroup memberships");
        }
    }
    let cgroup_path = unified.context("recovery helper has no cgroup-v2 membership")?;
    validate_cgroup_path(&cgroup_path)?;
    let relative = Path::new(&cgroup_path)
        .strip_prefix("/")
        .context("helper cgroup path is not absolute")?;
    let host_path = Path::new(CGROUPFS_ROOT).join(relative);
    let metadata = std::fs::symlink_metadata(&host_path)
        .with_context(|| format!("stat helper cgroup {}", host_path.display()))?;
    if !metadata.file_type().is_dir() || metadata.ino() == 0 {
        bail!("recovery helper cgroup is not a stable directory");
    }
    Ok(HelperCgroupIdentity {
        cgroup_path,
        cgroup_id: metadata.ino(),
    })
}

fn cgroup_is_within(candidate: &str, root: &str) -> bool {
    root == "/"
        || candidate == root
        || (candidate.starts_with(root)
            && candidate.as_bytes().get(root.len()).copied() == Some(b'/'))
}

fn validate_forbidden_cgroups(values: &[ForbiddenCgroupIdentity]) -> Result<()> {
    if values.len() > MAX_FORBIDDEN_CGROUPS {
        bail!("forbidden cgroup list exceeds {MAX_FORBIDDEN_CGROUPS} entries");
    }
    for value in values {
        value.validate()?;
    }
    for (index, value) in values.iter().enumerate() {
        if values[..index].iter().any(|prior| {
            prior.cgroup_path == value.cgroup_path || prior.cgroup_id == value.cgroup_id
        }) {
            bail!("forbidden cgroup list contains duplicate paths or IDs");
        }
    }
    Ok(())
}

fn validate_id(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("{label} must contain 1..={MAX_ID_BYTES} conservative ASCII identity bytes");
    }
    Ok(())
}

fn validate_absolute_path(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.as_bytes().contains(&0)
        || value.as_bytes().contains(&b'\n')
    {
        bail!("{label} path is empty or unbounded");
    }
    let path = Path::new(value);
    if !path.is_absolute()
        || path == Path::new("/")
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        bail!("{label} path must be absolute and lexically normalized");
    }
    Ok(())
}

fn validate_cgroup_path(value: &str) -> Result<()> {
    validate_absolute_path_allow_root(value, "cgroup")?;
    if value.len() > 1 && value.ends_with('/') {
        bail!("cgroup path must not have a trailing slash");
    }
    if value != "/"
        && value[1..]
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        bail!("cgroup path must be a normalized Linux path");
    }
    Ok(())
}

fn validate_absolute_path_allow_root(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || !value.starts_with('/')
        || value.as_bytes().contains(&0)
        || value.as_bytes().contains(&b'\n')
    {
        bail!("{label} path must be an absolute bounded Linux path");
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} SHA-256 must contain 64 lowercase hexadecimal bytes");
    }
    Ok(())
}

fn set_nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error()).context("set pipe nonblocking");
    }
    Ok(())
}

fn set_cloexec(fd: RawFd, enabled: bool) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error()).context("read descriptor flags");
    }
    let next = if enabled {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, next) } < 0 {
        return Err(std::io::Error::last_os_error()).context("write descriptor flags");
    }
    Ok(())
}

fn duration_ns(duration: Duration) -> Result<u64> {
    u64::try_from(duration.as_nanos()).context("recovery duration exceeds u64 nanoseconds")
}

fn unix_ns() -> Result<u128> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_nanos())
}

fn finish_evidence(evidence: &mut RecoveryEvidence, duration: Option<Duration>) {
    evidence.ended_unix_ns = unix_ns().unwrap_or(evidence.attempt_started_unix_ns);
    if evidence.command_duration_ns.is_none() {
        evidence.command_duration_ns = duration.and_then(|value| duration_ns(value).ok());
    }
}

fn append_error(slot: &mut Option<String>, error: String) {
    let mut bounded = error;
    bounded.truncate(MAX_ERROR_BYTES);
    match slot {
        Some(existing) if existing.len() < MAX_ERROR_BYTES => {
            existing.push_str("; ");
            let remaining = MAX_ERROR_BYTES.saturating_sub(existing.len());
            existing.extend(bounded.chars().take(remaining));
        }
        Some(_) => {}
        None => *slot = Some(bounded),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(1);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "bpf-observer-recovery-{}-{serial}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn script(&self, body: &str, mode: u32) -> PathBuf {
            let path = self.0.join("recover");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&path)
                .unwrap();
            file.write_all(body.as_bytes()).unwrap();
            file.sync_all().unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn config(path: &Path) -> RecoveryConfig {
        let mut prepared = PreparedExecutable::open(path.to_str().unwrap()).unwrap();
        let (_, digest) = prepared.rehash().unwrap();
        RecoveryConfig {
            checkpoint_id: "checkpoint-1".to_owned(),
            recovery_id: "recovery-1".to_owned(),
            executable_path: path.to_str().unwrap().to_owned(),
            expected_sha256: digest,
            argv: vec!["argument".to_owned()],
            timeout_ms: 2_000,
            max_output_bytes: 64,
        }
    }

    #[test]
    fn recovery_success_captures_bounded_binary_safe_output() {
        let directory = TestDir::new();
        let path = directory.script(
            "#!/bin/sh\nprintf 'hello-%s' \"$1\"\nprintf 'warning' >&2\n",
            0o700,
        );
        let evidence = execute(&config(&path), &[]).unwrap();
        assert!(evidence.success, "{:?}", evidence.error_reason);
        assert!(evidence.before_environment.is_none());
        assert!(evidence.after_environment.is_none());
        assert_eq!(
            hex::decode(&evidence.stdout.captured_prefix_bytes_hex).unwrap(),
            b"hello-argument"
        );
        assert_eq!(
            hex::decode(&evidence.stderr.captured_prefix_bytes_hex).unwrap(),
            b"warning"
        );
        assert_eq!(evidence.exit_code, Some(0));
        assert_eq!(
            evidence.helper_outside_forbidden_cgroups_at_start,
            Some(true)
        );
    }

    #[test]
    fn nonzero_exit_is_evidence_not_an_api_error() {
        let directory = TestDir::new();
        let path = directory.script("#!/bin/sh\nexit 23\n", 0o700);
        let evidence = execute(&config(&path), &[]).unwrap();
        assert!(!evidence.success);
        assert_eq!(evidence.exit_code, Some(23));
        assert!(evidence.error_reason.unwrap().contains("status 23"));
    }

    #[test]
    fn timeout_terminates_the_private_process_group() {
        let directory = TestDir::new();
        let path = directory.script("#!/bin/sh\nwhile :; do :; done\n", 0o700);
        let mut value = config(&path);
        value.timeout_ms = 30;
        let evidence = execute(&value, &[]).unwrap();
        assert!(!evidence.success);
        assert!(evidence.timed_out);
        assert!(evidence.term_sent_to_process_group);
        assert_eq!(evidence.process_group_empty_after_wait, Some(true));
    }

    #[test]
    fn digest_mismatch_prevents_execution() {
        let directory = TestDir::new();
        let path = directory.script("#!/bin/sh\nexit 0\n", 0o700);
        let mut value = config(&path);
        value.expected_sha256 = "0".repeat(64);
        let evidence = execute(&value, &[]).unwrap();
        assert!(!evidence.success);
        assert!(evidence.helper_pid.is_none());
        assert!(evidence.error_reason.unwrap().contains("does not match"));
    }

    #[test]
    fn forbidden_startup_cgroup_prevents_execution() {
        let directory = TestDir::new();
        let path = directory.script("#!/bin/sh\nexit 0\n", 0o700);
        let membership = read_helper_cgroup(std::process::id() as libc::pid_t).unwrap();
        let forbidden = [ForbiddenCgroupIdentity {
            cgroup_path: membership.cgroup_path,
            cgroup_id: membership.cgroup_id,
        }];
        let evidence = execute(&config(&path), &forbidden).unwrap();
        assert!(!evidence.success);
        assert!(evidence.helper_pid.is_some());
        assert_eq!(
            evidence.helper_outside_forbidden_cgroups_at_start,
            Some(false)
        );
        assert!(evidence.command_started_unix_ns.is_none());
        assert!(evidence
            .error_reason
            .unwrap()
            .contains("overlaps an observed target cgroup"));
    }

    #[test]
    fn unsafe_permissions_prevent_execution() {
        let directory = TestDir::new();
        let path = directory.script("#!/bin/sh\nexit 0\n", 0o720);
        let value = RecoveryConfig {
            checkpoint_id: "checkpoint-1".to_owned(),
            recovery_id: "recovery-1".to_owned(),
            executable_path: path.to_str().unwrap().to_owned(),
            expected_sha256: "0".repeat(64),
            argv: Vec::new(),
            timeout_ms: 100,
            max_output_bytes: 64,
        };
        let evidence = execute(&value, &[]).unwrap();
        assert!(!evidence.success);
        assert!(evidence.helper_pid.is_none());
        assert!(evidence.error_reason.unwrap().contains("world-writable"));
    }

    #[test]
    fn schema_rejects_relative_path_and_unknown_json_field() {
        let value = RecoveryConfig {
            checkpoint_id: "checkpoint-1".to_owned(),
            recovery_id: "recovery-1".to_owned(),
            executable_path: "relative/recover".to_owned(),
            expected_sha256: "0".repeat(64),
            argv: Vec::new(),
            timeout_ms: 100,
            max_output_bytes: 64,
        };
        assert!(value.validate_schema().is_err());
        let json = r#"{
            "checkpoint_id":"c","recovery_id":"r","executable_path":"/bin/true",
            "expected_sha256":"0000000000000000000000000000000000000000000000000000000000000000",
            "argv":[],"timeout_ms":100,"max_output_bytes":64,"unexpected":true
        }"#;
        assert!(serde_json::from_str::<RecoveryConfig>(json).is_err());
    }
}
