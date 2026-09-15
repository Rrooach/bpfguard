// SPDX-License-Identifier: GPL-2.0-only

//! Per-run Observer peer for the Allox system-effects supervisor protocol.
//!
//! Allox owns the workload and cgroup lifecycle.  This process only opens an
//! already-created, sealed cgroup, records operations attributed to its exact
//! kernel ID, and commits a closed evidence directory after Allox presents an
//! empty+frozen FINISH barrier.

use crate::{
    cgroup::ManagedCgroup,
    effects_supervisor_protocol::{
        read_json_line, Binding, FinalizedResult, FinishMessage, Quiescence, StartMessage,
        PROTOCOL, PROTOCOL_VERSION,
    },
    environment,
};
use anyhow::{anyhow, bail, Context, Result};
use bpf_observer_schema::ArtifactDigest;
use bpf_observer_system_effects::{
    coverage_gaps, describe_policy, policy_sha256, AttributionContract, CaptureSource,
    CaptureStatus, CapturedArgument, CgroupMatchMode, CoverageStatus, EffectAttribution,
    EffectOperation, EventKind, FileObjectResolutionMode, KernelEvent, ObjectIdentity,
    ObjectReference, ObjectResolution, ObjectResolutionAuthority, ObjectResolutionQuality,
    ObjectResolutionStatus, ObjectRole, PolicyDescription, PolicyProfile, ResultStatus,
    SystemEffectEvent, SystemEffectHealth, SystemEffectRecorder, TransportStatus,
    EFFECT_EVENT_SCHEMA_VERSION, FLAG_OBJECT_DELETE_FAILED, FLAG_OBJECT_JOIN_AMBIGUOUS,
    FLAG_OBJECT_JOIN_MISSING, FLAG_OBJECT_PATH_UNAVAILABLE, FLAG_OBJECT_READ_FAILED,
    FLAG_PAYLOAD1_INVALID_LENGTH, FLAG_PAYLOAD1_READ_FAILED, FLAG_PAYLOAD1_TRUNCATED,
    FLAG_PAYLOAD2_INVALID_LENGTH, FLAG_PAYLOAD2_READ_FAILED, FLAG_PAYLOAD2_TRUNCATED,
    FLAG_PENDING_DELETE_FAILED, FLAG_PENDING_INSERT_FAILED, FLAG_PENDING_MISSING,
    FLAG_PENDING_POISONED, FLAG_POLICY_INVALID, FLAG_SYSCALL_MISMATCH, KERNEL_FILE_EVENT_SIZE,
    OBJECT_IDENTITY_PROTOCOL_VERSION,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::Duration;

const MANIFEST_NAME: &str = "manifest.json";
const POLICY_NAME: &str = "system-effects.policy.json";
const HEALTH_NAME: &str = "system-effects.health.json";
const WAL_NAME: &str = "system-effects.raw.bin";
const JSONL_NAME: &str = "system-effects.jsonl";
const ARTIFACT_NAMES: [&str; 4] = [POLICY_NAME, HEALTH_NAME, WAL_NAME, JSONL_NAME];
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const MAX_SMALL_JSON_BYTES: u64 = 8 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_WAL_BYTES: u64 = 384 * 1024 * 1024;
const MAX_JSONL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EVENT_JSON_BYTES: u64 = 64 * 1024;
const MAX_EVENTS: u64 = 1_000_000;
const WAL_COMPACT_EVENT_BYTES: usize = 152;
const WAL_FILE_OBJECT_EVENT_BYTES: usize = KERNEL_FILE_EVENT_SIZE;
const WAL_FULL_EVENT_BYTES: usize = 344;
const EVENT_ATTEMPT: u16 = 1;
const EVENT_RESULT: u16 = 2;
const PAYLOAD_NONE: u8 = 0;
const PAYLOAD_USER_STRING: u8 = 1;
const PAYLOAD_SOCKADDR: u8 = 2;
const CAPTURE_BYTES: usize = 96;
const EVENT_SEMANTICS: &str = "OBSERVED_OPERATION_NOT_PROOF_OF_DURABLE_STATE_CHANGE";
const CAPTURE_AUTHORITY: &str = "USER_MEMORY_AT_SYSCALL_ENTRY_NOT_KERNEL_RESOLVED_OBJECT";
const EVIDENCE_KIND: &str = "ALLOX_SYSTEM_EFFECT_OPERATION_STREAM_V1";
const FATAL_FLAGS: u32 = FLAG_PENDING_INSERT_FAILED
    | FLAG_PENDING_MISSING
    | FLAG_PENDING_POISONED
    | FLAG_PENDING_DELETE_FAILED
    | FLAG_POLICY_INVALID
    | FLAG_SYSCALL_MISMATCH
    | FLAG_OBJECT_JOIN_MISSING
    | FLAG_OBJECT_JOIN_AMBIGUOUS
    | FLAG_OBJECT_READ_FAILED
    | FLAG_OBJECT_DELETE_FAILED
    | FLAG_OBJECT_PATH_UNAVAILABLE;

#[derive(Clone, Debug)]
pub struct ServeRequest {
    pub recorder_object: PathBuf,
    pub drain_timeout_ms: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyArtifact {
    schema_version: u32,
    profile: PolicyProfile,
    policy_sha256: String,
    entries: Vec<PolicyDescription>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RecorderBinding {
    expected_object_sha256: String,
    loaded_object_sha256: String,
    object_resolution_mode: FileObjectResolutionMode,
    policy_sha256: String,
    policy_artifact: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundaryEvidence {
    cgroup_identity_verified_before_ready: bool,
    cgroup_leaf_seal_verified_before_ready: bool,
    cgroup_identity_verified_after_finish: bool,
    cgroup_empty_frozen_verified_after_finish: bool,
    evidence_directory_private_and_anchored: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Coverage {
    attribution_scope: String,
    delegated_causality: String,
    event_semantics: String,
    operation_events_are_state_diff: bool,
    final_system_state_confirmed: bool,
    coverage_status: String,
    gaps: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SupervisorManifest {
    schema_version: u32,
    evidence_kind: String,
    supervisor_protocol: String,
    supervisor_protocol_version: u32,
    binding: Binding,
    evidence_directory: String,
    outcome: crate::effects_supervisor_protocol::Outcome,
    quiescence: Quiescence,
    started_unix_ns: u128,
    finalized_unix_ns: u128,
    kernel_release: String,
    boot_id: String,
    observer_version: String,
    source_commit: Option<String>,
    recorder: RecorderBinding,
    attribution_contract: AttributionContract,
    boundary: BoundaryEvidence,
    transport_status: TransportStatus,
    health_artifact: String,
    coverage: Coverage,
    artifacts: BTreeMap<String, ArtifactDigest>,
    notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

struct EvidenceDirectory {
    requested: PathBuf,
    anchored: PathBuf,
    handle: File,
    identity: DirectoryIdentity,
}

impl EvidenceDirectory {
    fn open_empty_private(path: &Path) -> Result<Self> {
        if !path.is_absolute() || path.as_os_str().as_bytes().contains(&0) {
            bail!("effects evidence directory must be an absolute path without NUL");
        }
        let lexical = path.to_path_buf();
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect effects evidence directory {}", path.display()))?;
        if !metadata.file_type().is_dir() {
            bail!("effects evidence directory must be a real non-symlink directory");
        }
        let canonical = fs::canonicalize(path).with_context(|| {
            format!("canonicalize effects evidence directory {}", path.display())
        })?;
        if canonical != lexical {
            bail!("effects evidence directory path must already be canonical");
        }
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o7777 != 0o700
        {
            bail!("effects evidence directory must be owned by the sidecar euid with mode 0700");
        }
        if fs::read_dir(path)
            .with_context(|| format!("enumerate effects evidence directory {}", path.display()))?
            .next()
            .is_some()
        {
            bail!("effects evidence directory must be empty at START");
        }
        let handle = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(path)
            .with_context(|| format!("anchor effects evidence directory {}", path.display()))?;
        let identity = directory_identity(&handle.metadata()?)?;
        let anchored = PathBuf::from(format!("/proc/self/fd/{}", handle.as_raw_fd()));
        if identity != directory_identity(&metadata)?
            || fs::read_dir(&anchored)
                .context("re-enumerate anchored effects evidence directory")?
                .next()
                .is_some()
        {
            bail!("effects evidence directory changed while it was anchored");
        }
        Ok(Self {
            requested: lexical,
            anchored,
            handle,
            identity,
        })
    }

    fn path(&self) -> &Path {
        &self.anchored
    }

    fn requested_path(&self) -> &Path {
        &self.requested
    }

    fn verify_identity(&self) -> Result<()> {
        let by_handle = directory_identity(&self.handle.metadata()?)?;
        let by_path = fs::symlink_metadata(&self.requested).with_context(|| {
            format!(
                "reinspect effects evidence directory {}",
                self.requested.display()
            )
        })?;
        if !by_path.file_type().is_dir()
            || directory_identity(&by_path)? != self.identity
            || by_handle != self.identity
        {
            bail!("effects evidence directory changed identity or permissions");
        }
        Ok(())
    }

    fn create_json<T: Serialize>(&self, name: &str, value: &T, limit: u64) -> Result<()> {
        validate_artifact_name(name)?;
        self.verify_identity()?;
        let bytes = serde_json::to_vec(value).context("serialize supervisor evidence JSON")?;
        let size = (bytes.len() as u64)
            .checked_add(1)
            .context("supervisor JSON size overflow")?;
        if size > limit {
            bail!("supervisor artifact {name} exceeds its {limit}-byte limit");
        }
        let path = self.anchored.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .with_context(|| format!("create supervisor artifact {name}"))?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()
            .with_context(|| format!("fsync supervisor artifact {name}"))?;
        self.handle
            .sync_all()
            .context("fsync supervisor evidence directory")?;
        Ok(())
    }
}

fn directory_identity(metadata: &fs::Metadata) -> Result<DirectoryIdentity> {
    if !metadata.file_type().is_dir() {
        bail!("evidence directory identity no longer names a directory");
    }
    Ok(DirectoryIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode(),
    })
}

trait RecorderDriver {
    fn poll(&mut self, timeout: Duration) -> Result<usize>;
    fn finish_run(
        &mut self,
        cgroup_id: u64,
        epoch: u64,
        timeout: Duration,
        producer_barrier_complete: bool,
    ) -> Result<SystemEffectHealth>;
    fn unregister_run(&mut self, cgroup_id: u64, epoch: u64) -> Result<()>;
}

impl RecorderDriver for SystemEffectRecorder {
    fn poll(&mut self, timeout: Duration) -> Result<usize> {
        SystemEffectRecorder::poll(self, timeout)
    }

    fn finish_run(
        &mut self,
        cgroup_id: u64,
        epoch: u64,
        timeout: Duration,
        producer_barrier_complete: bool,
    ) -> Result<SystemEffectHealth> {
        SystemEffectRecorder::finish_run(self, cgroup_id, epoch, timeout, producer_barrier_complete)
    }

    fn unregister_run(&mut self, cgroup_id: u64, epoch: u64) -> Result<()> {
        SystemEffectRecorder::unregister_run(self, cgroup_id, epoch)
    }
}

trait CgroupBoundary {
    fn verify_start(&self, expected_id: u64) -> Result<()>;
    fn verify_finish(&self, expected_id: u64) -> Result<()>;
}

impl CgroupBoundary for ManagedCgroup {
    fn verify_start(&self, expected_id: u64) -> Result<()> {
        self.verify_identity(expected_id)?;
        self.verify_leaf_seal()
    }

    fn verify_finish(&self, expected_id: u64) -> Result<()> {
        self.verify_empty_frozen(expected_id)
    }
}

pub fn serve(request: ServeRequest) -> Result<()> {
    if request.drain_timeout_ms == 0 || request.drain_timeout_ms > 300_000 {
        bail!("effects supervisor drain timeout must be in 1..=300000 ms");
    }
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin);
    let start: StartMessage = read_json_line(&mut reader)?;
    start.validate()?;
    let started_unix_ns = environment::now_unix_ns();
    let kernel_release = environment::kernel_release()?;
    let boot_id = environment::boot_id()?;
    let evidence = EvidenceDirectory::open_empty_private(Path::new(&start.evidence_directory))?;
    let cgroup = ManagedCgroup::open_existing(Path::new(&start.binding.cgroup_path))
        .context("open Allox-owned effects cgroup")?;
    cgroup.verify_start(start.binding.cgroup_id)?;

    let entries = describe_policy(start.binding.profile).context("describe supervisor policy")?;
    let expected_policy_sha256 =
        policy_sha256(start.binding.profile).context("hash supervisor policy")?;
    let policy = PolicyArtifact {
        schema_version: EFFECT_EVENT_SCHEMA_VERSION,
        profile: start.binding.profile,
        policy_sha256: expected_policy_sha256.clone(),
        entries,
    };
    let mut recorder = SystemEffectRecorder::open(
        &request.recorder_object,
        &start.binding.expected_recorder_sha256,
        evidence.path(),
        &start.binding.run_id,
        &boot_id,
        start.binding.profile,
        FileObjectResolutionMode::UserInput,
    )
    .context("load effects supervisor recorder")?;
    if recorder.object_sha256() != start.binding.expected_recorder_sha256
        || recorder.profile() != start.binding.profile
        || recorder.policy_sha256() != expected_policy_sha256
    {
        bail!("loaded recorder is not exactly bound to START policy");
    }
    evidence.create_json(POLICY_NAME, &policy, MAX_SMALL_JSON_BYTES)?;
    recorder
        .register_run(start.binding.cgroup_id, start.binding.run_epoch)
        .context("register Allox effects run before READY")?;
    cgroup.verify_start(start.binding.cgroup_id)?;
    evidence.verify_identity()?;

    let ready = start.ready()?;
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout);
    serde_json::to_writer(&mut writer, &ready).context("encode supervisor READY")?;
    writer.write_all(b"\n")?;
    writer.flush().context("flush supervisor READY")?;

    let finish = wait_for_finish(reader, &mut recorder)?;
    finish.validate_against(&start)?;
    cgroup.verify_finish(start.binding.cgroup_id)?;
    evidence.verify_identity()?;
    let health = finish_engine(
        &start,
        &finish,
        &cgroup,
        &mut recorder,
        Duration::from_millis(request.drain_timeout_ms),
    )?;
    evidence.create_json(HEALTH_NAME, &health, MAX_SMALL_JSON_BYTES)?;
    let loaded_object_sha256 = recorder.object_sha256().to_owned();
    recorder
        .unregister_run(start.binding.cgroup_id, start.binding.run_epoch)
        .context("unregister finalized Allox effects run")?;
    drop(recorder);

    let artifacts = collect_artifacts(&evidence)?;
    let finalized_unix_ns = environment::now_unix_ns().max(started_unix_ns);
    let manifest = SupervisorManifest {
        schema_version: EFFECT_EVENT_SCHEMA_VERSION,
        evidence_kind: EVIDENCE_KIND.to_owned(),
        supervisor_protocol: PROTOCOL.to_owned(),
        supervisor_protocol_version: PROTOCOL_VERSION,
        binding: start.binding.clone(),
        evidence_directory: start.evidence_directory.clone(),
        outcome: finish.outcome,
        quiescence: finish.quiescence.clone(),
        started_unix_ns,
        finalized_unix_ns,
        kernel_release,
        boot_id,
        observer_version: env!("CARGO_PKG_VERSION").to_owned(),
        source_commit: option_env!("BPF_OBSERVER_SOURCE_COMMIT").map(str::to_owned),
        recorder: RecorderBinding {
            expected_object_sha256: start.binding.expected_recorder_sha256.clone(),
            loaded_object_sha256,
            object_resolution_mode: FileObjectResolutionMode::UserInput,
            policy_sha256: expected_policy_sha256,
            policy_artifact: POLICY_NAME.to_owned(),
        },
        attribution_contract: AttributionContract::direct_v1(),
        boundary: BoundaryEvidence {
            cgroup_identity_verified_before_ready: true,
            cgroup_leaf_seal_verified_before_ready: true,
            cgroup_identity_verified_after_finish: true,
            cgroup_empty_frozen_verified_after_finish: true,
            evidence_directory_private_and_anchored: true,
        },
        transport_status: health.transport_status,
        health_artifact: HEALTH_NAME.to_owned(),
        coverage: supervisor_coverage(start.binding.profile),
        artifacts,
        notes: vec![
            "operation events are history, not proof of durable final system state".to_owned(),
            "exact cgroup attribution identifies the direct syscall caller; delegated causality is not established".to_owned(),
            "Allox, not this sidecar, owns workload launch, termination, and cgroup deletion".to_owned(),
        ],
    };
    evidence.create_json(MANIFEST_NAME, &manifest, MAX_MANIFEST_BYTES)?;
    cgroup.verify_finish(start.binding.cgroup_id)?;
    evidence.verify_identity()?;

    let verification = verify_finalized(&evidence, &start, &finish, &manifest, &health)?;
    cgroup.verify_finish(start.binding.cgroup_id)?;
    let result = FinalizedResult {
        evidence_status: "COMPLETE".to_owned(),
        verification_status: "VERIFIED".to_owned(),
        manifest_path: MANIFEST_NAME.to_owned(),
        manifest_sha256: verification.manifest_sha256,
    };
    let finalized = finish.finalized(&start, &result)?;
    serde_json::to_writer(&mut writer, &finalized).context("encode supervisor FINALIZED")?;
    writer.write_all(b"\n")?;
    writer.flush().context("flush supervisor FINALIZED")?;
    Ok(())
}

fn wait_for_finish<R: BufRead + Send + 'static>(
    mut reader: R,
    recorder: &mut impl RecorderDriver,
) -> Result<FinishMessage> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = read_json_line(&mut reader);
        let _ = sender.send(result);
    });
    loop {
        match receiver.try_recv() {
            Ok(result) => return result,
            Err(TryRecvError::Disconnected) => {
                bail!("effects supervisor FINISH reader terminated without a message")
            }
            Err(TryRecvError::Empty) => {
                recorder
                    .poll(POLL_INTERVAL)
                    .context("poll effects while waiting for FINISH")?;
            }
        }
    }
}

fn finish_engine(
    start: &StartMessage,
    finish: &FinishMessage,
    cgroup: &impl CgroupBoundary,
    recorder: &mut impl RecorderDriver,
    drain_timeout: Duration,
) -> Result<SystemEffectHealth> {
    finish.validate_against(start)?;
    cgroup.verify_finish(start.binding.cgroup_id)?;
    let health = recorder
        .finish_run(
            start.binding.cgroup_id,
            start.binding.run_epoch,
            drain_timeout,
            true,
        )
        .context("drain Allox effects run")?;
    if !health.drain_completed
        || !health.producer_barrier_complete
        || !health.wal_durable
        || health.transport_status != TransportStatus::Complete
    {
        bail!(
            "effects supervisor refuses FINALIZED without COMPLETE durable transport: {:?}",
            health.transport_status
        );
    }
    cgroup.verify_finish(start.binding.cgroup_id)?;
    Ok(health)
}

fn supervisor_coverage(profile: PolicyProfile) -> Coverage {
    Coverage {
        attribution_scope: "DIRECT_SYSCALL_CALLERS_IN_EXACT_CGROUP_V2_ID".to_owned(),
        delegated_causality: "NOT_ESTABLISHED".to_owned(),
        event_semantics: "OPERATION_ATTEMPT_AND_RETURN_NOT_DURABLE_STATE_DIFF".to_owned(),
        operation_events_are_state_diff: false,
        final_system_state_confirmed: false,
        coverage_status: "PARTIAL".to_owned(),
        gaps: coverage_gaps(profile),
    }
}

#[derive(Debug)]
struct VerificationResult {
    manifest_sha256: String,
}

fn collect_artifacts(evidence: &EvidenceDirectory) -> Result<BTreeMap<String, ArtifactDigest>> {
    evidence.verify_identity()?;
    let mut artifacts = BTreeMap::new();
    for name in ARTIFACT_NAMES {
        artifacts.insert(name.to_owned(), measure_artifact(evidence.path(), name)?);
    }
    let names = directory_entries(evidence.path())?;
    let expected = ARTIFACT_NAMES
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    if names != expected {
        bail!("pre-manifest supervisor evidence set is not closed");
    }
    evidence.verify_identity()?;
    Ok(artifacts)
}

fn measure_artifact(directory: &Path, name: &str) -> Result<ArtifactDigest> {
    let limit = artifact_limit(name)?;
    let path = directory.join(name);
    let mut file = open_artifact(directory, name, limit, None)?;
    let before = file.metadata()?;
    let mut hasher = Sha256::new();
    let mut size_bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("hash supervisor artifact {name}"))?;
        if count == 0 {
            break;
        }
        size_bytes = size_bytes
            .checked_add(count as u64)
            .context("supervisor artifact byte count overflow")?;
        if size_bytes > limit {
            bail!("supervisor artifact {name} grew beyond its verification limit");
        }
        hasher.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    if size_bytes != before.len() || file_state(&before) != file_state(&after) {
        bail!("supervisor artifact {name} changed while it was hashed");
    }
    let reopened = open_artifact(directory, name, limit, Some(size_bytes))?;
    if file_state(&reopened.metadata()?) != file_state(&after) {
        bail!(
            "supervisor artifact {} was replaced while it was hashed",
            path.display()
        );
    }
    Ok(ArtifactDigest {
        sha256: format!("{:x}", hasher.finalize()),
        size_bytes,
    })
}

fn artifact_limit(name: &str) -> Result<u64> {
    match name {
        POLICY_NAME | HEALTH_NAME => Ok(MAX_SMALL_JSON_BYTES),
        WAL_NAME => Ok(MAX_WAL_BYTES),
        JSONL_NAME => Ok(MAX_JSONL_BYTES),
        MANIFEST_NAME => Ok(MAX_MANIFEST_BYTES),
        _ => bail!("unknown supervisor artifact {name:?}"),
    }
}

fn validate_artifact_name(name: &str) -> Result<()> {
    if !matches!(
        name,
        MANIFEST_NAME | POLICY_NAME | HEALTH_NAME | WAL_NAME | JSONL_NAME
    ) {
        bail!("unsupported supervisor artifact name {name:?}");
    }
    Ok(())
}

fn directory_entries(directory: &Path) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(directory)
        .with_context(|| format!("enumerate supervisor evidence {}", directory.display()))?
    {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("supervisor evidence contains a non-UTF-8 entry"))?;
        if !names.insert(name.clone()) {
            bail!("supervisor evidence contains duplicate entry {name:?}");
        }
        if names.len() > ARTIFACT_NAMES.len() + 1 {
            bail!("supervisor evidence contains more than the closed artifact set");
        }
    }
    Ok(names)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileState {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

fn file_state(metadata: &fs::Metadata) -> FileState {
    FileState {
        dev: metadata.dev(),
        ino: metadata.ino(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        nlink: metadata.nlink(),
        len: metadata.len(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    }
}

fn open_artifact(
    directory: &Path,
    name: &str,
    limit: u64,
    expected_size: Option<u64>,
) -> Result<File> {
    validate_artifact_name(name)?;
    let path = directory.join(name);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open supervisor artifact {name}"))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect supervisor artifact {name}"))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.len() > limit
        || matches!(expected_size, Some(size) if metadata.len() != size)
    {
        bail!("supervisor artifact {name} violates type, owner, mode, link, or size policy");
    }
    Ok(file)
}

fn reopen_matches_state(directory: &Path, name: &str, expected: FileState) -> Result<()> {
    let file = open_artifact(directory, name, artifact_limit(name)?, Some(expected.len))?;
    if file_state(&file.metadata()?) != expected {
        bail!("supervisor artifact {name} pathname changed during verification");
    }
    Ok(())
}

fn read_stable_file(directory: &Path, name: &str, limit: u64) -> Result<(Vec<u8>, FileState)> {
    let mut file = open_artifact(directory, name, limit, None)?;
    let before = file
        .metadata()
        .with_context(|| format!("inspect supervisor artifact {name}"))?;
    let capacity = usize::try_from(before.len()).context("artifact size is not representable")?;
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read supervisor artifact {name}"))?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len() || file_state(&before) != file_state(&after) {
        bail!("supervisor artifact {name} changed while it was read");
    }
    let state = file_state(&after);
    reopen_matches_state(directory, name, state)?;
    Ok((bytes, state))
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be a lowercase 64-character SHA-256 digest");
    }
    Ok(())
}

struct VerifiedArtifactReader {
    directory: PathBuf,
    name: String,
    file: File,
    before: fs::Metadata,
    expected: ArtifactDigest,
    hasher: Sha256,
    bytes_read: u64,
}

impl VerifiedArtifactReader {
    fn open(directory: &Path, name: &str, expected: &ArtifactDigest, limit: u64) -> Result<Self> {
        validate_sha256(&expected.sha256, &format!("artifact {name}"))?;
        if expected.size_bytes > limit {
            bail!("supervisor artifact {name} exceeds its verification limit");
        }
        let file = open_artifact(directory, name, limit, Some(expected.size_bytes))?;
        let before = file.metadata()?;
        Ok(Self {
            directory: directory.to_path_buf(),
            name: name.to_owned(),
            file,
            before,
            expected: expected.clone(),
            hasher: Sha256::new(),
            bytes_read: 0,
        })
    }

    fn finish(mut self) -> Result<FileState> {
        let mut buffer = [0u8; 64 * 1024];
        while self.read(&mut buffer)? != 0 {}
        let after = self.file.metadata()?;
        if file_state(&self.before) != file_state(&after) {
            bail!("supervisor artifact {} changed while read", self.name);
        }
        if self.bytes_read != self.expected.size_bytes {
            bail!(
                "supervisor artifact {} byte count differs from manifest",
                self.name
            );
        }
        if format!("{:x}", self.hasher.finalize()) != self.expected.sha256 {
            bail!(
                "supervisor artifact {} SHA-256 differs from manifest",
                self.name
            );
        }
        let state = file_state(&after);
        reopen_matches_state(&self.directory, &self.name, state)?;
        Ok(state)
    }
}

impl Read for VerifiedArtifactReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.file.read(output)?;
        if count != 0 {
            self.bytes_read = self
                .bytes_read
                .checked_add(count as u64)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "byte count overflow"))?;
            if self.bytes_read > self.expected.size_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "artifact grew beyond manifest size",
                ));
            }
            self.hasher.update(&output[..count]);
        }
        Ok(count)
    }
}

fn read_verified_json<T: DeserializeOwned>(
    directory: &Path,
    name: &str,
    expected: &ArtifactDigest,
    limit: u64,
) -> Result<(T, FileState)> {
    let mut artifact = VerifiedArtifactReader::open(directory, name, expected, limit)?;
    let value = {
        let reader = BufReader::new(&mut artifact);
        serde_json::from_reader(reader)
            .with_context(|| format!("decode supervisor artifact {name}"))?
    };
    let state = artifact.finish()?;
    Ok((value, state))
}

fn verify_finalized(
    evidence: &EvidenceDirectory,
    start: &StartMessage,
    finish: &FinishMessage,
    expected_manifest: &SupervisorManifest,
    expected_health: &SystemEffectHealth,
) -> Result<VerificationResult> {
    evidence.verify_identity()?;
    let expected_names = ARTIFACT_NAMES
        .iter()
        .chain(std::iter::once(&MANIFEST_NAME))
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    if directory_entries(evidence.path())? != expected_names {
        bail!("finalized supervisor evidence directory is not the closed v1 set");
    }

    let (manifest_bytes, manifest_state) =
        read_stable_file(evidence.path(), MANIFEST_NAME, MAX_MANIFEST_BYTES)?;
    let mut expected_manifest_bytes =
        serde_json::to_vec(expected_manifest).context("encode expected supervisor manifest")?;
    expected_manifest_bytes.push(10);
    if manifest_bytes != expected_manifest_bytes {
        bail!("supervisor manifest differs from the sidecar-created commit");
    }
    let manifest: SupervisorManifest =
        serde_json::from_slice(&manifest_bytes).context("decode supervisor manifest")?;
    verify_manifest(&manifest, evidence, start, finish)?;

    if manifest.artifacts.keys().cloned().collect::<BTreeSet<_>>()
        != ARTIFACT_NAMES
            .iter()
            .map(|name| (*name).to_owned())
            .collect()
    {
        bail!("supervisor manifest does not bind the closed artifact set");
    }
    let mut verified_states = BTreeMap::new();
    let (policy, policy_state): (PolicyArtifact, _) = read_verified_json(
        evidence.path(),
        POLICY_NAME,
        manifest
            .artifacts
            .get(POLICY_NAME)
            .context("manifest omitted policy")?,
        MAX_SMALL_JSON_BYTES,
    )?;
    verified_states.insert(POLICY_NAME.to_owned(), policy_state);
    verify_policy(&manifest, &policy)?;
    let (health, health_state): (SystemEffectHealth, _) = read_verified_json(
        evidence.path(),
        HEALTH_NAME,
        manifest
            .artifacts
            .get(HEALTH_NAME)
            .context("manifest omitted health")?,
        MAX_SMALL_JSON_BYTES,
    )?;
    verified_states.insert(HEALTH_NAME.to_owned(), health_state);
    if &health != expected_health {
        bail!("supervisor health differs from the recorder result used to commit the run");
    }
    verify_health(&manifest, &health)?;
    let (wal_state, jsonl_state) = verify_event_streams(
        evidence.path(),
        &manifest.binding,
        &health,
        &policy.entries,
        &manifest.artifacts,
    )?;
    verified_states.insert(WAL_NAME.to_owned(), wal_state);
    verified_states.insert(JSONL_NAME.to_owned(), jsonl_state);
    for name in ARTIFACT_NAMES {
        let state = verified_states
            .get(name)
            .context("not every committed supervisor artifact was verified")?;
        reopen_matches_state(evidence.path(), name, *state)?;
    }
    let (manifest_after, state_after) =
        read_stable_file(evidence.path(), MANIFEST_NAME, MAX_MANIFEST_BYTES)?;
    if manifest_after != manifest_bytes || state_after != manifest_state {
        bail!("supervisor manifest changed during verification");
    }
    if directory_entries(evidence.path())? != expected_names {
        bail!("supervisor evidence directory changed during verification");
    }
    evidence.verify_identity()?;
    Ok(VerificationResult {
        manifest_sha256: format!("{:x}", Sha256::digest(&manifest_bytes)),
    })
}

fn verify_manifest(
    manifest: &SupervisorManifest,
    evidence: &EvidenceDirectory,
    start: &StartMessage,
    finish: &FinishMessage,
) -> Result<()> {
    if manifest.schema_version != EFFECT_EVENT_SCHEMA_VERSION
        || manifest.evidence_kind != EVIDENCE_KIND
        || manifest.supervisor_protocol != PROTOCOL
        || manifest.supervisor_protocol_version != PROTOCOL_VERSION
        || manifest.binding != start.binding
        || manifest.evidence_directory != start.evidence_directory
        || Path::new(&manifest.evidence_directory) != evidence.requested_path()
        || manifest.outcome != finish.outcome
        || manifest.quiescence != finish.quiescence
        || manifest.started_unix_ns == 0
        || manifest.finalized_unix_ns < manifest.started_unix_ns
        || manifest.kernel_release.is_empty()
        || manifest.boot_id.is_empty()
        || manifest.kernel_release != environment::kernel_release()?
        || manifest.boot_id != environment::boot_id()?
        || manifest.observer_version != env!("CARGO_PKG_VERSION")
        || manifest.source_commit != option_env!("BPF_OBSERVER_SOURCE_COMMIT").map(str::to_owned)
        || manifest.transport_status != TransportStatus::Complete
        || manifest.health_artifact != HEALTH_NAME
    {
        bail!("supervisor manifest is not exactly bound to START/FINISH and COMPLETE transport");
    }
    if manifest
        .source_commit
        .as_deref()
        .map_or(false, |value| value.is_empty() || value.contains('\0'))
        || manifest.kernel_release.contains('\0')
        || manifest.boot_id.contains('\0')
    {
        bail!("supervisor manifest contains invalid environment identity");
    }
    let expected_policy = policy_sha256(start.binding.profile)?;
    manifest.attribution_contract.validate()?;
    if manifest.attribution_contract != AttributionContract::direct_v1() {
        bail!("supervisor manifest has an unsupported attribution contract");
    }
    if manifest.recorder.expected_object_sha256 != start.binding.expected_recorder_sha256
        || manifest.recorder.loaded_object_sha256 != start.binding.expected_recorder_sha256
        || manifest.recorder.object_resolution_mode != FileObjectResolutionMode::UserInput
        || manifest.recorder.policy_sha256 != expected_policy
        || manifest.recorder.policy_artifact != POLICY_NAME
    {
        bail!("supervisor manifest recorder binding differs from START or compiled policy");
    }
    if manifest.boundary
        != (BoundaryEvidence {
            cgroup_identity_verified_before_ready: true,
            cgroup_leaf_seal_verified_before_ready: true,
            cgroup_identity_verified_after_finish: true,
            cgroup_empty_frozen_verified_after_finish: true,
            evidence_directory_private_and_anchored: true,
        })
    {
        bail!("supervisor manifest lacks the complete producer boundary");
    }
    if manifest.coverage != supervisor_coverage(start.binding.profile)
        || manifest.notes.len() != 3
        || !manifest.notes.iter().any(|note| note.contains("not proof"))
        || manifest.notes.iter().any(|note| note.contains('\0'))
    {
        bail!("supervisor manifest overstates or ambiguously encodes coverage");
    }
    Ok(())
}

fn verify_policy(manifest: &SupervisorManifest, policy: &PolicyArtifact) -> Result<()> {
    let expected_entries = describe_policy(manifest.binding.profile)?;
    let expected_sha256 = policy_sha256(manifest.binding.profile)?;
    if policy.schema_version != EFFECT_EVENT_SCHEMA_VERSION
        || policy.profile != manifest.binding.profile
        || policy.policy_sha256 != expected_sha256
        || policy.policy_sha256 != manifest.recorder.policy_sha256
        || policy.entries != expected_entries
        || policy.entries.is_empty()
    {
        bail!("supervisor policy artifact does not match the compiled frozen policy");
    }
    Ok(())
}

fn verify_health(manifest: &SupervisorManifest, health: &SystemEffectHealth) -> Result<()> {
    if health.schema_version != EFFECT_EVENT_SCHEMA_VERSION
        || health.run_id != manifest.binding.run_id
        || health.run_epoch != manifest.binding.run_epoch
        || health.cgroup_id != manifest.binding.cgroup_id
        || health.profile != manifest.binding.profile
        || health.object_resolution_mode != FileObjectResolutionMode::UserInput
        || health.transport_status != TransportStatus::Complete
        || health.coverage_status != CoverageStatus::Partial
        || health.object_resolution_status != ObjectResolutionStatus::Partial
        || !health.producer_barrier_complete
        || !health.drain_completed
        || !health.wal_durable
        || !health.reasons.is_empty()
    {
        bail!("supervisor health is not bound COMPLETE transport evidence");
    }
    if health.operation_attempted == 0
        || health.operation_attempted != health.operation_completed
        || health
            .operation_attempted
            .checked_add(health.operation_completed)
            != Some(health.event_attempted)
        || health.event_published.checked_add(health.event_dropped) != Some(health.event_attempted)
        || health.event_published != health.events_persisted
        || health.event_dropped != 0
        || health.pending_insert_failed != 0
        || health.pending_missing != 0
        || health.pending_remaining != 0
        || health.userspace_failures != 0
        || health.fatal_kernel_flags != 0
        || health.object_resolution_attempted != 0
        || health.object_resolution_resolved != 0
        || health.object_resolution_unresolved != 0
        || health.object_resolution_failed_syscalls != 0
        || health.object_join_missing != 0
        || health.object_join_ambiguous != 0
        || health.object_read_failed != 0
        || health.object_delete_failed != 0
        || health.object_path_unavailable != 0
        || health.object_pending_remaining != 0
        || health.events_persisted == 0
        || health.events_persisted > MAX_EVENTS
    {
        bail!("supervisor health violates lossless accounting invariants");
    }
    if health.poll_calls == 0
        || health.callback_queue_capacity != 4_096
        || health.callback_queue_high_water == 0
        || health.maximum_events_per_poll == 0
        || health.callback_queue_high_water > health.callback_queue_capacity
        || health.maximum_events_per_poll > health.callback_queue_high_water
        || health.capture_read_failures > health.operation_attempted
        || health.capture_truncations > health.operation_attempted
        || health.capture_invalid_lengths > health.operation_attempted
        || health.coverage_gaps != coverage_gaps(manifest.binding.profile)
    {
        bail!("supervisor health has invalid resource, capture, or coverage counters");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AttemptIdentity {
    pid_tgid: u64,
    syscall_nr: i32,
    domain: u16,
    operation: u32,
    ktime_ns: u64,
    args: [u64; 6],
}

fn verify_event_streams(
    directory: &Path,
    binding: &Binding,
    health: &SystemEffectHealth,
    policies: &[PolicyDescription],
    artifacts: &BTreeMap<String, ArtifactDigest>,
) -> Result<(FileState, FileState)> {
    let mut wal = VerifiedArtifactReader::open(
        directory,
        WAL_NAME,
        artifacts.get(WAL_NAME).context("manifest omitted WAL")?,
        MAX_WAL_BYTES,
    )?;
    let mut jsonl_artifact = VerifiedArtifactReader::open(
        directory,
        JSONL_NAME,
        artifacts
            .get(JSONL_NAME)
            .context("manifest omitted JSONL")?,
        MAX_JSONL_BYTES,
    )?;
    let mut jsonl = BufReader::new(&mut jsonl_artifact);
    let policies = policies
        .iter()
        .map(|policy| (policy.syscall_nr, policy))
        .collect::<HashMap<_, _>>();
    if policies.is_empty() {
        bail!("supervisor event policy is empty");
    }

    let total = usize::try_from(health.events_persisted)
        .context("supervisor event count is not representable")?;
    let mut seen_sequences = vec![false; total];
    let mut attempts = HashMap::<u64, AttemptIdentity>::new();
    let mut attempted = 0u64;
    let mut completed = 0u64;
    let mut capture_read_failures = 0u64;
    let mut capture_truncations = 0u64;
    let mut capture_invalid_lengths = 0u64;
    let mut count = 0u64;

    loop {
        let raw = read_wal_frame(&mut wal)?;
        let json = read_effect_json_line(&mut jsonl)?;
        let (raw, json) = match (raw, json) {
            (None, None) => break,
            (Some(_), None) | (None, Some(_)) => {
                bail!("supervisor WAL/JSONL event count mismatch")
            }
            (Some(raw), Some(json)) => (raw, json),
        };
        count = count
            .checked_add(1)
            .context("supervisor event count overflow")?;
        if count > MAX_EVENTS || count > health.events_persisted {
            bail!("supervisor event stream exceeds its bound health count");
        }
        if raw.run_epoch != binding.run_epoch || raw.cgroup_id != binding.cgroup_id {
            bail!("supervisor WAL event is not bound to START");
        }
        let sequence_index = raw
            .event_seq
            .checked_sub(1)
            .and_then(|sequence| usize::try_from(sequence).ok())
            .filter(|index| *index < seen_sequences.len())
            .context("supervisor event sequence is outside the complete range")?;
        if std::mem::replace(&mut seen_sequences[sequence_index], true) {
            bail!("supervisor event stream contains a duplicate sequence");
        }
        let policy = policies
            .get(&raw.syscall_nr)
            .context("supervisor event syscall is absent from the frozen policy")?;
        validate_event_policy(&raw, policy)?;
        validate_json_event(&raw, &json, binding, policy)?;
        if raw.flags & FATAL_FLAGS != 0 {
            bail!("COMPLETE supervisor stream contains a fatal correlation flag");
        }
        if raw.flags & (FLAG_PAYLOAD1_READ_FAILED | FLAG_PAYLOAD2_READ_FAILED) != 0 {
            capture_read_failures += 1;
        }
        if raw.flags & (FLAG_PAYLOAD1_TRUNCATED | FLAG_PAYLOAD2_TRUNCATED) != 0 {
            capture_truncations += 1;
        }
        if raw.flags & (FLAG_PAYLOAD1_INVALID_LENGTH | FLAG_PAYLOAD2_INVALID_LENGTH) != 0 {
            capture_invalid_lengths += 1;
        }
        match raw.kind {
            EVENT_ATTEMPT => {
                attempted += 1;
                let identity = AttemptIdentity {
                    pid_tgid: raw.pid_tgid,
                    syscall_nr: raw.syscall_nr,
                    domain: raw.domain,
                    operation: raw.operation,
                    ktime_ns: raw.ktime_ns,
                    args: raw.args,
                };
                if attempts.insert(raw.event_seq, identity).is_some() {
                    bail!("supervisor stream duplicated an operation attempt");
                }
            }
            EVENT_RESULT => {
                completed += 1;
                let attempt = attempts
                    .remove(&raw.related_attempt_seq)
                    .context("supervisor result has no preceding operation attempt")?;
                if attempt.pid_tgid != raw.pid_tgid
                    || attempt.syscall_nr != raw.syscall_nr
                    || attempt.domain != raw.domain
                    || attempt.operation != raw.operation
                    || attempt.args != raw.args
                    || raw.event_seq <= raw.related_attempt_seq
                    || raw.ktime_ns < attempt.ktime_ns
                {
                    bail!("supervisor operation result does not match its attempt");
                }
            }
            _ => bail!("supervisor WAL contains an unsupported event kind"),
        }
    }
    if count != health.events_persisted
        || attempted != health.operation_attempted
        || completed != health.operation_completed
        || !attempts.is_empty()
        || seen_sequences.iter().any(|seen| !seen)
        || capture_read_failures != health.capture_read_failures
        || capture_truncations != health.capture_truncations
        || capture_invalid_lengths != health.capture_invalid_lengths
    {
        bail!("supervisor WAL/JSONL replay does not reproduce health accounting");
    }
    drop(jsonl);
    let wal_state = wal.finish()?;
    let jsonl_state = jsonl_artifact.finish()?;
    Ok((wal_state, jsonl_state))
}

fn validate_event_policy(raw: &KernelEvent, policy: &PolicyDescription) -> Result<()> {
    if raw.domain != policy.domain as u16 || raw.operation != policy.operation as u32 {
        bail!("supervisor WAL event disagrees with frozen policy identity");
    }
    if raw.kind != EVENT_ATTEMPT {
        return Ok(());
    }
    let mut expected_kinds = [PAYLOAD_NONE; 2];
    let mut expected_indices = [0u8; 2];
    if policy.capture.len() > expected_kinds.len() {
        bail!("supervisor policy has more captures than the recorder ABI supports");
    }
    for (slot, capture) in policy.capture.iter().enumerate() {
        expected_kinds[slot] = match capture.kind.as_str() {
            "USER_SUPPLIED_STRING" => PAYLOAD_USER_STRING,
            "RAW_USER_SOCKADDR" => PAYLOAD_SOCKADDR,
            _ => bail!("supervisor policy has an unknown capture kind"),
        };
        expected_indices[slot] = capture.argument_index;
    }
    if raw.payload_kinds != expected_kinds || raw.payload_arg_indices != expected_indices {
        bail!("supervisor WAL capture metadata disagrees with frozen policy");
    }
    if let Some(filter) = policy.kernel_filter.as_ref() {
        if filter.kind != "ARG_ANY_BITS" || filter.mask == 0 {
            bail!("supervisor policy has an unsupported kernel filter");
        }
        let argument = raw
            .args
            .get(usize::from(filter.argument_index))
            .context("supervisor policy filter argument is outside syscall ABI")?;
        if argument & filter.mask == 0 {
            bail!("supervisor WAL attempt does not satisfy its frozen policy filter");
        }
    }
    Ok(())
}

fn validate_json_event(
    raw: &KernelEvent,
    json: &SystemEffectEvent,
    binding: &Binding,
    policy: &PolicyDescription,
) -> Result<()> {
    if raw.file_object.is_some() {
        bail!("USER_INPUT supervisor v1 WAL unexpectedly contains kernel-object evidence");
    }
    json.validate_object_resolution()
        .context("validate supervisor object-resolution evidence")?;
    json.validate_attribution()
        .context("validate supervisor direct-attribution evidence")?;
    let expected_kind = match raw.kind {
        EVENT_ATTEMPT => EventKind::OperationAttempt,
        EVENT_RESULT => EventKind::OperationResult,
        _ => bail!("unsupported supervisor event kind"),
    };
    let expected_return = (raw.kind == EVENT_RESULT).then_some(raw.return_value);
    let expected_status = expected_return.map(|value| classify_result(policy.operation, value));
    if json.schema_version != EFFECT_EVENT_SCHEMA_VERSION
        || json.run_id != binding.run_id
        || json.run_epoch != raw.run_epoch
        || json.event_seq != raw.event_seq
        || json.related_attempt_seq != raw.related_attempt_seq
        || json.kind != expected_kind
        || json.domain as u16 != raw.domain
        || json.operation as u32 != raw.operation
        || json.syscall_nr != raw.syscall_nr
        || json.syscall_name != policy.syscall_name
        || json.ktime_ns != raw.ktime_ns
        || json.cgroup_id != raw.cgroup_id
        || json.pid != raw.pid_tgid as u32
        || json.tgid != (raw.pid_tgid >> 32) as u32
        || json.comm != nul_terminated_lossy(&raw.comm)
        || json.raw_arguments != raw.args
        || json.return_value != expected_return
        || json.result_status != expected_status
        || json.flags != raw.flags
        || json.semantics != EVENT_SEMANTICS
        || json.captures != expected_captures(raw)
        || json.object_resolution != expected_object_resolution(raw)
        || json.attribution != expected_attribution(raw)
    {
        bail!("supervisor JSONL event does not derive exactly from its WAL record");
    }
    Ok(())
}

fn expected_object_resolution(raw: &KernelEvent) -> ObjectResolution {
    let captures = expected_captures(raw);
    let objects = if raw.kind == EVENT_ATTEMPT {
        captures
            .iter()
            .enumerate()
            .filter(|(_, capture)| {
                matches!(
                    capture.status,
                    CaptureStatus::Captured | CaptureStatus::Truncated
                )
            })
            .map(|(slot, capture)| ObjectReference {
                slot: slot as u8,
                role: ObjectRole::SyscallArgument,
                identity: ObjectIdentity::UserInputOnly {
                    argument_index: capture.argument_index,
                    source: capture.source,
                    status: capture.status,
                },
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let (quality, authority) = if objects.is_empty() {
        (
            ObjectResolutionQuality::Unresolved,
            ObjectResolutionAuthority::None,
        )
    } else {
        (
            ObjectResolutionQuality::UserInputOnly,
            ObjectResolutionAuthority::SyscallEntryUserMemory,
        )
    };
    ObjectResolution {
        protocol_version: OBJECT_IDENTITY_PROTOCOL_VERSION,
        source_event_seq: raw.event_seq,
        operation_attempt_seq: if raw.kind == EVENT_ATTEMPT {
            raw.event_seq
        } else {
            raw.related_attempt_seq
        },
        quality,
        authority,
        objects,
    }
}

fn expected_attribution(raw: &KernelEvent) -> EffectAttribution {
    let contract = AttributionContract::direct_v1();
    EffectAttribution {
        protocol_version: contract.protocol_version,
        mode: contract.mode,
        authority: contract.authority,
        subject: contract.subject,
        component: contract.component,
        delegated_effects: contract.delegated_effects,
        causal_status: contract.causal_status,
        cgroup_match_mode: CgroupMatchMode::ExactCurrent,
        matched_scope_cgroup_id: raw.cgroup_id,
        leaf_cgroup_id_retained: true,
        cgroup_id_at_syscall_entry: raw.cgroup_id,
        source_event_seq: raw.event_seq,
        operation_attempt_seq: if raw.kind == EVENT_ATTEMPT {
            raw.event_seq
        } else {
            raw.related_attempt_seq
        },
    }
}

fn expected_captures(raw: &KernelEvent) -> Vec<CapturedArgument> {
    if raw.kind != EVENT_ATTEMPT {
        return Vec::new();
    }
    (0..2)
        .filter_map(|slot| expected_capture(raw, slot))
        .collect()
}

fn expected_capture(raw: &KernelEvent, slot: usize) -> Option<CapturedArgument> {
    let kind = raw.payload_kinds[slot];
    if kind == PAYLOAD_NONE {
        return None;
    }
    let (read_flag, truncated_flag, invalid_flag) = if slot == 0 {
        (
            FLAG_PAYLOAD1_READ_FAILED,
            FLAG_PAYLOAD1_TRUNCATED,
            FLAG_PAYLOAD1_INVALID_LENGTH,
        )
    } else {
        (
            FLAG_PAYLOAD2_READ_FAILED,
            FLAG_PAYLOAD2_TRUNCATED,
            FLAG_PAYLOAD2_INVALID_LENGTH,
        )
    };
    let read_failed = raw.flags & read_flag != 0;
    let truncated = raw.flags & truncated_flag != 0;
    let invalid_length = raw.flags & invalid_flag != 0;
    let available = !read_failed && !invalid_length;
    let length = usize::from(raw.payload_lens[slot]).min(CAPTURE_BYTES);
    let bytes = &raw.payloads[slot][..length];
    let (source, display) = match kind {
        PAYLOAD_USER_STRING => (
            CaptureSource::UserSuppliedString,
            available.then(|| nul_terminated_lossy(bytes)),
        ),
        PAYLOAD_SOCKADDR => (
            CaptureSource::RawUserSockaddr,
            available.then(|| format_sockaddr(bytes)),
        ),
        _ => unreachable!("KernelEvent decoder rejected unknown capture kinds"),
    };
    Some(CapturedArgument {
        argument_index: raw.payload_arg_indices[slot],
        source,
        status: if read_failed {
            CaptureStatus::ReadFailed
        } else if invalid_length {
            CaptureStatus::InvalidLength
        } else if truncated {
            CaptureStatus::Truncated
        } else {
            CaptureStatus::Captured
        },
        length: length as u16,
        display,
        raw_hex: available.then(|| hex(bytes)),
        authority: CAPTURE_AUTHORITY.to_owned(),
    })
}

fn classify_result(operation: EffectOperation, value: i64) -> ResultStatus {
    if value >= 0 {
        ResultStatus::ReturnedSuccess
    } else if matches!(value, -512 | -513 | -514 | -516) {
        ResultStatus::KernelRestart
    } else if operation == EffectOperation::SocketConnect
        && matches!(value, x if x == -(libc::EINPROGRESS as i64) || x == -(libc::EALREADY as i64))
    {
        ResultStatus::AsyncPending
    } else {
        ResultStatus::ReturnedError
    }
}

fn read_wal_frame(reader: &mut impl Read) -> Result<Option<KernelEvent>> {
    let mut length_bytes = [0u8; 4];
    if !read_exact_or_eof(reader, &mut length_bytes, "WAL frame length")? {
        return Ok(None);
    }
    let length = u32::from_le_bytes(length_bytes) as usize;
    if !matches!(
        length,
        WAL_COMPACT_EVENT_BYTES | WAL_FILE_OBJECT_EVENT_BYTES | WAL_FULL_EVENT_BYTES
    ) {
        bail!("unsupported supervisor WAL frame length {length}");
    }
    let mut payload = vec![0u8; length];
    read_exact_required(reader, &mut payload, "WAL frame payload")?;
    let mut checksum = [0u8; 4];
    read_exact_required(reader, &mut checksum, "WAL frame checksum")?;
    if crc32fast::hash(&payload) != u32::from_le_bytes(checksum) {
        bail!("supervisor WAL checksum mismatch");
    }
    KernelEvent::decode_le(&payload)
        .map(Some)
        .context("decode supervisor WAL event")
}

fn read_exact_or_eof(reader: &mut impl Read, output: &mut [u8], label: &str) -> Result<bool> {
    let mut offset = 0usize;
    while offset < output.len() {
        match reader.read(&mut output[offset..]) {
            Ok(0) if offset == 0 => return Ok(false),
            Ok(0) => bail!("supervisor {label} is truncated"),
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).with_context(|| format!("read supervisor {label}")),
        }
    }
    Ok(true)
}

fn read_exact_required(reader: &mut impl Read, output: &mut [u8], label: &str) -> Result<()> {
    if !read_exact_or_eof(reader, output, label)? {
        bail!("supervisor {label} is truncated");
    }
    Ok(())
}

fn read_effect_json_line(reader: &mut impl BufRead) -> Result<Option<SystemEffectEvent>> {
    let mut bytes = Vec::new();
    let count = reader
        .take(MAX_EVENT_JSON_BYTES + 1)
        .read_until(b'\n', &mut bytes)
        .context("read supervisor JSONL event")?;
    if count == 0 {
        return Ok(None);
    }
    if count as u64 > MAX_EVENT_JSON_BYTES || bytes.last() != Some(&b'\n') {
        bail!("supervisor JSONL event exceeds its bound or is truncated");
    }
    if bytes[..bytes.len() - 1]
        .iter()
        .all(|byte| byte.is_ascii_whitespace())
    {
        bail!("supervisor JSONL contains a blank line");
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .context("decode supervisor JSONL event")
}

fn nul_terminated_lossy(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    output
}

fn format_sockaddr(bytes: &[u8]) -> String {
    if bytes.len() < 2 {
        return format!("sockaddr:{}", hex(bytes));
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    match family as i32 {
        libc::AF_INET if bytes.len() >= 8 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let address = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            format!("{address}:{port}")
        }
        libc::AF_INET6 if bytes.len() >= 24 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[8..24]);
            let address = Ipv6Addr::from(octets);
            format!("[{address}]:{port}")
        }
        libc::AF_UNIX => format!("unix:{}", nul_terminated_lossy(&bytes[2..])),
        _ => format!("family={family}:{}", hex(&bytes[2..])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bpf_observer_system_effects::EffectDomain;
    use std::cell::Cell;
    use std::io::Cursor;
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create(mode: u32) -> Self {
            let nonce = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/effects-supervisor-tests")
                .join(format!("{}-{nonce}", std::process::id()));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let mut builder = fs::DirBuilder::new();
            builder.mode(mode).create(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            Self(fs::canonicalize(path).unwrap())
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn start() -> StartMessage {
        serde_json::from_value(serde_json::json!({
            "protocol": PROTOCOL,
            "version": PROTOCOL_VERSION,
            "type": "START",
            "binding": {
                "run_id": "0123456789abcdef0123456789abcdef",
                "run_epoch": 7,
                "cgroup_path": "/sys/fs/cgroup/allox/agents/a/sessions/s",
                "cgroup_id": 42,
                "profile": "balanced",
                "expected_recorder_sha256": "ab".repeat(32),
            },
            "evidence_directory": "/var/lib/allox/run/system-effects",
            "auth_challenge": "cd".repeat(32),
            "auth_capability": "ef".repeat(32),
        }))
        .unwrap()
    }

    fn finish(start: &StartMessage) -> FinishMessage {
        serde_json::from_value(serde_json::json!({
            "protocol": PROTOCOL,
            "version": PROTOCOL_VERSION,
            "type": "FINISH",
            "binding": start.binding,
            "auth_challenge": start.auth_challenge,
            "outcome": "completed",
            "quiescence": {
                "status": "QUIESCENT_WITHIN_CGROUP",
                "basis": "CGROUP_V2_EMPTY_FROZEN_VERIFIED",
                "cgroup_id": start.binding.cgroup_id,
            },
        }))
        .unwrap()
    }

    fn complete_health(start: &StartMessage) -> SystemEffectHealth {
        SystemEffectHealth {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            run_id: start.binding.run_id.clone(),
            run_epoch: start.binding.run_epoch,
            cgroup_id: start.binding.cgroup_id,
            profile: start.binding.profile,
            object_resolution_mode: FileObjectResolutionMode::UserInput,
            transport_status: TransportStatus::Complete,
            coverage_status: CoverageStatus::Partial,
            object_resolution_status: ObjectResolutionStatus::Partial,
            operation_attempted: 1,
            operation_completed: 1,
            event_attempted: 2,
            event_published: 2,
            event_dropped: 0,
            events_persisted: 2,
            pending_insert_failed: 0,
            pending_missing: 0,
            pending_remaining: 0,
            userspace_failures: 0,
            fatal_kernel_flags: 0,
            capture_read_failures: 0,
            capture_truncations: 0,
            capture_invalid_lengths: 0,
            object_resolution_attempted: 0,
            object_resolution_resolved: 0,
            object_resolution_unresolved: 0,
            object_resolution_failed_syscalls: 0,
            object_join_missing: 0,
            object_join_ambiguous: 0,
            object_read_failed: 0,
            object_delete_failed: 0,
            object_path_unavailable: 0,
            object_pending_remaining: 0,
            task_read_failed: 0,
            object_unsupported: 0,
            socket_state: None,
            producer_barrier_complete: true,
            drain_completed: true,
            wal_durable: true,
            poll_calls: 2,
            maximum_events_per_poll: 2,
            callback_queue_high_water: 2,
            callback_queue_capacity: 4_096,
            reasons: Vec::new(),
            coverage_gaps: coverage_gaps(start.binding.profile),
        }
    }

    struct FakeBoundary {
        finish_checks: Cell<usize>,
        fail: bool,
    }

    impl CgroupBoundary for FakeBoundary {
        fn verify_start(&self, _expected_id: u64) -> Result<()> {
            Ok(())
        }

        fn verify_finish(&self, expected_id: u64) -> Result<()> {
            if expected_id != 42 || self.fail {
                bail!("fake cgroup boundary mismatch");
            }
            self.finish_checks.set(self.finish_checks.get() + 1);
            Ok(())
        }
    }

    struct FakeRecorder {
        health: SystemEffectHealth,
        polls: Arc<AtomicUsize>,
        finish_calls: usize,
        unregister_calls: usize,
    }

    impl RecorderDriver for FakeRecorder {
        fn poll(&mut self, _timeout: Duration) -> Result<usize> {
            self.polls.fetch_add(1, Ordering::Relaxed);
            thread::sleep(Duration::from_millis(1));
            Ok(0)
        }

        fn finish_run(
            &mut self,
            cgroup_id: u64,
            epoch: u64,
            _timeout: Duration,
            producer_barrier_complete: bool,
        ) -> Result<SystemEffectHealth> {
            assert_eq!(cgroup_id, 42);
            assert_eq!(epoch, 7);
            assert!(producer_barrier_complete);
            self.finish_calls += 1;
            Ok(self.health.clone())
        }

        fn unregister_run(&mut self, cgroup_id: u64, epoch: u64) -> Result<()> {
            assert_eq!((cgroup_id, epoch), (42, 7));
            self.unregister_calls += 1;
            Ok(())
        }
    }

    #[test]
    fn evidence_directory_is_existing_private_empty_and_create_new_only() {
        let directory = TestDirectory::create(0o700);
        let evidence = EvidenceDirectory::open_empty_private(&directory.0).unwrap();
        evidence
            .create_json(POLICY_NAME, &serde_json::json!({"ok": true}), 1024)
            .unwrap();
        assert!(evidence
            .create_json(POLICY_NAME, &serde_json::json!({"ok": false}), 1024)
            .is_err());
        assert_eq!(
            fs::metadata(directory.0.join(POLICY_NAME))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }

    #[test]
    fn evidence_directory_rejects_permissions_and_preexisting_entries() {
        let public = TestDirectory::create(0o750);
        assert!(EvidenceDirectory::open_empty_private(&public.0).is_err());

        let dirty = TestDirectory::create(0o700);
        File::create(dirty.0.join("foreign")).unwrap();
        assert!(EvidenceDirectory::open_empty_private(&dirty.0).is_err());
    }

    #[test]
    fn artifact_collector_rejects_unbound_directory_entries() {
        let directory = TestDirectory::create(0o700);
        let evidence = EvidenceDirectory::open_empty_private(&directory.0).unwrap();
        for name in ARTIFACT_NAMES {
            evidence
                .create_json(name, &serde_json::json!({ "fixture": name }), 4096)
                .unwrap();
        }
        assert_eq!(collect_artifacts(&evidence).unwrap().len(), 4);
        write_private(&directory.0.join("unbound"), b"x").unwrap();
        assert!(collect_artifacts(&evidence).is_err());
    }

    #[test]
    fn stable_reader_rejects_symlink_and_hardlink_substitution() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::create(0o700);
        let outside = directory.0.with_extension("outside");
        write_private(&outside, b"outside").unwrap();
        symlink(&outside, directory.0.join(POLICY_NAME)).unwrap();
        assert!(read_stable_file(&directory.0, POLICY_NAME, 1024).is_err());
        fs::remove_file(directory.0.join(POLICY_NAME)).unwrap();
        fs::hard_link(&outside, directory.0.join(POLICY_NAME)).unwrap();
        assert!(read_stable_file(&directory.0, POLICY_NAME, 1024).is_err());
        fs::remove_file(outside).unwrap();
    }

    #[test]
    fn fake_engine_requires_two_independent_finish_boundary_checks() {
        let start = start();
        let finish = finish(&start);
        let boundary = FakeBoundary {
            finish_checks: Cell::new(0),
            fail: false,
        };
        let mut recorder = FakeRecorder {
            health: complete_health(&start),
            polls: Arc::new(AtomicUsize::new(0)),
            finish_calls: 0,
            unregister_calls: 0,
        };
        let health = finish_engine(
            &start,
            &finish,
            &boundary,
            &mut recorder,
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(health.transport_status, TransportStatus::Complete);
        assert_eq!(boundary.finish_checks.get(), 2);
        assert_eq!(recorder.finish_calls, 1);
    }

    #[test]
    fn fake_engine_rejects_incomplete_transport_and_bad_boundary() {
        let start = start();
        let finish = finish(&start);
        let mut incomplete = FakeRecorder {
            health: {
                let mut health = complete_health(&start);
                health.transport_status = TransportStatus::Incomplete;
                health
            },
            polls: Arc::new(AtomicUsize::new(0)),
            finish_calls: 0,
            unregister_calls: 0,
        };
        let good_boundary = FakeBoundary {
            finish_checks: Cell::new(0),
            fail: false,
        };
        assert!(finish_engine(
            &start,
            &finish,
            &good_boundary,
            &mut incomplete,
            Duration::from_secs(1)
        )
        .is_err());

        let bad_boundary = FakeBoundary {
            finish_checks: Cell::new(0),
            fail: true,
        };
        let mut complete = FakeRecorder {
            health: complete_health(&start),
            polls: Arc::new(AtomicUsize::new(0)),
            finish_calls: 0,
            unregister_calls: 0,
        };
        assert!(finish_engine(
            &start,
            &finish,
            &bad_boundary,
            &mut complete,
            Duration::from_secs(1)
        )
        .is_err());
        assert_eq!(complete.finish_calls, 0);
    }

    struct DelayedReader {
        input: Cursor<Vec<u8>>,
        delayed: bool,
    }

    impl Read for DelayedReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if !self.delayed {
                self.delayed = true;
                thread::sleep(Duration::from_millis(25));
            }
            self.input.read(output)
        }
    }

    #[test]
    fn waiting_for_finish_polls_recorder_instead_of_blocking_ring_drain() {
        let start = start();
        let encoded = format!(
            "{}\n",
            serde_json::json!({
                "protocol": PROTOCOL,
                "version": PROTOCOL_VERSION,
                "type": "FINISH",
                "binding": start.binding,
                "auth_challenge": start.auth_challenge,
                "outcome": "completed",
                "quiescence": {
                    "status": "QUIESCENT_WITHIN_CGROUP",
                    "basis": "CGROUP_V2_EMPTY_FROZEN_VERIFIED",
                    "cgroup_id": start.binding.cgroup_id,
                },
            })
        );
        let polls = Arc::new(AtomicUsize::new(0));
        let mut recorder = FakeRecorder {
            health: complete_health(&start),
            polls: Arc::clone(&polls),
            finish_calls: 0,
            unregister_calls: 0,
        };
        let received = wait_for_finish(
            BufReader::new(DelayedReader {
                input: Cursor::new(encoded.into_bytes()),
                delayed: false,
            }),
            &mut recorder,
        )
        .unwrap();
        received.validate_against(&start).unwrap();
        assert!(polls.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn wal_projection_rejects_forged_json_argument() {
        let start = start();
        let policy = describe_policy(PolicyProfile::Balanced)
            .unwrap()
            .into_iter()
            .find(|entry| entry.syscall_nr == libc::SYS_bpf as i32)
            .unwrap();
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"test");
        let raw = KernelEvent {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            kind: EVENT_ATTEMPT,
            domain: EffectDomain::KernelControl as u16,
            operation: EffectOperation::BpfCommand as u32,
            flags: 0,
            syscall_nr: libc::SYS_bpf as i32,
            run_epoch: start.binding.run_epoch,
            event_seq: 1,
            related_attempt_seq: 0,
            ktime_ns: 10,
            cgroup_id: start.binding.cgroup_id,
            pid_tgid: (123u64 << 32) | 124,
            return_value: 0,
            args: [1, 2, 3, 4, 5, 6],
            comm,
            task_start_boottime_ns: 44,
            payload_lens: [0, 0],
            payload_kinds: [PAYLOAD_NONE, PAYLOAD_NONE],
            payload_arg_indices: [0, 0],
            payloads: [[0; CAPTURE_BYTES]; 2],
            file_object: None,
            socket_object: None,
        };
        let mut json = SystemEffectEvent {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            run_id: start.binding.run_id.clone(),
            run_epoch: raw.run_epoch,
            event_seq: raw.event_seq,
            related_attempt_seq: 0,
            kind: EventKind::OperationAttempt,
            domain: EffectDomain::KernelControl,
            operation: EffectOperation::BpfCommand,
            syscall_nr: raw.syscall_nr,
            syscall_name: policy.syscall_name.clone(),
            ktime_ns: raw.ktime_ns,
            cgroup_id: raw.cgroup_id,
            pid: raw.pid_tgid as u32,
            tgid: (raw.pid_tgid >> 32) as u32,
            comm: "test".to_owned(),
            process_identity: Default::default(),
            raw_arguments: raw.args,
            captures: Vec::new(),
            object_resolution: expected_object_resolution(&raw),
            attribution: expected_attribution(&raw),
            return_value: None,
            result_status: None,
            flags: raw.flags,
            semantics: EVENT_SEMANTICS.to_owned(),
        };
        validate_json_event(&raw, &json, &start.binding, &policy).unwrap();
        json.raw_arguments[0] = 999;
        assert!(validate_json_event(&raw, &json, &start.binding, &policy).is_err());
    }

    #[test]
    fn strict_replay_rejects_wal_jsonl_count_mismatch() {
        let start = start();
        let directory = TestDirectory::create(0o700);
        let policy = describe_policy(PolicyProfile::Balanced)
            .unwrap()
            .into_iter()
            .find(|entry| entry.syscall_nr == libc::SYS_bpf as i32)
            .unwrap();
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"test");
        let attempt = KernelEvent {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            kind: EVENT_ATTEMPT,
            domain: EffectDomain::KernelControl as u16,
            operation: EffectOperation::BpfCommand as u32,
            flags: 0,
            syscall_nr: libc::SYS_bpf as i32,
            run_epoch: start.binding.run_epoch,
            event_seq: 1,
            related_attempt_seq: 0,
            ktime_ns: 10,
            cgroup_id: start.binding.cgroup_id,
            pid_tgid: (123u64 << 32) | 124,
            return_value: 0,
            args: [1, 2, 3, 4, 5, 6],
            comm,
            task_start_boottime_ns: 44,
            payload_lens: [0, 0],
            payload_kinds: [PAYLOAD_NONE, PAYLOAD_NONE],
            payload_arg_indices: [0, 0],
            payloads: [[0; CAPTURE_BYTES]; 2],
            file_object: None,
            socket_object: None,
        };
        let mut result = attempt.clone();
        result.kind = EVENT_RESULT;
        result.event_seq = 2;
        result.related_attempt_seq = 1;
        result.ktime_ns = 11;
        let mut wal = Vec::new();
        for event in [&attempt, &result] {
            let payload = event.encode_le();
            wal.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            wal.extend_from_slice(&payload);
            wal.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
        }
        write_private(&directory.0.join(WAL_NAME), &wal).unwrap();
        let projected = SystemEffectEvent {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            run_id: start.binding.run_id.clone(),
            run_epoch: attempt.run_epoch,
            event_seq: attempt.event_seq,
            related_attempt_seq: 0,
            kind: EventKind::OperationAttempt,
            domain: EffectDomain::KernelControl,
            operation: EffectOperation::BpfCommand,
            syscall_nr: attempt.syscall_nr,
            syscall_name: policy.syscall_name.clone(),
            ktime_ns: attempt.ktime_ns,
            cgroup_id: attempt.cgroup_id,
            pid: attempt.pid_tgid as u32,
            tgid: (attempt.pid_tgid >> 32) as u32,
            comm: "test".to_owned(),
            process_identity: Default::default(),
            raw_arguments: attempt.args,
            captures: Vec::new(),
            object_resolution: expected_object_resolution(&attempt),
            attribution: expected_attribution(&attempt),
            return_value: None,
            result_status: None,
            flags: attempt.flags,
            semantics: EVENT_SEMANTICS.to_owned(),
        };
        let mut jsonl = serde_json::to_vec(&projected).unwrap();
        jsonl.push(b'\n');
        write_private(&directory.0.join(JSONL_NAME), &jsonl).unwrap();
        let health = complete_health(&start);
        let artifacts = BTreeMap::from([
            (
                WAL_NAME.to_owned(),
                measure_artifact(&directory.0, WAL_NAME).unwrap(),
            ),
            (
                JSONL_NAME.to_owned(),
                measure_artifact(&directory.0, JSONL_NAME).unwrap(),
            ),
        ]);
        assert!(
            verify_event_streams(&directory.0, &start.binding, &health, &[policy], &artifacts,)
                .is_err()
        );
    }

    fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }
}
