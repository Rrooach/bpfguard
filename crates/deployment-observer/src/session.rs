// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, Context, Result};
use bpf_observer_deployment::{
    discover, validate_against_live_procfs_for_phase, DeploymentManifest, DeploymentRequest,
    LiveIdentityValidation, RevalidationPhase, ValidationMismatch,
};
use bpf_observer_filesystem_confirmer::{
    FilesystemScope, FilesystemSnapshot, SnapshotPhase as FilesystemSnapshotPhase,
};
use bpf_observer_linux_state_confirmers::{
    capture_with_retained_namespaces as capture_linux_state, compare as compare_linux_state,
    CaptureRequest, LinuxNamespaceKind, RetainedNamespace, RetainedNamespaces, SnapshotPhase,
    StateScope, StateSnapshot,
};
use bpf_observer_schema::{ClaimScope, ObjectExclusions, Snapshot as BpfSnapshot};
use bpf_observer_system_effects::lifecycle::ProcessLifecycleRecorder;
use bpf_observer_system_effects::socket_state::{
    SOCKET_STATE_HEALTH_NAME, SOCKET_STATE_JSONL_NAME, SOCKET_STATE_WAL_NAME,
};
use bpf_observer_system_effects::{FileObjectResolutionMode, PolicyProfile, SystemEffectRecorder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc::{self, TryRecvError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::barrier::{verify_frozen_roots, RootFreezeBarrier, RootFreezeIdentity};
use crate::endpoint_state::{
    bpf_scope_sha256, capture_bpf_endpoint, capture_filesystem_endpoint, compare_bpf_endpoints,
    compare_filesystem_endpoints, endpoint_contract_reasons, filesystem_mount_namespace_target,
    filesystem_namespace_reasons, merge_exclusions, validate_exclusions,
    validate_filesystem_output_separation, BpfStateArtifactBindings, BpfStateReport,
    EndpointContractEvidence, FilesystemStateReport, BPF_STATE_S0_FILE, BPF_STATE_S1_FILE,
    BPF_STATE_VERDICT_FILE, FILESYSTEM_STATE_COMPARISON_FILE, FILESYSTEM_STATE_S0_FILE,
    FILESYSTEM_STATE_S1_FILE,
};
use crate::linux_state::{
    bind_linux_state_scope, confirmation_contract_reasons, retained_namespace_contract_reasons,
    BoundLinuxStateScope, LinuxStateReport,
};
use crate::protocol::{
    FinishCommand, ProtocolMachine, ReadyMessage, TerminalMessage,
    DEPLOYMENT_OBSERVER_PROTOCOL_VERSION, DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
};
use crate::recovery::RecoveryConfig;
use crate::report::{
    aggregate_health, aggregate_lifecycle_health, checked_artifact_total_bytes,
    overall_evidence_status, AggregateEvidenceStatus, ArtifactDigest, ArtifactManifest,
    CgroupLifecycleOutcome, CgroupRecorderOutcome, ClosingDrainTelemetry,
    DeploymentObservationReport, DiagnosticPerformanceTelemetry, EndpointCaptureTelemetry,
    IdentityAssessment, SocketStateHealthArtifact, SocketStateReport,
};
use crate::{CgroupScopeCapability, MAX_ANCESTOR_ROOTS};

const MAX_PROTOCOL_LINE_BYTES: usize = 16 * 1024;
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_POLL_INTERVAL_MS: u64 = 1000;
const MAX_DRAIN_TIMEOUT_MS: u64 = 60_000;

const CONTRACT_FILE: &str = "observation-contract.json";
const DEPLOYMENT_FILE: &str = "deployment-manifest.json";
const READY_BARRIER_FILE: &str = "ready-barrier.json";
const READY_VALIDATION_FILE: &str = "ready-validation.json";
const READY_MESSAGE_FILE: &str = "ready-message.json";
const PRE_FINISH_BARRIER_FILE: &str = "pre-finish-barrier.json";
const PRE_FINISH_VALIDATION_FILE: &str = "pre-finish-validation.json";
const CLOSURE_BARRIER_FILE: &str = "closure-barrier.json";
const CLOSURE_VALIDATION_FILE: &str = "closure-validation.json";
const MAX_IDENTITY_MISMATCH_DIAGNOSTICS: usize = 16;

pub(crate) fn identity_mismatch_diagnostic(
    stage: &str,
    validation: &LiveIdentityValidation,
) -> String {
    let mismatch_count = validation.mismatches.len();
    let mismatch_sample = validation
        .mismatches
        .iter()
        .take(MAX_IDENTITY_MISMATCH_DIAGNOSTICS)
        .collect::<Vec<_>>();
    format!(
        "deployment identity changed during {stage}: mismatch_count={mismatch_count}, \
         first_mismatches={mismatch_sample:?}"
    )
}
const REPORT_FILE: &str = "deployment-observation-report.json";
const ARTIFACT_MANIFEST_FILE: &str = "artifact-manifest.json";
const EFFECT_WAL_FILE: &str = "system-effects.raw.bin";
const EFFECT_JSONL_FILE: &str = "system-effects.jsonl";
const LIFECYCLE_WAL_FILE: &str = "process-lifecycle.raw.bin";
const LIFECYCLE_JSONL_FILE: &str = "process-lifecycle.jsonl";
const LINUX_STATE_S0_FILE: &str = "linux-state-s0.json";
const LINUX_STATE_S1_FILE: &str = "linux-state-s1.json";
const LINUX_STATE_COMPARISON_FILE: &str = "linux-state-comparison.json";

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentObserverConfig {
    pub protocol_version: u32,
    pub deployment: DeploymentRequest,
    pub recorder_object_path: String,
    pub recorder_object_sha256: String,
    pub lifecycle_object_path: String,
    pub lifecycle_object_sha256: String,
    pub output_directory: String,
    pub run_id: String,
    pub epoch: u64,
    pub profile: PolicyProfile,
    pub object_resolution_mode: FileObjectResolutionMode,
    /// Optional global BPF object inventory. This is an explicit scope and is
    /// never inferred from a container or Kata identity.
    #[serde(default)]
    pub bpf_state_scope: Option<ClaimScope>,
    /// Optional observer-visible path-tree scope. In particular, Kata block
    /// images are never recursively scanned or auto-bound.
    #[serde(default)]
    pub filesystem_state_scope: Option<FilesystemScope>,
    #[serde(default)]
    pub linux_state_scope: Option<StateScope>,
    /// Protocol v3 only: a content-bound, synchronous external recovery helper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryConfig>,
    pub poll_interval_ms: u64,
    pub drain_timeout_ms: u64,
}

impl DeploymentObserverConfig {
    pub fn validate(&self) -> Result<()> {
        self.validate_schema()?;
        if !Path::new(&self.recorder_object_path).is_file() {
            bail!("recorder object path is not a regular file");
        }
        if !Path::new(&self.lifecycle_object_path).is_file() {
            bail!("lifecycle object path is not a regular file");
        }
        Ok(())
    }

    pub fn validate_schema(&self) -> Result<()> {
        match (self.protocol_version, self.recovery.as_ref()) {
            (DEPLOYMENT_OBSERVER_PROTOCOL_VERSION, None) => {}
            (DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION, Some(recovery)) => {
                recovery.validate_schema()?;
            }
            _ => bail!("deployment-observer protocol and recovery contract disagree"),
        }
        self.deployment.validate()?;
        if let Some(scope) = &self.linux_state_scope {
            scope.validate()?;
        }
        if let Some(scope) = &self.bpf_state_scope {
            bpf_observer_oracle::validate_claim_scope(scope)?;
        }
        if let Some(scope) = &self.filesystem_state_scope {
            scope.validate()?;
        }
        validate_path(&self.recorder_object_path, "recorder object")?;
        validate_path(&self.lifecycle_object_path, "lifecycle object")?;
        validate_path(&self.output_directory, "output directory")?;
        validate_sha256(&self.recorder_object_sha256, "recorder object")?;
        validate_sha256(&self.lifecycle_object_sha256, "lifecycle object")?;
        if self.run_id.is_empty()
            || self.run_id.len() > 128
            || !self.run_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            bail!("run_id must contain 1..=128 conservative ASCII identity bytes");
        }
        if self.epoch == 0 {
            bail!("deployment observation epoch must be nonzero");
        }
        if self.poll_interval_ms == 0 || self.poll_interval_ms > MAX_POLL_INTERVAL_MS {
            bail!("poll_interval_ms must be in 1..={MAX_POLL_INTERVAL_MS}");
        }
        if self.drain_timeout_ms == 0 || self.drain_timeout_ms > MAX_DRAIN_TIMEOUT_MS {
            bail!("drain_timeout_ms must be in 1..={MAX_DRAIN_TIMEOUT_MS}");
        }
        Ok(())
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| format!("open deployment-observer config {}", path.display()))?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.len() > MAX_CONFIG_BYTES
        {
            bail!("deployment-observer config must be a bounded regular file");
        }
        let mut bytes = Vec::new();
        let mut limited = file.take(MAX_CONFIG_BYTES + 1);
        limited.read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            bail!("deployment-observer config exceeds {MAX_CONFIG_BYTES} bytes");
        }
        let after = limited.get_ref().metadata()?;
        if metadata.dev() != after.dev()
            || metadata.ino() != after.ino()
            || metadata.len() != after.len()
            || metadata.mtime() != after.mtime()
            || metadata.mtime_nsec() != after.mtime_nsec()
            || metadata.ctime() != after.ctime()
            || metadata.ctime_nsec() != after.ctime_nsec()
            || bytes.len() as u64 != metadata.len()
        {
            bail!("deployment-observer config changed while it was read");
        }
        let config: Self = serde_json::from_slice(&bytes)
            .context("parse deployment-observer configuration JSON")?;
        config.validate()?;
        Ok(config)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationPlan {
    pub deployment_scope_sha256: String,
    pub root_cgroup_ids: Vec<u64>,
    pub dynamic_descendant_policy: String,
}

impl RegistrationPlan {
    pub fn from_manifest(manifest: &DeploymentManifest) -> Result<Self> {
        manifest.validate()?;
        let mut root_cgroup_ids = manifest.registration_root_cgroup_ids();
        let root_count = root_cgroup_ids.len();
        root_cgroup_ids.sort_unstable();
        root_cgroup_ids.dedup();
        if root_cgroup_ids.len() != root_count {
            bail!("deployment contains duplicate root cgroup identities");
        }
        if root_cgroup_ids.is_empty()
            || root_cgroup_ids.len() > MAX_ANCESTOR_ROOTS
            || manifest.root_cgroups.iter().any(|root| root.path == "/")
        {
            bail!("deployment roots must be non-root cgroup-v2 freeze boundaries");
        }
        for (index, root) in manifest.root_cgroups.iter().enumerate() {
            for other in manifest.root_cgroups.iter().skip(index + 1) {
                let root_prefix = format!("{}/", root.path);
                let other_prefix = format!("{}/", other.path);
                if other.path.starts_with(&root_prefix) || root.path.starts_with(&other_prefix) {
                    bail!("deployment ancestor roots must be pairwise disjoint");
                }
            }
        }
        Ok(Self {
            deployment_scope_sha256: manifest.scope_sha256.clone(),
            root_cgroup_ids,
            dynamic_descendant_policy: "BPF_CURRENT_TASK_UNDER_CGROUP_CGROUP_ARRAY_BOUNDED_V1"
                .to_owned(),
        })
    }
}

pub struct DeploymentSession {
    config: DeploymentObserverConfig,
    manifest: DeploymentManifest,
    plan: RegistrationPlan,
    ready_barrier: RootFreezeBarrier,
    ready_validation: bpf_observer_deployment::LiveIdentityValidation,
    recorder: SystemEffectRecorder,
    lifecycle_recorder: ProcessLifecycleRecorder,
    recorder_object_sha256: String,
    lifecycle_object_sha256: String,
    recorder_policy_sha256: String,
    protocol: ProtocolMachine,
    output_directory: PathBuf,
    linux_state: Option<BoundLinuxStateScope>,
    linux_state_namespaces: Option<RetainedNamespaces>,
    linux_state_s0: Option<StateSnapshot>,
    linux_state_s0_digest: Option<ArtifactDigest>,
    bpf_state_s0: Option<BpfSnapshot>,
    bpf_state_s0_digest: Option<ArtifactDigest>,
    system_effect_recorder_exclusions: ObjectExclusions,
    lifecycle_recorder_exclusions: ObjectExclusions,
    bpf_state_exclusions: ObjectExclusions,
    filesystem_state_s0: Option<FilesystemSnapshot>,
    filesystem_state_s0_digest: Option<ArtifactDigest>,
    filesystem_mount_namespace: Option<RetainedNamespace>,
    s0_endpoint_capture_telemetry: EndpointCaptureTelemetry,
    cgroup_scope_capability: CgroupScopeCapability,
    cgroup_scope_capability_sha256: String,
}

/// One sequential endpoint capture used by the opt-in recovery coordinator.
/// The three domain collectors are intentionally not represented as an atomic
/// whole-Linux snapshot; `captured_started_unix_ns` and
/// `captured_completed_unix_ns` expose the collection window explicitly.
#[derive(Clone, Debug)]
pub(crate) struct RecoveryEndpointSnapshots {
    pub captured_started_unix_ns: u128,
    pub captured_completed_unix_ns: u128,
    pub raw_phase: String,
    pub bpf: Option<BpfSnapshot>,
    pub filesystem: Option<FilesystemSnapshot>,
    pub linux: Option<StateSnapshot>,
    pub telemetry: EndpointCaptureTelemetry,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRecorderFinalization {
    pub protocol_version: u32,
    pub run_id: String,
    pub epoch: u64,
    pub root_cgroup_ids: Vec<u64>,
    pub system_effects: Vec<CgroupRecorderOutcome>,
    pub process_lifecycle: Vec<CgroupLifecycleOutcome>,
    pub endpoint_capture_telemetry: Vec<EndpointCaptureTelemetry>,
    pub complete: bool,
    pub reasons: Vec<String>,
}

impl DeploymentSession {
    pub fn prepare(config: DeploymentObserverConfig) -> Result<(Self, ReadyMessage)> {
        config.validate()?;
        let output_directory = PathBuf::from(&config.output_directory);
        if output_directory.exists() {
            bail!("deployment-observer output directory must not already exist");
        }
        let parent = output_directory
            .parent()
            .context("output directory has no parent")?;
        if !parent.is_dir() {
            bail!("deployment-observer output parent is not a directory");
        }
        if let Some(scope) = config.filesystem_state_scope.as_ref() {
            validate_filesystem_output_separation(scope, &output_directory)?;
        }
        let mut directory_builder = fs::DirBuilder::new();
        directory_builder
            .mode(0o700)
            .create(&output_directory)
            .with_context(|| {
                format!(
                    "create exclusive deployment-observer output directory {}",
                    output_directory.display()
                )
            })?;

        let manifest = discover(&config.deployment)?;
        if manifest
            .processes
            .iter()
            .any(|process| process.pid == std::process::id())
        {
            bail!("observer process must be outside every observed deployment cgroup");
        }
        let plan = RegistrationPlan::from_manifest(&manifest)?;
        let mut linux_state = bind_linux_state_scope(config.linux_state_scope.as_ref(), &manifest)?;
        let initial_barrier = verify_frozen_roots(&manifest)?;
        require_barrier(&initial_barrier, "initial")?;
        let initial_validation =
            validate_against_live_procfs_for_phase(&manifest, RevalidationPhase::Ready)?;
        if !initial_validation.is_stable() {
            bail!(identity_mismatch_diagnostic(
                "initial READY validation",
                &initial_validation
            ));
        }
        // Namespace FDs are capabilities, not late PID lookups. Pin every
        // selected namespace while the deployment is frozen and alive so S1
        // remains valid after an expected process exit.
        let linux_state_namespaces = linux_state
            .as_ref()
            .map(|bound| {
                RetainedNamespaces::open(&bound.scope, bound.sysctl_namespace_targets.as_ref())
            })
            .transpose()
            .context("retain deployment Linux-state namespaces")?;
        let filesystem_namespace_target = config
            .filesystem_state_scope
            .as_ref()
            .map(|_| filesystem_mount_namespace_target(&manifest))
            .transpose()?
            .flatten();
        let filesystem_mount_namespace = filesystem_namespace_target
            .as_ref()
            .map(|target| RetainedNamespace::open(target, LinuxNamespaceKind::Mount))
            .transpose()
            .context("retain deployment filesystem mount namespace")?;

        let boot_id = read_boot_id()?;
        if boot_id != manifest.boot_id {
            bail!("deployment boot identity changed before recorder startup");
        }
        let mut recorder = SystemEffectRecorder::open(
            Path::new(&config.recorder_object_path),
            &config.recorder_object_sha256,
            &output_directory,
            &config.run_id,
            &boot_id,
            config.profile,
            config.object_resolution_mode,
        )?;
        let mut lifecycle_recorder = ProcessLifecycleRecorder::open(
            Path::new(&config.lifecycle_object_path),
            &config.lifecycle_object_sha256,
            &output_directory,
            &config.run_id,
            &boot_id,
        )?;
        let mut system_effect_recorder_exclusions = ObjectExclusions::default();
        let mut lifecycle_recorder_exclusions = ObjectExclusions::default();
        let mut bpf_state_exclusions = ObjectExclusions::default();
        if let Some(scope) = config.bpf_state_scope.as_ref() {
            system_effect_recorder_exclusions = recorder.object_exclusions()?;
            lifecycle_recorder_exclusions = lifecycle_recorder.object_exclusions()?;
            validate_exclusions(&system_effect_recorder_exclusions)?;
            validate_exclusions(&lifecycle_recorder_exclusions)?;
            bpf_state_exclusions = system_effect_recorder_exclusions.clone();
            merge_exclusions(&mut bpf_state_exclusions, &lifecycle_recorder_exclusions);
            validate_exclusions(&bpf_state_exclusions)?;
            bpf_observer_oracle::validate_claim_scope_exclusions(scope, &bpf_state_exclusions)?;
        }
        for cgroup_id in &plan.root_cgroup_ids {
            let root = manifest
                .root_cgroups
                .iter()
                .find(|root| root.cgroup_id == *cgroup_id)
                .context("registration root ID disappeared from deployment manifest")?;
            let root_path = Path::new("/sys/fs/cgroup").join(
                root.path
                    .strip_prefix('/')
                    .context("deployment root path is not absolute")?,
            );
            recorder.register_ancestor_root(&root_path, *cgroup_id, config.epoch)?;
            lifecycle_recorder.register_ancestor_root(&root_path, *cgroup_id, config.epoch)?;
        }
        recorder.seal_ancestor_roots()?;
        lifecycle_recorder.seal_ancestor_roots()?;
        recorder.verify_ancestor_roots()?;
        lifecycle_recorder.verify_ancestor_roots()?;
        let cgroup_scope_capability = CgroupScopeCapability::for_roots(&plan.root_cgroup_ids)?;
        let cgroup_scope_capability_sha256 = cgroup_scope_capability.sha256()?;

        // Revalidate only after every exact ID is active. No READY line is
        // emitted unless both the process/cgroup set and the caller-owned
        // freeze barrier remain stable across recorder registration.
        let registration_validation =
            validate_against_live_procfs_for_phase(&manifest, RevalidationPhase::Ready)?;
        if !registration_validation.is_stable() {
            bail!("deployment identity changed while recorder registrations were installed");
        }
        let registration_barrier = verify_frozen_roots(&manifest)?;
        require_barrier(&registration_barrier, "pre-S0")?;

        // Endpoint confirmation is intentionally outside the syscall hot path.
        // The target is still caller-frozen and no READY line has been emitted.
        let (bpf_state_s0, bpf_s0_duration_ns) = match config.bpf_state_scope.as_ref() {
            Some(scope) => {
                let started = Instant::now();
                let snapshot = capture_bpf_endpoint(
                    scope,
                    &bpf_state_exclusions,
                    &config.run_id,
                    config.epoch,
                    "S0",
                )
                .context("capture deployment BPF endpoint state S0")?;
                (
                    Some(snapshot),
                    Some(duration_ns(started.elapsed(), "BPF S0 capture")?),
                )
            }
            None => (None, None),
        };
        let (filesystem_state_s0, filesystem_s0_duration_ns) =
            match config.filesystem_state_scope.as_ref() {
                Some(scope) => {
                    validate_filesystem_output_separation(scope, &output_directory)
                        .context("revalidate filesystem/evidence separation at S0")?;
                    let started = Instant::now();
                    let snapshot = capture_filesystem_endpoint(
                        scope,
                        &config.run_id,
                        config.epoch,
                        FilesystemSnapshotPhase::S0,
                        filesystem_mount_namespace.as_ref(),
                    )
                    .context("capture deployment filesystem endpoint state S0")?;
                    (
                        Some(snapshot),
                        Some(duration_ns(started.elapsed(), "filesystem S0 capture")?),
                    )
                }
                None => (None, None),
            };
        let (linux_state_s0, linux_s0_duration_ns) = match &mut linux_state {
            Some(bound) => {
                let started = Instant::now();
                let retained = linux_state_namespaces
                    .as_ref()
                    .context("enabled Linux state confirmation has no retained namespaces")?;
                let snapshot = capture_linux_state(
                    &bound.scope,
                    &CaptureRequest {
                        snapshot_id: format!("{}:linux-state:s0", config.run_id),
                        phase: SnapshotPhase::S0,
                    },
                    retained,
                )?;
                (
                    Some(snapshot),
                    Some(duration_ns(started.elapsed(), "Linux S0 capture")?),
                )
            }
            None => (None, None),
        };
        let s0_endpoint_capture_telemetry = EndpointCaptureTelemetry::new(
            bpf_s0_duration_ns,
            filesystem_s0_duration_ns,
            linux_s0_duration_ns,
        )?;

        // Re-establish both barriers after the sequential endpoint collectors
        // so READY commits their final pre-resume state.
        let ready_validation =
            validate_against_live_procfs_for_phase(&manifest, RevalidationPhase::Ready)?;
        if !ready_validation.is_stable() {
            bail!("deployment identity changed during Linux state S0 capture");
        }
        let ready_barrier = verify_frozen_roots(&manifest)?;
        require_barrier(&ready_barrier, "READY")?;

        let recorder_object_sha256 = recorder.object_sha256().to_owned();
        let lifecycle_object_sha256 = lifecycle_recorder.object_sha256().to_owned();
        let recorder_policy_sha256 = recorder.policy_sha256().to_owned();
        let finish_nonce = random_nonce()?;
        let mut protocol = ProtocolMachine::new(&config.run_id, &finish_nonce)?;
        protocol.mark_ready()?;

        write_json_new(&output_directory.join(CONTRACT_FILE), &config)?;
        let deployment_digest = write_json_new(&output_directory.join(DEPLOYMENT_FILE), &manifest)?;
        let ready_barrier_digest =
            write_json_new(&output_directory.join(READY_BARRIER_FILE), &ready_barrier)?;
        let ready_validation_digest = write_json_new(
            &output_directory.join(READY_VALIDATION_FILE),
            &ready_validation,
        )?;
        let linux_state_s0_digest = linux_state_s0
            .as_ref()
            .map(|snapshot| {
                write_json_compact_new(&output_directory.join(LINUX_STATE_S0_FILE), snapshot)
            })
            .transpose()?;
        let bpf_state_s0_digest = bpf_state_s0
            .as_ref()
            .map(|snapshot| {
                write_json_compact_new(&output_directory.join(BPF_STATE_S0_FILE), snapshot)
            })
            .transpose()?;
        let filesystem_state_s0_digest = filesystem_state_s0
            .as_ref()
            .map(|snapshot| {
                write_json_compact_new(&output_directory.join(FILESYSTEM_STATE_S0_FILE), snapshot)
            })
            .transpose()?;
        let ready_message = ReadyMessage {
            protocol_version: DEPLOYMENT_OBSERVER_PROTOCOL_VERSION,
            status: "READY".to_owned(),
            run_id: config.run_id.clone(),
            epoch: config.epoch,
            finish_nonce,
            deployment_scope_sha256: manifest.scope_sha256.clone(),
            registration_cgroup_ids: plan.root_cgroup_ids.clone(),
            cgroup_scope_capability_sha256: cgroup_scope_capability_sha256.clone(),
            cgroup_scope_capability: cgroup_scope_capability.clone(),
            deployment_manifest_sha256: deployment_digest.sha256,
            ready_barrier_sha256: ready_barrier_digest.sha256,
            ready_validation_sha256: ready_validation_digest.sha256,
            recorder_object_sha256: recorder_object_sha256.clone(),
            lifecycle_object_sha256: lifecycle_object_sha256.clone(),
            socket_state_enabled: config.object_resolution_mode
                == FileObjectResolutionMode::KernelObjectExpandedPartial,
            bpf_state_scope_sha256: config
                .bpf_state_scope
                .as_ref()
                .map(bpf_scope_sha256)
                .transpose()?,
            bpf_state_s0_sha256: bpf_state_s0_digest
                .as_ref()
                .map(|digest| digest.sha256.clone()),
            filesystem_state_scope_sha256: config
                .filesystem_state_scope
                .as_ref()
                .map(FilesystemScope::sha256)
                .transpose()?,
            filesystem_state_s0_sha256: filesystem_state_s0_digest
                .as_ref()
                .map(|digest| digest.sha256.clone()),
            linux_state_scope_sha256: linux_state_s0
                .as_ref()
                .map(|snapshot| snapshot.scope_sha256.clone()),
            linux_state_s0_sha256: linux_state_s0_digest
                .as_ref()
                .map(|digest| digest.sha256.clone()),
        };
        write_json_new(&output_directory.join(READY_MESSAGE_FILE), &ready_message)?;
        sync_directory(&output_directory)?;

        Ok((
            Self {
                config,
                manifest,
                plan,
                ready_barrier,
                ready_validation,
                recorder,
                lifecycle_recorder,
                recorder_object_sha256,
                lifecycle_object_sha256,
                recorder_policy_sha256,
                protocol,
                output_directory,
                linux_state,
                linux_state_namespaces,
                linux_state_s0,
                linux_state_s0_digest,
                bpf_state_s0,
                bpf_state_s0_digest,
                system_effect_recorder_exclusions,
                lifecycle_recorder_exclusions,
                bpf_state_exclusions,
                filesystem_state_s0,
                filesystem_state_s0_digest,
                filesystem_mount_namespace,
                s0_endpoint_capture_telemetry,
                cgroup_scope_capability,
                cgroup_scope_capability_sha256,
            },
            ready_message,
        ))
    }

    pub fn poll_once(&mut self) -> Result<usize> {
        let first_wait = self.config.poll_interval_ms / 2;
        let second_wait = self.config.poll_interval_ms - first_wait;
        let effects = self.recorder.poll(Duration::from_millis(first_wait))?;
        let lifecycle = self
            .lifecycle_recorder
            .poll(Duration::from_millis(second_wait))?;
        effects
            .checked_add(lifecycle)
            .context("combined recorder poll count overflow")
    }

    pub(crate) fn manifest(&self) -> &DeploymentManifest {
        &self.manifest
    }

    pub(crate) fn config(&self) -> &DeploymentObserverConfig {
        &self.config
    }

    pub(crate) fn cgroup_scope_capability(&self) -> &CgroupScopeCapability {
        &self.cgroup_scope_capability
    }

    pub(crate) fn baseline_endpoint_snapshots(&self) -> RecoveryEndpointSnapshots {
        let mut captured = self
            .bpf_state_s0
            .as_ref()
            .map(|snapshot| snapshot.captured_unix_ns)
            .into_iter()
            .chain(
                self.filesystem_state_s0
                    .as_ref()
                    .map(|snapshot| snapshot.captured_unix_ns),
            )
            .chain(
                self.linux_state_s0
                    .as_ref()
                    .map(|snapshot| snapshot.captured_unix_ns),
            )
            .collect::<Vec<_>>();
        captured.sort_unstable();
        let start = captured
            .first()
            .copied()
            .unwrap_or(self.ready_barrier.checked_unix_ns);
        let end = self.ready_barrier.checked_unix_ns;
        RecoveryEndpointSnapshots {
            captured_started_unix_ns: start,
            captured_completed_unix_ns: end,
            raw_phase: "S0".to_owned(),
            bpf: self.bpf_state_s0.clone(),
            filesystem: self.filesystem_state_s0.clone(),
            linux: self.linux_state_s0.clone(),
            telemetry: self.s0_endpoint_capture_telemetry.clone(),
        }
    }

    /// Drain currently available ring-buffer records without sealing any BPF
    /// producer or unregistering the target roots. This keeps the Observer's
    /// Program/Map/Link exclusion set stable through snapshots B and C.
    pub(crate) fn drain_open_recorders_at_boundary(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_millis(self.config.drain_timeout_ms);
        let mut consecutive_empty_polls = 0_u8;
        while Instant::now() < deadline {
            let effects = self.recorder.poll(Duration::from_millis(0))?;
            let lifecycle = self.lifecycle_recorder.poll(Duration::from_millis(0))?;
            if effects == 0 && lifecycle == 0 {
                consecutive_empty_polls = consecutive_empty_polls.saturating_add(1);
                if consecutive_empty_polls == 2 {
                    return Ok(());
                }
            } else {
                consecutive_empty_polls = 0;
            }
            std::thread::yield_now();
        }
        bail!("open recorder boundary drain did not reach two empty polls before timeout")
    }

    pub(crate) fn validate_recovery_boundary(
        &self,
        stage: &str,
    ) -> Result<(RootFreezeBarrier, IdentityAssessment)> {
        let barrier = assess_barrier(&self.manifest);
        require_barrier(&barrier, stage)?;
        let mut validation = IdentityAssessment::from_result(
            validate_against_live_procfs_for_phase(&self.manifest, RevalidationPhase::Closure),
        );
        // The v2 final closure legitimately treats every newly added process
        // as a residual mismatch. At B/C, however, Agent descendants may
        // still exist inside the frozen registered root. Their presence is
        // state to confirm, not a replacement of the deployment anchor.
        // Only that precise mismatch is tolerated; PID reuse, namespace or
        // cgroup identity drift, missing backends, and all other mismatches
        // still prevent an endpoint from being committed.
        if let Some(live) = validation.validation.as_ref() {
            validation.stable = live.phase == RevalidationPhase::Closure
                && live.mismatches.iter().all(|mismatch| {
                    matches!(mismatch, ValidationMismatch::ProcessSetChanged {
                        added,
                        removed_unexpected,
                    } if !added.is_empty() && removed_unexpected.is_empty())
                });
        }
        if !validation.stable {
            bail!("deployment identity changed at recovery boundary {stage}: {validation:?}");
        }
        self.recorder.verify_ancestor_roots()?;
        self.lifecycle_recorder.verify_ancestor_roots()?;
        if read_boot_id()? != self.manifest.boot_id {
            bail!("target Linux boot identity changed at recovery boundary {stage}");
        }
        Ok((barrier, validation))
    }

    pub(crate) fn capture_recovery_endpoint_snapshots(
        &mut self,
        phase: &str,
    ) -> Result<RecoveryEndpointSnapshots> {
        let (filesystem_phase, linux_phase) = match phase {
            "B" => (FilesystemSnapshotPhase::B, SnapshotPhase::B),
            "C" => (FilesystemSnapshotPhase::C, SnapshotPhase::C),
            _ => bail!("recovery endpoint capture supports only B or C after READY"),
        };
        let captured_started_unix_ns = now_unix_ns();
        let (bpf, bpf_duration_ns) = match self.config.bpf_state_scope.as_ref() {
            Some(scope) => {
                let started = Instant::now();
                let snapshot = capture_bpf_endpoint(
                    scope,
                    &self.bpf_state_exclusions,
                    &self.config.run_id,
                    self.config.epoch,
                    phase,
                )
                .with_context(|| format!("capture deployment BPF endpoint state {phase}"))?;
                (
                    Some(snapshot),
                    Some(duration_ns(
                        started.elapsed(),
                        &format!("BPF {phase} capture"),
                    )?),
                )
            }
            None => (None, None),
        };
        let (filesystem, filesystem_duration_ns) = match self.config.filesystem_state_scope.as_ref()
        {
            Some(scope) => {
                validate_filesystem_output_separation(scope, &self.output_directory).with_context(
                    || format!("revalidate filesystem/evidence separation at {phase}"),
                )?;
                let started = Instant::now();
                let snapshot = capture_filesystem_endpoint(
                    scope,
                    &self.config.run_id,
                    self.config.epoch,
                    filesystem_phase,
                    self.filesystem_mount_namespace.as_ref(),
                )
                .with_context(|| format!("capture deployment filesystem endpoint state {phase}"))?;
                (
                    Some(snapshot),
                    Some(duration_ns(
                        started.elapsed(),
                        &format!("filesystem {phase} capture"),
                    )?),
                )
            }
            None => (None, None),
        };
        let (linux, linux_duration_ns) = match &mut self.linux_state {
            Some(bound) => {
                let retained = self
                    .linux_state_namespaces
                    .as_ref()
                    .context("enabled Linux state confirmation has no retained namespaces")?;
                let started = Instant::now();
                let snapshot = capture_linux_state(
                    &bound.scope,
                    &CaptureRequest {
                        snapshot_id: format!(
                            "{}:linux-state:{}",
                            self.config.run_id,
                            phase.to_ascii_lowercase()
                        ),
                        phase: linux_phase,
                    },
                    retained,
                )?;
                (
                    Some(snapshot),
                    Some(duration_ns(
                        started.elapsed(),
                        &format!("Linux {phase} capture"),
                    )?),
                )
            }
            None => (None, None),
        };
        let telemetry = EndpointCaptureTelemetry::new(
            bpf_duration_ns,
            filesystem_duration_ns,
            linux_duration_ns,
        )?;
        Ok(RecoveryEndpointSnapshots {
            captured_started_unix_ns,
            captured_completed_unix_ns: now_unix_ns(),
            raw_phase: phase.to_owned(),
            bpf,
            filesystem,
            linux,
            telemetry,
        })
    }

    /// Close Agent operation streams after C has been durably captured. The
    /// Observer's BPF Links therefore remain present in all A/B/C inventories.
    pub(crate) fn finalize_recovery_recorders(&mut self) -> Result<RecoveryRecorderFinalization> {
        self.validate_recovery_boundary("pre-recovery-recorder-finalization")?;
        self.recorder
            .seal_socket_state_producers()
            .context("seal deployment TCP-state producers after snapshot C")?;
        let mut system_effects = Vec::with_capacity(self.plan.root_cgroup_ids.len());
        let mut process_lifecycle = Vec::with_capacity(self.plan.root_cgroup_ids.len());
        let mut reasons = Vec::new();
        for cgroup_id in &self.plan.root_cgroup_ids {
            let outcome = match self.recorder.finish_run(
                *cgroup_id,
                self.config.epoch,
                Duration::from_millis(self.config.drain_timeout_ms),
                true,
            ) {
                Ok(health) => CgroupRecorderOutcome {
                    cgroup_id: *cgroup_id,
                    health: Some(health),
                    finalization_error: None,
                    unregistered: false,
                },
                Err(error) => CgroupRecorderOutcome {
                    cgroup_id: *cgroup_id,
                    health: None,
                    finalization_error: Some(format!("{error:#}")),
                    unregistered: false,
                },
            };
            system_effects.push(outcome);
            let outcome = match self.lifecycle_recorder.finish_run(
                *cgroup_id,
                self.config.epoch,
                Duration::from_millis(self.config.drain_timeout_ms),
                true,
            ) {
                Ok(health) => CgroupLifecycleOutcome {
                    cgroup_id: *cgroup_id,
                    health: Some(health),
                    finalization_error: None,
                    unregistered: false,
                },
                Err(error) => CgroupLifecycleOutcome {
                    cgroup_id: *cgroup_id,
                    health: None,
                    finalization_error: Some(format!("{error:#}")),
                    unregistered: false,
                },
            };
            process_lifecycle.push(outcome);
        }
        for outcome in &mut system_effects {
            if let Err(error) = self
                .recorder
                .unregister_ancestor_root(outcome.cgroup_id, self.config.epoch)
            {
                append_error(
                    &mut outcome.finalization_error,
                    format!("unregister: {error:#}"),
                );
            } else {
                outcome.unregistered = true;
            }
            let healthy = outcome.health.as_ref().map_or(false, |health| {
                health.producer_barrier_complete
                    && health.drain_completed
                    && health.wal_durable
                    && health.event_dropped == 0
                    && health.userspace_failures == 0
                    && health.fatal_kernel_flags == 0
                    && health.pending_remaining == 0
                    && health.object_pending_remaining == 0
                    && health.reasons.is_empty()
            });
            if !healthy || !outcome.unregistered || outcome.finalization_error.is_some() {
                reasons.push(format!(
                    "system-effect recorder cgroup {} did not finalize without loss or error",
                    outcome.cgroup_id
                ));
            }
        }
        for outcome in &mut process_lifecycle {
            if let Err(error) = self
                .lifecycle_recorder
                .unregister_ancestor_root(outcome.cgroup_id, self.config.epoch)
            {
                append_error(
                    &mut outcome.finalization_error,
                    format!("unregister: {error:#}"),
                );
            } else {
                outcome.unregistered = true;
            }
            let healthy = outcome.health.as_ref().map_or(false, |health| {
                health.producer_barrier_complete
                    && health.drain_completed
                    && health.wal_durable
                    && health.event_dropped == 0
                    && health.userspace_failures == 0
                    && health.reasons.is_empty()
            });
            if !healthy || !outcome.unregistered || outcome.finalization_error.is_some() {
                reasons.push(format!(
                    "process-lifecycle recorder cgroup {} did not finalize without loss or error",
                    outcome.cgroup_id
                ));
            }
        }
        reasons.sort();
        reasons.dedup();
        let result = RecoveryRecorderFinalization {
            protocol_version: DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
            run_id: self.config.run_id.clone(),
            epoch: self.config.epoch,
            root_cgroup_ids: self.plan.root_cgroup_ids.clone(),
            system_effects,
            process_lifecycle,
            endpoint_capture_telemetry: Vec::new(),
            complete: reasons.is_empty(),
            reasons,
        };
        if self.config.object_resolution_mode
            == FileObjectResolutionMode::KernelObjectExpandedPartial
        {
            let health = SocketStateHealthArtifact::from_outcomes(
                &self.config.run_id,
                &self.manifest.boot_id,
                self.config.epoch,
                &self.plan.root_cgroup_ids,
                &result.system_effects,
            )?;
            write_json_compact_new(
                &self.output_directory.join(SOCKET_STATE_HEALTH_NAME),
                &health,
            )?;
        }
        sync_directory(&self.output_directory)?;
        Ok(result)
    }

    pub fn finish(
        mut self,
        command: FinishCommand,
    ) -> Result<(
        DeploymentObservationReport,
        ArtifactManifest,
        TerminalMessage,
    )> {
        self.protocol.accept_finish(&command)?;

        let pre_finish_barrier = assess_barrier(&self.manifest);
        let pre_finish_validation = IdentityAssessment::from_result(
            validate_against_live_procfs_for_phase(&self.manifest, RevalidationPhase::Closure),
        );
        require_barrier(&pre_finish_barrier, "pre-FINISH")?;
        if !pre_finish_validation.stable {
            bail!("deployment identity changed before recorder drain");
        }
        self.recorder.verify_ancestor_roots()?;
        self.lifecycle_recorder.verify_ancestor_roots()?;
        if read_boot_id()? != self.manifest.boot_id {
            bail!("target Linux boot identity changed before recorder drain");
        }
        let producer_barrier_complete = true;
        let system_drain_started = Instant::now();

        // inet_sock_set_state/tcp_destroy_sock are asynchronous with respect
        // to workload task exit.  Every producer root is now frozen; detach
        // those two global links once before any root drains or retires socket
        // owners.  The remaining task-bound hooks stay attached through S1.
        self.recorder
            .seal_socket_state_producers()
            .context("synchronously seal deployment TCP-state producers")?;

        let mut outcomes = Vec::with_capacity(self.plan.root_cgroup_ids.len());
        for cgroup_id in &self.plan.root_cgroup_ids {
            match self.recorder.finish_run(
                *cgroup_id,
                self.config.epoch,
                Duration::from_millis(self.config.drain_timeout_ms),
                producer_barrier_complete,
            ) {
                Ok(health) => outcomes.push(CgroupRecorderOutcome {
                    cgroup_id: *cgroup_id,
                    health: Some(health),
                    finalization_error: None,
                    unregistered: false,
                }),
                Err(error) => outcomes.push(CgroupRecorderOutcome {
                    cgroup_id: *cgroup_id,
                    health: None,
                    finalization_error: Some(format!("{error:#}")),
                    unregistered: false,
                }),
            }
        }
        let system_effects_duration_ns = duration_ns(
            system_drain_started.elapsed(),
            "system-effect producer seal and closing drain",
        )?;
        let lifecycle_drain_started = Instant::now();
        let mut lifecycle_outcomes = Vec::with_capacity(self.plan.root_cgroup_ids.len());
        for cgroup_id in &self.plan.root_cgroup_ids {
            match self.lifecycle_recorder.finish_run(
                *cgroup_id,
                self.config.epoch,
                Duration::from_millis(self.config.drain_timeout_ms),
                producer_barrier_complete,
            ) {
                Ok(health) => lifecycle_outcomes.push(CgroupLifecycleOutcome {
                    cgroup_id: *cgroup_id,
                    health: Some(health),
                    finalization_error: None,
                    unregistered: false,
                }),
                Err(error) => lifecycle_outcomes.push(CgroupLifecycleOutcome {
                    cgroup_id: *cgroup_id,
                    health: None,
                    finalization_error: Some(format!("{error:#}")),
                    unregistered: false,
                }),
            }
        }
        let process_lifecycle_duration_ns = duration_ns(
            lifecycle_drain_started.elapsed(),
            "process-lifecycle closing drain",
        )?;
        let closing_drain_telemetry =
            ClosingDrainTelemetry::new(system_effects_duration_ns, process_lifecycle_duration_ns)?;

        let recorder_drains_complete = outcomes.iter().all(|outcome| {
            outcome.finalization_error.is_none()
                && outcome
                    .health
                    .as_ref()
                    .map(|health| health.drain_completed)
                    .unwrap_or(false)
        }) && lifecycle_outcomes.iter().all(|outcome| {
            outcome.finalization_error.is_none()
                && outcome
                    .health
                    .as_ref()
                    .map(|health| health.drain_completed)
                    .unwrap_or(false)
        });
        if !recorder_drains_complete {
            bail!("refusing endpoint S1 capture before every recorder reaches a closed drain boundary");
        }

        // S1 is captured only after both recorder drains have completed while
        // the caller-owned roots remain frozen. Collector work runs in this
        // observer's cgroup and therefore adds no target hot-path cost.
        let (bpf_state_finish, bpf_s1_duration_ns) =
            if let Some(scope) = self.config.bpf_state_scope.as_ref() {
                let s0 = self
                    .bpf_state_s0
                    .as_ref()
                    .context("enabled BPF state confirmation has no S0 snapshot")?;
                let started = Instant::now();
                let s1 = capture_bpf_endpoint(
                    scope,
                    &self.bpf_state_exclusions,
                    &self.config.run_id,
                    self.config.epoch,
                    "S1",
                )
                .context("capture deployment BPF endpoint state S1")?;
                let capture_duration_ns = duration_ns(started.elapsed(), "BPF S1 capture")?;
                let verdict = compare_bpf_endpoints(s0, &s1)?;
                (Some((s1, verdict)), Some(capture_duration_ns))
            } else {
                if self.bpf_state_s0.is_some() || self.bpf_state_s0_digest.is_some() {
                    bail!("disabled BPF state confirmation unexpectedly contains S0 evidence");
                }
                (None, None)
            };
        let (filesystem_state_finish, filesystem_s1_duration_ns) = if let Some(scope) =
            self.config.filesystem_state_scope.as_ref()
        {
            let s0 = self
                .filesystem_state_s0
                .as_ref()
                .context("enabled filesystem state confirmation has no S0 snapshot")?;
            validate_filesystem_output_separation(scope, &self.output_directory)
                .context("revalidate filesystem/evidence separation at S1")?;
            let started = Instant::now();
            let s1 = capture_filesystem_endpoint(
                scope,
                &self.config.run_id,
                self.config.epoch,
                FilesystemSnapshotPhase::S1,
                self.filesystem_mount_namespace.as_ref(),
            )
            .context("capture deployment filesystem endpoint state S1")?;
            let capture_duration_ns = duration_ns(started.elapsed(), "filesystem S1 capture")?;
            let comparison = compare_filesystem_endpoints(s0, &s1)?;
            (Some((s1, comparison)), Some(capture_duration_ns))
        } else {
            if self.filesystem_state_s0.is_some() || self.filesystem_state_s0_digest.is_some() {
                bail!("disabled filesystem state confirmation unexpectedly contains S0 evidence");
            }
            (None, None)
        };
        let (linux_state_finish, linux_s1_duration_ns) = if let Some(bound) = &mut self.linux_state
        {
            let s0 = self
                .linux_state_s0
                .as_ref()
                .context("enabled Linux state confirmation has no S0 snapshot")?;
            let started = Instant::now();
            let retained = self
                .linux_state_namespaces
                .as_ref()
                .context("enabled Linux state confirmation has no retained namespaces")?;
            let s1 = capture_linux_state(
                &bound.scope,
                &CaptureRequest {
                    snapshot_id: format!("{}:linux-state:s1", self.config.run_id),
                    phase: SnapshotPhase::S1,
                },
                retained,
            )?;
            let capture_duration_ns = duration_ns(started.elapsed(), "Linux S1 capture")?;
            let comparison = compare_linux_state(s0, &s1)?;
            (Some((s1, comparison)), Some(capture_duration_ns))
        } else {
            if self.linux_state_s0.is_some() || self.linux_state_s0_digest.is_some() {
                bail!("disabled Linux state confirmation unexpectedly contains S0 evidence");
            }
            (None, None)
        };
        let s1_endpoint_capture_telemetry = EndpointCaptureTelemetry::new(
            bpf_s1_duration_ns,
            filesystem_s1_duration_ns,
            linux_s1_duration_ns,
        )?;
        let diagnostic_performance = DiagnosticPerformanceTelemetry::new(
            self.s0_endpoint_capture_telemetry.clone(),
            closing_drain_telemetry,
            s1_endpoint_capture_telemetry,
        );

        // Descendant churn is expected and remains covered by the kernel
        // ancestor predicate.  Closure therefore binds the still-frozen root
        // paths and the FD-pinned cgroup objects, not a stale procfs snapshot
        // of every leaf that happened to exist at READY.
        let closure_barrier = assess_barrier(&self.manifest);
        let closure_validation = IdentityAssessment::from_result(
            validate_against_live_procfs_for_phase(&self.manifest, RevalidationPhase::Closure),
        );
        require_barrier(&closure_barrier, "post-S1 closure")?;
        if !closure_validation.stable {
            bail!("deployment identity changed during endpoint S1 capture");
        }
        self.recorder.verify_ancestor_roots()?;
        self.lifecycle_recorder.verify_ancestor_roots()?;
        if read_boot_id()? != self.manifest.boot_id {
            bail!("target Linux boot identity changed during endpoint S1 capture");
        }
        let roots_frozen = pre_finish_barrier.all_roots_frozen && closure_barrier.all_roots_frozen;
        let root_identity_stable =
            roots_frozen && pre_finish_validation.stable && closure_validation.stable;

        for outcome in &mut outcomes {
            if outcome
                .health
                .as_ref()
                .map(|health| health.drain_completed)
                .unwrap_or(false)
            {
                match self
                    .recorder
                    .unregister_ancestor_root(outcome.cgroup_id, self.config.epoch)
                {
                    Ok(()) => outcome.unregistered = true,
                    Err(error) => append_error(
                        &mut outcome.finalization_error,
                        format!("unregister failed: {error:#}"),
                    ),
                }
            }
        }
        for outcome in &mut lifecycle_outcomes {
            if outcome
                .health
                .as_ref()
                .map(|health| health.drain_completed)
                .unwrap_or(false)
            {
                match self
                    .lifecycle_recorder
                    .unregister_ancestor_root(outcome.cgroup_id, self.config.epoch)
                {
                    Ok(()) => outcome.unregistered = true,
                    Err(error) => append_error(
                        &mut outcome.finalization_error,
                        format!("unregister failed: {error:#}"),
                    ),
                }
            }
        }
        outcomes.sort_by_key(|outcome| outcome.cgroup_id);
        lifecycle_outcomes.sort_by_key(|outcome| outcome.cgroup_id);
        let aggregate_health = aggregate_health(
            &self.plan.root_cgroup_ids,
            &outcomes,
            roots_frozen,
            root_identity_stable,
        )?;
        let aggregate_lifecycle_health =
            aggregate_lifecycle_health(&self.plan.root_cgroup_ids, &lifecycle_outcomes)?;
        let socket_state = if self.config.object_resolution_mode
            == FileObjectResolutionMode::KernelObjectExpandedPartial
        {
            let health = SocketStateHealthArtifact::from_outcomes(
                &self.config.run_id,
                &self.manifest.boot_id,
                self.config.epoch,
                &self.plan.root_cgroup_ids,
                &outcomes,
            )?;
            let health_digest = write_json_compact_new(
                &self.output_directory.join(SOCKET_STATE_HEALTH_NAME),
                &health,
            )?;
            Some(SocketStateReport::from_health(
                &health,
                health_digest.sha256,
            )?)
        } else {
            if outcomes.iter().any(|outcome| {
                outcome
                    .health
                    .as_ref()
                    .and_then(|health| health.socket_state.as_ref())
                    .is_some()
            }) {
                bail!("non-expanded object mode unexpectedly produced socket-state health");
            }
            None
        };

        let bpf_state = match bpf_state_finish {
            Some((s1, verdict)) => {
                let scope = self
                    .config
                    .bpf_state_scope
                    .as_ref()
                    .context("BPF state result has no configured scope")?;
                let s0 = self
                    .bpf_state_s0
                    .as_ref()
                    .context("BPF state result has no S0 snapshot")?;
                let s0_digest = self
                    .bpf_state_s0_digest
                    .as_ref()
                    .context("BPF state result has no committed S0 digest")?;
                let s1_digest =
                    write_json_compact_new(&self.output_directory.join(BPF_STATE_S1_FILE), &s1)?;
                let verdict_digest = write_json_compact_new(
                    &self.output_directory.join(BPF_STATE_VERDICT_FILE),
                    &verdict,
                )?;
                let contract_reasons = endpoint_contract_reasons(
                    &EndpointContractEvidence {
                        deployment_boot_id: &self.manifest.boot_id,
                        s0_boot_id: &s0.boot_id,
                        s1_boot_id: &s1.boot_id,
                        ready_barrier_complete: self.ready_barrier.all_roots_frozen,
                        ready_identity_stable: self.ready_validation.stable,
                        pre_finish_barrier_complete: pre_finish_barrier.all_roots_frozen,
                        pre_finish_identity_stable: pre_finish_validation.stable,
                        closure_barrier_complete: closure_barrier.all_roots_frozen,
                        closure_identity_stable: closure_validation.stable,
                        recorder_drains_complete,
                    },
                    &[],
                );
                Some(BpfStateReport::from_verdict(
                    scope,
                    &self.system_effect_recorder_exclusions,
                    &self.lifecycle_recorder_exclusions,
                    &verdict,
                    &BpfStateArtifactBindings {
                        s0_snapshot_id: &s0.snapshot_id,
                        s0_digest,
                        s1_snapshot_id: &s1.snapshot_id,
                        s1_digest: &s1_digest,
                        verdict_digest: &verdict_digest,
                    },
                    &contract_reasons,
                )?)
            }
            None => None,
        };
        let filesystem_state = match filesystem_state_finish {
            Some((s1, comparison)) => {
                let scope = self
                    .config
                    .filesystem_state_scope
                    .as_ref()
                    .context("filesystem state result has no configured scope")?;
                let s0 = self
                    .filesystem_state_s0
                    .as_ref()
                    .context("filesystem state result has no S0 snapshot")?;
                let s0_digest = self
                    .filesystem_state_s0_digest
                    .as_ref()
                    .context("filesystem state result has no committed S0 digest")?;
                let s1_digest = write_json_compact_new(
                    &self.output_directory.join(FILESYSTEM_STATE_S1_FILE),
                    &s1,
                )?;
                let comparison_digest = write_json_compact_new(
                    &self.output_directory.join(FILESYSTEM_STATE_COMPARISON_FILE),
                    &comparison,
                )?;
                let mut extra = filesystem_namespace_reasons(
                    s0,
                    &self.manifest.mount_namespace_ids,
                    self.filesystem_mount_namespace
                        .as_ref()
                        .map(RetainedNamespace::inode),
                    self.manifest.deployment_kind,
                );
                extra.extend(filesystem_namespace_reasons(
                    &s1,
                    &self.manifest.mount_namespace_ids,
                    self.filesystem_mount_namespace
                        .as_ref()
                        .map(RetainedNamespace::inode),
                    self.manifest.deployment_kind,
                ));
                let contract_reasons = endpoint_contract_reasons(
                    &EndpointContractEvidence {
                        deployment_boot_id: &self.manifest.boot_id,
                        s0_boot_id: &s0.boot_id,
                        s1_boot_id: &s1.boot_id,
                        ready_barrier_complete: self.ready_barrier.all_roots_frozen,
                        ready_identity_stable: self.ready_validation.stable,
                        pre_finish_barrier_complete: pre_finish_barrier.all_roots_frozen,
                        pre_finish_identity_stable: pre_finish_validation.stable,
                        closure_barrier_complete: closure_barrier.all_roots_frozen,
                        closure_identity_stable: closure_validation.stable,
                        recorder_drains_complete,
                    },
                    &extra,
                );
                Some(FilesystemStateReport::from_comparison(
                    scope,
                    &comparison,
                    s0_digest,
                    &s1_digest,
                    &comparison_digest,
                    &contract_reasons,
                )?)
            }
            None => None,
        };
        let linux_state = match linux_state_finish {
            Some((s1, comparison)) => {
                let bound = self
                    .linux_state
                    .as_ref()
                    .context("Linux state result has no bound scope")?;
                let drains_complete = !outcomes.iter().any(|outcome| {
                    !outcome
                        .health
                        .as_ref()
                        .map(|health| health.drain_completed)
                        .unwrap_or(false)
                }) && !lifecycle_outcomes.iter().any(|outcome| {
                    !outcome
                        .health
                        .as_ref()
                        .map(|health| health.drain_completed)
                        .unwrap_or(false)
                });
                let s1_digest =
                    write_json_compact_new(&self.output_directory.join(LINUX_STATE_S1_FILE), &s1)?;
                let comparison_digest = write_json_compact_new(
                    &self.output_directory.join(LINUX_STATE_COMPARISON_FILE),
                    &comparison,
                )?;
                let s0_digest = self
                    .linux_state_s0_digest
                    .as_ref()
                    .context("Linux state result has no committed S0 digest")?;
                let s0 = self
                    .linux_state_s0
                    .as_ref()
                    .context("Linux state result has no S0 snapshot")?;
                let mut namespace_reasons = retained_namespace_contract_reasons(bound, s0);
                namespace_reasons.extend(retained_namespace_contract_reasons(bound, &s1));
                namespace_reasons.extend(bound.forced_incomplete_reasons.iter().cloned());
                namespace_reasons.sort();
                namespace_reasons.dedup();
                let contract_reasons = confirmation_contract_reasons(
                    &namespace_reasons,
                    &self.manifest.boot_id,
                    s0,
                    &s1,
                    producer_barrier_complete,
                    roots_frozen && root_identity_stable,
                    drains_complete,
                );
                Some(LinuxStateReport::from_comparison(
                    &comparison,
                    s0_digest.sha256.clone(),
                    s1_digest.sha256,
                    comparison_digest.sha256,
                    &contract_reasons,
                )?)
            }
            None => None,
        };

        let mut report = DeploymentObservationReport {
            protocol_version: DEPLOYMENT_OBSERVER_PROTOCOL_VERSION,
            run_id: self.config.run_id.clone(),
            epoch: self.config.epoch,
            deployment: self.manifest.clone(),
            recorder_object_sha256: self.recorder_object_sha256.clone(),
            lifecycle_object_sha256: self.lifecycle_object_sha256.clone(),
            recorder_policy_sha256: self.recorder_policy_sha256.clone(),
            registration_cgroup_ids: self.plan.root_cgroup_ids.clone(),
            cgroup_scope_capability_sha256: self.cgroup_scope_capability_sha256.clone(),
            cgroup_scope_capability: self.cgroup_scope_capability.clone(),
            ready_barrier: self.ready_barrier.clone(),
            ready_validation: self.ready_validation.clone(),
            pre_finish_barrier: pre_finish_barrier.clone(),
            pre_finish_validation: pre_finish_validation.clone(),
            closure_barrier: closure_barrier.clone(),
            closure_validation: closure_validation.clone(),
            cgroup_outcomes: outcomes,
            aggregate_health,
            lifecycle_outcomes,
            aggregate_lifecycle_health,
            overall_evidence_status: AggregateEvidenceStatus::Incomplete,
            socket_state,
            bpf_state,
            filesystem_state,
            linux_state,
            diagnostic_performance: diagnostic_performance.clone(),
            kata_guest_entered: false,
            observation_boundary:
                "TARGET_LINUX_HOST_DIRECT_SYSCALLS_AND_DYNAMIC_CGROUP_ROOT_SUBTREES".to_owned(),
        };
        report.overall_evidence_status = overall_evidence_status(&report);
        report.validate()?;

        write_json_new(
            &self.output_directory.join(PRE_FINISH_BARRIER_FILE),
            &pre_finish_barrier,
        )?;
        write_json_new(
            &self.output_directory.join(PRE_FINISH_VALIDATION_FILE),
            &pre_finish_validation,
        )?;
        write_json_new(
            &self.output_directory.join(CLOSURE_BARRIER_FILE),
            &closure_barrier,
        )?;
        write_json_new(
            &self.output_directory.join(CLOSURE_VALIDATION_FILE),
            &closure_validation,
        )?;
        let report_digest = write_json_new(&self.output_directory.join(REPORT_FILE), &report)?;

        let mut artifacts = Vec::new();
        for name in [
            CLOSURE_BARRIER_FILE,
            CLOSURE_VALIDATION_FILE,
            CONTRACT_FILE,
            DEPLOYMENT_FILE,
            REPORT_FILE,
            PRE_FINISH_BARRIER_FILE,
            PRE_FINISH_VALIDATION_FILE,
            READY_BARRIER_FILE,
            READY_MESSAGE_FILE,
            READY_VALIDATION_FILE,
            EFFECT_JSONL_FILE,
            EFFECT_WAL_FILE,
            LIFECYCLE_JSONL_FILE,
            LIFECYCLE_WAL_FILE,
        ] {
            artifacts.push(digest_file(&self.output_directory.join(name), name)?);
        }
        if report.linux_state.is_some() {
            for name in [
                LINUX_STATE_COMPARISON_FILE,
                LINUX_STATE_S0_FILE,
                LINUX_STATE_S1_FILE,
            ] {
                artifacts.push(digest_file(&self.output_directory.join(name), name)?);
            }
        }
        if report.bpf_state.is_some() {
            for name in [BPF_STATE_S0_FILE, BPF_STATE_S1_FILE, BPF_STATE_VERDICT_FILE] {
                artifacts.push(digest_file(&self.output_directory.join(name), name)?);
            }
        }
        if report.filesystem_state.is_some() {
            for name in [
                FILESYSTEM_STATE_COMPARISON_FILE,
                FILESYSTEM_STATE_S0_FILE,
                FILESYSTEM_STATE_S1_FILE,
            ] {
                artifacts.push(digest_file(&self.output_directory.join(name), name)?);
            }
        }
        if report.socket_state.is_some() {
            for name in [
                SOCKET_STATE_HEALTH_NAME,
                SOCKET_STATE_JSONL_NAME,
                SOCKET_STATE_WAL_NAME,
            ] {
                artifacts.push(digest_file(&self.output_directory.join(name), name)?);
            }
        }
        artifacts.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        let committed_artifact_total_bytes = checked_artifact_total_bytes(&artifacts)?;
        let artifact_manifest = ArtifactManifest {
            protocol_version: DEPLOYMENT_OBSERVER_PROTOCOL_VERSION,
            run_id: self.config.run_id.clone(),
            epoch: self.config.epoch,
            deployment_scope_sha256: self.manifest.scope_sha256.clone(),
            cgroup_scope_capability_sha256: self.cgroup_scope_capability_sha256.clone(),
            // This is the conservative aggregate over the full domain vector,
            // not just the system-effect transport.
            evidence_status: report.overall_evidence_status,
            socket_state_status: report.socket_state.as_ref().map(|state| state.status),
            bpf_state_scope_sha256: report
                .bpf_state
                .as_ref()
                .map(|state| state.scope_sha256.clone()),
            bpf_state_verdict: report
                .bpf_state
                .as_ref()
                .map(|state| state.state_verdict.clone()),
            filesystem_state_scope_sha256: report
                .filesystem_state
                .as_ref()
                .map(|state| state.scope_sha256.clone()),
            filesystem_state_verdict: report
                .filesystem_state
                .as_ref()
                .map(|state| state.state_verdict),
            linux_state_scope_sha256: report
                .linux_state
                .as_ref()
                .map(|state| state.scope_sha256.clone()),
            linux_state_evidence_status: report
                .linux_state
                .as_ref()
                .map(|state| state.evidence_status),
            diagnostic_performance,
            committed_artifact_total_bytes,
            artifacts,
        };
        let artifact_manifest_digest = write_json_new(
            &self.output_directory.join(ARTIFACT_MANIFEST_FILE),
            &artifact_manifest,
        )?;
        sync_directory(&self.output_directory)?;
        self.protocol.mark_finished()?;
        let terminal = TerminalMessage {
            protocol_version: DEPLOYMENT_OBSERVER_PROTOCOL_VERSION,
            status: "FINISHED".to_owned(),
            run_id: self.config.run_id.clone(),
            evidence_status: evidence_status_name(report.overall_evidence_status).to_owned(),
            report_sha256: report_digest.sha256,
            artifact_manifest_sha256: artifact_manifest_digest.sha256,
        };
        Ok((report, artifact_manifest, terminal))
    }
}

pub fn run_stdio(config: DeploymentObserverConfig) -> Result<()> {
    if config.protocol_version == DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION {
        return crate::recovery_session::run_recovery_stdio(config);
    }
    let (mut session, ready) = DeploymentSession::prepare(config)?;
    emit_line(&ready)?;
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result =
            read_protocol_line(std::io::stdin().lock()).map_err(|error| format!("{error:#}"));
        let _ = sender.send(result);
    });
    let command = loop {
        match receiver.try_recv() {
            Ok(Ok(line)) => {
                let command: FinishCommand =
                    serde_json::from_slice(&line).context("parse FINISH command JSON")?;
                break command;
            }
            Ok(Err(error)) => bail!("read FINISH command: {error}"),
            Err(TryRecvError::Disconnected) => bail!("FINISH input reader terminated"),
            Err(TryRecvError::Empty) => {
                session.poll_once()?;
            }
        }
    };
    let (_, _, terminal) = session.finish(command)?;
    emit_line(&terminal)
}

fn require_barrier(barrier: &RootFreezeBarrier, phase: &str) -> Result<()> {
    if !barrier.all_roots_frozen {
        let failures = barrier
            .roots
            .iter()
            .filter(|root| !root.verified)
            .map(|root| {
                format!(
                    "{}: {}",
                    root.path,
                    root.error.as_deref().unwrap_or("not frozen")
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        bail!("{phase} cgroup freeze barrier is incomplete: {failures}");
    }
    Ok(())
}

fn assess_barrier(manifest: &DeploymentManifest) -> RootFreezeBarrier {
    match verify_frozen_roots(manifest) {
        Ok(barrier) => barrier,
        Err(error) => RootFreezeBarrier {
            checked_unix_ns: now_unix_ns(),
            method: "CGROUP_V2_ROOT_SUBTREE_FREEZE".to_owned(),
            all_roots_frozen: false,
            roots: manifest
                .root_cgroups
                .iter()
                .map(|root| RootFreezeIdentity {
                    path: root.path.clone(),
                    expected_cgroup_id: root.cgroup_id,
                    observed_cgroup_id: None,
                    freeze_requested: None,
                    frozen: None,
                    populated: None,
                    verified: false,
                    error: Some(format!("{error:#}")),
                })
                .collect(),
        },
    }
}

pub(crate) fn now_unix_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

pub(crate) fn random_nonce() -> Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/dev/urandom")
        .context("open /dev/urandom for FINISH challenge")?;
    let mut bytes = [0_u8; 32];
    file.read_exact(&mut bytes)
        .context("read FINISH challenge")?;
    Ok(hex::encode(bytes))
}

fn read_boot_id() -> Result<String> {
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("read target Linux boot ID")?;
    let value = value.trim().to_owned();
    if value.len() != 36 || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        bail!("target Linux boot ID is not canonical");
    }
    Ok(value)
}

fn validate_path(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > 4096 || value.contains('\0') || value.contains('\n') {
        bail!("{label} path is empty or unbounded");
    }
    let path = Path::new(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        bail!("{label} path must be absolute and lexically normalized");
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

fn duration_ns(duration: Duration, label: &str) -> Result<u64> {
    u64::try_from(duration.as_nanos())
        .with_context(|| format!("{label} exceeds the u64 nanosecond telemetry range"))
}

pub(crate) fn write_json_new<T: Serialize>(path: &Path, value: &T) -> Result<ArtifactDigest> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_bytes_new(path, &bytes)
}

pub(crate) fn write_json_compact_new<T: Serialize>(
    path: &Path,
    value: &T,
) -> Result<ArtifactDigest> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    write_bytes_new(path, &bytes)
}

pub(crate) fn write_json_canonical_new<T: Serialize>(
    path: &Path,
    value: &T,
) -> Result<ArtifactDigest> {
    write_bytes_new(path, &serde_json::to_vec(value)?)
}

fn write_bytes_new(path: &Path, bytes: &[u8]) -> Result<ArtifactDigest> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("create evidence artifact {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("artifact name is not UTF-8")?;
    Ok(ArtifactDigest {
        relative_path: name.to_owned(),
        size_bytes: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
    })
}

pub(crate) fn digest_file(path: &Path, relative_path: &str) -> Result<ArtifactDigest> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open evidence artifact {}", path.display()))?;
    let before = file.metadata()?;
    if !before.file_type().is_file() || before.nlink() != 1 {
        bail!("evidence artifact {relative_path} is not a singly-linked regular file");
    }
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
            .context("artifact size overflow")?;
        hasher.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    if before.len() != size
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        bail!("evidence artifact {relative_path} changed while hashing");
    }
    Ok(ArtifactDigest {
        relative_path: relative_path.to_owned(),
        size_bytes: size,
        sha256: hex::encode(hasher.finalize()),
    })
}

pub(crate) fn sync_directory(path: &Path) -> Result<()> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open evidence directory {}", path.display()))?
        .sync_all()
        .context("sync evidence directory")
}

fn append_error(slot: &mut Option<String>, error: String) {
    match slot {
        Some(existing) => {
            existing.push_str("; ");
            existing.push_str(&error);
        }
        None => *slot = Some(error),
    }
}

fn evidence_status_name(status: crate::AggregateEvidenceStatus) -> &'static str {
    match status {
        crate::AggregateEvidenceStatus::Complete => "COMPLETE",
        crate::AggregateEvidenceStatus::Incomplete => "INCOMPLETE",
        crate::AggregateEvidenceStatus::UnprovenNoEvents => "UNPROVEN_NO_EVENTS",
    }
}

pub(crate) fn emit_line<T: Serialize>(message: &T) -> Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer(&mut lock, message)?;
    lock.write_all(b"\n")?;
    lock.flush()?;
    Ok(())
}

pub(crate) fn read_protocol_line<R: BufRead>(mut reader: R) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            bail!("stdin reached EOF before FINISH");
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|index| index + 1)
            .unwrap_or(available.len());
        if line.len().saturating_add(take) > MAX_PROTOCOL_LINE_BYTES {
            bail!("FINISH protocol line exceeds {MAX_PROTOCOL_LINE_BYTES} bytes");
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if line.last() == Some(&b'\n') {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.is_empty() {
                bail!("FINISH protocol line is empty");
            }
            return Ok(line);
        }
    }
}
