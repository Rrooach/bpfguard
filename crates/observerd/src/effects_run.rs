// SPDX-License-Identifier: GPL-2.0-only

//! Standalone system-effect operation collection with an optional, explicitly
//! scoped BPF endpoint-state confirmer. Operation events remain history: they
//! are not reinterpreted as a state snapshot, durable-state diff, or rollback
//! proof.

use crate::{
    atomic_file, cgroup::ManagedCgroup, environment, input,
    object_resolution::ObjectResolutionMode, run,
};
use anyhow::{anyhow, bail, Context, Result};
use bpf_observer_comparator::compare;
use bpf_observer_filesystem_confirmer::{
    capture as capture_filesystem, compare as compare_filesystem, ActorContractStatus,
    ActorQuiescenceContract, CaptureRequest as FilesystemCaptureRequest, CausalAttributionStatus,
    CompletenessStatus as FilesystemCompletenessStatus, EndpointDifferenceStatus,
    FilesystemComparison, FilesystemScope, FilesystemVerdict,
    SnapshotPhase as FilesystemSnapshotPhase, FILESYSTEM_CONFIRMATION_DOMAIN,
    FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION, HARD_MAX_ACTOR_CONTRACT_JSON_BYTES,
    HARD_MAX_COMPARISON_JSON_BYTES, HARD_MAX_SCOPE_JSON_BYTES, HARD_MAX_SNAPSHOT_JSON_BYTES,
};
use bpf_observer_linux_state_confirmers::{
    capture as capture_linux_state, compare as compare_linux_state, encode_absolute_path,
    CaptureLimits as LinuxStateCaptureLimits, CaptureRequest as LinuxStateCaptureRequest,
    CompletenessStatus as LinuxCompletenessStatus, DomainComparison as LinuxDomainComparison,
    EndpointDifferenceStatus as LinuxEndpointDifferenceStatus, ProcessResidualScope,
    SnapshotPhase as LinuxStateSnapshotPhase, StateComparison as LinuxStateComparison,
    StateDomainComparisons as LinuxStateDomainComparisons, StateScope as LinuxStateScope,
    StateVerdict as LinuxStateVerdict, TerminalState as LinuxTerminalState, ValueEvidenceMode,
    HARD_MAX_COMPARISON_JSON_BYTES as HARD_MAX_LINUX_STATE_COMPARISON_JSON_BYTES,
    HARD_MAX_SCOPE_JSON_BYTES as HARD_MAX_LINUX_STATE_SCOPE_JSON_BYTES,
    HARD_MAX_SNAPSHOT_JSON_BYTES as HARD_MAX_LINUX_STATE_SNAPSHOT_JSON_BYTES,
    LINUX_STATE_CONFIRMATION_DOMAIN, LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
};
use bpf_observer_oracle::{capture, CaptureOptions};
use bpf_observer_schema::{
    ArtifactDigest, Attribution, ClaimScope, CompletenessStatus, ContractCheck, EvidenceHealth,
    ObjectExclusions, QuiescenceBasis, QuiescenceReport, QuiescenceStatus, RunStatus, Snapshot,
    StateVerdict, Verdict, MAX_MANIFEST_JSON_BYTES, MAX_SNAPSHOT_JSON_BYTES,
    MAX_VERDICT_JSON_BYTES, MAX_WORKLOAD_OUTPUT_BYTES,
};
use bpf_observer_system_effects::{
    coverage_gaps_for, describe_policy,
    lifecycle::{
        ProcessLifecycleRecorder, ProcessLifecycleStatus, PROCESS_LIFECYCLE_HEALTH_NAME,
        PROCESS_LIFECYCLE_JSONL_NAME, PROCESS_LIFECYCLE_SCHEMA_VERSION, PROCESS_LIFECYCLE_WAL_NAME,
    },
    policy_sha256,
    socket_state::{
        SocketStateProducerSeal, SocketStateStatus, SOCKET_STATE_HEALTH_NAME,
        SOCKET_STATE_JSONL_NAME, SOCKET_STATE_SCHEMA_VERSION, SOCKET_STATE_WAL_NAME,
    },
    AttributionContract, FileObjectResolutionMode, PolicyDescription, PolicyProfile,
    SystemEffectHealth, SystemEffectRecorder, TransportStatus, EFFECT_EVENT_SCHEMA_VERSION,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_millis(20);
const CLOSING_BARRIER_TIMEOUT: Duration = Duration::from_secs(2);
const FAILURE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const DRAIN_CHUNKS_PER_POLL: usize = 16;
const DRAIN_CHUNKS_AT_EOF: usize = 1024;
const MAX_WORKLOAD_ARGV_BYTES: usize = 1024 * 1024;
const MAX_SMALL_JSON_BYTES: u64 = 8 * 1024 * 1024;
const MAX_EFFECT_WAL_BYTES: u64 = 384 * 1024 * 1024;
const MAX_EFFECT_JSONL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_LIFECYCLE_WAL_BYTES: u64 = 264 * 1_000_000;
const MAX_LIFECYCLE_JSONL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SOCKET_STATE_WAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SOCKET_STATE_JSONL_BYTES: u64 = 256 * 1024 * 1024;

pub(crate) const EVIDENCE_KIND_V1: &str = "SYSTEM_EFFECT_OPERATION_STREAM_V1";
pub(crate) const EVIDENCE_KIND_FILESYSTEM_V2: &str =
    "SYSTEM_EFFECT_OPERATION_AND_FILESYSTEM_ENDPOINT_STATE_V2";
pub(crate) const EVIDENCE_KIND_SCOPED_STATE_V3: &str =
    "SYSTEM_EFFECT_OPERATION_AND_SCOPED_ENDPOINT_STATE_V3";

const MANIFEST_NAME: &str = "system-effects.manifest.json";
const POLICY_NAME: &str = "system-effects.policy.json";
const HEALTH_NAME: &str = "system-effects.health.json";
const WAL_NAME: &str = "system-effects.raw.bin";
const JSONL_NAME: &str = "system-effects.jsonl";
const STDOUT_NAME: &str = "workload.stdout";
const STDERR_NAME: &str = "workload.stderr";
pub(crate) const BPF_STATE_S0_NAME: &str = "bpf-state-s0.json";
pub(crate) const BPF_STATE_S1_NAME: &str = "bpf-state-s1.json";
pub(crate) const BPF_STATE_VERDICT_NAME: &str = "bpf-state-verdict.json";
pub(crate) const BPF_STATE_CONFIRMATION_PROTOCOL_VERSION: u32 = 1;
pub(crate) const BPF_STATE_CONFIRMATION_DOMAIN: &str =
    "FINAL_BPF_OBJECT_STATE_WITHIN_EXPLICIT_CLAIM_SCOPE";
pub(crate) const FILESYSTEM_STATE_S0_NAME: &str = "filesystem-state-s0.json";
pub(crate) const FILESYSTEM_STATE_S1_NAME: &str = "filesystem-state-s1.json";
pub(crate) const FILESYSTEM_STATE_COMPARISON_NAME: &str = "filesystem-state-comparison.json";
pub(crate) const FILESYSTEM_ACTOR_CONTRACT_NAME: &str = "filesystem-actor-contract.json";
pub(crate) const LINUX_STATE_S0_NAME: &str = "linux-state-s0.json";
pub(crate) const LINUX_STATE_S1_NAME: &str = "linux-state-s1.json";
pub(crate) const LINUX_STATE_COMPARISON_NAME: &str = "linux-state-comparison.json";
const BASE_FINAL_ARTIFACTS: [&str; 6] = [
    POLICY_NAME,
    HEALTH_NAME,
    WAL_NAME,
    JSONL_NAME,
    STDOUT_NAME,
    STDERR_NAME,
];

#[derive(Debug)]
pub struct ObserveRequest {
    pub recorder_object: PathBuf,
    pub expected_recorder_sha256: String,
    pub process_lifecycle_object: Option<PathBuf>,
    pub expected_process_lifecycle_sha256: Option<String>,
    pub output_dir: PathBuf,
    pub cgroup_root: PathBuf,
    pub run_id: Option<String>,
    pub run_epoch: u64,
    pub profile: PolicyProfile,
    pub timeout_ms: u64,
    pub drain_timeout_ms: u64,
    pub object_resolution_mode: ObjectResolutionMode,
    pub allow_incomplete_transport: bool,
    /// Optional JSON ClaimScope for BPF object S0/S1 confirmation. Without
    /// this explicit opt-in, observe-effects retains its operation-only path.
    pub bpf_state_scope: Option<PathBuf>,
    /// Optional explicit filesystem endpoint scope. This confirmer is fully
    /// disabled when the path is absent, preserving the recorder hot path.
    pub filesystem_state_scope: Option<PathBuf>,
    /// Optional caller-supplied exclusive-writer/quiescence claim. It is
    /// useful only with `filesystem_state_scope` and is copied into the closed
    /// artifact set for exact verification; this process does not authenticate
    /// the claim's issuer.
    pub filesystem_actor_contract: Option<PathBuf>,
    /// Optional explicit sysctl/mount/network/module state scope.
    pub linux_state_scope: Option<PathBuf>,
    /// Inject a residual-process scope derived from the actual run cgroup.
    pub confirm_process_residual: bool,
    pub workload: Vec<OsString>,
}

#[derive(Debug, Serialize)]
pub struct ObserveOutcome {
    pub schema_version: u32,
    pub run_id: String,
    pub run_epoch: u64,
    pub workload_exit_code: Option<i32>,
    pub workload_signal: Option<i32>,
    pub transport_status: TransportStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_lifecycle_status: Option<ProcessLifecycleStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket_state_status: Option<SocketStateStatus>,
    pub attribution_contract: AttributionContract,
    pub operation_events_are_state_diff: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bpf_state_verdict: Option<StateVerdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesystem_endpoint_difference: Option<EndpointDifferenceStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesystem_state_verdict: Option<FilesystemVerdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesystem_state_completeness: Option<FilesystemCompletenessStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesystem_actor_contract_status: Option<ActorContractStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesystem_actor_contract_trust: Option<FilesystemActorContractTrust>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesystem_causal_attribution: Option<CausalAttributionStatus>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub filesystem_limitations: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux_state_scope_sha256: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub linux_state_limitations: Vec<String>,
    pub state_domains: SystemStateDomainVector,
    pub output_dir: String,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FilesystemActorContractTrust {
    NotProvided,
    ExternalExactInputNotAuthenticatedByObserver,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DomainStateVerdict {
    ChangedWithinScope,
    UnchangedWithinScope,
    Inconclusive,
    NotConfirmed,
    NotConfirmable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemStateDomainVector {
    pub filesystem: DomainStateVerdict,
    pub bpf: DomainStateVerdict,
    pub network_config: DomainStateVerdict,
    pub sysctl: DomainStateVerdict,
    pub mounts: DomainStateVerdict,
    pub modules: DomainStateVerdict,
    pub process_residual: DomainStateVerdict,
    pub keyrings: DomainStateVerdict,
    pub remote_network_effect: DomainStateVerdict,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum EffectRunStatus {
    Running,
    Finalized,
    Failed,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyArtifact {
    schema_version: u32,
    profile: PolicyProfile,
    /// SHA-256 of the compact JSON encoding of `entries`, in entry order.
    policy_sha256: String,
    entries: Vec<PolicyDescription>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct CoverageDescription {
    attribution_scope: &'static str,
    event_semantics: &'static str,
    operation_events_are_state_diff: bool,
    durable_state_change_proven: bool,
    rollback_completeness_proven: bool,
    workload_privilege_isolation_enforced: bool,
    evidence_write_isolation_enforced: bool,
    coverage_status: &'static str,
    object_resolution_status: &'static str,
    gaps: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BpfStateConfirmation {
    pub protocol_version: u32,
    pub confirmation_domain: &'static str,
    pub scope: ClaimScope,
    pub observer_exclusions: ObjectExclusions,
    pub s0_artifact: &'static str,
    pub s1_artifact: &'static str,
    pub verdict_artifact: &'static str,
    pub state_verdict: StateVerdict,
    pub state_completeness: CompletenessStatus,
    pub evidence_status: CompletenessStatus,
    pub attribution: Attribution,
    pub operation_events_are_state_diff: bool,
    pub unchanged_verdict_authorized: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FilesystemStateConfirmation {
    pub protocol_version: u32,
    pub confirmation_domain: &'static str,
    pub scope_sha256: String,
    pub s0_artifact: &'static str,
    pub s1_artifact: &'static str,
    pub comparison_artifact: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_contract_artifact: Option<&'static str>,
    pub endpoint_difference: EndpointDifferenceStatus,
    pub state_verdict: FilesystemVerdict,
    pub state_completeness: FilesystemCompletenessStatus,
    pub actor_contract_status: ActorContractStatus,
    pub causal_attribution_status: CausalAttributionStatus,
    pub actor_contract_authenticated_by_observer: bool,
    pub operation_events_are_state_diff: bool,
    pub atomic_with_other_confirmation_domains: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxStateConfirmation {
    pub protocol_version: u32,
    pub confirmation_domain: &'static str,
    pub scope_sha256: String,
    pub s0_artifact: &'static str,
    pub s1_artifact: &'static str,
    pub comparison_artifact: &'static str,
    pub auto_process_residual_bound: bool,
    pub domains: LinuxStateDomainComparisons,
    pub operation_events_are_state_diff: bool,
    pub atomic_with_other_confirmation_domains: bool,
    pub whole_linux_unchanged_authorized: bool,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct EffectsManifest {
    schema_version: u32,
    evidence_kind: &'static str,
    run_id: String,
    run_epoch: u64,
    run_status: EffectRunStatus,
    started_unix_ns: u128,
    finalized_unix_ns: Option<u128>,
    cgroup_path: String,
    cgroup_id: u64,
    workload: Vec<String>,
    workload_exit_code: Option<i32>,
    workload_signal: Option<i32>,
    workload_stdout_truncated: bool,
    workload_stderr_truncated: bool,
    policy_profile: PolicyProfile,
    object_resolution_mode: ObjectResolutionMode,
    policy_sha256: String,
    policy_entry_count: usize,
    policy_artifact: &'static str,
    expected_recorder_object_sha256: String,
    loaded_recorder_object_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_lifecycle: Option<ProcessLifecycleEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    socket_state: Option<SocketStateEvidence>,
    kernel_release: String,
    boot_id: String,
    observer_version: &'static str,
    source_commit: Option<&'static str>,
    cgroup_frozen_at_close: bool,
    transport_status: Option<TransportStatus>,
    attribution_contract: AttributionContract,
    coverage: CoverageDescription,
    #[serde(skip_serializing_if = "Option::is_none")]
    bpf_state_confirmation: Option<BpfStateConfirmation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filesystem_state_confirmation: Option<FilesystemStateConfirmation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    linux_state_confirmation: Option<LinuxStateConfirmation>,
    artifacts: BTreeMap<String, ArtifactDigest>,
    failure: Option<String>,
    notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ProcessLifecycleEvidence {
    protocol_version: u32,
    expected_object_sha256: String,
    loaded_object_sha256: String,
    observer_exclusions: ObjectExclusions,
    wal_artifact: &'static str,
    jsonl_artifact: &'static str,
    health_artifact: &'static str,
    status: ProcessLifecycleStatus,
    event_published: u64,
    event_dropped: u64,
    task_read_failed: u64,
    lineage: Option<bpf_observer_system_effects::lifecycle::ProcessLineageSummary>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct SocketStateEvidence {
    protocol_version: u32,
    wal_artifact: &'static str,
    jsonl_artifact: &'static str,
    health_artifact: &'static str,
    status: SocketStateStatus,
    event_published: u64,
    event_dropped: u64,
    destroy_events_persisted: u64,
    owners_retired_at_barrier: u64,
    async_producer_seal: SocketStateProducerSeal,
}

/// Observe selected native syscall operations from one newly-created cgroup.
///
/// The returned success only means the collection lifecycle finalized.  The
/// caller must inspect `transport_status`; even COMPLETE transport remains
/// partial operation evidence and is never a state-diff verdict.
pub fn observe(request: ObserveRequest) -> Result<ObserveOutcome> {
    validate_request(&request)?;
    let bpf_state_scope = load_bpf_state_scope(request.bpf_state_scope.as_deref())?;
    let filesystem_state_scope =
        load_filesystem_state_scope(request.filesystem_state_scope.as_deref())?;
    let filesystem_actor_contract =
        load_filesystem_actor_contract(request.filesystem_actor_contract.as_deref())?;
    let linux_state_base_scope = load_linux_state_scope(request.linux_state_scope.as_deref())?;
    if request.confirm_process_residual
        && linux_state_base_scope
            .as_ref()
            .and_then(|scope| scope.process_residual.as_ref())
            .is_some()
    {
        bail!("--confirm-process-residual cannot override process_residual in --linux-state-scope");
    }
    let linux_state_requested =
        linux_state_base_scope.is_some() || request.confirm_process_residual;
    if filesystem_actor_contract.is_some() && filesystem_state_scope.is_none() {
        bail!("filesystem actor contract requires --filesystem-state-scope");
    }
    let run_id = request.run_id.clone().unwrap_or(environment::new_run_id()?);
    run::validate_run_id(&run_id)?;
    if let Some(scope) = filesystem_state_scope.as_ref() {
        validate_filesystem_output_separation(scope, &request.output_dir)?;
        if let Some(contract) = filesystem_actor_contract.as_ref() {
            validate_filesystem_actor_binding(contract, scope, &run_id, request.run_epoch)?;
        }
    }
    let workload = workload_strings(&request.workload)?;
    let policy_entries = describe_policy(request.profile).context("describe effect policy")?;
    let expected_policy_sha256 = policy_sha256(request.profile).context("hash effect policy")?;
    let kernel_release = environment::kernel_release()?;
    let boot_id = environment::boot_id()?;

    prepare_output_directory(&request.output_dir)?;
    if let Some(scope) = filesystem_state_scope.as_ref() {
        validate_filesystem_output_separation(scope, &request.output_dir)?;
    }
    let started_unix_ns = environment::now_unix_ns();
    let mut manifest = EffectsManifest {
        schema_version: EFFECT_EVENT_SCHEMA_VERSION,
        evidence_kind: if linux_state_requested {
            EVIDENCE_KIND_SCOPED_STATE_V3
        } else if filesystem_state_scope.is_some() {
            EVIDENCE_KIND_FILESYSTEM_V2
        } else {
            EVIDENCE_KIND_V1
        },
        run_id: run_id.clone(),
        run_epoch: request.run_epoch,
        run_status: EffectRunStatus::Running,
        started_unix_ns,
        finalized_unix_ns: None,
        cgroup_path: request.cgroup_root.join(&run_id).display().to_string(),
        cgroup_id: 0,
        workload,
        workload_exit_code: None,
        workload_signal: None,
        workload_stdout_truncated: false,
        workload_stderr_truncated: false,
        policy_profile: request.profile,
        object_resolution_mode: request.object_resolution_mode,
        policy_sha256: expected_policy_sha256.clone(),
        policy_entry_count: policy_entries.len(),
        policy_artifact: POLICY_NAME,
        expected_recorder_object_sha256: request.expected_recorder_sha256.clone(),
        loaded_recorder_object_sha256: None,
        process_lifecycle: None,
        socket_state: None,
        kernel_release,
        boot_id: boot_id.clone(),
        observer_version: env!("CARGO_PKG_VERSION"),
        source_commit: option_env!("BPF_OBSERVER_SOURCE_COMMIT"),
        cgroup_frozen_at_close: false,
        transport_status: None,
        attribution_contract: AttributionContract::direct_v1(),
        coverage: initial_coverage(request.profile, request.object_resolution_mode),
        bpf_state_confirmation: None,
        filesystem_state_confirmation: None,
        linux_state_confirmation: None,
        artifacts: BTreeMap::new(),
        failure: None,
        notes: vec![
            "operation attempts/results are diagnostic history, not proof of a durable state change"
                .to_owned(),
            "this independent artifact set does not alter the BPF-state observe/verify-run contract"
                .to_owned(),
            "the standalone launcher preserves the caller's uid, gid, and capabilities; use an external sandbox for privilege separation"
                .to_owned(),
        ],
    };
    let manifest_path = request.output_dir.join(MANIFEST_NAME);
    atomic_file::write_json_atomic(&manifest_path, &manifest)?;

    let policy_artifact = PolicyArtifact {
        schema_version: EFFECT_EVENT_SCHEMA_VERSION,
        profile: request.profile,
        policy_sha256: expected_policy_sha256,
        entries: policy_entries,
    };
    let mut cgroup: Option<ManagedCgroup> = None;
    let result = (|| -> Result<ObserveOutcome> {
        let mut recorder = SystemEffectRecorder::open(
            &request.recorder_object,
            &request.expected_recorder_sha256,
            &request.output_dir,
            &run_id,
            &boot_id,
            request.profile,
            recorder_resolution_mode(request.object_resolution_mode),
        )
        .context("load system-effect recorder")?;
        if recorder.policy_sha256() != manifest.policy_sha256.as_str() {
            bail!("loaded recorder policy digest changed after preflight");
        }
        let mut lifecycle = match (
            request.process_lifecycle_object.as_deref(),
            request.expected_process_lifecycle_sha256.as_deref(),
        ) {
            (Some(object), Some(expected_sha256)) => Some(
                ProcessLifecycleRecorder::open(
                    object,
                    expected_sha256,
                    &request.output_dir,
                    &run_id,
                    &boot_id,
                )
                .context("load process-lifecycle recorder")?,
            ),
            (None, None) => None,
            _ => unreachable!("validate_request enforces lifecycle object/digest pairing"),
        };
        let lifecycle_exclusions = lifecycle
            .as_ref()
            .map(ProcessLifecycleRecorder::object_exclusions)
            .transpose()?
            .unwrap_or_default();
        let recorder_exclusions = if let Some(scope) = bpf_state_scope.as_ref() {
            let mut exclusions = recorder.object_exclusions()?;
            merge_exclusions(&mut exclusions, &lifecycle_exclusions);
            bpf_observer_oracle::validate_claim_scope_exclusions(scope, &exclusions)
                .context("validate BPF state scope against recorder-owned exclusions")?;
            exclusions
        } else {
            ObjectExclusions::default()
        };
        manifest.loaded_recorder_object_sha256 = Some(recorder.object_sha256().to_owned());
        atomic_file::write_json_atomic(&request.output_dir.join(POLICY_NAME), &policy_artifact)?;

        cgroup = Some(ManagedCgroup::create(&request.cgroup_root, &run_id)?);
        let active_cgroup = cgroup.as_mut().expect("cgroup was just installed");
        manifest.cgroup_path = active_cgroup.path().display().to_string();
        manifest.cgroup_id = active_cgroup.id();
        atomic_file::write_json_atomic(&manifest_path, &manifest)?;

        recorder
            .register_run(active_cgroup.id(), request.run_epoch)
            .context("register system-effect run")?;
        if let Some(lifecycle) = lifecycle.as_mut() {
            lifecycle
                .register_run(active_cgroup.id(), request.run_epoch)
                .context("register process-lifecycle run")?;
        }
        let linux_state_scope = effective_linux_state_scope(
            linux_state_base_scope.as_ref(),
            request.confirm_process_residual,
            active_cgroup.path(),
            active_cgroup.id(),
        )?;
        let linux_state_s0 = if let Some(scope) = linux_state_scope.as_ref() {
            let snapshot = capture_linux_state(
                scope,
                &LinuxStateCaptureRequest {
                    snapshot_id: linux_state_snapshot_id(&run_id, request.run_epoch, "S0"),
                    phase: LinuxStateSnapshotPhase::S0,
                },
            )
            .context("capture optional Linux endpoint state S0")?;
            atomic_file::write_json_atomic(
                &request.output_dir.join(LINUX_STATE_S0_NAME),
                &snapshot,
            )?;
            Some(snapshot)
        } else {
            None
        };
        let bpf_state_s0 = if let Some(scope) = bpf_state_scope.as_ref() {
            let options = bpf_capture_options(&run_id, "S0", &recorder_exclusions);
            let snapshot = capture(scope, &options).context("capture optional BPF state S0")?;
            atomic_file::write_json_atomic(&request.output_dir.join(BPF_STATE_S0_NAME), &snapshot)?;
            Some(snapshot)
        } else {
            None
        };
        if let Some(contract) = filesystem_actor_contract.as_ref() {
            atomic_file::write_json_atomic(
                &request.output_dir.join(FILESYSTEM_ACTOR_CONTRACT_NAME),
                contract,
            )?;
        }
        let filesystem_state_s0 = if let Some(scope) = filesystem_state_scope.as_ref() {
            validate_filesystem_output_separation(scope, &request.output_dir)
                .context("revalidate filesystem/output separation at S0")?;
            let snapshot = capture_filesystem(
                scope,
                &FilesystemCaptureRequest {
                    snapshot_id: filesystem_snapshot_id(&run_id, request.run_epoch, "S0"),
                    phase: FilesystemSnapshotPhase::S0,
                },
            )
            .context("capture optional filesystem state S0")?;
            atomic_file::write_json_atomic(
                &request.output_dir.join(FILESYSTEM_STATE_S0_NAME),
                &snapshot,
            )?;
            Some(snapshot)
        } else {
            None
        };
        let (status, output) = execute_workload(
            &mut recorder,
            lifecycle.as_mut(),
            active_cgroup,
            &request.workload,
            &request.output_dir,
            Duration::from_millis(request.timeout_ms),
        )?;
        manifest.workload_exit_code = status.code();
        manifest.workload_signal = status.signal();
        manifest.workload_stdout_truncated = output.stdout_truncated;
        manifest.workload_stderr_truncated = output.stderr_truncated;

        // Empty + frozen is the producer-side barrier. A task moved into this
        // exact cgroup after the check cannot execute before event draining.
        active_cgroup
            .freeze_empty(CLOSING_BARRIER_TIMEOUT)
            .context("freeze empty system-effect cgroup")?;
        manifest.cgroup_frozen_at_close = true;
        recorder
            .seal_socket_state_producers()
            .context("synchronously seal asynchronous TCP-state producers")?;
        let health = recorder
            .finish_run(
                active_cgroup.id(),
                request.run_epoch,
                Duration::from_millis(request.drain_timeout_ms),
                true,
            )
            .context("drain system-effect recorder")?;
        atomic_file::write_json_atomic(&request.output_dir.join(HEALTH_NAME), &health)?;
        if let Some(socket_health) = health.socket_state.as_ref() {
            atomic_file::write_json_atomic(
                &request.output_dir.join(SOCKET_STATE_HEALTH_NAME),
                socket_health,
            )?;
            manifest.socket_state = Some(SocketStateEvidence {
                protocol_version: SOCKET_STATE_SCHEMA_VERSION,
                wal_artifact: SOCKET_STATE_WAL_NAME,
                jsonl_artifact: SOCKET_STATE_JSONL_NAME,
                health_artifact: SOCKET_STATE_HEALTH_NAME,
                status: socket_health.status,
                event_published: socket_health.event_published,
                event_dropped: socket_health.event_dropped,
                destroy_events_persisted: socket_health.destroy_events_persisted,
                owners_retired_at_barrier: socket_health.owners_retired_at_barrier,
                async_producer_seal: socket_health.async_producer_seal,
            });
        }
        apply_health(&mut manifest, &health);
        if !health.drain_completed {
            bail!("system-effect recorder did not reach a closed drain boundary");
        }
        if health.transport_status != TransportStatus::Complete
            && !request.allow_incomplete_transport
        {
            bail!(
                "system-effect transport is {:?}; pass --allow-incomplete-transport only for diagnostic collection",
                health.transport_status
            );
        }
        let lifecycle_health = lifecycle
            .as_mut()
            .map(|lifecycle| {
                lifecycle.finish_run(
                    active_cgroup.id(),
                    request.run_epoch,
                    Duration::from_millis(request.drain_timeout_ms),
                    true,
                )
            })
            .transpose()
            .context("drain process-lifecycle recorder")?;
        if let Some(lifecycle_health) = lifecycle_health.as_ref() {
            atomic_file::write_json_atomic(
                &request.output_dir.join(PROCESS_LIFECYCLE_HEALTH_NAME),
                lifecycle_health,
            )?;
            if !lifecycle_health.drain_completed {
                bail!("process-lifecycle recorder did not reach a closed drain boundary");
            }
            if matches!(
                lifecycle_health.status,
                ProcessLifecycleStatus::Incomplete | ProcessLifecycleStatus::UnprovenNoEvents
            ) && !request.allow_incomplete_transport
            {
                bail!(
                    "process-lifecycle transport is {:?}; pass --allow-incomplete-transport only for diagnostic collection",
                    lifecycle_health.status
                );
            }
            let lifecycle_recorder = lifecycle
                .as_ref()
                .expect("lifecycle health requires a loaded recorder");
            manifest.process_lifecycle = Some(ProcessLifecycleEvidence {
                protocol_version: PROCESS_LIFECYCLE_SCHEMA_VERSION,
                expected_object_sha256: request
                    .expected_process_lifecycle_sha256
                    .clone()
                    .expect("expanded request has lifecycle digest"),
                loaded_object_sha256: lifecycle_recorder.object_sha256().to_owned(),
                observer_exclusions: lifecycle_exclusions,
                wal_artifact: PROCESS_LIFECYCLE_WAL_NAME,
                jsonl_artifact: PROCESS_LIFECYCLE_JSONL_NAME,
                health_artifact: PROCESS_LIFECYCLE_HEALTH_NAME,
                status: lifecycle_health.status,
                event_published: lifecycle_health.event_published,
                event_dropped: lifecycle_health.event_dropped,
                task_read_failed: lifecycle_health.task_read_failed,
                lineage: lifecycle_health.lineage.clone(),
            });
        }

        let linux_state_comparison = if let (Some(scope), Some(s0)) =
            (linux_state_scope.as_ref(), linux_state_s0.as_ref())
        {
            // Unlike operation events, this runs only at the endpoint. The
            // tracked cgroup is empty, frozen, still registered, and the ring
            // transport has reached its closed drain boundary.
            let s1 = capture_linux_state(
                scope,
                &LinuxStateCaptureRequest {
                    snapshot_id: linux_state_snapshot_id(&run_id, request.run_epoch, "S1"),
                    phase: LinuxStateSnapshotPhase::S1,
                },
            )
            .context("capture optional Linux endpoint state S1")?;
            atomic_file::write_json_atomic(&request.output_dir.join(LINUX_STATE_S1_NAME), &s1)?;
            let comparison =
                compare_linux_state(s0, &s1).context("compare optional Linux endpoint state")?;
            if request.confirm_process_residual {
                validate_auto_process_residual(&comparison)?;
            }
            atomic_file::write_json_atomic(
                &request.output_dir.join(LINUX_STATE_COMPARISON_NAME),
                &comparison,
            )?;
            manifest.linux_state_confirmation = Some(linux_state_confirmation_summary(
                scope,
                &comparison,
                request.confirm_process_residual,
            )?);
            manifest.notes.push(
                "Linux endpoint confirmation is an explicit per-domain vector; it never authorizes a whole-Linux unchanged claim"
                    .to_owned(),
            );
            Some(comparison)
        } else {
            None
        };

        if let (Some(scope), Some(s0)) = (bpf_state_scope.as_ref(), bpf_state_s0.as_ref()) {
            // The cgroup is still empty, frozen, and registered here. This is
            // the endpoint-state boundary; recorder teardown happens only
            // after S1 has excluded the still-live recorder objects.
            let options = bpf_capture_options(&run_id, "S1", &recorder_exclusions);
            let s1 = capture(scope, &options).context("capture optional BPF state S1")?;
            atomic_file::write_json_atomic(&request.output_dir.join(BPF_STATE_S1_NAME), &s1)?;
            let verdict = compare_bpf_state_endpoints(s0, &s1)
                .context("compare optional BPF state endpoints")?;
            atomic_file::write_json_atomic(
                &request.output_dir.join(BPF_STATE_VERDICT_NAME),
                &verdict,
            )?;
            manifest.bpf_state_confirmation = Some(BpfStateConfirmation {
                protocol_version: BPF_STATE_CONFIRMATION_PROTOCOL_VERSION,
                confirmation_domain: BPF_STATE_CONFIRMATION_DOMAIN,
                scope: scope.clone(),
                observer_exclusions: recorder_exclusions,
                s0_artifact: BPF_STATE_S0_NAME,
                s1_artifact: BPF_STATE_S1_NAME,
                verdict_artifact: BPF_STATE_VERDICT_NAME,
                state_verdict: verdict.state_verdict.clone(),
                state_completeness: verdict.state_completeness.status.clone(),
                evidence_status: verdict.evidence_status.status.clone(),
                attribution: verdict.attribution,
                operation_events_are_state_diff: false,
                unchanged_verdict_authorized: false,
            });
            manifest.notes.push(
                "optional S0/S1 confirmation covers final BPF object state only; system-effect events remain operation history"
                    .to_owned(),
            );
        }
        let mut filesystem_limitations = Vec::new();
        if let (Some(scope), Some(s0)) = (
            filesystem_state_scope.as_ref(),
            filesystem_state_s0.as_ref(),
        ) {
            // This is sequential with any BPF S1, not an atomic whole-system
            // snapshot. The workload cgroup remains empty, frozen, registered,
            // and fully drained throughout both endpoint captures.
            validate_filesystem_output_separation(scope, &request.output_dir)
                .context("revalidate filesystem/output separation at S1")?;
            let s1 = capture_filesystem(
                scope,
                &FilesystemCaptureRequest {
                    snapshot_id: filesystem_snapshot_id(&run_id, request.run_epoch, "S1"),
                    phase: FilesystemSnapshotPhase::S1,
                },
            )
            .context("capture optional filesystem state S1")?;
            atomic_file::write_json_atomic(
                &request.output_dir.join(FILESYSTEM_STATE_S1_NAME),
                &s1,
            )?;
            let comparison = compare_filesystem(s0, &s1, filesystem_actor_contract.as_ref())
                .context("compare optional filesystem state endpoints")?;
            filesystem_limitations = comparison.limitations.clone();
            atomic_file::write_json_atomic(
                &request.output_dir.join(FILESYSTEM_STATE_COMPARISON_NAME),
                &comparison,
            )?;
            manifest.filesystem_state_confirmation = Some(filesystem_confirmation_summary(
                scope,
                &comparison,
                filesystem_actor_contract.is_some(),
            )?);
            manifest.notes.push(
                "filesystem S0/S1 confirms only the explicit path-tree v1 field model; captures are sequential and system-effect events remain separate operation history"
                    .to_owned(),
            );
        }
        recorder
            .unregister_run(active_cgroup.id(), request.run_epoch)
            .context("unregister system-effect run")?;
        if let Some(lifecycle) = lifecycle.as_mut() {
            lifecycle
                .unregister_run(active_cgroup.id(), request.run_epoch)
                .context("unregister process-lifecycle run")?;
        }
        drop(recorder);
        drop(lifecycle);

        active_cgroup
            .cleanup()
            .context("remove empty system-effect cgroup")?;
        manifest.artifacts = collect_artifacts(
            &request.output_dir,
            manifest.bpf_state_confirmation.is_some(),
            manifest.filesystem_state_confirmation.is_some(),
            filesystem_actor_contract.is_some(),
            manifest.linux_state_confirmation.is_some(),
            manifest.process_lifecycle.is_some(),
        )?;
        manifest.run_status = EffectRunStatus::Finalized;
        manifest.finalized_unix_ns = Some(environment::now_unix_ns().max(started_unix_ns));
        let outcome = ObserveOutcome {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            run_id: run_id.clone(),
            run_epoch: request.run_epoch,
            workload_exit_code: status.code(),
            workload_signal: status.signal(),
            transport_status: health.transport_status,
            process_lifecycle_status: lifecycle_health.as_ref().map(|health| health.status),
            socket_state_status: health.socket_state.as_ref().map(|health| health.status),
            attribution_contract: manifest.attribution_contract,
            operation_events_are_state_diff: false,
            bpf_state_verdict: manifest
                .bpf_state_confirmation
                .as_ref()
                .map(|confirmation| confirmation.state_verdict.clone()),
            filesystem_endpoint_difference: manifest
                .filesystem_state_confirmation
                .as_ref()
                .map(|confirmation| confirmation.endpoint_difference),
            filesystem_state_verdict: manifest
                .filesystem_state_confirmation
                .as_ref()
                .map(|confirmation| confirmation.state_verdict),
            filesystem_state_completeness: manifest
                .filesystem_state_confirmation
                .as_ref()
                .map(|confirmation| confirmation.state_completeness),
            filesystem_actor_contract_status: manifest
                .filesystem_state_confirmation
                .as_ref()
                .map(|confirmation| confirmation.actor_contract_status),
            filesystem_actor_contract_trust: manifest.filesystem_state_confirmation.as_ref().map(
                |confirmation| {
                    if confirmation.actor_contract_artifact.is_some() {
                        FilesystemActorContractTrust::ExternalExactInputNotAuthenticatedByObserver
                    } else {
                        FilesystemActorContractTrust::NotProvided
                    }
                },
            ),
            filesystem_causal_attribution: manifest
                .filesystem_state_confirmation
                .as_ref()
                .map(|confirmation| confirmation.causal_attribution_status),
            filesystem_limitations,
            linux_state_scope_sha256: linux_state_comparison
                .as_ref()
                .map(|comparison| comparison.scope_sha256.clone()),
            linux_state_limitations: linux_state_comparison
                .as_ref()
                .map(|comparison| comparison.limitations.clone())
                .unwrap_or_default(),
            state_domains: system_state_domain_vector_with_linux(
                manifest
                    .bpf_state_confirmation
                    .as_ref()
                    .map(|confirmation| &confirmation.state_verdict),
                manifest
                    .filesystem_state_confirmation
                    .as_ref()
                    .map(|confirmation| confirmation.state_verdict),
                linux_state_comparison.as_ref(),
            ),
            output_dir: request.output_dir.display().to_string(),
        };

        // This is the commit record. Do no fallible work after replacing it.
        atomic_file::write_json_atomic(&manifest_path, &manifest)?;
        Ok(outcome)
    })();

    match result {
        Ok(outcome) => Ok(outcome),
        Err(primary) => {
            let cleanup_error = cgroup
                .as_mut()
                .and_then(|active| active.abort_and_cleanup(FAILURE_CLEANUP_TIMEOUT).err());
            manifest.run_status = EffectRunStatus::Failed;
            manifest.finalized_unix_ns = Some(environment::now_unix_ns().max(started_unix_ns));
            let mut failure = format!("{primary:#}");
            if let Some(cleanup) = cleanup_error {
                failure.push_str("; cgroup cleanup also failed: ");
                failure.push_str(&format!("{cleanup:#}"));
            }
            manifest.failure = Some(truncate_utf8(&failure, 16 * 1024));
            if let Err(commit_error) = atomic_file::write_json_atomic(&manifest_path, &manifest) {
                return Err(anyhow!(
                    "{failure}; additionally failed to commit FAILED system-effect manifest: {commit_error:#}"
                ));
            }
            Err(anyhow!(failure))
        }
    }
}

#[cfg(test)]
pub(crate) fn system_state_domain_vector(
    bpf: Option<&StateVerdict>,
    filesystem: Option<FilesystemVerdict>,
) -> SystemStateDomainVector {
    system_state_domain_vector_with_linux(bpf, filesystem, None)
}

pub(crate) fn system_state_domain_vector_with_linux(
    bpf: Option<&StateVerdict>,
    filesystem: Option<FilesystemVerdict>,
    linux: Option<&LinuxStateComparison>,
) -> SystemStateDomainVector {
    let bpf = match bpf {
        Some(StateVerdict::ChangedWithinScope) => DomainStateVerdict::ChangedWithinScope,
        Some(StateVerdict::UnchangedWithinScope) => DomainStateVerdict::UnchangedWithinScope,
        Some(StateVerdict::Inconclusive) => DomainStateVerdict::Inconclusive,
        None => DomainStateVerdict::NotConfirmed,
    };
    let filesystem = match filesystem {
        Some(FilesystemVerdict::ChangedWithinScope) => DomainStateVerdict::ChangedWithinScope,
        Some(FilesystemVerdict::UnchangedWithinScope) => DomainStateVerdict::UnchangedWithinScope,
        Some(FilesystemVerdict::Inconclusive) => DomainStateVerdict::Inconclusive,
        None => DomainStateVerdict::NotConfirmed,
    };
    let linux_verdict = |domain: &LinuxDomainComparison| match domain.verdict {
        LinuxStateVerdict::ChangedWithinScope => DomainStateVerdict::ChangedWithinScope,
        LinuxStateVerdict::Inconclusive => DomainStateVerdict::Inconclusive,
        LinuxStateVerdict::NotConfirmed => DomainStateVerdict::NotConfirmed,
    };
    SystemStateDomainVector {
        filesystem,
        bpf,
        network_config: linux
            .map(|comparison| linux_verdict(&comparison.domains.network))
            .unwrap_or(DomainStateVerdict::NotConfirmed),
        sysctl: linux
            .map(|comparison| linux_verdict(&comparison.domains.sysctl))
            .unwrap_or(DomainStateVerdict::NotConfirmed),
        mounts: linux
            .map(|comparison| linux_verdict(&comparison.domains.mounts))
            .unwrap_or(DomainStateVerdict::NotConfirmed),
        modules: linux
            .map(|comparison| linux_verdict(&comparison.domains.modules))
            .unwrap_or(DomainStateVerdict::NotConfirmed),
        process_residual: linux
            .map(|comparison| linux_verdict(&comparison.domains.process_residual))
            .unwrap_or(DomainStateVerdict::NotConfirmed),
        keyrings: DomainStateVerdict::NotConfirmed,
        remote_network_effect: DomainStateVerdict::NotConfirmable,
    }
}

fn load_bpf_state_scope(path: Option<&Path>) -> Result<Option<ClaimScope>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let scope: ClaimScope = input::read_json(path, MAX_MANIFEST_JSON_BYTES)
        .context("read explicit BPF state confirmation scope")?;
    run::validate_observe_scope(&scope).context("validate BPF state confirmation scope")?;
    Ok(Some(scope))
}

fn load_filesystem_state_scope(path: Option<&Path>) -> Result<Option<FilesystemScope>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let scope: FilesystemScope = input::read_json(path, HARD_MAX_SCOPE_JSON_BYTES)
        .context("read explicit filesystem state confirmation scope")?;
    scope
        .validate()
        .context("validate filesystem state confirmation scope")?;
    Ok(Some(scope))
}

fn load_filesystem_actor_contract(path: Option<&Path>) -> Result<Option<ActorQuiescenceContract>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let contract: ActorQuiescenceContract =
        input::read_json(path, HARD_MAX_ACTOR_CONTRACT_JSON_BYTES)
            .context("read external filesystem actor contract")?;
    contract
        .validate()
        .context("validate filesystem actor contract")?;
    Ok(Some(contract))
}

fn load_linux_state_scope(path: Option<&Path>) -> Result<Option<LinuxStateScope>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let scope: LinuxStateScope = input::read_json(path, HARD_MAX_LINUX_STATE_SCOPE_JSON_BYTES)
        .context("read explicit Linux endpoint-state scope")?;
    scope
        .validate()
        .context("validate Linux endpoint-state scope")?;
    Ok(Some(scope))
}

pub(crate) fn effective_linux_state_scope(
    base: Option<&LinuxStateScope>,
    auto_process_residual: bool,
    cgroup_path: &Path,
    cgroup_id: u64,
) -> Result<Option<LinuxStateScope>> {
    if !auto_process_residual {
        return Ok(base.cloned());
    }
    if cgroup_id == 0 {
        bail!("automatic process residual confirmation requires a nonzero cgroup ID");
    }
    let mut scope = base.cloned().unwrap_or(LinuxStateScope {
        protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
        sysctl: None,
        mounts: None,
        network: None,
        modules: None,
        process_residual: None,
    });
    if scope.process_residual.is_some() {
        bail!("automatic process residual scope cannot override an explicit scope");
    }
    scope.process_residual = Some(ProcessResidualScope {
        cgroup_path_bytes_hex: encode_absolute_path(cgroup_path)
            .context("encode automatic residual cgroup path")?,
        expected_cgroup_id: cgroup_id,
        additional_roots: Vec::new(),
        recursive: true,
        require_cgroup2: true,
        // PID/command bytes are not needed to compare endpoint identity; this
        // minimizes evidence I/O while preserving exact record digests.
        evidence: ValueEvidenceMode::Sha256Only,
        limits: LinuxStateCaptureLimits::default(),
    });
    scope.validate()?;
    Ok(Some(scope))
}

pub(crate) fn linux_state_snapshot_id(run_id: &str, run_epoch: u64, phase: &str) -> String {
    format!("{run_id}-E{run_epoch}-EFFECTS-LINUX-STATE-{phase}")
}

fn linux_state_confirmation_summary(
    scope: &LinuxStateScope,
    comparison: &LinuxStateComparison,
    auto_process_residual_bound: bool,
) -> Result<LinuxStateConfirmation> {
    if comparison.protocol_version != LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION
        || comparison.domain != LINUX_STATE_CONFIRMATION_DOMAIN
        || comparison.scope_sha256 != scope.sha256()?
    {
        bail!("Linux state comparison is not bound to the requested confirmation scope");
    }
    Ok(LinuxStateConfirmation {
        protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
        confirmation_domain: LINUX_STATE_CONFIRMATION_DOMAIN,
        scope_sha256: comparison.scope_sha256.clone(),
        s0_artifact: LINUX_STATE_S0_NAME,
        s1_artifact: LINUX_STATE_S1_NAME,
        comparison_artifact: LINUX_STATE_COMPARISON_NAME,
        auto_process_residual_bound,
        domains: comparison.domains.clone(),
        operation_events_are_state_diff: false,
        atomic_with_other_confirmation_domains: false,
        whole_linux_unchanged_authorized: false,
    })
}

fn validate_auto_process_residual(comparison: &LinuxStateComparison) -> Result<()> {
    let residual = &comparison.domains.process_residual;
    if residual.state_completeness.status != LinuxCompletenessStatus::Complete
        || residual.endpoint_difference != LinuxEndpointDifferenceStatus::ObservedIdentical
        || residual.verdict != LinuxStateVerdict::Inconclusive
        || residual.terminal_state != LinuxTerminalState::EmptyWithinScope
    {
        bail!(
            "automatic process residual confirmation contradicts the empty/frozen cgroup barrier"
        );
    }
    Ok(())
}

pub(crate) fn filesystem_snapshot_id(run_id: &str, run_epoch: u64, phase: &str) -> String {
    format!("{run_id}-E{run_epoch}-EFFECTS-FILESYSTEM-{phase}")
}

fn validate_filesystem_actor_binding(
    contract: &ActorQuiescenceContract,
    scope: &FilesystemScope,
    run_id: &str,
    run_epoch: u64,
) -> Result<()> {
    contract.validate()?;
    if contract.scope_sha256 != scope.sha256()?
        || contract.s0_snapshot_id != filesystem_snapshot_id(run_id, run_epoch, "S0")
        || contract.s1_snapshot_id != filesystem_snapshot_id(run_id, run_epoch, "S1")
    {
        bail!("filesystem actor contract is not bound to this run, epoch, and scope");
    }
    Ok(())
}

fn filesystem_confirmation_summary(
    scope: &FilesystemScope,
    comparison: &FilesystemComparison,
    actor_contract_present: bool,
) -> Result<FilesystemStateConfirmation> {
    if comparison.protocol_version != FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION
        || comparison.domain != FILESYSTEM_CONFIRMATION_DOMAIN
        || comparison.scope_sha256 != scope.sha256()?
        || (actor_contract_present
            && comparison.actor_contract_status == ActorContractStatus::Missing)
        || (!actor_contract_present
            && comparison.actor_contract_status != ActorContractStatus::Missing)
    {
        bail!("filesystem comparison is not bound to the requested confirmation contract");
    }
    Ok(FilesystemStateConfirmation {
        protocol_version: FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION,
        confirmation_domain: FILESYSTEM_CONFIRMATION_DOMAIN,
        scope_sha256: comparison.scope_sha256.clone(),
        s0_artifact: FILESYSTEM_STATE_S0_NAME,
        s1_artifact: FILESYSTEM_STATE_S1_NAME,
        comparison_artifact: FILESYSTEM_STATE_COMPARISON_NAME,
        actor_contract_artifact: actor_contract_present.then_some(FILESYSTEM_ACTOR_CONTRACT_NAME),
        endpoint_difference: comparison.endpoint_difference,
        state_verdict: comparison.verdict,
        state_completeness: comparison.state_completeness.status,
        actor_contract_status: comparison.actor_contract_status,
        causal_attribution_status: comparison.causal_attribution_status,
        actor_contract_authenticated_by_observer: false,
        operation_events_are_state_diff: false,
        atomic_with_other_confirmation_domains: false,
    })
}

pub(crate) fn validate_filesystem_output_separation(
    scope: &FilesystemScope,
    output_dir: &Path,
) -> Result<()> {
    if scope.overlaps_path(output_dir)? {
        bail!("filesystem confirmation scope overlaps the observer output directory");
    }
    let physical_output = physical_path_with_missing_tail(output_dir)
        .context("resolve physical observer output location")?;
    for root in scope.decoded_roots()? {
        let physical_root = physical_path_with_missing_tail(&root)
            .with_context(|| format!("resolve physical filesystem root {}", root.display()))?;
        if paths_overlap(&physical_root, &physical_output) {
            bail!(
                "filesystem confirmation root {} physically overlaps observer output {}",
                root.display(),
                output_dir.display()
            );
        }
    }
    Ok(())
}

fn physical_path_with_missing_tail(path: &Path) -> Result<PathBuf> {
    use std::path::Component;

    if !path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        bail!("path must be an absolute canonical path without '.' or '..'");
    }
    let mut cursor = path;
    let mut tail = Vec::<OsString>::new();
    loop {
        match fs::canonicalize(cursor) {
            Ok(mut resolved) => {
                for component in tail.iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = cursor
                    .file_name()
                    .context("missing path has no existing ancestor")?;
                tail.push(name.to_os_string());
                cursor = cursor.parent().context("missing path has no parent")?;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("canonicalize existing path {}", cursor.display()))
            }
        }
    }
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn bpf_capture_options(run_id: &str, phase: &str, exclusions: &ObjectExclusions) -> CaptureOptions {
    CaptureOptions {
        snapshot_id: format!("{run_id}-EFFECTS-BPF-{phase}"),
        phase: phase.to_owned(),
        exclusions: exclusions.clone(),
        // An empty frozen workload cgroup does not prove global BPF Map
        // quiescence; only an authenticated exclusive harness can do that.
        maps_quiescent: false,
    }
}

pub(crate) fn compare_bpf_state_endpoints(before: &Snapshot, after: &Snapshot) -> Result<Verdict> {
    let mut evidence = EvidenceHealth::default();
    evidence.reasons.push(
        "observe-effects operation transport is not the BPF_USER_SYSCALL evidence contract required to prove an unchanged final BPF state"
            .to_owned(),
    );
    let quiescence = QuiescenceReport {
        status: QuiescenceStatus::Unknown,
        basis: QuiescenceBasis::ObservedOnly,
        contract_id: None,
        checks: vec![ContractCheck {
            name: "cgroup_empty".to_owned(),
            passed: true,
            evidence: "workload cgroup reported populated=0 and was frozen before S1".to_owned(),
        }],
        exclusive_actor_attribution: false,
        authentication: None,
    };
    let mut verdict = compare(before, after, &evidence, quiescence)?;
    verdict.run_status = RunStatus::Provisional;
    verdict.limitations.push(
        "This confirmer covers only final BPF object state inside its explicit ClaimScope; the system-effect JSONL is separate operation history."
            .to_owned(),
    );
    verdict.limitations.push(
        "UNCHANGED_WITHIN_SCOPE is intentionally unauthorized without the exclusive-vm-v1 harness and its BPF_USER_SYSCALL evidence contract."
            .to_owned(),
    );
    Ok(verdict)
}

fn apply_health(manifest: &mut EffectsManifest, health: &SystemEffectHealth) {
    manifest.transport_status = Some(health.transport_status);
    manifest.coverage.coverage_status = "PARTIAL";
    manifest.coverage.object_resolution_status = "PARTIAL";
    manifest.coverage.gaps.extend(health.coverage_gaps.clone());
    manifest.coverage.gaps.sort();
    manifest.coverage.gaps.dedup();
    if health.transport_status == TransportStatus::Incomplete {
        manifest.notes.push(
            "transport is incomplete; the event stream must not be treated as exhaustive".into(),
        );
    }
}

fn validate_request(request: &ObserveRequest) -> Result<()> {
    if request.workload.is_empty() {
        bail!("workload command must not be empty");
    }
    if request.run_epoch == 0 {
        bail!("run_epoch must be nonzero");
    }
    if request.timeout_ms == 0 || request.drain_timeout_ms == 0 {
        bail!("workload and drain timeouts must be nonzero");
    }
    validate_sha256(&request.expected_recorder_sha256)?;
    match (
        request.object_resolution_mode,
        request.process_lifecycle_object.as_ref(),
        request.expected_process_lifecycle_sha256.as_deref(),
    ) {
        (ObjectResolutionMode::KernelObjectExpandedPartial, Some(_), Some(digest)) => {
            validate_sha256(digest)?;
        }
        (ObjectResolutionMode::KernelObjectExpandedPartial, _, _) => {
            bail!("expanded object resolution requires both process-lifecycle object and digest")
        }
        (_, None, None) => {}
        _ => bail!("process-lifecycle object evidence is only valid in expanded object mode"),
    }
    run::validate_cgroup_root(&request.cgroup_root)?;
    if let Some(run_id) = request.run_id.as_deref() {
        run::validate_run_id(run_id)?;
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("expected recorder object digest must be canonical lowercase SHA-256");
    }
    Ok(())
}

fn workload_strings(arguments: &[OsString]) -> Result<Vec<String>> {
    let mut total = 0usize;
    arguments
        .iter()
        .map(|argument| {
            let value = argument
                .to_str()
                .context("workload argv contains non-UTF-8 bytes")?;
            if value.contains('\0') {
                bail!("workload argv contains a NUL byte");
            }
            total = total
                .checked_add(value.len())
                .context("workload argv byte count overflow")?;
            if total > MAX_WORKLOAD_ARGV_BYTES {
                bail!("workload argv exceeds {MAX_WORKLOAD_ARGV_BYTES} bytes");
            }
            Ok(value.to_owned())
        })
        .collect()
}

fn initial_coverage(
    profile: PolicyProfile,
    object_resolution_mode: ObjectResolutionMode,
) -> CoverageDescription {
    let mut gaps = coverage_gaps_for(profile, recorder_resolution_mode(object_resolution_mode));
    gaps.push(
        "standalone observe-effects does not isolate workload credentials or enforce evidence-directory write isolation; an external sandbox/harness must do so"
            .to_owned(),
    );
    CoverageDescription {
        attribution_scope: "SELECTED_NATIVE_SYSCALLS_FROM_EXACT_CGROUP_V2_ID",
        event_semantics: "OPERATION_ATTEMPT_AND_RETURN_NOT_DURABLE_STATE_DIFF",
        operation_events_are_state_diff: false,
        durable_state_change_proven: false,
        rollback_completeness_proven: false,
        workload_privilege_isolation_enforced: false,
        evidence_write_isolation_enforced: false,
        coverage_status: "PARTIAL",
        object_resolution_status: "PARTIAL",
        gaps,
    }
}

fn recorder_resolution_mode(mode: ObjectResolutionMode) -> FileObjectResolutionMode {
    match mode {
        ObjectResolutionMode::UserInput => FileObjectResolutionMode::UserInput,
        ObjectResolutionMode::KernelFileOpenPartial => {
            FileObjectResolutionMode::KernelFileOpenPartial
        }
        ObjectResolutionMode::KernelFileOpenWritePartial => {
            FileObjectResolutionMode::KernelFileOpenWritePartial
        }
        ObjectResolutionMode::KernelObjectExpandedPartial => {
            FileObjectResolutionMode::KernelObjectExpandedPartial
        }
    }
}

fn merge_exclusions(target: &mut ObjectExclusions, source: &ObjectExclusions) {
    target
        .program_ids
        .extend(source.program_ids.iter().copied());
    target.map_ids.extend(source.map_ids.iter().copied());
    target.link_ids.extend(source.link_ids.iter().copied());
}

#[derive(Clone, Copy, Debug, Default)]
struct OutputSummary {
    stdout_truncated: bool,
    stderr_truncated: bool,
}

struct BoundedCapture {
    reader: Box<dyn Read>,
    file: File,
    retained: u64,
    total: u64,
    eof: bool,
}

impl BoundedCapture {
    fn new<R: Read + AsRawFd + 'static>(reader: R, file: File) -> Result<Self> {
        let fd = reader.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error()).context("make workload output nonblocking");
        }
        Ok(Self {
            reader: Box::new(reader),
            file,
            retained: 0,
            total: 0,
            eof: false,
        })
    }

    fn drain(&mut self) -> Result<()> {
        self.drain_chunks(DRAIN_CHUNKS_PER_POLL)
    }

    fn drain_chunks(&mut self, maximum: usize) -> Result<()> {
        let mut buffer = [0u8; 64 * 1024];
        for _ in 0..maximum {
            match self.reader.read(&mut buffer) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(());
                }
                Ok(count) => {
                    self.total = self.total.saturating_add(count as u64);
                    let remaining = MAX_WORKLOAD_OUTPUT_BYTES.saturating_sub(self.retained);
                    let retained = usize::try_from(remaining.min(count as u64)).unwrap_or(0);
                    if retained != 0 {
                        self.file.write_all(&buffer[..retained])?;
                        self.retained += retained as u64;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error).context("read workload output"),
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<bool> {
        self.drain_chunks(DRAIN_CHUNKS_AT_EOF)?;
        if !self.eof {
            bail!("workload output pipe remained open after its cgroup became empty");
        }
        self.file.sync_all().context("fsync workload output")?;
        Ok(self.total > self.retained)
    }
}

fn execute_workload(
    recorder: &mut SystemEffectRecorder,
    mut lifecycle: Option<&mut ProcessLifecycleRecorder>,
    cgroup: &ManagedCgroup,
    workload: &[OsString],
    output_dir: &Path,
    timeout: Duration,
) -> Result<(ExitStatus, OutputSummary)> {
    let executable = workload.first().context("workload command is empty")?;
    let mut command = Command::new(executable);
    command.args(&workload[1..]);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let stdout_file = open_capture_file(&output_dir.join(STDOUT_NAME))?;
    let stderr_file = open_capture_file(&output_dir.join(STDERR_NAME))?;
    cgroup.configure_child(&mut command)?;
    let mut child = command
        .spawn()
        .with_context(|| format!("spawn system-effect workload {executable:?}"))?;
    let captures = (|| -> Result<(BoundedCapture, BoundedCapture)> {
        let stdout = child
            .stdout
            .take()
            .context("workload stdout pipe is absent")?;
        let stderr = child
            .stderr
            .take()
            .context("workload stderr pipe is absent")?;
        Ok((
            BoundedCapture::new(stdout, stdout_file)?,
            BoundedCapture::new(stderr, stderr_file)?,
        ))
    })();
    let (mut stdout, mut stderr) = match captures {
        Ok(captures) => captures,
        Err(error) => {
            kill_and_reap_bounded(&mut child, cgroup);
            return Err(error).context("configure workload output capture");
        }
    };
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("workload timeout exceeds monotonic clock range")?;
    let mut root_status = None;

    let monitored = (|| -> Result<ExitStatus> {
        loop {
            recorder.poll(Duration::ZERO)?;
            if let Some(lifecycle) = lifecycle.as_mut() {
                lifecycle.poll(poll_duration(deadline))?;
            } else {
                recorder.poll(poll_duration(deadline))?;
            }
            stdout.drain()?;
            stderr.drain()?;
            if root_status.is_none() {
                root_status = child.try_wait().context("wait for workload root")?;
            }
            if root_status.is_some() && !cgroup.populated()? {
                break;
            }
            if Instant::now() >= deadline {
                bail!("workload process tree exceeded timeout of {timeout:?}");
            }
            thread::yield_now();
        }
        root_status.context("workload cgroup emptied before root status was available")
    })();

    let status = match monitored {
        Ok(status) => status,
        Err(error) => {
            kill_and_reap_bounded(&mut child, cgroup);
            let _ = recorder.poll(Duration::ZERO);
            if let Some(lifecycle) = lifecycle.as_mut() {
                let _ = lifecycle.poll(Duration::ZERO);
            }
            let _ = stdout.drain();
            let _ = stderr.drain();
            return Err(error);
        }
    };
    let summary = OutputSummary {
        stdout_truncated: stdout.finish()?,
        stderr_truncated: stderr.finish()?,
    };
    Ok((status, summary))
}

fn open_capture_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("create workload capture {}", path.display()))
}

fn kill_and_reap_bounded(child: &mut Child, cgroup: &ManagedCgroup) {
    let _ = cgroup.kill_all();
    let _ = child.kill();
    let deadline = Instant::now() + FAILURE_CLEANUP_TIMEOUT;
    loop {
        let root_reaped = child.try_wait().ok().flatten().is_some();
        let cgroup_empty = matches!(cgroup.populated(), Ok(false));
        if root_reaped && cgroup_empty {
            return;
        }
        if Instant::now() >= deadline {
            return;
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn poll_duration(deadline: Instant) -> Duration {
    POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now()))
}

fn prepare_output_directory(path: &Path) -> Result<()> {
    let parent = path.parent().context("output directory has no parent")?;
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create output parent {}", parent.display()))?;
    }
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path).with_context(|| {
        format!(
            "atomically claim new system-effect output {}; it must not exist",
            path.display()
        )
    })
}

fn collect_artifacts(
    output_dir: &Path,
    includes_bpf_state: bool,
    includes_filesystem_state: bool,
    includes_filesystem_actor_contract: bool,
    includes_linux_state: bool,
    includes_process_lifecycle: bool,
) -> Result<BTreeMap<String, ArtifactDigest>> {
    validate_output_entries(
        output_dir,
        includes_bpf_state,
        includes_filesystem_state,
        includes_filesystem_actor_contract,
        includes_linux_state,
        includes_process_lifecycle,
    )?;
    let mut artifacts = BTreeMap::new();
    for name in final_artifact_names_with_linux(
        includes_bpf_state,
        includes_filesystem_state,
        includes_filesystem_actor_contract,
        includes_linux_state,
        includes_process_lifecycle,
    )? {
        artifacts.insert(
            name.to_owned(),
            measure_artifact(&output_dir.join(name), artifact_limit(name)?)?,
        );
    }
    validate_output_entries(
        output_dir,
        includes_bpf_state,
        includes_filesystem_state,
        includes_filesystem_actor_contract,
        includes_linux_state,
        includes_process_lifecycle,
    )?;
    Ok(artifacts)
}

#[cfg(test)]
fn final_artifact_names(
    includes_bpf_state: bool,
    includes_filesystem_state: bool,
    includes_filesystem_actor_contract: bool,
) -> Result<Vec<&'static str>> {
    final_artifact_names_with_linux(
        includes_bpf_state,
        includes_filesystem_state,
        includes_filesystem_actor_contract,
        false,
        false,
    )
}

fn final_artifact_names_with_linux(
    includes_bpf_state: bool,
    includes_filesystem_state: bool,
    includes_filesystem_actor_contract: bool,
    includes_linux_state: bool,
    includes_process_lifecycle: bool,
) -> Result<Vec<&'static str>> {
    if includes_filesystem_actor_contract && !includes_filesystem_state {
        bail!("filesystem actor contract cannot exist without filesystem state evidence");
    }
    let mut names = BASE_FINAL_ARTIFACTS.to_vec();
    if includes_bpf_state {
        names.extend([BPF_STATE_S0_NAME, BPF_STATE_S1_NAME, BPF_STATE_VERDICT_NAME]);
    }
    if includes_filesystem_state {
        names.extend([
            FILESYSTEM_STATE_S0_NAME,
            FILESYSTEM_STATE_S1_NAME,
            FILESYSTEM_STATE_COMPARISON_NAME,
        ]);
    }
    if includes_filesystem_actor_contract {
        names.push(FILESYSTEM_ACTOR_CONTRACT_NAME);
    }
    if includes_linux_state {
        names.extend([
            LINUX_STATE_S0_NAME,
            LINUX_STATE_S1_NAME,
            LINUX_STATE_COMPARISON_NAME,
        ]);
    }
    if includes_process_lifecycle {
        names.extend([
            PROCESS_LIFECYCLE_WAL_NAME,
            PROCESS_LIFECYCLE_JSONL_NAME,
            PROCESS_LIFECYCLE_HEALTH_NAME,
            SOCKET_STATE_WAL_NAME,
            SOCKET_STATE_JSONL_NAME,
            SOCKET_STATE_HEALTH_NAME,
        ]);
    }
    Ok(names)
}

fn validate_output_entries(
    output_dir: &Path,
    includes_bpf_state: bool,
    includes_filesystem_state: bool,
    includes_filesystem_actor_contract: bool,
    includes_linux_state: bool,
    includes_process_lifecycle: bool,
) -> Result<()> {
    let mut allowed = final_artifact_names_with_linux(
        includes_bpf_state,
        includes_filesystem_state,
        includes_filesystem_actor_contract,
        includes_linux_state,
        includes_process_lifecycle,
    )?
    .into_iter()
    .collect::<BTreeSet<_>>();
    allowed.insert(MANIFEST_NAME);
    for entry in fs::read_dir(output_dir)
        .with_context(|| format!("enumerate system-effect output {}", output_dir.display()))?
    {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("system-effect output has a non-UTF-8 entry"))?;
        if !allowed.contains(name.as_str()) {
            bail!("system-effect output contains unbound entry {name:?}");
        }
    }
    Ok(())
}

fn artifact_limit(name: &str) -> Result<u64> {
    match name {
        POLICY_NAME | HEALTH_NAME => Ok(MAX_SMALL_JSON_BYTES),
        PROCESS_LIFECYCLE_HEALTH_NAME | SOCKET_STATE_HEALTH_NAME => Ok(MAX_SMALL_JSON_BYTES),
        BPF_STATE_S0_NAME | BPF_STATE_S1_NAME => Ok(MAX_SNAPSHOT_JSON_BYTES),
        BPF_STATE_VERDICT_NAME => Ok(MAX_VERDICT_JSON_BYTES),
        FILESYSTEM_STATE_S0_NAME | FILESYSTEM_STATE_S1_NAME => Ok(HARD_MAX_SNAPSHOT_JSON_BYTES),
        FILESYSTEM_STATE_COMPARISON_NAME => Ok(HARD_MAX_COMPARISON_JSON_BYTES),
        FILESYSTEM_ACTOR_CONTRACT_NAME => Ok(HARD_MAX_ACTOR_CONTRACT_JSON_BYTES),
        LINUX_STATE_S0_NAME | LINUX_STATE_S1_NAME => Ok(HARD_MAX_LINUX_STATE_SNAPSHOT_JSON_BYTES),
        LINUX_STATE_COMPARISON_NAME => Ok(HARD_MAX_LINUX_STATE_COMPARISON_JSON_BYTES),
        WAL_NAME => Ok(MAX_EFFECT_WAL_BYTES),
        JSONL_NAME => Ok(MAX_EFFECT_JSONL_BYTES),
        PROCESS_LIFECYCLE_WAL_NAME => Ok(MAX_LIFECYCLE_WAL_BYTES),
        PROCESS_LIFECYCLE_JSONL_NAME => Ok(MAX_LIFECYCLE_JSONL_BYTES),
        SOCKET_STATE_WAL_NAME => Ok(MAX_SOCKET_STATE_WAL_BYTES),
        SOCKET_STATE_JSONL_NAME => Ok(MAX_SOCKET_STATE_JSONL_BYTES),
        STDOUT_NAME | STDERR_NAME => Ok(MAX_WORKLOAD_OUTPUT_BYTES),
        _ => bail!("no size policy for system-effect artifact {name:?}"),
    }
}

fn measure_artifact(path: &Path, limit: u64) -> Result<ArtifactDigest> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open system-effect artifact {}", path.display()))?;
    let before = file
        .metadata()
        .with_context(|| format!("inspect system-effect artifact {}", path.display()))?;
    if !before.file_type().is_file() || before.nlink() != 1 {
        bail!("system-effect artifact must be a singly linked regular file");
    }
    if before.len() > limit {
        bail!(
            "system-effect artifact {} exceeds its {limit}-byte limit",
            path.display()
        );
    }
    let (sha256, bytes_read) = environment::sha256_reader_counted((&mut file).take(limit + 1))?;
    let after = file.metadata()?;
    if bytes_read != before.len() || !same_file_state(&before, &after) {
        bail!("system-effect artifact changed while it was hashed");
    }
    Ok(ArtifactDigest {
        sha256,
        size_bytes: before.len(),
    })
}

fn same_file_state(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn truncate_utf8(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.to_owned();
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...[truncated]", &value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use bpf_observer_filesystem_confirmer::{FilesystemCaptureLimits, FilesystemCapturePolicy};
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scope(root: &Path) -> FilesystemScope {
        FilesystemScope::new(
            vec![root.to_path_buf()],
            FilesystemCapturePolicy::default(),
            FilesystemCaptureLimits::default(),
        )
        .unwrap()
    }

    fn actor_contract(
        scope: &FilesystemScope,
        run_id: &str,
        epoch: u64,
    ) -> ActorQuiescenceContract {
        ActorQuiescenceContract {
            protocol_version: FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION,
            contract_id: "exclusive-test-v1".to_owned(),
            evidence_sha256: "ab".repeat(32),
            scope_sha256: scope.sha256().unwrap(),
            s0_snapshot_id: filesystem_snapshot_id(run_id, epoch, "S0"),
            s1_snapshot_id: filesystem_snapshot_id(run_id, epoch, "S1"),
            exclusive_writer_enforced: true,
            s0_quiescent: true,
            s1_quiescent: true,
        }
    }

    #[test]
    fn filesystem_actor_contract_is_bound_to_scope_run_and_epoch() {
        let selected = scope(Path::new("/tmp/bpf-observer-state-scope"));
        let contract = actor_contract(&selected, "run-a", 7);
        validate_filesystem_actor_binding(&contract, &selected, "run-a", 7).unwrap();
        assert!(validate_filesystem_actor_binding(&contract, &selected, "run-a", 8).is_err());
        assert!(validate_filesystem_actor_binding(&contract, &selected, "run-b", 7).is_err());

        let other = scope(Path::new("/tmp/bpf-observer-other-scope"));
        assert!(validate_filesystem_actor_binding(&contract, &other, "run-a", 7).is_err());
    }

    #[test]
    fn filesystem_output_must_be_lexically_and_physically_outside_scope() {
        let selected = scope(Path::new("/tmp/bpf-observer-state-scope"));
        assert!(validate_filesystem_output_separation(
            &selected,
            Path::new("/tmp/bpf-observer-state-scope/evidence")
        )
        .is_err());
        validate_filesystem_output_separation(
            &selected,
            Path::new("/tmp/bpf-observer-evidence-sibling"),
        )
        .unwrap();

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let lexical_base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/effects-run-tests")
            .join(format!("{}-{nonce}", std::process::id()));
        fs::create_dir_all(&lexical_base).unwrap();
        let base = fs::canonicalize(&lexical_base).unwrap();
        let selected_root = base.join("selected");
        fs::create_dir(&selected_root).unwrap();
        let alias = base.join("alias");
        symlink(&selected_root, &alias).unwrap();
        let aliased_output = alias.join("evidence");
        let selected = scope(&selected_root);
        let result = validate_filesystem_output_separation(&selected, &aliased_output);

        let _ = fs::remove_file(&alias);
        let _ = fs::remove_dir(&selected_root);
        let _ = fs::remove_dir(&base);
        assert!(result.is_err());
    }

    #[test]
    fn artifact_set_expansion_is_exact_and_fail_closed() {
        assert_eq!(final_artifact_names(false, false, false).unwrap().len(), 6);
        assert_eq!(final_artifact_names(true, false, false).unwrap().len(), 9);
        assert_eq!(final_artifact_names(false, true, false).unwrap().len(), 9);
        assert_eq!(final_artifact_names(true, true, true).unwrap().len(), 13);
        assert_eq!(
            final_artifact_names_with_linux(false, false, false, true, false)
                .unwrap()
                .len(),
            9
        );
        assert_eq!(
            final_artifact_names_with_linux(true, true, true, true, false)
                .unwrap()
                .len(),
            16
        );
        assert!(final_artifact_names(false, false, true).is_err());
    }

    #[test]
    fn automatic_process_residual_scope_binds_the_recursive_run_cgroup() {
        let scope = effective_linux_state_scope(
            None,
            true,
            Path::new("/sys/fs/cgroup/bpf-state-observer-effects/test-run"),
            77,
        )
        .unwrap()
        .unwrap();
        let residual = scope.process_residual.unwrap();
        assert_eq!(residual.expected_cgroup_id, 77);
        assert!(residual.recursive);
        assert!(residual.require_cgroup2);
        assert_eq!(
            residual.cgroup_path_bytes_hex,
            encode_absolute_path(Path::new(
                "/sys/fs/cgroup/bpf-state-observer-effects/test-run",
            ))
            .unwrap()
        );

        let explicit = LinuxStateScope {
            protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
            sysctl: None,
            mounts: None,
            network: None,
            modules: None,
            process_residual: Some(residual),
        };
        assert!(effective_linux_state_scope(
            Some(&explicit),
            true,
            Path::new("/sys/fs/cgroup/other"),
            88,
        )
        .is_err());
    }

    #[test]
    fn state_vector_never_promotes_unimplemented_domains() {
        let vector = system_state_domain_vector(
            Some(&StateVerdict::ChangedWithinScope),
            Some(FilesystemVerdict::UnchangedWithinScope),
        );
        assert_eq!(vector.bpf, DomainStateVerdict::ChangedWithinScope);
        assert_eq!(vector.filesystem, DomainStateVerdict::UnchangedWithinScope);
        assert_eq!(vector.network_config, DomainStateVerdict::NotConfirmed);
        assert_eq!(vector.sysctl, DomainStateVerdict::NotConfirmed);
        assert_eq!(
            vector.remote_network_effect,
            DomainStateVerdict::NotConfirmable
        );
    }
}
