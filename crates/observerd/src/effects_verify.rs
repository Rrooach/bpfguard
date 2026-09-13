// SPDX-License-Identifier: GPL-2.0-only

//! Offline verification for the independent system-effect artifact set.

use crate::{
    effects_run::{self, FilesystemActorContractTrust, SystemStateDomainVector},
    object_resolution::ObjectResolutionMode,
    run,
};
use anyhow::{anyhow, bail, Context, Result};
use bpf_observer_filesystem_confirmer::{
    compare as compare_filesystem, ActorContractStatus, ActorQuiescenceContract,
    CausalAttributionStatus, CompletenessStatus as FilesystemCompletenessStatus,
    EndpointDifferenceStatus, FilesystemComparison, FilesystemScope, FilesystemSnapshot,
    FilesystemVerdict, SnapshotPhase as FilesystemSnapshotPhase, FILESYSTEM_CONFIRMATION_DOMAIN,
    FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION, HARD_MAX_ACTOR_CONTRACT_JSON_BYTES,
    HARD_MAX_COMPARISON_JSON_BYTES, HARD_MAX_SNAPSHOT_JSON_BYTES,
};
use bpf_observer_oracle::validate_snapshot_resource_bounds;
use bpf_observer_schema::{
    ArtifactDigest, Attribution, ClaimScope, CompletenessStatus, ObjectExclusions, RunStatus,
    Snapshot, StateVerdict, Verdict, MAX_SNAPSHOT_JSON_BYTES, MAX_VERDICT_JSON_BYTES,
    MAX_WORKLOAD_OUTPUT_BYTES,
};
use bpf_observer_system_effects::{
    coverage_gaps_for, describe_policy, policy_sha256, AttributionContract, CaptureSource,
    CaptureStatus, CapturedArgument, CoverageStatus, EffectAttribution, EffectOperation, EventKind,
    FileObjectResolutionMode, FilePathObservation, FilesystemClass, KernelEvent,
    KernelObjectResolver, ObjectIdentity, ObjectReference, ObjectResolution,
    ObjectResolutionAuthority, ObjectResolutionQuality, ObjectResolutionStatus, ObjectRole,
    PathResolutionAuthority, PathResolutionQuality, PolicyDescription, PolicyProfile, ResolvedPath,
    ResultStatus, SystemEffectEvent, SystemEffectHealth, TransportStatus,
    EFFECT_EVENT_SCHEMA_VERSION, FILE_PATH_NOT_REQUESTED, FILE_PATH_RESOLVED_AT_HOOK,
    FILE_PATH_UNAVAILABLE, FLAG_OBJECT_DELETE_FAILED, FLAG_OBJECT_JOIN_AMBIGUOUS,
    FLAG_OBJECT_JOIN_MISSING, FLAG_OBJECT_PATH_UNAVAILABLE, FLAG_OBJECT_READ_FAILED,
    FLAG_PAYLOAD1_INVALID_LENGTH, FLAG_PAYLOAD1_READ_FAILED, FLAG_PAYLOAD1_TRUNCATED,
    FLAG_PAYLOAD2_INVALID_LENGTH, FLAG_PAYLOAD2_READ_FAILED, FLAG_PAYLOAD2_TRUNCATED,
    FLAG_PENDING_DELETE_FAILED, FLAG_PENDING_INSERT_FAILED, FLAG_PENDING_MISSING,
    FLAG_PENDING_POISONED, FLAG_POLICY_INVALID, FLAG_SYSCALL_MISMATCH,
    OBJECT_IDENTITY_PROTOCOL_VERSION,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const MANIFEST_NAME: &str = "system-effects.manifest.json";
const POLICY_NAME: &str = "system-effects.policy.json";
const HEALTH_NAME: &str = "system-effects.health.json";
const WAL_NAME: &str = "system-effects.raw.bin";
const JSONL_NAME: &str = "system-effects.jsonl";
const STDOUT_NAME: &str = "workload.stdout";
const STDERR_NAME: &str = "workload.stderr";
const BASE_FINAL_ARTIFACTS: [&str; 6] = [
    POLICY_NAME,
    HEALTH_NAME,
    WAL_NAME,
    JSONL_NAME,
    STDOUT_NAME,
    STDERR_NAME,
];

const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SMALL_JSON_BYTES: u64 = 8 * 1024 * 1024;
const MAX_WAL_BYTES: u64 = 384 * 1024 * 1024;
const MAX_JSONL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EVENT_JSON_BYTES: u64 = 64 * 1024;
const MAX_EVENTS: u64 = 1_000_000;
const CALLBACK_QUEUE_CAPACITY: u64 = 4_096;
const MAX_WORKLOAD_ARGV_BYTES: usize = 1024 * 1024;
const WAL_COMPACT_EVENT_BYTES: usize = 152;
const WAL_FILE_OBJECT_EVENT_BYTES: usize = 328;
const WAL_FULL_EVENT_BYTES: usize = 344;
const EVENT_ATTEMPT: u16 = 1;
const EVENT_RESULT: u16 = 2;
const PAYLOAD_NONE: u8 = 0;
const PAYLOAD_USER_STRING: u8 = 1;
const PAYLOAD_SOCKADDR: u8 = 2;
const CAPTURE_BYTES: usize = 96;
const EVENT_SEMANTICS: &str = "OBSERVED_OPERATION_NOT_PROOF_OF_DURABLE_STATE_CHANGE";
const CAPTURE_AUTHORITY: &str = "USER_MEMORY_AT_SYSCALL_ENTRY_NOT_KERNEL_RESOLVED_OBJECT";
const STANDALONE_ISOLATION_GAP: &str = "standalone observe-effects does not isolate workload credentials or enforce evidence-directory write isolation; an external sandbox/harness must do so";

const FATAL_FLAGS: u32 = FLAG_PENDING_INSERT_FAILED
    | FLAG_PENDING_MISSING
    | FLAG_PENDING_POISONED
    | FLAG_PENDING_DELETE_FAILED
    | FLAG_POLICY_INVALID
    | FLAG_SYSCALL_MISMATCH
    | FLAG_OBJECT_JOIN_MISSING
    | FLAG_OBJECT_JOIN_AMBIGUOUS
    | FLAG_OBJECT_READ_FAILED
    | FLAG_OBJECT_DELETE_FAILED;

#[derive(Debug, Serialize)]
pub struct EffectsVerificationReport {
    pub schema_version: u32,
    pub run_id: String,
    pub run_epoch: u64,
    pub manifest_sha256: String,
    pub artifacts_verified: usize,
    pub events_verified: u64,
    pub recorder_object_sha256: String,
    pub policy_profile: PolicyProfile,
    pub object_resolution_mode: ObjectResolutionMode,
    pub external_recorder_digest_checked: bool,
    pub transport_complete: bool,
    pub attribution_contract: AttributionContract,
    pub direct_event_attribution_validated: bool,
    pub causal_attribution_complete: bool,
    pub coverage_complete: bool,
    pub operation_events_are_state_diff: bool,
    pub bpf_state_confirmation_verified: bool,
    pub external_bpf_state_scope_checked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bpf_state_verdict: Option<StateVerdict>,
    pub filesystem_artifact_consistency_verified: bool,
    pub external_filesystem_state_scope_exact_match: bool,
    pub external_filesystem_actor_contract_exact_match: bool,
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
    pub state_domains: SystemStateDomainVector,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum EffectRunStatus {
    Running,
    Finalized,
    Failed,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CoverageDescription {
    attribution_scope: String,
    event_semantics: String,
    operation_events_are_state_diff: bool,
    durable_state_change_proven: bool,
    rollback_completeness_proven: bool,
    workload_privilege_isolation_enforced: bool,
    evidence_write_isolation_enforced: bool,
    coverage_status: String,
    object_resolution_status: String,
    gaps: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BpfStateConfirmation {
    protocol_version: u32,
    confirmation_domain: String,
    scope: ClaimScope,
    observer_exclusions: ObjectExclusions,
    s0_artifact: String,
    s1_artifact: String,
    verdict_artifact: String,
    state_verdict: StateVerdict,
    state_completeness: CompletenessStatus,
    evidence_status: CompletenessStatus,
    attribution: Attribution,
    operation_events_are_state_diff: bool,
    unchanged_verdict_authorized: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FilesystemStateConfirmation {
    protocol_version: u32,
    confirmation_domain: String,
    scope_sha256: String,
    s0_artifact: String,
    s1_artifact: String,
    comparison_artifact: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actor_contract_artifact: Option<String>,
    endpoint_difference: EndpointDifferenceStatus,
    state_verdict: FilesystemVerdict,
    state_completeness: FilesystemCompletenessStatus,
    actor_contract_status: ActorContractStatus,
    causal_attribution_status: CausalAttributionStatus,
    actor_contract_authenticated_by_observer: bool,
    operation_events_are_state_diff: bool,
    atomic_with_other_confirmation_domains: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EffectsManifest {
    schema_version: u32,
    evidence_kind: String,
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
    policy_artifact: String,
    expected_recorder_object_sha256: String,
    loaded_recorder_object_sha256: Option<String>,
    kernel_release: String,
    boot_id: String,
    observer_version: String,
    source_commit: Option<String>,
    cgroup_frozen_at_close: bool,
    transport_status: Option<TransportStatus>,
    attribution_contract: AttributionContract,
    coverage: CoverageDescription,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bpf_state_confirmation: Option<BpfStateConfirmation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    filesystem_state_confirmation: Option<FilesystemStateConfirmation>,
    artifacts: BTreeMap<String, ArtifactDigest>,
    failure: Option<String>,
    notes: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyArtifact {
    schema_version: u32,
    profile: PolicyProfile,
    policy_sha256: String,
    entries: Vec<PolicyDescription>,
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

#[derive(Default)]
struct AttemptReplayState {
    by_sequence: HashMap<u64, AttemptIdentity>,
    active_by_pid_tgid: HashMap<u64, u64>,
}

impl AttemptReplayState {
    fn start(&mut self, raw: &KernelEvent) -> Result<()> {
        if self.by_sequence.contains_key(&raw.event_seq) {
            bail!("system-effect stream duplicated an operation attempt");
        }
        if self.active_by_pid_tgid.contains_key(&raw.pid_tgid) {
            bail!("system-effect stream contains overlapping attempts for one thread");
        }
        self.by_sequence.insert(
            raw.event_seq,
            AttemptIdentity {
                pid_tgid: raw.pid_tgid,
                syscall_nr: raw.syscall_nr,
                domain: raw.domain,
                operation: raw.operation,
                ktime_ns: raw.ktime_ns,
                args: raw.args,
            },
        );
        self.active_by_pid_tgid.insert(raw.pid_tgid, raw.event_seq);
        Ok(())
    }

    fn complete(&mut self, raw: &KernelEvent) -> Result<()> {
        let active_sequence = self
            .active_by_pid_tgid
            .get(&raw.pid_tgid)
            .copied()
            .context("system-effect result has no active attempt for its thread")?;
        if active_sequence != raw.related_attempt_seq {
            bail!("system-effect result does not close its thread's active attempt");
        }
        let attempt = self
            .by_sequence
            .get(&raw.related_attempt_seq)
            .copied()
            .context("system-effect result has no preceding operation attempt")?;
        if attempt.pid_tgid != raw.pid_tgid
            || attempt.syscall_nr != raw.syscall_nr
            || attempt.domain != raw.domain
            || attempt.operation != raw.operation
            || attempt.args != raw.args
            || raw.event_seq <= raw.related_attempt_seq
            || raw.ktime_ns < attempt.ktime_ns
        {
            bail!("system-effect result does not match its operation attempt");
        }
        self.by_sequence.remove(&raw.related_attempt_seq);
        self.active_by_pid_tgid.remove(&raw.pid_tgid);
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.by_sequence.is_empty() && self.active_by_pid_tgid.is_empty()
    }
}

pub fn verify_run(
    directory: &Path,
    expected_recorder_sha256: &str,
    expected_profile: PolicyProfile,
    expected_object_resolution: ObjectResolutionMode,
    expected_bpf_state_scope: Option<&ClaimScope>,
    expected_filesystem_state_scope: Option<&FilesystemScope>,
    expected_filesystem_actor_contract: Option<&ActorQuiescenceContract>,
) -> Result<EffectsVerificationReport> {
    let directory_state = validate_directory(directory)?;
    validate_sha256(
        expected_recorder_sha256,
        "externally trusted recorder object",
    )?;

    let (manifest, manifest_state, manifest_sha256): (EffectsManifest, _, _) =
        read_manifest(directory)?;
    validate_manifest(
        &manifest,
        expected_recorder_sha256,
        expected_profile,
        expected_object_resolution,
    )?;

    let mut artifacts = VerifiedArtifacts::new(directory, &manifest)?;
    let policy: PolicyArtifact = artifacts.read_json(POLICY_NAME, MAX_SMALL_JSON_BYTES)?;
    validate_policy(&manifest, &policy)?;
    let health: SystemEffectHealth = artifacts.read_json(HEALTH_NAME, MAX_SMALL_JSON_BYTES)?;
    validate_health(&manifest, &health)?;

    let policy_by_syscall = policy
        .entries
        .iter()
        .map(|entry| (entry.syscall_nr, entry))
        .collect::<HashMap<_, _>>();
    if policy_by_syscall.len() != policy.entries.len() {
        bail!("system-effect policy contains duplicate syscall numbers");
    }

    let events_verified = artifacts.verify_event_streams(&manifest, &health, &policy_by_syscall)?;
    artifacts.verify_only(STDOUT_NAME, MAX_WORKLOAD_OUTPUT_BYTES)?;
    artifacts.verify_only(STDERR_NAME, MAX_WORKLOAD_OUTPUT_BYTES)?;
    let bpf_state_verdict =
        verify_bpf_state_confirmation(&manifest, &mut artifacts, expected_bpf_state_scope)?;
    let filesystem_comparison = verify_filesystem_state_confirmation(
        &manifest,
        &mut artifacts,
        expected_filesystem_state_scope,
        expected_filesystem_actor_contract,
    )?;
    let artifacts_verified = expected_artifact_names(&manifest).len();
    artifacts.finish()?;
    verify_manifest_path(directory, manifest_state)?;
    verify_directory_path(directory, directory_state)?;

    let state_domains = effects_run::system_state_domain_vector(
        bpf_state_verdict.as_ref(),
        filesystem_comparison
            .as_ref()
            .map(|comparison| comparison.verdict),
    );
    Ok(EffectsVerificationReport {
        schema_version: EFFECT_EVENT_SCHEMA_VERSION,
        run_id: manifest.run_id,
        run_epoch: manifest.run_epoch,
        manifest_sha256,
        artifacts_verified,
        events_verified,
        recorder_object_sha256: manifest.expected_recorder_object_sha256,
        policy_profile: manifest.policy_profile,
        object_resolution_mode: manifest.object_resolution_mode,
        external_recorder_digest_checked: true,
        transport_complete: true,
        attribution_contract: manifest.attribution_contract,
        direct_event_attribution_validated: true,
        causal_attribution_complete: false,
        coverage_complete: false,
        operation_events_are_state_diff: false,
        bpf_state_confirmation_verified: bpf_state_verdict.is_some(),
        external_bpf_state_scope_checked: expected_bpf_state_scope.is_some(),
        bpf_state_verdict,
        filesystem_artifact_consistency_verified: filesystem_comparison.is_some(),
        external_filesystem_state_scope_exact_match: filesystem_comparison.is_some()
            && expected_filesystem_state_scope.is_some(),
        external_filesystem_actor_contract_exact_match: filesystem_comparison.is_some()
            && expected_filesystem_actor_contract.is_some(),
        filesystem_endpoint_difference: filesystem_comparison
            .as_ref()
            .map(|comparison| comparison.endpoint_difference),
        filesystem_state_verdict: filesystem_comparison
            .as_ref()
            .map(|comparison| comparison.verdict),
        filesystem_state_completeness: filesystem_comparison
            .as_ref()
            .map(|comparison| comparison.state_completeness.status),
        filesystem_actor_contract_status: filesystem_comparison
            .as_ref()
            .map(|comparison| comparison.actor_contract_status),
        filesystem_actor_contract_trust: filesystem_comparison.as_ref().map(|comparison| {
            if comparison.actor_contract_status == ActorContractStatus::Missing {
                FilesystemActorContractTrust::NotProvided
            } else {
                FilesystemActorContractTrust::ExternalExactInputNotAuthenticatedByObserver
            }
        }),
        filesystem_causal_attribution: filesystem_comparison
            .as_ref()
            .map(|comparison| comparison.causal_attribution_status),
        filesystem_limitations: filesystem_comparison
            .as_ref()
            .map(|comparison| comparison.limitations.clone())
            .unwrap_or_default(),
        state_domains,
    })
}

fn verify_bpf_state_confirmation(
    manifest: &EffectsManifest,
    artifacts: &mut VerifiedArtifacts<'_>,
    expected_scope: Option<&ClaimScope>,
) -> Result<Option<StateVerdict>> {
    let confirmation = match (manifest.bpf_state_confirmation.as_ref(), expected_scope) {
        (None, None) => return Ok(None),
        (None, Some(_)) => bail!("externally required BPF state confirmation is absent"),
        (Some(_), None) => {
            bail!("BPF state confirmation requires an externally trusted expected scope")
        }
        (Some(confirmation), Some(expected)) => {
            if confirmation.scope != *expected {
                bail!("BPF state confirmation scope does not match external trust policy");
            }
            confirmation
        }
    };
    if confirmation.protocol_version != effects_run::BPF_STATE_CONFIRMATION_PROTOCOL_VERSION
        || confirmation.confirmation_domain != effects_run::BPF_STATE_CONFIRMATION_DOMAIN
        || confirmation.s0_artifact != effects_run::BPF_STATE_S0_NAME
        || confirmation.s1_artifact != effects_run::BPF_STATE_S1_NAME
        || confirmation.verdict_artifact != effects_run::BPF_STATE_VERDICT_NAME
        || confirmation.operation_events_are_state_diff
        || confirmation.unchanged_verdict_authorized
    {
        bail!("BPF state confirmation declares an unsupported or overstated contract");
    }
    run::validate_observe_scope(&confirmation.scope)
        .context("validate confirmed BPF state scope")?;
    bpf_observer_oracle::validate_claim_scope_exclusions(
        &confirmation.scope,
        &confirmation.observer_exclusions,
    )
    .context("validate confirmed BPF state recorder exclusions")?;
    if confirmation.observer_exclusions.program_ids.is_empty()
        || confirmation.observer_exclusions.map_ids.is_empty()
        || confirmation.observer_exclusions.link_ids.is_empty()
    {
        bail!("BPF state confirmation omitted recorder-owned object exclusions");
    }

    let s0: Snapshot =
        artifacts.read_json(effects_run::BPF_STATE_S0_NAME, MAX_SNAPSHOT_JSON_BYTES)?;
    let s1: Snapshot =
        artifacts.read_json(effects_run::BPF_STATE_S1_NAME, MAX_SNAPSHOT_JSON_BYTES)?;
    let verdict: Verdict =
        artifacts.read_json(effects_run::BPF_STATE_VERDICT_NAME, MAX_VERDICT_JSON_BYTES)?;
    validate_snapshot_resource_bounds(&s0).context("validate BPF state S0 resource bounds")?;
    validate_snapshot_resource_bounds(&s1).context("validate BPF state S1 resource bounds")?;

    let expected_s0_id = format!("{}-EFFECTS-BPF-S0", manifest.run_id);
    let expected_s1_id = format!("{}-EFFECTS-BPF-S1", manifest.run_id);
    if s0.snapshot_id != expected_s0_id
        || s1.snapshot_id != expected_s1_id
        || s0.phase != "S0"
        || s1.phase != "S1"
        || s0.claim_scope != confirmation.scope
        || s1.claim_scope != confirmation.scope
        || s0.observer_exclusions != confirmation.observer_exclusions
        || s1.observer_exclusions != confirmation.observer_exclusions
        || s0.boot_id != manifest.boot_id
        || s1.boot_id != manifest.boot_id
        || s0.kernel_release != manifest.kernel_release
        || s1.kernel_release != manifest.kernel_release
    {
        bail!("BPF state snapshots are not bound to the effects run, scope, and exclusions");
    }

    let recomputed = effects_run::compare_bpf_state_endpoints(&s0, &s1)
        .context("recompute BPF state confirmation verdict")?;
    if verdict != recomputed {
        bail!("stored BPF state verdict does not match the verified endpoint snapshots");
    }
    if verdict.run_status != RunStatus::Provisional
        || verdict.state_verdict == StateVerdict::UnchangedWithinScope
        || confirmation.state_verdict != verdict.state_verdict
        || confirmation.state_completeness != verdict.state_completeness.status
        || confirmation.evidence_status != verdict.evidence_status.status
        || confirmation.attribution != verdict.attribution
    {
        bail!("BPF state confirmation summary does not match its conservative verdict");
    }
    Ok(Some(verdict.state_verdict))
}

fn verify_filesystem_state_confirmation(
    manifest: &EffectsManifest,
    artifacts: &mut VerifiedArtifacts<'_>,
    expected_scope: Option<&FilesystemScope>,
    expected_actor_contract: Option<&ActorQuiescenceContract>,
) -> Result<Option<FilesystemComparison>> {
    let confirmation = match manifest.filesystem_state_confirmation.as_ref() {
        None => {
            if expected_scope.is_some() || expected_actor_contract.is_some() {
                bail!("externally required filesystem state confirmation is absent");
            }
            return Ok(None);
        }
        Some(confirmation) => confirmation,
    };
    let expected_scope = expected_scope
        .context("filesystem state confirmation requires an externally trusted scope")?;
    expected_scope
        .validate()
        .context("validate externally trusted filesystem scope")?;
    let evidence_directory = fs::canonicalize(artifacts.directory)
        .context("canonicalize filesystem evidence directory")?;
    effects_run::validate_filesystem_output_separation(expected_scope, &evidence_directory)
        .context("verify filesystem scope is separate from the evidence directory")?;
    if confirmation.protocol_version != FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION
        || confirmation.confirmation_domain != FILESYSTEM_CONFIRMATION_DOMAIN
        || confirmation.scope_sha256 != expected_scope.sha256()?
        || confirmation.s0_artifact != effects_run::FILESYSTEM_STATE_S0_NAME
        || confirmation.s1_artifact != effects_run::FILESYSTEM_STATE_S1_NAME
        || confirmation.comparison_artifact != effects_run::FILESYSTEM_STATE_COMPARISON_NAME
        || confirmation.operation_events_are_state_diff
        || confirmation.atomic_with_other_confirmation_domains
        || confirmation.actor_contract_authenticated_by_observer
    {
        bail!("filesystem state confirmation declares an unsupported or overstated contract");
    }

    let actor_contract = match (
        confirmation.actor_contract_artifact.as_deref(),
        expected_actor_contract,
    ) {
        (None, None) => {
            if confirmation.actor_contract_status != ActorContractStatus::Missing {
                bail!("filesystem confirmation claims an absent actor contract");
            }
            None
        }
        (None, Some(_)) => bail!("externally required filesystem actor contract is absent"),
        (Some(_), None) => {
            bail!("filesystem actor contract requires an externally trusted exact contract")
        }
        (Some(name), Some(expected)) => {
            if name != effects_run::FILESYSTEM_ACTOR_CONTRACT_NAME {
                bail!("filesystem confirmation names an unexpected actor contract artifact");
            }
            expected
                .validate()
                .context("validate externally trusted filesystem actor contract")?;
            let stored: ActorQuiescenceContract = artifacts.read_json(
                effects_run::FILESYSTEM_ACTOR_CONTRACT_NAME,
                HARD_MAX_ACTOR_CONTRACT_JSON_BYTES,
            )?;
            if stored != *expected {
                bail!("filesystem actor contract does not match external trust policy");
            }
            Some(stored)
        }
    };

    let s0: FilesystemSnapshot = artifacts.read_json(
        effects_run::FILESYSTEM_STATE_S0_NAME,
        HARD_MAX_SNAPSHOT_JSON_BYTES,
    )?;
    let s1: FilesystemSnapshot = artifacts.read_json(
        effects_run::FILESYSTEM_STATE_S1_NAME,
        HARD_MAX_SNAPSHOT_JSON_BYTES,
    )?;
    let stored_comparison: FilesystemComparison = artifacts.read_json(
        effects_run::FILESYSTEM_STATE_COMPARISON_NAME,
        HARD_MAX_COMPARISON_JSON_BYTES,
    )?;
    if stored_comparison.verdict == FilesystemVerdict::UnchangedWithinScope
        || confirmation.state_verdict == FilesystemVerdict::UnchangedWithinScope
    {
        bail!(
            "filesystem confirmation protocol v1 cannot authorize UNCHANGED_WITHIN_SCOPE from an unauthenticated actor contract"
        );
    }
    s0.validate().context("validate filesystem state S0")?;
    s1.validate().context("validate filesystem state S1")?;
    let expected_s0_id =
        effects_run::filesystem_snapshot_id(&manifest.run_id, manifest.run_epoch, "S0");
    let expected_s1_id =
        effects_run::filesystem_snapshot_id(&manifest.run_id, manifest.run_epoch, "S1");
    if s0.snapshot_id != expected_s0_id
        || s1.snapshot_id != expected_s1_id
        || s0.phase != FilesystemSnapshotPhase::S0
        || s1.phase != FilesystemSnapshotPhase::S1
        || s0.scope != *expected_scope
        || s1.scope != *expected_scope
        || s0.scope_sha256 != confirmation.scope_sha256
        || s1.scope_sha256 != confirmation.scope_sha256
        || s0.boot_id != manifest.boot_id
        || s1.boot_id != manifest.boot_id
        || s0.captured_unix_ns < manifest.started_unix_ns
        || s1.captured_unix_ns < s0.captured_unix_ns
        || Some(s1.captured_unix_ns) > manifest.finalized_unix_ns
    {
        bail!("filesystem snapshots are not bound to the effects run and external scope");
    }

    let recomputed = compare_filesystem(&s0, &s1, actor_contract.as_ref())
        .context("recompute filesystem endpoint comparison")?;
    if stored_comparison != recomputed {
        bail!("stored filesystem comparison does not match verified endpoint snapshots");
    }
    if confirmation.endpoint_difference != recomputed.endpoint_difference
        || confirmation.state_verdict != recomputed.verdict
        || confirmation.state_completeness != recomputed.state_completeness.status
        || confirmation.actor_contract_status != recomputed.actor_contract_status
        || confirmation.causal_attribution_status != recomputed.causal_attribution_status
    {
        bail!("filesystem manifest summary does not match its recomputed comparison");
    }
    Ok(Some(recomputed))
}

fn validate_directory(directory: &Path) -> Result<FileState> {
    let metadata = fs::symlink_metadata(directory).with_context(|| {
        format!(
            "inspect system-effect run directory {}",
            directory.display()
        )
    })?;
    if !metadata.file_type().is_dir() {
        bail!("system-effect run path must be a non-symlink directory");
    }
    Ok(file_state(&metadata))
}

fn validate_manifest(
    manifest: &EffectsManifest,
    trusted_digest: &str,
    trusted_profile: PolicyProfile,
    trusted_object_resolution: ObjectResolutionMode,
) -> Result<()> {
    let evidence_kind_valid = (manifest.evidence_kind == effects_run::EVIDENCE_KIND_V1
        && manifest.filesystem_state_confirmation.is_none())
        || (manifest.evidence_kind == effects_run::EVIDENCE_KIND_FILESYSTEM_V2
            && manifest.filesystem_state_confirmation.is_some());
    if manifest.schema_version != EFFECT_EVENT_SCHEMA_VERSION
        || !evidence_kind_valid
        || manifest.run_status != EffectRunStatus::Finalized
        || manifest.failure.is_some()
        || manifest.started_unix_ns == 0
        || manifest.finalized_unix_ns.is_none()
        || manifest.finalized_unix_ns < Some(manifest.started_unix_ns)
        || manifest.run_epoch == 0
        || manifest.cgroup_id == 0
    {
        bail!("system-effect manifest is not a valid committed FINALIZED run");
    }
    run::validate_run_id(&manifest.run_id).context("validate system-effect manifest run_id")?;
    run::validate_cgroup_root(Path::new(&manifest.cgroup_path))
        .context("validate system-effect manifest cgroup path")?;
    if Path::new(&manifest.cgroup_path)
        .file_name()
        .and_then(|name| name.to_str())
        != Some(manifest.run_id.as_str())
    {
        bail!("system-effect manifest cgroup path is not bound to run_id");
    }
    if manifest.workload.first().map(String::is_empty) != Some(false) {
        bail!("system-effect manifest has no workload executable");
    }
    let workload_bytes = manifest
        .workload
        .iter()
        .try_fold(0usize, |total, argument| {
            if argument.contains('\0') {
                bail!("system-effect manifest workload contains NUL");
            }
            total
                .checked_add(argument.len())
                .context("system-effect workload argv size overflow")
        })?;
    if workload_bytes > MAX_WORKLOAD_ARGV_BYTES {
        bail!("system-effect manifest workload argv exceeds its producer limit");
    }
    match (manifest.workload_exit_code, manifest.workload_signal) {
        (Some(code), None) if (0..=255).contains(&code) => {}
        (None, Some(signal)) if (1..128).contains(&signal) => {}
        _ => bail!("system-effect manifest has an invalid workload termination status"),
    }
    if manifest.policy_artifact != POLICY_NAME {
        bail!("system-effect manifest names an unexpected policy artifact");
    }
    validate_sha256(&manifest.policy_sha256, "system-effect policy")?;
    validate_sha256(
        &manifest.expected_recorder_object_sha256,
        "manifest expected recorder object",
    )?;
    let loaded = manifest
        .loaded_recorder_object_sha256
        .as_deref()
        .context("system-effect manifest omitted the loaded recorder digest")?;
    validate_sha256(loaded, "manifest loaded recorder object")?;
    if loaded != manifest.expected_recorder_object_sha256 {
        bail!("loaded system-effect recorder digest disagrees with manifest policy");
    }
    if trusted_digest != loaded {
        bail!("system-effect recorder digest does not match external trust policy");
    }
    if trusted_profile != manifest.policy_profile {
        bail!("system-effect policy profile does not match external trust policy");
    }
    if trusted_object_resolution != manifest.object_resolution_mode {
        bail!("system-effect object resolution does not match external trust policy");
    }
    if manifest.kernel_release.is_empty()
        || manifest.kernel_release.contains('\0')
        || !is_canonical_boot_id(&manifest.boot_id)
        || manifest.observer_version != env!("CARGO_PKG_VERSION")
        || manifest
            .source_commit
            .as_deref()
            .map_or(false, |commit| commit.is_empty() || commit.contains('\0'))
    {
        bail!("system-effect manifest has invalid environment identity");
    }
    if !manifest.cgroup_frozen_at_close
        || manifest.transport_status != Some(TransportStatus::Complete)
    {
        bail!("system-effect manifest lacks a complete producer close boundary");
    }
    manifest
        .attribution_contract
        .validate()
        .context("validate system-effect attribution contract")?;
    validate_coverage(
        &manifest.coverage,
        manifest.policy_profile,
        manifest.object_resolution_mode,
    )?;
    if !manifest.notes.iter().any(|note| note.contains("not proof"))
        || manifest.notes.iter().any(|note| note.contains('\0'))
    {
        bail!("system-effect manifest omits its non-state-diff interpretation warning");
    }
    validate_output_bound(manifest, STDOUT_NAME, manifest.workload_stdout_truncated)?;
    validate_output_bound(manifest, STDERR_NAME, manifest.workload_stderr_truncated)?;
    Ok(())
}

fn validate_output_bound(manifest: &EffectsManifest, name: &str, truncated: bool) -> Result<()> {
    let artifact = manifest
        .artifacts
        .get(name)
        .with_context(|| format!("system-effect manifest omitted artifact {name}"))?;
    if artifact.size_bytes > MAX_WORKLOAD_OUTPUT_BYTES
        || (truncated && artifact.size_bytes != MAX_WORKLOAD_OUTPUT_BYTES)
    {
        bail!("system-effect {name} truncation metadata disagrees with artifact size");
    }
    Ok(())
}

fn validate_coverage(
    coverage: &CoverageDescription,
    profile: PolicyProfile,
    object_resolution_mode: ObjectResolutionMode,
) -> Result<()> {
    let mut expected_gaps =
        coverage_gaps_for(profile, recorder_resolution_mode(object_resolution_mode));
    expected_gaps.push(STANDALONE_ISOLATION_GAP.to_owned());
    expected_gaps.sort();
    expected_gaps.dedup();
    if coverage.attribution_scope != "SELECTED_NATIVE_SYSCALLS_FROM_EXACT_CGROUP_V2_ID"
        || coverage.event_semantics != "OPERATION_ATTEMPT_AND_RETURN_NOT_DURABLE_STATE_DIFF"
        || coverage.operation_events_are_state_diff
        || coverage.durable_state_change_proven
        || coverage.rollback_completeness_proven
        || coverage.workload_privilege_isolation_enforced
        || coverage.evidence_write_isolation_enforced
        || coverage.coverage_status != "PARTIAL"
        || coverage.object_resolution_status != "PARTIAL"
        || coverage.gaps != expected_gaps
    {
        bail!("system-effect manifest overstates or ambiguously encodes coverage");
    }
    Ok(())
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
    }
}

fn validate_policy(manifest: &EffectsManifest, policy: &PolicyArtifact) -> Result<()> {
    let expected_entries = describe_policy(manifest.policy_profile)?;
    let expected_digest = policy_sha256(manifest.policy_profile)?;
    if policy.schema_version != EFFECT_EVENT_SCHEMA_VERSION
        || policy.profile != manifest.policy_profile
        || policy.policy_sha256 != manifest.policy_sha256
        || policy.policy_sha256 != expected_digest
        || policy.entries != expected_entries
        || policy.entries.len() != manifest.policy_entry_count
        || policy.entries.is_empty()
    {
        bail!("system-effect policy artifact does not match the compiled frozen policy");
    }
    Ok(())
}

fn validate_health(manifest: &EffectsManifest, health: &SystemEffectHealth) -> Result<()> {
    if health.schema_version != EFFECT_EVENT_SCHEMA_VERSION
        || health.run_id != manifest.run_id
        || health.run_epoch != manifest.run_epoch
        || health.cgroup_id != manifest.cgroup_id
        || health.profile != manifest.policy_profile
        || health.object_resolution_mode
            != recorder_resolution_mode(manifest.object_resolution_mode)
        || health.transport_status != TransportStatus::Complete
        || health.coverage_status != CoverageStatus::Partial
        || health.object_resolution_status != ObjectResolutionStatus::Partial
        || !health.producer_barrier_complete
        || !health.drain_completed
        || !health.wal_durable
        || !health.reasons.is_empty()
    {
        bail!("system-effect health is not bound COMPLETE transport evidence");
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
        || health.object_pending_remaining != 0
        || health.userspace_failures != 0
        || health.fatal_kernel_flags != 0
        || health.events_persisted == 0
        || health.events_persisted > MAX_EVENTS
    {
        bail!("system-effect health violates lossless accounting invariants");
    }
    match health.object_resolution_mode {
        FileObjectResolutionMode::UserInput => {
            if health.object_resolution_attempted != 0
                || health.object_resolution_resolved != 0
                || health.object_resolution_unresolved != 0
                || health.object_resolution_failed_syscalls != 0
                || health.object_join_missing != 0
                || health.object_join_ambiguous != 0
                || health.object_read_failed != 0
                || health.object_delete_failed != 0
                || health.object_path_unavailable != 0
            {
                bail!("user-input health contains kernel file-object activity");
            }
        }
        FileObjectResolutionMode::KernelFileOpenPartial
        | FileObjectResolutionMode::KernelFileOpenWritePartial => {
            if health
                .object_resolution_resolved
                .checked_add(health.object_resolution_unresolved)
                != Some(health.object_resolution_attempted)
                || health.object_resolution_failed_syscalls != health.object_resolution_unresolved
                || health.object_join_missing != 0
                || health.object_join_ambiguous != 0
                || health.object_read_failed != 0
                || health.object_delete_failed != 0
            {
                bail!("kernel file-object health violates resolution accounting invariants");
            }
        }
    }
    if health.poll_calls == 0
        || health.callback_queue_capacity != CALLBACK_QUEUE_CAPACITY
        || health.callback_queue_high_water == 0
        || health.maximum_events_per_poll == 0
        || health.callback_queue_high_water > health.callback_queue_capacity
        || health.maximum_events_per_poll > health.callback_queue_high_water
        || health.capture_read_failures > health.operation_attempted
        || health.capture_truncations > health.operation_attempted
        || health.capture_invalid_lengths > health.operation_attempted
    {
        bail!("system-effect health has invalid resource or capture counters");
    }
    if health.coverage_gaps
        != coverage_gaps_for(
            manifest.policy_profile,
            recorder_resolution_mode(manifest.object_resolution_mode),
        )
    {
        bail!("system-effect health coverage gaps are not bound into the manifest");
    }
    Ok(())
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

struct ArtifactReader {
    name: String,
    file: File,
    before: fs::Metadata,
    expected: ArtifactDigest,
    hasher: Sha256,
    bytes_read: u64,
}

impl ArtifactReader {
    fn open(
        directory: &Path,
        name: &str,
        expected: &ArtifactDigest,
        max_bytes: u64,
    ) -> Result<Self> {
        validate_sha256(&expected.sha256, &format!("artifact {name}"))?;
        if expected.size_bytes > max_bytes {
            bail!("artifact {name} exceeds its {max_bytes}-byte verification limit");
        }
        let path = directory.join(name);
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .with_context(|| format!("open system-effect artifact {}", path.display()))?;
        let before = file
            .metadata()
            .with_context(|| format!("inspect system-effect artifact {}", path.display()))?;
        if !before.file_type().is_file() || before.nlink() != 1 {
            bail!("system-effect artifact {name} must be a singly linked regular file");
        }
        if before.len() != expected.size_bytes {
            bail!("system-effect artifact {name} size does not match manifest");
        }
        Ok(Self {
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
        if !same_file_state(&self.before, &after) {
            bail!("system-effect artifact {} changed while read", self.name);
        }
        if self.bytes_read != self.expected.size_bytes {
            bail!("system-effect artifact {} byte count changed", self.name);
        }
        if format!("{:x}", self.hasher.finalize()) != self.expected.sha256 {
            bail!(
                "system-effect artifact {} SHA-256 does not match manifest",
                self.name
            );
        }
        Ok(file_state(&after))
    }
}

impl Read for ArtifactReader {
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

struct VerifiedArtifacts<'a> {
    directory: &'a Path,
    manifest: &'a EffectsManifest,
    states: BTreeMap<String, FileState>,
}

impl<'a> VerifiedArtifacts<'a> {
    fn new(directory: &'a Path, manifest: &'a EffectsManifest) -> Result<Self> {
        verify_artifact_names(directory, manifest)?;
        Ok(Self {
            directory,
            manifest,
            states: BTreeMap::new(),
        })
    }

    fn open(&self, name: &str, max_bytes: u64) -> Result<ArtifactReader> {
        let expected = self
            .manifest
            .artifacts
            .get(name)
            .with_context(|| format!("system-effect manifest omitted artifact {name}"))?;
        ArtifactReader::open(self.directory, name, expected, max_bytes)
    }

    fn record(&mut self, name: &str, state: FileState) -> Result<()> {
        if self.states.insert(name.to_owned(), state).is_some() {
            bail!("system-effect artifact {name} was verified twice");
        }
        Ok(())
    }

    fn read_json<T: DeserializeOwned>(&mut self, name: &str, max_bytes: u64) -> Result<T> {
        let mut artifact = self.open(name, max_bytes)?;
        let value = serde_json::from_reader(&mut artifact)
            .with_context(|| format!("parse system-effect JSON artifact {name}"))?;
        let state = artifact.finish()?;
        self.record(name, state)?;
        Ok(value)
    }

    fn verify_event_streams(
        &mut self,
        manifest: &EffectsManifest,
        health: &SystemEffectHealth,
        policy_by_syscall: &HashMap<i32, &PolicyDescription>,
    ) -> Result<u64> {
        let mut wal = self.open(WAL_NAME, MAX_WAL_BYTES)?;
        let mut jsonl = self.open(JSONL_NAME, MAX_JSONL_BYTES)?;
        let count = {
            let mut json_reader = BufReader::new(&mut jsonl);
            verify_stream_records(
                &mut wal,
                &mut json_reader,
                manifest,
                health,
                policy_by_syscall,
            )?
        };
        let wal_state = wal.finish()?;
        let jsonl_state = jsonl.finish()?;
        self.record(WAL_NAME, wal_state)?;
        self.record(JSONL_NAME, jsonl_state)?;
        Ok(count)
    }

    fn verify_only(&mut self, name: &str, max_bytes: u64) -> Result<()> {
        let state = self.open(name, max_bytes)?.finish()?;
        self.record(name, state)
    }

    fn finish(self) -> Result<()> {
        let expected = expected_artifact_names(self.manifest);
        if self.states.keys().cloned().collect::<BTreeSet<_>>() != expected {
            bail!("not every finalized system-effect artifact was verified");
        }
        verify_artifact_names(self.directory, self.manifest)?;
        for (name, state) in self.states {
            let path = self.directory.join(&name);
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&path)
                .with_context(|| format!("reopen verified artifact {}", path.display()))?;
            let metadata = file.metadata()?;
            if !metadata.file_type().is_file()
                || metadata.nlink() != 1
                || file_state(&metadata) != state
            {
                bail!("system-effect artifact {name} pathname changed during verification");
            }
        }
        Ok(())
    }
}

fn verify_stream_records(
    wal: &mut ArtifactReader,
    jsonl: &mut impl BufRead,
    manifest: &EffectsManifest,
    health: &SystemEffectHealth,
    policy_by_syscall: &HashMap<i32, &PolicyDescription>,
) -> Result<u64> {
    let total = usize::try_from(health.events_persisted)
        .context("system-effect event count is not representable")?;
    let mut seen_sequences = vec![false; total];
    let mut attempts = AttemptReplayState::default();
    let mut attempted = 0u64;
    let mut completed = 0u64;
    let mut capture_read_failures = 0u64;
    let mut capture_truncations = 0u64;
    let mut capture_invalid_lengths = 0u64;
    let mut object_resolution_attempted = 0u64;
    let mut object_resolution_resolved = 0u64;
    let mut object_resolution_unresolved = 0u64;
    let mut object_resolution_failed_syscalls = 0u64;
    let mut object_join_missing = 0u64;
    let mut object_join_ambiguous = 0u64;
    let mut object_read_failed = 0u64;
    let mut object_delete_failed = 0u64;
    let mut object_path_unavailable = 0u64;
    let mut count = 0u64;

    loop {
        let raw = read_wal_frame(wal)?;
        let json = read_json_line(jsonl)?;
        let (raw, json) = match (raw, json) {
            (None, None) => break,
            (Some(_), None) | (None, Some(_)) => {
                bail!("system-effect WAL/JSONL event count mismatch")
            }
            (Some(raw), Some(json)) => (raw, json),
        };
        count = count
            .checked_add(1)
            .context("system-effect event count overflow")?;
        if count > MAX_EVENTS || count > health.events_persisted {
            bail!("system-effect event stream exceeds its bound health count");
        }
        if raw.run_epoch != manifest.run_epoch || raw.cgroup_id != manifest.cgroup_id {
            bail!("system-effect WAL event is not bound to the finalized run");
        }
        let sequence_index = raw
            .event_seq
            .checked_sub(1)
            .and_then(|sequence| usize::try_from(sequence).ok())
            .filter(|index| *index < seen_sequences.len())
            .context("system-effect event sequence is outside the complete range")?;
        if std::mem::replace(&mut seen_sequences[sequence_index], true) {
            bail!("system-effect event stream contains a duplicate sequence");
        }
        let policy = policy_by_syscall
            .get(&raw.syscall_nr)
            .context("system-effect event syscall is absent from frozen policy")?;
        if raw.domain != policy.domain as u16 || raw.operation != policy.operation as u32 {
            bail!("system-effect WAL event disagrees with frozen policy identity");
        }
        validate_event_policy(&raw, policy)?;
        validate_json_event(&raw, &json, manifest, policy)?;
        if raw.flags & FATAL_FLAGS != 0 {
            bail!("COMPLETE system-effect stream contains a fatal correlation flag");
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
        object_join_missing += u64::from(raw.flags & FLAG_OBJECT_JOIN_MISSING != 0);
        object_join_ambiguous += u64::from(raw.flags & FLAG_OBJECT_JOIN_AMBIGUOUS != 0);
        object_read_failed += u64::from(raw.flags & FLAG_OBJECT_READ_FAILED != 0);
        object_delete_failed += u64::from(raw.flags & FLAG_OBJECT_DELETE_FAILED != 0);
        object_path_unavailable += u64::from(raw.flags & FLAG_OBJECT_PATH_UNAVAILABLE != 0);
        let object_accounting =
            replay_object_resolution(manifest.object_resolution_mode, &raw, policy)?;

        match raw.kind {
            EVENT_ATTEMPT => {
                attempted += 1;
                attempts.start(&raw)?;
            }
            EVENT_RESULT => {
                completed += 1;
                match object_accounting {
                    ReplayedObjectResolution::NotApplicable => {}
                    ReplayedObjectResolution::Resolved => {
                        object_resolution_attempted += 1;
                        object_resolution_resolved += 1;
                    }
                    ReplayedObjectResolution::FailedSyscall => {
                        object_resolution_attempted += 1;
                        object_resolution_unresolved += 1;
                        object_resolution_failed_syscalls += 1;
                    }
                }
                attempts.complete(&raw)?;
            }
            _ => unreachable!("KernelEvent decoder rejected unknown kinds"),
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
        || object_resolution_attempted != health.object_resolution_attempted
        || object_resolution_resolved != health.object_resolution_resolved
        || object_resolution_unresolved != health.object_resolution_unresolved
        || object_resolution_failed_syscalls != health.object_resolution_failed_syscalls
        || object_join_missing != health.object_join_missing
        || object_join_ambiguous != health.object_join_ambiguous
        || object_read_failed != health.object_read_failed
        || object_delete_failed != health.object_delete_failed
        || object_path_unavailable != health.object_path_unavailable
    {
        bail!("system-effect streams do not reproduce health accounting");
    }
    Ok(count)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplayedObjectResolution {
    NotApplicable,
    Resolved,
    FailedSyscall,
}

fn replay_object_resolution(
    mode: ObjectResolutionMode,
    raw: &KernelEvent,
    policy: &PolicyDescription,
) -> Result<ReplayedObjectResolution> {
    let resolver = KernelObjectResolver::for_operation(policy.operation);
    let required = if raw.kind != EVENT_RESULT {
        false
    } else {
        match mode {
            ObjectResolutionMode::UserInput => false,
            ObjectResolutionMode::KernelFileOpenPartial => {
                resolver == KernelObjectResolver::FileOpen
            }
            ObjectResolutionMode::KernelFileOpenWritePartial => match resolver {
                KernelObjectResolver::FileOpen => true,
                KernelObjectResolver::FilePermissionWrite => raw.return_value > 0,
                KernelObjectResolver::None => false,
            },
        }
    };
    if !required {
        if raw.file_object.is_some() {
            bail!("system-effect stream contains FILE_OBJECT evidence outside the selected mode and eligible result set");
        }
        return Ok(ReplayedObjectResolution::NotApplicable);
    }
    if resolver == KernelObjectResolver::FileOpen && raw.return_value < 0 {
        if raw.file_object.is_some() {
            bail!("failed file-open result contains FILE_OBJECT evidence");
        }
        return Ok(ReplayedObjectResolution::FailedSyscall);
    }
    if raw.file_object.is_none() {
        bail!("eligible successful file-object result silently downgraded without FILE_OBJECT evidence");
    }
    Ok(ReplayedObjectResolution::Resolved)
}

fn validate_event_policy(raw: &KernelEvent, policy: &PolicyDescription) -> Result<()> {
    if raw.kind != EVENT_ATTEMPT {
        return Ok(());
    }

    let mut expected_kinds = [PAYLOAD_NONE; 2];
    let mut expected_indices = [0u8; 2];
    if policy.capture.len() > expected_kinds.len() {
        bail!("system-effect policy has more captures than the recorder ABI supports");
    }
    for (slot, capture) in policy.capture.iter().enumerate() {
        expected_kinds[slot] = match capture.kind.as_str() {
            "USER_SUPPLIED_STRING" => PAYLOAD_USER_STRING,
            "RAW_USER_SOCKADDR" => PAYLOAD_SOCKADDR,
            _ => bail!("system-effect policy has an unknown capture kind"),
        };
        expected_indices[slot] = capture.argument_index;
    }
    if raw.payload_kinds != expected_kinds || raw.payload_arg_indices != expected_indices {
        bail!("system-effect WAL capture metadata disagrees with frozen policy");
    }

    if let Some(filter) = policy.kernel_filter.as_ref() {
        if filter.kind != "ARG_ANY_BITS" || filter.mask == 0 {
            bail!("system-effect policy has an unsupported kernel filter");
        }
        let argument = raw
            .args
            .get(usize::from(filter.argument_index))
            .context("system-effect policy filter argument is outside the syscall ABI")?;
        if argument & filter.mask == 0 {
            bail!("system-effect WAL attempt does not satisfy its frozen policy filter");
        }
    }
    Ok(())
}

fn validate_json_event(
    raw: &KernelEvent,
    json: &SystemEffectEvent,
    manifest: &EffectsManifest,
    policy: &PolicyDescription,
) -> Result<()> {
    json.validate_object_resolution()
        .context("validate system-effect object-resolution protocol")?;
    json.validate_attribution()
        .context("validate system-effect attribution protocol")?;
    let expected_kind = match raw.kind {
        EVENT_ATTEMPT => EventKind::OperationAttempt,
        EVENT_RESULT => EventKind::OperationResult,
        _ => unreachable!("KernelEvent decoder rejected unknown kinds"),
    };
    let expected_return = (raw.kind == EVENT_RESULT).then_some(raw.return_value);
    let expected_status = expected_return.map(|value| classify_result(policy.operation, value));
    if json.schema_version != EFFECT_EVENT_SCHEMA_VERSION
        || json.run_id != manifest.run_id
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
        || json.object_resolution != expected_object_resolution(raw, &manifest.boot_id)
        || json.attribution != EffectAttribution::from_kernel_event(raw)
    {
        bail!("system-effect JSONL event does not derive from its WAL record");
    }
    Ok(())
}

fn expected_object_resolution(raw: &KernelEvent, boot_id: &str) -> ObjectResolution {
    let captures = expected_captures(raw);
    let objects = if let Some(object) = &raw.file_object {
        let path_len = usize::from(object.path_len);
        let path = match object.path_quality {
            FILE_PATH_NOT_REQUESTED => FilePathObservation::default(),
            FILE_PATH_UNAVAILABLE => FilePathObservation {
                quality: PathResolutionQuality::Unavailable,
                authority: PathResolutionAuthority::None,
                resolved_path: None,
            },
            FILE_PATH_RESOLVED_AT_HOOK => {
                let bytes = &object.path[..path_len];
                FilePathObservation {
                    quality: PathResolutionQuality::ResolvedAtHook,
                    authority: PathResolutionAuthority::KernelPathSnapshot,
                    resolved_path: Some(ResolvedPath {
                        display: String::from_utf8_lossy(bytes).into_owned(),
                        raw_hex: hex(bytes),
                    }),
                }
            }
            _ => unreachable!("KernelEvent decoder rejected unknown file path quality"),
        };
        vec![ObjectReference {
            slot: 0,
            role: ObjectRole::Primary,
            identity: ObjectIdentity::FileObject {
                boot_id: boot_id.to_owned(),
                mount_id_unique: object.mount_id_unique,
                device_major: object.device_major,
                device_minor: object.device_minor,
                inode: object.inode,
                inode_generation: (object.generation_valid == 1).then_some(object.inode_generation),
                filesystem_magic: object.filesystem_magic,
                filesystem_class: filesystem_class(object.filesystem_magic),
                path,
            },
        }]
    } else if raw.kind == EVENT_ATTEMPT {
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
    let (quality, authority) = if raw.file_object.is_some() {
        (
            ObjectResolutionQuality::KernelResolved,
            ObjectResolutionAuthority::KernelObjectHook,
        )
    } else if objects.is_empty() {
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

fn filesystem_class(magic: u64) -> FilesystemClass {
    match magic {
        0x9fa0 => FilesystemClass::Procfs,
        0x6265_6572 => FilesystemClass::Sysfs,
        0x27e0_eb => FilesystemClass::CgroupV1,
        0x6367_7270 => FilesystemClass::CgroupV2,
        _ => FilesystemClass::Other,
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
        bail!("unsupported system-effect WAL frame length {length}");
    }
    let mut payload = vec![0u8; length];
    read_exact_required(reader, &mut payload, "WAL frame payload")?;
    let mut checksum = [0u8; 4];
    read_exact_required(reader, &mut checksum, "WAL frame checksum")?;
    if crc32fast::hash(&payload) != u32::from_le_bytes(checksum) {
        bail!("system-effect WAL checksum mismatch");
    }
    KernelEvent::decode_le(&payload)
        .map(Some)
        .context("decode system-effect WAL event")
}

fn read_exact_or_eof(reader: &mut impl Read, output: &mut [u8], label: &str) -> Result<bool> {
    let mut offset = 0usize;
    while offset < output.len() {
        match reader.read(&mut output[offset..]) {
            Ok(0) if offset == 0 => return Ok(false),
            Ok(0) => bail!("system-effect {label} is truncated"),
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).with_context(|| format!("read system-effect {label}")),
        }
    }
    Ok(true)
}

fn read_exact_required(reader: &mut impl Read, output: &mut [u8], label: &str) -> Result<()> {
    if !read_exact_or_eof(reader, output, label)? {
        bail!("system-effect {label} is truncated");
    }
    Ok(())
}

fn read_json_line(reader: &mut impl BufRead) -> Result<Option<SystemEffectEvent>> {
    let mut bytes = Vec::new();
    let count = reader
        .take(MAX_EVENT_JSON_BYTES + 1)
        .read_until(b'\n', &mut bytes)
        .context("read system-effect JSONL event")?;
    if count == 0 {
        return Ok(None);
    }
    if count as u64 > MAX_EVENT_JSON_BYTES {
        bail!("system-effect JSONL event exceeds its per-line limit");
    }
    if bytes.last() != Some(&b'\n') {
        bail!("system-effect JSONL has a truncated final line");
    }
    if bytes[..bytes.len() - 1]
        .iter()
        .all(|byte| byte.is_ascii_whitespace())
    {
        bail!("system-effect JSONL contains a blank line");
    }
    serde_json::from_slice(&bytes).context("parse system-effect JSONL event")
}

fn read_manifest<T: DeserializeOwned>(directory: &Path) -> Result<(T, FileState, String)> {
    let path = directory.join(MANIFEST_NAME);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .with_context(|| format!("open system-effect manifest {}", path.display()))?;
    let before = file.metadata()?;
    if !before.file_type().is_file() || before.nlink() != 1 {
        bail!("system-effect manifest must be a singly linked regular file");
    }
    if before.len() > MAX_MANIFEST_BYTES {
        bail!("system-effect manifest exceeds its verification limit");
    }
    let capacity = usize::try_from(before.len()).context("manifest size is not representable")?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut reader = BufReader::new(file);
    reader
        .by_ref()
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = reader.get_ref().metadata()?;
    if bytes.len() as u64 != before.len() || !same_file_state(&before, &after) {
        bail!("system-effect manifest changed while it was read");
    }
    let value = serde_json::from_slice(&bytes).context("parse system-effect manifest")?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    Ok((value, file_state(&after), digest))
}

fn verify_manifest_path(directory: &Path, expected: FileState) -> Result<()> {
    let path = directory.join(MANIFEST_NAME);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .with_context(|| format!("reopen system-effect manifest {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 || file_state(&metadata) != expected
    {
        bail!("system-effect manifest pathname changed during verification");
    }
    Ok(())
}

fn verify_directory_path(directory: &Path, expected: FileState) -> Result<()> {
    let metadata = fs::symlink_metadata(directory).with_context(|| {
        format!(
            "reinspect system-effect run directory {}",
            directory.display()
        )
    })?;
    if !metadata.file_type().is_dir() || file_state(&metadata) != expected {
        bail!("system-effect run directory changed during verification");
    }
    Ok(())
}

fn verify_artifact_names(directory: &Path, manifest: &EffectsManifest) -> Result<()> {
    let expected = expected_artifact_names(manifest);
    if manifest.artifacts.keys().cloned().collect::<BTreeSet<_>>() != expected {
        bail!("system-effect manifest artifact set is not the closed v1 set");
    }
    let mut directory_entries = BTreeSet::new();
    for entry in fs::read_dir(directory)
        .with_context(|| format!("enumerate system-effect run {}", directory.display()))?
    {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("system-effect run has a non-UTF-8 entry"))?;
        if !directory_entries.insert(name.clone()) {
            bail!("system-effect run contains duplicate entry {name:?}");
        }
        if directory_entries.len() > expected.len() + 1 {
            bail!("system-effect run directory contains more than the closed v1 artifact set");
        }
    }
    let mut allowed = expected;
    allowed.insert(MANIFEST_NAME.to_owned());
    if directory_entries != allowed {
        bail!("system-effect run directory is not the closed finalized artifact set");
    }
    Ok(())
}

fn expected_artifact_names(manifest: &EffectsManifest) -> BTreeSet<String> {
    let mut expected = BASE_FINAL_ARTIFACTS
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    if manifest.bpf_state_confirmation.is_some() {
        expected.extend([
            effects_run::BPF_STATE_S0_NAME.to_owned(),
            effects_run::BPF_STATE_S1_NAME.to_owned(),
            effects_run::BPF_STATE_VERDICT_NAME.to_owned(),
        ]);
    }
    if let Some(confirmation) = manifest.filesystem_state_confirmation.as_ref() {
        expected.extend([
            effects_run::FILESYSTEM_STATE_S0_NAME.to_owned(),
            effects_run::FILESYSTEM_STATE_S1_NAME.to_owned(),
            effects_run::FILESYSTEM_STATE_COMPARISON_NAME.to_owned(),
        ]);
        if confirmation.actor_contract_artifact.is_some() {
            expected.insert(effects_run::FILESYSTEM_ACTOR_CONTRACT_NAME.to_owned());
        }
    }
    expected
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{label} digest is not canonical lowercase SHA-256");
    }
    Ok(())
}

fn is_canonical_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        })
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

fn same_file_state(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    file_state(left) == file_state(right)
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
    use bpf_observer_filesystem_confirmer::{
        capture as capture_filesystem, CaptureRequest as FilesystemCaptureRequest,
        FilesystemCaptureLimits, FilesystemCapturePolicy,
    };
    use bpf_observer_schema::{
        Completeness, MapContentState, MapMetadata, MapSampleStatus, MapState,
        ObjectIdentity as BpfObjectIdentity, ObjectType, SCHEMA_VERSION,
    };
    use bpf_observer_system_effects::{
        KernelFileObject, FLAG_USER_MEMORY_SNAPSHOT, KERNEL_FILE_PATH_BYTES,
    };
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const TEST_BOOT_ID: &str = "00000000-0000-0000-0000-000000000001";
    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create() -> Self {
            let nonce = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/effects-verify-tests")
                .join(format!("{}-{nonce}", std::process::id()));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_artifact(directory: &Path, name: &str, bytes: &[u8]) -> ArtifactDigest {
        fs::write(directory.join(name), bytes).unwrap();
        ArtifactDigest {
            sha256: format!("{:x}", Sha256::digest(bytes)),
            size_bytes: bytes.len() as u64,
        }
    }

    fn append_wal(bytes: &mut Vec<u8>, event: &KernelEvent) {
        let payload = event.encode_le();
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
    }

    fn json_event(
        raw: &KernelEvent,
        run_id: &str,
        policy: &PolicyDescription,
    ) -> SystemEffectEvent {
        SystemEffectEvent {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            run_id: run_id.to_owned(),
            run_epoch: raw.run_epoch,
            event_seq: raw.event_seq,
            related_attempt_seq: raw.related_attempt_seq,
            kind: if raw.kind == EVENT_ATTEMPT {
                EventKind::OperationAttempt
            } else {
                EventKind::OperationResult
            },
            domain: policy.domain,
            operation: policy.operation,
            syscall_nr: raw.syscall_nr,
            syscall_name: policy.syscall_name.clone(),
            ktime_ns: raw.ktime_ns,
            cgroup_id: raw.cgroup_id,
            pid: raw.pid_tgid as u32,
            tgid: (raw.pid_tgid >> 32) as u32,
            comm: nul_terminated_lossy(&raw.comm),
            raw_arguments: raw.args,
            captures: expected_captures(raw),
            object_resolution: expected_object_resolution(raw, TEST_BOOT_ID),
            attribution: EffectAttribution::from_kernel_event(raw),
            return_value: (raw.kind == EVENT_RESULT).then_some(raw.return_value),
            result_status: (raw.kind == EVENT_RESULT)
                .then(|| classify_result(policy.operation, raw.return_value)),
            flags: raw.flags,
            semantics: EVENT_SEMANTICS.to_owned(),
        }
    }

    fn bpf_state_snapshot(
        run_id: &str,
        phase: &str,
        scope: &ClaimScope,
        exclusions: &ObjectExclusions,
    ) -> Snapshot {
        Snapshot {
            schema_version: SCHEMA_VERSION,
            snapshot_id: format!("{run_id}-EFFECTS-BPF-{phase}"),
            phase: phase.to_owned(),
            boot_id: TEST_BOOT_ID.to_owned(),
            captured_unix_ns: 1,
            capture_duration_ns: 1,
            kernel_release: "test-kernel".to_owned(),
            byte_order: "little".to_owned(),
            possible_cpu_ids: vec![0],
            claim_scope: scope.clone(),
            observer_exclusions: exclusions.clone(),
            programs: Vec::new(),
            maps: vec![MapState {
                identity: BpfObjectIdentity {
                    boot_id: TEST_BOOT_ID.to_owned(),
                    object_type: ObjectType::Map,
                    id: 12,
                },
                metadata: MapMetadata {
                    // UAPI BPF_MAP_TYPE_RINGBUF.
                    map_type: 27,
                    name: "observer".to_owned(),
                    key_size: 0,
                    value_size: 0,
                    max_entries: 4096,
                    map_flags: 0,
                    map_extra: 0,
                    ifindex: 0,
                    netns_dev: 0,
                    netns_ino: 0,
                    btf_id: 0,
                    btf_key_type_id: 0,
                    btf_value_type_id: 0,
                    btf_vmlinux_value_type_id: 0,
                    frozen: None,
                },
                content: MapContentState {
                    status: MapSampleStatus::OutsideClaimScope,
                    semantic_complete: false,
                    entries: Vec::new(),
                    digest_sha256: None,
                    bytes_read: 0,
                    possible_cpu_ids: Vec::new(),
                    error: None,
                },
                excluded: true,
            }],
            links: Vec::new(),
            pin_roots: Vec::new(),
            pins: Vec::new(),
            read_failures: Vec::new(),
            completeness: Completeness::complete(),
            notes: Vec::new(),
        }
    }

    #[test]
    fn write_file_object_replay_is_mode_and_positive_result_bound() {
        let policy = describe_policy(PolicyProfile::Balanced)
            .unwrap()
            .into_iter()
            .find(|entry| entry.syscall_nr == libc::SYS_write as i32)
            .unwrap();
        let file_object = KernelFileObject {
            mount_id_unique: 44,
            inode: 55,
            filesystem_magic: 0xef53,
            device_major: 8,
            device_minor: 2,
            inode_generation: 9,
            path_len: 0,
            generation_valid: 1,
            path_quality: FILE_PATH_NOT_REQUESTED,
            path: [0; KERNEL_FILE_PATH_BYTES],
        };
        let resolved = KernelEvent {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            kind: EVENT_RESULT,
            domain: policy.domain as u16,
            operation: policy.operation as u32,
            flags: 0,
            syscall_nr: policy.syscall_nr,
            run_epoch: 1,
            event_seq: 2,
            related_attempt_seq: 1,
            ktime_ns: 2,
            cgroup_id: 3,
            pid_tgid: (4u64 << 32) | 5,
            return_value: 8,
            args: [6, 0x1000, 8, 0, 0, 0],
            comm: [0; 16],
            payload_lens: [0; 2],
            payload_kinds: [PAYLOAD_NONE; 2],
            payload_arg_indices: [0; 2],
            payloads: [[0; CAPTURE_BYTES]; 2],
            file_object: Some(file_object),
        };

        assert_eq!(
            replay_object_resolution(
                ObjectResolutionMode::KernelFileOpenWritePartial,
                &resolved,
                &policy,
            )
            .unwrap(),
            ReplayedObjectResolution::Resolved
        );

        let mut missing = resolved.clone();
        missing.file_object = None;
        let missing_error = replay_object_resolution(
            ObjectResolutionMode::KernelFileOpenWritePartial,
            &missing,
            &policy,
        )
        .unwrap_err();
        assert!(missing_error.to_string().contains("silently downgraded"));

        let error = replay_object_resolution(
            ObjectResolutionMode::KernelFileOpenPartial,
            &resolved,
            &policy,
        )
        .unwrap_err();
        assert!(error.to_string().contains("outside the selected mode"));

        let mut zero = resolved;
        zero.return_value = 0;
        let error = replay_object_resolution(
            ObjectResolutionMode::KernelFileOpenWritePartial,
            &zero,
            &policy,
        )
        .unwrap_err();
        assert!(error.to_string().contains("eligible result set"));
        zero.file_object = None;
        assert_eq!(
            replay_object_resolution(
                ObjectResolutionMode::KernelFileOpenWritePartial,
                &zero,
                &policy,
            )
            .unwrap(),
            ReplayedObjectResolution::NotApplicable
        );
    }

    #[test]
    fn successful_open_without_file_hook_fails_closed() {
        let policy = describe_policy(PolicyProfile::Control)
            .unwrap()
            .into_iter()
            .find(|entry| entry.syscall_nr == libc::SYS_openat2 as i32)
            .unwrap();
        let result = KernelEvent {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            kind: EVENT_RESULT,
            domain: policy.domain as u16,
            operation: policy.operation as u32,
            flags: 0,
            syscall_nr: policy.syscall_nr,
            run_epoch: 1,
            event_seq: 2,
            related_attempt_seq: 1,
            ktime_ns: 2,
            cgroup_id: 3,
            pid_tgid: (4u64 << 32) | 5,
            return_value: 6,
            args: [libc::AT_FDCWD as u64, 0x1000, 0x2000, 24, 0, 0],
            comm: [0; 16],
            payload_lens: [0; 2],
            payload_kinds: [PAYLOAD_NONE; 2],
            payload_arg_indices: [0; 2],
            payloads: [[0; CAPTURE_BYTES]; 2],
            file_object: None,
        };

        for mode in [
            ObjectResolutionMode::KernelFileOpenPartial,
            ObjectResolutionMode::KernelFileOpenWritePartial,
        ] {
            let error = replay_object_resolution(mode, &result, &policy).unwrap_err();
            assert!(error.to_string().contains("silently downgraded"));
        }
    }

    #[test]
    fn replay_enforces_per_thread_single_flight_but_allows_thread_interleaving() {
        let first_attempt = KernelEvent {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            kind: EVENT_ATTEMPT,
            domain: 1,
            operation: 1,
            flags: 0,
            syscall_nr: libc::SYS_bpf as i32,
            run_epoch: 1,
            event_seq: 1,
            related_attempt_seq: 0,
            ktime_ns: 10,
            cgroup_id: 2,
            pid_tgid: (3u64 << 32) | 3,
            return_value: 0,
            args: [0; 6],
            comm: [0; 16],
            payload_lens: [0; 2],
            payload_kinds: [PAYLOAD_NONE; 2],
            payload_arg_indices: [0; 2],
            payloads: [[0; CAPTURE_BYTES]; 2],
            file_object: None,
        };
        let mut replay = AttemptReplayState::default();
        replay.start(&first_attempt).unwrap();

        let overlapping_same_thread = KernelEvent {
            event_seq: 2,
            ktime_ns: 11,
            ..first_attempt.clone()
        };
        assert!(replay
            .start(&overlapping_same_thread)
            .unwrap_err()
            .to_string()
            .contains("overlapping attempts"));

        let second_thread_attempt = KernelEvent {
            pid_tgid: (3u64 << 32) | 4,
            ..overlapping_same_thread
        };
        replay.start(&second_thread_attempt).unwrap();
        let second_thread_result = KernelEvent {
            kind: EVENT_RESULT,
            event_seq: 3,
            related_attempt_seq: 2,
            ktime_ns: 12,
            ..second_thread_attempt
        };
        replay.complete(&second_thread_result).unwrap();
        let first_result = KernelEvent {
            kind: EVENT_RESULT,
            event_seq: 4,
            related_attempt_seq: 1,
            ktime_ns: 13,
            ..first_attempt
        };
        replay.complete(&first_result).unwrap();
        assert!(replay.is_empty());
    }

    #[test]
    fn verifies_a_complete_closed_artifact_set() {
        let directory = TestDirectory::create();
        let profile = PolicyProfile::Control;
        let entries = describe_policy(profile).unwrap();
        let policy = entries
            .iter()
            .find(|entry| {
                entry.operation == EffectOperation::BpfCommand
                    && entry.capture.is_empty()
                    && entry.kernel_filter.is_none()
            })
            .unwrap();
        let run_id = format!(
            "effects-{}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.load(Ordering::Relaxed)
        );
        let pid_tgid = (42u64 << 32) | 42;
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"test");
        let attempt = KernelEvent {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            kind: EVENT_ATTEMPT,
            domain: policy.domain as u16,
            operation: policy.operation as u32,
            flags: 0,
            syscall_nr: policy.syscall_nr,
            run_epoch: 7,
            event_seq: 1,
            related_attempt_seq: 0,
            ktime_ns: 100,
            cgroup_id: 9,
            pid_tgid,
            return_value: 0,
            args: [0; 6],
            comm,
            payload_lens: [0; 2],
            payload_kinds: [PAYLOAD_NONE; 2],
            payload_arg_indices: [0; 2],
            payloads: [[0; CAPTURE_BYTES]; 2],
            file_object: None,
        };
        let mut wal = Vec::new();
        append_wal(&mut wal, &attempt);
        let mut jsonl = Vec::new();
        serde_json::to_writer(&mut jsonl, &json_event(&attempt, &run_id, policy)).unwrap();
        jsonl.push(b'\n');
        let result = KernelEvent {
            kind: EVENT_RESULT,
            event_seq: 2,
            related_attempt_seq: 1,
            ktime_ns: 101,
            ..attempt
        };
        append_wal(&mut wal, &result);
        serde_json::to_writer(&mut jsonl, &json_event(&result, &run_id, policy)).unwrap();
        jsonl.push(b'\n');

        let policy_digest = policy_sha256(profile).unwrap();
        let policy_artifact = PolicyArtifact {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            profile,
            policy_sha256: policy_digest.clone(),
            entries,
        };
        let health = SystemEffectHealth {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            run_id: run_id.clone(),
            run_epoch: 7,
            cgroup_id: 9,
            profile,
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
            producer_barrier_complete: true,
            drain_completed: true,
            wal_durable: true,
            poll_calls: 1,
            maximum_events_per_poll: 2,
            callback_queue_high_water: 2,
            callback_queue_capacity: CALLBACK_QUEUE_CAPACITY,
            reasons: Vec::new(),
            coverage_gaps: coverage_gaps_for(profile, FileObjectResolutionMode::UserInput),
        };

        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            POLICY_NAME.to_owned(),
            write_artifact(
                &directory.0,
                POLICY_NAME,
                &serde_json::to_vec(&policy_artifact).unwrap(),
            ),
        );
        artifacts.insert(
            HEALTH_NAME.to_owned(),
            write_artifact(
                &directory.0,
                HEALTH_NAME,
                &serde_json::to_vec(&health).unwrap(),
            ),
        );
        artifacts.insert(
            WAL_NAME.to_owned(),
            write_artifact(&directory.0, WAL_NAME, &wal),
        );
        artifacts.insert(
            JSONL_NAME.to_owned(),
            write_artifact(&directory.0, JSONL_NAME, &jsonl),
        );
        artifacts.insert(
            STDOUT_NAME.to_owned(),
            write_artifact(&directory.0, STDOUT_NAME, b""),
        );
        artifacts.insert(
            STDERR_NAME.to_owned(),
            write_artifact(&directory.0, STDERR_NAME, b""),
        );

        let mut gaps = coverage_gaps_for(profile, FileObjectResolutionMode::UserInput);
        gaps.push(STANDALONE_ISOLATION_GAP.to_owned());
        gaps.sort();
        gaps.dedup();
        let recorder_digest = "11".repeat(32);
        let mut manifest = EffectsManifest {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            evidence_kind: "SYSTEM_EFFECT_OPERATION_STREAM_V1".to_owned(),
            run_id: run_id.clone(),
            run_epoch: 7,
            run_status: EffectRunStatus::Finalized,
            started_unix_ns: 1,
            finalized_unix_ns: Some(2),
            cgroup_path: format!("/sys/fs/cgroup/bpf-state-observer-effects/{run_id}"),
            cgroup_id: 9,
            workload: vec!["/bin/true".to_owned()],
            workload_exit_code: Some(0),
            workload_signal: None,
            workload_stdout_truncated: false,
            workload_stderr_truncated: false,
            policy_profile: profile,
            object_resolution_mode: ObjectResolutionMode::UserInput,
            policy_sha256: policy_digest,
            policy_entry_count: policy_artifact.entries.len(),
            policy_artifact: POLICY_NAME.to_owned(),
            expected_recorder_object_sha256: recorder_digest.clone(),
            loaded_recorder_object_sha256: Some(recorder_digest.clone()),
            kernel_release: "test-kernel".to_owned(),
            boot_id: TEST_BOOT_ID.to_owned(),
            observer_version: env!("CARGO_PKG_VERSION").to_owned(),
            source_commit: None,
            cgroup_frozen_at_close: true,
            transport_status: Some(TransportStatus::Complete),
            attribution_contract: AttributionContract::direct_v1(),
            coverage: CoverageDescription {
                attribution_scope: "SELECTED_NATIVE_SYSCALLS_FROM_EXACT_CGROUP_V2_ID".to_owned(),
                event_semantics: "OPERATION_ATTEMPT_AND_RETURN_NOT_DURABLE_STATE_DIFF".to_owned(),
                operation_events_are_state_diff: false,
                durable_state_change_proven: false,
                rollback_completeness_proven: false,
                workload_privilege_isolation_enforced: false,
                evidence_write_isolation_enforced: false,
                coverage_status: "PARTIAL".to_owned(),
                object_resolution_status: "PARTIAL".to_owned(),
                gaps,
            },
            bpf_state_confirmation: None,
            filesystem_state_confirmation: None,
            artifacts,
            failure: None,
            notes: vec![
                "operation attempts/results are diagnostic history, not proof of a durable state change"
                    .to_owned(),
            ],
        };
        fs::write(
            directory.0.join(MANIFEST_NAME),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let profile_error = verify_run(
            &directory.0,
            &recorder_digest,
            PolicyProfile::Full,
            ObjectResolutionMode::UserInput,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(format!("{profile_error:#}").contains("policy profile"));

        let report = verify_run(
            &directory.0,
            &recorder_digest,
            profile,
            ObjectResolutionMode::UserInput,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(report.run_id, run_id);
        assert_eq!(report.events_verified, 2);
        assert!(report.transport_complete);
        assert_eq!(
            report.attribution_contract,
            AttributionContract::direct_v1()
        );
        assert!(report.direct_event_attribution_validated);
        assert!(!report.causal_attribution_complete);
        assert!(!report.coverage_complete);
        assert!(!report.operation_events_are_state_diff);
        assert!(!report.bpf_state_confirmation_verified);
        assert!(!report.external_bpf_state_scope_checked);
        assert_eq!(report.bpf_state_verdict, None);
        assert!(report.external_recorder_digest_checked);
        assert_eq!(report.policy_profile, profile);

        // Recomputing the artifact digest is insufficient to forge stronger
        // attribution: the strict verifier reconstructs the event-local claim
        // from WAL and accepts only the closed DIRECT/non-causal contract.
        {
            let original_values = jsonl
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
                .collect::<Vec<_>>();
            let mut verify_forged = |values: Vec<serde_json::Value>| {
                let mut forged = Vec::new();
                for value in values {
                    serde_json::to_writer(&mut forged, &value).unwrap();
                    forged.push(b'\n');
                }
                manifest.artifacts.insert(
                    JSONL_NAME.to_owned(),
                    write_artifact(&directory.0, JSONL_NAME, &forged),
                );
                fs::write(
                    directory.0.join(MANIFEST_NAME),
                    serde_json::to_vec(&manifest).unwrap(),
                )
                .unwrap();
                verify_run(
                    &directory.0,
                    &recorder_digest,
                    profile,
                    ObjectResolutionMode::UserInput,
                    None,
                    None,
                    None,
                )
                .unwrap_err()
            };

            let mut missing = original_values.clone();
            missing[0].as_object_mut().unwrap().remove("attribution");
            assert!(format!("{:#}", verify_forged(missing)).contains("attribution protocol"));

            for (field, forged_value) in [
                ("mode", "DELEGATED"),
                ("authority", "BROKER_ASSERTION"),
                ("causal_status", "CAUSAL_ESTABLISHED"),
            ] {
                let mut forged = original_values.clone();
                forged[0]["attribution"][field] =
                    serde_json::Value::String(forged_value.to_owned());
                assert!(format!("{:#}", verify_forged(forged))
                    .contains("parse system-effect JSONL event"));
            }

            let mut bad_sequence = original_values;
            bad_sequence[0]["attribution"]["operation_attempt_seq"] = serde_json::Value::from(2);
            assert!(format!("{:#}", verify_forged(bad_sequence)).contains("attribution protocol"));
        }
        manifest.artifacts.insert(
            JSONL_NAME.to_owned(),
            write_artifact(&directory.0, JSONL_NAME, &jsonl),
        );
        let valid_attribution_contract = manifest.attribution_contract;
        manifest.attribution_contract.protocol_version += 1;
        fs::write(
            directory.0.join(MANIFEST_NAME),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let forged_contract = verify_run(
            &directory.0,
            &recorder_digest,
            profile,
            ObjectResolutionMode::UserInput,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(format!("{forged_contract:#}").contains("attribution contract"));
        manifest.attribution_contract = valid_attribution_contract;
        fs::write(
            directory.0.join(MANIFEST_NAME),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        // Optional BPF endpoint confirmation expands the otherwise closed
        // artifact set to exactly nine files. It remains conservative: an
        // empty endpoint diff cannot become UNCHANGED without authenticated
        // exclusive-vm evidence.
        let scope = ClaimScope {
            object_types: BTreeSet::from([ObjectType::Map]),
            ..ClaimScope::default()
        };
        let exclusions = ObjectExclusions {
            program_ids: BTreeSet::from([11]),
            map_ids: BTreeSet::from([12]),
            link_ids: BTreeSet::from([13]),
        };
        let s0 = bpf_state_snapshot(&run_id, "S0", &scope, &exclusions);
        let s1 = bpf_state_snapshot(&run_id, "S1", &scope, &exclusions);
        let verdict = effects_run::compare_bpf_state_endpoints(&s0, &s1).unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::Inconclusive);
        manifest.artifacts.insert(
            effects_run::BPF_STATE_S0_NAME.to_owned(),
            write_artifact(
                &directory.0,
                effects_run::BPF_STATE_S0_NAME,
                &serde_json::to_vec(&s0).unwrap(),
            ),
        );
        manifest.artifacts.insert(
            effects_run::BPF_STATE_S1_NAME.to_owned(),
            write_artifact(
                &directory.0,
                effects_run::BPF_STATE_S1_NAME,
                &serde_json::to_vec(&s1).unwrap(),
            ),
        );
        manifest.artifacts.insert(
            effects_run::BPF_STATE_VERDICT_NAME.to_owned(),
            write_artifact(
                &directory.0,
                effects_run::BPF_STATE_VERDICT_NAME,
                &serde_json::to_vec(&verdict).unwrap(),
            ),
        );
        manifest.bpf_state_confirmation = Some(BpfStateConfirmation {
            protocol_version: effects_run::BPF_STATE_CONFIRMATION_PROTOCOL_VERSION,
            confirmation_domain: effects_run::BPF_STATE_CONFIRMATION_DOMAIN.to_owned(),
            scope: scope.clone(),
            observer_exclusions: exclusions,
            s0_artifact: effects_run::BPF_STATE_S0_NAME.to_owned(),
            s1_artifact: effects_run::BPF_STATE_S1_NAME.to_owned(),
            verdict_artifact: effects_run::BPF_STATE_VERDICT_NAME.to_owned(),
            state_verdict: verdict.state_verdict.clone(),
            state_completeness: verdict.state_completeness.status.clone(),
            evidence_status: verdict.evidence_status.status.clone(),
            attribution: verdict.attribution.clone(),
            operation_events_are_state_diff: false,
            unchanged_verdict_authorized: false,
        });
        fs::write(
            directory.0.join(MANIFEST_NAME),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let missing_scope = verify_run(
            &directory.0,
            &recorder_digest,
            profile,
            ObjectResolutionMode::UserInput,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(format!("{missing_scope:#}").contains("externally trusted expected scope"));
        let report = verify_run(
            &directory.0,
            &recorder_digest,
            profile,
            ObjectResolutionMode::UserInput,
            Some(&scope),
            None,
            None,
        )
        .unwrap();
        assert_eq!(report.artifacts_verified, 9);
        assert!(report.bpf_state_confirmation_verified);
        assert!(report.external_bpf_state_scope_checked);
        assert_eq!(report.bpf_state_verdict, Some(StateVerdict::Inconclusive));

        let mut forged_verdict = verdict.clone();
        forged_verdict.state_verdict = StateVerdict::ChangedWithinScope;
        manifest.artifacts.insert(
            effects_run::BPF_STATE_VERDICT_NAME.to_owned(),
            write_artifact(
                &directory.0,
                effects_run::BPF_STATE_VERDICT_NAME,
                &serde_json::to_vec(&forged_verdict).unwrap(),
            ),
        );
        fs::write(
            directory.0.join(MANIFEST_NAME),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let error = verify_run(
            &directory.0,
            &recorder_digest,
            profile,
            ObjectResolutionMode::UserInput,
            Some(&scope),
            None,
            None,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("does not match the verified endpoint snapshots"));

        manifest.artifacts.insert(
            effects_run::BPF_STATE_VERDICT_NAME.to_owned(),
            write_artifact(
                &directory.0,
                effects_run::BPF_STATE_VERDICT_NAME,
                &serde_json::to_vec(&verdict).unwrap(),
            ),
        );

        // A structurally valid resolved object claim still has to be derived
        // from trusted WAL evidence.  The current raw-syscall ABI carries no
        // such evidence, so rewriting JSONL and its manifest digest must fail.
        let mut events = jsonl
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<SystemEffectEvent>(line).unwrap())
            .collect::<Vec<_>>();
        events[1].object_resolution.quality = ObjectResolutionQuality::KernelResolved;
        events[1].object_resolution.authority = ObjectResolutionAuthority::KernelObjectHook;
        events[1].object_resolution.objects = vec![ObjectReference {
            slot: 0,
            role: ObjectRole::Primary,
            identity: ObjectIdentity::FileObject {
                boot_id: "00000000-0000-0000-0000-000000000001".to_owned(),
                mount_id_unique: 1,
                device_major: 8,
                device_minor: 1,
                inode: 2,
                inode_generation: Some(3),
                filesystem_magic: 0xef53,
                filesystem_class: bpf_observer_system_effects::FilesystemClass::Other,
                path: Default::default(),
            },
        }];
        assert!(events[1].validate_object_resolution().is_err());
        let mut forged_jsonl = Vec::new();
        for event in events {
            serde_json::to_writer(&mut forged_jsonl, &event).unwrap();
            forged_jsonl.push(b'\n');
        }
        manifest.artifacts.insert(
            JSONL_NAME.to_owned(),
            write_artifact(&directory.0, JSONL_NAME, &forged_jsonl),
        );
        fs::write(
            directory.0.join(MANIFEST_NAME),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let error = verify_run(
            &directory.0,
            &recorder_digest,
            profile,
            ObjectResolutionMode::UserInput,
            Some(&scope),
            None,
            None,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("object-resolution protocol"));

        // Restore the trusted operation stream, then extend the closed run
        // with real filesystem S0/S1 artifacts. The verifier must require the
        // exact external scope and actor contract and recompute the comparison
        // from the snapshots instead of trusting JSON summary claims.
        manifest.artifacts.insert(
            JSONL_NAME.to_owned(),
            write_artifact(&directory.0, JSONL_NAME, &jsonl),
        );
        let filesystem_root = TestDirectory::create();
        let filesystem_root_path = fs::canonicalize(filesystem_root.0.as_path()).unwrap();
        let tracked_file = filesystem_root_path.join("tracked.txt");
        fs::write(&tracked_file, b"before").unwrap();
        let filesystem_scope = FilesystemScope::new(
            vec![filesystem_root_path],
            FilesystemCapturePolicy::default(),
            FilesystemCaptureLimits::default(),
        )
        .unwrap();
        let mut filesystem_s0 = capture_filesystem(
            &filesystem_scope,
            &FilesystemCaptureRequest {
                snapshot_id: effects_run::filesystem_snapshot_id(&run_id, 7, "S0"),
                phase: FilesystemSnapshotPhase::S0,
            },
        )
        .unwrap();
        fs::write(&tracked_file, b"after").unwrap();
        let mut filesystem_s1 = capture_filesystem(
            &filesystem_scope,
            &FilesystemCaptureRequest {
                snapshot_id: effects_run::filesystem_snapshot_id(&run_id, 7, "S1"),
                phase: FilesystemSnapshotPhase::S1,
            },
        )
        .unwrap();
        // A fixture may use a synthetic run boot/time identity, but the two
        // captured endpoint payloads and their comparison remain real.
        filesystem_s0.boot_id = TEST_BOOT_ID.to_owned();
        filesystem_s1.boot_id = TEST_BOOT_ID.to_owned();
        filesystem_s0.captured_unix_ns = 1;
        filesystem_s1.captured_unix_ns = 2;
        let filesystem_contract = ActorQuiescenceContract {
            protocol_version: FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION,
            contract_id: "exclusive-test-v1".to_owned(),
            evidence_sha256: "33".repeat(32),
            scope_sha256: filesystem_scope.sha256().unwrap(),
            s0_snapshot_id: filesystem_s0.snapshot_id.clone(),
            s1_snapshot_id: filesystem_s1.snapshot_id.clone(),
            exclusive_writer_enforced: true,
            s0_quiescent: true,
            s1_quiescent: true,
        };
        let filesystem_comparison =
            compare_filesystem(&filesystem_s0, &filesystem_s1, Some(&filesystem_contract)).unwrap();
        assert_eq!(
            filesystem_comparison.endpoint_difference,
            EndpointDifferenceStatus::ObservedDifferent
        );
        assert_eq!(
            filesystem_comparison.verdict,
            FilesystemVerdict::ChangedWithinScope
        );
        assert_eq!(
            filesystem_comparison.causal_attribution_status,
            CausalAttributionStatus::NotEstablished
        );

        for (name, bytes) in [
            (
                effects_run::FILESYSTEM_STATE_S0_NAME,
                serde_json::to_vec(&filesystem_s0).unwrap(),
            ),
            (
                effects_run::FILESYSTEM_STATE_S1_NAME,
                serde_json::to_vec(&filesystem_s1).unwrap(),
            ),
            (
                effects_run::FILESYSTEM_STATE_COMPARISON_NAME,
                serde_json::to_vec(&filesystem_comparison).unwrap(),
            ),
            (
                effects_run::FILESYSTEM_ACTOR_CONTRACT_NAME,
                serde_json::to_vec(&filesystem_contract).unwrap(),
            ),
        ] {
            manifest
                .artifacts
                .insert(name.to_owned(), write_artifact(&directory.0, name, &bytes));
        }
        manifest.evidence_kind = effects_run::EVIDENCE_KIND_FILESYSTEM_V2.to_owned();
        manifest.filesystem_state_confirmation = Some(FilesystemStateConfirmation {
            protocol_version: FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION,
            confirmation_domain: FILESYSTEM_CONFIRMATION_DOMAIN.to_owned(),
            scope_sha256: filesystem_scope.sha256().unwrap(),
            s0_artifact: effects_run::FILESYSTEM_STATE_S0_NAME.to_owned(),
            s1_artifact: effects_run::FILESYSTEM_STATE_S1_NAME.to_owned(),
            comparison_artifact: effects_run::FILESYSTEM_STATE_COMPARISON_NAME.to_owned(),
            actor_contract_artifact: Some(effects_run::FILESYSTEM_ACTOR_CONTRACT_NAME.to_owned()),
            endpoint_difference: filesystem_comparison.endpoint_difference,
            state_verdict: filesystem_comparison.verdict,
            state_completeness: filesystem_comparison.state_completeness.status,
            actor_contract_status: filesystem_comparison.actor_contract_status,
            causal_attribution_status: filesystem_comparison.causal_attribution_status,
            actor_contract_authenticated_by_observer: false,
            operation_events_are_state_diff: false,
            atomic_with_other_confirmation_domains: false,
        });
        fs::write(
            directory.0.join(MANIFEST_NAME),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let missing_filesystem_scope = verify_run(
            &directory.0,
            &recorder_digest,
            profile,
            ObjectResolutionMode::UserInput,
            Some(&scope),
            None,
            Some(&filesystem_contract),
        )
        .unwrap_err();
        assert!(format!("{missing_filesystem_scope:#}").contains("trusted scope"));
        let missing_actor_contract = verify_run(
            &directory.0,
            &recorder_digest,
            profile,
            ObjectResolutionMode::UserInput,
            Some(&scope),
            Some(&filesystem_scope),
            None,
        )
        .unwrap_err();
        assert!(format!("{missing_actor_contract:#}").contains("trusted exact contract"));
        let report = verify_run(
            &directory.0,
            &recorder_digest,
            profile,
            ObjectResolutionMode::UserInput,
            Some(&scope),
            Some(&filesystem_scope),
            Some(&filesystem_contract),
        )
        .unwrap();
        assert_eq!(report.artifacts_verified, 13);
        assert!(report.filesystem_artifact_consistency_verified);
        assert!(report.external_filesystem_state_scope_exact_match);
        assert!(report.external_filesystem_actor_contract_exact_match);
        assert_eq!(
            report.filesystem_endpoint_difference,
            Some(EndpointDifferenceStatus::ObservedDifferent)
        );
        assert_eq!(
            report.filesystem_state_verdict,
            Some(FilesystemVerdict::ChangedWithinScope)
        );
        assert_eq!(
            report.filesystem_causal_attribution,
            Some(CausalAttributionStatus::NotEstablished)
        );

        let mut forged_filesystem_comparison = filesystem_comparison.clone();
        forged_filesystem_comparison.verdict = FilesystemVerdict::UnchangedWithinScope;
        manifest.artifacts.insert(
            effects_run::FILESYSTEM_STATE_COMPARISON_NAME.to_owned(),
            write_artifact(
                &directory.0,
                effects_run::FILESYSTEM_STATE_COMPARISON_NAME,
                &serde_json::to_vec(&forged_filesystem_comparison).unwrap(),
            ),
        );
        fs::write(
            directory.0.join(MANIFEST_NAME),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let forged_comparison = verify_run(
            &directory.0,
            &recorder_digest,
            profile,
            ObjectResolutionMode::UserInput,
            Some(&scope),
            Some(&filesystem_scope),
            Some(&filesystem_contract),
        )
        .unwrap_err();
        assert!(
            format!("{forged_comparison:#}").contains("cannot authorize UNCHANGED_WITHIN_SCOPE")
        );

        manifest.artifacts.insert(
            effects_run::FILESYSTEM_STATE_COMPARISON_NAME.to_owned(),
            write_artifact(
                &directory.0,
                effects_run::FILESYSTEM_STATE_COMPARISON_NAME,
                &serde_json::to_vec(&filesystem_comparison).unwrap(),
            ),
        );
        manifest.evidence_kind = effects_run::EVIDENCE_KIND_V1.to_owned();
        fs::write(
            directory.0.join(MANIFEST_NAME),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let downgrade = verify_run(
            &directory.0,
            &recorder_digest,
            profile,
            ObjectResolutionMode::UserInput,
            Some(&scope),
            Some(&filesystem_scope),
            Some(&filesystem_contract),
        )
        .unwrap_err();
        assert!(format!("{downgrade:#}").contains("valid committed FINALIZED run"));
    }

    #[test]
    fn verifies_kernel_file_open_identity_and_rejects_mode_or_json_substitution() {
        let directory = TestDirectory::create();
        let profile = PolicyProfile::Control;
        let entries = describe_policy(profile).unwrap();
        let policy = entries
            .iter()
            .find(|entry| entry.syscall_nr == libc::SYS_openat as i32)
            .unwrap();
        let run_id = format!(
            "effects-kernel-file-{}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.load(Ordering::Relaxed)
        );

        let mut comm = [0u8; 16];
        comm[..5].copy_from_slice(b"agent");
        let mut captured_path = [0u8; CAPTURE_BYTES];
        let captured_path_bytes = b"/tmp/result\0";
        captured_path[..captured_path_bytes.len()].copy_from_slice(captured_path_bytes);
        let attempt = KernelEvent {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            kind: EVENT_ATTEMPT,
            domain: policy.domain as u16,
            operation: policy.operation as u32,
            flags: FLAG_USER_MEMORY_SNAPSHOT,
            syscall_nr: policy.syscall_nr,
            run_epoch: 17,
            event_seq: 1,
            related_attempt_seq: 0,
            ktime_ns: 1_000,
            cgroup_id: 91,
            pid_tgid: (71u64 << 32) | 72,
            return_value: 0,
            args: [
                libc::AT_FDCWD as u64,
                0x1000,
                libc::O_CREAT as u64,
                0o600,
                0,
                0,
            ],
            comm,
            payload_lens: [captured_path_bytes.len() as u16, 0],
            payload_kinds: [PAYLOAD_USER_STRING, PAYLOAD_NONE],
            payload_arg_indices: [1, 0],
            payloads: [captured_path, [0; CAPTURE_BYTES]],
            file_object: None,
        };
        let mut resolved_path = [0u8; KERNEL_FILE_PATH_BYTES];
        let resolved_path_bytes = b"/tmp/result";
        resolved_path[..resolved_path_bytes.len()].copy_from_slice(resolved_path_bytes);
        let result = KernelEvent {
            kind: EVENT_RESULT,
            flags: 0,
            event_seq: 2,
            related_attempt_seq: 1,
            ktime_ns: 1_001,
            return_value: 3,
            payload_lens: [0; 2],
            payload_kinds: [PAYLOAD_NONE; 2],
            payload_arg_indices: [0; 2],
            payloads: [[0; CAPTURE_BYTES]; 2],
            file_object: Some(KernelFileObject {
                mount_id_unique: 44,
                inode: 55,
                filesystem_magic: 0xef53,
                device_major: 8,
                device_minor: 2,
                inode_generation: 9,
                path_len: resolved_path_bytes.len() as u16,
                generation_valid: 1,
                path_quality: FILE_PATH_RESOLVED_AT_HOOK,
                path: resolved_path,
            }),
            ..attempt
        };
        let failed_attempt = KernelEvent {
            event_seq: 3,
            ktime_ns: 1_002,
            ..attempt.clone()
        };
        let failed_result = KernelEvent {
            kind: EVENT_RESULT,
            flags: 0,
            event_seq: 4,
            related_attempt_seq: 3,
            ktime_ns: 1_003,
            return_value: -libc::ENOENT as i64,
            payload_lens: [0; 2],
            payload_kinds: [PAYLOAD_NONE; 2],
            payload_arg_indices: [0; 2],
            payloads: [[0; CAPTURE_BYTES]; 2],
            file_object: None,
            ..attempt
        };

        let mut wal = Vec::new();
        for event in [&attempt, &result, &failed_attempt, &failed_result] {
            append_wal(&mut wal, event);
        }
        let attempt_json = json_event(&attempt, &run_id, policy);
        let result_json = json_event(&result, &run_id, policy);
        let failed_attempt_json = json_event(&failed_attempt, &run_id, policy);
        let failed_result_json = json_event(&failed_result, &run_id, policy);
        assert_eq!(
            failed_result_json.object_resolution.quality,
            ObjectResolutionQuality::Unresolved
        );
        let mut jsonl = Vec::new();
        for event in [
            &attempt_json,
            &result_json,
            &failed_attempt_json,
            &failed_result_json,
        ] {
            serde_json::to_writer(&mut jsonl, event).unwrap();
            jsonl.push(b'\n');
        }

        let policy_digest = policy_sha256(profile).unwrap();
        let policy_artifact = PolicyArtifact {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            profile,
            policy_sha256: policy_digest.clone(),
            entries,
        };
        let health = SystemEffectHealth {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            run_id: run_id.clone(),
            run_epoch: 17,
            cgroup_id: 91,
            profile,
            object_resolution_mode: FileObjectResolutionMode::KernelFileOpenPartial,
            transport_status: TransportStatus::Complete,
            coverage_status: CoverageStatus::Partial,
            object_resolution_status: ObjectResolutionStatus::Partial,
            operation_attempted: 2,
            operation_completed: 2,
            event_attempted: 4,
            event_published: 4,
            event_dropped: 0,
            events_persisted: 4,
            pending_insert_failed: 0,
            pending_missing: 0,
            pending_remaining: 0,
            userspace_failures: 0,
            fatal_kernel_flags: 0,
            capture_read_failures: 0,
            capture_truncations: 0,
            capture_invalid_lengths: 0,
            object_resolution_attempted: 2,
            object_resolution_resolved: 1,
            object_resolution_unresolved: 1,
            object_resolution_failed_syscalls: 1,
            object_join_missing: 0,
            object_join_ambiguous: 0,
            object_read_failed: 0,
            object_delete_failed: 0,
            object_path_unavailable: 0,
            object_pending_remaining: 0,
            producer_barrier_complete: true,
            drain_completed: true,
            wal_durable: true,
            poll_calls: 1,
            maximum_events_per_poll: 4,
            callback_queue_high_water: 4,
            callback_queue_capacity: CALLBACK_QUEUE_CAPACITY,
            reasons: Vec::new(),
            coverage_gaps: coverage_gaps_for(
                profile,
                FileObjectResolutionMode::KernelFileOpenPartial,
            ),
        };

        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            POLICY_NAME.to_owned(),
            write_artifact(
                &directory.0,
                POLICY_NAME,
                &serde_json::to_vec(&policy_artifact).unwrap(),
            ),
        );
        artifacts.insert(
            HEALTH_NAME.to_owned(),
            write_artifact(
                &directory.0,
                HEALTH_NAME,
                &serde_json::to_vec(&health).unwrap(),
            ),
        );
        artifacts.insert(
            WAL_NAME.to_owned(),
            write_artifact(&directory.0, WAL_NAME, &wal),
        );
        artifacts.insert(
            JSONL_NAME.to_owned(),
            write_artifact(&directory.0, JSONL_NAME, &jsonl),
        );
        artifacts.insert(
            STDOUT_NAME.to_owned(),
            write_artifact(&directory.0, STDOUT_NAME, b""),
        );
        artifacts.insert(
            STDERR_NAME.to_owned(),
            write_artifact(&directory.0, STDERR_NAME, b""),
        );
        let mut gaps = coverage_gaps_for(profile, FileObjectResolutionMode::KernelFileOpenPartial);
        gaps.push(STANDALONE_ISOLATION_GAP.to_owned());
        gaps.sort();
        gaps.dedup();
        let recorder_digest = "22".repeat(32);
        let mut manifest = EffectsManifest {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            evidence_kind: "SYSTEM_EFFECT_OPERATION_STREAM_V1".to_owned(),
            run_id: run_id.clone(),
            run_epoch: 17,
            run_status: EffectRunStatus::Finalized,
            started_unix_ns: 1,
            finalized_unix_ns: Some(2),
            cgroup_path: format!("/sys/fs/cgroup/bpf-state-observer-effects/{run_id}"),
            cgroup_id: 91,
            workload: vec!["/bin/true".to_owned()],
            workload_exit_code: Some(0),
            workload_signal: None,
            workload_stdout_truncated: false,
            workload_stderr_truncated: false,
            policy_profile: profile,
            object_resolution_mode: ObjectResolutionMode::KernelFileOpenPartial,
            policy_sha256: policy_digest,
            policy_entry_count: policy_artifact.entries.len(),
            policy_artifact: POLICY_NAME.to_owned(),
            expected_recorder_object_sha256: recorder_digest.clone(),
            loaded_recorder_object_sha256: Some(recorder_digest.clone()),
            kernel_release: "test-kernel".to_owned(),
            boot_id: TEST_BOOT_ID.to_owned(),
            observer_version: env!("CARGO_PKG_VERSION").to_owned(),
            source_commit: None,
            cgroup_frozen_at_close: true,
            transport_status: Some(TransportStatus::Complete),
            attribution_contract: AttributionContract::direct_v1(),
            coverage: CoverageDescription {
                attribution_scope: "SELECTED_NATIVE_SYSCALLS_FROM_EXACT_CGROUP_V2_ID".to_owned(),
                event_semantics: "OPERATION_ATTEMPT_AND_RETURN_NOT_DURABLE_STATE_DIFF".to_owned(),
                operation_events_are_state_diff: false,
                durable_state_change_proven: false,
                rollback_completeness_proven: false,
                workload_privilege_isolation_enforced: false,
                evidence_write_isolation_enforced: false,
                coverage_status: "PARTIAL".to_owned(),
                object_resolution_status: "PARTIAL".to_owned(),
                gaps,
            },
            bpf_state_confirmation: None,
            filesystem_state_confirmation: None,
            artifacts,
            failure: None,
            notes: vec![
                "operation attempts/results are diagnostic history, not proof of a durable state change"
                    .to_owned(),
            ],
        };
        fs::write(
            directory.0.join(MANIFEST_NAME),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let report = verify_run(
            &directory.0,
            &recorder_digest,
            profile,
            ObjectResolutionMode::KernelFileOpenPartial,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(report.events_verified, 4);
        assert_eq!(
            report.object_resolution_mode,
            ObjectResolutionMode::KernelFileOpenPartial
        );

        let mode_error = verify_run(
            &directory.0,
            &recorder_digest,
            profile,
            ObjectResolutionMode::UserInput,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(format!("{mode_error:#}").contains("external trust policy"));

        let mut forged_result = result_json;
        match &mut forged_result.object_resolution.objects[0].identity {
            ObjectIdentity::FileObject { inode, .. } => *inode += 1,
            other => panic!("expected FILE_OBJECT, got {other:?}"),
        }
        let mut forged_jsonl = Vec::new();
        for event in [
            &attempt_json,
            &forged_result,
            &failed_attempt_json,
            &failed_result_json,
        ] {
            serde_json::to_writer(&mut forged_jsonl, event).unwrap();
            forged_jsonl.push(b'\n');
        }
        manifest.artifacts.insert(
            JSONL_NAME.to_owned(),
            write_artifact(&directory.0, JSONL_NAME, &forged_jsonl),
        );
        fs::write(
            directory.0.join(MANIFEST_NAME),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let json_error = verify_run(
            &directory.0,
            &recorder_digest,
            profile,
            ObjectResolutionMode::KernelFileOpenPartial,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(format!("{json_error:#}").contains("does not derive from its WAL"));
    }

    #[test]
    fn rejects_truncated_wal_frame() {
        let mut bytes = (WAL_COMPACT_EVENT_BYTES as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0; 8]);
        let error = read_wal_frame(&mut bytes.as_slice()).unwrap_err();
        assert!(format!("{error:#}").contains("truncated"));
    }

    #[test]
    fn rejects_attempt_that_does_not_satisfy_policy_filter() {
        let policy = describe_policy(PolicyProfile::Control)
            .unwrap()
            .into_iter()
            .find(|entry| entry.kernel_filter.is_some())
            .unwrap();
        let mut kinds = [PAYLOAD_NONE; 2];
        let mut indices = [0u8; 2];
        for (slot, capture) in policy.capture.iter().enumerate() {
            kinds[slot] = match capture.kind.as_str() {
                "USER_SUPPLIED_STRING" => PAYLOAD_USER_STRING,
                "RAW_USER_SOCKADDR" => PAYLOAD_SOCKADDR,
                _ => unreachable!(),
            };
            indices[slot] = capture.argument_index;
        }
        let event = KernelEvent {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            kind: EVENT_ATTEMPT,
            domain: policy.domain as u16,
            operation: policy.operation as u32,
            flags: 0,
            syscall_nr: policy.syscall_nr,
            run_epoch: 1,
            event_seq: 1,
            related_attempt_seq: 0,
            ktime_ns: 1,
            cgroup_id: 1,
            pid_tgid: 1,
            return_value: 0,
            args: [0; 6],
            comm: [0; 16],
            payload_lens: [0; 2],
            payload_kinds: kinds,
            payload_arg_indices: indices,
            payloads: [[0; CAPTURE_BYTES]; 2],
            file_object: None,
        };
        assert!(validate_event_policy(&event, &policy).is_err());
    }
}
