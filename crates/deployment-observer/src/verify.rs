// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, Context, Result};
use bpf_observer_deployment::{DeploymentManifest, LiveIdentityValidation};
use bpf_observer_filesystem_confirmer::{
    FilesystemComparison, FilesystemSnapshot, SnapshotPhase as FilesystemSnapshotPhase,
    HARD_MAX_COMPARISON_JSON_BYTES as HARD_MAX_FILESYSTEM_COMPARISON_JSON_BYTES,
    HARD_MAX_SNAPSHOT_JSON_BYTES as HARD_MAX_FILESYSTEM_SNAPSHOT_JSON_BYTES,
};
use bpf_observer_linux_state_confirmers::{
    compare as compare_linux_state, StateComparison, StateSnapshot, HARD_MAX_COMPARISON_JSON_BYTES,
    HARD_MAX_SNAPSHOT_JSON_BYTES,
};
use bpf_observer_schema::{
    Snapshot as BpfSnapshot, Verdict as BpfVerdict, MAX_SNAPSHOT_JSON_BYTES, MAX_VERDICT_JSON_BYTES,
};
use bpf_observer_system_effects::lifecycle::{
    recover_process_lifecycle_wal, ProcessLifecycleEvent, ProcessLifecycleStatus,
    ProcessLineageVerifier, PROCESS_LIFECYCLE_ENROLLMENT_LIMITATION,
};
use bpf_observer_system_effects::socket_state::{
    verify_socket_state_artifacts, SocketStateRunVerification, SocketStateStatus,
    SocketStateVerificationBinding, MAX_SOCKET_STATE_WAL_BYTES, SOCKET_STATE_HEALTH_NAME,
    SOCKET_STATE_JSONL_NAME, SOCKET_STATE_WAL_NAME,
};
use bpf_observer_system_effects::{
    policy_sha256, verify_system_effect_artifacts, CgroupMatchMode, SystemEffectRunVerification,
    SystemEffectVerificationBinding,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use crate::endpoint_state::{
    bpf_scope_sha256, bpf_snapshot_id, compare_bpf_endpoints, compare_filesystem_endpoints,
    endpoint_contract_reasons, filesystem_mount_namespace_target, filesystem_namespace_reasons,
    filesystem_snapshot_id, validate_filesystem_output_separation, BpfStateArtifactBindings,
    BpfStateReport, EndpointContractEvidence, FilesystemStateReport, BPF_STATE_S0_FILE,
    BPF_STATE_S1_FILE, BPF_STATE_VERDICT_FILE, FILESYSTEM_STATE_COMPARISON_FILE,
    FILESYSTEM_STATE_S0_FILE, FILESYSTEM_STATE_S1_FILE,
};
use crate::protocol::{ReadyMessage, DEPLOYMENT_OBSERVER_PROTOCOL_VERSION};
use crate::report::{
    aggregate_health, checked_artifact_total_bytes, overall_evidence_status, ArtifactDigest,
    ArtifactManifest, DeploymentObservationReport, IdentityAssessment, SocketStateHealthArtifact,
    SocketStateReport,
};
use crate::session::DeploymentObserverConfig;
use crate::{
    linux_state::{
        bind_linux_state_scope, confirmation_contract_reasons, retained_namespace_contract_reasons,
    },
    CgroupScopeCapability, LinuxStateReport,
};

const MAX_JSON_BYTES: u64 = 16 * 1024 * 1024;
const MAX_COMMITTED_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_EVENT_LINE_BYTES: usize = 1024 * 1024;
const MAX_EVENTS: usize = 1_000_000;
const ARTIFACT_MANIFEST_FILE: &str = "artifact-manifest.json";
const REPORT_FILE: &str = "deployment-observation-report.json";
const EFFECT_WAL_FILE: &str = "system-effects.raw.bin";
const EFFECT_JSONL_FILE: &str = "system-effects.jsonl";
const LIFECYCLE_WAL_FILE: &str = "process-lifecycle.raw.bin";
const LIFECYCLE_JSONL_FILE: &str = "process-lifecycle.jsonl";
const LINUX_STATE_S0_FILE: &str = "linux-state-s0.json";
const LINUX_STATE_S1_FILE: &str = "linux-state-s1.json";
const LINUX_STATE_COMPARISON_FILE: &str = "linux-state-comparison.json";

const BASE_COMMITTED_ARTIFACTS: &[&str] = &[
    "closure-barrier.json",
    "closure-validation.json",
    "deployment-manifest.json",
    "deployment-observation-report.json",
    "observation-contract.json",
    "pre-finish-barrier.json",
    "pre-finish-validation.json",
    "process-lifecycle.jsonl",
    "process-lifecycle.raw.bin",
    "ready-barrier.json",
    "ready-message.json",
    "ready-validation.json",
    "system-effects.jsonl",
    "system-effects.raw.bin",
];

pub(crate) fn committed_artifacts(
    socket_state_enabled: bool,
    bpf_state_enabled: bool,
    filesystem_state_enabled: bool,
    linux_state_enabled: bool,
) -> Vec<&'static str> {
    let mut names = BASE_COMMITTED_ARTIFACTS.to_vec();
    if socket_state_enabled {
        names.extend([
            SOCKET_STATE_HEALTH_NAME,
            SOCKET_STATE_JSONL_NAME,
            SOCKET_STATE_WAL_NAME,
        ]);
    }
    if bpf_state_enabled {
        names.extend([BPF_STATE_S0_FILE, BPF_STATE_S1_FILE, BPF_STATE_VERDICT_FILE]);
    }
    if filesystem_state_enabled {
        names.extend([
            FILESYSTEM_STATE_COMPARISON_FILE,
            FILESYSTEM_STATE_S0_FILE,
            FILESYSTEM_STATE_S1_FILE,
        ]);
    }
    if linux_state_enabled {
        names.extend([
            LINUX_STATE_COMPARISON_FILE,
            LINUX_STATE_S0_FILE,
            LINUX_STATE_S1_FILE,
        ]);
    }
    names.sort_unstable();
    names
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationExpectation {
    pub expected_config: DeploymentObserverConfig,
    pub expected_artifact_manifest_sha256: String,
    pub expected_report_sha256: String,
}

impl VerificationExpectation {
    pub fn validate(&self) -> Result<()> {
        self.expected_config.validate_schema()?;
        validate_sha256(
            &self.expected_artifact_manifest_sha256,
            "expected artifact manifest",
        )?;
        validate_sha256(&self.expected_report_sha256, "expected observation report")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineVerification {
    pub protocol_version: u32,
    pub verified: bool,
    pub run_id: String,
    pub epoch: u64,
    pub deployment_scope_sha256: String,
    pub artifact_count: u64,
    pub committed_artifact_total_bytes: u64,
    pub system_effect_wal_event_count: u64,
    pub system_effect_jsonl_event_count: u64,
    pub process_lifecycle_wal_event_count: u64,
    pub process_lifecycle_jsonl_event_count: u64,
    /// Conservative overall status across every enabled and replayed domain.
    pub evidence_status: crate::report::AggregateEvidenceStatus,
    pub socket_state_status: Option<SocketStateStatus>,
    pub socket_state_event_count: Option<u64>,
    pub bpf_state_scope_sha256: Option<String>,
    pub bpf_state_verdict: Option<bpf_observer_schema::StateVerdict>,
    pub filesystem_state_scope_sha256: Option<String>,
    pub filesystem_state_verdict: Option<bpf_observer_filesystem_confirmer::FilesystemVerdict>,
    pub linux_state_scope_sha256: Option<String>,
    pub linux_state_evidence_status: Option<crate::LinuxStateEvidenceStatus>,
}

pub fn verify_artifacts(
    directory: &Path,
    expectation: &VerificationExpectation,
) -> Result<OfflineVerification> {
    expectation.validate()?;
    let directory_file = open_directory(directory)?;
    let before = directory_file.metadata()?;
    let actual_names = directory_entries(directory)?;
    let committed_names = committed_artifacts(
        expectation.expected_config.object_resolution_mode
            == bpf_observer_system_effects::FileObjectResolutionMode::KernelObjectExpandedPartial,
        expectation.expected_config.bpf_state_scope.is_some(),
        expectation.expected_config.filesystem_state_scope.is_some(),
        expectation.expected_config.linux_state_scope.is_some(),
    );
    let mut expected_names = committed_names
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    expected_names.insert(ARTIFACT_MANIFEST_FILE.to_owned());
    if actual_names != expected_names {
        bail!("evidence directory contains a missing or uncommitted artifact");
    }

    let artifact_manifest_digest = digest_file(
        &directory.join(ARTIFACT_MANIFEST_FILE),
        ARTIFACT_MANIFEST_FILE,
    )?;
    if artifact_manifest_digest.sha256 != expectation.expected_artifact_manifest_sha256 {
        bail!("artifact manifest digest does not match the external expectation");
    }
    let artifact_manifest: ArtifactManifest =
        read_json(&directory.join(ARTIFACT_MANIFEST_FILE), MAX_JSON_BYTES)?;
    validate_artifact_manifest(&artifact_manifest, expectation)?;

    for expected in &artifact_manifest.artifacts {
        let observed = digest_file(
            &directory.join(&expected.relative_path),
            &expected.relative_path,
        )?;
        if &observed != expected {
            bail!(
                "artifact {} does not match its committed digest",
                expected.relative_path
            );
        }
    }

    let contract: DeploymentObserverConfig =
        read_json(&directory.join("observation-contract.json"), MAX_JSON_BYTES)?;
    if contract != expectation.expected_config {
        bail!("embedded observation contract differs from the external expected config");
    }
    let report_digest = digest_file(&directory.join(REPORT_FILE), REPORT_FILE)?;
    if report_digest.sha256 != expectation.expected_report_sha256 {
        bail!("observation report digest does not match the external expectation");
    }
    let report: DeploymentObservationReport =
        read_json(&directory.join(REPORT_FILE), MAX_JSON_BYTES)?;
    report.validate()?;
    validate_report_bindings(directory, &report, &artifact_manifest, &contract)?;

    let system_runs = report
        .cgroup_outcomes
        .iter()
        .map(|outcome| {
            let health = outcome.health.as_ref().with_context(|| {
                format!(
                    "cannot strictly verify system-effect cgroup {} without finalized health",
                    outcome.cgroup_id
                )
            })?;
            Ok(SystemEffectRunVerification {
                cgroup_id: outcome.cgroup_id,
                run_epoch: report.epoch,
                published: health.event_published,
                dropped: health.event_dropped,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let system_verification = verify_system_effect_artifacts(
        &directory.join(EFFECT_WAL_FILE),
        &directory.join(EFFECT_JSONL_FILE),
        &SystemEffectVerificationBinding {
            run_id: report.run_id.clone(),
            boot_id: report.deployment.boot_id.clone(),
            profile: contract.profile,
            object_resolution_mode: contract.object_resolution_mode,
            cgroup_match_mode: CgroupMatchMode::AncestorRoot,
            runs: system_runs,
        },
    )?;
    validate_system_verification(&report, &system_verification)?;
    let lifecycle_recovery = recover_process_lifecycle_wal(&directory.join(LIFECYCLE_WAL_FILE))?;
    if lifecycle_recovery.truncated_tail {
        bail!("process-lifecycle WAL has a truncated tail");
    }
    let lifecycle_json = read_lifecycle_jsonl(&directory.join(LIFECYCLE_JSONL_FILE))?;
    validate_lifecycle_streams(&report, &lifecycle_recovery.events, &lifecycle_json)?;

    let after = directory_file.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        bail!("evidence directory changed during offline verification");
    }
    Ok(OfflineVerification {
        protocol_version: DEPLOYMENT_OBSERVER_PROTOCOL_VERSION,
        verified: true,
        run_id: report.run_id,
        epoch: report.epoch,
        deployment_scope_sha256: report.deployment.scope_sha256,
        artifact_count: artifact_manifest.artifacts.len() as u64,
        committed_artifact_total_bytes: artifact_manifest.committed_artifact_total_bytes,
        system_effect_wal_event_count: system_verification.wal_event_count,
        system_effect_jsonl_event_count: system_verification.wal_event_count,
        process_lifecycle_wal_event_count: lifecycle_recovery.events.len() as u64,
        process_lifecycle_jsonl_event_count: lifecycle_json.len() as u64,
        evidence_status: report.overall_evidence_status,
        socket_state_status: artifact_manifest.socket_state_status,
        socket_state_event_count: report
            .socket_state
            .as_ref()
            .map(|state| state.event_published),
        bpf_state_scope_sha256: artifact_manifest.bpf_state_scope_sha256,
        bpf_state_verdict: artifact_manifest.bpf_state_verdict,
        filesystem_state_scope_sha256: artifact_manifest.filesystem_state_scope_sha256,
        filesystem_state_verdict: artifact_manifest.filesystem_state_verdict,
        linux_state_scope_sha256: artifact_manifest.linux_state_scope_sha256,
        linux_state_evidence_status: artifact_manifest.linux_state_evidence_status,
    })
}

fn validate_system_verification(
    report: &DeploymentObservationReport,
    verification: &bpf_observer_system_effects::SystemEffectArtifactVerification,
) -> Result<()> {
    if !verification.jsonl_projection_verified
        || verification.policy_sha256 != report.recorder_policy_sha256
        || verification.wal_event_count != report.aggregate_health.events_persisted
        || verification.runs.len() != report.cgroup_outcomes.len()
    {
        bail!("strict system-effect replay disagrees with the observation report");
    }
    for (verified, outcome) in verification.runs.iter().zip(&report.cgroup_outcomes) {
        let health = outcome
            .health
            .as_ref()
            .context("strictly verified system-effect run has no finalized health")?;
        if verified.cgroup_id != outcome.cgroup_id
            || verified.run_epoch != report.epoch
            || verified.published != health.event_published
            || verified.dropped != health.event_dropped
            || verified.recovered != health.events_persisted
            || verified.fatal_correlation_events != health.fatal_kernel_flags
        {
            bail!("strict system-effect per-cgroup replay disagrees with recorder health");
        }
    }
    Ok(())
}

fn validate_artifact_manifest(
    manifest: &ArtifactManifest,
    expectation: &VerificationExpectation,
) -> Result<()> {
    if manifest.protocol_version != DEPLOYMENT_OBSERVER_PROTOCOL_VERSION
        || manifest.run_id != expectation.expected_config.run_id
        || manifest.epoch != expectation.expected_config.epoch
    {
        bail!("artifact manifest is not bound to the external run expectation");
    }
    validate_sha256(
        &manifest.cgroup_scope_capability_sha256,
        "artifact cgroup scope capability",
    )?;
    let socket_state_enabled = expectation.expected_config.object_resolution_mode
        == bpf_observer_system_effects::FileObjectResolutionMode::KernelObjectExpandedPartial;
    if socket_state_enabled != manifest.socket_state_status.is_some() {
        bail!("artifact manifest socket-state presence differs from external object mode");
    }
    manifest.diagnostic_performance.validate(
        expectation.expected_config.bpf_state_scope.is_some(),
        expectation.expected_config.filesystem_state_scope.is_some(),
        expectation.expected_config.linux_state_scope.is_some(),
    )?;
    for (enabled, scope_digest, verdict_present, label) in [
        (
            expectation.expected_config.bpf_state_scope.is_some(),
            manifest.bpf_state_scope_sha256.as_deref(),
            manifest.bpf_state_verdict.is_some(),
            "BPF state",
        ),
        (
            expectation.expected_config.filesystem_state_scope.is_some(),
            manifest.filesystem_state_scope_sha256.as_deref(),
            manifest.filesystem_state_verdict.is_some(),
            "filesystem state",
        ),
    ] {
        if enabled != scope_digest.is_some() || enabled != verdict_present {
            bail!("artifact manifest {label} presence differs from external configuration");
        }
        if let Some(digest) = scope_digest {
            validate_sha256(digest, label)?;
        }
    }
    let names = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.relative_path.as_str())
        .collect::<Vec<_>>();
    let expected_names = committed_artifacts(
        expectation.expected_config.object_resolution_mode
            == bpf_observer_system_effects::FileObjectResolutionMode::KernelObjectExpandedPartial,
        expectation.expected_config.bpf_state_scope.is_some(),
        expectation.expected_config.filesystem_state_scope.is_some(),
        expectation.expected_config.linux_state_scope.is_some(),
    );
    if names != expected_names {
        bail!("artifact manifest does not contain the exact canonical artifact set");
    }
    for artifact in &manifest.artifacts {
        validate_artifact_name(&artifact.relative_path)?;
        validate_sha256(&artifact.sha256, &artifact.relative_path)?;
        if artifact.size_bytes > MAX_COMMITTED_ARTIFACT_BYTES {
            bail!("committed artifact exceeds the offline verification byte limit");
        }
    }
    let recomputed_total = checked_artifact_total_bytes(&manifest.artifacts)?;
    if manifest.committed_artifact_total_bytes != recomputed_total {
        bail!("committed artifact byte total does not recompute from the closed artifact set");
    }
    Ok(())
}

fn validate_report_bindings(
    directory: &Path,
    report: &DeploymentObservationReport,
    artifact_manifest: &ArtifactManifest,
    contract: &DeploymentObserverConfig,
) -> Result<()> {
    if report.run_id != contract.run_id
        || report.epoch != contract.epoch
        || report.recorder_object_sha256 != contract.recorder_object_sha256
        || report.lifecycle_object_sha256 != contract.lifecycle_object_sha256
        || report.recorder_policy_sha256 != policy_sha256(contract.profile)?
        || artifact_manifest.run_id != report.run_id
        || artifact_manifest.epoch != report.epoch
        || artifact_manifest.deployment_scope_sha256 != report.deployment.scope_sha256
        || artifact_manifest.cgroup_scope_capability_sha256 != report.cgroup_scope_capability_sha256
        || report.overall_evidence_status != overall_evidence_status(report)
        || artifact_manifest.evidence_status != report.overall_evidence_status
        || artifact_manifest.diagnostic_performance != report.diagnostic_performance
        || artifact_manifest.socket_state_status
            != report.socket_state.as_ref().map(|state| state.status)
        || artifact_manifest.bpf_state_scope_sha256
            != report
                .bpf_state
                .as_ref()
                .map(|state| state.scope_sha256.clone())
        || artifact_manifest.bpf_state_verdict
            != report
                .bpf_state
                .as_ref()
                .map(|state| state.state_verdict.clone())
        || artifact_manifest.filesystem_state_scope_sha256
            != report
                .filesystem_state
                .as_ref()
                .map(|state| state.scope_sha256.clone())
        || artifact_manifest.filesystem_state_verdict
            != report
                .filesystem_state
                .as_ref()
                .map(|state| state.state_verdict)
    {
        bail!("observation report is not bound to the contract/artifact manifest");
    }
    let deployment: DeploymentManifest =
        read_json(&directory.join("deployment-manifest.json"), MAX_JSON_BYTES)?;
    if deployment != report.deployment {
        bail!("standalone deployment manifest differs from the report");
    }
    let mut root_ids = deployment.registration_root_cgroup_ids();
    root_ids.sort_unstable();
    root_ids.dedup();
    let rebuilt_scope_capability = CgroupScopeCapability::for_roots(&root_ids)?;
    if rebuilt_scope_capability != report.cgroup_scope_capability
        || rebuilt_scope_capability.sha256()? != report.cgroup_scope_capability_sha256
    {
        bail!("cgroup ancestor capability does not independently rebuild from deployment roots");
    }
    let ready: ReadyMessage = read_json(&directory.join("ready-message.json"), MAX_JSON_BYTES)?;
    let committed = artifact_manifest
        .artifacts
        .iter()
        .map(|artifact| (artifact.relative_path.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    if ready.protocol_version != DEPLOYMENT_OBSERVER_PROTOCOL_VERSION
        || ready.status != "READY"
        || ready.run_id != report.run_id
        || ready.epoch != report.epoch
        || ready.deployment_scope_sha256 != report.deployment.scope_sha256
        || ready.registration_cgroup_ids != report.registration_cgroup_ids
        || ready.cgroup_scope_capability != report.cgroup_scope_capability
        || ready.cgroup_scope_capability_sha256 != report.cgroup_scope_capability_sha256
        || ready.recorder_object_sha256 != report.recorder_object_sha256
        || ready.lifecycle_object_sha256 != report.lifecycle_object_sha256
        || ready.socket_state_enabled != report.socket_state.is_some()
        || ready.bpf_state_scope_sha256
            != report
                .bpf_state
                .as_ref()
                .map(|state| state.scope_sha256.clone())
        || ready.bpf_state_s0_sha256
            != report
                .bpf_state
                .as_ref()
                .map(|state| state.s0_snapshot_sha256.clone())
        || ready.filesystem_state_scope_sha256
            != report
                .filesystem_state
                .as_ref()
                .map(|state| state.scope_sha256.clone())
        || ready.filesystem_state_s0_sha256
            != report
                .filesystem_state
                .as_ref()
                .map(|state| state.s0_snapshot_sha256.clone())
        || ready.finish_nonce.len() != 64
        || !ready
            .finish_nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || committed
            .get("deployment-manifest.json")
            .map(|artifact| artifact.sha256.as_str())
            != Some(ready.deployment_manifest_sha256.as_str())
        || committed
            .get("ready-barrier.json")
            .map(|artifact| artifact.sha256.as_str())
            != Some(ready.ready_barrier_sha256.as_str())
        || committed
            .get("ready-validation.json")
            .map(|artifact| artifact.sha256.as_str())
            != Some(ready.ready_validation_sha256.as_str())
    {
        bail!("READY message is not bound to the observation report");
    }
    let ready_validation: LiveIdentityValidation =
        read_json(&directory.join("ready-validation.json"), MAX_JSON_BYTES)?;
    if ready_validation != report.ready_validation || !ready_validation.is_stable() {
        bail!("READY identity validation is not stable or differs from the report");
    }
    let ready_barrier: crate::RootFreezeBarrier =
        read_json(&directory.join("ready-barrier.json"), MAX_JSON_BYTES)?;
    let pre_barrier: crate::RootFreezeBarrier =
        read_json(&directory.join("pre-finish-barrier.json"), MAX_JSON_BYTES)?;
    let closure_barrier: crate::RootFreezeBarrier =
        read_json(&directory.join("closure-barrier.json"), MAX_JSON_BYTES)?;
    if ready_barrier != report.ready_barrier
        || pre_barrier != report.pre_finish_barrier
        || closure_barrier != report.closure_barrier
    {
        bail!("standalone cgroup barrier artifact differs from the observation report");
    }
    let pre: IdentityAssessment = read_json(
        &directory.join("pre-finish-validation.json"),
        MAX_JSON_BYTES,
    )?;
    let closure: IdentityAssessment =
        read_json(&directory.join("closure-validation.json"), MAX_JSON_BYTES)?;
    if pre != report.pre_finish_validation || closure != report.closure_validation {
        bail!("closure identity assessment differs from the observation report");
    }
    let recomputed = aggregate_health(
        &report.registration_cgroup_ids,
        &report.cgroup_outcomes,
        report.pre_finish_barrier.all_roots_frozen && report.closure_barrier.all_roots_frozen,
        report.pre_finish_validation.stable && report.closure_validation.stable,
    )?;
    if recomputed != report.aggregate_health {
        bail!("aggregate recorder health does not recompute from per-cgroup evidence");
    }
    let lifecycle_recomputed = crate::aggregate_lifecycle_health(
        &report.registration_cgroup_ids,
        &report.lifecycle_outcomes,
    )?;
    if lifecycle_recomputed != report.aggregate_lifecycle_health {
        bail!("aggregate lifecycle health does not recompute from per-cgroup evidence");
    }
    for outcome in &report.cgroup_outcomes {
        if let Some(health) = &outcome.health {
            if health.run_id != report.run_id
                || health.run_epoch != report.epoch
                || health.profile != contract.profile
                || health.object_resolution_mode != contract.object_resolution_mode
            {
                bail!("per-cgroup effect health is not bound to the observation contract");
            }
        }
    }
    for outcome in &report.lifecycle_outcomes {
        if let Some(health) = &outcome.health {
            if health.run_id != report.run_id || health.run_epoch != report.epoch {
                bail!("per-cgroup lifecycle health is not bound to the observation contract");
            }
        }
    }
    validate_socket_state_artifacts(
        directory,
        report,
        artifact_manifest,
        contract,
        &ready,
        &committed,
    )?;
    validate_bpf_state_artifacts(
        directory,
        report,
        artifact_manifest,
        contract,
        &ready,
        &committed,
    )?;
    validate_filesystem_state_artifacts(
        directory,
        report,
        artifact_manifest,
        contract,
        &ready,
        &committed,
    )?;
    validate_linux_state_artifacts(
        directory,
        report,
        artifact_manifest,
        contract,
        &ready,
        &committed,
    )?;
    Ok(())
}

fn validate_socket_state_artifacts(
    directory: &Path,
    report: &DeploymentObservationReport,
    artifact_manifest: &ArtifactManifest,
    contract: &DeploymentObserverConfig,
    ready: &ReadyMessage,
    committed: &BTreeMap<&str, &ArtifactDigest>,
) -> Result<()> {
    let enabled = contract.object_resolution_mode
        == bpf_observer_system_effects::FileObjectResolutionMode::KernelObjectExpandedPartial;
    if report.socket_state.is_some() != enabled
        || ready.socket_state_enabled != enabled
        || artifact_manifest.socket_state_status.is_some() != enabled
    {
        bail!("socket-state presence differs from the externally bound object mode");
    }
    let Some(socket_report) = report.socket_state.as_ref() else {
        if report.cgroup_outcomes.iter().any(|outcome| {
            outcome
                .health
                .as_ref()
                .and_then(|health| health.socket_state.as_ref())
                .is_some()
        }) {
            bail!("disabled socket-state stream is present in recorder health");
        }
        return Ok(());
    };
    socket_report.validate()?;
    if artifact_manifest.socket_state_status != Some(socket_report.status) {
        bail!("socket-state artifact manifest status differs from the report");
    }
    let health_digest = committed
        .get(SOCKET_STATE_HEALTH_NAME)
        .context("artifact manifest has no socket-state health")?;
    let wal_digest = committed
        .get(SOCKET_STATE_WAL_NAME)
        .context("artifact manifest has no socket-state WAL")?;
    committed
        .get(SOCKET_STATE_JSONL_NAME)
        .context("artifact manifest has no socket-state JSONL")?;
    if health_digest.sha256 != socket_report.health_sha256 {
        bail!("socket-state health digest differs from the report");
    }
    if wal_digest.size_bytes > MAX_SOCKET_STATE_WAL_BYTES {
        bail!("socket-state WAL exceeds its protocol byte bound");
    }
    let stored_health: SocketStateHealthArtifact =
        read_json(&directory.join(SOCKET_STATE_HEALTH_NAME), MAX_JSON_BYTES)?;
    stored_health.validate()?;
    let rebuilt_health = SocketStateHealthArtifact::from_outcomes(
        &report.run_id,
        &report.deployment.boot_id,
        report.epoch,
        &report.registration_cgroup_ids,
        &report.cgroup_outcomes,
    )?;
    if stored_health != rebuilt_health {
        bail!("socket-state health artifact differs from finalized per-root health");
    }
    let rebuilt_report =
        SocketStateReport::from_health(&stored_health, health_digest.sha256.clone())?;
    if &rebuilt_report != socket_report {
        bail!("socket-state report does not independently aggregate from health");
    }
    let runs = stored_health
        .runs
        .iter()
        .map(|health| SocketStateRunVerification {
            cgroup_id: health.cgroup_id,
            run_epoch: health.run_epoch,
            published: health.event_published,
            dropped: health.event_dropped,
        })
        .collect();
    let verified = verify_socket_state_artifacts(
        &directory.join(SOCKET_STATE_WAL_NAME),
        &directory.join(SOCKET_STATE_JSONL_NAME),
        &directory.join(EFFECT_WAL_FILE),
        &SocketStateVerificationBinding {
            run_id: report.run_id.clone(),
            boot_id: report.deployment.boot_id.clone(),
            cgroup_match_mode: CgroupMatchMode::AncestorRoot,
            runs,
        },
        &stored_health.runs,
    )
    .context("strictly replay deployment socket-state WAL, JSONL, health, and syscall origins")?;
    if !verified.jsonl_projection_verified
        || verified.events_verified != socket_report.event_published
        || verified.origin_links_verified != socket_report.event_published
        || verified.runs.len() != socket_report.root_count as usize
        || verified
            .runs
            .iter()
            .map(|run| run.destroy_events_verified)
            .try_fold(0_u64, |total, value| total.checked_add(value))
            != Some(socket_report.destroy_events_persisted)
    {
        bail!("socket-state strict replay disagrees with the deployment report");
    }
    Ok(())
}

fn validate_bpf_state_artifacts(
    directory: &Path,
    report: &DeploymentObservationReport,
    artifact_manifest: &ArtifactManifest,
    contract: &DeploymentObserverConfig,
    ready: &ReadyMessage,
    committed: &BTreeMap<&str, &ArtifactDigest>,
) -> Result<()> {
    let configured = contract.bpf_state_scope.is_some();
    if report.bpf_state.is_some() != configured {
        bail!("BPF state report presence differs from the external configuration");
    }
    let Some(state_report) = report.bpf_state.as_ref() else {
        if artifact_manifest.bpf_state_scope_sha256.is_some()
            || artifact_manifest.bpf_state_verdict.is_some()
            || ready.bpf_state_scope_sha256.is_some()
            || ready.bpf_state_s0_sha256.is_some()
        {
            bail!("disabled BPF state confirmation carries evidence bindings");
        }
        return Ok(());
    };
    let scope = contract
        .bpf_state_scope
        .as_ref()
        .context("enabled BPF state confirmation has no external scope")?;
    bpf_observer_oracle::validate_claim_scope(scope)?;
    bpf_observer_oracle::validate_claim_scope_exclusions(scope, &state_report.observer_exclusions)?;
    let scope_sha256 = bpf_scope_sha256(scope)?;
    if state_report.scope_sha256 != scope_sha256
        || artifact_manifest.bpf_state_scope_sha256.as_deref() != Some(scope_sha256.as_str())
        || artifact_manifest.bpf_state_verdict.as_ref() != Some(&state_report.state_verdict)
        || ready.bpf_state_scope_sha256.as_deref() != Some(scope_sha256.as_str())
        || ready.bpf_state_s0_sha256.as_deref() != Some(state_report.s0_snapshot_sha256.as_str())
    {
        bail!("BPF state external scope/READY/report/manifest bindings disagree");
    }
    let s0_digest = committed
        .get(BPF_STATE_S0_FILE)
        .context("artifact manifest has no BPF state S0")?;
    let s1_digest = committed
        .get(BPF_STATE_S1_FILE)
        .context("artifact manifest has no BPF state S1")?;
    let verdict_digest = committed
        .get(BPF_STATE_VERDICT_FILE)
        .context("artifact manifest has no BPF state verdict")?;
    if s0_digest.sha256 != state_report.s0_snapshot_sha256
        || s1_digest.sha256 != state_report.s1_snapshot_sha256
        || verdict_digest.sha256 != state_report.verdict_sha256
    {
        bail!("BPF state report digests differ from the artifact manifest");
    }
    let s0: BpfSnapshot = read_json(&directory.join(BPF_STATE_S0_FILE), MAX_SNAPSHOT_JSON_BYTES)?;
    let s1: BpfSnapshot = read_json(&directory.join(BPF_STATE_S1_FILE), MAX_SNAPSHOT_JSON_BYTES)?;
    let stored_verdict: BpfVerdict = read_json(
        &directory.join(BPF_STATE_VERDICT_FILE),
        MAX_VERDICT_JSON_BYTES,
    )?;
    bpf_observer_oracle::validate_snapshot_resource_bounds(&s0)?;
    bpf_observer_oracle::validate_snapshot_resource_bounds(&s1)?;
    if s0.snapshot_id != bpf_snapshot_id(&report.run_id, report.epoch, "S0")
        || s1.snapshot_id != bpf_snapshot_id(&report.run_id, report.epoch, "S1")
        || s0.phase != "S0"
        || s1.phase != "S1"
        || s0.boot_id != report.deployment.boot_id
        || s1.boot_id != report.deployment.boot_id
        || s0.captured_unix_ns > s1.captured_unix_ns
        || s0.claim_scope != *scope
        || s1.claim_scope != *scope
        || s0.observer_exclusions != state_report.observer_exclusions
        || s1.observer_exclusions != state_report.observer_exclusions
    {
        bail!("BPF state snapshots are not bound to the deployment run and external scope");
    }
    let rebuilt_verdict = compare_bpf_endpoints(&s0, &s1)?;
    if rebuilt_verdict != stored_verdict {
        bail!("stored BPF state verdict is not the independent S0/S1 comparison");
    }
    let reasons = endpoint_contract_reasons(
        &EndpointContractEvidence {
            deployment_boot_id: &report.deployment.boot_id,
            s0_boot_id: &s0.boot_id,
            s1_boot_id: &s1.boot_id,
            ready_barrier_complete: report.ready_barrier.all_roots_frozen,
            ready_identity_stable: report.ready_validation.stable,
            pre_finish_barrier_complete: report.pre_finish_barrier.all_roots_frozen,
            pre_finish_identity_stable: report.pre_finish_validation.stable,
            closure_barrier_complete: report.closure_barrier.all_roots_frozen,
            closure_identity_stable: report.closure_validation.stable,
            recorder_drains_complete: recorder_drains_complete(report),
        },
        &[],
    );
    let rebuilt_report = BpfStateReport::from_verdict(
        scope,
        &state_report.system_effect_recorder_exclusions,
        &state_report.lifecycle_recorder_exclusions,
        &rebuilt_verdict,
        &BpfStateArtifactBindings {
            s0_snapshot_id: &s0.snapshot_id,
            s0_digest,
            s1_snapshot_id: &s1.snapshot_id,
            s1_digest,
            verdict_digest,
        },
        &reasons,
    )?;
    if &rebuilt_report != state_report {
        bail!("BPF state report does not independently recompute");
    }
    Ok(())
}

fn validate_filesystem_state_artifacts(
    directory: &Path,
    report: &DeploymentObservationReport,
    artifact_manifest: &ArtifactManifest,
    contract: &DeploymentObserverConfig,
    ready: &ReadyMessage,
    committed: &BTreeMap<&str, &ArtifactDigest>,
) -> Result<()> {
    let configured = contract.filesystem_state_scope.is_some();
    if report.filesystem_state.is_some() != configured {
        bail!("filesystem state report presence differs from the external configuration");
    }
    let Some(state_report) = report.filesystem_state.as_ref() else {
        if artifact_manifest.filesystem_state_scope_sha256.is_some()
            || artifact_manifest.filesystem_state_verdict.is_some()
            || ready.filesystem_state_scope_sha256.is_some()
            || ready.filesystem_state_s0_sha256.is_some()
        {
            bail!("disabled filesystem state confirmation carries evidence bindings");
        }
        return Ok(());
    };
    let scope = contract
        .filesystem_state_scope
        .as_ref()
        .context("enabled filesystem state confirmation has no external scope")?;
    scope.validate()?;
    let evidence_directory =
        fs::canonicalize(directory).context("canonicalize deployment evidence directory")?;
    validate_filesystem_output_separation(scope, &evidence_directory)?;
    let scope_sha256 = scope.sha256()?;
    if state_report.scope_sha256 != scope_sha256
        || artifact_manifest.filesystem_state_scope_sha256.as_deref() != Some(scope_sha256.as_str())
        || artifact_manifest.filesystem_state_verdict != Some(state_report.state_verdict)
        || ready.filesystem_state_scope_sha256.as_deref() != Some(scope_sha256.as_str())
        || ready.filesystem_state_s0_sha256.as_deref()
            != Some(state_report.s0_snapshot_sha256.as_str())
    {
        bail!("filesystem state external scope/READY/report/manifest bindings disagree");
    }
    let s0_digest = committed
        .get(FILESYSTEM_STATE_S0_FILE)
        .context("artifact manifest has no filesystem state S0")?;
    let s1_digest = committed
        .get(FILESYSTEM_STATE_S1_FILE)
        .context("artifact manifest has no filesystem state S1")?;
    let comparison_digest = committed
        .get(FILESYSTEM_STATE_COMPARISON_FILE)
        .context("artifact manifest has no filesystem state comparison")?;
    if s0_digest.sha256 != state_report.s0_snapshot_sha256
        || s1_digest.sha256 != state_report.s1_snapshot_sha256
        || comparison_digest.sha256 != state_report.comparison_sha256
    {
        bail!("filesystem state report digests differ from the artifact manifest");
    }
    let s0: FilesystemSnapshot = read_json(
        &directory.join(FILESYSTEM_STATE_S0_FILE),
        HARD_MAX_FILESYSTEM_SNAPSHOT_JSON_BYTES,
    )?;
    let s1: FilesystemSnapshot = read_json(
        &directory.join(FILESYSTEM_STATE_S1_FILE),
        HARD_MAX_FILESYSTEM_SNAPSHOT_JSON_BYTES,
    )?;
    let stored_comparison: FilesystemComparison = read_json(
        &directory.join(FILESYSTEM_STATE_COMPARISON_FILE),
        HARD_MAX_FILESYSTEM_COMPARISON_JSON_BYTES,
    )?;
    s0.validate()?;
    s1.validate()?;
    if s0.snapshot_id != filesystem_snapshot_id(&report.run_id, report.epoch, "S0")
        || s1.snapshot_id != filesystem_snapshot_id(&report.run_id, report.epoch, "S1")
        || s0.phase != FilesystemSnapshotPhase::S0
        || s1.phase != FilesystemSnapshotPhase::S1
        || s0.boot_id != report.deployment.boot_id
        || s1.boot_id != report.deployment.boot_id
        || s0.captured_unix_ns > s1.captured_unix_ns
        || s0.scope != *scope
        || s1.scope != *scope
        || s0.scope_sha256 != scope_sha256
        || s1.scope_sha256 != scope_sha256
    {
        bail!("filesystem snapshots are not bound to the deployment run and external scope");
    }
    let rebuilt_comparison = compare_filesystem_endpoints(&s0, &s1)?;
    if rebuilt_comparison != stored_comparison {
        bail!("stored filesystem comparison is not the independent S0/S1 comparison");
    }
    let required_mount_namespace = filesystem_mount_namespace_target(&report.deployment)?
        .map(|target| target.expected_namespace_inode);
    let mut extra = filesystem_namespace_reasons(
        &s0,
        &report.deployment.mount_namespace_ids,
        required_mount_namespace,
        report.deployment.deployment_kind,
    );
    extra.extend(filesystem_namespace_reasons(
        &s1,
        &report.deployment.mount_namespace_ids,
        required_mount_namespace,
        report.deployment.deployment_kind,
    ));
    let reasons = endpoint_contract_reasons(
        &EndpointContractEvidence {
            deployment_boot_id: &report.deployment.boot_id,
            s0_boot_id: &s0.boot_id,
            s1_boot_id: &s1.boot_id,
            ready_barrier_complete: report.ready_barrier.all_roots_frozen,
            ready_identity_stable: report.ready_validation.stable,
            pre_finish_barrier_complete: report.pre_finish_barrier.all_roots_frozen,
            pre_finish_identity_stable: report.pre_finish_validation.stable,
            closure_barrier_complete: report.closure_barrier.all_roots_frozen,
            closure_identity_stable: report.closure_validation.stable,
            recorder_drains_complete: recorder_drains_complete(report),
        },
        &extra,
    );
    let rebuilt_report = FilesystemStateReport::from_comparison(
        scope,
        &rebuilt_comparison,
        s0_digest,
        s1_digest,
        comparison_digest,
        &reasons,
    )?;
    if &rebuilt_report != state_report {
        bail!("filesystem state report does not independently recompute");
    }
    Ok(())
}

fn recorder_drains_complete(report: &DeploymentObservationReport) -> bool {
    report.cgroup_outcomes.iter().all(|outcome| {
        outcome.finalization_error.is_none()
            && outcome
                .health
                .as_ref()
                .map(|health| health.drain_completed)
                .unwrap_or(false)
    }) && report.lifecycle_outcomes.iter().all(|outcome| {
        outcome.finalization_error.is_none()
            && outcome
                .health
                .as_ref()
                .map(|health| health.drain_completed)
                .unwrap_or(false)
    })
}

fn validate_linux_state_artifacts(
    directory: &Path,
    report: &DeploymentObservationReport,
    artifact_manifest: &ArtifactManifest,
    contract: &DeploymentObserverConfig,
    ready: &ReadyMessage,
    committed: &BTreeMap<&str, &ArtifactDigest>,
) -> Result<()> {
    let configured = contract.linux_state_scope.is_some();
    if report.linux_state.is_some() != configured {
        bail!("Linux state report presence differs from the external configuration");
    }
    let Some(state_report) = &report.linux_state else {
        if artifact_manifest.linux_state_scope_sha256.is_some()
            || artifact_manifest.linux_state_evidence_status.is_some()
            || ready.linux_state_scope_sha256.is_some()
            || ready.linux_state_s0_sha256.is_some()
        {
            bail!("disabled Linux state confirmation carries state evidence bindings");
        }
        return Ok(());
    };
    if artifact_manifest.linux_state_scope_sha256.as_deref()
        != Some(state_report.scope_sha256.as_str())
        || artifact_manifest.linux_state_evidence_status != Some(state_report.evidence_status)
        || ready.linux_state_scope_sha256.as_deref() != Some(state_report.scope_sha256.as_str())
        || ready.linux_state_s0_sha256.as_deref() != Some(state_report.s0_snapshot_sha256.as_str())
    {
        bail!("Linux state READY/report/artifact-manifest bindings disagree");
    }
    let s0_digest = committed
        .get(LINUX_STATE_S0_FILE)
        .context("artifact manifest has no Linux state S0")?;
    let s1_digest = committed
        .get(LINUX_STATE_S1_FILE)
        .context("artifact manifest has no Linux state S1")?;
    let comparison_digest = committed
        .get(LINUX_STATE_COMPARISON_FILE)
        .context("artifact manifest has no Linux state comparison")?;
    if s0_digest.sha256 != state_report.s0_snapshot_sha256
        || s1_digest.sha256 != state_report.s1_snapshot_sha256
        || comparison_digest.sha256 != state_report.comparison_sha256
    {
        bail!("Linux state report digests differ from the artifact manifest");
    }

    let s0: StateSnapshot = read_json(
        &directory.join(LINUX_STATE_S0_FILE),
        HARD_MAX_SNAPSHOT_JSON_BYTES + 1,
    )?;
    let s1: StateSnapshot = read_json(
        &directory.join(LINUX_STATE_S1_FILE),
        HARD_MAX_SNAPSHOT_JSON_BYTES + 1,
    )?;
    let committed_comparison: StateComparison = read_json(
        &directory.join(LINUX_STATE_COMPARISON_FILE),
        HARD_MAX_COMPARISON_JSON_BYTES + 1,
    )?;
    let bound = bind_linux_state_scope(contract.linux_state_scope.as_ref(), &report.deployment)?
        .context("enabled Linux state configuration produced no bound scope")?;
    if s0.scope != bound.scope
        || s1.scope != bound.scope
        || s0.scope_sha256 != state_report.scope_sha256
        || s1.scope_sha256 != state_report.scope_sha256
        || s0.snapshot_id != format!("{}:linux-state:s0", report.run_id)
        || s1.snapshot_id != format!("{}:linux-state:s1", report.run_id)
    {
        bail!("Linux state snapshots are not bound to the effective deployment scope/run");
    }
    let rebuilt_comparison = compare_linux_state(&s0, &s1)?;
    if committed_comparison != rebuilt_comparison {
        bail!("Linux state comparison artifact is not the independent S0/S1 comparison");
    }
    let drains_complete = report.cgroup_outcomes.iter().all(|outcome| {
        outcome
            .health
            .as_ref()
            .map(|health| health.drain_completed)
            .unwrap_or(false)
    }) && report.lifecycle_outcomes.iter().all(|outcome| {
        outcome
            .health
            .as_ref()
            .map(|health| health.drain_completed)
            .unwrap_or(false)
    });
    let mut namespace_reasons = retained_namespace_contract_reasons(&bound, &s0);
    namespace_reasons.extend(retained_namespace_contract_reasons(&bound, &s1));
    namespace_reasons.extend(bound.forced_incomplete_reasons.iter().cloned());
    namespace_reasons.sort();
    namespace_reasons.dedup();
    let contract_reasons = confirmation_contract_reasons(
        &namespace_reasons,
        &report.deployment.boot_id,
        &s0,
        &s1,
        report.pre_finish_barrier.all_roots_frozen && report.pre_finish_validation.stable,
        report.closure_barrier.all_roots_frozen
            && report.closure_validation.stable
            && report.pre_finish_barrier.all_roots_frozen
            && report.pre_finish_validation.stable,
        drains_complete,
    );
    let rebuilt_report = LinuxStateReport::from_comparison(
        &rebuilt_comparison,
        s0_digest.sha256.clone(),
        s1_digest.sha256.clone(),
        comparison_digest.sha256.clone(),
        &contract_reasons,
    )?;
    if &rebuilt_report != state_report {
        bail!("Linux state report/domain vector does not independently recompute");
    }
    Ok(())
}

fn validate_lifecycle_streams(
    report: &DeploymentObservationReport,
    wal: &[bpf_observer_system_effects::lifecycle::KernelProcessLifecycleEvent],
    json: &[ProcessLifecycleEvent],
) -> Result<()> {
    if wal.len() != json.len() {
        bail!("process-lifecycle WAL and JSONL contain different event counts");
    }
    let allowed = report
        .registration_cgroup_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut counts = BTreeMap::<u64, u64>::new();
    let mut verifiers = BTreeMap::new();
    let mut replay_failed = BTreeSet::new();
    for cgroup_id in &report.registration_cgroup_ids {
        verifiers.insert(
            *cgroup_id,
            ProcessLineageVerifier::new(report.epoch, *cgroup_id)?,
        );
    }
    for (raw, decoded) in wal.iter().zip(json) {
        raw.validate()?;
        decoded.validate()?;
        if raw.run_epoch != report.epoch || !allowed.contains(&raw.cgroup_id) {
            bail!("process-lifecycle WAL event is outside the registration plan");
        }
        let projected = raw.to_event_with_cgroup_match(
            &report.run_id,
            &report.deployment.boot_id,
            CgroupMatchMode::AncestorRoot,
        )?;
        if decoded != &projected || serde_json::to_vec(&projected)? != serde_json::to_vec(decoded)?
        {
            bail!("process-lifecycle JSONL is not the canonical WAL projection");
        }
        *counts.entry(raw.cgroup_id).or_default() += 1;
        if !replay_failed.contains(&raw.cgroup_id)
            && verifiers
                .get_mut(&raw.cgroup_id)
                .context("missing lifecycle replay verifier")?
                .ingest(raw)
                .is_err()
        {
            replay_failed.insert(raw.cgroup_id);
        }
    }
    for outcome in &report.lifecycle_outcomes {
        let Some(health) = &outcome.health else {
            continue;
        };
        if counts.get(&outcome.cgroup_id).copied().unwrap_or(0) != health.events_persisted
            || health.event_published != health.events_persisted
        {
            bail!("lifecycle WAL count disagrees with per-cgroup health");
        }
        health
            .validate_partial_enrollment_contract()
            .with_context(|| {
                format!(
                    "cgroup {} lifecycle health violates the partial-enrollment contract",
                    outcome.cgroup_id
                )
            })?;
        if health.status == ProcessLifecycleStatus::Complete
            || !health
                .limitations
                .iter()
                .any(|limitation| limitation == PROCESS_LIFECYCLE_ENROLLMENT_LIMITATION)
        {
            bail!("lifecycle health overclaims unsupported whole-tree enrollment");
        }
        if replay_failed.contains(&outcome.cgroup_id) {
            if health.lineage.is_some() || health.status != ProcessLifecycleStatus::Incomplete {
                bail!("lifecycle health hides an offline lineage replay failure");
            }
            continue;
        }
        let lineage = verifiers
            .get(&outcome.cgroup_id)
            .context("missing lifecycle verifier at finalization")?
            .finish(health.event_published, health.event_dropped);
        match (lineage, &health.lineage) {
            (Ok(rebuilt), Some(committed)) if &rebuilt == committed => {}
            (Err(_), None) if health.status == ProcessLifecycleStatus::Incomplete => {}
            _ => bail!("lifecycle lineage does not independently replay from the WAL"),
        }
    }
    if report.aggregate_lifecycle_health.events_persisted != wal.len() as u64 {
        bail!("lifecycle WAL count disagrees with aggregate health");
    }
    Ok(())
}

fn read_lifecycle_jsonl(path: &Path) -> Result<Vec<ProcessLifecycleEvent>> {
    read_bounded_jsonl(path, "process-lifecycle")
}

fn read_bounded_jsonl<T: DeserializeOwned + Serialize>(path: &Path, label: &str) -> Result<Vec<T>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.len() > MAX_COMMITTED_ARTIFACT_BYTES
    {
        bail!("{label} JSONL is not a bounded singly-linked regular file");
    }
    let mut reader = BufReader::new(file);
    let mut events = Vec::new();
    let mut bytes_read = 0_u64;
    loop {
        let Some(line) = read_bounded_line(&mut reader)? else {
            break;
        };
        bytes_read = bytes_read
            .checked_add(line.len() as u64 + 1)
            .context("JSONL byte count overflow")?;
        let event: T =
            serde_json::from_slice(&line).with_context(|| format!("parse {label} JSONL event"))?;
        if serde_json::to_vec(&event)? != line {
            bail!("{label} JSONL event is not canonical recorder JSON");
        }
        events.push(event);
        if events.len() > MAX_EVENTS {
            bail!("{label} JSONL exceeds the recorder event-count bound");
        }
    }
    let after = reader.get_ref().metadata()?;
    if bytes_read != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        bail!("{label} JSONL changed while it was verified");
    }
    Ok(events)
}

fn read_bounded_line<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            bail!("JSONL has a truncated final line");
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|index| index + 1)
            .unwrap_or(available.len());
        if line.len().saturating_add(take) > MAX_EVENT_LINE_BYTES {
            bail!("JSONL line exceeds {MAX_EVENT_LINE_BYTES} bytes");
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if line.last() == Some(&b'\n') {
            line.pop();
            if line.is_empty() {
                bail!("JSONL contains an empty line");
            }
            return Ok(Some(line));
        }
    }
}

fn read_json<T: DeserializeOwned>(path: &Path, maximum: u64) -> Result<T> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    if !before.file_type().is_file() || before.nlink() != 1 || before.len() > maximum {
        bail!("JSON evidence artifact is not a bounded singly-linked regular file");
    }
    let mut bytes = Vec::new();
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        bail!("JSON evidence artifact exceeds verification bound");
    }
    let after = file.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        bail!("JSON evidence artifact changed while reading");
    }
    serde_json::from_slice(&bytes).context("parse JSON evidence artifact")
}

fn digest_file(path: &Path, relative_path: &str) -> Result<ArtifactDigest> {
    use sha2::{Digest, Sha256};
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    if !before.file_type().is_file() || before.nlink() != 1 {
        bail!("artifact {relative_path} is not a singly-linked regular file");
    }
    if before.len() > MAX_COMMITTED_ARTIFACT_BYTES {
        bail!("artifact {relative_path} exceeds the verification byte limit");
    }
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .context("artifact size overflow")?;
        hasher.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    if before.len() != bytes
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        bail!("artifact {relative_path} changed while hashing");
    }
    Ok(ArtifactDigest {
        relative_path: relative_path.to_owned(),
        size_bytes: bytes,
        sha256: hex::encode(hasher.finalize()),
    })
}

fn directory_entries(directory: &Path) -> Result<BTreeSet<String>> {
    let mut entries = BTreeSet::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("evidence artifact name is not UTF-8"))?;
        validate_artifact_name(&name)?;
        if !entry.file_type()?.is_file() || !entries.insert(name) {
            bail!("evidence directory contains a non-file or duplicate entry");
        }
    }
    Ok(entries)
}

fn open_directory(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open evidence directory {}", path.display()))
}

fn validate_artifact_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || name.contains('/')
        || name == "."
        || name == ".."
        || name.contains('\0')
        || name.contains('\n')
    {
        bail!("invalid evidence artifact name");
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} SHA-256 is not canonical lowercase hexadecimal");
    }
    Ok(())
}
