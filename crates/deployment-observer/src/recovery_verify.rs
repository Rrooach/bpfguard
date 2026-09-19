// SPDX-License-Identifier: GPL-2.0-only

//! Offline replay of a committed recovery observation.
//!
//! A digest supplied outside the evidence directory is the root of trust.
//! JSON verdicts and pair deltas are never accepted as inputs to the
//! comparison: they are rebuilt from the three raw endpoint snapshots.

use anyhow::{bail, Context, Result};
use bpf_observer_deployment::{
    DeploymentManifest, LiveIdentityValidation, RevalidationPhase, ValidationMismatch,
    DEPLOYMENT_PROTOCOL_VERSION,
};
use bpf_observer_filesystem_confirmer::{
    compare_phases as compare_filesystem_phases, FilesystemSnapshot,
    SnapshotPhase as FilesystemPhase, HARD_MAX_SNAPSHOT_JSON_BYTES as MAX_FS_SNAPSHOT_BYTES,
};
use bpf_observer_linux_state_confirmers::{
    compare_phases as compare_linux_phases, SnapshotPhase as LinuxPhase, StateSnapshot,
    HARD_MAX_SNAPSHOT_JSON_BYTES as MAX_LINUX_SNAPSHOT_BYTES,
};
use bpf_observer_schema::{
    Snapshot as BpfSnapshot, MAX_SNAPSHOT_JSON_BYTES as MAX_BPF_SNAPSHOT_BYTES,
};
use bpf_observer_system_effects::lifecycle::{
    recover_process_lifecycle_wal, ProcessLifecycleEvent, ProcessLifecycleStatus,
    ProcessLineageVerifier, PROCESS_LIFECYCLE_ENROLLMENT_LIMITATION,
};
use bpf_observer_system_effects::socket_state::{
    verify_socket_state_artifacts, SocketStateRunVerification, SocketStateVerificationBinding,
};
use bpf_observer_system_effects::{
    policy_sha256, verify_system_effect_artifacts, CgroupMatchMode, SystemEffectRunVerification,
    SystemEffectVerificationBinding,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::Path;

use crate::barrier::RootFreezeBarrier;
use crate::endpoint_state::{
    bpf_scope_sha256, bpf_snapshot_id, compare_bpf_endpoints_with_phases, filesystem_snapshot_id,
};
use crate::linux_state::bind_linux_state_scope;
use crate::protocol::{
    AgentStartedMessage, ReadyMessage, RecoveryControlCommand, RecoveryProtocolMachine,
    RecoveryProtocolState, RecoveryReadyMessage, RestoreCompleteMessage, SnapshotBMessage,
    SnapshotCMessage, DEPLOYMENT_OBSERVER_PROTOCOL_VERSION,
    DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
};
use crate::recovery::RecoveryEvidence;
use crate::recovery_report::{
    build_recovery_verdict_report_with_raw, RecoveryComparisonSet, RecoveryComparisonTriplet,
    RecoveryConsistencyVerdict, RecoveryDomain, RecoveryPairDelta, RecoveryRawSnapshotSet,
    RecoveryRawSnapshotTriplet, RecoverySnapshotEnvelope, RecoverySnapshotPhase,
    RecoverySnapshotTriplet, RecoveryVerdictReport, SnapshotDomainBinding,
};
use crate::report::{
    checked_artifact_total_bytes, ArtifactDigest, IdentityAssessment, SocketStateHealthArtifact,
};
use crate::scope::CgroupScopeCapability;
use crate::session::{DeploymentObserverConfig, RecoveryRecorderFinalization};

pub const RECOVERY_ARTIFACT_MANIFEST_FILE: &str = "recovery-artifact-manifest.json";
pub const RECOVERY_CONTROL_TRANSCRIPT_FILE: &str = "recovery-control-transcript.json";
pub const RECOVERY_VERDICT_FILE: &str = "recovery-verdict.json";
pub const RECOVERY_SNAPSHOT_A_FILE: &str = "snapshot-a.json";
pub const RECOVERY_SNAPSHOT_B_FILE: &str = "snapshot-b.json";
pub const RECOVERY_SNAPSHOT_C_FILE: &str = "snapshot-c.json";
pub const RECOVERY_AGENT_DELTA_FILE: &str = "agent-delta.json";
pub const RECOVERY_RECOVERY_DELTA_FILE: &str = "recovery-delta.json";
pub const RECOVERY_RESIDUAL_DELTA_FILE: &str = "residual-delta.json";
pub const RECOVERY_EVIDENCE_FILE: &str = "recovery.json";
pub const RECOVERY_RECORDER_HEALTH_FILE: &str = "recovery-recorder-health.json";

const MAX_JSON_BYTES: u64 = 512 * 1024 * 1024;
const MAX_COMMITTED_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ARTIFACTS: usize = 64;
const RECOVERY_VERIFICATION_SCHEMA_VERSION: u32 = 1;
const BASE_ARTIFACTS: &[&str] = &[
    "agent-delta.json",
    "agent-started.json",
    "deployment-manifest.json",
    "observation-contract.json",
    "post-restore-barrier.json",
    "post-restore-validation.json",
    "pre-restore-barrier.json",
    "pre-restore-validation.json",
    "process-lifecycle.jsonl",
    "process-lifecycle.raw.bin",
    "ready-barrier.json",
    "ready-message.json",
    "ready-validation.json",
    "recovery-control-transcript.json",
    "recovery-delta.json",
    "recovery-ready-message.json",
    "recovery-recorder-health.json",
    "recovery-verdict.json",
    "recovery.json",
    "residual-delta.json",
    "snapshot-a.json",
    "snapshot-b.json",
    "snapshot-c.json",
    "system-effects.jsonl",
    "system-effects.raw.bin",
];

/// Canonical closed artifact set for protocol v3. The manifest itself is the
/// only uncommitted file, because it cannot hash itself.
pub fn recovery_committed_artifacts(
    config: &DeploymentObserverConfig,
) -> Result<Vec<&'static str>> {
    config.validate_schema()?;
    if config.protocol_version != DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION
        || config.recovery.is_none()
    {
        bail!("recovery artifact set requires a protocol-v3 recovery config");
    }
    let mut names = BASE_ARTIFACTS.to_vec();
    if config.object_resolution_mode
        == bpf_observer_system_effects::FileObjectResolutionMode::KernelObjectExpandedPartial
    {
        names.extend([
            bpf_observer_system_effects::socket_state::SOCKET_STATE_HEALTH_NAME,
            bpf_observer_system_effects::socket_state::SOCKET_STATE_JSONL_NAME,
            bpf_observer_system_effects::socket_state::SOCKET_STATE_WAL_NAME,
        ]);
    }
    if config.bpf_state_scope.is_some() {
        names.extend(["bpf-state-s0.json", "bpf-state-b.json", "bpf-state-c.json"]);
    }
    if config.filesystem_state_scope.is_some() {
        names.extend([
            "filesystem-state-s0.json",
            "filesystem-state-b.json",
            "filesystem-state-c.json",
        ]);
    }
    if config.linux_state_scope.is_some() {
        names.extend([
            "linux-state-s0.json",
            "linux-state-b.json",
            "linux-state-c.json",
        ]);
    }
    names.sort_unstable();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        bail!("recovery artifact set contains a duplicate name");
    }
    Ok(names)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryArtifactManifest {
    pub protocol_version: u32,
    pub run_id: String,
    pub epoch: u64,
    pub checkpoint_id: String,
    pub recovery_id: String,
    pub deployment_scope_sha256: String,
    pub recovery_config_sha256: String,
    pub recovery_verdict_sha256: String,
    pub snapshot_a_sha256: String,
    pub snapshot_b_sha256: String,
    pub snapshot_c_sha256: String,
    pub committed_artifact_total_bytes: u64,
    pub artifacts: Vec<ArtifactDigest>,
}

impl RecoveryArtifactManifest {
    pub fn validate(&self, config: &DeploymentObserverConfig) -> Result<()> {
        let recovery = config
            .recovery
            .as_ref()
            .context("missing recovery config")?;
        if self.protocol_version != DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION
            || self.run_id != config.run_id
            || self.epoch != config.epoch
            || self.checkpoint_id != recovery.checkpoint_id
            || self.recovery_id != recovery.recovery_id
        {
            bail!("recovery artifact manifest is not bound to external run/config identity");
        }
        for (label, value) in [
            ("deployment scope", &self.deployment_scope_sha256),
            ("recovery config", &self.recovery_config_sha256),
            ("recovery verdict", &self.recovery_verdict_sha256),
            ("snapshot A", &self.snapshot_a_sha256),
            ("snapshot B", &self.snapshot_b_sha256),
            ("snapshot C", &self.snapshot_c_sha256),
        ] {
            validate_sha256(value, label)?;
        }
        if self.recovery_config_sha256 != sha256_json(recovery)? {
            bail!("recovery config digest does not recompute from external expectation");
        }
        if self.artifacts.len() > MAX_ARTIFACTS {
            bail!("recovery artifact count exceeds hard bound");
        }
        let expected = recovery_committed_artifacts(config)?;
        let actual = self
            .artifacts
            .iter()
            .map(|artifact| artifact.relative_path.as_str())
            .collect::<Vec<_>>();
        if actual != expected {
            bail!("recovery artifact manifest does not list the exact canonical closed set");
        }
        for artifact in &self.artifacts {
            validate_name(&artifact.relative_path)?;
            validate_sha256(&artifact.sha256, &artifact.relative_path)?;
            if artifact.size_bytes > MAX_COMMITTED_ARTIFACT_BYTES {
                bail!("committed recovery artifact exceeds size bound");
            }
        }
        if checked_artifact_total_bytes(&self.artifacts)? != self.committed_artifact_total_bytes {
            bail!("recovery artifact committed byte total does not recompute");
        }
        let digest = |name: &str| {
            self.artifacts
                .iter()
                .find(|artifact| artifact.relative_path == name)
                .map(|artifact| artifact.sha256.as_str())
        };
        for (name, expected_digest) in [
            (RECOVERY_VERDICT_FILE, &self.recovery_verdict_sha256),
            (RECOVERY_SNAPSHOT_A_FILE, &self.snapshot_a_sha256),
            (RECOVERY_SNAPSHOT_B_FILE, &self.snapshot_b_sha256),
            (RECOVERY_SNAPSHOT_C_FILE, &self.snapshot_c_sha256),
        ] {
            if digest(name) != Some(expected_digest.as_str()) {
                bail!("recovery manifest top-level digest differs from artifact entry");
            }
        }
        Ok(())
    }

    fn artifact(&self, name: &str) -> Result<&ArtifactDigest> {
        self.artifacts
            .iter()
            .find(|artifact| artifact.relative_path == name)
            .with_context(|| format!("recovery manifest lacks {name}"))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryVerificationExpectation {
    pub expected_config: DeploymentObserverConfig,
    pub expected_artifact_manifest_sha256: String,
    pub expected_recovery_verdict_sha256: String,
}

impl RecoveryVerificationExpectation {
    pub fn validate(&self) -> Result<()> {
        self.expected_config.validate_schema()?;
        if self.expected_config.protocol_version != DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION
            || self.expected_config.recovery.is_none()
        {
            bail!("offline recovery verification requires a v3 recovery config");
        }
        validate_sha256(
            &self.expected_artifact_manifest_sha256,
            "external recovery manifest",
        )?;
        validate_sha256(
            &self.expected_recovery_verdict_sha256,
            "external recovery verdict",
        )
    }
}

/// Transcript entries are typed, fixed, and replayed through the v3 state
/// machine. It intentionally excludes FINISHED: that message commits the
/// manifest digest and would create a self-reference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryControlTranscript {
    pub schema_version: u32,
    pub ready: RecoveryReadyMessage,
    pub agent_started_command: RecoveryControlCommand,
    pub agent_started: AgentStartedMessage,
    pub pre_restore_command: RecoveryControlCommand,
    pub snapshot_b: SnapshotBMessage,
    pub restore_complete: RestoreCompleteMessage,
    pub snapshot_c: SnapshotCMessage,
    pub finish_command: RecoveryControlCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryOfflineVerification {
    pub schema_version: u32,
    pub protocol_version: u32,
    pub verified: bool,
    pub run_id: String,
    pub epoch: u64,
    pub checkpoint_id: String,
    pub recovery_id: String,
    pub artifact_count: u64,
    pub committed_artifact_total_bytes: u64,
    pub verdict: RecoveryConsistencyVerdict,
    /// Verifies A/B/C state and the protocol transcript; recorder WAL replay
    /// is reported separately and must never be inferred from this flag.
    pub endpoint_replay_verified: bool,
    pub recorder_wal_replay_verified: bool,
}

pub fn verify_recovery_artifacts(
    directory: &Path,
    expectation: &RecoveryVerificationExpectation,
) -> Result<RecoveryOfflineVerification> {
    expectation.validate()?;
    let dir = open_directory(directory)?;
    let before_dir = dir.metadata()?;
    let expected_names = recovery_committed_artifacts(&expectation.expected_config)?
        .into_iter()
        .map(str::to_owned)
        .chain(std::iter::once(RECOVERY_ARTIFACT_MANIFEST_FILE.to_owned()))
        .collect::<BTreeSet<_>>();
    if directory_entries(&dir)? != expected_names {
        bail!("recovery evidence directory has a missing or uncommitted artifact");
    }

    let manifest_digest = digest_file(&dir, RECOVERY_ARTIFACT_MANIFEST_FILE)?;
    if manifest_digest.sha256 != expectation.expected_artifact_manifest_sha256 {
        bail!("recovery manifest digest differs from the external expectation");
    }
    let manifest: RecoveryArtifactManifest = read_json_with_digest(
        &dir,
        RECOVERY_ARTIFACT_MANIFEST_FILE,
        MAX_JSON_BYTES,
        &expectation.expected_artifact_manifest_sha256,
    )?;
    manifest.validate(&expectation.expected_config)?;
    if manifest.recovery_verdict_sha256 != expectation.expected_recovery_verdict_sha256 {
        bail!("recovery verdict digest differs from the external expectation");
    }
    for committed in &manifest.artifacts {
        if &digest_file(&dir, &committed.relative_path)? != committed {
            bail!("committed recovery artifact digest differs from manifest");
        }
    }
    let config: DeploymentObserverConfig =
        read_committed_json(&dir, &manifest, "observation-contract.json", MAX_JSON_BYTES)?;
    if config != expectation.expected_config {
        bail!("embedded recovery config differs from external expectation");
    }
    let deployment: DeploymentManifest =
        read_committed_json(&dir, &manifest, "deployment-manifest.json", MAX_JSON_BYTES)?;
    deployment.validate()?;
    if deployment.scope_sha256 != manifest.deployment_scope_sha256 {
        bail!("deployment manifest scope differs from recovery artifact manifest");
    }

    let a: RecoverySnapshotEnvelope =
        read_committed_json(&dir, &manifest, RECOVERY_SNAPSHOT_A_FILE, MAX_JSON_BYTES)?;
    let b: RecoverySnapshotEnvelope =
        read_committed_json(&dir, &manifest, RECOVERY_SNAPSHOT_B_FILE, MAX_JSON_BYTES)?;
    let c: RecoverySnapshotEnvelope =
        read_committed_json(&dir, &manifest, RECOVERY_SNAPSHOT_C_FILE, MAX_JSON_BYTES)?;
    validate_envelopes(&dir, &manifest, &deployment, &config, [&a, &b, &c])?;
    let recovery: RecoveryEvidence =
        read_committed_json(&dir, &manifest, RECOVERY_EVIDENCE_FILE, MAX_JSON_BYTES)?;
    validate_recovery_evidence(
        &dir,
        &manifest,
        &recovery,
        &config,
        &deployment,
        [&a, &b, &c],
    )?;

    let recorder_health: RecoveryRecorderFinalization = read_committed_json(
        &dir,
        &manifest,
        RECOVERY_RECORDER_HEALTH_FILE,
        MAX_JSON_BYTES,
    )?;
    validate_recorder_health(&recorder_health, &config, &deployment)?;
    verify_recorder_wals(&dir, &manifest, &config, &deployment, &recorder_health)?;
    let external_reasons =
        external_incompleteness_reasons(&dir, &manifest, &deployment, &recovery, &recorder_health)?;

    let transcript: RecoveryControlTranscript = read_committed_json(
        &dir,
        &manifest,
        RECOVERY_CONTROL_TRANSCRIPT_FILE,
        MAX_JSON_BYTES,
    )?;
    validate_transcript(&dir, &manifest, &config, &deployment, &transcript)?;

    let bpf = read_bpf_triplet(&dir, &manifest, &config, [&a, &b, &c])?;
    let filesystem = read_filesystem_triplet(&dir, &manifest, &config, [&a, &b, &c])?;
    let linux = read_linux_triplet(&dir, &manifest, &deployment, &config, [&a, &b, &c])?;

    let bpf_comparisons = if let Some([before, middle, after]) = bpf.as_ref() {
        Some([
            compare_bpf_endpoints_with_phases(before, middle, "S0", "B")?,
            compare_bpf_endpoints_with_phases(middle, after, "B", "C")?,
            compare_bpf_endpoints_with_phases(before, after, "S0", "C")?,
        ])
    } else {
        None
    };
    let filesystem_comparisons = if let Some([before, middle, after]) = filesystem.as_ref() {
        Some([
            compare_filesystem_phases(
                before,
                middle,
                FilesystemPhase::S0,
                FilesystemPhase::B,
                None,
            )?,
            compare_filesystem_phases(middle, after, FilesystemPhase::B, FilesystemPhase::C, None)?,
            compare_filesystem_phases(
                before,
                after,
                FilesystemPhase::S0,
                FilesystemPhase::C,
                None,
            )?,
        ])
    } else {
        None
    };
    let linux_comparisons = if let Some([before, middle, after]) = linux.as_ref() {
        Some([
            compare_linux_phases(before, middle, LinuxPhase::S0, LinuxPhase::B)?,
            compare_linux_phases(middle, after, LinuxPhase::B, LinuxPhase::C)?,
            compare_linux_phases(before, after, LinuxPhase::S0, LinuxPhase::C)?,
        ])
    } else {
        None
    };
    let comparison_set = |index: usize| RecoveryComparisonSet {
        bpf: bpf_comparisons.as_ref().map(|values| &values[index]),
        filesystem: filesystem_comparisons.as_ref().map(|values| &values[index]),
        linux: linux_comparisons.as_ref().map(|values| &values[index]),
    };
    let raw_set = |index: usize| RecoveryRawSnapshotSet {
        bpf: bpf.as_ref().map(|values| &values[index]),
        filesystem: filesystem.as_ref().map(|values| &values[index]),
        linux: linux.as_ref().map(|values| &values[index]),
    };
    let rebuilt_verdict = build_recovery_verdict_report_with_raw(
        RecoverySnapshotTriplet {
            a: &a,
            b: &b,
            c: &c,
        },
        RecoveryRawSnapshotTriplet {
            a: raw_set(0),
            b: raw_set(1),
            c: raw_set(2),
        },
        RecoveryComparisonTriplet {
            agent: comparison_set(0),
            recovery: comparison_set(1),
            residual: comparison_set(2),
        },
        &external_reasons,
    )?;
    for (name, rebuilt) in [
        (RECOVERY_AGENT_DELTA_FILE, &rebuilt_verdict.agent_delta),
        (
            RECOVERY_RECOVERY_DELTA_FILE,
            &rebuilt_verdict.recovery_delta,
        ),
        (
            RECOVERY_RESIDUAL_DELTA_FILE,
            &rebuilt_verdict.residual_delta,
        ),
    ] {
        let recorded: RecoveryPairDelta =
            read_committed_json(&dir, &manifest, name, MAX_JSON_BYTES)?;
        if &recorded != rebuilt {
            bail!("{name} does not independently recompute from raw A/B/C snapshots");
        }
    }
    let recorded_verdict: RecoveryVerdictReport =
        read_committed_json(&dir, &manifest, RECOVERY_VERDICT_FILE, MAX_JSON_BYTES)?;
    recorded_verdict.validate()?;
    if recorded_verdict != rebuilt_verdict {
        bail!("recovery verdict does not independently recompute");
    }

    let after_dir = dir.metadata()?;
    if !same_metadata(&before_dir, &after_dir) || directory_entries(&dir)? != expected_names {
        bail!("recovery evidence directory changed during verification");
    }
    Ok(RecoveryOfflineVerification {
        schema_version: RECOVERY_VERIFICATION_SCHEMA_VERSION,
        protocol_version: DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
        verified: true,
        run_id: config.run_id,
        epoch: config.epoch,
        checkpoint_id: recovery.checkpoint_id,
        recovery_id: recovery.recovery_id,
        artifact_count: manifest.artifacts.len() as u64,
        committed_artifact_total_bytes: manifest.committed_artifact_total_bytes,
        verdict: rebuilt_verdict.verdict,
        endpoint_replay_verified: true,
        recorder_wal_replay_verified: true,
    })
}

fn validate_envelopes(
    dir: &File,
    manifest: &RecoveryArtifactManifest,
    deployment: &DeploymentManifest,
    config: &DeploymentObserverConfig,
    envelopes: [&RecoverySnapshotEnvelope; 3],
) -> Result<()> {
    let recovery = config
        .recovery
        .as_ref()
        .context("missing recovery config")?;
    let mut root_ids = deployment.registration_root_cgroup_ids();
    root_ids.sort_unstable();
    root_ids.dedup();
    let capability = CgroupScopeCapability::for_roots(&root_ids)?;
    for (index, envelope) in envelopes.iter().enumerate() {
        envelope.validate()?;
        let phase = [
            RecoverySnapshotPhase::A,
            RecoverySnapshotPhase::B,
            RecoverySnapshotPhase::C,
        ][index];
        let envelope_name = [
            RECOVERY_SNAPSHOT_A_FILE,
            RECOVERY_SNAPSHOT_B_FILE,
            RECOVERY_SNAPSHOT_C_FILE,
        ][index];
        if envelope.phase != phase
            || envelope.run_id != config.run_id
            || envelope.epoch != config.epoch
            || envelope.checkpoint_id != recovery.checkpoint_id
            || envelope.recovery_id != recovery.recovery_id
            || envelope.boot_id != deployment.boot_id
            || envelope.deployment_scope_sha256 != deployment.scope_sha256
            || envelope.cgroup_scope_capability != capability
            || envelope.bpf.is_some() != config.bpf_state_scope.is_some()
            || envelope.filesystem.is_some() != config.filesystem_state_scope.is_some()
            || envelope.linux.is_some() != config.linux_state_scope.is_some()
        {
            bail!("recovery snapshot envelope differs from external scope or phase");
        }
        if envelope.sha256()? != manifest.artifact(envelope_name)?.sha256 {
            bail!("recovery snapshot envelope semantic SHA differs from committed file");
        }
        let expected_id = recovery_snapshot_id(config, phase)?;
        if envelope.snapshot_id != expected_id {
            bail!("recovery envelope snapshot ID does not derive from run/checkpoint/phase");
        }
        let expected = RecoverySnapshotEnvelope::from_deployment_manifest(
            phase,
            config.run_id.clone(),
            config.epoch,
            recovery.checkpoint_id.clone(),
            recovery.recovery_id.clone(),
            envelope.snapshot_id.clone(),
            envelope.capture_started_unix_ns,
            envelope.capture_completed_unix_ns,
            deployment,
            capability.clone(),
            envelope.barrier_sha256.clone(),
            envelope.identity_assessment_sha256.clone(),
            envelope.bpf.clone(),
            envelope.filesystem.clone(),
            envelope.linux.clone(),
        )?;
        if **envelope != expected {
            bail!("recovery snapshot envelope cgroup/namespace binding does not rebuild");
        }
        let (barrier_name, identity_name) = match phase {
            RecoverySnapshotPhase::A => ("ready-barrier.json", "ready-validation.json"),
            RecoverySnapshotPhase::B => ("pre-restore-barrier.json", "pre-restore-validation.json"),
            RecoverySnapshotPhase::C => {
                ("post-restore-barrier.json", "post-restore-validation.json")
            }
        };
        if envelope.barrier_sha256 != manifest.artifact(barrier_name)?.sha256
            || envelope.identity_assessment_sha256 != manifest.artifact(identity_name)?.sha256
        {
            bail!("recovery snapshot barrier/identity evidence is not committed");
        }
        // Read both now, so malformed but correctly hashed barriers cannot
        // become an apparently complete phase.
        let barrier: RootFreezeBarrier =
            read_committed_json(dir, manifest, barrier_name, MAX_JSON_BYTES)?;
        validate_phase_barrier(&barrier, deployment)?;
        if phase == RecoverySnapshotPhase::A && !barrier.all_roots_frozen {
            bail!("READY snapshot A lacks a complete frozen-root barrier");
        }
        if phase == RecoverySnapshotPhase::A {
            let validation: LiveIdentityValidation =
                read_committed_json(dir, manifest, identity_name, MAX_JSON_BYTES)?;
            if validation.phase != RevalidationPhase::Ready
                || validation.scope_sha256 != deployment.scope_sha256
                || !validation.is_stable()
            {
                bail!("READY identity validation is not stable within the deployment scope");
            }
        } else {
            let assessment: IdentityAssessment =
                read_committed_json(dir, manifest, identity_name, MAX_JSON_BYTES)?;
            validate_identity_assessment(&assessment, deployment)?;
        }
    }
    if envelopes[0].snapshot_id == envelopes[1].snapshot_id
        || envelopes[0].snapshot_id == envelopes[2].snapshot_id
        || envelopes[1].snapshot_id == envelopes[2].snapshot_id
        || !capture_order_is_monotonic(envelopes)
    {
        bail!("A/B/C snapshot IDs or capture time order are invalid");
    }
    Ok(())
}

fn capture_order_is_monotonic(envelopes: [&RecoverySnapshotEnvelope; 3]) -> bool {
    capture_intervals_are_monotonic([
        [
            envelopes[0].capture_started_unix_ns,
            envelopes[0].capture_completed_unix_ns,
        ],
        [
            envelopes[1].capture_started_unix_ns,
            envelopes[1].capture_completed_unix_ns,
        ],
        [
            envelopes[2].capture_started_unix_ns,
            envelopes[2].capture_completed_unix_ns,
        ],
    ])
}

fn capture_intervals_are_monotonic(intervals: [[u128; 2]; 3]) -> bool {
    intervals[0][0] > 0
        && intervals[0][0] <= intervals[0][1]
        && intervals[0][1] <= intervals[1][0]
        && intervals[1][0] <= intervals[1][1]
        && intervals[1][1] <= intervals[2][0]
        && intervals[2][0] <= intervals[2][1]
}

fn validate_phase_barrier(
    barrier: &RootFreezeBarrier,
    deployment: &DeploymentManifest,
) -> Result<()> {
    if barrier.checked_unix_ns == 0
        || barrier.method != "CGROUP_V2_ROOT_SUBTREE_FREEZE"
        || barrier.roots.len() != deployment.root_cgroups.len()
    {
        bail!("recovery freeze barrier has an invalid envelope");
    }
    for (observed, expected) in barrier.roots.iter().zip(&deployment.root_cgroups) {
        if observed.path != expected.path || observed.expected_cgroup_id != expected.cgroup_id {
            bail!("recovery freeze barrier is bound to another cgroup");
        }
        let recomputed = observed.observed_cgroup_id == Some(expected.cgroup_id)
            && observed.freeze_requested == Some(true)
            && observed.frozen == Some(true);
        if observed.verified != recomputed {
            bail!("recovery freeze root verdict does not recompute");
        }
    }
    if barrier.all_roots_frozen != barrier.roots.iter().all(|root| root.verified) {
        bail!("recovery freeze aggregate verdict does not recompute");
    }
    Ok(())
}

fn validate_identity_assessment(
    assessment: &IdentityAssessment,
    deployment: &DeploymentManifest,
) -> Result<()> {
    match (&assessment.validation, &assessment.error) {
        (Some(validation), None)
            if validation.phase == RevalidationPhase::Closure
                && validation.scope_sha256 == deployment.scope_sha256
                && assessment.stable == recovery_boundary_identity_stable(validation) =>
        {
            Ok(())
        }
        (None, Some(error)) if !assessment.stable && !error.is_empty() => Ok(()),
        _ => bail!("recovery identity assessment has inconsistent scope/result"),
    }
}

/// A running Agent may leave newly forked descendants in its own frozen
/// cgroup. This does not replace the committed deployment identity. Every
/// other mismatch, including an unexpected process removal, still fails.
fn recovery_boundary_identity_stable(validation: &LiveIdentityValidation) -> bool {
    if validation.protocol_version != DEPLOYMENT_PROTOCOL_VERSION
        || validation.phase != RevalidationPhase::Closure
        || validation.checked_unix_ns == 0
        || validation.stable != validation.mismatches.is_empty()
    {
        return false;
    }
    let mut seen_added = BTreeSet::new();
    validation.mismatches.iter().all(|mismatch| match mismatch {
        ValidationMismatch::ProcessSetChanged {
            added,
            removed_unexpected,
        } => {
            !added.is_empty()
                && removed_unexpected.is_empty()
                && added.iter().all(|pid| *pid != 0 && seen_added.insert(*pid))
                && added.windows(2).all(|pair| pair[0] < pair[1])
        }
        _ => false,
    })
}

fn validate_recovery_evidence(
    dir: &File,
    manifest: &RecoveryArtifactManifest,
    evidence: &RecoveryEvidence,
    config: &DeploymentObserverConfig,
    deployment: &DeploymentManifest,
    snapshots: [&RecoverySnapshotEnvelope; 3],
) -> Result<()> {
    let [a, b, c] = snapshots;
    let expected = config
        .recovery
        .as_ref()
        .context("missing recovery config")?;
    if evidence.schema_version != crate::recovery::RECOVERY_EVIDENCE_SCHEMA_VERSION
        || evidence.mechanism != "DIRECT_EXEC_NO_SHELL"
        || evidence.checkpoint_id != expected.checkpoint_id
        || evidence.recovery_id != expected.recovery_id
        || evidence.executable_path != expected.executable_path
        || evidence.argv != expected.argv
        || evidence.timeout_ms != expected.timeout_ms
        || evidence.max_output_bytes != expected.max_output_bytes
        || evidence.expected_executable_sha256 != expected.expected_sha256
        || evidence.containment_evidence_model
            != "STARTUP_CGROUP_AND_PROCESS_GROUP_ONLY; POST_EXEC_CGROUP_MIGRATION_NOT_EXCLUDED"
    {
        bail!("recovery execution evidence differs from the externally pinned command");
    }
    let forbidden = deployment
        .root_cgroups
        .iter()
        .map(|root| (root.path.as_str(), root.cgroup_id))
        .collect::<Vec<_>>();
    let observed = evidence
        .forbidden_target_cgroups
        .iter()
        .map(|root| (root.cgroup_path.as_str(), root.cgroup_id))
        .collect::<Vec<_>>();
    if observed != forbidden {
        bail!("recovery helper forbidden cgroups differ from deployment roots");
    }
    let outside_at_start = evidence.helper_start_cgroup.as_ref().map(|helper| {
        helper.cgroup_id != 0
            && helper.cgroup_path.starts_with('/')
            && !evidence.forbidden_target_cgroups.iter().any(|root| {
                helper.cgroup_id == root.cgroup_id
                    || helper.cgroup_path == root.cgroup_path
                    || helper
                        .cgroup_path
                        .strip_prefix(&root.cgroup_path)
                        .map_or(false, |suffix| suffix.starts_with('/'))
            })
    });
    if outside_at_start != evidence.helper_outside_forbidden_cgroups_at_start {
        bail!("recovery helper outside-target cgroup assertion does not recompute");
    }
    if evidence.attempt_started_unix_ns < b.capture_completed_unix_ns
        || evidence.attempt_started_unix_ns < a.capture_completed_unix_ns
        || evidence.ended_unix_ns < evidence.attempt_started_unix_ns
        || evidence.ended_unix_ns > c.capture_started_unix_ns
    {
        bail!("recovery execution does not occur strictly between snapshots B and C");
    }
    validate_recovery_environment_evidence(dir, manifest, evidence, deployment, b, c)?;
    if let Some(started) = evidence.command_started_unix_ns {
        if started < evidence.attempt_started_unix_ns || started > evidence.ended_unix_ns {
            bail!("recovery helper start timestamp lies outside the attempt interval");
        }
    }
    for digest in evidence
        .executable_sha256_before
        .iter()
        .chain(evidence.executable_sha256_after.iter())
        .chain([&evidence.stdout.sha256, &evidence.stderr.sha256])
    {
        validate_sha256(digest, "recovery execution")?;
    }
    if let Some(stable) = evidence.executable_identity_stable {
        let independently_stable = evidence.executable_identity_before.is_some()
            && evidence.executable_identity_before == evidence.executable_identity_after
            && evidence.executable_sha256_before.as_deref()
                == Some(expected.expected_sha256.as_str())
            && evidence.executable_sha256_before == evidence.executable_sha256_after;
        if stable != independently_stable {
            bail!("recovery executable identity stability assertion does not recompute");
        }
    }
    for stream in [&evidence.stdout, &evidence.stderr] {
        let prefix = hex::decode(&stream.captured_prefix_bytes_hex)
            .context("recovery output prefix is not valid lowercase hexadecimal")?;
        if hex::encode(&prefix) != stream.captured_prefix_bytes_hex
            || stream.captured_bytes != prefix.len() as u64
            || stream.captured_bytes > expected.max_output_bytes
            || stream.observed_bytes < stream.captured_bytes
            || stream.truncated
                != (stream.observed_bytes > stream.captured_bytes || !stream.stream_closed)
        {
            bail!("recovery output capture counters/prefix are inconsistent");
        }
        if stream.stream_closed
            && !stream.truncated
            && hex::encode(Sha256::digest(&prefix)) != stream.sha256
        {
            bail!("complete recovery output digest does not match captured bytes");
        }
    }
    let independently_successful = evidence.command_started_unix_ns.is_some()
        && evidence.exit_code == Some(0)
        && evidence.termination_signal.is_none()
        && !evidence.timed_out
        && evidence.helper_outside_forbidden_cgroups_at_start == Some(true)
        && evidence.process_group_empty_after_wait == Some(true)
        && evidence.executable_identity_stable == Some(true)
        && evidence.stdout.stream_closed
        && evidence.stderr.stream_closed
        && evidence.error_reason.is_none()
        && evidence.executable_sha256_before.as_deref() == Some(expected.expected_sha256.as_str())
        && evidence.executable_sha256_after.as_deref() == Some(expected.expected_sha256.as_str());
    if evidence.success != independently_successful {
        bail!("recovery success flag does not independently recompute");
    }
    Ok(())
}

fn validate_recovery_environment_evidence(
    dir: &File,
    manifest: &RecoveryArtifactManifest,
    evidence: &RecoveryEvidence,
    deployment: &DeploymentManifest,
    b: &RecoverySnapshotEnvelope,
    c: &RecoverySnapshotEnvelope,
) -> Result<()> {
    let before = evidence
        .before_environment
        .as_ref()
        .context("committed v3 recovery evidence lacks before_environment")?;
    let after = evidence
        .after_environment
        .as_ref()
        .context("committed v3 recovery evidence lacks after_environment")?;
    let committed_before_barrier: RootFreezeBarrier =
        read_committed_json(dir, manifest, "pre-restore-barrier.json", MAX_JSON_BYTES)?;
    let committed_before_identity: IdentityAssessment =
        read_committed_json(dir, manifest, "pre-restore-validation.json", MAX_JSON_BYTES)?;
    if before.boot_id != deployment.boot_id
        || before.boot_id != b.boot_id
        || before.barrier != committed_before_barrier
        || before.identity_assessment != committed_before_identity
    {
        bail!("before_environment is not exactly the committed B-side environment identity");
    }
    for environment in [before, after] {
        if environment.boot_id != deployment.boot_id || environment.boot_id != c.boot_id {
            bail!("recovery environment boot identity differs from A/B/C scope");
        }
        validate_phase_barrier(&environment.barrier, deployment)?;
        validate_identity_assessment(&environment.identity_assessment, deployment)?;
        if !environment.barrier.all_roots_frozen || !environment.identity_assessment.stable {
            bail!("committed recovery environment is not frozen and identity-stable");
        }
    }
    let before_identity_checked = before
        .identity_assessment
        .validation
        .as_ref()
        .context("before_environment lacks a successful identity validation")?
        .checked_unix_ns;
    let after_identity_checked = after
        .identity_assessment
        .validation
        .as_ref()
        .context("after_environment lacks a successful identity validation")?
        .checked_unix_ns;
    if !recovery_environment_times_are_ordered(
        b.capture_completed_unix_ns,
        [before.barrier.checked_unix_ns, before_identity_checked],
        evidence.attempt_started_unix_ns,
        evidence.ended_unix_ns,
        [after.barrier.checked_unix_ns, after_identity_checked],
        c.capture_started_unix_ns,
    ) {
        bail!("recovery environment identities are not ordered B-before-helper-after-C");
    }
    Ok(())
}

fn recovery_environment_times_are_ordered(
    b_completed: u128,
    before_checks: [u128; 2],
    attempt_started: u128,
    helper_ended: u128,
    after_checks: [u128; 2],
    c_started: u128,
) -> bool {
    b_completed > 0
        && b_completed <= before_checks[0]
        && b_completed <= before_checks[1]
        && before_checks[0] <= attempt_started
        && before_checks[1] <= attempt_started
        && attempt_started <= helper_ended
        && helper_ended <= after_checks[0]
        && helper_ended <= after_checks[1]
        && after_checks[0] <= c_started
        && after_checks[1] <= c_started
        && after_checks[0] > before_checks[0]
        && after_checks[1] > before_checks[1]
}

fn validate_recorder_health(
    health: &RecoveryRecorderFinalization,
    config: &DeploymentObserverConfig,
    deployment: &DeploymentManifest,
) -> Result<()> {
    let mut expected_ids = deployment.registration_root_cgroup_ids();
    expected_ids.sort_unstable();
    expected_ids.dedup();
    if health.protocol_version != DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION
        || health.run_id != config.run_id
        || health.epoch != config.epoch
        || health.root_cgroup_ids != expected_ids
        || health.system_effects.len() != expected_ids.len()
        || health.process_lifecycle.len() != expected_ids.len()
    {
        bail!("recovery recorder finalization is not bound to the deployment roots");
    }
    for (expected_id, outcome) in expected_ids.iter().zip(&health.system_effects) {
        if outcome.cgroup_id != *expected_id {
            bail!("system-effect finalization root order is noncanonical");
        }
    }
    for (expected_id, outcome) in expected_ids.iter().zip(&health.process_lifecycle) {
        if outcome.cgroup_id != *expected_id {
            bail!("process-lifecycle finalization root order is noncanonical");
        }
    }
    let mut independently_derived_reasons = Vec::new();
    for outcome in &health.system_effects {
        let healthy = outcome.health.as_ref().map_or(false, |value| {
            value.producer_barrier_complete
                && value.drain_completed
                && value.wal_durable
                && value.event_dropped == 0
                && value.userspace_failures == 0
                && value.fatal_kernel_flags == 0
                && value.pending_remaining == 0
                && value.object_pending_remaining == 0
                && value.reasons.is_empty()
        });
        if !healthy || !outcome.unregistered || outcome.finalization_error.is_some() {
            independently_derived_reasons.push(format!(
                "system-effect recorder cgroup {} did not finalize without loss or error",
                outcome.cgroup_id
            ));
        }
    }
    for outcome in &health.process_lifecycle {
        let healthy = outcome.health.as_ref().map_or(false, |value| {
            value.producer_barrier_complete
                && value.drain_completed
                && value.wal_durable
                && value.event_dropped == 0
                && value.userspace_failures == 0
                && value.reasons.is_empty()
        });
        if !healthy || !outcome.unregistered || outcome.finalization_error.is_some() {
            independently_derived_reasons.push(format!(
                "process-lifecycle recorder cgroup {} did not finalize without loss or error",
                outcome.cgroup_id
            ));
        }
    }
    independently_derived_reasons.sort();
    independently_derived_reasons.dedup();
    if health.reasons != independently_derived_reasons
        || health.complete != independently_derived_reasons.is_empty()
    {
        bail!("recovery recorder completeness/reasons do not independently recompute");
    }
    if health.reasons.len() > 4096
        || health
            .reasons
            .iter()
            .any(|reason| reason.is_empty() || reason.len() > 4096)
    {
        bail!("recorder finalization reasons exceed their bounds");
    }
    Ok(())
}

fn pinned_artifact_path(directory: &File, name: &str) -> Result<std::path::PathBuf> {
    validate_name(name)?;
    Ok(std::path::PathBuf::from(format!(
        "/proc/self/fd/{}/{name}",
        directory.as_raw_fd()
    )))
}

fn verify_recorder_wals(
    dir: &File,
    manifest: &RecoveryArtifactManifest,
    config: &DeploymentObserverConfig,
    deployment: &DeploymentManifest,
    finalization: &RecoveryRecorderFinalization,
) -> Result<()> {
    let system_runs = finalization
        .system_effects
        .iter()
        .map(|outcome| {
            let health = outcome
                .health
                .as_ref()
                .context("cannot strictly replay system-effect WAL without finalized health")?;
            Ok(SystemEffectRunVerification {
                cgroup_id: outcome.cgroup_id,
                run_epoch: config.epoch,
                published: health.event_published,
                dropped: health.event_dropped,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let effects_wal = pinned_artifact_path(dir, "system-effects.raw.bin")?;
    let effects_jsonl = pinned_artifact_path(dir, "system-effects.jsonl")?;
    let system_verified = verify_system_effect_artifacts(
        &effects_wal,
        &effects_jsonl,
        &SystemEffectVerificationBinding {
            run_id: config.run_id.clone(),
            boot_id: deployment.boot_id.clone(),
            profile: config.profile,
            object_resolution_mode: config.object_resolution_mode,
            cgroup_match_mode: CgroupMatchMode::AncestorRoot,
            runs: system_runs,
        },
    )?;
    if !system_verified.jsonl_projection_verified
        || system_verified.policy_sha256 != policy_sha256(config.profile)?
        || system_verified.runs.len() != finalization.system_effects.len()
    {
        bail!("system-effect WAL/JSONL replay does not bind to recovery recorder health");
    }
    for (replayed, outcome) in system_verified
        .runs
        .iter()
        .zip(&finalization.system_effects)
    {
        let health = outcome
            .health
            .as_ref()
            .context("missing system-effect health after replay")?;
        if replayed.cgroup_id != outcome.cgroup_id
            || replayed.run_epoch != config.epoch
            || replayed.published != health.event_published
            || replayed.dropped != health.event_dropped
            || replayed.recovered != health.events_persisted
            || replayed.fatal_correlation_events != health.fatal_kernel_flags
        {
            bail!("system-effect WAL replay differs from per-cgroup health");
        }
    }

    let lifecycle_wal = pinned_artifact_path(dir, "process-lifecycle.raw.bin")?;
    let recovered = recover_process_lifecycle_wal(&lifecycle_wal)?;
    if recovered.truncated_tail {
        bail!("process-lifecycle WAL has a truncated tail");
    }
    let decoded: Vec<ProcessLifecycleEvent> =
        read_committed_jsonl(dir, manifest, "process-lifecycle.jsonl")?;
    if decoded.len() != recovered.events.len() {
        bail!("process-lifecycle WAL and JSONL event counts disagree");
    }
    let mut counts = BTreeMap::<u64, u64>::new();
    let mut verifiers = BTreeMap::new();
    let mut failed = BTreeSet::new();
    for id in &finalization.root_cgroup_ids {
        verifiers.insert(*id, ProcessLineageVerifier::new(config.epoch, *id)?);
    }
    for (raw, json) in recovered.events.iter().zip(&decoded) {
        raw.validate()?;
        json.validate()?;
        if raw.run_epoch != config.epoch
            || !verifiers.contains_key(&raw.cgroup_id)
            || raw.to_event_with_cgroup_match(
                &config.run_id,
                &deployment.boot_id,
                CgroupMatchMode::AncestorRoot,
            )? != *json
        {
            bail!("process-lifecycle JSONL is not a bound projection of the WAL");
        }
        *counts.entry(raw.cgroup_id).or_default() += 1;
        if !failed.contains(&raw.cgroup_id)
            && verifiers
                .get_mut(&raw.cgroup_id)
                .context("missing lifecycle lineage verifier")?
                .ingest(raw)
                .is_err()
        {
            failed.insert(raw.cgroup_id);
        }
    }
    for outcome in &finalization.process_lifecycle {
        let health = outcome
            .health
            .as_ref()
            .context("cannot strictly replay lifecycle WAL without finalized health")?;
        if counts.get(&outcome.cgroup_id).copied().unwrap_or(0) != health.events_persisted
            || health.event_published != health.events_persisted
        {
            bail!("process-lifecycle WAL count differs from per-cgroup health");
        }
        health.validate_partial_enrollment_contract()?;
        if health.status == ProcessLifecycleStatus::Complete
            || !health
                .limitations
                .iter()
                .any(|reason| reason == PROCESS_LIFECYCLE_ENROLLMENT_LIMITATION)
        {
            bail!("process-lifecycle health overclaims whole-tree enrollment");
        }
        if failed.contains(&outcome.cgroup_id) {
            if health.lineage.is_some() || health.status != ProcessLifecycleStatus::Incomplete {
                bail!("process-lifecycle health hides an offline lineage replay failure");
            }
        } else {
            let rebuilt = verifiers
                .get(&outcome.cgroup_id)
                .context("missing lifecycle verifier at finish")?
                .finish(health.event_published, health.event_dropped);
            match (rebuilt, &health.lineage) {
                (Ok(expected), Some(committed)) if &expected == committed => {}
                (Err(_), None) if health.status == ProcessLifecycleStatus::Incomplete => {}
                _ => bail!("lifecycle lineage does not independently replay from the WAL"),
            }
        }
    }

    if config.object_resolution_mode
        == bpf_observer_system_effects::FileObjectResolutionMode::KernelObjectExpandedPartial
    {
        let socket_health: SocketStateHealthArtifact = read_committed_json(
            dir,
            manifest,
            bpf_observer_system_effects::socket_state::SOCKET_STATE_HEALTH_NAME,
            MAX_JSON_BYTES,
        )?;
        socket_health.validate()?;
        let rebuilt_health = SocketStateHealthArtifact::from_outcomes(
            &config.run_id,
            &deployment.boot_id,
            config.epoch,
            &finalization.root_cgroup_ids,
            &finalization.system_effects,
        )?;
        if socket_health != rebuilt_health {
            bail!("socket-state health artifact does not rebuild from recorder outcomes");
        }
        let runs = socket_health
            .runs
            .iter()
            .map(|health| SocketStateRunVerification {
                cgroup_id: health.cgroup_id,
                run_epoch: health.run_epoch,
                published: health.event_published,
                dropped: health.event_dropped,
            })
            .collect::<Vec<_>>();
        let replayed = verify_socket_state_artifacts(
            &pinned_artifact_path(
                dir,
                bpf_observer_system_effects::socket_state::SOCKET_STATE_WAL_NAME,
            )?,
            &pinned_artifact_path(
                dir,
                bpf_observer_system_effects::socket_state::SOCKET_STATE_JSONL_NAME,
            )?,
            &effects_wal,
            &SocketStateVerificationBinding {
                run_id: config.run_id.clone(),
                boot_id: deployment.boot_id.clone(),
                cgroup_match_mode: CgroupMatchMode::AncestorRoot,
                runs,
            },
            &socket_health.runs,
        )?;
        if !replayed.jsonl_projection_verified {
            bail!("socket-state JSONL is not the authoritative WAL projection");
        }
    }
    Ok(())
}

fn read_committed_jsonl<T: DeserializeOwned + Serialize>(
    dir: &File,
    manifest: &RecoveryArtifactManifest,
    name: &str,
) -> Result<Vec<T>> {
    let bytes = read_bounded_file(dir, name, MAX_COMMITTED_ARTIFACT_BYTES)?;
    let committed = manifest.artifact(name)?;
    if bytes.len() as u64 != committed.size_bytes
        || hex::encode(Sha256::digest(&bytes)) != committed.sha256
    {
        bail!("{name} changed after its committed digest was checked");
    }
    if !bytes.is_empty() && bytes.last() != Some(&b'\n') {
        bail!("{name} has a truncated final JSONL event");
    }
    let mut events = Vec::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if line.len() > 1024 * 1024 || events.len() >= 1_000_000 {
            bail!("{name} exceeds event line/count bound");
        }
        let event: T = serde_json::from_slice(line)?;
        if serde_json::to_vec(&event)? != line {
            bail!("{name} has a noncanonical JSONL event");
        }
        events.push(event);
    }
    Ok(events)
}

fn external_incompleteness_reasons(
    dir: &File,
    manifest: &RecoveryArtifactManifest,
    deployment: &DeploymentManifest,
    recovery: &RecoveryEvidence,
    recorder: &RecoveryRecorderFinalization,
) -> Result<Vec<String>> {
    let mut reasons = Vec::new();
    if !recovery.success {
        reasons.push("external recovery command did not complete successfully".to_owned());
    }
    if !recorder.complete {
        reasons.extend(recorder.reasons.iter().cloned());
    }
    for (barrier_name, assessment_name) in [
        ("pre-restore-barrier.json", "pre-restore-validation.json"),
        ("post-restore-barrier.json", "post-restore-validation.json"),
    ] {
        let barrier: RootFreezeBarrier =
            read_committed_json(dir, manifest, barrier_name, MAX_JSON_BYTES)?;
        validate_phase_barrier(&barrier, deployment)?;
        if !barrier.all_roots_frozen {
            reasons.push("recovery snapshot freeze barrier incomplete".to_owned());
        }
        let assessment: IdentityAssessment =
            read_committed_json(dir, manifest, assessment_name, MAX_JSON_BYTES)?;
        validate_identity_assessment(&assessment, deployment)?;
        if !assessment.stable {
            reasons.push("deployment identity changed during recovery".to_owned());
        }
    }
    reasons.sort();
    reasons.dedup();
    Ok(reasons)
}

fn validate_transcript(
    dir: &File,
    manifest: &RecoveryArtifactManifest,
    config: &DeploymentObserverConfig,
    deployment: &DeploymentManifest,
    transcript: &RecoveryControlTranscript,
) -> Result<()> {
    let recovery = config
        .recovery
        .as_ref()
        .context("missing recovery config")?;
    if transcript.schema_version != 1 {
        bail!("unsupported recovery control transcript schema");
    }
    let ready: RecoveryReadyMessage =
        read_committed_json(dir, manifest, "recovery-ready-message.json", MAX_JSON_BYTES)?;
    let agent_started: AgentStartedMessage =
        read_committed_json(dir, manifest, "agent-started.json", MAX_JSON_BYTES)?;
    let legacy_ready: ReadyMessage =
        read_committed_json(dir, manifest, "ready-message.json", MAX_JSON_BYTES)?;
    let mut root_ids = deployment.registration_root_cgroup_ids();
    root_ids.sort_unstable();
    root_ids.dedup();
    let capability = CgroupScopeCapability::for_roots(&root_ids)?;
    if transcript.ready != ready
        || transcript.agent_started != agent_started
        || legacy_ready.protocol_version != DEPLOYMENT_OBSERVER_PROTOCOL_VERSION
        || legacy_ready.status != "READY"
        || legacy_ready.run_id != config.run_id
        || legacy_ready.epoch != config.epoch
        || legacy_ready.deployment_scope_sha256 != manifest.deployment_scope_sha256
        || legacy_ready.registration_cgroup_ids != root_ids
        || legacy_ready.cgroup_scope_capability != capability
        || legacy_ready.cgroup_scope_capability_sha256 != capability.sha256()?
        || legacy_ready.deployment_manifest_sha256
            != manifest.artifact("deployment-manifest.json")?.sha256
        || legacy_ready.recorder_object_sha256 != config.recorder_object_sha256
        || legacy_ready.lifecycle_object_sha256 != config.lifecycle_object_sha256
        || legacy_ready.socket_state_enabled
            != (config.object_resolution_mode
                == bpf_observer_system_effects::FileObjectResolutionMode::KernelObjectExpandedPartial)
        || legacy_ready.ready_barrier_sha256 != manifest.artifact("ready-barrier.json")?.sha256
        || legacy_ready.ready_validation_sha256
            != manifest.artifact("ready-validation.json")?.sha256
        || legacy_ready.bpf_state_s0_sha256
            != config
                .bpf_state_scope
                .as_ref()
                .map(|_| {
                    manifest
                        .artifact("bpf-state-s0.json")
                        .map(|value| value.sha256.clone())
                })
                .transpose()?
        || legacy_ready.filesystem_state_s0_sha256
            != config
                .filesystem_state_scope
                .as_ref()
                .map(|_| {
                    manifest
                        .artifact("filesystem-state-s0.json")
                        .map(|value| value.sha256.clone())
                })
                .transpose()?
        || legacy_ready.linux_state_s0_sha256
            != config
                .linux_state_scope
                .as_ref()
                .map(|_| {
                    manifest
                        .artifact("linux-state-s0.json")
                        .map(|value| value.sha256.clone())
                })
                .transpose()?
    {
        bail!("READY artifacts and recovery transcript disagree");
    }
    let expect_identity =
        |version: u32, run_id: &str, epoch: u64, checkpoint: &str, recovery_id: &str| {
            version == DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION
                && run_id == config.run_id
                && epoch == config.epoch
                && checkpoint == recovery.checkpoint_id
                && recovery_id == recovery.recovery_id
        };
    let r = &transcript.ready;
    if !expect_identity(
        r.protocol_version,
        &r.run_id,
        r.epoch,
        &r.checkpoint_id,
        &r.recovery_id,
    ) || r.status != "READY"
        || r.command_seq != 1
        || r.snapshot_a_sha256 != manifest.snapshot_a_sha256
    {
        bail!("recovery READY message has an invalid identity or A digest");
    }
    let mut machine = RecoveryProtocolMachine::new(
        &config.run_id,
        config.epoch,
        &recovery.checkpoint_id,
        &recovery.recovery_id,
        &r.nonce,
    )?;
    machine.mark_ready_a_committed()?;
    machine.accept_agent_started(
        &transcript.agent_started_command,
        &transcript.agent_started.nonce,
    )?;
    let started = &transcript.agent_started;
    if !expect_identity(
        started.protocol_version,
        &started.run_id,
        started.epoch,
        &started.checkpoint_id,
        &started.recovery_id,
    ) || started.status != "AGENT_STARTED"
        || started.command_seq != 2
        || started.nonce != machine.nonce()
        || started.agent_started_sha256 != sha256_json(&transcript.agent_started_command)?
    {
        bail!("AGENT_STARTED acknowledgment does not bind the accepted command");
    }

    let nonce2 = started.nonce.clone();
    machine.accept_pre_restore(
        &transcript.pre_restore_command,
        &transcript.snapshot_c.nonce,
    )?;
    let snapshot_b = &transcript.snapshot_b;
    if !expect_identity(
        snapshot_b.protocol_version,
        &snapshot_b.run_id,
        snapshot_b.epoch,
        &snapshot_b.checkpoint_id,
        &snapshot_b.recovery_id,
    ) || snapshot_b.status != "SNAPSHOT_B"
        || snapshot_b.command_seq != 2
        || snapshot_b.nonce != nonce2
        || snapshot_b.pre_restore_sha256 != manifest.artifact("pre-restore-validation.json")?.sha256
        || snapshot_b.snapshot_b_sha256 != manifest.snapshot_b_sha256
    {
        bail!("SNAPSHOT_B acknowledgment has invalid phase evidence or leaks the FINISH nonce");
    }
    machine.mark_b_committed()?;
    machine.mark_restoring()?;
    let restored = &transcript.restore_complete;
    if !expect_identity(
        restored.protocol_version,
        &restored.run_id,
        restored.epoch,
        &restored.checkpoint_id,
        &restored.recovery_id,
    ) || restored.status != "RESTORE_COMPLETE"
        || restored.command_seq != 2
        || restored.nonce != nonce2
        || restored.recovery_sha256 != manifest.artifact(RECOVERY_EVIDENCE_FILE)?.sha256
    {
        bail!("RESTORE_COMPLETE acknowledgment lacks the committed recovery evidence");
    }
    machine.mark_restore_complete()?;
    machine.mark_c_committed()?;
    let snapshot_c = &transcript.snapshot_c;
    if !expect_identity(
        snapshot_c.protocol_version,
        &snapshot_c.run_id,
        snapshot_c.epoch,
        &snapshot_c.checkpoint_id,
        &snapshot_c.recovery_id,
    ) || snapshot_c.status != "SNAPSHOT_C"
        || snapshot_c.command_seq != 3
        || snapshot_c.nonce != machine.nonce()
        || snapshot_c.snapshot_c_sha256 != manifest.snapshot_c_sha256
    {
        bail!("SNAPSHOT_C acknowledgment has an invalid FINISH challenge or C digest");
    }
    machine.accept_finish(&transcript.finish_command)?;
    machine.mark_finished()?;
    if machine.state() != RecoveryProtocolState::Finished {
        bail!("recovery transcript did not replay through FINISHED");
    }
    Ok(())
}

fn open_directory(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open recovery evidence directory {}", path.display()))?;
    if !file.metadata()?.is_dir() {
        bail!("recovery evidence root is not a directory");
    }
    Ok(file)
}

fn directory_entries(directory: &File) -> Result<BTreeSet<String>> {
    // The proc-fd path refers to the already-open directory rather than a
    // pathname that an attacker could swap between enumeration and openat.
    let pinned = format!("/proc/self/fd/{}", directory.as_raw_fd());
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(pinned)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-UTF-8 recovery artifact name"))?;
        validate_name(&name)?;
        if !entry.file_type()?.is_file() || !names.insert(name) {
            bail!("recovery evidence contains a non-regular or duplicate artifact");
        }
    }
    Ok(names)
}

fn open_artifact(directory: &File, name: &str) -> Result<File> {
    validate_name(name)?;
    let c_name = CString::new(name).context("artifact name contains a NUL byte")?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c_name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("open recovery artifact {name}"));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > MAX_COMMITTED_ARTIFACT_BYTES
    {
        bail!("{name} is not a bounded singly-linked regular file");
    }
    Ok(file)
}

fn read_json_with_digest<T: DeserializeOwned>(
    directory: &File,
    name: &str,
    maximum: u64,
    expected_sha256: &str,
) -> Result<T> {
    let bytes = read_bounded_file(directory, name, maximum)?;
    if hex::encode(Sha256::digest(&bytes)) != expected_sha256 {
        bail!("{name} changed after its externally pinned digest was checked");
    }
    serde_json::from_slice(&bytes).with_context(|| format!("parse recovery artifact {name}"))
}

fn read_committed_json<T: DeserializeOwned>(
    directory: &File,
    manifest: &RecoveryArtifactManifest,
    name: &str,
    maximum: u64,
) -> Result<T> {
    let bytes = read_bounded_file(directory, name, maximum)?;
    let expected = manifest.artifact(name)?;
    if bytes.len() as u64 != expected.size_bytes
        || hex::encode(Sha256::digest(&bytes)) != expected.sha256
    {
        bail!("{name} changed after its committed digest was checked");
    }
    serde_json::from_slice(&bytes).with_context(|| format!("parse recovery artifact {name}"))
}

fn read_bounded_file(directory: &File, name: &str, maximum: u64) -> Result<Vec<u8>> {
    let mut file = open_artifact(directory, name)?;
    let before = file.metadata()?;
    if before.len() > maximum {
        bail!("{name} exceeds its JSON byte limit");
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(before.len().min(8 * 1024 * 1024))
            .context("artifact allocation bound does not fit usize")?,
    );
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum || bytes.len() as u64 != before.len() {
        bail!("{name} size changed or exceeds its bound");
    }
    if !same_metadata(&before, &file.metadata()?) {
        bail!("{name} changed while it was read");
    }
    Ok(bytes)
}

fn digest_file(directory: &File, name: &str) -> Result<ArtifactDigest> {
    let mut file = open_artifact(directory, name)?;
    let before = file.metadata()?;
    let mut hasher = Sha256::new();
    let mut read_bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        read_bytes = read_bytes
            .checked_add(count as u64)
            .context("recovery artifact length overflow")?;
        if read_bytes > MAX_COMMITTED_ARTIFACT_BYTES {
            bail!("{name} exceeds its hard artifact byte limit");
        }
        hasher.update(&buffer[..count]);
    }
    if read_bytes != before.len() || !same_metadata(&before, &file.metadata()?) {
        bail!("{name} changed while it was hashed");
    }
    Ok(ArtifactDigest {
        relative_path: name.to_owned(),
        size_bytes: read_bytes,
        sha256: hex::encode(hasher.finalize()),
    })
}

fn same_metadata(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || name.contains('/')
        || name == "."
        || name == ".."
        || name.contains('\0')
        || name.contains('\n')
    {
        bail!("invalid recovery evidence artifact name");
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

fn sha256_json<T: Serialize>(value: &T) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

fn recovery_snapshot_id(
    config: &DeploymentObserverConfig,
    phase: RecoverySnapshotPhase,
) -> Result<String> {
    let recovery = config
        .recovery
        .as_ref()
        .context("missing recovery config")?;
    let identity = (
        "DEPLOYMENT_RECOVERY_SNAPSHOT_V1",
        &config.run_id,
        config.epoch,
        &recovery.checkpoint_id,
        &recovery.recovery_id,
        phase.as_str(),
    );
    Ok(format!("{}-{}", phase.as_str(), sha256_json(&identity)?))
}

fn verify_snapshot_binding(
    binding: &SnapshotDomainBinding,
    phase: RecoverySnapshotPhase,
    expected_path: &str,
    expected_raw_id: &str,
    expected_raw_phase: &str,
    manifest: &RecoveryArtifactManifest,
) -> Result<()> {
    if binding.artifact_relative_path != expected_path
        || binding.artifact_size_bytes != manifest.artifact(expected_path)?.size_bytes
        || binding.artifact_sha256 != manifest.artifact(expected_path)?.sha256
        || binding.raw_snapshot_id != expected_raw_id
        || binding.raw_phase != expected_raw_phase
        || phase == RecoverySnapshotPhase::A && expected_raw_phase != "S0"
    {
        bail!("raw snapshot binding differs from the committed phase artifact");
    }
    Ok(())
}

fn captured_within_envelope(captured: u128, envelope: &RecoverySnapshotEnvelope) -> Result<()> {
    if captured < envelope.capture_started_unix_ns || captured > envelope.capture_completed_unix_ns
    {
        bail!("raw snapshot capture timestamp lies outside its A/B/C envelope");
    }
    Ok(())
}

fn read_bpf_triplet(
    dir: &File,
    manifest: &RecoveryArtifactManifest,
    config: &DeploymentObserverConfig,
    envelopes: [&RecoverySnapshotEnvelope; 3],
) -> Result<Option<[BpfSnapshot; 3]>> {
    let Some(scope) = config.bpf_state_scope.as_ref() else {
        return Ok(None);
    };
    let names = ["bpf-state-s0.json", "bpf-state-b.json", "bpf-state-c.json"];
    let phases = ["S0", "B", "C"];
    let mut raw = Vec::with_capacity(3);
    for index in 0..3 {
        let snapshot: BpfSnapshot =
            read_committed_json(dir, manifest, names[index], MAX_BPF_SNAPSHOT_BYTES)?;
        let binding = envelopes[index]
            .bpf
            .as_ref()
            .context("BPF-enabled snapshot envelope lacks BPF binding")?;
        let expected_id = bpf_snapshot_id(&config.run_id, config.epoch, phases[index]);
        verify_snapshot_binding(
            binding,
            envelopes[index].phase,
            names[index],
            &expected_id,
            phases[index],
            manifest,
        )?;
        if snapshot.phase != phases[index]
            || snapshot.snapshot_id != expected_id
            || snapshot.boot_id != envelopes[index].boot_id
            || snapshot.claim_scope != *scope
            || bpf_scope_sha256(&snapshot.claim_scope)? != bpf_scope_sha256(scope)?
            || binding.domains != [RecoveryDomain::Bpf]
        {
            bail!("raw BPF snapshot does not match its phase, identity, or external scope");
        }
        captured_within_envelope(snapshot.captured_unix_ns, envelopes[index])?;
        raw.push(snapshot);
    }
    Ok(Some(
        raw.try_into()
            .map_err(|_| anyhow::anyhow!("BPF triplet cardinality"))?,
    ))
}

fn read_filesystem_triplet(
    dir: &File,
    manifest: &RecoveryArtifactManifest,
    config: &DeploymentObserverConfig,
    envelopes: [&RecoverySnapshotEnvelope; 3],
) -> Result<Option<[FilesystemSnapshot; 3]>> {
    let Some(scope) = config.filesystem_state_scope.as_ref() else {
        return Ok(None);
    };
    let names = [
        "filesystem-state-s0.json",
        "filesystem-state-b.json",
        "filesystem-state-c.json",
    ];
    let phase_text = ["S0", "B", "C"];
    let phase_enum = [FilesystemPhase::S0, FilesystemPhase::B, FilesystemPhase::C];
    let mut raw = Vec::with_capacity(3);
    for index in 0..3 {
        let snapshot: FilesystemSnapshot =
            read_committed_json(dir, manifest, names[index], MAX_FS_SNAPSHOT_BYTES)?;
        snapshot.validate()?;
        let binding = envelopes[index]
            .filesystem
            .as_ref()
            .context("filesystem-enabled envelope lacks filesystem binding")?;
        let expected_id = filesystem_snapshot_id(&config.run_id, config.epoch, phase_text[index]);
        verify_snapshot_binding(
            binding,
            envelopes[index].phase,
            names[index],
            &expected_id,
            phase_text[index],
            manifest,
        )?;
        if snapshot.phase != phase_enum[index]
            || snapshot.snapshot_id != expected_id
            || snapshot.boot_id != envelopes[index].boot_id
            || snapshot.scope != *scope
            || !envelopes[index]
                .mount_namespace_ids
                .contains(&snapshot.mount_namespace_inode)
            || binding.domains != [RecoveryDomain::Filesystem]
        {
            bail!("raw filesystem snapshot does not match phase, mount namespace, or scope");
        }
        captured_within_envelope(snapshot.captured_unix_ns, envelopes[index])?;
        raw.push(snapshot);
    }
    Ok(Some(raw.try_into().map_err(|_| {
        anyhow::anyhow!("filesystem triplet cardinality")
    })?))
}

fn read_linux_triplet(
    dir: &File,
    manifest: &RecoveryArtifactManifest,
    deployment: &DeploymentManifest,
    config: &DeploymentObserverConfig,
    envelopes: [&RecoverySnapshotEnvelope; 3],
) -> Result<Option<[StateSnapshot; 3]>> {
    let Some(bound) = bind_linux_state_scope(config.linux_state_scope.as_ref(), deployment)? else {
        return Ok(None);
    };
    let names = [
        "linux-state-s0.json",
        "linux-state-b.json",
        "linux-state-c.json",
    ];
    let phase_text = ["s0", "b", "c"];
    let raw_phase = ["S0", "B", "C"];
    let phase_enum = [LinuxPhase::S0, LinuxPhase::B, LinuxPhase::C];
    let mut raw = Vec::with_capacity(3);
    for index in 0..3 {
        let snapshot: StateSnapshot =
            read_committed_json(dir, manifest, names[index], MAX_LINUX_SNAPSHOT_BYTES)?;
        let binding = envelopes[index]
            .linux
            .as_ref()
            .context("Linux-state-enabled envelope lacks Linux-state binding")?;
        let expected_id = format!("{}:linux-state:{}", config.run_id, phase_text[index]);
        verify_snapshot_binding(
            binding,
            envelopes[index].phase,
            names[index],
            &expected_id,
            raw_phase[index],
            manifest,
        )?;
        if snapshot.phase != phase_enum[index]
            || snapshot.snapshot_id != expected_id
            || snapshot.boot_id != envelopes[index].boot_id
            || snapshot.scope != bound.scope
            || snapshot.scope_sha256 != bound.scope.sha256()?
        {
            bail!("raw Linux-state snapshot does not match phase, boot, or bound scope");
        }
        let mut expected_domains = Vec::new();
        if snapshot.sysctl.is_some() {
            expected_domains.push(RecoveryDomain::Sysctl);
        }
        if snapshot.mounts.is_some() {
            expected_domains.push(RecoveryDomain::Mount);
        }
        if snapshot.network.is_some() {
            expected_domains.push(RecoveryDomain::Network);
        }
        if snapshot.modules.is_some() {
            expected_domains.push(RecoveryDomain::Modules);
        }
        if snapshot.process_residual.is_some() {
            expected_domains.push(RecoveryDomain::ProcessResidual);
        }
        expected_domains.sort();
        if binding.domains != expected_domains {
            bail!("Linux-state envelope domain vector differs from raw snapshot");
        }
        captured_within_envelope(snapshot.captured_unix_ns, envelopes[index])?;
        raw.push(snapshot);
    }
    Ok(Some(raw.try_into().map_err(|_| {
        anyhow::anyhow!("Linux-state triplet cardinality")
    })?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let serial = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "bpf-observer-recovery-verifier-{}-{serial}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove test directory");
        }
    }

    fn manifest_with(artifact: ArtifactDigest) -> RecoveryArtifactManifest {
        RecoveryArtifactManifest {
            protocol_version: DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
            run_id: "test-run".to_owned(),
            epoch: 1,
            checkpoint_id: "checkpoint".to_owned(),
            recovery_id: "recovery".to_owned(),
            deployment_scope_sha256: "0".repeat(64),
            recovery_config_sha256: "0".repeat(64),
            recovery_verdict_sha256: "0".repeat(64),
            snapshot_a_sha256: "0".repeat(64),
            snapshot_b_sha256: "0".repeat(64),
            snapshot_c_sha256: "0".repeat(64),
            committed_artifact_total_bytes: artifact.size_bytes,
            artifacts: vec![artifact],
        }
    }

    #[test]
    fn b_c_delta_recovery_and_verdict_tampering_is_rejected() {
        for name in [
            "bpf-state-b.json",
            "bpf-state-c.json",
            "filesystem-state-b.json",
            "filesystem-state-c.json",
            "linux-state-b.json",
            "linux-state-c.json",
            RECOVERY_AGENT_DELTA_FILE,
            RECOVERY_RECOVERY_DELTA_FILE,
            RECOVERY_RESIDUAL_DELTA_FILE,
            RECOVERY_EVIDENCE_FILE,
            RECOVERY_VERDICT_FILE,
        ] {
            let test = TestDir::new();
            fs::write(test.0.join(name), b"{}").expect("write artifact");
            let dir = open_directory(&test.0).expect("open directory");
            let manifest = manifest_with(digest_file(&dir, name).expect("digest artifact"));
            let original: serde_json::Value =
                read_committed_json(&dir, &manifest, name, 1024).expect("read committed artifact");
            assert_eq!(original, serde_json::json!({}), "{name}");
            fs::write(test.0.join(name), b"{\"tampered\":true}").expect("tamper artifact");
            assert!(
                read_committed_json::<serde_json::Value>(&dir, &manifest, name, 1024).is_err(),
                "{name} tampering escaped digest check"
            );
        }
    }

    #[test]
    fn extra_symlink_and_hardlink_artifacts_are_rejected() {
        let test = TestDir::new();
        fs::write(test.0.join("snapshot-b.json"), b"{}").expect("write artifact");
        let dir = open_directory(&test.0).expect("open directory");
        let expected = directory_entries(&dir).expect("list initial artifacts");
        fs::write(test.0.join("extra.json"), b"{}").expect("write extra artifact");
        assert_ne!(
            directory_entries(&dir).expect("list extra artifact"),
            expected
        );
        fs::remove_file(test.0.join("extra.json")).expect("remove extra artifact");
        symlink(
            test.0.join("snapshot-b.json"),
            test.0.join("snapshot-c.json"),
        )
        .expect("make symlink");
        assert!(directory_entries(&dir).is_err());
        assert!(open_artifact(&dir, "snapshot-c.json").is_err());
        fs::remove_file(test.0.join("snapshot-c.json")).expect("remove symlink");
        fs::hard_link(
            test.0.join("snapshot-b.json"),
            test.0.join("snapshot-c.json"),
        )
        .expect("make hardlink");
        assert!(digest_file(&dir, "snapshot-b.json").is_err());
    }

    #[test]
    fn time_order_rejects_backward_clock_and_overlaps() {
        assert!(capture_intervals_are_monotonic([
            [10, 20],
            [20, 30],
            [30, 40]
        ]));
        assert!(!capture_intervals_are_monotonic([
            [10, 20],
            [19, 30],
            [30, 40]
        ]));
        assert!(!capture_intervals_are_monotonic([
            [10, 20],
            [20, 30],
            [29, 40]
        ]));
        assert!(!capture_intervals_are_monotonic([
            [10, 20],
            [20, 19],
            [30, 40]
        ]));
        assert!(!capture_intervals_are_monotonic([
            [0, 20],
            [20, 30],
            [30, 40]
        ]));
    }

    #[test]
    fn recovery_boundary_allows_only_new_agent_descendants() {
        let mut validation = LiveIdentityValidation {
            protocol_version: DEPLOYMENT_PROTOCOL_VERSION,
            scope_sha256: "0".repeat(64),
            phase: RevalidationPhase::Closure,
            checked_unix_ns: 1,
            stable: true,
            expected_process_exits: Vec::new(),
            mismatches: Vec::new(),
        };
        assert!(recovery_boundary_identity_stable(&validation));
        validation.stable = false;
        validation
            .mismatches
            .push(ValidationMismatch::ProcessSetChanged {
                added: vec![101, 102],
                removed_unexpected: Vec::new(),
            });
        assert!(recovery_boundary_identity_stable(&validation));
        validation
            .mismatches
            .push(ValidationMismatch::ProcessSetChanged {
                added: vec![103],
                removed_unexpected: Vec::new(),
            });
        assert!(recovery_boundary_identity_stable(&validation));

        validation
            .mismatches
            .push(ValidationMismatch::ProcessSetChanged {
                added: vec![104],
                removed_unexpected: vec![99],
            });
        assert!(!recovery_boundary_identity_stable(&validation));
        validation.mismatches.pop();
        validation
            .mismatches
            .push(ValidationMismatch::ProcessIdentityChanged {
                pid: 101,
                changed_fields: vec!["start_time".to_owned()],
            });
        assert!(!recovery_boundary_identity_stable(&validation));
        validation.mismatches.pop();
        validation
            .mismatches
            .push(ValidationMismatch::ProcessSetChanged {
                added: vec![102],
                removed_unexpected: Vec::new(),
            });
        assert!(!recovery_boundary_identity_stable(&validation));
        validation.mismatches.pop();
        validation.stable = true;
        assert!(!recovery_boundary_identity_stable(&validation));
    }

    #[test]
    fn recovery_environment_checks_must_bracket_helper_between_b_and_c() {
        assert!(recovery_environment_times_are_ordered(
            10,
            [11, 12],
            13,
            20,
            [21, 22],
            23
        ));
        assert!(!recovery_environment_times_are_ordered(
            10,
            [9, 12],
            13,
            20,
            [21, 22],
            23
        ));
        assert!(!recovery_environment_times_are_ordered(
            10,
            [11, 14],
            13,
            20,
            [21, 22],
            23
        ));
        assert!(!recovery_environment_times_are_ordered(
            10,
            [11, 12],
            13,
            20,
            [19, 22],
            23
        ));
        assert!(!recovery_environment_times_are_ordered(
            10,
            [11, 12],
            13,
            20,
            [21, 24],
            23
        ));
        assert!(!recovery_environment_times_are_ordered(
            10,
            [11, 12],
            13,
            20,
            [11, 22],
            23
        ));
    }
}
