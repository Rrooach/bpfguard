// SPDX-License-Identifier: GPL-2.0-only

//! Optional endpoint-state confirmation at the deployment READY/FINISH
//! barriers.  These collectors are deliberately absent from the syscall hot
//! path.  A positive endpoint delta is retained, but neither collector claims
//! that the deployment caused a global state change.

use anyhow::{bail, Context, Result};
use bpf_observer_comparator::compare_phases as compare_bpf_phases;
use bpf_observer_deployment::{DeploymentKind, DeploymentManifest, ProcessRole};
use bpf_observer_filesystem_confirmer::{
    capture as capture_filesystem, capture_in_retained_mount_namespace,
    compare as compare_filesystem, ActorContractStatus, CaptureRequest as FilesystemCaptureRequest,
    CausalAttributionStatus, CompletenessStatus as FilesystemCompletenessStatus,
    EndpointDifferenceStatus, FilesystemComparison, FilesystemScope, FilesystemSnapshot,
    FilesystemVerdict, MountNamespaceCaptureSource, SnapshotPhase as FilesystemSnapshotPhase,
    FILESYSTEM_CONFIRMATION_DOMAIN, FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION,
};
use bpf_observer_linux_state_confirmers::{LinuxNamespaceKind, NamespaceTarget, RetainedNamespace};
use bpf_observer_oracle::{capture as capture_bpf, CaptureOptions};
use bpf_observer_schema::{
    Attribution, ClaimScope, CompletenessStatus as BpfCompletenessStatus, EvidenceHealth,
    ObjectExclusions, QuiescenceBasis, QuiescenceReport, QuiescenceStatus, RunStatus, Snapshot,
    StateVerdict, Verdict,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::report::ArtifactDigest;

pub(crate) const BPF_STATE_CONFIRMATION_PROTOCOL_VERSION: u32 = 1;
pub(crate) const BPF_STATE_CONFIRMATION_DOMAIN: &str =
    "FINAL_BPF_OBJECT_STATE_WITHIN_EXPLICIT_CLAIM_SCOPE";
pub(crate) const BPF_STATE_S0_FILE: &str = "bpf-state-s0.json";
pub(crate) const BPF_STATE_S1_FILE: &str = "bpf-state-s1.json";
pub(crate) const BPF_STATE_VERDICT_FILE: &str = "bpf-state-verdict.json";
pub(crate) const FILESYSTEM_STATE_S0_FILE: &str = "filesystem-state-s0.json";
pub(crate) const FILESYSTEM_STATE_S1_FILE: &str = "filesystem-state-s1.json";
pub(crate) const FILESYSTEM_STATE_COMPARISON_FILE: &str = "filesystem-state-comparison.json";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BpfStateReport {
    pub protocol_version: u32,
    pub domain: String,
    pub scope_sha256: String,
    pub system_effect_recorder_exclusions: ObjectExclusions,
    pub lifecycle_recorder_exclusions: ObjectExclusions,
    pub observer_exclusions: ObjectExclusions,
    pub s0_snapshot_id: String,
    pub s0_snapshot_sha256: String,
    pub s1_snapshot_id: String,
    pub s1_snapshot_sha256: String,
    pub verdict_sha256: String,
    pub state_verdict: StateVerdict,
    pub state_completeness: BpfCompletenessStatus,
    pub evidence_status: BpfCompletenessStatus,
    pub attribution: Attribution,
    pub change_count: u64,
    pub contract_complete: bool,
    pub contract_incomplete_reasons: Vec<String>,
    pub causal_attribution_established: bool,
    pub operation_events_are_state_diff: bool,
    pub atomic_with_other_confirmation_domains: bool,
    pub unchanged_verdict_authorized: bool,
}

pub(crate) struct BpfStateArtifactBindings<'a> {
    pub s0_snapshot_id: &'a str,
    pub s0_digest: &'a ArtifactDigest,
    pub s1_snapshot_id: &'a str,
    pub s1_digest: &'a ArtifactDigest,
    pub verdict_digest: &'a ArtifactDigest,
}

impl BpfStateReport {
    pub(crate) fn from_verdict(
        scope: &ClaimScope,
        system_effect_recorder_exclusions: &ObjectExclusions,
        lifecycle_recorder_exclusions: &ObjectExclusions,
        verdict: &Verdict,
        artifacts: &BpfStateArtifactBindings<'_>,
        contract_incomplete_reasons: &[String],
    ) -> Result<Self> {
        let reasons = canonical_reasons(contract_incomplete_reasons);
        validate_exclusions(system_effect_recorder_exclusions)?;
        validate_exclusions(lifecycle_recorder_exclusions)?;
        let mut exclusions = system_effect_recorder_exclusions.clone();
        merge_exclusions(&mut exclusions, lifecycle_recorder_exclusions);
        let report = Self {
            protocol_version: BPF_STATE_CONFIRMATION_PROTOCOL_VERSION,
            domain: BPF_STATE_CONFIRMATION_DOMAIN.to_owned(),
            scope_sha256: bpf_scope_sha256(scope)?,
            system_effect_recorder_exclusions: system_effect_recorder_exclusions.clone(),
            lifecycle_recorder_exclusions: lifecycle_recorder_exclusions.clone(),
            observer_exclusions: exclusions,
            s0_snapshot_id: artifacts.s0_snapshot_id.to_owned(),
            s0_snapshot_sha256: artifacts.s0_digest.sha256.clone(),
            s1_snapshot_id: artifacts.s1_snapshot_id.to_owned(),
            s1_snapshot_sha256: artifacts.s1_digest.sha256.clone(),
            verdict_sha256: artifacts.verdict_digest.sha256.clone(),
            state_verdict: verdict.state_verdict.clone(),
            state_completeness: verdict.state_completeness.status.clone(),
            evidence_status: verdict.evidence_status.status.clone(),
            attribution: verdict.attribution.clone(),
            change_count: verdict.changes.len() as u64,
            contract_complete: reasons.is_empty(),
            contract_incomplete_reasons: reasons,
            causal_attribution_established: false,
            operation_events_are_state_diff: false,
            atomic_with_other_confirmation_domains: false,
            unchanged_verdict_authorized: false,
        };
        report.validate()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != BPF_STATE_CONFIRMATION_PROTOCOL_VERSION
            || self.domain != BPF_STATE_CONFIRMATION_DOMAIN
            || self.s0_snapshot_id.is_empty()
            || self.s1_snapshot_id.is_empty()
        {
            bail!("BPF state report envelope is invalid");
        }
        validate_sha256(&self.scope_sha256, "BPF state scope")?;
        validate_sha256(&self.s0_snapshot_sha256, "BPF state S0")?;
        validate_sha256(&self.s1_snapshot_sha256, "BPF state S1")?;
        validate_sha256(&self.verdict_sha256, "BPF state verdict")?;
        validate_exclusions(&self.observer_exclusions)?;
        validate_exclusions(&self.system_effect_recorder_exclusions)?;
        validate_exclusions(&self.lifecycle_recorder_exclusions)?;
        let mut merged = self.system_effect_recorder_exclusions.clone();
        merge_exclusions(&mut merged, &self.lifecycle_recorder_exclusions);
        if merged != self.observer_exclusions {
            bail!("BPF state observer exclusions are not the exact recorder union");
        }
        if self.state_verdict == StateVerdict::UnchangedWithinScope
            || self.causal_attribution_established
            || self.operation_events_are_state_diff
            || self.atomic_with_other_confirmation_domains
            || self.unchanged_verdict_authorized
            || matches!(
                self.attribution,
                Attribution::WorkloadAttributed | Attribution::PartiallyAttributed
            )
        {
            bail!("BPF state report overstates endpoint or causal authority");
        }
        validate_contract_reasons(
            self.contract_complete,
            &self.contract_incomplete_reasons,
            "BPF state",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemStateReport {
    pub protocol_version: u32,
    pub domain: String,
    pub scope_sha256: String,
    pub s0_snapshot_id: String,
    pub s0_snapshot_sha256: String,
    pub s1_snapshot_id: String,
    pub s1_snapshot_sha256: String,
    pub comparison_sha256: String,
    pub endpoint_difference: EndpointDifferenceStatus,
    pub state_verdict: FilesystemVerdict,
    pub state_completeness: FilesystemCompletenessStatus,
    pub actor_contract_status: ActorContractStatus,
    pub causal_attribution_status: CausalAttributionStatus,
    pub change_count: u64,
    pub contract_complete: bool,
    pub contract_incomplete_reasons: Vec<String>,
    pub actor_contract_authenticated_by_observer: bool,
    pub operation_events_are_state_diff: bool,
    pub atomic_with_other_confirmation_domains: bool,
    pub unchanged_verdict_authorized: bool,
}

impl FilesystemStateReport {
    pub(crate) fn from_comparison(
        scope: &FilesystemScope,
        comparison: &FilesystemComparison,
        s0_digest: &ArtifactDigest,
        s1_digest: &ArtifactDigest,
        comparison_digest: &ArtifactDigest,
        contract_incomplete_reasons: &[String],
    ) -> Result<Self> {
        let reasons = canonical_reasons(contract_incomplete_reasons);
        let report = Self {
            protocol_version: FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION,
            domain: FILESYSTEM_CONFIRMATION_DOMAIN.to_owned(),
            scope_sha256: scope.sha256()?,
            s0_snapshot_id: comparison.s0_snapshot_id.clone(),
            s0_snapshot_sha256: s0_digest.sha256.clone(),
            s1_snapshot_id: comparison.s1_snapshot_id.clone(),
            s1_snapshot_sha256: s1_digest.sha256.clone(),
            comparison_sha256: comparison_digest.sha256.clone(),
            endpoint_difference: comparison.endpoint_difference,
            state_verdict: comparison.verdict,
            state_completeness: comparison.state_completeness.status,
            actor_contract_status: comparison.actor_contract_status,
            causal_attribution_status: comparison.causal_attribution_status,
            change_count: comparison.changes.len() as u64,
            contract_complete: reasons.is_empty(),
            contract_incomplete_reasons: reasons,
            actor_contract_authenticated_by_observer: false,
            operation_events_are_state_diff: false,
            atomic_with_other_confirmation_domains: false,
            unchanged_verdict_authorized: false,
        };
        report.validate()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION
            || self.domain != FILESYSTEM_CONFIRMATION_DOMAIN
            || self.s0_snapshot_id.is_empty()
            || self.s1_snapshot_id.is_empty()
        {
            bail!("filesystem state report envelope is invalid");
        }
        validate_sha256(&self.scope_sha256, "filesystem state scope")?;
        validate_sha256(&self.s0_snapshot_sha256, "filesystem state S0")?;
        validate_sha256(&self.s1_snapshot_sha256, "filesystem state S1")?;
        validate_sha256(&self.comparison_sha256, "filesystem state comparison")?;
        if self.actor_contract_status != ActorContractStatus::Missing
            || self.causal_attribution_status != CausalAttributionStatus::NotEstablished
            || self.state_verdict == FilesystemVerdict::UnchangedWithinScope
            || self.actor_contract_authenticated_by_observer
            || self.operation_events_are_state_diff
            || self.atomic_with_other_confirmation_domains
            || self.unchanged_verdict_authorized
        {
            bail!("filesystem state report overstates endpoint or causal authority");
        }
        validate_contract_reasons(
            self.contract_complete,
            &self.contract_incomplete_reasons,
            "filesystem state",
        )
    }
}

pub(crate) fn bpf_scope_sha256(scope: &ClaimScope) -> Result<String> {
    bpf_observer_oracle::validate_claim_scope(scope)?;
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(scope)?)))
}

pub(crate) fn merge_exclusions(target: &mut ObjectExclusions, source: &ObjectExclusions) {
    target
        .program_ids
        .extend(source.program_ids.iter().copied());
    target.map_ids.extend(source.map_ids.iter().copied());
    target.link_ids.extend(source.link_ids.iter().copied());
}

pub(crate) fn validate_exclusions(exclusions: &ObjectExclusions) -> Result<()> {
    if exclusions.program_ids.is_empty()
        || exclusions.map_ids.is_empty()
        || exclusions.link_ids.is_empty()
        || exclusions.program_ids.contains(&0)
        || exclusions.map_ids.contains(&0)
        || exclusions.link_ids.contains(&0)
    {
        bail!("observer BPF object exclusions must contain nonzero program, map, and link IDs");
    }
    Ok(())
}

pub(crate) fn bpf_snapshot_id(run_id: &str, epoch: u64, phase: &str) -> String {
    stable_snapshot_id("DEPLOYMENT-BPF", run_id, epoch, phase)
}

pub(crate) fn filesystem_snapshot_id(run_id: &str, epoch: u64, phase: &str) -> String {
    stable_snapshot_id("DEPLOYMENT-FILESYSTEM", run_id, epoch, phase)
}

fn stable_snapshot_id(domain: &str, run_id: &str, epoch: u64, phase: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(run_id.as_bytes());
    hasher.update([0]);
    hasher.update(epoch.to_le_bytes());
    format!("{domain}-{phase}-{}", hex::encode(hasher.finalize()))
}

pub(crate) fn capture_bpf_endpoint(
    scope: &ClaimScope,
    exclusions: &ObjectExclusions,
    run_id: &str,
    epoch: u64,
    phase: &str,
) -> Result<Snapshot> {
    let options = CaptureOptions {
        snapshot_id: bpf_snapshot_id(run_id, epoch, phase),
        phase: phase.to_owned(),
        exclusions: exclusions.clone(),
        // Freezing deployment roots does not establish global BPF-map
        // quiescence because unrelated host actors can still mutate maps.
        maps_quiescent: false,
    };
    capture_bpf(scope, &options)
}

pub(crate) fn compare_bpf_endpoints(before: &Snapshot, after: &Snapshot) -> Result<Verdict> {
    compare_bpf_endpoints_with_phases(before, after, "S0", "S1")
}

pub(crate) fn compare_bpf_endpoints_with_phases(
    before: &Snapshot,
    after: &Snapshot,
    before_phase: &str,
    after_phase: &str,
) -> Result<Verdict> {
    let mut evidence = EvidenceHealth::default();
    evidence.reasons.push(
        "deployment operation streams do not establish the exclusive BPF_USER_SYSCALL evidence contract required for a negative global BPF-state claim"
            .to_owned(),
    );
    let quiescence = QuiescenceReport {
        status: QuiescenceStatus::Unknown,
        basis: QuiescenceBasis::ObservedOnly,
        contract_id: None,
        checks: Vec::new(),
        exclusive_actor_attribution: false,
        authentication: None,
    };
    let mut verdict = compare_bpf_phases(
        before,
        after,
        before_phase,
        after_phase,
        &evidence,
        quiescence,
    )?;
    verdict.run_status = RunStatus::Provisional;
    verdict.limitations.push(
        "deployment cgroup freeze barriers do not exclude unrelated host BPF actors; a positive delta remains unattributed and an empty delta remains inconclusive"
            .to_owned(),
    );
    verdict.limitations.push(
        "BPF, filesystem, and Linux-domain endpoint captures are sequential rather than one atomic whole-system snapshot"
            .to_owned(),
    );
    verdict.limitations.sort();
    verdict.limitations.dedup();
    Ok(verdict)
}

pub(crate) fn capture_filesystem_endpoint(
    scope: &FilesystemScope,
    run_id: &str,
    epoch: u64,
    phase: FilesystemSnapshotPhase,
    retained_mount_namespace: Option<&RetainedNamespace>,
) -> Result<FilesystemSnapshot> {
    let phase_name = match phase {
        FilesystemSnapshotPhase::S0 => "S0",
        FilesystemSnapshotPhase::S1 => "S1",
        FilesystemSnapshotPhase::A => "A",
        FilesystemSnapshotPhase::B => "B",
        FilesystemSnapshotPhase::C => "C",
    };
    let request = FilesystemCaptureRequest {
        snapshot_id: filesystem_snapshot_id(run_id, epoch, phase_name),
        phase,
    };
    match retained_mount_namespace {
        Some(namespace) => {
            if namespace.kind() != LinuxNamespaceKind::Mount {
                bail!("filesystem namespace capability is not a mount namespace");
            }
            let (root_device, root_inode) = namespace.mount_root_identity()?;
            namespace.run_with_mount_root(|| {
                capture_in_retained_mount_namespace(
                    scope,
                    &request,
                    namespace.inode(),
                    root_device,
                    root_inode,
                )
            })
        }
        None => capture_filesystem(scope, &request),
    }
}

pub(crate) fn compare_filesystem_endpoints(
    before: &FilesystemSnapshot,
    after: &FilesystemSnapshot,
) -> Result<FilesystemComparison> {
    // Static deployment-observer input is not an authenticated exclusive
    // writer contract.  Passing None preserves positive endpoint differences
    // while preventing an UNCHANGED_WITHIN_SCOPE or causal claim.
    compare_filesystem(before, after, None)
}

pub(crate) fn validate_filesystem_output_separation(
    scope: &FilesystemScope,
    output_directory: &Path,
) -> Result<()> {
    scope.validate()?;
    if scope.overlaps_path(output_directory)? {
        bail!("filesystem confirmation scope overlaps the observer output directory");
    }
    let physical_output = physical_path_with_missing_tail(output_directory)
        .context("resolve physical deployment evidence directory")?;
    for root in scope.decoded_roots()? {
        let physical_root = physical_path_with_missing_tail(&root)
            .with_context(|| format!("resolve physical filesystem root {}", root.display()))?;
        if paths_overlap(&physical_root, &physical_output) {
            bail!(
                "filesystem confirmation root {} physically overlaps deployment evidence {}",
                root.display(),
                output_directory.display()
            );
        }
    }
    Ok(())
}

fn physical_path_with_missing_tail(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        bail!("path must be absolute and lexically normalized");
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

pub(crate) struct EndpointContractEvidence<'a> {
    pub deployment_boot_id: &'a str,
    pub s0_boot_id: &'a str,
    pub s1_boot_id: &'a str,
    pub ready_barrier_complete: bool,
    pub ready_identity_stable: bool,
    pub pre_finish_barrier_complete: bool,
    pub pre_finish_identity_stable: bool,
    pub closure_barrier_complete: bool,
    pub closure_identity_stable: bool,
    pub recorder_drains_complete: bool,
}

pub(crate) fn endpoint_contract_reasons(
    evidence: &EndpointContractEvidence<'_>,
    extra: &[String],
) -> Vec<String> {
    let mut reasons = extra.to_vec();
    for (label, boot_id) in [("S0", evidence.s0_boot_id), ("S1", evidence.s1_boot_id)] {
        if boot_id != evidence.deployment_boot_id {
            reasons.push(format!(
                "{label} endpoint snapshot boot identity differs from the deployment manifest"
            ));
        }
    }
    for (condition, reason) in [
        (
            evidence.ready_barrier_complete,
            "deployment roots were not frozen at the final READY barrier",
        ),
        (
            evidence.ready_identity_stable,
            "deployment identity was not stable at the final READY barrier",
        ),
        (
            evidence.pre_finish_barrier_complete,
            "deployment roots were not frozen before recorder drain",
        ),
        (
            evidence.pre_finish_identity_stable,
            "deployment identity was not stable before recorder drain",
        ),
        (
            evidence.closure_barrier_complete,
            "deployment roots were not frozen after endpoint S1 capture",
        ),
        (
            evidence.closure_identity_stable,
            "deployment identity was not stable after endpoint S1 capture",
        ),
        (
            evidence.recorder_drains_complete,
            "every operation/lifecycle recorder did not reach its closed drain boundary before S1",
        ),
    ] {
        if !condition {
            reasons.push(reason.to_owned());
        }
    }
    canonical_reasons(&reasons)
}

pub(crate) fn filesystem_namespace_reasons(
    snapshot: &FilesystemSnapshot,
    deployment_mount_namespace_ids: &[u64],
    required_retained_mount_namespace_inode: Option<u64>,
    deployment_kind: DeploymentKind,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if !deployment_mount_namespace_ids.contains(&snapshot.mount_namespace_inode) {
        reasons.push(
            "filesystem scope was captured from an observer-visible mount namespace not committed as a deployment process namespace; the paths remain explicit host-view endpoints and are not container-root coverage"
                .to_owned(),
        );
    }
    if let Some(expected) = required_retained_mount_namespace_inode {
        if snapshot.mount_namespace_inode != expected
            || snapshot.mount_namespace_capture_source
                != MountNamespaceCaptureSource::RetainedFileDescriptor
        {
            reasons.push(
                "filesystem scope was not resolved through the required retained deployment mount namespace capability"
                    .to_owned(),
            );
        }
    }
    if deployment_kind == DeploymentKind::KataHost {
        reasons.push(
            "Kata host filesystem scope has no unique mount namespace: protocol v1 does not retain every backend owner mount namespace plus O_PATH backend identity"
                .to_owned(),
        );
    }
    canonical_reasons(&reasons)
}

/// Direct and Docker each have one authoritative filesystem namespace anchor.
/// Kata can have multiple QEMU/virtiofs/backend mount namespaces and protocol
/// v1 does not yet pin an object FD in each, so it must remain unbound.
pub(crate) fn filesystem_mount_namespace_target(
    manifest: &DeploymentManifest,
) -> Result<Option<NamespaceTarget>> {
    let role = match manifest.deployment_kind {
        DeploymentKind::Direct => ProcessRole::DirectRoot,
        DeploymentKind::Docker => ProcessRole::DockerInit,
        DeploymentKind::KataHost => return Ok(None),
    };
    let mut anchors = manifest
        .processes
        .iter()
        .filter(|process| process.role == role);
    let anchor = anchors
        .next()
        .with_context(|| format!("deployment has no {role:?} filesystem namespace anchor"))?;
    if anchors.next().is_some() {
        bail!("deployment has multiple {role:?} filesystem namespace anchors");
    }
    Ok(Some(NamespaceTarget {
        pid: anchor.pid,
        expected_namespace_inode: anchor.mount_namespace_id,
    }))
}

fn canonical_reasons(reasons: &[String]) -> Vec<String> {
    let mut reasons = reasons.to_vec();
    reasons.sort();
    reasons.dedup();
    reasons
}

fn validate_contract_reasons(complete: bool, reasons: &[String], label: &str) -> Result<()> {
    if !reasons.windows(2).all(|pair| pair[0] < pair[1]) || complete != reasons.is_empty() {
        bail!("{label} contract status/reasons are not canonical");
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
