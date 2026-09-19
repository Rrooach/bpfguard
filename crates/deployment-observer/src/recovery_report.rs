// SPDX-License-Identifier: GPL-2.0-only

//! Recovery-specific A/B/C endpoint evidence.
//!
//! This module is deliberately pure: it maps already-produced endpoint
//! comparisons into phase-neutral pair deltas and derives the recovery
//! consistency verdict.  It does not run a recovery helper, capture state, or
//! trust the `UNCHANGED_WITHIN_SCOPE` authority of an underlying comparer.

use anyhow::{bail, Context, Result};
use bpf_observer_deployment::DeploymentManifest;
use bpf_observer_filesystem_confirmer::{
    ChangedField as FilesystemChangedField, CompletenessStatus as FilesystemCompletenessStatus,
    EndpointDifferenceStatus as FilesystemEndpointDifferenceStatus, FilesystemChangeKind,
    FilesystemComparison, FilesystemSnapshot, RootCaptureStatus,
    SnapshotPhase as FilesystemSnapshotPhase,
};
use bpf_observer_linux_state_confirmers::{
    ChangeKind as LinuxChangeKind, CompletenessStatus as LinuxCompletenessStatus,
    DomainComparison as LinuxDomainComparison, DomainKind as LinuxDomainKind,
    EndpointDifferenceStatus as LinuxEndpointDifferenceStatus, SnapshotPhase as LinuxSnapshotPhase,
    StateComparison as LinuxStateComparison, StateSnapshot as LinuxStateSnapshot,
};
use bpf_observer_schema::{
    ChangeCertainty, ChangeKind as BpfChangeKind, CompletenessStatus as BpfCompletenessStatus,
    EvidenceHealth, ObjectIdentity, Snapshot as BpfSnapshot, StateChange as BpfStateChange,
    StateVerdict as BpfStateVerdict, Verdict as BpfVerdict, MAX_SNAPSHOT_JSON_BYTES,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::protocol::DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION;
use crate::scope::CgroupScopeCapability;

pub const RECOVERY_REPORT_SCHEMA_VERSION: u32 = 1;

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 4096;
const MAX_REASON_BYTES: usize = 4096;
const MAX_REASONS: usize = 4096;
const MAX_OBJECTS: usize = 2_000_000;
const MAX_NAMESPACES: usize = 65_536;
const MAX_ENCODED_REPORT_BYTES: usize = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoverySnapshotPhase {
    A,
    B,
    C,
}

impl RecoverySnapshotPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryDomain {
    Bpf,
    Filesystem,
    Sysctl,
    Mount,
    Network,
    Modules,
    ProcessResidual,
}

impl RecoveryDomain {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bpf => "BPF",
            Self::Filesystem => "FILESYSTEM",
            Self::Sysctl => "SYSCTL",
            Self::Mount => "MOUNT",
            Self::Network => "NETWORK",
            Self::Modules => "MODULES",
            Self::ProcessResidual => "PROCESS_RESIDUAL",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotDomainBinding {
    pub artifact_relative_path: String,
    pub artifact_size_bytes: u64,
    pub artifact_sha256: String,
    pub raw_snapshot_id: String,
    pub raw_phase: String,
    /// Logical domains carried by this artifact. BPF and filesystem bindings
    /// contain exactly one domain; a Linux-state artifact can carry any
    /// canonical non-empty subset of its five domains.
    pub domains: Vec<RecoveryDomain>,
}

impl SnapshotDomainBinding {
    pub fn new(
        phase: RecoverySnapshotPhase,
        raw_phase: impl Into<String>,
        artifact_relative_path: impl Into<String>,
        artifact_size_bytes: u64,
        artifact_sha256: impl Into<String>,
        raw_snapshot_id: impl Into<String>,
        domains: Vec<RecoveryDomain>,
    ) -> Result<Self> {
        let binding = Self {
            artifact_relative_path: artifact_relative_path.into(),
            artifact_size_bytes,
            artifact_sha256: artifact_sha256.into(),
            raw_snapshot_id: raw_snapshot_id.into(),
            raw_phase: raw_phase.into(),
            domains,
        };
        binding.validate_common(phase)?;
        Ok(binding)
    }

    fn validate_common(&self, phase: RecoverySnapshotPhase) -> Result<()> {
        validate_relative_artifact_path(&self.artifact_relative_path)?;
        if self.artifact_size_bytes == 0 || self.artifact_size_bytes > MAX_SNAPSHOT_JSON_BYTES {
            bail!("snapshot artifact size is zero or exceeds the hard snapshot bound");
        }
        validate_sha256(&self.artifact_sha256, "snapshot artifact")?;
        validate_identifier(&self.raw_snapshot_id, "raw snapshot_id")?;
        let phase_mapping_valid = matches!(
            (phase, self.raw_phase.as_str()),
            (RecoverySnapshotPhase::A, "S0")
                | (RecoverySnapshotPhase::A, "A")
                | (RecoverySnapshotPhase::B, "B")
                | (RecoverySnapshotPhase::C, "C")
        );
        if !phase_mapping_valid {
            bail!("snapshot-domain raw phase is not a valid recovery-envelope phase mapping");
        }
        ensure_sorted_unique(&self.domains, "snapshot-domain logical domains")?;
        if self.domains.is_empty() {
            bail!("snapshot-domain binding has an empty logical domain set");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRootCgroupBinding {
    pub cgroup_id: u64,
    pub path: String,
}

impl RecoveryRootCgroupBinding {
    fn validate(&self) -> Result<()> {
        if self.cgroup_id == 0 {
            bail!("recovery snapshot root cgroup ID must be nonzero");
        }
        validate_cgroup_path(&self.path)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySnapshotEnvelope {
    pub schema_version: u32,
    pub protocol_version: u32,
    pub phase: RecoverySnapshotPhase,
    pub run_id: String,
    pub epoch: u64,
    pub checkpoint_id: String,
    pub recovery_id: String,
    pub snapshot_id: String,
    pub capture_started_unix_ns: u128,
    pub capture_completed_unix_ns: u128,
    pub boot_id: String,
    pub deployment_scope_sha256: String,
    pub cgroup_scope_capability: CgroupScopeCapability,
    pub cgroup_scope_capability_sha256: String,
    pub root_cgroups: Vec<RecoveryRootCgroupBinding>,
    pub mount_namespace_ids: Vec<u64>,
    pub pid_namespace_ids: Vec<u64>,
    pub net_namespace_ids: Vec<u64>,
    pub uts_namespace_ids: Vec<u64>,
    pub ipc_namespace_ids: Vec<u64>,
    pub barrier_sha256: String,
    pub identity_assessment_sha256: String,
    pub bpf: Option<SnapshotDomainBinding>,
    pub filesystem: Option<SnapshotDomainBinding>,
    pub linux: Option<SnapshotDomainBinding>,
}

impl RecoverySnapshotEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn from_deployment_manifest(
        phase: RecoverySnapshotPhase,
        run_id: impl Into<String>,
        epoch: u64,
        checkpoint_id: impl Into<String>,
        recovery_id: impl Into<String>,
        snapshot_id: impl Into<String>,
        capture_started_unix_ns: u128,
        capture_completed_unix_ns: u128,
        deployment: &DeploymentManifest,
        cgroup_scope_capability: CgroupScopeCapability,
        barrier_sha256: impl Into<String>,
        identity_assessment_sha256: impl Into<String>,
        bpf: Option<SnapshotDomainBinding>,
        filesystem: Option<SnapshotDomainBinding>,
        linux: Option<SnapshotDomainBinding>,
    ) -> Result<Self> {
        deployment.validate()?;
        let mut root_cgroups = deployment
            .root_cgroups
            .iter()
            .map(|root| RecoveryRootCgroupBinding {
                cgroup_id: root.cgroup_id,
                path: root.path.clone(),
            })
            .collect::<Vec<_>>();
        root_cgroups.sort();
        let mut pid_namespace_ids = deployment
            .processes
            .iter()
            .map(|process| process.pid_namespace_id)
            .collect::<Vec<_>>();
        pid_namespace_ids.sort_unstable();
        pid_namespace_ids.dedup();
        let cgroup_scope_capability_sha256 = cgroup_scope_capability.sha256()?;
        let envelope = Self {
            schema_version: RECOVERY_REPORT_SCHEMA_VERSION,
            protocol_version: DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
            phase,
            run_id: run_id.into(),
            epoch,
            checkpoint_id: checkpoint_id.into(),
            recovery_id: recovery_id.into(),
            snapshot_id: snapshot_id.into(),
            capture_started_unix_ns,
            capture_completed_unix_ns,
            boot_id: deployment.boot_id.clone(),
            deployment_scope_sha256: deployment.scope_sha256.clone(),
            cgroup_scope_capability,
            cgroup_scope_capability_sha256,
            root_cgroups,
            mount_namespace_ids: deployment.mount_namespace_ids.clone(),
            pid_namespace_ids,
            net_namespace_ids: deployment.net_namespace_ids.clone(),
            uts_namespace_ids: deployment.uts_namespace_ids.clone(),
            ipc_namespace_ids: deployment.ipc_namespace_ids.clone(),
            barrier_sha256: barrier_sha256.into(),
            identity_assessment_sha256: identity_assessment_sha256.into(),
            bpf,
            filesystem,
            linux,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != RECOVERY_REPORT_SCHEMA_VERSION
            || self.protocol_version != DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION
        {
            bail!("unsupported recovery snapshot envelope schema/protocol version");
        }
        validate_identifier(&self.run_id, "run_id")?;
        validate_identifier(&self.checkpoint_id, "checkpoint_id")?;
        validate_identifier(&self.recovery_id, "recovery_id")?;
        validate_identifier(&self.snapshot_id, "snapshot_id")?;
        if self.epoch == 0 {
            bail!("recovery snapshot epoch must be nonzero");
        }
        if self.capture_started_unix_ns == 0
            || self.capture_completed_unix_ns < self.capture_started_unix_ns
        {
            bail!("recovery snapshot capture interval is invalid");
        }
        validate_uuid(&self.boot_id, "boot_id")?;
        validate_sha256(&self.deployment_scope_sha256, "deployment scope")?;
        validate_sha256(&self.cgroup_scope_capability_sha256, "cgroup capability")?;
        validate_sha256(&self.barrier_sha256, "snapshot barrier")?;
        validate_sha256(&self.identity_assessment_sha256, "identity assessment")?;
        self.cgroup_scope_capability.validate()?;
        if self.cgroup_scope_capability.sha256()? != self.cgroup_scope_capability_sha256 {
            bail!("recovery snapshot cgroup capability digest does not recompute");
        }
        ensure_sorted_unique(&self.root_cgroups, "recovery root cgroups")?;
        if self.root_cgroups.is_empty()
            || self.root_cgroups.len() > self.cgroup_scope_capability.maximum_roots as usize
        {
            bail!("recovery snapshot root-cgroup cardinality is invalid");
        }
        for root in &self.root_cgroups {
            root.validate()?;
        }
        let mut root_ids = self
            .root_cgroups
            .iter()
            .map(|root| root.cgroup_id)
            .collect::<Vec<_>>();
        root_ids.sort_unstable();
        if root_ids.windows(2).any(|pair| pair[0] == pair[1])
            || root_ids != self.cgroup_scope_capability.root_cgroup_ids
        {
            bail!("recovery root cgroups do not exactly match the cgroup capability");
        }
        validate_namespace_ids(&self.mount_namespace_ids, "mount")?;
        validate_namespace_ids(&self.pid_namespace_ids, "PID")?;
        validate_namespace_ids(&self.net_namespace_ids, "network")?;
        validate_namespace_ids(&self.uts_namespace_ids, "UTS")?;
        validate_namespace_ids(&self.ipc_namespace_ids, "IPC")?;

        if let Some(binding) = &self.bpf {
            binding.validate_common(self.phase)?;
            if binding.domains != [RecoveryDomain::Bpf] {
                bail!("BPF snapshot binding must contain exactly the BPF domain");
            }
        }
        if let Some(binding) = &self.filesystem {
            binding.validate_common(self.phase)?;
            if binding.domains != [RecoveryDomain::Filesystem] {
                bail!("filesystem snapshot binding must contain exactly the filesystem domain");
            }
        }
        if let Some(binding) = &self.linux {
            binding.validate_common(self.phase)?;
            if binding
                .domains
                .iter()
                .any(|domain| matches!(domain, RecoveryDomain::Bpf | RecoveryDomain::Filesystem))
            {
                bail!("Linux snapshot binding contains a non-Linux logical domain");
            }
        }
        Ok(())
    }

    pub fn sha256(&self) -> Result<String> {
        self.validate()?;
        sha256_json(self)
    }

    fn enabled_domains(&self) -> BTreeSet<RecoveryDomain> {
        self.bpf
            .iter()
            .chain(self.filesystem.iter())
            .chain(self.linux.iter())
            .flat_map(|binding| binding.domains.iter().copied())
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryPairKind {
    AgentDelta,
    RecoveryDelta,
    ResidualDelta,
}

impl RecoveryPairKind {
    fn phases(self) -> (RecoverySnapshotPhase, RecoverySnapshotPhase) {
        match self {
            Self::AgentDelta => (RecoverySnapshotPhase::A, RecoverySnapshotPhase::B),
            Self::RecoveryDelta => (RecoverySnapshotPhase::B, RecoverySnapshotPhase::C),
            Self::ResidualDelta => (RecoverySnapshotPhase::A, RecoverySnapshotPhase::C),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryEndpointStatus {
    NotEnabled,
    ObservedIdentical,
    ObservedDifferent,
    Indeterminate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDomainOutcome {
    pub enabled: bool,
    pub endpoint_status: RecoveryEndpointStatus,
    pub complete: bool,
    pub change_count: u64,
    pub reasons: Vec<String>,
    pub comparison_sha256: Option<String>,
}

impl RecoveryDomainOutcome {
    fn disabled() -> Self {
        Self {
            enabled: false,
            endpoint_status: RecoveryEndpointStatus::NotEnabled,
            complete: false,
            change_count: 0,
            reasons: vec!["domain was not enabled in the recovery snapshot scope".to_owned()],
            comparison_sha256: None,
        }
    }

    fn unavailable() -> Self {
        Self {
            enabled: true,
            endpoint_status: RecoveryEndpointStatus::Indeterminate,
            complete: false,
            change_count: 0,
            reasons: vec!["comparison is unavailable for an enabled recovery domain".to_owned()],
            comparison_sha256: None,
        }
    }

    fn validate(&self) -> Result<()> {
        validate_reasons(&self.reasons)?;
        if let Some(digest) = &self.comparison_sha256 {
            validate_sha256(digest, "domain comparison")?;
        }
        if !self.enabled {
            if self.endpoint_status != RecoveryEndpointStatus::NotEnabled
                || self.complete
                || self.change_count != 0
                || self.comparison_sha256.is_some()
            {
                bail!("disabled recovery domain has evidence claims");
            }
            return Ok(());
        }
        if self.endpoint_status == RecoveryEndpointStatus::NotEnabled {
            bail!("enabled recovery domain is marked NOT_ENABLED");
        }
        if self.complete {
            if !self.reasons.is_empty() || self.comparison_sha256.is_none() {
                bail!("complete recovery domain has reasons or lacks a comparison digest");
            }
            let expected = if self.change_count == 0 {
                RecoveryEndpointStatus::ObservedIdentical
            } else {
                RecoveryEndpointStatus::ObservedDifferent
            };
            if self.endpoint_status != expected {
                bail!("complete recovery domain endpoint status disagrees with its changes");
            }
        } else if self.endpoint_status != RecoveryEndpointStatus::Indeterminate {
            bail!("incomplete recovery domain must have an indeterminate endpoint");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDomainVector {
    pub bpf: RecoveryDomainOutcome,
    pub filesystem: RecoveryDomainOutcome,
    pub sysctl: RecoveryDomainOutcome,
    pub mount: RecoveryDomainOutcome,
    pub network: RecoveryDomainOutcome,
    pub modules: RecoveryDomainOutcome,
    pub process_residual: RecoveryDomainOutcome,
}

impl RecoveryDomainVector {
    fn get(&self, domain: RecoveryDomain) -> &RecoveryDomainOutcome {
        match domain {
            RecoveryDomain::Bpf => &self.bpf,
            RecoveryDomain::Filesystem => &self.filesystem,
            RecoveryDomain::Sysctl => &self.sysctl,
            RecoveryDomain::Mount => &self.mount,
            RecoveryDomain::Network => &self.network,
            RecoveryDomain::Modules => &self.modules,
            RecoveryDomain::ProcessResidual => &self.process_residual,
        }
    }

    fn all(&self) -> [(RecoveryDomain, &RecoveryDomainOutcome); 7] {
        [
            (RecoveryDomain::Bpf, &self.bpf),
            (RecoveryDomain::Filesystem, &self.filesystem),
            (RecoveryDomain::Sysctl, &self.sysctl),
            (RecoveryDomain::Mount, &self.mount),
            (RecoveryDomain::Network, &self.network),
            (RecoveryDomain::Modules, &self.modules),
            (RecoveryDomain::ProcessResidual, &self.process_residual),
        ]
    }

    fn validate(&self) -> Result<()> {
        for (_, outcome) in self.all() {
            outcome.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryChangeKind {
    Added,
    Removed,
    Modified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryObjectRef {
    pub domain: RecoveryDomain,
    /// Unambiguous, domain-prefixed identity. BPF keys encode
    /// entity+identity+field; filesystem keys encode root+path; Linux keys
    /// encode domain+record key.
    pub canonical_key: String,
    pub change_kind: RecoveryChangeKind,
    pub before_sha256: Option<String>,
    pub after_sha256: Option<String>,
    pub changed_fields: Vec<String>,
    /// True only after the complete raw A/B/C snapshots have been checked
    /// against the corresponding pair comparison and this object's endpoint
    /// fingerprints have been derived from those snapshots.
    pub raw_value_confirmed: bool,
}

impl RecoveryObjectRef {
    fn validate(&self) -> Result<()> {
        if self.canonical_key.is_empty()
            || self.canonical_key.len() > MAX_PATH_BYTES * 4
            || self.canonical_key.contains('\0')
            || self.canonical_key.contains('\n')
        {
            bail!("recovery object canonical key is empty or exceeds its bound");
        }
        if !self
            .canonical_key
            .starts_with(&format!("{}:", self.domain.as_str().to_ascii_lowercase()))
        {
            bail!("recovery object canonical key has the wrong domain prefix");
        }
        if let Some(value) = &self.before_sha256 {
            validate_sha256(value, "object before value")?;
        }
        if let Some(value) = &self.after_sha256 {
            validate_sha256(value, "object after value")?;
        }
        if self.raw_value_confirmed {
            if self.before_sha256 == self.after_sha256 {
                bail!("raw-confirmed recovery change has identical endpoint values");
            }
            match self.change_kind {
                RecoveryChangeKind::Added
                    if self.before_sha256.is_some() || self.after_sha256.is_none() =>
                {
                    bail!("raw-confirmed added object has invalid presence semantics");
                }
                RecoveryChangeKind::Removed
                    if self.before_sha256.is_none() || self.after_sha256.is_some() =>
                {
                    bail!("raw-confirmed removed object has invalid presence semantics");
                }
                RecoveryChangeKind::Modified
                    if self.before_sha256.is_none() || self.after_sha256.is_none() =>
                {
                    bail!("raw-confirmed modified object has invalid presence semantics");
                }
                _ => {}
            }
        }
        ensure_sorted_unique(&self.changed_fields, "object changed fields")?;
        if self
            .changed_fields
            .iter()
            .any(|field| field.is_empty() || field.len() > MAX_IDENTIFIER_BYTES)
        {
            bail!("recovery object changed field is empty or oversized");
        }
        Ok(())
    }

    fn identity(&self) -> (RecoveryDomain, &str) {
        (self.domain, self.canonical_key.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPairDelta {
    pub schema_version: u32,
    pub protocol_version: u32,
    pub pair: RecoveryPairKind,
    pub before_phase: RecoverySnapshotPhase,
    pub after_phase: RecoverySnapshotPhase,
    pub before_snapshot_id: String,
    pub after_snapshot_id: String,
    pub domains: RecoveryDomainVector,
    pub objects: Vec<RecoveryObjectRef>,
}

impl RecoveryPairDelta {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != RECOVERY_REPORT_SCHEMA_VERSION
            || self.protocol_version != DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION
        {
            bail!("unsupported recovery pair-delta schema/protocol version");
        }
        if (self.before_phase, self.after_phase) != self.pair.phases() {
            bail!("recovery pair phases do not match the declared pair kind");
        }
        validate_identifier(&self.before_snapshot_id, "before snapshot_id")?;
        validate_identifier(&self.after_snapshot_id, "after snapshot_id")?;
        if self.before_snapshot_id == self.after_snapshot_id {
            bail!("recovery pair must bind distinct snapshot IDs");
        }
        self.domains.validate()?;
        validate_objects(&self.objects)?;
        for (domain, outcome) in self.domains.all() {
            let count = self
                .objects
                .iter()
                .filter(|object| object.domain == domain)
                .count() as u64;
            if outcome.change_count != count {
                bail!("recovery domain change count does not match its object vector");
            }
        }
        Ok(())
    }

    pub fn sha256(&self) -> Result<String> {
        self.validate()?;
        sha256_json(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryObjectClassifications {
    /// Agent changes whose A/B/C raw values prove A==C and A!=B.
    pub restored: Vec<RecoveryObjectRef>,
    /// Every Agent-changed canonical key that remains different in A->C.
    /// `partially_restored` is intentionally a subset of this vector.
    pub unrecovered: Vec<RecoveryObjectRef>,
    /// Conservative annotation for unrecovered keys that recovery changed
    /// away from B but did not return to A, or for which a strict subset of
    /// the Agent-changed filesystem fields remains.
    pub partially_restored: Vec<RecoveryObjectRef>,
    /// A->C differences on canonical keys absent from A->B.
    pub recovery_introduced: Vec<RecoveryObjectRef>,
    /// Any object for which complete raw endpoint value continuity is not
    /// available. It must never be silently classified as restored.
    pub unresolved: Vec<RecoveryObjectRef>,
}

impl RecoveryObjectClassifications {
    fn validate(&self) -> Result<()> {
        validate_objects(&self.restored)?;
        validate_objects(&self.unrecovered)?;
        validate_objects(&self.partially_restored)?;
        validate_objects(&self.recovery_introduced)?;
        validate_objects(&self.unresolved)?;
        let unrecovered = identity_set(&self.unrecovered);
        if self
            .partially_restored
            .iter()
            .any(|object| !unrecovered.contains(&object.identity()))
        {
            bail!("partially-restored objects must be a subset of unrecovered objects");
        }
        let mut unique = BTreeSet::new();
        for category in [
            &self.restored,
            &self.unrecovered,
            &self.recovery_introduced,
            &self.unresolved,
        ] {
            for object in category {
                if !unique.insert(object.identity()) {
                    bail!("recovery object belongs to multiple exclusive classifications");
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryConsistencyVerdict {
    ConsistentWithinScope,
    InconsistentWithinScope,
    Inconclusive,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryVerdictReport {
    pub schema_version: u32,
    pub protocol_version: u32,
    pub run_id: String,
    pub epoch: u64,
    pub checkpoint_id: String,
    pub recovery_id: String,
    pub snapshot_a_id: String,
    pub snapshot_b_id: String,
    pub snapshot_c_id: String,
    pub snapshot_a_sha256: String,
    pub snapshot_b_sha256: String,
    pub snapshot_c_sha256: String,
    pub agent_delta: RecoveryPairDelta,
    pub recovery_delta: RecoveryPairDelta,
    pub residual_delta: RecoveryPairDelta,
    pub classifications: RecoveryObjectClassifications,
    /// A claim made by the producer only. The offline verifier must repeat
    /// raw artifact binding and A/B/C value-chain reconstruction before
    /// accepting it.
    pub raw_endpoint_proof_complete: bool,
    pub state_complete: bool,
    pub external_incompleteness_reasons: Vec<String>,
    pub incompleteness_reasons: Vec<String>,
    pub verdict: RecoveryConsistencyVerdict,
    pub limitations: Vec<String>,
}

impl RecoveryVerdictReport {
    /// Legacy comparison-only constructor. It deliberately cannot establish
    /// raw endpoint proof and therefore always remains `INCONCLUSIVE`.
    #[allow(clippy::too_many_arguments)]
    pub fn from_pair_deltas(
        run_id: impl Into<String>,
        epoch: u64,
        checkpoint_id: impl Into<String>,
        recovery_id: impl Into<String>,
        snapshot_a_sha256: impl Into<String>,
        snapshot_b_sha256: impl Into<String>,
        snapshot_c_sha256: impl Into<String>,
        agent_delta: RecoveryPairDelta,
        recovery_delta: RecoveryPairDelta,
        residual_delta: RecoveryPairDelta,
        external_incompleteness_reasons: Vec<String>,
    ) -> Result<Self> {
        Self::from_pair_deltas_with_raw_status(
            run_id,
            epoch,
            checkpoint_id,
            recovery_id,
            snapshot_a_sha256,
            snapshot_b_sha256,
            snapshot_c_sha256,
            agent_delta,
            recovery_delta,
            residual_delta,
            external_incompleteness_reasons,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_pair_deltas_with_raw_status(
        run_id: impl Into<String>,
        epoch: u64,
        checkpoint_id: impl Into<String>,
        recovery_id: impl Into<String>,
        snapshot_a_sha256: impl Into<String>,
        snapshot_b_sha256: impl Into<String>,
        snapshot_c_sha256: impl Into<String>,
        agent_delta: RecoveryPairDelta,
        recovery_delta: RecoveryPairDelta,
        residual_delta: RecoveryPairDelta,
        external_incompleteness_reasons: Vec<String>,
        raw_endpoint_proof_complete: bool,
    ) -> Result<Self> {
        agent_delta.validate()?;
        recovery_delta.validate()?;
        residual_delta.validate()?;
        let classifications = classify_objects(&agent_delta, &recovery_delta, &residual_delta)?;
        let mut incompleteness_reasons =
            comparison_incompleteness_reasons(&agent_delta, &recovery_delta, &residual_delta);
        let mut external = external_incompleteness_reasons;
        canonicalize_reasons(&mut external)?;
        incompleteness_reasons.extend(external.iter().cloned());
        canonicalize_reasons(&mut incompleteness_reasons)?;
        let enabled_count = agent_delta
            .domains
            .all()
            .iter()
            .filter(|(_, outcome)| outcome.enabled)
            .count();
        if enabled_count == 0 {
            insert_reason(
                &mut incompleteness_reasons,
                "no endpoint confirmation domain is enabled",
            )?;
        }
        if !raw_endpoint_proof_complete {
            insert_reason(
                &mut incompleteness_reasons,
                "complete raw A/B/C endpoint proof was not established",
            )?;
        }
        if !classifications.unresolved.is_empty() {
            insert_reason(
                &mut incompleteness_reasons,
                "one or more object restoration classifications are unresolved",
            )?;
        }
        let state_complete = incompleteness_reasons.is_empty();
        let verdict = if !state_complete {
            RecoveryConsistencyVerdict::Inconclusive
        } else if residual_delta.objects.is_empty() {
            RecoveryConsistencyVerdict::ConsistentWithinScope
        } else {
            RecoveryConsistencyVerdict::InconsistentWithinScope
        };
        let report = Self {
            schema_version: RECOVERY_REPORT_SCHEMA_VERSION,
            protocol_version: DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
            run_id: run_id.into(),
            epoch,
            checkpoint_id: checkpoint_id.into(),
            recovery_id: recovery_id.into(),
            snapshot_a_id: agent_delta.before_snapshot_id.clone(),
            snapshot_b_id: agent_delta.after_snapshot_id.clone(),
            snapshot_c_id: recovery_delta.after_snapshot_id.clone(),
            snapshot_a_sha256: snapshot_a_sha256.into(),
            snapshot_b_sha256: snapshot_b_sha256.into(),
            snapshot_c_sha256: snapshot_c_sha256.into(),
            agent_delta,
            recovery_delta,
            residual_delta,
            classifications,
            raw_endpoint_proof_complete,
            state_complete,
            external_incompleteness_reasons: external,
            incompleteness_reasons,
            verdict,
            limitations: canonical_limitations(),
        };
        report.validate()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != RECOVERY_REPORT_SCHEMA_VERSION
            || self.protocol_version != DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION
        {
            bail!("unsupported recovery verdict schema/protocol version");
        }
        validate_identifier(&self.run_id, "run_id")?;
        validate_identifier(&self.checkpoint_id, "checkpoint_id")?;
        validate_identifier(&self.recovery_id, "recovery_id")?;
        if self.epoch == 0 {
            bail!("recovery verdict epoch must be nonzero");
        }
        validate_sha256(&self.snapshot_a_sha256, "snapshot A envelope")?;
        validate_sha256(&self.snapshot_b_sha256, "snapshot B envelope")?;
        validate_sha256(&self.snapshot_c_sha256, "snapshot C envelope")?;
        self.agent_delta.validate()?;
        self.recovery_delta.validate()?;
        self.residual_delta.validate()?;
        if self.agent_delta.pair != RecoveryPairKind::AgentDelta
            || self.recovery_delta.pair != RecoveryPairKind::RecoveryDelta
            || self.residual_delta.pair != RecoveryPairKind::ResidualDelta
            || self.snapshot_a_id != self.agent_delta.before_snapshot_id
            || self.snapshot_b_id != self.agent_delta.after_snapshot_id
            || self.snapshot_b_id != self.recovery_delta.before_snapshot_id
            || self.snapshot_c_id != self.recovery_delta.after_snapshot_id
            || self.snapshot_a_id != self.residual_delta.before_snapshot_id
            || self.snapshot_c_id != self.residual_delta.after_snapshot_id
        {
            bail!("recovery verdict pair/snapshot chain is not A->B->C");
        }
        for domain in all_domains() {
            let enabled = self.agent_delta.domains.get(domain).enabled;
            if self.recovery_delta.domains.get(domain).enabled != enabled
                || self.residual_delta.domains.get(domain).enabled != enabled
            {
                bail!("recovery domain enablement differs across pair deltas");
            }
        }
        self.classifications.validate()?;
        let expected_classifications = classify_objects(
            &self.agent_delta,
            &self.recovery_delta,
            &self.residual_delta,
        )?;
        if self.classifications != expected_classifications {
            bail!("recovery object classifications do not recompute");
        }
        validate_reasons(&self.external_incompleteness_reasons)?;
        validate_reasons(&self.incompleteness_reasons)?;
        let mut expected_reasons = comparison_incompleteness_reasons(
            &self.agent_delta,
            &self.recovery_delta,
            &self.residual_delta,
        );
        expected_reasons.extend(self.external_incompleteness_reasons.iter().cloned());
        if !self
            .agent_delta
            .domains
            .all()
            .iter()
            .any(|(_, value)| value.enabled)
        {
            expected_reasons.push("no endpoint confirmation domain is enabled".to_owned());
        }
        if !self.raw_endpoint_proof_complete {
            expected_reasons
                .push("complete raw A/B/C endpoint proof was not established".to_owned());
        }
        if !self.classifications.unresolved.is_empty() {
            expected_reasons
                .push("one or more object restoration classifications are unresolved".to_owned());
        }
        canonicalize_reasons(&mut expected_reasons)?;
        if expected_reasons != self.incompleteness_reasons {
            bail!("recovery verdict incompleteness reasons do not recompute");
        }
        let expected_complete = expected_reasons.is_empty();
        let expected_verdict = if !expected_complete {
            RecoveryConsistencyVerdict::Inconclusive
        } else if self.residual_delta.objects.is_empty() {
            RecoveryConsistencyVerdict::ConsistentWithinScope
        } else {
            RecoveryConsistencyVerdict::InconsistentWithinScope
        };
        if self.state_complete != expected_complete || self.verdict != expected_verdict {
            bail!("recovery consistency verdict does not recompute");
        }
        let expected_limitations = canonical_limitations();
        if self.limitations != expected_limitations {
            bail!("recovery verdict limitations differ from the protocol contract");
        }
        let encoded = serde_json::to_vec(self).context("serialize recovery verdict")?;
        if encoded.len() > MAX_ENCODED_REPORT_BYTES {
            bail!("recovery verdict exceeds the encoded artifact bound");
        }
        Ok(())
    }

    pub fn sha256(&self) -> Result<String> {
        self.validate()?;
        sha256_json(self)
    }
}

/// Borrowed comparison inputs for one endpoint pair. Missing input for a
/// domain enabled by the snapshot envelope is represented as incomplete,
/// rather than silently treating the domain as disabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct RecoveryComparisonSet<'a> {
    pub bpf: Option<&'a BpfVerdict>,
    pub filesystem: Option<&'a FilesystemComparison>,
    pub linux: Option<&'a LinuxStateComparison>,
}

#[derive(Clone, Copy, Debug)]
pub struct RecoveryComparisonTriplet<'a> {
    pub agent: RecoveryComparisonSet<'a>,
    pub recovery: RecoveryComparisonSet<'a>,
    pub residual: RecoveryComparisonSet<'a>,
}

#[derive(Clone, Copy, Debug)]
pub struct RecoverySnapshotTriplet<'a> {
    pub a: &'a RecoverySnapshotEnvelope,
    pub b: &'a RecoverySnapshotEnvelope,
    pub c: &'a RecoverySnapshotEnvelope,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RecoveryRawSnapshotSet<'a> {
    pub bpf: Option<&'a BpfSnapshot>,
    pub filesystem: Option<&'a FilesystemSnapshot>,
    pub linux: Option<&'a LinuxStateSnapshot>,
}

#[derive(Clone, Copy, Debug)]
pub struct RecoveryRawSnapshotTriplet<'a> {
    pub a: RecoveryRawSnapshotSet<'a>,
    pub b: RecoveryRawSnapshotSet<'a>,
    pub c: RecoveryRawSnapshotSet<'a>,
}

/// Comparison-only convenience builder. Use
/// [`build_recovery_verdict_report_with_raw`] for a confirmable verdict.
pub fn build_recovery_verdict_report(
    snapshots: RecoverySnapshotTriplet<'_>,
    comparisons: RecoveryComparisonTriplet<'_>,
    external_incompleteness_reasons: &[String],
) -> Result<RecoveryVerdictReport> {
    validate_snapshot_triplet(snapshots)?;
    let agent_delta = build_recovery_pair_delta(
        RecoveryPairKind::AgentDelta,
        snapshots.a,
        snapshots.b,
        comparisons.agent,
    )?;
    let recovery_delta = build_recovery_pair_delta(
        RecoveryPairKind::RecoveryDelta,
        snapshots.b,
        snapshots.c,
        comparisons.recovery,
    )?;
    let residual_delta = build_recovery_pair_delta(
        RecoveryPairKind::ResidualDelta,
        snapshots.a,
        snapshots.c,
        comparisons.residual,
    )?;
    RecoveryVerdictReport::from_pair_deltas(
        snapshots.a.run_id.clone(),
        snapshots.a.epoch,
        snapshots.a.checkpoint_id.clone(),
        snapshots.a.recovery_id.clone(),
        snapshots.a.sha256()?,
        snapshots.b.sha256()?,
        snapshots.c.sha256()?,
        agent_delta,
        recovery_delta,
        residual_delta,
        external_incompleteness_reasons.to_vec(),
    )
}

/// Build a recovery verdict only after checking the three complete raw
/// endpoints and independently recomputing every supplied pair comparison.
/// The raw object fingerprints are the authority for restoration labels;
/// missing raw evidence leaves those labels unresolved and the verdict
/// inconclusive, even if the comparison JSON claims an empty residual delta.
pub fn build_recovery_verdict_report_with_raw(
    snapshots: RecoverySnapshotTriplet<'_>,
    raw: RecoveryRawSnapshotTriplet<'_>,
    comparisons: RecoveryComparisonTriplet<'_>,
    external_incompleteness_reasons: &[String],
) -> Result<RecoveryVerdictReport> {
    validate_snapshot_triplet(snapshots)?;
    validate_raw_set(snapshots.a, raw.a)?;
    validate_raw_set(snapshots.b, raw.b)?;
    validate_raw_set(snapshots.c, raw.c)?;

    let mut agent_delta = build_recovery_pair_delta(
        RecoveryPairKind::AgentDelta,
        snapshots.a,
        snapshots.b,
        comparisons.agent,
    )?;
    let mut recovery_delta = build_recovery_pair_delta(
        RecoveryPairKind::RecoveryDelta,
        snapshots.b,
        snapshots.c,
        comparisons.recovery,
    )?;
    let mut residual_delta = build_recovery_pair_delta(
        RecoveryPairKind::ResidualDelta,
        snapshots.a,
        snapshots.c,
        comparisons.residual,
    )?;

    let agent_raw_complete =
        enrich_pair_from_raw(&mut agent_delta, raw.a, raw.b, comparisons.agent)?;
    let recovery_raw_complete =
        enrich_pair_from_raw(&mut recovery_delta, raw.b, raw.c, comparisons.recovery)?;
    let residual_raw_complete =
        enrich_pair_from_raw(&mut residual_delta, raw.a, raw.c, comparisons.residual)?;
    let raw_endpoint_proof_complete =
        agent_raw_complete && recovery_raw_complete && residual_raw_complete;
    RecoveryVerdictReport::from_pair_deltas_with_raw_status(
        snapshots.a.run_id.clone(),
        snapshots.a.epoch,
        snapshots.a.checkpoint_id.clone(),
        snapshots.a.recovery_id.clone(),
        snapshots.a.sha256()?,
        snapshots.b.sha256()?,
        snapshots.c.sha256()?,
        agent_delta,
        recovery_delta,
        residual_delta,
        external_incompleteness_reasons.to_vec(),
        raw_endpoint_proof_complete,
    )
}

fn validate_raw_set(
    envelope: &RecoverySnapshotEnvelope,
    raw: RecoveryRawSnapshotSet<'_>,
) -> Result<()> {
    match (&envelope.bpf, raw.bpf) {
        (None, Some(_)) => bail!("raw BPF snapshot supplied for a disabled domain"),
        (Some(binding), Some(snapshot)) => {
            bpf_observer_oracle::validate_snapshot_resource_bounds(snapshot)?;
            if snapshot.snapshot_id != binding.raw_snapshot_id
                || snapshot.phase != binding.raw_phase
                || snapshot.boot_id != envelope.boot_id
            {
                bail!("raw BPF snapshot identity differs from its A/B/C envelope");
            }
        }
        _ => {}
    }
    match (&envelope.filesystem, raw.filesystem) {
        (None, Some(_)) => bail!("raw filesystem snapshot supplied for a disabled domain"),
        (Some(binding), Some(snapshot)) => {
            snapshot.validate()?;
            if snapshot.snapshot_id != binding.raw_snapshot_id
                || filesystem_phase_label(snapshot.phase) != binding.raw_phase
                || snapshot.boot_id != envelope.boot_id
            {
                bail!("raw filesystem snapshot identity differs from its A/B/C envelope");
            }
        }
        _ => {}
    }
    match (&envelope.linux, raw.linux) {
        (None, Some(_)) => bail!("raw Linux snapshot supplied for a disabled domain"),
        (Some(binding), Some(snapshot)) => {
            if snapshot.snapshot_id != binding.raw_snapshot_id
                || linux_phase_label(snapshot.phase) != binding.raw_phase
                || snapshot.boot_id != envelope.boot_id
            {
                bail!("raw Linux snapshot identity differs from its A/B/C envelope");
            }
            let enabled = [
                (RecoveryDomain::Sysctl, snapshot.sysctl.is_some()),
                (RecoveryDomain::Mount, snapshot.mounts.is_some()),
                (RecoveryDomain::Network, snapshot.network.is_some()),
                (RecoveryDomain::Modules, snapshot.modules.is_some()),
                (
                    RecoveryDomain::ProcessResidual,
                    snapshot.process_residual.is_some(),
                ),
            ]
            .into_iter()
            .filter_map(|(domain, enabled)| enabled.then_some(domain))
            .collect::<Vec<_>>();
            if enabled != binding.domains {
                bail!("raw Linux snapshot domain enablement differs from its envelope");
            }
        }
        _ => {}
    }
    Ok(())
}

fn enrich_pair_from_raw(
    pair: &mut RecoveryPairDelta,
    before: RecoveryRawSnapshotSet<'_>,
    after: RecoveryRawSnapshotSet<'_>,
    comparisons: RecoveryComparisonSet<'_>,
) -> Result<bool> {
    let mut all_enabled_proven = true;
    if pair.domains.bpf.enabled {
        if let (Some(before), Some(after), Some(comparison)) =
            (before.bpf, after.bpf, comparisons.bpf)
        {
            let independent = bpf_observer_comparator::compare_phases(
                before,
                after,
                &before.phase,
                &after.phase,
                &EvidenceHealth::default(),
                comparison.quiescence.clone(),
            )?;
            if independent.state_verdict != comparison.state_verdict
                || independent.state_completeness != comparison.state_completeness
                || independent.changes.len() != comparison.changes.len()
                || independent
                    .changes
                    .iter()
                    .zip(&comparison.changes)
                    .any(|(left, right)| !same_bpf_change(left, right))
            {
                bail!("BPF comparison does not independently reconstruct from raw snapshots");
            }
            for object in pair
                .objects
                .iter_mut()
                .filter(|object| object.domain == RecoveryDomain::Bpf)
            {
                let (entity, identity, _) = decode_bpf_object_key(&object.canonical_key)?;
                object.before_sha256 = raw_bpf_object_sha256(before, &entity, &identity)?;
                object.after_sha256 = raw_bpf_object_sha256(after, &entity, &identity)?;
                object.raw_value_confirmed = raw_object_change_compatible(object);
            }
        } else {
            all_enabled_proven = false;
        }
    }
    if pair.domains.filesystem.enabled {
        if let (Some(before), Some(after), Some(comparison)) =
            (before.filesystem, after.filesystem, comparisons.filesystem)
        {
            let independent = bpf_observer_filesystem_confirmer::compare_phases(
                before,
                after,
                before.phase,
                after.phase,
                None,
            )?;
            if independent.changes != comparison.changes
                || independent.state_completeness != comparison.state_completeness
                || independent.endpoint_difference != comparison.endpoint_difference
            {
                bail!("filesystem comparison does not reconstruct from raw snapshots");
            }
            for object in pair
                .objects
                .iter_mut()
                .filter(|object| object.domain == RecoveryDomain::Filesystem)
            {
                object.before_sha256 = raw_filesystem_object_sha256(before, &object.canonical_key)?;
                object.after_sha256 = raw_filesystem_object_sha256(after, &object.canonical_key)?;
                object.raw_value_confirmed = raw_object_change_compatible(object);
            }
        } else {
            all_enabled_proven = false;
        }
    }
    if pair.domains.all().iter().any(|(domain, outcome)| {
        !matches!(domain, RecoveryDomain::Bpf | RecoveryDomain::Filesystem) && outcome.enabled
    }) {
        if let (Some(before), Some(after), Some(comparison)) =
            (before.linux, after.linux, comparisons.linux)
        {
            let independent = bpf_observer_linux_state_confirmers::compare_phases(
                before,
                after,
                before.phase,
                after.phase,
            )?;
            if independent.domains != comparison.domains {
                bail!("Linux comparison does not reconstruct from raw snapshots");
            }
            for object in pair.objects.iter_mut().filter(|object| {
                !matches!(
                    object.domain,
                    RecoveryDomain::Bpf | RecoveryDomain::Filesystem
                )
            }) {
                object.before_sha256 = raw_linux_object_sha256(before, object)?;
                object.after_sha256 = raw_linux_object_sha256(after, object)?;
                object.raw_value_confirmed = raw_object_change_compatible(object);
            }
        } else {
            all_enabled_proven = false;
        }
    }
    pair.validate()?;
    if pair
        .objects
        .iter()
        .any(|object| !object.raw_value_confirmed)
    {
        all_enabled_proven = false;
    }
    Ok(all_enabled_proven)
}

fn same_bpf_change(left: &BpfStateChange, right: &BpfStateChange) -> bool {
    left.kind == right.kind
        && left.certainty == right.certainty
        && left.entity == right.entity
        && left.identity == right.identity
        && left.field == right.field
        && left.before == right.before
        && left.after == right.after
}

fn raw_object_change_compatible(object: &RecoveryObjectRef) -> bool {
    if object.before_sha256 == object.after_sha256 {
        return false;
    }
    match object.change_kind {
        RecoveryChangeKind::Added => {
            object.before_sha256.is_none() && object.after_sha256.is_some()
        }
        RecoveryChangeKind::Removed => {
            object.before_sha256.is_some() && object.after_sha256.is_none()
        }
        RecoveryChangeKind::Modified => {
            object.before_sha256.is_some() && object.after_sha256.is_some()
        }
    }
}

fn decode_bpf_object_key(key: &str) -> Result<(String, String, String)> {
    let encoded = key
        .strip_prefix("bpf:")
        .context("BPF recovery object key lacks its domain prefix")?;
    let values: Vec<String> = serde_json::from_str(encoded).context("decode BPF object key")?;
    if values.len() != 3 {
        bail!("BPF recovery object key must contain entity, identity, and field");
    }
    Ok((values[0].clone(), values[1].clone(), values[2].clone()))
}

fn raw_bpf_object_sha256(
    snapshot: &BpfSnapshot,
    entity: &str,
    identity: &str,
) -> Result<Option<String>> {
    match entity {
        "program" => {
            let id = bpf_object_id(identity)?;
            snapshot
                .programs
                .binary_search_by_key(&id, |value| value.identity.id)
                .ok()
                .map(|index| &snapshot.programs[index])
                .filter(|value| !value.excluded && bpf_identity_key(&value.identity) == identity)
                .map(sha256_json)
                .transpose()
        }
        "map" => {
            let id = bpf_object_id(identity)?;
            snapshot
                .maps
                .binary_search_by_key(&id, |value| value.identity.id)
                .ok()
                .map(|index| &snapshot.maps[index])
                .filter(|value| !value.excluded && bpf_identity_key(&value.identity) == identity)
                .map(sha256_json)
                .transpose()
        }
        "link" => {
            let id = bpf_object_id(identity)?;
            snapshot
                .links
                .binary_search_by_key(&id, |value| value.identity.id)
                .ok()
                .map(|index| &snapshot.links[index])
                .filter(|value| !value.excluded && bpf_identity_key(&value.identity) == identity)
                .map(sha256_json)
                .transpose()
        }
        "pin" => {
            let mut components = identity.split(':');
            let mount_namespace_inode: u64 = components
                .next()
                .context("BPF pin key lacks mount namespace")?
                .parse()
                .context("decode BPF pin mount namespace")?;
            let mount_id: u64 = components
                .next()
                .context("BPF pin key lacks mount ID")?
                .parse()
                .context("decode BPF pin mount ID")?;
            let path_bytes_hex = components.next().context("BPF pin key lacks path")?;
            if components.next().is_some() {
                bail!("BPF pin key has too many components");
            }
            snapshot
                .pins
                .binary_search_by(|value| {
                    (
                        value.mount_namespace_inode,
                        value.mount_id,
                        value.path_bytes_hex.as_str(),
                    )
                        .cmp(&(
                            mount_namespace_inode,
                            mount_id,
                            path_bytes_hex,
                        ))
                })
                .ok()
                .map(|index| &snapshot.pins[index])
                .filter(|value| !value.excluded)
                .map(sha256_json)
                .transpose()
        }
        _ => bail!("BPF recovery object has an unsupported entity kind"),
    }
}

fn bpf_object_id(identity: &str) -> Result<u32> {
    let id: u32 = identity
        .rsplit(':')
        .next()
        .context("BPF object key lacks an ID")?
        .parse()
        .context("decode BPF object ID")?;
    if id == 0 {
        bail!("BPF object key contains zero ID");
    }
    Ok(id)
}

fn bpf_identity_key(identity: &ObjectIdentity) -> String {
    format!(
        "{}:{:?}:{}",
        identity.boot_id, identity.object_type, identity.id
    )
}

fn raw_filesystem_object_sha256(
    snapshot: &FilesystemSnapshot,
    canonical_key: &str,
) -> Result<Option<String>> {
    let encoded = canonical_key
        .strip_prefix("filesystem:")
        .context("filesystem recovery object key lacks its domain prefix")?;
    let (root_index, relative_path_bytes_hex) = encoded
        .split_once(':')
        .context("filesystem recovery object key lacks its path")?;
    let root_index: u32 = root_index.parse().context("decode filesystem root index")?;
    let entry = snapshot
        .entries
        .binary_search_by(|entry| {
            (entry.root_index, entry.relative_path_bytes_hex.as_str())
                .cmp(&(root_index, relative_path_bytes_hex))
        })
        .ok()
        .map(|index| &snapshot.entries[index]);
    if relative_path_bytes_hex.is_empty() {
        let root = snapshot
            .roots
            .iter()
            .find(|root| root.root_index == root_index)
            .context("filesystem root object identity is absent")?;
        if root.status == RootCaptureStatus::Missing {
            return Ok(None);
        }
        return Ok(Some(sha256_json(&(root, entry))?));
    }
    entry.map(sha256_json).transpose()
}

fn raw_linux_object_sha256(
    snapshot: &LinuxStateSnapshot,
    object: &RecoveryObjectRef,
) -> Result<Option<String>> {
    let prefix = format!("{}:", object.domain.as_str().to_ascii_lowercase());
    let encoded = object
        .canonical_key
        .strip_prefix(&prefix)
        .context("Linux recovery object key has an invalid domain prefix")?;
    let key: String = serde_json::from_str(encoded).context("decode Linux record key")?;
    let domain = match object.domain {
        RecoveryDomain::Sysctl => snapshot.sysctl.as_ref(),
        RecoveryDomain::Mount => snapshot.mounts.as_ref(),
        RecoveryDomain::Network => snapshot.network.as_ref(),
        RecoveryDomain::Modules => snapshot.modules.as_ref(),
        RecoveryDomain::ProcessResidual => snapshot.process_residual.as_ref(),
        _ => bail!("non-Linux object passed to Linux raw lookup"),
    };
    Ok(domain
        .and_then(|domain| {
            domain
                .records
                .binary_search_by(|record| record.key.as_str().cmp(&key))
                .ok()
                .map(|index| &domain.records[index])
        })
        .map(|record| record.value_sha256.clone()))
}

fn filesystem_phase_label(phase: FilesystemSnapshotPhase) -> &'static str {
    match phase {
        FilesystemSnapshotPhase::S0 => "S0",
        FilesystemSnapshotPhase::S1 => "S1",
        FilesystemSnapshotPhase::A => "A",
        FilesystemSnapshotPhase::B => "B",
        FilesystemSnapshotPhase::C => "C",
    }
}

fn linux_phase_label(phase: LinuxSnapshotPhase) -> &'static str {
    match phase {
        LinuxSnapshotPhase::S0 => "S0",
        LinuxSnapshotPhase::S1 => "S1",
        LinuxSnapshotPhase::A => "A",
        LinuxSnapshotPhase::B => "B",
        LinuxSnapshotPhase::C => "C",
    }
}

pub fn build_recovery_pair_delta(
    pair: RecoveryPairKind,
    before: &RecoverySnapshotEnvelope,
    after: &RecoverySnapshotEnvelope,
    comparisons: RecoveryComparisonSet<'_>,
) -> Result<RecoveryPairDelta> {
    before.validate()?;
    after.validate()?;
    let (expected_before, expected_after) = pair.phases();
    if before.phase != expected_before || after.phase != expected_after {
        bail!("recovery comparison envelopes do not match the requested pair kind");
    }
    validate_snapshot_identity_continuity(before, after)?;
    if before.enabled_domains() != after.enabled_domains() {
        bail!("enabled recovery domains differ across snapshot envelopes");
    }
    validate_comparison_presence(before, &comparisons)?;

    let mut objects = Vec::new();
    let bpf = build_bpf_outcome(before, comparisons.bpf, &mut objects)?;
    let filesystem = build_filesystem_outcome(before, after, comparisons.filesystem, &mut objects)?;
    let linux = build_linux_outcomes(before, after, comparisons.linux, &mut objects)?;
    objects.sort_by(object_order);
    if objects.len() > MAX_OBJECTS {
        bail!("recovery pair object vector exceeds its hard bound");
    }
    if objects
        .windows(2)
        .any(|pair| pair[0].identity() == pair[1].identity())
    {
        bail!("recovery pair has duplicate canonical object keys");
    }
    let delta = RecoveryPairDelta {
        schema_version: RECOVERY_REPORT_SCHEMA_VERSION,
        protocol_version: DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
        pair,
        before_phase: before.phase,
        after_phase: after.phase,
        before_snapshot_id: before.snapshot_id.clone(),
        after_snapshot_id: after.snapshot_id.clone(),
        domains: RecoveryDomainVector {
            bpf,
            filesystem,
            sysctl: linux[0].clone(),
            mount: linux[1].clone(),
            network: linux[2].clone(),
            modules: linux[3].clone(),
            process_residual: linux[4].clone(),
        },
        objects,
    };
    delta.validate()?;
    Ok(delta)
}

fn validate_snapshot_triplet(snapshots: RecoverySnapshotTriplet<'_>) -> Result<()> {
    snapshots.a.validate()?;
    snapshots.b.validate()?;
    snapshots.c.validate()?;
    if snapshots.a.phase != RecoverySnapshotPhase::A
        || snapshots.b.phase != RecoverySnapshotPhase::B
        || snapshots.c.phase != RecoverySnapshotPhase::C
    {
        bail!("recovery snapshot triplet must be ordered A/B/C");
    }
    validate_snapshot_identity_continuity(snapshots.a, snapshots.b)?;
    validate_snapshot_identity_continuity(snapshots.b, snapshots.c)?;
    if snapshots.a.enabled_domains() != snapshots.b.enabled_domains()
        || snapshots.a.enabled_domains() != snapshots.c.enabled_domains()
    {
        bail!("enabled recovery domains differ across A/B/C");
    }
    Ok(())
}

fn validate_snapshot_identity_continuity(
    before: &RecoverySnapshotEnvelope,
    after: &RecoverySnapshotEnvelope,
) -> Result<()> {
    if before.run_id != after.run_id
        || before.epoch != after.epoch
        || before.checkpoint_id != after.checkpoint_id
        || before.recovery_id != after.recovery_id
        || before.boot_id != after.boot_id
        || before.deployment_scope_sha256 != after.deployment_scope_sha256
        || before.cgroup_scope_capability != after.cgroup_scope_capability
        || before.root_cgroups != after.root_cgroups
        || before.mount_namespace_ids != after.mount_namespace_ids
        || before.pid_namespace_ids != after.pid_namespace_ids
        || before.net_namespace_ids != after.net_namespace_ids
        || before.uts_namespace_ids != after.uts_namespace_ids
        || before.ipc_namespace_ids != after.ipc_namespace_ids
    {
        bail!("recovery snapshot environment identity changed across phases");
    }
    if before.snapshot_id == after.snapshot_id {
        bail!("recovery snapshot IDs must be distinct across phases");
    }
    Ok(())
}

fn validate_comparison_presence(
    envelope: &RecoverySnapshotEnvelope,
    comparisons: &RecoveryComparisonSet<'_>,
) -> Result<()> {
    if envelope.bpf.is_none() && comparisons.bpf.is_some() {
        bail!("BPF comparison was supplied for a disabled snapshot domain");
    }
    if envelope.filesystem.is_none() && comparisons.filesystem.is_some() {
        bail!("filesystem comparison was supplied for a disabled snapshot domain");
    }
    if envelope.linux.is_none() && comparisons.linux.is_some() {
        bail!("Linux comparison was supplied for a disabled snapshot domain");
    }
    Ok(())
}

fn build_bpf_outcome(
    envelope: &RecoverySnapshotEnvelope,
    comparison: Option<&BpfVerdict>,
    objects: &mut Vec<RecoveryObjectRef>,
) -> Result<RecoveryDomainOutcome> {
    if envelope.bpf.is_none() {
        return Ok(RecoveryDomainOutcome::disabled());
    }
    let Some(comparison) = comparison else {
        return Ok(RecoveryDomainOutcome::unavailable());
    };
    let digest = sha256_json(comparison)?;
    let negative_unproven = comparison.changes.is_empty()
        && comparison.state_verdict != BpfStateVerdict::UnchangedWithinScope;
    let positive_unproven = !comparison.changes.is_empty()
        && comparison.state_verdict != BpfStateVerdict::ChangedWithinScope;
    let complete = comparison.state_completeness.status == BpfCompletenessStatus::Complete
        && !negative_unproven
        && !positive_unproven
        && comparison
            .changes
            .iter()
            .all(|change| change.certainty == ChangeCertainty::Confirmed);
    let mut reasons = comparison.state_completeness.reasons.clone();
    if negative_unproven {
        reasons.push(
            "BPF endpoint equality lacks an authorized UNCHANGED_WITHIN_SCOPE verdict".to_owned(),
        );
    }
    if positive_unproven {
        reasons.push("BPF endpoint changes lack a CHANGED_WITHIN_SCOPE verdict".to_owned());
    }
    if comparison
        .changes
        .iter()
        .any(|change| change.certainty == ChangeCertainty::Indeterminate)
    {
        reasons.push("BPF comparison contains indeterminate object changes".to_owned());
    }
    canonicalize_reasons(&mut reasons)?;
    if !complete && reasons.is_empty() {
        reasons.push("BPF endpoint comparison is incomplete without a reason".to_owned());
    }
    let start = objects.len();
    for change in &comparison.changes {
        objects.push(bpf_object(change)?);
    }
    let change_count = (objects.len() - start) as u64;
    Ok(RecoveryDomainOutcome {
        enabled: true,
        endpoint_status: endpoint_status(complete, change_count),
        complete,
        change_count,
        reasons,
        comparison_sha256: Some(digest),
    })
}

fn build_filesystem_outcome(
    before: &RecoverySnapshotEnvelope,
    after: &RecoverySnapshotEnvelope,
    comparison: Option<&FilesystemComparison>,
    objects: &mut Vec<RecoveryObjectRef>,
) -> Result<RecoveryDomainOutcome> {
    let Some(before_binding) = &before.filesystem else {
        return Ok(RecoveryDomainOutcome::disabled());
    };
    let after_binding = after
        .filesystem
        .as_ref()
        .context("filesystem binding disappeared across snapshots")?;
    let Some(comparison) = comparison else {
        return Ok(RecoveryDomainOutcome::unavailable());
    };
    if comparison.s0_snapshot_id != before_binding.raw_snapshot_id
        || comparison.s1_snapshot_id != after_binding.raw_snapshot_id
    {
        bail!("filesystem comparison snapshot IDs do not match the envelope bindings");
    }
    let digest = sha256_json(comparison)?;
    let complete = comparison.state_completeness.status == FilesystemCompletenessStatus::Complete;
    let mut reasons = comparison.state_completeness.reasons.clone();
    canonicalize_reasons(&mut reasons)?;
    if !complete && reasons.is_empty() {
        reasons.push("filesystem endpoint comparison is incomplete without a reason".to_owned());
    }
    let start = objects.len();
    for change in &comparison.changes {
        objects.push(filesystem_object(change)?);
    }
    let change_count = (objects.len() - start) as u64;
    let expected = endpoint_status(complete, change_count);
    let observed = match comparison.endpoint_difference {
        FilesystemEndpointDifferenceStatus::ObservedIdentical => {
            RecoveryEndpointStatus::ObservedIdentical
        }
        FilesystemEndpointDifferenceStatus::ObservedDifferent => {
            RecoveryEndpointStatus::ObservedDifferent
        }
        FilesystemEndpointDifferenceStatus::Indeterminate => RecoveryEndpointStatus::Indeterminate,
    };
    if observed != expected {
        bail!("filesystem endpoint status disagrees with completeness/change vector");
    }
    Ok(RecoveryDomainOutcome {
        enabled: true,
        endpoint_status: observed,
        complete,
        change_count,
        reasons,
        comparison_sha256: Some(digest),
    })
}

fn build_linux_outcomes(
    before: &RecoverySnapshotEnvelope,
    after: &RecoverySnapshotEnvelope,
    comparison: Option<&LinuxStateComparison>,
    objects: &mut Vec<RecoveryObjectRef>,
) -> Result<[RecoveryDomainOutcome; 5]> {
    let Some(before_binding) = &before.linux else {
        return Ok([
            RecoveryDomainOutcome::disabled(),
            RecoveryDomainOutcome::disabled(),
            RecoveryDomainOutcome::disabled(),
            RecoveryDomainOutcome::disabled(),
            RecoveryDomainOutcome::disabled(),
        ]);
    };
    let after_binding = after
        .linux
        .as_ref()
        .context("Linux binding disappeared across snapshots")?;
    let expected = before_binding
        .domains
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let Some(comparison) = comparison else {
        return Ok(all_domains()
            .into_iter()
            .filter(|domain| !matches!(domain, RecoveryDomain::Bpf | RecoveryDomain::Filesystem))
            .map(|domain| {
                if expected.contains(&domain) {
                    RecoveryDomainOutcome::unavailable()
                } else {
                    RecoveryDomainOutcome::disabled()
                }
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("five Linux logical domains"));
    };
    if comparison.s0_snapshot_id != before_binding.raw_snapshot_id
        || comparison.s1_snapshot_id != after_binding.raw_snapshot_id
    {
        bail!("Linux comparison snapshot IDs do not match the envelope bindings");
    }
    let entries = [
        (RecoveryDomain::Sysctl, &comparison.domains.sysctl),
        (RecoveryDomain::Mount, &comparison.domains.mounts),
        (RecoveryDomain::Network, &comparison.domains.network),
        (RecoveryDomain::Modules, &comparison.domains.modules),
        (
            RecoveryDomain::ProcessResidual,
            &comparison.domains.process_residual,
        ),
    ];
    let mut outcomes = Vec::with_capacity(entries.len());
    for (domain, value) in entries {
        let enabled = expected.contains(&domain);
        outcomes.push(build_linux_outcome(domain, value, enabled, objects)?);
    }
    Ok(outcomes.try_into().expect("five Linux logical domains"))
}

fn build_linux_outcome(
    domain: RecoveryDomain,
    comparison: &LinuxDomainComparison,
    enabled: bool,
    objects: &mut Vec<RecoveryObjectRef>,
) -> Result<RecoveryDomainOutcome> {
    if linux_recovery_domain(comparison.domain) != domain {
        bail!("Linux comparison domain is in the wrong vector slot");
    }
    if !enabled {
        if comparison.endpoint_difference != LinuxEndpointDifferenceStatus::NotConfirmed
            || comparison.state_completeness.status != LinuxCompletenessStatus::NotConfirmed
            || !comparison.changes.is_empty()
        {
            bail!("disabled Linux domain contains endpoint evidence");
        }
        return Ok(RecoveryDomainOutcome::disabled());
    }
    if comparison.endpoint_difference == LinuxEndpointDifferenceStatus::NotConfirmed
        || comparison.state_completeness.status == LinuxCompletenessStatus::NotConfirmed
    {
        bail!("enabled Linux domain is marked NOT_CONFIRMED");
    }
    let digest = sha256_json(comparison)?;
    let complete = comparison.state_completeness.status == LinuxCompletenessStatus::Complete;
    let mut reasons = comparison.state_completeness.reasons.clone();
    canonicalize_reasons(&mut reasons)?;
    if !complete && reasons.is_empty() {
        reasons.push(format!(
            "{} endpoint comparison is incomplete without a reason",
            domain.as_str()
        ));
    }
    let start = objects.len();
    for change in &comparison.changes {
        objects.push(linux_object(domain, change)?);
    }
    let change_count = (objects.len() - start) as u64;
    let expected_status = endpoint_status(complete, change_count);
    let observed = match comparison.endpoint_difference {
        LinuxEndpointDifferenceStatus::ObservedIdentical => {
            RecoveryEndpointStatus::ObservedIdentical
        }
        LinuxEndpointDifferenceStatus::ObservedDifferent => {
            RecoveryEndpointStatus::ObservedDifferent
        }
        LinuxEndpointDifferenceStatus::Indeterminate => RecoveryEndpointStatus::Indeterminate,
        LinuxEndpointDifferenceStatus::NotConfirmed => unreachable!("rejected above"),
    };
    if observed != expected_status {
        bail!("Linux endpoint status disagrees with completeness/change vector");
    }
    Ok(RecoveryDomainOutcome {
        enabled: true,
        endpoint_status: observed,
        complete,
        change_count,
        reasons,
        comparison_sha256: Some(digest),
    })
}

fn bpf_object(change: &BpfStateChange) -> Result<RecoveryObjectRef> {
    let field = change.field.as_deref().unwrap_or("");
    let key_components =
        serde_json::to_string(&[change.entity.as_str(), change.identity.as_str(), field])
            .context("encode canonical BPF object key")?;
    let mut changed_fields = change.field.iter().cloned().collect::<Vec<_>>();
    changed_fields.sort();
    changed_fields.dedup();
    let value = RecoveryObjectRef {
        domain: RecoveryDomain::Bpf,
        canonical_key: format!("bpf:{key_components}"),
        change_kind: bpf_change_kind(&change.kind),
        before_sha256: optional_json_sha256(change.before.as_ref())?,
        after_sha256: optional_json_sha256(change.after.as_ref())?,
        changed_fields,
        raw_value_confirmed: false,
    };
    value.validate()?;
    Ok(value)
}

fn filesystem_object(
    change: &bpf_observer_filesystem_confirmer::FilesystemChange,
) -> Result<RecoveryObjectRef> {
    validate_lower_hex(&change.relative_path_bytes_hex, "filesystem relative path")?;
    let mut changed_fields = change
        .changed_fields
        .iter()
        .map(|field| filesystem_field(*field).to_owned())
        .collect::<Vec<_>>();
    changed_fields.sort();
    changed_fields.dedup();
    let value = RecoveryObjectRef {
        domain: RecoveryDomain::Filesystem,
        canonical_key: format!(
            "filesystem:{}:{}",
            change.root_index, change.relative_path_bytes_hex
        ),
        change_kind: match change.kind {
            FilesystemChangeKind::Added => RecoveryChangeKind::Added,
            FilesystemChangeKind::Removed => RecoveryChangeKind::Removed,
            FilesystemChangeKind::Modified => RecoveryChangeKind::Modified,
        },
        before_sha256: None,
        after_sha256: None,
        changed_fields,
        raw_value_confirmed: false,
    };
    value.validate()?;
    Ok(value)
}

fn linux_object(
    domain: RecoveryDomain,
    change: &bpf_observer_linux_state_confirmers::StateChange,
) -> Result<RecoveryObjectRef> {
    if change.key.is_empty() || change.key.len() > MAX_PATH_BYTES || change.key.contains('\0') {
        bail!("Linux state comparison contains an invalid record key");
    }
    if let Some(value) = &change.before_sha256 {
        validate_sha256(value, "Linux before value")?;
    }
    if let Some(value) = &change.after_sha256 {
        validate_sha256(value, "Linux after value")?;
    }
    let encoded_key = serde_json::to_string(&change.key).context("encode canonical Linux key")?;
    let value = RecoveryObjectRef {
        domain,
        canonical_key: format!("{}:{encoded_key}", domain.as_str().to_ascii_lowercase()),
        change_kind: match change.kind {
            LinuxChangeKind::Added => RecoveryChangeKind::Added,
            LinuxChangeKind::Removed => RecoveryChangeKind::Removed,
            LinuxChangeKind::Modified => RecoveryChangeKind::Modified,
        },
        before_sha256: change.before_sha256.clone(),
        after_sha256: change.after_sha256.clone(),
        changed_fields: Vec::new(),
        raw_value_confirmed: false,
    };
    value.validate()?;
    Ok(value)
}

fn classify_objects(
    agent: &RecoveryPairDelta,
    recovery: &RecoveryPairDelta,
    residual: &RecoveryPairDelta,
) -> Result<RecoveryObjectClassifications> {
    let agent_map = object_map(&agent.objects)?;
    let recovery_map = object_map(&recovery.objects)?;
    let residual_map = object_map(&residual.objects)?;
    let mut restored = Vec::new();
    let mut unrecovered = Vec::new();
    let mut partially_restored = Vec::new();
    let mut recovery_introduced = Vec::new();
    let mut unresolved = Vec::new();
    for (identity, agent_object) in &agent_map {
        let domain = agent_object.domain;
        let complete = [agent, recovery, residual]
            .iter()
            .all(|pair| pair.domains.get(domain).complete);
        let recovery_object = recovery_map.get(identity).copied();
        match residual_map.get(identity) {
            None => {
                if complete
                    && agent_object.raw_value_confirmed
                    && recovery_object.map(|value| value.raw_value_confirmed) == Some(true)
                    && recovery_object.map(|value| value.before_sha256.as_ref())
                        == Some(agent_object.after_sha256.as_ref())
                    && recovery_object.map(|value| value.after_sha256.as_ref())
                        == Some(agent_object.before_sha256.as_ref())
                    && agent_object.before_sha256 != agent_object.after_sha256
                {
                    restored.push((*agent_object).clone());
                } else {
                    unresolved.push((*agent_object).clone());
                }
            }
            Some(residual_object) => {
                if complete
                    && agent_object.raw_value_confirmed
                    && residual_object.raw_value_confirmed
                    && agent_object.before_sha256 == residual_object.before_sha256
                    && agent_object.after_sha256 != agent_object.before_sha256
                    && residual_object.after_sha256 != residual_object.before_sha256
                    && recovery_object
                        .map(|value| {
                            value.raw_value_confirmed
                                && value.before_sha256 == agent_object.after_sha256
                                && value.after_sha256 == residual_object.after_sha256
                        })
                        .unwrap_or_else(|| {
                            agent_object.after_sha256 == residual_object.after_sha256
                        })
                {
                    unrecovered.push((*residual_object).clone());
                    if let Some(recovery_object) = recovery_object {
                        if partially_restored_evidence(
                            agent_object,
                            recovery_object,
                            residual_object,
                        ) {
                            partially_restored.push((*residual_object).clone());
                        }
                    }
                } else {
                    unresolved.push((*residual_object).clone());
                }
            }
        }
    }
    for (identity, residual_object) in &residual_map {
        if !agent_map.contains_key(identity) {
            let complete = [agent, recovery, residual]
                .iter()
                .all(|pair| pair.domains.get(residual_object.domain).complete);
            let recovery_object = recovery_map.get(identity).copied();
            if complete
                && residual_object.raw_value_confirmed
                && recovery_object.map(|value| value.raw_value_confirmed) == Some(true)
                && recovery_object.map(|value| value.before_sha256.as_ref())
                    == Some(residual_object.before_sha256.as_ref())
                && recovery_object.map(|value| value.after_sha256.as_ref())
                    == Some(residual_object.after_sha256.as_ref())
                && residual_object.before_sha256 != residual_object.after_sha256
            {
                recovery_introduced.push((*residual_object).clone());
            } else {
                unresolved.push((*residual_object).clone());
            }
        }
    }
    for values in [
        &mut restored,
        &mut unrecovered,
        &mut partially_restored,
        &mut recovery_introduced,
        &mut unresolved,
    ] {
        values.sort_by(object_order);
    }
    let result = RecoveryObjectClassifications {
        restored,
        unrecovered,
        partially_restored,
        recovery_introduced,
        unresolved,
    };
    result.validate()?;
    Ok(result)
}

fn partially_restored_evidence(
    agent: &RecoveryObjectRef,
    recovery: &RecoveryObjectRef,
    residual: &RecoveryObjectRef,
) -> bool {
    if agent.identity() != recovery.identity() || agent.identity() != residual.identity() {
        return false;
    }
    if !agent.raw_value_confirmed || !recovery.raw_value_confirmed || !residual.raw_value_confirmed
    {
        return false;
    }
    if agent.domain == RecoveryDomain::Filesystem {
        let agent_fields = agent.changed_fields.iter().collect::<BTreeSet<_>>();
        let residual_fields = residual.changed_fields.iter().collect::<BTreeSet<_>>();
        return agent.before_sha256 != agent.after_sha256
            && residual.after_sha256 != agent.before_sha256
            && residual.after_sha256 != agent.after_sha256
            && recovery.before_sha256 == agent.after_sha256
            && recovery.after_sha256 == residual.after_sha256
            && !residual_fields.is_empty()
            && residual_fields.len() < agent_fields.len()
            && residual_fields.is_subset(&agent_fields);
    }
    // For atomic BPF/Linux fields, prove only that C is neither A nor B and
    // that B->C connects those exact endpoint fingerprints. This never moves
    // the object out of `unrecovered`; it is merely a conservative annotation.
    agent.before_sha256.is_some()
        && agent.after_sha256.is_some()
        && residual.before_sha256 == agent.before_sha256
        && residual.after_sha256.is_some()
        && residual.after_sha256 != agent.before_sha256
        && residual.after_sha256 != agent.after_sha256
        && recovery.before_sha256 == agent.after_sha256
        && recovery.after_sha256 == residual.after_sha256
}

fn comparison_incompleteness_reasons(
    agent: &RecoveryPairDelta,
    recovery: &RecoveryPairDelta,
    residual: &RecoveryPairDelta,
) -> Vec<String> {
    let mut reasons = Vec::new();
    for pair in [agent, recovery, residual] {
        for (domain, outcome) in pair.domains.all() {
            if outcome.enabled && !outcome.complete {
                if outcome.reasons.is_empty() {
                    reasons.push(format!(
                        "{:?}/{} comparison is incomplete",
                        pair.pair,
                        domain.as_str()
                    ));
                } else {
                    reasons.extend(
                        outcome
                            .reasons
                            .iter()
                            .map(|reason| format!("{:?}/{}: {reason}", pair.pair, domain.as_str())),
                    );
                }
            }
        }
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

fn endpoint_status(complete: bool, change_count: u64) -> RecoveryEndpointStatus {
    if !complete {
        RecoveryEndpointStatus::Indeterminate
    } else if change_count == 0 {
        RecoveryEndpointStatus::ObservedIdentical
    } else {
        RecoveryEndpointStatus::ObservedDifferent
    }
}

fn validate_objects(objects: &[RecoveryObjectRef]) -> Result<()> {
    if objects.len() > MAX_OBJECTS {
        bail!("recovery object vector exceeds its hard bound");
    }
    for object in objects {
        object.validate()?;
    }
    if objects
        .windows(2)
        .any(|pair| object_order(&pair[0], &pair[1]).is_gt())
    {
        bail!("recovery object vector is not canonically sorted");
    }
    if objects
        .windows(2)
        .any(|pair| pair[0].identity() == pair[1].identity())
    {
        bail!("recovery object vector contains duplicate identities");
    }
    Ok(())
}

fn object_map(
    objects: &[RecoveryObjectRef],
) -> Result<BTreeMap<(RecoveryDomain, &str), &RecoveryObjectRef>> {
    validate_objects(objects)?;
    let mut values = BTreeMap::new();
    for object in objects {
        if values.insert(object.identity(), object).is_some() {
            bail!("duplicate recovery object identity");
        }
    }
    Ok(values)
}

fn identity_set(objects: &[RecoveryObjectRef]) -> BTreeSet<(RecoveryDomain, &str)> {
    objects.iter().map(RecoveryObjectRef::identity).collect()
}

fn object_order(left: &RecoveryObjectRef, right: &RecoveryObjectRef) -> std::cmp::Ordering {
    left.domain
        .cmp(&right.domain)
        .then_with(|| left.canonical_key.cmp(&right.canonical_key))
}

fn bpf_change_kind(kind: &BpfChangeKind) -> RecoveryChangeKind {
    match kind {
        BpfChangeKind::Added => RecoveryChangeKind::Added,
        BpfChangeKind::Removed => RecoveryChangeKind::Removed,
        BpfChangeKind::Modified => RecoveryChangeKind::Modified,
    }
}

fn linux_recovery_domain(domain: LinuxDomainKind) -> RecoveryDomain {
    match domain {
        LinuxDomainKind::Sysctl => RecoveryDomain::Sysctl,
        LinuxDomainKind::Mount => RecoveryDomain::Mount,
        LinuxDomainKind::Network => RecoveryDomain::Network,
        LinuxDomainKind::KernelModule => RecoveryDomain::Modules,
        LinuxDomainKind::ProcessResidual => RecoveryDomain::ProcessResidual,
    }
}

fn filesystem_field(field: FilesystemChangedField) -> &'static str {
    match field {
        FilesystemChangedField::RootCaptureStatus => "ROOT_CAPTURE_STATUS",
        FilesystemChangedField::RootFilesystemMagic => "ROOT_FILESYSTEM_MAGIC",
        FilesystemChangedField::RootFilesystemClass => "ROOT_FILESYSTEM_CLASS",
        FilesystemChangedField::Type => "TYPE",
        FilesystemChangedField::Device => "DEVICE",
        FilesystemChangedField::Inode => "INODE",
        FilesystemChangedField::Rdev => "RDEV",
        FilesystemChangedField::Mode => "MODE",
        FilesystemChangedField::Uid => "UID",
        FilesystemChangedField::Gid => "GID",
        FilesystemChangedField::HardLinkCount => "HARD_LINK_COUNT",
        FilesystemChangedField::Size => "SIZE",
        FilesystemChangedField::Mtime => "MTIME",
        FilesystemChangedField::Ctime => "CTIME",
        FilesystemChangedField::Traversal => "TRAVERSAL",
        FilesystemChangedField::Content => "CONTENT",
        FilesystemChangedField::Symlink => "SYMLINK",
        FilesystemChangedField::Xattrs => "XATTRS",
    }
}

fn optional_json_sha256(value: Option<&Value>) -> Result<Option<String>> {
    value.map(sha256_json).transpose()
}

fn sha256_json<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value).context("serialize recovery evidence for SHA-256")?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("{label} must contain 1..=128 conservative ASCII identity bytes");
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} SHA-256 must be exactly 64 lowercase hexadecimal bytes");
    }
    Ok(())
}

fn validate_lower_hex(value: &str, label: &str) -> Result<()> {
    if value.len() > MAX_PATH_BYTES * 2
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be bounded canonical lowercase hex");
    }
    Ok(())
}

fn validate_uuid(value: &str, label: &str) -> Result<()> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
    {
        bail!("{label} must be a canonical lowercase UUID");
    }
    Ok(())
}

fn validate_cgroup_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || !path.starts_with('/')
        || path.as_bytes().contains(&0)
        || path.as_bytes().contains(&b'\n')
        || (path != "/"
            && path[1..]
                .split('/')
                .any(|component| component.is_empty() || component == "." || component == ".."))
        || (path.len() > 1 && path.ends_with('/'))
    {
        bail!("recovery root cgroup path must be an absolute normalized Linux path");
    }
    Ok(())
}

fn validate_relative_artifact_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || path.starts_with('/')
        || path.ends_with('/')
        || path.as_bytes().contains(&0)
        || path.as_bytes().contains(&b'\n')
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        bail!("snapshot artifact path must be a bounded normalized relative path");
    }
    Ok(())
}

fn validate_namespace_ids(values: &[u64], label: &str) -> Result<()> {
    if values.is_empty()
        || values.len() > MAX_NAMESPACES
        || values.iter().any(|value| *value == 0)
        || values.windows(2).any(|pair| pair[0] >= pair[1])
    {
        bail!("recovery snapshot {label} namespace IDs are empty or non-canonical");
    }
    Ok(())
}

fn ensure_sorted_unique<T: Ord>(values: &[T], label: &str) -> Result<()> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        bail!("{label} must be strictly sorted and unique");
    }
    Ok(())
}

fn validate_reasons(reasons: &[String]) -> Result<()> {
    if reasons.len() > MAX_REASONS
        || reasons.iter().any(|reason| {
            reason.is_empty() || reason.len() > MAX_REASON_BYTES || reason.contains('\0')
        })
        || reasons.windows(2).any(|pair| pair[0] >= pair[1])
    {
        bail!("recovery reasons are oversized or non-canonical");
    }
    Ok(())
}

fn canonicalize_reasons(reasons: &mut Vec<String>) -> Result<()> {
    reasons.sort();
    reasons.dedup();
    validate_reasons(reasons)
}

fn insert_reason(reasons: &mut Vec<String>, reason: &str) -> Result<()> {
    reasons.push(reason.to_owned());
    canonicalize_reasons(reasons)
}

fn all_domains() -> [RecoveryDomain; 7] {
    [
        RecoveryDomain::Bpf,
        RecoveryDomain::Filesystem,
        RecoveryDomain::Sysctl,
        RecoveryDomain::Mount,
        RecoveryDomain::Network,
        RecoveryDomain::Modules,
        RecoveryDomain::ProcessResidual,
    ]
}

fn canonical_limitations() -> Vec<String> {
    let mut values = vec![
        "A/C equality is only a claim about enabled, complete endpoint-confirmation scopes"
            .to_owned(),
        "endpoint equality does not prove absence of transient A->B->C operations".to_owned(),
        "recovery consistency does not establish causal attribution for delegated effects"
            .to_owned(),
        "remote service and database state is outside target-Linux endpoint confirmation"
            .to_owned(),
    ];
    values.sort();
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use bpf_observer_linux_state_confirmers::{
        encode_absolute_path, CaptureLimits, Completeness as LinuxCompleteness, DomainSnapshot,
        ProcessResidualScope, StateRecord, StateScope, ValueEvidenceMode,
        LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
    };
    use bpf_observer_schema::{
        Attribution as BpfAttribution, Completeness as BpfCompleteness,
        QuiescenceBasis as BpfQuiescenceBasis, QuiescenceReport as BpfQuiescenceReport,
        QuiescenceStatus as BpfQuiescenceStatus, RunStatus as BpfRunStatus,
    };
    use std::path::Path;

    fn digest(byte: char) -> String {
        std::iter::repeat(byte).take(64).collect()
    }

    #[test]
    fn empty_bpf_delta_without_authorized_unchanged_verdict_is_incomplete() {
        let mut envelope = raw_process_envelope(RecoverySnapshotPhase::A, "S0", "snapshot-a");
        envelope.bpf = Some(
            SnapshotDomainBinding::new(
                RecoverySnapshotPhase::A,
                "S0",
                "bpf-state-s0.json",
                128,
                digest('a'),
                "bpf-snapshot-a",
                vec![RecoveryDomain::Bpf],
            )
            .unwrap(),
        );
        let mut comparison = BpfVerdict {
            schema_version: 1,
            state_verdict: BpfStateVerdict::Inconclusive,
            state_completeness: BpfCompleteness::complete(),
            evidence_status: BpfCompleteness::complete(),
            attribution: BpfAttribution::Unknown,
            quiescence: BpfQuiescenceReport {
                status: BpfQuiescenceStatus::Unknown,
                basis: BpfQuiescenceBasis::ObservedOnly,
                contract_id: None,
                checks: Vec::new(),
                exclusive_actor_attribution: false,
                authentication: None,
            },
            run_status: BpfRunStatus::Provisional,
            changes: Vec::new(),
            limitations: Vec::new(),
        };
        let incomplete = build_bpf_outcome(&envelope, Some(&comparison), &mut Vec::new()).unwrap();
        assert!(!incomplete.complete);
        assert_eq!(
            incomplete.endpoint_status,
            RecoveryEndpointStatus::Indeterminate
        );
        assert!(incomplete
            .reasons
            .iter()
            .any(|reason| reason.contains("UNCHANGED_WITHIN_SCOPE")));

        comparison.state_verdict = BpfStateVerdict::UnchangedWithinScope;
        let complete = build_bpf_outcome(&envelope, Some(&comparison), &mut Vec::new()).unwrap();
        assert!(complete.complete);
    }

    fn object(
        domain: RecoveryDomain,
        key: &str,
        before: Option<&str>,
        after: Option<&str>,
        fields: &[&str],
    ) -> RecoveryObjectRef {
        RecoveryObjectRef {
            domain,
            canonical_key: format!("{}:{key}", domain.as_str().to_ascii_lowercase()),
            change_kind: RecoveryChangeKind::Modified,
            before_sha256: before.map(str::to_owned),
            after_sha256: after.map(str::to_owned),
            changed_fields: fields.iter().map(|value| (*value).to_owned()).collect(),
            raw_value_confirmed: false,
        }
    }

    fn outcome(enabled: bool, objects: usize, complete: bool) -> RecoveryDomainOutcome {
        if !enabled {
            return RecoveryDomainOutcome::disabled();
        }
        RecoveryDomainOutcome {
            enabled: true,
            endpoint_status: endpoint_status(complete, objects as u64),
            complete,
            change_count: objects as u64,
            reasons: if complete {
                Vec::new()
            } else {
                vec!["capture incomplete".to_owned()]
            },
            comparison_sha256: Some(digest('a')),
        }
    }

    fn domains(objects: &[RecoveryObjectRef], complete: bool) -> RecoveryDomainVector {
        let fs_count = objects
            .iter()
            .filter(|value| value.domain == RecoveryDomain::Filesystem)
            .count();
        let sysctl_count = objects
            .iter()
            .filter(|value| value.domain == RecoveryDomain::Sysctl)
            .count();
        RecoveryDomainVector {
            bpf: RecoveryDomainOutcome::disabled(),
            filesystem: outcome(true, fs_count, complete),
            sysctl: outcome(true, sysctl_count, complete),
            mount: RecoveryDomainOutcome::disabled(),
            network: RecoveryDomainOutcome::disabled(),
            modules: RecoveryDomainOutcome::disabled(),
            process_residual: RecoveryDomainOutcome::disabled(),
        }
    }

    fn pair(
        pair: RecoveryPairKind,
        mut objects: Vec<RecoveryObjectRef>,
        complete: bool,
    ) -> RecoveryPairDelta {
        objects.sort_by(object_order);
        let (before_phase, after_phase) = pair.phases();
        let (before_snapshot_id, after_snapshot_id) = match pair {
            RecoveryPairKind::AgentDelta => ("snapshot-a", "snapshot-b"),
            RecoveryPairKind::RecoveryDelta => ("snapshot-b", "snapshot-c"),
            RecoveryPairKind::ResidualDelta => ("snapshot-a", "snapshot-c"),
        };
        RecoveryPairDelta {
            schema_version: RECOVERY_REPORT_SCHEMA_VERSION,
            protocol_version: DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
            pair,
            before_phase,
            after_phase,
            before_snapshot_id: before_snapshot_id.to_owned(),
            after_snapshot_id: after_snapshot_id.to_owned(),
            domains: domains(&objects, complete),
            objects,
        }
    }

    fn report(
        agent: Vec<RecoveryObjectRef>,
        recovery: Vec<RecoveryObjectRef>,
        residual: Vec<RecoveryObjectRef>,
        complete: bool,
    ) -> RecoveryVerdictReport {
        RecoveryVerdictReport::from_pair_deltas(
            "run-1",
            1,
            "checkpoint-1",
            "recovery-1",
            digest('1'),
            digest('2'),
            digest('3'),
            pair(RecoveryPairKind::AgentDelta, agent, complete),
            pair(RecoveryPairKind::RecoveryDelta, recovery, complete),
            pair(RecoveryPairKind::ResidualDelta, residual, complete),
            Vec::new(),
        )
        .unwrap()
    }

    fn proven_report(
        agent: Vec<RecoveryObjectRef>,
        recovery: Vec<RecoveryObjectRef>,
        residual: Vec<RecoveryObjectRef>,
    ) -> RecoveryVerdictReport {
        RecoveryVerdictReport::from_pair_deltas_with_raw_status(
            "run-1",
            1,
            "checkpoint-1",
            "recovery-1",
            digest('1'),
            digest('2'),
            digest('3'),
            pair(RecoveryPairKind::AgentDelta, agent, true),
            pair(RecoveryPairKind::RecoveryDelta, recovery, true),
            pair(RecoveryPairKind::ResidualDelta, residual, true),
            Vec::new(),
            true,
        )
        .unwrap()
    }

    fn proven_object(
        domain: RecoveryDomain,
        key: &str,
        kind: RecoveryChangeKind,
        before: Option<&str>,
        after: Option<&str>,
        fields: &[&str],
    ) -> RecoveryObjectRef {
        let mut value = object(domain, key, before, after, fields);
        value.change_kind = kind;
        value.raw_value_confirmed = true;
        value
    }

    #[test]
    fn complete_restoration_is_consistent() {
        let a = digest('a');
        let b = digest('b');
        let agent = proven_object(
            RecoveryDomain::Filesystem,
            "0:61",
            RecoveryChangeKind::Modified,
            Some(&a),
            Some(&b),
            &["CONTENT"],
        );
        let recovery = proven_object(
            RecoveryDomain::Filesystem,
            "0:61",
            RecoveryChangeKind::Modified,
            Some(&b),
            Some(&a),
            &["CONTENT"],
        );
        let result = proven_report(vec![agent], vec![recovery], Vec::new());
        assert_eq!(
            result.verdict,
            RecoveryConsistencyVerdict::ConsistentWithinScope
        );
        assert_eq!(result.classifications.restored.len(), 1);
        assert!(result.classifications.unrecovered.is_empty());
        result.validate().unwrap();
    }

    #[test]
    fn leftover_is_inconsistent() {
        let a = digest('a');
        let b = digest('b');
        let changed = proven_object(
            RecoveryDomain::Filesystem,
            "0:61",
            RecoveryChangeKind::Modified,
            Some(&a),
            Some(&b),
            &["CONTENT"],
        );
        let result = proven_report(vec![changed.clone()], Vec::new(), vec![changed]);
        assert_eq!(
            result.verdict,
            RecoveryConsistencyVerdict::InconsistentWithinScope
        );
        assert_eq!(result.classifications.unrecovered.len(), 1);
    }

    #[test]
    fn any_incomplete_pair_is_inconclusive_before_residual_state() {
        let changed = object(RecoveryDomain::Filesystem, "0:61", None, None, &["CONTENT"]);
        let result = report(vec![changed.clone()], Vec::new(), vec![changed], false);
        assert_eq!(result.verdict, RecoveryConsistencyVerdict::Inconclusive);
        assert!(!result.state_complete);
        assert!(!result.incompleteness_reasons.is_empty());
    }

    #[test]
    fn recovery_side_effect_is_classified_and_inconsistent() {
        let side_effect = proven_object(
            RecoveryDomain::Sysctl,
            "\"kernel/new\"",
            RecoveryChangeKind::Added,
            None,
            Some(&digest('2')),
            &[],
        );
        let result = proven_report(Vec::new(), vec![side_effect.clone()], vec![side_effect]);
        assert_eq!(
            result.verdict,
            RecoveryConsistencyVerdict::InconsistentWithinScope
        );
        assert_eq!(result.classifications.recovery_introduced.len(), 1);
    }

    #[test]
    fn partial_restoration_remains_unrecovered() {
        let a = digest('1');
        let b = digest('2');
        let c = digest('3');
        let agent = proven_object(
            RecoveryDomain::Sysctl,
            "\"kernel/value\"",
            RecoveryChangeKind::Modified,
            Some(&a),
            Some(&b),
            &[],
        );
        let recovery = proven_object(
            RecoveryDomain::Sysctl,
            "\"kernel/value\"",
            RecoveryChangeKind::Modified,
            Some(&b),
            Some(&c),
            &[],
        );
        let residual = proven_object(
            RecoveryDomain::Sysctl,
            "\"kernel/value\"",
            RecoveryChangeKind::Modified,
            Some(&a),
            Some(&c),
            &[],
        );
        let result = proven_report(vec![agent], vec![recovery], vec![residual]);
        assert_eq!(
            result.verdict,
            RecoveryConsistencyVerdict::InconsistentWithinScope
        );
        assert_eq!(result.classifications.partially_restored.len(), 1);
        assert_eq!(result.classifications.unrecovered.len(), 1);
    }

    #[test]
    fn comparison_only_cannot_claim_restoration() {
        let a = digest('a');
        let b = digest('b');
        let agent = object(
            RecoveryDomain::Filesystem,
            "0:61",
            Some(&a),
            Some(&b),
            &["CONTENT"],
        );
        let recovery = object(
            RecoveryDomain::Filesystem,
            "0:61",
            Some(&b),
            Some(&a),
            &["CONTENT"],
        );
        let result = report(vec![agent], vec![recovery], Vec::new(), true);
        assert_eq!(result.verdict, RecoveryConsistencyVerdict::Inconclusive);
        assert_eq!(result.classifications.unresolved.len(), 1);
        assert!(result.classifications.restored.is_empty());
    }

    fn raw_process_snapshot(
        scope: &StateScope,
        id: &str,
        phase: LinuxSnapshotPhase,
        has_process: bool,
    ) -> LinuxStateSnapshot {
        LinuxStateSnapshot {
            protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
            snapshot_id: id.to_owned(),
            phase,
            captured_unix_ns: 1,
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            scope: scope.clone(),
            scope_sha256: scope.sha256().unwrap(),
            sysctl: None,
            mounts: None,
            network: None,
            modules: None,
            process_residual: Some(DomainSnapshot {
                domain: LinuxDomainKind::ProcessResidual,
                namespace_inode: None,
                namespace_context: Vec::new(),
                source_identity_sha256: Some(digest('1')),
                records: if has_process {
                    vec![StateRecord {
                        key: "process/42".to_owned(),
                        value_sha256: hex::encode(Sha256::digest(b"x")),
                        value_size: 1,
                        value_bytes_hex: None,
                    }]
                } else {
                    Vec::new()
                },
                completeness: LinuxCompleteness {
                    status: LinuxCompletenessStatus::Complete,
                    reasons: Vec::new(),
                },
                issues: Vec::new(),
            }),
        }
    }

    fn raw_process_envelope(
        phase: RecoverySnapshotPhase,
        raw_phase: &str,
        snapshot_id: &str,
    ) -> RecoverySnapshotEnvelope {
        let capability = CgroupScopeCapability::for_roots(&[42]).unwrap();
        let binding = SnapshotDomainBinding::new(
            phase,
            raw_phase,
            format!("linux-state-{}.json", phase.as_str().to_ascii_lowercase()),
            128,
            digest('a'),
            snapshot_id,
            vec![RecoveryDomain::ProcessResidual],
        )
        .unwrap();
        let envelope = RecoverySnapshotEnvelope {
            schema_version: RECOVERY_REPORT_SCHEMA_VERSION,
            protocol_version: DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
            phase,
            run_id: "run-1".to_owned(),
            epoch: 1,
            checkpoint_id: "checkpoint-1".to_owned(),
            recovery_id: "recovery-1".to_owned(),
            snapshot_id: snapshot_id.to_owned(),
            capture_started_unix_ns: 1,
            capture_completed_unix_ns: 2,
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            deployment_scope_sha256: digest('b'),
            cgroup_scope_capability_sha256: capability.sha256().unwrap(),
            cgroup_scope_capability: capability,
            root_cgroups: vec![RecoveryRootCgroupBinding {
                cgroup_id: 42,
                path: "/observer-test".to_owned(),
            }],
            mount_namespace_ids: vec![100],
            pid_namespace_ids: vec![101],
            net_namespace_ids: vec![102],
            uts_namespace_ids: vec![103],
            ipc_namespace_ids: vec![104],
            barrier_sha256: digest('c'),
            identity_assessment_sha256: digest('d'),
            bpf: None,
            filesystem: None,
            linux: Some(binding),
        };
        envelope.validate().unwrap();
        envelope
    }

    #[test]
    fn raw_abc_process_object_values_prove_restoration() {
        let scope = StateScope {
            protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
            sysctl: None,
            mounts: None,
            network: None,
            modules: None,
            process_residual: Some(ProcessResidualScope {
                cgroup_path_bytes_hex: encode_absolute_path(Path::new(
                    "/sys/fs/cgroup/observer-test",
                ))
                .unwrap(),
                expected_cgroup_id: 42,
                additional_roots: Vec::new(),
                recursive: true,
                require_cgroup2: true,
                evidence: ValueEvidenceMode::Sha256Only,
                limits: CaptureLimits::default(),
            }),
        };
        let a = raw_process_snapshot(&scope, "snapshot-a", LinuxSnapshotPhase::S0, false);
        let b = raw_process_snapshot(&scope, "snapshot-b", LinuxSnapshotPhase::B, true);
        let c = raw_process_snapshot(&scope, "snapshot-c", LinuxSnapshotPhase::C, false);
        let ab =
            bpf_observer_linux_state_confirmers::compare_phases(&a, &b, a.phase, b.phase).unwrap();
        let bc =
            bpf_observer_linux_state_confirmers::compare_phases(&b, &c, b.phase, c.phase).unwrap();
        let ac =
            bpf_observer_linux_state_confirmers::compare_phases(&a, &c, a.phase, c.phase).unwrap();
        let a_envelope = raw_process_envelope(RecoverySnapshotPhase::A, "S0", "snapshot-a");
        let b_envelope = raw_process_envelope(RecoverySnapshotPhase::B, "B", "snapshot-b");
        let c_envelope = raw_process_envelope(RecoverySnapshotPhase::C, "C", "snapshot-c");
        let envelopes = RecoverySnapshotTriplet {
            a: &a_envelope,
            b: &b_envelope,
            c: &c_envelope,
        };
        let raw = RecoveryRawSnapshotTriplet {
            a: RecoveryRawSnapshotSet {
                linux: Some(&a),
                ..Default::default()
            },
            b: RecoveryRawSnapshotSet {
                linux: Some(&b),
                ..Default::default()
            },
            c: RecoveryRawSnapshotSet {
                linux: Some(&c),
                ..Default::default()
            },
        };
        let comparisons = RecoveryComparisonTriplet {
            agent: RecoveryComparisonSet {
                linux: Some(&ab),
                ..Default::default()
            },
            recovery: RecoveryComparisonSet {
                linux: Some(&bc),
                ..Default::default()
            },
            residual: RecoveryComparisonSet {
                linux: Some(&ac),
                ..Default::default()
            },
        };
        let report =
            build_recovery_verdict_report_with_raw(envelopes, raw, comparisons, &[]).unwrap();
        assert_eq!(
            report.verdict,
            RecoveryConsistencyVerdict::ConsistentWithinScope
        );
        assert_eq!(report.classifications.restored.len(), 1);
        assert!(report.classifications.unresolved.is_empty());

        let mut forged_ab = ab.clone();
        forged_ab.domains.process_residual.changes[0].key = "process/99".to_owned();
        let forged_comparisons = RecoveryComparisonTriplet {
            agent: RecoveryComparisonSet {
                linux: Some(&forged_ab),
                ..Default::default()
            },
            recovery: RecoveryComparisonSet {
                linux: Some(&bc),
                ..Default::default()
            },
            residual: RecoveryComparisonSet {
                linux: Some(&ac),
                ..Default::default()
            },
        };
        assert!(
            build_recovery_verdict_report_with_raw(envelopes, raw, forged_comparisons, &[])
                .is_err()
        );
    }
}
