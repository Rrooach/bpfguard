// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, Context, Result};
use bpf_observer_deployment::{DeploymentKind, DeploymentManifest, ProcessRole};
use bpf_observer_linux_state_confirmers::{
    CaptureLimits, CausalAttributionStatus, CompletenessStatus, DomainComparison, DomainKind,
    EndpointDifferenceStatus, LinuxNamespaceKind, NamespaceCaptureEvidence, NamespaceCaptureSource,
    NamespaceTarget, ProcessResidualRoot, ProcessResidualScope, StateComparison, StateScope,
    StateSnapshot, StateVerdict, SysctlNamespaceTargets, TerminalState, ValueEvidenceMode,
    HARD_MAX_PROCESS_RESIDUAL_ROOTS, LINUX_STATE_CONFIRMATION_DOMAIN,
    LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

const CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BoundLinuxStateScope {
    pub scope: StateScope,
    pub sysctl_namespace_targets: Option<SysctlNamespaceTargets>,
    pub forced_incomplete_reasons: Vec<String>,
}

/// Bind namespace and process-residual confirmation to kernel identities in
/// the deployment manifest rather than accepting observer-relative targets.
pub(crate) fn bind_linux_state_scope(
    configured: Option<&StateScope>,
    manifest: &DeploymentManifest,
) -> Result<Option<BoundLinuxStateScope>> {
    let Some(configured) = configured else {
        return Ok(None);
    };
    configured.validate()?;
    manifest.validate()?;
    let mut effective = configured.clone();
    if let Some(mounts) = effective.mounts.as_mut() {
        mounts.namespace =
            bind_namespace_target(&mounts.namespace, manifest, NamespaceKind::Mount)?;
    }
    if let Some(network) = effective.network.as_mut() {
        network.namespace =
            bind_namespace_target(&network.namespace, manifest, NamespaceKind::Network)?;
    }
    if manifest.root_cgroups.len() > HARD_MAX_PROCESS_RESIDUAL_ROOTS {
        bail!(
            "deployment has {} residual roots; maximum is {HARD_MAX_PROCESS_RESIDUAL_ROOTS}",
            manifest.root_cgroups.len()
        );
    }
    let mut residual_roots = Vec::with_capacity(manifest.root_cgroups.len());
    for root in &manifest.root_cgroups {
        let relative = root
            .path
            .strip_prefix('/')
            .context("deployment root cgroup path is not absolute")?;
        let path = if relative.is_empty() {
            Path::new(CGROUP_V2_ROOT).to_owned()
        } else {
            Path::new(CGROUP_V2_ROOT).join(relative)
        };
        residual_roots.push(ProcessResidualRoot::new(&path, root.cgroup_id)?);
    }
    let primary = residual_roots
        .first()
        .context("deployment manifest has no residual root")?;
    let residual = ProcessResidualScope {
        cgroup_path_bytes_hex: primary.cgroup_path_bytes_hex.clone(),
        expected_cgroup_id: primary.expected_cgroup_id,
        additional_roots: residual_roots.into_iter().skip(1).collect(),
        recursive: true,
        require_cgroup2: true,
        evidence: ValueEvidenceMode::Sha256Only,
        limits: CaptureLimits {
            max_records: 65_536,
            max_value_bytes: 4 * 1024 * 1024,
            max_total_value_bytes: 16 * 1024 * 1024,
            deadline_ms: 15_000,
        },
    };
    let sysctl_namespace_targets = effective
        .sysctl
        .as_ref()
        .map(|_| bind_sysctl_namespace_targets(manifest))
        .transpose()?;
    Ok(Some(BoundLinuxStateScope {
        scope: effective.with_process_residual(residual)?,
        sysctl_namespace_targets,
        forced_incomplete_reasons: Vec::new(),
    }))
}

fn bind_sysctl_namespace_targets(manifest: &DeploymentManifest) -> Result<SysctlNamespaceTargets> {
    let expected_role = match manifest.deployment_kind {
        DeploymentKind::Direct => ProcessRole::DirectRoot,
        DeploymentKind::Docker => ProcessRole::DockerInit,
        DeploymentKind::KataHost => ProcessRole::KataShim,
    };
    let process = manifest
        .processes
        .iter()
        .filter(|process| process.role == expected_role)
        .min_by_key(|process| process.pid)
        .with_context(|| format!("deployment has no {expected_role:?} sysctl namespace anchor"))?;
    Ok(SysctlNamespaceTargets {
        network: NamespaceTarget {
            pid: process.pid,
            expected_namespace_inode: process.net_namespace_id,
        },
        uts: NamespaceTarget {
            pid: process.pid,
            expected_namespace_inode: process.uts_namespace_id,
        },
        ipc: NamespaceTarget {
            pid: process.pid,
            expected_namespace_inode: process.ipc_namespace_id,
        },
    })
}

pub(crate) fn retained_namespace_contract_reasons(
    bound: &BoundLinuxStateScope,
    snapshot: &StateSnapshot,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if let (Some(targets), Some(domain)) = (
        bound.sysctl_namespace_targets.as_ref(),
        snapshot.sysctl.as_ref(),
    ) {
        let expected = vec![
            NamespaceCaptureEvidence {
                kind: LinuxNamespaceKind::Ipc,
                inode: targets.ipc.expected_namespace_inode,
                source: NamespaceCaptureSource::RetainedFileDescriptor,
            },
            NamespaceCaptureEvidence {
                kind: LinuxNamespaceKind::Network,
                inode: targets.network.expected_namespace_inode,
                source: NamespaceCaptureSource::RetainedFileDescriptor,
            },
            NamespaceCaptureEvidence {
                kind: LinuxNamespaceKind::Uts,
                inode: targets.uts.expected_namespace_inode,
                source: NamespaceCaptureSource::RetainedFileDescriptor,
            },
        ];
        if domain.namespace_context != expected {
            reasons.push(
                "sysctl snapshot was not captured through the retained deployment network/UTS/IPC namespace capabilities"
                    .to_owned(),
            );
        }
    }
    if let (Some(scope), Some(domain)) = (bound.scope.mounts.as_ref(), snapshot.mounts.as_ref()) {
        let expected = vec![NamespaceCaptureEvidence {
            kind: LinuxNamespaceKind::Mount,
            inode: scope.namespace.expected_namespace_inode,
            source: NamespaceCaptureSource::RetainedFileDescriptor,
        }];
        if domain.namespace_context != expected {
            reasons.push(
                "mount snapshot was not captured through the retained deployment mount namespace capability"
                    .to_owned(),
            );
        }
    }
    if let (Some(scope), Some(domain)) = (bound.scope.network.as_ref(), snapshot.network.as_ref()) {
        let expected = vec![NamespaceCaptureEvidence {
            kind: LinuxNamespaceKind::Network,
            inode: scope.namespace.expected_namespace_inode,
            source: NamespaceCaptureSource::RetainedFileDescriptor,
        }];
        if domain.namespace_context != expected {
            reasons.push(
                "network snapshot was not captured through the retained deployment network namespace capability"
                    .to_owned(),
            );
        }
    }
    reasons
}

#[derive(Clone, Copy)]
enum NamespaceKind {
    Mount,
    Network,
}

impl NamespaceKind {
    fn label(self) -> &'static str {
        match self {
            Self::Mount => "mount",
            Self::Network => "network",
        }
    }

    fn inode(self, process: &bpf_observer_deployment::ProcessIdentity) -> u64 {
        match self {
            Self::Mount => process.mount_namespace_id,
            Self::Network => process.net_namespace_id,
        }
    }
}

fn bind_namespace_target(
    configured: &NamespaceTarget,
    manifest: &DeploymentManifest,
    kind: NamespaceKind,
) -> Result<NamespaceTarget> {
    let matching_inode = manifest
        .processes
        .iter()
        .filter(|process| kind.inode(process) == configured.expected_namespace_inode);
    let process = if configured.pid == 0 {
        matching_inode
            .min_by_key(|process| process.pid)
            .with_context(|| {
                format!(
                    "configured {} namespace inode {} is not owned by a deployment process; refusing observer-namespace fallback",
                    kind.label(),
                    configured.expected_namespace_inode
                )
            })?
    } else {
        let process = manifest
            .processes
            .iter()
            .find(|process| process.pid == configured.pid)
            .with_context(|| {
                format!(
                    "configured {} namespace PID {} is not a deployment process",
                    kind.label(),
                    configured.pid
                )
            })?;
        if kind.inode(process) != configured.expected_namespace_inode {
            bail!(
                "configured {} namespace PID/inode pair does not match the deployment manifest",
                kind.label()
            );
        }
        process
    };
    if process.pid == 0 {
        bail!("deployment namespace anchor PID must be non-zero");
    }
    Ok(NamespaceTarget {
        pid: process.pid,
        expected_namespace_inode: kind.inode(process),
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LinuxStateEvidenceStatus {
    Complete,
    Incomplete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxStateDomainSummary {
    pub domain: DomainKind,
    pub protocol_domain: String,
    pub endpoint_difference: EndpointDifferenceStatus,
    pub verdict: StateVerdict,
    pub state_completeness: CompletenessStatus,
    pub terminal_state: TerminalState,
    pub causal_attribution_status: CausalAttributionStatus,
    pub change_count: u64,
}

impl LinuxStateDomainSummary {
    fn from_comparison(comparison: &DomainComparison) -> Result<Self> {
        if comparison.protocol_domain != comparison.domain.protocol_name() {
            bail!("Linux state comparison domain protocol identity is inconsistent");
        }
        Ok(Self {
            domain: comparison.domain,
            protocol_domain: comparison.protocol_domain.clone(),
            endpoint_difference: comparison.endpoint_difference,
            verdict: comparison.verdict,
            state_completeness: comparison.state_completeness.status,
            terminal_state: comparison.terminal_state,
            causal_attribution_status: comparison.causal_attribution_status,
            change_count: comparison.changes.len() as u64,
        })
    }

    fn validate_kind(&self, expected: DomainKind) -> Result<()> {
        if self.domain != expected || self.protocol_domain != expected.protocol_name() {
            bail!("Linux state report domain vector is mislabelled");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxStateDomainVector {
    pub sysctl: LinuxStateDomainSummary,
    pub mounts: LinuxStateDomainSummary,
    pub network: LinuxStateDomainSummary,
    pub modules: LinuxStateDomainSummary,
    pub process_residual: LinuxStateDomainSummary,
}

impl LinuxStateDomainVector {
    fn from_comparison(comparison: &StateComparison) -> Result<Self> {
        Ok(Self {
            sysctl: LinuxStateDomainSummary::from_comparison(&comparison.domains.sysctl)?,
            mounts: LinuxStateDomainSummary::from_comparison(&comparison.domains.mounts)?,
            network: LinuxStateDomainSummary::from_comparison(&comparison.domains.network)?,
            modules: LinuxStateDomainSummary::from_comparison(&comparison.domains.modules)?,
            process_residual: LinuxStateDomainSummary::from_comparison(
                &comparison.domains.process_residual,
            )?,
        })
    }

    fn summaries(&self) -> [&LinuxStateDomainSummary; 5] {
        [
            &self.sysctl,
            &self.mounts,
            &self.network,
            &self.modules,
            &self.process_residual,
        ]
    }

    fn validate(&self) -> Result<()> {
        self.sysctl.validate_kind(DomainKind::Sysctl)?;
        self.mounts.validate_kind(DomainKind::Mount)?;
        self.network.validate_kind(DomainKind::Network)?;
        self.modules.validate_kind(DomainKind::KernelModule)?;
        self.process_residual
            .validate_kind(DomainKind::ProcessResidual)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxStateReport {
    pub protocol_version: u32,
    pub domain: String,
    pub scope_sha256: String,
    pub s0_snapshot_id: String,
    pub s0_snapshot_sha256: String,
    pub s1_snapshot_id: String,
    pub s1_snapshot_sha256: String,
    pub comparison_sha256: String,
    pub evidence_status: LinuxStateEvidenceStatus,
    pub domains: LinuxStateDomainVector,
    pub contract_incomplete_reasons: Vec<String>,
    pub reasons: Vec<String>,
}

impl LinuxStateReport {
    pub(crate) fn from_comparison(
        comparison: &StateComparison,
        s0_snapshot_sha256: String,
        s1_snapshot_sha256: String,
        comparison_sha256: String,
        contract_incomplete_reasons: &[String],
    ) -> Result<Self> {
        if comparison.protocol_version != LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION
            || comparison.domain != LINUX_STATE_CONFIRMATION_DOMAIN
        {
            bail!("unsupported Linux state comparison envelope");
        }
        let domains = LinuxStateDomainVector::from_comparison(comparison)?;
        let mut contract_incomplete_reasons = contract_incomplete_reasons.to_vec();
        contract_incomplete_reasons.sort();
        contract_incomplete_reasons.dedup();
        let reasons = evidence_reasons(&domains, &contract_incomplete_reasons);
        let report = Self {
            protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
            domain: LINUX_STATE_CONFIRMATION_DOMAIN.to_owned(),
            scope_sha256: comparison.scope_sha256.clone(),
            s0_snapshot_id: comparison.s0_snapshot_id.clone(),
            s0_snapshot_sha256,
            s1_snapshot_id: comparison.s1_snapshot_id.clone(),
            s1_snapshot_sha256,
            comparison_sha256,
            evidence_status: if reasons.is_empty() {
                LinuxStateEvidenceStatus::Complete
            } else {
                LinuxStateEvidenceStatus::Incomplete
            },
            domains,
            contract_incomplete_reasons,
            reasons,
        };
        report.validate()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION
            || self.domain != LINUX_STATE_CONFIRMATION_DOMAIN
            || self.s0_snapshot_id.is_empty()
            || self.s1_snapshot_id.is_empty()
        {
            bail!("Linux state report envelope is invalid");
        }
        validate_sha256(&self.scope_sha256, "Linux state scope")?;
        validate_sha256(&self.s0_snapshot_sha256, "Linux state S0")?;
        validate_sha256(&self.s1_snapshot_sha256, "Linux state S1")?;
        validate_sha256(&self.comparison_sha256, "Linux state comparison")?;
        self.domains.validate()?;
        if !self
            .contract_incomplete_reasons
            .windows(2)
            .all(|pair| pair[0] < pair[1])
            || !self.reasons.windows(2).all(|pair| pair[0] < pair[1])
        {
            bail!("Linux state evidence reasons must be canonical sorted and unique");
        }
        let rebuilt_reasons = evidence_reasons(&self.domains, &self.contract_incomplete_reasons);
        if rebuilt_reasons != self.reasons
            || self.evidence_status
                != if self.reasons.is_empty() {
                    LinuxStateEvidenceStatus::Complete
                } else {
                    LinuxStateEvidenceStatus::Incomplete
                }
        {
            bail!("Linux state report status/reasons are internally inconsistent");
        }
        Ok(())
    }
}

pub(crate) fn confirmation_contract_reasons(
    base: &[String],
    deployment_boot_id: &str,
    s0: &StateSnapshot,
    s1: &StateSnapshot,
    pre_finish_barrier_complete: bool,
    closure_barrier_complete: bool,
    recorder_drains_complete: bool,
) -> Vec<String> {
    let mut reasons = base.to_vec();
    if s0.boot_id != deployment_boot_id {
        reasons
            .push("Linux state S0 boot identity differs from the deployment manifest".to_owned());
    }
    if s1.boot_id != deployment_boot_id {
        reasons
            .push("Linux state S1 boot identity differs from the deployment manifest".to_owned());
    }
    if !pre_finish_barrier_complete {
        reasons.push(
            "Linux state S1 was not protected by a complete pre-FINISH freeze and identity barrier"
                .to_owned(),
        );
    }
    if !closure_barrier_complete {
        reasons.push(
            "Linux state S1 closure freeze or deployment identity barrier is incomplete".to_owned(),
        );
    }
    if !recorder_drains_complete {
        reasons.push(
            "Linux state S1 followed an incomplete effect or lifecycle recorder drain".to_owned(),
        );
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

fn evidence_reasons(
    domains: &LinuxStateDomainVector,
    forced_incomplete_reasons: &[String],
) -> Vec<String> {
    let mut reasons = forced_incomplete_reasons.to_vec();
    for summary in domains.summaries() {
        if summary.state_completeness == CompletenessStatus::Incomplete {
            reasons.push(format!(
                "domain {} endpoint state is incomplete",
                summary.protocol_domain
            ));
        }
    }
    reasons.sort();
    reasons.dedup();
    reasons
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
