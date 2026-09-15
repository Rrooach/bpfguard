// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const DEPLOYMENT_PROTOCOL_VERSION: u32 = 2;
pub const DEPLOYMENT_SCOPE_DOMAIN: &str = "LINUX_DEPLOYMENT_SCOPE_V2";
pub const HARD_MAX_PROCESSES: usize = 65_536;
pub const HARD_MAX_CGROUPS: usize = 16_384;
pub const HARD_MAX_RESOURCES: usize = 4096;
pub const HARD_MAX_PROC_SCAN: u32 = 1_000_000;
pub const HARD_MAX_CGROUP_DEPTH: u32 = 256;
pub const HARD_MAX_CGROUP_NODES: u32 = HARD_MAX_CGROUPS as u32;
pub const HARD_MAX_OPEN_FDS: u32 = 65_536;
pub const HARD_MAX_STRING_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeploymentKind {
    Direct,
    Docker,
    KataHost,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoverySourceTrust {
    KernelFilesystemsVerified,
    FixtureUntrusted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityStrength {
    KernelAnchored,
    KernelAnchoredWithUnresolvedResources,
    FixtureOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "deployment_kind",
    content = "configuration",
    deny_unknown_fields
)]
pub enum DeploymentRequest {
    #[serde(rename = "DIRECT")]
    Direct(DirectRequest),
    #[serde(rename = "DOCKER")]
    Docker(DockerRequest),
    #[serde(rename = "KATA_HOST")]
    KataHost(KataHostRequest),
}

impl DeploymentRequest {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Direct(request) => request.validate(),
            Self::Docker(request) => request.validate(),
            Self::KataHost(request) => request.validate(),
        }
    }

    pub fn kind(&self) -> DeploymentKind {
        match self {
            Self::Direct(_) => DeploymentKind::Direct,
            Self::Docker(_) => DeploymentKind::Docker,
            Self::KataHost(_) => DeploymentKind::KataHost,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryLimits {
    pub max_proc_entries: u32,
    pub max_cgroup_nodes: u32,
    pub max_cgroup_depth: u32,
    pub max_open_fds_per_process: u32,
}

impl Default for DiscoveryLimits {
    fn default() -> Self {
        Self {
            max_proc_entries: 131_072,
            max_cgroup_nodes: 4096,
            max_cgroup_depth: 64,
            max_open_fds_per_process: 8192,
        }
    }
}

impl DiscoveryLimits {
    pub fn validate(&self) -> Result<()> {
        validate_bound(
            "max_proc_entries",
            self.max_proc_entries,
            HARD_MAX_PROC_SCAN,
        )?;
        validate_bound(
            "max_cgroup_nodes",
            self.max_cgroup_nodes,
            HARD_MAX_CGROUP_NODES,
        )?;
        validate_bound(
            "max_cgroup_depth",
            self.max_cgroup_depth,
            HARD_MAX_CGROUP_DEPTH,
        )?;
        validate_bound(
            "max_open_fds_per_process",
            self.max_open_fds_per_process,
            HARD_MAX_OPEN_FDS,
        )
    }
}

fn validate_bound(name: &str, value: u32, hard_maximum: u32) -> Result<()> {
    if value == 0 || value > hard_maximum {
        bail!("deployment discovery {name} must be in 1..={hard_maximum}");
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectRequest {
    pub root_pid: u32,
    pub expected_cgroup_path: Option<String>,
    pub require_dedicated_cgroup: bool,
    pub limits: DiscoveryLimits,
}

impl DirectRequest {
    pub fn new(root_pid: u32) -> Self {
        Self {
            root_pid,
            expected_cgroup_path: None,
            require_dedicated_cgroup: true,
            limits: DiscoveryLimits::default(),
        }
    }

    fn validate(&self) -> Result<()> {
        validate_pid(self.root_pid)?;
        validate_optional_cgroup(&self.expected_cgroup_path)?;
        self.limits.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DockerRequest {
    /// Strict discovery requires a full lowercase 64-hex container identity.
    pub container_id: String,
    /// Supplying the init PID avoids an O(number-of-processes) procfs scan.
    pub init_pid: Option<u32>,
    pub expected_cgroup_path: Option<String>,
    pub limits: DiscoveryLimits,
}

impl DockerRequest {
    pub fn new(container_id: impl Into<String>, init_pid: Option<u32>) -> Self {
        Self {
            container_id: container_id.into(),
            init_pid,
            expected_cgroup_path: None,
            limits: DiscoveryLimits::default(),
        }
    }

    fn validate(&self) -> Result<()> {
        validate_lower_hex_id(&self.container_id, 64, "Docker container ID")?;
        if let Some(pid) = self.init_pid {
            validate_pid(pid)?;
        }
        validate_optional_cgroup(&self.expected_cgroup_path)?;
        self.limits.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KataHostRequest {
    /// Kata sandbox/container identity used to reject an unrelated shim.
    pub sandbox_id: String,
    /// Long-lived Kata shim/runtime anchor on the target Linux host.
    pub shim_pid: u32,
    pub expected_hypervisor_pid: Option<u32>,
    /// Optional long-lived runtime/virtiofs/backend PIDs that live outside the
    /// shim cgroup subtree. Each receives its own exact cgroup root.
    #[serde(default)]
    pub additional_host_pids: Vec<u32>,
    pub expected_cgroup_path: Option<String>,
    pub limits: DiscoveryLimits,
}

impl KataHostRequest {
    pub fn new(sandbox_id: impl Into<String>, shim_pid: u32) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
            shim_pid,
            expected_hypervisor_pid: None,
            additional_host_pids: Vec::new(),
            expected_cgroup_path: None,
            limits: DiscoveryLimits::default(),
        }
    }

    fn validate(&self) -> Result<()> {
        validate_subject_id(&self.sandbox_id, "Kata sandbox ID")?;
        validate_pid(self.shim_pid)?;
        if let Some(pid) = self.expected_hypervisor_pid {
            validate_pid(pid)?;
            if pid == self.shim_pid {
                bail!("Kata shim and hypervisor PIDs must differ");
            }
        }
        if self.additional_host_pids.len() > 64 {
            bail!("Kata request contains more than 64 explicit host PIDs");
        }
        let mut pids = self.additional_host_pids.clone();
        pids.sort_unstable();
        pids.dedup();
        if pids != self.additional_host_pids {
            bail!("Kata additional_host_pids must be canonical sorted and unique");
        }
        for pid in &pids {
            validate_pid(*pid)?;
            if *pid == self.shim_pid || Some(*pid) == self.expected_hypervisor_pid {
                bail!("Kata explicit host PID is duplicated across request roles");
            }
        }
        validate_optional_cgroup(&self.expected_cgroup_path)?;
        self.limits.validate()
    }
}

fn validate_pid(pid: u32) -> Result<()> {
    if pid == 0 || pid > i32::MAX as u32 {
        bail!("deployment PID must be in 1..={}", i32::MAX);
    }
    Ok(())
}

fn validate_optional_cgroup(value: &Option<String>) -> Result<()> {
    if let Some(path) = value {
        validate_cgroup_path(path)?;
    }
    Ok(())
}

pub(crate) fn validate_subject_id(value: &str, label: &str) -> Result<()> {
    if value.len() < 8 || value.len() > 128 || !value.is_ascii() {
        bail!("{label} must contain 8..=128 ASCII bytes");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("{label} contains an unsupported byte");
    }
    Ok(())
}

fn validate_lower_hex_id(value: &str, expected_len: usize, label: &str) -> Result<()> {
    if value.len() != expected_len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be exactly {expected_len} lowercase hexadecimal bytes");
    }
    Ok(())
}

pub(crate) fn validate_cgroup_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > HARD_MAX_STRING_BYTES
        || !path.starts_with('/')
        || path.as_bytes().contains(&0)
        || path.as_bytes().contains(&b'\n')
        || (path != "/"
            && path[1..]
                .split('/')
                .any(|component| component.is_empty() || component == "." || component == ".."))
    {
        bail!("cgroup path must be an absolute normalized Linux path");
    }
    if path.len() > 1 && path.ends_with('/') {
        bail!("cgroup path must not contain a trailing slash");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessRole {
    DirectRoot,
    DirectMember,
    DockerInit,
    DockerMember,
    KataShim,
    KataRuntime,
    KataHypervisor,
    KataAuxiliary,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub role: ProcessRole,
    pub start_time_ticks: u64,
    pub comm: String,
    pub executable_path_bytes_hex: String,
    pub executable_device: u64,
    pub executable_inode: u64,
    pub cmdline_sha256: String,
    pub cgroup_path: String,
    pub cgroup_id: u64,
    pub mount_namespace_id: u64,
    pub pid_namespace_id: u64,
    pub net_namespace_id: u64,
    pub uts_namespace_id: u64,
    pub ipc_namespace_id: u64,
    pub namespace_pid_chain: Vec<u32>,
}

impl ProcessIdentity {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_pid(self.pid)?;
        if self.start_time_ticks == 0
            || self.executable_device == 0
            || self.executable_inode == 0
            || self.cgroup_id == 0
            || self.mount_namespace_id == 0
            || self.pid_namespace_id == 0
            || self.net_namespace_id == 0
            || self.uts_namespace_id == 0
            || self.ipc_namespace_id == 0
        {
            bail!("process identity contains a zero kernel identity");
        }
        validate_text(&self.comm, "process comm")?;
        validate_lower_hex(&self.executable_path_bytes_hex, None, "executable path")?;
        let executable_path = hex::decode(&self.executable_path_bytes_hex)
            .context("decode executable path identity")?;
        if executable_path.len() > HARD_MAX_STRING_BYTES
            || executable_path.first() != Some(&b'/')
            || executable_path.contains(&0)
            || executable_path.contains(&b'\n')
        {
            bail!("executable path identity is not a bounded absolute Linux path");
        }
        validate_lower_hex(&self.cmdline_sha256, Some(64), "cmdline SHA-256")?;
        validate_cgroup_path(&self.cgroup_path)?;
        if self.namespace_pid_chain.is_empty()
            || self.namespace_pid_chain.iter().any(|pid| *pid == 0)
        {
            bail!("process namespace PID chain is empty or invalid");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CgroupIdentity {
    pub path: String,
    pub cgroup_id: u64,
    pub parent_cgroup_id: Option<u64>,
    pub depth_from_root: u32,
    pub populated: bool,
}

impl CgroupIdentity {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_cgroup_path(&self.path)?;
        if self.cgroup_id == 0 {
            bail!("cgroup identity must be nonzero");
        }
        if self.depth_from_root == 0 && self.parent_cgroup_id.is_none() {
            // A root can have an unobserved parent. None is therefore legal.
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KataResourceKind {
    VirtualDiskFile,
    VirtualBlockDevice,
    TapInterface,
    UnresolvedDiskArgument,
    UnresolvedNetworkArgument,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResourceResolutionStatus {
    Resolved,
    Unresolved,
}

/// The exact QEMU command-line mechanism that bound a resolved TAP backend.
/// `QemuFd` and `QemuFds` are accepted only after every referenced descriptor
/// has been proven to be an open tun descriptor owned by the captured QEMU
/// process and its `fdinfo` `iff:` identity has been checked.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KataNetworkBinding {
    QemuIfname,
    QemuFd,
    QemuFds,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KataHostResource {
    pub kind: KataResourceKind,
    pub resolution: ResourceResolutionStatus,
    pub owner_pid: u32,
    pub source_argument_sha256: String,
    pub path_bytes_hex: Option<String>,
    pub device: Option<u64>,
    pub inode: Option<u64>,
    pub rdev: Option<u64>,
    pub size_bytes: Option<u64>,
    pub interface_name: Option<String>,
    pub interface_index: Option<u32>,
    pub net_namespace_id: Option<u64>,
    pub network_binding: Option<KataNetworkBinding>,
    #[serde(default)]
    pub network_file_descriptors: Vec<u32>,
    pub unresolved_reason: Option<String>,
}

impl KataHostResource {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_pid(self.owner_pid)?;
        validate_lower_hex(
            &self.source_argument_sha256,
            Some(64),
            "Kata source argument SHA-256",
        )?;
        match self.resolution {
            ResourceResolutionStatus::Resolved => {
                if self.unresolved_reason.is_some() {
                    bail!("resolved Kata resource carries an unresolved reason");
                }
                match self.kind {
                    KataResourceKind::VirtualDiskFile | KataResourceKind::VirtualBlockDevice => {
                        let path = self
                            .path_bytes_hex
                            .as_deref()
                            .context("resolved Kata disk has no path")?;
                        validate_lower_hex(path, None, "Kata disk path")?;
                        if !matches!(self.device, Some(value) if value != 0)
                            || !matches!(self.inode, Some(value) if value != 0)
                        {
                            bail!("resolved Kata disk contains a zero object identity");
                        }
                        if self.network_binding.is_some()
                            || !self.network_file_descriptors.is_empty()
                        {
                            bail!("resolved Kata disk carries network binding evidence");
                        }
                    }
                    KataResourceKind::TapInterface => {
                        validate_text(
                            self.interface_name
                                .as_deref()
                                .context("resolved TAP has no interface name")?,
                            "TAP interface name",
                        )?;
                        if self.interface_index == Some(0) || self.net_namespace_id == Some(0) {
                            bail!("resolved TAP contains a zero network identity");
                        }
                        match self
                            .network_binding
                            .context("resolved TAP has no QEMU binding mechanism")?
                        {
                            KataNetworkBinding::QemuIfname => {
                                if !self.network_file_descriptors.is_empty() {
                                    bail!("ifname-bound TAP carries file descriptors");
                                }
                            }
                            KataNetworkBinding::QemuFd => {
                                if self.network_file_descriptors.len() != 1 {
                                    bail!("fd-bound TAP must carry exactly one descriptor");
                                }
                            }
                            KataNetworkBinding::QemuFds => {
                                if self.network_file_descriptors.is_empty() {
                                    bail!("fds-bound TAP carries no descriptors");
                                }
                            }
                        }
                        let mut descriptors = HashSet::new();
                        for descriptor in &self.network_file_descriptors {
                            if *descriptor >= HARD_MAX_OPEN_FDS || !descriptors.insert(*descriptor)
                            {
                                bail!("resolved TAP descriptor set is invalid or duplicated");
                            }
                        }
                    }
                    KataResourceKind::UnresolvedDiskArgument
                    | KataResourceKind::UnresolvedNetworkArgument => {
                        bail!("an unresolved Kata resource kind cannot be resolved")
                    }
                }
            }
            ResourceResolutionStatus::Unresolved => {
                if self.unresolved_reason.as_deref().unwrap_or("").is_empty() {
                    bail!("unresolved Kata resource has no reason");
                }
                if !matches!(
                    self.kind,
                    KataResourceKind::UnresolvedDiskArgument
                        | KataResourceKind::UnresolvedNetworkArgument
                ) {
                    bail!("resolved Kata resource kind is marked unresolved");
                }
                if self.path_bytes_hex.is_some()
                    || self.device.is_some()
                    || self.inode.is_some()
                    || self.rdev.is_some()
                    || self.size_bytes.is_some()
                    || self.interface_name.is_some()
                    || self.interface_index.is_some()
                    || self.net_namespace_id.is_some()
                    || self.network_binding.is_some()
                    || !self.network_file_descriptors.is_empty()
                {
                    bail!("unresolved Kata resource carries unverified object identity");
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DescendantObservationRequirement {
    ExactLeaf,
    CgroupV2AncestorMatchRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentCoverage {
    pub direct_syscall_attribution_only: bool,
    pub whole_current_cgroup_subtree_enumerated: bool,
    pub descendant_observation_requirement: DescendantObservationRequirement,
    pub mount_namespaces_identified: bool,
    pub network_namespaces_identified: bool,
    pub uts_namespaces_identified: bool,
    pub ipc_namespaces_identified: bool,
    pub kata_guest_entered: bool,
    pub kata_host_backends_discovered_from_qemu_argv: bool,
    /// True iff at least one QEMU `fd=`/`fds=` TAP argument was resolved from
    /// that exact QEMU process's tun `fdinfo`, rather than inferred by time.
    pub kata_tap_fdinfo_evidence_present: bool,
    /// False in protocol v1: resolved backend path identities are not yet
    /// retained as an owner-mountns FD plus an O_PATH object FD.
    pub kata_host_backend_namespace_pinned: bool,
    pub external_runtime_tool_used: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentManifest {
    pub protocol_version: u32,
    pub domain: String,
    pub deployment_kind: DeploymentKind,
    pub source_trust: DiscoverySourceTrust,
    pub identity_strength: IdentityStrength,
    pub subject_id: String,
    pub captured_unix_ns: u128,
    pub boot_id: String,
    pub root_cgroups: Vec<CgroupIdentity>,
    pub observed_cgroups: Vec<CgroupIdentity>,
    pub processes: Vec<ProcessIdentity>,
    pub mount_namespace_ids: Vec<u64>,
    pub net_namespace_ids: Vec<u64>,
    pub uts_namespace_ids: Vec<u64>,
    pub ipc_namespace_ids: Vec<u64>,
    pub kata_host_resources: Vec<KataHostResource>,
    pub coverage: DeploymentCoverage,
    pub limitations: Vec<String>,
    pub scope_sha256: String,
}

impl DeploymentManifest {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != DEPLOYMENT_PROTOCOL_VERSION
            || self.domain != DEPLOYMENT_SCOPE_DOMAIN
        {
            bail!("unsupported deployment manifest protocol/domain");
        }
        validate_subject_id(&self.subject_id, "deployment subject ID")?;
        if self.captured_unix_ns == 0 || !is_canonical_uuid(&self.boot_id) {
            bail!("deployment manifest lacks capture time or boot identity");
        }
        if self.root_cgroups.is_empty()
            || self.root_cgroups.len() > HARD_MAX_CGROUPS
            || self.observed_cgroups.is_empty()
            || self.observed_cgroups.len() > HARD_MAX_CGROUPS
            || self.processes.is_empty()
            || self.processes.len() > HARD_MAX_PROCESSES
            || self.kata_host_resources.len() > HARD_MAX_RESOURCES
        {
            bail!("deployment manifest collection cardinality is invalid");
        }
        if self.source_trust == DiscoverySourceTrust::FixtureUntrusted
            && self.identity_strength != IdentityStrength::FixtureOnly
        {
            bail!("fixture discovery cannot claim a kernel-anchored identity");
        }
        if self.source_trust == DiscoverySourceTrust::KernelFilesystemsVerified
            && self.identity_strength == IdentityStrength::FixtureOnly
        {
            bail!("live discovery cannot claim fixture-only identity");
        }
        for cgroup in self.root_cgroups.iter().chain(&self.observed_cgroups) {
            cgroup.validate()?;
        }
        for process in &self.processes {
            process.validate()?;
        }
        for resource in &self.kata_host_resources {
            resource.validate()?;
        }
        ensure_sorted_unique_by(
            &self.root_cgroups,
            |value| value.path.clone(),
            "root cgroups",
        )?;
        ensure_sorted_unique_by(
            &self.observed_cgroups,
            |value| value.path.clone(),
            "observed cgroups",
        )?;
        ensure_sorted_unique_by(&self.processes, |value| value.pid, "process identities")?;
        ensure_sorted_unique(&self.mount_namespace_ids, "mount namespace IDs")?;
        ensure_sorted_unique(&self.net_namespace_ids, "network namespace IDs")?;
        ensure_sorted_unique(&self.uts_namespace_ids, "UTS namespace IDs")?;
        ensure_sorted_unique(&self.ipc_namespace_ids, "IPC namespace IDs")?;
        ensure_sorted_unique(&self.limitations, "deployment limitations")?;
        let observed_paths = self
            .observed_cgroups
            .iter()
            .map(|value| value.path.as_str())
            .collect::<HashSet<_>>();
        for root in &self.root_cgroups {
            if !observed_paths.contains(root.path.as_str()) || root.depth_from_root != 0 {
                bail!("deployment root cgroup is absent from the observed subtree");
            }
        }
        for process in &self.processes {
            if !observed_paths.contains(process.cgroup_path.as_str()) {
                bail!("deployment process is outside the committed cgroup subtree");
            }
            let cgroup = self
                .observed_cgroups
                .iter()
                .find(|value| value.path == process.cgroup_path)
                .context("process cgroup disappeared from observed identities")?;
            if cgroup.cgroup_id != process.cgroup_id {
                bail!("process cgroup path/ID binding is inconsistent");
            }
            if self
                .mount_namespace_ids
                .binary_search(&process.mount_namespace_id)
                .is_err()
                || self
                    .net_namespace_ids
                    .binary_search(&process.net_namespace_id)
                    .is_err()
                || self
                    .uts_namespace_ids
                    .binary_search(&process.uts_namespace_id)
                    .is_err()
                || self
                    .ipc_namespace_ids
                    .binary_search(&process.ipc_namespace_id)
                    .is_err()
            {
                bail!("process namespace identity is absent from namespace indexes");
            }
        }
        self.validate_kind_contract()?;
        validate_lower_hex(&self.scope_sha256, Some(64), "deployment scope SHA-256")?;
        if self.compute_scope_sha256()? != self.scope_sha256 {
            bail!("deployment scope SHA-256 does not match manifest identities");
        }
        Ok(())
    }

    /// Exact current cgroup inode IDs for recorders that do not implement an
    /// ancestor-cgroup match. Callers must mark evidence incomplete if the
    /// subtree can change after READY.
    pub fn registration_cgroup_ids(&self) -> Vec<u64> {
        self.observed_cgroups
            .iter()
            .map(|cgroup| cgroup.cgroup_id)
            .collect()
    }

    /// Stable cgroup-v2 roots for a recorder with kernel ancestor matching.
    pub fn registration_root_cgroup_ids(&self) -> Vec<u64> {
        self.root_cgroups
            .iter()
            .map(|cgroup| cgroup.cgroup_id)
            .collect()
    }

    fn validate_kind_contract(&self) -> Result<()> {
        let has_role = |role| self.processes.iter().any(|process| process.role == role);
        match self.deployment_kind {
            DeploymentKind::Direct => {
                if !has_role(ProcessRole::DirectRoot)
                    || self.processes.iter().any(|process| {
                        !matches!(
                            process.role,
                            ProcessRole::DirectRoot | ProcessRole::DirectMember
                        )
                    })
                    || !self.kata_host_resources.is_empty()
                    || self.coverage.kata_tap_fdinfo_evidence_present
                    || self.coverage.kata_host_backend_namespace_pinned
                {
                    bail!("direct deployment role/resource contract is invalid");
                }
            }
            DeploymentKind::Docker => {
                validate_lower_hex_id(&self.subject_id, 64, "Docker manifest subject")?;
                if self
                    .processes
                    .iter()
                    .filter(|process| process.role == ProcessRole::DockerInit)
                    .count()
                    != 1
                    || self.processes.iter().any(|process| {
                        !matches!(
                            process.role,
                            ProcessRole::DockerInit | ProcessRole::DockerMember
                        )
                    })
                    || !self.kata_host_resources.is_empty()
                    || self.coverage.kata_tap_fdinfo_evidence_present
                    || self.coverage.kata_host_backend_namespace_pinned
                {
                    bail!("Docker deployment role/resource contract is invalid");
                }
            }
            DeploymentKind::KataHost => {
                if self
                    .processes
                    .iter()
                    .filter(|process| process.role == ProcessRole::KataShim)
                    .count()
                    != 1
                    || !has_role(ProcessRole::KataHypervisor)
                    || self.coverage.kata_guest_entered
                    || self.coverage.kata_host_backend_namespace_pinned
                {
                    bail!("Kata-host deployment role/boundary contract is invalid");
                }
                let fdinfo_evidence_present = self.kata_host_resources.iter().any(|resource| {
                    resource.resolution == ResourceResolutionStatus::Resolved
                        && matches!(
                            resource.network_binding,
                            Some(KataNetworkBinding::QemuFd | KataNetworkBinding::QemuFds)
                        )
                });
                if self.coverage.kata_tap_fdinfo_evidence_present != fdinfo_evidence_present {
                    bail!("Kata TAP fdinfo coverage disagrees with resource evidence");
                }
                for resource in &self.kata_host_resources {
                    let owner = self
                        .processes
                        .iter()
                        .find(|process| process.pid == resource.owner_pid)
                        .context("Kata host resource owner is absent from process identities")?;
                    if owner.role != ProcessRole::KataHypervisor {
                        bail!("Kata host resource owner is not a captured hypervisor");
                    }
                    if resource.kind == KataResourceKind::TapInterface
                        && resource.net_namespace_id != Some(owner.net_namespace_id)
                    {
                        bail!("Kata TAP namespace disagrees with its QEMU owner");
                    }
                }
            }
        }
        if !self.coverage.direct_syscall_attribution_only
            || !self.coverage.whole_current_cgroup_subtree_enumerated
            || !self.coverage.mount_namespaces_identified
            || !self.coverage.network_namespaces_identified
            || !self.coverage.uts_namespaces_identified
            || !self.coverage.ipc_namespaces_identified
            || self.coverage.external_runtime_tool_used
        {
            bail!("deployment coverage contains an unsupported assurance claim");
        }
        Ok(())
    }

    pub fn compute_scope_sha256(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Scope<'a> {
            protocol_version: u32,
            domain: &'a str,
            deployment_kind: DeploymentKind,
            source_trust: DiscoverySourceTrust,
            identity_strength: IdentityStrength,
            subject_id: &'a str,
            boot_id: &'a str,
            root_cgroups: &'a [CgroupIdentity],
            observed_cgroups: &'a [CgroupIdentity],
            processes: &'a [ProcessIdentity],
            mount_namespace_ids: &'a [u64],
            net_namespace_ids: &'a [u64],
            uts_namespace_ids: &'a [u64],
            ipc_namespace_ids: &'a [u64],
            kata_host_resources: &'a [KataHostResource],
            coverage: &'a DeploymentCoverage,
        }
        let canonical = serde_json::to_vec(&Scope {
            protocol_version: self.protocol_version,
            domain: &self.domain,
            deployment_kind: self.deployment_kind,
            source_trust: self.source_trust,
            identity_strength: self.identity_strength,
            subject_id: &self.subject_id,
            boot_id: &self.boot_id,
            root_cgroups: &self.root_cgroups,
            observed_cgroups: &self.observed_cgroups,
            processes: &self.processes,
            mount_namespace_ids: &self.mount_namespace_ids,
            net_namespace_ids: &self.net_namespace_ids,
            uts_namespace_ids: &self.uts_namespace_ids,
            ipc_namespace_ids: &self.ipc_namespace_ids,
            kata_host_resources: &self.kata_host_resources,
            coverage: &self.coverage,
        })
        .context("serialize canonical deployment scope")?;
        Ok(hex::encode(Sha256::digest(canonical)))
    }
}

fn ensure_sorted_unique<T: Ord>(values: &[T], label: &str) -> Result<()> {
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        bail!("{label} must be canonical sorted and unique");
    }
    Ok(())
}

fn ensure_sorted_unique_by<T, K: Ord, F: Fn(&T) -> K>(
    values: &[T],
    key: F,
    label: &str,
) -> Result<()> {
    if !values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1])) {
        bail!("{label} must be canonical sorted and unique");
    }
    Ok(())
}

fn validate_text(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > HARD_MAX_STRING_BYTES
        || value.as_bytes().contains(&0)
        || value.as_bytes().contains(&b'\n')
    {
        bail!("{label} is empty or exceeds the closed text contract");
    }
    Ok(())
}

pub(crate) fn validate_lower_hex(value: &str, len: Option<usize>, label: &str) -> Result<()> {
    if value.is_empty()
        || len.map(|expected| value.len() != expected).unwrap_or(false)
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} is not canonical lowercase hexadecimal");
    }
    Ok(())
}

pub(crate) fn is_canonical_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    value.bytes().enumerate().all(|(index, byte)| match index {
        8 | 13 | 18 | 23 => byte == b'-',
        _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
    })
}
