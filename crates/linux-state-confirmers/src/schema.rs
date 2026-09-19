// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION: u32 = 1;
pub const LINUX_STATE_CONFIRMATION_DOMAIN: &str = "LINUX_SCOPED_ENDPOINT_STATE_V1";
pub const HARD_MAX_SCOPE_JSON_BYTES: u64 = 2 * 1024 * 1024;
pub const HARD_MAX_SNAPSHOT_JSON_BYTES: u64 = 64 * 1024 * 1024;
pub const HARD_MAX_COMPARISON_JSON_BYTES: u64 = 64 * 1024 * 1024;
pub const HARD_MAX_RECORDS_PER_DOMAIN: usize = 262_144;
pub const HARD_MAX_RECORD_VALUE_BYTES: u64 = 16 * 1024 * 1024;
pub const HARD_MAX_TOTAL_VALUE_BYTES: u64 = 64 * 1024 * 1024;
pub const HARD_MAX_ISSUES_PER_DOMAIN: usize = 1024;
pub const HARD_MAX_ISSUE_KEY_CHARS: usize = 256;
pub const HARD_MAX_ISSUE_DETAIL_CHARS: usize = 512;
pub const HARD_MAX_KEY_BYTES: usize = 4096;
pub const HARD_MAX_PATH_BYTES: usize = 4096;
pub const HARD_MAX_DEADLINE_MS: u64 = 120_000;
pub const HARD_MAX_PROCESS_RESIDUAL_ROOTS: usize = 8;
const MAX_IDENTIFIER_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SnapshotPhase {
    S0,
    S1,
    A,
    B,
    C,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureRequest {
    pub snapshot_id: String,
    pub phase: SnapshotPhase,
}

impl CaptureRequest {
    pub fn validate(&self) -> Result<()> {
        validate_identifier("snapshot_id", &self.snapshot_id)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DomainKind {
    Sysctl,
    Mount,
    Network,
    KernelModule,
    ProcessResidual,
}

impl DomainKind {
    pub fn protocol_name(self) -> &'static str {
        match self {
            Self::Sysctl => "SYSCTL_ENDPOINT_STATE_V1",
            Self::Mount => "MOUNT_ENDPOINT_STATE_V1",
            Self::Network => "LOCAL_NETWORK_ENDPOINT_STATE_V1",
            Self::KernelModule => "KERNEL_MODULE_ENDPOINT_STATE_V1",
            Self::ProcessResidual => "TRACKED_CGROUP_PROCESS_RESIDUAL_V1",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValueEvidenceMode {
    Sha256Only,
    BytesAndSha256,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureLimits {
    pub max_records: u64,
    pub max_value_bytes: u64,
    pub max_total_value_bytes: u64,
    pub deadline_ms: u64,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            max_records: 16_384,
            max_value_bytes: 4 * 1024 * 1024,
            max_total_value_bytes: 16 * 1024 * 1024,
            deadline_ms: 15_000,
        }
    }
}

impl CaptureLimits {
    pub fn validate(&self) -> Result<()> {
        validate_limit(
            "max_records",
            self.max_records,
            HARD_MAX_RECORDS_PER_DOMAIN as u64,
        )?;
        validate_limit(
            "max_value_bytes",
            self.max_value_bytes,
            HARD_MAX_RECORD_VALUE_BYTES,
        )?;
        validate_limit(
            "max_total_value_bytes",
            self.max_total_value_bytes,
            HARD_MAX_TOTAL_VALUE_BYTES,
        )?;
        if self.max_value_bytes > self.max_total_value_bytes {
            bail!("max_value_bytes cannot exceed max_total_value_bytes");
        }
        validate_limit("deadline_ms", self.deadline_ms, HARD_MAX_DEADLINE_MS)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceTarget {
    /// Zero selects the confirmer process.  A non-zero PID is checked against
    /// `expected_namespace_inode` on every capture to reject PID reuse.
    pub pid: u32,
    pub expected_namespace_inode: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LinuxNamespaceKind {
    Mount,
    Network,
    Uts,
    Ipc,
}

impl LinuxNamespaceKind {
    pub fn proc_name(self) -> &'static str {
        match self {
            Self::Mount => "mnt",
            Self::Network => "net",
            Self::Uts => "uts",
            Self::Ipc => "ipc",
        }
    }

    pub fn clone_flag(self) -> libc::c_int {
        match self {
            Self::Mount => libc::CLONE_NEWNS,
            Self::Network => libc::CLONE_NEWNET,
            Self::Uts => libc::CLONE_NEWUTS,
            Self::Ipc => libc::CLONE_NEWIPC,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NamespaceCaptureSource {
    CurrentProcess,
    LivePid,
    RetainedFileDescriptor,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceCaptureEvidence {
    pub kind: LinuxNamespaceKind,
    pub inode: u64,
    pub source: NamespaceCaptureSource,
}

impl NamespaceTarget {
    pub fn current(namespace: &str) -> Result<Self> {
        let inode = namespace_inode(0, namespace)?;
        Ok(Self {
            pid: 0,
            expected_namespace_inode: inode,
        })
    }

    pub fn for_pid(pid: u32, namespace: &str) -> Result<Self> {
        if pid == 0 {
            bail!("for_pid requires a non-zero PID");
        }
        let inode = namespace_inode(pid, namespace)?;
        Ok(Self {
            pid,
            expected_namespace_inode: inode,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.expected_namespace_inode == 0 {
            bail!("expected namespace inode must be non-zero");
        }
        Ok(())
    }

    pub(crate) fn proc_component(&self) -> String {
        if self.pid == 0 {
            // Namespace membership is per-thread. `thread-self` remains
            // correct when capture temporarily enters a retained namespace in
            // a multithreaded observer process.
            "thread-self".to_owned()
        } else {
            self.pid.to_string()
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SysctlScope {
    pub proc_sys_root_bytes_hex: String,
    /// Canonical relative names such as `kernel/yama/ptrace_scope`.
    pub keys: Vec<String>,
    pub evidence: ValueEvidenceMode,
    pub limits: CaptureLimits,
}

impl SysctlScope {
    pub fn new(root: &Path, keys: Vec<String>) -> Result<Self> {
        let scope = Self {
            proc_sys_root_bytes_hex: encode_absolute_path(root)?,
            keys,
            evidence: ValueEvidenceMode::BytesAndSha256,
            limits: CaptureLimits::default(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        let _ = decode_absolute_path(&self.proc_sys_root_bytes_hex, "proc_sys_root")?;
        if self.keys.is_empty() || self.keys.len() > HARD_MAX_RECORDS_PER_DOMAIN {
            bail!("sysctl scope requires 1..={HARD_MAX_RECORDS_PER_DOMAIN} explicit keys");
        }
        if self.keys.len() as u64 > self.limits.max_records {
            bail!("sysctl key count exceeds configured max_records");
        }
        let mut prior: Option<&str> = None;
        for key in &self.keys {
            validate_relative_key("sysctl key", key)?;
            // `kernel/ns_last_pid` is selected by the caller's PID namespace,
            // but entering a PID namespace with setns(2) only affects future
            // children. This confirmer deliberately retains only net, UTS,
            // and IPC namespaces, so accepting this key would capture the
            // observer's PID namespace while claiming deployment provenance.
            if key == "kernel/ns_last_pid" {
                bail!(
                    "sysctl key kernel/ns_last_pid is PID-namespace scoped and unsupported by the net/UTS/IPC namespace model"
                );
            }
            // `user/max_*_namespaces` is selected by the caller's user
            // namespace. Deployment capture does not retain or enter that
            // namespace, so reading it would silently report the observer's
            // value with false deployment provenance.
            if key == "user" || key.starts_with("user/") {
                bail!(
                    "sysctl keys under user/ are user-namespace scoped and unsupported by the net/UTS/IPC namespace model"
                );
            }
            if prior.map_or(false, |value| value >= key.as_str()) {
                bail!("sysctl keys must be strictly sorted and unique");
            }
            prior = Some(key);
        }
        self.limits.validate()
    }

    pub(crate) fn root(&self) -> Result<PathBuf> {
        decode_absolute_path(&self.proc_sys_root_bytes_hex, "proc_sys_root")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MountScope {
    pub namespace: NamespaceTarget,
    pub evidence: ValueEvidenceMode,
    pub limits: CaptureLimits,
}

impl MountScope {
    pub fn validate(&self) -> Result<()> {
        self.namespace.validate()?;
        self.limits.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkCollectors {
    pub addresses: bool,
    pub routes: bool,
    pub rules: bool,
    pub traffic_control: bool,
    pub nftables: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NetworkNormalization {
    /// Preserve semantic configuration while excluding explicit runtime
    /// counters, queue occupancy, countdown lifetimes, and kernel-assigned
    /// nft handles.
    #[serde(rename = "NETWORK_CONFIGURATION_ONLY_V1")]
    ConfigurationOnlyV1,
}

impl NetworkNormalization {
    pub fn protocol_name(self) -> &'static str {
        match self {
            Self::ConfigurationOnlyV1 => "NETWORK_CONFIGURATION_ONLY_V1",
        }
    }
}

impl NetworkCollectors {
    fn any(&self) -> bool {
        self.addresses || self.routes || self.rules || self.traffic_control || self.nftables
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkScope {
    pub namespace: NamespaceTarget,
    pub collectors: NetworkCollectors,
    pub normalization: NetworkNormalization,
    /// Exact trusted binaries. An empty string is permitted only when no
    /// collector backed by that tool is selected.
    pub ip_binary_bytes_hex: String,
    pub expected_ip_sha256: String,
    pub tc_binary_bytes_hex: String,
    pub expected_tc_sha256: String,
    pub nft_binary_bytes_hex: String,
    pub expected_nft_sha256: String,
    /// tc filter/class collection is bounded to these interfaces.  Qdiscs are
    /// collected globally within the selected network namespace.
    pub tc_interfaces: Vec<String>,
    pub evidence: ValueEvidenceMode,
    pub limits: CaptureLimits,
}

impl NetworkScope {
    pub fn validate(&self) -> Result<()> {
        self.namespace.validate()?;
        if !self.collectors.any() {
            bail!("network scope must enable at least one collector");
        }
        if self.collectors.addresses || self.collectors.routes || self.collectors.rules {
            let _ = decode_absolute_path(&self.ip_binary_bytes_hex, "ip binary")?;
            validate_sha256("expected ip SHA-256", &self.expected_ip_sha256)?;
        } else {
            validate_empty_hex(&self.ip_binary_bytes_hex, "unused ip binary")?;
            validate_empty_hex(&self.expected_ip_sha256, "unused ip SHA-256")?;
        }
        if self.collectors.traffic_control {
            let _ = decode_absolute_path(&self.tc_binary_bytes_hex, "tc binary")?;
            validate_sha256("expected tc SHA-256", &self.expected_tc_sha256)?;
        } else {
            validate_empty_hex(&self.tc_binary_bytes_hex, "unused tc binary")?;
            validate_empty_hex(&self.expected_tc_sha256, "unused tc SHA-256")?;
        }
        if self.collectors.nftables {
            let _ = decode_absolute_path(&self.nft_binary_bytes_hex, "nft binary")?;
            validate_sha256("expected nft SHA-256", &self.expected_nft_sha256)?;
        } else {
            validate_empty_hex(&self.nft_binary_bytes_hex, "unused nft binary")?;
            validate_empty_hex(&self.expected_nft_sha256, "unused nft SHA-256")?;
        }
        if self.tc_interfaces.len() > 1024 {
            bail!("tc interface scope exceeds 1024 entries");
        }
        if !self.collectors.traffic_control && !self.tc_interfaces.is_empty() {
            bail!("tc interfaces must be empty when traffic-control confirmation is disabled");
        }
        let mut prior: Option<&str> = None;
        for interface in &self.tc_interfaces {
            validate_interface(interface)?;
            if prior.map_or(false, |value| value >= interface.as_str()) {
                bail!("tc interfaces must be strictly sorted and unique");
            }
            prior = Some(interface);
        }
        self.limits.validate()
    }

    pub(crate) fn ip_binary(&self) -> Result<PathBuf> {
        decode_absolute_path(&self.ip_binary_bytes_hex, "ip binary")
    }

    pub(crate) fn tc_binary(&self) -> Result<PathBuf> {
        decode_absolute_path(&self.tc_binary_bytes_hex, "tc binary")
    }

    pub(crate) fn nft_binary(&self) -> Result<PathBuf> {
        decode_absolute_path(&self.nft_binary_bytes_hex, "nft binary")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "mode", content = "names")]
pub enum ModuleSelection {
    AllLoaded,
    Explicit(Vec<String>),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleScope {
    pub proc_modules_path_bytes_hex: String,
    pub sys_module_root_bytes_hex: String,
    pub selection: ModuleSelection,
    pub capture_parameters: bool,
    pub evidence: ValueEvidenceMode,
    pub limits: CaptureLimits,
}

impl ModuleScope {
    pub fn validate(&self) -> Result<()> {
        let _ = decode_absolute_path(&self.proc_modules_path_bytes_hex, "proc modules path")?;
        let _ = decode_absolute_path(&self.sys_module_root_bytes_hex, "sys module root")?;
        if let ModuleSelection::Explicit(names) = &self.selection {
            if names.is_empty() || names.len() > HARD_MAX_RECORDS_PER_DOMAIN {
                bail!("explicit module selection must contain a bounded non-empty list");
            }
            if names.len() as u64 > self.limits.max_records {
                bail!("explicit module selection exceeds configured max_records");
            }
            let mut prior: Option<&str> = None;
            for name in names {
                validate_module_name(name)?;
                if prior.map_or(false, |value| value >= name.as_str()) {
                    bail!("module names must be strictly sorted and unique");
                }
                prior = Some(name);
            }
        }
        self.limits.validate()
    }

    pub(crate) fn proc_modules_path(&self) -> Result<PathBuf> {
        decode_absolute_path(&self.proc_modules_path_bytes_hex, "proc modules path")
    }

    pub(crate) fn sys_module_root(&self) -> Result<PathBuf> {
        decode_absolute_path(&self.sys_module_root_bytes_hex, "sys module root")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessResidualRoot {
    pub cgroup_path_bytes_hex: String,
    /// cgroup v2 kernfs inode (`bpf_get_current_cgroup_id` identity).
    pub expected_cgroup_id: u64,
}

impl ProcessResidualRoot {
    pub fn new(path: &Path, expected_cgroup_id: u64) -> Result<Self> {
        let root = Self {
            cgroup_path_bytes_hex: encode_absolute_path(path)?,
            expected_cgroup_id,
        };
        root.validate()?;
        Ok(root)
    }

    pub fn validate(&self) -> Result<()> {
        let _ = decode_absolute_path(&self.cgroup_path_bytes_hex, "cgroup path")?;
        if self.expected_cgroup_id == 0 {
            bail!("expected cgroup ID must be non-zero");
        }
        Ok(())
    }

    pub(crate) fn cgroup_path(&self) -> Result<PathBuf> {
        decode_absolute_path(&self.cgroup_path_bytes_hex, "cgroup path")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessResidualScope {
    pub cgroup_path_bytes_hex: String,
    /// cgroup v2 kernfs inode (`bpf_get_current_cgroup_id` identity).
    pub expected_cgroup_id: u64,
    /// Additional disjoint roots.  This field is omitted from legacy/single-root
    /// JSON so existing protocol-v1 scope documents remain valid and stable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_roots: Vec<ProcessResidualRoot>,
    pub recursive: bool,
    pub require_cgroup2: bool,
    pub evidence: ValueEvidenceMode,
    pub limits: CaptureLimits,
}

impl ProcessResidualScope {
    pub fn for_cgroup(path: &Path, expected_cgroup_id: u64, recursive: bool) -> Result<Self> {
        let canonical = fs::canonicalize(path).context("canonicalize managed cgroup path")?;
        if canonical != path {
            bail!("managed cgroup path must be canonical and contain no symlink traversal");
        }
        let metadata = fs::symlink_metadata(path).context("inspect managed cgroup path")?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            bail!("managed cgroup path must identify a directory without a final symlink");
        }
        if metadata.ino() != expected_cgroup_id {
            bail!(
                "managed cgroup inode {} != supplied cgroup ID {expected_cgroup_id}",
                metadata.ino()
            );
        }
        let path_c = std::ffi::CString::new(path.as_os_str().as_bytes())
            .context("managed cgroup path contains NUL")?;
        let mut statfs = unsafe { std::mem::zeroed::<libc::statfs>() };
        if unsafe { libc::statfs(path_c.as_ptr(), &mut statfs) } != 0 {
            return Err(std::io::Error::last_os_error()).context("statfs managed cgroup");
        }
        if statfs.f_type != 0x6367_7270 {
            bail!("managed cgroup path is not on a cgroup v2 filesystem");
        }
        let scope = Self {
            cgroup_path_bytes_hex: encode_absolute_path(path)?,
            expected_cgroup_id,
            additional_roots: Vec::new(),
            recursive,
            require_cgroup2: true,
            evidence: ValueEvidenceMode::Sha256Only,
            limits: CaptureLimits {
                max_records: 65_536,
                max_value_bytes: 4 * 1024 * 1024,
                max_total_value_bytes: 16 * 1024 * 1024,
                deadline_ms: 15_000,
            },
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        if self.additional_roots.len() >= HARD_MAX_PROCESS_RESIDUAL_ROOTS {
            bail!("process-residual scope exceeds {HARD_MAX_PROCESS_RESIDUAL_ROOTS} roots");
        }
        let mut roots = Vec::with_capacity(1 + self.additional_roots.len());
        roots.push(ProcessResidualRoot {
            cgroup_path_bytes_hex: self.cgroup_path_bytes_hex.clone(),
            expected_cgroup_id: self.expected_cgroup_id,
        });
        roots.extend(self.additional_roots.iter().cloned());
        let mut prior_path: Option<PathBuf> = None;
        let mut ids = std::collections::BTreeSet::new();
        for root in &roots {
            root.validate()?;
            let path = root.cgroup_path()?;
            if let Some(prior) = &prior_path {
                if prior.as_os_str().as_bytes() >= path.as_os_str().as_bytes() {
                    bail!("process-residual roots must be strictly path-sorted and unique");
                }
            }
            if !ids.insert(root.expected_cgroup_id) {
                bail!("process-residual roots contain a duplicate cgroup ID");
            }
            prior_path = Some(path);
        }
        for (index, left) in roots.iter().enumerate() {
            let left = left.cgroup_path()?;
            for right in roots.iter().skip(index + 1) {
                let right = right.cgroup_path()?;
                if right.starts_with(&left) || left.starts_with(&right) {
                    bail!("process-residual roots must be pairwise disjoint");
                }
            }
        }
        self.limits.validate()
    }

    pub(crate) fn cgroup_path(&self) -> Result<PathBuf> {
        decode_absolute_path(&self.cgroup_path_bytes_hex, "cgroup path")
    }

    pub(crate) fn roots(&self) -> Result<Vec<(PathBuf, u64)>> {
        let mut roots = Vec::with_capacity(1 + self.additional_roots.len());
        roots.push((self.cgroup_path()?, self.expected_cgroup_id));
        for root in &self.additional_roots {
            roots.push((root.cgroup_path()?, root.expected_cgroup_id));
        }
        Ok(roots)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateScope {
    pub protocol_version: u32,
    pub sysctl: Option<SysctlScope>,
    pub mounts: Option<MountScope>,
    pub network: Option<NetworkScope>,
    pub modules: Option<ModuleScope>,
    pub process_residual: Option<ProcessResidualScope>,
}

impl StateScope {
    /// Attach the exact managed cgroup to an existing explicit scope. A
    /// conflicting caller-supplied residual scope is rejected, never replaced.
    pub fn with_process_residual(mut self, process: ProcessResidualScope) -> Result<Self> {
        process.validate()?;
        match &self.process_residual {
            Some(existing) if existing != &process => {
                bail!("caller process-residual scope conflicts with the managed cgroup")
            }
            Some(_) => {}
            None => self.process_residual = Some(process),
        }
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION {
            bail!(
                "Linux state scope protocol {} != supported protocol {}",
                self.protocol_version,
                LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION
            );
        }
        if self.sysctl.is_none()
            && self.mounts.is_none()
            && self.network.is_none()
            && self.modules.is_none()
            && self.process_residual.is_none()
        {
            bail!("Linux state scope must explicitly enable at least one domain");
        }
        if let Some(scope) = &self.sysctl {
            scope.validate()?;
        }
        if let Some(scope) = &self.mounts {
            scope.validate()?;
        }
        if let Some(scope) = &self.network {
            scope.validate()?;
        }
        if let Some(scope) = &self.modules {
            scope.validate()?;
        }
        if let Some(scope) = &self.process_residual {
            scope.validate()?;
        }
        let encoded = serde_json::to_vec(self).context("serialize Linux state scope")?;
        if encoded.len() as u64 > HARD_MAX_SCOPE_JSON_BYTES {
            bail!("Linux state scope exceeds artifact size bound");
        }
        Ok(())
    }

    pub fn sha256(&self) -> Result<String> {
        self.validate()?;
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompletenessStatus {
    Complete,
    Incomplete,
    NotConfirmed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Completeness {
    pub status: CompletenessStatus,
    pub reasons: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CaptureIssueKind {
    Io,
    Permission,
    Missing,
    Limit,
    Deadline,
    IdentityMismatch,
    Parse,
    CommandFailure,
    ToolIdentity,
    Race,
    Unsupported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureIssue {
    pub key: String,
    pub kind: CaptureIssueKind,
    pub errno: Option<i32>,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateRecord {
    pub key: String,
    pub value_sha256: String,
    pub value_size: u64,
    pub value_bytes_hex: Option<String>,
}

impl StateRecord {
    pub(crate) fn new(key: String, value: &[u8], mode: ValueEvidenceMode) -> Result<Self> {
        if key.is_empty() || key.as_bytes().len() > HARD_MAX_KEY_BYTES {
            bail!("state record key is empty or exceeds hard bound");
        }
        Ok(Self {
            key,
            value_sha256: hex::encode(Sha256::digest(value)),
            value_size: value.len() as u64,
            value_bytes_hex: match mode {
                ValueEvidenceMode::Sha256Only => None,
                ValueEvidenceMode::BytesAndSha256 => Some(hex::encode(value)),
            },
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DomainSnapshot {
    pub domain: DomainKind,
    pub namespace_inode: Option<u64>,
    /// Exact namespace capabilities used for this domain. This is a vector
    /// because procfs sysctls may be selected by network, UTS, or IPC
    /// namespace state simultaneously.
    #[serde(default)]
    pub namespace_context: Vec<NamespaceCaptureEvidence>,
    pub source_identity_sha256: Option<String>,
    pub records: Vec<StateRecord>,
    pub completeness: Completeness,
    pub issues: Vec<CaptureIssue>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateSnapshot {
    pub protocol_version: u32,
    pub snapshot_id: String,
    pub phase: SnapshotPhase,
    pub captured_unix_ns: u128,
    pub boot_id: String,
    pub scope: StateScope,
    pub scope_sha256: String,
    pub sysctl: Option<DomainSnapshot>,
    pub mounts: Option<DomainSnapshot>,
    pub network: Option<DomainSnapshot>,
    pub modules: Option<DomainSnapshot>,
    pub process_residual: Option<DomainSnapshot>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EndpointDifferenceStatus {
    NotConfirmed,
    ObservedIdentical,
    ObservedDifferent,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StateVerdict {
    NotConfirmed,
    ChangedWithinScope,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CausalAttributionStatus {
    NotEstablished,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TerminalState {
    NotApplicable,
    EmptyWithinScope,
    NonEmptyWithinScope,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateChange {
    pub key: String,
    pub kind: ChangeKind,
    pub before_sha256: Option<String>,
    pub after_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DomainComparison {
    pub domain: DomainKind,
    pub protocol_domain: String,
    pub endpoint_difference: EndpointDifferenceStatus,
    pub verdict: StateVerdict,
    pub state_completeness: Completeness,
    pub terminal_state: TerminalState,
    pub causal_attribution_status: CausalAttributionStatus,
    pub changes: Vec<StateChange>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateDomainComparisons {
    pub sysctl: DomainComparison,
    pub mounts: DomainComparison,
    pub network: DomainComparison,
    pub modules: DomainComparison,
    pub process_residual: DomainComparison,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateComparison {
    pub protocol_version: u32,
    pub domain: String,
    pub scope_sha256: String,
    /// Legacy wire name retained for compatibility. Generic pair comparisons
    /// store the before-snapshot identifier here.
    pub s0_snapshot_id: String,
    /// Legacy wire name retained for compatibility. Generic pair comparisons
    /// store the after-snapshot identifier here.
    pub s1_snapshot_id: String,
    /// Deliberately a vector. It must not be collapsed into a claim about all
    /// Linux state.
    pub domains: StateDomainComparisons,
    pub limitations: Vec<String>,
}

pub fn encode_absolute_path(path: &Path) -> Result<String> {
    let bytes = path.as_os_str().as_bytes();
    validate_absolute_path(bytes)?;
    Ok(hex::encode(bytes))
}

pub(crate) fn decode_absolute_path(encoded: &str, label: &str) -> Result<PathBuf> {
    if encoded.len() > HARD_MAX_PATH_BYTES * 2 || encoded.len() % 2 != 0 {
        bail!("{label} hex encoding exceeds path bound or has odd length");
    }
    if encoded
        .bytes()
        .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must use canonical lowercase hex");
    }
    let bytes = hex::decode(encoded).with_context(|| format!("decode {label}"))?;
    validate_absolute_path(&bytes)?;
    Ok(PathBuf::from(OsString::from_vec(bytes)))
}

fn validate_absolute_path(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty()
        || bytes.len() > HARD_MAX_PATH_BYTES
        || bytes[0] != b'/'
        || bytes.contains(&0)
    {
        bail!("path must be a bounded absolute Linux pathname without NUL");
    }
    if bytes.len() > 1 && bytes.ends_with(b"/") {
        bail!("path must not contain a trailing slash");
    }
    for part in bytes.split(|byte| *byte == b'/') {
        if part == b"." || part == b".." {
            bail!("path must not contain dot components");
        }
    }
    Ok(())
}

fn validate_empty_hex(encoded: &str, label: &str) -> Result<()> {
    if !encoded.is_empty() {
        bail!("{label} must be empty");
    }
    Ok(())
}

fn validate_sha256(label: &str, encoded: &str) -> Result<()> {
    if encoded.len() != 64
        || encoded
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be 64 canonical lowercase hex characters");
    }
    Ok(())
}

fn validate_relative_key(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > HARD_MAX_PATH_BYTES
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\0')
    {
        bail!("{label} is not a bounded canonical relative path");
    }
    for part in value.split('/') {
        if part.is_empty()
            || part == "."
            || part == ".."
            || !part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            bail!("{label} contains an invalid component");
        }
    }
    Ok(())
}

fn validate_interface(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 15
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'@')
        })
    {
        bail!("network interface name is invalid or exceeds IFNAMSIZ-1");
    }
    Ok(())
}

fn validate_module_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        bail!("kernel module name is invalid");
    }
    Ok(())
}

fn validate_identifier(label: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.as_bytes().len() > MAX_IDENTIFIER_BYTES || value.contains('\0') {
        bail!("{label} is empty or exceeds its bound");
    }
    Ok(())
}

fn validate_limit(label: &str, value: u64, maximum: u64) -> Result<()> {
    if value == 0 || value > maximum {
        bail!("{label} must be in 1..={maximum}");
    }
    Ok(())
}

pub(crate) fn namespace_inode(pid: u32, namespace: &str) -> Result<u64> {
    if !matches!(namespace, "mnt" | "net" | "uts" | "ipc") {
        bail!("unsupported namespace type");
    }
    let component = if pid == 0 {
        "self".to_owned()
    } else {
        pid.to_string()
    };
    let inode = fs::metadata(format!("/proc/{component}/ns/{namespace}"))
        .with_context(|| format!("inspect {namespace} namespace for PID {component}"))?
        .ino();
    if inode == 0 {
        bail!("kernel returned zero namespace inode");
    }
    Ok(inode)
}
