// SPDX-License-Identifier: GPL-2.0-only

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const SCHEMA_VERSION: u32 = 1;

pub const FINALIZED_RUN_ARTIFACTS_V1: [&str; 10] = [
    "canary-health.json",
    "health.json",
    "quiescence.json",
    "raw-events.bin",
    "raw-events.jsonl",
    "s0.json",
    "s1.json",
    "verdict.json",
    "workload.stderr",
    "workload.stdout",
];

pub const MAX_MANIFEST_JSON_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_HEALTH_JSON_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_QUIESCENCE_JSON_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_SNAPSHOT_JSON_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_VERDICT_JSON_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_RAW_WAL_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_RAW_JSONL_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_RECORDED_EVENTS: u64 = 262_144;
pub const MAX_WORKLOAD_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_GENERIC_JSON_BYTES: u64 = 512 * 1024 * 1024;

pub fn artifact_size_limit(name: &str) -> Option<u64> {
    match name {
        "manifest.json" => Some(MAX_MANIFEST_JSON_BYTES),
        "canary-health.json" | "health.json" => Some(MAX_HEALTH_JSON_BYTES),
        "quiescence.json" => Some(MAX_QUIESCENCE_JSON_BYTES),
        "s0.json" | "s1.json" => Some(MAX_SNAPSHOT_JSON_BYTES),
        "verdict.json" => Some(MAX_VERDICT_JSON_BYTES),
        "raw-events.bin" => Some(MAX_RAW_WAL_BYTES),
        "raw-events.jsonl" => Some(MAX_RAW_JSONL_BYTES),
        "workload.stderr" | "workload.stdout" => Some(MAX_WORKLOAD_OUTPUT_BYTES),
        _ => None,
    }
}

/// Closed set of checks understood by the deterministic `exclusive-vm-v1`
/// verdict logic.  Merely labelling an arbitrary report `HARNESS_ENFORCED`
/// must never be enough to enable an unchanged verdict.
pub const EXCLUSIVE_VM_V1_CHECKS: &[&str] = &[
    "exclusive_vm",
    "no_other_bpf_actors",
    "no_external_bpf_fds",
    "scm_rights_blocked",
    "pidfd_getfd_blocked",
    "writable_map_mmap_blocked",
    "cgroup_empty",
    "attachment_dependency_closure_complete",
    "special_map_values_excluded",
    "prog_test_run_blocked",
    "new_bpf_loaders_blocked",
    "in_flight_bpf_barrier_complete",
];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObjectType {
    Program,
    Map,
    Link,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MapContentType {
    Array,
    Hash,
    PercpuArray,
    PercpuHash,
}

impl MapContentType {
    pub fn kernel_type(&self) -> u32 {
        match self {
            Self::Hash => 1,
            Self::Array => 2,
            Self::PercpuHash => 5,
            Self::PercpuArray => 6,
        }
    }
}

fn default_object_types() -> BTreeSet<ObjectType> {
    [ObjectType::Program, ObjectType::Map, ObjectType::Link]
        .into_iter()
        .collect()
}

fn default_map_types() -> BTreeSet<MapContentType> {
    BTreeSet::new()
}

fn default_event_interfaces() -> BTreeSet<String> {
    ["BPF_USER_SYSCALL".to_string()].into_iter().collect()
}

fn default_max_map_entries() -> u64 {
    65_536
}

fn default_max_map_bytes() -> u64 {
    64 * 1024 * 1024
}

fn default_deadline_ms() -> u64 {
    5_000
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceBudget {
    pub max_map_entries: u64,
    pub max_map_bytes: u64,
    pub per_map_deadline_ms: u64,
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self {
            max_map_entries: default_max_map_entries(),
            max_map_bytes: default_max_map_bytes(),
            per_map_deadline_ms: default_deadline_ms(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaimScope {
    pub event_interfaces: BTreeSet<String>,
    pub allowed_bpf_commands: BTreeSet<u32>,
    pub object_types: BTreeSet<ObjectType>,
    pub map_content_types: BTreeSet<MapContentType>,
    pub map_ids: BTreeSet<u32>,
    pub bpffs_roots: Vec<String>,
    pub attachment_targets: Vec<Value>,
    pub budget: ResourceBudget,
}

impl Default for ClaimScope {
    fn default() -> Self {
        Self {
            event_interfaces: default_event_interfaces(),
            allowed_bpf_commands: BTreeSet::new(),
            object_types: default_object_types(),
            map_content_types: default_map_types(),
            map_ids: BTreeSet::new(),
            bpffs_roots: Vec::new(),
            attachment_targets: Vec::new(),
            budget: ResourceBudget::default(),
        }
    }
}

impl ClaimScope {
    pub fn samples_map(&self, map_id: u32, map_type: u32) -> bool {
        (self.map_ids.is_empty() || self.map_ids.contains(&map_id))
            && self
                .map_content_types
                .iter()
                .any(|candidate| candidate.kernel_type() == map_type)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(deny_unknown_fields)]
pub struct ObjectIdentity {
    pub boot_id: String,
    pub object_type: ObjectType,
    pub id: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObjectExclusions {
    pub program_ids: BTreeSet<u32>,
    pub map_ids: BTreeSet<u32>,
    pub link_ids: BTreeSet<u32>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentFingerprint {
    pub kernel_release: String,
    pub boot_id: String,
    pub observer_version: String,
    pub recorder_object_sha256: Option<String>,
    pub kernel_btf_sha256: Option<String>,
    pub source_commit: Option<String>,
    /// Exact Observer executable measured before an authenticated run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observer_executable_sha256: Option<String>,
    /// Exact workload executable measured before and after an authenticated run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_executable_sha256: Option<String>,
    /// Host policy identity for the measured VM kernel/rootfs combination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_kernel_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_policy_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_public_key_fingerprint_sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RunManifest {
    pub schema_version: u32,
    pub run_id: String,
    pub run_epoch: u64,
    pub run_status: RunStatus,
    pub started_unix_ns: u128,
    pub finalized_unix_ns: Option<u128>,
    pub cgroup_path: String,
    pub cgroup_id: u64,
    pub workload: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_signal: Option<i32>,
    pub requested_scope: ClaimScope,
    pub effective_scope: ClaimScope,
    pub scope_accepted: bool,
    pub observer_exclusions: ObjectExclusions,
    pub environment: EnvironmentFingerprint,
    /// Exact bytes committed by this run. A FINALIZED manifest is valid only
    /// when a verifier checks every listed digest and the closed artifact set.
    pub artifacts: BTreeMap<String, ArtifactDigest>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigest {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProgramState {
    pub identity: ObjectIdentity,
    pub program_type: u32,
    pub name: String,
    pub tag_hex: String,
    pub load_time_ns: u64,
    pub created_by_uid: u32,
    pub btf_id: u32,
    pub attach_btf_obj_id: u32,
    pub attach_btf_id: u32,
    pub ifindex: u32,
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub map_ids: Vec<u32>,
    #[serde(default)]
    pub excluded: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MapMetadata {
    pub map_type: u32,
    pub name: String,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub map_extra: u64,
    pub ifindex: u32,
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub btf_id: u32,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
    /// Kernel BTF value type. Older snapshots did not retain this field, so a
    /// missing value is interpreted as zero.
    #[serde(default)]
    pub btf_vmlinux_value_type_id: u32,
    pub frozen: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MapEntry {
    pub key_hex: String,
    /// One value for regular maps; one value per possible CPU for per-CPU maps.
    pub values_hex: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MapSampleStatus {
    CompleteQuiescent,
    BestEffortNonAtomic,
    UnsupportedType,
    ReadForbidden,
    OpaqueValue,
    TruncatedResourceLimit,
    ReadFailed,
    ObjectDisappeared,
    ConcurrentMutation,
    AmbiguousIdReuse,
    OutsideClaimScope,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MapContentState {
    pub status: MapSampleStatus,
    #[serde(default)]
    pub semantic_complete: bool,
    #[serde(default)]
    pub entries: Vec<MapEntry>,
    pub digest_sha256: Option<String>,
    #[serde(default)]
    pub bytes_read: u64,
    #[serde(default)]
    pub possible_cpu_ids: Vec<u32>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MapState {
    pub identity: ObjectIdentity,
    pub metadata: MapMetadata,
    pub content: MapContentState,
    #[serde(default)]
    pub excluded: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LinkState {
    pub identity: ObjectIdentity,
    pub link_type: u32,
    pub program_id: u32,
    pub target: Option<Value>,
    #[serde(default)]
    pub excluded: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PinState {
    /// Lossy, human-readable rendering only. Identity comparisons MUST use
    /// `path_bytes_hex`, because Linux paths are arbitrary byte strings.
    pub path: String,
    /// Exact absolute pathname bytes, hex encoded.
    pub path_bytes_hex: String,
    pub mount_namespace_inode: u64,
    /// Per-entry mount ID from statx(STATX_MNT_ID), not a value inherited
    /// from the configured root.
    pub mount_id: u64,
    pub object_type: ObjectType,
    pub object_id: u32,
    #[serde(default)]
    pub excluded: bool,
}

/// Identity of one bpffs root actually opened and verified by the producer.
/// This remains present even when the root contains no pinned objects, so an
/// empty pin inventory cannot silently mean "the producer observed elsewhere".
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct PinRootIdentity {
    /// Canonical absolute path, equal to one root in `ClaimScope::bpffs_roots`.
    pub path: String,
    pub mount_namespace_inode: u64,
    pub mount_id: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObjectReadFailure {
    pub object_type: ObjectType,
    pub id: u32,
    pub operation: String,
    pub error: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompletenessStatus {
    Complete,
    Incomplete,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Completeness {
    pub status: CompletenessStatus,
    #[serde(default)]
    pub reasons: Vec<String>,
}

impl Completeness {
    pub fn complete() -> Self {
        Self {
            status: CompletenessStatus::Complete,
            reasons: Vec::new(),
        }
    }

    pub fn mark_incomplete(&mut self, reason: impl Into<String>) {
        self.status = CompletenessStatus::Incomplete;
        let reason = reason.into();
        const REASON_LIMIT: usize = 4_096;
        const TRUNCATED: &str = "additional incompleteness reasons omitted at configured limit";
        if self.reasons.binary_search(&reason).is_ok() {
            return;
        }
        if self
            .reasons
            .binary_search_by(|current| current.as_str().cmp(TRUNCATED))
            .is_ok()
        {
            return;
        }
        if self.reasons.len() >= REASON_LIMIT - 1 {
            if let Err(index) = self
                .reasons
                .binary_search_by(|current| current.as_str().cmp(TRUNCATED))
            {
                self.reasons.insert(index, TRUNCATED.into());
            }
            return;
        }
        let index = self
            .reasons
            .binary_search(&reason)
            .expect_err("duplicate reason returned above");
        self.reasons.insert(index, reason);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema_version: u32,
    pub snapshot_id: String,
    pub phase: String,
    pub boot_id: String,
    pub captured_unix_ns: u128,
    pub capture_duration_ns: u128,
    pub kernel_release: String,
    pub byte_order: String,
    pub possible_cpu_ids: Vec<u32>,
    pub claim_scope: ClaimScope,
    /// Exact observer-owned IDs applied while producing this raw snapshot.
    /// The comparator verifies equality across S0/S1 instead of trusting
    /// per-object `excluded` booleans in isolation.
    pub observer_exclusions: ObjectExclusions,
    pub programs: Vec<ProgramState>,
    pub maps: Vec<MapState>,
    pub links: Vec<LinkState>,
    #[serde(default)]
    pub pin_roots: Vec<PinRootIdentity>,
    pub pins: Vec<PinState>,
    pub read_failures: Vec<ObjectReadFailure>,
    pub completeness: Completeness,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventKind {
    SyscallAttempted,
    CommandCompleted,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEvent {
    pub schema_version: u32,
    pub run_id: String,
    pub run_epoch: u64,
    pub event_seq: u64,
    pub related_attempt_seq: u64,
    pub kind: EventKind,
    pub ktime_ns: u64,
    pub cgroup_id: u64,
    pub pid: u32,
    pub tgid: u32,
    pub command: u32,
    pub command_name: String,
    pub attr_size: u32,
    pub return_value: Option<i64>,
    pub argument_provenance: String,
    #[serde(default)]
    pub flags: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct EvidenceHealth {
    /// Lifecycle facts are explicit so an all-zero counter document cannot be
    /// mistaken for proof that a recorder was ever active.
    #[serde(default)]
    pub recorder_loaded: bool,
    #[serde(default)]
    pub run_registered: bool,
    #[serde(default)]
    pub producer_barrier_complete: bool,
    #[serde(default)]
    pub drain_completed: bool,
    #[serde(default)]
    pub wal_durable: bool,
    /// A harmless native `bpf()` call was observed end-to-end through the
    /// exact loaded programs, cgroup filter, ring buffer, decoder, and WAL
    /// before the formal run was registered.
    #[serde(default)]
    pub native_transport_canary_passed: bool,
    pub syscall_attempted: u64,
    pub syscall_completed: u64,
    pub last_event_seq: u64,
    pub event_attempted: u64,
    pub event_published: u64,
    pub event_dropped: u64,
    pub events_persisted: u64,
    pub pending_insert_failed: u64,
    pub pending_missing: u64,
    pub pending_remaining: u64,
    /// Number of `bpf()` attempts made during an authenticated exclusive
    /// window by a TGID other than the measured Observer and outside every
    /// registered workload cgroup.  Any nonzero value disproves exclusivity,
    /// even when the caller destroys its object before S1.
    #[serde(default)]
    pub outside_cgroup_syscall_attempted: u64,
    pub parse_failed: u64,
    pub unsupported_commands: BTreeSet<u32>,
    #[serde(default)]
    pub reasons: Vec<String>,
}

impl EvidenceHealth {
    pub fn is_complete(&self) -> bool {
        self.recorder_loaded
            && self.run_registered
            && self.producer_barrier_complete
            && self.drain_completed
            && self.wal_durable
            && self.native_transport_canary_passed
            && self.syscall_attempted == self.syscall_completed
            && self.syscall_attempted.checked_add(self.syscall_completed)
                == Some(self.event_attempted)
            && self.last_event_seq == self.event_attempted
            && self.event_published.checked_add(self.event_dropped) == Some(self.event_attempted)
            && self.event_dropped == 0
            && self.event_published == self.events_persisted
            && self.pending_insert_failed == 0
            && self.pending_missing == 0
            && self.pending_remaining == 0
            && self.outside_cgroup_syscall_attempted == 0
            && self.parse_failed == 0
            && self.unsupported_commands.is_empty()
            && self.reasons.is_empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuiescenceStatus {
    QuiescentWithinModel,
    NotQuiescent,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuiescenceBasis {
    HarnessEnforced,
    ObservedOnly,
    Assumed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContractCheck {
    pub name: String,
    pub passed: bool,
    pub evidence: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QuiescenceReport {
    pub status: QuiescenceStatus,
    pub basis: QuiescenceBasis,
    pub contract_id: Option<String>,
    pub checks: Vec<ContractCheck>,
    pub exclusive_actor_attribution: bool,
    /// Signed, run-bound harness transcript. The schema crate deliberately
    /// stores this as JSON and does not perform cryptography; integrated
    /// producers and verifiers must parse and authenticate the closed
    /// harness protocol before trusting a HARNESS_ENFORCED report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Value>,
}

impl QuiescenceReport {
    pub fn supports_unchanged(&self) -> bool {
        self.status == QuiescenceStatus::QuiescentWithinModel
            && self.basis == QuiescenceBasis::HarnessEnforced
            && self.contract_id.as_deref() == Some("exclusive-vm-v1")
            && self.exclusive_actor_attribution
            && self.authentication.is_some()
            && !self.checks.is_empty()
            && self
                .checks
                .iter()
                .all(|check| check.passed && !check.evidence.trim().is_empty())
            && self.checks.len() == EXCLUSIVE_VM_V1_CHECKS.len()
            && EXCLUSIVE_VM_V1_CHECKS.iter().all(|required| {
                self.checks
                    .iter()
                    .filter(|check| check.name == *required && check.passed)
                    .count()
                    == 1
            })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StateVerdict {
    ChangedWithinScope,
    UnchangedWithinScope,
    Inconclusive,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Attribution {
    WorkloadAttributed,
    PartiallyAttributed,
    UnattributedSystemChange,
    NoStateChange,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChangeCertainty {
    Confirmed,
    Indeterminate,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StateChange {
    pub kind: ChangeKind,
    pub certainty: ChangeCertainty,
    pub entity: String,
    pub identity: String,
    pub field: Option<String>,
    pub before: Option<Value>,
    pub after: Option<Value>,
    pub attribution: Attribution,
    #[serde(default)]
    pub attribution_evidence: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunStatus {
    Provisional,
    Running,
    Finalized,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Verdict {
    pub schema_version: u32,
    pub state_verdict: StateVerdict,
    pub state_completeness: Completeness,
    pub evidence_status: Completeness,
    pub attribution: Attribution,
    pub quiescence: QuiescenceReport,
    pub run_status: RunStatus,
    #[serde(default)]
    pub changes: Vec<StateChange>,
    #[serde(default)]
    pub limitations: Vec<String>,
}

pub fn bpf_command_name(command: u32) -> &'static str {
    const NAMES: &[&str] = &[
        "BPF_MAP_CREATE",
        "BPF_MAP_LOOKUP_ELEM",
        "BPF_MAP_UPDATE_ELEM",
        "BPF_MAP_DELETE_ELEM",
        "BPF_MAP_GET_NEXT_KEY",
        "BPF_PROG_LOAD",
        "BPF_OBJ_PIN",
        "BPF_OBJ_GET",
        "BPF_PROG_ATTACH",
        "BPF_PROG_DETACH",
        "BPF_PROG_TEST_RUN",
        "BPF_PROG_GET_NEXT_ID",
        "BPF_MAP_GET_NEXT_ID",
        "BPF_PROG_GET_FD_BY_ID",
        "BPF_MAP_GET_FD_BY_ID",
        "BPF_OBJ_GET_INFO_BY_FD",
        "BPF_PROG_QUERY",
        "BPF_RAW_TRACEPOINT_OPEN",
        "BPF_BTF_LOAD",
        "BPF_BTF_GET_FD_BY_ID",
        "BPF_TASK_FD_QUERY",
        "BPF_MAP_LOOKUP_AND_DELETE_ELEM",
        "BPF_MAP_FREEZE",
        "BPF_BTF_GET_NEXT_ID",
        "BPF_MAP_LOOKUP_BATCH",
        "BPF_MAP_LOOKUP_AND_DELETE_BATCH",
        "BPF_MAP_UPDATE_BATCH",
        "BPF_MAP_DELETE_BATCH",
        "BPF_LINK_CREATE",
        "BPF_LINK_UPDATE",
        "BPF_LINK_GET_FD_BY_ID",
        "BPF_LINK_GET_NEXT_ID",
        "BPF_ENABLE_STATS",
        "BPF_ITER_CREATE",
        "BPF_LINK_DETACH",
        "BPF_PROG_BIND_MAP",
        "BPF_TOKEN_CREATE",
        "BPF_PROG_STREAM_READ_BY_FD",
        "BPF_PROG_ASSOC_STRUCT_OPS",
    ];
    NAMES
        .get(command as usize)
        .copied()
        .unwrap_or("BPF_UNKNOWN_COMMAND")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_requires_counted_and_persisted_events() {
        let mut health = EvidenceHealth::default();
        assert!(!health.is_complete());
        health.recorder_loaded = true;
        health.run_registered = true;
        health.producer_barrier_complete = true;
        health.drain_completed = true;
        health.wal_durable = true;
        health.native_transport_canary_passed = true;
        health.last_event_seq = 2;
        health.event_attempted = 2;
        health.event_published = 2;
        health.events_persisted = 1;
        health.syscall_attempted = 1;
        health.syscall_completed = 1;
        assert!(!health.is_complete());
        health.events_persisted = 2;
        assert!(health.is_complete());
        health.outside_cgroup_syscall_attempted = 1;
        assert!(!health.is_complete());
    }

    #[test]
    fn health_event_accounting_cannot_wrap() {
        let health = EvidenceHealth {
            recorder_loaded: true,
            run_registered: true,
            producer_barrier_complete: true,
            drain_completed: true,
            wal_durable: true,
            native_transport_canary_passed: true,
            last_event_seq: 0,
            event_attempted: 0,
            event_published: u64::MAX,
            event_dropped: 1,
            events_persisted: u64::MAX,
            ..EvidenceHealth::default()
        };
        assert!(!health.is_complete());
    }

    #[test]
    fn health_rejects_missing_enter_exit_event_accounting() {
        let health = EvidenceHealth {
            recorder_loaded: true,
            run_registered: true,
            producer_barrier_complete: true,
            drain_completed: true,
            wal_durable: true,
            native_transport_canary_passed: true,
            syscall_attempted: 1,
            syscall_completed: 1,
            ..EvidenceHealth::default()
        };
        assert!(!health.is_complete());
    }

    #[test]
    fn unchanged_requires_checked_harness_contract() {
        let mut report = QuiescenceReport {
            status: QuiescenceStatus::QuiescentWithinModel,
            basis: QuiescenceBasis::HarnessEnforced,
            contract_id: Some("exclusive-vm-v1".into()),
            checks: vec![],
            exclusive_actor_attribution: true,
            authentication: None,
        };
        assert!(!report.supports_unchanged());
        report.checks = EXCLUSIVE_VM_V1_CHECKS
            .iter()
            .map(|name| ContractCheck {
                name: (*name).into(),
                passed: true,
                evidence: "test fixture".into(),
            })
            .collect();
        report.authentication = Some(serde_json::json!({"test_fixture": true}));
        assert!(report.supports_unchanged());
        report.checks[0].passed = false;
        assert!(!report.supports_unchanged());

        report.checks[0].passed = true;
        report.exclusive_actor_attribution = false;
        assert!(!report.supports_unchanged());
    }

    #[test]
    fn claim_scope_json_is_closed_and_requires_every_field() {
        let mut value = serde_json::to_value(ClaimScope::default()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("typo_field".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<ClaimScope>(value).is_err());

        let mut value = serde_json::to_value(ClaimScope::default()).unwrap();
        value.as_object_mut().unwrap().remove("map_ids");
        assert!(serde_json::from_value::<ClaimScope>(value).is_err());
    }

    #[test]
    fn completeness_reason_growth_is_bounded() {
        let mut completeness = Completeness::complete();
        for index in 0..10_000 {
            completeness.mark_incomplete(format!("reason-{index:05}"));
        }
        assert_eq!(completeness.status, CompletenessStatus::Incomplete);
        assert_eq!(completeness.reasons.len(), 4_096);
        assert!(completeness
            .reasons
            .iter()
            .any(|reason| reason.contains("reasons omitted")));
    }
}
