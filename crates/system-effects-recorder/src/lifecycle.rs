// SPDX-License-Identifier: GPL-2.0-only

//! Closed process-lifecycle evidence ABI and offline replay.
//!
//! This stream is deliberately independent from syscall attempt/result WAL.
//! Scheduler events have their own sequence and loss accounting and are never
//! assigned a synthetic syscall identity.

use super::ancestor::{AncestorConfig, AncestorRootSet, MAX_ANCESTOR_ROOTS};
use super::{
    check_pointer, check_rc, collect_exclusions, find_map_fd, find_program, libbpf_error,
    map_delete, map_lookup, map_update, read_object, validate_map_abi, verify_digest,
    CgroupMatchMode, KernelResources, MapAbi,
};
use anyhow::{bail, Context, Result};
use bpf_observer_schema::ObjectExclusions;
use libbpf_sys as libbpf;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::os::raw::c_int;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::ptr;
use std::slice;
use std::time::{Duration, Instant};

pub const PROCESS_LIFECYCLE_SCHEMA_VERSION: u32 = 2;
pub const KERNEL_PROCESS_LIFECYCLE_EVENT_SIZE: usize = 248;
pub const PROCESS_EXEC_PATH_BYTES: usize = 128;
pub const MAX_PROCESS_LIFECYCLE_WAL_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_PROCESS_LIFECYCLE_EVENTS: usize = 1_000_000;
pub const PROCESS_LIFECYCLE_WAL_NAME: &str = "process-lifecycle.raw.bin";
pub const PROCESS_LIFECYCLE_JSONL_NAME: &str = "process-lifecycle.jsonl";
pub const PROCESS_LIFECYCLE_HEALTH_NAME: &str = "process-lifecycle.health.json";
pub const PROCESS_LIFECYCLE_ENROLLMENT_LIMITATION: &str = "process-lifecycle schema v2 has no authoritative S0 task/thread enrollment ledger and no cgroup migration or CLONE_INTO_CGROUP enrollment hook; EXEC/EXIT may introduce identities during replay, so whole-tree lifecycle association is PARTIAL";

const MAP_LIFECYCLE_RUNS: &str = "effect_lifecycle_runs";
const MAP_LIFECYCLE_EVENTS: &str = "effect_lifecycle_events";
const MAP_LIFECYCLE_ROOTS: &str = "life_roots";
const MAP_LIFECYCLE_ROOT_IDS: &str = "life_root_ids";
const MAP_LIFECYCLE_ROOT_CONFIG: &str = "life_root_cfg";
const PROGRAM_LIFECYCLE_HOOKS: &[&str] = &[
    "trace_effect_process_fork",
    "trace_effect_process_exec",
    "trace_effect_process_exit",
];
const MAX_LIFECYCLE_RUNS: u32 = 1024;
const LIFECYCLE_RING_BYTES: u32 = 1 << 20;
const MAX_LIFECYCLE_CALLBACK_QUEUE_EVENTS: usize = 4_096;
const MAX_PROCESS_LIFECYCLE_JSONL_BYTES: u64 = 256 * 1024 * 1024;

pub const PROCESS_LIFECYCLE_FORK: u16 = 1;
pub const PROCESS_LIFECYCLE_EXEC: u16 = 2;
pub const PROCESS_LIFECYCLE_EXIT: u16 = 3;

pub const PROCESS_FLAG_EXEC_PATH_READ_FAILED: u32 = 1 << 0;
pub const PROCESS_FLAG_EXEC_PATH_TRUNCATED: u32 = 1 << 1;
pub const PROCESS_FLAG_TASK_READ_FAILED: u32 = 1 << 2;
const KNOWN_PROCESS_FLAGS: u32 = PROCESS_FLAG_EXEC_PATH_READ_FAILED
    | PROCESS_FLAG_EXEC_PATH_TRUNCATED
    | PROCESS_FLAG_TASK_READ_FAILED;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
struct ProcessLifecycleRunState {
    epoch: u64,
    next_event_seq: u64,
    event_attempted: u64,
    event_published: u64,
    event_dropped: u64,
    task_read_failed: u64,
    exec_path_read_failed: u64,
    exec_path_truncated: u64,
}

#[derive(Default)]
struct ProcessLifecycleCallbackState {
    queue: VecDeque<KernelProcessLifecycleEvent>,
    decode_failures: u64,
    routing_failures: u64,
    verification_failures: u64,
    capacity_failures: u64,
    accepted_events: u64,
    queue_high_water: usize,
    batch_limit_reached: bool,
}

fn enqueue_process_lifecycle_event(
    state: &mut ProcessLifecycleCallbackState,
    event: KernelProcessLifecycleEvent,
) -> c_int {
    if state.queue.len() >= MAX_LIFECYCLE_CALLBACK_QUEUE_EVENTS
        || state.accepted_events >= MAX_PROCESS_LIFECYCLE_EVENTS as u64
    {
        state.capacity_failures = state.capacity_failures.saturating_add(1);
        return -libc::EFBIG;
    }
    state.queue.push_back(event);
    state.accepted_events = state.accepted_events.saturating_add(1);
    state.queue_high_water = state.queue_high_water.max(state.queue.len());
    if state.queue.len() == MAX_LIFECYCLE_CALLBACK_QUEUE_EVENTS {
        state.batch_limit_reached = true;
        -libc::EAGAIN
    } else {
        0
    }
}

unsafe extern "C" fn receive_process_lifecycle_event(
    context: *mut c_void,
    data: *mut c_void,
    size: u64,
) -> c_int {
    if context.is_null() || data.is_null() {
        return -libc::EINVAL;
    }
    let state = &mut *(context as *mut ProcessLifecycleCallbackState);
    let Ok(size) = usize::try_from(size) else {
        state.decode_failures = state.decode_failures.saturating_add(1);
        return -libc::EBADMSG;
    };
    let bytes = slice::from_raw_parts(data.cast::<u8>(), size);
    match KernelProcessLifecycleEvent::decode_native(bytes) {
        Ok(event) => enqueue_process_lifecycle_event(state, event),
        Err(_) => {
            state.decode_failures = state.decode_failures.saturating_add(1);
            -libc::EBADMSG
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelProcessLifecycleEvent {
    pub schema_version: u32,
    pub kind: u16,
    /// Logical pathname bytes; unlike `bpf_probe_read_kernel_str`, excludes NUL.
    pub exec_path_len: u16,
    pub flags: u32,
    pub exit_code: i32,
    pub run_epoch: u64,
    pub event_seq: u64,
    pub ktime_ns: u64,
    pub cgroup_id: u64,
    pub start_boottime_ns: u64,
    pub parent_start_boottime_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub parent_pid: u32,
    pub parent_tgid: u32,
    /// Previous task PID supplied by sched_process_exec (de-thread correlation).
    pub old_pid: u32,
    /// sched_process_exit's process-wide-last-thread indication.
    pub group_dead: u8,
    pub comm: [u8; 16],
    pub parent_comm: [u8; 16],
    pub exec_path: [u8; PROCESS_EXEC_PATH_BYTES],
}

impl KernelProcessLifecycleEvent {
    pub fn decode_native(bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes, Endian::Native, false)
    }

    pub fn decode_le(bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes, Endian::Little, true)
    }

    fn decode(bytes: &[u8], endian: Endian, require_canonical_tail: bool) -> Result<Self> {
        if bytes.len() != KERNEL_PROCESS_LIFECYCLE_EVENT_SIZE {
            bail!(
                "process-lifecycle event has {} bytes, expected {KERNEL_PROCESS_LIFECYCLE_EVENT_SIZE}",
                bytes.len()
            );
        }
        if bytes[85..88] != [0; 3] {
            bail!("process-lifecycle event has a nonzero reserved field");
        }
        let mut comm = [0u8; 16];
        comm.copy_from_slice(&bytes[88..104]);
        let mut parent_comm = [0u8; 16];
        parent_comm.copy_from_slice(&bytes[104..120]);
        let mut exec_path = [0u8; PROCESS_EXEC_PATH_BYTES];
        exec_path.copy_from_slice(&bytes[120..248]);
        let event = Self {
            schema_version: endian.u32(&bytes[0..4]),
            kind: endian.u16(&bytes[4..6]),
            exec_path_len: endian.u16(&bytes[6..8]),
            flags: endian.u32(&bytes[8..12]),
            exit_code: endian.i32(&bytes[12..16]),
            run_epoch: endian.u64(&bytes[16..24]),
            event_seq: endian.u64(&bytes[24..32]),
            ktime_ns: endian.u64(&bytes[32..40]),
            cgroup_id: endian.u64(&bytes[40..48]),
            start_boottime_ns: endian.u64(&bytes[48..56]),
            parent_start_boottime_ns: endian.u64(&bytes[56..64]),
            pid: endian.u32(&bytes[64..68]),
            tgid: endian.u32(&bytes[68..72]),
            parent_pid: endian.u32(&bytes[72..76]),
            parent_tgid: endian.u32(&bytes[76..80]),
            old_pid: endian.u32(&bytes[80..84]),
            group_dead: bytes[84],
            comm,
            parent_comm,
            exec_path,
        };
        event.validate()?;
        if require_canonical_tail {
            let retained = usize::from(event.exec_path_len);
            if event.exec_path[retained..].iter().any(|byte| *byte != 0) {
                bail!("process-lifecycle WAL exec path has a nonzero unused tail");
            }
        }
        Ok(event)
    }

    pub fn encode_le(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; KERNEL_PROCESS_LIFECYCLE_EVENT_SIZE];
        bytes[0..4].copy_from_slice(&self.schema_version.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.kind.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.exec_path_len.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.flags.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.exit_code.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.run_epoch.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.event_seq.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.ktime_ns.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.cgroup_id.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.start_boottime_ns.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.parent_start_boottime_ns.to_le_bytes());
        bytes[64..68].copy_from_slice(&self.pid.to_le_bytes());
        bytes[68..72].copy_from_slice(&self.tgid.to_le_bytes());
        bytes[72..76].copy_from_slice(&self.parent_pid.to_le_bytes());
        bytes[76..80].copy_from_slice(&self.parent_tgid.to_le_bytes());
        bytes[80..84].copy_from_slice(&self.old_pid.to_le_bytes());
        bytes[84] = self.group_dead;
        bytes[88..104].copy_from_slice(&self.comm);
        bytes[104..120].copy_from_slice(&self.parent_comm);
        let retained = usize::from(self.exec_path_len).min(PROCESS_EXEC_PATH_BYTES);
        bytes[120..120 + retained].copy_from_slice(&self.exec_path[..retained]);
        bytes
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != PROCESS_LIFECYCLE_SCHEMA_VERSION {
            bail!(
                "unsupported process-lifecycle schema {}",
                self.schema_version
            );
        }
        if !matches!(
            self.kind,
            PROCESS_LIFECYCLE_FORK | PROCESS_LIFECYCLE_EXEC | PROCESS_LIFECYCLE_EXIT
        ) {
            bail!("unknown process-lifecycle event kind {}", self.kind);
        }
        if self.flags & !KNOWN_PROCESS_FLAGS != 0 || self.group_dead > 1 {
            bail!("process-lifecycle event has unknown flags or non-boolean group_dead");
        }
        if self.run_epoch == 0 || self.event_seq == 0 || self.ktime_ns == 0 || self.cgroup_id == 0 {
            bail!("process-lifecycle event has a zero run identity field");
        }
        if self.flags & PROCESS_FLAG_TASK_READ_FAILED == 0
            && (self.pid == 0
                || self.tgid == 0
                || self.start_boottime_ns == 0
                || self.parent_pid == 0
                || self.parent_tgid == 0
                || self.parent_start_boottime_ns == 0)
        {
            bail!("process-lifecycle task identity is incomplete without a failure flag");
        }
        let path_len = usize::from(self.exec_path_len);
        if path_len >= PROCESS_EXEC_PATH_BYTES {
            bail!("process-lifecycle exec path exceeds its logical-byte bound");
        }
        match self.kind {
            PROCESS_LIFECYCLE_EXEC => {
                let failed = self.flags & PROCESS_FLAG_EXEC_PATH_READ_FAILED != 0;
                if failed != (path_len == 0)
                    || self.old_pid == 0
                    || self.group_dead != 0
                    || self.exit_code != 0
                {
                    bail!("process EXEC kind-specific fields disagree");
                }
                if !failed {
                    if self.exec_path[..path_len].contains(&0) {
                        bail!("process exec path contains an embedded NUL");
                    }
                    if (self.flags & PROCESS_FLAG_EXEC_PATH_TRUNCATED != 0)
                        != (path_len == PROCESS_EXEC_PATH_BYTES - 1)
                    {
                        bail!("process exec-path truncation flag is not canonical");
                    }
                } else if self.flags & PROCESS_FLAG_EXEC_PATH_TRUNCATED != 0 {
                    bail!("failed process exec-path read is marked truncated");
                }
            }
            PROCESS_LIFECYCLE_EXIT => {
                if path_len != 0
                    || self.old_pid != 0
                    || self.flags
                        & (PROCESS_FLAG_EXEC_PATH_READ_FAILED | PROCESS_FLAG_EXEC_PATH_TRUNCATED)
                        != 0
                {
                    bail!("process EXIT kind-specific fields disagree");
                }
            }
            PROCESS_LIFECYCLE_FORK => {
                if path_len != 0
                    || self.old_pid != 0
                    || self.group_dead != 0
                    || self.exit_code != 0
                    || self.flags
                        & (PROCESS_FLAG_EXEC_PATH_READ_FAILED | PROCESS_FLAG_EXEC_PATH_TRUNCATED)
                        != 0
                {
                    bail!("process FORK kind-specific fields disagree");
                }
            }
            _ => unreachable!("validated lifecycle kind"),
        }
        Ok(())
    }

    pub fn to_event(&self, run_id: &str, boot_id: &str) -> Result<ProcessLifecycleEvent> {
        self.to_event_with_cgroup_match(run_id, boot_id, CgroupMatchMode::ExactCurrent)
    }

    pub fn to_event_with_cgroup_match(
        &self,
        run_id: &str,
        boot_id: &str,
        cgroup_match_mode: CgroupMatchMode,
    ) -> Result<ProcessLifecycleEvent> {
        self.validate()?;
        validate_boot_id(boot_id)?;
        if run_id.is_empty() || run_id.contains('\0') {
            bail!("run_id must be nonempty and contain no NUL bytes");
        }
        let kind = match self.kind {
            PROCESS_LIFECYCLE_FORK => ProcessLifecycleKind::Fork,
            PROCESS_LIFECYCLE_EXEC => ProcessLifecycleKind::Exec,
            PROCESS_LIFECYCLE_EXIT => ProcessLifecycleKind::Exit,
            _ => unreachable!("validated lifecycle kind"),
        };
        let exec_path = if self.exec_path_len == 0 {
            None
        } else {
            let bytes = &self.exec_path[..usize::from(self.exec_path_len)];
            Some(ProcessExecPath {
                display: String::from_utf8_lossy(bytes).into_owned(),
                raw_hex: hex(bytes),
                truncated: self.flags & PROCESS_FLAG_EXEC_PATH_TRUNCATED != 0,
                authority: ProcessExecPathAuthority::KernelBinprmFilenameAtSuccessfulExec,
            })
        };
        Ok(ProcessLifecycleEvent {
            schema_version: PROCESS_LIFECYCLE_SCHEMA_VERSION,
            run_id: run_id.to_owned(),
            run_epoch: self.run_epoch,
            event_seq: self.event_seq,
            ktime_ns: self.ktime_ns,
            cgroup_id: self.cgroup_id,
            cgroup_match_mode,
            cgroup_id_semantics: match cgroup_match_mode {
                CgroupMatchMode::ExactCurrent => "CURRENT_CGROUP_AT_LIFECYCLE_HOOK",
                CgroupMatchMode::AncestorRoot => "MATCHED_SCOPE_ROOT_AT_LIFECYCLE_HOOK",
            }
            .to_owned(),
            leaf_cgroup_id_retained: cgroup_match_mode == CgroupMatchMode::ExactCurrent,
            kind,
            subject: ProcessIdentity::from_raw(
                boot_id,
                self.pid,
                self.tgid,
                self.start_boottime_ns,
                &self.comm,
            ),
            parent: ProcessIdentity::from_raw(
                boot_id,
                self.parent_pid,
                self.parent_tgid,
                self.parent_start_boottime_ns,
                &self.parent_comm,
            ),
            old_pid: (self.kind == PROCESS_LIFECYCLE_EXEC).then_some(self.old_pid),
            group_dead: (self.kind == PROCESS_LIFECYCLE_EXIT).then_some(self.group_dead == 1),
            exec_path,
            exit_code: (self.kind == PROCESS_LIFECYCLE_EXIT).then_some(self.exit_code),
            flags: self.flags,
            attribution: match cgroup_match_mode {
                CgroupMatchMode::ExactCurrent => "DIRECT_CURRENT_CGROUP_AT_LIFECYCLE_HOOK",
                CgroupMatchMode::AncestorRoot => {
                    "DIRECT_ANCESTOR_ROOT_MEMBERSHIP_AT_LIFECYCLE_HOOK"
                }
            }
            .to_owned(),
            semantics: "PROCESS_LIFECYCLE_OBSERVATION_NOT_DELEGATED_CAUSALITY".to_owned(),
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessLifecycleKind {
    Fork,
    Exec,
    Exit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub boot_id: String,
    pub pid: u32,
    pub tgid: u32,
    pub start_boottime_ns: u64,
    pub comm: String,
}

impl ProcessIdentity {
    fn from_raw(boot_id: &str, pid: u32, tgid: u32, start: u64, comm: &[u8]) -> Self {
        Self {
            boot_id: boot_id.to_owned(),
            pid,
            tgid,
            start_boottime_ns: start,
            comm: nul_terminated_lossy(comm),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessExecPathAuthority {
    /// Kernel-copied descriptive filename; deliberately not a FILE_OBJECT.
    KernelBinprmFilenameAtSuccessfulExec,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessExecPath {
    pub display: String,
    pub raw_hex: String,
    pub truncated: bool,
    pub authority: ProcessExecPathAuthority,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessLifecycleEvent {
    pub schema_version: u32,
    pub run_id: String,
    pub run_epoch: u64,
    pub event_seq: u64,
    pub ktime_ns: u64,
    pub cgroup_id: u64,
    pub cgroup_match_mode: CgroupMatchMode,
    pub cgroup_id_semantics: String,
    pub leaf_cgroup_id_retained: bool,
    pub kind: ProcessLifecycleKind,
    pub subject: ProcessIdentity,
    pub parent: ProcessIdentity,
    pub old_pid: Option<u32>,
    pub group_dead: Option<bool>,
    pub exec_path: Option<ProcessExecPath>,
    pub exit_code: Option<i32>,
    pub flags: u32,
    pub attribution: String,
    pub semantics: String,
}

impl ProcessLifecycleEvent {
    pub fn validate(&self) -> Result<()> {
        validate_boot_id(&self.subject.boot_id)?;
        validate_boot_id(&self.parent.boot_id)?;
        if self.subject.boot_id != self.parent.boot_id
            || self.schema_version != PROCESS_LIFECYCLE_SCHEMA_VERSION
            || self.run_id.is_empty()
            || self.run_id.contains('\0')
            || self.run_epoch == 0
            || self.event_seq == 0
            || self.ktime_ns == 0
            || self.cgroup_id == 0
            || self.flags & !KNOWN_PROCESS_FLAGS != 0
            || self.semantics != "PROCESS_LIFECYCLE_OBSERVATION_NOT_DELEGATED_CAUSALITY"
        {
            bail!("invalid process-lifecycle event envelope");
        }
        let (semantics, attribution, leaf_retained) = match self.cgroup_match_mode {
            CgroupMatchMode::ExactCurrent => (
                "CURRENT_CGROUP_AT_LIFECYCLE_HOOK",
                "DIRECT_CURRENT_CGROUP_AT_LIFECYCLE_HOOK",
                true,
            ),
            CgroupMatchMode::AncestorRoot => (
                "MATCHED_SCOPE_ROOT_AT_LIFECYCLE_HOOK",
                "DIRECT_ANCESTOR_ROOT_MEMBERSHIP_AT_LIFECYCLE_HOOK",
                false,
            ),
        };
        if self.cgroup_id_semantics != semantics
            || self.attribution != attribution
            || self.leaf_cgroup_id_retained != leaf_retained
        {
            bail!("process-lifecycle cgroup scope semantics are inconsistent");
        }
        if self.flags & PROCESS_FLAG_TASK_READ_FAILED == 0 {
            validate_process_identity(&self.subject)?;
            validate_process_identity(&self.parent)?;
        }
        match self.kind {
            ProcessLifecycleKind::Exec => {
                if self.exit_code.is_some()
                    || self.group_dead.is_some()
                    || self.old_pid == Some(0)
                    || self.old_pid.is_none()
                {
                    bail!("EXEC lifecycle event contains invalid kind-specific fields");
                }
                let failed = self.flags & PROCESS_FLAG_EXEC_PATH_READ_FAILED != 0;
                if failed != self.exec_path.is_none() {
                    bail!("EXEC path and read status disagree");
                }
                if let Some(path) = &self.exec_path {
                    let bytes = decode_hex(&path.raw_hex, PROCESS_EXEC_PATH_BYTES - 1)?;
                    if bytes.is_empty()
                        || bytes.contains(&0)
                        || path.display != String::from_utf8_lossy(&bytes)
                        || path.truncated != (self.flags & PROCESS_FLAG_EXEC_PATH_TRUNCATED != 0)
                    {
                        bail!("invalid kernel-derived EXEC path");
                    }
                }
            }
            ProcessLifecycleKind::Exit => {
                if self.exec_path.is_some()
                    || self.exit_code.is_none()
                    || self.group_dead.is_none()
                    || self.old_pid.is_some()
                {
                    bail!("EXIT lifecycle event has invalid kind-specific fields");
                }
            }
            ProcessLifecycleKind::Fork => {
                if self.exec_path.is_some()
                    || self.exit_code.is_some()
                    || self.group_dead.is_some()
                    || self.old_pid.is_some()
                {
                    bail!("FORK lifecycle event has invalid kind-specific fields");
                }
            }
        }
        Ok(())
    }
}

fn validate_process_identity(identity: &ProcessIdentity) -> Result<()> {
    if identity.pid == 0 || identity.tgid == 0 || identity.start_boottime_ns == 0 {
        bail!("process identity has a zero stable field");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct TaskKey {
    pid: u32,
    start_boottime_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TaskEnrollmentOrigin {
    Fork,
    ExecWithoutEnrollment,
    ExitWithoutEnrollment,
}

#[derive(Clone, Copy, Debug)]
struct TaskState {
    exited: bool,
    group_dead: bool,
    enrollment_origin: TaskEnrollmentOrigin,
}

/// Offline lineage replay keyed by boot-scoped `(pid,start_boottime)`. EXEC
/// uses `old_pid` to preserve identity across de-thread PID replacement.
pub struct ProcessLineageVerifier {
    run_epoch: u64,
    cgroup_id: u64,
    seen_sequences: BTreeSet<u64>,
    tasks: BTreeMap<TaskKey, TaskState>,
    forks_with_unenrolled_parent: u64,
    count: u64,
}

impl ProcessLineageVerifier {
    pub fn new(run_epoch: u64, cgroup_id: u64) -> Result<Self> {
        if run_epoch == 0 || cgroup_id == 0 {
            bail!("lineage verifier needs nonzero run identity");
        }
        Ok(Self {
            run_epoch,
            cgroup_id,
            seen_sequences: BTreeSet::new(),
            tasks: BTreeMap::new(),
            forks_with_unenrolled_parent: 0,
            count: 0,
        })
    }

    pub fn ingest(&mut self, event: &KernelProcessLifecycleEvent) -> Result<()> {
        event.validate()?;
        if event.run_epoch != self.run_epoch || event.cgroup_id != self.cgroup_id {
            bail!("process-lifecycle event is outside the verified run");
        }
        if event.flags & PROCESS_FLAG_TASK_READ_FAILED != 0 {
            bail!("complete lineage cannot include a failed task identity read");
        }
        if !self.seen_sequences.insert(event.event_seq) {
            bail!("duplicate process-lifecycle event sequence");
        }
        self.count = self
            .count
            .checked_add(1)
            .context("lifecycle count overflow")?;
        let subject = TaskKey {
            pid: event.pid,
            start_boottime_ns: event.start_boottime_ns,
        };
        match event.kind {
            PROCESS_LIFECYCLE_FORK => {
                if self.tasks.contains_key(&subject) {
                    bail!("duplicate process FORK identity");
                }
                let parent = TaskKey {
                    pid: event.parent_pid,
                    start_boottime_ns: event.parent_start_boottime_ns,
                };
                if !self.tasks.contains_key(&parent) {
                    self.forks_with_unenrolled_parent = self
                        .forks_with_unenrolled_parent
                        .checked_add(1)
                        .context("unenrolled-parent fork count overflow")?;
                }
                self.tasks.insert(
                    subject,
                    TaskState {
                        exited: false,
                        group_dead: false,
                        enrollment_origin: TaskEnrollmentOrigin::Fork,
                    },
                );
            }
            PROCESS_LIFECYCLE_EXEC => {
                let previous = TaskKey {
                    pid: event.old_pid,
                    start_boottime_ns: event.start_boottime_ns,
                };
                if previous == subject {
                    let state = self.tasks.entry(subject).or_insert(TaskState {
                        exited: false,
                        group_dead: false,
                        enrollment_origin: TaskEnrollmentOrigin::ExecWithoutEnrollment,
                    });
                    if state.exited {
                        bail!("process EXEC contradicts its lifecycle identity");
                    }
                } else {
                    let state = self.tasks.remove(&previous).unwrap_or(TaskState {
                        exited: false,
                        group_dead: false,
                        enrollment_origin: TaskEnrollmentOrigin::ExecWithoutEnrollment,
                    });
                    if state.exited || self.tasks.contains_key(&subject) {
                        bail!("de-thread EXEC contradicts its lifecycle identity");
                    }
                    self.tasks.insert(subject, state);
                }
            }
            PROCESS_LIFECYCLE_EXIT => {
                let state = self.tasks.entry(subject).or_insert(TaskState {
                    exited: false,
                    group_dead: false,
                    enrollment_origin: TaskEnrollmentOrigin::ExitWithoutEnrollment,
                });
                if state.exited {
                    bail!("process EXIT contradicts or duplicates its lifecycle identity");
                }
                state.exited = true;
                state.group_dead = event.group_dead == 1;
            }
            _ => unreachable!("validated lifecycle kind"),
        }
        Ok(())
    }

    pub fn finish(&self, published: u64, dropped: u64) -> Result<ProcessLineageSummary> {
        if dropped != 0 || published != self.count {
            bail!("process-lifecycle stream has loss or accounting mismatch");
        }
        if self.count != 0
            && (self.seen_sequences.len() as u64 != self.count
                || self.seen_sequences.first().copied() != Some(1)
                || self.seen_sequences.last().copied() != Some(self.count))
        {
            bail!("process-lifecycle sequence range is incomplete");
        }
        if self.tasks.values().any(|state| !state.exited) {
            bail!("an observed process identity has no terminal EXIT event");
        }
        let summary = ProcessLineageSummary {
            event_count: self.count,
            task_identities: self.tasks.len() as u64,
            exited_task_identities: self.tasks.values().filter(|state| state.exited).count() as u64,
            group_dead_exits: self.tasks.values().filter(|state| state.group_dead).count() as u64,
            enrollment: ProcessEnrollmentSummary {
                initial_task_ledger_present: false,
                initial_tasks_enrolled: 0,
                migration_hook_present: false,
                clone_into_cgroup_covered: false,
                migration_enrolled_task_identities: 0,
                fork_enrolled_task_identities: self
                    .tasks
                    .values()
                    .filter(|state| state.enrollment_origin == TaskEnrollmentOrigin::Fork)
                    .count() as u64,
                exec_introduced_task_identities: self
                    .tasks
                    .values()
                    .filter(|state| {
                        state.enrollment_origin == TaskEnrollmentOrigin::ExecWithoutEnrollment
                    })
                    .count() as u64,
                exit_introduced_task_identities: self
                    .tasks
                    .values()
                    .filter(|state| {
                        state.enrollment_origin == TaskEnrollmentOrigin::ExitWithoutEnrollment
                    })
                    .count() as u64,
                forks_with_unenrolled_parent: self.forks_with_unenrolled_parent,
                complete: false,
            },
            correlation: "PARTIAL_FORK_EXEC_EXIT_BY_BOOT_ID_PID_START_BOOTTIME_AND_EXEC_OLD_PID"
                .to_owned(),
        };
        summary.validate()?;
        Ok(summary)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessEnrollmentSummary {
    pub initial_task_ledger_present: bool,
    pub initial_tasks_enrolled: u64,
    pub migration_hook_present: bool,
    pub clone_into_cgroup_covered: bool,
    pub migration_enrolled_task_identities: u64,
    pub fork_enrolled_task_identities: u64,
    pub exec_introduced_task_identities: u64,
    pub exit_introduced_task_identities: u64,
    pub forks_with_unenrolled_parent: u64,
    pub complete: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessLineageSummary {
    pub event_count: u64,
    pub task_identities: u64,
    pub exited_task_identities: u64,
    pub group_dead_exits: u64,
    pub enrollment: ProcessEnrollmentSummary,
    pub correlation: String,
}

impl ProcessLineageSummary {
    pub fn validate(&self) -> Result<()> {
        let enrolled_or_introduced = self
            .enrollment
            .initial_tasks_enrolled
            .checked_add(self.enrollment.migration_enrolled_task_identities)
            .and_then(|value| value.checked_add(self.enrollment.fork_enrolled_task_identities))
            .and_then(|value| value.checked_add(self.enrollment.exec_introduced_task_identities))
            .and_then(|value| value.checked_add(self.enrollment.exit_introduced_task_identities))
            .context("process enrollment accounting overflow")?;
        if enrolled_or_introduced != self.task_identities
            || self.enrollment.forks_with_unenrolled_parent
                > self.enrollment.fork_enrolled_task_identities
            || self.enrollment.initial_task_ledger_present
            || self.enrollment.initial_tasks_enrolled != 0
            || self.enrollment.migration_hook_present
            || self.enrollment.clone_into_cgroup_covered
            || self.enrollment.migration_enrolled_task_identities != 0
            || self.enrollment.complete
            || self.correlation
                != "PARTIAL_FORK_EXEC_EXIT_BY_BOOT_ID_PID_START_BOOTTIME_AND_EXEC_OLD_PID"
        {
            bail!("process lineage overclaims unsupported task enrollment coverage");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessLifecycleStatus {
    Complete,
    Partial,
    Incomplete,
    UnprovenNoEvents,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessLifecycleHealth {
    pub schema_version: u32,
    pub run_id: String,
    pub run_epoch: u64,
    pub cgroup_id: u64,
    pub status: ProcessLifecycleStatus,
    pub event_attempted: u64,
    pub event_published: u64,
    pub event_dropped: u64,
    pub events_persisted: u64,
    pub task_read_failed: u64,
    pub exec_path_read_failed: u64,
    pub exec_path_truncated: u64,
    pub userspace_failures: u64,
    pub producer_barrier_complete: bool,
    pub drain_completed: bool,
    pub wal_durable: bool,
    pub poll_calls: u64,
    pub maximum_events_per_poll: u64,
    pub callback_queue_high_water: u64,
    pub callback_queue_capacity: u64,
    pub lineage: Option<ProcessLineageSummary>,
    pub reasons: Vec<String>,
    pub limitations: Vec<String>,
}

impl ProcessLifecycleHealth {
    /// Validate the strongest lifecycle statement supported by schema v2.
    ///
    /// The three scheduler hooks provide a loss-accounted stream for events
    /// admitted while a task is in scope. They do not enroll tasks already
    /// present at S0 and do not observe every cgroup-entry mechanism. A
    /// serialized `COMPLETE` value is therefore always an overclaim, even
    /// when the admitted event stream is terminal and lossless.
    pub fn validate_partial_enrollment_contract(&self) -> Result<()> {
        if self.schema_version != PROCESS_LIFECYCLE_SCHEMA_VERSION
            || self.run_id.is_empty()
            || self.run_id.contains('\0')
            || self.run_epoch == 0
            || self.cgroup_id == 0
        {
            bail!("invalid process-lifecycle health identity");
        }
        if self.event_published.checked_add(self.event_dropped) != Some(self.event_attempted)
            || self.events_persisted > self.event_published
            || self.task_read_failed > self.event_published
            || self.exec_path_read_failed > self.event_published
            || self.exec_path_truncated > self.event_published
            || self.callback_queue_capacity != MAX_LIFECYCLE_CALLBACK_QUEUE_EVENTS as u64
            || self.callback_queue_high_water > self.callback_queue_capacity
            || self.maximum_events_per_poll > self.callback_queue_capacity
        {
            bail!("invalid process-lifecycle health accounting");
        }
        if !self
            .limitations
            .iter()
            .any(|limitation| limitation == PROCESS_LIFECYCLE_ENROLLMENT_LIMITATION)
        {
            bail!("process-lifecycle health omits its partial-enrollment limitation");
        }
        if let Some(lineage) = &self.lineage {
            lineage.validate()?;
            if lineage.event_count != self.events_persisted
                || lineage.task_identities != lineage.exited_task_identities
            {
                bail!("process-lifecycle health lineage is not terminal or WAL-bound");
            }
        }

        let lossless_closed = self.event_dropped == 0
            && self.event_published == self.events_persisted
            && self.task_read_failed == 0
            && self.userspace_failures == 0
            && self.producer_barrier_complete
            && self.drain_completed
            && self.wal_durable
            && self.reasons.is_empty()
            && self.lineage.is_some();
        match self.status {
            ProcessLifecycleStatus::Complete => {
                bail!("process-lifecycle schema v2 cannot claim complete task enrollment")
            }
            ProcessLifecycleStatus::Partial => {
                if !lossless_closed || self.event_attempted == 0 {
                    bail!("PARTIAL lifecycle health is not a nonempty lossless closed stream");
                }
            }
            ProcessLifecycleStatus::UnprovenNoEvents => {
                let empty_lineage = self.lineage.as_ref().map_or(false, |lineage| {
                    lineage.event_count == 0
                        && lineage.task_identities == 0
                        && lineage.exited_task_identities == 0
                        && lineage.group_dead_exits == 0
                });
                if !lossless_closed
                    || self.event_attempted != 0
                    || self.exec_path_read_failed != 0
                    || self.exec_path_truncated != 0
                    || !empty_lineage
                {
                    bail!("UNPROVEN_NO_EVENTS lifecycle health is not canonically empty");
                }
            }
            ProcessLifecycleStatus::Incomplete => {
                if self.reasons.is_empty() {
                    bail!("INCOMPLETE lifecycle health lacks a reason");
                }
            }
        }
        Ok(())
    }
}

/// Dedicated process-lifecycle recorder.  Its object, ring buffer, sequence
/// space, WAL and JSONL are intentionally independent from syscall effects.
/// A runner must register the same `(cgroup_id, epoch)` in both recorders while
/// the workload is stopped and pass the same empty/frozen producer barrier to
/// both finalizers.
pub struct ProcessLifecycleRecorder {
    resources: KernelResources,
    callback: Box<ProcessLifecycleCallbackState>,
    run_states_fd: c_int,
    ancestor_roots: AncestorRootSet,
    cgroup_registration_mode: Option<bool>,
    run_id: String,
    boot_id: String,
    object_sha256: String,
    wal: ProcessLifecycleWalWriter,
    jsonl: BufWriter<File>,
    jsonl_bytes: u64,
    persisted: HashMap<(u64, u64), u64>,
    verifiers: HashMap<(u64, u64), Option<ProcessLineageVerifier>>,
    verification_errors: HashMap<(u64, u64), Vec<String>>,
    finished: HashSet<(u64, u64)>,
    ever_used: HashSet<(u64, u64)>,
    poll_calls: u64,
    maximum_events_per_poll: u64,
}

impl ProcessLifecycleRecorder {
    pub fn open(
        object_path: &Path,
        expected_object_sha256: &str,
        output_dir: &Path,
        run_id: &str,
        boot_id: &str,
    ) -> Result<Self> {
        if run_id.is_empty() || run_id.contains('\0') {
            bail!("run_id must be nonempty and contain no NUL bytes");
        }
        validate_boot_id(boot_id)?;
        std::fs::create_dir_all(output_dir)
            .with_context(|| format!("create process-lifecycle output {}", output_dir.display()))?;
        let wal = ProcessLifecycleWalWriter::create(&output_dir.join(PROCESS_LIFECYCLE_WAL_NAME))?;
        let jsonl = open_process_lifecycle_output(&output_dir.join(PROCESS_LIFECYCLE_JSONL_NAME))?;

        let (object_bytes, object_sha256) = read_object(object_path)?;
        verify_digest(&object_sha256, expected_object_sha256)?;
        let object = unsafe {
            libbpf::bpf_object__open_mem(
                object_bytes.as_ptr().cast(),
                object_bytes.len() as u64,
                ptr::null(),
            )
        };
        check_pointer(object.cast(), "open process-lifecycle BPF object")?;
        let mut resources = KernelResources::new(object);
        check_rc(
            unsafe { libbpf::bpf_object__load(resources.object) },
            "load process-lifecycle BPF object",
        )?;
        let run_states_fd = find_map_fd(resources.object, MAP_LIFECYCLE_RUNS)?;
        let events_fd = find_map_fd(resources.object, MAP_LIFECYCLE_EVENTS)?;
        let root_cgroups_fd = find_map_fd(resources.object, MAP_LIFECYCLE_ROOTS)?;
        let root_ids_fd = find_map_fd(resources.object, MAP_LIFECYCLE_ROOT_IDS)?;
        let root_config_fd = find_map_fd(resources.object, MAP_LIFECYCLE_ROOT_CONFIG)?;
        validate_map_abi(
            run_states_fd,
            MapAbi::new(
                MAP_LIFECYCLE_RUNS,
                libbpf::BPF_MAP_TYPE_HASH,
                8,
                std::mem::size_of::<ProcessLifecycleRunState>() as u32,
                MAX_LIFECYCLE_RUNS,
            ),
        )?;
        validate_map_abi(
            events_fd,
            MapAbi::new(
                MAP_LIFECYCLE_EVENTS,
                libbpf::BPF_MAP_TYPE_RINGBUF,
                0,
                0,
                LIFECYCLE_RING_BYTES,
            ),
        )?;
        validate_map_abi(
            root_cgroups_fd,
            MapAbi::new(
                MAP_LIFECYCLE_ROOTS,
                libbpf::BPF_MAP_TYPE_CGROUP_ARRAY,
                4,
                4,
                MAX_ANCESTOR_ROOTS,
            ),
        )?;
        validate_map_abi(
            root_ids_fd,
            MapAbi::new(
                MAP_LIFECYCLE_ROOT_IDS,
                libbpf::BPF_MAP_TYPE_ARRAY,
                4,
                8,
                MAX_ANCESTOR_ROOTS,
            ),
        )?;
        validate_map_abi(
            root_config_fd,
            MapAbi::new(
                MAP_LIFECYCLE_ROOT_CONFIG,
                libbpf::BPF_MAP_TYPE_ARRAY,
                4,
                std::mem::size_of::<AncestorConfig>() as u32,
                1,
            ),
        )?;
        for program_name in PROGRAM_LIFECYCLE_HOOKS {
            let program = find_program(resources.object, program_name)?;
            let link = unsafe { libbpf::bpf_program__attach(program) };
            check_pointer(link.cast(), "attach process-lifecycle tp_btf program")?;
            resources.links.push(link);
        }

        let mut callback = Box::<ProcessLifecycleCallbackState>::default();
        resources.ring = unsafe {
            libbpf::ring_buffer__new(
                events_fd,
                Some(receive_process_lifecycle_event),
                (&mut *callback as *mut ProcessLifecycleCallbackState).cast(),
                ptr::null(),
            )
        };
        if resources.ring.is_null() {
            return Err(std::io::Error::last_os_error())
                .context("create process-lifecycle ring buffer");
        }

        Ok(Self {
            resources,
            callback,
            run_states_fd,
            ancestor_roots: AncestorRootSet::new(root_cgroups_fd, root_ids_fd, root_config_fd),
            cgroup_registration_mode: None,
            run_id: run_id.to_owned(),
            boot_id: boot_id.to_owned(),
            object_sha256,
            wal,
            jsonl,
            jsonl_bytes: 0,
            persisted: HashMap::new(),
            verifiers: HashMap::new(),
            verification_errors: HashMap::new(),
            finished: HashSet::new(),
            ever_used: HashSet::new(),
            poll_calls: 0,
            maximum_events_per_poll: 0,
        })
    }

    pub fn object_sha256(&self) -> &str {
        &self.object_sha256
    }

    pub fn object_exclusions(&self) -> Result<ObjectExclusions> {
        collect_exclusions(&self.resources)
            .context("resolve every process-lifecycle recorder-owned BPF object ID")
    }

    pub fn register_run(&mut self, cgroup_id: u64, epoch: u64) -> Result<()> {
        if self.cgroup_registration_mode == Some(true) {
            bail!("cannot mix exact and ancestor-root lifecycle registrations");
        }
        if cgroup_id == 0 || epoch == 0 {
            bail!("process-lifecycle cgroup_id and epoch must both be nonzero");
        }
        let key = (cgroup_id, epoch);
        if self.ever_used.contains(&key) || self.persisted.contains_key(&key) {
            bail!("process-lifecycle cgroup/epoch identity cannot be reused");
        }
        let state = ProcessLifecycleRunState {
            epoch,
            ..ProcessLifecycleRunState::default()
        };
        map_update(
            self.run_states_fd,
            &cgroup_id,
            &state,
            libbpf::BPF_NOEXIST as u64,
        )
        .context("register exact cgroup with process-lifecycle recorder")?;
        self.ever_used.insert(key);
        self.persisted.insert(key, 0);
        self.verifiers
            .insert(key, Some(ProcessLineageVerifier::new(epoch, cgroup_id)?));
        self.verification_errors.insert(key, Vec::new());
        self.cgroup_registration_mode = Some(false);
        Ok(())
    }

    pub fn register_ancestor_root(
        &mut self,
        cgroup_path: &Path,
        cgroup_id: u64,
        epoch: u64,
    ) -> Result<()> {
        if self.cgroup_registration_mode == Some(false) {
            bail!("cannot mix ancestor-root and exact lifecycle registrations");
        }
        if cgroup_id == 0 || epoch == 0 {
            bail!("process-lifecycle ancestor root and epoch must be nonzero");
        }
        let key = (cgroup_id, epoch);
        if self.ever_used.contains(&key) || self.persisted.contains_key(&key) {
            bail!("process-lifecycle ancestor root/epoch cannot be reused");
        }
        let state = ProcessLifecycleRunState {
            epoch,
            ..ProcessLifecycleRunState::default()
        };
        map_update(
            self.run_states_fd,
            &cgroup_id,
            &state,
            libbpf::BPF_NOEXIST as u64,
        )
        .context("register ancestor root with process-lifecycle recorder")?;
        if let Err(error) = self.ancestor_roots.register(cgroup_path, cgroup_id, epoch) {
            let _ = map_delete(self.run_states_fd, &cgroup_id);
            return Err(error);
        }
        self.ever_used.insert(key);
        self.persisted.insert(key, 0);
        self.verifiers
            .insert(key, Some(ProcessLineageVerifier::new(epoch, cgroup_id)?));
        self.verification_errors.insert(key, Vec::new());
        self.cgroup_registration_mode = Some(true);
        Ok(())
    }

    pub fn seal_ancestor_roots(&mut self) -> Result<()> {
        if self.cgroup_registration_mode != Some(true) {
            bail!("process-lifecycle recorder has no ancestor roots to seal");
        }
        self.ancestor_roots.seal()
    }

    pub fn verify_ancestor_roots(&self) -> Result<()> {
        if self.cgroup_registration_mode != Some(true) {
            bail!("process-lifecycle recorder is not in ancestor-root mode");
        }
        self.ancestor_roots.verify()
    }

    pub fn poll(&mut self, timeout: Duration) -> Result<usize> {
        self.poll_calls = self.poll_calls.saturating_add(1);
        self.callback.batch_limit_reached = false;
        let rc = unsafe { libbpf::ring_buffer__consume(self.resources.ring) };
        self.validate_consume_result(rc, "consume process-lifecycle ring buffer")?;
        let mut persisted = self.persist_queued()?;
        if persisted != 0 {
            self.maximum_events_per_poll = self.maximum_events_per_poll.max(persisted as u64);
            return Ok(persisted);
        }

        self.callback.batch_limit_reached = false;
        let millis = timeout.as_millis().min(c_int::MAX as u128) as c_int;
        let rc = unsafe { libbpf::ring_buffer__poll(self.resources.ring, millis) };
        self.validate_consume_result(rc, "poll process-lifecycle ring buffer")?;
        persisted = self.persist_queued()?;
        self.maximum_events_per_poll = self.maximum_events_per_poll.max(persisted as u64);
        Ok(persisted)
    }

    pub fn finish_run(
        &mut self,
        cgroup_id: u64,
        epoch: u64,
        timeout: Duration,
        producer_barrier_complete: bool,
    ) -> Result<ProcessLifecycleHealth> {
        let key = (cgroup_id, epoch);
        if !self.persisted.contains_key(&key) {
            bail!("process-lifecycle run cgroup/epoch is not registered");
        }
        if self.finished.contains(&key) {
            bail!("process-lifecycle run was already finalized");
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .context("process-lifecycle drain timeout exceeds monotonic clock range")?;
        let mut timed_out = false;
        loop {
            self.poll(
                Duration::from_millis(20).min(deadline.saturating_duration_since(Instant::now())),
            )?;
            let first = self.read_run_state(cgroup_id, epoch)?;
            let persisted = self.persisted.get(&key).copied().unwrap_or(0);
            if first.event_published == persisted {
                self.poll(Duration::ZERO)?;
                let second = self.read_run_state(cgroup_id, epoch)?;
                let persisted = self.persisted.get(&key).copied().unwrap_or(0);
                if first == second && second.event_published == persisted {
                    break;
                }
            }
            if Instant::now() >= deadline {
                timed_out = true;
                break;
            }
        }
        self.sync_outputs()?;
        let state = self.read_run_state(cgroup_id, epoch)?;
        let persisted = self.persisted.get(&key).copied().unwrap_or(0);
        let mut reasons = Vec::new();
        if timed_out {
            reasons.push("process-lifecycle recorder drain timed out".to_owned());
        }
        if state.event_published.checked_add(state.event_dropped) != Some(state.event_attempted) {
            reasons.push("process-lifecycle kernel event accounting invariant failed".to_owned());
        }
        if state.next_event_seq != state.event_published {
            reasons
                .push("process-lifecycle sequence allocation did not match publication".to_owned());
        }
        if state.event_published != persisted {
            reasons.push("published process-lifecycle events were not all persisted".to_owned());
        }
        if state.event_dropped != 0 {
            reasons.push("kernel ring buffer dropped process-lifecycle events".to_owned());
        }
        if state.task_read_failed != 0 {
            reasons
                .push("TASK_READ_FAILED prevents complete process identity correlation".to_owned());
        }
        if !producer_barrier_complete {
            reasons.push("producer cgroup empty/frozen barrier was not established".to_owned());
        }
        let userspace_failures = self
            .callback
            .decode_failures
            .saturating_add(self.callback.routing_failures)
            .saturating_add(self.callback.verification_failures)
            .saturating_add(self.callback.capacity_failures);
        if userspace_failures != 0 {
            reasons.push(
                "process-lifecycle userspace decode, routing, replay, or capacity failure"
                    .to_owned(),
            );
        }
        if let Some(errors) = self.verification_errors.get(&key) {
            reasons.extend(
                errors
                    .iter()
                    .map(|error| format!("offline lineage replay: {error}")),
            );
        }
        let lineage = self
            .verifiers
            .get(&key)
            .and_then(Option::as_ref)
            .and_then(|verifier| {
                match verifier.finish(state.event_published, state.event_dropped) {
                    Ok(summary) => Some(summary),
                    Err(error) => {
                        reasons.push(format!("offline lineage finalization: {error:#}"));
                        None
                    }
                }
            });
        let drain_completed = !timed_out && state.event_published == persisted;
        let status = if !reasons.is_empty() {
            ProcessLifecycleStatus::Incomplete
        } else if state.event_attempted == 0 {
            ProcessLifecycleStatus::UnprovenNoEvents
        } else {
            // Schema v2 proves lossless replay only for events admitted by the
            // three scheduler hooks.  Without an S0 task/thread ledger and
            // migration/CLONE_INTO_CGROUP enrollment, it must never claim a
            // complete whole-tree lifecycle association.
            ProcessLifecycleStatus::Partial
        };
        let mut limitations = vec![
            PROCESS_LIFECYCLE_ENROLLMENT_LIMITATION.to_owned(),
            "EXEC filename is a bounded kernel-copied description, not executable FILE_OBJECT identity".to_owned(),
            "direct exact-cgroup lifecycle attribution does not establish delegated causality".to_owned(),
            "lossless terminal WAL replay applies only to lifecycle events admitted by the three scheduler hooks".to_owned(),
        ];
        if state.exec_path_read_failed != 0 {
            limitations.push("one or more EXEC descriptive paths were unavailable".to_owned());
        }
        if state.exec_path_truncated != 0 {
            limitations.push("one or more EXEC descriptive paths were truncated".to_owned());
        }
        if drain_completed {
            self.finished.insert(key);
        }
        let health = ProcessLifecycleHealth {
            schema_version: PROCESS_LIFECYCLE_SCHEMA_VERSION,
            run_id: self.run_id.clone(),
            run_epoch: epoch,
            cgroup_id,
            status,
            event_attempted: state.event_attempted,
            event_published: state.event_published,
            event_dropped: state.event_dropped,
            events_persisted: persisted,
            task_read_failed: state.task_read_failed,
            exec_path_read_failed: state.exec_path_read_failed,
            exec_path_truncated: state.exec_path_truncated,
            userspace_failures,
            producer_barrier_complete,
            drain_completed,
            wal_durable: true,
            poll_calls: self.poll_calls,
            maximum_events_per_poll: self.maximum_events_per_poll,
            callback_queue_high_water: self.callback.queue_high_water as u64,
            callback_queue_capacity: MAX_LIFECYCLE_CALLBACK_QUEUE_EVENTS as u64,
            lineage,
            reasons,
            limitations,
        };
        health.validate_partial_enrollment_contract()?;
        Ok(health)
    }

    pub fn unregister_run(&mut self, cgroup_id: u64, epoch: u64) -> Result<()> {
        if self.cgroup_registration_mode == Some(true) {
            bail!("ancestor-root lifecycle runs require unregister_ancestor_root");
        }
        let key = (cgroup_id, epoch);
        if !self.finished.contains(&key) {
            bail!("finish_run must drain before process-lifecycle unregister_run");
        }
        let state = self.read_run_state(cgroup_id, epoch)?;
        let persisted = self.persisted.get(&key).copied().unwrap_or(0);
        if state.event_published != persisted {
            bail!("refusing to unregister an undrained process-lifecycle run");
        }
        map_delete(self.run_states_fd, &cgroup_id).context("unregister process-lifecycle run")?;
        self.persisted.remove(&key);
        self.verifiers.remove(&key);
        self.verification_errors.remove(&key);
        self.finished.remove(&key);
        Ok(())
    }

    pub fn unregister_ancestor_root(&mut self, cgroup_id: u64, epoch: u64) -> Result<()> {
        if self.cgroup_registration_mode != Some(true) {
            bail!("process-lifecycle recorder is not in ancestor-root mode");
        }
        let key = (cgroup_id, epoch);
        if !self.finished.contains(&key) {
            bail!("finish_run must drain before unregister_ancestor_root");
        }
        let state = self.read_run_state(cgroup_id, epoch)?;
        let persisted = self.persisted.get(&key).copied().unwrap_or(0);
        if state.event_published != persisted {
            bail!("refusing to unregister an undrained lifecycle ancestor root");
        }
        self.ancestor_roots.unregister(cgroup_id, epoch)?;
        map_delete(self.run_states_fd, &cgroup_id)
            .context("unregister process-lifecycle ancestor root")?;
        self.persisted.remove(&key);
        self.verifiers.remove(&key);
        self.verification_errors.remove(&key);
        self.finished.remove(&key);
        Ok(())
    }

    fn validate_consume_result(&self, rc: c_int, action: &'static str) -> Result<()> {
        if rc >= 0 || rc == -libc::EINTR {
            if self.callback.batch_limit_reached {
                bail!("process-lifecycle callback batch stop was not propagated by libbpf");
            }
            return Ok(());
        }
        if rc == -libc::EAGAIN && self.callback.batch_limit_reached {
            return Ok(());
        }
        if self.callback.capacity_failures != 0 {
            bail!(
                "process-lifecycle event capacity exceeded (batch <= {MAX_LIFECYCLE_CALLBACK_QUEUE_EVENTS}, total <= {MAX_PROCESS_LIFECYCLE_EVENTS})"
            );
        }
        Err(libbpf_error(rc)).context(action)
    }

    fn persist_queued(&mut self) -> Result<usize> {
        let mut count = 0usize;
        while let Some(event) = self.callback.queue.pop_front() {
            let key = (event.cgroup_id, event.run_epoch);
            let cgroup_match_mode = match self.cgroup_registration_mode {
                Some(true) => CgroupMatchMode::AncestorRoot,
                Some(false) => CgroupMatchMode::ExactCurrent,
                None => {
                    self.callback.routing_failures =
                        self.callback.routing_failures.saturating_add(1);
                    bail!("lifecycle event arrived without a cgroup registration mode");
                }
            };
            let schema =
                event.to_event_with_cgroup_match(&self.run_id, &self.boot_id, cgroup_match_mode)?;
            let json = serde_json::to_vec(&schema)?;
            let next_size = self
                .jsonl_bytes
                .checked_add(json.len() as u64 + 1)
                .context("process-lifecycle JSONL size overflow")?;
            if next_size > MAX_PROCESS_LIFECYCLE_JSONL_BYTES {
                bail!("process-lifecycle JSONL exceeded {MAX_PROCESS_LIFECYCLE_JSONL_BYTES} bytes");
            }
            self.wal.append(&event)?;
            self.jsonl.write_all(&json)?;
            self.jsonl.write_all(b"\n")?;
            self.jsonl_bytes = next_size;

            if let Some(persisted) = self.persisted.get_mut(&key) {
                *persisted = persisted.saturating_add(1);
                if let Some(verifier_slot) = self.verifiers.get_mut(&key) {
                    if let Some(verifier) = verifier_slot.as_mut() {
                        if let Err(error) = verifier.ingest(&event) {
                            self.callback.verification_failures =
                                self.callback.verification_failures.saturating_add(1);
                            self.verification_errors
                                .entry(key)
                                .or_default()
                                .push(format!("{error:#}"));
                            *verifier_slot = None;
                        }
                    }
                } else {
                    self.callback.routing_failures =
                        self.callback.routing_failures.saturating_add(1);
                }
            } else {
                self.callback.routing_failures = self.callback.routing_failures.saturating_add(1);
            }
            count = count.saturating_add(1);
        }
        Ok(count)
    }

    fn sync_outputs(&mut self) -> Result<()> {
        self.wal.sync().context("sync process-lifecycle WAL")?;
        self.jsonl
            .flush()
            .context("flush process-lifecycle JSONL")?;
        self.jsonl
            .get_ref()
            .sync_all()
            .context("sync process-lifecycle JSONL")?;
        Ok(())
    }

    fn read_run_state(&self, cgroup_id: u64, epoch: u64) -> Result<ProcessLifecycleRunState> {
        let mut state = ProcessLifecycleRunState::default();
        map_lookup(self.run_states_fd, &cgroup_id, &mut state)
            .context("read process-lifecycle run counters")?;
        if state.epoch != epoch {
            bail!(
                "process-lifecycle run epoch mismatch for cgroup {cgroup_id}: {} != {epoch}",
                state.epoch
            );
        }
        Ok(state)
    }
}

fn open_process_lifecycle_output(path: &Path) -> Result<BufWriter<File>> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create process-lifecycle output {}", path.display()))?;
    Ok(BufWriter::new(file))
}

pub struct ProcessLifecycleWalWriter {
    writer: BufWriter<File>,
}

impl ProcessLifecycleWalWriter {
    pub fn create(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("create process-lifecycle WAL {}", path.display()))?;
        Ok(Self {
            writer: BufWriter::new(file),
        })
    }

    pub fn append(&mut self, event: &KernelProcessLifecycleEvent) -> Result<()> {
        event.validate()?;
        let payload = event.encode_le();
        self.writer
            .write_all(&(payload.len() as u32).to_le_bytes())?;
        self.writer.write_all(&payload)?;
        self.writer
            .write_all(&crc32fast::hash(&payload).to_le_bytes())?;
        Ok(())
    }

    pub fn sync(&mut self) -> Result<()> {
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessLifecycleWalRecovery {
    pub events: Vec<KernelProcessLifecycleEvent>,
    pub truncated_tail: bool,
}

pub fn recover_process_lifecycle_wal(path: &Path) -> Result<ProcessLifecycleWalRecovery> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open process-lifecycle WAL {}", path.display()))?;
    let before = file.metadata()?;
    if !before.file_type().is_file() || before.nlink() != 1 {
        bail!("process-lifecycle WAL must be a singly linked regular file");
    }
    if before.len() > MAX_PROCESS_LIFECYCLE_WAL_BYTES {
        bail!("process-lifecycle WAL exceeds its recovery byte limit");
    }
    let recovery = recover_process_lifecycle_reader(&mut file)?;
    let after = file.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        bail!("process-lifecycle WAL changed while it was recovered");
    }
    Ok(recovery)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessLifecycleVerification {
    pub schema_version: u32,
    pub wal_event_count: u64,
    pub jsonl_projection_verified: bool,
    pub lineage: ProcessLineageSummary,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessLifecycleVerificationBinding {
    pub run_id: String,
    pub boot_id: String,
    pub run_epoch: u64,
    pub cgroup_id: u64,
    pub cgroup_match_mode: CgroupMatchMode,
    pub published: u64,
    pub dropped: u64,
}

/// Independently rebuild lifecycle evidence from the CRC-framed WAL and prove
/// that the human-readable JSONL is exactly its canonical projection.  JSONL
/// is never used as authority for lineage or counters.
pub fn verify_process_lifecycle_artifacts(
    wal_path: &Path,
    jsonl_path: &Path,
    binding: &ProcessLifecycleVerificationBinding,
) -> Result<ProcessLifecycleVerification> {
    if binding.run_id.is_empty() || binding.run_id.contains('\0') {
        bail!("run_id must be nonempty and contain no NUL bytes");
    }
    validate_boot_id(&binding.boot_id)?;
    let recovery = recover_process_lifecycle_wal(wal_path)?;
    if recovery.truncated_tail {
        bail!("process-lifecycle WAL has a truncated tail");
    }
    let mut verifier = ProcessLineageVerifier::new(binding.run_epoch, binding.cgroup_id)?;
    let mut projected = Vec::with_capacity(recovery.events.len());
    for event in &recovery.events {
        verifier.ingest(event)?;
        projected.push(event.to_event_with_cgroup_match(
            &binding.run_id,
            &binding.boot_id,
            binding.cgroup_match_mode,
        )?);
    }
    let lineage = verifier.finish(binding.published, binding.dropped)?;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(jsonl_path)
        .with_context(|| format!("open process-lifecycle JSONL {}", jsonl_path.display()))?;
    let before = file.metadata()?;
    if !before.file_type().is_file() || before.nlink() != 1 {
        bail!("process-lifecycle JSONL must be a singly linked regular file");
    }
    if before.len() > MAX_PROCESS_LIFECYCLE_JSONL_BYTES {
        bail!("process-lifecycle JSONL exceeds its verification byte limit");
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    let mut limited = file.take(MAX_PROCESS_LIFECYCLE_JSONL_BYTES + 1);
    limited.read_to_end(&mut bytes)?;
    let after = limited.get_ref().metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || bytes.len() as u64 != before.len()
    {
        bail!("process-lifecycle JSONL changed while it was verified");
    }
    if (!projected.is_empty() && !bytes.ends_with(b"\n"))
        || (projected.is_empty() && !bytes.is_empty())
    {
        bail!("process-lifecycle JSONL has a noncanonical terminator");
    }
    let body = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    let lines: Vec<&[u8]> = if body.is_empty() {
        Vec::new()
    } else {
        let lines: Vec<&[u8]> = body.split(|byte| *byte == b'\n').collect();
        if lines.iter().any(|line| line.is_empty()) {
            bail!("process-lifecycle JSONL contains an empty line");
        }
        lines
    };
    if lines.len() != projected.len() {
        bail!("process-lifecycle JSONL/WAL event counts disagree");
    }
    for (index, (line, expected)) in lines.iter().zip(&projected).enumerate() {
        let decoded: ProcessLifecycleEvent = serde_json::from_slice(line)
            .with_context(|| format!("decode process-lifecycle JSONL line {}", index + 1))?;
        decoded.validate()?;
        if &decoded != expected || serde_json::to_vec(expected)?.as_slice() != *line {
            bail!(
                "process-lifecycle JSONL line {} is not the canonical WAL projection",
                index + 1
            );
        }
    }
    Ok(ProcessLifecycleVerification {
        schema_version: PROCESS_LIFECYCLE_SCHEMA_VERSION,
        wal_event_count: recovery.events.len() as u64,
        jsonl_projection_verified: true,
        lineage,
    })
}

pub fn recover_process_lifecycle_reader(reader: impl Read) -> Result<ProcessLifecycleWalRecovery> {
    let mut reader = BufReader::new(reader);
    let mut events = Vec::new();
    let mut consumed = 0u64;
    loop {
        let mut length_bytes = [0u8; 4];
        match read_part(&mut reader, &mut length_bytes)? {
            ReadPart::Eof => {
                return Ok(ProcessLifecycleWalRecovery {
                    events,
                    truncated_tail: false,
                })
            }
            ReadPart::Truncated => {
                return Ok(ProcessLifecycleWalRecovery {
                    events,
                    truncated_tail: true,
                })
            }
            ReadPart::Complete => {}
        }
        let length = u32::from_le_bytes(length_bytes) as usize;
        if length != KERNEL_PROCESS_LIFECYCLE_EVENT_SIZE {
            bail!("unsupported process-lifecycle WAL frame length {length}");
        }
        consumed = consumed
            .checked_add(8 + length as u64)
            .context("process-lifecycle WAL byte count overflow")?;
        if consumed > MAX_PROCESS_LIFECYCLE_WAL_BYTES
            || events.len() >= MAX_PROCESS_LIFECYCLE_EVENTS
        {
            bail!("process-lifecycle WAL exceeds a recovery limit");
        }
        let mut payload = vec![0u8; length];
        if read_part(&mut reader, &mut payload)? != ReadPart::Complete {
            return Ok(ProcessLifecycleWalRecovery {
                events,
                truncated_tail: true,
            });
        }
        let mut checksum = [0u8; 4];
        if read_part(&mut reader, &mut checksum)? != ReadPart::Complete {
            return Ok(ProcessLifecycleWalRecovery {
                events,
                truncated_tail: true,
            });
        }
        if crc32fast::hash(&payload) != u32::from_le_bytes(checksum) {
            bail!("process-lifecycle WAL checksum mismatch");
        }
        events.push(KernelProcessLifecycleEvent::decode_le(&payload)?);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadPart {
    Eof,
    Truncated,
    Complete,
}

fn read_part(reader: &mut impl Read, output: &mut [u8]) -> Result<ReadPart> {
    let mut offset = 0;
    while offset < output.len() {
        match reader.read(&mut output[offset..]) {
            Ok(0) if offset == 0 => return Ok(ReadPart::Eof),
            Ok(0) => return Ok(ReadPart::Truncated),
            Ok(count) => offset += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(ReadPart::Complete)
}

#[derive(Clone, Copy)]
enum Endian {
    Native,
    Little,
}

impl Endian {
    fn u16(self, bytes: &[u8]) -> u16 {
        match self {
            Self::Native => u16::from_ne_bytes(bytes.try_into().unwrap()),
            Self::Little => u16::from_le_bytes(bytes.try_into().unwrap()),
        }
    }
    fn u32(self, bytes: &[u8]) -> u32 {
        match self {
            Self::Native => u32::from_ne_bytes(bytes.try_into().unwrap()),
            Self::Little => u32::from_le_bytes(bytes.try_into().unwrap()),
        }
    }
    fn i32(self, bytes: &[u8]) -> i32 {
        match self {
            Self::Native => i32::from_ne_bytes(bytes.try_into().unwrap()),
            Self::Little => i32::from_le_bytes(bytes.try_into().unwrap()),
        }
    }
    fn u64(self, bytes: &[u8]) -> u64 {
        match self {
            Self::Native => u64::from_ne_bytes(bytes.try_into().unwrap()),
            Self::Little => u64::from_le_bytes(bytes.try_into().unwrap()),
        }
    }
}

fn nul_terminated_lossy(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(TABLE[(byte >> 4) as usize] as char);
        output.push(TABLE[(byte & 0xf) as usize] as char);
    }
    output
}

fn decode_hex(value: &str, maximum_bytes: usize) -> Result<Vec<u8>> {
    if value.len() % 2 != 0
        || value.is_empty()
        || value.len() > maximum_bytes.saturating_mul(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("value is not bounded canonical lowercase hex");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((hex_nibble(pair[0]) << 4) | hex_nibble(pair[1])))
        .collect()
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => unreachable!("decode_hex validated every nibble"),
    }
}

fn validate_boot_id(value: &str) -> Result<()> {
    if value.len() != 36
        || value.bytes().enumerate().any(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte != b'-'
            } else {
                !(byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            }
        })
    {
        bail!("boot_id must be a canonical lowercase UUID");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const BOOT_ID: &str = "01234567-89ab-cdef-0123-456789abcdef";

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "bpf-observer-lifecycle-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn event(kind: u16, sequence: u64, pid: u32, start: u64) -> KernelProcessLifecycleEvent {
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"task");
        let mut parent_comm = [0u8; 16];
        parent_comm[..6].copy_from_slice(b"parent");
        KernelProcessLifecycleEvent {
            schema_version: PROCESS_LIFECYCLE_SCHEMA_VERSION,
            kind,
            exec_path_len: 0,
            flags: 0,
            exit_code: 0,
            run_epoch: 7,
            event_seq: sequence,
            ktime_ns: 100 + sequence,
            cgroup_id: 9,
            start_boottime_ns: start,
            parent_start_boottime_ns: 10,
            pid,
            tgid: pid,
            parent_pid: 1,
            parent_tgid: 1,
            old_pid: 0,
            group_dead: 0,
            comm,
            parent_comm,
            exec_path: [0; PROCESS_EXEC_PATH_BYTES],
        }
    }

    fn exec(sequence: u64, pid: u32, start: u64) -> KernelProcessLifecycleEvent {
        let mut event = event(PROCESS_LIFECYCLE_EXEC, sequence, pid, start);
        event.old_pid = pid;
        event.exec_path[..9].copy_from_slice(b"/bin/true");
        event.exec_path_len = 9;
        event
    }

    #[test]
    fn fixed_frame_round_trip_and_exec_schema() {
        let raw = exec(1, 22, 44);
        let encoded = raw.encode_le();
        assert_eq!(encoded.len(), KERNEL_PROCESS_LIFECYCLE_EVENT_SIZE);
        assert_eq!(
            KernelProcessLifecycleEvent::decode_le(&encoded).unwrap(),
            raw
        );
        let event = raw.to_event("run", BOOT_ID).unwrap();
        event.validate().unwrap();
        assert_eq!(event.exec_path.unwrap().display, "/bin/true");
    }

    #[test]
    fn decoder_rejects_noncanonical_tail_and_forged_path_status() {
        let mut raw = exec(1, 22, 44);
        let mut encoded = raw.encode_le();
        encoded[140] = 1;
        assert!(KernelProcessLifecycleEvent::decode_le(&encoded).is_err());
        raw.flags |= PROCESS_FLAG_EXEC_PATH_READ_FAILED;
        assert!(raw.validate().is_err());
    }

    #[test]
    fn lineage_replay_correlates_fork_exec_exit_and_pid_reuse() {
        let mut verifier = ProcessLineageVerifier::new(7, 9).unwrap();
        verifier
            .ingest(&event(PROCESS_LIFECYCLE_FORK, 1, 22, 44))
            .unwrap();
        verifier.ingest(&exec(2, 22, 44)).unwrap();
        let mut exit = event(PROCESS_LIFECYCLE_EXIT, 3, 22, 44);
        exit.group_dead = 1;
        verifier.ingest(&exit).unwrap();
        verifier
            .ingest(&event(PROCESS_LIFECYCLE_FORK, 4, 22, 55))
            .unwrap();
        let mut reused_exit = event(PROCESS_LIFECYCLE_EXIT, 5, 22, 55);
        reused_exit.group_dead = 1;
        verifier.ingest(&reused_exit).unwrap();
        let summary = verifier.finish(5, 0).unwrap();
        assert_eq!(summary.task_identities, 2);
        assert_eq!(summary.exited_task_identities, 2);
        assert_eq!(summary.group_dead_exits, 2);
    }

    #[test]
    fn lineage_replay_fails_closed_on_loss_gap_or_duplicate_exit() {
        let mut verifier = ProcessLineageVerifier::new(7, 9).unwrap();
        verifier
            .ingest(&event(PROCESS_LIFECYCLE_FORK, 1, 22, 44))
            .unwrap();
        verifier
            .ingest(&event(PROCESS_LIFECYCLE_EXIT, 3, 22, 44))
            .unwrap();
        assert!(verifier.finish(2, 0).is_err());

        let mut verifier = ProcessLineageVerifier::new(7, 9).unwrap();
        verifier
            .ingest(&event(PROCESS_LIFECYCLE_EXIT, 1, 22, 44))
            .unwrap();
        assert!(verifier
            .ingest(&event(PROCESS_LIFECYCLE_EXIT, 2, 22, 44))
            .is_err());
    }

    #[test]
    fn framed_wal_recovers_complete_prefix_only() {
        let raw = event(PROCESS_LIFECYCLE_FORK, 1, 22, 44);
        let encoded = raw.encode_le();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&encoded);
        bytes.extend_from_slice(&crc32fast::hash(&encoded).to_le_bytes());
        bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&encoded[..7]);
        let recovery = recover_process_lifecycle_reader(bytes.as_slice()).unwrap();
        assert_eq!(recovery.events, vec![raw]);
        assert!(recovery.truncated_tail);
    }

    #[test]
    fn lifecycle_transport_layout_and_callback_boundary_are_closed() {
        assert_eq!(std::mem::size_of::<ProcessLifecycleRunState>(), 64);
        assert_eq!(KERNEL_PROCESS_LIFECYCLE_EVENT_SIZE, 248);
        let mut callback = ProcessLifecycleCallbackState::default();
        for index in 0..MAX_LIFECYCLE_CALLBACK_QUEUE_EVENTS {
            let rc = enqueue_process_lifecycle_event(
                &mut callback,
                event(
                    PROCESS_LIFECYCLE_FORK,
                    index as u64 + 1,
                    index as u32 + 2,
                    index as u64 + 20,
                ),
            );
            if index + 1 == MAX_LIFECYCLE_CALLBACK_QUEUE_EVENTS {
                assert_eq!(rc, -libc::EAGAIN);
            } else {
                assert_eq!(rc, 0);
            }
        }
        assert_eq!(callback.queue.len(), MAX_LIFECYCLE_CALLBACK_QUEUE_EVENTS);
        assert_eq!(
            enqueue_process_lifecycle_event(
                &mut callback,
                event(PROCESS_LIFECYCLE_FORK, 5000, 5000, 5000),
            ),
            -libc::EFBIG
        );
    }

    fn partial_health(status: ProcessLifecycleStatus, events: u64) -> ProcessLifecycleHealth {
        ProcessLifecycleHealth {
            schema_version: PROCESS_LIFECYCLE_SCHEMA_VERSION,
            run_id: "run".to_owned(),
            run_epoch: 7,
            cgroup_id: 9,
            status,
            event_attempted: events,
            event_published: events,
            event_dropped: 0,
            events_persisted: events,
            task_read_failed: 0,
            exec_path_read_failed: 0,
            exec_path_truncated: 0,
            userspace_failures: 0,
            producer_barrier_complete: true,
            drain_completed: true,
            wal_durable: true,
            poll_calls: 1,
            maximum_events_per_poll: events,
            callback_queue_high_water: events,
            callback_queue_capacity: MAX_LIFECYCLE_CALLBACK_QUEUE_EVENTS as u64,
            lineage: Some(ProcessLineageSummary {
                event_count: events,
                task_identities: events,
                exited_task_identities: events,
                group_dead_exits: events,
                enrollment: ProcessEnrollmentSummary {
                    initial_task_ledger_present: false,
                    initial_tasks_enrolled: 0,
                    migration_hook_present: false,
                    clone_into_cgroup_covered: false,
                    migration_enrolled_task_identities: 0,
                    fork_enrolled_task_identities: 0,
                    exec_introduced_task_identities: 0,
                    exit_introduced_task_identities: events,
                    forks_with_unenrolled_parent: 0,
                    complete: false,
                },
                correlation:
                    "PARTIAL_FORK_EXEC_EXIT_BY_BOOT_ID_PID_START_BOOTTIME_AND_EXEC_OLD_PID"
                        .to_owned(),
            }),
            reasons: Vec::new(),
            limitations: vec![PROCESS_LIFECYCLE_ENROLLMENT_LIMITATION.to_owned()],
        }
    }

    #[test]
    fn lifecycle_health_never_accepts_complete_enrollment() {
        let partial = partial_health(ProcessLifecycleStatus::Partial, 1);
        partial.validate_partial_enrollment_contract().unwrap();

        let mut complete = partial;
        complete.status = ProcessLifecycleStatus::Complete;
        assert!(complete.validate_partial_enrollment_contract().is_err());

        let empty = partial_health(ProcessLifecycleStatus::UnprovenNoEvents, 0);
        empty.validate_partial_enrollment_contract().unwrap();

        let mut false_partial = empty;
        false_partial.status = ProcessLifecycleStatus::Partial;
        assert!(false_partial
            .validate_partial_enrollment_contract()
            .is_err());
    }

    #[test]
    fn offline_verifier_rebuilds_wal_and_rejects_projection_tampering() {
        let directory = TestDirectory::new();
        let wal_path = directory.0.join(PROCESS_LIFECYCLE_WAL_NAME);
        let jsonl_path = directory.0.join(PROCESS_LIFECYCLE_JSONL_NAME);
        let root_exec = exec(1, 22, 44);
        let mut root_exit = event(PROCESS_LIFECYCLE_EXIT, 2, 22, 44);
        root_exit.group_dead = 1;
        let events = [root_exec, root_exit];
        let mut wal = ProcessLifecycleWalWriter::create(&wal_path).unwrap();
        let mut jsonl = open_process_lifecycle_output(&jsonl_path).unwrap();
        for raw in &events {
            wal.append(raw).unwrap();
            serde_json::to_writer(&mut jsonl, &raw.to_event("run", BOOT_ID).unwrap()).unwrap();
            jsonl.write_all(b"\n").unwrap();
        }
        wal.sync().unwrap();
        jsonl.flush().unwrap();
        jsonl.get_ref().sync_all().unwrap();
        drop(jsonl);
        drop(wal);

        let binding = ProcessLifecycleVerificationBinding {
            run_id: "run".to_owned(),
            boot_id: BOOT_ID.to_owned(),
            run_epoch: 7,
            cgroup_id: 9,
            cgroup_match_mode: CgroupMatchMode::ExactCurrent,
            published: 2,
            dropped: 0,
        };
        let verified =
            verify_process_lifecycle_artifacts(&wal_path, &jsonl_path, &binding).unwrap();
        assert_eq!(verified.wal_event_count, 2);
        assert_eq!(verified.lineage.exited_task_identities, 1);

        let mut tampered = std::fs::read(&jsonl_path).unwrap();
        let position = tampered.iter().position(|byte| *byte == b'r').unwrap();
        tampered[position] = b'R';
        std::fs::write(&jsonl_path, tampered).unwrap();
        assert!(verify_process_lifecycle_artifacts(&wal_path, &jsonl_path, &binding).is_err());
    }
}
