// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, Result};
use bpf_observer_schema::{EventKind, EvidenceEvent, SCHEMA_VERSION};
use std::collections::BTreeSet;

pub const KERNEL_EVENT_SIZE: usize = 72;
pub const EVENT_SYSCALL_ATTEMPTED: u16 = 1;
pub const EVENT_COMMAND_COMPLETED: u16 = 2;
pub const FLAG_COMMON_ATTRS: u16 = 1 << 0;
pub const FLAG_PENDING_INSERT_FAILED: u16 = 1 << 1;
pub const FLAG_PENDING_MISSING: u16 = 1 << 2;
pub const FLAG_PENDING_POISONED: u16 = 1 << 3;
pub const FLAG_PENDING_DELETE_FAILED: u16 = 1 << 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct RunState {
    pub epoch: u64,
    pub next_event_seq: u64,
    pub syscall_attempted: u64,
    pub syscall_completed: u64,
    pub event_attempted: u64,
    pub event_published: u64,
    pub event_dropped: u64,
    pub pending_insert_failed: u64,
    pub pending_missing: u64,
    pub pending_remaining: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelEvent {
    pub schema_version: u32,
    pub kind: u16,
    pub flags: u16,
    pub command: u32,
    pub attr_size: u32,
    pub run_epoch: u64,
    pub event_seq: u64,
    pub related_attempt_seq: u64,
    pub ktime_ns: u64,
    pub cgroup_id: u64,
    pub pid_tgid: u64,
    pub return_value: i64,
}

impl KernelEvent {
    pub fn decode_native(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KERNEL_EVENT_SIZE {
            bail!(
                "kernel event has {} bytes, expected {KERNEL_EVENT_SIZE}",
                bytes.len()
            );
        }
        let event = Self {
            schema_version: u32::from_ne_bytes(bytes[0..4].try_into().unwrap()),
            kind: u16::from_ne_bytes(bytes[4..6].try_into().unwrap()),
            flags: u16::from_ne_bytes(bytes[6..8].try_into().unwrap()),
            command: u32::from_ne_bytes(bytes[8..12].try_into().unwrap()),
            attr_size: u32::from_ne_bytes(bytes[12..16].try_into().unwrap()),
            run_epoch: u64::from_ne_bytes(bytes[16..24].try_into().unwrap()),
            event_seq: u64::from_ne_bytes(bytes[24..32].try_into().unwrap()),
            related_attempt_seq: u64::from_ne_bytes(bytes[32..40].try_into().unwrap()),
            ktime_ns: u64::from_ne_bytes(bytes[40..48].try_into().unwrap()),
            cgroup_id: u64::from_ne_bytes(bytes[48..56].try_into().unwrap()),
            pid_tgid: u64::from_ne_bytes(bytes[56..64].try_into().unwrap()),
            return_value: i64::from_ne_bytes(bytes[64..72].try_into().unwrap()),
        };
        event.validate()?;
        Ok(event)
    }

    pub fn decode_le(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KERNEL_EVENT_SIZE {
            bail!(
                "WAL event has {} bytes, expected {KERNEL_EVENT_SIZE}",
                bytes.len()
            );
        }
        let event = Self {
            schema_version: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            kind: u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
            flags: u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
            command: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            attr_size: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
            run_epoch: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            event_seq: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
            related_attempt_seq: u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
            ktime_ns: u64::from_le_bytes(bytes[40..48].try_into().unwrap()),
            cgroup_id: u64::from_le_bytes(bytes[48..56].try_into().unwrap()),
            pid_tgid: u64::from_le_bytes(bytes[56..64].try_into().unwrap()),
            return_value: i64::from_le_bytes(bytes[64..72].try_into().unwrap()),
        };
        event.validate()?;
        Ok(event)
    }

    pub fn encode_le(&self) -> [u8; KERNEL_EVENT_SIZE] {
        let mut bytes = [0u8; KERNEL_EVENT_SIZE];
        bytes[0..4].copy_from_slice(&self.schema_version.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.kind.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.flags.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.command.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.attr_size.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.run_epoch.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.event_seq.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.related_attempt_seq.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.ktime_ns.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.cgroup_id.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.pid_tgid.to_le_bytes());
        bytes[64..72].copy_from_slice(&self.return_value.to_le_bytes());
        bytes
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            bail!(
                "kernel event schema {} != userspace schema {SCHEMA_VERSION}",
                self.schema_version
            );
        }
        if !matches!(self.kind, EVENT_SYSCALL_ATTEMPTED | EVENT_COMMAND_COMPLETED) {
            bail!("unknown kernel event kind {}", self.kind);
        }
        if self.kind == EVENT_SYSCALL_ATTEMPTED && self.return_value != 0 {
            bail!("attempted event has a nonzero return value");
        }
        if self.run_epoch == 0 || self.event_seq == 0 || self.cgroup_id == 0 {
            bail!("kernel event has a zero identity field");
        }
        if self.kind == EVENT_COMMAND_COMPLETED && self.related_attempt_seq == 0 {
            // An explicit pending-missing completion is allowed to have no pair.
            if self.flags & FLAG_PENDING_MISSING == 0 {
                bail!("completed event has no related attempt");
            }
        }
        Ok(())
    }

    pub fn to_schema(&self, run_id: &str) -> EvidenceEvent {
        let (kind, return_value, argument_provenance) = match self.kind {
            EVENT_SYSCALL_ATTEMPTED => (EventKind::SyscallAttempted, None, "RAW_SYSCALL_REGISTERS"),
            EVENT_COMMAND_COMPLETED => (
                EventKind::CommandCompleted,
                Some(self.return_value),
                "PENDING_RAW_SYSCALL_CORRELATION",
            ),
            _ => unreachable!("validated before conversion"),
        };
        EvidenceEvent {
            schema_version: self.schema_version,
            run_id: run_id.to_owned(),
            run_epoch: self.run_epoch,
            event_seq: self.event_seq,
            related_attempt_seq: self.related_attempt_seq,
            kind,
            ktime_ns: self.ktime_ns,
            cgroup_id: self.cgroup_id,
            pid: self.pid_tgid as u32,
            tgid: (self.pid_tgid >> 32) as u32,
            command: self.command,
            command_name: command_name(self.command).to_owned(),
            attr_size: self.attr_size,
            return_value,
            argument_provenance: argument_provenance.to_owned(),
            flags: u32::from(self.flags),
        }
    }

    pub fn is_unsupported(&self, allowed: &BTreeSet<u32>) -> bool {
        self.kind == EVENT_SYSCALL_ATTEMPTED
            && !allowed.is_empty()
            && !allowed.contains(&self.command)
    }
}

pub fn command_name(command: u32) -> &'static str {
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
        .unwrap_or("UNKNOWN_BPF_COMMAND")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> KernelEvent {
        KernelEvent {
            schema_version: SCHEMA_VERSION,
            kind: EVENT_COMMAND_COMPLETED,
            flags: 0,
            command: 28,
            attr_size: 144,
            run_epoch: 9,
            event_seq: 11,
            related_attempt_seq: 10,
            ktime_ns: 1234,
            cgroup_id: 55,
            pid_tgid: (77u64 << 32) | 78,
            return_value: -22,
        }
    }

    #[test]
    fn little_endian_round_trip_is_stable() {
        let event = fixture();
        assert_eq!(KernelEvent::decode_le(&event.encode_le()).unwrap(), event);
    }

    #[test]
    fn schema_conversion_preserves_pid_and_tgid() {
        let event = fixture().to_schema("run");
        assert_eq!(event.pid, 78);
        assert_eq!(event.tgid, 77);
        assert_eq!(event.command_name, "BPF_LINK_CREATE");
        assert_eq!(event.return_value, Some(-22));
    }

    #[test]
    fn missing_pair_requires_explicit_flag() {
        let mut event = fixture();
        event.related_attempt_seq = 0;
        assert!(KernelEvent::decode_le(&event.encode_le()).is_err());
        event.flags = FLAG_PENDING_MISSING;
        assert!(KernelEvent::decode_le(&event.encode_le()).is_ok());
    }

    #[test]
    fn attempted_event_requires_zero_raw_return_value() {
        let mut event = fixture();
        event.kind = EVENT_SYSCALL_ATTEMPTED;
        event.related_attempt_seq = 0;
        assert!(KernelEvent::decode_le(&event.encode_le()).is_err());
        event.return_value = 0;
        assert!(KernelEvent::decode_le(&event.encode_le()).is_ok());
    }
}
