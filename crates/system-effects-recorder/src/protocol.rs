// SPDX-License-Identifier: GPL-2.0-only

use crate::policy::{EffectDomain, EffectOperation, EventPolicyIdentity};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const EFFECT_EVENT_SCHEMA_VERSION: u32 = 1;
/// Version of the userspace attribution contract, including boot-scoped task
/// start time carried by the kernel/WAL ABI.
pub const EFFECT_ATTRIBUTION_PROTOCOL_VERSION: u32 = 2;
/// Version of the additive userspace object-identity protocol carried by a
/// decoded system-effect event.
pub const OBJECT_IDENTITY_PROTOCOL_VERSION: u32 = 1;
pub const KERNEL_EVENT_HEADER_SIZE: usize = 160;
pub const KERNEL_EVENT_SIZE: usize = 352;
pub const KERNEL_FILE_EVENT_SIZE: usize = 336;
pub const KERNEL_SOCKET_EVENT_SIZE: usize = 336;
pub const CAPTURE_BYTES: usize = 96;
pub const KERNEL_FILE_PATH_BYTES: usize = 128;
pub const MAX_OBJECT_REFERENCES: usize = 2;
pub const MAX_RESOLVED_PATH_BYTES: usize = 512;
pub const MAX_SOCKET_ENDPOINT_BYTES: usize = 128;

pub const EVENT_OPERATION_ATTEMPT: u16 = 1;
pub const EVENT_OPERATION_RESULT: u16 = 2;

pub const FLAG_PENDING_INSERT_FAILED: u32 = 1 << 0;
pub const FLAG_PENDING_MISSING: u32 = 1 << 1;
pub const FLAG_PENDING_POISONED: u32 = 1 << 2;
pub const FLAG_PENDING_DELETE_FAILED: u32 = 1 << 3;
pub const FLAG_PAYLOAD1_READ_FAILED: u32 = 1 << 4;
pub const FLAG_PAYLOAD1_TRUNCATED: u32 = 1 << 5;
pub const FLAG_PAYLOAD2_READ_FAILED: u32 = 1 << 6;
pub const FLAG_PAYLOAD2_TRUNCATED: u32 = 1 << 7;
pub const FLAG_POLICY_INVALID: u32 = 1 << 8;
pub const FLAG_USER_MEMORY_SNAPSHOT: u32 = 1 << 9;
pub const FLAG_SYSCALL_MISMATCH: u32 = 1 << 10;
pub const FLAG_PAYLOAD1_INVALID_LENGTH: u32 = 1 << 11;
pub const FLAG_PAYLOAD2_INVALID_LENGTH: u32 = 1 << 12;
pub const FLAG_OBJECT_JOIN_MISSING: u32 = 1 << 13;
pub const FLAG_OBJECT_JOIN_AMBIGUOUS: u32 = 1 << 14;
pub const FLAG_OBJECT_READ_FAILED: u32 = 1 << 15;
pub const FLAG_OBJECT_DELETE_FAILED: u32 = 1 << 16;
pub const FLAG_OBJECT_PATH_UNAVAILABLE: u32 = 1 << 17;
pub const FLAG_TASK_READ_FAILED: u32 = 1 << 18;
/// The selected resolver deliberately rejected an object outside its frozen
/// semantic contract. This is nonfatal but keeps an otherwise successful
/// syscall explicitly UNRESOLVED instead of claiming a generic identity.
pub const FLAG_OBJECT_UNSUPPORTED: u32 = 1 << 19;
const KNOWN_FLAGS: u32 = FLAG_PENDING_INSERT_FAILED
    | FLAG_PENDING_MISSING
    | FLAG_PENDING_POISONED
    | FLAG_PENDING_DELETE_FAILED
    | FLAG_PAYLOAD1_READ_FAILED
    | FLAG_PAYLOAD1_TRUNCATED
    | FLAG_PAYLOAD2_READ_FAILED
    | FLAG_PAYLOAD2_TRUNCATED
    | FLAG_POLICY_INVALID
    | FLAG_USER_MEMORY_SNAPSHOT
    | FLAG_SYSCALL_MISMATCH
    | FLAG_PAYLOAD1_INVALID_LENGTH
    | FLAG_PAYLOAD2_INVALID_LENGTH
    | FLAG_OBJECT_JOIN_MISSING
    | FLAG_OBJECT_JOIN_AMBIGUOUS
    | FLAG_OBJECT_READ_FAILED
    | FLAG_OBJECT_DELETE_FAILED
    | FLAG_OBJECT_PATH_UNAVAILABLE
    | FLAG_TASK_READ_FAILED
    | FLAG_OBJECT_UNSUPPORTED;
const CAPTURE_FLAGS: u32 = FLAG_PAYLOAD1_READ_FAILED
    | FLAG_PAYLOAD1_TRUNCATED
    | FLAG_PAYLOAD2_READ_FAILED
    | FLAG_PAYLOAD2_TRUNCATED
    | FLAG_PAYLOAD1_INVALID_LENGTH
    | FLAG_PAYLOAD2_INVALID_LENGTH;

pub const PAYLOAD_NONE: u8 = 0;
pub const PAYLOAD_USER_STRING: u8 = 1;
pub const PAYLOAD_SOCKADDR: u8 = 2;

pub const FILE_PATH_NOT_REQUESTED: u8 = 0;
pub const FILE_PATH_RESOLVED_AT_HOOK: u8 = 1;
pub const FILE_PATH_TRUNCATED_AT_HOOK: u8 = 2;
pub const FILE_PATH_UNAVAILABLE: u8 = 3;
pub const SOCKET_ENDPOINT_AUTHORITY_LSM_ARGUMENT: u8 = 1;
pub const SOCKET_ENDPOINT_AUTHORITY_KERNEL_STATE: u8 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelFileObject {
    pub mount_id_unique: u64,
    pub inode: u64,
    pub filesystem_magic: u64,
    pub device_major: u32,
    pub device_minor: u32,
    pub inode_generation: u32,
    pub path_len: u16,
    pub generation_valid: u8,
    pub path_quality: u8,
    pub path: [u8; KERNEL_FILE_PATH_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelSocketObject {
    pub network_namespace_cookie: u64,
    pub socket_cookie: u64,
    pub address_family: u32,
    pub socket_type: u32,
    pub protocol: u32,
    pub endpoint_address_family: u32,
    pub endpoint_len: u16,
    pub endpoint_role: u8,
    pub endpoint_quality: u8,
    pub endpoint: [u8; MAX_SOCKET_ENDPOINT_BYTES],
    pub endpoint_authority: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelEvent {
    pub schema_version: u32,
    pub kind: u16,
    pub domain: u16,
    pub operation: u32,
    pub flags: u32,
    pub syscall_nr: i32,
    pub run_epoch: u64,
    pub event_seq: u64,
    pub related_attempt_seq: u64,
    pub ktime_ns: u64,
    pub cgroup_id: u64,
    pub pid_tgid: u64,
    pub return_value: i64,
    pub args: [u64; 6],
    pub comm: [u8; 16],
    pub task_start_boottime_ns: u64,
    pub payload_lens: [u16; 2],
    pub payload_kinds: [u8; 2],
    pub payload_arg_indices: [u8; 2],
    pub payloads: [[u8; CAPTURE_BYTES]; 2],
    pub file_object: Option<KernelFileObject>,
    pub socket_object: Option<KernelSocketObject>,
}

impl KernelEvent {
    pub fn decode_native(bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes, Endian::Native, false)
    }

    pub fn decode_le(bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes, Endian::Little, true)
    }

    fn decode(bytes: &[u8], endian: Endian, require_canonical_tail: bool) -> Result<Self> {
        if !matches!(
            bytes.len(),
            KERNEL_EVENT_HEADER_SIZE | KERNEL_FILE_EVENT_SIZE | KERNEL_EVENT_SIZE
        ) {
            bail!(
                "system-effect event has {} bytes, expected {KERNEL_EVENT_HEADER_SIZE}, {KERNEL_FILE_EVENT_SIZE}, or {KERNEL_EVENT_SIZE}",
                bytes.len()
            );
        }
        if bytes[20..24] != [0; 4] {
            bail!("system-effect event has a nonzero reserved field");
        }
        let mut args = [0u64; 6];
        for (index, argument) in args.iter_mut().enumerate() {
            let start = 80 + index * 8;
            *argument = endian.u64(&bytes[start..start + 8]);
        }
        let mut comm = [0u8; 16];
        comm.copy_from_slice(&bytes[128..144]);
        let mut first = [0u8; CAPTURE_BYTES];
        let mut second = [0u8; CAPTURE_BYTES];
        if bytes.len() == KERNEL_EVENT_SIZE {
            first.copy_from_slice(&bytes[160..256]);
            second.copy_from_slice(&bytes[256..352]);
        }
        let domain = endian.u16(&bytes[6..8]);
        let operation = endian.u32(&bytes[8..12]);
        let is_socket_frame = bytes.len() == KERNEL_SOCKET_EVENT_SIZE
            && domain == EffectDomain::Network as u16
            && matches!(
                EffectOperation::from_raw(operation),
                Some(
                    EffectOperation::SocketConnect
                        | EffectOperation::SocketBind
                        | EffectOperation::SocketAccept
                )
            );
        let file_object = if bytes.len() == KERNEL_FILE_EVENT_SIZE && !is_socket_frame {
            if bytes[200..204] != [0; 4] || bytes[332..336] != [0; 4] {
                bail!("kernel file-object event has a nonzero reserved field");
            }
            let path_len = endian.u16(&bytes[196..198]);
            let retained = usize::from(path_len).min(KERNEL_FILE_PATH_BYTES);
            if require_canonical_tail && bytes[204 + retained..332].iter().any(|byte| *byte != 0) {
                bail!("kernel file-object WAL path has a nonzero unused tail");
            }
            // bpf_d_path is allowed to leave helper scratch bytes beyond its
            // returned length. Normalize those bytes before they enter the WAL.
            let mut path = [0u8; KERNEL_FILE_PATH_BYTES];
            path[..retained].copy_from_slice(&bytes[204..204 + retained]);
            Some(KernelFileObject {
                mount_id_unique: endian.u64(&bytes[160..168]),
                inode: endian.u64(&bytes[168..176]),
                filesystem_magic: endian.u64(&bytes[176..184]),
                device_major: endian.u32(&bytes[184..188]),
                device_minor: endian.u32(&bytes[188..192]),
                inode_generation: endian.u32(&bytes[192..196]),
                path_len,
                generation_valid: bytes[198],
                path_quality: bytes[199],
                path,
            })
        } else {
            None
        };
        let socket_object = if is_socket_frame {
            if bytes[325..336].iter().any(|byte| *byte != 0) {
                bail!("kernel socket-object event has a nonzero reserved field");
            }
            let endpoint_len = endian.u16(&bytes[192..194]);
            let retained = usize::from(endpoint_len).min(MAX_SOCKET_ENDPOINT_BYTES);
            if require_canonical_tail && bytes[196 + retained..324].iter().any(|byte| *byte != 0) {
                bail!("kernel socket-object WAL endpoint has a nonzero unused tail");
            }
            let mut endpoint = [0u8; MAX_SOCKET_ENDPOINT_BYTES];
            endpoint[..retained].copy_from_slice(&bytes[196..196 + retained]);
            Some(KernelSocketObject {
                network_namespace_cookie: endian.u64(&bytes[160..168]),
                socket_cookie: endian.u64(&bytes[168..176]),
                address_family: endian.u32(&bytes[176..180]),
                socket_type: endian.u32(&bytes[180..184]),
                protocol: endian.u32(&bytes[184..188]),
                endpoint_address_family: endian.u32(&bytes[188..192]),
                endpoint_len,
                endpoint_role: bytes[194],
                endpoint_quality: bytes[195],
                endpoint,
                endpoint_authority: bytes[324],
            })
        } else {
            None
        };
        let event = Self {
            schema_version: endian.u32(&bytes[0..4]),
            kind: endian.u16(&bytes[4..6]),
            domain: endian.u16(&bytes[6..8]),
            operation: endian.u32(&bytes[8..12]),
            flags: endian.u32(&bytes[12..16]),
            syscall_nr: endian.i32(&bytes[16..20]),
            run_epoch: endian.u64(&bytes[24..32]),
            event_seq: endian.u64(&bytes[32..40]),
            related_attempt_seq: endian.u64(&bytes[40..48]),
            ktime_ns: endian.u64(&bytes[48..56]),
            cgroup_id: endian.u64(&bytes[56..64]),
            pid_tgid: endian.u64(&bytes[64..72]),
            return_value: endian.i64(&bytes[72..80]),
            args,
            comm,
            task_start_boottime_ns: endian.u64(&bytes[152..160]),
            payload_lens: [endian.u16(&bytes[144..146]), endian.u16(&bytes[146..148])],
            payload_kinds: [bytes[148], bytes[149]],
            payload_arg_indices: [bytes[150], bytes[151]],
            payloads: [first, second],
            file_object,
            socket_object,
        };
        event.validate()?;
        if bytes.len() == KERNEL_EVENT_HEADER_SIZE {
            if event.payload_lens != [0, 0] || event.payload_kinds != [PAYLOAD_NONE; 2] {
                bail!("compact system-effect event claims an absent payload");
            }
        } else if bytes.len() == KERNEL_EVENT_SIZE && event.payload_kinds == [PAYLOAD_NONE; 2] {
            bail!("expanded system-effect event has no payload capture");
        }
        Ok(event)
    }

    pub fn encode_le(&self) -> Vec<u8> {
        let size = if self.file_object.is_some() || self.socket_object.is_some() {
            KERNEL_FILE_EVENT_SIZE
        } else if self.payload_kinds == [PAYLOAD_NONE; 2] {
            KERNEL_EVENT_HEADER_SIZE
        } else {
            KERNEL_EVENT_SIZE
        };
        let mut bytes = vec![0u8; size];
        bytes[0..4].copy_from_slice(&self.schema_version.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.kind.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.domain.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.operation.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.flags.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.syscall_nr.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.run_epoch.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.event_seq.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.related_attempt_seq.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.ktime_ns.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.cgroup_id.to_le_bytes());
        bytes[64..72].copy_from_slice(&self.pid_tgid.to_le_bytes());
        bytes[72..80].copy_from_slice(&self.return_value.to_le_bytes());
        for (index, argument) in self.args.iter().enumerate() {
            let start = 80 + index * 8;
            bytes[start..start + 8].copy_from_slice(&argument.to_le_bytes());
        }
        bytes[128..144].copy_from_slice(&self.comm);
        bytes[144..146].copy_from_slice(&self.payload_lens[0].to_le_bytes());
        bytes[146..148].copy_from_slice(&self.payload_lens[1].to_le_bytes());
        bytes[148..150].copy_from_slice(&self.payload_kinds);
        bytes[150..152].copy_from_slice(&self.payload_arg_indices);
        bytes[152..160].copy_from_slice(&self.task_start_boottime_ns.to_le_bytes());
        if size == KERNEL_EVENT_SIZE {
            bytes[160..256].copy_from_slice(&self.payloads[0]);
            bytes[256..352].copy_from_slice(&self.payloads[1]);
        } else if let Some(object) = &self.file_object {
            bytes[160..168].copy_from_slice(&object.mount_id_unique.to_le_bytes());
            bytes[168..176].copy_from_slice(&object.inode.to_le_bytes());
            bytes[176..184].copy_from_slice(&object.filesystem_magic.to_le_bytes());
            bytes[184..188].copy_from_slice(&object.device_major.to_le_bytes());
            bytes[188..192].copy_from_slice(&object.device_minor.to_le_bytes());
            bytes[192..196].copy_from_slice(&object.inode_generation.to_le_bytes());
            bytes[196..198].copy_from_slice(&object.path_len.to_le_bytes());
            bytes[198] = object.generation_valid;
            bytes[199] = object.path_quality;
            bytes[204..332].copy_from_slice(&object.path);
        } else if let Some(object) = &self.socket_object {
            bytes[160..168].copy_from_slice(&object.network_namespace_cookie.to_le_bytes());
            bytes[168..176].copy_from_slice(&object.socket_cookie.to_le_bytes());
            bytes[176..180].copy_from_slice(&object.address_family.to_le_bytes());
            bytes[180..184].copy_from_slice(&object.socket_type.to_le_bytes());
            bytes[184..188].copy_from_slice(&object.protocol.to_le_bytes());
            bytes[188..192].copy_from_slice(&object.endpoint_address_family.to_le_bytes());
            bytes[192..194].copy_from_slice(&object.endpoint_len.to_le_bytes());
            bytes[194] = object.endpoint_role;
            bytes[195] = object.endpoint_quality;
            bytes[196..324].copy_from_slice(&object.endpoint);
            bytes[324] = object.endpoint_authority;
        }
        bytes
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != EFFECT_EVENT_SCHEMA_VERSION {
            bail!(
                "system-effect event schema {} != userspace schema {}",
                self.schema_version,
                EFFECT_EVENT_SCHEMA_VERSION
            );
        }
        if !matches!(self.kind, EVENT_OPERATION_ATTEMPT | EVENT_OPERATION_RESULT) {
            bail!("unknown system-effect event kind {}", self.kind);
        }
        if EffectDomain::from_raw(self.domain).is_none() {
            bail!("unknown system-effect domain {}", self.domain);
        }
        if EffectOperation::from_raw(self.operation).is_none() {
            bail!("unknown system-effect operation {}", self.operation);
        }
        if self.flags & !KNOWN_FLAGS != 0 {
            bail!("system-effect event has unknown flags {:#x}", self.flags);
        }
        if self.syscall_nr < 0 || self.syscall_nr as u32 >= crate::policy::POLICY_MAP_ENTRIES {
            bail!(
                "system-effect event has invalid syscall number {}",
                self.syscall_nr
            );
        }
        if self.run_epoch == 0 || self.event_seq == 0 || self.cgroup_id == 0 || self.pid_tgid == 0 {
            bail!("system-effect event has a zero identity field");
        }
        if (self.flags & FLAG_TASK_READ_FAILED == 0) != (self.task_start_boottime_ns != 0) {
            bail!("system-effect task start identity and read-failure flag disagree");
        }
        if self.kind == EVENT_OPERATION_ATTEMPT {
            if self.related_attempt_seq != 0 || self.return_value != 0 {
                bail!("operation attempt has result-only fields");
            }
            if self.flags
                & (FLAG_PENDING_MISSING
                    | FLAG_PENDING_POISONED
                    | FLAG_PENDING_DELETE_FAILED
                    | FLAG_SYSCALL_MISMATCH
                    | FLAG_OBJECT_JOIN_MISSING
                    | FLAG_OBJECT_JOIN_AMBIGUOUS
                    | FLAG_OBJECT_READ_FAILED
                    | FLAG_OBJECT_DELETE_FAILED
                    | FLAG_OBJECT_PATH_UNAVAILABLE
                    | FLAG_OBJECT_UNSUPPORTED)
                != 0
            {
                bail!("operation attempt has result-only correlation flags");
            }
        } else {
            if self.related_attempt_seq == 0 && self.flags & FLAG_PENDING_MISSING == 0 {
                bail!("operation result has no related attempt");
            }
            if self.payload_lens != [0, 0]
                || self.payload_kinds != [PAYLOAD_NONE; 2]
                || self.payload_arg_indices != [0, 0]
            {
                bail!("operation result unexpectedly repeats entry payload metadata");
            }
            if self.flags
                & (CAPTURE_FLAGS
                    | FLAG_USER_MEMORY_SNAPSHOT
                    | FLAG_POLICY_INVALID
                    | FLAG_PENDING_INSERT_FAILED)
                != 0
            {
                bail!("operation result has entry-only flags");
            }
        }
        if self.file_object.is_some() && self.socket_object.is_some() {
            bail!("system-effect result contains two incompatible object frame types");
        }
        const OBJECT_FLAGS: u32 = FLAG_OBJECT_JOIN_MISSING
            | FLAG_OBJECT_JOIN_AMBIGUOUS
            | FLAG_OBJECT_READ_FAILED
            | FLAG_OBJECT_DELETE_FAILED
            | FLAG_OBJECT_PATH_UNAVAILABLE
            | FLAG_OBJECT_UNSUPPORTED;
        let is_file_open_result = self.kind == EVENT_OPERATION_RESULT
            && self.domain == EffectDomain::Filesystem as u16
            && matches!(
                EffectOperation::from_raw(self.operation),
                Some(EffectOperation::FileCreateOrTruncate | EffectOperation::FileOpenRequest)
            );
        let is_file_io_result = self.kind == EVENT_OPERATION_RESULT
            && self.domain == EffectDomain::Io as u16
            && matches!(
                EffectOperation::from_raw(self.operation),
                Some(EffectOperation::FdWrite | EffectOperation::FdRead)
            );
        if is_file_io_result
            && self.operation == EffectOperation::FdRead as u32
            && matches!(
                self.syscall_nr as libc::c_long,
                libc::SYS_read | libc::SYS_pread64
            )
            && self.return_value >= 0
            && self.return_value as u64 > self.args[2]
        {
            bail!("scalar read result exceeds the requested byte count");
        }
        let operation = EffectOperation::from_raw(self.operation).expect("validated operation");
        let is_extended_file_result = self.kind == EVENT_OPERATION_RESULT
            && matches!(
                operation,
                EffectOperation::DirectoryCreate
                    | EffectOperation::SymlinkCreate
                    | EffectOperation::DeviceNodeCreate
                    | EffectOperation::HardLinkCreate
                    | EffectOperation::FileUnlink
                    | EffectOperation::DirectoryRemove
                    | EffectOperation::PathEntryRemove
                    | EffectOperation::FileRename
                    | EffectOperation::PermissionsChange
                    | EffectOperation::OwnershipChange
                    | EffectOperation::ExtendedAttributeSet
                    | EffectOperation::ExtendedAttributeRemove
                    | EffectOperation::MemoryWriteChannel
            );
        let is_socket_result = self.kind == EVENT_OPERATION_RESULT
            && matches!(
                operation,
                EffectOperation::SocketConnect
                    | EffectOperation::SocketBind
                    | EffectOperation::SocketAccept
            );
        if self.flags & OBJECT_FLAGS != 0
            && !(is_file_open_result
                || is_file_io_result
                || is_extended_file_result
                || is_socket_result)
        {
            bail!("kernel object flags are present on an unsupported operation result");
        }
        if is_file_io_result && self.flags & FLAG_OBJECT_PATH_UNAVAILABLE != 0 {
            bail!(
                "file_permission read/write result unexpectedly reports path resolution activity"
            );
        }
        if is_file_open_result
            && self.return_value >= 0
            && self.file_object.is_none()
            && self.flags & FLAG_OBJECT_PATH_UNAVAILABLE != 0
            && self.flags
                & (FLAG_PENDING_MISSING
                    | FLAG_PENDING_POISONED
                    | FLAG_SYSCALL_MISMATCH
                    | FLAG_OBJECT_JOIN_AMBIGUOUS
                    | FLAG_OBJECT_READ_FAILED
                    | FLAG_OBJECT_DELETE_FAILED)
                == 0
        {
            bail!(
                "successful file-open result without FILE_OBJECT evidence cannot report path resolution activity"
            );
        }
        if let Some(object) = &self.file_object {
            if !((is_file_open_result && self.return_value >= 0)
                || (is_file_io_result && self.return_value > 0)
                || (is_extended_file_result && self.return_value >= 0))
                || self.flags
                    & (FLAG_PENDING_MISSING
                        | FLAG_PENDING_POISONED
                        | FLAG_SYSCALL_MISMATCH
                        | FLAG_OBJECT_JOIN_MISSING
                        | FLAG_OBJECT_JOIN_AMBIGUOUS
                        | FLAG_OBJECT_READ_FAILED
                        | FLAG_OBJECT_DELETE_FAILED)
                    != 0
            {
                bail!("kernel file-object evidence is not an eligible successful open or positive-byte read/write result");
            }
            object.validate(operation)?;
            if is_file_io_result && object.path_quality != FILE_PATH_NOT_REQUESTED {
                bail!(
                    "file_permission read/write object unexpectedly claims a kernel path snapshot"
                );
            }
            if is_file_open_result
                && !matches!(
                    object.path_quality,
                    FILE_PATH_RESOLVED_AT_HOOK | FILE_PATH_UNAVAILABLE
                )
            {
                bail!("file_post_open object has a path quality not produced by the current hook");
            }
            if is_extended_file_result && object.path_quality != FILE_PATH_NOT_REQUESTED {
                bail!("extended file-object hook unexpectedly claims a path snapshot");
            }
            if (object.path_quality == FILE_PATH_UNAVAILABLE)
                != (self.flags & FLAG_OBJECT_PATH_UNAVAILABLE != 0)
            {
                bail!("kernel file-object path quality and event flag disagree");
            }
        }
        if let Some(object) = &self.socket_object {
            if !is_socket_result
                || self.flags
                    & (FLAG_PENDING_MISSING
                        | FLAG_PENDING_POISONED
                        | FLAG_SYSCALL_MISMATCH
                        | FLAG_OBJECT_JOIN_MISSING
                        | FLAG_OBJECT_JOIN_AMBIGUOUS
                        | FLAG_OBJECT_READ_FAILED
                        | FLAG_OBJECT_DELETE_FAILED)
                    != 0
            {
                bail!("kernel socket-object evidence is not an eligible socket result");
            }
            object.validate(operation)?;
        }
        if self.flags & FLAG_OBJECT_UNSUPPORTED != 0 {
            if !((is_socket_result && self.return_value >= 0)
                || operation == EffectOperation::MemoryWriteChannel)
                || self.socket_object.is_some()
                || self.file_object.is_some()
            {
                bail!("explicit unsupported-object flag is not an unresolved socket or memory-write-channel result");
            }
            if self.flags
                & (FLAG_OBJECT_JOIN_MISSING
                    | FLAG_OBJECT_JOIN_AMBIGUOUS
                    | FLAG_OBJECT_READ_FAILED
                    | FLAG_OBJECT_DELETE_FAILED)
                != 0
            {
                bail!("unsupported-object flag is mixed with a resolver failure flag");
            }
        }
        let has_capture = self.payload_kinds != [PAYLOAD_NONE; 2];
        if self.kind == EVENT_OPERATION_ATTEMPT
            && has_capture != (self.flags & FLAG_USER_MEMORY_SNAPSHOT != 0)
        {
            bail!("operation attempt capture metadata and snapshot flag disagree");
        }
        for slot in 0..2 {
            if usize::from(self.payload_lens[slot]) > CAPTURE_BYTES {
                bail!("payload {slot} length exceeds fixed capture storage");
            }
            if !matches!(
                self.payload_kinds[slot],
                PAYLOAD_NONE | PAYLOAD_USER_STRING | PAYLOAD_SOCKADDR
            ) {
                bail!(
                    "payload {slot} has unknown kind {}",
                    self.payload_kinds[slot]
                );
            }
            if self.payload_kinds[slot] == PAYLOAD_NONE && self.payload_lens[slot] != 0 {
                bail!("payload {slot} has bytes without a capture kind");
            }
            if self.payload_kinds[slot] == PAYLOAD_NONE && self.payload_arg_indices[slot] != 0 {
                bail!("payload {slot} has an argument index without a capture kind");
            }
            if self.payload_arg_indices[slot] > 5 {
                bail!("payload {slot} has invalid syscall argument index");
            }
            let (read_failed, truncated, invalid_length) = if slot == 0 {
                (
                    self.flags & FLAG_PAYLOAD1_READ_FAILED != 0,
                    self.flags & FLAG_PAYLOAD1_TRUNCATED != 0,
                    self.flags & FLAG_PAYLOAD1_INVALID_LENGTH != 0,
                )
            } else {
                (
                    self.flags & FLAG_PAYLOAD2_READ_FAILED != 0,
                    self.flags & FLAG_PAYLOAD2_TRUNCATED != 0,
                    self.flags & FLAG_PAYLOAD2_INVALID_LENGTH != 0,
                )
            };
            if self.payload_kinds[slot] == PAYLOAD_NONE
                && (read_failed || truncated || invalid_length)
            {
                bail!("payload {slot} has capture flags without a capture kind");
            }
            if invalid_length && self.payload_kinds[slot] != PAYLOAD_SOCKADDR {
                bail!("payload {slot} has an invalid-length flag for a non-sockaddr capture");
            }
            if (read_failed || invalid_length) && self.payload_lens[slot] != 0 {
                bail!("payload {slot} has bytes despite a failed capture");
            }
            if self.payload_kinds[slot] != PAYLOAD_NONE
                && !read_failed
                && !invalid_length
                && self.payload_lens[slot] == 0
            {
                bail!("payload {slot} has a successful capture with zero bytes");
            }
        }
        Ok(())
    }

    pub(crate) fn to_schema(
        &self,
        run_id: &str,
        boot_id: &str,
        policy: EventPolicyIdentity,
    ) -> Result<SystemEffectEvent> {
        self.to_schema_with_cgroup_match(run_id, boot_id, policy, CgroupMatchMode::ExactCurrent)
    }

    pub(crate) fn to_schema_with_cgroup_match(
        &self,
        run_id: &str,
        boot_id: &str,
        policy: EventPolicyIdentity,
        cgroup_match_mode: CgroupMatchMode,
    ) -> Result<SystemEffectEvent> {
        if self.domain != policy.domain as u16 || self.operation != policy.operation as u32 {
            bail!(
                "event syscall {} identity {}/{} disagrees with frozen policy {}/{}",
                self.syscall_nr,
                self.domain,
                self.operation,
                policy.domain as u16,
                policy.operation as u32
            );
        }
        if self.kind == EVENT_OPERATION_ATTEMPT {
            for slot in 0..2 {
                if self.payload_kinds[slot] != policy.capture[slot].kind
                    || self.payload_arg_indices[slot] != policy.capture[slot].arg_index
                {
                    bail!(
                        "event syscall {} payload slot {} disagrees with frozen policy",
                        self.syscall_nr,
                        slot
                    );
                }
            }
        }
        let event_kind = if self.kind == EVENT_OPERATION_ATTEMPT {
            EventKind::OperationAttempt
        } else {
            EventKind::OperationResult
        };
        let return_value = (self.kind == EVENT_OPERATION_RESULT).then_some(self.return_value);
        let result_status = return_value.map(|value| classify_result(policy.operation, value));
        let captures = if self.kind == EVENT_OPERATION_ATTEMPT {
            (0..2)
                .filter_map(|slot| self.capture(slot))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let object_resolution = ObjectResolution::from_kernel_event(self, &captures, boot_id);
        let attribution = EffectAttribution::from_kernel_event(self, cgroup_match_mode);
        let process_identity = EffectProcessIdentity::from_kernel_event(self, boot_id);
        let event = SystemEffectEvent {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            run_id: run_id.to_owned(),
            run_epoch: self.run_epoch,
            event_seq: self.event_seq,
            related_attempt_seq: self.related_attempt_seq,
            kind: event_kind,
            domain: EffectDomain::from_raw(self.domain).expect("validated domain"),
            operation: EffectOperation::from_raw(self.operation).expect("validated operation"),
            syscall_nr: self.syscall_nr,
            syscall_name: policy.syscall_name.to_owned(),
            ktime_ns: self.ktime_ns,
            cgroup_id: self.cgroup_id,
            pid: self.pid_tgid as u32,
            tgid: (self.pid_tgid >> 32) as u32,
            comm: nul_terminated_lossy(&self.comm),
            process_identity,
            raw_arguments: self.args,
            captures,
            object_resolution,
            attribution,
            return_value,
            result_status,
            flags: self.flags,
            semantics: "OBSERVED_OPERATION_NOT_PROOF_OF_DURABLE_STATE_CHANGE".to_owned(),
        };
        event.validate_object_resolution()?;
        event.validate_attribution()?;
        event.validate_process_identity()?;
        Ok(event)
    }

    fn capture(&self, slot: usize) -> Option<CapturedArgument> {
        let kind = self.payload_kinds[slot];
        if kind == PAYLOAD_NONE {
            return None;
        }
        let failed_flag = if slot == 0 {
            FLAG_PAYLOAD1_READ_FAILED
        } else {
            FLAG_PAYLOAD2_READ_FAILED
        };
        let truncated_flag = if slot == 0 {
            FLAG_PAYLOAD1_TRUNCATED
        } else {
            FLAG_PAYLOAD2_TRUNCATED
        };
        let invalid_length_flag = if slot == 0 {
            FLAG_PAYLOAD1_INVALID_LENGTH
        } else {
            FLAG_PAYLOAD2_INVALID_LENGTH
        };
        let read_failed = self.flags & failed_flag != 0;
        let truncated = self.flags & truncated_flag != 0;
        let invalid_length = self.flags & invalid_length_flag != 0;
        let capture_available = !read_failed && !invalid_length;
        let length = usize::from(self.payload_lens[slot]).min(CAPTURE_BYTES);
        let bytes = &self.payloads[slot][..length];
        let (source, display) = match kind {
            PAYLOAD_USER_STRING => (
                CaptureSource::UserSuppliedString,
                capture_available.then(|| nul_terminated_lossy(bytes)),
            ),
            PAYLOAD_SOCKADDR => (
                CaptureSource::RawUserSockaddr,
                capture_available.then(|| format_sockaddr(bytes)),
            ),
            _ => unreachable!("validated payload kind"),
        };
        Some(CapturedArgument {
            argument_index: self.payload_arg_indices[slot],
            source,
            status: if read_failed {
                CaptureStatus::ReadFailed
            } else if invalid_length {
                CaptureStatus::InvalidLength
            } else if truncated {
                CaptureStatus::Truncated
            } else {
                CaptureStatus::Captured
            },
            length: length as u16,
            display,
            raw_hex: capture_available.then(|| hex(bytes)),
            authority: "USER_MEMORY_AT_SYSCALL_ENTRY_NOT_KERNEL_RESOLVED_OBJECT".to_owned(),
        })
    }
}

impl KernelFileObject {
    fn validate(&self, operation: EffectOperation) -> Result<()> {
        let inode_only = matches!(
            operation,
            EffectOperation::ExtendedAttributeSet | EffectOperation::ExtendedAttributeRemove
        );
        if (!inode_only && self.mount_id_unique == 0)
            || (inode_only && self.mount_id_unique != 0)
            || self.inode == 0
            || self.filesystem_magic == 0
        {
            bail!("kernel file-object identity has a zero stable field");
        }
        if self.device_major >= 1 << 12 || self.device_minor >= 1 << 20 {
            bail!("kernel file-object device number exceeds Linux dev_t encoding");
        }
        if self.generation_valid > 1 || (self.generation_valid == 0 && self.inode_generation != 0) {
            bail!("kernel file-object generation validity is not canonical");
        }
        let path_len = usize::from(self.path_len);
        if path_len > KERNEL_FILE_PATH_BYTES {
            bail!("kernel file-object path exceeds fixed storage");
        }
        match self.path_quality {
            FILE_PATH_NOT_REQUESTED | FILE_PATH_UNAVAILABLE if path_len == 0 => {}
            FILE_PATH_RESOLVED_AT_HOOK if path_len != 0 && path_len < KERNEL_FILE_PATH_BYTES => {}
            _ => bail!("kernel file-object path quality and length disagree"),
        }
        if self.path[..path_len].contains(&0) {
            bail!("kernel file-object path contains an embedded NUL byte");
        }
        if self.path[path_len..].iter().any(|byte| *byte != 0) {
            bail!("kernel file-object path has a nonzero unused tail");
        }
        Ok(())
    }
}

impl KernelSocketObject {
    fn validate(&self, operation: EffectOperation) -> Result<()> {
        if self.network_namespace_cookie == 0
            || self.socket_cookie == 0
            || self.address_family == 0
            || self.socket_type == 0
            || !matches!(self.endpoint_role, 1 | 2)
            || !matches!(self.endpoint_quality, 1 | 2)
            || !matches!(
                self.endpoint_authority,
                SOCKET_ENDPOINT_AUTHORITY_LSM_ARGUMENT | SOCKET_ENDPOINT_AUTHORITY_KERNEL_STATE
            )
        {
            bail!("kernel socket-object identity has an invalid stable field");
        }
        let length = usize::from(self.endpoint_len);
        if !(2..=MAX_SOCKET_ENDPOINT_BYTES).contains(&length) {
            bail!("kernel socket endpoint has an invalid bounded length");
        }
        if self.endpoint_quality == 2 && length != MAX_SOCKET_ENDPOINT_BYTES {
            bail!("kernel socket endpoint truncation status is not canonical");
        }
        if self.endpoint[length..].iter().any(|byte| *byte != 0) {
            bail!("kernel socket endpoint has a nonzero unused tail");
        }
        let copied_family = u16::from_ne_bytes(
            self.endpoint[..2]
                .try_into()
                .expect("validated socket endpoint family bytes"),
        );
        if u32::from(copied_family) != self.endpoint_address_family {
            bail!("kernel socket endpoint family disagrees with copied sockaddr bytes");
        }
        match operation {
            EffectOperation::SocketConnect | EffectOperation::SocketBind
                if self.endpoint_authority == SOCKET_ENDPOINT_AUTHORITY_LSM_ARGUMENT => {}
            EffectOperation::SocketAccept
                if self.endpoint_authority == SOCKET_ENDPOINT_AUTHORITY_KERNEL_STATE
                    && self.endpoint_role == 2
                    && self.endpoint_address_family == self.address_family => {}
            _ => bail!("kernel socket endpoint authority overstates its producing hook"),
        }
        Ok(())
    }
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

    fn i64(self, bytes: &[u8]) -> i64 {
        match self {
            Self::Native => i64::from_ne_bytes(bytes.try_into().unwrap()),
            Self::Little => i64::from_le_bytes(bytes.try_into().unwrap()),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventKind {
    OperationAttempt,
    OperationResult,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResultStatus {
    ReturnedSuccess,
    ReturnedError,
    AsyncPending,
    KernelRestart,
}

fn classify_result(operation: EffectOperation, value: i64) -> ResultStatus {
    if value >= 0 {
        ResultStatus::ReturnedSuccess
    } else if matches!(value, -512 | -513 | -514 | -516) {
        ResultStatus::KernelRestart
    } else if operation == EffectOperation::SocketConnect
        && matches!(value, x if x == -(libc::EINPROGRESS as i64) || x == -(libc::EALREADY as i64))
    {
        ResultStatus::AsyncPending
    } else {
        ResultStatus::ReturnedError
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CaptureSource {
    UserSuppliedString,
    RawUserSockaddr,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CaptureStatus {
    Captured,
    Truncated,
    ReadFailed,
    InvalidLength,
}

/// Strength of the object claim attached to an operation event.
///
/// `USER_INPUT_ONLY` is intentionally not a kernel object identity.  It only
/// says that the recorder retained bytes supplied by userspace at syscall
/// entry. `KERNEL_RESOLVED` is emitted only for result-side evidence produced
/// by an explicitly enabled and attested kernel object hook.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObjectResolutionQuality {
    Unresolved,
    UserInputOnly,
    KernelResolved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObjectResolutionAuthority {
    None,
    SyscallEntryUserMemory,
    KernelObjectHook,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObjectRole {
    SyscallArgument,
    Primary,
    Source,
    Destination,
    Parent,
    Peer,
}

/// Filesystem classification derived from the resolved object's superblock.
/// It must never be inferred from an untrusted pathname prefix.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FilesystemClass {
    Procfs,
    Sysfs,
    CgroupV1,
    CgroupV2,
    Other,
}

/// Quality of a point-in-time kernel path rendering.  Path text is mutable
/// descriptive evidence; the mount/device/inode tuple remains the identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PathResolutionQuality {
    NotRequested,
    ResolvedAtHook,
    TruncatedAtHook,
    Unavailable,
    UnstableAtHook,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PathResolutionAuthority {
    None,
    KernelPathSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedPath {
    /// Lossy UTF-8 rendering derived from `raw_hex`, for display only.
    pub display: String,
    /// Canonical lowercase hex of at most `MAX_RESOLVED_PATH_BYTES` bytes.
    pub raw_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilePathObservation {
    pub quality: PathResolutionQuality,
    pub authority: PathResolutionAuthority,
    pub resolved_path: Option<ResolvedPath>,
}

impl Default for FilePathObservation {
    fn default() -> Self {
        Self {
            quality: PathResolutionQuality::NotRequested,
            authority: PathResolutionAuthority::None,
            resolved_path: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SocketEndpointQuality {
    NotRequested,
    KernelResolved,
    KernelResolvedTruncated,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SocketEndpointAuthority {
    None,
    KernelSocketState,
    KernelCopiedSockaddrAtLsmHook,
}

/// Bounded sockaddr bytes copied from the BPF LSM hook argument before the
/// operation. This is requested endpoint evidence, not post-bind/post-connect
/// state; bind port zero therefore remains zero here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum SocketEndpointAddress {
    Inet4 {
        /// Network-order address octets; `port` is represented in host order.
        address: [u8; 4],
        port: u16,
    },
    Inet6 {
        /// Network-order address octets; scalar fields are in host order.
        address: [u8; 16],
        port: u16,
        flowinfo: u32,
        scope_id: u32,
    },
    Unix {
        /// Exact name bytes excluding `sa_family`, in canonical lowercase hex.
        name_hex: String,
        abstract_namespace: bool,
        unnamed: bool,
    },
    Other {
        address_family: u32,
        /// Exact bounded kernel endpoint bytes in canonical lowercase hex.
        raw_hex: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SocketEndpointObservation {
    pub quality: SocketEndpointQuality,
    pub authority: SocketEndpointAuthority,
    pub address: Option<SocketEndpointAddress>,
}

impl Default for SocketEndpointObservation {
    fn default() -> Self {
        Self {
            quality: SocketEndpointQuality::NotRequested,
            authority: SocketEndpointAuthority::None,
            address: None,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SocketEndpointPair {
    pub local: SocketEndpointObservation,
    pub peer: SocketEndpointObservation,
}

/// A closed set of object identities understood by this protocol.
///
/// The variants are produced by the corresponding opt-in file, path, inode,
/// mmap and socket BPF LSM hooks and reconstructed from the binary WAL.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ObjectIdentity {
    UserInputOnly {
        argument_index: u8,
        source: CaptureSource,
        status: CaptureStatus,
    },
    FileObject {
        boot_id: String,
        mount_id_unique: u64,
        device_major: u32,
        device_minor: u32,
        inode: u64,
        inode_generation: Option<u32>,
        filesystem_magic: u64,
        filesystem_class: FilesystemClass,
        /// Optional point-in-time path evidence, deliberately separated from
        /// the event-time kernel-derived tuple above. Optional generation
        /// means the tuple does not rule out later inode reuse.
        path: FilePathObservation,
    },
    /// Actual inode passed to an inode LSM hook when that hook has no mount.
    /// This is deliberately weaker than FILE_OBJECT and cannot distinguish
    /// bind mounts of the same device/inode.
    InodeObject {
        boot_id: String,
        device_major: u32,
        device_minor: u32,
        inode: u64,
        inode_generation: Option<u32>,
        filesystem_magic: u64,
        filesystem_class: FilesystemClass,
        identity_scope: String,
    },
    SocketObject {
        boot_id: String,
        network_namespace_cookie: u64,
        socket_cookie: u64,
        address_family: u32,
        socket_type: u32,
        protocol: u32,
        endpoint_address_family: u32,
        /// Pre-operation local/peer request copied from the kernel LSM
        /// argument. A user-memory capture is never accepted as this evidence.
        endpoints: SocketEndpointPair,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectReference {
    /// Stable slot within this event.  It is bounded by
    /// `MAX_OBJECT_REFERENCES` and must be strictly increasing.
    pub slot: u8,
    pub role: ObjectRole,
    pub identity: ObjectIdentity,
}

/// Event-local object evidence and its explicit join to the syscall attempt.
///
/// `source_event_seq` identifies the event that supplied this evidence;
/// `operation_attempt_seq` is the causal key shared by its attempt and result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectResolution {
    pub protocol_version: u32,
    pub source_event_seq: u64,
    pub operation_attempt_seq: u64,
    pub quality: ObjectResolutionQuality,
    pub authority: ObjectResolutionAuthority,
    pub objects: Vec<ObjectReference>,
}

impl Default for ObjectResolution {
    /// Deserialization sentinel for pre-v1.1 JSONL.  It permits tooling to
    /// identify legacy records, but strict validation always rejects protocol
    /// version zero rather than silently upgrading an absent claim.
    fn default() -> Self {
        Self {
            protocol_version: 0,
            source_event_seq: 0,
            operation_attempt_seq: 0,
            quality: ObjectResolutionQuality::Unresolved,
            authority: ObjectResolutionAuthority::None,
            objects: Vec::new(),
        }
    }
}

impl ObjectResolution {
    pub fn from_kernel_event(
        event: &KernelEvent,
        captures: &[CapturedArgument],
        boot_id: &str,
    ) -> Self {
        let objects = if let Some(object) = &event.file_object {
            let path_len = usize::from(object.path_len);
            let path = match object.path_quality {
                FILE_PATH_NOT_REQUESTED => FilePathObservation::default(),
                FILE_PATH_UNAVAILABLE => FilePathObservation {
                    quality: PathResolutionQuality::Unavailable,
                    authority: PathResolutionAuthority::None,
                    resolved_path: None,
                },
                FILE_PATH_RESOLVED_AT_HOOK => {
                    let bytes = &object.path[..path_len];
                    FilePathObservation {
                        quality: PathResolutionQuality::ResolvedAtHook,
                        authority: PathResolutionAuthority::KernelPathSnapshot,
                        resolved_path: Some(ResolvedPath {
                            display: String::from_utf8_lossy(bytes).into_owned(),
                            raw_hex: hex(bytes),
                        }),
                    }
                }
                _ => unreachable!("validated kernel file path quality"),
            };
            let role = match EffectOperation::from_raw(event.operation) {
                Some(
                    EffectOperation::DirectoryCreate
                    | EffectOperation::SymlinkCreate
                    | EffectOperation::DeviceNodeCreate,
                ) => ObjectRole::Parent,
                Some(EffectOperation::FileRename | EffectOperation::HardLinkCreate) => {
                    ObjectRole::Source
                }
                _ => ObjectRole::Primary,
            };
            let identity = if object.mount_id_unique == 0 {
                ObjectIdentity::InodeObject {
                    boot_id: boot_id.to_owned(),
                    device_major: object.device_major,
                    device_minor: object.device_minor,
                    inode: object.inode,
                    inode_generation: (object.generation_valid == 1)
                        .then_some(object.inode_generation),
                    filesystem_magic: object.filesystem_magic,
                    filesystem_class: filesystem_class(object.filesystem_magic),
                    identity_scope: "DEVICE_INODE_GENERATION_WITHOUT_MOUNT".to_owned(),
                }
            } else {
                ObjectIdentity::FileObject {
                    boot_id: boot_id.to_owned(),
                    mount_id_unique: object.mount_id_unique,
                    device_major: object.device_major,
                    device_minor: object.device_minor,
                    inode: object.inode,
                    inode_generation: (object.generation_valid == 1)
                        .then_some(object.inode_generation),
                    filesystem_magic: object.filesystem_magic,
                    filesystem_class: filesystem_class(object.filesystem_magic),
                    path,
                }
            };
            vec![ObjectReference {
                slot: 0,
                role,
                identity,
            }]
        } else if let Some(object) = &event.socket_object {
            let bytes = &object.endpoint[..usize::from(object.endpoint_len)];
            let endpoint = SocketEndpointObservation {
                quality: if object.endpoint_quality == 1 {
                    SocketEndpointQuality::KernelResolved
                } else {
                    SocketEndpointQuality::KernelResolvedTruncated
                },
                authority: if object.endpoint_authority == SOCKET_ENDPOINT_AUTHORITY_KERNEL_STATE {
                    SocketEndpointAuthority::KernelSocketState
                } else {
                    SocketEndpointAuthority::KernelCopiedSockaddrAtLsmHook
                },
                address: Some(kernel_sockaddr(bytes, object.endpoint_address_family)),
            };
            let mut endpoints = SocketEndpointPair::default();
            let role = if object.endpoint_role == 1 {
                endpoints.local = endpoint;
                ObjectRole::Primary
            } else {
                endpoints.peer = endpoint;
                ObjectRole::Peer
            };
            vec![ObjectReference {
                slot: 0,
                role,
                identity: ObjectIdentity::SocketObject {
                    boot_id: boot_id.to_owned(),
                    network_namespace_cookie: object.network_namespace_cookie,
                    socket_cookie: object.socket_cookie,
                    address_family: object.address_family,
                    socket_type: object.socket_type,
                    protocol: object.protocol,
                    endpoint_address_family: object.endpoint_address_family,
                    endpoints,
                },
            }]
        } else if event.kind == EVENT_OPERATION_ATTEMPT {
            captures
                .iter()
                .enumerate()
                .filter(|(_, capture)| {
                    matches!(
                        capture.status,
                        CaptureStatus::Captured | CaptureStatus::Truncated
                    )
                })
                .map(|(slot, capture)| ObjectReference {
                    slot: slot as u8,
                    role: ObjectRole::SyscallArgument,
                    identity: ObjectIdentity::UserInputOnly {
                        argument_index: capture.argument_index,
                        source: capture.source,
                        status: capture.status,
                    },
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let (quality, authority) = if event.file_object.is_some() || event.socket_object.is_some() {
            (
                ObjectResolutionQuality::KernelResolved,
                ObjectResolutionAuthority::KernelObjectHook,
            )
        } else if objects.is_empty() {
            (
                ObjectResolutionQuality::Unresolved,
                ObjectResolutionAuthority::None,
            )
        } else {
            (
                ObjectResolutionQuality::UserInputOnly,
                ObjectResolutionAuthority::SyscallEntryUserMemory,
            )
        };
        Self {
            protocol_version: OBJECT_IDENTITY_PROTOCOL_VERSION,
            source_event_seq: event.event_seq,
            operation_attempt_seq: if event.kind == EVENT_OPERATION_ATTEMPT {
                event.event_seq
            } else {
                event.related_attempt_seq
            },
            quality,
            authority,
            objects,
        }
    }

    fn validate_for_event(&self, event: &SystemEffectEvent) -> Result<()> {
        if self.protocol_version != OBJECT_IDENTITY_PROTOCOL_VERSION {
            bail!(
                "object identity protocol {} != supported protocol {}",
                self.protocol_version,
                OBJECT_IDENTITY_PROTOCOL_VERSION
            );
        }
        let expected_attempt_seq = match event.kind {
            EventKind::OperationAttempt => event.event_seq,
            EventKind::OperationResult => event.related_attempt_seq,
        };
        if self.source_event_seq != event.event_seq
            || self.operation_attempt_seq != expected_attempt_seq
            || self.source_event_seq == 0
        {
            bail!("object resolution is not correlated to its enclosing operation event");
        }
        if self.operation_attempt_seq == 0
            && !(event.kind == EventKind::OperationResult
                && event.flags & FLAG_PENDING_MISSING != 0)
        {
            bail!("object resolution has no operation-attempt correlation");
        }
        if self.objects.len() > MAX_OBJECT_REFERENCES {
            bail!("object resolution exceeds its fixed reference bound");
        }
        let mut previous_slot = None;
        for object in &self.objects {
            if usize::from(object.slot) >= MAX_OBJECT_REFERENCES
                || previous_slot.map_or(false, |slot| object.slot <= slot)
            {
                bail!("object references have duplicate, unordered, or invalid slots");
            }
            previous_slot = Some(object.slot);
            validate_object_reference(object, event)?;
        }
        match (self.quality, self.authority) {
            (ObjectResolutionQuality::Unresolved, ObjectResolutionAuthority::None) => {
                if !self.objects.is_empty() {
                    bail!("UNRESOLVED object resolution contains an identity");
                }
            }
            (
                ObjectResolutionQuality::UserInputOnly,
                ObjectResolutionAuthority::SyscallEntryUserMemory,
            ) => {
                if self.objects.is_empty()
                    || self.objects.iter().any(|object| {
                        !matches!(object.identity, ObjectIdentity::UserInputOnly { .. })
                    })
                {
                    bail!("USER_INPUT_ONLY resolution has non-user or empty identity data");
                }
            }
            (
                ObjectResolutionQuality::KernelResolved,
                ObjectResolutionAuthority::KernelObjectHook,
            ) => {
                if event.kind != EventKind::OperationResult
                    || self.objects.is_empty()
                    || self.objects.iter().any(|object| {
                        matches!(object.identity, ObjectIdentity::UserInputOnly { .. })
                    })
                {
                    bail!("KERNEL_RESOLVED resolution lacks result-side kernel object evidence");
                }
            }
            _ => bail!("object resolution quality and authority disagree"),
        }
        Ok(())
    }
}

fn validate_object_reference(object: &ObjectReference, event: &SystemEffectEvent) -> Result<()> {
    match &object.identity {
        ObjectIdentity::UserInputOnly {
            argument_index,
            source,
            status,
        } => {
            if object.role != ObjectRole::SyscallArgument
                || event.kind != EventKind::OperationAttempt
                || *argument_index > 5
                || !matches!(status, CaptureStatus::Captured | CaptureStatus::Truncated)
            {
                bail!("invalid USER_INPUT_ONLY object reference");
            }
            let capture = event
                .captures
                .get(usize::from(object.slot))
                .context("USER_INPUT_ONLY object has no matching capture slot")?;
            if capture.argument_index != *argument_index
                || capture.source != *source
                || capture.status != *status
            {
                bail!("USER_INPUT_ONLY object disagrees with its captured argument");
            }
        }
        ObjectIdentity::FileObject {
            boot_id,
            mount_id_unique,
            inode,
            filesystem_magic,
            filesystem_class,
            path,
            ..
        } => {
            if invalid_boot_id(boot_id)
                || *mount_id_unique == 0
                || *inode == 0
                || *filesystem_magic == 0
                || !filesystem_class_matches(*filesystem_class, *filesystem_magic)
                || object.role == ObjectRole::SyscallArgument
                || !matches!(
                    event.operation,
                    EffectOperation::FileCreateOrTruncate
                        | EffectOperation::FileOpenRequest
                        | EffectOperation::FdWrite
                        | EffectOperation::FdRead
                        | EffectOperation::DirectoryCreate
                        | EffectOperation::SymlinkCreate
                        | EffectOperation::DeviceNodeCreate
                        | EffectOperation::HardLinkCreate
                        | EffectOperation::FileUnlink
                        | EffectOperation::DirectoryRemove
                        | EffectOperation::PathEntryRemove
                        | EffectOperation::FileRename
                        | EffectOperation::PermissionsChange
                        | EffectOperation::OwnershipChange
                        | EffectOperation::MemoryWriteChannel
                )
            {
                bail!("invalid FILE_OBJECT identity");
            }
            validate_file_path_observation(path)?;
            match event.operation {
                EffectOperation::FdWrite | EffectOperation::FdRead
                    if *path != FilePathObservation::default() =>
                {
                    bail!("file_permission read/write object unexpectedly claims a kernel path snapshot")
                }
                EffectOperation::FileCreateOrTruncate | EffectOperation::FileOpenRequest
                    if !matches!(
                        path.quality,
                        PathResolutionQuality::ResolvedAtHook | PathResolutionQuality::Unavailable
                    ) =>
                {
                    bail!(
                        "file_post_open object has a path quality not produced by the current hook"
                    )
                }
                _ => {}
            }
            let expected_role = match event.operation {
                EffectOperation::DirectoryCreate
                | EffectOperation::SymlinkCreate
                | EffectOperation::DeviceNodeCreate => ObjectRole::Parent,
                EffectOperation::FileRename | EffectOperation::HardLinkCreate => ObjectRole::Source,
                _ => ObjectRole::Primary,
            };
            if object.role != expected_role {
                bail!("FILE_OBJECT role overstates the object supplied by its hook");
            }
        }
        ObjectIdentity::InodeObject {
            boot_id,
            inode,
            filesystem_magic,
            filesystem_class,
            identity_scope,
            ..
        } => {
            if invalid_boot_id(boot_id)
                || *inode == 0
                || *filesystem_magic == 0
                || !filesystem_class_matches(*filesystem_class, *filesystem_magic)
                || identity_scope != "DEVICE_INODE_GENERATION_WITHOUT_MOUNT"
                || object.role != ObjectRole::Primary
                || !matches!(
                    event.operation,
                    EffectOperation::ExtendedAttributeSet
                        | EffectOperation::ExtendedAttributeRemove
                )
            {
                bail!("invalid mountless INODE_OBJECT identity");
            }
        }
        ObjectIdentity::SocketObject {
            boot_id,
            network_namespace_cookie,
            socket_cookie,
            address_family,
            socket_type,
            endpoint_address_family,
            endpoints,
            ..
        } => {
            if invalid_boot_id(boot_id)
                || *network_namespace_cookie == 0
                || *socket_cookie == 0
                || *address_family == 0
                || *socket_type == 0
                || !matches!(
                    (event.operation, object.role),
                    (EffectOperation::SocketConnect, ObjectRole::Peer)
                        | (EffectOperation::SocketBind, ObjectRole::Primary)
                        | (EffectOperation::SocketAccept, ObjectRole::Peer)
                )
            {
                bail!("invalid SOCKET_OBJECT identity");
            }
            validate_socket_endpoints(endpoints, *endpoint_address_family)?;
        }
    }
    Ok(())
}

fn invalid_boot_id(value: &str) -> bool {
    if value.len() != 36 {
        return true;
    }
    value.bytes().enumerate().any(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) {
            byte != b'-'
        } else {
            !(byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        }
    })
}

fn filesystem_class_matches(class: FilesystemClass, magic: u64) -> bool {
    class == filesystem_class(magic)
}

fn filesystem_class(magic: u64) -> FilesystemClass {
    const PROC_SUPER_MAGIC: u64 = 0x9fa0;
    const SYSFS_MAGIC: u64 = 0x6265_6572;
    const CGROUP_SUPER_MAGIC: u64 = 0x0027_e0eb;
    const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
    match magic {
        PROC_SUPER_MAGIC => FilesystemClass::Procfs,
        SYSFS_MAGIC => FilesystemClass::Sysfs,
        CGROUP_SUPER_MAGIC => FilesystemClass::CgroupV1,
        CGROUP2_SUPER_MAGIC => FilesystemClass::CgroupV2,
        _ => FilesystemClass::Other,
    }
}

fn validate_file_path_observation(observation: &FilePathObservation) -> Result<()> {
    let has_path = observation.resolved_path.is_some();
    match (observation.quality, observation.authority, has_path) {
        (
            PathResolutionQuality::NotRequested | PathResolutionQuality::Unavailable,
            PathResolutionAuthority::None,
            false,
        ) => return Ok(()),
        (
            PathResolutionQuality::ResolvedAtHook
            | PathResolutionQuality::TruncatedAtHook
            | PathResolutionQuality::UnstableAtHook,
            PathResolutionAuthority::KernelPathSnapshot,
            true,
        ) => {}
        _ => bail!("file path quality, authority, and payload disagree"),
    }
    let path = observation
        .resolved_path
        .as_ref()
        .context("resolved file path payload is absent")?;
    let bytes = decode_canonical_hex(&path.raw_hex, MAX_RESOLVED_PATH_BYTES, false)
        .context("invalid resolved file path bytes")?;
    if bytes.contains(&0) {
        bail!("resolved file path contains a NUL byte");
    }
    if path.display != String::from_utf8_lossy(&bytes) {
        bail!("resolved file path display is not derived from raw_hex");
    }
    Ok(())
}

fn validate_socket_endpoints(endpoints: &SocketEndpointPair, family: u32) -> Result<()> {
    validate_socket_endpoint(&endpoints.local, family).context("invalid local socket endpoint")?;
    validate_socket_endpoint(&endpoints.peer, family).context("invalid peer socket endpoint")
}

fn validate_socket_endpoint(endpoint: &SocketEndpointObservation, family: u32) -> Result<()> {
    let has_address = endpoint.address.is_some();
    match (endpoint.quality, endpoint.authority, has_address) {
        (
            SocketEndpointQuality::NotRequested | SocketEndpointQuality::Unavailable,
            SocketEndpointAuthority::None,
            false,
        ) => return Ok(()),
        (
            SocketEndpointQuality::KernelResolved | SocketEndpointQuality::KernelResolvedTruncated,
            SocketEndpointAuthority::KernelSocketState
            | SocketEndpointAuthority::KernelCopiedSockaddrAtLsmHook,
            true,
        ) => {}
        _ => bail!("socket endpoint quality, authority, and payload disagree"),
    }
    let address = endpoint
        .address
        .as_ref()
        .context("resolved socket endpoint payload is absent")?;
    match address {
        SocketEndpointAddress::Inet4 { .. } => {
            if family != libc::AF_INET as u32 {
                bail!("INET4 endpoint disagrees with socket address family");
            }
            if endpoint.quality == SocketEndpointQuality::KernelResolvedTruncated {
                bail!("fixed-size INET4 endpoint cannot be marked truncated");
            }
        }
        SocketEndpointAddress::Inet6 { .. } => {
            if family != libc::AF_INET6 as u32 {
                bail!("INET6 endpoint disagrees with socket address family");
            }
            if endpoint.quality == SocketEndpointQuality::KernelResolvedTruncated {
                bail!("fixed-size INET6 endpoint cannot be marked truncated");
            }
        }
        SocketEndpointAddress::Unix {
            name_hex,
            abstract_namespace,
            unnamed,
        } => {
            if family != libc::AF_UNIX as u32 {
                bail!("UNIX endpoint disagrees with socket address family");
            }
            let name = decode_canonical_hex(name_hex, MAX_SOCKET_ENDPOINT_BYTES, *unnamed)
                .context("invalid UNIX endpoint bytes")?;
            if *unnamed {
                if !name.is_empty() || *abstract_namespace {
                    bail!("unnamed UNIX endpoint contains a name");
                }
            } else if *abstract_namespace {
                if name.first() != Some(&0) {
                    bail!("abstract UNIX endpoint lacks its leading NUL byte");
                }
            } else if name.contains(&0) {
                bail!("pathname UNIX endpoint contains a NUL byte");
            }
        }
        SocketEndpointAddress::Other {
            address_family,
            raw_hex,
        } => {
            if *address_family != family
                || matches!(
                    family,
                    value if value == libc::AF_INET as u32
                        || value == libc::AF_INET6 as u32
                        || value == libc::AF_UNIX as u32
                )
            {
                bail!("OTHER endpoint has a known or mismatched address family");
            }
            decode_canonical_hex(raw_hex, MAX_SOCKET_ENDPOINT_BYTES, false)
                .context("invalid OTHER endpoint bytes")?;
        }
    }
    Ok(())
}

fn kernel_sockaddr(bytes: &[u8], family: u32) -> SocketEndpointAddress {
    if family == libc::AF_INET as u32 && bytes.len() >= 8 {
        return SocketEndpointAddress::Inet4 {
            port: u16::from_be_bytes([bytes[2], bytes[3]]),
            address: bytes[4..8].try_into().expect("fixed IPv4 slice"),
        };
    }
    if family == libc::AF_INET6 as u32 && bytes.len() >= 28 {
        return SocketEndpointAddress::Inet6 {
            port: u16::from_be_bytes([bytes[2], bytes[3]]),
            flowinfo: u32::from_be_bytes(bytes[4..8].try_into().expect("fixed flowinfo slice")),
            address: bytes[8..24].try_into().expect("fixed IPv6 slice"),
            scope_id: u32::from_ne_bytes(bytes[24..28].try_into().expect("fixed scope slice")),
        };
    }
    if family == libc::AF_UNIX as u32 {
        let raw_name = bytes.get(2..).unwrap_or_default();
        let abstract_namespace = raw_name.first() == Some(&0);
        let name = if abstract_namespace {
            raw_name
        } else {
            &raw_name[..raw_name
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(raw_name.len())]
        };
        return SocketEndpointAddress::Unix {
            name_hex: hex(name),
            abstract_namespace,
            unnamed: name.is_empty(),
        };
    }
    SocketEndpointAddress::Other {
        address_family: family,
        raw_hex: hex(bytes),
    }
}

fn decode_canonical_hex(value: &str, maximum_bytes: usize, allow_empty: bool) -> Result<Vec<u8>> {
    if value.len() % 2 != 0
        || value.len() > maximum_bytes.saturating_mul(2)
        || (!allow_empty && value.is_empty())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("value is not bounded canonical lowercase hex");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]);
            let low = hex_nibble(pair[1]);
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => unreachable!("decode_canonical_hex validated every nibble"),
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedArgument {
    pub argument_index: u8,
    pub source: CaptureSource,
    pub status: CaptureStatus,
    pub length: u16,
    pub display: Option<String>,
    pub raw_hex: Option<String>,
    pub authority: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectProcessIdentityAuthority {
    None,
    KernelTaskStartBoottimeAtSyscallEntry,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectProcessIdentity {
    pub boot_id: String,
    pub run_epoch: u64,
    pub cgroup_id: u64,
    pub pid: u32,
    pub tgid: u32,
    pub start_boottime_ns: Option<u64>,
    pub authority: EffectProcessIdentityAuthority,
    pub stable_key: Option<String>,
}

impl Default for EffectProcessIdentity {
    fn default() -> Self {
        Self {
            boot_id: String::new(),
            run_epoch: 0,
            cgroup_id: 0,
            pid: 0,
            tgid: 0,
            start_boottime_ns: None,
            authority: EffectProcessIdentityAuthority::None,
            stable_key: None,
        }
    }
}

impl EffectProcessIdentity {
    fn from_kernel_event(event: &KernelEvent, boot_id: &str) -> Self {
        let pid = event.pid_tgid as u32;
        let tgid = (event.pid_tgid >> 32) as u32;
        let resolved = event.flags & FLAG_TASK_READ_FAILED == 0;
        let start = resolved.then_some(event.task_start_boottime_ns);
        Self {
            boot_id: boot_id.to_owned(),
            run_epoch: event.run_epoch,
            cgroup_id: event.cgroup_id,
            pid,
            tgid,
            start_boottime_ns: start,
            authority: if resolved {
                EffectProcessIdentityAuthority::KernelTaskStartBoottimeAtSyscallEntry
            } else {
                EffectProcessIdentityAuthority::None
            },
            stable_key: start.map(|start| {
                format!(
                    "{boot_id}/cgroup:{}/epoch:{}/tgid:{tgid}/pid:{pid}/start:{start}",
                    event.cgroup_id, event.run_epoch
                )
            }),
        }
    }

    fn validate_for_event(&self, event: &SystemEffectEvent) -> Result<()> {
        let resolved = event.flags & FLAG_TASK_READ_FAILED == 0;
        let expected_start = if resolved {
            Some(
                self.start_boottime_ns
                    .context("resolved process identity has no task start time")?,
            )
        } else {
            None
        };
        let expected_key = expected_start.map(|start| {
            format!(
                "{}/cgroup:{}/epoch:{}/tgid:{}/pid:{}/start:{start}",
                self.boot_id, event.cgroup_id, event.run_epoch, event.tgid, event.pid
            )
        });
        if invalid_boot_id(&self.boot_id)
            || self.run_epoch != event.run_epoch
            || self.cgroup_id != event.cgroup_id
            || self.pid != event.pid
            || self.tgid != event.tgid
            || self.pid == 0
            || self.tgid == 0
            || self.start_boottime_ns != expected_start
            || self.stable_key != expected_key
            || self.authority
                != if resolved {
                    EffectProcessIdentityAuthority::KernelTaskStartBoottimeAtSyscallEntry
                } else {
                    EffectProcessIdentityAuthority::None
                }
        {
            bail!("system-effect process identity is not derived from the raw event");
        }
        Ok(())
    }
}

/// Attribution mode supported by the current raw-syscall recorder.
///
/// `DIRECT` means only that the syscall caller was a member of the registered
/// run cgroup at syscall entry. It does not identify Agent code or establish
/// delegated causality.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectAttributionMode {
    Direct,
}

/// Meaning of the kernel frame's `cgroup_id` field.  The ancestor form binds
/// the matched, FD-pinned scope root; the leaf cgroup is not present in ABI v1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CgroupMatchMode {
    ExactCurrent,
    AncestorRoot,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectAttributionAuthority {
    KernelCurrentCgroupIdAtSyscallEntry,
    KernelCurrentTaskUnderCgroupAtSyscallEntry,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectAttributionSubject {
    RunExecutionDomain,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectAttributionComponent {
    UnclassifiedCgroupMember,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DelegatedEffectsStatus {
    NotObserved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectCausalStatus {
    CausalNotEstablished,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DirectAttributionClaim {
    SelectedNativeSyscallCallerInExactCgroupAtEntry,
    SelectedNativeSyscallCallerWithinBoundCgroupV2RootAtEntry,
}

/// Run-wide closed interpretation contract for every v1 attribution record.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionContract {
    pub protocol_version: u32,
    pub direct_claim: DirectAttributionClaim,
    pub mode: EffectAttributionMode,
    pub authority: EffectAttributionAuthority,
    pub subject: EffectAttributionSubject,
    pub component: EffectAttributionComponent,
    pub delegated_effects: DelegatedEffectsStatus,
    pub causal_status: EffectCausalStatus,
}

impl AttributionContract {
    pub const fn direct_v1() -> Self {
        Self {
            protocol_version: EFFECT_ATTRIBUTION_PROTOCOL_VERSION,
            direct_claim: DirectAttributionClaim::SelectedNativeSyscallCallerInExactCgroupAtEntry,
            mode: EffectAttributionMode::Direct,
            authority: EffectAttributionAuthority::KernelCurrentCgroupIdAtSyscallEntry,
            subject: EffectAttributionSubject::RunExecutionDomain,
            component: EffectAttributionComponent::UnclassifiedCgroupMember,
            delegated_effects: DelegatedEffectsStatus::NotObserved,
            causal_status: EffectCausalStatus::CausalNotEstablished,
        }
    }

    pub const fn ancestor_root_v2() -> Self {
        Self {
            protocol_version: EFFECT_ATTRIBUTION_PROTOCOL_VERSION,
            direct_claim:
                DirectAttributionClaim::SelectedNativeSyscallCallerWithinBoundCgroupV2RootAtEntry,
            mode: EffectAttributionMode::Direct,
            authority: EffectAttributionAuthority::KernelCurrentTaskUnderCgroupAtSyscallEntry,
            subject: EffectAttributionSubject::RunExecutionDomain,
            component: EffectAttributionComponent::UnclassifiedCgroupMember,
            delegated_effects: DelegatedEffectsStatus::NotObserved,
            causal_status: EffectCausalStatus::CausalNotEstablished,
        }
    }

    pub const fn for_cgroup_match(mode: CgroupMatchMode) -> Self {
        match mode {
            CgroupMatchMode::ExactCurrent => Self::direct_v1(),
            CgroupMatchMode::AncestorRoot => Self::ancestor_root_v2(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if *self != Self::direct_v1() && *self != Self::ancestor_root_v2() {
            bail!("system-effect attribution contract is unsupported or overstates authority");
        }
        Ok(())
    }
}

/// Event-local attribution derived from the raw event's entry-time identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectAttribution {
    pub protocol_version: u32,
    pub mode: EffectAttributionMode,
    pub authority: EffectAttributionAuthority,
    pub subject: EffectAttributionSubject,
    pub component: EffectAttributionComponent,
    pub delegated_effects: DelegatedEffectsStatus,
    pub causal_status: EffectCausalStatus,
    pub cgroup_match_mode: CgroupMatchMode,
    pub matched_scope_cgroup_id: u64,
    pub leaf_cgroup_id_retained: bool,
    pub cgroup_id_at_syscall_entry: u64,
    pub source_event_seq: u64,
    pub operation_attempt_seq: u64,
}

impl Default for EffectAttribution {
    /// Deserialization sentinel for JSON written before the attribution
    /// protocol existed. Strict validation rejects version zero.
    fn default() -> Self {
        Self {
            protocol_version: 0,
            mode: EffectAttributionMode::Direct,
            authority: EffectAttributionAuthority::KernelCurrentCgroupIdAtSyscallEntry,
            subject: EffectAttributionSubject::RunExecutionDomain,
            component: EffectAttributionComponent::UnclassifiedCgroupMember,
            delegated_effects: DelegatedEffectsStatus::NotObserved,
            causal_status: EffectCausalStatus::CausalNotEstablished,
            cgroup_match_mode: CgroupMatchMode::ExactCurrent,
            matched_scope_cgroup_id: 0,
            leaf_cgroup_id_retained: false,
            cgroup_id_at_syscall_entry: 0,
            source_event_seq: 0,
            operation_attempt_seq: 0,
        }
    }
}

impl EffectAttribution {
    pub fn from_kernel_event(event: &KernelEvent, cgroup_match_mode: CgroupMatchMode) -> Self {
        let operation_attempt_seq = if event.kind == EVENT_OPERATION_ATTEMPT {
            event.event_seq
        } else {
            event.related_attempt_seq
        };
        let exact = cgroup_match_mode == CgroupMatchMode::ExactCurrent;
        let contract = AttributionContract::for_cgroup_match(cgroup_match_mode);
        Self {
            protocol_version: EFFECT_ATTRIBUTION_PROTOCOL_VERSION,
            mode: contract.mode,
            authority: contract.authority,
            subject: contract.subject,
            component: contract.component,
            delegated_effects: contract.delegated_effects,
            causal_status: contract.causal_status,
            cgroup_match_mode,
            matched_scope_cgroup_id: event.cgroup_id,
            leaf_cgroup_id_retained: exact,
            cgroup_id_at_syscall_entry: if exact { event.cgroup_id } else { 0 },
            source_event_seq: event.event_seq,
            operation_attempt_seq,
        }
    }

    fn validate_for_event(&self, event: &SystemEffectEvent) -> Result<()> {
        let expected_contract = AttributionContract::for_cgroup_match(self.cgroup_match_mode);
        if self.protocol_version != expected_contract.protocol_version
            || self.mode != expected_contract.mode
            || self.authority != expected_contract.authority
            || self.subject != expected_contract.subject
            || self.component != expected_contract.component
            || self.delegated_effects != expected_contract.delegated_effects
            || self.causal_status != expected_contract.causal_status
        {
            bail!("system-effect attribution contract disagrees with cgroup match mode");
        }
        let expected_attempt_seq = match event.kind {
            EventKind::OperationAttempt => event.event_seq,
            EventKind::OperationResult => event.related_attempt_seq,
        };
        let exact = self.cgroup_match_mode == CgroupMatchMode::ExactCurrent;
        if self.matched_scope_cgroup_id != event.cgroup_id
            || self.matched_scope_cgroup_id == 0
            || self.leaf_cgroup_id_retained != exact
            || (exact && self.cgroup_id_at_syscall_entry != event.cgroup_id)
            || (!exact && self.cgroup_id_at_syscall_entry != 0)
            || self.source_event_seq != event.event_seq
            || self.source_event_seq == 0
            || self.operation_attempt_seq != expected_attempt_seq
        {
            bail!("system-effect attribution is not derived from its raw event identity");
        }
        if self.operation_attempt_seq == 0
            && !(event.kind == EventKind::OperationResult
                && event.flags & FLAG_PENDING_MISSING != 0)
        {
            bail!("system-effect attribution has no operation-attempt correlation");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemEffectEvent {
    pub schema_version: u32,
    pub run_id: String,
    pub run_epoch: u64,
    pub event_seq: u64,
    pub related_attempt_seq: u64,
    pub kind: EventKind,
    pub domain: EffectDomain,
    pub operation: EffectOperation,
    pub syscall_nr: i32,
    pub syscall_name: String,
    pub ktime_ns: u64,
    pub cgroup_id: u64,
    pub pid: u32,
    pub tgid: u32,
    pub comm: String,
    #[serde(default)]
    pub process_identity: EffectProcessIdentity,
    pub raw_arguments: [u64; 6],
    pub captures: Vec<CapturedArgument>,
    #[serde(default)]
    pub object_resolution: ObjectResolution,
    #[serde(default)]
    pub attribution: EffectAttribution,
    pub return_value: Option<i64>,
    pub result_status: Option<ResultStatus>,
    pub flags: u32,
    pub semantics: String,
}

impl SystemEffectEvent {
    pub fn validate_object_resolution(&self) -> Result<()> {
        self.object_resolution.validate_for_event(self)
    }

    pub fn validate_attribution(&self) -> Result<()> {
        self.attribution.validate_for_event(self)
    }

    pub fn validate_process_identity(&self) -> Result<()> {
        self.process_identity.validate_for_event(self)
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
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    output
}

fn format_sockaddr(bytes: &[u8]) -> String {
    if bytes.len() < 2 {
        return format!("sockaddr:{}", hex(bytes));
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    match family as i32 {
        libc::AF_INET if bytes.len() >= 8 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let address = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            format!("{address}:{port}")
        }
        libc::AF_INET6 if bytes.len() >= 24 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[8..24]);
            let address = Ipv6Addr::from(octets);
            format!("[{address}]:{port}")
        }
        libc::AF_UNIX => {
            let path = nul_terminated_lossy(&bytes[2..]);
            format!("unix:{path}")
        }
        _ => format!("family={family}:{}", hex(&bytes[2..])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT_ID: &str = "00000000-0000-0000-0000-000000000001";

    fn fixture() -> KernelEvent {
        let mut payload = [0u8; CAPTURE_BYTES];
        payload[..9].copy_from_slice(b"file.txt\0");
        KernelEvent {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            kind: EVENT_OPERATION_ATTEMPT,
            domain: EffectDomain::Filesystem as u16,
            operation: EffectOperation::FileRename as u32,
            flags: FLAG_USER_MEMORY_SNAPSHOT,
            syscall_nr: libc::SYS_renameat2 as i32,
            run_epoch: 7,
            event_seq: 11,
            related_attempt_seq: 0,
            ktime_ns: 99,
            cgroup_id: 100,
            pid_tgid: (42u64 << 32) | 43,
            return_value: 0,
            args: [1, 2, 3, 4, 5, 6],
            comm: {
                let mut comm = [0; 16];
                comm[..5].copy_from_slice(b"agent");
                comm
            },
            task_start_boottime_ns: 77,
            payload_lens: [9, 9],
            payload_kinds: [PAYLOAD_USER_STRING, PAYLOAD_USER_STRING],
            payload_arg_indices: [1, 3],
            payloads: [payload, payload],
            file_object: None,
            socket_object: None,
        }
    }

    fn file_open_result() -> KernelEvent {
        let mut event = fixture();
        event.kind = EVENT_OPERATION_RESULT;
        event.domain = EffectDomain::Filesystem as u16;
        event.operation = EffectOperation::FileCreateOrTruncate as u32;
        event.flags = 0;
        event.syscall_nr = libc::SYS_openat as i32;
        event.event_seq = 12;
        event.related_attempt_seq = 11;
        event.return_value = 7;
        event.payload_lens = [0; 2];
        event.payload_kinds = [PAYLOAD_NONE; 2];
        event.payload_arg_indices = [0; 2];
        event.payloads = [[0; CAPTURE_BYTES]; 2];
        let mut path = [0u8; KERNEL_FILE_PATH_BYTES];
        let path_bytes = b"/tmp/agent-output";
        path[..path_bytes.len()].copy_from_slice(path_bytes);
        event.file_object = Some(KernelFileObject {
            mount_id_unique: 41,
            inode: 99,
            filesystem_magic: 0xef53,
            device_major: 8,
            device_minor: 1,
            inode_generation: 3,
            path_len: path_bytes.len() as u16,
            generation_valid: 1,
            path_quality: FILE_PATH_RESOLVED_AT_HOOK,
            path,
        });
        event
    }

    fn file_write_result() -> KernelEvent {
        let mut event = file_open_result();
        event.domain = EffectDomain::Io as u16;
        event.operation = EffectOperation::FdWrite as u32;
        event.syscall_nr = libc::SYS_write as i32;
        event.return_value = 4;
        event.args = [7, 0x1000, 4, 0, 0, 0];
        let object = event.file_object.as_mut().expect("file object fixture");
        object.path_len = 0;
        object.path_quality = FILE_PATH_NOT_REQUESTED;
        object.path = [0; KERNEL_FILE_PATH_BYTES];
        event
    }

    fn hard_link_result(syscall_nr: i32) -> KernelEvent {
        let mut event = file_write_result();
        event.domain = EffectDomain::Filesystem as u16;
        event.operation = EffectOperation::HardLinkCreate as u32;
        event.syscall_nr = syscall_nr;
        event.return_value = 0;
        event.args = [0x1000, 0x2000, 0, 0, 0, 0];
        event
    }

    #[test]
    fn little_endian_round_trip_is_stable() {
        let event = fixture();
        assert_eq!(KernelEvent::decode_le(&event.encode_le()).unwrap(), event);
    }

    #[test]
    fn kernel_file_object_round_trip_derives_boot_scoped_identity() {
        let raw = file_open_result();
        let encoded = raw.encode_le();
        assert_eq!(encoded.len(), KERNEL_FILE_EVENT_SIZE);
        assert_eq!(KernelEvent::decode_le(&encoded).unwrap(), raw);

        let policies =
            crate::policy::event_policy_identities(crate::policy::PolicyProfile::Balanced).unwrap();
        let event = raw
            .to_schema("run", BOOT_ID, policies[&(libc::SYS_openat as i32)])
            .unwrap();
        assert_eq!(
            event.object_resolution.quality,
            ObjectResolutionQuality::KernelResolved
        );
        assert_eq!(
            event.object_resolution.authority,
            ObjectResolutionAuthority::KernelObjectHook
        );
        assert_eq!(event.object_resolution.operation_attempt_seq, 11);
        assert_eq!(event.object_resolution.objects.len(), 1);
        match &event.object_resolution.objects[0].identity {
            ObjectIdentity::FileObject {
                boot_id,
                mount_id_unique,
                device_major,
                device_minor,
                inode,
                inode_generation,
                filesystem_magic,
                filesystem_class,
                path,
            } => {
                assert_eq!(boot_id, BOOT_ID);
                assert_eq!(*mount_id_unique, 41);
                assert_eq!((*device_major, *device_minor), (8, 1));
                assert_eq!(*inode, 99);
                assert_eq!(*inode_generation, Some(3));
                assert_eq!(*filesystem_magic, 0xef53);
                assert_eq!(*filesystem_class, FilesystemClass::Other);
                assert_eq!(path.quality, PathResolutionQuality::ResolvedAtHook);
                assert_eq!(path.authority, PathResolutionAuthority::KernelPathSnapshot);
                assert_eq!(
                    path.resolved_path
                        .as_ref()
                        .map(|value| value.display.as_str()),
                    Some("/tmp/agent-output")
                );
            }
            other => panic!("expected FILE_OBJECT, got {other:?}"),
        }
        event.validate_object_resolution().unwrap();
    }

    #[test]
    fn fd_write_result_uses_the_same_authoritative_file_object_frame() {
        let raw = file_write_result();
        let encoded = raw.encode_le();
        assert_eq!(encoded.len(), KERNEL_FILE_EVENT_SIZE);
        assert_eq!(KernelEvent::decode_le(&encoded).unwrap(), raw);

        let policies =
            crate::policy::event_policy_identities(crate::policy::PolicyProfile::Balanced).unwrap();
        let mut event = raw
            .to_schema("run", BOOT_ID, policies[&(libc::SYS_write as i32)])
            .unwrap();
        assert_eq!(event.operation, EffectOperation::FdWrite);
        assert_eq!(
            event.object_resolution.quality,
            ObjectResolutionQuality::KernelResolved
        );
        assert_eq!(
            event.object_resolution.authority,
            ObjectResolutionAuthority::KernelObjectHook
        );
        match &event.object_resolution.objects[0].identity {
            ObjectIdentity::FileObject { path, .. } => {
                assert_eq!(path, &FilePathObservation::default());
            }
            other => panic!("expected FILE_OBJECT, got {other:?}"),
        }
        event.validate_object_resolution().unwrap();

        if let ObjectIdentity::FileObject { path, .. } =
            &mut event.object_resolution.objects[0].identity
        {
            path.quality = PathResolutionQuality::ResolvedAtHook;
            path.authority = PathResolutionAuthority::KernelPathSnapshot;
            path.resolved_path = Some(ResolvedPath {
                display: "/forged/write/path".to_owned(),
                raw_hex: hex(b"/forged/write/path"),
            });
        }
        assert!(event.validate_object_resolution().is_err());

        let mut zero_byte = raw;
        zero_byte.return_value = 0;
        assert!(zero_byte.validate().is_err());
    }

    #[test]
    fn hard_link_file_frame_round_trips_and_projects_only_the_source() {
        let policies =
            crate::policy::event_policy_identities(crate::policy::PolicyProfile::Control).unwrap();
        for syscall_nr in [libc::SYS_link as i32, libc::SYS_linkat as i32] {
            let raw = hard_link_result(syscall_nr);
            let encoded = raw.encode_le();
            assert_eq!(encoded.len(), KERNEL_FILE_EVENT_SIZE);
            assert_eq!(KernelEvent::decode_le(&encoded).unwrap(), raw);

            let event = raw
                .to_schema("run", BOOT_ID, policies[&syscall_nr])
                .unwrap();
            assert_eq!(event.operation, EffectOperation::HardLinkCreate);
            assert_eq!(
                event.object_resolution.quality,
                ObjectResolutionQuality::KernelResolved
            );
            assert_eq!(event.object_resolution.objects.len(), 1);
            assert_eq!(event.object_resolution.objects[0].role, ObjectRole::Source);
            assert!(matches!(
                event.object_resolution.objects[0].identity,
                ObjectIdentity::FileObject { .. }
            ));
            event.validate_object_resolution().unwrap();
        }
    }

    #[test]
    fn raw_hook_path_contract_is_operation_specific() {
        let write = file_write_result();
        write.validate().expect("canonical file_permission result");

        let mut forged_write = write;
        let object = forged_write
            .file_object
            .as_mut()
            .expect("file object fixture");
        let path = b"/forged/write/path";
        object.path[..path.len()].copy_from_slice(path);
        object.path_len = path.len() as u16;
        object.path_quality = FILE_PATH_RESOLVED_AT_HOOK;
        assert!(forged_write.validate().is_err());

        let mut forged_open = file_open_result();
        let object = forged_open
            .file_object
            .as_mut()
            .expect("file object fixture");
        object.path = [0; KERNEL_FILE_PATH_BYTES];
        object.path_len = 0;
        object.path_quality = FILE_PATH_NOT_REQUESTED;
        assert!(forged_open.validate().is_err());

        let mut oversized_open = file_open_result();
        let object = oversized_open
            .file_object
            .as_mut()
            .expect("file object fixture");
        object.path = [b'x'; KERNEL_FILE_PATH_BYTES];
        object.path_len = KERNEL_FILE_PATH_BYTES as u16;
        object.path_quality = FILE_PATH_RESOLVED_AT_HOOK;
        assert!(oversized_open.validate().is_err());

        let mut impossible_write_flag = file_write_result();
        impossible_write_flag.file_object = None;
        impossible_write_flag.flags = FLAG_OBJECT_PATH_UNAVAILABLE;
        assert!(impossible_write_flag.validate().is_err());

        let mut impossible_successful_open_flag = file_open_result();
        impossible_successful_open_flag.file_object = None;
        impossible_successful_open_flag.flags = FLAG_OBJECT_PATH_UNAVAILABLE;
        assert!(impossible_successful_open_flag.validate().is_err());

        let mut fatal_open_after_path_resolution = file_open_result();
        fatal_open_after_path_resolution.file_object = None;
        fatal_open_after_path_resolution.flags =
            FLAG_OBJECT_PATH_UNAVAILABLE | FLAG_OBJECT_JOIN_AMBIGUOUS;
        fatal_open_after_path_resolution
            .validate()
            .expect("fatal compact result may retain its path-helper diagnostic");

        // The hook can resolve an object before a later VFS step rejects the
        // open. The failed result intentionally drops transient identity while
        // retaining the path-helper diagnostic from the hook.
        let mut failed_open_after_hook = file_open_result();
        failed_open_after_hook.return_value = -libc::EIO as i64;
        failed_open_after_hook.file_object = None;
        failed_open_after_hook.flags = FLAG_OBJECT_PATH_UNAVAILABLE;
        failed_open_after_hook
            .validate()
            .expect("failed post-hook open may retain its path diagnostic");
    }

    #[test]
    fn file_object_wal_is_canonical_and_cannot_describe_failed_open() {
        let raw = file_open_result();
        let mut encoded = raw.encode_le();
        let path_len = usize::from(raw.file_object.as_ref().unwrap().path_len);
        encoded[204 + path_len] = 0xaa;
        let error = KernelEvent::decode_le(&encoded).unwrap_err().to_string();
        assert!(error.contains("nonzero unused tail"));

        // Native ring-buffer decoding normalizes bpf_d_path helper scratch;
        // only the canonicalized representation is accepted as persisted WAL.
        let normalized = KernelEvent::decode_native(&encoded).unwrap();
        assert!(normalized.file_object.as_ref().unwrap().path[path_len..]
            .iter()
            .all(|byte| *byte == 0));

        let mut failed = raw.clone();
        failed.return_value = -libc::ENOENT as i64;
        assert!(failed
            .validate()
            .unwrap_err()
            .to_string()
            .contains("eligible successful"));

        let mut inconsistent = raw;
        inconsistent.flags = FLAG_OBJECT_PATH_UNAVAILABLE;
        assert!(inconsistent
            .validate()
            .unwrap_err()
            .to_string()
            .contains("path quality and event flag disagree"));
    }

    #[test]
    fn schema_keeps_operation_semantics_explicit() {
        let policies =
            crate::policy::event_policy_identities(crate::policy::PolicyProfile::Balanced).unwrap();
        let event = fixture()
            .to_schema("run", BOOT_ID, policies[&(libc::SYS_renameat2 as i32)])
            .unwrap();
        assert_eq!(event.pid, 43);
        assert_eq!(event.tgid, 42);
        assert_eq!(event.comm, "agent");
        assert_eq!(event.captures[0].display.as_deref(), Some("file.txt"));
        assert!(event.semantics.contains("NOT_PROOF"));
        assert_eq!(
            event.object_resolution.quality,
            ObjectResolutionQuality::UserInputOnly
        );
        assert_eq!(
            event.object_resolution.authority,
            ObjectResolutionAuthority::SyscallEntryUserMemory
        );
        assert_eq!(event.object_resolution.source_event_seq, event.event_seq);
        assert_eq!(
            event.object_resolution.operation_attempt_seq,
            event.event_seq
        );
        assert_eq!(event.object_resolution.objects.len(), 2);
        assert!(event
            .object_resolution
            .objects
            .iter()
            .all(|object| matches!(object.identity, ObjectIdentity::UserInputOnly { .. })));
    }

    #[test]
    fn non_resolver_result_is_explicitly_unresolved() {
        let policies =
            crate::policy::event_policy_identities(crate::policy::PolicyProfile::Balanced).unwrap();
        let mut raw = fixture();
        raw.kind = EVENT_OPERATION_RESULT;
        raw.flags = 0;
        raw.event_seq = 12;
        raw.related_attempt_seq = 11;
        raw.return_value = 0;
        raw.payload_lens = [0; 2];
        raw.payload_kinds = [PAYLOAD_NONE; 2];
        raw.payload_arg_indices = [0; 2];
        raw.payloads = [[0; CAPTURE_BYTES]; 2];
        let event = raw
            .to_schema("run", BOOT_ID, policies[&(libc::SYS_renameat2 as i32)])
            .unwrap();

        assert_eq!(
            event.object_resolution.quality,
            ObjectResolutionQuality::Unresolved
        );
        assert_eq!(
            event.object_resolution.authority,
            ObjectResolutionAuthority::None
        );
        assert_eq!(event.object_resolution.operation_attempt_seq, 11);
        assert!(event.object_resolution.objects.is_empty());
    }

    #[test]
    fn failed_user_capture_is_not_promoted_to_an_object_identity() {
        let policies =
            crate::policy::event_policy_identities(crate::policy::PolicyProfile::Balanced).unwrap();
        let mut raw = fixture();
        raw.flags =
            FLAG_USER_MEMORY_SNAPSHOT | FLAG_PAYLOAD1_READ_FAILED | FLAG_PAYLOAD2_READ_FAILED;
        raw.payload_lens = [0; 2];
        let event = raw
            .to_schema("run", BOOT_ID, policies[&(libc::SYS_renameat2 as i32)])
            .unwrap();

        assert_eq!(
            event.object_resolution.quality,
            ObjectResolutionQuality::Unresolved
        );
        assert!(event.object_resolution.objects.is_empty());
    }

    #[test]
    fn object_resolution_rejects_false_authority_and_bad_correlation() {
        let policies =
            crate::policy::event_policy_identities(crate::policy::PolicyProfile::Balanced).unwrap();
        let mut event = fixture()
            .to_schema("run", BOOT_ID, policies[&(libc::SYS_renameat2 as i32)])
            .unwrap();
        event.object_resolution.quality = ObjectResolutionQuality::KernelResolved;
        event.object_resolution.authority = ObjectResolutionAuthority::KernelObjectHook;
        assert!(event.validate_object_resolution().is_err());

        event.object_resolution.quality = ObjectResolutionQuality::UserInputOnly;
        event.object_resolution.authority = ObjectResolutionAuthority::SyscallEntryUserMemory;
        event.object_resolution.operation_attempt_seq += 1;
        assert!(event.validate_object_resolution().is_err());
    }

    #[test]
    fn resolved_identity_variants_enforce_stable_fields() {
        let policies =
            crate::policy::event_policy_identities(crate::policy::PolicyProfile::Balanced).unwrap();
        let mut raw = fixture();
        raw.kind = EVENT_OPERATION_RESULT;
        raw.flags = 0;
        raw.event_seq = 12;
        raw.related_attempt_seq = 11;
        raw.payload_lens = [0; 2];
        raw.payload_kinds = [PAYLOAD_NONE; 2];
        raw.payload_arg_indices = [0; 2];
        raw.payloads = [[0; CAPTURE_BYTES]; 2];
        let mut event = raw
            .to_schema("run", BOOT_ID, policies[&(libc::SYS_renameat2 as i32)])
            .unwrap();
        event.object_resolution.quality = ObjectResolutionQuality::KernelResolved;
        event.object_resolution.authority = ObjectResolutionAuthority::KernelObjectHook;
        event.object_resolution.objects = vec![ObjectReference {
            slot: 0,
            role: ObjectRole::Peer,
            identity: ObjectIdentity::FileObject {
                boot_id: "00000000-0000-0000-0000-000000000001".to_owned(),
                mount_id_unique: 1,
                device_major: 0,
                device_minor: 1,
                inode: 2,
                inode_generation: Some(3),
                filesystem_magic: 0x9fa0,
                filesystem_class: FilesystemClass::Sysfs,
                path: FilePathObservation::default(),
            },
        }];
        assert!(event.validate_object_resolution().is_err());

        event.object_resolution.objects = vec![ObjectReference {
            slot: 0,
            role: ObjectRole::Primary,
            identity: ObjectIdentity::SocketObject {
                boot_id: "00000000-0000-0000-0000-000000000001".to_owned(),
                network_namespace_cookie: 1,
                socket_cookie: 0,
                address_family: libc::AF_INET as u32,
                socket_type: libc::SOCK_STREAM as u32,
                protocol: 0,
                endpoint_address_family: libc::AF_INET as u32,
                endpoints: SocketEndpointPair::default(),
            },
        }];
        assert!(event.validate_object_resolution().is_err());
    }

    #[test]
    fn resolved_path_requires_bounded_kernel_snapshot_authority() {
        let policies =
            crate::policy::event_policy_identities(crate::policy::PolicyProfile::Balanced).unwrap();
        let raw = file_open_result();
        let mut event = raw
            .to_schema("run", BOOT_ID, policies[&(libc::SYS_openat as i32)])
            .unwrap();
        event.object_resolution.quality = ObjectResolutionQuality::KernelResolved;
        event.object_resolution.authority = ObjectResolutionAuthority::KernelObjectHook;
        event.object_resolution.objects = vec![ObjectReference {
            slot: 0,
            role: ObjectRole::Primary,
            identity: ObjectIdentity::FileObject {
                boot_id: "00000000-0000-0000-0000-000000000001".to_owned(),
                mount_id_unique: 1,
                device_major: 0,
                device_minor: 1,
                inode: 2,
                inode_generation: Some(3),
                filesystem_magic: 0x9fa0,
                filesystem_class: FilesystemClass::Procfs,
                path: FilePathObservation {
                    quality: PathResolutionQuality::ResolvedAtHook,
                    authority: PathResolutionAuthority::KernelPathSnapshot,
                    resolved_path: Some(ResolvedPath {
                        display: "/proc/self/status".to_owned(),
                        raw_hex: hex(b"/proc/self/status"),
                    }),
                },
            },
        }];
        assert!(event.validate_object_resolution().is_ok());

        if let ObjectIdentity::FileObject { path, .. } =
            &mut event.object_resolution.objects[0].identity
        {
            path.authority = PathResolutionAuthority::None;
        }
        assert!(event.validate_object_resolution().is_err());
    }

    #[test]
    fn resolved_socket_endpoint_cannot_be_sourced_from_user_sockaddr() {
        let policies =
            crate::policy::event_policy_identities(crate::policy::PolicyProfile::Balanced).unwrap();
        let mut raw = fixture();
        raw.kind = EVENT_OPERATION_RESULT;
        raw.flags = 0;
        raw.domain = EffectDomain::Network as u16;
        raw.operation = EffectOperation::SocketConnect as u32;
        raw.syscall_nr = libc::SYS_connect as i32;
        raw.event_seq = 12;
        raw.related_attempt_seq = 11;
        raw.payload_lens = [0; 2];
        raw.payload_kinds = [PAYLOAD_NONE; 2];
        raw.payload_arg_indices = [0; 2];
        raw.payloads = [[0; CAPTURE_BYTES]; 2];
        let mut event = raw
            .to_schema("run", BOOT_ID, policies[&(libc::SYS_connect as i32)])
            .unwrap();
        event.object_resolution.quality = ObjectResolutionQuality::KernelResolved;
        event.object_resolution.authority = ObjectResolutionAuthority::KernelObjectHook;
        event.object_resolution.objects = vec![ObjectReference {
            slot: 0,
            role: ObjectRole::Peer,
            identity: ObjectIdentity::SocketObject {
                boot_id: "00000000-0000-0000-0000-000000000001".to_owned(),
                network_namespace_cookie: 1,
                socket_cookie: 2,
                address_family: libc::AF_INET as u32,
                socket_type: libc::SOCK_STREAM as u32,
                protocol: libc::IPPROTO_TCP as u32,
                endpoint_address_family: libc::AF_INET as u32,
                endpoints: SocketEndpointPair {
                    local: SocketEndpointObservation::default(),
                    peer: SocketEndpointObservation {
                        quality: SocketEndpointQuality::KernelResolved,
                        authority: SocketEndpointAuthority::KernelSocketState,
                        address: Some(SocketEndpointAddress::Inet4 {
                            address: [127, 0, 0, 1],
                            port: 12345,
                        }),
                    },
                },
            },
        }];
        assert!(event.validate_object_resolution().is_ok());

        if let ObjectIdentity::SocketObject { endpoints, .. } =
            &mut event.object_resolution.objects[0].identity
        {
            endpoints.peer.authority = SocketEndpointAuthority::None;
        }
        assert!(event.validate_object_resolution().is_err());
    }

    #[test]
    fn socket_and_sockaddr_families_are_not_conflated_for_unspec_disconnect() {
        let policies =
            crate::policy::event_policy_identities(crate::policy::PolicyProfile::Balanced).unwrap();
        let mut raw = fixture();
        raw.kind = EVENT_OPERATION_RESULT;
        raw.flags = 0;
        raw.domain = EffectDomain::Network as u16;
        raw.operation = EffectOperation::SocketConnect as u32;
        raw.syscall_nr = libc::SYS_connect as i32;
        raw.event_seq = 12;
        raw.related_attempt_seq = 11;
        raw.payload_lens = [0; 2];
        raw.payload_kinds = [PAYLOAD_NONE; 2];
        raw.payload_arg_indices = [0; 2];
        raw.payloads = [[0; CAPTURE_BYTES]; 2];
        raw.socket_object = Some(KernelSocketObject {
            network_namespace_cookie: 1,
            socket_cookie: 2,
            address_family: libc::AF_INET as u32,
            socket_type: libc::SOCK_DGRAM as u32,
            protocol: libc::IPPROTO_UDP as u32,
            endpoint_address_family: libc::AF_UNSPEC as u32,
            endpoint_len: 2,
            endpoint_role: 2,
            endpoint_quality: 1,
            endpoint: [0; MAX_SOCKET_ENDPOINT_BYTES],
            endpoint_authority: SOCKET_ENDPOINT_AUTHORITY_LSM_ARGUMENT,
        });
        let encoded = raw.encode_le();
        let decoded = KernelEvent::decode_le(&encoded).unwrap();
        let event = decoded
            .to_schema("run", BOOT_ID, policies[&(libc::SYS_connect as i32)])
            .unwrap();
        let ObjectIdentity::SocketObject {
            address_family,
            endpoint_address_family,
            endpoints,
            ..
        } = &event.object_resolution.objects[0].identity
        else {
            panic!("expected socket object");
        };
        assert_eq!(*address_family, libc::AF_INET as u32);
        assert_eq!(*endpoint_address_family, libc::AF_UNSPEC as u32);
        assert!(matches!(
            endpoints.peer.address,
            Some(SocketEndpointAddress::Other {
                address_family: 0,
                ..
            })
        ));
    }

    #[test]
    fn accepted_tcp_peer_round_trips_as_post_accept_kernel_state() {
        let policies =
            crate::policy::event_policy_identities(crate::policy::PolicyProfile::Control).unwrap();
        let mut raw = fixture();
        raw.kind = EVENT_OPERATION_RESULT;
        raw.flags = 0;
        raw.domain = EffectDomain::Network as u16;
        raw.operation = EffectOperation::SocketAccept as u32;
        raw.syscall_nr = libc::SYS_accept4 as i32;
        raw.event_seq = 12;
        raw.related_attempt_seq = 11;
        raw.return_value = 7;
        raw.payload_lens = [0; 2];
        raw.payload_kinds = [PAYLOAD_NONE; 2];
        raw.payload_arg_indices = [0; 2];
        raw.payloads = [[0; CAPTURE_BYTES]; 2];
        let mut endpoint = [0; MAX_SOCKET_ENDPOINT_BYTES];
        endpoint[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        endpoint[2..4].copy_from_slice(&443u16.to_be_bytes());
        endpoint[4..8].copy_from_slice(&[192, 0, 2, 9]);
        raw.socket_object = Some(KernelSocketObject {
            network_namespace_cookie: 1,
            socket_cookie: 2,
            address_family: libc::AF_INET as u32,
            socket_type: libc::SOCK_STREAM as u32,
            protocol: libc::IPPROTO_TCP as u32,
            endpoint_address_family: libc::AF_INET as u32,
            endpoint_len: 16,
            endpoint_role: 2,
            endpoint_quality: 1,
            endpoint,
            endpoint_authority: SOCKET_ENDPOINT_AUTHORITY_KERNEL_STATE,
        });
        let decoded = KernelEvent::decode_le(&raw.encode_le()).unwrap();
        let projected = decoded
            .to_schema("run", BOOT_ID, policies[&(libc::SYS_accept4 as i32)])
            .unwrap();
        assert_eq!(
            projected.object_resolution.quality,
            ObjectResolutionQuality::KernelResolved
        );
        assert_eq!(
            projected.object_resolution.objects[0].role,
            ObjectRole::Peer
        );
        let ObjectIdentity::SocketObject { endpoints, .. } =
            &projected.object_resolution.objects[0].identity
        else {
            panic!("expected accepted socket identity");
        };
        assert_eq!(
            endpoints.peer.authority,
            SocketEndpointAuthority::KernelSocketState
        );
        assert_eq!(
            endpoints.peer.address,
            Some(SocketEndpointAddress::Inet4 {
                address: [192, 0, 2, 9],
                port: 443,
            })
        );
    }

    #[test]
    fn unsupported_successful_accept_is_explicitly_unresolved() {
        let mut raw = fixture();
        raw.kind = EVENT_OPERATION_RESULT;
        raw.flags = FLAG_OBJECT_UNSUPPORTED;
        raw.domain = EffectDomain::Network as u16;
        raw.operation = EffectOperation::SocketAccept as u32;
        raw.syscall_nr = libc::SYS_accept as i32;
        raw.event_seq = 12;
        raw.related_attempt_seq = 11;
        raw.return_value = 7;
        raw.payload_lens = [0; 2];
        raw.payload_kinds = [PAYLOAD_NONE; 2];
        raw.payload_arg_indices = [0; 2];
        raw.payloads = [[0; CAPTURE_BYTES]; 2];
        assert!(KernelEvent::decode_le(&raw.encode_le()).is_ok());
        raw.return_value = -libc::EAGAIN as i64;
        assert!(KernelEvent::decode_le(&raw.encode_le()).is_err());
    }

    #[test]
    fn closed_object_schema_rejects_unknown_fields() {
        let json = r#"{
            "kind":"SOCKET_OBJECT",
            "boot_id":"boot",
            "network_namespace_cookie":1,
            "socket_cookie":2,
            "address_family":2,
            "socket_type":1,
            "protocol":0,
            "kernel_pointer":123
        }"#;
        assert!(serde_json::from_str::<ObjectIdentity>(json).is_err());
    }

    #[test]
    fn legacy_json_is_readable_but_cannot_pass_v1_1_validation() {
        let policies =
            crate::policy::event_policy_identities(crate::policy::PolicyProfile::Balanced).unwrap();
        let event = fixture()
            .to_schema("run", BOOT_ID, policies[&(libc::SYS_renameat2 as i32)])
            .unwrap();
        let mut value = serde_json::to_value(event).unwrap();
        value.as_object_mut().unwrap().remove("object_resolution");
        let legacy = serde_json::from_value::<SystemEffectEvent>(value).unwrap();
        assert_eq!(legacy.object_resolution.protocol_version, 0);
        assert!(legacy.validate_object_resolution().is_err());
    }

    #[test]
    fn attribution_is_direct_entry_time_cgroup_evidence_not_causality() {
        let policies =
            crate::policy::event_policy_identities(crate::policy::PolicyProfile::Balanced).unwrap();
        let event = fixture()
            .to_schema("run", BOOT_ID, policies[&(libc::SYS_renameat2 as i32)])
            .unwrap();
        assert_eq!(
            event.attribution.protocol_version,
            EFFECT_ATTRIBUTION_PROTOCOL_VERSION
        );
        assert_eq!(event.attribution.mode, EffectAttributionMode::Direct);
        assert_eq!(
            event.attribution.authority,
            EffectAttributionAuthority::KernelCurrentCgroupIdAtSyscallEntry
        );
        assert_eq!(
            event.attribution.subject,
            EffectAttributionSubject::RunExecutionDomain
        );
        assert_eq!(
            event.attribution.component,
            EffectAttributionComponent::UnclassifiedCgroupMember
        );
        assert_eq!(
            event.attribution.delegated_effects,
            DelegatedEffectsStatus::NotObserved
        );
        assert_eq!(
            event.attribution.causal_status,
            EffectCausalStatus::CausalNotEstablished
        );
        assert_eq!(
            event.attribution.cgroup_id_at_syscall_entry,
            event.cgroup_id
        );
        assert_eq!(event.attribution.source_event_seq, event.event_seq);
        assert_eq!(event.attribution.operation_attempt_seq, event.event_seq);
        event.validate_attribution().unwrap();
        AttributionContract::direct_v1().validate().unwrap();
    }

    #[test]
    fn attribution_rejects_missing_or_forged_authority_and_correlation() {
        let policies =
            crate::policy::event_policy_identities(crate::policy::PolicyProfile::Balanced).unwrap();
        let event = fixture()
            .to_schema("run", BOOT_ID, policies[&(libc::SYS_renameat2 as i32)])
            .unwrap();

        let mut missing = serde_json::to_value(&event).unwrap();
        missing.as_object_mut().unwrap().remove("attribution");
        let missing = serde_json::from_value::<SystemEffectEvent>(missing).unwrap();
        assert_eq!(missing.attribution.protocol_version, 0);
        assert!(missing.validate_attribution().is_err());

        for (field, forged) in [
            ("mode", "DELEGATED"),
            ("authority", "BROKER_ASSERTION"),
            ("causal_status", "CAUSAL_ESTABLISHED"),
        ] {
            let mut value = serde_json::to_value(&event).unwrap();
            value["attribution"][field] = serde_json::Value::String(forged.to_owned());
            assert!(serde_json::from_value::<SystemEffectEvent>(value).is_err());
        }

        let mut forged_sequence = event;
        forged_sequence.attribution.operation_attempt_seq += 1;
        assert!(forged_sequence.validate_attribution().is_err());

        let mut forged_contract = AttributionContract::direct_v1();
        forged_contract.protocol_version += 1;
        assert!(forged_contract.validate().is_err());
    }

    #[test]
    fn async_connect_is_not_reported_as_no_effect_failure() {
        assert_eq!(
            classify_result(EffectOperation::SocketConnect, -(libc::EINPROGRESS as i64)),
            ResultStatus::AsyncPending
        );
        assert_eq!(
            classify_result(EffectOperation::BpfCommand, -(libc::EINPROGRESS as i64)),
            ResultStatus::ReturnedError
        );
    }

    #[test]
    fn result_rejects_entry_payload_metadata_and_flags() {
        let mut event = fixture();
        event.kind = EVENT_OPERATION_RESULT;
        event.event_seq = 12;
        event.related_attempt_seq = 11;
        event.return_value = 0;
        assert!(event.validate().is_err());

        event.payload_lens = [0, 0];
        event.payload_kinds = [PAYLOAD_NONE; 2];
        event.payload_arg_indices = [0, 0];
        event.flags = FLAG_USER_MEMORY_SNAPSHOT;
        assert!(event.validate().is_err());
    }

    #[test]
    fn attempt_rejects_capture_flags_without_capture_metadata() {
        let mut event = fixture();
        event.payload_lens = [0, 0];
        event.payload_kinds = [PAYLOAD_NONE; 2];
        event.payload_arg_indices = [0, 0];
        event.flags = FLAG_PAYLOAD1_READ_FAILED;
        assert!(event.validate().is_err());
    }

    #[test]
    fn invalid_sockaddr_length_is_not_reported_as_captured() {
        let policies =
            crate::policy::event_policy_identities(crate::policy::PolicyProfile::Balanced).unwrap();
        let mut event = fixture();
        event.domain = EffectDomain::Network as u16;
        event.operation = EffectOperation::SocketConnect as u32;
        event.syscall_nr = libc::SYS_connect as i32;
        event.flags = FLAG_USER_MEMORY_SNAPSHOT | FLAG_PAYLOAD1_INVALID_LENGTH;
        event.payload_lens = [0, 0];
        event.payload_kinds = [PAYLOAD_SOCKADDR, PAYLOAD_NONE];
        event.payload_arg_indices = [1, 0];

        let schema = event
            .to_schema("run", BOOT_ID, policies[&(libc::SYS_connect as i32)])
            .unwrap();
        assert_eq!(schema.captures[0].status, CaptureStatus::InvalidLength);
        assert_eq!(schema.captures[0].display, None);
        assert_eq!(schema.captures[0].raw_hex, None);
    }
}
