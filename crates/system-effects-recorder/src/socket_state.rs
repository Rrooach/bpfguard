// SPDX-License-Identifier: GPL-2.0-only

//! Closed accepted-socket/TCP-state evidence ABI and offline replay.
//!
//! TCP state transitions are asynchronous kernel events.  They intentionally
//! use a stream separate from syscall attempt/result evidence and retain the
//! immutable syscall-entry identity which introduced the socket-cookie owner.

use crate::{
    policy::{EffectDomain, EffectOperation},
    protocol::{CgroupMatchMode, KernelEvent, EVENT_OPERATION_ATTEMPT},
    wal,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, ErrorKind, Read, Write};
use std::os::raw::c_int;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::slice;

pub const SOCKET_STATE_SCHEMA_VERSION: u32 = 2;
pub const SOCKET_STATE_ASYNC_PRODUCER_LINKS: u32 = 2;
pub const KERNEL_SOCKET_STATE_EVENT_SIZE: usize = 152;
pub const MAX_SOCKET_STATE_WAL_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_SOCKET_STATE_EVENTS: usize = 1_000_000;
pub const SOCKET_STATE_WAL_NAME: &str = "socket-state.raw.bin";
pub const SOCKET_STATE_JSONL_NAME: &str = "socket-state.jsonl";
pub const SOCKET_STATE_HEALTH_NAME: &str = "socket-state.health.json";

pub const SOCKET_STATE_ACCEPT_SNAPSHOT: u16 = 1;
pub const SOCKET_STATE_TRANSITION: u16 = 2;
pub const SOCKET_STATE_DESTROY: u16 = 3;
pub const SOCKET_STATE_F_OWNER_PROVISIONAL: u16 = 1 << 0;
const KNOWN_SOCKET_STATE_FLAGS: u16 = SOCKET_STATE_F_OWNER_PROVISIONAL;

const MAX_SOCKET_STATE_JSONL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SOCKET_STATE_JSON_BYTES: usize = 64 * 1024;
const MAX_SOCKET_STATE_CALLBACK_QUEUE_EVENTS: usize = 4_096;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct SocketStateRunState {
    pub epoch: u64,
    pub next_event_seq: u64,
    pub event_attempted: u64,
    pub event_published: u64,
    pub event_dropped: u64,
    pub owner_insert_failed: u64,
    pub owner_conflict: u64,
    pub owner_delete_failed: u64,
    /// Kernel ownership count at producer detach. Userspace retirement does
    /// not rewrite this counter; COMPLETE requires it to equal the retired
    /// Map-entry count below.
    pub owner_remaining: u64,
    pub state_read_failed: u64,
    pub unsupported_sockets: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelSocketStateEvent {
    pub schema_version: u32,
    pub kind: u16,
    pub flags: u16,
    pub run_epoch: u64,
    pub event_seq: u64,
    pub ktime_ns: u64,
    pub cgroup_id: u64,
    pub origin_attempt_seq: u64,
    pub origin_pid_tgid: u64,
    pub origin_task_start_boottime_ns: u64,
    pub socket_cookie: u64,
    pub network_namespace_cookie: u64,
    pub address_family: u32,
    pub socket_type: u32,
    pub protocol: u32,
    pub old_state: u32,
    pub new_state: u32,
    pub origin_operation: u32,
    pub local_port: u16,
    pub peer_port: u16,
    pub local_address: [u8; 16],
    pub peer_address: [u8; 16],
}

impl KernelSocketStateEvent {
    pub fn decode_native(bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes, Endian::Native)
    }

    pub fn decode_le(bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes, Endian::Little)
    }

    fn decode(bytes: &[u8], endian: Endian) -> Result<Self> {
        if bytes.len() != KERNEL_SOCKET_STATE_EVENT_SIZE {
            bail!(
                "socket-state event has {} bytes, expected {KERNEL_SOCKET_STATE_EVENT_SIZE}",
                bytes.len()
            );
        }
        if bytes[140..152].iter().any(|byte| *byte != 0) {
            bail!("socket-state event has a nonzero reserved tail");
        }
        let mut local_address = [0u8; 16];
        local_address.copy_from_slice(&bytes[108..124]);
        let mut peer_address = [0u8; 16];
        peer_address.copy_from_slice(&bytes[124..140]);
        let event = Self {
            schema_version: endian.u32(&bytes[0..4]),
            kind: endian.u16(&bytes[4..6]),
            flags: endian.u16(&bytes[6..8]),
            run_epoch: endian.u64(&bytes[8..16]),
            event_seq: endian.u64(&bytes[16..24]),
            ktime_ns: endian.u64(&bytes[24..32]),
            cgroup_id: endian.u64(&bytes[32..40]),
            origin_attempt_seq: endian.u64(&bytes[40..48]),
            origin_pid_tgid: endian.u64(&bytes[48..56]),
            origin_task_start_boottime_ns: endian.u64(&bytes[56..64]),
            socket_cookie: endian.u64(&bytes[64..72]),
            network_namespace_cookie: endian.u64(&bytes[72..80]),
            address_family: endian.u32(&bytes[80..84]),
            socket_type: endian.u32(&bytes[84..88]),
            protocol: endian.u32(&bytes[88..92]),
            old_state: endian.u32(&bytes[92..96]),
            new_state: endian.u32(&bytes[96..100]),
            origin_operation: endian.u32(&bytes[100..104]),
            local_port: endian.u16(&bytes[104..106]),
            peer_port: endian.u16(&bytes[106..108]),
            local_address,
            peer_address,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn encode_le(&self) -> [u8; KERNEL_SOCKET_STATE_EVENT_SIZE] {
        let mut bytes = [0u8; KERNEL_SOCKET_STATE_EVENT_SIZE];
        bytes[0..4].copy_from_slice(&self.schema_version.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.kind.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.flags.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.run_epoch.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.event_seq.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.ktime_ns.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.cgroup_id.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.origin_attempt_seq.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.origin_pid_tgid.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.origin_task_start_boottime_ns.to_le_bytes());
        bytes[64..72].copy_from_slice(&self.socket_cookie.to_le_bytes());
        bytes[72..80].copy_from_slice(&self.network_namespace_cookie.to_le_bytes());
        bytes[80..84].copy_from_slice(&self.address_family.to_le_bytes());
        bytes[84..88].copy_from_slice(&self.socket_type.to_le_bytes());
        bytes[88..92].copy_from_slice(&self.protocol.to_le_bytes());
        bytes[92..96].copy_from_slice(&self.old_state.to_le_bytes());
        bytes[96..100].copy_from_slice(&self.new_state.to_le_bytes());
        bytes[100..104].copy_from_slice(&self.origin_operation.to_le_bytes());
        bytes[104..106].copy_from_slice(&self.local_port.to_le_bytes());
        bytes[106..108].copy_from_slice(&self.peer_port.to_le_bytes());
        bytes[108..124].copy_from_slice(&self.local_address);
        bytes[124..140].copy_from_slice(&self.peer_address);
        bytes
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SOCKET_STATE_SCHEMA_VERSION {
            bail!(
                "unsupported socket-state schema version {}",
                self.schema_version
            );
        }
        if self.flags & !KNOWN_SOCKET_STATE_FLAGS != 0 {
            bail!("socket-state event has unknown flags");
        }
        if self.run_epoch == 0
            || self.event_seq == 0
            || self.ktime_ns == 0
            || self.cgroup_id == 0
            || self.origin_attempt_seq == 0
            || self.origin_pid_tgid == 0
            || self.origin_task_start_boottime_ns == 0
            || self.socket_cookie == 0
            || self.network_namespace_cookie == 0
        {
            bail!("socket-state event has a zero stable identity field");
        }
        if !matches!(self.address_family as i32, libc::AF_INET | libc::AF_INET6)
            || self.socket_type != libc::SOCK_STREAM as u32
            || self.protocol != libc::IPPROTO_TCP as u32
        {
            bail!("socket-state event is outside the AF_INET/AF_INET6 TCP contract");
        }
        if !matches!(
            EffectOperation::from_raw(self.origin_operation),
            Some(
                EffectOperation::SocketConnect
                    | EffectOperation::SocketBind
                    | EffectOperation::SocketAccept
            )
        ) {
            bail!("socket-state event has an ineligible owner operation");
        }
        if self.address_family as i32 == libc::AF_INET
            && (self.local_address[4..].iter().any(|byte| *byte != 0)
                || self.peer_address[4..].iter().any(|byte| *byte != 0))
        {
            bail!("IPv4 socket-state event has a nonzero address tail");
        }
        let valid_state = |state: u32| (1..=12).contains(&state);
        match self.kind {
            SOCKET_STATE_ACCEPT_SNAPSHOT
                if self.old_state == 0 && valid_state(self.new_state) && self.flags == 0 => {}
            SOCKET_STATE_TRANSITION
                if valid_state(self.old_state) && valid_state(self.new_state) => {}
            SOCKET_STATE_DESTROY
                if valid_state(self.old_state) && self.new_state == 0 && self.flags == 0 => {}
            _ => bail!("socket-state kind, state pair, and flags disagree"),
        }
        Ok(())
    }

    pub fn to_schema(
        &self,
        run_id: &str,
        boot_id: &str,
        cgroup_match_mode: CgroupMatchMode,
    ) -> Result<SocketStateEvent> {
        self.validate()?;
        validate_boot_id(boot_id)?;
        if run_id.is_empty() || run_id.contains('\0') {
            bail!("run_id must be nonempty and contain no NUL bytes");
        }
        Ok(SocketStateEvent {
            schema_version: SOCKET_STATE_SCHEMA_VERSION,
            kind: match self.kind {
                SOCKET_STATE_ACCEPT_SNAPSHOT => SocketStateEventKind::AcceptSnapshot,
                SOCKET_STATE_TRANSITION => SocketStateEventKind::Transition,
                SOCKET_STATE_DESTROY => SocketStateEventKind::Destroy,
                _ => unreachable!("validated above"),
            },
            flags: SocketStateEventFlags {
                owner_provisional: self.flags & SOCKET_STATE_F_OWNER_PROVISIONAL != 0,
            },
            run_id: run_id.to_owned(),
            run_epoch: self.run_epoch,
            event_seq: self.event_seq,
            ktime_ns: self.ktime_ns,
            cgroup_id: self.cgroup_id,
            attribution: SocketStateAttribution {
                authority: SocketStateAttributionAuthority::SocketCookieOwnerFromSyscallEntry,
                cgroup_match_mode,
                boot_id: boot_id.to_owned(),
                origin_attempt_seq: self.origin_attempt_seq,
                origin_pid: self.origin_pid_tgid as u32,
                origin_tgid: (self.origin_pid_tgid >> 32) as u32,
                origin_task_start_boottime_ns: self.origin_task_start_boottime_ns,
                origin_operation: EffectOperation::from_raw(self.origin_operation)
                    .context("validated socket-state operation disappeared")?,
            },
            socket: SocketStateIdentity {
                boot_id: boot_id.to_owned(),
                socket_cookie: self.socket_cookie,
                network_namespace_cookie: self.network_namespace_cookie,
                address_family: self.address_family,
                socket_type: self.socket_type,
                protocol: self.protocol,
                local: SocketStateEndpoint {
                    address: socket_address(self.address_family, self.local_address),
                    port: self.local_port,
                },
                peer: SocketStateEndpoint {
                    address: socket_address(self.address_family, self.peer_address),
                    port: self.peer_port,
                },
            },
            old_state: (self.old_state != 0).then_some(self.old_state),
            new_state: (self.new_state != 0).then_some(self.new_state),
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SocketStateEventKind {
    AcceptSnapshot,
    Transition,
    Destroy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SocketStateEventFlags {
    pub owner_provisional: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SocketStateAttributionAuthority {
    SocketCookieOwnerFromSyscallEntry,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SocketStateAttribution {
    pub authority: SocketStateAttributionAuthority,
    pub cgroup_match_mode: CgroupMatchMode,
    pub boot_id: String,
    pub origin_attempt_seq: u64,
    pub origin_pid: u32,
    pub origin_tgid: u32,
    pub origin_task_start_boottime_ns: u64,
    pub origin_operation: EffectOperation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SocketStateEndpoint {
    /// Network-byte-order address bytes, four bytes for IPv4 and sixteen for IPv6.
    pub address: Vec<u8>,
    /// Host-order TCP port. Zero is retained when the endpoint was not assigned.
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SocketStateIdentity {
    pub boot_id: String,
    pub socket_cookie: u64,
    pub network_namespace_cookie: u64,
    pub address_family: u32,
    pub socket_type: u32,
    pub protocol: u32,
    pub local: SocketStateEndpoint,
    pub peer: SocketStateEndpoint,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SocketStateEvent {
    pub schema_version: u32,
    pub kind: SocketStateEventKind,
    pub flags: SocketStateEventFlags,
    pub run_id: String,
    pub run_epoch: u64,
    pub event_seq: u64,
    pub ktime_ns: u64,
    pub cgroup_id: u64,
    pub attribution: SocketStateAttribution,
    pub socket: SocketStateIdentity,
    pub old_state: Option<u32>,
    pub new_state: Option<u32>,
}

fn socket_address(family: u32, address: [u8; 16]) -> Vec<u8> {
    if family as i32 == libc::AF_INET {
        address[..4].to_vec()
    } else {
        address.to_vec()
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

    fn u64(self, bytes: &[u8]) -> u64 {
        match self {
            Self::Native => u64::from_ne_bytes(bytes.try_into().unwrap()),
            Self::Little => u64::from_le_bytes(bytes.try_into().unwrap()),
        }
    }
}

pub(crate) struct SocketStateWalWriter {
    writer: BufWriter<File>,
}

impl SocketStateWalWriter {
    fn create(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("create socket-state WAL {}", path.display()))?;
        Ok(Self {
            writer: BufWriter::new(file),
        })
    }

    fn append(&mut self, event: &KernelSocketStateEvent) -> Result<()> {
        let payload = event.encode_le();
        self.writer
            .write_all(&(KERNEL_SOCKET_STATE_EVENT_SIZE as u32).to_le_bytes())?;
        self.writer.write_all(&payload)?;
        self.writer
            .write_all(&crc32fast::hash(&payload).to_le_bytes())?;
        Ok(())
    }

    fn sync(&mut self) -> Result<()> {
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketStateWalRecovery {
    pub events: Vec<KernelSocketStateEvent>,
    pub truncated_tail: bool,
}

pub fn recover_socket_state_wal(path: &Path) -> Result<SocketStateWalRecovery> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open socket-state WAL {}", path.display()))?;
    let before = file.metadata()?;
    if !before.file_type().is_file() || before.nlink() != 1 {
        bail!("socket-state WAL must be a singly linked regular file");
    }
    if before.len() > MAX_SOCKET_STATE_WAL_BYTES {
        bail!("socket-state WAL exceeds its recovery byte limit");
    }
    let recovery = recover_socket_state_reader(&mut file)?;
    let after = file.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        bail!("socket-state WAL changed while it was recovered");
    }
    Ok(recovery)
}

pub fn recover_socket_state_reader(reader: impl Read) -> Result<SocketStateWalRecovery> {
    let mut reader = BufReader::new(reader);
    let mut events = Vec::new();
    let mut consumed = 0u64;
    loop {
        let mut length_bytes = [0u8; 4];
        match read_part(&mut reader, &mut length_bytes)? {
            ReadPart::Eof => {
                return Ok(SocketStateWalRecovery {
                    events,
                    truncated_tail: false,
                })
            }
            ReadPart::Truncated => {
                return Ok(SocketStateWalRecovery {
                    events,
                    truncated_tail: true,
                })
            }
            ReadPart::Complete => {}
        }
        let length = u32::from_le_bytes(length_bytes) as usize;
        if length != KERNEL_SOCKET_STATE_EVENT_SIZE {
            bail!("unsupported socket-state WAL frame length {length}");
        }
        consumed = consumed
            .checked_add(8 + length as u64)
            .context("socket-state WAL byte count overflow")?;
        if consumed > MAX_SOCKET_STATE_WAL_BYTES || events.len() >= MAX_SOCKET_STATE_EVENTS {
            bail!("socket-state WAL exceeds its bounded recovery limits");
        }
        let mut payload = [0u8; KERNEL_SOCKET_STATE_EVENT_SIZE];
        if read_part(&mut reader, &mut payload)? != ReadPart::Complete {
            return Ok(SocketStateWalRecovery {
                events,
                truncated_tail: true,
            });
        }
        let mut checksum = [0u8; 4];
        if read_part(&mut reader, &mut checksum)? != ReadPart::Complete {
            return Ok(SocketStateWalRecovery {
                events,
                truncated_tail: true,
            });
        }
        if crc32fast::hash(&payload) != u32::from_le_bytes(checksum) {
            bail!("socket-state WAL checksum mismatch");
        }
        events.push(KernelSocketStateEvent::decode_le(&payload)?);
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

#[derive(Default)]
pub(crate) struct SocketStateCallbackState {
    queue: VecDeque<KernelSocketStateEvent>,
    decode_failures: u64,
    capacity_failures: u64,
    accepted_events: u64,
    queue_high_water: usize,
    batch_limit_reached: bool,
}

fn enqueue_socket_state_event(
    state: &mut SocketStateCallbackState,
    event: KernelSocketStateEvent,
) -> c_int {
    if state.queue.len() >= MAX_SOCKET_STATE_CALLBACK_QUEUE_EVENTS
        || state.accepted_events >= MAX_SOCKET_STATE_EVENTS as u64
    {
        state.capacity_failures = state.capacity_failures.saturating_add(1);
        return -libc::EFBIG;
    }
    state.queue.push_back(event);
    state.accepted_events = state.accepted_events.saturating_add(1);
    state.queue_high_water = state.queue_high_water.max(state.queue.len());
    if state.queue.len() == MAX_SOCKET_STATE_CALLBACK_QUEUE_EVENTS {
        state.batch_limit_reached = true;
        -libc::EAGAIN
    } else {
        0
    }
}

pub(crate) unsafe extern "C" fn receive_socket_state_event(
    context: *mut c_void,
    data: *mut c_void,
    size: u64,
) -> c_int {
    if context.is_null() || data.is_null() {
        return -libc::EINVAL;
    }
    let state = &mut *(context as *mut SocketStateCallbackState);
    let Ok(size) = usize::try_from(size) else {
        state.decode_failures = state.decode_failures.saturating_add(1);
        return -libc::EBADMSG;
    };
    let bytes = slice::from_raw_parts(data.cast::<u8>(), size);
    let Ok(event) = KernelSocketStateEvent::decode_native(bytes) else {
        state.decode_failures = state.decode_failures.saturating_add(1);
        return -libc::EBADMSG;
    };
    enqueue_socket_state_event(state, event)
}

pub(crate) struct SocketStateOutputs {
    callback: Box<SocketStateCallbackState>,
    wal: SocketStateWalWriter,
    jsonl: BufWriter<File>,
    jsonl_bytes: u64,
    persisted: HashMap<(u64, u64), u64>,
    sequences: HashMap<(u64, u64), BTreeSet<u64>>,
    destroy_events: HashMap<(u64, u64), u64>,
    cgroup_match_modes: HashMap<(u64, u64), CgroupMatchMode>,
    routing_failures: u64,
    run_id: String,
    boot_id: String,
}

impl SocketStateOutputs {
    pub(crate) fn create(output_dir: &Path, run_id: &str, boot_id: &str) -> Result<Self> {
        validate_boot_id(boot_id)?;
        let wal = SocketStateWalWriter::create(&output_dir.join(SOCKET_STATE_WAL_NAME))?;
        let jsonl = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(output_dir.join(SOCKET_STATE_JSONL_NAME))
            .context("create socket-state JSONL")?;
        Ok(Self {
            callback: Box::default(),
            wal,
            jsonl: BufWriter::new(jsonl),
            jsonl_bytes: 0,
            persisted: HashMap::new(),
            sequences: HashMap::new(),
            destroy_events: HashMap::new(),
            cgroup_match_modes: HashMap::new(),
            routing_failures: 0,
            run_id: run_id.to_owned(),
            boot_id: boot_id.to_owned(),
        })
    }

    pub(crate) fn callback_context(&mut self) -> *mut c_void {
        (&mut *self.callback as *mut SocketStateCallbackState).cast()
    }

    pub(crate) fn reset_callback_batch_limit(&mut self) {
        self.callback.batch_limit_reached = false;
    }

    pub(crate) fn callback_batch_limit_reached(&self) -> bool {
        self.callback.batch_limit_reached
    }

    pub(crate) fn register_run(
        &mut self,
        cgroup_id: u64,
        epoch: u64,
        cgroup_match_mode: CgroupMatchMode,
    ) -> Result<()> {
        let key = (cgroup_id, epoch);
        if self.persisted.insert(key, 0).is_some()
            || self.sequences.insert(key, BTreeSet::new()).is_some()
            || self.destroy_events.insert(key, 0).is_some()
            || self
                .cgroup_match_modes
                .insert(key, cgroup_match_mode)
                .is_some()
        {
            bail!("socket-state run is already registered");
        }
        Ok(())
    }

    pub(crate) fn persist_queued(&mut self) -> Result<usize> {
        let mut count = 0;
        while let Some(event) = self.callback.queue.pop_front() {
            let key = (event.cgroup_id, event.run_epoch);
            let Some(persisted) = self.persisted.get_mut(&key) else {
                self.routing_failures = self.routing_failures.saturating_add(1);
                continue;
            };
            let cgroup_match_mode = *self
                .cgroup_match_modes
                .get(&key)
                .context("socket-state run has no cgroup attribution mode")?;
            let schema = event.to_schema(&self.run_id, &self.boot_id, cgroup_match_mode)?;
            let json = serde_json::to_vec(&schema)?;
            let next_size = self
                .jsonl_bytes
                .checked_add(json.len() as u64 + 1)
                .context("socket-state JSONL size overflow")?;
            if next_size > MAX_SOCKET_STATE_JSONL_BYTES {
                bail!("socket-state JSONL exceeds its size limit");
            }
            self.wal.append(&event)?;
            self.jsonl.write_all(&json)?;
            self.jsonl.write_all(b"\n")?;
            self.jsonl_bytes = next_size;
            *persisted = persisted.saturating_add(1);
            if !self
                .sequences
                .get_mut(&key)
                .context("socket-state run has no sequence tracker")?
                .insert(event.event_seq)
            {
                self.routing_failures = self.routing_failures.saturating_add(1);
            }
            if event.kind == SOCKET_STATE_DESTROY {
                let destroy_events = self
                    .destroy_events
                    .get_mut(&key)
                    .context("socket-state run has no destroy-event counter")?;
                *destroy_events = destroy_events.saturating_add(1);
            }
            count += 1;
        }
        Ok(count)
    }

    pub(crate) fn sync(&mut self) -> Result<()> {
        self.wal.sync()?;
        self.jsonl.flush()?;
        self.jsonl.get_ref().sync_all()?;
        Ok(())
    }

    pub(crate) fn persisted(&self, key: (u64, u64)) -> u64 {
        self.persisted.get(&key).copied().unwrap_or(0)
    }

    pub(crate) fn sequence_complete(&self, key: (u64, u64), last: u64) -> bool {
        let Some(sequences) = self.sequences.get(&key) else {
            return false;
        };
        if last == 0 {
            return sequences.is_empty();
        }
        sequences.len() as u64 == last
            && sequences.contains(&1)
            && sequences.contains(&last)
            && sequences.iter().all(|sequence| *sequence <= last)
    }

    pub(crate) fn userspace_failures(&self) -> u64 {
        self.callback
            .decode_failures
            .saturating_add(self.callback.capacity_failures)
            .saturating_add(self.routing_failures)
    }

    pub(crate) fn queue_high_water(&self) -> u64 {
        self.callback.queue_high_water as u64
    }

    pub(crate) fn destroy_events(&self, key: (u64, u64)) -> u64 {
        self.destroy_events.get(&key).copied().unwrap_or(0)
    }

    pub(crate) fn cgroup_match_mode(&self, key: (u64, u64)) -> Option<CgroupMatchMode> {
        self.cgroup_match_modes.get(&key).copied()
    }

    pub(crate) fn unregister_run(&mut self, key: (u64, u64)) {
        self.persisted.remove(&key);
        self.sequences.remove(&key);
        self.destroy_events.remove(&key);
        self.cgroup_match_modes.remove(&key);
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SocketStateStatus {
    Complete,
    Incomplete,
}

/// Producer-side proof for the global asynchronous TCP-state hooks.
///
/// The two links are `inet_sock_set_state` and `tcp_destroy_sock`.  This is a
/// closing-barrier attestation, not an event-derived fact: offline replay can
/// validate its closed shape and digest binding but cannot re-perform a past
/// kernel detach.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SocketStateProducerSeal {
    pub complete: bool,
    pub links_expected: u32,
    pub links_detached: u32,
}

impl SocketStateProducerSeal {
    pub fn has_required_shape(self) -> bool {
        self.links_expected == SOCKET_STATE_ASYNC_PRODUCER_LINKS
            && self.links_detached <= self.links_expected
            && (!self.complete || self.links_detached == self.links_expected)
    }

    pub fn is_required_complete(self) -> bool {
        self.has_required_shape() && self.complete
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SocketStateHealth {
    pub schema_version: u32,
    pub run_id: String,
    pub boot_id: String,
    pub run_epoch: u64,
    pub cgroup_id: u64,
    pub cgroup_match_mode: CgroupMatchMode,
    pub status: SocketStateStatus,
    pub event_attempted: u64,
    pub event_published: u64,
    pub event_dropped: u64,
    pub events_persisted: u64,
    pub final_event_seq: u64,
    pub destroy_events_persisted: u64,
    pub owner_insert_failed: u64,
    pub owner_conflict: u64,
    pub owner_delete_failed: u64,
    pub owner_remaining: u64,
    /// Owners explicitly removed by userspace only after the producer
    /// cgroup-empty/frozen barrier. These are not reported as DESTROY events.
    pub owners_retired_at_barrier: u64,
    pub state_read_failed: u64,
    pub unsupported_sockets: u64,
    pub userspace_failures: u64,
    pub async_producer_seal: SocketStateProducerSeal,
    pub producer_barrier_complete: bool,
    pub drain_completed: bool,
    pub wal_durable: bool,
    pub callback_queue_high_water: u64,
    pub callback_queue_capacity: u64,
    pub reasons: Vec<String>,
    pub coverage_gaps: Vec<String>,
}

pub(crate) struct SocketStateClosingBoundary {
    pub owners_retired_at_barrier: u64,
    pub async_producer_seal: SocketStateProducerSeal,
    pub producer_barrier_complete: bool,
    pub timed_out: bool,
}

pub(crate) fn socket_state_health(
    run_id: &str,
    cgroup_id: u64,
    state: SocketStateRunState,
    outputs: &SocketStateOutputs,
    closing: SocketStateClosingBoundary,
) -> SocketStateHealth {
    let SocketStateClosingBoundary {
        owners_retired_at_barrier,
        async_producer_seal,
        producer_barrier_complete,
        timed_out,
    } = closing;
    let key = (cgroup_id, state.epoch);
    let persisted = outputs.persisted(key);
    let cgroup_match_mode = outputs
        .cgroup_match_mode(key)
        .expect("registered socket-state run has a cgroup match mode");
    let userspace_failures = outputs.userspace_failures();
    let mut reasons = Vec::new();
    if state.event_attempted != state.event_published.saturating_add(state.event_dropped) {
        reasons.push("socket-state event accounting invariant failed".to_owned());
    }
    if state.event_dropped != 0 {
        reasons.push("socket-state ring buffer dropped evidence".to_owned());
    }
    if state.event_published != persisted {
        reasons.push("published socket-state evidence was not fully persisted".to_owned());
    }
    if !outputs.sequence_complete(key, state.next_event_seq) {
        reasons.push("socket-state sequence is incomplete or duplicated".to_owned());
    }
    if state.owner_insert_failed != 0
        || state.owner_conflict != 0
        || state.owner_delete_failed != 0
        || state.state_read_failed != 0
    {
        reasons.push("socket-cookie ownership or state resolution failed".to_owned());
    }
    if state.owner_remaining != owners_retired_at_barrier {
        reasons.push(
            "socket-owner counter did not exactly match entries retired after producer detach"
                .to_owned(),
        );
    }
    if userspace_failures != 0 {
        reasons.push("socket-state userspace decode, routing, or capacity failure".to_owned());
    }
    if !async_producer_seal.is_required_complete() {
        reasons.push(
            "global async TCP-state BPF producers were not synchronously detached before drain"
                .to_owned(),
        );
    }
    if !producer_barrier_complete {
        reasons.push("producer cgroup empty/frozen barrier was not established".to_owned());
    }
    if timed_out {
        reasons.push("socket-state drain timed out".to_owned());
    }
    let drain_completed = !timed_out
        && async_producer_seal.is_required_complete()
        && state.owner_remaining == owners_retired_at_barrier
        && state.event_published == persisted
        && outputs.callback.queue.is_empty();
    SocketStateHealth {
        schema_version: SOCKET_STATE_SCHEMA_VERSION,
        run_id: run_id.to_owned(),
        boot_id: outputs.boot_id.clone(),
        run_epoch: state.epoch,
        cgroup_id,
        cgroup_match_mode,
        status: if drain_completed && reasons.is_empty() {
            SocketStateStatus::Complete
        } else {
            SocketStateStatus::Incomplete
        },
        event_attempted: state.event_attempted,
        event_published: state.event_published,
        event_dropped: state.event_dropped,
        events_persisted: persisted,
        final_event_seq: state.next_event_seq,
        destroy_events_persisted: outputs.destroy_events(key),
        owner_insert_failed: state.owner_insert_failed,
        owner_conflict: state.owner_conflict,
        owner_delete_failed: state.owner_delete_failed,
        owner_remaining: state.owner_remaining,
        owners_retired_at_barrier,
        state_read_failed: state.state_read_failed,
        unsupported_sockets: state.unsupported_sockets,
        userspace_failures,
        async_producer_seal,
        producer_barrier_complete,
        drain_completed,
        wal_durable: true,
        callback_queue_high_water: outputs.queue_high_water(),
        callback_queue_capacity: MAX_SOCKET_STATE_CALLBACK_QUEUE_EVENTS as u64,
        reasons,
        coverage_gaps: vec![
            "state ownership covers directly observed AF_INET/AF_INET6 TCP bind/connect/accept operations only".to_owned(),
            "accepted sockets receive a post-do_accept snapshot; TCP transitions before ownership publication are not claimed".to_owned(),
            "owners still present after the producer barrier are retired from attribution; retirement is counted separately and is never projected as an observed TCP DESTROY event".to_owned(),
            "UDP, Unix-domain, raw, packet, inherited, SCM_RIGHTS, io_uring, and delegated sockets are explicitly outside this partial state contract".to_owned(),
        ],
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketStateRunVerification {
    pub cgroup_id: u64,
    pub run_epoch: u64,
    pub published: u64,
    pub dropped: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketStateVerificationBinding {
    pub run_id: String,
    pub boot_id: String,
    pub cgroup_match_mode: CgroupMatchMode,
    pub runs: Vec<SocketStateRunVerification>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketStateRunVerificationResult {
    pub cgroup_id: u64,
    pub run_epoch: u64,
    pub published: u64,
    pub dropped: u64,
    pub recovered: u64,
    pub final_sequence: u64,
    pub destroy_events_verified: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketStateArtifactVerification {
    pub schema_version: u32,
    pub events_verified: u64,
    pub origin_links_verified: u64,
    pub jsonl_projection_verified: bool,
    pub runs: Vec<SocketStateRunVerificationResult>,
}

pub fn verify_socket_state_artifacts(
    wal_path: &Path,
    jsonl_path: &Path,
    system_effect_wal_path: &Path,
    binding: &SocketStateVerificationBinding,
    health: &[SocketStateHealth],
) -> Result<SocketStateArtifactVerification> {
    validate_boot_id(&binding.boot_id)?;
    if binding.run_id.is_empty() || binding.run_id.contains('\0') || binding.runs.is_empty() {
        bail!("socket-state verification requires a nonempty run_id and bound runs");
    }
    let mut bound = BTreeMap::new();
    for run in &binding.runs {
        if run.cgroup_id == 0 || run.run_epoch == 0 {
            bail!("bound socket-state cgroup and epoch must be nonzero");
        }
        if run.dropped != 0 {
            bail!("socket-state verification requires lossless transport accounting");
        }
        if bound
            .insert((run.cgroup_id, run.run_epoch), run.clone())
            .is_some()
        {
            bail!("duplicate bound socket-state cgroup/epoch identity");
        }
    }
    let recovery = recover_socket_state_wal(wal_path)?;
    if recovery.truncated_tail {
        bail!("socket-state WAL has a truncated tail");
    }
    let system_recovery = wal::recover(system_effect_wal_path)?;
    if system_recovery.truncated_tail {
        bail!("system-effect WAL has a truncated tail while linking socket owners");
    }
    let origins = eligible_origins(&system_recovery.events, &bound)?;
    let mut expected_json = Vec::with_capacity(recovery.events.len());
    let mut replay: BTreeMap<(u64, u64), SocketStateRunVerificationResult> = bound
        .values()
        .map(|run| {
            (
                (run.cgroup_id, run.run_epoch),
                SocketStateRunVerificationResult {
                    cgroup_id: run.cgroup_id,
                    run_epoch: run.run_epoch,
                    published: run.published,
                    dropped: run.dropped,
                    recovered: 0,
                    final_sequence: 0,
                    destroy_events_verified: 0,
                },
            )
        })
        .collect();
    let mut origin_links_verified = 0u64;
    for event in &recovery.events {
        let key = (event.cgroup_id, event.run_epoch);
        let run = replay
            .get_mut(&key)
            .context("socket-state WAL event is outside the bound run set")?;
        if event.event_seq != run.final_sequence + 1 {
            bail!("socket-state WAL sequence is not contiguous from one");
        }
        run.final_sequence = event.event_seq;
        run.recovered = run.recovered.saturating_add(1);
        if event.kind == SOCKET_STATE_DESTROY {
            run.destroy_events_verified = run.destroy_events_verified.saturating_add(1);
        }
        let origin = OriginKey {
            cgroup_id: event.cgroup_id,
            run_epoch: event.run_epoch,
            attempt_seq: event.origin_attempt_seq,
            pid_tgid: event.origin_pid_tgid,
            task_start_boottime_ns: event.origin_task_start_boottime_ns,
            operation: event.origin_operation,
        };
        let attempt_ktime = origins
            .get(&origin)
            .context("socket-state owner has no exact syscall-entry origin")?;
        if event.ktime_ns < *attempt_ktime {
            bail!("socket-state event precedes its syscall-entry origin");
        }
        origin_links_verified += 1;
        expected_json.push(serde_json::to_vec(&event.to_schema(
            &binding.run_id,
            &binding.boot_id,
            binding.cgroup_match_mode,
        )?)?);
    }
    let mut runs = replay.into_values().collect::<Vec<_>>();
    runs.sort_by_key(|run| (run.cgroup_id, run.run_epoch));
    for run in &runs {
        if run.recovered != run.published || run.final_sequence != run.published {
            bail!("socket-state WAL does not match bound lossless accounting");
        }
    }
    verify_jsonl_exact(jsonl_path, &expected_json)?;
    verify_health(health, binding, &runs)?;
    Ok(SocketStateArtifactVerification {
        schema_version: SOCKET_STATE_SCHEMA_VERSION,
        events_verified: recovery.events.len() as u64,
        origin_links_verified,
        jsonl_projection_verified: true,
        runs,
    })
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct OriginKey {
    cgroup_id: u64,
    run_epoch: u64,
    attempt_seq: u64,
    pid_tgid: u64,
    task_start_boottime_ns: u64,
    operation: u32,
}

fn eligible_origins(
    events: &[KernelEvent],
    bound: &BTreeMap<(u64, u64), SocketStateRunVerification>,
) -> Result<HashMap<OriginKey, u64>> {
    let mut origins = HashMap::new();
    for event in events {
        if !bound.contains_key(&(event.cgroup_id, event.run_epoch)) {
            continue;
        }
        if event.kind != EVENT_OPERATION_ATTEMPT
            || event.domain != EffectDomain::Network as u16
            || !matches!(
                EffectOperation::from_raw(event.operation),
                Some(
                    EffectOperation::SocketConnect
                        | EffectOperation::SocketBind
                        | EffectOperation::SocketAccept
                )
            )
        {
            continue;
        }
        let key = OriginKey {
            cgroup_id: event.cgroup_id,
            run_epoch: event.run_epoch,
            attempt_seq: event.event_seq,
            pid_tgid: event.pid_tgid,
            task_start_boottime_ns: event.task_start_boottime_ns,
            operation: event.operation,
        };
        if origins.insert(key, event.ktime_ns).is_some() {
            bail!("duplicate eligible socket owner origin in system-effect WAL");
        }
    }
    Ok(origins)
}

fn verify_health(
    health: &[SocketStateHealth],
    binding: &SocketStateVerificationBinding,
    runs: &[SocketStateRunVerificationResult],
) -> Result<()> {
    let mut expected = runs
        .iter()
        .map(|run| ((run.cgroup_id, run.run_epoch), run))
        .collect::<BTreeMap<_, _>>();
    if health.len() != expected.len() {
        bail!("socket-state health count differs from the bound run count");
    }
    for value in health {
        let run = expected
            .remove(&(value.cgroup_id, value.run_epoch))
            .context("socket-state health is outside or duplicates the bound run set")?;
        if value.schema_version != SOCKET_STATE_SCHEMA_VERSION
            || value.run_id != binding.run_id
            || value.boot_id != binding.boot_id
            || value.cgroup_match_mode != binding.cgroup_match_mode
            || value.status != SocketStateStatus::Complete
            || value.event_published != run.published
            || value.event_dropped != run.dropped
            || value.events_persisted != run.recovered
            || value.final_event_seq != run.final_sequence
            || value.destroy_events_persisted != run.destroy_events_verified
            || value.event_attempted != value.event_published.saturating_add(value.event_dropped)
            || value.owner_insert_failed != 0
            || value.owner_conflict != 0
            || value.owner_delete_failed != 0
            || value.state_read_failed != 0
            || value.userspace_failures != 0
            || value.owner_remaining != value.owners_retired_at_barrier
            || !value.async_producer_seal.is_required_complete()
            || !value.producer_barrier_complete
            || !value.drain_completed
            || !value.wal_durable
            || value.callback_queue_high_water > value.callback_queue_capacity
            || !value.reasons.is_empty()
        {
            bail!("socket-state health is inconsistent with strict replay");
        }
    }
    if !expected.is_empty() {
        bail!("socket-state health omits a bound run");
    }
    Ok(())
}

fn verify_jsonl_exact(path: &Path, expected: &[Vec<u8>]) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open socket-state JSONL {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        bail!("socket-state JSONL must be a singly linked regular file");
    }
    if metadata.len() > MAX_SOCKET_STATE_JSONL_BYTES {
        bail!("socket-state JSONL exceeds its verification limit");
    }
    let mut lines = BufReader::new(file).split(b'\n');
    for canonical in expected {
        let line = lines
            .next()
            .context("socket-state JSONL ended before the WAL projection")??;
        if line.len() > MAX_SOCKET_STATE_JSON_BYTES {
            bail!("socket-state JSON line exceeds its bounded size");
        }
        if &line != canonical {
            bail!("socket-state JSONL differs from the canonical WAL projection");
        }
    }
    if let Some(extra) = lines.next() {
        let extra = extra?;
        if !extra.is_empty() || lines.next().is_some() {
            bail!("socket-state JSONL contains records absent from the WAL");
        }
    }
    Ok(())
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
        bail!("boot_id is not a canonical lowercase UUID");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{EFFECT_EVENT_SCHEMA_VERSION, PAYLOAD_NONE};
    use std::sync::atomic::{AtomicU64, Ordering};

    const BOOT_ID: &str = "00000000-0000-0000-0000-000000000001";

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn create() -> Self {
            let path = std::env::temp_dir().join(format!(
                "bpf-observer-socket-state-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn state_event(sequence: u64) -> KernelSocketStateEvent {
        KernelSocketStateEvent {
            schema_version: SOCKET_STATE_SCHEMA_VERSION,
            kind: SOCKET_STATE_TRANSITION,
            flags: SOCKET_STATE_F_OWNER_PROVISIONAL,
            run_epoch: 7,
            event_seq: sequence,
            ktime_ns: 100 + sequence,
            cgroup_id: 9,
            origin_attempt_seq: 1,
            origin_pid_tgid: (44u64 << 32) | 45,
            origin_task_start_boottime_ns: 55,
            socket_cookie: 66,
            network_namespace_cookie: 77,
            address_family: libc::AF_INET as u32,
            socket_type: libc::SOCK_STREAM as u32,
            protocol: libc::IPPROTO_TCP as u32,
            old_state: 7,
            new_state: 2,
            origin_operation: EffectOperation::SocketConnect as u32,
            local_port: 1234,
            peer_port: 443,
            local_address: [0; 16],
            peer_address: {
                let mut address = [0; 16];
                address[..4].copy_from_slice(&[192, 0, 2, 1]);
                address
            },
        }
    }

    fn system_attempt() -> KernelEvent {
        KernelEvent {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            kind: EVENT_OPERATION_ATTEMPT,
            domain: EffectDomain::Network as u16,
            operation: EffectOperation::SocketConnect as u32,
            flags: 0,
            syscall_nr: libc::SYS_connect as i32,
            run_epoch: 7,
            event_seq: 1,
            related_attempt_seq: 0,
            ktime_ns: 100,
            cgroup_id: 9,
            pid_tgid: (44u64 << 32) | 45,
            return_value: 0,
            args: [0; 6],
            comm: [0; 16],
            task_start_boottime_ns: 55,
            payload_lens: [0; 2],
            payload_kinds: [PAYLOAD_NONE; 2],
            payload_arg_indices: [0; 2],
            payloads: [[0; crate::protocol::CAPTURE_BYTES]; 2],
            file_object: None,
            socket_object: None,
        }
    }

    fn complete_health() -> SocketStateHealth {
        SocketStateHealth {
            schema_version: SOCKET_STATE_SCHEMA_VERSION,
            run_id: "run".to_owned(),
            boot_id: BOOT_ID.to_owned(),
            run_epoch: 7,
            cgroup_id: 9,
            cgroup_match_mode: CgroupMatchMode::ExactCurrent,
            status: SocketStateStatus::Complete,
            event_attempted: 1,
            event_published: 1,
            event_dropped: 0,
            events_persisted: 1,
            final_event_seq: 1,
            destroy_events_persisted: 0,
            owner_insert_failed: 0,
            owner_conflict: 0,
            owner_delete_failed: 0,
            owner_remaining: 0,
            owners_retired_at_barrier: 0,
            state_read_failed: 0,
            unsupported_sockets: 0,
            userspace_failures: 0,
            async_producer_seal: SocketStateProducerSeal {
                complete: true,
                links_expected: SOCKET_STATE_ASYNC_PRODUCER_LINKS,
                links_detached: SOCKET_STATE_ASYNC_PRODUCER_LINKS,
            },
            producer_barrier_complete: true,
            drain_completed: true,
            wal_durable: true,
            callback_queue_high_water: 1,
            callback_queue_capacity: MAX_SOCKET_STATE_CALLBACK_QUEUE_EVENTS as u64,
            reasons: Vec::new(),
            coverage_gaps: vec!["partial".to_owned()],
        }
    }

    #[test]
    fn fixed_frame_round_trip_and_reserved_tail() {
        let event = state_event(1);
        let bytes = event.encode_le();
        assert_eq!(KernelSocketStateEvent::decode_le(&bytes).unwrap(), event);
        let mut noncanonical = bytes;
        noncanonical[151] = 1;
        assert!(KernelSocketStateEvent::decode_le(&noncanonical).is_err());
    }

    #[test]
    fn callback_burst_is_drained_in_lossless_bounded_batches() {
        let mut state = SocketStateCallbackState::default();
        let burst = MAX_SOCKET_STATE_CALLBACK_QUEUE_EVENTS + 17;
        let mut retained = 0;

        for sequence in 1..=burst {
            let rc = enqueue_socket_state_event(&mut state, state_event(sequence as u64));
            retained += 1;
            if state.queue.len() == MAX_SOCKET_STATE_CALLBACK_QUEUE_EVENTS {
                assert_eq!(rc, -libc::EAGAIN);
                assert!(state.batch_limit_reached);
                assert_eq!(state.queue.len(), MAX_SOCKET_STATE_CALLBACK_QUEUE_EVENTS);
                state.queue.clear();
                state.batch_limit_reached = false;
            } else {
                assert_eq!(rc, 0);
            }
        }

        assert_eq!(retained, burst);
        assert_eq!(state.accepted_events, burst as u64);
        assert_eq!(state.queue.len(), 17);
        assert_eq!(
            state.queue_high_water,
            MAX_SOCKET_STATE_CALLBACK_QUEUE_EVENTS
        );
        assert_eq!(state.capacity_failures, 0);
    }

    #[test]
    fn callback_boundary_is_retained_and_undrained_overflow_is_a_capacity_failure() {
        let mut state = SocketStateCallbackState::default();
        for sequence in 1..=MAX_SOCKET_STATE_CALLBACK_QUEUE_EVENTS {
            let rc = enqueue_socket_state_event(&mut state, state_event(sequence as u64));
            if sequence == MAX_SOCKET_STATE_CALLBACK_QUEUE_EVENTS {
                assert_eq!(rc, -libc::EAGAIN);
            } else {
                assert_eq!(rc, 0);
            }
        }
        assert_eq!(state.queue.len(), MAX_SOCKET_STATE_CALLBACK_QUEUE_EVENTS);
        assert_eq!(
            state.accepted_events,
            MAX_SOCKET_STATE_CALLBACK_QUEUE_EVENTS as u64
        );
        assert!(state.batch_limit_reached);
        assert_eq!(state.capacity_failures, 0);

        assert_eq!(
            enqueue_socket_state_event(&mut state, state_event(9_999)),
            -libc::EFBIG
        );
        assert_eq!(state.queue.len(), MAX_SOCKET_STATE_CALLBACK_QUEUE_EVENTS);
        assert_eq!(
            state.accepted_events,
            MAX_SOCKET_STATE_CALLBACK_QUEUE_EVENTS as u64
        );
        assert_eq!(state.capacity_failures, 1);
    }

    #[test]
    fn ipv4_tail_and_state_kind_are_closed() {
        let mut event = state_event(1);
        event.peer_address[15] = 1;
        assert!(event.validate().is_err());
        event.peer_address[15] = 0;
        event.kind = SOCKET_STATE_DESTROY;
        assert!(event.validate().is_err());
    }

    #[test]
    fn strict_replay_links_exact_origin_and_json() {
        let directory = TestDirectory::create();
        let socket_wal = directory.path().join(SOCKET_STATE_WAL_NAME);
        let socket_jsonl = directory.path().join(SOCKET_STATE_JSONL_NAME);
        let system_wal = directory.path().join("system-effects.raw.bin");

        let event = state_event(1);
        let mut writer = SocketStateWalWriter::create(&socket_wal).unwrap();
        writer.append(&event).unwrap();
        writer.sync().unwrap();
        let schema = event
            .to_schema("run", BOOT_ID, CgroupMatchMode::ExactCurrent)
            .unwrap();
        std::fs::write(
            &socket_jsonl,
            [serde_json::to_vec(&schema).unwrap(), b"\n".to_vec()].concat(),
        )
        .unwrap();

        let mut system_writer = crate::wal::WalWriter::create(&system_wal).unwrap();
        system_writer.append(&system_attempt()).unwrap();
        system_writer.sync().unwrap();

        let verified = verify_socket_state_artifacts(
            &socket_wal,
            &socket_jsonl,
            &system_wal,
            &SocketStateVerificationBinding {
                run_id: "run".to_owned(),
                boot_id: BOOT_ID.to_owned(),
                cgroup_match_mode: CgroupMatchMode::ExactCurrent,
                runs: vec![SocketStateRunVerification {
                    cgroup_id: 9,
                    run_epoch: 7,
                    published: 1,
                    dropped: 0,
                }],
            },
            &[complete_health()],
        )
        .unwrap();
        assert_eq!(verified.events_verified, 1);
        assert_eq!(verified.origin_links_verified, 1);
    }

    #[test]
    fn strict_replay_rejects_wrong_origin_start_time() {
        let events = vec![system_attempt()];
        let binding = SocketStateVerificationBinding {
            run_id: "run".to_owned(),
            boot_id: BOOT_ID.to_owned(),
            cgroup_match_mode: CgroupMatchMode::ExactCurrent,
            runs: vec![SocketStateRunVerification {
                cgroup_id: 9,
                run_epoch: 7,
                published: 1,
                dropped: 0,
            }],
        };
        let bound = binding
            .runs
            .iter()
            .map(|run| ((run.cgroup_id, run.run_epoch), run.clone()))
            .collect();
        let origins = eligible_origins(&events, &bound).unwrap();
        let mut key = OriginKey {
            cgroup_id: 9,
            run_epoch: 7,
            attempt_seq: 1,
            pid_tgid: (44u64 << 32) | 45,
            task_start_boottime_ns: 55,
            operation: EffectOperation::SocketConnect as u32,
        };
        assert!(origins.contains_key(&key));
        key.task_start_boottime_ns += 1;
        assert!(!origins.contains_key(&key));
    }

    #[test]
    fn barrier_retirement_is_not_counted_as_destroy_and_must_cover_remaining_owners() {
        let binding = SocketStateVerificationBinding {
            run_id: "run".to_owned(),
            boot_id: BOOT_ID.to_owned(),
            cgroup_match_mode: CgroupMatchMode::ExactCurrent,
            runs: vec![SocketStateRunVerification {
                cgroup_id: 9,
                run_epoch: 7,
                published: 1,
                dropped: 0,
            }],
        };
        let runs = vec![SocketStateRunVerificationResult {
            cgroup_id: 9,
            run_epoch: 7,
            published: 1,
            dropped: 0,
            recovered: 1,
            final_sequence: 1,
            destroy_events_verified: 0,
        }];
        let mut health = complete_health();
        health.owner_remaining = 1;
        health.owners_retired_at_barrier = 1;
        assert!(verify_health(&[health.clone()], &binding, &runs).is_ok());
        health.owners_retired_at_barrier = 0;
        assert!(verify_health(&[health.clone()], &binding, &runs).is_err());
        health.owner_remaining = 0;
        health.owners_retired_at_barrier = 1;
        assert!(verify_health(&[health], &binding, &runs).is_err());
    }

    #[test]
    fn strict_replay_rejects_missing_or_partial_async_producer_seal() {
        let binding = SocketStateVerificationBinding {
            run_id: "run".to_owned(),
            boot_id: BOOT_ID.to_owned(),
            cgroup_match_mode: CgroupMatchMode::ExactCurrent,
            runs: vec![SocketStateRunVerification {
                cgroup_id: 9,
                run_epoch: 7,
                published: 1,
                dropped: 0,
            }],
        };
        let runs = vec![SocketStateRunVerificationResult {
            cgroup_id: 9,
            run_epoch: 7,
            published: 1,
            dropped: 0,
            recovered: 1,
            final_sequence: 1,
            destroy_events_verified: 0,
        }];
        let mut health = complete_health();
        health.async_producer_seal.complete = false;
        health.async_producer_seal.links_detached = 0;
        assert!(verify_health(&[health.clone()], &binding, &runs).is_err());
        health.async_producer_seal.complete = true;
        health.async_producer_seal.links_detached = 1;
        assert!(verify_health(&[health], &binding, &runs).is_err());
    }
}
