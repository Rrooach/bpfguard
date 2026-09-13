// SPDX-License-Identifier: GPL-2.0-only

pub mod delegation;
mod policy;
mod protocol;
mod wal;

pub use policy::{
    describe_policy, policy_sha256, EffectDomain, EffectOperation, KernelObjectResolver,
    PolicyDescription, PolicyProfile,
};
pub use protocol::{
    AttributionContract, CaptureSource, CaptureStatus, CapturedArgument, DelegatedEffectsStatus,
    DirectAttributionClaim, EffectAttribution, EffectAttributionAuthority,
    EffectAttributionComponent, EffectAttributionMode, EffectAttributionSubject,
    EffectCausalStatus, EventKind, FilePathObservation, FilesystemClass, KernelEvent,
    KernelFileObject, ObjectIdentity, ObjectReference, ObjectResolution, ObjectResolutionAuthority,
    ObjectResolutionQuality, ObjectRole, PathResolutionAuthority, PathResolutionQuality,
    ResolvedPath, ResultStatus, SocketEndpointAddress, SocketEndpointAuthority,
    SocketEndpointObservation, SocketEndpointPair, SocketEndpointQuality, SystemEffectEvent,
    EFFECT_ATTRIBUTION_PROTOCOL_VERSION, EFFECT_EVENT_SCHEMA_VERSION, FILE_PATH_NOT_REQUESTED,
    FILE_PATH_RESOLVED_AT_HOOK, FILE_PATH_TRUNCATED_AT_HOOK, FILE_PATH_UNAVAILABLE,
    FLAG_OBJECT_DELETE_FAILED, FLAG_OBJECT_JOIN_AMBIGUOUS, FLAG_OBJECT_JOIN_MISSING,
    FLAG_OBJECT_PATH_UNAVAILABLE, FLAG_OBJECT_READ_FAILED, FLAG_PAYLOAD1_INVALID_LENGTH,
    FLAG_PAYLOAD1_READ_FAILED, FLAG_PAYLOAD1_TRUNCATED, FLAG_PAYLOAD2_INVALID_LENGTH,
    FLAG_PAYLOAD2_READ_FAILED, FLAG_PAYLOAD2_TRUNCATED, FLAG_PENDING_DELETE_FAILED,
    FLAG_PENDING_INSERT_FAILED, FLAG_PENDING_MISSING, FLAG_PENDING_POISONED, FLAG_POLICY_INVALID,
    FLAG_SYSCALL_MISMATCH, FLAG_USER_MEMORY_SNAPSHOT, KERNEL_FILE_EVENT_SIZE,
    KERNEL_FILE_PATH_BYTES, MAX_OBJECT_REFERENCES, MAX_RESOLVED_PATH_BYTES,
    MAX_SOCKET_ENDPOINT_BYTES, OBJECT_IDENTITY_PROTOCOL_VERSION,
};
pub use wal::{recover as recover_wal, recover_reader as recover_wal_reader, WalRecovery};

use anyhow::{anyhow, bail, Context, Result};
use bpf_observer_schema::ObjectExclusions;
use libbpf_sys as libbpf;
use policy::{
    event_policy_identities, kernel_policies, EventPolicyIdentity, KernelPolicy, POLICY_MAP_ENTRIES,
};
use protocol::{EVENT_OPERATION_ATTEMPT, EVENT_OPERATION_RESULT};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{c_void, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::os::raw::c_int;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::ptr;
use std::slice;
use std::time::{Duration, Instant};
use wal::WalWriter;

const MAP_POLICY: &str = "effect_policy";
const MAP_RUNS: &str = "effect_runs";
const MAP_PENDING: &str = "effect_pending";
const MAP_EVENTS: &str = "effect_events";
const MAP_OBJECT_CONFIG: &str = "effect_object_config";
const MAP_FILE_OBJECTS: &str = "effect_file_objects";
const PROGRAM_ENTER: &str = "trace_effect_enter";
const PROGRAM_EXIT: &str = "trace_effect_exit";
const PROGRAM_FILE_EXIT: &str = "trace_effect_file_exit";
const PROGRAM_FILE_OBJECT: &str = "trace_effect_file_object";
const PROGRAM_FILE_PERMISSION: &str = "trace_effect_file_permission";

const OBJECT_RESOLVE_FILE_OPEN: u32 = 1 << 0;
const OBJECT_RESOLVE_FILE_PERMISSION_WRITE: u32 = 1 << 1;

const MAX_RUNS: u32 = 1024;
const MAX_PENDING: u32 = 16384;
const PENDING_VALUE_SIZE: u32 = 96;
const FILE_PENDING_VALUE_SIZE: u32 = 200;
const RING_BYTES: u32 = 1 << 22;
const MAX_OBJECT_BYTES: u64 = 16 * 1024 * 1024;
/* libbpf 1.0's poll/consume functions otherwise keep draining while producers
 * advance the ring. The callback returns a private -EAGAIN after this many
 * accepted records; userspace persists the batch before consuming again.
 */
const MAX_CALLBACK_QUEUE_EVENTS: usize = 4_096;
const MAX_RECORDED_EVENTS: u64 = 1_000_000;
const MAX_JSONL_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
struct RunState {
    epoch: u64,
    next_event_seq: u64,
    operation_attempted: u64,
    operation_completed: u64,
    event_attempted: u64,
    event_published: u64,
    event_dropped: u64,
    pending_insert_failed: u64,
    pending_missing: u64,
    pending_remaining: u64,
    object_resolution_attempted: u64,
    object_resolution_resolved: u64,
    object_resolution_unresolved: u64,
    object_resolution_failed_syscalls: u64,
    object_join_missing: u64,
    object_join_ambiguous: u64,
    object_read_failed: u64,
    object_delete_failed: u64,
    object_path_unavailable: u64,
    object_pending_remaining: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FileObjectResolutionMode {
    UserInput,
    KernelFileOpenPartial,
    KernelFileOpenWritePartial,
}

impl FileObjectResolutionMode {
    fn kernel_file_object_enabled(self) -> bool {
        self != Self::UserInput
    }

    fn kernel_file_write_enabled(self) -> bool {
        self == Self::KernelFileOpenWritePartial
    }

    fn resolver_mask(self) -> u32 {
        match self {
            Self::UserInput => 0,
            Self::KernelFileOpenPartial => OBJECT_RESOLVE_FILE_OPEN,
            Self::KernelFileOpenWritePartial => {
                OBJECT_RESOLVE_FILE_OPEN | OBJECT_RESOLVE_FILE_PERMISSION_WRITE
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct ObjectConfig {
    resolver_mask: u32,
    capture_path: u32,
}

#[derive(Default)]
struct CallbackState {
    queue: VecDeque<KernelEvent>,
    decode_failures: u64,
    routing_failures: u64,
    pairing_failures: u64,
    capacity_failures: u64,
    accepted_events: u64,
    queue_high_water: usize,
    batch_limit_reached: bool,
}

fn enqueue_event(state: &mut CallbackState, event: KernelEvent) -> c_int {
    if state.queue.len() >= MAX_CALLBACK_QUEUE_EVENTS
        || state.accepted_events >= MAX_RECORDED_EVENTS
    {
        state.capacity_failures = state.capacity_failures.saturating_add(1);
        return -libc::EFBIG;
    }
    state.queue.push_back(event);
    state.accepted_events = state.accepted_events.saturating_add(1);
    state.queue_high_water = state.queue_high_water.max(state.queue.len());
    if state.queue.len() == MAX_CALLBACK_QUEUE_EVENTS {
        state.batch_limit_reached = true;
        -libc::EAGAIN
    } else {
        0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AttemptIdentity {
    pid_tgid: u64,
    syscall_nr: i32,
    domain: u16,
    operation: u32,
    ktime_ns: u64,
    args: [u64; 6],
}

unsafe extern "C" fn receive_event(context: *mut c_void, data: *mut c_void, size: u64) -> c_int {
    if context.is_null() || data.is_null() {
        return -libc::EINVAL;
    }
    let state = &mut *(context as *mut CallbackState);
    let Ok(size) = usize::try_from(size) else {
        state.decode_failures = state.decode_failures.saturating_add(1);
        return -libc::EBADMSG;
    };
    let bytes = slice::from_raw_parts(data.cast::<u8>(), size);
    match KernelEvent::decode_native(bytes) {
        Ok(event) => enqueue_event(state, event),
        Err(_) => {
            state.decode_failures = state.decode_failures.saturating_add(1);
            -libc::EBADMSG
        }
    }
}

struct KernelResources {
    object: *mut libbpf::bpf_object,
    links: Vec<*mut libbpf::bpf_link>,
    ring: *mut libbpf::ring_buffer,
}

impl KernelResources {
    fn new(object: *mut libbpf::bpf_object) -> Self {
        Self {
            object,
            links: Vec::new(),
            ring: ptr::null_mut(),
        }
    }
}

impl Drop for KernelResources {
    fn drop(&mut self) {
        unsafe {
            if !self.ring.is_null() {
                libbpf::ring_buffer__free(self.ring);
            }
            for link in self.links.drain(..).rev() {
                if !link.is_null() {
                    libbpf::bpf_link__destroy(link);
                }
            }
            if !self.object.is_null() {
                libbpf::bpf_object__close(self.object);
            }
        }
    }
}

/// Low-overhead syscall operation recorder for one or more exact cgroup IDs.
///
/// The global raw-syscall programs do one ARRAY lookup first. Only syscalls in
/// the selected policy perform cgroup lookup, argument capture, pending-map
/// insertion, or ring-buffer publication.
pub struct SystemEffectRecorder {
    resources: KernelResources,
    callback: Box<CallbackState>,
    run_states_fd: c_int,
    run_id: String,
    boot_id: String,
    profile: PolicyProfile,
    object_resolution_mode: FileObjectResolutionMode,
    event_policies: HashMap<i32, EventPolicyIdentity>,
    object_sha256: String,
    policy_sha256: String,
    wal: WalWriter,
    jsonl: BufWriter<File>,
    jsonl_bytes: u64,
    persisted: HashMap<(u64, u64), u64>,
    open_attempts: HashMap<(u64, u64), HashMap<u64, AttemptIdentity>>,
    seen_sequences: HashMap<(u64, u64), HashSet<u64>>,
    fatal_kernel_flags: HashMap<(u64, u64), u64>,
    capture_read_failures: HashMap<(u64, u64), u64>,
    capture_truncations: HashMap<(u64, u64), u64>,
    capture_invalid_lengths: HashMap<(u64, u64), u64>,
    poll_calls: u64,
    maximum_events_per_poll: u64,
    finished: HashSet<(u64, u64)>,
    ever_used: HashSet<(u64, u64)>,
}

impl SystemEffectRecorder {
    pub fn open(
        object_path: &Path,
        expected_object_sha256: &str,
        output_dir: &Path,
        run_id: &str,
        boot_id: &str,
        profile: PolicyProfile,
        object_resolution_mode: FileObjectResolutionMode,
    ) -> Result<Self> {
        if run_id.is_empty() || run_id.contains('\0') {
            bail!("run_id must be nonempty and contain no NUL bytes");
        }
        validate_boot_id(boot_id)?;
        fs::create_dir_all(output_dir)
            .with_context(|| format!("create system-effect output {}", output_dir.display()))?;
        let wal = WalWriter::create(&output_dir.join("system-effects.raw.bin"))?;
        let jsonl = open_new(&output_dir.join("system-effects.jsonl"))?;

        let (object_bytes, object_sha256) = read_object(object_path)?;
        verify_digest(&object_sha256, expected_object_sha256)?;
        let object = unsafe {
            libbpf::bpf_object__open_mem(
                object_bytes.as_ptr().cast(),
                object_bytes.len() as u64,
                ptr::null(),
            )
        };
        check_pointer(object.cast(), "open system-effect BPF object")?;
        let mut resources = KernelResources::new(object);
        configure_object_autoload(resources.object, object_resolution_mode)?;
        check_rc(
            unsafe { libbpf::bpf_object__load(resources.object) },
            "load system-effect BPF object",
        )?;

        let policy_fd = find_map_fd(resources.object, MAP_POLICY)?;
        let run_states_fd = find_map_fd(resources.object, MAP_RUNS)?;
        let pending_fd = find_map_fd(resources.object, MAP_PENDING)?;
        let events_fd = find_map_fd(resources.object, MAP_EVENTS)?;
        let object_fds = if object_resolution_mode.kernel_file_object_enabled() {
            Some((
                find_map_fd(resources.object, MAP_OBJECT_CONFIG)?,
                find_map_fd(resources.object, MAP_FILE_OBJECTS)?,
            ))
        } else {
            None
        };
        validate_map_abi(
            policy_fd,
            MapAbi::new(
                MAP_POLICY,
                libbpf::BPF_MAP_TYPE_ARRAY,
                4,
                std::mem::size_of::<KernelPolicy>() as u32,
                POLICY_MAP_ENTRIES,
            ),
        )?;
        validate_map_abi(
            run_states_fd,
            MapAbi::new(
                MAP_RUNS,
                libbpf::BPF_MAP_TYPE_HASH,
                8,
                std::mem::size_of::<RunState>() as u32,
                MAX_RUNS,
            ),
        )?;
        validate_map_abi(
            pending_fd,
            MapAbi::new(
                MAP_PENDING,
                libbpf::BPF_MAP_TYPE_HASH,
                8,
                PENDING_VALUE_SIZE,
                MAX_PENDING,
            ),
        )?;
        validate_map_abi(
            events_fd,
            MapAbi::new(MAP_EVENTS, libbpf::BPF_MAP_TYPE_RINGBUF, 0, 0, RING_BYTES),
        )?;
        if let Some((config_fd, file_objects_fd)) = object_fds {
            validate_map_abi(
                config_fd,
                MapAbi::new(
                    MAP_OBJECT_CONFIG,
                    libbpf::BPF_MAP_TYPE_ARRAY,
                    4,
                    std::mem::size_of::<ObjectConfig>() as u32,
                    1,
                ),
            )?;
            validate_map_abi(
                file_objects_fd,
                MapAbi::new(
                    MAP_FILE_OBJECTS,
                    libbpf::BPF_MAP_TYPE_HASH,
                    8,
                    FILE_PENDING_VALUE_SIZE,
                    MAX_PENDING,
                )
                .with_flags(0),
            )?;
            let config = ObjectConfig {
                resolver_mask: object_resolution_mode.resolver_mask(),
                capture_path: 1,
            };
            map_update(config_fd, &0u32, &config, libbpf::BPF_ANY as u64)
                .context("enable kernel file-object resolution")?;
            check_rc(
                unsafe { libbpf::bpf_map_freeze(config_fd) },
                "freeze immutable file-object resolution config",
            )?;
        }

        for (number, policy) in kernel_policies(profile)? {
            map_update(policy_fd, &number, &policy, libbpf::BPF_ANY as u64)
                .with_context(|| format!("install syscall policy for number {number}"))?;
        }
        check_rc(
            unsafe { libbpf::bpf_map_freeze(policy_fd) },
            "freeze immutable system-effect syscall policy",
        )?;
        attach_tracepoint(&mut resources, PROGRAM_ENTER, "raw_syscalls", "sys_enter")?;
        if object_resolution_mode.kernel_file_object_enabled() {
            attach_tracepoint(
                &mut resources,
                PROGRAM_FILE_EXIT,
                "raw_syscalls",
                "sys_exit",
            )?;
            attach_lsm(&mut resources, PROGRAM_FILE_OBJECT)?;
            if object_resolution_mode.kernel_file_write_enabled() {
                attach_lsm(&mut resources, PROGRAM_FILE_PERMISSION)?;
            }
        } else {
            attach_tracepoint(&mut resources, PROGRAM_EXIT, "raw_syscalls", "sys_exit")?;
        }

        let mut callback = Box::<CallbackState>::default();
        resources.ring = unsafe {
            libbpf::ring_buffer__new(
                events_fd,
                Some(receive_event),
                (&mut *callback as *mut CallbackState).cast(),
                ptr::null(),
            )
        };
        if resources.ring.is_null() {
            return Err(std::io::Error::last_os_error())
                .context("create system-effect ring buffer");
        }

        Ok(Self {
            resources,
            callback,
            run_states_fd,
            run_id: run_id.to_owned(),
            boot_id: boot_id.to_owned(),
            profile,
            object_resolution_mode,
            event_policies: event_policy_identities(profile)?,
            object_sha256,
            policy_sha256: policy::policy_sha256(profile)?,
            wal,
            jsonl,
            jsonl_bytes: 0,
            persisted: HashMap::new(),
            open_attempts: HashMap::new(),
            seen_sequences: HashMap::new(),
            fatal_kernel_flags: HashMap::new(),
            capture_read_failures: HashMap::new(),
            capture_truncations: HashMap::new(),
            capture_invalid_lengths: HashMap::new(),
            poll_calls: 0,
            maximum_events_per_poll: 0,
            finished: HashSet::new(),
            ever_used: HashSet::new(),
        })
    }

    pub fn object_sha256(&self) -> &str {
        &self.object_sha256
    }

    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }

    /// Kernel IDs of all maps, programs, and links owned by this recorder.
    ///
    /// Consumers must use the same set for S0 and S1 and keep the recorder
    /// loaded until both captures have completed.
    pub fn object_exclusions(&self) -> Result<ObjectExclusions> {
        collect_exclusions(&self.resources)
            .context("resolve every system-effect recorder-owned BPF object ID")
    }

    pub fn profile(&self) -> PolicyProfile {
        self.profile
    }

    pub fn register_run(&mut self, cgroup_id: u64, epoch: u64) -> Result<()> {
        if cgroup_id == 0 || epoch == 0 {
            bail!("cgroup_id and epoch must both be nonzero");
        }
        let key = (cgroup_id, epoch);
        if self.ever_used.contains(&key) {
            bail!("system-effect run cgroup/epoch identity cannot be reused");
        }
        if self.persisted.contains_key(&key) {
            bail!("system-effect run cgroup/epoch is already registered");
        }
        let state = RunState {
            epoch,
            ..RunState::default()
        };
        map_update(
            self.run_states_fd,
            &cgroup_id,
            &state,
            libbpf::BPF_NOEXIST as u64,
        )
        .context("register exact cgroup with system-effect recorder")?;
        self.ever_used.insert(key);
        self.persisted.insert(key, 0);
        self.open_attempts.insert(key, HashMap::new());
        self.seen_sequences.insert(key, HashSet::new());
        self.fatal_kernel_flags.insert(key, 0);
        self.capture_read_failures.insert(key, 0);
        self.capture_truncations.insert(key, 0);
        self.capture_invalid_lengths.insert(key, 0);
        Ok(())
    }

    pub fn poll(&mut self, timeout: Duration) -> Result<usize> {
        self.poll_calls = self.poll_calls.saturating_add(1);
        self.callback.batch_limit_reached = false;
        let rc = unsafe { libbpf::ring_buffer__consume(self.resources.ring) };
        self.validate_consume_result(rc, "consume system-effect ring buffer")?;
        let mut persisted = self.persist_queued()?;

        /* Avoid epoll when consume found data. Besides reducing latency, this
         * guarantees progress after the callback deliberately stopped a
         * previous libbpf drain with -EAGAIN while records remained queued in
         * the kernel ring.
         */
        if persisted != 0 {
            self.maximum_events_per_poll = self.maximum_events_per_poll.max(persisted as u64);
            return Ok(persisted);
        }

        self.callback.batch_limit_reached = false;
        let millis = timeout.as_millis().min(c_int::MAX as u128) as c_int;
        let rc = unsafe { libbpf::ring_buffer__poll(self.resources.ring, millis) };
        self.validate_consume_result(rc, "poll system-effect ring buffer")?;
        persisted = self.persist_queued()?;
        self.maximum_events_per_poll = self.maximum_events_per_poll.max(persisted as u64);
        Ok(persisted)
    }

    fn validate_consume_result(&self, rc: c_int, action: &'static str) -> Result<()> {
        if rc >= 0 || rc == -libc::EINTR {
            if self.callback.batch_limit_reached {
                bail!("system-effect callback batch stop was not propagated by libbpf");
            }
            return Ok(());
        }
        if rc == -libc::EAGAIN && self.callback.batch_limit_reached {
            return Ok(());
        }
        if self.callback.capacity_failures != 0 {
            bail!(
                "system-effect event capacity exceeded (batch <= {MAX_CALLBACK_QUEUE_EVENTS}, total <= {MAX_RECORDED_EVENTS})"
            );
        }
        Err(libbpf_error(rc)).context(action)
    }

    pub fn finish_run(
        &mut self,
        cgroup_id: u64,
        epoch: u64,
        timeout: Duration,
        producer_barrier_complete: bool,
    ) -> Result<SystemEffectHealth> {
        let key = (cgroup_id, epoch);
        if !self.persisted.contains_key(&key) {
            bail!("system-effect run cgroup/epoch is not registered");
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .context("system-effect drain timeout exceeds monotonic clock range")?;
        let mut timed_out = false;
        loop {
            self.poll(
                Duration::from_millis(20).min(deadline.saturating_duration_since(Instant::now())),
            )?;
            let first = self.read_run_state(cgroup_id, epoch)?;
            let persisted = self.persisted.get(&key).copied().unwrap_or(0);
            if first.pending_remaining == 0
                && first.object_pending_remaining == 0
                && first.event_published == persisted
            {
                self.poll(Duration::ZERO)?;
                let second = self.read_run_state(cgroup_id, epoch)?;
                let persisted = self.persisted.get(&key).copied().unwrap_or(0);
                if first == second
                    && second.pending_remaining == 0
                    && second.object_pending_remaining == 0
                    && second.event_published == persisted
                {
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
            reasons.push("recorder drain timed out".to_owned());
        }
        if state.event_published.checked_add(state.event_dropped) != Some(state.event_attempted) {
            reasons.push("kernel event accounting invariant failed".to_owned());
        }
        if state
            .operation_attempted
            .checked_add(state.operation_completed)
            != Some(state.event_attempted)
        {
            reasons.push("operation-to-event accounting invariant failed".to_owned());
        }
        if state.next_event_seq != state.event_attempted {
            reasons.push("kernel sequence allocation did not match event attempts".to_owned());
        }
        if state.operation_attempted != state.operation_completed {
            reasons.push("selected syscall enter/exit accounting did not balance".to_owned());
        }
        if state.event_published != persisted {
            reasons.push("published events were not all persisted".to_owned());
        }
        if state.pending_remaining != 0 {
            reasons.push("selected syscalls remain pending".to_owned());
        }
        if state.object_pending_remaining != 0 {
            reasons.push("kernel file-object joins remain pending".to_owned());
        }
        if state.pending_insert_failed != 0 || state.pending_missing != 0 {
            reasons.push("pending-call correlation was incomplete".to_owned());
        }
        if state.event_dropped != 0 {
            reasons.push("kernel ring buffer dropped effect events".to_owned());
        }
        if self.object_resolution_mode.kernel_file_object_enabled() {
            if state
                .object_resolution_resolved
                .checked_add(state.object_resolution_unresolved)
                != Some(state.object_resolution_attempted)
            {
                reasons
                    .push("kernel file-object resolution accounting invariant failed".to_owned());
            }
            if state.object_resolution_failed_syscalls != state.object_resolution_unresolved {
                reasons.push(
                    "unresolved file-object results are not exactly the failed selected opens"
                        .to_owned(),
                );
            }
            if state.object_join_missing != 0
                || state.object_join_ambiguous != 0
                || state.object_read_failed != 0
                || state.object_delete_failed != 0
            {
                reasons
                    .push("kernel file-object resolution or correlation was incomplete".to_owned());
            }
        } else if state.object_resolution_attempted != 0
            || state.object_resolution_resolved != 0
            || state.object_resolution_unresolved != 0
            || state.object_resolution_failed_syscalls != 0
            || state.object_join_missing != 0
            || state.object_join_ambiguous != 0
            || state.object_read_failed != 0
            || state.object_delete_failed != 0
            || state.object_path_unavailable != 0
            || state.object_pending_remaining != 0
        {
            reasons.push("disabled kernel file-object path reported activity".to_owned());
        }
        let parse_failures = self
            .callback
            .decode_failures
            .saturating_add(self.callback.routing_failures)
            .saturating_add(self.callback.pairing_failures)
            .saturating_add(self.callback.capacity_failures);
        if parse_failures != 0 {
            reasons.push("userspace decode, routing, pairing, or capacity failure".to_owned());
        }
        let fatal_kernel_flags = self.fatal_kernel_flags.get(&key).copied().unwrap_or(0);
        if fatal_kernel_flags != 0 {
            reasons.push(format!(
                "{fatal_kernel_flags} event(s) reported a fatal kernel correlation flag"
            ));
        }
        let open_attempts = self
            .open_attempts
            .get(&key)
            .map(HashMap::len)
            .unwrap_or_default() as u64;
        if open_attempts != 0 && state.event_dropped == 0 {
            reasons.push(format!(
                "{open_attempts} persisted operation attempt(s) had no persisted result"
            ));
        }
        let seen_sequences = self
            .seen_sequences
            .get(&key)
            .context("registered run has no sequence tracker")?;
        if state.event_dropped == 0 && state.event_published == persisted {
            let sequence_range_complete = if persisted == 0 {
                seen_sequences.is_empty() && state.next_event_seq == 0
            } else {
                seen_sequences.len() as u64 == persisted
                    && seen_sequences.contains(&1)
                    && seen_sequences.contains(&state.next_event_seq)
                    && seen_sequences
                        .iter()
                        .all(|sequence| *sequence <= state.next_event_seq)
            };
            if !sequence_range_complete {
                reasons.push("persisted event sequence set is incomplete or duplicated".to_owned());
            }
        }
        if !producer_barrier_complete {
            reasons.push("producer cgroup empty/frozen barrier was not established".to_owned());
        }
        if state.event_attempted == 0 {
            reasons.push(
                "no selected operation exercised the event transport during this run".to_owned(),
            );
        }
        let drain_completed = !timed_out
            && state.pending_remaining == 0
            && state.object_pending_remaining == 0
            && state.event_published == persisted;
        let transport_status =
            if state.event_attempted == 0 && drain_completed && reasons.len() == 1 {
                TransportStatus::UnprovenNoEvents
            } else if drain_completed && reasons.is_empty() {
                TransportStatus::Complete
            } else {
                TransportStatus::Incomplete
            };
        if drain_completed {
            self.finished.insert(key);
        }
        Ok(SystemEffectHealth {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            run_id: self.run_id.clone(),
            run_epoch: epoch,
            cgroup_id,
            profile: self.profile,
            object_resolution_mode: self.object_resolution_mode,
            transport_status,
            coverage_status: CoverageStatus::Partial,
            object_resolution_status: ObjectResolutionStatus::Partial,
            operation_attempted: state.operation_attempted,
            operation_completed: state.operation_completed,
            event_attempted: state.event_attempted,
            event_published: state.event_published,
            event_dropped: state.event_dropped,
            events_persisted: persisted,
            pending_insert_failed: state.pending_insert_failed,
            pending_missing: state.pending_missing,
            pending_remaining: state.pending_remaining,
            userspace_failures: parse_failures,
            fatal_kernel_flags,
            capture_read_failures: self.capture_read_failures.get(&key).copied().unwrap_or(0),
            capture_truncations: self.capture_truncations.get(&key).copied().unwrap_or(0),
            capture_invalid_lengths: self.capture_invalid_lengths.get(&key).copied().unwrap_or(0),
            object_resolution_attempted: state.object_resolution_attempted,
            object_resolution_resolved: state.object_resolution_resolved,
            object_resolution_unresolved: state.object_resolution_unresolved,
            object_resolution_failed_syscalls: state.object_resolution_failed_syscalls,
            object_join_missing: state.object_join_missing,
            object_join_ambiguous: state.object_join_ambiguous,
            object_read_failed: state.object_read_failed,
            object_delete_failed: state.object_delete_failed,
            object_path_unavailable: state.object_path_unavailable,
            object_pending_remaining: state.object_pending_remaining,
            producer_barrier_complete,
            drain_completed,
            wal_durable: true,
            poll_calls: self.poll_calls,
            maximum_events_per_poll: self.maximum_events_per_poll,
            callback_queue_high_water: self.callback.queue_high_water as u64,
            callback_queue_capacity: MAX_CALLBACK_QUEUE_EVENTS as u64,
            reasons,
            coverage_gaps: coverage_gaps_for(self.profile, self.object_resolution_mode),
        })
    }

    pub fn unregister_run(&mut self, cgroup_id: u64, epoch: u64) -> Result<()> {
        let key = (cgroup_id, epoch);
        if !self.finished.contains(&key) {
            bail!("finish_run must succeed before unregister_run");
        }
        let state = self.read_run_state(cgroup_id, epoch)?;
        if state.pending_remaining != 0 || state.object_pending_remaining != 0 {
            bail!("refusing to unregister a run with pending effect or object operations");
        }
        map_delete(self.run_states_fd, &cgroup_id).context("unregister system-effect run")?;
        self.persisted.remove(&key);
        self.open_attempts.remove(&key);
        self.seen_sequences.remove(&key);
        self.fatal_kernel_flags.remove(&key);
        self.capture_read_failures.remove(&key);
        self.capture_truncations.remove(&key);
        self.capture_invalid_lengths.remove(&key);
        self.finished.remove(&key);
        Ok(())
    }

    fn persist_queued(&mut self) -> Result<usize> {
        let mut count = 0;
        while let Some(event) = self.callback.queue.pop_front() {
            let key = (event.cgroup_id, event.run_epoch);
            let policy = self
                .event_policies
                .get(&event.syscall_nr)
                .copied()
                .context("event syscall is absent from the frozen policy")?;
            let schema = event.to_schema(&self.run_id, &self.boot_id, policy)?;
            let json = serde_json::to_vec(&schema)?;
            let next_size = self
                .jsonl_bytes
                .checked_add(json.len() as u64 + 1)
                .context("system-effect JSONL size overflow")?;
            if next_size > MAX_JSONL_BYTES {
                bail!("system-effect JSONL exceeded {MAX_JSONL_BYTES} bytes");
            }
            self.wal.append(&event)?;
            self.jsonl.write_all(&json)?;
            self.jsonl.write_all(b"\n")?;
            self.jsonl_bytes = next_size;

            if let Some(persisted) = self.persisted.get_mut(&key) {
                *persisted = persisted.saturating_add(1);
                if let Some(sequences) = self.seen_sequences.get_mut(&key) {
                    if !sequences.insert(event.event_seq) {
                        self.callback.pairing_failures =
                            self.callback.pairing_failures.saturating_add(1);
                    }
                } else {
                    self.callback.routing_failures =
                        self.callback.routing_failures.saturating_add(1);
                }
                const FATAL_FLAGS: u32 = FLAG_PENDING_INSERT_FAILED
                    | FLAG_PENDING_MISSING
                    | FLAG_PENDING_POISONED
                    | FLAG_PENDING_DELETE_FAILED
                    | FLAG_POLICY_INVALID
                    | FLAG_SYSCALL_MISMATCH
                    | FLAG_OBJECT_JOIN_MISSING
                    | FLAG_OBJECT_JOIN_AMBIGUOUS
                    | FLAG_OBJECT_READ_FAILED
                    | FLAG_OBJECT_DELETE_FAILED;
                if event.flags & FATAL_FLAGS != 0 {
                    if let Some(count) = self.fatal_kernel_flags.get_mut(&key) {
                        *count = count.saturating_add(1);
                    }
                }
                if event.flags & (FLAG_PAYLOAD1_READ_FAILED | FLAG_PAYLOAD2_READ_FAILED) != 0 {
                    if let Some(count) = self.capture_read_failures.get_mut(&key) {
                        *count = count.saturating_add(1);
                    }
                }
                if event.flags & (FLAG_PAYLOAD1_TRUNCATED | FLAG_PAYLOAD2_TRUNCATED) != 0 {
                    if let Some(count) = self.capture_truncations.get_mut(&key) {
                        *count = count.saturating_add(1);
                    }
                }
                if event.flags & (FLAG_PAYLOAD1_INVALID_LENGTH | FLAG_PAYLOAD2_INVALID_LENGTH) != 0
                {
                    if let Some(count) = self.capture_invalid_lengths.get_mut(&key) {
                        *count = count.saturating_add(1);
                    }
                }
                if let Some(attempts) = self.open_attempts.get_mut(&key) {
                    if event.kind == EVENT_OPERATION_ATTEMPT {
                        let identity = AttemptIdentity {
                            pid_tgid: event.pid_tgid,
                            syscall_nr: event.syscall_nr,
                            domain: event.domain,
                            operation: event.operation,
                            ktime_ns: event.ktime_ns,
                            args: event.args,
                        };
                        if attempts.insert(event.event_seq, identity).is_some() {
                            self.callback.pairing_failures =
                                self.callback.pairing_failures.saturating_add(1);
                        }
                    } else if event.kind == EVENT_OPERATION_RESULT && event.related_attempt_seq != 0
                    {
                        let identity = attempts.remove(&event.related_attempt_seq);
                        let matches = identity
                            .map(|attempt| {
                                attempt.pid_tgid == event.pid_tgid
                                    && attempt.syscall_nr == event.syscall_nr
                                    && attempt.domain == event.domain
                                    && attempt.operation == event.operation
                                    && attempt.args == event.args
                                    && event.event_seq > event.related_attempt_seq
                                    && attempt.ktime_ns <= event.ktime_ns
                            })
                            .unwrap_or(false);
                        if !matches {
                            self.callback.pairing_failures =
                                self.callback.pairing_failures.saturating_add(1);
                        }
                    }
                } else {
                    self.callback.routing_failures =
                        self.callback.routing_failures.saturating_add(1);
                }
            } else {
                self.callback.routing_failures = self.callback.routing_failures.saturating_add(1);
            }
            count += 1;
        }
        Ok(count)
    }

    fn sync_outputs(&mut self) -> Result<()> {
        self.wal.sync().context("sync system-effect WAL")?;
        self.jsonl.flush().context("flush system-effect JSONL")?;
        self.jsonl
            .get_ref()
            .sync_all()
            .context("sync system-effect JSONL")?;
        Ok(())
    }

    fn read_run_state(&self, cgroup_id: u64, epoch: u64) -> Result<RunState> {
        let mut state = RunState::default();
        map_lookup(self.run_states_fd, &cgroup_id, &mut state)
            .context("read system-effect run counters")?;
        if state.epoch != epoch {
            bail!(
                "system-effect run epoch mismatch for cgroup {cgroup_id}: {} != {epoch}",
                state.epoch
            );
        }
        Ok(state)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransportStatus {
    Complete,
    Incomplete,
    UnprovenNoEvents,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageStatus {
    Partial,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObjectResolutionStatus {
    Partial,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemEffectHealth {
    pub schema_version: u32,
    pub run_id: String,
    pub run_epoch: u64,
    pub cgroup_id: u64,
    pub profile: PolicyProfile,
    pub object_resolution_mode: FileObjectResolutionMode,
    pub transport_status: TransportStatus,
    pub coverage_status: CoverageStatus,
    pub object_resolution_status: ObjectResolutionStatus,
    pub operation_attempted: u64,
    pub operation_completed: u64,
    pub event_attempted: u64,
    pub event_published: u64,
    pub event_dropped: u64,
    pub events_persisted: u64,
    pub pending_insert_failed: u64,
    pub pending_missing: u64,
    pub pending_remaining: u64,
    pub userspace_failures: u64,
    pub fatal_kernel_flags: u64,
    pub capture_read_failures: u64,
    pub capture_truncations: u64,
    pub capture_invalid_lengths: u64,
    pub object_resolution_attempted: u64,
    pub object_resolution_resolved: u64,
    pub object_resolution_unresolved: u64,
    pub object_resolution_failed_syscalls: u64,
    pub object_join_missing: u64,
    pub object_join_ambiguous: u64,
    pub object_read_failed: u64,
    pub object_delete_failed: u64,
    pub object_path_unavailable: u64,
    pub object_pending_remaining: u64,
    pub producer_barrier_complete: bool,
    pub drain_completed: bool,
    pub wal_durable: bool,
    pub poll_calls: u64,
    pub maximum_events_per_poll: u64,
    pub callback_queue_high_water: u64,
    pub callback_queue_capacity: u64,
    pub reasons: Vec<String>,
    pub coverage_gaps: Vec<String>,
}

pub fn coverage_gaps(profile: PolicyProfile) -> Vec<String> {
    coverage_gaps_for(profile, FileObjectResolutionMode::UserInput)
}

pub fn coverage_gaps_for(
    profile: PolicyProfile,
    object_resolution_mode: FileObjectResolutionMode,
) -> Vec<String> {
    let mut gaps = vec![
        "native syscall ABI only; compat/x32 calls are not reliably classified".to_owned(),
        "successful operation results are not proof that durable state differs".to_owned(),
        "MAP_SHARED memory writes are not observed after the mapping is established".to_owned(),
        "io_uring requests and completions are not decoded or causally joined".to_owned(),
        "namespace creation through clone/clone3 is not recorded by this syscall-pair sensor"
            .to_owned(),
        "kernel-worker, writeback, softirq, and delayed async effects are not causally attributed"
            .to_owned(),
        "exact cgroup attribution identifies an unclassified run-execution-domain caller; it does not identify Agent code or observe delegated effects"
            .to_owned(),
        "netlink and generic ioctl payload semantics are not decoded".to_owned(),
        "cooperative controlled workloads only; a privileged adversarial workload can evade the exact cgroup or tamper with enumerable BPF maps".to_owned(),
    ];
    match object_resolution_mode {
        FileObjectResolutionMode::UserInput => gaps.push(
            "path captures are bounded user input, not kernel-resolved file identities".to_owned(),
        ),
        FileObjectResolutionMode::KernelFileOpenPartial => gaps.push(
            "KERNEL_RESOLVED FILE_OBJECT covers successful selected native open/openat/openat2/creat results only when exactly one file_open join is observed; O_PATH/no-hook and duplicate stacked-filesystem opens fail evidence closed, while attempts, failed opens, other file operations, and all socket operations remain USER_INPUT_ONLY or UNRESOLVED"
                .to_owned(),
        ),
        FileObjectResolutionMode::KernelFileOpenWritePartial => gaps.push(
            "KERNEL_RESOLVED FILE_OBJECT covers successful selected native open/openat/openat2/creat results with exactly one file_open join and positive-byte write/pwrite64/writev/pwritev/pwritev2 results with their required non-sleepable file_permission join; missing required hooks, O_PATH, and duplicate stacked-filesystem opens fail evidence closed; pipefs/socketfs FILE_OBJECT identities are not socket endpoints or persistent-state proof, and write identities deliberately have no kernel path snapshot"
                .to_owned(),
        ),
    }
    if object_resolution_mode != FileObjectResolutionMode::KernelFileOpenWritePartial {
        gaps.push(
            "fd-based operations do not yet resolve mount/dev/inode object identity".to_owned(),
        );
    } else {
        gaps.push(
            "FD object identity remains unresolved for truncate, setattr, allocation, range-transfer, sync, mmap, ioctl, and other non-write FD operations"
                .to_owned(),
        );
    }
    match profile {
        PolicyProfile::Control => gaps.push(
            "control profile omits write/send data-path syscalls and noisy generic interfaces"
                .to_owned(),
        ),
        PolicyProfile::Balanced => gaps.push(
            "balanced profile omits mmap/mprotect, fsync, ioctl, prctl, and setsockopt events"
                .to_owned(),
        ),
        PolicyProfile::Full => {}
    }
    gaps
}

fn read_object(path: &Path) -> Result<(Vec<u8>, String)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open system-effect BPF object {}", path.display()))?;
    let before = file
        .metadata()
        .context("inspect system-effect BPF object")?;
    if !before.file_type().is_file() || before.nlink() != 1 {
        bail!("system-effect BPF object must be a singly linked regular file");
    }
    if before.len() == 0 || before.len() > MAX_OBJECT_BYTES {
        bail!("system-effect BPF object size must be in 1..={MAX_OBJECT_BYTES} bytes");
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    let mut limited = file.take(MAX_OBJECT_BYTES + 1);
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
        bail!("system-effect BPF object changed while being read");
    }
    let digest = format!("{:x}", Sha256::digest(&bytes));
    Ok((bytes, digest))
}

fn verify_digest(actual: &str, expected: &str) -> Result<()> {
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("expected system-effect object digest is not canonical SHA-256");
    }
    if actual != expected {
        bail!("system-effect object digest does not match trusted policy");
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
        bail!("boot_id must be a canonical lowercase UUID");
    }
    Ok(())
}

fn open_new(path: &Path) -> Result<BufWriter<File>> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create system-effect output {}", path.display()))?;
    Ok(BufWriter::new(file))
}

fn find_map_fd(object: *mut libbpf::bpf_object, name: &str) -> Result<c_int> {
    let name = CString::new(name).unwrap();
    let fd = unsafe { libbpf::bpf_object__find_map_fd_by_name(object, name.as_ptr()) };
    if fd < 0 {
        return Err(libbpf_error(fd)).context(format!("find BPF map {}", name.to_string_lossy()));
    }
    Ok(fd)
}

#[derive(Clone, Copy)]
struct MapAbi {
    name: &'static str,
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
}

impl MapAbi {
    const fn new(
        name: &'static str,
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
    ) -> Self {
        Self {
            name,
            map_type,
            key_size,
            value_size,
            max_entries,
            map_flags: 0,
        }
    }

    const fn with_flags(mut self, map_flags: u32) -> Self {
        self.map_flags = map_flags;
        self
    }
}

fn validate_map_abi(fd: c_int, expected: MapAbi) -> Result<()> {
    let mut info = libbpf::bpf_map_info::default();
    let mut length = std::mem::size_of::<libbpf::bpf_map_info>() as u32;
    let info_ptr: *mut libbpf::bpf_map_info = &mut info;
    check_rc(
        unsafe { libbpf::bpf_obj_get_info_by_fd(fd, info_ptr.cast(), &mut length) },
        "read system-effect map ABI",
    )?;
    if info.type_ != expected.map_type
        || info.key_size != expected.key_size
        || info.value_size != expected.value_size
        || info.max_entries != expected.max_entries
        || info.map_flags != expected.map_flags
    {
        bail!(
            "map {} ABI is {}/{}/{}/{}/{}; expected {}/{}/{}/{}/{}",
            expected.name,
            info.type_,
            info.key_size,
            info.value_size,
            info.max_entries,
            info.map_flags,
            expected.map_type,
            expected.key_size,
            expected.value_size,
            expected.max_entries,
            expected.map_flags
        );
    }
    Ok(())
}

fn find_program(object: *mut libbpf::bpf_object, name: &str) -> Result<*mut libbpf::bpf_program> {
    let name = CString::new(name).unwrap();
    let program = unsafe { libbpf::bpf_object__find_program_by_name(object, name.as_ptr()) };
    if program.is_null() {
        bail!(
            "system-effect BPF program {} is absent",
            name.to_string_lossy()
        );
    }
    Ok(program)
}

fn set_program_autoload(object: *mut libbpf::bpf_object, name: &str, autoload: bool) -> Result<()> {
    let program = find_program(object, name)?;
    check_rc(
        unsafe { libbpf::bpf_program__set_autoload(program, autoload) },
        &format!("set system-effect BPF program {name} autoload={autoload}"),
    )
}

fn set_map_autocreate(object: *mut libbpf::bpf_object, name: &str, autocreate: bool) -> Result<()> {
    let c_name = CString::new(name).unwrap();
    let map = unsafe { libbpf::bpf_object__find_map_by_name(object, c_name.as_ptr()) };
    if map.is_null() {
        bail!("system-effect BPF map {name} is absent");
    }
    check_rc(
        unsafe { libbpf::bpf_map__set_autocreate(map, autocreate) },
        &format!("set system-effect BPF map {name} autocreate={autocreate}"),
    )
}

fn configure_object_autoload(
    object: *mut libbpf::bpf_object,
    mode: FileObjectResolutionMode,
) -> Result<()> {
    let kernel_file_object = mode.kernel_file_object_enabled();
    set_program_autoload(object, PROGRAM_EXIT, !kernel_file_object)?;
    set_program_autoload(object, PROGRAM_FILE_EXIT, kernel_file_object)?;
    set_program_autoload(object, PROGRAM_FILE_OBJECT, kernel_file_object)?;
    set_program_autoload(
        object,
        PROGRAM_FILE_PERMISSION,
        mode.kernel_file_write_enabled(),
    )?;
    if !kernel_file_object {
        set_map_autocreate(object, MAP_OBJECT_CONFIG, false)?;
        set_map_autocreate(object, MAP_FILE_OBJECTS, false)?;
    }
    Ok(())
}

fn attach_tracepoint(
    resources: &mut KernelResources,
    program_name: &str,
    category: &str,
    name: &str,
) -> Result<()> {
    let category = CString::new(category).unwrap();
    let name = CString::new(name).unwrap();
    let program = find_program(resources.object, program_name)?;
    let link = unsafe {
        libbpf::bpf_program__attach_tracepoint(program, category.as_ptr(), name.as_ptr())
    };
    check_pointer(link.cast(), "attach system-effect raw tracepoint")?;
    resources.links.push(link);
    Ok(())
}

fn attach_lsm(resources: &mut KernelResources, program_name: &str) -> Result<()> {
    let program = find_program(resources.object, program_name)?;
    let link = unsafe { libbpf::bpf_program__attach_lsm(program) };
    check_pointer(link.cast(), "attach system-effect BPF LSM file_open")?;
    resources.links.push(link);
    Ok(())
}

fn collect_exclusions(resources: &KernelResources) -> Result<ObjectExclusions> {
    let mut exclusions = ObjectExclusions::default();
    unsafe {
        let mut program = ptr::null_mut();
        loop {
            program = libbpf::bpf_object__next_program(resources.object, program);
            if program.is_null() {
                break;
            }
            let fd = libbpf::bpf_program__fd(program);
            if fd < 0 {
                continue;
            }
            let id = program_id(fd)?;
            if !exclusions.program_ids.insert(id) {
                bail!("duplicate system-effect recorder program ID {id}");
            }
        }

        let mut map = ptr::null_mut();
        loop {
            map = libbpf::bpf_object__next_map(resources.object, map);
            if map.is_null() {
                break;
            }
            let fd = libbpf::bpf_map__fd(map);
            if fd < 0 {
                continue;
            }
            let id = map_id(fd)?;
            if !exclusions.map_ids.insert(id) {
                bail!("duplicate system-effect recorder map ID {id}");
            }
        }

        for link in &resources.links {
            let id = link_id(libbpf::bpf_link__fd(*link))?;
            if !exclusions.link_ids.insert(id) {
                bail!("duplicate system-effect recorder link ID {id}");
            }
        }
    }
    if exclusions.program_ids.is_empty()
        || exclusions.map_ids.is_empty()
        || exclusions.link_ids.is_empty()
    {
        bail!("system-effect recorder loaded without enumerable programs, maps, or links");
    }
    Ok(exclusions)
}

unsafe fn program_id(fd: c_int) -> Result<u32> {
    if fd < 0 {
        bail!("system-effect recorder program has no valid FD");
    }
    let mut info = libbpf::bpf_prog_info::default();
    let mut length = std::mem::size_of::<libbpf::bpf_prog_info>() as u32;
    let info_ptr: *mut libbpf::bpf_prog_info = &mut info;
    check_rc(
        libbpf::bpf_obj_get_info_by_fd(fd, info_ptr.cast(), &mut length),
        "read system-effect recorder program ID",
    )?;
    if info.id == 0 {
        bail!("system-effect recorder program returned a zero ID");
    }
    Ok(info.id)
}

unsafe fn map_id(fd: c_int) -> Result<u32> {
    if fd < 0 {
        bail!("system-effect recorder map has no valid FD");
    }
    let mut info = libbpf::bpf_map_info::default();
    let mut length = std::mem::size_of::<libbpf::bpf_map_info>() as u32;
    let info_ptr: *mut libbpf::bpf_map_info = &mut info;
    check_rc(
        libbpf::bpf_obj_get_info_by_fd(fd, info_ptr.cast(), &mut length),
        "read system-effect recorder map ID",
    )?;
    if info.id == 0 {
        bail!("system-effect recorder map returned a zero ID");
    }
    Ok(info.id)
}

unsafe fn link_id(fd: c_int) -> Result<u32> {
    if fd < 0 {
        bail!("system-effect recorder link has no valid FD");
    }
    let mut info = std::mem::zeroed::<libbpf::bpf_link_info>();
    let mut length = std::mem::size_of::<libbpf::bpf_link_info>() as u32;
    let info_ptr: *mut libbpf::bpf_link_info = &mut info;
    check_rc(
        libbpf::bpf_obj_get_info_by_fd(fd, info_ptr.cast(), &mut length),
        "read system-effect recorder link ID",
    )?;
    if info.id == 0 {
        bail!("system-effect recorder link returned a zero ID");
    }
    Ok(info.id)
}

fn map_update<K, V>(fd: c_int, key: &K, value: &V, flags: u64) -> Result<()> {
    check_rc(
        unsafe {
            libbpf::bpf_map_update_elem(
                fd,
                (key as *const K).cast(),
                (value as *const V).cast(),
                flags,
            )
        },
        "update system-effect BPF map",
    )
}

fn map_lookup<K, V>(fd: c_int, key: &K, value: &mut V) -> Result<()> {
    check_rc(
        unsafe {
            libbpf::bpf_map_lookup_elem(fd, (key as *const K).cast(), (value as *mut V).cast())
        },
        "look up system-effect BPF map",
    )
}

fn map_delete<K>(fd: c_int, key: &K) -> Result<()> {
    check_rc(
        unsafe { libbpf::bpf_map_delete_elem(fd, (key as *const K).cast()) },
        "delete system-effect BPF map entry",
    )
}

fn check_pointer(pointer: *const c_void, operation: &str) -> Result<()> {
    if pointer.is_null() {
        return Err(std::io::Error::last_os_error()).context(operation.to_owned());
    }
    let error = unsafe { libbpf::libbpf_get_error(pointer) };
    if error != 0 {
        return Err(libbpf_error(error as c_int)).context(operation.to_owned());
    }
    Ok(())
}

fn check_rc(rc: c_int, operation: &str) -> Result<()> {
    if rc < 0 {
        Err(libbpf_error(rc)).context(operation.to_owned())
    } else {
        Ok(())
    }
}

fn libbpf_error(rc: c_int) -> anyhow::Error {
    let errno = if rc < 0 { -rc } else { rc };
    anyhow!("{}", std::io::Error::from_raw_os_error(errno))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn callback_fixture() -> KernelEvent {
        KernelEvent {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            kind: EVENT_OPERATION_ATTEMPT,
            domain: EffectDomain::KernelControl as u16,
            operation: EffectOperation::BpfCommand as u32,
            flags: 0,
            syscall_nr: libc::SYS_bpf as i32,
            run_epoch: 1,
            event_seq: 1,
            related_attempt_seq: 0,
            ktime_ns: 1,
            cgroup_id: 1,
            pid_tgid: 1,
            return_value: 0,
            args: [0; 6],
            comm: [0; 16],
            payload_lens: [0; 2],
            payload_kinds: [protocol::PAYLOAD_NONE; 2],
            payload_arg_indices: [0; 2],
            payloads: [[0; protocol::CAPTURE_BYTES]; 2],
            file_object: None,
        }
    }

    #[test]
    fn rust_map_layouts_are_stable() {
        assert_eq!(std::mem::size_of::<RunState>(), 160);
        assert_eq!(std::mem::size_of::<ObjectConfig>(), 8);
        assert_eq!(std::mem::size_of::<KernelPolicy>(), 32);
        assert_eq!(protocol::KERNEL_EVENT_SIZE, 344);
        assert_eq!(protocol::KERNEL_FILE_EVENT_SIZE, 328);
    }

    #[test]
    fn every_profile_reports_semantic_gaps() {
        for profile in [
            PolicyProfile::Control,
            PolicyProfile::Balanced,
            PolicyProfile::Full,
        ] {
            let gaps = coverage_gaps(profile);
            assert!(gaps.iter().any(|gap| gap.contains("not proof")));
            assert!(gaps.iter().any(|gap| gap.contains("native syscall ABI")));
        }
    }

    #[test]
    fn callback_batch_yields_only_after_retaining_the_boundary_event() {
        let mut state = CallbackState::default();
        for index in 0..MAX_CALLBACK_QUEUE_EVENTS {
            let result = enqueue_event(&mut state, callback_fixture());
            if index + 1 == MAX_CALLBACK_QUEUE_EVENTS {
                assert_eq!(result, -libc::EAGAIN);
            } else {
                assert_eq!(result, 0);
            }
        }
        assert_eq!(state.queue.len(), MAX_CALLBACK_QUEUE_EVENTS);
        assert!(state.batch_limit_reached);
        assert_eq!(state.capacity_failures, 0);

        assert_eq!(enqueue_event(&mut state, callback_fixture()), -libc::EFBIG);
        assert_eq!(state.queue.len(), MAX_CALLBACK_QUEUE_EVENTS);
        assert_eq!(state.capacity_failures, 1);
    }
}
