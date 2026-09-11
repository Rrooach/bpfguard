// SPDX-License-Identifier: GPL-2.0-only

mod protocol;
mod wal;

pub use protocol::{
    command_name, KernelEvent, FLAG_COMMON_ATTRS, FLAG_PENDING_DELETE_FAILED,
    FLAG_PENDING_INSERT_FAILED, FLAG_PENDING_MISSING, FLAG_PENDING_POISONED,
};
pub use wal::{
    recover as recover_wal, recover_reader as recover_wal_reader, WalRecovery, WalWriter,
};

use anyhow::{anyhow, bail, Context, Result};
use bpf_observer_schema::{
    EvidenceHealth, ObjectExclusions, MAX_RAW_JSONL_BYTES, MAX_RECORDED_EVENTS,
};
use libbpf_sys as libbpf;
use protocol::{RunState, EVENT_SYSCALL_ATTEMPTED};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::ffi::{c_void, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::os::raw::c_int;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::ptr;
use std::slice;
use std::time::{Duration, Instant};

const MAP_CONFIG: &str = "recorder_config";
const MAP_RUN_STATES: &str = "run_states";
const MAP_PENDING_CALLS: &str = "pending_calls";
const MAP_EVENTS: &str = "events";
const PROGRAM_ENTER: &str = "trace_bpf_enter";
const PROGRAM_EXIT: &str = "trace_bpf_exit";
const MAX_CALLBACK_QUEUE_EVENTS: usize = 4_096;
const MAX_RECORDER_OBJECT_BYTES: u64 = 16 * 1024 * 1024;
const RECORDER_MAX_RUNS: u32 = 1_024;
const RECORDER_MAX_PENDING: u32 = 16_384;
const RECORDER_RING_BYTES: u32 = 1 << 20;
const RECORDER_PENDING_VALUE_SIZE: u32 = 40;

#[repr(C)]
struct KernelConfig {
    bpf_syscall_nrs: [i64; 3],
    observer_tgid: u32,
    exclusive_window: u32,
    outside_cgroup_syscall_attempted: u64,
}

#[derive(Default)]
struct CallbackState {
    queue: VecDeque<KernelEvent>,
    decode_failures: u64,
    routing_failures: u64,
    capacity_failures: u64,
    accepted_events: u64,
}

fn enqueue_event(state: &mut CallbackState, event: KernelEvent) -> c_int {
    if state.queue.len() >= MAX_CALLBACK_QUEUE_EVENTS
        || state.accepted_events >= MAX_RECORDED_EVENTS
    {
        state.capacity_failures = state.capacity_failures.saturating_add(1);
        // A negative callback result forces libbpf to return from
        // ring_buffer__poll instead of continuously consuming into memory.
        return -libc::EFBIG;
    }
    state.queue.push_back(event);
    state.accepted_events = state.accepted_events.saturating_add(1);
    0
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
                self.ring = ptr::null_mut();
            }
            for link in self.links.drain(..).rev() {
                if !link.is_null() {
                    libbpf::bpf_link__destroy(link);
                }
            }
            if !self.object.is_null() {
                libbpf::bpf_object__close(self.object);
                self.object = ptr::null_mut();
            }
        }
    }
}

/// Loaded raw-syscall recorder plus its crash-detectable output streams.
///
/// `finish_run` assumes the caller has first made the exact cgroup empty. It
/// proves that every kernel-published record for the stable run counters was
/// consumed and synced, and that no syscall remains in the pending table.
pub struct Recorder {
    // Resources must be dropped before callback, whose address is owned by the
    // libbpf ring buffer.
    resources: KernelResources,
    callback: Box<CallbackState>,
    config_fd: c_int,
    run_states_fd: c_int,
    run_id: String,
    allowed: BTreeSet<u32>,
    exclusions: ObjectExclusions,
    object_sha256: String,
    wal: WalWriter,
    jsonl: BufWriter<File>,
    jsonl_bytes: u64,
    persisted: HashMap<(u64, u64), u64>,
    persisted_samples: HashMap<(u64, u64), Vec<KernelEvent>>,
    unsupported: HashMap<(u64, u64), BTreeSet<u32>>,
    allowlist_enforced: HashSet<(u64, u64)>,
    finished: HashSet<(u64, u64)>,
    exclusive_window_state: ExclusiveWindowState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExclusiveWindowState {
    Inactive,
    Armed,
    Closed,
}

impl Recorder {
    pub fn open(
        bpf_object: &Path,
        expected_object_sha256: &str,
        output_dir: &Path,
        run_id: &str,
        allowed: &BTreeSet<u32>,
    ) -> Result<Self> {
        if run_id.is_empty() || run_id.contains('\0') {
            bail!("run_id must be a nonempty string without NUL bytes");
        }
        fs::create_dir_all(output_dir)
            .with_context(|| format!("create recorder output {}", output_dir.display()))?;
        let wal = WalWriter::create(&output_dir.join("raw-events.bin"))?;
        let jsonl = open_new(&output_dir.join("raw-events.jsonl"))?;

        // Read, hash, and load exactly the same immutable byte buffer. Opening
        // the pathname once avoids a load-vs-manifest TOCTOU where a replaced
        // file could otherwise give the loaded object a different digest.
        let (object_bytes, object_sha256) = read_recorder_object(bpf_object)?;
        verify_recorder_object_digest(&object_sha256, expected_object_sha256)?;
        let object = unsafe {
            libbpf::bpf_object__open_mem(
                object_bytes.as_ptr().cast(),
                object_bytes.len() as u64,
                ptr::null(),
            )
        };
        check_libbpf_pointer(object.cast(), "open BPF recorder object")?;
        let mut resources = KernelResources::new(object);

        let rc = unsafe { libbpf::bpf_object__load(resources.object) };
        check_libbpf_rc(rc, "load BPF recorder object")?;

        let config_fd = find_map_fd(resources.object, MAP_CONFIG)?;
        let run_states_fd = find_map_fd(resources.object, MAP_RUN_STATES)?;
        let pending_calls_fd = find_map_fd(resources.object, MAP_PENDING_CALLS)?;
        let events_fd = find_map_fd(resources.object, MAP_EVENTS)?;
        validate_map_abi(
            config_fd,
            MapAbi {
                name: MAP_CONFIG,
                map_type: libbpf::BPF_MAP_TYPE_ARRAY,
                key_size: std::mem::size_of::<u32>() as u32,
                value_size: std::mem::size_of::<KernelConfig>() as u32,
                max_entries: 1,
            },
        )?;
        validate_map_abi(
            run_states_fd,
            MapAbi {
                name: MAP_RUN_STATES,
                map_type: libbpf::BPF_MAP_TYPE_HASH,
                key_size: std::mem::size_of::<u64>() as u32,
                value_size: std::mem::size_of::<RunState>() as u32,
                max_entries: RECORDER_MAX_RUNS,
            },
        )?;
        validate_map_abi(
            pending_calls_fd,
            MapAbi {
                name: MAP_PENDING_CALLS,
                map_type: libbpf::BPF_MAP_TYPE_HASH,
                key_size: std::mem::size_of::<u64>() as u32,
                value_size: RECORDER_PENDING_VALUE_SIZE,
                max_entries: RECORDER_MAX_PENDING,
            },
        )?;
        validate_map_abi(
            events_fd,
            MapAbi {
                name: MAP_EVENTS,
                map_type: libbpf::BPF_MAP_TYPE_RINGBUF,
                key_size: 0,
                value_size: 0,
                max_entries: RECORDER_RING_BYTES,
            },
        )?;
        let zero = 0u32;
        let config = KernelConfig {
            bpf_syscall_nrs: bpf_syscall_numbers(),
            observer_tgid: std::process::id(),
            exclusive_window: 0,
            outside_cgroup_syscall_attempted: 0,
        };
        map_update(config_fd, &zero, &config, libbpf::BPF_ANY as u64)
            .context("configure bpf syscall number")?;

        attach_tracepoint(&mut resources, PROGRAM_ENTER, "raw_syscalls", "sys_enter")?;
        attach_tracepoint(&mut resources, PROGRAM_EXIT, "raw_syscalls", "sys_exit")?;

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
            return Err(std::io::Error::last_os_error()).context("create recorder ring buffer");
        }

        let exclusions =
            collect_exclusions(&resources).context("resolve every observer-owned BPF object ID")?;
        Ok(Self {
            resources,
            callback,
            config_fd,
            run_states_fd,
            run_id: run_id.to_owned(),
            allowed: allowed.clone(),
            exclusions,
            object_sha256,
            wal,
            jsonl,
            jsonl_bytes: 0,
            persisted: HashMap::new(),
            persisted_samples: HashMap::new(),
            unsupported: HashMap::new(),
            allowlist_enforced: HashSet::new(),
            finished: HashSet::new(),
            exclusive_window_state: ExclusiveWindowState::Inactive,
        })
    }

    pub fn object_exclusions(&self) -> ObjectExclusions {
        self.exclusions.clone()
    }

    /// Digest of the exact bytes supplied to `bpf_object__open_mem`.
    pub fn object_sha256(&self) -> &str {
        &self.object_sha256
    }

    /// Enable the kernel-side negative gate used by authenticated exclusive
    /// runs. The raw tracepoints then count every bpf() attempt that is neither
    /// made by this exact Observer TGID nor from a registered run cgroup.
    pub fn begin_exclusive_window(&mut self) -> Result<()> {
        if self.exclusive_window_state != ExclusiveWindowState::Inactive {
            bail!("recorder exclusive window cannot be armed more than once");
        }
        let mut config = self.read_config()?;
        if config.exclusive_window != 0 || config.outside_cgroup_syscall_attempted != 0 {
            bail!("recorder exclusive window was already active or tainted");
        }
        config.observer_tgid = std::process::id();
        config.exclusive_window = 1;
        map_update(self.config_fd, &0u32, &config, libbpf::BPF_ANY as u64)
            .context("enable recorder exclusive-actor gate")?;
        self.exclusive_window_state = ExclusiveWindowState::Armed;
        Ok(())
    }

    /// Read the global negative counter without weakening the active gate.
    pub fn assert_exclusive_window_clean(&self) -> Result<()> {
        if self.exclusive_window_state != ExclusiveWindowState::Armed
            || self.resources.links.len() != 2
        {
            bail!("recorder exclusive-actor gate is not fully armed");
        }
        self.read_exclusive_window_clean()
    }

    fn read_exclusive_window_clean(&self) -> Result<()> {
        let config = self.read_config()?;
        if config.exclusive_window != 1 {
            bail!("recorder exclusive-actor gate is not active");
        }
        if config.observer_tgid != std::process::id() {
            bail!("recorder exclusive-actor Observer TGID changed");
        }
        if config.outside_cgroup_syscall_attempted != 0 {
            bail!(
                "observed {} bpf() attempt(s) outside the measured Observer and registered workload cgroup",
                config.outside_cgroup_syscall_attempted
            );
        }
        Ok(())
    }

    /// Establish the local acceptance boundary after FINAL. Destroying the
    /// tracepoint links first is the producer-side barrier: kernel tracepoint
    /// detach waits for invocations that already selected the program. Only
    /// then is the independent map counter read, so a preempted sys_enter
    /// cannot publish its increment after userspace accepted zero.
    ///
    /// The configuration is never rewritten to disable the gate because that
    /// could overwrite a concurrent increment in the ARRAY value.
    pub fn finish_exclusive_window(&mut self) -> Result<()> {
        if self.exclusive_window_state != ExclusiveWindowState::Armed
            || self.resources.links.len() != 2
        {
            bail!("recorder exclusive-actor gate is not fully armed");
        }
        let mut first_error = None;
        for link in self.resources.links.drain(..).rev() {
            let rc = unsafe { libbpf::bpf_link__destroy(link) };
            if rc != 0 && first_error.is_none() {
                first_error = Some(libbpf_error(rc));
            }
        }
        self.exclusive_window_state = ExclusiveWindowState::Closed;
        if let Some(error) = first_error {
            return Err(error).context("detach recorder tracepoints at exclusive boundary");
        }
        self.read_exclusive_window_clean()
    }

    pub fn register_run(&mut self, cgroup_id: u64, epoch: u64) -> Result<()> {
        self.register_run_with_policy(cgroup_id, epoch, true)
    }

    /// Register the transport self-test epoch without applying the workload's
    /// command allowlist. The canary deliberately uses command zero, which is
    /// not necessarily part of the caller's formal scope.
    pub fn register_canary_run(&mut self, cgroup_id: u64, epoch: u64) -> Result<()> {
        self.register_run_with_policy(cgroup_id, epoch, false)
    }

    fn register_run_with_policy(
        &mut self,
        cgroup_id: u64,
        epoch: u64,
        enforce_allowlist: bool,
    ) -> Result<()> {
        if cgroup_id == 0 || epoch == 0 {
            bail!("cgroup_id and epoch must both be nonzero");
        }
        let key = (cgroup_id, epoch);
        if self.persisted.contains_key(&key) {
            bail!("run cgroup/epoch is already registered");
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
        .context("register exact cgroup run")?;
        self.persisted.insert(key, 0);
        self.persisted_samples.insert(key, Vec::new());
        self.unsupported.insert(key, BTreeSet::new());
        if enforce_allowlist {
            self.allowlist_enforced.insert(key);
        }
        Ok(())
    }

    /// Poll the ring buffer and append all decoded records to the binary WAL
    /// and JSONL stream. The return value is the number of fully appended
    /// records, not merely the number consumed from the ring.
    pub fn poll(&mut self, timeout: Duration) -> Result<usize> {
        let millis = timeout.as_millis().min(c_int::MAX as u128) as c_int;
        let rc = unsafe { libbpf::ring_buffer__poll(self.resources.ring, millis) };
        if rc < 0 && rc != -libc::EINTR {
            if self.callback.capacity_failures != 0 {
                bail!(
                    "recorder event capacity exceeded (per-poll queue <= {MAX_CALLBACK_QUEUE_EVENTS}, total events <= {MAX_RECORDED_EVENTS})"
                );
            }
            return Err(libbpf_error(rc)).context("poll recorder ring buffer");
        }
        self.persist_queued()
    }

    pub fn finish_run(
        &mut self,
        cgroup_id: u64,
        epoch: u64,
        timeout: Duration,
    ) -> Result<EvidenceHealth> {
        let key = (cgroup_id, epoch);
        if !self.persisted.contains_key(&key) {
            bail!("run cgroup/epoch is not registered");
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .context("recorder drain timeout exceeds monotonic clock range")?;
        let mut timed_out = false;

        loop {
            self.poll(
                Duration::from_millis(20).min(deadline.saturating_duration_since(Instant::now())),
            )?;
            let first = self.read_run_state(cgroup_id, epoch)?;
            let persisted = self.persisted.get(&key).copied().unwrap_or(0);
            if first.pending_remaining == 0 && first.event_published == persisted {
                // A zero-time consume plus a second counter read closes the
                // producer/consumer visibility race at the end of the run.
                self.poll(Duration::ZERO)?;
                let second = self.read_run_state(cgroup_id, epoch)?;
                let persisted = self.persisted.get(&key).copied().unwrap_or(0);
                if first == second
                    && second.pending_remaining == 0
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
        let mut health = self.health_from_state(key, state);
        health.drain_completed = !timed_out
            && health.pending_remaining == 0
            && health.event_published == health.events_persisted;
        health.wal_durable = true;
        if timed_out {
            health.reasons.push(format!(
                "recorder drain timed out: published={}, persisted={}, pending={}",
                health.event_published, health.events_persisted, health.pending_remaining
            ));
        }
        if health.event_published.checked_add(health.event_dropped) != Some(health.event_attempted)
        {
            health
                .reasons
                .push("kernel event accounting invariant failed".into());
        }
        if health.syscall_attempted != health.syscall_completed {
            health
                .reasons
                .push("bpf syscall enter/exit accounting did not balance".into());
        }
        if health.event_published != health.events_persisted {
            health
                .reasons
                .push("published events were not all durably persisted".into());
        }
        if health.pending_remaining != 0 {
            health
                .reasons
                .push("in-flight bpf syscalls remain pending".into());
        }
        if !timed_out
            && health.pending_remaining == 0
            && health.event_published == health.events_persisted
        {
            self.finished.insert(key);
        }
        Ok(health)
    }

    pub fn unregister_run(&mut self, cgroup_id: u64, epoch: u64) -> Result<()> {
        let key = (cgroup_id, epoch);
        if !self.finished.contains(&key) {
            bail!("finish_run must be called before unregister_run");
        }
        let state = self.read_run_state(cgroup_id, epoch)?;
        if state.pending_remaining != 0 {
            bail!("refusing to unregister a run with pending syscalls");
        }
        map_delete(self.run_states_fd, &cgroup_id).context("unregister exact cgroup run")?;
        self.persisted.remove(&key);
        self.persisted_samples.remove(&key);
        self.unsupported.remove(&key);
        self.allowlist_enforced.remove(&key);
        self.finished.remove(&key);
        Ok(())
    }

    fn persist_queued(&mut self) -> Result<usize> {
        let mut count = 0usize;
        while let Some(event) = self.callback.queue.pop_front() {
            let key = (event.cgroup_id, event.run_epoch);
            let schema_event = event.to_schema(&self.run_id);
            let json = serde_json::to_vec(&schema_event)?;
            let next_jsonl_bytes = self
                .jsonl_bytes
                .checked_add(json.len() as u64 + 1)
                .context("recorder JSONL byte counter overflow")?;
            if next_jsonl_bytes > MAX_RAW_JSONL_BYTES {
                bail!("recorder JSONL exceeded the {MAX_RAW_JSONL_BYTES}-byte hard limit");
            }
            self.wal.append(&event)?;
            self.jsonl.write_all(&json)?;
            self.jsonl.write_all(b"\n")?;
            self.jsonl_bytes = next_jsonl_bytes;
            if let Some(persisted) = self.persisted.get_mut(&key) {
                *persisted = persisted.saturating_add(1);
                if let Some(samples) = self.persisted_samples.get_mut(&key) {
                    if samples.len() < 3 {
                        samples.push(event.clone());
                    }
                } else {
                    self.callback.routing_failures =
                        self.callback.routing_failures.saturating_add(1);
                }
                if event.kind == EVENT_SYSCALL_ATTEMPTED
                    && self.allowlist_enforced.contains(&key)
                    && event.is_unsupported(&self.allowed)
                {
                    if let Some(unsupported) = self.unsupported.get_mut(&key) {
                        unsupported.insert(event.command);
                    } else {
                        self.callback.routing_failures =
                            self.callback.routing_failures.saturating_add(1);
                    }
                }
            } else {
                // Keep the record in the forensic streams, but do not create a
                // phantom registered run. Any routing mismatch taints health.
                self.callback.routing_failures = self.callback.routing_failures.saturating_add(1);
            }
            count += 1;
        }
        Ok(count)
    }

    fn sync_outputs(&mut self) -> Result<()> {
        self.wal.sync().context("sync recorder binary WAL")?;
        self.jsonl.flush().context("flush recorder JSONL")?;
        self.jsonl
            .get_ref()
            .sync_all()
            .context("sync recorder JSONL")?;
        Ok(())
    }

    pub fn validate_native_canary(&self, cgroup_id: u64, epoch: u64) -> Result<()> {
        let key = (cgroup_id, epoch);
        if self.persisted.get(&key) != Some(&2) {
            bail!("native canary did not persist exactly two events");
        }
        let events = self
            .persisted_samples
            .get(&key)
            .context("native canary samples are absent")?;
        if events.len() != 2 {
            bail!("native canary sample count is not exactly two");
        }
        let attempt = &events[0];
        let completion = &events[1];
        let exact = attempt.kind == protocol::EVENT_SYSCALL_ATTEMPTED
            && attempt.flags == 0
            && attempt.command == 0
            && attempt.attr_size == 0
            && attempt.event_seq == 1
            && attempt.related_attempt_seq == 0
            && attempt.cgroup_id == cgroup_id
            && attempt.run_epoch == epoch
            && completion.kind == protocol::EVENT_COMMAND_COMPLETED
            && completion.flags == 0
            && completion.command == 0
            && completion.attr_size == 0
            && completion.event_seq == 2
            && completion.related_attempt_seq == 1
            && completion.cgroup_id == cgroup_id
            && completion.run_epoch == epoch
            && completion.pid_tgid == attempt.pid_tgid
            && completion.ktime_ns >= attempt.ktime_ns
            && completion.return_value < 0;
        if !exact {
            bail!("native canary events do not match the harmless null/zero-size call");
        }
        Ok(())
    }

    fn read_run_state(&self, cgroup_id: u64, epoch: u64) -> Result<RunState> {
        let mut state = RunState::default();
        map_lookup(self.run_states_fd, &cgroup_id, &mut state)
            .context("read recorder run counters")?;
        if state.epoch != epoch {
            bail!(
                "recorder run epoch mismatch for cgroup {cgroup_id}: {} != {epoch}",
                state.epoch
            );
        }
        Ok(state)
    }

    fn read_config(&self) -> Result<KernelConfig> {
        let mut config = KernelConfig {
            bpf_syscall_nrs: [-1; 3],
            observer_tgid: 0,
            exclusive_window: 0,
            outside_cgroup_syscall_attempted: 0,
        };
        map_lookup(self.config_fd, &0u32, &mut config)
            .context("read recorder exclusive-actor configuration")?;
        Ok(config)
    }

    fn health_from_state(&self, key: (u64, u64), state: RunState) -> EvidenceHealth {
        EvidenceHealth {
            recorder_loaded: true,
            run_registered: true,
            producer_barrier_complete: false,
            drain_completed: false,
            wal_durable: false,
            native_transport_canary_passed: false,
            syscall_attempted: state.syscall_attempted,
            syscall_completed: state.syscall_completed,
            last_event_seq: state.next_event_seq,
            event_attempted: state.event_attempted,
            event_published: state.event_published,
            event_dropped: state.event_dropped,
            events_persisted: self.persisted.get(&key).copied().unwrap_or(0),
            pending_insert_failed: state.pending_insert_failed,
            pending_missing: state.pending_missing,
            pending_remaining: state.pending_remaining,
            outside_cgroup_syscall_attempted: self
                .read_config()
                .map(|config| config.outside_cgroup_syscall_attempted)
                .unwrap_or(u64::MAX),
            parse_failed: self
                .callback
                .decode_failures
                .saturating_add(self.callback.routing_failures)
                .saturating_add(self.callback.capacity_failures),
            unsupported_commands: self.unsupported.get(&key).cloned().unwrap_or_default(),
            reasons: Vec::new(),
        }
    }
}

fn read_recorder_object(path: &Path) -> Result<(Vec<u8>, String)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open BPF recorder object {}", path.display()))?;
    let before = file
        .metadata()
        .with_context(|| format!("inspect BPF recorder object {}", path.display()))?;
    if !before.file_type().is_file() || before.nlink() != 1 {
        bail!("BPF recorder object must be a singly linked regular file");
    }
    if before.len() == 0 || before.len() > MAX_RECORDER_OBJECT_BYTES {
        bail!("BPF recorder object size must be in 1..={MAX_RECORDER_OBJECT_BYTES} bytes");
    }

    let mut bytes = Vec::with_capacity(before.len() as usize);
    let mut limited = file.take(MAX_RECORDER_OBJECT_BYTES + 1);
    limited
        .read_to_end(&mut bytes)
        .with_context(|| format!("read BPF recorder object {}", path.display()))?;
    let after = limited
        .get_ref()
        .metadata()
        .with_context(|| format!("reinspect BPF recorder object {}", path.display()))?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || bytes.len() as u64 != before.len()
    {
        bail!("BPF recorder object changed while it was read");
    }
    let digest = format!("{:x}", Sha256::digest(&bytes));
    Ok((bytes, digest))
}

fn verify_recorder_object_digest(actual: &str, expected: &str) -> Result<()> {
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("expected recorder object digest is not canonical SHA-256");
    }
    if actual != expected {
        bail!("recorder object digest does not match trusted policy");
    }
    Ok(())
}

fn bpf_syscall_numbers() -> [i64; 3] {
    #[cfg(target_arch = "x86_64")]
    {
        // x86-64, i386 compat, and x32. raw_syscalls may expose the x32 bit,
        // so retain it rather than assuming the native number is universal.
        return [libc::SYS_bpf, 357, 0x4000_0000 + 321];
    }
    #[cfg(target_arch = "aarch64")]
    {
        // AArch64 plus the AArch32 compat syscall table.
        return [libc::SYS_bpf as i64, 386, -1];
    }
    #[allow(unreachable_code)]
    [libc::SYS_bpf, -1, -1]
}

fn open_new(path: &Path) -> Result<BufWriter<File>> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create recorder output {}", path.display()))?;
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
}

fn validate_map_abi(fd: c_int, expected: MapAbi) -> Result<()> {
    if fd < 0 {
        bail!("recorder map {} has no valid FD", expected.name);
    }
    let mut info = libbpf::bpf_map_info::default();
    let mut length = std::mem::size_of::<libbpf::bpf_map_info>() as u32;
    let info_ptr: *mut libbpf::bpf_map_info = &mut info;
    check_libbpf_rc(
        unsafe { libbpf::bpf_obj_get_info_by_fd(fd, info_ptr.cast(), &mut length) },
        "read recorder map ABI",
    )?;
    if !map_abi_matches(&info, expected) {
        bail!(
            "recorder map {} has incompatible ABI: type/key/value/max/flags={}/{}/{}/{}/{} expected {}/{}/{}/{}/0",
            expected.name,
            info.type_,
            info.key_size,
            info.value_size,
            info.max_entries,
            info.map_flags,
            expected.map_type,
            expected.key_size,
            expected.value_size,
            expected.max_entries
        );
    }
    Ok(())
}

fn map_abi_matches(info: &libbpf::bpf_map_info, expected: MapAbi) -> bool {
    info.type_ == expected.map_type
        && info.key_size == expected.key_size
        && info.value_size == expected.value_size
        && info.max_entries == expected.max_entries
        && info.map_flags == 0
}

fn attach_tracepoint(
    resources: &mut KernelResources,
    program_name: &str,
    category: &str,
    name: &str,
) -> Result<()> {
    let program_name = CString::new(program_name).unwrap();
    let category = CString::new(category).unwrap();
    let name = CString::new(name).unwrap();
    let program = unsafe {
        libbpf::bpf_object__find_program_by_name(resources.object, program_name.as_ptr())
    };
    if program.is_null() {
        bail!(
            "BPF recorder program {} is absent",
            program_name.to_string_lossy()
        );
    }
    let link = unsafe {
        libbpf::bpf_program__attach_tracepoint(program, category.as_ptr(), name.as_ptr())
    };
    check_libbpf_pointer(link.cast(), "attach raw_syscalls tracepoint")?;
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
            let id = program_id(libbpf::bpf_program__fd(program))?;
            if !exclusions.program_ids.insert(id) {
                bail!("duplicate observer-owned program ID {id}");
            }
        }
        let mut map = ptr::null_mut();
        loop {
            map = libbpf::bpf_object__next_map(resources.object, map);
            if map.is_null() {
                break;
            }
            let id = map_id(libbpf::bpf_map__fd(map))?;
            if !exclusions.map_ids.insert(id) {
                bail!("duplicate observer-owned map ID {id}");
            }
        }
        for link in &resources.links {
            let id = link_id(libbpf::bpf_link__fd(*link))?;
            if !exclusions.link_ids.insert(id) {
                bail!("duplicate observer-owned link ID {id}");
            }
        }
    }
    if exclusions.program_ids.is_empty() || exclusions.map_ids.is_empty() {
        bail!("recorder loaded without an enumerable program or map");
    }
    Ok(exclusions)
}

unsafe fn program_id(fd: c_int) -> Result<u32> {
    if fd < 0 {
        bail!("observer program has no valid FD");
    }
    let mut info = libbpf::bpf_prog_info::default();
    let mut length = std::mem::size_of::<libbpf::bpf_prog_info>() as u32;
    let info_ptr: *mut libbpf::bpf_prog_info = &mut info;
    check_libbpf_rc(
        libbpf::bpf_obj_get_info_by_fd(fd, info_ptr.cast(), &mut length),
        "read observer program ID",
    )?;
    if info.id == 0 {
        bail!("observer program returned a zero ID");
    }
    Ok(info.id)
}

unsafe fn map_id(fd: c_int) -> Result<u32> {
    if fd < 0 {
        bail!("observer map has no valid FD");
    }
    let mut info = libbpf::bpf_map_info::default();
    let mut length = std::mem::size_of::<libbpf::bpf_map_info>() as u32;
    let info_ptr: *mut libbpf::bpf_map_info = &mut info;
    check_libbpf_rc(
        libbpf::bpf_obj_get_info_by_fd(fd, info_ptr.cast(), &mut length),
        "read observer map ID",
    )?;
    if info.id == 0 {
        bail!("observer map returned a zero ID");
    }
    Ok(info.id)
}

unsafe fn link_id(fd: c_int) -> Result<u32> {
    if fd < 0 {
        bail!("observer link has no valid FD");
    }
    let mut info = std::mem::zeroed::<libbpf::bpf_link_info>();
    let mut length = std::mem::size_of::<libbpf::bpf_link_info>() as u32;
    let info_ptr: *mut libbpf::bpf_link_info = &mut info;
    check_libbpf_rc(
        libbpf::bpf_obj_get_info_by_fd(fd, info_ptr.cast(), &mut length),
        "read observer link ID",
    )?;
    if info.id == 0 {
        bail!("observer link returned a zero ID");
    }
    Ok(info.id)
}

fn map_update<K, V>(fd: c_int, key: &K, value: &V, flags: u64) -> Result<()> {
    let rc = unsafe {
        libbpf::bpf_map_update_elem(
            fd,
            (key as *const K).cast(),
            (value as *const V).cast(),
            flags,
        )
    };
    check_libbpf_rc(rc, "update BPF map")
}

fn map_lookup<K, V>(fd: c_int, key: &K, value: &mut V) -> Result<()> {
    let rc = unsafe {
        libbpf::bpf_map_lookup_elem(fd, (key as *const K).cast(), (value as *mut V).cast())
    };
    check_libbpf_rc(rc, "look up BPF map")
}

fn map_delete<K>(fd: c_int, key: &K) -> Result<()> {
    let rc = unsafe { libbpf::bpf_map_delete_elem(fd, (key as *const K).cast()) };
    check_libbpf_rc(rc, "delete BPF map element")
}

fn check_libbpf_pointer(pointer: *const c_void, operation: &str) -> Result<()> {
    if pointer.is_null() {
        return Err(std::io::Error::last_os_error()).context(operation.to_owned());
    }
    let error = unsafe { libbpf::libbpf_get_error(pointer) };
    if error != 0 {
        return Err(libbpf_error(error as c_int)).context(operation.to_owned());
    }
    Ok(())
}

fn check_libbpf_rc(rc: c_int, operation: &str) -> Result<()> {
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

    fn test_path(label: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "bpf-observer-recorder-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn attempted_event(sequence: u64) -> KernelEvent {
        KernelEvent {
            schema_version: bpf_observer_schema::SCHEMA_VERSION,
            kind: protocol::EVENT_SYSCALL_ATTEMPTED,
            flags: 0,
            command: 0,
            attr_size: 0,
            run_epoch: 1,
            event_seq: sequence,
            related_attempt_seq: 0,
            ktime_ns: sequence,
            cgroup_id: 1,
            pid_tgid: 1,
            return_value: 0,
        }
    }

    #[test]
    fn run_state_layout_matches_bpf_abi() {
        assert_eq!(std::mem::size_of::<RunState>(), 80);
        assert_eq!(std::mem::size_of::<KernelConfig>(), 40);
    }

    #[test]
    fn map_abi_check_rejects_a_larger_kernel_value() {
        let expected = MapAbi {
            name: MAP_RUN_STATES,
            map_type: libbpf::BPF_MAP_TYPE_HASH,
            key_size: 8,
            value_size: 80,
            max_entries: RECORDER_MAX_RUNS,
        };
        let mut info = libbpf::bpf_map_info {
            type_: expected.map_type,
            key_size: expected.key_size,
            value_size: expected.value_size,
            max_entries: expected.max_entries,
            ..libbpf::bpf_map_info::default()
        };
        assert!(map_abi_matches(&info, expected));
        info.value_size += 8;
        assert!(!map_abi_matches(&info, expected));
    }

    #[test]
    fn native_bpf_syscall_is_always_configured() {
        assert_eq!(bpf_syscall_numbers()[0], libc::SYS_bpf);
    }

    #[test]
    fn empty_allowed_set_makes_no_command_specific_guarantee() {
        let event = attempted_event(1);
        assert!(!event.is_unsupported(&BTreeSet::new()));
        assert!(event.is_unsupported(&BTreeSet::from([1])));
    }

    #[test]
    fn callback_queue_is_hard_bounded() {
        let mut state = CallbackState::default();
        for sequence in 1..=MAX_CALLBACK_QUEUE_EVENTS as u64 {
            assert_eq!(enqueue_event(&mut state, attempted_event(sequence)), 0);
        }
        assert_eq!(state.queue.len(), MAX_CALLBACK_QUEUE_EVENTS);
        assert_eq!(
            enqueue_event(
                &mut state,
                attempted_event(MAX_CALLBACK_QUEUE_EVENTS as u64 + 1)
            ),
            -libc::EFBIG
        );
        assert_eq!(state.queue.len(), MAX_CALLBACK_QUEUE_EVENTS);
        assert_eq!(state.capacity_failures, 1);
    }

    #[test]
    fn callback_total_event_count_is_hard_bounded() {
        let mut state = CallbackState {
            accepted_events: MAX_RECORDED_EVENTS,
            ..CallbackState::default()
        };
        assert_eq!(enqueue_event(&mut state, attempted_event(1)), -libc::EFBIG);
        assert!(state.queue.is_empty());
        assert_eq!(state.capacity_failures, 1);
    }

    #[test]
    fn recorder_object_digest_covers_the_loaded_bytes() {
        let path = test_path("digest");
        fs::write(&path, b"abc").unwrap();
        let (bytes, digest) = read_recorder_object(&path).unwrap();
        assert_eq!(bytes, b"abc");
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn recorder_digest_must_match_canonical_external_policy() {
        let digest = "00".repeat(32);
        assert!(verify_recorder_object_digest(&digest, &digest).is_ok());
        assert!(verify_recorder_object_digest(&digest, &"11".repeat(32)).is_err());
        assert!(verify_recorder_object_digest(&digest, &"AA".repeat(32)).is_err());
    }

    #[test]
    fn recorder_object_size_is_hard_bounded_before_read() {
        let path = test_path("oversized");
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_len(MAX_RECORDER_OBJECT_BYTES + 1).unwrap();
        assert!(read_recorder_object(&path).is_err());
        fs::remove_file(path).unwrap();
    }
}
