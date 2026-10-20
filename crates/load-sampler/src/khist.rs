// SPDX-License-Identifier: GPL-2.0-only
//! Loader and reader for `bpf/kernel_hist.bpf.c`: per-subsystem latency
//! histograms for multiple inclusive target cgroups using one probe set. Each sample
//! copies the cumulative per-CPU slots out of an mmapped ARRAY map.

use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::ptr;

use anyhow::{bail, Context, Result};
use libbpf_sys as libbpf;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const BUCKETS: usize = 32;
pub const MAX_DOMAINS: usize = 16;
pub const ABI_VERSION: u32 = 2;

/// `(name, subsystem, scope)` in `enum kh_metric` order.
pub const METRICS: [(&str, &str, &str); 27] = [
    ("sched_runq", "sched", "target"),
    ("sched_offcpu_d", "sched", "target"),
    ("sched_offcpu_s", "sched", "target"),
    ("sched_oncpu", "sched", "target"),
    ("mem_fault_minor", "mem", "target"),
    ("mem_fault_major", "mem", "target"),
    ("mem_page_alloc", "mem", "target"),
    ("mem_memcg_charge", "mem", "target"),
    ("mem_direct_reclaim", "mem", "target"),
    ("mem_memcg_reclaim", "mem", "target"),
    ("mem_compaction", "mem", "target"),
    ("lock_spin", "lock", "target"),
    ("lock_mutex", "lock", "target"),
    ("lock_rwsem", "lock", "target"),
    ("lock_other", "lock", "target"),
    ("blk_queue", "blk", "system"),
    ("blk_service", "blk", "system"),
    ("softirq_net", "irq", "system"),
    ("softirq_block", "irq", "system"),
    ("softirq_other", "irq", "system"),
    ("syscall_file_io", "syscall", "target"),
    ("syscall_file_meta", "syscall", "target"),
    ("syscall_memory", "syscall", "target"),
    ("syscall_process", "syscall", "target"),
    ("syscall_network", "syscall", "target"),
    ("syscall_wait", "syscall", "target"),
    ("syscall_other", "syscall", "target"),
];

/// `enum kh_counter` order.
pub const COUNTERS: [&str; 22] = [
    "switch_voluntary",
    "switch_preempted",
    "migrations",
    "wakeups",
    "storage_miss",
    "blk_untracked",
    "unpaired_end",
    "initial_child_return_censored",
    "domain_change",
    "task_enrolled",
    "task_exit",
    "task_exit_unfinished",
    "exit_syscall_censored",
    "blk_partial_completion",
    "blk_requeue",
    "blk_start_collision",
    "blk_issue_without_insert",
    "blk_complete_error",
    "blk_byte_mismatch",
    "blk_update_failed",
    "blk_delete_failed",
    "blk_zero_length_unsupported",
];

const SLOT_WORDS: usize = METRICS.len() * BUCKETS + METRICS.len() + COUNTERS.len();
const SLOT_BYTES: usize = SLOT_WORDS * 8;

pub const GROUPS: [(&str, &[&str]); 6] = [
    (
        "sched",
        &[
            "kh_sched_wakeup",
            "kh_sched_wakeup_new",
            "kh_sched_switch",
            "kh_sched_migrate",
        ],
    ),
    (
        "mem",
        &[
            "kh_fault_enter",
            "kh_fault_exit",
            "kh_alloc_enter",
            "kh_alloc_exit",
            "kh_charge_enter",
            "kh_charge_exit",
            "kh_mm_vmscan_direct_reclaim_begin",
            "kh_mm_vmscan_direct_reclaim_end",
            "kh_mm_vmscan_memcg_reclaim_begin",
            "kh_mm_vmscan_memcg_reclaim_end",
            "kh_mm_compaction_begin",
            "kh_mm_compaction_end",
        ],
    ),
    ("lock", &["kh_lock_begin", "kh_lock_end"]),
    (
        "blk",
        &[
            "kh_blk_insert",
            "kh_blk_issue",
            "kh_blk_complete",
            "kh_blk_requeue",
        ],
    ),
    ("irq", &["kh_softirq_entry", "kh_softirq_exit"]),
    ("syscall", &["kh_sys_enter", "kh_sys_exit"]),
];

/// x86-64 syscall number -> class index (0 file_io, 1 file_meta, 2 memory,
/// 3 process, 4 network, 5 wait; anything else is 6 other).
const SYSCALL_CLASSES: [(u32, &[u32]); 6] = [
    (
        0,
        &[
            0, 1, 17, 18, 19, 20, 40, 74, 75, 77, 275, 276, 277, 285, 295, 296, 326, 327, 328,
        ],
    ),
    (
        1,
        &[
            2, 3, 4, 5, 6, 8, 16, 21, 22, 32, 33, 72, 76, 78, 79, 80, 81, 82, 83, 84, 86, 87, 88,
            89, 90, 91, 92, 93, 94, 137, 138, 217, 254, 257, 258, 260, 262, 263, 264, 265, 266,
            267, 268, 269, 280, 292, 293, 316, 332, 436, 437, 439,
        ],
    ),
    (2, &[9, 10, 11, 12, 25, 26, 27, 28, 149, 150, 324]),
    (
        3,
        &[
            56, 57, 58, 59, 60, 62, 109, 112, 157, 158, 218, 231, 234, 302, 322, 334, 435,
        ],
    ),
    (
        4,
        &[
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 288, 299, 307,
        ],
    ),
    (
        5,
        &[
            7, 23, 34, 35, 61, 128, 130, 202, 208, 230, 232, 247, 270, 271, 281, 441,
        ],
    ),
];
const SYSCALL_OTHER: u32 = 6;
const SYSCALL_SLOTS: u32 = 512;

pub fn syscall_class_names() -> Value {
    json!([
        "file_io",
        "file_meta",
        "memory",
        "process",
        "network",
        "wait",
        "other"
    ])
}

#[derive(Clone)]
pub struct Snapshot {
    pub counts: Vec<[u64; BUCKETS]>,
    pub sum_ns: Vec<u64>,
    pub counters: Vec<u64>,
}

impl Snapshot {
    /// Compact JSON: per metric `[n, sum_ns, buckets...]` with trailing
    /// zero buckets trimmed.
    pub fn to_json(&self) -> Value {
        let metrics: Vec<Value> = self
            .counts
            .iter()
            .zip(&self.sum_ns)
            .map(|(buckets, sum)| {
                let used = buckets.iter().rposition(|&c| c != 0).map_or(0, |i| i + 1);
                let total: u64 = buckets.iter().sum();
                let mut row = vec![total, *sum];
                row.extend_from_slice(&buckets[..used]);
                Value::from(row)
            })
            .collect();
        json!({"m": metrics, "c": self.counters})
    }
}

pub struct KernelHist {
    object: *mut libbpf::bpf_object,
    links: Vec<*mut libbpf::bpf_link>,
    view: *const u64,
    view_len: usize,
    cpus: usize,
    stats_fd: Option<i32>,
    _cgroups: Vec<File>,
    pub domains: Vec<Value>,
    pub sha256: String,
    pub groups: Vec<String>,
    pub cgroup_level: u32,
    runtime_stats_requested: bool,
    syscall_backend: String,
    syscall_nrs: Vec<u32>,
    syscall_hook_abi: Option<Value>,
    memory_backend: String,
    memory_hook_abi: Option<Value>,
    trace_events: Vec<OwnedTraceEvent>,
    loaded_program_count: usize,
    online_cpus: Vec<usize>,
}

pub struct KernelHistOptions<'a> {
    pub groups: &'a [String],
    pub runtime_stats_requested: bool,
    pub syscall_backend: &'a str,
    pub syscall_nrs: &'a [u32],
    pub memory_backend: &'a str,
}

const MEMORY_PROBES: [(&str, &str, bool); 6] = [
    ("kh_fault_enter_kprobe", "handle_mm_fault", false),
    ("kh_fault_exit_kprobe", "handle_mm_fault", true),
    (
        "kh_alloc_enter_kprobe",
        "__alloc_frozen_pages_noprof",
        false,
    ),
    ("kh_alloc_exit_kprobe", "__alloc_frozen_pages_noprof", true),
    ("kh_charge_enter_kprobe", "try_charge_memcg", false),
    ("kh_charge_exit_kprobe", "try_charge_memcg", true),
];
const TRACE_GROUP: &str = "allox_khist";
const KRETPROBE_MAXACTIVE: u32 = 1024;
const TRACE_TEXT_LIMIT: u64 = 4 * 1024 * 1024;

struct OwnedTraceEvent {
    root: PathBuf,
    name: String,
    anchor: String,
    is_return: bool,
    definition: Option<String>,
    identity: Option<(u64, u64, u64)>,
    initial: Option<[u64; 2]>,
    initial_collection_ns: Option<[u64; 2]>,
}

fn trace_monotonic_ns() -> Result<u64> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error()).context("clock trace profile boundary");
    }
    Ok(value.tv_sec as u64 * 1_000_000_000 + value.tv_nsec as u64)
}

fn read_bounded(path: &Path) -> Result<String> {
    let mut text = String::new();
    File::open(path)?
        .take(TRACE_TEXT_LIMIT + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > TRACE_TEXT_LIMIT {
        bail!("tracefs text exceeds bounded 4 MiB read");
    }
    Ok(text)
}

fn trace_command(root: &Path, command: &str) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .append(true)
        .open(root.join("kprobe_events"))?;
    file.write_all(command.as_bytes())?;
    Ok(())
}

fn online_cpu_ids(possible: usize) -> Result<Vec<usize>> {
    let text = fs::read_to_string("/sys/devices/system/cpu/online")?;
    parse_online_cpu_ids(&text, possible)
}

fn parse_online_cpu_ids(text: &str, possible: usize) -> Result<Vec<usize>> {
    let mut out = std::collections::BTreeSet::new();
    for field in text.trim().split(',') {
        let (start, end) = match field.split_once('-') {
            Some((start, end)) => (start.parse::<usize>()?, end.parse::<usize>()?),
            None => {
                let cpu = field.parse::<usize>()?;
                (cpu, cpu)
            }
        };
        if start > end || end >= possible {
            bail!("online CPU range outside possible CPU count");
        }
        for cpu in start..=end {
            if !out.insert(cpu) {
                bail!("duplicate online CPU identity");
            }
        }
    }
    if out.is_empty() {
        bail!("no online CPU identities");
    }
    Ok(out.into_iter().collect())
}

impl OwnedTraceEvent {
    fn identity(&self) -> Result<(u64, u64, u64)> {
        let dir = self.root.join("events").join(TRACE_GROUP).join(&self.name);
        let metadata = fs::metadata(&dir)?;
        let id = fs::read_to_string(dir.join("id"))?.trim().parse::<u64>()?;
        Ok((metadata.dev(), metadata.ino(), id))
    }

    fn definition(&self) -> Result<String> {
        let text = read_bounded(&self.root.join("kprobe_events"))?;
        let token = format!("{TRACE_GROUP}/{}", self.name);
        let lines = text
            .lines()
            .filter(|line| {
                line.split_whitespace().next().map_or(false, |head| {
                    head.split_once(':')
                        .map_or(false, |(_, name)| name == token)
                })
            })
            .collect::<Vec<_>>();
        if lines.len() != 1 {
            bail!("owned trace event definition missing or ambiguous");
        }
        let parts = lines[0].split_whitespace().collect::<Vec<_>>();
        let expected_kind = if self.is_return {
            format!("r{KRETPROBE_MAXACTIVE}:{token}")
        } else {
            format!("p:{token}")
        };
        if parts.len() != 2
            || parts[0] != expected_kind
            || !(parts[1] == self.anchor || parts[1] == format!("{}+0", self.anchor))
        {
            bail!("owned trace event definition differs from exact requested anchor/maxactive");
        }
        Ok(lines[0].trim().to_owned())
    }

    fn profile(&self) -> Result<[u64; 2]> {
        parse_trace_profile(
            &read_bounded(&self.root.join("kprobe_profile"))?,
            &self.name,
        )
    }

    fn remove_verified(&self) -> Result<()> {
        let definition = self.definition()?;
        if self
            .definition
            .as_ref()
            .map_or(false, |expected| expected != &definition)
            || self.identity.map_or(false, |expected| {
                self.identity().map_or(true, |current| current != expected)
            })
        {
            bail!("owned trace event changed; refusing deletion");
        }
        trace_command(&self.root, &format!("-:{TRACE_GROUP}/{}\n", self.name))
    }

    fn json(&self) -> Value {
        let started = trace_monotonic_ns().ok();
        let (status, hits, misses, detail) = match self.profile() {
            Ok([hits, misses]) => ("OBSERVED", Some(hits), Some(misses), None),
            Err(error) => ("UNKNOWN", None, None, Some(error.to_string())),
        };
        let ended = trace_monotonic_ns().ok();
        json!({"name": self.name, "group": TRACE_GROUP, "anchor": self.anchor,
            "is_return": self.is_return, "maxactive": if self.is_return { Some(KRETPROBE_MAXACTIVE) } else { None },
            "tracefs_root": self.root, "definition": self.definition,
            "device": self.identity.map(|v| v.0), "directory_inode": self.identity.map(|v| v.1), "event_id": self.identity.map(|v| v.2),
            "initial_hits": self.initial.map(|v| v[0]), "initial_misses": self.initial.map(|v| v[1]),
            "initial_collection_start_ns": self.initial_collection_ns.map(|v| v[0]), "initial_collection_end_ns": self.initial_collection_ns.map(|v| v[1]),
            "collection_start_ns": started, "collection_end_ns": ended,
            "counter_sampling": "non-atomic kernel sums; lifecycle identity and monotonicity must be checked independently",
            "profile_status": status, "hits": hits, "misses": misses, "detail": detail,
            "scope": "SYSTEM_HOOK_COUNTERS_NOT_AGENT_ATTRIBUTED; selected Agent histogram is separate"})
    }
}

fn parse_trace_profile(text: &str, name: &str) -> Result<[u64; 2]> {
    let rows = text
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .filter(|row| row.first().map_or(false, |value| *value == name))
        .collect::<Vec<_>>();
    if rows.len() != 1 || rows[0].len() != 3 {
        bail!("owned kprobe_profile row missing, malformed or ambiguous");
    }
    Ok([rows[0][1].parse()?, rows[0][2].parse()?])
}

fn check_rc(rc: i32, what: &str) -> Result<()> {
    if rc < 0 {
        bail!("{what}: {}", std::io::Error::from_raw_os_error(-rc));
    }
    Ok(())
}

fn map_fd(object: *mut libbpf::bpf_object, name: &str) -> Result<(*mut libbpf::bpf_map, i32)> {
    let c_name = CString::new(name).unwrap();
    let map = unsafe { libbpf::bpf_object__find_map_by_name(object, c_name.as_ptr()) };
    if map.is_null() {
        bail!("kernel-hist BPF map {name} is absent");
    }
    Ok((map, unsafe { libbpf::bpf_map__fd(map) }))
}

fn update<V>(fd: i32, key: u32, value: &V, what: &str) -> Result<()> {
    let rc = unsafe {
        libbpf::bpf_map_update_elem(
            fd,
            (&key as *const u32).cast(),
            (value as *const V).cast(),
            0,
        )
    };
    check_rc(rc, what)
}

/// Canonical path depth below the conventional host cgroup-v2 mount. This
/// equals kernel cgroup->level only with a host-view mount; it is not proof
/// that the caller is in the initial cgroup namespace or mount namespace.
fn cgroup_level(dir: &Path) -> Result<u32> {
    let root = Path::new("/sys/fs/cgroup");
    let rel = dir
        .strip_prefix(root)
        .with_context(|| format!("{} is not below {}", dir.display(), root.display()))?;
    if rel.components().any(|c| !matches!(c, Component::Normal(_))) {
        bail!("kernel-hist cgroup path must be canonical without . or ..");
    }
    let rebuilt = if rel.as_os_str().is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel.components().collect::<std::path::PathBuf>())
    };
    if rebuilt.as_os_str() != dir.as_os_str() {
        bail!("kernel-hist cgroup path must be canonical");
    }
    let level = rel.components().count() as u32;
    if level > 31 {
        bail!("kernel-hist cgroup depth {level} exceeds the supported maximum of 31");
    }
    Ok(level)
}

struct KernelBtf(*mut libbpf::btf);
impl Drop for KernelBtf {
    fn drop(&mut self) {
        unsafe { libbpf::btf__free(self.0) };
    }
}

fn btf_type(btf: *const libbpf::btf, mut id: u32) -> Result<*const libbpf::btf_type> {
    for _ in 0..16 {
        let ty = unsafe { libbpf::btf__type_by_id(btf, id) };
        if ty.is_null() {
            bail!("syscall hook ABI references missing BTF type {id}");
        }
        let kind = unsafe { ((*ty).info >> 24) & 31 };
        if [8, 9, 10, 11, 18].contains(&kind) {
            id = unsafe { (*ty).__bindgen_anon_1.type_ };
        } else {
            return Ok(ty);
        }
    }
    bail!("syscall hook ABI BTF modifier chain exceeds 16 entries")
}

fn btf_name(btf: *const libbpf::btf, offset: u32) -> Result<String> {
    let name = unsafe { libbpf::btf__name_by_offset(btf, offset) };
    if name.is_null() {
        bail!("syscall hook ABI has invalid BTF name offset");
    }
    Ok(unsafe { CStr::from_ptr(name) }
        .to_string_lossy()
        .into_owned())
}

fn validate_syscall_kprobe_abi_from(btf: *const libbpf::btf) -> Result<Value> {
    let mut anchors = Vec::new();
    for (name, argc) in [
        ("trace_syscall_enter", 1usize),
        ("trace_syscall_exit", 2usize),
    ] {
        let cname = CString::new(name).unwrap();
        let id =
            unsafe { libbpf::btf__find_by_name_kind(btf, cname.as_ptr(), libbpf::BTF_KIND_FUNC) };
        if id <= 0 {
            bail!("kprobe syscall backend requires BTF anchor {name}");
        }
        let func = btf_type(btf, id as u32)?;
        let proto = btf_type(btf, unsafe { (*func).__bindgen_anon_1.type_ })?;
        if unsafe { ((*proto).info >> 24) & 31 } != libbpf::BTF_KIND_FUNC_PROTO
            || unsafe { (*proto).info & 65535 } as usize != argc
            || unsafe { (*proto).__bindgen_anon_1.type_ } != 0
        {
            bail!("kprobe syscall anchor {name} must return void with exactly {argc} parameters");
        }
        let params =
            unsafe { std::slice::from_raw_parts(proto.add(1).cast::<libbpf::btf_param>(), argc) };
        let pointer = btf_type(btf, params[0].type_)?;
        if unsafe { ((*pointer).info >> 24) & 31 } != libbpf::BTF_KIND_PTR {
            bail!("kprobe syscall anchor {name} first argument must be a pt_regs pointer");
        }
        let regs = btf_type(btf, unsafe { (*pointer).__bindgen_anon_1.type_ })?;
        if unsafe { ((*regs).info >> 24) & 31 } != libbpf::BTF_KIND_STRUCT
            || btf_name(btf, unsafe { (*regs).name_off })? != "pt_regs"
        {
            bail!("kprobe syscall anchor {name} first argument does not point to struct pt_regs");
        }
        let member_count = unsafe { (*regs).info & 65535 } as usize;
        if member_count > 256 {
            bail!("pt_regs BTF has excessive member count");
        }
        let members = unsafe {
            std::slice::from_raw_parts(regs.add(1).cast::<libbpf::btf_member>(), member_count)
        };
        for field in ["di", "si", "orig_ax"] {
            let member = members
                .iter()
                .find(|m| btf_name(btf, m.name_off).map_or(false, |name| name == field))
                .with_context(|| format!("x86-64 kprobe backend requires pt_regs.{field}"))?;
            let ty = btf_type(btf, member.type_)?;
            if unsafe { ((*ty).info >> 24) & 31 } != libbpf::BTF_KIND_INT
                || unsafe { (*ty).__bindgen_anon_1.size } != 8
            {
                bail!("x86-64 pt_regs.{field} must be a 64-bit integer");
            }
        }
        if argc == 2 {
            let result = btf_type(btf, params[1].type_)?;
            if unsafe { ((*result).info >> 24) & 31 } != libbpf::BTF_KIND_INT
                || unsafe { (*result).__bindgen_anon_1.size } != 8
                || unsafe { *result.add(1).cast::<u32>() >> 24 & 1 } != 1
            {
                bail!("trace_syscall_exit return-value parameter must be a signed 64-bit integer");
            }
        }
        anchors.push(json!({"name": name, "btf_function_id": id, "parameter_count": argc}));
    }
    Ok(
        json!({"status": "VALIDATED", "architecture": "x86_64", "anchors": anchors,
        "raw_dispatch_role": "REGISTER_SYSCALL_WORK_ONLY_NO_HISTOGRAM_PAYLOAD",
        "measurement": "kprobe handler before raw dispatcher; no simultaneous raw measurement"}),
    )
}

fn validate_syscall_kprobe_abi() -> Result<Value> {
    let raw = unsafe { libbpf::btf__load_vmlinux_btf() };
    if raw.is_null() || (raw as isize) < 0 && (raw as isize) > -4096 {
        bail!("kprobe syscall backend requires readable kernel BTF");
    }
    let btf = KernelBtf(raw);
    validate_syscall_kprobe_abi_from(btf.0)
}

fn validate_memory_kprobe_abi() -> Result<Value> {
    let raw = unsafe { libbpf::btf__load_vmlinux_btf() };
    if raw.is_null() || (raw as isize) < 0 && (raw as isize) > -4096 {
        bail!("memory kprobe backend requires readable kernel BTF");
    }
    let btf = KernelBtf(raw);
    let mut anchors = Vec::new();
    for (name, argc, return_kind, size) in [
        ("handle_mm_fault", 4usize, libbpf::BTF_KIND_INT, Some(4)),
        ("__alloc_frozen_pages_noprof", 5, libbpf::BTF_KIND_PTR, None),
        ("try_charge_memcg", 3, libbpf::BTF_KIND_INT, Some(4)),
    ] {
        let cname = CString::new(name).unwrap();
        let id =
            unsafe { libbpf::btf__find_by_name_kind(btf.0, cname.as_ptr(), libbpf::BTF_KIND_FUNC) };
        if id <= 0 {
            bail!("memory backend requires BTF anchor {name}");
        }
        let function = btf_type(btf.0, id as u32)?;
        let proto = btf_type(btf.0, unsafe { (*function).__bindgen_anon_1.type_ })?;
        if unsafe { ((*proto).info >> 24) & 31 } != libbpf::BTF_KIND_FUNC_PROTO
            || unsafe { (*proto).info & 65535 } as usize != argc
        {
            bail!("memory backend anchor {name} prototype differs from supported ABI");
        }
        let ret = btf_type(btf.0, unsafe { (*proto).__bindgen_anon_1.type_ })?;
        if unsafe { ((*ret).info >> 24) & 31 } != return_kind
            || size.map_or(
                false,
                |size| unsafe { (*ret).__bindgen_anon_1.size } != size,
            )
        {
            bail!("memory backend anchor {name} return type differs from supported ABI");
        }
        anchors.push(json!({"name": name, "btf_function_id": id, "parameter_count": argc, "return_kind": return_kind, "return_size": size}));
    }
    let name = CString::new("pt_regs").unwrap();
    let id =
        unsafe { libbpf::btf__find_by_name_kind(btf.0, name.as_ptr(), libbpf::BTF_KIND_STRUCT) };
    if id <= 0 {
        bail!("memory backend requires x86-64 pt_regs");
    }
    let regs = btf_type(btf.0, id as u32)?;
    let count = unsafe { (*regs).info & 65535 } as usize;
    if count > 256 {
        bail!("pt_regs excessive member count");
    }
    let members =
        unsafe { std::slice::from_raw_parts(regs.add(1).cast::<libbpf::btf_member>(), count) };
    let ax = members
        .iter()
        .find(|member| btf_name(btf.0, member.name_off).map_or(false, |name| name == "ax"))
        .context("memory backend requires pt_regs.ax")?;
    let ax_type = btf_type(btf.0, ax.type_)?;
    if unsafe { ((*ax_type).info >> 24) & 31 } != libbpf::BTF_KIND_INT
        || unsafe { (*ax_type).__bindgen_anon_1.size } != 8
    {
        bail!("pt_regs.ax must be 64-bit");
    }
    Ok(
        json!({"status": "VALIDATED", "architecture": "x86_64", "anchors": anchors,
        "fault_metric_interpretation": "handle_mm_fault completed returns split by VM_FAULT_MAJOR; non-major includes RETRY/errors, not successful rusage fault count"}),
    )
}

impl KernelHist {
    pub fn metadata(&self) -> Value {
        json!({
            "object_sha256": self.sha256, "groups": self.groups,
            "abi_version": ABI_VERSION, "domains": self.domains, "probe_sets_loaded": 1,
            "target_cgroup": self.domains[0]["path"], "cgroup_level": self.cgroup_level,
            "cgroup_level_basis": "canonical path depth below /sys/fs/cgroup; requires host-view hierarchy, not namespace enforcement",
            "domain_semantics": "INCLUSIVE_CGROUP_AND_DESCENDANTS; root and child overlap, never sum across domains",
            "global_metric_scope": "SYSTEM_UNATTRIBUTED block and softirq",
            "block_extension_version": 1,
            "registration": "FROZEN_IMMUTABLE_DURING_OBJECT_LIFETIME; selected cgroup file descriptors held until detach",
            "registry_frozen": true,
            "membership_cache": "4096-entry bounded LRU_HASH keyed by generation-bearing leaf kernfs ID; positive and negative masks; cache failure/eviction recomputes rather than drops; task storage rechecked against current cgroup identity",
            "required_membership_helper": "bpf_loop (Linux >= 5.17); unsupported helper fails load, no first-domain fallback",
            "span_semantics": "completed spans may cross windows and overlap; non-returning exit syscalls are censored and counted",
            "birth_return_semantics": "only sched_wakeup_new-proven child clone/fork return without child enter is censored; every other unmatched selected return counts unpaired_end",
            "boundary_semantics": "enrolled minus exited is an approximate unresolved enrollment count; domain_change discards cross-domain spans",
            "limitations": ["Host-view cgroup hierarchy required", "Hard IRQ allocations/locks may appear in current task context", "Shared services need explicit request linkage", "Block merges/writeback have no Agent attribution"],
            "runtime_stats_requested": self.runtime_stats_requested,
            "syscall_backend": self.syscall_backend, "syscall_number_selection": self.syscall_nrs,
            "syscall_hook_abi": self.syscall_hook_abi,
            "memory_backend": self.memory_backend, "memory_hook_abi": self.memory_hook_abi,
            "memory_return_probe_maxactive": KRETPROBE_MAXACTIVE,
            "memory_fault_metric_interpretation": "completed handle_mm_fault returns split by VM_FAULT_MAJOR; non-major includes retry/error; do not equate directly to rusage faults",
            "metrics": METRICS.iter().map(|(name, subsystem, scope)| json!({"name":name,"subsystem":subsystem,"scope":scope})).collect::<Vec<_>>(),
            "counters": COUNTERS, "syscall_classes": syscall_class_names(), "buckets": BUCKETS,
            "encoding": "m[i]=[count,sum_ns,bucket0,...]; trailing zero buckets trimmed; bucket b=[2^b,2^(b+1))ns",
            "legacy_projection": "khist.m/c is first domain plus system metrics; use khist.domains/system for separate scopes",
            "programs": self.programs(), "map_ids": self.map_ids(),
        })
    }

    pub fn open(
        object_path: &Path,
        expected_sha256: &str,
        cgroup_dirs: &[PathBuf],
        options: KernelHistOptions<'_>,
    ) -> Result<Self> {
        let KernelHistOptions {
            groups,
            runtime_stats_requested,
            syscall_backend,
            syscall_nrs,
            memory_backend,
        } = options;
        if cgroup_dirs.is_empty() || cgroup_dirs.len() > MAX_DOMAINS {
            bail!("kernel-hist needs between 1 and {MAX_DOMAINS} cgroup domains");
        }
        let mut cgroups = Vec::new();
        let mut domains = Vec::new();
        let mut identities = std::collections::BTreeSet::new();
        for (index, cgroup_dir) in cgroup_dirs.iter().enumerate() {
            let canonical = fs::canonicalize(cgroup_dir)?;
            if canonical != *cgroup_dir {
                bail!("kernel-hist cgroup path must be canonical");
            }
            let level = cgroup_level(&canonical)?;
            let file = File::open(&canonical)?;
            let identity = file.metadata()?;
            if !identities.insert((identity.dev(), identity.ino())) {
                bail!("kernel-hist cgroup identities must be unique");
            }
            domains.push(json!({"domain_index": index, "path": canonical,
                "inode": identity.ino(), "device": identity.dev(), "cgroup_level": level,
                "scope": "INCLUSIVE_CGROUP_AND_DESCENDANTS", "overlap_policy": "ROOT_AND_CHILD_ARE_NOT_ADDITIVE"}));
            cgroups.push(file);
        }
        for group in groups {
            if !GROUPS.iter().any(|(name, _)| name == group) {
                bail!("unknown kernel-hist group {group}");
            }
        }
        if groups.is_empty()
            || groups
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != groups.len()
        {
            bail!("kernel-hist groups must be nonempty and unique");
        }
        let mut groups = groups.to_vec();
        let has = |groups: &[String], g: &str| groups.iter().any(|x| x == g);
        if (has(&groups, "mem") || has(&groups, "lock"))
            && !(has(&groups, "sched") || has(&groups, "syscall"))
        {
            bail!("kernel-hist groups mem/lock need sched or syscall to create per-task state");
        }
        // mem/lock skip softirq context using the irq group's in-softirq flag.
        if (has(&groups, "mem") || has(&groups, "lock")) && !has(&groups, "irq") {
            groups.push("irq".to_string());
        }
        let has = |g: &str| groups.iter().any(|x| x == g);
        if !["kprobe", "raw-btf"].contains(&syscall_backend) {
            bail!("unknown syscall diagnostic backend {syscall_backend}");
        }
        if syscall_nrs.iter().any(|nr| *nr >= SYSCALL_SLOTS)
            || syscall_nrs
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != syscall_nrs.len()
        {
            bail!("selected syscall numbers must be unique and within 0..511");
        }
        if !syscall_nrs.is_empty() && !has("syscall") {
            bail!("syscall-number selection requires the syscall group");
        }
        let syscall_hook_abi = if has("syscall") && syscall_backend == "kprobe" {
            Some(validate_syscall_kprobe_abi()?)
        } else {
            None
        };
        if !["fentry", "kprobe-tracefs"].contains(&memory_backend) {
            bail!("unknown memory diagnostic backend {memory_backend}");
        }
        let memory_hook_abi = if has("mem") && memory_backend == "kprobe-tracefs" {
            Some(validate_memory_kprobe_abi()?)
        } else {
            None
        };
        let bytes =
            fs::read(object_path).with_context(|| format!("read {}", object_path.display()))?;
        let sha256: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if sha256 != expected_sha256.to_ascii_lowercase() {
            bail!("kernel-hist BPF object digest {sha256} does not match the expected value");
        }
        let name = CString::new("kernel_hist").unwrap();
        let opts = libbpf::bpf_object_open_opts {
            sz: std::mem::size_of::<libbpf::bpf_object_open_opts>() as u64,
            object_name: name.as_ptr(),
            ..unsafe { std::mem::zeroed() }
        };
        let object = unsafe {
            libbpf::bpf_object__open_mem(bytes.as_ptr().cast(), bytes.len() as u64, &opts)
        };
        if object.is_null() || (object as isize) < 0 && (object as isize) > -4096 {
            bail!("open kernel-hist BPF object");
        }
        let cpus = unsafe { libbpf::libbpf_num_possible_cpus() };
        let mut this = KernelHist {
            object,
            links: Vec::new(),
            view: ptr::null(),
            view_len: 0,
            cpus: cpus.max(0) as usize,
            stats_fd: None,
            _cgroups: cgroups,
            domains,
            sha256,
            groups: groups.clone(),
            cgroup_level: 0,
            runtime_stats_requested,
            syscall_backend: syscall_backend.to_owned(),
            syscall_nrs: syscall_nrs.to_vec(),
            syscall_hook_abi,
            memory_backend: memory_backend.to_owned(),
            memory_hook_abi,
            trace_events: Vec::new(),
            loaded_program_count: 0,
            online_cpus: Vec::new(),
        };
        if cpus <= 0 {
            bail!("libbpf could not count possible CPUs");
        }
        this.online_cpus = online_cpu_ids(this.cpus)?;
        let (hist, _) = map_fd(object, "kh_hist")?;
        check_rc(
            unsafe {
                libbpf::bpf_map__set_max_entries(
                    hist,
                    cpus as u32 * (this.domains.len() as u32 + 1),
                )
            },
            "size kh_hist to CPUs times registered domains plus system",
        )?;
        for (group, programs) in GROUPS {
            for program in programs {
                let c = CString::new(*program).unwrap();
                let prog = unsafe { libbpf::bpf_object__find_program_by_name(object, c.as_ptr()) };
                if prog.is_null() {
                    bail!("kernel-hist BPF program {program} is absent");
                }
                check_rc(
                    unsafe {
                        libbpf::bpf_program__set_autoload(
                            prog,
                            has(group)
                                && !(group == "syscall" && syscall_backend == "kprobe")
                                && !(group == "mem"
                                    && memory_backend == "kprobe-tracefs"
                                    && [
                                        "kh_fault_enter",
                                        "kh_fault_exit",
                                        "kh_alloc_enter",
                                        "kh_alloc_exit",
                                        "kh_charge_enter",
                                        "kh_charge_exit",
                                    ]
                                    .contains(program)),
                        )
                    },
                    "set program autoload",
                )?;
            }
        }
        for (name, _, _) in MEMORY_PROBES {
            let c = CString::new(name).unwrap();
            let prog = unsafe { libbpf::bpf_object__find_program_by_name(object, c.as_ptr()) };
            if prog.is_null() {
                bail!("memory backend program {name} is absent");
            }
            check_rc(
                unsafe {
                    libbpf::bpf_program__set_autoload(
                        prog,
                        has("mem") && memory_backend == "kprobe-tracefs",
                    )
                },
                "set memory backend autoload",
            )?;
        }
        for name in [
            "kh_sys_enter_dispatch",
            "kh_sys_exit_dispatch",
            "kh_sys_enter_kprobe",
            "kh_sys_exit_kprobe",
        ] {
            let c = CString::new(name).unwrap();
            let prog = unsafe { libbpf::bpf_object__find_program_by_name(object, c.as_ptr()) };
            if prog.is_null() {
                bail!("kernel-hist syscall backend program {name} is absent");
            }
            check_rc(
                unsafe {
                    libbpf::bpf_program__set_autoload(
                        prog,
                        has("syscall") && syscall_backend == "kprobe",
                    )
                },
                "set syscall backend autoload",
            )?;
        }
        let exit_name = CString::new("kh_sched_exit").unwrap();
        let exit_program =
            unsafe { libbpf::bpf_object__find_program_by_name(object, exit_name.as_ptr()) };
        if exit_program.is_null() {
            bail!("kernel-hist lifecycle exit program is absent");
        }
        check_rc(
            unsafe {
                libbpf::bpf_program__set_autoload(exit_program, has("sched") || has("syscall"))
            },
            "set lifecycle exit autoload",
        )?;
        check_rc(
            unsafe { libbpf::bpf_object__load(object) },
            "load kernel-hist BPF object",
        )?;
        if unsafe { libbpf::bpf_map__value_size(hist) } as usize != SLOT_BYTES {
            bail!("kh_hist value size differs from the {SLOT_BYTES}-byte user-space layout");
        }

        let (_, config_fd) = map_fd(object, "kh_config")?;
        let (_, target_fd) = map_fd(object, "kh_domains")?;
        let (_, class_fd) = map_fd(object, "kh_syscall_class")?;
        #[repr(C)]
        struct Domain {
            cgroup_id: u64,
            cgroup_level: u32,
            reserved: u32,
        }
        for (index, domain) in this.domains.iter().enumerate() {
            update(
                target_fd,
                index as u32,
                &Domain {
                    cgroup_id: domain["inode"].as_u64().unwrap(),
                    cgroup_level: domain["cgroup_level"].as_u64().unwrap() as u32,
                    reserved: 0,
                },
                "install inclusive cgroup domain",
            )?;
        }
        this.cgroup_level = this.domains[0]["cgroup_level"].as_u64().unwrap() as u32;
        for nr in 0..SYSCALL_SLOTS {
            let class = if !syscall_nrs.is_empty() && !syscall_nrs.contains(&nr) {
                u32::MAX
            } else {
                SYSCALL_CLASSES
                    .iter()
                    .find(|(_, nrs)| nrs.contains(&nr))
                    .map_or(SYSCALL_OTHER, |(c, _)| *c)
            };
            update(class_fd, nr, &class, "install syscall class")?;
        }

        let hist_fd = unsafe { libbpf::bpf_map__fd(hist) };
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let len = (this.cpus * (this.domains.len() + 1) * SLOT_BYTES + page - 1) / page * page;
        let view = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                hist_fd,
                0,
            )
        };
        if view == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error()).context("mmap kh_hist");
        }
        this.view = view.cast();
        this.view_len = len;

        if runtime_stats_requested {
            let fd = unsafe { libbpf::bpf_enable_stats(libbpf::BPF_STATS_RUN_TIME) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("enable explicitly requested global BPF runtime accounting");
            }
            this.stats_fd = Some(fd);
        }

        let mut program = ptr::null_mut();
        loop {
            program = unsafe { libbpf::bpf_object__next_program(object, program) };
            if program.is_null() {
                break;
            }
            if !unsafe { libbpf::bpf_program__autoload(program) } {
                continue;
            }
            this.loaded_program_count += 1;
            let name =
                unsafe { CStr::from_ptr(libbpf::bpf_program__name(program)) }.to_string_lossy();
            if memory_backend == "kprobe-tracefs" {
                if let Some((_, anchor, is_return)) = MEMORY_PROBES
                    .iter()
                    .find(|(expected, _, _)| *expected == name)
                {
                    this.attach_owned_tracefs(program, &name, anchor, *is_return)?;
                    continue;
                }
            }
            let link = unsafe { libbpf::bpf_program__attach(program) };
            if link.is_null() || (link as isize) < 0 && (link as isize) > -4096 {
                let name = unsafe { CStr::from_ptr(libbpf::bpf_program__name(program)) };
                bail!("attach kernel-hist program {}", name.to_string_lossy());
            }
            this.links.push(link);
        }
        // Enable counting only once every selected program is attached.
        #[repr(C)]
        struct Config {
            cpu_count: u32,
            domain_count: u32,
            enabled: u32,
            abi_version: u32,
        }
        update(
            config_fd,
            0,
            &Config {
                cpu_count: this.cpus as u32,
                domain_count: this.domains.len() as u32,
                enabled: 1 | if syscall_nrs.is_empty() { 0 } else { 2 },
                abi_version: ABI_VERSION,
            },
            "enable kernel-hist",
        )?;
        // Membership caches are valid only while the registry is immutable.
        // Freeze before READY; any failure aborts and detaches the object.
        for (fd, name) in [
            (config_fd, "config"),
            (target_fd, "domains"),
            (class_fd, "syscall classes"),
        ] {
            check_rc(
                unsafe { libbpf::bpf_map_freeze(fd) },
                &format!("freeze kernel-hist {name}"),
            )?;
        }
        Ok(this)
    }

    fn attach_owned_tracefs(
        &mut self,
        program: *mut libbpf::bpf_program,
        program_name: &str,
        anchor: &str,
        is_return: bool,
    ) -> Result<()> {
        let roots = [
            Path::new("/sys/kernel/tracing"),
            Path::new("/sys/kernel/debug/tracing"),
        ];
        let root = roots.iter().find(|root| root.join("kprobe_events").is_file()).context("memory backend requires mounted writable tracefs kprobe_events and readable kprobe_profile")?;
        let root = fs::canonicalize(root)?;
        let uuid = fs::read_to_string("/proc/sys/kernel/random/uuid")?
            .trim()
            .replace('-', "");
        if uuid.len() != 32 || !uuid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("invalid UUID for owned trace event");
        }
        let name = format!("alloxkh_{uuid}_{program_name}");
        let dir = root.join("events").join(TRACE_GROUP).join(&name);
        if dir.exists() {
            bail!("refusing existing trace event identity");
        }
        let prefix = if is_return {
            format!("r{KRETPROBE_MAXACTIVE}")
        } else {
            "p".to_owned()
        };
        trace_command(&root, &format!("{prefix}:{TRACE_GROUP}/{name} {anchor}\n"))?;
        self.trace_events.push(OwnedTraceEvent {
            root,
            name,
            anchor: anchor.to_owned(),
            is_return,
            definition: None,
            identity: None,
            initial: None,
            initial_collection_ns: None,
        });
        let event = self.trace_events.last_mut().unwrap();
        event.definition = Some(event.definition()?);
        event.identity = Some(event.identity()?);
        let start = trace_monotonic_ns()?;
        event.initial = Some(event.profile()?);
        event.initial_collection_ns = Some([start, trace_monotonic_ns()?]);
        let id = event.identity.unwrap().2;
        // trace_kprobe's global prog_array runs before checking the per-CPU
        // perf sample list. Attach exactly once: attaching the same program
        // on every CPU both fails EEXIST and would risk duplicate counting.
        // Programs return 0, so no perf ring-buffer payload is emitted.
        for &cpu in self.online_cpus.iter().take(1) {
            let attr = libbpf::perf_event_attr {
                type_: libbpf::PERF_TYPE_TRACEPOINT,
                size: std::mem::size_of::<libbpf::perf_event_attr>() as u32,
                config: id,
                ..unsafe { std::mem::zeroed() }
            };
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_perf_event_open,
                    &attr,
                    -1,
                    cpu as i32,
                    -1,
                    libbpf::PERF_FLAG_FD_CLOEXEC,
                )
            } as i32;
            if fd < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("open owned kprobe perf event for online CPU");
            }
            let link = unsafe { libbpf::bpf_program__attach_perf_event(program, fd) };
            if link.is_null() || (link as isize) < 0 && (link as isize) > -4096 {
                unsafe { libc::close(fd) };
                bail!("attach owned memory probe {program_name} on CPU {cpu}");
            }
            self.links.push(link); // libbpf owns and closes perf fd on destroy
        }
        Ok(())
    }

    fn remove_owned_events(&mut self) -> Vec<Value> {
        let mut failures = Vec::new();
        let mut remaining = Vec::new();
        for event in self.trace_events.drain(..).rev() {
            let result = event.remove_verified();
            if let Err(error) = result {
                failures.push(json!({"name": event.name, "error": error.to_string()}));
                remaining.push(event);
            }
        }
        self.trace_events = remaining;
        failures
    }

    /// Disable all owned handlers, sample terminal counters, then remove only
    /// exact owned trace event identities. Raw evidence is returned before Drop.
    pub fn finish(&mut self) -> Value {
        let mut detach_errors = Vec::new();
        for link in self.links.drain(..) {
            let rc = unsafe { libbpf::bpf_link__destroy(link) };
            if rc != 0 {
                detach_errors.push(rc);
            }
        }
        let mut stats = self.programs();
        let owned_count = self.trace_events.len();
        let cleanup_errors = self.remove_owned_events();
        stats["tracefs_cleanup"] = json!({"status": if cleanup_errors.is_empty() && detach_errors.is_empty() { "COMPLETE" } else { "INCOMPLETE" },
            "owned_events": owned_count, "remaining_owned_events": self.trace_events.len(),
            "detach_errors": detach_errors, "errors": cleanup_errors,
            "order": "disable/close own perf handlers; collect final profile; verify own exact definition/inode/event_id; delete only own UUID-prefixed events"});
        stats
    }

    fn read_slot(&self, slot_id: usize) -> Snapshot {
        let mut snap = Snapshot {
            counts: vec![[0; BUCKETS]; METRICS.len()],
            sum_ns: vec![0; METRICS.len()],
            counters: vec![0; COUNTERS.len()],
        };
        for cpu in 0..self.cpus {
            // Aligned u64 loads are single-copy atomic on x86-64.
            let word = |i: usize| unsafe {
                ptr::read_volatile(self.view.add((slot_id * self.cpus + cpu) * SLOT_WORDS + i))
            };
            for m in 0..METRICS.len() {
                for b in 0..BUCKETS {
                    snap.counts[m][b] += word(m * BUCKETS + b);
                }
                snap.sum_ns[m] += word(METRICS.len() * BUCKETS + m);
            }
            for c in 0..COUNTERS.len() {
                snap.counters[c] += word(METRICS.len() * BUCKETS + METRICS.len() + c);
            }
        }
        snap
    }

    pub fn read(&self) -> Value {
        let system = self.read_slot(0);
        let targets = (0..self.domains.len())
            .map(|index| self.read_slot(index + 1))
            .collect::<Vec<_>>();
        // Compatibility projection: first inclusive domain plus explicitly
        // system-scoped metrics. New consumers must use domains/system.
        let mut legacy = targets[0].clone();
        for index in 15..20 {
            legacy.counts[index] = system.counts[index];
            legacy.sum_ns[index] = system.sum_ns[index];
        }
        for index in std::iter::once(5).chain(13..COUNTERS.len()) {
            legacy.counters[index] = system.counters[index];
        }
        let mut value = legacy.to_json();
        value["abi_version"] = json!(ABI_VERSION);
        value["domains"] = Value::from(
            targets
                .iter()
                .zip(&self.domains)
                .map(|(snapshot, identity)| {
                    let mut row = snapshot.to_json();
                    row["identity"] = identity.clone();
                    row
                })
                .collect::<Vec<_>>(),
        );
        let mut global = system.to_json();
        global["scope"] = json!("SYSTEM_UNATTRIBUTED");
        value["system"] = global;
        value
    }

    /// Program IDs plus kernel-measured run time (needs BPF stats).
    pub fn programs(&self) -> Value {
        let mut out = Vec::new();
        let mut info_read_errors = 0;
        let mut program = ptr::null_mut();
        loop {
            program = unsafe { libbpf::bpf_object__next_program(self.object, program) };
            if program.is_null() {
                break;
            }
            let fd = unsafe { libbpf::bpf_program__fd(program) };
            if fd < 0 {
                continue;
            }
            let mut info: libbpf::bpf_prog_info = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libbpf::bpf_prog_info>() as u32;
            if unsafe {
                libbpf::bpf_obj_get_info_by_fd(
                    fd,
                    (&mut info as *mut libbpf::bpf_prog_info).cast(),
                    &mut len,
                )
            } != 0
            {
                info_read_errors += 1;
                continue;
            }
            let name = unsafe { CStr::from_ptr(libbpf::bpf_program__name(program)) };
            out.push(json!({
                "name": name.to_string_lossy(), "id": info.id,
                "role": if name.to_string_lossy().ends_with("_dispatch") { "REGISTRATION_ONLY_NO_HISTOGRAM_PAYLOAD" } else { "MEASUREMENT" },
                "run_cnt": info.run_cnt, "run_time_ns": info.run_time_ns,
                "recursion_misses": info.recursion_misses,
            }));
        }
        let current_cpus = online_cpu_ids(self.cpus).ok();
        let cpu_status = if current_cpus.as_ref() == Some(&self.online_cpus) {
            "STABLE"
        } else {
            "CHANGED_OR_UNKNOWN"
        };
        json!({
            "abi_version": ABI_VERSION,
            "domain_count": self.domains.len(),
            "probe_sets_loaded": 1,
            "program_info_expected_count": self.loaded_program_count,
            "program_info_read_errors": info_read_errors,
            "histogram_storage_bytes": self.cpus * (self.domains.len() + 1) * SLOT_BYTES,
            "block_semantics": "bounded HASH; partial nr_bytes accumulate until terminal; blk_service is data request service; zero-byte opcode FLUSH has a separate extension histogram; requeued/error/unknown-zero-byte requests omitted from service histograms; issue without insert has UNKNOWN queue span (direct dispatch is legal); untracked completion may be late attach, flush sequencing, or coverage loss and remains UNKNOWN; merges and async writeback are not Agent-attributed",
            "block_diagnostics": self.block_diagnostics(),
            "block_pending_requests": self.block_pending_requests(),
            "bpf_stats_enabled": self.stats_fd.is_some(),
            "runtime_stats_requested": self.runtime_stats_requested,
            "runtime_stats_enabled_by_sampler": self.stats_fd.is_some(),
            "runtime_stats_external_state": "UNKNOWN",
            "runtime_stats_scope": "global across BPF programs while enabled; counters may be partial without a sampler-held stats fd",
            "programs": out,
            "memory_backend": self.memory_backend,
            "memory_attachment_scope": "single perf FD enables global trace_kprobe prog_array before per-CPU sample-list check; programs return zero and do not emit perf sample payload",
            "memory_return_probe_profiles": self.trace_events.iter().map(OwnedTraceEvent::json).collect::<Vec<_>>(),
            "online_cpu_identity": {"initial": self.online_cpus, "current": current_cpus, "status": cpu_status},
        })
    }

    fn block_diagnostics(&self) -> Value {
        const SAMPLES: usize = 8;
        const SAMPLE_WORDS: usize = 6;
        const NAMES: [&str; 10] = [
            "request_read_failed",
            "flush_issued",
            "flush_completed",
            "flush_error",
            "queue_span_unknown",
            "untracked_complete",
            "untracked_requeue",
            "zero_nonflush_unsupported",
            "zero_flush_invalid_bytes",
            "sample_attempts",
        ];
        const WORDS: usize = BUCKETS + 1 + NAMES.len() + SAMPLES * SAMPLE_WORDS;
        const REASONS: [&str; 9] = [
            "INVALID",
            "ISSUE_WITHOUT_INSERT_QUEUE_UNKNOWN",
            "ZERO_BYTE_FLUSH_COMPLETED",
            "ZERO_NONFLUSH_UNSUPPORTED",
            "UNTRACKED_COMPLETE_UNKNOWN",
            "UNTRACKED_REQUEUE_UNKNOWN",
            "REQUEST_READ_FAILED",
            "ZERO_FLUSH_INVALID_BYTES",
            "ZERO_BYTE_FLUSH_ERROR",
        ];
        let (map, fd) = match map_fd(self.object, "kh_block_diagnostics") {
            Ok(pair) => pair,
            Err(error) => {
                return json!({"status":"NOT_AVAILABLE_LEGACY_OBJECT", "detail":error.to_string()})
            }
        };
        if unsafe { libbpf::bpf_map__value_size(map) } as usize != WORDS * 8 {
            return json!({"status":"INVALID_EXTENSION_LAYOUT"});
        }
        let mut words = vec![0u64; WORDS * self.cpus];
        let zero = 0u32;
        if unsafe {
            libbpf::bpf_map_lookup_elem(fd, (&zero as *const u32).cast(), words.as_mut_ptr().cast())
        } != 0
        {
            return json!({"status":"READ_FAILED", "detail":std::io::Error::last_os_error().to_string()});
        }
        let mut buckets = [0u64; BUCKETS];
        let mut sum_ns = 0u64;
        let mut counters = [0u64; NAMES.len()];
        let mut samples = Vec::new();
        let mut truncated = 0u64;
        for (cpu, row) in words.chunks_exact(WORDS).enumerate() {
            for (i, count) in buckets.iter_mut().enumerate() {
                *count += row[i];
            }
            sum_ns += row[BUCKETS];
            for (i, count) in counters.iter_mut().enumerate() {
                *count += row[BUCKETS + 1 + i];
            }
            let attempted = row[BUCKETS + NAMES.len()];
            truncated += attempted.saturating_sub(SAMPLES as u64);
            for i in 0..usize::min(attempted as usize, SAMPLES) {
                let offset = BUCKETS + 1 + NAMES.len() + i * SAMPLE_WORDS;
                let value = &row[offset..offset + SAMPLE_WORDS];
                let reason = value[5] as u32 as usize;
                let mut identity = Sha256::new();
                identity.update(value[1].to_ne_bytes());
                samples.push(json!({"cpu":cpu, "timestamp_ns":value[0],
                    "request_address_digest":format!("{:x}", identity.finalize()),
                    "remaining_bytes":value[2], "nr_bytes":value[3] as u32,
                    "cmd_flags":(value[3] >> 32) as u32, "rq_flags":value[4] as u32,
                    "error":(value[4] >> 32) as u32 as i32,
                    "reason":REASONS.get(reason).copied().unwrap_or("UNSUPPORTED_REASON"),
                    "reason_code":reason,
                    "object_fields_status":if value[5] >> 32 == 1 { "RESOLVED_REQUEST_FIELDS" } else { "UNRESOLVED_OR_PARTIAL" }}));
            }
        }
        json!({"version":1,"status":"OBSERVED_NON_ATOMIC","scope":"SYSTEM_UNATTRIBUTED",
            "counters":NAMES.iter().zip(counters).collect::<std::collections::BTreeMap<_,_>>(),
            "flush_service":{"count":buckets.iter().sum::<u64>(),"sum_ns":sum_ns,"buckets":buckets,
                "semantics":"observed issue -> terminal successful zero-byte opcode FLUSH completion; requeued/error omitted; not data service, not end-to-end fdatasync latency"},
            "samples":samples,"sample_capacity_per_cpu":SAMPLES,"samples_truncated":truncated,
            "sample_semantics":"bounded first special events per CPU; missing samples are explicit truncation, not a full history; request address digest is not a generation-bearing lifetime identity; no diagnosis of older untyped evidence",
            "queue_semantics":"absence of insert may be legal direct dispatch/bypass; queue span UNKNOWN, not zero; tracked service still measured",
            "untracked_semantics":"opcode and raw flags are hints; late attach, flush-sequence secondary completion and genuine loss cannot be distinguished without further lifecycle evidence; remains UNKNOWN"})
    }

    fn block_pending_requests(&self) -> Value {
        let (_, fd) = match map_fd(self.object, "kh_blk_inflight") {
            Ok(value) => value,
            Err(error) => return json!({"status": "UNKNOWN", "detail": error.to_string()}),
        };
        let mut current = 0u64;
        let mut has_current = false;
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..=16384 {
            let mut next = 0u64;
            let previous = if has_current {
                (&current as *const u64).cast()
            } else {
                ptr::null()
            };
            if unsafe { libbpf::bpf_map_get_next_key(fd, previous, (&mut next as *mut u64).cast()) }
                != 0
            {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                    return json!({"status":"OBSERVED_NON_ATOMIC", "count":seen.len(), "max_entries":16384});
                }
                return json!({"status":"UNKNOWN", "observed_count":seen.len(), "max_entries":16384});
            }
            if !seen.insert(next) {
                return json!({"status":"INDETERMINATE_CONCURRENT_MAP_CHANGE", "observed_count":seen.len(), "max_entries":16384});
            }
            current = next;
            has_current = true;
        }
        json!({"status":"TRUNCATED", "observed_count":seen.len(), "max_entries":16384})
    }

    pub fn map_ids(&self) -> Vec<u32> {
        let mut ids = Vec::new();
        let mut map = ptr::null_mut();
        loop {
            map = unsafe { libbpf::bpf_object__next_map(self.object, map) };
            if map.is_null() {
                break;
            }
            let mut info: libbpf::bpf_map_info = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libbpf::bpf_map_info>() as u32;
            let fd = unsafe { libbpf::bpf_map__fd(map) };
            if fd >= 0
                && unsafe {
                    libbpf::bpf_obj_get_info_by_fd(
                        fd,
                        (&mut info as *mut libbpf::bpf_map_info).cast(),
                        &mut len,
                    )
                } == 0
            {
                ids.push(info.id);
            }
        }
        ids
    }
}

impl Drop for KernelHist {
    fn drop(&mut self) {
        unsafe {
            for link in self.links.drain(..) {
                libbpf::bpf_link__destroy(link);
            }
            let errors = self.remove_owned_events();
            if !errors.is_empty() {
                eprintln!("owned tracefs cleanup incomplete: {}", json!(errors));
            }
            if !self.view.is_null() {
                libc::munmap(self.view as *mut libc::c_void, self.view_len);
            }
            libbpf::bpf_object__close(self.object);
            if let Some(fd) = self.stats_fd.take() {
                libc::close(fd);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_profile_is_exact_and_missing_or_malformed_is_not_zero() {
        assert_eq!(
            parse_trace_profile(" other 5 9\n owned 100 7\n", "owned").unwrap(),
            [100, 7]
        );
        for text in [
            "owned_prefix 1 0",
            "owned 1",
            "owned 1 nope",
            "owned 1 0\nowned 2 0",
        ] {
            assert!(parse_trace_profile(text, "owned").is_err());
        }
    }

    #[test]
    fn online_cpu_ranges_are_bounded_unique_and_nonempty() {
        assert_eq!(
            parse_online_cpu_ids("0-2,4,8-10\n", 16).unwrap(),
            [0, 1, 2, 4, 8, 9, 10]
        );
        for text in ["", "0,0", "2-1", "0-16", "0-1,1-2", "x"] {
            assert!(parse_online_cpu_ids(text, 16).is_err());
        }
    }

    #[test]
    fn trace_cleanup_refuses_changed_definition_or_event_identity() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("kh-trace-owner-{}-{nonce}", std::process::id()));
        let dir = root.join("events").join(TRACE_GROUP).join("alloxkh_owned");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("id"), "7\n").unwrap();
        let definition = format!("p:{TRACE_GROUP}/alloxkh_owned handle_mm_fault");
        fs::write(root.join("kprobe_events"), format!("{definition}\n")).unwrap();
        let mut event = OwnedTraceEvent {
            root: root.clone(),
            name: "alloxkh_owned".to_owned(),
            anchor: "handle_mm_fault".to_owned(),
            is_return: false,
            definition: Some(definition.clone()),
            identity: None,
            initial: Some([0, 0]),
            initial_collection_ns: Some([1, 2]),
        };
        event.identity = Some(event.identity().unwrap());
        let changed = format!("p:{TRACE_GROUP}/alloxkh_owned other_anchor\n");
        fs::write(root.join("kprobe_events"), &changed).unwrap();
        assert!(event.remove_verified().is_err());
        assert_eq!(
            fs::read_to_string(root.join("kprobe_events")).unwrap(),
            changed
        );
        fs::write(root.join("kprobe_events"), format!("{definition}\n")).unwrap();
        fs::write(dir.join("id"), "8\n").unwrap();
        assert!(event.remove_verified().is_err());
        assert_eq!(
            fs::read_to_string(root.join("kprobe_events")).unwrap(),
            format!("{definition}\n")
        );
        fs::write(dir.join("id"), "7\n").unwrap();
        event.remove_verified().unwrap();
        assert!(fs::read_to_string(root.join("kprobe_events"))
            .unwrap()
            .ends_with(&format!("-:{TRACE_GROUP}/alloxkh_owned\n")));
        fs::remove_dir_all(root).unwrap();
    }

    fn synthetic_syscall_abi(
        missing_orig_ax: bool,
        unsigned_ret: bool,
        extra_enter_param: bool,
    ) -> KernelBtf {
        let btf = KernelBtf(unsafe { libbpf::btf__new_empty() });
        assert!(!btf.0.is_null());
        let cname = |value: &str| CString::new(value).unwrap();
        let uint = unsafe { libbpf::btf__add_int(btf.0, cname("unsigned long").as_ptr(), 8, 0) };
        let sint = unsafe { libbpf::btf__add_int(btf.0, cname("long").as_ptr(), 8, 1) };
        let regs = unsafe { libbpf::btf__add_struct(btf.0, cname("pt_regs").as_ptr(), 24) };
        assert!(uint > 0 && sint > 0 && regs > 0);
        for (field, offset) in [("di", 0), ("si", 64), ("orig_ax", 128)] {
            if missing_orig_ax && field == "orig_ax" {
                continue;
            }
            assert_eq!(
                unsafe { libbpf::btf__add_field(btf.0, cname(field).as_ptr(), uint, offset, 0) },
                0
            );
        }
        let pointer = unsafe { libbpf::btf__add_ptr(btf.0, regs) };
        let entry = unsafe { libbpf::btf__add_func_proto(btf.0, 0) };
        assert!(pointer > 0 && entry > 0);
        assert_eq!(
            unsafe { libbpf::btf__add_func_param(btf.0, cname("regs").as_ptr(), pointer) },
            0
        );
        if extra_enter_param {
            assert_eq!(
                unsafe { libbpf::btf__add_func_param(btf.0, cname("extra").as_ptr(), uint) },
                0
            );
        }
        assert!(
            unsafe {
                libbpf::btf__add_func(
                    btf.0,
                    cname("trace_syscall_enter").as_ptr(),
                    libbpf::BTF_FUNC_GLOBAL,
                    entry,
                )
            } > 0
        );
        let exit = unsafe { libbpf::btf__add_func_proto(btf.0, 0) };
        assert!(exit > 0);
        assert_eq!(
            unsafe { libbpf::btf__add_func_param(btf.0, cname("regs").as_ptr(), pointer) },
            0
        );
        assert_eq!(
            unsafe {
                libbpf::btf__add_func_param(
                    btf.0,
                    cname("ret").as_ptr(),
                    if unsigned_ret { uint } else { sint },
                )
            },
            0
        );
        assert!(
            unsafe {
                libbpf::btf__add_func(
                    btf.0,
                    cname("trace_syscall_exit").as_ptr(),
                    libbpf::BTF_FUNC_GLOBAL,
                    exit,
                )
            } > 0
        );
        btf
    }

    #[test]
    fn syscall_kprobe_abi_accepts_exact_x86_64_contract() {
        let btf = synthetic_syscall_abi(false, false, false);
        assert_eq!(
            validate_syscall_kprobe_abi_from(btf.0).unwrap()["status"],
            "VALIDATED"
        );
    }

    #[test]
    fn syscall_kprobe_abi_rejects_missing_anchors_fields_unsigned_ret_and_extra_parameters() {
        let btf = KernelBtf(unsafe { libbpf::btf__new_empty() });
        assert!(validate_syscall_kprobe_abi_from(btf.0)
            .unwrap_err()
            .to_string()
            .contains("BTF anchor"));
        for (missing, unsigned, extra, expected) in [
            (true, false, false, "orig_ax"),
            (false, true, false, "signed"),
            (false, false, true, "exactly"),
        ] {
            let btf = synthetic_syscall_abi(missing, unsigned, extra);
            assert!(validate_syscall_kprobe_abi_from(btf.0)
                .unwrap_err()
                .to_string()
                .contains(expected));
        }
    }

    #[test]
    fn layout_matches_header() {
        // struct kh_slot in bpf/kernel_hist.h: 27 metrics x 32 buckets,
        // 27 sums and 22 counters, all __u64.
        assert_eq!(SLOT_BYTES, 7304);
        assert_eq!(GROUPS.iter().map(|(_, p)| p.len()).sum::<usize>(), 26);
    }

    #[test]
    fn syscall_classes_are_disjoint_and_in_range() {
        let mut seen = std::collections::BTreeSet::new();
        for (class, nrs) in SYSCALL_CLASSES {
            assert!(class < SYSCALL_OTHER);
            for nr in nrs {
                assert!(*nr < SYSCALL_SLOTS);
                assert!(seen.insert(*nr), "syscall {nr} is in two classes");
            }
        }
    }

    #[test]
    fn snapshot_json_trims_trailing_zero_buckets() {
        let mut counts = vec![[0u64; BUCKETS]; METRICS.len()];
        counts[0][3] = 2;
        counts[0][5] = 1;
        let snap = Snapshot {
            counts,
            sum_ns: vec![7; METRICS.len()],
            counters: vec![1; COUNTERS.len()],
        };
        let v = snap.to_json();
        assert_eq!(v["m"][0], json!([3, 7, 0, 0, 0, 2, 0, 1]));
        assert_eq!(v["m"][1], json!([0, 7]));
        assert_eq!(v["c"].as_array().unwrap().len(), COUNTERS.len());
    }

    #[test]
    fn cgroup_level_counts_components() {
        assert_eq!(cgroup_level(Path::new("/sys/fs/cgroup")).unwrap(), 0);
        assert_eq!(
            cgroup_level(Path::new("/sys/fs/cgroup/system.slice/docker-x.scope")).unwrap(),
            2
        );
        assert!(cgroup_level(Path::new("/tmp/x")).is_err());
        assert!(cgroup_level(Path::new("/sys/fs/cgroup/a/../b")).is_err());
        assert!(cgroup_level(Path::new("/sys/fs/cgroup/a/./b")).is_err());
        assert!(cgroup_level(Path::new("/sys/fs/cgroup//a")).is_err());
        let limit = Path::new("/sys/fs/cgroup").join(vec!["x"; 31].join("/"));
        assert_eq!(cgroup_level(&limit).unwrap(), 31);
        assert!(cgroup_level(&limit.join("x")).is_err());
    }
}
