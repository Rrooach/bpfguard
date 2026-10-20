// SPDX-License-Identifier: GPL-2.0-only
//! Opt-in file-object diagnostics. Not an Observer WAL or safety verdict.
use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;
use libbpf_sys as bpf;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const LIMIT: usize = 8192;
const HEALTH: [&str; 9] = [
    "context_full",
    "pending_full",
    "object_read_failed",
    "aggregate_full",
    "nested_hooks_skipped",
    "unpaired_exit",
    "syscall_exit_pending",
    "unresolved_mmap",
    "unsupported_syscall_abi",
];
const OPS: [&str; 4] = [
    "read_or_pread",
    "readv_or_preadv",
    "directory_iteration",
    "file_mmap",
];
static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn stop(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

#[derive(Parser)]
#[clap(about = "Explicit bounded VFS file-object diagnostic collector")]
struct Args {
    #[clap(long)]
    output_dir: PathBuf,
    #[clap(long)]
    bpf_object: PathBuf,
    #[clap(long)]
    bpf_sha256: String,
    /// Non-overlapping canonical cgroup v2 roots; repeatable, at most 16.
    #[clap(long, required = true)]
    cgroup: Vec<PathBuf>,
    #[clap(long)]
    label: Option<String>,
    /// Safety timeout; no periodic object dump in the hot path.
    #[clap(long, default_value = "1200")]
    max_seconds: u64,
    /// Diagnostic file/instance cardinality budget (1024..131072). Default
    /// 8192; higher settings consume more kernel memory, never auto-grow.
    #[clap(long, default_value = "8192")]
    max_file_records: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug, PartialEq)]
struct Key {
    domain_id: u64,
    caller_cgroup_id: u64,
    process_start_boottime_ns: u64,
    thread_start_boottime_ns: u64,
    mount_id: u64,
    inode: u64,
    size: i64,
    mtime_sec: i64,
    ctime_sec: i64,
    device: u32,
    generation: u32,
    mtime_nsec: u32,
    ctime_nsec: u32,
    tgid: u32,
    tid: u32,
    operation: u32,
    reserved: u32,
}
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Counts {
    calls: u64,
    success_calls: u64,
    errors: u64,
    returned_bytes: u64,
    duration_ns: u64,
    max_duration_ns: u64,
    first_start_ns: u64,
    last_end_ns: u64,
}
#[repr(C)]
#[derive(Default)]
struct Pending {
    object: Key,
    start_ns: u64,
    return_value: i64,
    end_ns: u64,
    object_valid: u32,
    depth: u32,
}
#[repr(C)]
struct Config {
    count: u32,
    enabled: u32,
}
#[repr(C)]
struct Domain {
    cgroup_id: u64,
    level: u32,
    reserved: u32,
}

fn ns(clock: libc::clockid_t) -> u64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(clock, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}
fn domains(paths: &[PathBuf]) -> Result<Vec<(File, Value, Domain)>> {
    if paths.is_empty() || paths.len() > 16 {
        bail!("one to 16 cgroups required");
    }
    for (i, path) in paths.iter().enumerate() {
        for other in &paths[i + 1..] {
            if path.starts_with(other) || other.starts_with(path) {
                bail!("overlapping file-profiler roots would double-attribute observations");
            }
        }
    }
    let mut out = Vec::new();
    for path in paths {
        if !path.is_absolute() || fs::canonicalize(path)? != *path {
            bail!("cgroup must be an absolute canonical path");
        }
        let rel = path.strip_prefix("/sys/fs/cgroup")?;
        if rel.components().any(|c| !matches!(c, Component::Normal(_))) {
            bail!("invalid cgroup components");
        }
        let level = rel.components().count();
        if level == 0 || level > 31 || !path.join("cgroup.controllers").is_file() {
            bail!("require a non-root cgroup-v2 directory of depth <=31");
        }
        let file = File::open(path)?;
        let meta = file.metadata()?;
        let identity = json!({"path": path, "inode": meta.ino(), "device": meta.dev(),
                              "level": level});
        out.push((
            file,
            identity,
            Domain {
                cgroup_id: meta.ino(),
                level: level as u32,
                reserved: 0,
            },
        ));
    }
    Ok(out)
}
fn rc(value: i32, operation: &str) -> Result<()> {
    if value < 0 {
        bail!("{operation}: {}", io::Error::last_os_error());
    }
    Ok(())
}
fn native_arch(arch: &str) -> Result<()> {
    if arch != "x86_64" {
        bail!("file-profiler syscall numbering supports native x86-64 only");
    }
    Ok(())
}
fn pointer_bad<T>(ptr: *mut T) -> bool {
    ptr.is_null() || (ptr as isize) < 0 && (ptr as isize) > -4096
}
struct Collector {
    object: *mut bpf::bpf_object,
    links: Vec<*mut bpf::bpf_link>,
    config_fd: i32,
    file_fd: i32,
    health_fd: i32,
    calls_fd: i32,
    pending_fd: i32,
    pending_sample_fd: i32,
    cpus: usize,
    file_limit: usize,
    roots: Vec<(File, Value, Domain)>,
}
fn map(object: *mut bpf::bpf_object, name: &str, key: u32, value: u32) -> Result<i32> {
    let c = CString::new(name)?;
    let map = unsafe { bpf::bpf_object__find_map_by_name(object, c.as_ptr()) };
    if map.is_null() {
        bail!("missing map {name}");
    }
    if unsafe { bpf::bpf_map__key_size(map) } != key
        || unsafe { bpf::bpf_map__value_size(map) } != value
    {
        bail!("file-profiler map {name} ABI mismatch");
    }
    let fd = unsafe { bpf::bpf_map__fd(map) };
    if fd < 0 {
        bail!("map {name} is not loaded");
    }
    Ok(fd)
}
fn update<T>(fd: i32, index: u32, value: &T) -> Result<()> {
    rc(
        unsafe {
            bpf::bpf_map_update_elem(
                fd,
                (&index as *const u32).cast(),
                (value as *const T).cast(),
                bpf::BPF_ANY as u64,
            )
        },
        "update config",
    )
}
impl Collector {
    fn open(args: &Args) -> Result<(Self, String)> {
        native_arch(std::env::consts::ARCH)?;
        if !(1024..=131072).contains(&args.max_file_records) {
            bail!("max-file-records must be 1024..131072");
        }
        let roots = domains(&args.cgroup)?;
        let bytes = fs::read(&args.bpf_object)?;
        if bytes.len() > 2 * 1024 * 1024 {
            bail!("BPF object exceeds 2 MiB");
        }
        let digest = format!("{:x}", Sha256::digest(&bytes));
        if digest != args.bpf_sha256.to_ascii_lowercase() {
            bail!("BPF digest mismatch");
        }
        let name = CString::new("file_profile")?;
        let opts = bpf::bpf_object_open_opts {
            sz: std::mem::size_of::<bpf::bpf_object_open_opts>() as u64,
            object_name: name.as_ptr(),
            ..unsafe { std::mem::zeroed() }
        };
        let object =
            unsafe { bpf::bpf_object__open_mem(bytes.as_ptr().cast(), bytes.len() as u64, &opts) };
        if pointer_bad(object) {
            bail!("open file-profiler BPF object");
        }
        let mut this = Self {
            object,
            links: Vec::new(),
            config_fd: -1,
            file_fd: -1,
            health_fd: -1,
            calls_fd: -1,
            pending_fd: -1,
            pending_sample_fd: -1,
            cpus: 0,
            file_limit: args.max_file_records as usize,
            roots,
        };
        let files_name = CString::new("fp_files")?;
        let file_map = unsafe { bpf::bpf_object__find_map_by_name(object, files_name.as_ptr()) };
        if file_map.is_null() {
            bail!("missing fp_files map");
        }
        rc(
            unsafe { bpf::bpf_map__set_max_entries(file_map, args.max_file_records) },
            "size bounded file map",
        )?;
        rc(
            unsafe { bpf::bpf_object__load(object) },
            "load file-profiler BPF; required BTF hooks cannot silently degrade",
        )?;
        this.config_fd = map(object, "fp_config", 4, 8)?;
        this.file_fd = map(object, "fp_files", 104, 64)?;
        this.health_fd = map(object, "fp_health", 4, 8)?;
        this.calls_fd = map(object, "fp_calls", 8, 136)?;
        this.pending_fd = map(object, "fp_pending", 8, 136)?;
        this.pending_sample_fd = map(object, "fp_pending_sample", 4, 136)?;
        let domain_fd = map(object, "fp_domains", 4, 16)?;
        let cpus = unsafe { bpf::libbpf_num_possible_cpus() };
        if cpus <= 0 {
            bail!("cannot count possible CPUs");
        }
        this.cpus = cpus as usize;
        for (i, (_, _, root)) in this.roots.iter().enumerate() {
            update(domain_fd, i as u32, root)?;
        }
        let mut program = ptr::null_mut();
        loop {
            program = unsafe { bpf::bpf_object__next_program(object, program) };
            if program.is_null() {
                break;
            }
            let link = unsafe { bpf::bpf_program__attach(program) };
            if pointer_bad(link) {
                let name = unsafe { CStr::from_ptr(bpf::bpf_program__name(program)) };
                bail!("attach required hook {}", name.to_string_lossy());
            }
            this.links.push(link);
        }
        update(
            this.config_fd,
            0,
            &Config {
                count: this.roots.len() as u32,
                enabled: 0,
            },
        )?;
        Ok((this, digest))
    }
    fn enable(&mut self) -> Result<()> {
        update(
            self.config_fd,
            0,
            &Config {
                count: self.roots.len() as u32,
                enabled: 1,
            },
        )
    }
    fn detach(&mut self) -> Result<()> {
        update(
            self.config_fd,
            0,
            &Config {
                count: self.roots.len() as u32,
                enabled: 0,
            },
        )?;
        for link in self.links.drain(..).rev() {
            unsafe { bpf::bpf_link__destroy(link) };
        }
        Ok(())
    }
    fn active(&self, fd: i32) -> Result<usize> {
        let mut prev: Option<u64> = None;
        let mut count = 0;
        loop {
            let mut next: u64 = 0;
            let rc = unsafe {
                bpf::bpf_map_get_next_key(
                    fd,
                    prev.as_ref()
                        .map_or(ptr::null(), |v| (v as *const u64).cast()),
                    (&mut next as *mut u64).cast(),
                )
            };
            if rc != 0 {
                if io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                    bail!("enumerate pending map");
                }
                return Ok(count);
            }
            count += 1;
            if count > LIMIT {
                bail!("pending-map enumeration exceeded bound");
            }
            prev = Some(next);
        }
    }
    fn result(&self, boot_id: &str) -> Result<Value> {
        let mut rows = Vec::new();
        let mut previous: Option<Key> = None;
        loop {
            let mut next = Key::default();
            let code = unsafe {
                bpf::bpf_map_get_next_key(
                    self.file_fd,
                    previous
                        .as_ref()
                        .map_or(ptr::null(), |v| (v as *const Key).cast()),
                    (&mut next as *mut Key).cast(),
                )
            };
            if code != 0 {
                if io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                    bail!("enumerate file map");
                }
                break;
            }
            if rows.len() >= self.file_limit {
                bail!("file map enumeration exceeded bound");
            }
            let mut counts = Counts::default();
            rc(
                unsafe {
                    bpf::bpf_map_lookup_elem(
                        self.file_fd,
                        (&next as *const Key).cast(),
                        (&mut counts as *mut Counts).cast(),
                    )
                },
                "lookup file counters",
            )?;
            rows.push(row(&next, &counts, boot_id)?);
            previous = Some(next);
        }
        let mut health = serde_json::Map::new();
        let mut incomplete = false;
        for (index, name) in HEALTH.iter().enumerate() {
            let mut values = vec![0u64; self.cpus];
            let key = index as u32;
            rc(
                unsafe {
                    bpf::bpf_map_lookup_elem(
                        self.health_fd,
                        (&key as *const u32).cast(),
                        values.as_mut_ptr().cast(),
                    )
                },
                "read health counters",
            )?;
            let total: u64 = values.into_iter().sum();
            if total != 0 && *name != "nested_hooks_skipped" {
                incomplete = true;
            }
            health.insert((*name).into(), json!(total));
        }
        let pending = self.active(self.pending_fd)?;
        let contexts = self.active(self.calls_fd)?;
        incomplete |= pending != 0 || contexts != 0;
        let mut last_pending = Pending::default();
        let zero = 0u32;
        rc(
            unsafe {
                bpf::bpf_map_lookup_elem(
                    self.pending_sample_fd,
                    (&zero as *const u32).cast(),
                    (&mut last_pending as *mut Pending).cast(),
                )
            },
            "read unmatched sample",
        )?;
        let unmatched_sample = if last_pending.depth == 0 {
            Value::Null
        } else {
            json!({
            "pid": last_pending.object.tgid, "tid": last_pending.object.tid,
            "operation": OPS.get(last_pending.object.operation as usize),
            "inode": last_pending.object.inode, "start_monotonic_ns": last_pending.start_ns,
            "depth": last_pending.depth, "quality": "LAST_UNMATCHED_INTERVAL_NOT_COMPLETE_LOG" })
        };
        let mut programs = Vec::new();
        let mut program = ptr::null_mut();
        loop {
            program = unsafe { bpf::bpf_object__next_program(self.object, program) };
            if program.is_null() {
                break;
            }
            let fd = unsafe { bpf::bpf_program__fd(program) };
            let mut info: bpf::bpf_prog_info = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<bpf::bpf_prog_info>() as u32;
            if unsafe {
                bpf::bpf_obj_get_info_by_fd(
                    fd,
                    (&mut info as *mut bpf::bpf_prog_info).cast(),
                    &mut len,
                )
            } != 0
            {
                bail!("read BPF program recursion health");
            }
            let misses = info.recursion_misses;
            incomplete |= misses != 0;
            programs.push(json!({"name": unsafe { CStr::from_ptr(bpf::bpf_program__name(program)) }.to_string_lossy(),
                "recursion_misses": misses, "id": info.id}));
        }
        Ok(json!({"schema_version": 2, "boot_id": boot_id,
            "registered_domains": self.roots.iter().map(|(_, id, _)| id).collect::<Vec<_>>(),
            "performance_side_channel_not_audit": true,
            "observation_health": if incomplete { "INCOMPLETE" } else { "COMPLETE_FOR_SELECTED_HOOKS" },
            "health": health, "pending_vfs_calls": pending, "pending_syscalls": contexts,
            "records": rows, "last_unmatched_vfs": unmatched_sample, "programs": programs,
            "coverage": ["native x86-64 read/pread64, readv/preadv/preadv2 outermost VFS entry/return",
                "getdents/getdents64 directory iteration duration (not directory byte counts)",
                "file mmap attempt with resolved file identity, classified success/error (zero measured access bytes)"],
            "limits": ["Native x86-64 only; compat/x32 syscall ABI is not supported",
                "No mmap access-byte or page-fault-to-file accounting, io_uring, splice/sendfile or delegated reads",
                "Returned bytes include page-cache hits; not physical I/O and not whole-syscall time",
                "Metadata at operation entry is VERSION_HINT; not content hash, snapshot or inode-reuse-proof version",
                "Nested VFS reads use outermost user-visible object only; asynchronous work not attributed",
                "Process/thread instances use boot_id + PID/TID + start_boottime_ns (not CLOCK_MONOTONIC)",
                "Domain/task and thread/request association requires separately recorded execution intervals; no permanent thread ownership"]}))
    }
}
impl Drop for Collector {
    fn drop(&mut self) {
        for link in self.links.drain(..).rev() {
            unsafe { bpf::bpf_link__destroy(link) };
        }
        unsafe { bpf::bpf_object__close(self.object) };
    }
}
fn row(key: &Key, value: &Counts, boot: &str) -> Result<Value> {
    let operation = OPS
        .get(key.operation as usize)
        .context("unknown BPF operation")?;
    if key.inode == 0 || key.mount_id == 0 || value.calls != value.success_calls + value.errors {
        bail!("invalid file-profile record");
    }
    if key.operation >= 2 && value.returned_bytes != 0 {
        bail!("mmap and directory iteration cannot claim observed bytes");
    }
    // Match inode_get_ctime_nsec(): Linux multigrain timestamp bit 31 is
    // I_CTIME_QUERIED, not nanoseconds. Preserve storage bits independently.
    let ctime_nsec = key.ctime_nsec & !(1u32 << 31);
    if ctime_nsec >= 1_000_000_000 || key.mtime_nsec >= 1_000_000_000 {
        bail!("invalid inode timestamp nanoseconds");
    }
    Ok(
        json!({"boot_id": boot, "domain_id": key.domain_id, "caller_cgroup_id": key.caller_cgroup_id,
        "process": {"pid": key.tgid, "start_boottime_ns": key.process_start_boottime_ns},
        "thread": {"tid": key.tid, "start_boottime_ns": key.thread_start_boottime_ns},
        "object": {"mount_id_unique": key.mount_id, "kernel_device": key.device,
            "inode": key.inode, "inode_generation": key.generation,
            "generation_valid": key.generation != 0,
            "version_quality": "METADATA_VERSION_HINT",
            "size": key.size, "mtime_sec": key.mtime_sec, "mtime_nsec": key.mtime_nsec,
            "ctime_sec": key.ctime_sec, "ctime_nsec": ctime_nsec,
            "raw_ctime_nsec": key.ctime_nsec, "ctime_queried_flag": key.ctime_nsec & (1u32 << 31) != 0},
        "operation": operation, "calls": value.calls, "success_calls": value.success_calls,
        "errors": value.errors, "returned_bytes": value.returned_bytes,
        "duration_ns": value.duration_ns, "max_duration_ns": value.max_duration_ns,
        "first_start_ns": value.first_start_ns, "last_end_ns": value.last_end_ns,
        "latency_scope": if key.operation == 3 { "SYSCALL_MAPPING_ONLY" } else { "OUTERMOST_VFS_CALL" }}),
    )
}
fn write_new(path: &Path, value: &Value) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
fn run(args: Args) -> Result<()> {
    if args.max_seconds == 0 || args.max_seconds > 3600 {
        bail!("max-seconds must be 1..3600");
    }
    let (mut collector, digest) = Collector::open(&args)?;
    fs::create_dir(&args.output_dir).context("output directory must not exist")?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    let start = ns(libc::CLOCK_MONOTONIC);
    write_new(
        &args.output_dir.join("file-profile-meta.json"),
        &json!({
            "schema_version": 2, "label": args.label, "boot_id": boot, "bpf_sha256": digest,
            "start_monotonic_ns": start, "start_boottime_ns": ns(libc::CLOCK_BOOTTIME),
            "start_boundary_scope": "PRE_ENABLE_LOWER_BOUND_REQUIRES_WORKLOAD_READY_GATE",
            "native_syscall_abi": "X86_64_EXCLUDING_TS_COMPAT_AND_X32",
        "clock_ticks_per_second": unsafe { libc::sysconf(libc::_SC_CLK_TCK) },
            "domains": collector.roots.iter().map(|(_, id, _)| id).collect::<Vec<_>>(),
        "file_key_bytes": std::mem::size_of::<Key>(), "entry_limit": args.max_file_records,
        "maximum_payload_bytes_excluding_kernel_hash_overhead": args.max_file_records as u64 * 168,
            "profile": "EXPLICIT_DIAGNOSTIC_NOT_DEFAULT", "periodic_object_dump": false
        }),
    )?;
    for signal in [libc::SIGTERM, libc::SIGINT] {
        if unsafe { libc::signal(signal, stop as usize) } == libc::SIG_ERR {
            bail!("signal handler");
        }
    }
    collector.enable()?;
    println!("READY");
    io::stdout().flush()?;
    let deadline = Instant::now() + Duration::from_secs(args.max_seconds);
    while !STOP.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let timed_out = !STOP.load(Ordering::SeqCst);
    collector.detach()?;
    let mut result = collector.result(&boot)?;
    result["start_monotonic_ns"] = json!(start);
    result["end_monotonic_ns"] = json!(ns(libc::CLOCK_MONOTONIC));
    result["timed_out"] = json!(timed_out);
    if timed_out {
        result["observation_health"] = json!("INCOMPLETE");
    }
    write_new(&args.output_dir.join("file-profile.json"), &result)
}
fn main() {
    if let Err(error) = run(Args::parse()) {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_architecture_fails_before_loading() {
        assert!(native_arch("x86_64").is_ok());
        for arch in ["x86", "aarch64", "riscv64"] {
            assert!(native_arch(arch).is_err());
        }
    }
    fn fixture() -> (Key, Counts) {
        (
            Key {
                mount_id: 1,
                inode: 2,
                operation: 0,
                ..Key::default()
            },
            Counts {
                calls: 2,
                success_calls: 1,
                errors: 1,
                returned_bytes: 19,
                ..Counts::default()
            },
        )
    }
    #[test]
    fn abi() {
        assert_eq!(std::mem::size_of::<Key>(), 104);
        assert_eq!(std::mem::size_of::<Counts>(), 64);
    }
    #[test]
    fn truthful_record() {
        let (key, counts) = fixture();
        let v = row(&key, &counts, "boot").unwrap();
        assert_eq!(v["returned_bytes"], 19);
        assert_eq!(v["object"]["version_quality"], "METADATA_VERSION_HINT");
        assert_eq!(v["object"]["generation_valid"], false);
    }
    #[test]
    fn mmap_has_no_byte_claim() {
        let (mut key, mut counts) = fixture();
        key.operation = 3;
        assert!(row(&key, &counts, "boot").is_err());
        counts.returned_bytes = 0;
        assert_eq!(
            row(&key, &counts, "boot").unwrap()["latency_scope"],
            "SYSCALL_MAPPING_ONLY"
        );
    }
    #[test]
    fn directory_positive_status_is_not_returned_bytes() {
        let (mut key, mut counts) = fixture();
        key.operation = 2;
        assert!(row(&key, &counts, "boot").is_err());
        counts.returned_bytes = 0;
        assert!(row(&key, &counts, "boot").is_ok());
    }
    #[test]
    fn invalid_identity_counts_and_operations_rejected() {
        let (mut key, mut counts) = fixture();
        key.operation = 12;
        assert!(row(&key, &counts, "b").is_err());
        key.operation = 0;
        key.inode = 0;
        assert!(row(&key, &counts, "b").is_err());
        key.inode = 2;
        counts.calls += 1;
        assert!(row(&key, &counts, "b").is_err());
    }
    #[test]
    fn root_overlap_rejected_before_loading() {
        assert!(domains(&["/sys/fs/cgroup/a".into(), "/sys/fs/cgroup/a/child".into()]).is_err());
        assert!(domains(&["/sys/fs/cgroup/a".into(), "/sys/fs/cgroup/a".into()]).is_err());
    }
    #[test]
    fn ctime_query_bit_is_not_nanoseconds_and_raw_storage_is_preserved() {
        let (mut key, counts) = fixture();
        key.ctime_nsec = (1u32 << 31) | 42;
        let value = row(&key, &counts, "b").unwrap();
        assert_eq!(value["object"]["ctime_nsec"], 42);
        assert_eq!(value["object"]["raw_ctime_nsec"], (1u32 << 31) | 42);
        assert_eq!(value["object"]["ctime_queried_flag"], true);
        key.ctime_nsec = 1_000_000_000;
        assert!(row(&key, &counts, "b").is_err());
    }
}
