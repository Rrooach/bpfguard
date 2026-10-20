// SPDX-License-Identifier: GPL-2.0-only
//! Periodic whole-system and per-cgroup load sampler for Agent runs.
//!
//! This is a measurement side channel, not Observer evidence: its output is
//! never bound into a manifest, WAL, or verdict. Samples carry
//! `CLOCK_MONOTONIC` timestamps so they align with Observer `ktime_ns`
//! events and runner phase marks.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, ErrorKind, Write};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use allox_load_sampler::*;
use anyhow::{bail, Context, Result};
use clap::Parser;
use serde_json::{json, Map, Value};

const SCHEMA_VERSION: u32 = 1;
const MAX_PROCESSES: usize = 4096;
const MAX_CGROUP_DIRS: usize = 256;

const MEMINFO_KEYS: &[&str] = &[
    "MemTotal",
    "MemFree",
    "MemAvailable",
    "Buffers",
    "Cached",
    "SwapCached",
    "Active",
    "Inactive",
    "Dirty",
    "Writeback",
    "AnonPages",
    "Mapped",
    "Shmem",
    "Slab",
    "SReclaimable",
    "SUnreclaim",
    "KernelStack",
    "PageTables",
    "Committed_AS",
    "SwapTotal",
    "SwapFree",
];
const VMSTAT_KEYS: &[&str] = &[
    "pgfault",
    "pgmajfault",
    "pswpin",
    "pswpout",
    "pgpgin",
    "pgpgout",
    "pgscan_kswapd",
    "pgscan_direct",
    "pgsteal_kswapd",
    "pgsteal_direct",
    "allocstall*",
    "compact_stall",
    "workingset_refault*",
    "oom_kill",
    "nr_dirty",
    "nr_writeback",
    "thp_fault_alloc",
];
const MEMORY_STAT_KEYS: &[&str] = &[
    "anon",
    "file",
    "kernel",
    "kernel_stack",
    "pagetables",
    "sock",
    "shmem",
    "file_mapped",
    "file_dirty",
    "file_writeback",
    "slab",
    "active_file",
    "inactive_file",
    "pgfault",
    "pgmajfault",
    "workingset_refault_anon",
    "workingset_refault_file",
    "pgscan",
    "pgsteal",
];
const TCP_KEYS: &[&str] = &[
    "ActiveOpens",
    "PassiveOpens",
    "AttemptFails",
    "EstabResets",
    "CurrEstab",
    "InSegs",
    "OutSegs",
    "RetransSegs",
    "InErrs",
    "OutRsts",
];

#[derive(Parser)]
#[clap(about = "Sample CPU, memory, I/O, network and pressure at a fixed interval")]
struct Args {
    /// New directory for load-meta.json, load-samples.jsonl, load-processes.jsonl
    /// and load-sampler-stats.json; must not exist.
    #[clap(long)]
    output_dir: PathBuf,
    /// System and cgroup sampling period.
    #[clap(long, default_value = "100")]
    interval_ms: u64,
    /// Per-process sampling period inside --cgroup trees; 0 disables it.
    #[clap(long, default_value = "500")]
    process_interval_ms: u64,
    /// Explicitly sample thread instances and scheduler counters; polling is
    /// partial lifecycle evidence and increases /proc work.
    #[clap(long)]
    sample_threads: bool,
    /// Restrict thread diagnostics to these TIDs, pinned on first observation.
    #[clap(long, requires = "sample-threads")]
    thread_tid: Vec<u32>,
    /// Maximum TID rows and examined thread directories per process sample.
    #[clap(long, default_value = "4096")]
    max_thread_samples: usize,
    /// Absolute cgroup-v2 directory to sample; repeatable.
    #[clap(long)]
    cgroup: Vec<PathBuf>,
    /// Free-form label stored in load-meta.json (for example an Observer run ID).
    #[clap(long)]
    label: Option<String>,
    /// Stop after this many system samples even without a signal.
    #[clap(long, default_value = "200000")]
    max_samples: u64,
    /// Ask the kernel to send SIGTERM if the launching process exits.
    #[clap(long)]
    exit_with_parent: bool,
    /// Optional kernel_hist.bpf.o: per-subsystem latency histograms for the
    /// selected inclusive cgroups using one probe set. Unloaded at exit.
    #[clap(long, requires = "kernel-hist-sha256")]
    kernel_hist_object: Option<PathBuf>,
    /// Optional subset of --cgroup for detailed kernel diagnostics; repeatable.
    #[clap(long, requires = "kernel-hist-object")]
    kernel_hist_cgroup: Vec<PathBuf>,
    /// Expected SHA-256 of --kernel-hist-object.
    #[clap(long)]
    kernel_hist_sha256: Option<String>,
    /// Comma-separated probe groups: sched, mem, lock, blk, irq, syscall.
    #[clap(long, default_value = "sched,mem,lock,blk,irq,syscall")]
    kernel_hist_groups: String,
    /// Syscall diagnostic backend: kprobe (non-preemptible handler plus noop
    /// dispatch registration) or legacy raw-btf. No fallback on hook failure.
    #[clap(long, default_value = "kprobe", possible_values = ["kprobe", "raw-btf"])]
    kernel_hist_syscall_backend: String,
    /// Optional exact x86-64 syscall-number selection (0..511), repeatable.
    /// Unselected syscall classes are not measured; selection is frozen.
    #[clap(long, requires = "kernel-hist-object")]
    kernel_hist_syscall_nr: Vec<u32>,
    /// Memory diagnostic backend. kprobe-tracefs has bounded maxactive and
    /// auditable return-probe misses; fentry is explicit legacy diagnostics.
    #[clap(long, default_value = "kprobe-tracefs", possible_values = ["kprobe-tracefs", "fentry"])]
    kernel_hist_memory_backend: String,
    /// Opt in to global BPF runtime accounting while kernel-hist runs. This
    /// adds measurement overhead to all BPF programs, not just this sampler.
    #[clap(long, requires = "kernel-hist-object")]
    kernel_hist_runtime_stats: bool,
}

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() -> Result<()> {
    for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        // No SA_RESTART: a signal must interrupt clock_nanosleep promptly.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = on_signal as usize;
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error()).context("sigaction");
        }
    }
    Ok(())
}

fn clock_ns(clock: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(clock, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn monotonic_ns() -> u64 {
    clock_ns(libc::CLOCK_MONOTONIC)
}

/// Sleep until an absolute CLOCK_MONOTONIC deadline; returns early on signal.
fn sleep_until(deadline_ns: u64) {
    let ts = libc::timespec {
        tv_sec: (deadline_ns / 1_000_000_000) as libc::time_t,
        tv_nsec: (deadline_ns % 1_000_000_000) as libc::c_long,
    };
    unsafe {
        libc::clock_nanosleep(
            libc::CLOCK_MONOTONIC,
            libc::TIMER_ABSTIME,
            &ts,
            std::ptr::null_mut(),
        )
    };
}

/// A kept-open proc/sysfs/cgroup file re-read from offset 0 each sample.
struct Source {
    path: PathBuf,
    file: Option<File>,
}

impl Source {
    fn open(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let file = File::open(&path).ok();
        Source { path, file }
    }

    fn available(&self) -> bool {
        self.file.is_some()
    }

    fn read<'a>(&mut self, buf: &'a mut Vec<u8>) -> io::Result<&'a str> {
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "source unavailable"))?;
        read_all_at(file, buf)?;
        std::str::from_utf8(buf).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
    }
}

fn read_all_at(file: &File, buf: &mut Vec<u8>) -> io::Result<()> {
    buf.clear();
    let mut chunk = [0u8; 16384];
    loop {
        match file.read_at(&mut chunk, buf.len() as u64) {
            Ok(0) => return Ok(()),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

struct SystemSources {
    stat: Source,
    loadavg: Source,
    schedstat: Source,
    meminfo: Source,
    vmstat: Source,
    diskstats: Source,
    net_dev: Source,
    snmp: Source,
    psi: [(&'static str, Source); 3],
    disks: Vec<String>,
}

impl SystemSources {
    fn open() -> Self {
        SystemSources {
            stat: Source::open("/proc/stat"),
            loadavg: Source::open("/proc/loadavg"),
            schedstat: Source::open("/proc/schedstat"),
            meminfo: Source::open("/proc/meminfo"),
            vmstat: Source::open("/proc/vmstat"),
            diskstats: Source::open("/proc/diskstats"),
            net_dev: Source::open("/proc/net/dev"),
            snmp: Source::open("/proc/net/snmp"),
            psi: [
                ("cpu", Source::open("/proc/pressure/cpu")),
                ("memory", Source::open("/proc/pressure/memory")),
                ("io", Source::open("/proc/pressure/io")),
            ],
            disks: block_devices(),
        }
    }

    fn availability(&self) -> Map<String, Value> {
        let mut out = Map::new();
        let mut put = |s: &Source| {
            out.insert(s.path.display().to_string(), Value::from(s.available()));
        };
        for s in [
            &self.stat,
            &self.loadavg,
            &self.schedstat,
            &self.meminfo,
            &self.vmstat,
            &self.diskstats,
            &self.net_dev,
            &self.snmp,
        ] {
            put(s);
        }
        for (_, s) in &self.psi {
            put(s);
        }
        out
    }
}

/// Whole block devices, excluding loop and ram devices.
fn block_devices() -> Vec<String> {
    let mut out: Vec<String> = fs::read_dir("/sys/block")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.starts_with("loop") && !n.starts_with("ram"))
        .collect();
    out.sort();
    out
}

struct CgroupSources {
    dir: PathBuf,
    present: bool,
    cpu_stat: Source,
    memory_current: Source,
    memory_peak: Source,
    memory_stat: Source,
    memory_events: Source,
    io_stat: Source,
    pids_current: Source,
    psi: [(&'static str, Source); 3],
}

impl CgroupSources {
    fn open(dir: &Path) -> Self {
        CgroupSources {
            dir: dir.to_path_buf(),
            present: true,
            cpu_stat: Source::open(dir.join("cpu.stat")),
            memory_current: Source::open(dir.join("memory.current")),
            memory_peak: Source::open(dir.join("memory.peak")),
            memory_stat: Source::open(dir.join("memory.stat")),
            memory_events: Source::open(dir.join("memory.events")),
            io_stat: Source::open(dir.join("io.stat")),
            pids_current: Source::open(dir.join("pids.current")),
            psi: [
                ("cpu", Source::open(dir.join("cpu.pressure"))),
                ("memory", Source::open(dir.join("memory.pressure"))),
                ("io", Source::open(dir.join("io.pressure"))),
            ],
        }
    }

    fn static_limits(&self) -> Value {
        let metadata = fs::metadata(&self.dir).ok();
        let read = |name: &str| {
            fs::read_to_string(self.dir.join(name))
                .ok()
                .map(|v| v.trim().to_string())
        };
        json!({
            "path": self.dir.display().to_string(),
            "inode": metadata.as_ref().map(|m| m.ino()),
            "device": metadata.as_ref().map(|m| m.dev()),
            "cpu.max": read("cpu.max"),
            "cpu.weight": read("cpu.weight"),
            "memory.max": read("memory.max"),
            "memory.high": read("memory.high"),
            "pids.max": read("pids.max"),
            "cpuset.cpus.effective": read("cpuset.cpus.effective"),
            "available": {
                "cpu.stat": self.cpu_stat.available(),
                "memory.stat": self.memory_stat.available(),
                "io.stat": self.io_stat.available(),
                "pids.current": self.pids_current.available(),
                "memory.peak": self.memory_peak.available(),
                "pressure": self.psi.iter().all(|(_, s)| s.available()),
            },
        })
    }
}

#[derive(Default)]
struct Stats {
    samples: u64,
    process_samples: u64,
    missed_ticks: u64,
    max_lateness_ns: u64,
    max_sample_cost_ns: u64,
    total_sample_cost_ns: u64,
    max_loop_cost_ns: u64,
    total_loop_cost_ns: u64,
    read_errors: u64,
    vanished_processes: u64,
    truncated_process_sets: u64,
    truncated_cgroup_traversals: u64,
    cgroup_traversal_read_errors: u64,
    thread_read_errors: u64,
    vanished_threads_during_read: u64,
    truncated_thread_samples: u64,
    thread_identity_changes: u64,
    thread_disappeared_between_samples: u64,
    bytes_written: u64,
}

struct Sampler {
    system: SystemSources,
    cgroups: Vec<CgroupSources>,
    buf: Vec<u8>,
    stats: Stats,
    sample_threads: bool,
    selected_tids: BTreeSet<u32>,
    pinned_tids: BTreeMap<u32, ThreadIdentity>,
    previous_threads: Vec<BTreeSet<ThreadIdentity>>,
    max_thread_samples: usize,
    boot_id: String,
}

impl Sampler {
    /// Read one source; failures are counted and reported per sample instead
    /// of being silently replaced by zeros.
    fn read_with<F>(
        buf: &mut Vec<u8>,
        stats: &mut Stats,
        errors: &mut Vec<Value>,
        source: &mut Source,
        parse: F,
    ) -> Option<Value>
    where
        F: FnOnce(&str) -> Value,
    {
        if !source.available() {
            return None;
        }
        match source.read(buf) {
            Ok(text) => Some(parse(text)),
            Err(e) => {
                stats.read_errors += 1;
                errors.push(
                    json!({"path": source.path.display().to_string(), "error": e.to_string()}),
                );
                None
            }
        }
    }

    fn sample_system(&mut self, row: &mut Map<String, Value>, errors: &mut Vec<Value>) {
        let (buf, stats, s) = (&mut self.buf, &mut self.stats, &mut self.system);
        if let Some(v) = Self::read_with(buf, stats, errors, &mut s.stat, |t| {
            let p = parse_proc_stat(t);
            json!({
                "cpu_total": p.total,
                "cpu": p.per_cpu.iter().map(|(_, v)| v.clone()).collect::<Vec<_>>(),
                "cpu_ids": p.per_cpu.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
                "ctxt": p.ctxt, "processes": p.processes, "intr": p.intr_total,
                "procs_running": p.procs_running, "procs_blocked": p.procs_blocked,
            })
        }) {
            row.insert("stat".into(), v);
        }
        if let Some(v) = Self::read_with(buf, stats, errors, &mut s.loadavg, |t| {
            let f: Vec<&str> = t.split_whitespace().collect();
            let (runnable, threads) = f
                .get(3)
                .and_then(|v| v.split_once('/'))
                .unwrap_or(("0", "0"));
            json!({
                "load1": f.first().and_then(|v| v.parse::<f64>().ok()),
                "runnable": runnable.parse::<u64>().ok(),
                "threads": threads.parse::<u64>().ok(),
            })
        }) {
            row.insert("loadavg".into(), v);
        }
        if let Some(v) = Self::read_with(buf, stats, errors, &mut s.schedstat, |t| {
            Value::from(
                parse_schedstat(t)
                    .into_iter()
                    .map(|(_, f)| f.to_vec())
                    .collect::<Vec<_>>(),
            )
        }) {
            row.insert("schedstat".into(), v);
        }
        if let Some(v) = Self::read_with(buf, stats, errors, &mut s.meminfo, |t| {
            Value::Object(parse_key_values(t, Some(MEMINFO_KEYS)))
        }) {
            row.insert("meminfo_kb".into(), v);
        }
        if let Some(v) = Self::read_with(buf, stats, errors, &mut s.vmstat, |t| {
            Value::Object(parse_key_values(t, Some(VMSTAT_KEYS)))
        }) {
            row.insert("vmstat".into(), v);
        }
        let disks = s.disks.clone();
        if let Some(v) = Self::read_with(buf, stats, errors, &mut s.diskstats, |t| {
            Value::Object(parse_diskstats(t, &disks))
        }) {
            row.insert("diskstats".into(), v);
        }
        if let Some(v) = Self::read_with(buf, stats, errors, &mut s.net_dev, |t| {
            Value::Object(parse_net_dev(t))
        }) {
            row.insert("net_dev".into(), v);
        }
        if let Some(v) = Self::read_with(buf, stats, errors, &mut s.snmp, |t| {
            Value::Object(parse_snmp_section(t, "Tcp", TCP_KEYS))
        }) {
            row.insert("tcp".into(), v);
        }
        let mut psi = Map::new();
        for (name, source) in s.psi.iter_mut() {
            if let Some(v) =
                Self::read_with(buf, stats, errors, source, |t| Value::Object(parse_psi(t)))
            {
                psi.insert((*name).into(), v);
            }
        }
        if !psi.is_empty() {
            row.insert("psi".into(), Value::Object(psi));
        }
    }

    fn sample_cgroups(&mut self, row: &mut Map<String, Value>, errors: &mut Vec<Value>) {
        let mut out = Vec::new();
        for cg in self.cgroups.iter_mut() {
            if !cg.present {
                out.push(json!({"present": false}));
                continue;
            }
            let (buf, stats) = (&mut self.buf, &mut self.stats);
            let mut local_errors = Vec::new();
            let mut entry = Map::new();
            let number = |t: &str| Value::from(t.trim().parse::<u64>().ok());
            if let Some(v) = Self::read_with(buf, stats, &mut local_errors, &mut cg.cpu_stat, |t| {
                Value::Object(parse_key_values(t, None))
            }) {
                entry.insert("cpu_stat".into(), v);
            }
            if let Some(v) = Self::read_with(
                buf,
                stats,
                &mut local_errors,
                &mut cg.memory_current,
                number,
            ) {
                entry.insert("memory_current".into(), v);
            }
            if let Some(v) =
                Self::read_with(buf, stats, &mut local_errors, &mut cg.memory_peak, number)
            {
                entry.insert("memory_peak".into(), v);
            }
            if let Some(v) =
                Self::read_with(buf, stats, &mut local_errors, &mut cg.memory_stat, |t| {
                    Value::Object(parse_key_values(t, Some(MEMORY_STAT_KEYS)))
                })
            {
                entry.insert("memory_stat".into(), v);
            }
            if let Some(v) =
                Self::read_with(buf, stats, &mut local_errors, &mut cg.memory_events, |t| {
                    Value::Object(parse_key_values(t, None))
                })
            {
                entry.insert("memory_events".into(), v);
            }
            if let Some(v) = Self::read_with(
                buf,
                stats,
                &mut local_errors,
                &mut cg.io_stat,
                |t| json!({"aggregate": parse_io_stat(t), "by_device": parse_io_stat_by_device(t)}),
            ) {
                entry.insert("io_stat".into(), v["aggregate"].clone());
                entry.insert("io_stat_by_device".into(), v["by_device"].clone());
            }
            if let Some(v) =
                Self::read_with(buf, stats, &mut local_errors, &mut cg.pids_current, number)
            {
                entry.insert("pids_current".into(), v);
            }
            let mut psi = Map::new();
            for (name, source) in cg.psi.iter_mut() {
                if let Some(v) = Self::read_with(buf, stats, &mut local_errors, source, |t| {
                    Value::Object(parse_psi(t))
                }) {
                    psi.insert((*name).into(), v);
                }
            }
            if !psi.is_empty() {
                entry.insert("psi".into(), Value::Object(psi));
            }
            // A removed cgroup makes every kept-open kernfs file fail (ENODEV);
            // stop sampling it rather than reporting the same error forever.
            if !cg.dir.exists() {
                cg.present = false;
                local_errors.clear();
                entry.clear();
                entry.insert("present".into(), Value::from(false));
            } else {
                entry.insert("present".into(), Value::from(true));
            }
            errors.extend(local_errors);
            out.push(Value::Object(entry));
        }
        if !out.is_empty() {
            row.insert("cgroups".into(), Value::from(out));
        }
    }

    fn sample_processes(&mut self, seq: u64, now: u64) -> Value {
        let mut groups = Vec::new();
        let schedstats_enabled = schedstats_runtime_enabled();
        let mut thread_budget = self.max_thread_samples;
        for (group_index, cg) in self.cgroups.iter().enumerate() {
            let mut thread_identities = BTreeSet::new();
            let collection = collect_cgroup_processes_with(
                &cg.dir,
                MAX_CGROUP_DIRS,
                MAX_PROCESSES,
                read_cgroup_process_directory,
            );
            if collection.truncated_process_set {
                self.stats.truncated_process_sets += 1;
            }
            if collection.truncated_cgroup_dirs {
                self.stats.truncated_cgroup_traversals += 1;
            }
            self.stats.cgroup_traversal_read_errors += collection.errors.len() as u64;
            let mut processes = Vec::new();
            for pid in collection.pids {
                let base = PathBuf::from(format!("/proc/{pid}"));
                let Some(stat) = fs::read_to_string(base.join("stat"))
                    .ok()
                    .and_then(|t| parse_pid_stat(&t))
                else {
                    self.stats.vanished_processes += 1;
                    continue;
                };
                let sched = fs::read_to_string(base.join("schedstat"))
                    .ok()
                    .and_then(|t| parse_task_schedstat(&t));
                let mut process = json!({
                    "pid": pid, "ppid": stat.ppid, "start_ticks": stat.start_ticks,
                    "boot_id": self.boot_id,
                    "comm": stat.comm, "state": stat.state, "threads": stat.threads,
                    "utime": stat.utime, "stime": stat.stime,
                    "minflt": stat.minflt, "majflt": stat.majflt, "rss_pages": stat.rss_pages,
                    "leader_run_ns": sched.map(|s| s[0]), "leader_wait_ns": schedstats_enabled.then(|| sched.map(|s| s[1])).flatten(),
                    "leader_wait_counter_status": if schedstats_enabled { "ENABLED" } else { "DISABLED_OR_UNKNOWN" },
                });
                if self.sample_threads {
                    let (rows, identities, issues) = sample_threads_for_process(
                        pid,
                        &stat,
                        &mut ThreadScan {
                            boot_id: &self.boot_id,
                            selected: &self.selected_tids,
                            pinned: &mut self.pinned_tids,
                            budget: &mut thread_budget,
                            schedstats_enabled,
                            stats: &mut self.stats,
                        },
                    );
                    thread_identities.extend(identities);
                    process["tid_samples"] = json!(rows);
                    process["tid_sampling_issues"] = json!(issues);
                }
                processes.push(process);
            }
            let disappeared = if self.sample_threads {
                self.previous_threads[group_index]
                    .difference(&thread_identities)
                    .map(|identity| {
                        json!({"identity": identity.to_json(),
                        "status": "NO_LONGER_OBSERVED_EXIT_SCOPE_CHANGE_OR_SAMPLING_GAP_UNKNOWN"})
                    })
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            self.stats.thread_disappeared_between_samples += disappeared.len() as u64;
            self.previous_threads[group_index] = thread_identities;
            groups.push(json!({
                "present": cg.present, "processes": processes,
                "visited_cgroup_dirs": collection.visited_dirs,
                "truncated_cgroup_dirs": collection.truncated_cgroup_dirs,
                "truncated_process_set": collection.truncated_process_set,
                "traversal_errors": collection.errors,
                "thread_sampling": if self.sample_threads { "PARTIAL_POLLED_NOT_FULL_LIFECYCLE" } else { "DISABLED" },
                "disappeared_threads": disappeared,
            }));
        }
        self.stats.process_samples += 1;
        json!({"seq": seq, "monotonic_ns": now, "collection_end_ns": monotonic_ns(),
               "schedstats_runtime_enabled": schedstats_enabled, "cgroups": groups})
    }
}

fn schedstats_runtime_enabled() -> bool {
    fs::read_to_string("/proc/sys/kernel/sched_schedstats").map_or(false, |text| text.trim() == "1")
}

struct ThreadScan<'a> {
    boot_id: &'a str,
    selected: &'a BTreeSet<u32>,
    pinned: &'a mut BTreeMap<u32, ThreadIdentity>,
    budget: &'a mut usize,
    schedstats_enabled: bool,
    stats: &'a mut Stats,
}

fn sample_threads_for_process(
    pid: u32,
    process: &PidStat,
    scan: &mut ThreadScan<'_>,
) -> (Vec<Value>, BTreeSet<ThreadIdentity>, Vec<Value>) {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let mut rows = Vec::new();
    let mut identities = BTreeSet::new();
    let mut issues = Vec::new();
    let entries = match fs::read_dir(root.join("task")) {
        Ok(entries) => entries,
        Err(error) => {
            scan.stats.thread_read_errors += 1;
            issues
                .push(json!({"code": "THREAD_DIRECTORY_UNAVAILABLE", "detail": error.to_string()}));
            return (rows, identities, issues);
        }
    };
    for entry in entries {
        if *scan.budget == 0 {
            scan.stats.truncated_thread_samples += 1;
            issues.push(json!({"code": "THREAD_SAMPLE_LIMIT", "detail": "bounded global scan budget reached"}));
            break;
        }
        *scan.budget -= 1;
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                scan.stats.thread_read_errors += 1;
                issues.push(
                    json!({"code": "THREAD_DIRECTORY_READ_FAILED", "detail": error.to_string()}),
                );
                continue;
            }
        };
        let Some(tid) = entry.file_name().to_str().and_then(|name| name.parse::<u32>().ok()) else { continue; };
        if !scan.selected.is_empty() && !scan.selected.contains(&tid) {
            continue;
        }
        let started = monotonic_ns();
        let read_stat = |path: &Path| {
            fs::read_to_string(path)
                .ok()
                .and_then(|text| parse_pid_stat(&text))
        };
        let Some(thread) = read_stat(&entry.path().join("stat")) else {
            scan.stats.vanished_threads_during_read += 1;
            issues.push(json!({"code": "THREAD_VANISHED_DURING_READ", "tid": tid}));
            continue;
        };
        let sched = fs::read_to_string(entry.path().join("schedstat"))
            .ok()
            .and_then(|text| parse_task_schedstat(&text));
        let after = read_stat(&entry.path().join("stat"));
        let process_after = read_stat(&root.join("stat"));
        let (Some(after), Some(process_after)) = (after, process_after) else {
            scan.stats.vanished_threads_during_read += 1;
            issues.push(json!({"code": "THREAD_OR_PROCESS_VANISHED_DURING_READ", "tid": tid}));
            continue;
        };
        if !same_thread_instance(process, &process_after, &thread, &after) {
            scan.stats.thread_identity_changes += 1;
            issues.push(json!({"code": "THREAD_INSTANCE_CHANGED_DURING_READ", "tid": tid}));
            continue;
        }
        let identity = ThreadIdentity {
            boot_id: scan.boot_id.to_owned(),
            pid,
            process_start_ticks: process.start_ticks,
            tid,
            thread_start_ticks: thread.start_ticks,
        };
        if scan.selected.contains(&tid) {
            if let Some(previous) = scan.pinned.get(&tid) {
                if previous != &identity {
                    scan.stats.thread_identity_changes += 1;
                    issues.push(json!({"code": "SELECTED_TID_INSTANCE_CHANGED", "tid": tid,
                        "original_identity": previous.to_json(), "observed_identity": identity.to_json()}));
                    continue;
                }
            } else {
                scan.pinned.insert(tid, identity.clone());
            }
        }
        if sched.is_none() {
            scan.stats.thread_read_errors += 1;
            issues.push(json!({"code": "THREAD_SCHEDSTAT_UNAVAILABLE", "tid": tid}));
        }
        rows.push(json!({"identity": identity.to_json(), "comm": thread.comm, "state": thread.state,
            "utime": thread.utime, "stime": thread.stime, "run_ns": sched.map(|value| value[0]),
            "wait_ns": if scan.schedstats_enabled { sched.map(|value| value[1]) } else { None },
            "timeslices": if scan.schedstats_enabled { sched.map(|value| value[2]) } else { None },
            "wait_counter_status": if scan.schedstats_enabled { "ENABLED" } else { "DISABLED_OR_UNKNOWN" },
            "collection_start_ns": started, "collection_end_ns": monotonic_ns(),
            "lifecycle_status": "POLLED_INSTANCE_NOT_FULL_LIFECYCLE"}));
        identities.insert(identity);
    }
    (rows, identities, issues)
}

fn read_cgroup_process_directory(dir: &Path) -> CgroupProcessDirectory {
    let mut out = CgroupProcessDirectory::default();
    match fs::read_to_string(dir.join("cgroup.procs")) {
        Ok(text) => out.pids.extend(
            text.lines()
                .filter_map(|l| l.trim().parse::<u32>().ok())
                .take(MAX_PROCESSES + 1),
        ),
        Err(e) => out
            .errors
            .push(format!("{}: {e}", dir.join("cgroup.procs").display())),
    }
    match fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries {
                match entry.and_then(|e| e.file_type().map(|t| (e.path(), t))) {
                    Ok((path, kind)) if kind.is_dir() => {
                        out.children.push(path);
                        // The extra child makes truncation observable without
                        // constructing an arbitrarily large pending subtree.
                        if out.children.len() > MAX_CGROUP_DIRS {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => out.errors.push(format!("{}: {e}", dir.display())),
                }
            }
        }
        Err(e) => out.errors.push(format!("{}: {e}", dir.display())),
    }
    out
}

fn create_new(path: &Path) -> Result<BufWriter<File>> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    Ok(BufWriter::new(file))
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    let mut out = create_new(path)?;
    serde_json::to_writer_pretty(&mut out, value)?;
    out.write_all(b"\n")?;
    out.flush()?;
    out.get_ref().sync_all()?;
    Ok(())
}

fn write_line(out: &mut BufWriter<File>, value: &Value, stats: &mut Stats) -> Result<()> {
    let mut line = serde_json::to_vec(value)?;
    line.push(b'\n');
    out.write_all(&line)?;
    // One flush per sample keeps the stream usable if the sampler is killed.
    out.flush()?;
    stats.bytes_written += line.len() as u64;
    Ok(())
}

fn clock_pair() -> Value {
    json!({"monotonic_ns": monotonic_ns(), "realtime_ns": clock_ns(libc::CLOCK_REALTIME),
           "boottime_ns": clock_ns(libc::CLOCK_BOOTTIME)})
}

fn self_rusage() -> Value {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let us = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
    json!({"user_usec": us(usage.ru_utime), "system_usec": us(usage.ru_stime),
           "max_rss_kb": usage.ru_maxrss, "voluntary_ctxt": usage.ru_nvcsw,
           "involuntary_ctxt": usage.ru_nivcsw})
}

fn main() -> Result<()> {
    let mut args = Args::parse();
    if !(10..=60_000).contains(&args.interval_ms) {
        bail!("--interval-ms must be within 10..=60000");
    }
    if args.process_interval_ms != 0 && args.process_interval_ms < args.interval_ms {
        bail!("--process-interval-ms must be 0 or at least --interval-ms");
    }
    let process_interval_ns = args
        .process_interval_ms
        .checked_mul(1_000_000)
        .context("--process-interval-ms is too large")?;
    if args.max_samples == 0 {
        bail!("--max-samples must be at least 1 (READY requires a flushed sample)");
    }
    if args.sample_threads && (args.process_interval_ms == 0 || args.cgroup.is_empty()) {
        bail!("--sample-threads requires --cgroup and nonzero --process-interval-ms");
    }
    if args.max_thread_samples == 0
        || args.max_thread_samples > 65_536
        || args.thread_tid.contains(&0)
    {
        bail!("thread sampling bounds must be 1..=65536 and selected TIDs nonzero");
    }
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    if boot_id.is_empty() {
        bail!("boot_id is required for sampler process instances");
    }
    for cg in args
        .cgroup
        .iter_mut()
        .chain(args.kernel_hist_cgroup.iter_mut())
    {
        if !cg.is_absolute() || !cg.join("cgroup.procs").exists() {
            bail!("{} is not an absolute cgroup-v2 directory", cg.display());
        }
        *cg = fs::canonicalize(&cg)?;
    }
    if args.exit_with_parent {
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
    }
    install_signal_handlers()?;
    fs::create_dir(&args.output_dir)
        .with_context(|| format!("create new output directory {}", args.output_dir.display()))?;

    let mut kernel_hist = match (&args.kernel_hist_object, &args.kernel_hist_sha256) {
        (Some(object), Some(sha256)) => {
            let targets = if args.kernel_hist_cgroup.is_empty() {
                &args.cgroup
            } else {
                &args.kernel_hist_cgroup
            };
            if targets.is_empty() {
                bail!("--kernel-hist-object needs --cgroup");
            }
            if targets.iter().any(|path| !args.cgroup.contains(path)) {
                bail!("kernel-hist cgroups must also be registered with --cgroup");
            }
            let groups: Vec<String> = args
                .kernel_hist_groups
                .split(',')
                .map(|g| g.trim().to_string())
                .filter(|g| !g.is_empty())
                .collect();
            Some(khist::KernelHist::open(
                object,
                sha256,
                targets,
                khist::KernelHistOptions {
                    groups: &groups,
                    runtime_stats_requested: args.kernel_hist_runtime_stats,
                    syscall_backend: &args.kernel_hist_syscall_backend,
                    syscall_nrs: &args.kernel_hist_syscall_nr,
                    memory_backend: &args.kernel_hist_memory_backend,
                },
            )?)
        }
        _ => None,
    };
    let system = SystemSources::open();
    let cgroups: Vec<CgroupSources> = args.cgroup.iter().map(|d| CgroupSources::open(d)).collect();
    let start = clock_pair();
    let uname = {
        let mut u: libc::utsname = unsafe { std::mem::zeroed() };
        unsafe { libc::uname(&mut u) };
        unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    };
    write_json(
        &args.output_dir.join("load-meta.json"),
        &json!({
            "schema_version": SCHEMA_VERSION,
            "tool": "allox-load-sampler",
            "tool_version": env!("CARGO_PKG_VERSION"),
            "label": args.label,
            "kernel_release": uname,
            "boot_id": fs::read_to_string("/proc/sys/kernel/random/boot_id").ok().map(|v| v.trim().to_string()),
            "thread_sampling": {"enabled": args.sample_threads, "selected_tids": args.thread_tid,
                "max_thread_samples_per_process_sample": args.max_thread_samples,
                "identity": "boot_id,pid,process_start_ticks,tid,thread_start_ticks; USER_HZ tick granularity",
                "selection_binding": "explicit TIDs pin their first observed instance; reused numeric TIDs are not rebound",
                "lifecycle_coverage": "PARTIAL_POLLING; short-lived threads may never be observed; disappearance does not prove exit",
                "schedstats_runtime_enabled_at_start": schedstats_runtime_enabled()},
            "interval_ms": args.interval_ms,
            "process_interval_ms": args.process_interval_ms,
            "process_sampling_schedule": "independent CLOCK_MONOTONIC deadlines serviced on system ticks; missed process periods skipped, never rounded down to a multiple of interval_ms",
            "clk_tck": unsafe { libc::sysconf(libc::_SC_CLK_TCK) },
            "page_size": unsafe { libc::sysconf(libc::_SC_PAGESIZE) },
            "online_cpus": unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) },
            "pid": std::process::id(),
            "start_clock": start,
            "block_devices": system.disks,
            "sources": system.availability(),
            "cgroups": cgroups.iter().map(|c| c.static_limits()).collect::<Vec<_>>(),
            "units": {
                "stat.cpu*": format!("USER_HZ ticks, columns {:?}", CPU_FIELDS),
                "schedstat": "per CPU [rq_cpu_time_ns, run_delay_ns, timeslices]",
                "diskstats": "[reads, reads_merged, sectors_read, read_ms, writes, writes_merged, sectors_written, write_ms, in_flight, io_ms, weighted_io_ms]",
                "net_dev": "[rx_bytes, rx_packets, rx_errs, rx_drop, tx_bytes, tx_packets, tx_errs, tx_drop]",
                "psi": "cumulative stall microseconds",
                "process.utime/stime": "USER_HZ ticks, whole thread group",
                "process.leader_*": "thread-group leader only (from /proc/<pid>/schedstat)",
                "process.tid_samples": "per-thread cumulative utime/stime ticks, run/wait ns and timeslices; wait counters null if schedstats disabled; never sum overlap into wall time",
                "cgroup.io_stat": "legacy cross-device sum; stacked devices may double-count; prefer io_stat_by_device",
                "cgroup.io_stat_by_device": "raw counters keyed by major:minor; no cross-device aggregation",
                "collection_end_ns": "CLOCK_MONOTONIC end of non-atomic source collection, before serialization/flush",
            },
            "kernel_hist": kernel_hist.as_ref().map(|kernel| kernel.metadata()),
            "note": "Measurement side channel; not Observer evidence. Counters are raw cumulative values.",
        }),
    )?;
    let mut samples = create_new(&args.output_dir.join("load-samples.jsonl"))?;
    let mut processes = if args.process_interval_ms > 0 && !args.cgroup.is_empty() {
        Some(create_new(&args.output_dir.join("load-processes.jsonl"))?)
    } else {
        None
    };
    let mut sampler = Sampler {
        system,
        cgroups,
        buf: Vec::with_capacity(65536),
        stats: Stats::default(),
        previous_threads: vec![BTreeSet::new(); args.cgroup.len()],
        sample_threads: args.sample_threads,
        selected_tids: args.thread_tid.iter().copied().collect(),
        pinned_tids: BTreeMap::new(),
        max_thread_samples: args.max_thread_samples,
        boot_id,
    };

    let interval_ns = args.interval_ms * 1_000_000;
    let origin = monotonic_ns();
    let mut next_process_ns = origin;
    let mut tick: u64 = 0;
    let mut stop_reason = "signal";
    while !STOP.load(Ordering::SeqCst) {
        if sampler.stats.samples >= args.max_samples {
            stop_reason = "max_samples";
            break;
        }
        let scheduled = origin + tick * interval_ns;
        let before = monotonic_ns();
        let mut row = Map::new();
        let mut errors = Vec::new();
        row.insert("seq".into(), Value::from(sampler.stats.samples));
        row.insert("monotonic_ns".into(), Value::from(before));
        row.insert(
            "lateness_ns".into(),
            Value::from(before.saturating_sub(scheduled)),
        );
        sampler.sample_system(&mut row, &mut errors);
        sampler.sample_cgroups(&mut row, &mut errors);
        if let Some(k) = kernel_hist.as_ref() {
            row.insert("khist".into(), k.read());
        }
        let after = monotonic_ns();
        let cost = after - before;
        row.insert("collection_end_ns".into(), Value::from(after));
        row.insert("sample_cost_ns".into(), Value::from(cost));
        if !errors.is_empty() {
            row.insert("errors".into(), Value::from(errors));
        }
        let seq = sampler.stats.samples;
        write_line(&mut samples, &Value::Object(row), &mut sampler.stats)?;
        if let Some(out) = processes.as_mut() {
            let process_now = monotonic_ns();
            if process_interval_ns > 0 && process_now >= next_process_ns {
                let value = sampler.sample_processes(seq, process_now);
                write_line(out, &value, &mut sampler.stats)?;
                next_process_ns =
                    next_periodic_deadline(origin, monotonic_ns(), process_interval_ns);
            }
        }
        // Do not release a stopped workload until all requested output streams
        // exist and their first sample is visible to the launcher.
        if seq == 0 {
            println!("READY");
            io::stdout().flush()?;
        }
        let loop_cost = monotonic_ns() - before;
        let stats = &mut sampler.stats;
        stats.samples += 1;
        stats.total_sample_cost_ns += cost;
        stats.max_sample_cost_ns = stats.max_sample_cost_ns.max(cost);
        stats.total_loop_cost_ns += loop_cost;
        stats.max_loop_cost_ns = stats.max_loop_cost_ns.max(loop_cost);
        stats.max_lateness_ns = stats.max_lateness_ns.max(before.saturating_sub(scheduled));
        // Skip, and count, ticks that already passed instead of bursting.
        let now = monotonic_ns();
        let next = (now - origin) / interval_ns + 1;
        stats.missed_ticks += next - tick - 1;
        tick = next;
        if stats.samples >= args.max_samples {
            stop_reason = "max_samples";
            break;
        }
        sleep_until(origin + tick * interval_ns);
    }
    let kernel_final = kernel_hist.as_mut().map(|kernel| kernel.finish());
    let s = &sampler.stats;
    write_json(
        &args.output_dir.join("load-sampler-stats.json"),
        &json!({
            "schema_version": SCHEMA_VERSION,
            "stop_reason": stop_reason,
            "start_clock": start,
            "end_clock": clock_pair(),
            "samples": s.samples,
            "process_samples": s.process_samples,
            "missed_ticks": s.missed_ticks,
            "max_lateness_ns": s.max_lateness_ns,
            "mean_sample_cost_ns": if s.samples > 0 { s.total_sample_cost_ns / s.samples } else { 0 },
            "max_sample_cost_ns": s.max_sample_cost_ns,
            "total_loop_cost_ns": s.total_loop_cost_ns,
            "mean_loop_cost_ns": if s.samples > 0 { s.total_loop_cost_ns / s.samples } else { 0 },
            "max_loop_cost_ns": s.max_loop_cost_ns,
            "loop_cost_scope": "system/cgroup/kernel-hist collection, optional process scan, serialization and JSONL flush; excludes sleeping and final metadata fsync",
            "read_errors": s.read_errors,
            "vanished_processes": s.vanished_processes,
            "truncated_process_sets": s.truncated_process_sets,
            "truncated_cgroup_traversals": s.truncated_cgroup_traversals,
            "cgroup_traversal_read_errors": s.cgroup_traversal_read_errors,
            "thread_read_errors": s.thread_read_errors,
            "vanished_threads_during_read": s.vanished_threads_during_read,
            "truncated_thread_samples": s.truncated_thread_samples,
            "thread_identity_changes": s.thread_identity_changes,
            "thread_disappeared_between_samples": s.thread_disappeared_between_samples,
            "thread_sampling_status": if !args.sample_threads { "DISABLED" } else if s.thread_read_errors + s.vanished_threads_during_read + s.truncated_thread_samples + s.thread_identity_changes > 0 { "PARTIAL_POLLED_WITH_GAPS" } else { "PARTIAL_POLLED" },
            "bytes_written": s.bytes_written,
            "self_rusage": self_rusage(),
            "kernel_hist": kernel_final,
        }),
    )?;
    samples.get_ref().sync_all()?;
    if let Some(out) = processes.as_ref() {
        out.get_ref().sync_all()?;
    }
    Ok(())
}
