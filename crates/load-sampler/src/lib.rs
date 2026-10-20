// SPDX-License-Identifier: GPL-2.0-only
//! Pure parsers for the `/proc` and cgroup-v2 text files read by the load
//! sampler. Every value is kept as the kernel's cumulative counter or gauge;
//! rates and percentages are derived offline so they can be recomputed.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

pub mod khist;

/// Advance a periodic deadline strictly past `now`, skipping missed periods
/// without a burst. Caller must supply a nonzero interval in nanoseconds.
pub fn next_periodic_deadline(origin_ns: u64, now_ns: u64, interval_ns: u64) -> u64 {
    let next = (now_ns.saturating_sub(origin_ns) / interval_ns).saturating_add(1);
    origin_ns.saturating_add(next.saturating_mul(interval_ns))
}

/// Column order of `/proc/stat` CPU lines, in USER_HZ ticks.
pub const CPU_FIELDS: [&str; 8] = [
    "user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal",
];

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ProcStat {
    pub total: Vec<u64>,
    pub per_cpu: Vec<(u32, Vec<u64>)>,
    pub ctxt: Option<u64>,
    pub processes: Option<u64>,
    pub procs_running: Option<u64>,
    pub procs_blocked: Option<u64>,
    pub intr_total: Option<u64>,
}

fn numbers(fields: &[&str]) -> Vec<u64> {
    fields.iter().map(|f| f.parse().unwrap_or(0)).collect()
}

pub fn parse_proc_stat(text: &str) -> ProcStat {
    let mut out = ProcStat::default();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some((&key, rest)) = fields.split_first() else {
            continue;
        };
        let first = rest.first().and_then(|v| v.parse().ok());
        match key {
            "cpu" => out.total = numbers(&rest[..rest.len().min(CPU_FIELDS.len())]),
            "ctxt" => out.ctxt = first,
            "processes" => out.processes = first,
            "procs_running" => out.procs_running = first,
            "procs_blocked" => out.procs_blocked = first,
            "intr" => out.intr_total = first,
            _ => {
                if let Some(index) = key.strip_prefix("cpu").and_then(|v| v.parse().ok()) {
                    out.per_cpu
                        .push((index, numbers(&rest[..rest.len().min(CPU_FIELDS.len())])));
                }
            }
        }
    }
    out
}

/// `key value` lines (vmstat, cpu.stat, memory.stat, memory.events) and
/// `Key:   value kB` lines (meminfo). `keep` filters by exact name or by a
/// trailing-`*` prefix; `None` keeps every numeric line.
pub fn parse_key_values(text: &str, keep: Option<&[&str]>) -> Map<String, Value> {
    let mut out = Map::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(key), Some(value)) = (fields.next(), fields.next()) else {
            continue;
        };
        let key = key.trim_end_matches(':');
        let Ok(value) = value.parse::<u64>() else {
            continue;
        };
        let wanted = keep.map_or(true, |keep| {
            keep.iter().any(|k| match k.strip_suffix('*') {
                Some(prefix) => key.starts_with(prefix),
                None => *k == key,
            })
        });
        if wanted {
            out.insert(key.to_string(), Value::from(value));
        }
    }
    out
}

/// Per-CPU `rq_cpu_time`, `run_delay` (both ns) and timeslice count from
/// `/proc/schedstat` (fields 7..=9 of each `cpuN` line).
pub fn parse_schedstat(text: &str) -> Vec<(u32, [u64; 3])> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(index) = fields
            .first()
            .and_then(|f| f.strip_prefix("cpu"))
            .and_then(|f| f.parse().ok())
        else {
            continue;
        };
        if fields.len() >= 10 {
            let n = |i: usize| fields[i].parse().unwrap_or(0);
            out.push((index, [n(7), n(8), n(9)]));
        }
    }
    out
}

/// `/proc/diskstats` fields after the device name: reads, reads merged,
/// sectors read, read ms, writes, writes merged, sectors written, write ms,
/// in flight, io ms, weighted io ms. Only `devices` are kept.
pub fn parse_diskstats(text: &str, devices: &[String]) -> Map<String, Value> {
    let mut out = Map::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 14 && devices.iter().any(|d| d == fields[2]) {
            out.insert(fields[2].to_string(), Value::from(numbers(&fields[3..14])));
        }
    }
    out
}

/// `/proc/net/dev`: rx bytes, rx packets, rx errs, rx drop, tx bytes,
/// tx packets, tx errs, tx drop per interface.
pub fn parse_net_dev(text: &str) -> Map<String, Value> {
    let mut out = Map::new();
    for line in text.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let f = numbers(&rest.split_whitespace().collect::<Vec<_>>());
        if f.len() >= 12 {
            let picked = [f[0], f[1], f[2], f[3], f[8], f[9], f[10], f[11]];
            out.insert(name.trim().to_string(), Value::from(picked.to_vec()));
        }
    }
    out
}

/// One protocol section of `/proc/net/snmp` (a header line then a value line).
pub fn parse_snmp_section(text: &str, section: &str, keep: &[&str]) -> Map<String, Value> {
    let prefix = format!("{section}:");
    let lines: Vec<&str> = text.lines().filter(|l| l.starts_with(&prefix)).collect();
    let mut out = Map::new();
    if let [header, values, ..] = lines.as_slice() {
        for (key, value) in header
            .split_whitespace()
            .zip(values.split_whitespace())
            .skip(1)
        {
            if keep.contains(&key) {
                if let Ok(value) = value.parse::<i64>() {
                    out.insert(key.to_string(), Value::from(value));
                }
            }
        }
    }
    out
}

/// PSI `some`/`full` cumulative stall totals in microseconds.
pub fn parse_psi(text: &str) -> Map<String, Value> {
    let mut out = Map::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(kind) = fields.next() else { continue };
        if let Some(total) = fields.find_map(|f| f.strip_prefix("total=")) {
            if let Ok(total) = total.parse::<u64>() {
                out.insert(format!("{kind}_total_us"), Value::from(total));
            }
        }
    }
    out
}

/// Legacy cgroup `io.stat` aggregate, retained for existing readers. Stacked
/// devices can account the same I/O more than once; prefer `parse_io_stat_by_device`.
pub fn parse_io_stat(text: &str) -> Map<String, Value> {
    let mut sums: Vec<(String, u64)> = Vec::new();
    for line in text.lines() {
        for pair in line.split_whitespace().skip(1) {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            let Ok(value) = value.parse::<u64>() else {
                continue;
            };
            match sums.iter_mut().find(|(k, _)| k == key) {
                Some((_, sum)) => *sum += value,
                None => sums.push((key.to_string(), value)),
            }
        }
    }
    sums.into_iter().map(|(k, v)| (k, Value::from(v))).collect()
}

/// Raw cgroup `io.stat` counters, keyed by kernel major:minor device identity.
/// Deliberately does not combine devices: partitions and device-mapper layers
/// need an explicit topology choice before any offline aggregation.
pub fn parse_io_stat_by_device(text: &str) -> Map<String, Value> {
    let mut out = Map::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(device) = fields.next() else { continue };
        let Some((major, minor)) = device.split_once(':') else { continue };
        if major.parse::<u32>().is_err() || minor.parse::<u32>().is_err() {
            continue;
        }
        let mut counters = Map::new();
        for pair in fields {
            let Some((name, value)) = pair.split_once('=') else { continue };
            if let Ok(value) = value.parse::<u64>() {
                counters.insert(name.to_string(), Value::from(value));
            }
        }
        out.insert(device.to_string(), Value::Object(counters));
    }
    out
}

/// A single cgroup directory read. Errors are retained separately from
/// cardinality truncation so an unreadable subtree is never reported complete.
#[derive(Default)]
pub struct CgroupProcessDirectory {
    pub pids: Vec<u32>,
    pub children: Vec<PathBuf>,
    pub errors: Vec<String>,
}

#[derive(Default, Debug)]
pub struct CgroupProcessCollection {
    pub pids: BTreeSet<u32>,
    pub visited_dirs: usize,
    pub truncated_cgroup_dirs: bool,
    pub truncated_process_set: bool,
    pub errors: Vec<String>,
}

/// Bounded traversal with an injectable directory reader for deterministic
/// tests. Pending directory and PID storage are bounded independently.
pub fn collect_cgroup_processes_with<F>(
    root: &Path,
    max_dirs: usize,
    max_processes: usize,
    mut read: F,
) -> CgroupProcessCollection
where
    F: FnMut(&Path) -> CgroupProcessDirectory,
{
    let mut out = CgroupProcessCollection::default();
    if max_dirs == 0 {
        out.truncated_cgroup_dirs = true;
        return out;
    }
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        out.visited_dirs += 1;
        let entry = read(&dir);
        out.errors.extend(entry.errors);
        for pid in entry.pids {
            if out.pids.len() < max_processes || out.pids.contains(&pid) {
                out.pids.insert(pid);
            } else {
                out.truncated_process_set = true;
            }
        }
        for child in entry.children {
            if out.visited_dirs + pending.len() < max_dirs {
                pending.push(child);
            } else {
                out.truncated_cgroup_dirs = true;
            }
        }
    }
    out
}

#[derive(Debug, PartialEq, Eq)]
pub struct PidStat {
    pub comm: String,
    pub state: String,
    pub ppid: u64,
    pub minflt: u64,
    pub majflt: u64,
    pub utime: u64,
    pub stime: u64,
    pub threads: u64,
    pub start_ticks: u64,
    pub rss_pages: u64,
}

/// Polling identity: includes both process and thread birth times. Tick
/// granularity is explicit; this is not kernel-event lifecycle evidence.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ThreadIdentity {
    pub boot_id: String,
    pub pid: u32,
    pub process_start_ticks: u64,
    pub tid: u32,
    pub thread_start_ticks: u64,
}

impl ThreadIdentity {
    pub fn to_json(&self) -> Value {
        serde_json::json!({"boot_id": self.boot_id, "pid": self.pid,
            "process_start_ticks": self.process_start_ticks, "tid": self.tid,
            "thread_start_ticks": self.thread_start_ticks,
            "authority": "PROCFS_STARTTIME_TICKS_NON_ATOMIC_POLL"})
    }
}

/// Refuse to correlate counters across a PID/TID instance replacement.
pub fn same_thread_instance(
    process_before: &PidStat,
    process_after: &PidStat,
    thread_before: &PidStat,
    thread_after: &PidStat,
) -> bool {
    process_before.start_ticks == process_after.start_ticks
        && thread_before.start_ticks == thread_after.start_ticks
}

/// `/proc/<pid>/stat`; `comm` may contain spaces and parentheses, so fields
/// are split after the last `)`.
pub fn parse_pid_stat(text: &str) -> Option<PidStat> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    let rest: Vec<&str> = text.get(close + 1..)?.split_whitespace().collect();
    // rest[0] is field 3 (state); field N is rest[N - 3].
    let n = |field: usize| rest.get(field - 3).and_then(|v| v.parse().ok());
    Some(PidStat {
        comm: text.get(open + 1..close)?.to_string(),
        state: rest.first()?.to_string(),
        ppid: n(4)?,
        minflt: n(10)?,
        majflt: n(12)?,
        utime: n(14)?,
        stime: n(15)?,
        threads: n(20)?,
        start_ticks: n(22)?,
        rss_pages: n(24)?,
    })
}

/// `/proc/<pid>/schedstat`: on-CPU ns, runqueue wait ns, timeslices.
pub fn parse_task_schedstat(text: &str) -> Option<[u64; 3]> {
    let f: Vec<u64> = text
        .split_whitespace()
        .map(|v| v.parse().ok())
        .collect::<Option<_>>()?;
    (f.len() == 3).then(|| [f[0], f[1], f[2]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_periods_skip_missed_deadlines_without_rounding_down() {
        // 333 ns system ticks and a 500 ns process period must not become a
        // process scan on every 333 ns tick due to integer division.
        let mut deadline = 0;
        let mut collected = Vec::new();
        for now in [0, 333, 666, 999, 1332, 1665] {
            if now >= deadline {
                collected.push(now);
                deadline = next_periodic_deadline(0, now, 500);
            }
        }
        assert_eq!(collected, vec![0, 666, 1332, 1665]);
        assert_eq!(next_periodic_deadline(100, 1600, 500), 2100);
        assert_eq!(next_periodic_deadline(100, 5000, 500), 5100);
    }

    #[test]
    fn proc_stat_totals_and_per_cpu() {
        let text = "cpu  10 1 20 300 4 5 6 7 0 0\ncpu0 5 0 10 150 2 2 3 3 0 0\n\
                    cpu1 5 1 10 150 2 3 3 4 0 0\nintr 999 1 2\nctxt 1234\nbtime 1\n\
                    processes 77\nprocs_running 3\nprocs_blocked 1\n";
        let s = parse_proc_stat(text);
        assert_eq!(s.total, vec![10, 1, 20, 300, 4, 5, 6, 7]);
        assert_eq!(s.per_cpu.len(), 2);
        assert_eq!(s.per_cpu[1], (1, vec![5, 1, 10, 150, 2, 3, 3, 4]));
        assert_eq!(s.ctxt, Some(1234));
        assert_eq!(s.processes, Some(77));
        assert_eq!(s.procs_running, Some(3));
        assert_eq!(s.procs_blocked, Some(1));
        assert_eq!(s.intr_total, Some(999));
    }

    #[test]
    fn key_values_with_filter_and_meminfo_units() {
        let meminfo = "MemTotal:       12000 kB\nMemFree:  500 kB\nHugePages_Total: 0\n";
        let m = parse_key_values(meminfo, Some(&["MemTotal", "MemFree"]));
        assert_eq!(m["MemTotal"], 12000);
        assert_eq!(m["MemFree"], 500);
        assert!(!m.contains_key("HugePages_Total"));
        let vm = "pgfault 10\npgmajfault 2\npgscan_kswapd 3\npgscan_direct 4\nnr_free_pages 9\n";
        let v = parse_key_values(vm, Some(&["pgfault", "pgmajfault", "pgscan*"]));
        assert_eq!(v.len(), 4);
        assert!(!v.contains_key("nr_free_pages"));
        assert_eq!(
            parse_key_values("usage_usec 5\nnr_throttled 0\n", None).len(),
            2
        );
    }

    #[test]
    fn schedstat_v17_cpu_lines() {
        let text = "version 17\ntimestamp 4295\ncpu0 0 0 0 0 0 0 111 222 333\n\
                    domain0 MC 0f 1 2 3\ncpu1 0 0 0 0 0 0 444 555 666\n";
        assert_eq!(
            parse_schedstat(text),
            vec![(0, [111, 222, 333]), (1, [444, 555, 666])]
        );
    }

    #[test]
    fn diskstats_selects_whole_devices() {
        let text = "   8       0 sda 1 2 3 4 5 6 7 8 9 10 11 0 0 0 0 0 0\n\
                       8       1 sda1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0\n";
        let d = parse_diskstats(text, &["sda".to_string()]);
        assert_eq!(d.len(), 1);
        assert_eq!(
            d["sda"],
            serde_json::json!([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
        );
    }

    #[test]
    fn net_dev_and_snmp() {
        let dev = "Inter-|   Receive\n face |bytes\n  eth0: 100 2 0 0 0 0 0 0 300 4 0 1 0 0 0 0\n";
        assert_eq!(
            parse_net_dev(dev)["eth0"],
            serde_json::json!([100, 2, 0, 0, 300, 4, 0, 1])
        );
        let snmp = "Ip: Forwarding DefaultTTL\nIp: 1 64\nTcp: RtoAlgorithm ActiveOpens RetransSegs CurrEstab\n\
                    Tcp: 1 12 3 -1\n";
        let t = parse_snmp_section(snmp, "Tcp", &["ActiveOpens", "RetransSegs", "CurrEstab"]);
        assert_eq!(t["ActiveOpens"], 12);
        assert_eq!(t["RetransSegs"], 3);
        assert_eq!(t["CurrEstab"], -1);
    }

    #[test]
    fn psi_and_io_stat() {
        let psi = "some avg10=1.00 avg60=0.50 avg300=0.10 total=12345\n\
                   full avg10=0.00 avg60=0.00 avg300=0.00 total=67\n";
        let p = parse_psi(psi);
        assert_eq!(p["some_total_us"], 12345);
        assert_eq!(p["full_total_us"], 67);
        let io = "8:0 rbytes=10 wbytes=20 rios=1 wios=2 dbytes=0 dios=0\n\
                  253:0 rbytes=5 wbytes=5 rios=1 wios=1 dbytes=0 dios=0\n";
        let i = parse_io_stat(io);
        assert_eq!(i["rbytes"], 15);
        assert_eq!(i["wios"], 3);
        let by_device = parse_io_stat_by_device(io);
        assert_eq!(by_device["8:0"]["rbytes"], 10);
        assert_eq!(by_device["253:0"]["rbytes"], 5);
        assert_eq!(by_device.len(), 2);
        assert!(parse_io_stat_by_device("invalid rbytes=5\n8:x rbytes=7").is_empty());
        assert_eq!(
            parse_io_stat_by_device("8:0 rbytes=bad wbytes=7")["8:0"]["wbytes"],
            7
        );
    }

    #[test]
    fn cgroup_traversal_and_process_caps_are_reported_separately() {
        let root = Path::new("/group");
        let read = |dir: &Path| CgroupProcessDirectory {
            pids: if dir == root { vec![1, 2] } else { vec![2, 3] },
            children: if dir == root {
                vec![root.join("a"), root.join("b")]
            } else {
                vec![]
            },
            errors: vec![],
        };
        let dirs_limited = collect_cgroup_processes_with(root, 1, 10, read);
        assert_eq!(dirs_limited.visited_dirs, 1);
        assert!(dirs_limited.truncated_cgroup_dirs);
        assert!(!dirs_limited.truncated_process_set);
        let pids_limited = collect_cgroup_processes_with(root, 3, 2, read);
        assert_eq!(pids_limited.visited_dirs, 3);
        assert!(!pids_limited.truncated_cgroup_dirs);
        assert!(pids_limited.truncated_process_set);
        assert_eq!(pids_limited.pids.len(), 2);
        let complete = collect_cgroup_processes_with(root, 3, 3, read);
        assert!(!complete.truncated_cgroup_dirs);
        assert!(!complete.truncated_process_set);
        assert_eq!(complete.pids.len(), 3);
    }

    #[test]
    fn cgroup_read_errors_are_not_truncation() {
        let got =
            collect_cgroup_processes_with(Path::new("/group"), 3, 3, |_| CgroupProcessDirectory {
                errors: vec!["permission denied".into()],
                ..CgroupProcessDirectory::default()
            });
        assert_eq!(got.errors.len(), 1);
        assert!(!got.truncated_cgroup_dirs);
        assert!(!got.truncated_process_set);
    }

    #[test]
    fn pid_stat_with_hostile_comm() {
        let text = "42 (a) b (c)) S 7 42 42 0 -1 4194304 100 0 3 0 50 25 0 0 20 0 \
                    4 0 9999 1000000 256 18446744073709551615";
        let s = parse_pid_stat(text).unwrap();
        assert_eq!(s.comm, "a) b (c)");
        assert_eq!(s.state, "S");
        assert_eq!(s.ppid, 7);
        assert_eq!(s.minflt, 100);
        assert_eq!(s.majflt, 3);
        assert_eq!(s.utime, 50);
        assert_eq!(s.stime, 25);
        assert_eq!(s.threads, 4);
        assert_eq!(s.start_ticks, 9999);
        assert_eq!(s.rss_pages, 256);
        assert_eq!(parse_task_schedstat("10 20 30\n"), Some([10, 20, 30]));
        assert_eq!(parse_task_schedstat("10 x 30\n"), None);
    }

    #[test]
    fn thread_identity_requires_process_and_thread_births() {
        let make = |ticks| PidStat {
            comm: "worker".into(),
            state: "R".into(),
            ppid: 1,
            minflt: 0,
            majflt: 0,
            utime: 0,
            stime: 0,
            threads: 2,
            start_ticks: ticks,
            rss_pages: 0,
        };
        assert!(same_thread_instance(
            &make(10),
            &make(10),
            &make(20),
            &make(20)
        ));
        assert!(!same_thread_instance(
            &make(10),
            &make(11),
            &make(20),
            &make(20)
        ));
        assert!(!same_thread_instance(
            &make(10),
            &make(10),
            &make(20),
            &make(21)
        ));
        let first = ThreadIdentity {
            boot_id: "boot-a".into(),
            pid: 11,
            process_start_ticks: 10,
            tid: 12,
            thread_start_ticks: 20,
        };
        let mut reused = first.clone();
        reused.thread_start_ticks += 1;
        assert_ne!(first, reused);
        reused = first.clone();
        reused.boot_id = "boot-b".into();
        assert_ne!(first, reused);
        assert_eq!(first.to_json()["thread_start_ticks"], 20);
    }
}
