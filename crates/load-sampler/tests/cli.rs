// SPDX-License-Identifier: GPL-2.0-only
//! Read-only sampler smoke tests. No BPF loading or cgroup mutation is needed.
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "allox-sampler-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn ready_follows_first_flushed_samples_and_identity_metadata() {
    let scratch = Scratch::new("readiness");
    let out = scratch.0.join("output");
    // A directory fixture exercises the reader without moving any process or
    // claiming that the synthetic directory is a real kernel cgroup.
    let group = scratch.0.join("group-fixture");
    fs::create_dir(&group).unwrap();
    fs::write(
        group.join("cgroup.procs"),
        format!("{}\n", std::process::id()),
    )
    .unwrap();
    fs::write(group.join("io.stat"), "8:0 rbytes=7\n253:0 rbytes=9\n").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_allox-load-sampler"))
        .arg("--output-dir")
        .arg(&out)
        .arg("--interval-ms")
        .arg("10")
        .arg("--process-interval-ms")
        .arg("10")
        .arg("--max-samples")
        .arg("2")
        .arg("--cgroup")
        .arg(&group)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line, "READY\n");
    let meta: Value =
        serde_json::from_slice(&fs::read(out.join("load-meta.json")).unwrap()).unwrap();
    assert!(meta["boot_id"].as_str().map_or(false, |s| !s.is_empty()));
    let identity = fs::metadata(&group).unwrap();
    assert_eq!(meta["cgroups"][0]["inode"], identity.ino());
    assert_eq!(meta["cgroups"][0]["device"], identity.dev());
    let first = |name| -> Value {
        let text = fs::read_to_string(out.join(name)).unwrap();
        serde_json::from_str(text.lines().next().unwrap()).unwrap()
    };
    let sample = first("load-samples.jsonl");
    let processes = first("load-processes.jsonl");
    assert_eq!(sample["seq"], 0);
    assert!(
        sample["collection_end_ns"].as_u64().unwrap() >= sample["monotonic_ns"].as_u64().unwrap()
    );
    assert_eq!(
        sample["cgroups"][0]["io_stat_by_device"]["8:0"]["rbytes"],
        7
    );
    assert_eq!(
        sample["cgroups"][0]["io_stat_by_device"]["253:0"]["rbytes"],
        9
    );
    assert_eq!(sample["cgroups"][0]["io_stat"]["rbytes"], 16);
    assert_eq!(processes["cgroups"][0]["truncated_cgroup_dirs"], false);
    assert_eq!(processes["cgroups"][0]["truncated_process_set"], false);
    assert!(
        processes["collection_end_ns"].as_u64().unwrap()
            >= processes["monotonic_ns"].as_u64().unwrap()
    );
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stats: Value =
        serde_json::from_slice(&fs::read(out.join("load-sampler-stats.json")).unwrap()).unwrap();
    assert_eq!(stats["samples"], 2);
    assert_eq!(stats["stop_reason"], "max_samples");
    assert!(
        stats["mean_loop_cost_ns"].as_u64().unwrap()
            >= stats["mean_sample_cost_ns"].as_u64().unwrap()
    );
    assert_eq!(stats["truncated_cgroup_traversals"], 0);
}

#[test]
fn zero_samples_cannot_emit_ready_or_create_output() {
    let scratch = Scratch::new("zero");
    let out = scratch.0.join("output");
    let result = Command::new(env!("CARGO_BIN_EXE_allox-load-sampler"))
        .arg("--output-dir")
        .arg(&out)
        .arg("--max-samples")
        .arg("0")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(!out.exists());
    assert!(String::from_utf8_lossy(&result.stderr).contains("--max-samples must be at least 1"));
}

#[test]
fn global_runtime_stats_need_explicit_kernel_hist_object() {
    let scratch = Scratch::new("stats-opt-in");
    let out = scratch.0.join("output");
    let result = Command::new(env!("CARGO_BIN_EXE_allox-load-sampler"))
        .arg("--output-dir")
        .arg(&out)
        .arg("--kernel-hist-runtime-stats")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!out.exists());
    assert!(String::from_utf8_lossy(&result.stderr).contains("--kernel-hist-object"));
}

#[test]
fn optional_thread_sampling_binds_boot_process_and_thread_instances() {
    let scratch = Scratch::new("threads");
    let out = scratch.0.join("output");
    let group = scratch.0.join("group");
    fs::create_dir(&group).unwrap();
    fs::write(
        group.join("cgroup.procs"),
        format!("{}\n", std::process::id()),
    )
    .unwrap();
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
    let result = Command::new(env!("CARGO_BIN_EXE_allox-load-sampler"))
        .arg("--output-dir")
        .arg(&out)
        .arg("--cgroup")
        .arg(&group)
        .args(["--sample-threads", "--thread-tid"])
        .arg(tid.to_string())
        .args([
            "--max-samples",
            "3",
            "--interval-ms",
            "10",
            "--process-interval-ms",
            "10",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let meta: Value =
        serde_json::from_slice(&fs::read(out.join("load-meta.json")).unwrap()).unwrap();
    let samples = fs::read_to_string(out.join("load-processes.jsonl")).unwrap();
    for line in samples.lines() {
        let sample: Value = serde_json::from_str(line).unwrap();
        let threads = sample["cgroups"][0]["processes"][0]["tid_samples"]
            .as_array()
            .unwrap();
        assert_eq!(threads.len(), 1);
        let identity = &threads[0]["identity"];
        assert_eq!(identity["boot_id"], meta["boot_id"]);
        assert_eq!(identity["pid"], std::process::id());
        assert_eq!(identity["tid"], tid);
        assert!(identity["process_start_ticks"].as_u64().unwrap() > 0);
        assert!(identity["thread_start_ticks"].as_u64().unwrap() > 0);
        assert_eq!(
            threads[0]["lifecycle_status"],
            "POLLED_INSTANCE_NOT_FULL_LIFECYCLE"
        );
        if sample["schedstats_runtime_enabled"] == false {
            assert!(threads[0]["wait_ns"].is_null());
        }
    }
    let stats: Value =
        serde_json::from_slice(&fs::read(out.join("load-sampler-stats.json")).unwrap()).unwrap();
    assert_eq!(stats["thread_sampling_status"], "PARTIAL_POLLED");
    assert_eq!(stats["thread_identity_changes"], 0);
}

#[test]
fn thread_scan_truncation_is_explicit_and_disabled_process_sampling_is_rejected() {
    let scratch = Scratch::new("thread-limit");
    let group = scratch.0.join("group");
    fs::create_dir(&group).unwrap();
    fs::write(
        group.join("cgroup.procs"),
        format!("{}\n", std::process::id()),
    )
    .unwrap();
    let out = scratch.0.join("truncated");
    let result = Command::new(env!("CARGO_BIN_EXE_allox-load-sampler"))
        .arg("--output-dir")
        .arg(&out)
        .arg("--cgroup")
        .arg(&group)
        .args([
            "--sample-threads",
            "--max-thread-samples",
            "1",
            "--max-samples",
            "1",
            "--interval-ms",
            "10",
            "--process-interval-ms",
            "10",
        ])
        .output()
        .unwrap();
    assert!(result.status.success());
    let stats: Value =
        serde_json::from_slice(&fs::read(out.join("load-sampler-stats.json")).unwrap()).unwrap();
    assert!(stats["truncated_thread_samples"].as_u64().unwrap() > 0);
    assert_eq!(stats["thread_sampling_status"], "PARTIAL_POLLED_WITH_GAPS");
    let rejected = scratch.0.join("rejected");
    let result = Command::new(env!("CARGO_BIN_EXE_allox-load-sampler"))
        .arg("--output-dir")
        .arg(&rejected)
        .arg("--cgroup")
        .arg(&group)
        .args(["--sample-threads", "--process-interval-ms", "0"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!rejected.exists());
}
