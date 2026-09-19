// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::capture::validate_mountinfo_line;
use crate::command::canonical_json;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "linux-state-confirmer-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create test directory");
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove test directory");
    }
}

fn limits() -> CaptureLimits {
    CaptureLimits {
        max_records: 16_384,
        max_value_bytes: 4 * 1024 * 1024,
        max_total_value_bytes: 16 * 1024 * 1024,
        deadline_ms: 15_000,
    }
}

fn sysctl_state_scope(keys: Vec<String>) -> StateScope {
    StateScope {
        protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
        sysctl: Some(SysctlScope::new(Path::new("/proc/sys"), keys).expect("sysctl scope")),
        mounts: None,
        network: None,
        modules: None,
        process_residual: None,
    }
}

fn request(id: &str, phase: SnapshotPhase) -> CaptureRequest {
    CaptureRequest {
        snapshot_id: id.to_owned(),
        phase,
    }
}

#[test]
fn network_configuration_normalization_removes_only_volatile_state() {
    let encoded = serde_json::to_string(&NetworkNormalization::ConfigurationOnlyV1).unwrap();
    assert_eq!(encoded, "\"NETWORK_CONFIGURATION_ONLY_V1\"");
    assert_eq!(
        serde_json::from_str::<NetworkNormalization>(&encoded).unwrap(),
        NetworkNormalization::ConfigurationOnlyV1
    );

    let address_before = br#"[{"ifname":"eth0","mtu":1500,"stats64":{"rx":{"bytes":1}},"addr_info":[{"local":"192.0.2.1","valid_life_time":99,"preferred_life_time":50}]}]"#;
    let address_after = br#"[{"ifname":"eth0","mtu":1500,"stats64":{"rx":{"bytes":999}},"addr_info":[{"local":"192.0.2.1","valid_life_time":1,"preferred_life_time":0}]}]"#;
    assert_eq!(
        canonical_json(
            address_before,
            "ip/address",
            NetworkNormalization::ConfigurationOnlyV1,
        )
        .unwrap(),
        canonical_json(
            address_after,
            "ip/address",
            NetworkNormalization::ConfigurationOnlyV1,
        )
        .unwrap()
    );

    let address_order_a = br#"[{"ifindex":3,"ifname":"eth1","addr_info":[]},{"ifindex":2,"ifname":"eth0","addr_info":[]}]"#;
    let address_order_b = br#"[{"ifindex":2,"ifname":"eth0","addr_info":[]},{"ifindex":3,"ifname":"eth1","addr_info":[]}]"#;
    assert_eq!(
        canonical_json(
            address_order_a,
            "ip/address",
            NetworkNormalization::ConfigurationOnlyV1,
        )
        .unwrap(),
        canonical_json(
            address_order_b,
            "ip/address",
            NetworkNormalization::ConfigurationOnlyV1,
        )
        .unwrap()
    );

    // Equal-priority route/rule insertion order can be semantic. Preserve it
    // even though this conservatively permits an occasional false positive.
    let routes_a = br#"[{"dst":"198.51.100.0/24","dev":"eth1"},{"dst":"default","dev":"eth0"}]"#;
    let routes_b = br#"[{"dst":"default","dev":"eth0"},{"dst":"198.51.100.0/24","dev":"eth1"}]"#;
    assert_ne!(
        canonical_json(
            routes_a,
            "ip/route/ipv4",
            NetworkNormalization::ConfigurationOnlyV1,
        )
        .unwrap(),
        canonical_json(
            routes_b,
            "ip/route/ipv4",
            NetworkNormalization::ConfigurationOnlyV1,
        )
        .unwrap()
    );

    let tc_before = br#"[{"kind":"fq_codel","handle":"1:","options":{"limit":10240},"bytes":1,"packets":2,"drops":3,"qlen":4},{"kind":"clsact","handle":"ffff:"}]"#;
    let tc_after = br#"[{"kind":"clsact","handle":"ffff:"},{"kind":"fq_codel","handle":"1:","options":{"limit":10240},"bytes":10,"packets":20,"drops":30,"qlen":40}]"#;
    assert_eq!(
        canonical_json(
            tc_before,
            "tc/qdisc",
            NetworkNormalization::ConfigurationOnlyV1,
        )
        .unwrap(),
        canonical_json(
            tc_after,
            "tc/qdisc",
            NetworkNormalization::ConfigurationOnlyV1,
        )
        .unwrap()
    );

    let nft_before = br#"{"nftables":[{"table":{"family":"inet","name":"filter"}},{"rule":{"family":"inet","table":"filter","handle":7,"expr":[{"counter":{"packets":1,"bytes":2}},{"quota":{"val":1000,"used":3}}]}}]}"#;
    let nft_after = br#"{"nftables":[{"table":{"family":"inet","name":"filter"}},{"rule":{"family":"inet","table":"filter","handle":91,"expr":[{"counter":{"packets":99,"bytes":88}},{"quota":{"val":1000,"used":77}}]}}]}"#;
    assert_eq!(
        canonical_json(
            nft_before,
            "nft/ruleset",
            NetworkNormalization::ConfigurationOnlyV1,
        )
        .unwrap(),
        canonical_json(
            nft_after,
            "nft/ruleset",
            NetworkNormalization::ConfigurationOnlyV1,
        )
        .unwrap()
    );

    // Unlike ip/tc object enumeration, nft list and rule/expression order is
    // semantically significant and therefore must remain committed.
    let nft_reordered = br#"{"nftables":[{"rule":{"family":"inet","table":"filter","handle":91,"expr":[{"counter":{"packets":99,"bytes":88}},{"quota":{"val":1000,"used":77}}]}},{"table":{"family":"inet","name":"filter"}}]}"#;
    assert_ne!(
        canonical_json(
            nft_after,
            "nft/ruleset",
            NetworkNormalization::ConfigurationOnlyV1,
        )
        .unwrap(),
        canonical_json(
            nft_reordered,
            "nft/ruleset",
            NetworkNormalization::ConfigurationOnlyV1,
        )
        .unwrap()
    );
}

#[test]
fn retained_namespaces_survive_anchor_pid_exit() {
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork namespace anchor failed");
    if child == 0 {
        loop {
            unsafe { libc::pause() };
        }
    }
    let pid = child as u32;
    let mount = NamespaceTarget::for_pid(pid, "mnt").expect("anchor mount namespace");
    let sysctl_targets = SysctlNamespaceTargets {
        network: NamespaceTarget::for_pid(pid, "net").expect("anchor network namespace"),
        uts: NamespaceTarget::for_pid(pid, "uts").expect("anchor UTS namespace"),
        ipc: NamespaceTarget::for_pid(pid, "ipc").expect("anchor IPC namespace"),
    };
    let scope = StateScope {
        protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
        sysctl: Some(
            SysctlScope::new(Path::new("/proc/sys"), vec!["kernel/ostype".to_owned()]).unwrap(),
        ),
        mounts: Some(MountScope {
            namespace: mount,
            evidence: ValueEvidenceMode::Sha256Only,
            limits: limits(),
        }),
        network: None,
        modules: None,
        process_residual: None,
    };
    let retained =
        RetainedNamespaces::open(&scope, Some(&sysctl_targets)).expect("retain namespace FDs");
    unsafe {
        libc::kill(child, libc::SIGKILL);
        let mut status = 0;
        assert_eq!(libc::waitpid(child, &mut status, 0), child);
    }
    assert!(!Path::new(&format!("/proc/{pid}")).exists());

    let snapshot = capture_with_retained_namespaces(
        &scope,
        &request("dead-anchor-s1", SnapshotPhase::S1),
        &retained,
    )
    .expect("capture through retained namespace FDs after PID exit");
    let mounts = snapshot.mounts.expect("retained mount snapshot");
    assert_eq!(mounts.completeness.status, CompletenessStatus::Complete);
    assert!(!mounts.records.is_empty());
    assert_eq!(
        mounts.namespace_context[0].source,
        NamespaceCaptureSource::RetainedFileDescriptor
    );
    assert!(snapshot
        .sysctl
        .unwrap()
        .namespace_context
        .iter()
        .all(|evidence| evidence.source == NamespaceCaptureSource::RetainedFileDescriptor));
}

#[test]
fn protocol_has_distinct_domain_vector() {
    assert_eq!(
        DomainKind::Sysctl.protocol_name(),
        "SYSCTL_ENDPOINT_STATE_V1"
    );
    assert_eq!(DomainKind::Mount.protocol_name(), "MOUNT_ENDPOINT_STATE_V1");
    assert_eq!(
        DomainKind::Network.protocol_name(),
        "LOCAL_NETWORK_ENDPOINT_STATE_V1"
    );
    assert_eq!(
        DomainKind::KernelModule.protocol_name(),
        "KERNEL_MODULE_ENDPOINT_STATE_V1"
    );
    assert_eq!(
        DomainKind::ProcessResidual.protocol_name(),
        "TRACKED_CGROUP_PROCESS_RESIDUAL_V1"
    );
}

#[test]
fn scope_is_closed_canonical_and_rejects_unsorted_sysctls() {
    let valid = sysctl_state_scope(vec!["kernel/ostype".to_owned()]);
    valid.validate().expect("valid explicit scope");
    assert_eq!(valid.sha256().expect("scope digest").len(), 64);

    assert!(SysctlScope::new(
        Path::new("/proc/sys"),
        vec!["kernel/z".to_owned(), "kernel/a".to_owned()]
    )
    .is_err());
    assert!(SysctlScope::new(Path::new("/proc/sys"), vec!["../escape".to_owned()]).is_err());

    let mut encoded = serde_json::to_value(&valid).expect("serialize scope");
    encoded
        .as_object_mut()
        .expect("scope object")
        .insert("unknown".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<StateScope>(encoded).is_err());
}

#[test]
fn sysctl_scope_rejects_pid_namespace_key_without_pid_namespace_helper() {
    let error = SysctlScope::new(
        Path::new("/proc/sys"),
        vec!["kernel/ns_last_pid".to_owned()],
    )
    .expect_err("PID namespace sysctl must fail closed");
    assert!(error.to_string().contains("PID-namespace scoped"));
}

#[test]
fn sysctl_scope_rejects_user_namespace_keys_without_user_namespace_helper() {
    let error = SysctlScope::new(
        Path::new("/proc/sys"),
        vec!["user/max_user_namespaces".to_owned()],
    )
    .expect_err("user namespace sysctl must fail closed");
    assert!(error.to_string().contains("user-namespace scoped"));
}

#[test]
fn resource_bounds_fail_closed() {
    let mut invalid = limits();
    invalid.max_records = 0;
    assert!(invalid.validate().is_err());
    let mut invalid = limits();
    invalid.max_value_bytes = HARD_MAX_RECORD_VALUE_BYTES + 1;
    assert!(invalid.validate().is_err());
    let mut invalid = limits();
    invalid.max_total_value_bytes = invalid.max_value_bytes - 1;
    assert!(invalid.validate().is_err());
}

#[test]
fn sysctl_capture_and_changed_endpoint_are_typed() {
    let scope = sysctl_state_scope(vec!["kernel/ostype".to_owned()]);
    let before = capture(&scope, &request("sysctl-s0", SnapshotPhase::S0)).expect("capture S0");
    assert_eq!(
        before
            .sysctl
            .as_ref()
            .expect("sysctl domain")
            .completeness
            .status,
        CompletenessStatus::Complete
    );
    let mut after = before.clone();
    after.phase = SnapshotPhase::S1;
    after.snapshot_id = "sysctl-s1".to_owned();
    after.sysctl.as_mut().expect("sysctl domain").records[0] = StateRecord::new(
        "kernel/ostype".to_owned(),
        b"synthetic-different-value\n",
        ValueEvidenceMode::BytesAndSha256,
    )
    .expect("replacement record");

    let result = compare(&before, &after).expect("compare changed sysctl");
    assert_eq!(
        result.domains.sysctl.verdict,
        StateVerdict::ChangedWithinScope
    );
    assert_eq!(
        result.domains.sysctl.endpoint_difference,
        EndpointDifferenceStatus::ObservedDifferent
    );
    assert_eq!(result.domains.sysctl.changes.len(), 1);
    assert_eq!(result.domains.mounts.verdict, StateVerdict::NotConfirmed);
}

#[test]
fn restored_or_identical_endpoint_never_claims_unchanged() {
    let scope = sysctl_state_scope(vec!["kernel/ostype".to_owned()]);
    let before = capture(&scope, &request("restored-s0", SnapshotPhase::S0)).expect("capture S0");
    let mut after = before.clone();
    after.phase = SnapshotPhase::S1;
    after.snapshot_id = "restored-s1".to_owned();
    let result = compare(&before, &after).expect("compare identical endpoint");
    assert_eq!(
        result.domains.sysctl.endpoint_difference,
        EndpointDifferenceStatus::ObservedIdentical
    );
    assert_eq!(result.domains.sysctl.verdict, StateVerdict::Inconclusive);
    assert!(result.domains.sysctl.changes.is_empty());
}

#[test]
fn mount_parser_and_live_mount_snapshot_are_bounded() {
    assert_eq!(
        validate_mountinfo_line(b"36 25 0:32 / / rw,relatime - tmpfs tmpfs rw")
            .expect("valid mountinfo"),
        36
    );
    assert!(validate_mountinfo_line(b"36 broken").is_err());
    assert!(validate_mountinfo_line(b"0 25 0:32 / / rw - tmpfs tmpfs rw").is_err());

    let scope = StateScope {
        protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
        sysctl: None,
        mounts: Some(MountScope {
            namespace: NamespaceTarget::current("mnt").expect("current mount namespace"),
            evidence: ValueEvidenceMode::BytesAndSha256,
            limits: limits(),
        }),
        network: None,
        modules: None,
        process_residual: None,
    };
    let snapshot =
        capture(&scope, &request("mount-s0", SnapshotPhase::S0)).expect("capture mounts");
    let mounts = snapshot.mounts.expect("mount domain");
    assert_eq!(mounts.completeness.status, CompletenessStatus::Complete);
    assert!(!mounts.records.is_empty());
}

#[test]
fn module_snapshot_uses_procfs_and_sysfs_sources() {
    let scope = StateScope {
        protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
        sysctl: None,
        mounts: None,
        network: None,
        modules: Some(ModuleScope {
            proc_modules_path_bytes_hex: encode_absolute_path(Path::new("/proc/modules")).unwrap(),
            sys_module_root_bytes_hex: encode_absolute_path(Path::new("/sys/module")).unwrap(),
            selection: ModuleSelection::AllLoaded,
            capture_parameters: false,
            evidence: ValueEvidenceMode::Sha256Only,
            limits: limits(),
        }),
        process_residual: None,
    };
    let snapshot =
        capture(&scope, &request("module-s0", SnapshotPhase::S0)).expect("capture modules");
    assert_eq!(
        snapshot.modules.expect("module domain").completeness.status,
        CompletenessStatus::Complete
    );
}

#[test]
fn process_capture_rejects_wrong_cgroup_identity() {
    let directory = TestDirectory::new("cgroup-id");
    fs::write(directory.0.join("cgroup.procs"), b"").expect("fake membership");
    let inode = fs::metadata(&directory.0)
        .expect("fake cgroup metadata")
        .ino();
    let scope = StateScope {
        protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
        sysctl: None,
        mounts: None,
        network: None,
        modules: None,
        process_residual: Some(ProcessResidualScope {
            cgroup_path_bytes_hex: encode_absolute_path(&directory.0).unwrap(),
            expected_cgroup_id: inode + 1,
            additional_roots: Vec::new(),
            recursive: true,
            require_cgroup2: false,
            evidence: ValueEvidenceMode::Sha256Only,
            limits: limits(),
        }),
    };
    let snapshot =
        capture(&scope, &request("process-bad-id", SnapshotPhase::S1)).expect("capture result");
    let process = snapshot.process_residual.expect("process domain");
    assert_eq!(process.completeness.status, CompletenessStatus::Incomplete);
    assert!(process
        .issues
        .iter()
        .any(|issue| issue.kind == CaptureIssueKind::IdentityMismatch));
}

#[test]
fn process_capture_recurses_into_child_cgroups() {
    let directory = TestDirectory::new("cgroup-descendant");
    fs::write(directory.0.join("cgroup.procs"), b"").expect("fake root membership");
    let child = directory.0.join("child");
    fs::create_dir(&child).expect("create fake child cgroup");
    let pid = std::process::id();
    fs::write(child.join("cgroup.procs"), format!("{pid}\n")).expect("fake child membership");
    let inode = fs::metadata(&directory.0)
        .expect("fake cgroup metadata")
        .ino();
    let scope = StateScope {
        protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
        sysctl: None,
        mounts: None,
        network: None,
        modules: None,
        process_residual: Some(ProcessResidualScope {
            cgroup_path_bytes_hex: encode_absolute_path(&directory.0).unwrap(),
            expected_cgroup_id: inode,
            additional_roots: Vec::new(),
            recursive: true,
            require_cgroup2: false,
            evidence: ValueEvidenceMode::Sha256Only,
            limits: limits(),
        }),
    };

    let snapshot = capture(&scope, &request("process-child", SnapshotPhase::S1))
        .expect("capture recursive process residual");
    let process = snapshot.process_residual.expect("process domain");
    assert!(process
        .records
        .iter()
        .any(|record| { record.key == format!("process/{}/{pid:010}", hex::encode(b"child")) }));
}

#[test]
fn process_capture_uses_thread_membership_for_threaded_cgroup_root() {
    let directory = TestDirectory::new("cgroup-threaded");
    fs::write(directory.0.join("cgroup.type"), b"threaded\n").expect("fake cgroup type");
    let task_id = std::process::id();
    fs::write(directory.0.join("cgroup.threads"), format!("{task_id}\n"))
        .expect("fake threaded membership");
    let inode = fs::metadata(&directory.0)
        .expect("fake cgroup metadata")
        .ino();
    let scope = StateScope {
        protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
        sysctl: None,
        mounts: None,
        network: None,
        modules: None,
        process_residual: Some(ProcessResidualScope {
            cgroup_path_bytes_hex: encode_absolute_path(&directory.0).unwrap(),
            expected_cgroup_id: inode,
            additional_roots: Vec::new(),
            recursive: true,
            require_cgroup2: false,
            evidence: ValueEvidenceMode::BytesAndSha256,
            limits: limits(),
        }),
    };

    let snapshot = capture(&scope, &request("threaded-root", SnapshotPhase::S1))
        .expect("capture threaded residual task");
    let process = snapshot.process_residual.expect("process domain");
    assert_eq!(process.completeness.status, CompletenessStatus::Incomplete);
    assert!(process
        .records
        .iter()
        .any(|record| record.key == format!("thread//{task_id:010}")));
    assert!(process.records.iter().any(|record| {
        record.value_bytes_hex.as_deref().map_or(false, |value| {
            hex::decode(value)
                .expect("decode threaded membership evidence")
                .starts_with(b"membership_kind=THREAD\n")
        })
    }));
}

#[test]
fn process_capture_aggregates_disjoint_roots_with_namespaced_keys() {
    let mut directories = vec![
        TestDirectory::new("multi-root-a"),
        TestDirectory::new("multi-root-b"),
    ];
    directories.sort_by(|left, right| left.0.cmp(&right.0));
    fs::write(directories[0].0.join("cgroup.procs"), b"").expect("first membership");
    let task_id = std::process::id();
    fs::write(
        directories[1].0.join("cgroup.procs"),
        format!("{task_id}\n"),
    )
    .expect("second membership");
    let first_inode = fs::metadata(&directories[0].0).unwrap().ino();
    let second_inode = fs::metadata(&directories[1].0).unwrap().ino();
    let scope = StateScope {
        protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
        sysctl: None,
        mounts: None,
        network: None,
        modules: None,
        process_residual: Some(ProcessResidualScope {
            cgroup_path_bytes_hex: encode_absolute_path(&directories[0].0).unwrap(),
            expected_cgroup_id: first_inode,
            additional_roots: vec![
                ProcessResidualRoot::new(&directories[1].0, second_inode).unwrap()
            ],
            recursive: true,
            require_cgroup2: false,
            evidence: ValueEvidenceMode::Sha256Only,
            limits: limits(),
        }),
    };

    let snapshot = capture(&scope, &request("multi-root", SnapshotPhase::S1))
        .expect("capture multi-root residual");
    let process = snapshot.process_residual.expect("process domain");
    assert!(process.source_identity_sha256.is_some());
    assert!(process.records.iter().any(|record| {
        record.key == format!("root/01/{second_inode:020}/process//{task_id:010}")
    }));
}

#[test]
fn process_multi_root_scope_rejects_overlap_duplicate_id_and_global_limit_overrun() {
    let mut overlap = synthetic_process_scope();
    let residual = overlap.process_residual.as_mut().unwrap();
    residual.additional_roots =
        vec![
            ProcessResidualRoot::new(Path::new("/sys/fs/cgroup/observer-test/child"), 43).unwrap(),
        ];
    assert!(overlap.validate().is_err());

    let mut duplicate = synthetic_process_scope();
    duplicate
        .process_residual
        .as_mut()
        .unwrap()
        .additional_roots =
        vec![ProcessResidualRoot::new(Path::new("/sys/fs/cgroup/second"), 42).unwrap()];
    assert!(duplicate.validate().is_err());

    let mut directories = vec![
        TestDirectory::new("multi-limit-a"),
        TestDirectory::new("multi-limit-b"),
    ];
    directories.sort_by(|left, right| left.0.cmp(&right.0));
    fs::write(directories[0].0.join("cgroup.procs"), b"").unwrap();
    fs::write(directories[1].0.join("cgroup.procs"), b"").unwrap();
    let mut residual_limits = limits();
    residual_limits.max_records = 1;
    let bounded = StateScope {
        protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
        sysctl: None,
        mounts: None,
        network: None,
        modules: None,
        process_residual: Some(ProcessResidualScope {
            cgroup_path_bytes_hex: encode_absolute_path(&directories[0].0).unwrap(),
            expected_cgroup_id: fs::metadata(&directories[0].0).unwrap().ino(),
            additional_roots: vec![ProcessResidualRoot::new(
                &directories[1].0,
                fs::metadata(&directories[1].0).unwrap().ino(),
            )
            .unwrap()],
            recursive: true,
            require_cgroup2: false,
            evidence: ValueEvidenceMode::Sha256Only,
            limits: residual_limits,
        }),
    };
    let snapshot = capture(&bounded, &request("multi-limit", SnapshotPhase::S1)).unwrap();
    let process = snapshot.process_residual.unwrap();
    assert_eq!(process.completeness.status, CompletenessStatus::Incomplete);
    assert!(process
        .issues
        .iter()
        .any(|issue| issue.kind == CaptureIssueKind::Limit));
}

#[test]
fn single_root_process_scope_json_remains_legacy_compatible() {
    let scope = synthetic_process_scope();
    let encoded = serde_json::to_string(&scope).unwrap();
    assert!(!encoded.contains("additional_roots"));
    let decoded: StateScope = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, scope);
}

#[test]
fn process_terminal_state_distinguishes_empty_and_nonempty() {
    let scope = synthetic_process_scope();
    let before = synthetic_process_snapshot(&scope, "process-s0", SnapshotPhase::S0, Vec::new());
    let empty =
        synthetic_process_snapshot(&scope, "process-s1-empty", SnapshotPhase::S1, Vec::new());
    let empty_result = compare(&before, &empty).expect("compare empty cgroup");
    assert_eq!(
        empty_result.domains.process_residual.terminal_state,
        TerminalState::EmptyWithinScope
    );
    assert_eq!(
        empty_result.domains.process_residual.verdict,
        StateVerdict::Inconclusive
    );

    let record = StateRecord::new(
        "process//0000000123".to_owned(),
        b"pid=123\nstart_time_ticks=456\n",
        ValueEvidenceMode::Sha256Only,
    )
    .expect("process record");
    let nonempty = synthetic_process_snapshot(
        &scope,
        "process-s1-nonempty",
        SnapshotPhase::S1,
        vec![record],
    );
    let nonempty_result = compare(&before, &nonempty).expect("compare residual cgroup");
    assert_eq!(
        nonempty_result.domains.process_residual.terminal_state,
        TerminalState::NonEmptyWithinScope
    );
    assert_eq!(
        nonempty_result.domains.process_residual.verdict,
        StateVerdict::ChangedWithinScope
    );

    let mut multi_scope = scope;
    multi_scope
        .process_residual
        .as_mut()
        .unwrap()
        .additional_roots = vec![ProcessResidualRoot {
        cgroup_path_bytes_hex: encode_absolute_path(Path::new("/sys/fs/cgroup/observer-test-z"))
            .unwrap(),
        expected_cgroup_id: 43,
    }];
    multi_scope
        .validate()
        .expect("valid synthetic multi-root scope");
    let multi_before = synthetic_process_snapshot(
        &multi_scope,
        "process-multi-s0",
        SnapshotPhase::S0,
        Vec::new(),
    );
    let multi_record = StateRecord::new(
        "root/01/00000000000000000043/thread//0000000124".to_owned(),
        b"membership_kind=THREAD\ntask_id=124\nstart_time_ticks=457\n",
        ValueEvidenceMode::Sha256Only,
    )
    .expect("multi-root thread record");
    let multi = synthetic_process_snapshot(
        &multi_scope,
        "process-s1-multi",
        SnapshotPhase::S1,
        vec![multi_record],
    );
    let multi_result = compare(&multi_before, &multi).expect("compare multi-root residual");
    assert_eq!(
        multi_result.domains.process_residual.terminal_state,
        TerminalState::NonEmptyWithinScope
    );
}

#[test]
fn process_comparison_detects_residual_in_new_child_cgroup() {
    let scope = synthetic_process_scope();
    let before = synthetic_process_snapshot(&scope, "child-s0", SnapshotPhase::S0, Vec::new());
    let record = StateRecord::new(
        format!("process/{}/0000000123", hex::encode(b"new-child")),
        b"pid=123\nstart_time_ticks=456\n",
        ValueEvidenceMode::Sha256Only,
    )
    .expect("descendant process record");
    let after = synthetic_process_snapshot(&scope, "child-s1", SnapshotPhase::S1, vec![record]);

    let result = compare(&before, &after).expect("compare new child cgroup residual");
    assert_eq!(
        result.domains.process_residual.endpoint_difference,
        EndpointDifferenceStatus::ObservedDifferent
    );
    assert_eq!(
        result.domains.process_residual.verdict,
        StateVerdict::ChangedWithinScope
    );
    assert_eq!(
        result.domains.process_residual.terminal_state,
        TerminalState::NonEmptyWithinScope
    );
    assert_eq!(result.domains.process_residual.changes.len(), 1);
    assert_eq!(
        result.domains.process_residual.changes[0].kind,
        ChangeKind::Added
    );
}

#[test]
fn network_tool_digest_mismatch_is_incomplete_not_host_fallback() {
    let tool = std::env::current_exe().expect("test ELF path");
    let actual = trusted_collector_sha256(&tool).expect("strict ELF collector identity");
    assert_ne!(actual, "00".repeat(32));
    let scope = StateScope {
        protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
        sysctl: None,
        mounts: None,
        network: Some(NetworkScope {
            namespace: NamespaceTarget::current("net").expect("current net namespace"),
            collectors: NetworkCollectors {
                addresses: true,
                routes: false,
                rules: false,
                traffic_control: false,
                nftables: false,
            },
            normalization: NetworkNormalization::ConfigurationOnlyV1,
            ip_binary_bytes_hex: encode_absolute_path(&tool).unwrap(),
            expected_ip_sha256: "00".repeat(32),
            tc_binary_bytes_hex: String::new(),
            expected_tc_sha256: String::new(),
            nft_binary_bytes_hex: String::new(),
            expected_nft_sha256: String::new(),
            tc_interfaces: Vec::new(),
            evidence: ValueEvidenceMode::Sha256Only,
            limits: limits(),
        }),
        modules: None,
        process_residual: None,
    };
    let mut snapshot =
        capture(&scope, &request("network-bad-tool", SnapshotPhase::S0)).expect("capture result");
    let network = snapshot.network.as_ref().expect("network domain");
    assert_eq!(network.completeness.status, CompletenessStatus::Incomplete);
    assert!(network
        .issues
        .iter()
        .any(|issue| issue.kind == CaptureIssueKind::ToolIdentity));
    assert!(network.records.is_empty());

    let network = snapshot.network.as_mut().expect("network domain");
    network.issues.clear();
    network.completeness = Completeness {
        status: CompletenessStatus::Complete,
        reasons: Vec::new(),
    };
    network.source_identity_sha256 = Some("11".repeat(32));
    let mut after = snapshot.clone();
    after.snapshot_id = "network-empty-forged-s1".to_owned();
    after.phase = SnapshotPhase::S1;
    assert!(compare(&snapshot, &after).is_err());
}

#[test]
fn comparison_rejects_tamper_and_scope_mismatch_and_marks_boot_mismatch() {
    let scope = sysctl_state_scope(vec!["kernel/ostype".to_owned()]);
    let before = capture(&scope, &request("strict-s0", SnapshotPhase::S0)).expect("capture S0");
    let mut after = before.clone();
    after.phase = SnapshotPhase::S1;
    after.snapshot_id = "strict-s1".to_owned();

    let mut tampered = after.clone();
    tampered.sysctl.as_mut().unwrap().records[0].value_bytes_hex = Some("00".to_owned());
    assert!(compare(&before, &tampered).is_err());

    let mut empty_complete = before.clone();
    empty_complete.sysctl.as_mut().unwrap().records.clear();
    assert!(compare(&empty_complete, &after).is_err());

    let mut missing_bytes = before.clone();
    missing_bytes.sysctl.as_mut().unwrap().records[0].value_bytes_hex = None;
    assert!(compare(&missing_bytes, &after).is_err());

    let mut missing_source_identity = before.clone();
    missing_source_identity
        .sysctl
        .as_mut()
        .unwrap()
        .source_identity_sha256 = None;
    assert!(compare(&missing_source_identity, &after).is_err());

    let mut issue_claiming_complete = before.clone();
    issue_claiming_complete
        .sysctl
        .as_mut()
        .unwrap()
        .issues
        .push(CaptureIssue {
            key: "forged".to_owned(),
            kind: CaptureIssueKind::Io,
            errno: Some(libc::EIO),
            detail: "forged capture failure".to_owned(),
        });
    assert!(compare(&issue_claiming_complete, &after).is_err());

    let mut noncanonical_issues = before.clone();
    let domain = noncanonical_issues.sysctl.as_mut().unwrap();
    domain.issues = vec![
        CaptureIssue {
            key: "z-last".to_owned(),
            kind: CaptureIssueKind::Io,
            errno: None,
            detail: "last".to_owned(),
        },
        CaptureIssue {
            key: "a-first".to_owned(),
            kind: CaptureIssueKind::Io,
            errno: None,
            detail: "first".to_owned(),
        },
    ];
    domain.completeness = Completeness {
        status: CompletenessStatus::Incomplete,
        reasons: vec!["a-first: Io".to_owned(), "z-last: Io".to_owned()],
    };
    assert!(compare(&noncanonical_issues, &after).is_err());

    let mut oversized_issue = before.clone();
    let domain = oversized_issue.sysctl.as_mut().unwrap();
    domain.issues = vec![CaptureIssue {
        key: "oversized".to_owned(),
        kind: CaptureIssueKind::Io,
        errno: None,
        detail: "x".repeat(HARD_MAX_ISSUE_DETAIL_CHARS + 1),
    }];
    domain.completeness = Completeness {
        status: CompletenessStatus::Incomplete,
        reasons: vec!["oversized: Io".to_owned()],
    };
    assert!(compare(&oversized_issue, &after).is_err());

    let other_scope = sysctl_state_scope(vec!["kernel/hostname".to_owned()]);
    let mut mismatched = after.clone();
    mismatched.scope = other_scope.clone();
    mismatched.scope_sha256 = other_scope.sha256().unwrap();
    assert!(compare(&before, &mismatched).is_err());

    let mut rebooted = after;
    rebooted.boot_id = "synthetic-other-boot".to_owned();
    let result = compare(&before, &rebooted).expect("boot mismatch is typed");
    assert_eq!(
        result.domains.sysctl.endpoint_difference,
        EndpointDifferenceStatus::Indeterminate
    );
    assert_eq!(
        result.domains.sysctl.state_completeness.status,
        CompletenessStatus::Incomplete
    );
}

#[test]
fn managed_cgroup_merge_rejects_conflicting_scope() {
    let directory = TestDirectory::new("merge");
    fs::write(directory.0.join("cgroup.procs"), b"").expect("fake membership");
    let inode = fs::metadata(&directory.0).unwrap().ino();
    let first = ProcessResidualScope {
        cgroup_path_bytes_hex: encode_absolute_path(&directory.0).unwrap(),
        expected_cgroup_id: inode,
        additional_roots: Vec::new(),
        recursive: true,
        require_cgroup2: false,
        evidence: ValueEvidenceMode::Sha256Only,
        limits: limits(),
    };
    let mut second = first.clone();
    second.recursive = false;
    let base = sysctl_state_scope(vec!["kernel/ostype".to_owned()]);
    let bound = base
        .with_process_residual(first.clone())
        .expect("bind cgroup");
    assert_eq!(bound.process_residual, Some(first));
    assert!(bound.with_process_residual(second).is_err());
}

fn synthetic_process_scope() -> StateScope {
    StateScope {
        protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
        sysctl: None,
        mounts: None,
        network: None,
        modules: None,
        process_residual: Some(ProcessResidualScope {
            cgroup_path_bytes_hex: encode_absolute_path(Path::new("/sys/fs/cgroup/observer-test"))
                .unwrap(),
            expected_cgroup_id: 42,
            additional_roots: Vec::new(),
            recursive: true,
            require_cgroup2: true,
            evidence: ValueEvidenceMode::Sha256Only,
            limits: limits(),
        }),
    }
}

fn synthetic_process_snapshot(
    scope: &StateScope,
    id: &str,
    phase: SnapshotPhase,
    records: Vec<StateRecord>,
) -> StateSnapshot {
    StateSnapshot {
        protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
        snapshot_id: id.to_owned(),
        phase,
        captured_unix_ns: 1,
        boot_id: "synthetic-boot".to_owned(),
        scope: scope.clone(),
        scope_sha256: scope.sha256().unwrap(),
        sysctl: None,
        mounts: None,
        network: None,
        modules: None,
        process_residual: Some(DomainSnapshot {
            domain: DomainKind::ProcessResidual,
            namespace_inode: None,
            namespace_context: Vec::new(),
            source_identity_sha256: Some("11".repeat(32)),
            records,
            completeness: Completeness {
                status: CompletenessStatus::Complete,
                reasons: Vec::new(),
            },
            issues: Vec::new(),
        }),
    }
}

#[test]
fn generic_comparison_binds_all_recovery_phase_pairs() {
    let scope = synthetic_process_scope();

    for (index, (before_phase, after_phase)) in [
        (SnapshotPhase::A, SnapshotPhase::B),
        (SnapshotPhase::B, SnapshotPhase::C),
        (SnapshotPhase::A, SnapshotPhase::C),
    ]
    .into_iter()
    .enumerate()
    {
        let before = synthetic_process_snapshot(
            &scope,
            &format!("phase-before-{index}"),
            before_phase,
            Vec::new(),
        );
        let after = synthetic_process_snapshot(
            &scope,
            &format!("phase-after-{index}"),
            after_phase,
            Vec::new(),
        );

        let comparison = compare_phases(&before, &after, before_phase, after_phase)
            .expect("compare recovery phase pair");
        assert_eq!(comparison.s0_snapshot_id, before.snapshot_id);
        assert_eq!(comparison.s1_snapshot_id, after.snapshot_id);
    }
}

#[test]
fn generic_comparison_rejects_same_or_misbound_phases() {
    let scope = synthetic_process_scope();
    let before = synthetic_process_snapshot(&scope, "invalid-before", SnapshotPhase::A, Vec::new());
    let after = synthetic_process_snapshot(&scope, "invalid-after", SnapshotPhase::B, Vec::new());

    assert!(compare_phases(&before, &after, SnapshotPhase::A, SnapshotPhase::A,).is_err());
    assert!(compare_phases(&before, &after, SnapshotPhase::B, SnapshotPhase::C,).is_err());
}
