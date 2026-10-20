// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use sha2::{Digest, Sha256};
use std::ffi::{CString, OsString};
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{symlink, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(label: &str) -> Self {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "filesystem-confirmer-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create private filesystem confirmer test directory");
        Self { path }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).expect("remove private filesystem confirmer test directory");
    }
}

fn default_scope(root: &Path) -> FilesystemScope {
    FilesystemScope::new(
        vec![root.to_owned()],
        FilesystemCapturePolicy::default(),
        FilesystemCaptureLimits::default(),
    )
    .expect("valid filesystem scope")
}

fn snapshot(scope: &FilesystemScope, id: &str, phase: SnapshotPhase) -> FilesystemSnapshot {
    capture(
        scope,
        &CaptureRequest {
            snapshot_id: id.to_owned(),
            phase,
        },
    )
    .expect("capture filesystem snapshot")
}

fn established_contract(
    scope: &FilesystemScope,
    before: &FilesystemSnapshot,
    after: &FilesystemSnapshot,
) -> ActorQuiescenceContract {
    ActorQuiescenceContract {
        protocol_version: FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION,
        contract_id: "test-exclusive-writer-contract".to_owned(),
        evidence_sha256: "11".repeat(32),
        scope_sha256: scope.sha256().expect("scope digest"),
        s0_snapshot_id: before.snapshot_id.clone(),
        s1_snapshot_id: after.snapshot_id.clone(),
        exclusive_writer_enforced: true,
        s0_quiescent: true,
        s1_quiescent: true,
    }
}

fn entry<'a>(snapshot: &'a FilesystemSnapshot, path: &[u8]) -> &'a FilesystemEntry {
    let encoded = hex::encode(path);
    snapshot
        .entries
        .iter()
        .find(|entry| entry.relative_path_bytes_hex == encoded)
        .expect("captured entry")
}

fn try_set_xattr(path: &Path, name: &[u8], value: &[u8]) -> bool {
    let path = CString::new(path.as_os_str().as_bytes()).expect("xattr path without NUL");
    let name = CString::new(name).expect("xattr name without NUL");
    let result = unsafe {
        libc::lsetxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast::<libc::c_void>(),
            value.len(),
            0,
        )
    };
    if result == 0 {
        return true;
    }
    let errno = std::io::Error::last_os_error().raw_os_error();
    if matches!(errno, Some(libc::EOPNOTSUPP | libc::EPERM | libc::ENOSYS)) {
        false
    } else {
        panic!(
            "set test xattr failed: {:?}",
            std::io::Error::last_os_error()
        );
    }
}

#[test]
fn scope_is_explicit_canonical_and_exposes_overlap_guard() {
    let directory = TestDirectory::new("scope");
    let child = directory.path.join("child");
    let scope = default_scope(&child);

    assert_eq!(
        scope.decoded_roots().expect("decode roots"),
        vec![child.clone()]
    );
    assert!(scope.overlaps_path(&child).expect("same path"));
    assert!(scope
        .overlaps_path(&child.join("observer-output"))
        .expect("descendant path"));
    assert!(scope.overlaps_path(&directory.path).expect("ancestor path"));
    assert!(!scope
        .overlaps_path(&directory.path.join("sibling"))
        .expect("disjoint path"));

    assert!(FilesystemScope::new(
        vec![PathBuf::from("/")],
        FilesystemCapturePolicy::default(),
        FilesystemCaptureLimits::default(),
    )
    .is_err());
    assert!(FilesystemScope::new(
        vec![child.clone(), child.join("nested")],
        FilesystemCapturePolicy::default(),
        FilesystemCaptureLimits::default(),
    )
    .is_err());
    let include_cross_filesystems = FilesystemCapturePolicy {
        cross_filesystems: CrossFilesystemPolicy::Include,
        ..FilesystemCapturePolicy::default()
    };
    assert!(FilesystemScope::new(
        vec![child.clone()],
        include_cross_filesystems,
        FilesystemCaptureLimits::default(),
    )
    .unwrap_err()
    .to_string()
    .contains("SAME_DEVICE_ONLY"));
    assert!(FilesystemScope::new(
        vec![
            child.clone(),
            directory.path.join("child-0"),
            child.join("nested"),
        ],
        FilesystemCapturePolicy::default(),
        FilesystemCaptureLimits::default(),
    )
    .is_err());
}

#[test]
fn capture_is_canonical_and_preserves_linux_object_evidence() {
    let directory = TestDirectory::new("capture");
    let root = directory.path.join("scope");
    fs::create_dir(&root).expect("create scope root");
    fs::create_dir(root.join("directory")).expect("create directory");
    fs::write(root.join("file.txt"), b"payload").expect("write regular file");
    symlink("../file.txt", root.join("directory/link")).expect("create symlink");
    let non_utf8 = OsString::from_vec(vec![0xff, b'-', b'n', b'a', b'm', b'e']);
    fs::write(root.join(non_utf8), b"non-utf8").expect("write non-UTF-8 file");
    let fifo_path = root.join("fifo");
    let fifo_c = CString::new(fifo_path.as_os_str().as_bytes()).expect("FIFO path without NUL");
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
    let xattr_set = try_set_xattr(
        &root.join("file.txt"),
        b"user.observer-test",
        b"xattr-value",
    );

    let captured = snapshot(&default_scope(&root), "capture-s0", SnapshotPhase::S0);
    assert_eq!(captured.completeness.status, CompletenessStatus::Complete);
    assert!(captured.errors.is_empty());
    assert!(captured.limits_hit.is_empty());
    assert!(captured.entries.windows(2).all(|pair| {
        (pair[0].root_index, &pair[0].relative_path_bytes_hex)
            < (pair[1].root_index, &pair[1].relative_path_bytes_hex)
    }));

    let file = entry(&captured, b"file.txt");
    assert_eq!(file.entry_type, FilesystemEntryType::RegularFile);
    assert_ne!(file.device, 0);
    assert_ne!(file.inode, 0);
    assert_eq!(file.rdev, 0);
    assert_eq!(file.size_bytes, 7);
    assert!(file.ctime_seconds > 0);
    assert_eq!(file.content.status, ContentCaptureStatus::Captured);
    assert_eq!(
        file.content.sha256.as_deref(),
        Some(hex::encode(Sha256::digest(b"payload")).as_str())
    );
    if xattr_set {
        let attribute = file
            .xattrs
            .attributes
            .iter()
            .find(|attribute| attribute.name_bytes_hex == hex::encode(b"user.observer-test"))
            .expect("captured user xattr");
        assert_eq!(attribute.status, XattrValueStatus::Captured);
        assert_eq!(
            attribute.value_sha256.as_deref(),
            Some(hex::encode(Sha256::digest(b"xattr-value")).as_str())
        );
    }

    let link = entry(&captured, b"directory/link");
    assert_eq!(link.entry_type, FilesystemEntryType::Symlink);
    assert_eq!(link.symlink.status, SymlinkCaptureStatus::Captured);
    assert_eq!(
        link.symlink.target_bytes_hex.as_deref(),
        Some("2e2e2f66696c652e747874")
    );
    assert_eq!(
        entry(&captured, b"fifo").entry_type,
        FilesystemEntryType::Fifo
    );
    assert_eq!(
        entry(&captured, &[0xff, b'-', b'n', b'a', b'm', b'e']).relative_path_bytes_hex,
        "ff2d6e616d65"
    );
}

#[test]
fn content_capture_does_not_mutate_regular_file_atime() {
    let directory = TestDirectory::new("noatime");
    let root = directory.path.join("scope");
    fs::create_dir(&root).expect("create scope root");
    let file = root.join("payload");
    fs::write(&file, b"content whose read must not change atime").expect("write payload");

    let timestamps = [
        libc::timespec {
            tv_sec: 1_600_000_000,
            tv_nsec: 123_456_789,
        },
        libc::timespec {
            tv_sec: 1_700_000_000,
            tv_nsec: 987_654_321,
        },
    ];
    for target in [&root, &file] {
        let path = CString::new(target.as_os_str().as_bytes()).expect("path without NUL");
        assert_eq!(
            unsafe {
                libc::utimensat(
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    timestamps.as_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            },
            0,
            "set old atime: {}",
            std::io::Error::last_os_error()
        );
    }
    let before = fs::metadata(&file).expect("metadata before capture");
    let root_before = fs::metadata(&root).expect("root metadata before capture");

    let captured = snapshot(&default_scope(&root), "noatime-s0", SnapshotPhase::S0);
    assert_eq!(captured.completeness.status, CompletenessStatus::Complete);
    let after = fs::metadata(&file).expect("metadata after capture");
    let root_after = fs::metadata(&root).expect("root metadata after capture");
    assert_eq!(
        (before.atime(), before.atime_nsec()),
        (after.atime(), after.atime_nsec()),
        "filesystem confirmation must not cause an atime side effect"
    );
    assert_eq!(
        (root_before.atime(), root_before.atime_nsec()),
        (root_after.atime(), root_after.atime_nsec()),
        "directory enumeration must not cause an atime side effect"
    );
}

#[test]
fn missing_actor_contract_never_authorizes_unchanged() {
    let directory = TestDirectory::new("missing-contract");
    let root = directory.path.join("scope");
    fs::create_dir(&root).expect("create scope root");
    fs::write(root.join("file"), b"same").expect("write file");
    let scope = default_scope(&root);
    let before = snapshot(&scope, "missing-contract-s0", SnapshotPhase::S0);
    let after = snapshot(&scope, "missing-contract-s1", SnapshotPhase::S1);

    let result = compare(&before, &after, None).expect("compare snapshots");
    assert_eq!(
        result.endpoint_difference,
        EndpointDifferenceStatus::ObservedIdentical
    );
    assert_eq!(result.actor_contract_status, ActorContractStatus::Missing);
    assert_eq!(
        result.causal_attribution_status,
        CausalAttributionStatus::NotEstablished
    );
    assert_eq!(result.verdict, FilesystemVerdict::Inconclusive);
    assert!(result.changes.is_empty());
}

#[test]
fn comparison_rejects_cross_root_identity_as_complete_evidence() {
    let directory = TestDirectory::new("root-identity");
    let root = directory.path.join("scope");
    fs::create_dir(&root).expect("create scope root");
    fs::write(root.join("file"), b"same").expect("write file");
    let scope = default_scope(&root);
    let before = snapshot(&scope, "root-identity-s0", SnapshotPhase::S0);
    let mut after = snapshot(&scope, "root-identity-s1", SnapshotPhase::S1);
    after.mount_root_inode = if after.mount_root_inode == u64::MAX {
        u64::MAX - 1
    } else {
        after.mount_root_inode + 1
    };

    let result = compare(&before, &after, None).expect("compare cross-root snapshots");
    assert_eq!(
        result.state_completeness.status,
        CompletenessStatus::Incomplete
    );
    assert_eq!(
        result.endpoint_difference,
        EndpointDifferenceStatus::Indeterminate
    );
    assert_eq!(result.verdict, FilesystemVerdict::Inconclusive);
    assert!(result
        .state_completeness
        .reasons
        .iter()
        .any(|reason| reason.contains("root object identities differ")));
}

#[test]
fn unauthenticated_external_contract_never_authorizes_bounded_unchanged() {
    let directory = TestDirectory::new("unchanged");
    let root = directory.path.join("scope");
    fs::create_dir(&root).expect("create scope root");
    fs::write(root.join("file"), b"same").expect("write file");
    let scope = default_scope(&root);
    let before = snapshot(&scope, "unchanged-s0", SnapshotPhase::S0);
    let after = snapshot(&scope, "unchanged-s1", SnapshotPhase::S1);
    let contract = established_contract(&scope, &before, &after);

    let result = compare(&before, &after, Some(&contract)).expect("compare snapshots");
    assert_eq!(
        result.state_completeness.status,
        CompletenessStatus::Complete
    );
    assert_eq!(
        result.actor_contract_status,
        ActorContractStatus::AssertedNotAuthenticated
    );
    assert_eq!(
        result.endpoint_difference,
        EndpointDifferenceStatus::ObservedIdentical
    );
    assert_eq!(result.verdict, FilesystemVerdict::Inconclusive);
}

#[test]
fn missing_root_is_incomplete_and_cannot_authorize_unchanged() {
    let directory = TestDirectory::new("missing-root");
    let root = directory.path.join("absent");
    let scope = default_scope(&root);
    let before = snapshot(&scope, "missing-root-s0", SnapshotPhase::S0);
    let after = snapshot(&scope, "missing-root-s1", SnapshotPhase::S1);

    for captured in [&before, &after] {
        assert_eq!(captured.roots[0].status, RootCaptureStatus::Missing);
        assert_eq!(captured.completeness.status, CompletenessStatus::Incomplete);
        assert!(captured
            .completeness
            .reasons
            .iter()
            .any(|reason| reason.contains("roots are missing")));
    }

    let contract = established_contract(&scope, &before, &after);
    let result = compare(&before, &after, Some(&contract)).expect("compare missing roots");
    assert_eq!(
        result.state_completeness.status,
        CompletenessStatus::Incomplete
    );
    assert_eq!(
        result.endpoint_difference,
        EndpointDifferenceStatus::Indeterminate
    );
    assert_eq!(result.verdict, FilesystemVerdict::Inconclusive);
}

#[test]
fn validation_rejects_missing_root_claiming_complete() {
    let directory = TestDirectory::new("forged-missing-root");
    let root = directory.path.join("absent");
    let scope = default_scope(&root);
    let mut forged = snapshot(&scope, "forged-missing-root-s0", SnapshotPhase::S0);
    forged.completeness.status = CompletenessStatus::Complete;
    forged.completeness.reasons.clear();

    assert!(forged.validate().is_err());
}

#[test]
fn validation_rejects_entry_without_immediate_parent() {
    let directory = TestDirectory::new("forged-missing-parent");
    let root = directory.path.join("scope");
    fs::create_dir(&root).expect("create scope root");
    fs::create_dir(root.join("present")).expect("create present parent");
    fs::write(root.join("present/child"), b"payload").expect("write nested child");
    let scope = default_scope(&root);
    let mut forged = snapshot(&scope, "forged-missing-parent-s0", SnapshotPhase::S0);
    let child = forged
        .entries
        .iter_mut()
        .find(|entry| entry.relative_path_bytes_hex == hex::encode(b"present/child"))
        .expect("captured nested child");
    // Keep ordering and all byte-accounting unchanged while redirecting the
    // child beneath an absent, same-length parent.
    child.relative_path_bytes_hex = hex::encode(b"missing/child");
    child.relative_path_display = "missing/child".to_owned();

    assert!(forged.validate().is_err());
}

#[test]
fn validation_rejects_child_beneath_untraversed_parent() {
    let directory = TestDirectory::new("forged-untraversed-parent");
    let root = directory.path.join("scope");
    fs::create_dir(&root).expect("create scope root");
    fs::create_dir(root.join("parent")).expect("create parent");
    fs::write(root.join("parent/child"), b"payload").expect("write nested child");
    let scope = default_scope(&root);
    let mut forged = snapshot(&scope, "forged-untraversed-parent-s0", SnapshotPhase::S0);
    forged
        .entries
        .iter_mut()
        .find(|entry| entry.relative_path_bytes_hex == hex::encode(b"parent"))
        .expect("captured parent")
        .traversal = TraversalStatus::CrossDeviceExcluded;

    assert!(forged.validate().is_err());
}

#[test]
fn observed_difference_survives_causal_downgrade() {
    let directory = TestDirectory::new("changed");
    let root = directory.path.join("scope");
    fs::create_dir(&root).expect("create scope root");
    fs::write(root.join("file"), b"before").expect("write S0 file");
    let scope = default_scope(&root);
    let before = snapshot(&scope, "changed-s0", SnapshotPhase::S0);
    fs::write(root.join("file"), b"after-longer").expect("write S1 file");
    let after = snapshot(&scope, "changed-s1", SnapshotPhase::S1);

    let uncontracted = compare(&before, &after, None).expect("compare without contract");
    assert_eq!(
        uncontracted.endpoint_difference,
        EndpointDifferenceStatus::ObservedDifferent
    );
    assert_eq!(uncontracted.verdict, FilesystemVerdict::ChangedWithinScope);
    assert!(uncontracted.changes.iter().any(|change| {
        change.relative_path_bytes_hex == hex::encode(b"file")
            && change.kind == FilesystemChangeKind::Modified
            && change.changed_fields.contains(&ChangedField::Content)
    }));

    let contract = established_contract(&scope, &before, &after);
    let contracted = compare(&before, &after, Some(&contract)).expect("compare with contract");
    assert_eq!(
        contracted.endpoint_difference,
        EndpointDifferenceStatus::ObservedDifferent
    );
    assert_eq!(contracted.verdict, FilesystemVerdict::ChangedWithinScope);
}

#[test]
fn root_filesystem_observations_are_part_of_the_endpoint_state() {
    let directory = TestDirectory::new("root-observation");
    let root = directory.path.join("scope");
    fs::create_dir(&root).expect("create scope root");
    let scope = default_scope(&root);
    let before = snapshot(&scope, "root-observation-s0", SnapshotPhase::S0);
    let mut after = snapshot(&scope, "root-observation-s1", SnapshotPhase::S1);
    after.roots[0].filesystem_magic = Some(0xdead_beef);
    after.roots[0].filesystem_class = RootFilesystemClass::GenericPathTree;
    after.validate().expect("valid changed root observation");
    let contract = established_contract(&scope, &before, &after);

    let result = compare(&before, &after, Some(&contract)).expect("compare root observations");
    assert_eq!(
        result.endpoint_difference,
        EndpointDifferenceStatus::ObservedDifferent
    );
    assert_eq!(result.verdict, FilesystemVerdict::ChangedWithinScope);
    assert!(result.changes.iter().any(|change| {
        change.root_index == 0
            && change.relative_path_bytes_hex.is_empty()
            && change
                .changed_fields
                .contains(&ChangedField::RootFilesystemMagic)
    }));
}

#[test]
fn any_capture_limit_forces_inconclusive() {
    let directory = TestDirectory::new("limit");
    let root = directory.path.join("scope");
    fs::create_dir(&root).expect("create scope root");
    fs::write(root.join("file"), b"too-large").expect("write bounded file");
    let limits = FilesystemCaptureLimits {
        max_file_content_bytes: 1,
        ..FilesystemCaptureLimits::default()
    };
    let scope = FilesystemScope::new(
        vec![root.clone()],
        FilesystemCapturePolicy::default(),
        limits,
    )
    .expect("limited scope");
    let before = snapshot(&scope, "limit-s0", SnapshotPhase::S0);
    fs::write(root.join("file"), b"still-too-large-and-different")
        .expect("write different limited file");
    let after = snapshot(&scope, "limit-s1", SnapshotPhase::S1);
    assert_eq!(before.completeness.status, CompletenessStatus::Incomplete);
    assert!(!before.limits_hit.is_empty());
    let contract = established_contract(&scope, &before, &after);

    let result = compare(&before, &after, Some(&contract)).expect("compare limited snapshots");
    assert_eq!(
        result.state_completeness.status,
        CompletenessStatus::Incomplete
    );
    assert_eq!(
        result.endpoint_difference,
        EndpointDifferenceStatus::Indeterminate
    );
    assert!(!result.changes.is_empty());
    assert_eq!(result.verdict, FilesystemVerdict::Inconclusive);
}

#[test]
fn xattr_name_lists_are_charged_to_the_global_budget() {
    let directory = TestDirectory::new("xattr-list-budget");
    let root = directory.path.join("scope");
    fs::create_dir(&root).expect("create scope root");
    let file = root.join("file");
    fs::write(&file, b"content").expect("write file");
    if !try_set_xattr(&file, b"user.observer-budget", b"value") {
        return;
    }
    let limits = FilesystemCaptureLimits {
        max_total_xattr_bytes: 1,
        ..FilesystemCaptureLimits::default()
    };
    let scope = FilesystemScope::new(vec![root], FilesystemCapturePolicy::default(), limits)
        .expect("xattr-limited scope");

    let captured = snapshot(&scope, "xattr-budget-s0", SnapshotPhase::S0);
    assert_eq!(captured.completeness.status, CompletenessStatus::Incomplete);
    assert!(captured
        .limits_hit
        .iter()
        .any(|limit| limit.kind == LimitKind::TotalXattrBytes));
    assert_eq!(captured.statistics.xattr_name_bytes_captured, 0);
}

#[test]
fn incomplete_or_misbound_contract_cannot_upgrade_a_result() {
    let directory = TestDirectory::new("contract-binding");
    let root = directory.path.join("scope");
    fs::create_dir(&root).expect("create scope root");
    let scope = default_scope(&root);
    let before = snapshot(&scope, "binding-s0", SnapshotPhase::S0);
    let after = snapshot(&scope, "binding-s1", SnapshotPhase::S1);
    let mut contract = established_contract(&scope, &before, &after);
    contract.s1_quiescent = false;

    let result = compare(&before, &after, Some(&contract)).expect("compare incomplete contract");
    assert_eq!(
        result.actor_contract_status,
        ActorContractStatus::Incomplete
    );
    assert_eq!(result.verdict, FilesystemVerdict::Inconclusive);

    contract.s1_quiescent = true;
    contract.s1_snapshot_id = "different-snapshot".to_owned();
    assert!(compare(&before, &after, Some(&contract)).is_err());
}

#[test]
fn a_cross_environment_pair_is_inconclusive() {
    let directory = TestDirectory::new("environment");
    let root = directory.path.join("scope");
    fs::create_dir(&root).expect("create scope root");
    let scope = default_scope(&root);
    let before = snapshot(&scope, "environment-s0", SnapshotPhase::S0);
    let mut after = snapshot(&scope, "environment-s1", SnapshotPhase::S1);
    after.mount_namespace_inode = after.mount_namespace_inode.saturating_add(1);
    let contract = established_contract(&scope, &before, &after);

    let result = compare(&before, &after, Some(&contract)).expect("compare environments");
    assert_eq!(
        result.state_completeness.status,
        CompletenessStatus::Incomplete
    );
    assert_eq!(
        result.endpoint_difference,
        EndpointDifferenceStatus::Indeterminate
    );
    assert_eq!(result.verdict, FilesystemVerdict::Inconclusive);
}

#[test]
fn generic_comparison_binds_all_recovery_phase_pairs() {
    let directory = TestDirectory::new("phase-pairs");
    let root = directory.path.join("scope");
    fs::create_dir(&root).expect("create scope root");
    fs::write(root.join("file"), b"same").expect("write file");
    let scope = default_scope(&root);
    let template = snapshot(&scope, "phase-template", SnapshotPhase::A);

    for (index, (before_phase, after_phase)) in [
        (SnapshotPhase::A, SnapshotPhase::B),
        (SnapshotPhase::B, SnapshotPhase::C),
        (SnapshotPhase::A, SnapshotPhase::C),
    ]
    .into_iter()
    .enumerate()
    {
        let mut before = template.clone();
        before.phase = before_phase;
        before.snapshot_id = format!("phase-before-{index}");
        let mut after = template.clone();
        after.phase = after_phase;
        after.snapshot_id = format!("phase-after-{index}");

        let comparison = compare_phases(&before, &after, before_phase, after_phase, None)
            .expect("compare recovery phase pair");
        assert_eq!(comparison.s0_snapshot_id, before.snapshot_id);
        assert_eq!(comparison.s1_snapshot_id, after.snapshot_id);
    }
}

#[test]
fn generic_comparison_rejects_same_or_misbound_phases() {
    let directory = TestDirectory::new("invalid-phase-pair");
    let root = directory.path.join("scope");
    fs::create_dir(&root).expect("create scope root");
    let scope = default_scope(&root);
    let before = snapshot(&scope, "invalid-before", SnapshotPhase::A);
    let after = snapshot(&scope, "invalid-after", SnapshotPhase::B);

    assert!(compare_phases(&before, &after, SnapshotPhase::A, SnapshotPhase::A, None,).is_err());
    assert!(compare_phases(&before, &after, SnapshotPhase::B, SnapshotPhase::C, None,).is_err());
}
