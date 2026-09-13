// SPDX-License-Identifier: GPL-2.0-only

use crate::schema::*;
use anyhow::{bail, Result};
use std::cmp::Ordering;

pub const FILESYSTEM_CONFIRMATION_DOMAIN: &str = "FILESYSTEM_ENDPOINT_STATE_V1";

/// Compare two bounded filesystem snapshots.
///
/// Endpoint differences and actor/quiescence authority are independent. A
/// captured typed difference remains visible through `changes` and
/// `endpoint_difference`. Complete snapshots with a difference establish a
/// bounded endpoint-state change, independently of who caused it. Identical
/// snapshots cannot authorize `UnchangedWithinScope` until a future signed,
/// fresh supervisor/harness contract proves exclusive writing and both
/// quiescence barriers. The current static contract is only an unauthenticated
/// caller assertion and can never produce that authority.
pub fn compare(
    before: &FilesystemSnapshot,
    after: &FilesystemSnapshot,
    actor_contract: Option<&ActorQuiescenceContract>,
) -> Result<FilesystemComparison> {
    before.validate()?;
    after.validate()?;
    if before.phase != SnapshotPhase::S0 || after.phase != SnapshotPhase::S1 {
        bail!("filesystem comparison requires an S0 snapshot followed by an S1 snapshot");
    }
    if before.scope != after.scope || before.scope_sha256 != after.scope_sha256 {
        bail!("filesystem comparison scope mismatch");
    }

    let mut changes = compare_entries(&before.entries, &after.entries);
    merge_root_changes(&mut changes, &before.roots, &after.roots);
    if changes.len() > HARD_MAX_CHANGES {
        bail!("filesystem comparison exceeds the protocol change bound");
    }
    let mut state_reasons = Vec::new();
    if before.completeness.status != CompletenessStatus::Complete {
        state_reasons.push("S0 filesystem snapshot is incomplete".to_owned());
    }
    if after.completeness.status != CompletenessStatus::Complete {
        state_reasons.push("S1 filesystem snapshot is incomplete".to_owned());
    }
    if before.boot_id != after.boot_id {
        state_reasons.push("S0 and S1 kernel boot identities differ".to_owned());
    }
    if before.mount_namespace_inode != after.mount_namespace_inode {
        state_reasons.push("S0 and S1 mount namespace identities differ".to_owned());
    }
    state_reasons.sort();
    state_reasons.dedup();
    let state_completeness = Completeness {
        status: if state_reasons.is_empty() {
            CompletenessStatus::Complete
        } else {
            CompletenessStatus::Incomplete
        },
        reasons: state_reasons,
    };

    let actor_contract_status = validate_actor_contract(before, after, actor_contract)?;
    let endpoint_difference = if state_completeness.status != CompletenessStatus::Complete {
        EndpointDifferenceStatus::Indeterminate
    } else if changes.is_empty() {
        EndpointDifferenceStatus::ObservedIdentical
    } else {
        EndpointDifferenceStatus::ObservedDifferent
    };
    let verdict = if state_completeness.status != CompletenessStatus::Complete {
        FilesystemVerdict::Inconclusive
    } else if endpoint_difference == EndpointDifferenceStatus::ObservedDifferent {
        FilesystemVerdict::ChangedWithinScope
    } else {
        // ActorQuiescenceContract v1 is deliberately not an authentication
        // mechanism. Never turn its predictable booleans into a strong
        // negative system-state claim.
        FilesystemVerdict::Inconclusive
    };

    let mut limitations = vec![
        "bounded endpoint-state comparison does not provide operation history or generic causal attribution"
            .to_owned(),
        "v1 omits statx mount ID, inode generation, birth time, file flags, project ID, and mount-table state"
            .to_owned(),
        "tree capture is non-atomic; the external harness must enforce quiescence".to_owned(),
        "captured hashes confirm read bytes, not storage durability".to_owned(),
        "v1 intentionally omits atime because confirmation reads can update it".to_owned(),
        "COMPLETE is relative to the explicit capture policy and selected roots, never all filesystem state"
            .to_owned(),
        "v1 path walks do not pin intermediate components with openat2 and same-device traversal uses st_dev rather than mount ID"
            .to_owned(),
    ];
    if state_completeness.status != CompletenessStatus::Complete {
        limitations.push(
            "incomplete or cross-environment snapshots cannot establish the full scoped endpoint state"
                .to_owned(),
        );
    }
    match actor_contract_status {
        ActorContractStatus::Missing => limitations.push(
            "no external exclusive-writer and quiescence contract was supplied".to_owned(),
        ),
        ActorContractStatus::Incomplete => limitations.push(
            "the external contract does not establish exclusive writing and both quiescence points"
                .to_owned(),
        ),
        ActorContractStatus::AssertedNotAuthenticated => limitations.push(
            "exclusive writing and quiescence are unauthenticated caller assertions; they cannot authorize UNCHANGED_WITHIN_SCOPE"
                .to_owned(),
        ),
        ActorContractStatus::AuthenticatedAndEnforced => limitations.push(
            "authenticated actor enforcement is reserved for a future protocol and is never produced by the v1 static contract"
                .to_owned(),
        ),
    }
    limitations.sort();
    limitations.dedup();

    Ok(FilesystemComparison {
        protocol_version: FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION,
        domain: FILESYSTEM_CONFIRMATION_DOMAIN.to_owned(),
        scope_sha256: before.scope_sha256.clone(),
        s0_snapshot_id: before.snapshot_id.clone(),
        s1_snapshot_id: after.snapshot_id.clone(),
        endpoint_difference,
        verdict,
        state_completeness,
        actor_contract_status,
        causal_attribution_status: CausalAttributionStatus::NotEstablished,
        changes,
        limitations,
    })
}

fn validate_actor_contract(
    before: &FilesystemSnapshot,
    after: &FilesystemSnapshot,
    contract: Option<&ActorQuiescenceContract>,
) -> Result<ActorContractStatus> {
    let Some(contract) = contract else {
        return Ok(ActorContractStatus::Missing);
    };
    contract.validate()?;
    if contract.scope_sha256 != before.scope_sha256
        || contract.s0_snapshot_id != before.snapshot_id
        || contract.s1_snapshot_id != after.snapshot_id
    {
        bail!("filesystem actor contract is not bound to these snapshots and scope");
    }
    if contract.exclusive_writer_enforced && contract.s0_quiescent && contract.s1_quiescent {
        Ok(ActorContractStatus::AssertedNotAuthenticated)
    } else {
        Ok(ActorContractStatus::Incomplete)
    }
}

fn compare_entries(before: &[FilesystemEntry], after: &[FilesystemEntry]) -> Vec<FilesystemChange> {
    let mut changes = Vec::new();
    let mut before_index = 0;
    let mut after_index = 0;
    while before_index < before.len() || after_index < after.len() {
        match (before.get(before_index), after.get(after_index)) {
            (Some(left), Some(right)) => match entry_key(left).cmp(&entry_key(right)) {
                Ordering::Less => {
                    changes.push(change_for_entry(
                        left,
                        FilesystemChangeKind::Removed,
                        Vec::new(),
                    ));
                    before_index += 1;
                }
                Ordering::Greater => {
                    changes.push(change_for_entry(
                        right,
                        FilesystemChangeKind::Added,
                        Vec::new(),
                    ));
                    after_index += 1;
                }
                Ordering::Equal => {
                    let changed_fields = changed_fields(left, right);
                    if !changed_fields.is_empty() {
                        changes.push(change_for_entry(
                            left,
                            FilesystemChangeKind::Modified,
                            changed_fields,
                        ));
                    }
                    before_index += 1;
                    after_index += 1;
                }
            },
            (Some(left), None) => {
                changes.push(change_for_entry(
                    left,
                    FilesystemChangeKind::Removed,
                    Vec::new(),
                ));
                before_index += 1;
            }
            (None, Some(right)) => {
                changes.push(change_for_entry(
                    right,
                    FilesystemChangeKind::Added,
                    Vec::new(),
                ));
                after_index += 1;
            }
            (None, None) => break,
        }
    }
    changes
}

fn merge_root_changes(
    changes: &mut Vec<FilesystemChange>,
    before: &[RootObservation],
    after: &[RootObservation],
) {
    for (left, right) in before.iter().zip(after) {
        let mut root_fields = Vec::new();
        if left.status != right.status {
            root_fields.push(ChangedField::RootCaptureStatus);
        }
        if left.filesystem_magic != right.filesystem_magic {
            root_fields.push(ChangedField::RootFilesystemMagic);
        }
        if left.filesystem_class != right.filesystem_class {
            root_fields.push(ChangedField::RootFilesystemClass);
        }
        if root_fields.is_empty() {
            continue;
        }

        if let Some(existing) = changes.iter_mut().find(|change| {
            change.root_index == left.root_index && change.relative_path_bytes_hex.is_empty()
        }) {
            existing.changed_fields.extend(root_fields);
            existing.changed_fields.sort();
            existing.changed_fields.dedup();
        } else {
            changes.push(FilesystemChange {
                root_index: left.root_index,
                relative_path_bytes_hex: String::new(),
                kind: FilesystemChangeKind::Modified,
                changed_fields: root_fields,
            });
        }
    }
    changes.sort_by(|left, right| {
        (left.root_index, &left.relative_path_bytes_hex)
            .cmp(&(right.root_index, &right.relative_path_bytes_hex))
    });
}

fn entry_key(entry: &FilesystemEntry) -> (u32, &str) {
    (entry.root_index, &entry.relative_path_bytes_hex)
}

fn change_for_entry(
    entry: &FilesystemEntry,
    kind: FilesystemChangeKind,
    changed_fields: Vec<ChangedField>,
) -> FilesystemChange {
    FilesystemChange {
        root_index: entry.root_index,
        relative_path_bytes_hex: entry.relative_path_bytes_hex.clone(),
        kind,
        changed_fields,
    }
}

fn changed_fields(before: &FilesystemEntry, after: &FilesystemEntry) -> Vec<ChangedField> {
    let mut fields = Vec::new();
    if before.entry_type != after.entry_type {
        fields.push(ChangedField::Type);
    }
    if before.device != after.device {
        fields.push(ChangedField::Device);
    }
    if before.inode != after.inode {
        fields.push(ChangedField::Inode);
    }
    if before.rdev != after.rdev {
        fields.push(ChangedField::Rdev);
    }
    if before.mode != after.mode {
        fields.push(ChangedField::Mode);
    }
    if before.uid != after.uid {
        fields.push(ChangedField::Uid);
    }
    if before.gid != after.gid {
        fields.push(ChangedField::Gid);
    }
    if before.hard_link_count != after.hard_link_count {
        fields.push(ChangedField::HardLinkCount);
    }
    if before.size_bytes != after.size_bytes {
        fields.push(ChangedField::Size);
    }
    if before.mtime_seconds != after.mtime_seconds
        || before.mtime_nanoseconds != after.mtime_nanoseconds
    {
        fields.push(ChangedField::Mtime);
    }
    if before.ctime_seconds != after.ctime_seconds
        || before.ctime_nanoseconds != after.ctime_nanoseconds
    {
        fields.push(ChangedField::Ctime);
    }
    if before.traversal != after.traversal {
        fields.push(ChangedField::Traversal);
    }
    if before.content != after.content {
        fields.push(ChangedField::Content);
    }
    if before.symlink != after.symlink {
        fields.push(ChangedField::Symlink);
    }
    if before.xattrs != after.xattrs {
        fields.push(ChangedField::Xattrs);
    }
    fields
}
