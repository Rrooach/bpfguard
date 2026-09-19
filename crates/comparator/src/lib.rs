// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, Result};
use bpf_observer_oracle::validate_snapshot_resource_bounds;
use bpf_observer_schema::{
    Attribution, ChangeCertainty, ChangeKind, ClaimScope, Completeness, CompletenessStatus,
    EvidenceHealth, LinkState, MapSampleStatus, MapState, ObjectIdentity, ObjectType, PinState,
    ProgramState, QuiescenceReport, RunStatus, Snapshot, StateChange, StateVerdict, Verdict,
    SCHEMA_VERSION,
};
use serde_json::{json, to_value, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const BASELINE_EVENT_INTERFACE: &str = "BPF_USER_SYSCALL";

pub fn compare(
    before: &Snapshot,
    after: &Snapshot,
    health: &EvidenceHealth,
    quiescence: QuiescenceReport,
) -> Result<Verdict> {
    compare_phases(before, after, "S0", "S1", health, quiescence)
}

/// Compare two snapshots whose exact, distinct phases are supplied by the
/// caller.
///
/// Phase binding is checked before any state delta is calculated. Higher-level
/// protocols remain responsible for restricting which phase transitions are
/// legal in their state machine.
pub fn compare_phases(
    before: &Snapshot,
    after: &Snapshot,
    expected_before: &str,
    expected_after: &str,
    health: &EvidenceHealth,
    quiescence: QuiescenceReport,
) -> Result<Verdict> {
    validate_phase_pair(before, after, expected_before, expected_after)?;
    let mut completeness = merge_completeness(
        &before.completeness,
        &after.completeness,
        expected_before,
        expected_after,
    );

    if before.schema_version != SCHEMA_VERSION || after.schema_version != SCHEMA_VERSION {
        completeness.mark_incomplete("snapshot schema version is unsupported");
    }
    if before.boot_id != after.boot_id {
        completeness.mark_incomplete(format!(
            "{expected_before} and {expected_after} were captured from different boot IDs"
        ));
    }
    if before.claim_scope != after.claim_scope {
        completeness.mark_incomplete(format!(
            "{expected_before} and {expected_after} effective claim scopes differ"
        ));
    }
    if before.observer_exclusions != after.observer_exclusions {
        completeness.mark_incomplete(format!(
            "{expected_before} and {expected_after} observer exclusion sets differ"
        ));
    }
    if before.kernel_release != after.kernel_release {
        completeness.mark_incomplete(format!(
            "{expected_before} and {expected_after} kernel releases differ"
        ));
    }
    if before.byte_order != after.byte_order {
        completeness.mark_incomplete(format!(
            "{expected_before} and {expected_after} byte orders differ"
        ));
    }
    if before.possible_cpu_ids != after.possible_cpu_ids {
        completeness.mark_incomplete(format!(
            "{expected_before} and {expected_after} possible CPU topologies differ"
        ));
    }
    let pin_observation_domains_match = before.pin_roots == after.pin_roots;
    if !pin_observation_domains_match {
        completeness.mark_incomplete(format!(
            "{expected_before} and {expected_after} pin observation roots differ"
        ));
    }

    // The public comparator is fail-closed on the same producer contract as
    // persisted CLI input. Keeping this validator in the Oracle crate avoids
    // a second, gradually diverging definition of canonical kernel state.
    let before_contract_valid = match validate_snapshot_resource_bounds(before) {
        Ok(()) => true,
        Err(error) => {
            completeness.mark_incomplete(format!(
                "{expected_before} producer contract is invalid: {error:#}"
            ));
            false
        }
    };
    let after_contract_valid = match validate_snapshot_resource_bounds(after) {
        Ok(()) => true,
        Err(error) => {
            completeness.mark_incomplete(format!(
                "{expected_after} producer contract is invalid: {error:#}"
            ));
            false
        }
    };

    validate_snapshot_structure(before, expected_before, &mut completeness);
    validate_snapshot_structure(after, expected_after, &mut completeness);
    validate_snapshot_content(
        before,
        &before.claim_scope,
        expected_before,
        &mut completeness,
    );
    validate_snapshot_content(after, &after.claim_scope, expected_after, &mut completeness);

    let baseline_scope_supported = baseline_scope_supported(&before.claim_scope)
        && baseline_scope_supported(&after.claim_scope);
    if before.claim_scope.object_types.is_empty() {
        completeness.mark_incomplete(format!(
            "{expected_before} comparison object scope is empty"
        ));
    }
    if after.claim_scope.object_types.is_empty() {
        completeness.mark_incomplete(format!("{expected_after} comparison object scope is empty"));
    }
    if !baseline_event_interface_supported(&before.claim_scope) {
        completeness.mark_incomplete(format!(
            "{expected_before} event interfaces are not exactly the supported BPF_USER_SYSCALL baseline"
        ));
    }
    if !baseline_event_interface_supported(&after.claim_scope) {
        completeness.mark_incomplete(format!(
            "{expected_after} event interfaces are not exactly the supported BPF_USER_SYSCALL baseline"
        ));
    }

    let endpoints_match = before.schema_version == SCHEMA_VERSION
        && after.schema_version == SCHEMA_VERSION
        && before.phase == expected_before
        && after.phase == expected_after
        && before.boot_id == after.boot_id
        && before.kernel_release == after.kernel_release
        && before.byte_order == after.byte_order
        && before.possible_cpu_ids == after.possible_cpu_ids
        && before.claim_scope == after.claim_scope
        && before.observer_exclusions == after.observer_exclusions;
    let scopes_match = endpoints_match
        && before_contract_valid
        && after_contract_valid
        && baseline_scope_supported
        && pin_observation_domains_match;
    let default_attribution =
        if quiescence.exclusive_actor_attribution && quiescence.supports_unchanged() {
            Attribution::WorkloadAttributed
        } else {
            Attribution::UnattributedSystemChange
        };
    let before_reliability = InventoryReliability::new(before, before_contract_valid);
    let after_reliability = InventoryReliability::new(after, after_contract_valid);

    let mut changes = Vec::new();
    if endpoints_match {
        diff_objects(
            "program",
            ObjectType::Program,
            &before_reliability,
            &after_reliability,
            visible_programs(before),
            visible_programs(after),
            default_attribution.clone(),
            &mut changes,
        )?;
        diff_maps(
            before,
            after,
            &before_reliability,
            &after_reliability,
            visible_maps(before),
            visible_maps(after),
            quiescence.supports_unchanged(),
            default_attribution.clone(),
            &mut changes,
        )?;
        diff_links(
            before,
            after,
            &before_reliability,
            &after_reliability,
            visible_links(before),
            visible_links(after),
            default_attribution.clone(),
            &mut changes,
        )?;
        diff_pins(
            before,
            after,
            before_contract_valid && after_contract_valid && pin_observation_domains_match,
            &visible_pins(before),
            &visible_pins(after),
            default_attribution,
            &mut changes,
        )?;
    }

    let confirmed_changes = changes
        .iter()
        .filter(|change| change.certainty == ChangeCertainty::Confirmed)
        .count();
    let state_verdict = if confirmed_changes > 0 {
        StateVerdict::ChangedWithinScope
    } else if changes.is_empty()
        && completeness.status == CompletenessStatus::Complete
        && health.is_complete()
        && quiescence.supports_unchanged()
        && scopes_match
    {
        StateVerdict::UnchangedWithinScope
    } else {
        StateVerdict::Inconclusive
    };

    let attribution = aggregate_attribution(&changes, &state_verdict);
    let mut evidence_status = evidence_completeness(health);
    if !baseline_scope_supported {
        evidence_status.mark_incomplete(
            "claim scope is not covered by the comparator's BPF_USER_SYSCALL evidence baseline",
        );
    }
    let mut limitations = vec![
        format!(
            "{expected_before}/{expected_after} comparison says nothing about transient effects between the two snapshots"
        ),
        "BPF object IDs are scoped to one boot and do not provide a permanent generation ID".into(),
    ];
    if !quiescence.supports_unchanged() {
        limitations.push(
            "quiescence was not established by a complete harness contract; an empty diff is inconclusive"
                .into(),
        );
    }
    if !before.claim_scope.attachment_targets.is_empty() {
        limitations.push(
            "attachment adapters are target-specific and must report complete coverage".into(),
        );
    }
    let indeterminate_changes = changes.len().saturating_sub(confirmed_changes);
    if indeterminate_changes > 0 {
        limitations.push(format!(
            "{indeterminate_changes} candidate state delta(s) could not be confirmed because the relevant inventory was incomplete"
        ));
    }

    Ok(Verdict {
        schema_version: SCHEMA_VERSION,
        state_verdict,
        state_completeness: completeness,
        evidence_status,
        attribution,
        quiescence,
        // The pure comparator cannot commit a run or bind files together.
        // Only a digest-bearing FINALIZED manifest can do that.
        run_status: RunStatus::Provisional,
        changes,
        limitations,
    })
}

fn validate_phase_pair(
    before: &Snapshot,
    after: &Snapshot,
    expected_before: &str,
    expected_after: &str,
) -> Result<()> {
    if expected_before.is_empty() || expected_after.is_empty() {
        bail!("BPF snapshot comparison phases must be non-empty");
    }
    if expected_before == expected_after {
        bail!(
            "BPF snapshot comparison phases must differ, got {expected_before} -> {expected_after}"
        );
    }
    if before.phase != expected_before || after.phase != expected_after {
        bail!(
            "BPF snapshot comparison requires {expected_before} followed by {expected_after}, got {} followed by {}",
            before.phase,
            after.phase
        );
    }
    Ok(())
}

fn baseline_event_interface_supported(scope: &ClaimScope) -> bool {
    scope.event_interfaces.len() == 1 && scope.event_interfaces.contains(BASELINE_EVENT_INTERFACE)
}

fn baseline_scope_supported(scope: &ClaimScope) -> bool {
    !scope.object_types.is_empty() && baseline_event_interface_supported(scope)
}

fn validate_snapshot_structure(
    snapshot: &Snapshot,
    expected_phase: &str,
    completeness: &mut Completeness,
) {
    let issue = |completeness: &mut Completeness, message: String| {
        completeness.mark_incomplete(format!("{expected_phase}: {message}"));
    };

    if snapshot.phase != expected_phase {
        issue(
            completeness,
            format!(
                "snapshot phase is {:?}, expected {expected_phase}",
                snapshot.phase
            ),
        );
    }
    if snapshot.snapshot_id.is_empty()
        || snapshot.boot_id.is_empty()
        || snapshot.kernel_release.is_empty()
    {
        issue(completeness, "snapshot identity fields are empty".into());
    }
    if !matches!(snapshot.byte_order.as_str(), "little" | "big") {
        issue(
            completeness,
            format!("unsupported byte order {:?}", snapshot.byte_order),
        );
    }
    if snapshot.possible_cpu_ids.is_empty() || !strictly_increasing(&snapshot.possible_cpu_ids) {
        issue(
            completeness,
            "possible CPU IDs are not strictly increasing".into(),
        );
    }
    if snapshot.completeness.status == CompletenessStatus::Complete
        && (!snapshot.read_failures.is_empty() || !snapshot.completeness.reasons.is_empty())
    {
        issue(
            completeness,
            "failure reasons or read failures are present despite COMPLETE snapshot metadata"
                .into(),
        );
    }
    if !snapshot
        .claim_scope
        .map_ids
        .is_disjoint(&snapshot.observer_exclusions.map_ids)
    {
        issue(
            completeness,
            "explicit map_ids overlap observer-owned Map exclusions".into(),
        );
    }

    validate_programs(snapshot, expected_phase, completeness);
    validate_maps(snapshot, expected_phase, completeness);
    validate_links(snapshot, expected_phase, completeness);
    validate_pins(snapshot, expected_phase, completeness);
}

fn validate_programs(snapshot: &Snapshot, phase: &str, completeness: &mut Completeness) {
    if !snapshot
        .claim_scope
        .object_types
        .contains(&bpf_observer_schema::ObjectType::Program)
        && !snapshot.programs.is_empty()
    {
        completeness.mark_incomplete(format!(
            "{phase}: programs exist outside the declared object scope"
        ));
    }
    let mut ids = BTreeSet::new();
    for program in &snapshot.programs {
        if program.identity.boot_id != snapshot.boot_id
            || program.identity.object_type != bpf_observer_schema::ObjectType::Program
            || program.identity.id == 0
            || !ids.insert(program.identity.id)
        {
            completeness.mark_incomplete(format!(
                "{phase}: invalid or duplicate program identity {}",
                program.identity.id
            ));
        }
        if program.excluded
            != snapshot
                .observer_exclusions
                .program_ids
                .contains(&program.identity.id)
        {
            completeness.mark_incomplete(format!(
                "{phase}: program {} exclusion flag is inconsistent",
                program.identity.id
            ));
        }
        if !strictly_increasing(&program.map_ids) {
            completeness.mark_incomplete(format!(
                "{phase}: program {} map IDs are not canonical",
                program.identity.id
            ));
        }
    }
    if snapshot
        .claim_scope
        .object_types
        .contains(&bpf_observer_schema::ObjectType::Program)
    {
        let missing = snapshot
            .observer_exclusions
            .program_ids
            .iter()
            .filter(|id| !ids.contains(id))
            .count();
        if missing != 0 {
            completeness.mark_incomplete(format!(
                "{phase}: {missing} excluded observer programs are absent from raw inventory"
            ));
        }
    }
}

fn validate_maps(snapshot: &Snapshot, phase: &str, completeness: &mut Completeness) {
    if !snapshot
        .claim_scope
        .object_types
        .contains(&bpf_observer_schema::ObjectType::Map)
        && !snapshot.maps.is_empty()
    {
        completeness.mark_incomplete(format!(
            "{phase}: maps exist outside the declared object scope"
        ));
    }
    let mut ids = BTreeSet::new();
    for map in &snapshot.maps {
        if map.identity.boot_id != snapshot.boot_id
            || map.identity.object_type != bpf_observer_schema::ObjectType::Map
            || map.identity.id == 0
            || !ids.insert(map.identity.id)
        {
            completeness.mark_incomplete(format!(
                "{phase}: invalid or duplicate map identity {}",
                map.identity.id
            ));
        }
        if map.excluded
            != snapshot
                .observer_exclusions
                .map_ids
                .contains(&map.identity.id)
        {
            completeness.mark_incomplete(format!(
                "{phase}: map {} exclusion flag is inconsistent",
                map.identity.id
            ));
        }
        validate_map_encoding(snapshot, map, phase, completeness);
    }
    if snapshot
        .claim_scope
        .object_types
        .contains(&bpf_observer_schema::ObjectType::Map)
    {
        let missing = snapshot
            .observer_exclusions
            .map_ids
            .iter()
            .filter(|id| !ids.contains(id))
            .count();
        if missing != 0 {
            completeness.mark_incomplete(format!(
                "{phase}: {missing} excluded observer Maps are absent from raw inventory"
            ));
        }
    }
}

fn validate_map_encoding(
    snapshot: &Snapshot,
    map: &MapState,
    phase: &str,
    completeness: &mut Completeness,
) {
    if !map.content.semantic_complete {
        return;
    }
    if !matches!(
        map.content.status,
        MapSampleStatus::CompleteQuiescent | MapSampleStatus::BestEffortNonAtomic
    ) || map.content.digest_sha256.is_none()
        || map.content.error.is_some()
    {
        completeness.mark_incomplete(format!(
            "{phase}: map {} has an inconsistent complete-content encoding",
            map.identity.id
        ));
    }

    let per_cpu = matches!(map.metadata.map_type, 5 | 6);
    let expected_values = if per_cpu {
        if map.content.possible_cpu_ids != snapshot.possible_cpu_ids {
            completeness.mark_incomplete(format!(
                "{phase}: map {} per-CPU topology does not match snapshot topology",
                map.identity.id
            ));
        }
        snapshot.possible_cpu_ids.len()
    } else {
        if !map.content.possible_cpu_ids.is_empty() {
            completeness.mark_incomplete(format!(
                "{phase}: non-per-CPU map {} carries CPU slots",
                map.identity.id
            ));
        }
        1
    };

    let mut keys = BTreeSet::new();
    let mut calculated_bytes = 0u64;
    for entry in &map.content.entries {
        if !valid_hex_len(&entry.key_hex, map.metadata.key_size as usize) {
            completeness.mark_incomplete(format!(
                "{phase}: map {} has a malformed key",
                map.identity.id
            ));
        }
        if !keys.insert(&entry.key_hex) {
            completeness.mark_incomplete(format!(
                "{phase}: map {} has duplicate keys",
                map.identity.id
            ));
        }
        if entry.values_hex.len() != expected_values
            || entry
                .values_hex
                .iter()
                .any(|value| !valid_hex_len(value, map.metadata.value_size as usize))
        {
            completeness.mark_incomplete(format!(
                "{phase}: map {} has a malformed value vector",
                map.identity.id
            ));
        }
        let value_bytes =
            u64::from(map.metadata.value_size).checked_mul(entry.values_hex.len() as u64);
        calculated_bytes = value_bytes
            .and_then(|value| value.checked_add(u64::from(map.metadata.key_size)))
            .and_then(|value| calculated_bytes.checked_add(value))
            .unwrap_or(u64::MAX);
    }
    if (map.metadata.map_type == 2 || map.metadata.map_type == 6)
        && map.content.entries.len() != map.metadata.max_entries as usize
    {
        completeness.mark_incomplete(format!(
            "{phase}: array map {} does not contain every index",
            map.identity.id
        ));
    }
    if calculated_bytes != map.content.bytes_read {
        completeness.mark_incomplete(format!(
            "{phase}: map {} byte accounting is inconsistent",
            map.identity.id
        ));
    }
    if !canonical_map_content(snapshot, map) {
        completeness.mark_incomplete(format!(
            "{phase}: map {} content is not in canonical digest-bound form",
            map.identity.id
        ));
    }
}

fn canonical_map_content(snapshot: &Snapshot, map: &MapState) -> bool {
    if !map.content.semantic_complete
        || !matches!(
            map.content.status,
            MapSampleStatus::CompleteQuiescent | MapSampleStatus::BestEffortNonAtomic
        )
        || map.content.error.is_some()
        || map.metadata.key_size == 0
        || map.metadata.value_size == 0
        || map.metadata.btf_value_type_id != 0
        || map.metadata.btf_vmlinux_value_type_id != 0
    {
        return false;
    }
    let Some(digest) = map.content.digest_sha256.as_deref() else {
        return false;
    };
    if digest.len() != 64 || !digest.bytes().all(is_lower_hex) {
        return false;
    }
    let per_cpu = matches!(map.metadata.map_type, 5 | 6);
    let expected_values = if per_cpu {
        if map.content.possible_cpu_ids != snapshot.possible_cpu_ids {
            return false;
        }
        snapshot.possible_cpu_ids.len()
    } else {
        if !map.content.possible_cpu_ids.is_empty() {
            return false;
        }
        1
    };
    let mut previous_key: Option<&str> = None;
    let mut calculated_bytes = 0u64;
    for entry in &map.content.entries {
        if !valid_hex_len(&entry.key_hex, map.metadata.key_size as usize)
            || !entry.key_hex.bytes().all(is_lower_hex)
            || previous_key.map(|previous| previous >= entry.key_hex.as_str()) == Some(true)
            || entry.values_hex.len() != expected_values
            || entry.values_hex.iter().any(|value| {
                !valid_hex_len(value, map.metadata.value_size as usize)
                    || !value.bytes().all(is_lower_hex)
            })
        {
            return false;
        }
        previous_key = Some(&entry.key_hex);
        let entry_bytes = u64::from(map.metadata.key_size).checked_add(
            u64::from(map.metadata.value_size)
                .checked_mul(entry.values_hex.len() as u64)
                .unwrap_or(u64::MAX),
        );
        calculated_bytes = entry_bytes
            .and_then(|bytes| calculated_bytes.checked_add(bytes))
            .unwrap_or(u64::MAX);
    }
    if matches!(map.metadata.map_type, 2 | 6)
        && map.content.entries.len() != map.metadata.max_entries as usize
    {
        return false;
    }
    calculated_bytes == map.content.bytes_read && digest_entries(&map.content.entries) == digest
}

fn digest_entries(entries: &[bpf_observer_schema::MapEntry]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"BPF_MAP_CONTENT_V1\0");
    for entry in entries {
        digest_part(&mut hasher, entry.key_hex.as_bytes());
        hasher.update((entry.values_hex.len() as u64).to_le_bytes());
        for value in &entry.values_hex {
            digest_part(&mut hasher, value.as_bytes());
        }
    }
    hex::encode(hasher.finalize())
}

fn digest_part(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn validate_links(snapshot: &Snapshot, phase: &str, completeness: &mut Completeness) {
    if !snapshot
        .claim_scope
        .object_types
        .contains(&bpf_observer_schema::ObjectType::Link)
        && !snapshot.links.is_empty()
    {
        completeness.mark_incomplete(format!(
            "{phase}: links exist outside the declared object scope"
        ));
    }
    let mut ids = BTreeSet::new();
    for link in &snapshot.links {
        if link.identity.boot_id != snapshot.boot_id
            || link.identity.object_type != bpf_observer_schema::ObjectType::Link
            || link.identity.id == 0
            || !ids.insert(link.identity.id)
        {
            completeness.mark_incomplete(format!(
                "{phase}: invalid or duplicate link identity {}",
                link.identity.id
            ));
        }
        if link.excluded
            != snapshot
                .observer_exclusions
                .link_ids
                .contains(&link.identity.id)
        {
            completeness.mark_incomplete(format!(
                "{phase}: link {} exclusion flag is inconsistent",
                link.identity.id
            ));
        }
    }
    if snapshot
        .claim_scope
        .object_types
        .contains(&bpf_observer_schema::ObjectType::Link)
    {
        let missing = snapshot
            .observer_exclusions
            .link_ids
            .iter()
            .filter(|id| !ids.contains(id))
            .count();
        if missing != 0 {
            completeness.mark_incomplete(format!(
                "{phase}: {missing} excluded observer links are absent from raw inventory"
            ));
        }
    }
}

fn validate_pins(snapshot: &Snapshot, phase: &str, completeness: &mut Completeness) {
    let mut identities = BTreeSet::new();
    for pin in &snapshot.pins {
        let raw_path = hex::decode(&pin.path_bytes_hex).ok();
        let raw_path_valid = raw_path.as_ref().map(|path| {
            path.first() == Some(&b'/')
                && pin.path_bytes_hex.bytes().all(is_lower_hex)
                && pin.path == String::from_utf8_lossy(path)
                && snapshot
                    .claim_scope
                    .bpffs_roots
                    .iter()
                    .any(|root| path_is_within_root(path, root.as_bytes()))
        }) == Some(true);
        if pin.object_id == 0
            || pin.mount_namespace_inode == 0
            || pin.mount_id == 0
            || !snapshot.claim_scope.object_types.contains(&pin.object_type)
            || !raw_path_valid
        {
            completeness.mark_incomplete(format!(
                "{phase}: pin {:?} has an invalid identity",
                pin.path
            ));
        }
        if !identities.insert(pin_key(pin)) {
            completeness.mark_incomplete(format!("{phase}: duplicate pin identity {:?}", pin.path));
        }
        let expected_excluded = match pin.object_type {
            bpf_observer_schema::ObjectType::Program => snapshot
                .observer_exclusions
                .program_ids
                .contains(&pin.object_id),
            bpf_observer_schema::ObjectType::Map => snapshot
                .observer_exclusions
                .map_ids
                .contains(&pin.object_id),
            bpf_observer_schema::ObjectType::Link => snapshot
                .observer_exclusions
                .link_ids
                .contains(&pin.object_id),
        };
        if pin.excluded != expected_excluded {
            completeness.mark_incomplete(format!(
                "{phase}: pin {:?} exclusion flag is inconsistent",
                pin.path
            ));
        }
    }
}

fn valid_hex_len(value: &str, raw_len: usize) -> bool {
    value.len() == raw_len.saturating_mul(2) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn strictly_increasing(values: &[u32]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn merge_completeness(
    left: &Completeness,
    right: &Completeness,
    left_phase: &str,
    right_phase: &str,
) -> Completeness {
    let mut merged = Completeness::complete();
    if left.status == CompletenessStatus::Incomplete {
        merged.mark_incomplete(format!("{left_phase} reported incomplete state coverage"));
        for reason in &left.reasons {
            merged.mark_incomplete(format!("{left_phase}: {reason}"));
        }
    }
    if right.status == CompletenessStatus::Incomplete {
        merged.mark_incomplete(format!("{right_phase} reported incomplete state coverage"));
        for reason in &right.reasons {
            merged.mark_incomplete(format!("{right_phase}: {reason}"));
        }
    }
    merged
}

fn validate_snapshot_content(
    snapshot: &Snapshot,
    scope: &ClaimScope,
    phase: &str,
    completeness: &mut Completeness,
) {
    if !scope.attachment_targets.is_empty() {
        completeness.mark_incomplete(format!(
            "{phase}: one or more attachment targets lack a complete adapter"
        ));
    }

    for map in snapshot.maps.iter().filter(|map| !map.excluded) {
        if !scope.samples_map(map.identity.id, map.metadata.map_type) {
            continue;
        }
        if !map.content.semantic_complete {
            completeness.mark_incomplete(format!(
                "{phase}: map {} content is not semantically complete ({:?})",
                map.identity.id, map.content.status
            ));
        }
        if map.content.status != MapSampleStatus::CompleteQuiescent {
            completeness.mark_incomplete(format!(
                "{phase}: map {} content status is {:?}",
                map.identity.id, map.content.status
            ));
        }
        if map.metadata.frozen.is_none() {
            completeness.mark_incomplete(format!(
                "{phase}: map {} frozen state is unavailable",
                map.identity.id
            ));
        }
    }

    for link in snapshot.links.iter().filter(|link| !link.excluded) {
        if link.target.is_none() {
            completeness.mark_incomplete(format!(
                "{phase}: link {} target identity is unavailable",
                link.identity.id
            ));
        }
    }
}

fn object_key(identity: &ObjectIdentity) -> String {
    format!(
        "{}:{:?}:{}",
        identity.boot_id, identity.object_type, identity.id
    )
}

fn visible_programs(snapshot: &Snapshot) -> BTreeMap<String, &ProgramState> {
    snapshot
        .programs
        .iter()
        .filter(|program| !program.excluded)
        .map(|program| (object_key(&program.identity), program))
        .collect()
}

fn visible_maps(snapshot: &Snapshot) -> BTreeMap<String, &MapState> {
    snapshot
        .maps
        .iter()
        .filter(|map| !map.excluded)
        .map(|map| (object_key(&map.identity), map))
        .collect()
}

// These arguments deliberately keep both raw snapshots and their indexed
// reliability views adjacent at the endpoint-diff boundary.
#[allow(clippy::too_many_arguments)]
fn diff_maps(
    before_snapshot: &Snapshot,
    after_snapshot: &Snapshot,
    before_reliability: &InventoryReliability<'_>,
    after_reliability: &InventoryReliability<'_>,
    before: BTreeMap<String, &MapState>,
    after: BTreeMap<String, &MapState>,
    content_comparison_confirmable: bool,
    attribution: Attribution,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    for (identity, old) in &before {
        let Some(new) = after.get(identity) else {
            changes.push(change(
                ChangeKind::Removed,
                "map",
                identity,
                Some(map_change_value(old)),
                None,
                attribution.clone(),
                certainty(
                    before_reliability.reliable(ObjectType::Map, old.identity.id)
                        && after_reliability.reliable(ObjectType::Map, old.identity.id),
                ),
            ));
            continue;
        };

        let stable_metadata_changed = old.metadata.map_type != new.metadata.map_type
            || old.metadata.name != new.metadata.name
            || old.metadata.key_size != new.metadata.key_size
            || old.metadata.value_size != new.metadata.value_size
            || old.metadata.max_entries != new.metadata.max_entries
            || old.metadata.map_flags != new.metadata.map_flags
            || old.metadata.map_extra != new.metadata.map_extra
            || old.metadata.ifindex != new.metadata.ifindex
            || old.metadata.netns_dev != new.metadata.netns_dev
            || old.metadata.netns_ino != new.metadata.netns_ino
            || old.metadata.btf_id != new.metadata.btf_id
            || old.metadata.btf_key_type_id != new.metadata.btf_key_type_id
            || old.metadata.btf_value_type_id != new.metadata.btf_value_type_id
            || old.metadata.btf_vmlinux_value_type_id != new.metadata.btf_vmlinux_value_type_id;
        let frozen_changed = matches!(
            (old.metadata.frozen, new.metadata.frozen),
            (Some(left), Some(right)) if left != right
        );
        let content_changed_candidate = old.content.semantic_complete
            && new.content.semantic_complete
            && before_snapshot
                .claim_scope
                .samples_map(old.identity.id, old.metadata.map_type)
            && after_snapshot
                .claim_scope
                .samples_map(new.identity.id, new.metadata.map_type)
            && canonical_map_content(before_snapshot, old)
            && canonical_map_content(after_snapshot, new)
            && old.content.entries != new.content.entries;

        let metadata_changed = stable_metadata_changed || frozen_changed;
        if metadata_changed || content_changed_candidate {
            let inventory_reliable = before_reliability.reliable(ObjectType::Map, old.identity.id)
                && after_reliability.reliable(ObjectType::Map, old.identity.id);
            let metadata_confirmed = metadata_changed && inventory_reliable;
            let content_confirmed = content_changed_candidate
                && inventory_reliable
                && content_comparison_confirmable
                && old.content.status == MapSampleStatus::CompleteQuiescent
                && new.content.status == MapSampleStatus::CompleteQuiescent;
            changes.push(change(
                ChangeKind::Modified,
                "map",
                identity,
                Some(map_change_value(old)),
                Some(map_change_value(new)),
                attribution.clone(),
                certainty(metadata_confirmed || content_confirmed),
            ));
        }
    }
    for (identity, new) in &after {
        if !before.contains_key(identity) {
            changes.push(change(
                ChangeKind::Added,
                "map",
                identity,
                None,
                Some(map_change_value(new)),
                attribution.clone(),
                certainty(
                    before_reliability.reliable(ObjectType::Map, new.identity.id)
                        && after_reliability.reliable(ObjectType::Map, new.identity.id),
                ),
            ));
        }
    }
    Ok(())
}

/// Keep verdicts diagnostic without duplicating arbitrarily large canonical
/// Map entry arrays already preserved in S0/S1. The digest is validated against
/// those entries by the producer contract before this summary is constructed.
fn map_change_value(map: &MapState) -> Value {
    json!({
        "identity": &map.identity,
        "metadata": &map.metadata,
        "content": {
            "status": &map.content.status,
            "semantic_complete": map.content.semantic_complete,
            "digest_sha256": &map.content.digest_sha256,
            "entry_count": map.content.entries.len(),
            "bytes_read": map.content.bytes_read,
            "possible_cpu_ids": &map.content.possible_cpu_ids,
            "error": &map.content.error,
        },
        "excluded": map.excluded,
    })
}

fn visible_links(snapshot: &Snapshot) -> BTreeMap<String, &LinkState> {
    snapshot
        .links
        .iter()
        .filter(|link| !link.excluded)
        .map(|link| (object_key(&link.identity), link))
        .collect()
}

// Link target reliability is endpoint-specific in addition to inventory
// reliability, so both raw snapshots are required here.
#[allow(clippy::too_many_arguments)]
fn diff_links(
    before_snapshot: &Snapshot,
    after_snapshot: &Snapshot,
    before_reliability: &InventoryReliability<'_>,
    after_reliability: &InventoryReliability<'_>,
    before: BTreeMap<String, &LinkState>,
    after: BTreeMap<String, &LinkState>,
    attribution: Attribution,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    for (identity, old) in &before {
        let Some(new) = after.get(identity) else {
            changes.push(change(
                ChangeKind::Removed,
                "link",
                identity,
                Some(to_value(old)?),
                None,
                attribution.clone(),
                certainty(
                    before_reliability.reliable(ObjectType::Link, old.identity.id)
                        && after_reliability.reliable(ObjectType::Link, old.identity.id),
                ),
            ));
            continue;
        };
        if *old == *new {
            continue;
        }

        let core_changed = old.link_type != new.link_type || old.program_id != new.program_id;
        let target_changed = old.target != new.target;
        let inventories_reliable = before_reliability.reliable(ObjectType::Link, old.identity.id)
            && after_reliability.reliable(ObjectType::Link, new.identity.id);
        let target_change_reliable = target_changed
            && link_target_reliable(before_snapshot, old)
            && link_target_reliable(after_snapshot, new);
        changes.push(change(
            ChangeKind::Modified,
            "link",
            identity,
            Some(to_value(old)?),
            Some(to_value(new)?),
            attribution.clone(),
            certainty(inventories_reliable && (core_changed || target_change_reliable)),
        ));
    }
    for (identity, new) in &after {
        if !before.contains_key(identity) {
            changes.push(change(
                ChangeKind::Added,
                "link",
                identity,
                None,
                Some(to_value(new)?),
                attribution.clone(),
                certainty(
                    before_reliability.reliable(ObjectType::Link, new.identity.id)
                        && after_reliability.reliable(ObjectType::Link, new.identity.id),
                ),
            ));
        }
    }
    Ok(())
}

fn link_target_reliable(snapshot: &Snapshot, link: &LinkState) -> bool {
    link.target.is_some()
        && !snapshot.read_failures.iter().any(|failure| {
            failure.object_type == ObjectType::Link
                && (failure.id == 0 || failure.id == link.identity.id)
                && failure.operation.ends_with("-target-adapter")
        })
}

#[allow(clippy::too_many_arguments)]
fn diff_objects<T: serde::Serialize + PartialEq>(
    entity: &str,
    object_type: ObjectType,
    before_reliability: &InventoryReliability<'_>,
    after_reliability: &InventoryReliability<'_>,
    before: BTreeMap<String, &T>,
    after: BTreeMap<String, &T>,
    attribution: Attribution,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    for (identity, old) in &before {
        match after.get(identity) {
            None => changes.push(change(
                ChangeKind::Removed,
                entity,
                identity,
                Some(to_value(old)?),
                None,
                attribution.clone(),
                certainty(
                    before_reliability.reliable(object_type.clone(), object_id_from_key(identity))
                        && after_reliability
                            .reliable(object_type.clone(), object_id_from_key(identity)),
                ),
            )),
            Some(new) if *old != *new => changes.push(change(
                ChangeKind::Modified,
                entity,
                identity,
                Some(to_value(old)?),
                Some(to_value(new)?),
                attribution.clone(),
                certainty(
                    before_reliability.reliable(object_type.clone(), object_id_from_key(identity))
                        && after_reliability
                            .reliable(object_type.clone(), object_id_from_key(identity)),
                ),
            )),
            _ => {}
        }
    }
    for (identity, new) in &after {
        if !before.contains_key(identity) {
            changes.push(change(
                ChangeKind::Added,
                entity,
                identity,
                None,
                Some(to_value(new)?),
                attribution.clone(),
                certainty(
                    before_reliability.reliable(object_type.clone(), object_id_from_key(identity))
                        && after_reliability
                            .reliable(object_type.clone(), object_id_from_key(identity)),
                ),
            ));
        }
    }
    Ok(())
}

fn pin_key(pin: &PinState) -> String {
    format!(
        "{}:{}:{}",
        pin.mount_namespace_inode, pin.mount_id, pin.path_bytes_hex
    )
}

fn diff_pins(
    before_snapshot: &Snapshot,
    after_snapshot: &Snapshot,
    producer_contract_valid: bool,
    before: &[PinState],
    after: &[PinState],
    attribution: Attribution,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let left: BTreeMap<_, _> = before.iter().map(|pin| (pin_key(pin), pin)).collect();
    let right: BTreeMap<_, _> = after.iter().map(|pin| (pin_key(pin), pin)).collect();
    let reliable = producer_contract_valid
        && pin_inventory_reliable(before_snapshot)
        && pin_inventory_reliable(after_snapshot);
    for (identity, old) in &left {
        match right.get(identity) {
            None => changes.push(change(
                ChangeKind::Removed,
                "pin",
                identity,
                Some(to_value(old)?),
                None,
                attribution.clone(),
                certainty(reliable),
            )),
            Some(new) if *old != *new => changes.push(change(
                ChangeKind::Modified,
                "pin",
                identity,
                Some(to_value(old)?),
                Some(to_value(new)?),
                attribution.clone(),
                certainty(reliable),
            )),
            _ => {}
        }
    }
    for (identity, new) in &right {
        if !left.contains_key(identity) {
            changes.push(change(
                ChangeKind::Added,
                "pin",
                identity,
                None,
                Some(to_value(new)?),
                attribution.clone(),
                certainty(reliable),
            ));
        }
    }
    Ok(())
}

fn visible_pins(snapshot: &Snapshot) -> Vec<PinState> {
    snapshot
        .pins
        .iter()
        .filter(|pin| !pin.excluded)
        .cloned()
        .collect()
}

fn change(
    kind: ChangeKind,
    entity: &str,
    identity: &str,
    before: Option<Value>,
    after: Option<Value>,
    attribution: Attribution,
    certainty: ChangeCertainty,
) -> StateChange {
    let attribution = if certainty == ChangeCertainty::Confirmed {
        attribution
    } else {
        Attribution::UnattributedSystemChange
    };
    StateChange {
        kind,
        certainty,
        entity: entity.into(),
        identity: identity.into(),
        field: None,
        before,
        after,
        attribution,
        attribution_evidence: Vec::new(),
    }
}

fn certainty(confirmed: bool) -> ChangeCertainty {
    if confirmed {
        ChangeCertainty::Confirmed
    } else {
        ChangeCertainty::Indeterminate
    }
}

fn object_id_from_key(identity: &str) -> u32 {
    identity
        .rsplit(':')
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

struct InventoryReliability<'a> {
    snapshot: &'a Snapshot,
    globally_unreliable: BTreeSet<ObjectType>,
    unreliable_ids: BTreeSet<(ObjectType, u32)>,
}

impl<'a> InventoryReliability<'a> {
    fn new(snapshot: &'a Snapshot, producer_contract_valid: bool) -> Self {
        let mut result = Self {
            snapshot,
            globally_unreliable: BTreeSet::new(),
            unreliable_ids: BTreeSet::new(),
        };
        if !producer_contract_valid
            || snapshot.snapshot_id.is_empty()
            || snapshot.phase.is_empty()
            || snapshot.boot_id.is_empty()
            || snapshot.kernel_release.is_empty()
        {
            result.globally_unreliable.extend([
                ObjectType::Program,
                ObjectType::Map,
                ObjectType::Link,
            ]);
        }
        if diagnostics_were_truncated(snapshot) {
            result.globally_unreliable.extend([
                ObjectType::Program,
                ObjectType::Map,
                ObjectType::Link,
            ]);
        }
        for (object_type, marker) in [
            (
                ObjectType::Program,
                "program inventory changed during capture",
            ),
            (ObjectType::Map, "map inventory changed during capture"),
            (ObjectType::Link, "link inventory changed during capture"),
        ] {
            if snapshot
                .completeness
                .reasons
                .iter()
                .any(|reason| reason.contains(marker))
            {
                result.globally_unreliable.insert(object_type);
            }
        }

        if !inventory_is_canonical(
            snapshot,
            ObjectType::Program,
            snapshot
                .programs
                .iter()
                .map(|object| (&object.identity, object.excluded)),
        ) {
            result.globally_unreliable.insert(ObjectType::Program);
        }
        if !inventory_is_canonical(
            snapshot,
            ObjectType::Map,
            snapshot
                .maps
                .iter()
                .map(|object| (&object.identity, object.excluded)),
        ) {
            result.globally_unreliable.insert(ObjectType::Map);
        }
        if !inventory_is_canonical(
            snapshot,
            ObjectType::Link,
            snapshot
                .links
                .iter()
                .map(|object| (&object.identity, object.excluded)),
        ) {
            result.globally_unreliable.insert(ObjectType::Link);
        }

        for failure in &snapshot.read_failures {
            if failure.operation.ends_with("-enumerate")
                || failure.operation.ends_with("-get-fd")
                || failure.operation.ends_with("-get-info")
                || failure.operation.ends_with("-verify-id")
            {
                if failure.id == 0 {
                    result
                        .globally_unreliable
                        .insert(failure.object_type.clone());
                } else {
                    result
                        .unreliable_ids
                        .insert((failure.object_type.clone(), failure.id));
                }
            }
        }
        result
    }

    fn reliable(&self, object_type: ObjectType, id: u32) -> bool {
        id != 0
            && self
                .snapshot
                .claim_scope
                .object_types
                .contains(&object_type)
            && !self.globally_unreliable.contains(&object_type)
            && !self.unreliable_ids.contains(&(object_type.clone(), id))
            && !object_is_excluded(self.snapshot, &object_type, id)
    }
}

fn inventory_is_canonical<'a>(
    snapshot: &Snapshot,
    object_type: ObjectType,
    objects: impl Iterator<Item = (&'a ObjectIdentity, bool)>,
) -> bool {
    let mut previous = None;
    for (identity, excluded) in objects {
        if identity.boot_id != snapshot.boot_id
            || identity.object_type != object_type
            || identity.id == 0
            || previous.map(|id| id >= identity.id) == Some(true)
            || excluded != object_is_excluded(snapshot, &object_type, identity.id)
        {
            return false;
        }
        previous = Some(identity.id);
    }
    true
}

fn object_is_excluded(snapshot: &Snapshot, object_type: &ObjectType, id: u32) -> bool {
    match object_type {
        ObjectType::Program => snapshot.observer_exclusions.program_ids.contains(&id),
        ObjectType::Map => snapshot.observer_exclusions.map_ids.contains(&id),
        ObjectType::Link => snapshot.observer_exclusions.link_ids.contains(&id),
    }
}

fn pin_inventory_reliable(snapshot: &Snapshot) -> bool {
    !diagnostics_were_truncated(snapshot)
        && pins_structurally_valid(snapshot)
        && !snapshot
            .completeness
            .reasons
            .iter()
            .any(|reason| reason.contains("pin inventory changed during capture"))
        && !snapshot
            .read_failures
            .iter()
            .any(|failure| failure.operation.starts_with("pin-"))
}

fn diagnostics_were_truncated(snapshot: &Snapshot) -> bool {
    snapshot.completeness.reasons.iter().any(|reason| {
        reason.starts_with("read_failures was truncated at ")
            || reason == "additional incompleteness reasons omitted at configured limit"
    })
}

fn pins_structurally_valid(snapshot: &Snapshot) -> bool {
    if snapshot.claim_scope.bpffs_roots.is_empty() && !snapshot.pins.is_empty() {
        return false;
    }
    let mut identities = BTreeSet::new();
    let mut previous_key: Option<(u64, u64, &str)> = None;
    for pin in &snapshot.pins {
        let Ok(raw_path) = hex::decode(&pin.path_bytes_hex) else {
            return false;
        };
        let key = pin_key(pin);
        let sort_key = (
            pin.mount_namespace_inode,
            pin.mount_id,
            pin.path_bytes_hex.as_str(),
        );
        let expected_excluded = match pin.object_type {
            ObjectType::Program => snapshot
                .observer_exclusions
                .program_ids
                .contains(&pin.object_id),
            ObjectType::Map => snapshot
                .observer_exclusions
                .map_ids
                .contains(&pin.object_id),
            ObjectType::Link => snapshot
                .observer_exclusions
                .link_ids
                .contains(&pin.object_id),
        };
        if pin.object_id == 0
            || pin.mount_namespace_inode == 0
            || pin.mount_id == 0
            || !snapshot.claim_scope.object_types.contains(&pin.object_type)
            || raw_path.first() != Some(&b'/')
            || !snapshot
                .claim_scope
                .bpffs_roots
                .iter()
                .any(|root| path_is_within_root(&raw_path, root.as_bytes()))
            || !pin.path_bytes_hex.bytes().all(is_lower_hex)
            || pin.path != String::from_utf8_lossy(&raw_path)
            || pin.excluded != expected_excluded
            || !identities.insert(key.clone())
            || previous_key.map(|previous| previous >= sort_key) == Some(true)
        {
            return false;
        }
        previous_key = Some(sort_key);
    }
    true
}

fn path_is_within_root(path: &[u8], configured_root: &[u8]) -> bool {
    if !is_lexically_normal_absolute(path) || !is_lexically_normal_absolute(configured_root) {
        return false;
    }
    configured_root == b"/"
        || path == configured_root
        || (path.starts_with(configured_root) && path.get(configured_root.len()) == Some(&b'/'))
}

fn is_lexically_normal_absolute(path: &[u8]) -> bool {
    if path == b"/" {
        return true;
    }
    path.first() == Some(&b'/')
        && path.last() != Some(&b'/')
        && path[1..]
            .split(|byte| *byte == b'/')
            .all(|component| !component.is_empty() && component != b"." && component != b"..")
}

fn aggregate_attribution(changes: &[StateChange], state_verdict: &StateVerdict) -> Attribution {
    if changes.is_empty() {
        return if *state_verdict == StateVerdict::UnchangedWithinScope {
            Attribution::NoStateChange
        } else {
            Attribution::Unknown
        };
    }
    let workload = changes
        .iter()
        .filter(|change| change.attribution == Attribution::WorkloadAttributed)
        .count();
    if workload == changes.len() {
        Attribution::WorkloadAttributed
    } else if workload == 0 {
        Attribution::UnattributedSystemChange
    } else {
        Attribution::PartiallyAttributed
    }
}

fn evidence_completeness(health: &EvidenceHealth) -> Completeness {
    if health.is_complete() {
        return Completeness::complete();
    }
    let mut result = Completeness::complete();
    if !health.recorder_loaded {
        result.mark_incomplete("recorder load was not confirmed");
    }
    if !health.run_registered {
        result.mark_incomplete("run registration was not confirmed");
    }
    if !health.producer_barrier_complete {
        result.mark_incomplete("event producer barrier was not confirmed");
    }
    if !health.drain_completed {
        result.mark_incomplete("ring-buffer drain did not complete");
    }
    if !health.wal_durable {
        result.mark_incomplete("event WAL durability was not confirmed");
    }
    if !health.native_transport_canary_passed {
        result.mark_incomplete("native raw-syscall transport canary did not pass");
    }
    if health.syscall_attempted != health.syscall_completed {
        result.mark_incomplete(format!(
            "bpf syscall enter count {} differs from exit count {}",
            health.syscall_attempted, health.syscall_completed
        ));
    }
    if health
        .syscall_attempted
        .checked_add(health.syscall_completed)
        != Some(health.event_attempted)
    {
        result.mark_incomplete("event attempts do not equal syscall enter plus exit probes");
    }
    if health.last_event_seq != health.event_attempted {
        result.mark_incomplete(format!(
            "last event sequence {} differs from attempted event count {}",
            health.last_event_seq, health.event_attempted
        ));
    }
    if health.event_published.checked_add(health.event_dropped) != Some(health.event_attempted) {
        result.mark_incomplete("event accounting invariant failed");
    }
    if health.event_dropped > 0 {
        result.mark_incomplete(format!(
            "{} ring-buffer events were dropped",
            health.event_dropped
        ));
    }
    if health.event_published != health.events_persisted {
        result.mark_incomplete(format!(
            "published event count {} differs from persisted count {}",
            health.event_published, health.events_persisted
        ));
    }
    if health.pending_insert_failed > 0
        || health.pending_missing > 0
        || health.pending_remaining > 0
    {
        result.mark_incomplete("syscall entry/exit pairing was incomplete");
    }
    if health.parse_failed > 0 {
        result.mark_incomplete(format!("{} events failed to parse", health.parse_failed));
    }
    if !health.unsupported_commands.is_empty() {
        result.mark_incomplete(format!(
            "unsupported BPF commands observed: {:?}",
            health.unsupported_commands
        ));
    }
    for reason in &health.reasons {
        result.mark_incomplete(reason.clone());
    }
    if result.status == CompletenessStatus::Complete {
        result.mark_incomplete("evidence health failed an unspecified invariant");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use bpf_observer_schema::{
        Completeness, MapContentState, MapEntry, MapMetadata, MapState, ObjectReadFailure,
        ObjectType, PinRootIdentity, PinState, QuiescenceBasis, QuiescenceStatus, Snapshot,
        EXCLUSIVE_VM_V1_CHECKS, SCHEMA_VERSION,
    };

    fn snapshot(phase: &str) -> Snapshot {
        Snapshot {
            schema_version: SCHEMA_VERSION,
            snapshot_id: format!("snapshot-{phase}"),
            phase: phase.into(),
            boot_id: "boot".into(),
            captured_unix_ns: 0,
            capture_duration_ns: 0,
            kernel_release: "test".into(),
            byte_order: "little".into(),
            possible_cpu_ids: vec![0],
            claim_scope: ClaimScope::default(),
            observer_exclusions: Default::default(),
            programs: vec![],
            maps: vec![],
            links: vec![],
            pin_roots: vec![],
            pins: vec![],
            read_failures: vec![],
            completeness: Completeness::complete(),
            notes: vec![],
        }
    }

    fn unknown_quiescence() -> QuiescenceReport {
        QuiescenceReport {
            status: QuiescenceStatus::Unknown,
            basis: QuiescenceBasis::ObservedOnly,
            contract_id: None,
            checks: vec![],
            exclusive_actor_attribution: false,
            authentication: None,
        }
    }

    fn enforced_quiescence() -> QuiescenceReport {
        QuiescenceReport {
            status: QuiescenceStatus::QuiescentWithinModel,
            basis: QuiescenceBasis::HarnessEnforced,
            contract_id: Some("exclusive-vm-v1".into()),
            checks: EXCLUSIVE_VM_V1_CHECKS
                .iter()
                .map(|name| bpf_observer_schema::ContractCheck {
                    name: (*name).into(),
                    passed: true,
                    evidence: "fixture".into(),
                })
                .collect(),
            exclusive_actor_attribution: true,
            authentication: Some(serde_json::json!({"test_fixture": true})),
        }
    }

    fn healthy_evidence() -> EvidenceHealth {
        EvidenceHealth {
            recorder_loaded: true,
            run_registered: true,
            producer_barrier_complete: true,
            drain_completed: true,
            wal_durable: true,
            native_transport_canary_passed: true,
            ..EvidenceHealth::default()
        }
    }

    fn program(id: u32) -> ProgramState {
        ProgramState {
            identity: ObjectIdentity {
                boot_id: "boot".into(),
                object_type: ObjectType::Program,
                id,
            },
            program_type: 1,
            name: "new".into(),
            tag_hex: "0000000000000000".into(),
            load_time_ns: 1,
            created_by_uid: 0,
            btf_id: 0,
            attach_btf_obj_id: 0,
            attach_btf_id: 0,
            ifindex: 0,
            netns_dev: 0,
            netns_ino: 0,
            map_ids: vec![],
            excluded: false,
        }
    }

    fn complete_hash_map(entries: Vec<MapEntry>) -> MapState {
        let digest = digest_entries(&entries);
        MapState {
            identity: ObjectIdentity {
                boot_id: "boot".into(),
                object_type: ObjectType::Map,
                id: 7,
            },
            metadata: MapMetadata {
                map_type: 1,
                name: "map".into(),
                key_size: 1,
                value_size: 1,
                max_entries: 2,
                map_flags: 0,
                map_extra: 0,
                ifindex: 0,
                netns_dev: 0,
                netns_ino: 0,
                btf_id: 0,
                btf_key_type_id: 0,
                btf_value_type_id: 0,
                btf_vmlinux_value_type_id: 0,
                frozen: Some(false),
            },
            content: MapContentState {
                status: MapSampleStatus::CompleteQuiescent,
                semantic_complete: true,
                bytes_read: (entries.len() * 2) as u64,
                entries,
                digest_sha256: Some(digest),
                possible_cpu_ids: vec![],
                error: None,
            },
            excluded: false,
        }
    }

    fn link(target: Option<Value>) -> LinkState {
        LinkState {
            identity: ObjectIdentity {
                boot_id: "boot".into(),
                object_type: ObjectType::Link,
                id: 7,
            },
            link_type: 6,
            program_id: 8,
            target,
            excluded: false,
        }
    }

    #[test]
    fn empty_diff_without_contract_is_inconclusive() {
        let verdict = compare(
            &snapshot("S0"),
            &snapshot("S1"),
            &EvidenceHealth::default(),
            unknown_quiescence(),
        )
        .unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::Inconclusive);
        assert_eq!(verdict.attribution, Attribution::Unknown);
    }

    #[test]
    fn object_addition_is_changed_even_if_evidence_is_incomplete() {
        let before = snapshot("S0");
        let mut after = snapshot("S1");
        after.programs.push(program(7));
        let health = EvidenceHealth {
            last_event_seq: 1,
            event_attempted: 1,
            event_dropped: 1,
            ..EvidenceHealth::default()
        };
        let verdict = compare(&before, &after, &health, unknown_quiescence()).unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::ChangedWithinScope);
        assert_eq!(
            verdict.evidence_status.status,
            CompletenessStatus::Incomplete
        );
    }

    #[test]
    fn syscall_pairing_mismatch_is_incomplete() {
        let health = EvidenceHealth {
            syscall_attempted: 1,
            ..EvidenceHealth::default()
        };
        let verdict = compare(
            &snapshot("S0"),
            &snapshot("S1"),
            &health,
            unknown_quiescence(),
        )
        .unwrap();
        assert_eq!(
            verdict.evidence_status.status,
            CompletenessStatus::Incomplete
        );
    }

    #[test]
    fn incomplete_health_forbids_unchanged_in_library_api() {
        let verdict = compare(
            &snapshot("S0"),
            &snapshot("S1"),
            &EvidenceHealth::default(),
            enforced_quiescence(),
        )
        .unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::Inconclusive);
        assert_eq!(verdict.attribution, Attribution::Unknown);
    }

    #[test]
    fn incomplete_snapshot_status_without_reasons_forbids_unchanged() {
        let mut before = snapshot("S0");
        before.completeness.status = CompletenessStatus::Incomplete;
        let verdict = compare(
            &before,
            &snapshot("S1"),
            &healthy_evidence(),
            enforced_quiescence(),
        )
        .unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::Inconclusive);
    }

    #[test]
    fn complete_snapshot_cannot_hide_reasons_or_empty_cpu_topology() {
        let mut before = snapshot("S0");
        before.completeness.reasons.push("hidden failure".into());
        let verdict = compare(
            &before,
            &snapshot("S1"),
            &healthy_evidence(),
            enforced_quiescence(),
        )
        .unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::Inconclusive);

        let mut before = snapshot("S0");
        before.possible_cpu_ids.clear();
        let verdict = compare(
            &before,
            &snapshot("S1"),
            &healthy_evidence(),
            enforced_quiescence(),
        )
        .unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::Inconclusive);
    }

    #[test]
    fn enumeration_failure_makes_apparent_addition_indeterminate() {
        let mut before = snapshot("S0");
        before
            .completeness
            .mark_incomplete("program enumeration failed");
        before.read_failures.push(ObjectReadFailure {
            object_type: ObjectType::Program,
            id: 0,
            operation: "first-enumerate".into(),
            error: "permission denied".into(),
        });
        let mut after = snapshot("S1");
        after.programs.push(program(7));
        let verdict = compare(&before, &after, &healthy_evidence(), enforced_quiescence()).unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::Inconclusive);
        assert_eq!(verdict.changes.len(), 1);
        assert_eq!(verdict.changes[0].certainty, ChangeCertainty::Indeterminate);
    }

    #[test]
    fn truncated_diagnostics_make_apparent_addition_indeterminate() {
        let mut before = snapshot("S0");
        before
            .completeness
            .mark_incomplete("read_failures was truncated at 4096 records");
        let mut after = snapshot("S1");
        after.programs.push(program(7));
        let verdict = compare(&before, &after, &healthy_evidence(), enforced_quiescence()).unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::Inconclusive);
        assert_eq!(verdict.changes.len(), 1);
        assert_eq!(verdict.changes[0].certainty, ChangeCertainty::Indeterminate);
    }

    #[test]
    fn explicit_map_scope_cannot_be_silently_excluded() {
        let mut before = snapshot("S0");
        before.claim_scope.map_ids.insert(7);
        before.observer_exclusions.map_ids.insert(7);
        let mut after = snapshot("S1");
        after.claim_scope = before.claim_scope.clone();
        after.observer_exclusions = before.observer_exclusions.clone();
        let verdict = compare(&before, &after, &healthy_evidence(), enforced_quiescence()).unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::Inconclusive);
        assert_eq!(
            verdict.state_completeness.status,
            CompletenessStatus::Incomplete
        );
    }

    #[test]
    fn missing_link_target_cannot_manufacture_confirmed_change() {
        let mut before = snapshot("S0");
        before.links.push(link(Some(serde_json::json!({
            "kind": "XDP",
            "ifindex": 2
        }))));
        let mut after = snapshot("S1");
        after.links.push(link(None));
        after
            .completeness
            .mark_incomplete("one or more object or pin reads failed; see read_failures");
        after.read_failures.push(ObjectReadFailure {
            object_type: ObjectType::Link,
            id: 7,
            operation: "initial-target-adapter".into(),
            error: "target unavailable".into(),
        });

        let verdict = compare(&before, &after, &healthy_evidence(), enforced_quiescence()).unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::Inconclusive);
        assert_eq!(verdict.changes.len(), 1);
        assert_eq!(verdict.changes[0].certainty, ChangeCertainty::Indeterminate);
    }

    #[test]
    fn reliable_link_core_change_remains_confirmed_when_target_is_missing() {
        let mut before = snapshot("S0");
        before.programs = vec![program(8), program(9)];
        before.links.push(link(Some(serde_json::json!({
            "kind": "XDP",
            "ifindex": 2
        }))));
        let mut after = snapshot("S1");
        after.programs = before.programs.clone();
        let mut changed = link(None);
        changed.program_id = 9;
        after.links.push(changed);
        after
            .completeness
            .mark_incomplete("one or more object or pin reads failed; see read_failures");
        after.read_failures.push(ObjectReadFailure {
            object_type: ObjectType::Link,
            id: 7,
            operation: "initial-target-adapter".into(),
            error: "target unavailable".into(),
        });

        let verdict = compare(&before, &after, &healthy_evidence(), enforced_quiescence()).unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::ChangedWithinScope);
        assert_eq!(verdict.changes.len(), 1);
        assert_eq!(verdict.changes[0].certainty, ChangeCertainty::Confirmed);
    }

    #[test]
    fn fully_complete_bound_inputs_can_represent_unchanged() {
        let verdict = compare(
            &snapshot("S0"),
            &snapshot("S1"),
            &healthy_evidence(),
            enforced_quiescence(),
        )
        .unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::UnchangedWithinScope);
        assert_eq!(verdict.attribution, Attribution::NoStateChange);
    }

    #[test]
    fn empty_object_scope_cannot_represent_unchanged() {
        let mut before = snapshot("S0");
        before.claim_scope.object_types.clear();
        let mut after = snapshot("S1");
        after.claim_scope = before.claim_scope.clone();

        let verdict = compare(&before, &after, &healthy_evidence(), enforced_quiescence()).unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::Inconclusive);
        assert_eq!(
            verdict.state_completeness.status,
            CompletenessStatus::Incomplete
        );
        assert_eq!(
            verdict.evidence_status.status,
            CompletenessStatus::Incomplete
        );
    }

    #[test]
    fn unsupported_event_interface_cannot_represent_unchanged() {
        let mut before = snapshot("S0");
        before.claim_scope.event_interfaces = BTreeSet::from(["CUSTOM_HOOK".into()]);
        let mut after = snapshot("S1");
        after.claim_scope = before.claim_scope.clone();

        let verdict = compare(&before, &after, &healthy_evidence(), enforced_quiescence()).unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::Inconclusive);
        assert_eq!(
            verdict.state_completeness.status,
            CompletenessStatus::Incomplete
        );
        assert_eq!(
            verdict.evidence_status.status,
            CompletenessStatus::Incomplete
        );
    }

    #[test]
    fn changed_pin_observation_domain_cannot_represent_unchanged() {
        let mut before = snapshot("S0");
        before.claim_scope.bpffs_roots = vec!["/sys/fs/bpf".into()];
        before.programs = vec![program(7)];
        before.pin_roots = vec![PinRootIdentity {
            path: "/sys/fs/bpf".into(),
            mount_namespace_inode: 10,
            mount_id: 20,
        }];
        before.pins = vec![PinState {
            path: "/sys/fs/bpf/program".into(),
            path_bytes_hex: hex::encode(b"/sys/fs/bpf/program"),
            mount_namespace_inode: 10,
            mount_id: 20,
            object_type: ObjectType::Program,
            object_id: 7,
            excluded: false,
        }];
        let mut after = snapshot("S1");
        after.claim_scope = before.claim_scope.clone();
        after.programs = before.programs.clone();
        after.pin_roots = vec![PinRootIdentity {
            path: "/sys/fs/bpf".into(),
            mount_namespace_inode: 11,
            mount_id: 21,
        }];
        after.pins = vec![PinState {
            path: "/sys/fs/bpf/program".into(),
            path_bytes_hex: hex::encode(b"/sys/fs/bpf/program"),
            mount_namespace_inode: 11,
            mount_id: 21,
            object_type: ObjectType::Program,
            object_id: 7,
            excluded: false,
        }];

        let verdict = compare(&before, &after, &healthy_evidence(), enforced_quiescence()).unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::Inconclusive);
        assert_eq!(
            verdict.state_completeness.status,
            CompletenessStatus::Incomplete
        );
        assert_eq!(verdict.changes.len(), 2);
        assert!(verdict
            .changes
            .iter()
            .all(|change| change.certainty == ChangeCertainty::Indeterminate));
    }

    #[test]
    fn content_only_map_delta_without_enforced_quiescence_is_indeterminate() {
        let mut before = snapshot("S0");
        before
            .claim_scope
            .map_content_types
            .insert(bpf_observer_schema::MapContentType::Hash);
        before.maps = vec![complete_hash_map(vec![MapEntry {
            key_hex: "00".into(),
            values_hex: vec!["01".into()],
        }])];
        let mut after = snapshot("S1");
        after.claim_scope = before.claim_scope.clone();
        after.maps = vec![complete_hash_map(vec![MapEntry {
            key_hex: "00".into(),
            values_hex: vec!["02".into()],
        }])];

        let verdict = compare(&before, &after, &healthy_evidence(), unknown_quiescence()).unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::Inconclusive);
        assert_eq!(verdict.changes.len(), 1);
        assert_eq!(verdict.changes[0].kind, ChangeKind::Modified);
        assert_eq!(verdict.changes[0].certainty, ChangeCertainty::Indeterminate);
        let before_summary = verdict.changes[0].before.as_ref().unwrap();
        assert_eq!(before_summary["content"]["entry_count"], 1);
        assert!(before_summary["content"].get("entries").is_none());
    }

    #[test]
    fn stable_map_metadata_delta_remains_confirmed_without_quiescence() {
        let entries = vec![MapEntry {
            key_hex: "00".into(),
            values_hex: vec!["01".into()],
        }];
        let mut before = snapshot("S0");
        before
            .claim_scope
            .map_content_types
            .insert(bpf_observer_schema::MapContentType::Hash);
        before.maps = vec![complete_hash_map(entries.clone())];
        let mut after = snapshot("S1");
        after.claim_scope = before.claim_scope.clone();
        after.maps = vec![complete_hash_map(entries)];
        after.maps[0].metadata.name = "renamed".into();

        let verdict = compare(&before, &after, &healthy_evidence(), unknown_quiescence()).unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::ChangedWithinScope);
        assert_eq!(verdict.changes.len(), 1);
        assert_eq!(verdict.changes[0].kind, ChangeKind::Modified);
        assert_eq!(verdict.changes[0].certainty, ChangeCertainty::Confirmed);
    }

    #[test]
    fn noncanonical_map_order_cannot_manufacture_a_confirmed_change() {
        let entry_zero = MapEntry {
            key_hex: "00".into(),
            values_hex: vec!["01".into()],
        };
        let entry_one = MapEntry {
            key_hex: "01".into(),
            values_hex: vec!["02".into()],
        };
        let mut before = snapshot("S0");
        before
            .claim_scope
            .map_content_types
            .insert(bpf_observer_schema::MapContentType::Hash);
        before.maps = vec![complete_hash_map(vec![
            entry_zero.clone(),
            entry_one.clone(),
        ])];
        let mut after = snapshot("S1");
        after.claim_scope = before.claim_scope.clone();
        after.maps = vec![complete_hash_map(vec![entry_one, entry_zero])];
        let verdict = compare(&before, &after, &healthy_evidence(), enforced_quiescence()).unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::Inconclusive);
        assert!(verdict.changes.is_empty());
    }

    #[test]
    fn opaque_btf_map_content_cannot_manufacture_a_confirmed_change() {
        let before_entry = MapEntry {
            key_hex: "00".into(),
            values_hex: vec!["01".into()],
        };
        let after_entry = MapEntry {
            key_hex: "00".into(),
            values_hex: vec!["02".into()],
        };
        let mut before = snapshot("S0");
        before
            .claim_scope
            .map_content_types
            .insert(bpf_observer_schema::MapContentType::Hash);
        before.maps = vec![complete_hash_map(vec![before_entry])];
        before.maps[0].metadata.btf_vmlinux_value_type_id = 1;
        let mut after = snapshot("S1");
        after.claim_scope = before.claim_scope.clone();
        after.maps = vec![complete_hash_map(vec![after_entry])];
        after.maps[0].metadata.btf_vmlinux_value_type_id = 1;

        let verdict = compare(&before, &after, &healthy_evidence(), enforced_quiescence()).unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::Inconclusive);
        assert!(verdict.changes.is_empty());
    }

    #[test]
    fn out_of_scope_pin_cannot_manufacture_a_confirmed_change() {
        let mut before = snapshot("S0");
        before.claim_scope.object_types = BTreeSet::from([ObjectType::Program]);
        before.claim_scope.bpffs_roots = vec!["/sys/fs/bpf/scoped".into()];
        let mut after = snapshot("S1");
        after.claim_scope = before.claim_scope.clone();
        after.pins.push(PinState {
            path: "/outside".into(),
            path_bytes_hex: hex::encode(b"/outside"),
            mount_namespace_inode: 1,
            mount_id: 1,
            object_type: ObjectType::Program,
            object_id: 7,
            excluded: false,
        });
        let verdict = compare(&before, &after, &healthy_evidence(), enforced_quiescence()).unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::Inconclusive);
        assert_eq!(verdict.changes[0].certainty, ChangeCertainty::Indeterminate);
    }

    #[test]
    fn dotdot_pin_cannot_escape_the_declared_root() {
        let mut before = snapshot("S0");
        before.claim_scope.object_types = BTreeSet::from([ObjectType::Program]);
        before.claim_scope.bpffs_roots = vec!["/sys/fs/bpf/scoped".into()];
        let mut after = snapshot("S1");
        after.claim_scope = before.claim_scope.clone();
        let path = "/sys/fs/bpf/scoped/../escape";
        after.pins.push(PinState {
            path: path.into(),
            path_bytes_hex: hex::encode(path.as_bytes()),
            mount_namespace_inode: 1,
            mount_id: 1,
            object_type: ObjectType::Program,
            object_id: 7,
            excluded: false,
        });
        let verdict = compare(&before, &after, &healthy_evidence(), enforced_quiescence()).unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::Inconclusive);
        assert_eq!(verdict.changes[0].certainty, ChangeCertainty::Indeterminate);
    }

    #[test]
    fn invalid_scope_cannot_leave_a_pin_delta_confirmed() {
        let mut before = snapshot("S0");
        before.claim_scope.event_interfaces.clear();
        before.claim_scope.object_types = BTreeSet::from([ObjectType::Program]);
        before.claim_scope.bpffs_roots = vec!["/sys/fs/bpf/scoped".into()];
        let mut after = snapshot("S1");
        after.claim_scope = before.claim_scope.clone();
        let path = "/sys/fs/bpf/scoped/pin";
        after.pins.push(PinState {
            path: path.into(),
            path_bytes_hex: hex::encode(path.as_bytes()),
            mount_namespace_inode: 1,
            mount_id: 1,
            object_type: ObjectType::Program,
            object_id: 7,
            excluded: false,
        });
        let verdict = compare(&before, &after, &healthy_evidence(), enforced_quiescence()).unwrap();
        assert_eq!(verdict.state_verdict, StateVerdict::Inconclusive);
        assert_eq!(verdict.changes.len(), 1);
        assert_eq!(verdict.changes[0].certainty, ChangeCertainty::Indeterminate);
    }

    #[test]
    fn generic_comparison_binds_all_recovery_phase_pairs() {
        for (before_phase, after_phase) in [("A", "B"), ("B", "C"), ("A", "C")] {
            let verdict = compare_phases(
                &snapshot(before_phase),
                &snapshot(after_phase),
                before_phase,
                after_phase,
                &EvidenceHealth::default(),
                unknown_quiescence(),
            )
            .expect("compare recovery phase pair");
            assert!(verdict.limitations.iter().any(|limitation| {
                limitation.starts_with(&format!("{before_phase}/{after_phase} comparison"))
            }));
        }
    }

    #[test]
    fn generic_comparison_rejects_same_or_misbound_phases() {
        assert!(compare_phases(
            &snapshot("A"),
            &snapshot("B"),
            "A",
            "A",
            &EvidenceHealth::default(),
            unknown_quiescence(),
        )
        .is_err());
        assert!(compare_phases(
            &snapshot("A"),
            &snapshot("B"),
            "B",
            "C",
            &EvidenceHealth::default(),
            unknown_quiescence(),
        )
        .is_err());
    }

    #[test]
    fn generic_comparison_uses_dynamic_phase_completeness_labels() {
        let mut before = snapshot("B");
        before.completeness.mark_incomplete("fixture failure");
        let verdict = compare_phases(
            &before,
            &snapshot("C"),
            "B",
            "C",
            &EvidenceHealth::default(),
            unknown_quiescence(),
        )
        .expect("compare incomplete recovery phase pair");
        assert!(verdict
            .state_completeness
            .reasons
            .iter()
            .any(|reason| reason == "B: fixture failure"));
        assert!(!verdict
            .state_completeness
            .reasons
            .iter()
            .any(|reason| reason.starts_with("S0:")));
    }
}
