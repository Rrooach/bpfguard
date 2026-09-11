// SPDX-License-Identifier: GPL-2.0-only

//! A deliberately conservative, read-only BPF state sampler.
//!
//! Kernel and permission failures are represented in [`Snapshot::completeness`]
//! and [`Snapshot::read_failures`].  They are not converted into an empty
//! inventory, because an empty inventory is a valid state with a very different
//! meaning.

use anyhow::{anyhow, bail, Context, Result};
use bpf_observer_schema::{
    ClaimScope, Completeness, CompletenessStatus, LinkState, MapContentState, MapContentType,
    MapEntry, MapMetadata, MapSampleStatus, MapState, ObjectExclusions, ObjectIdentity,
    ObjectReadFailure, ObjectType, PinRootIdentity, PinState, ProgramState, Snapshot,
    SCHEMA_VERSION,
};
use libc::{c_int, c_void};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::ptr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BPF_FS_MAGIC: libc::c_long = 0xcafe4a11u32 as libc::c_long;
const HASH_BATCH_SIZE: usize = 64;
const MAX_CONFIGURED_MAP_ENTRIES: u64 = 65_536;
const MAX_CONFIGURED_MAP_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CONFIGURED_MAP_DEADLINE_MS: u64 = 60_000;
const MAX_INVENTORY_IDS_PER_TYPE: usize = 65_536;
const MAX_TOTAL_PROGRAM_MAP_REFS: usize = 262_144;
const MAX_TOTAL_SAMPLED_MAP_ENTRIES: u64 = 131_072;
const MAX_TOTAL_SAMPLED_MAP_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TOTAL_MAP_SAMPLING_MS: u64 = 60_000;
const MAX_PIN_WALK_ITEMS: usize = 65_536;
const MAX_PIN_REPRESENTATION_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_RETAINED_MAP_REPRESENTATION_BYTES: u64 = 64 * 1024 * 1024;
const MAX_POSSIBLE_CPUS: usize = 8_192;
const MAX_SCOPE_EVENT_INTERFACES: usize = 16;
const MAX_SCOPE_BPF_COMMANDS: usize = 256;
const MAX_SCOPE_MAP_IDS: usize = 65_536;
const MAX_SCOPE_BPFFS_ROOTS: usize = 64;
const MAX_SCOPE_PATH_BYTES: usize = 4_096;
const MAX_SCOPE_ATTACHMENT_TARGETS: usize = 256;
const MAX_SCOPE_ATTACHMENT_JSON_BYTES: usize = 1024 * 1024;
const MAX_SNAPSHOT_REASONS: usize = 4_096;
const MAX_SNAPSHOT_NOTES: usize = 4_096;
const MAX_DIAGNOSTIC_STRING_BYTES: usize = 64 * 1024;
const MAX_DIAGNOSTIC_TEXT_BYTES: usize = 8 * 1024 * 1024;
const MAX_RECORDED_READ_FAILURES: usize = 4_096;
const MAX_SNAPSHOT_ID_BYTES: usize = 128;
const MAX_PHASE_BYTES: usize = 32;
const MAX_BOOT_ID_BYTES: usize = 128;
const MAX_KERNEL_RELEASE_BYTES: usize = 256;
// A 16-byte kernel object name can expand under UTF-8 lossy rendering.
const MAX_OBJECT_NAME_BYTES: usize = 64;

#[derive(Clone, Copy, Debug)]
struct RemainingContentBudget {
    entries: u64,
    logical_bytes: u64,
    representation_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct CaptureOptions {
    pub snapshot_id: String,
    pub phase: String,
    pub exclusions: ObjectExclusions,
    /// This is an assertion made by the trusted harness, not something the
    /// Oracle can prove by reading a map.  It only controls the status label;
    /// structural sampling completeness is tracked separately.
    pub maps_quiescent: bool,
}

impl Default for CaptureOptions {
    fn default() -> Self {
        Self {
            snapshot_id: String::new(),
            phase: "UNSPECIFIED".into(),
            exclusions: ObjectExclusions::default(),
            maps_quiescent: false,
        }
    }
}

/// Capture one scoped endpoint snapshot.
///
/// Fundamental local setup failures are returned as `Err`.  Enumeration and
/// individual object failures remain data in the returned snapshot so callers
/// can safely produce `INCONCLUSIVE` rather than mistake failure for absence.
pub fn capture(scope: &ClaimScope, options: &CaptureOptions) -> Result<Snapshot> {
    validate_claim_scope(scope)?;
    validate_claim_scope_exclusions(scope, &options.exclusions)?;
    let started = Instant::now();
    let captured_unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_nanos();
    let boot_id =
        read_required_trimmed("/proc/sys/kernel/random/boot_id").context("read kernel boot ID")?;
    let kernel_release = kernel_release().context("read kernel release")?;

    let mut completeness = Completeness::complete();
    let mut failures = Vec::new();
    let mut notes = Vec::new();
    let possible_cpu_ids = match possible_cpu_ids() {
        Ok(ids) if ids.len() <= MAX_POSSIBLE_CPUS => ids,
        Ok(ids) => {
            completeness.mark_incomplete(format!(
                "CPU topology has {} entries, exceeding hard limit {MAX_POSSIBLE_CPUS}",
                ids.len()
            ));
            Vec::new()
        }
        Err(error) => {
            completeness.mark_incomplete(format!("CPU topology unavailable: {error:#}"));
            Vec::new()
        }
    };

    let programs = if scope.object_types.contains(&ObjectType::Program) {
        capture_programs(
            &boot_id,
            &options.exclusions,
            &mut failures,
            &mut completeness,
            "initial",
        )
    } else {
        Vec::new()
    };

    let mut maps = if scope.object_types.contains(&ObjectType::Map) {
        capture_maps(
            &boot_id,
            scope,
            options,
            &possible_cpu_ids,
            &mut failures,
            &mut completeness,
            true,
            None,
            "initial",
        )
    } else {
        Vec::new()
    };

    let mut links = if scope.object_types.contains(&ObjectType::Link) {
        capture_links(
            &boot_id,
            &options.exclusions,
            &mut failures,
            &mut completeness,
            None,
            "initial",
        )
    } else {
        Vec::new()
    };

    let pin_capture = capture_pins(
        scope,
        &options.exclusions,
        &mut failures,
        &mut completeness,
        &mut notes,
    );
    let initial_map_ids = maps
        .iter()
        .map(|map| map.identity.id)
        .collect::<BTreeSet<_>>();
    let initial_link_ids = links
        .iter()
        .map(|link| link.identity.id)
        .collect::<BTreeSet<_>>();

    // A second metadata inventory brackets content and pin sampling.  Equality
    // lowers the risk of accidental concurrent mutation, but is intentionally
    // not described as an atomic snapshot or as protection against ABA.
    let verify_programs = if scope.object_types.contains(&ObjectType::Program) {
        capture_programs(
            &boot_id,
            &options.exclusions,
            &mut failures,
            &mut completeness,
            "verification",
        )
    } else {
        Vec::new()
    };
    let verify_maps = if scope.object_types.contains(&ObjectType::Map) {
        capture_maps(
            &boot_id,
            scope,
            options,
            &possible_cpu_ids,
            &mut failures,
            &mut completeness,
            false,
            Some(&initial_map_ids),
            "verification",
        )
    } else {
        Vec::new()
    };
    let verify_links = if scope.object_types.contains(&ObjectType::Link) {
        capture_links(
            &boot_id,
            &options.exclusions,
            &mut failures,
            &mut completeness,
            Some(&initial_link_ids),
            "verification",
        )
    } else {
        Vec::new()
    };
    let verify_pin_capture = capture_pins(
        scope,
        &options.exclusions,
        &mut failures,
        &mut completeness,
        &mut notes,
    );

    if programs != verify_programs {
        completeness.mark_incomplete("program inventory changed during capture");
    }
    if map_metadata_view(&maps) != map_metadata_view(&verify_maps) {
        completeness.mark_incomplete("map inventory changed during capture");
        mark_maps_concurrent(&mut maps);
    }
    if links != verify_links {
        completeness.mark_incomplete("link inventory changed during capture");
    }
    if pin_capture != verify_pin_capture {
        completeness.mark_incomplete("pin inventory changed during capture");
    }

    // Optional fields that failed during the authoritative (initial) pass are
    // represented as missing in the persisted object as well as in diagnostics.
    // This makes the producer contract bidirectional: a field-specific failure
    // can never be injected beside an apparently successful field value.
    let frozen_failure_ids = failures
        .iter()
        .filter(|failure| failure.operation == "initial-read-fdinfo-frozen")
        .map(|failure| failure.id)
        .collect::<BTreeSet<_>>();
    for map in &mut maps {
        if frozen_failure_ids.contains(&map.identity.id) {
            map.metadata.frozen = None;
        }
    }
    let target_failure_ids = failures
        .iter()
        .filter(|failure| failure.operation == "initial-target-adapter")
        .map(|failure| failure.id)
        .collect::<BTreeSet<_>>();
    for link in &mut links {
        if target_failure_ids.contains(&link.identity.id) {
            link.target = None;
        }
    }

    failures.sort_by(|left, right| {
        (&left.object_type, left.id, &left.operation, &left.error).cmp(&(
            &right.object_type,
            right.id,
            &right.operation,
            &right.error,
        ))
    });
    notes.sort();
    notes.dedup();

    let snapshot_id = if options.snapshot_id.is_empty() {
        format!("{}-{captured_unix_ns}", options.phase)
    } else {
        options.snapshot_id.clone()
    };

    let snapshot = Snapshot {
        schema_version: SCHEMA_VERSION,
        snapshot_id,
        phase: options.phase.clone(),
        boot_id,
        captured_unix_ns,
        capture_duration_ns: started.elapsed().as_nanos(),
        kernel_release,
        byte_order: if cfg!(target_endian = "little") {
            "little".into()
        } else {
            "big".into()
        },
        possible_cpu_ids,
        claim_scope: scope.clone(),
        observer_exclusions: options.exclusions.clone(),
        programs,
        maps,
        links,
        pin_roots: pin_capture.roots,
        pins: pin_capture.pins,
        read_failures: failures,
        completeness,
        notes,
    };
    validate_snapshot_resource_bounds(&snapshot)
        .context("captured snapshot violates the producer contract")?;
    Ok(snapshot)
}

/// Validate that a deserialized snapshot could have been emitted by this
/// producer without bypassing its resource and canonicalization contracts.
///
/// This is intentionally read-only and performs no kernel access.  Consumers
/// must call it before comparing persisted snapshots: a JSON byte-size limit
/// alone does not prevent oversized nested collections or non-canonical state
/// from being used as evidence.
pub fn validate_snapshot_resource_bounds(snapshot: &Snapshot) -> Result<()> {
    if snapshot.schema_version != SCHEMA_VERSION {
        bail!(
            "unsupported snapshot schema version {}",
            snapshot.schema_version
        );
    }
    if snapshot.snapshot_id.is_empty()
        || snapshot.snapshot_id.len() > MAX_SNAPSHOT_ID_BYTES
        || snapshot.phase.is_empty()
        || snapshot.phase.len() > MAX_PHASE_BYTES
        || snapshot.boot_id.is_empty()
        || snapshot.boot_id.len() > MAX_BOOT_ID_BYTES
        || snapshot.kernel_release.is_empty()
        || snapshot.kernel_release.len() > MAX_KERNEL_RELEASE_BYTES
    {
        bail!("snapshot has an empty producer identity field");
    }
    validate_claim_scope(&snapshot.claim_scope).context("snapshot claim scope")?;
    validate_claim_scope_exclusions(&snapshot.claim_scope, &snapshot.observer_exclusions)
        .context("snapshot claim scope exclusions")?;
    validate_cpu_ids(&snapshot.possible_cpu_ids, "snapshot possible_cpu_ids")?;
    if snapshot.possible_cpu_ids.is_empty()
        && snapshot.completeness.status == CompletenessStatus::Complete
    {
        bail!("a COMPLETE snapshot has an empty possible CPU topology");
    }
    if snapshot.byte_order != "little" && snapshot.byte_order != "big" {
        bail!("snapshot byte_order must be little or big");
    }

    ensure_collection_limit(
        "program inventory",
        snapshot.programs.len(),
        MAX_INVENTORY_IDS_PER_TYPE,
    )?;
    ensure_collection_limit(
        "Map inventory",
        snapshot.maps.len(),
        MAX_INVENTORY_IDS_PER_TYPE,
    )?;
    ensure_collection_limit(
        "link inventory",
        snapshot.links.len(),
        MAX_INVENTORY_IDS_PER_TYPE,
    )?;
    ensure_collection_limit(
        "pin root inventory",
        snapshot.pin_roots.len(),
        MAX_SCOPE_BPFFS_ROOTS,
    )?;
    ensure_collection_limit("pin inventory", snapshot.pins.len(), MAX_PIN_WALK_ITEMS)?;
    for (name, ids) in [
        (
            "program exclusions",
            &snapshot.observer_exclusions.program_ids,
        ),
        ("Map exclusions", &snapshot.observer_exclusions.map_ids),
        ("link exclusions", &snapshot.observer_exclusions.link_ids),
    ] {
        ensure_collection_limit(name, ids.len(), MAX_INVENTORY_IDS_PER_TYPE)?;
        if ids.contains(&0) {
            bail!("{name} contains a zero object ID");
        }
    }

    validate_object_ids(
        "program inventory",
        snapshot.programs.iter().map(|program| &program.identity),
        ObjectType::Program,
        &snapshot.boot_id,
    )?;
    validate_object_ids(
        "Map inventory",
        snapshot.maps.iter().map(|map| &map.identity),
        ObjectType::Map,
        &snapshot.boot_id,
    )?;
    validate_object_ids(
        "link inventory",
        snapshot.links.iter().map(|link| &link.identity),
        ObjectType::Link,
        &snapshot.boot_id,
    )?;

    if snapshot.completeness.status == CompletenessStatus::Complete {
        validate_complete_reference_closure(snapshot)?;
    }

    let mut total_program_map_refs = 0usize;
    for program in &snapshot.programs {
        if !snapshot
            .claim_scope
            .object_types
            .contains(&ObjectType::Program)
        {
            bail!("program inventory is present outside the claim scope");
        }
        if program.excluded
            != snapshot
                .observer_exclusions
                .program_ids
                .contains(&program.identity.id)
        {
            bail!(
                "PROGRAM {} has a non-canonical excluded flag",
                program.identity.id
            );
        }
        ensure_collection_limit(
            "program map_ids",
            program.map_ids.len(),
            MAX_INVENTORY_IDS_PER_TYPE,
        )?;
        total_program_map_refs = total_program_map_refs
            .checked_add(program.map_ids.len())
            .ok_or_else(|| anyhow!("snapshot-wide Program-to-Map reference count overflow"))?;
        if total_program_map_refs > MAX_TOTAL_PROGRAM_MAP_REFS {
            bail!(
                "snapshot contains {total_program_map_refs} Program-to-Map references, exceeding {MAX_TOTAL_PROGRAM_MAP_REFS}"
            );
        }
        validate_strictly_increasing_nonzero(&program.map_ids, "program map_ids")?;
        validate_fixed_hex(&program.tag_hex, 8, "program tag")?;
        if program.name.len() > MAX_OBJECT_NAME_BYTES {
            bail!("PROGRAM {} has an oversized name", program.identity.id);
        }
    }

    let read_failures_truncated = snapshot
        .completeness
        .reasons
        .iter()
        .any(|reason| reason.starts_with("read_failures was truncated at "));
    let map_frozen_failure_ids = snapshot
        .read_failures
        .iter()
        .filter(|failure| {
            failure.object_type == ObjectType::Map
                && failure.operation == "initial-read-fdinfo-frozen"
        })
        .map(|failure| failure.id)
        .collect::<BTreeSet<_>>();

    let mut total_entries = 0u64;
    let mut total_logical_bytes = 0u64;
    let mut total_representation_bytes = 0u64;
    for map in &snapshot.maps {
        if !snapshot.claim_scope.object_types.contains(&ObjectType::Map) {
            bail!("Map inventory is present outside the claim scope");
        }
        if map.excluded
            != snapshot
                .observer_exclusions
                .map_ids
                .contains(&map.identity.id)
        {
            bail!("MAP {} has a non-canonical excluded flag", map.identity.id);
        }
        if !map.excluded
            && map.metadata.frozen.is_none()
            && !map_frozen_failure_ids.contains(&map.identity.id)
            && !read_failures_truncated
        {
            bail!(
                "MAP {} has no frozen state and no producer fdinfo failure",
                map.identity.id
            );
        }
        if map.metadata.name.len() > MAX_OBJECT_NAME_BYTES {
            bail!("MAP {} has an oversized name", map.identity.id);
        }
        if matches!(map.metadata.map_type, 1 | 2 | 5 | 6) {
            if map.metadata.key_size == 0
                || map.metadata.value_size == 0
                || map.metadata.max_entries == 0
            {
                bail!(
                    "MAP {} has impossible metadata for an enumerable content type",
                    map.identity.id
                );
            }
            if matches!(map.metadata.map_type, 2 | 6) && map.metadata.key_size != 4 {
                bail!(
                    "ARRAY MAP {} does not use the kernel u32 index width",
                    map.identity.id
                );
            }
        }
        let selected = !map.excluded
            && snapshot
                .claim_scope
                .samples_map(map.identity.id, map.metadata.map_type);
        validate_map_content(snapshot, map, selected)?;

        if map.content.semantic_complete {
            let entry_count = map.content.entries.len() as u64;
            let representation = checked_retained_representation_bytes(&map.content)?;
            total_entries = total_entries
                .checked_add(entry_count)
                .ok_or_else(|| anyhow!("snapshot-wide Map entry count overflow"))?;
            total_logical_bytes = total_logical_bytes
                .checked_add(map.content.bytes_read)
                .ok_or_else(|| anyhow!("snapshot-wide Map logical-byte count overflow"))?;
            total_representation_bytes = total_representation_bytes
                .checked_add(representation)
                .ok_or_else(|| anyhow!("snapshot-wide Map representation overflow"))?;
        }
    }
    if total_entries > MAX_TOTAL_SAMPLED_MAP_ENTRIES {
        bail!(
            "snapshot contains {total_entries} sampled Map entries, exceeding {MAX_TOTAL_SAMPLED_MAP_ENTRIES}"
        );
    }
    if total_logical_bytes > MAX_TOTAL_SAMPLED_MAP_BYTES {
        bail!(
            "snapshot contains {total_logical_bytes} logical Map bytes, exceeding {MAX_TOTAL_SAMPLED_MAP_BYTES}"
        );
    }
    if total_representation_bytes > MAX_TOTAL_RETAINED_MAP_REPRESENTATION_BYTES {
        bail!(
            "snapshot retains {total_representation_bytes} estimated Map representation bytes, exceeding {MAX_TOTAL_RETAINED_MAP_REPRESENTATION_BYTES}"
        );
    }

    let mut previous_root: Option<&str> = None;
    let mut root_mount_namespace = None;
    for root in &snapshot.pin_roots {
        if root.path.is_empty()
            || root.path.len() > MAX_SCOPE_PATH_BYTES
            || root.path.as_bytes().contains(&0)
            || !is_lexically_normal_absolute(root.path.as_bytes())
            || !snapshot
                .claim_scope
                .bpffs_roots
                .iter()
                .any(|declared| declared == &root.path)
        {
            bail!("pin root identity is not a declared canonical bpffs root");
        }
        if root.mount_namespace_inode == 0 || root.mount_id == 0 {
            bail!("pin root {} has an invalid mount identity", root.path);
        }
        if previous_root.map(|previous| previous >= root.path.as_str()) == Some(true) {
            bail!("pin root inventory is not strictly sorted and unique");
        }
        previous_root = Some(&root.path);
        match root_mount_namespace {
            Some(inode) if inode != root.mount_namespace_inode => {
                bail!("pin roots were observed in different mount namespaces");
            }
            None => root_mount_namespace = Some(root.mount_namespace_inode),
            _ => {}
        }
    }
    if snapshot.completeness.status == CompletenessStatus::Complete
        && (snapshot.pin_roots.len() != snapshot.claim_scope.bpffs_roots.len()
            || snapshot.claim_scope.bpffs_roots.iter().any(|declared| {
                !snapshot
                    .pin_roots
                    .iter()
                    .any(|observed| observed.path == *declared)
            }))
    {
        bail!("a COMPLETE snapshot does not identify every declared bpffs root");
    }

    let mut previous_pin = None;
    let mut pin_representation_bytes = 0u64;
    for pin in &snapshot.pins {
        if !snapshot.claim_scope.object_types.contains(&pin.object_type) {
            bail!("pin {} is outside the claim scope", pin.path);
        }
        if pin.object_id == 0 {
            bail!("pin {} has zero object ID", pin.path);
        }
        validate_canonical_hex(&pin.path_bytes_hex, "pin path_bytes_hex")?;
        let path_bytes = hex::decode(&pin.path_bytes_hex).context("decode pin path_bytes_hex")?;
        if !pin.path_bytes_hex.starts_with("2f")
            || path_bytes.contains(&0)
            || pin.path.is_empty()
            || !is_lexically_normal_absolute(&path_bytes)
            || !snapshot
                .claim_scope
                .bpffs_roots
                .iter()
                .any(|root| path_is_within_root(&path_bytes, root.as_bytes()))
        {
            bail!("pin path must be normalized and within a declared bpffs root");
        }
        if String::from_utf8_lossy(&path_bytes) != pin.path {
            bail!("pin path is not the lossy rendering of path_bytes_hex");
        }
        if pin.mount_namespace_inode == 0 || pin.mount_id == 0 {
            bail!("pin {} has an invalid mount identity", pin.path);
        }
        if !snapshot.pin_roots.iter().any(|root| {
            root.mount_namespace_inode == pin.mount_namespace_inode
                && root.mount_id == pin.mount_id
                && path_is_within_root(&path_bytes, root.path.as_bytes())
        }) {
            bail!("pin {} is outside its observed bpffs root domain", pin.path);
        }
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
        if pin.excluded != expected_excluded {
            bail!("pin {} has a non-canonical excluded flag", pin.path);
        }
        let key = (
            pin.mount_namespace_inode,
            pin.mount_id,
            pin.path_bytes_hex.as_str(),
        );
        if previous_pin.as_ref().map(|previous| previous >= &key) == Some(true) {
            bail!("pin inventory is not strictly sorted and unique");
        }
        previous_pin = Some(key);
        let retained = (pin.path.len() as u64)
            .checked_add(pin.path_bytes_hex.len() as u64)
            .and_then(|bytes| bytes.checked_add(128))
            .ok_or_else(|| anyhow!("pin representation estimate overflow"))?;
        pin_representation_bytes = pin_representation_bytes
            .checked_add(retained)
            .ok_or_else(|| anyhow!("pin representation estimate overflow"))?;
    }
    if pin_representation_bytes > MAX_PIN_REPRESENTATION_BYTES {
        bail!(
            "snapshot retains {pin_representation_bytes} estimated pin bytes, exceeding {MAX_PIN_REPRESENTATION_BYTES}"
        );
    }

    let link_target_failure_ids = snapshot
        .read_failures
        .iter()
        .filter(|failure| {
            failure.object_type == ObjectType::Link && failure.operation == "initial-target-adapter"
        })
        .map(|failure| failure.id)
        .collect::<BTreeSet<_>>();
    for link in &snapshot.links {
        if !snapshot
            .claim_scope
            .object_types
            .contains(&ObjectType::Link)
        {
            bail!("link inventory is present outside the claim scope");
        }
        if link.excluded
            != snapshot
                .observer_exclusions
                .link_ids
                .contains(&link.identity.id)
        {
            bail!(
                "LINK {} has a non-canonical excluded flag",
                link.identity.id
            );
        }
        validate_link_target(link)?;
        if link.target.is_none()
            && !link.excluded
            && !link_target_failure_ids.contains(&link.identity.id)
            && !read_failures_truncated
        {
            bail!(
                "LINK {} has no target and no producer target-adapter failure",
                link.identity.id
            );
        }
    }

    validate_diagnostics(snapshot)?;
    Ok(())
}

fn validate_complete_reference_closure(snapshot: &Snapshot) -> Result<()> {
    let program_ids = snapshot
        .programs
        .iter()
        .map(|program| program.identity.id)
        .collect::<BTreeSet<_>>();
    let map_ids = snapshot
        .maps
        .iter()
        .map(|map| map.identity.id)
        .collect::<BTreeSet<_>>();
    let link_ids = snapshot
        .links
        .iter()
        .map(|link| link.identity.id)
        .collect::<BTreeSet<_>>();

    for (object_type, excluded, present) in [
        (
            ObjectType::Program,
            &snapshot.observer_exclusions.program_ids,
            &program_ids,
        ),
        (
            ObjectType::Map,
            &snapshot.observer_exclusions.map_ids,
            &map_ids,
        ),
        (
            ObjectType::Link,
            &snapshot.observer_exclusions.link_ids,
            &link_ids,
        ),
    ] {
        if snapshot.claim_scope.object_types.contains(&object_type) && !excluded.is_subset(present)
        {
            bail!("a COMPLETE snapshot omits an observer-owned {object_type:?}");
        }
    }

    if snapshot.claim_scope.object_types.contains(&ObjectType::Map) {
        for program in &snapshot.programs {
            if !program.map_ids.iter().all(|id| map_ids.contains(id)) {
                bail!(
                    "PROGRAM {} references a Map absent from a COMPLETE inventory",
                    program.identity.id
                );
            }
        }
    }
    if snapshot
        .claim_scope
        .object_types
        .contains(&ObjectType::Program)
    {
        for link in &snapshot.links {
            if link.program_id != 0 && !program_ids.contains(&link.program_id) {
                bail!(
                    "LINK {} references a Program absent from a COMPLETE inventory",
                    link.identity.id
                );
            }
        }
    }
    for pin in &snapshot.pins {
        let present = match pin.object_type {
            ObjectType::Program => &program_ids,
            ObjectType::Map => &map_ids,
            ObjectType::Link => &link_ids,
        };
        if !present.contains(&pin.object_id) {
            bail!(
                "pin {} references an object absent from a COMPLETE inventory",
                pin.path
            );
        }
    }
    Ok(())
}

fn validate_link_target(link: &LinkState) -> Result<()> {
    let Some(target) = link.target.as_ref() else {
        return Ok(());
    };
    if link.program_id == 0 {
        bail!("LINK {} has a target without a program", link.identity.id);
    }
    let object = target
        .as_object()
        .ok_or_else(|| anyhow!("LINK {} target is not an object", link.identity.id))?;
    let (kind, fields): (&str, &[&str]) = match link.link_type {
        libbpf_sys::BPF_LINK_TYPE_TRACING => (
            "TRACING",
            &["kind", "attach_type", "target_obj_id", "target_btf_id"],
        ),
        libbpf_sys::BPF_LINK_TYPE_CGROUP => ("CGROUP", &["kind", "cgroup_id", "attach_type"]),
        libbpf_sys::BPF_LINK_TYPE_NETNS => ("NETNS", &["kind", "netns_ino", "attach_type"]),
        libbpf_sys::BPF_LINK_TYPE_XDP => ("XDP", &["kind", "ifindex"]),
        _ => bail!(
            "LINK {} has a target unsupported by the producer adapter",
            link.identity.id
        ),
    };
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        bail!("LINK {} target has a non-canonical shape", link.identity.id);
    }
    if object.get("kind").and_then(Value::as_str) != Some(kind) {
        bail!("LINK {} target kind is inconsistent", link.identity.id);
    }
    match link.link_type {
        libbpf_sys::BPF_LINK_TYPE_TRACING => {
            require_json_u32(object, "attach_type", false, link.identity.id)?;
            require_json_u32(object, "target_obj_id", false, link.identity.id)?;
            require_json_u32(object, "target_btf_id", false, link.identity.id)?;
        }
        libbpf_sys::BPF_LINK_TYPE_CGROUP => {
            require_json_u64(object, "cgroup_id", true, link.identity.id)?;
            require_json_u32(object, "attach_type", false, link.identity.id)?;
        }
        libbpf_sys::BPF_LINK_TYPE_NETNS => {
            require_json_u64(object, "netns_ino", true, link.identity.id)?;
            require_json_u32(object, "attach_type", false, link.identity.id)?;
        }
        libbpf_sys::BPF_LINK_TYPE_XDP => {
            require_json_u32(object, "ifindex", true, link.identity.id)?;
        }
        _ => unreachable!("unsupported link targets were rejected above"),
    }
    Ok(())
}

fn require_json_u32(
    object: &serde_json::Map<String, Value>,
    field: &str,
    nonzero: bool,
    link_id: u32,
) -> Result<u32> {
    let value = require_json_u64(object, field, nonzero, link_id)?;
    u32::try_from(value).with_context(|| format!("LINK {link_id} target field {field} exceeds u32"))
}

fn require_json_u64(
    object: &serde_json::Map<String, Value>,
    field: &str,
    nonzero: bool,
    link_id: u32,
) -> Result<u64> {
    let value = object.get(field).and_then(Value::as_u64).with_context(|| {
        format!("LINK {link_id} target field {field} is not an unsigned integer")
    })?;
    if nonzero && value == 0 {
        bail!("LINK {link_id} target field {field} must be nonzero");
    }
    Ok(value)
}

fn validate_map_content(snapshot: &Snapshot, map: &MapState, selected: bool) -> Result<()> {
    let content = &map.content;
    if selected == matches!(content.status, MapSampleStatus::OutsideClaimScope) {
        bail!(
            "MAP {} has a content status inconsistent with its claim scope",
            map.identity.id
        );
    }
    if content.semantic_complete {
        if !matches!(
            content.status,
            MapSampleStatus::CompleteQuiescent | MapSampleStatus::BestEffortNonAtomic
        ) || content.error.is_some()
        {
            bail!("MAP {} has inconsistent complete content", map.identity.id);
        }
        if map.metadata.key_size == 0
            || map.metadata.value_size == 0
            || map.metadata.max_entries == 0
        {
            bail!(
                "MAP {} complete content has a zero key/value width or capacity",
                map.identity.id
            );
        }
        if map.metadata.btf_value_type_id != 0 || map.metadata.btf_vmlinux_value_type_id != 0 {
            bail!(
                "MAP {} BTF value semantics are opaque to this producer",
                map.identity.id
            );
        }
    } else {
        if !content.entries.is_empty()
            || content.digest_sha256.is_some()
            || content.bytes_read != 0
            || !content.possible_cpu_ids.is_empty()
            || matches!(
                content.status,
                MapSampleStatus::CompleteQuiescent | MapSampleStatus::BestEffortNonAtomic
            )
        {
            bail!(
                "MAP {} has retained data for incomplete content",
                map.identity.id
            );
        }
        if selected {
            if content.error.as_deref().map(str::is_empty) != Some(false)
                || snapshot.completeness.status != CompletenessStatus::Incomplete
            {
                bail!(
                    "MAP {} incomplete selected content lacks producer diagnostics",
                    map.identity.id
                );
            }
        } else if content.error.is_some() {
            bail!(
                "MAP {} outside-scope content contains a producer error",
                map.identity.id
            );
        }
        return Ok(());
    }

    ensure_collection_limit(
        "Map entries",
        content.entries.len(),
        MAX_CONFIGURED_MAP_ENTRIES as usize,
    )?;
    if content.entries.len() as u64 > snapshot.claim_scope.budget.max_map_entries {
        bail!(
            "MAP {} exceeds the configured per-Map entry budget",
            map.identity.id
        );
    }
    if content.entries.len() as u64 > u64::from(map.metadata.max_entries) {
        bail!("MAP {} exceeds its declared max_entries", map.identity.id);
    }

    let per_cpu = matches!(map.metadata.map_type, 5 | 6);
    if per_cpu {
        validate_cpu_ids(&content.possible_cpu_ids, "Map possible_cpu_ids")?;
        if content.possible_cpu_ids.is_empty()
            || content.possible_cpu_ids != snapshot.possible_cpu_ids
        {
            bail!(
                "MAP {} has a non-canonical possible CPU topology",
                map.identity.id
            );
        }
    } else if !content.possible_cpu_ids.is_empty() {
        bail!(
            "non-per-CPU MAP {} contains possible CPU IDs",
            map.identity.id
        );
    }

    let expected_values = if per_cpu {
        content.possible_cpu_ids.len()
    } else {
        1
    };
    let expected_key_hex = usize::try_from(map.metadata.key_size)
        .ok()
        .and_then(|size| size.checked_mul(2))
        .ok_or_else(|| anyhow!("MAP {} key size overflow", map.identity.id))?;
    let expected_value_hex = usize::try_from(map.metadata.value_size)
        .ok()
        .and_then(|size| size.checked_mul(2))
        .ok_or_else(|| anyhow!("MAP {} value size overflow", map.identity.id))?;
    let mut previous_key: Option<&str> = None;
    for entry in &content.entries {
        validate_canonical_hex(&entry.key_hex, "Map key")?;
        if entry.key_hex.len() != expected_key_hex {
            bail!("MAP {} has a key with the wrong width", map.identity.id);
        }
        if previous_key.map(|previous| previous >= entry.key_hex.as_str()) == Some(true) {
            bail!(
                "MAP {} entries are not strictly sorted and unique",
                map.identity.id
            );
        }
        previous_key = Some(&entry.key_hex);
        if entry.values_hex.len() != expected_values {
            bail!("MAP {} has the wrong value cardinality", map.identity.id);
        }
        for value in &entry.values_hex {
            validate_canonical_hex(value, "Map value")?;
            if value.len() != expected_value_hex {
                bail!("MAP {} has a value with the wrong width", map.identity.id);
            }
        }
    }

    if matches!(map.metadata.map_type, 2 | 6) {
        if map.metadata.key_size != 4
            || content.entries.len() as u64 != u64::from(map.metadata.max_entries)
        {
            bail!(
                "ARRAY MAP {} is not a complete fixed-width inventory",
                map.identity.id
            );
        }
        let mut expected_keys: Vec<String> = (0..map.metadata.max_entries)
            .map(|index| {
                if snapshot.byte_order == "little" {
                    hex::encode(index.to_le_bytes())
                } else {
                    hex::encode(index.to_be_bytes())
                }
            })
            .collect();
        expected_keys.sort();
        for (entry, expected) in content.entries.iter().zip(expected_keys) {
            if entry.key_hex != expected {
                bail!(
                    "ARRAY MAP {} does not contain canonical contiguous keys",
                    map.identity.id
                );
            }
        }
    }

    let values_per_entry = u64::try_from(expected_values)
        .map_err(|_| anyhow!("MAP {} value cardinality overflow", map.identity.id))?;
    let logical_per_entry = u64::from(map.metadata.key_size)
        .checked_add(
            u64::from(map.metadata.value_size)
                .checked_mul(values_per_entry)
                .ok_or_else(|| anyhow!("MAP {} logical-byte count overflow", map.identity.id))?,
        )
        .ok_or_else(|| anyhow!("MAP {} logical-byte count overflow", map.identity.id))?;
    let logical_bytes = logical_per_entry
        .checked_mul(content.entries.len() as u64)
        .ok_or_else(|| anyhow!("MAP {} logical-byte count overflow", map.identity.id))?;
    if content.bytes_read != logical_bytes
        || logical_bytes > snapshot.claim_scope.budget.max_map_bytes
        || logical_bytes > MAX_CONFIGURED_MAP_BYTES
    {
        bail!("MAP {} has an invalid logical-byte count", map.identity.id);
    }

    let digest = content
        .digest_sha256
        .as_deref()
        .ok_or_else(|| anyhow!("MAP {} complete content lacks a digest", map.identity.id))?;
    validate_fixed_hex(digest, 32, "Map digest")?;
    if digest != digest_entries(&content.entries) {
        bail!("MAP {} content digest is not canonical", map.identity.id);
    }
    Ok(())
}

fn checked_retained_representation_bytes(content: &MapContentState) -> Result<u64> {
    let mut total = 0u64;
    for entry in &content.entries {
        let mut entry_bytes = 128u64
            .checked_add(
                (entry.key_hex.len() as u64)
                    .checked_mul(2)
                    .ok_or_else(|| anyhow!("retained Map key representation estimate overflow"))?,
            )
            .ok_or_else(|| anyhow!("retained Map entry representation estimate overflow"))?;
        for value in &entry.values_hex {
            entry_bytes = entry_bytes
                .checked_add(64)
                .and_then(|bytes| bytes.checked_add((value.len() as u64).checked_mul(2)?))
                .ok_or_else(|| anyhow!("retained Map value representation estimate overflow"))?;
        }
        total = total
            .checked_add(entry_bytes)
            .ok_or_else(|| anyhow!("retained Map representation estimate overflow"))?;
    }
    if !content.possible_cpu_ids.is_empty() {
        total = total
            .checked_add(
                (content.possible_cpu_ids.len() as u64)
                    .checked_mul(8)
                    .and_then(|bytes| bytes.checked_add(64))
                    .ok_or_else(|| anyhow!("CPU topology representation estimate overflow"))?,
            )
            .ok_or_else(|| anyhow!("retained Map representation estimate overflow"))?;
    }
    Ok(total)
}

const READ_FAILURE_REASON: &str = "one or more object or pin reads failed; see read_failures";
const READ_FAILURE_TRUNCATION_REASON: &str = "read_failures was truncated at 4096 records";
const DIAGNOSTIC_TRUNCATION_REASON: &str =
    "additional incompleteness reasons omitted at configured limit";

fn validate_completeness_reason(reason: &str) -> Result<()> {
    let exact = matches!(
        reason,
        "program inventory changed during capture"
            | "map inventory changed during capture"
            | "link inventory changed during capture"
            | "pin inventory changed during capture"
            | READ_FAILURE_REASON
            | READ_FAILURE_TRUNCATION_REASON
            | "snapshot-wide Map content resource budget was exhausted"
            | DIAGNOSTIC_TRUNCATION_REASON
    );
    if exact {
        return Ok(());
    }
    if reason
        .strip_prefix("CPU topology unavailable: ")
        .map(|error| !error.is_empty())
        == Some(true)
    {
        return Ok(());
    }
    if let Some(count) = reason
        .strip_prefix("CPU topology has ")
        .and_then(|value| value.strip_suffix(" entries, exceeding hard limit 8192"))
        .and_then(|value| value.parse::<usize>().ok())
    {
        if count > MAX_POSSIBLE_CPUS {
            return Ok(());
        }
    }
    if let Some(status) = reason
        .strip_prefix("one or more selected Map contents are not semantically complete (")
        .and_then(|value| value.strip_suffix(')'))
    {
        if matches!(
            status,
            "UnsupportedType"
                | "ReadForbidden"
                | "OpaqueValue"
                | "TruncatedResourceLimit"
                | "ReadFailed"
                | "ObjectDisappeared"
                | "ConcurrentMutation"
                | "AmbiguousIdReuse"
        ) {
            return Ok(());
        }
    }
    bail!("snapshot contains a completeness reason outside the producer grammar")
}

fn validate_failure_operation(snapshot: &Snapshot, failure: &ObjectReadFailure) -> Result<()> {
    if failure.operation == "pin-read-mount-namespace" {
        if failure.object_type == ObjectType::Map && failure.id == 0 {
            return Ok(());
        }
        bail!("pin mount-namespace failure has an invalid object identity");
    }

    const PIN_PREFIXES: &[&str] = &[
        "pin-root-symlink:",
        "pin-lstat-root:",
        "pin-canonicalize:",
        "pin-noncanonical-root:",
        "pin-open-root:",
        "pin-verify-bpffs:",
        "pin-mount-id-root:",
        "pin-read-dir:",
        "pin-resource-limit:",
        "pin-read-entry:",
        "pin-lstat:",
        "pin-symlink:",
        "pin-mount-id:",
        "pin-cross-mount:",
        "pin-open:",
    ];
    if failure.operation == "pin-resource-limit"
        || PIN_PREFIXES.iter().any(|prefix| {
            failure
                .operation
                .strip_prefix(prefix)
                .map(|suffix| !suffix.is_empty())
                == Some(true)
        })
    {
        if failure.object_type == ObjectType::Map && failure.id == 0 {
            return Ok(());
        }
        bail!("pin read failure has an invalid object identity");
    }

    let (pass, operation) = failure.operation.split_once('-').ok_or_else(|| {
        anyhow!("snapshot read failure operation is outside the producer grammar")
    })?;
    if !matches!(pass, "initial" | "verification") {
        bail!("snapshot read failure has an unknown capture pass");
    }
    let identity_is_valid = match (&failure.object_type, operation) {
        (ObjectType::Program, "enumerate")
        | (ObjectType::Map, "enumerate")
        | (ObjectType::Link, "enumerate") => failure.id == 0,
        (ObjectType::Program, "get-fd" | "get-info")
        | (ObjectType::Map, "get-fd" | "get-info" | "verify-id")
        | (ObjectType::Link, "get-fd" | "get-info") => failure.id != 0,
        (ObjectType::Map, "read-fdinfo-frozen") => {
            failure.id != 0
                && snapshot.maps.iter().any(|map| {
                    map.identity.id == failure.id
                        && (pass == "verification" || map.metadata.frozen.is_none())
                })
        }
        (ObjectType::Link, "target-adapter") => {
            failure.id != 0
                && snapshot.links.iter().any(|link| {
                    link.identity.id == failure.id
                        && (pass == "verification" || link.target.is_none())
                })
        }
        _ => false,
    };
    if !identity_is_valid {
        bail!("snapshot read failure operation/object identity is not producer-valid");
    }
    Ok(())
}

fn validate_diagnostics(snapshot: &Snapshot) -> Result<()> {
    ensure_collection_limit(
        "snapshot read_failures",
        snapshot.read_failures.len(),
        MAX_RECORDED_READ_FAILURES,
    )?;
    ensure_collection_limit(
        "snapshot completeness reasons",
        snapshot.completeness.reasons.len(),
        MAX_SNAPSHOT_REASONS,
    )?;
    ensure_collection_limit("snapshot notes", snapshot.notes.len(), MAX_SNAPSHOT_NOTES)?;

    if snapshot.completeness.status == CompletenessStatus::Complete
        && (!snapshot.completeness.reasons.is_empty() || !snapshot.read_failures.is_empty())
    {
        bail!("a COMPLETE snapshot contains failure diagnostics");
    }
    if snapshot.completeness.status == CompletenessStatus::Incomplete
        && snapshot.completeness.reasons.is_empty()
    {
        bail!("an INCOMPLETE snapshot lacks a reason");
    }
    validate_sorted_unique_text(&snapshot.completeness.reasons, "completeness reasons")?;
    validate_sorted_unique_text(&snapshot.notes, "snapshot notes")?;

    for reason in &snapshot.completeness.reasons {
        validate_completeness_reason(reason)?;
    }
    let has_read_failure_reason = snapshot
        .completeness
        .reasons
        .iter()
        .any(|reason| reason == READ_FAILURE_REASON);
    if has_read_failure_reason != !snapshot.read_failures.is_empty() {
        bail!("read_failures and its generic completeness reason are not bidirectionally bound");
    }
    if snapshot
        .completeness
        .reasons
        .iter()
        .any(|reason| reason == READ_FAILURE_TRUNCATION_REASON)
        && snapshot.read_failures.len() != MAX_RECORDED_READ_FAILURES
    {
        bail!("read_failures truncation reason is inconsistent with the producer limit");
    }
    if snapshot
        .completeness
        .reasons
        .iter()
        .any(|reason| reason == DIAGNOSTIC_TRUNCATION_REASON)
        && snapshot.completeness.reasons.len() != MAX_SNAPSHOT_REASONS
    {
        bail!("diagnostic truncation reason is inconsistent with the producer limit");
    }

    if snapshot.read_failures.windows(2).any(|pair| {
        let left = (
            &pair[0].object_type,
            pair[0].id,
            pair[0].operation.as_str(),
            pair[0].error.as_str(),
        );
        let right = (
            &pair[1].object_type,
            pair[1].id,
            pair[1].operation.as_str(),
            pair[1].error.as_str(),
        );
        left > right
    }) {
        bail!("snapshot read_failures are not canonically sorted");
    }

    let mut text_bytes = 0usize;
    for failure in &snapshot.read_failures {
        if failure.operation.is_empty() || failure.error.is_empty() {
            bail!("snapshot read failure contains an empty diagnostic");
        }
        add_diagnostic_text(&mut text_bytes, &failure.operation)?;
        add_diagnostic_text(&mut text_bytes, &failure.error)?;
        validate_failure_operation(snapshot, failure)?;
    }
    for reason in &snapshot.completeness.reasons {
        add_diagnostic_text(&mut text_bytes, reason)?;
    }
    for note in &snapshot.notes {
        add_diagnostic_text(&mut text_bytes, note)?;
    }
    for map in &snapshot.maps {
        if let Some(error) = &map.content.error {
            add_diagnostic_text(&mut text_bytes, error)?;
        }
    }
    Ok(())
}

fn add_diagnostic_text(total: &mut usize, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_DIAGNOSTIC_STRING_BYTES {
        bail!("snapshot diagnostic must contain 1..={MAX_DIAGNOSTIC_STRING_BYTES} bytes");
    }
    *total = total
        .checked_add(value.len())
        .ok_or_else(|| anyhow!("snapshot diagnostic byte count overflow"))?;
    if *total > MAX_DIAGNOSTIC_TEXT_BYTES {
        bail!("snapshot diagnostics exceed {MAX_DIAGNOSTIC_TEXT_BYTES} bytes");
    }
    Ok(())
}

fn validate_sorted_unique_text(values: &[String], name: &str) -> Result<()> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        bail!("{name} are not strictly sorted and unique");
    }
    Ok(())
}

fn validate_object_ids<'a>(
    name: &str,
    identities: impl Iterator<Item = &'a ObjectIdentity>,
    expected_type: ObjectType,
    boot_id: &str,
) -> Result<()> {
    let mut previous = None;
    for identity in identities {
        if identity.object_type != expected_type || identity.boot_id != boot_id || identity.id == 0
        {
            bail!("{name} contains an invalid object identity");
        }
        if previous.map(|id| id >= identity.id) == Some(true) {
            bail!("{name} is not strictly sorted and unique");
        }
        previous = Some(identity.id);
    }
    Ok(())
}

fn validate_cpu_ids(ids: &[u32], name: &str) -> Result<()> {
    ensure_collection_limit(name, ids.len(), MAX_POSSIBLE_CPUS)?;
    if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        bail!("{name} must be strictly sorted and unique");
    }
    Ok(())
}

fn validate_strictly_increasing_nonzero(ids: &[u32], name: &str) -> Result<()> {
    if ids.first() == Some(&0) || ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        bail!("{name} must contain strictly increasing nonzero IDs");
    }
    Ok(())
}

fn validate_fixed_hex(value: &str, bytes: usize, name: &str) -> Result<()> {
    if value.len() != bytes.saturating_mul(2) {
        bail!("{name} has the wrong width");
    }
    validate_canonical_hex(value, name)
}

fn validate_canonical_hex(value: &str, name: &str) -> Result<()> {
    if value.len() % 2 != 0
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        bail!("{name} is not canonical lowercase hexadecimal");
    }
    Ok(())
}

fn ensure_collection_limit(name: &str, actual: usize, limit: usize) -> Result<()> {
    if actual > limit {
        bail!("{name} contains {actual} entries, exceeding {limit}");
    }
    Ok(())
}

pub fn validate_claim_scope(scope: &ClaimScope) -> Result<()> {
    if (!scope.map_ids.is_empty() || !scope.map_content_types.is_empty())
        && !scope.object_types.contains(&ObjectType::Map)
    {
        bail!("map content scope requires MAP in object_types");
    }
    if scope.event_interfaces.is_empty()
        || scope.event_interfaces.len() > MAX_SCOPE_EVENT_INTERFACES
        || scope
            .event_interfaces
            .iter()
            .any(|name| name.is_empty() || name.len() > 128)
    {
        bail!("event_interfaces must contain 1..={MAX_SCOPE_EVENT_INTERFACES} short names");
    }
    if scope.allowed_bpf_commands.len() > MAX_SCOPE_BPF_COMMANDS {
        bail!("allowed_bpf_commands exceeds {MAX_SCOPE_BPF_COMMANDS} entries");
    }
    if scope.map_ids.len() > MAX_SCOPE_MAP_IDS || scope.map_ids.contains(&0) {
        bail!("map_ids must contain at most {MAX_SCOPE_MAP_IDS} nonzero IDs");
    }
    if scope.bpffs_roots.len() > MAX_SCOPE_BPFFS_ROOTS {
        bail!("bpffs_roots exceeds {MAX_SCOPE_BPFFS_ROOTS} entries");
    }
    let mut unique_roots = BTreeSet::new();
    for root in &scope.bpffs_roots {
        let path = Path::new(root);
        if !path.is_absolute() || !is_lexically_normal_absolute(root.as_bytes()) {
            bail!("bpffs root must be absolute: {root}");
        }
        if root.len() > MAX_SCOPE_PATH_BYTES || root.as_bytes().contains(&0) {
            bail!("bpffs root is too long or contains NUL");
        }
        if !unique_roots.insert(root) {
            bail!("bpffs_roots contains a duplicate path");
        }
    }
    for (index, root) in scope.bpffs_roots.iter().enumerate() {
        for other in scope.bpffs_roots.iter().skip(index + 1) {
            if path_is_within_root(root.as_bytes(), other.as_bytes())
                || path_is_within_root(other.as_bytes(), root.as_bytes())
            {
                bail!("bpffs_roots must not overlap or contain one another");
            }
        }
    }
    if scope.attachment_targets.len() > MAX_SCOPE_ATTACHMENT_TARGETS
        || !json_fits_limit(&scope.attachment_targets, MAX_SCOPE_ATTACHMENT_JSON_BYTES)
    {
        bail!(
            "attachment_targets exceeds its count or {MAX_SCOPE_ATTACHMENT_JSON_BYTES}-byte limit"
        );
    }
    if scope.budget.max_map_entries == 0
        || scope.budget.max_map_entries > MAX_CONFIGURED_MAP_ENTRIES
    {
        bail!(
            "max_map_entries must be in 1..={MAX_CONFIGURED_MAP_ENTRIES}, got {}",
            scope.budget.max_map_entries
        );
    }
    if scope.budget.max_map_bytes == 0 || scope.budget.max_map_bytes > MAX_CONFIGURED_MAP_BYTES {
        bail!(
            "max_map_bytes must be in 1..={MAX_CONFIGURED_MAP_BYTES}, got {}",
            scope.budget.max_map_bytes
        );
    }
    if scope.budget.per_map_deadline_ms == 0
        || scope.budget.per_map_deadline_ms > MAX_CONFIGURED_MAP_DEADLINE_MS
    {
        bail!(
            "per_map_deadline_ms must be in 1..={MAX_CONFIGURED_MAP_DEADLINE_MS}, got {}",
            scope.budget.per_map_deadline_ms
        );
    }
    Ok(())
}

fn json_fits_limit(value: &[Value], limit: usize) -> bool {
    struct LimitedWriter {
        written: usize,
        limit: usize,
    }

    impl io::Write for LimitedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let Some(total) = self.written.checked_add(bytes.len()) else {
                return Err(io::Error::new(io::ErrorKind::Other, "JSON size overflow"));
            };
            if total > self.limit {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "JSON exceeds configured size limit",
                ));
            }
            self.written = total;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut writer = LimitedWriter { written: 0, limit };
    serde_json::to_writer(&mut writer, value).is_ok()
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

fn path_is_within_root(path: &[u8], root: &[u8]) -> bool {
    if !is_lexically_normal_absolute(path) || !is_lexically_normal_absolute(root) {
        return false;
    }
    root == b"/" || path == root || (path.starts_with(root) && path.get(root.len()) == Some(&b'/'))
}

pub fn validate_claim_scope_exclusions(
    scope: &ClaimScope,
    exclusions: &ObjectExclusions,
) -> Result<()> {
    let overlap = scope
        .map_ids
        .intersection(&exclusions.map_ids)
        .copied()
        .collect::<Vec<_>>();
    if !overlap.is_empty() {
        bail!(
            "explicit map_ids overlap observer-owned maps and would silently reduce the requested scope: {overlap:?}"
        );
    }
    Ok(())
}

fn read_required_trimmed(path: &str) -> Result<String> {
    let value = fs::read_to_string(path).with_context(|| format!("read {path}"))?;
    let value = value.trim();
    if value.is_empty() {
        bail!("{path} is empty");
    }
    Ok(value.to_owned())
}

fn kernel_release() -> Result<String> {
    let mut uts = MaybeUninit::<libc::utsname>::zeroed();
    let rc = unsafe { libc::uname(uts.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error()).context("uname");
    }
    let uts = unsafe { uts.assume_init() };
    let release = unsafe { CStr::from_ptr(uts.release.as_ptr()) };
    Ok(release.to_string_lossy().into_owned())
}

fn possible_cpu_ids() -> Result<Vec<u32>> {
    let text = read_required_trimmed("/sys/devices/system/cpu/possible")?;
    let ids = parse_cpu_list(&text)?;
    let libbpf_count = unsafe { libbpf_sys::libbpf_num_possible_cpus() };
    if libbpf_count < 0 {
        return Err(errno_from_libbpf(libbpf_count)).context("libbpf_num_possible_cpus");
    }
    if ids.len() != libbpf_count as usize {
        bail!(
            "CPU topology count mismatch: sysfs={} libbpf={libbpf_count}",
            ids.len()
        );
    }
    Ok(ids)
}

fn parse_cpu_list(text: &str) -> Result<Vec<u32>> {
    let mut ids = BTreeSet::new();
    for item in text.trim().split(',') {
        if item.is_empty() {
            bail!("empty CPU range component");
        }
        if let Some((start, end)) = item.split_once('-') {
            let start: u32 = start
                .parse()
                .with_context(|| format!("invalid CPU {start}"))?;
            let end: u32 = end.parse().with_context(|| format!("invalid CPU {end}"))?;
            if start > end {
                bail!("descending CPU range {start}-{end}");
            }
            let span = u64::from(end) - u64::from(start) + 1;
            if span > MAX_POSSIBLE_CPUS as u64
                || ids.len().saturating_add(span as usize) > MAX_POSSIBLE_CPUS
            {
                bail!("possible CPU set exceeds hard limit {MAX_POSSIBLE_CPUS}");
            }
            for id in start..=end {
                ids.insert(id);
            }
        } else {
            ids.insert(
                item.parse()
                    .with_context(|| format!("invalid CPU {item}"))?,
            );
            if ids.len() > MAX_POSSIBLE_CPUS {
                bail!("possible CPU set exceeds hard limit {MAX_POSSIBLE_CPUS}");
            }
        }
    }
    if ids.is_empty() {
        bail!("possible CPU set is empty");
    }
    Ok(ids.into_iter().collect())
}

type NextIdFn = unsafe extern "C" fn(u32, *mut u32) -> c_int;

/// Perform the exact read-only global-inventory operations required by this
/// oracle. `ENOENT` means the object class is empty and is therefore success;
/// permission or kernel-support failures are returned to the caller.
pub fn probe_global_inventory_access() -> Result<()> {
    probe_next_id("program", libbpf_sys::bpf_prog_get_next_id)?;
    probe_next_id("map", libbpf_sys::bpf_map_get_next_id)?;
    probe_next_id("link", libbpf_sys::bpf_link_get_next_id)?;
    Ok(())
}

fn probe_next_id(kind: &str, next: NextIdFn) -> Result<()> {
    let mut candidate = 0u32;
    let rc = unsafe { next(0, &mut candidate) };
    if rc == 0 || rc == -libc::ENOENT {
        return Ok(());
    }
    Err(errno_from_libbpf(rc)).with_context(|| format!("enumerate first BPF {kind} ID"))
}

fn enumerate_ids(next: NextIdFn) -> Result<Vec<u32>> {
    let mut current = 0u32;
    let mut ids = Vec::new();
    loop {
        let mut candidate = 0u32;
        let rc = unsafe { next(current, &mut candidate) };
        if rc == -libc::ENOENT {
            break;
        }
        if rc < 0 {
            return Err(errno_from_libbpf(rc).into());
        }
        if candidate <= current {
            bail!("BPF object enumeration did not advance ({current} -> {candidate})");
        }
        ids.push(candidate);
        if ids.len() > MAX_INVENTORY_IDS_PER_TYPE {
            bail!(
                "BPF object inventory exceeds hard limit of {MAX_INVENTORY_IDS_PER_TYPE} IDs per type"
            );
        }
        current = candidate;
    }
    Ok(ids)
}

fn errno_from_libbpf(rc: c_int) -> io::Error {
    if rc < 0 {
        io::Error::from_raw_os_error(-rc)
    } else {
        io::Error::new(
            io::ErrorKind::Other,
            format!("unexpected libbpf result {rc}"),
        )
    }
}

fn owned_fd(rc: c_int) -> io::Result<OwnedFd> {
    if rc < 0 {
        Err(errno_from_libbpf(rc))
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(rc) })
    }
}

fn get_info<T>(fd: c_int, info: &mut T) -> io::Result<()> {
    let mut length = mem::size_of::<T>() as u32;
    let rc = unsafe {
        libbpf_sys::bpf_obj_get_info_by_fd(fd, info as *mut T as *mut c_void, &mut length)
    };
    if rc < 0 {
        Err(errno_from_libbpf(rc))
    } else {
        Ok(())
    }
}

fn record_failure(
    failures: &mut Vec<ObjectReadFailure>,
    completeness: &mut Completeness,
    object_type: ObjectType,
    id: u32,
    operation: impl Into<String>,
    error: impl Into<String>,
) {
    let operation = operation.into();
    let error = error.into();
    completeness.mark_incomplete("one or more object or pin reads failed; see read_failures");
    if failures.len() >= MAX_RECORDED_READ_FAILURES {
        completeness.mark_incomplete(format!(
            "read_failures was truncated at {MAX_RECORDED_READ_FAILURES} records"
        ));
        return;
    }
    failures.push(ObjectReadFailure {
        object_type,
        id,
        operation,
        error,
    });
}

fn capture_programs(
    boot_id: &str,
    exclusions: &ObjectExclusions,
    failures: &mut Vec<ObjectReadFailure>,
    completeness: &mut Completeness,
    pass: &str,
) -> Vec<ProgramState> {
    let ids = match enumerate_ids(libbpf_sys::bpf_prog_get_next_id) {
        Ok(ids) => ids,
        Err(error) => {
            record_failure(
                failures,
                completeness,
                ObjectType::Program,
                0,
                format!("{pass}-enumerate"),
                error.to_string(),
            );
            return Vec::new();
        }
    };

    let mut programs = Vec::with_capacity(ids.len());
    let mut total_map_refs = 0usize;
    for id in ids {
        let fd = match owned_fd(unsafe { libbpf_sys::bpf_prog_get_fd_by_id(id) }) {
            Ok(fd) => fd,
            Err(error) => {
                record_failure(
                    failures,
                    completeness,
                    ObjectType::Program,
                    id,
                    format!("{pass}-get-fd"),
                    error.to_string(),
                );
                continue;
            }
        };
        match read_program(
            fd.as_raw_fd(),
            boot_id,
            id,
            exclusions.program_ids.contains(&id),
            MAX_TOTAL_PROGRAM_MAP_REFS.saturating_sub(total_map_refs),
        ) {
            Ok(program) => {
                total_map_refs += program.map_ids.len();
                programs.push(program);
            }
            Err(error) => record_failure(
                failures,
                completeness,
                ObjectType::Program,
                id,
                format!("{pass}-get-info"),
                error.to_string(),
            ),
        }
    }
    programs.sort_by_key(|program| program.identity.id);
    programs
}

fn read_program(
    fd: c_int,
    boot_id: &str,
    expected_id: u32,
    excluded: bool,
    remaining_map_refs: usize,
) -> Result<ProgramState> {
    let mut info = libbpf_sys::bpf_prog_info::default();
    get_info(fd, &mut info)?;

    let wanted = info.nr_map_ids as usize;
    if wanted > MAX_INVENTORY_IDS_PER_TYPE {
        bail!(
            "program references {wanted} maps, exceeding hard limit {MAX_INVENTORY_IDS_PER_TYPE}"
        );
    }
    if wanted > remaining_map_refs {
        bail!(
            "snapshot-wide Program-to-Map reference limit {MAX_TOTAL_PROGRAM_MAP_REFS} would be exceeded"
        );
    }
    let mut map_ids = vec![0u32; wanted];
    if wanted > 0 {
        let mut expanded = libbpf_sys::bpf_prog_info {
            nr_map_ids: wanted as u32,
            map_ids: map_ids.as_mut_ptr() as u64,
            ..libbpf_sys::bpf_prog_info::default()
        };
        get_info(fd, &mut expanded)?;
        if expanded.nr_map_ids as usize > map_ids.len() {
            bail!(
                "program map ID count grew while reading ({} -> {})",
                map_ids.len(),
                expanded.nr_map_ids
            );
        }
        map_ids.truncate(expanded.nr_map_ids as usize);
        info = expanded;
    }
    map_ids.sort_unstable();
    map_ids.dedup();

    if info.id != expected_id {
        bail!(
            "program info ID {} does not match enumerated ID {expected_id}",
            info.id
        );
    }

    Ok(ProgramState {
        identity: ObjectIdentity {
            boot_id: boot_id.into(),
            object_type: ObjectType::Program,
            id: info.id,
        },
        program_type: info.type_,
        name: c_name(&info.name),
        tag_hex: hex::encode(info.tag),
        load_time_ns: info.load_time,
        created_by_uid: info.created_by_uid,
        btf_id: info.btf_id,
        attach_btf_obj_id: info.attach_btf_obj_id,
        attach_btf_id: info.attach_btf_id,
        ifindex: info.ifindex,
        netns_dev: info.netns_dev,
        netns_ino: info.netns_ino,
        map_ids,
        excluded,
    })
}

fn c_name(bytes: &[libc::c_char]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let bytes: Vec<u8> = bytes[..end].iter().map(|byte| *byte as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[allow(clippy::too_many_arguments)]
fn capture_maps(
    boot_id: &str,
    scope: &ClaimScope,
    options: &CaptureOptions,
    possible_cpus: &[u32],
    failures: &mut Vec<ObjectReadFailure>,
    completeness: &mut Completeness,
    sample_content: bool,
    optional_failure_ids: Option<&BTreeSet<u32>>,
    pass: &str,
) -> Vec<MapState> {
    let ids = match enumerate_ids(libbpf_sys::bpf_map_get_next_id) {
        Ok(ids) => ids,
        Err(error) => {
            record_failure(
                failures,
                completeness,
                ObjectType::Map,
                0,
                format!("{pass}-enumerate"),
                error.to_string(),
            );
            return Vec::new();
        }
    };

    let mut maps = Vec::with_capacity(ids.len());
    let mut total_sampled_entries = 0u64;
    let mut total_sampled_bytes = 0u64;
    let mut total_retained_representation_bytes = 0u64;
    let overall_sampling_deadline = Instant::now()
        .checked_add(Duration::from_millis(MAX_TOTAL_MAP_SAMPLING_MS))
        .unwrap_or_else(Instant::now);
    for id in ids {
        let excluded = options.exclusions.map_ids.contains(&id);
        let fd = match owned_fd(unsafe { libbpf_sys::bpf_map_get_fd_by_id(id) }) {
            Ok(fd) => fd,
            Err(error) => {
                record_failure(
                    failures,
                    completeness,
                    ObjectType::Map,
                    id,
                    format!("{pass}-get-fd"),
                    error.to_string(),
                );
                continue;
            }
        };
        let mut info = libbpf_sys::bpf_map_info::default();
        if let Err(error) = get_info(fd.as_raw_fd(), &mut info) {
            record_failure(
                failures,
                completeness,
                ObjectType::Map,
                id,
                format!("{pass}-get-info"),
                error.to_string(),
            );
            continue;
        }
        if info.id != id {
            record_failure(
                failures,
                completeness,
                ObjectType::Map,
                id,
                format!("{pass}-verify-id"),
                format!("map info ID {} does not match enumerated ID {id}", info.id),
            );
            continue;
        }

        let frozen = match read_frozen(fd.as_raw_fd(), info.id) {
            Ok(value) => Some(value),
            Err(error) => {
                if !excluded
                    && optional_failure_ids.map_or(true, |initial_ids| initial_ids.contains(&id))
                {
                    record_failure(
                        failures,
                        completeness,
                        ObjectType::Map,
                        id,
                        format!("{pass}-read-fdinfo-frozen"),
                        error.to_string(),
                    );
                }
                None
            }
        };

        let metadata = MapMetadata {
            map_type: info.type_,
            name: c_name(&info.name),
            key_size: info.key_size,
            value_size: info.value_size,
            max_entries: info.max_entries,
            map_flags: info.map_flags,
            map_extra: info.map_extra,
            ifindex: info.ifindex,
            netns_dev: info.netns_dev,
            netns_ino: info.netns_ino,
            btf_id: info.btf_id,
            btf_key_type_id: info.btf_key_type_id,
            btf_value_type_id: info.btf_value_type_id,
            btf_vmlinux_value_type_id: info.btf_vmlinux_value_type_id,
            frozen,
        };

        let mut content = if !sample_content || excluded || !scope.samples_map(id, info.type_) {
            outside_scope_content()
        } else if info.btf_value_type_id != 0 || info.btf_vmlinux_value_type_id != 0 {
            // The MVP does not yet traverse BTF deeply enough to rule out
            // bpf_spin_lock, bpf_timer, or kptr fields.  Raw bytes must not be
            // presented as semantically complete in that case.
            MapContentState {
                status: MapSampleStatus::OpaqueValue,
                semantic_complete: false,
                entries: Vec::new(),
                digest_sha256: None,
                bytes_read: 0,
                possible_cpu_ids: Vec::new(),
                error: Some(
                    "BTF value semantics are not inspected by the MVP; special kernel-managed fields cannot be excluded"
                        .into(),
                ),
            }
        } else {
            sample_map(
                fd.as_raw_fd(),
                &info,
                scope,
                options,
                possible_cpus,
                overall_sampling_deadline,
                RemainingContentBudget {
                    entries: MAX_TOTAL_SAMPLED_MAP_ENTRIES.saturating_sub(total_sampled_entries),
                    logical_bytes: MAX_TOTAL_SAMPLED_MAP_BYTES.saturating_sub(total_sampled_bytes),
                    representation_bytes: MAX_TOTAL_RETAINED_MAP_REPRESENTATION_BYTES
                        .saturating_sub(total_retained_representation_bytes),
                },
            )
        };

        if sample_content && content.semantic_complete {
            let next_entries = total_sampled_entries
                .checked_add(content.entries.len() as u64)
                .unwrap_or(u64::MAX);
            let next_bytes = total_sampled_bytes
                .checked_add(content.bytes_read)
                .unwrap_or(u64::MAX);
            let retained_representation = retained_representation_bytes(&content);
            let next_retained_representation = total_retained_representation_bytes
                .checked_add(retained_representation)
                .unwrap_or(u64::MAX);
            if next_entries > MAX_TOTAL_SAMPLED_MAP_ENTRIES
                || next_bytes > MAX_TOTAL_SAMPLED_MAP_BYTES
                || next_retained_representation > MAX_TOTAL_RETAINED_MAP_REPRESENTATION_BYTES
            {
                content = map_sample_error(
                    MapSampleStatus::TruncatedResourceLimit,
                    format!(
                        "snapshot-wide Map content cap exceeded (entries <= {MAX_TOTAL_SAMPLED_MAP_ENTRIES}, logical bytes <= {MAX_TOTAL_SAMPLED_MAP_BYTES}, retained representation <= {MAX_TOTAL_RETAINED_MAP_REPRESENTATION_BYTES})"
                    ),
                );
            } else {
                total_sampled_entries = next_entries;
                total_sampled_bytes = next_bytes;
                total_retained_representation_bytes = next_retained_representation;
            }
        }

        if sample_content
            && !excluded
            && scope.samples_map(id, info.type_)
            && !content.semantic_complete
        {
            if content.error.as_deref().map(|error| {
                error.contains("snapshot-wide") || error.contains("remaining snapshot budget")
            }) == Some(true)
            {
                completeness
                    .mark_incomplete("snapshot-wide Map content resource budget was exhausted");
            } else {
                completeness.mark_incomplete(format!(
                    "one or more selected Map contents are not semantically complete ({:?})",
                    content.status
                ));
            }
        }

        maps.push(MapState {
            identity: ObjectIdentity {
                boot_id: boot_id.into(),
                object_type: ObjectType::Map,
                id: info.id,
            },
            metadata,
            content,
            excluded,
        });
    }
    maps.sort_by_key(|map| map.identity.id);
    maps
}

fn outside_scope_content() -> MapContentState {
    MapContentState {
        status: MapSampleStatus::OutsideClaimScope,
        semantic_complete: false,
        entries: Vec::new(),
        digest_sha256: None,
        bytes_read: 0,
        possible_cpu_ids: Vec::new(),
        error: None,
    }
}

fn read_frozen(fd: c_int, expected_id: u32) -> Result<bool> {
    let text = fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))
        .with_context(|| format!("read /proc/self/fdinfo/{fd}"))?;
    parse_frozen_fdinfo(&text, expected_id)
}

fn parse_frozen_fdinfo(text: &str, expected_id: u32) -> Result<bool> {
    let mut map_id = None;
    let mut frozen = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "map_id" => map_id = Some(value.trim().parse::<u32>().context("parse map_id")?),
            "frozen" => {
                frozen = Some(match value.trim() {
                    "0" => false,
                    "1" => true,
                    other => bail!("invalid frozen value {other}"),
                })
            }
            _ => {}
        }
    }
    if map_id != Some(expected_id) {
        bail!(
            "fdinfo map_id {:?} does not match expected {expected_id}",
            map_id
        );
    }
    frozen.ok_or_else(|| anyhow!("fdinfo does not expose frozen state"))
}

fn sample_map(
    fd: c_int,
    info: &libbpf_sys::bpf_map_info,
    scope: &ClaimScope,
    options: &CaptureOptions,
    possible_cpus: &[u32],
    overall_deadline: Instant,
    remaining: RemainingContentBudget,
) -> MapContentState {
    let map_type = info.type_;
    let is_array = map_type == MapContentType::Array.kernel_type()
        || map_type == MapContentType::PercpuArray.kernel_type();
    let is_per_cpu = map_type == MapContentType::PercpuArray.kernel_type()
        || map_type == MapContentType::PercpuHash.kernel_type();
    if !is_array
        && map_type != MapContentType::Hash.kernel_type()
        && map_type != MapContentType::PercpuHash.kernel_type()
    {
        return map_sample_error(
            MapSampleStatus::UnsupportedType,
            format!("map type {map_type} is unsupported"),
        );
    }
    if info.key_size == 0 || info.value_size == 0 {
        return map_sample_error(
            MapSampleStatus::ReadFailed,
            "zero key_size or value_size".into(),
        );
    }
    if is_per_cpu && possible_cpus.is_empty() {
        return map_sample_error(
            MapSampleStatus::ReadFailed,
            "possible CPU topology is unavailable".into(),
        );
    }

    let mut effective_budget = scope.budget.clone();
    effective_budget.max_map_entries = effective_budget.max_map_entries.min(remaining.entries);
    effective_budget.max_map_bytes = effective_budget.max_map_bytes.min(remaining.logical_bytes);
    if effective_budget.max_map_entries == 0
        || effective_budget.max_map_bytes == 0
        || remaining.representation_bytes == 0
    {
        return map_sample_error(
            MapSampleStatus::TruncatedResourceLimit,
            "snapshot-wide Map content budget is exhausted".into(),
        );
    }
    let layout = match value_layout(info.value_size, is_per_cpu, possible_cpus) {
        Ok(layout) => layout,
        Err(error) => return map_sample_error(error.status, error.message),
    };
    let retained_entries = if is_array {
        u64::from(info.max_entries)
    } else {
        u64::from(info.max_entries).min(effective_budget.max_map_entries)
    };
    let retained_estimate = match retained_representation_estimate(
        info.key_size as usize,
        info.value_size as usize,
        layout.count,
        retained_entries,
    ) {
        Ok(estimate) => estimate,
        Err(error) => return map_sample_error(error.status, error.message),
    };
    if retained_estimate > remaining.representation_bytes {
        return map_sample_error(
            MapSampleStatus::TruncatedResourceLimit,
            format!(
                "Map retained representation estimate {retained_estimate} exceeds remaining snapshot budget {}",
                remaining.representation_bytes
            ),
        );
    }

    let deadline = Instant::now()
        .checked_add(Duration::from_millis(scope.budget.per_map_deadline_ms))
        .unwrap_or_else(Instant::now)
        .min(overall_deadline);
    let result = if is_array {
        sample_array(fd, info, possible_cpus, &effective_budget, deadline)
    } else {
        sample_hash(fd, info, possible_cpus, &effective_budget, deadline)
    };

    match result {
        Ok((entries, bytes_read)) => complete_map_sample(
            entries,
            bytes_read,
            is_per_cpu
                .then(|| possible_cpus.to_vec())
                .unwrap_or_default(),
            options.maps_quiescent,
        ),
        Err(error) => map_sample_error(error.status, error.message),
    }
}

#[derive(Debug)]
struct SampleError {
    status: MapSampleStatus,
    message: String,
}

impl SampleError {
    fn new(status: MapSampleStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

fn map_sample_error(status: MapSampleStatus, message: String) -> MapContentState {
    MapContentState {
        status,
        semantic_complete: false,
        entries: Vec::new(),
        digest_sha256: None,
        bytes_read: 0,
        possible_cpu_ids: Vec::new(),
        error: Some(message),
    }
}

fn complete_map_sample(
    mut entries: Vec<MapEntry>,
    bytes_read: u64,
    possible_cpu_ids: Vec<u32>,
    quiescent: bool,
) -> MapContentState {
    entries.sort_by(|left, right| left.key_hex.cmp(&right.key_hex));
    let digest_sha256 = Some(digest_entries(&entries));
    MapContentState {
        status: if quiescent {
            MapSampleStatus::CompleteQuiescent
        } else {
            MapSampleStatus::BestEffortNonAtomic
        },
        // This describes whether the selected entries and bytes were read in
        // full.  Atomicity/quiescence is an independent verdict axis.
        semantic_complete: true,
        entries,
        digest_sha256,
        bytes_read,
        possible_cpu_ids,
        error: None,
    }
}

fn sample_array(
    fd: c_int,
    info: &libbpf_sys::bpf_map_info,
    possible_cpus: &[u32],
    budget: &bpf_observer_schema::ResourceBudget,
    deadline: Instant,
) -> std::result::Result<(Vec<MapEntry>, u64), SampleError> {
    if u64::from(info.max_entries) > budget.max_map_entries {
        return Err(SampleError::new(
            MapSampleStatus::TruncatedResourceLimit,
            format!(
                "array max_entries {} exceeds budget {}",
                info.max_entries, budget.max_map_entries
            ),
        ));
    }
    let per_cpu = info.type_ == MapContentType::PercpuArray.kernel_type();
    let value_layout = value_layout(info.value_size, per_cpu, possible_cpus)?;
    ensure_staging_entry_fits(info.key_size as usize, &value_layout, budget)?;
    let logical_value_bytes = u64::from(info.value_size)
        .checked_mul(if per_cpu {
            possible_cpus.len() as u64
        } else {
            1
        })
        .ok_or_else(|| {
            SampleError::new(
                MapSampleStatus::TruncatedResourceLimit,
                "value size overflow",
            )
        })?;
    let per_entry_bytes = u64::from(info.key_size)
        .checked_add(logical_value_bytes)
        .ok_or_else(|| {
            SampleError::new(
                MapSampleStatus::TruncatedResourceLimit,
                "entry size overflow",
            )
        })?;
    let total = per_entry_bytes
        .checked_mul(u64::from(info.max_entries))
        .ok_or_else(|| {
            SampleError::new(MapSampleStatus::TruncatedResourceLimit, "map size overflow")
        })?;
    if total > budget.max_map_bytes {
        return Err(SampleError::new(
            MapSampleStatus::TruncatedResourceLimit,
            format!(
                "map needs {total} bytes, budget is {}",
                budget.max_map_bytes
            ),
        ));
    }

    let mut entries = Vec::new();
    entries
        .try_reserve_exact(info.max_entries as usize)
        .map_err(|error| {
            SampleError::new(
                MapSampleStatus::TruncatedResourceLimit,
                format!("array entry allocation failed: {error}"),
            )
        })?;
    for index in 0..info.max_entries {
        if Instant::now() > deadline {
            return Err(SampleError::new(
                MapSampleStatus::TruncatedResourceLimit,
                "per-map deadline exceeded",
            ));
        }
        let key = index.to_ne_bytes();
        let mut value = vec![0u8; value_layout.total_size];
        let rc = unsafe {
            libbpf_sys::bpf_map_lookup_elem(
                fd,
                key.as_ptr() as *const c_void,
                value.as_mut_ptr() as *mut c_void,
            )
        };
        if rc < 0 {
            return Err(classify_read_error(
                rc,
                format!("lookup array index {index}"),
            ));
        }
        entries.push(MapEntry {
            key_hex: hex::encode(key),
            values_hex: split_values(&value, info.value_size as usize, &value_layout),
        });
    }
    Ok((entries, total))
}

fn sample_hash(
    fd: c_int,
    info: &libbpf_sys::bpf_map_info,
    possible_cpus: &[u32],
    budget: &bpf_observer_schema::ResourceBudget,
    deadline: Instant,
) -> std::result::Result<(Vec<MapEntry>, u64), SampleError> {
    match sample_hash_batch(fd, info, possible_cpus, budget, deadline) {
        Err(error)
            if matches!(
                &error.status,
                MapSampleStatus::UnsupportedType | MapSampleStatus::ReadFailed
            ) && error.message.starts_with("batch unsupported:") =>
        {
            sample_hash_next_key(fd, info, possible_cpus, budget, deadline)
        }
        result => result,
    }
}

fn sample_hash_batch(
    fd: c_int,
    info: &libbpf_sys::bpf_map_info,
    possible_cpus: &[u32],
    budget: &bpf_observer_schema::ResourceBudget,
    deadline: Instant,
) -> std::result::Result<(Vec<MapEntry>, u64), SampleError> {
    let per_cpu = info.type_ == MapContentType::PercpuHash.kernel_type();
    let layout = value_layout(info.value_size, per_cpu, possible_cpus)?;
    let key_size = info.key_size as usize;
    let raw_entry_allocation = ensure_staging_entry_fits(key_size, &layout, budget)?;
    let cursor_size = key_size.max(mem::size_of::<u32>());
    let mut in_cursor = vec![0u8; cursor_size];
    let mut out_cursor = vec![0u8; cursor_size];
    let mut have_cursor = false;
    let mut collected: BTreeMap<Vec<u8>, Vec<Vec<u8>>> = BTreeMap::new();
    let mut bytes_read = 0u64;
    let mut first_call = true;

    loop {
        if Instant::now() > deadline {
            return Err(SampleError::new(
                MapSampleStatus::TruncatedResourceLimit,
                "per-map deadline exceeded",
            ));
        }
        let remaining = budget
            .max_map_entries
            .saturating_sub(collected.len() as u64);
        if remaining == 0 {
            // Distinguish a map whose cardinality is exactly the budget from a
            // genuinely truncated map.  The extra lookup is only an existence
            // probe; its payload is never included in the snapshot.
            let mut probe_key = vec![0u8; key_size];
            let mut probe_value = vec![0u8; layout.total_size];
            let mut probe_count = 1u32;
            let rc = unsafe {
                libbpf_sys::bpf_map_lookup_batch(
                    fd,
                    if have_cursor {
                        in_cursor.as_mut_ptr() as *mut c_void
                    } else {
                        ptr::null_mut()
                    },
                    out_cursor.as_mut_ptr() as *mut c_void,
                    probe_key.as_mut_ptr() as *mut c_void,
                    probe_value.as_mut_ptr() as *mut c_void,
                    &mut probe_count,
                    ptr::null(),
                )
            };
            if rc == -libc::ENOENT && probe_count == 0 {
                break;
            }
            if rc < 0 && rc != -libc::ENOENT {
                return Err(classify_read_error(rc, "batch end probe".into()));
            }
            return Err(SampleError::new(
                MapSampleStatus::TruncatedResourceLimit,
                "map contains more entries than the configured budget",
            ));
        }
        let kernel_remaining = u64::from(info.max_entries).saturating_sub(collected.len() as u64);
        if kernel_remaining == 0 {
            break;
        }
        let allocation_limit =
            usize::try_from(budget.max_map_bytes).unwrap_or(usize::MAX) / raw_entry_allocation;
        let requested = HASH_BATCH_SIZE
            .min(remaining as usize)
            .min(kernel_remaining as usize)
            .min(allocation_limit);
        if requested == 0 {
            return Err(SampleError::new(
                MapSampleStatus::TruncatedResourceLimit,
                "one batch entry exceeds the staging allocation budget",
            ));
        }
        let keys_len = key_size.checked_mul(requested).ok_or_else(|| {
            SampleError::new(
                MapSampleStatus::TruncatedResourceLimit,
                "key allocation overflow",
            )
        })?;
        let values_len = layout.total_size.checked_mul(requested).ok_or_else(|| {
            SampleError::new(
                MapSampleStatus::TruncatedResourceLimit,
                "value allocation overflow",
            )
        })?;
        let mut keys = vec![0u8; keys_len];
        let mut values = vec![0u8; values_len];
        let mut count = requested as u32;
        let rc = unsafe {
            libbpf_sys::bpf_map_lookup_batch(
                fd,
                if have_cursor {
                    in_cursor.as_mut_ptr() as *mut c_void
                } else {
                    ptr::null_mut()
                },
                out_cursor.as_mut_ptr() as *mut c_void,
                keys.as_mut_ptr() as *mut c_void,
                values.as_mut_ptr() as *mut c_void,
                &mut count,
                ptr::null(),
            )
        };
        if first_call && matches!(rc, x if x == -libc::EINVAL || x == -libc::EOPNOTSUPP) {
            return Err(SampleError::new(
                MapSampleStatus::UnsupportedType,
                format!("batch unsupported: {}", errno_from_libbpf(rc)),
            ));
        }
        first_call = false;
        if rc < 0 && rc != -libc::ENOENT {
            return Err(classify_read_error(rc, "batch lookup".into()));
        }
        if count as usize > requested {
            return Err(SampleError::new(
                MapSampleStatus::ReadFailed,
                "kernel returned more batch entries than requested",
            ));
        }
        for item in 0..count as usize {
            let key = keys[item * key_size..(item + 1) * key_size].to_vec();
            let raw_value = &values[item * layout.total_size..(item + 1) * layout.total_size];
            let split = split_value_bytes(raw_value, info.value_size as usize, &layout);
            let logical = logical_entry_bytes(&key, &split)?;
            let next_total = bytes_read.checked_add(logical).ok_or_else(|| {
                SampleError::new(
                    MapSampleStatus::TruncatedResourceLimit,
                    "byte count overflow",
                )
            })?;
            if next_total > budget.max_map_bytes {
                return Err(SampleError::new(
                    MapSampleStatus::TruncatedResourceLimit,
                    "map byte budget exceeded",
                ));
            }
            if collected.insert(key, split).is_some() {
                return Err(SampleError::new(
                    MapSampleStatus::ConcurrentMutation,
                    "hash batch traversal revisited a key",
                ));
            }
            bytes_read = next_total;
        }
        if rc == -libc::ENOENT {
            break;
        }
        if count == 0 {
            return Err(SampleError::new(
                MapSampleStatus::ReadFailed,
                "zero-length successful batch would not advance",
            ));
        }
        mem::swap(&mut in_cursor, &mut out_cursor);
        have_cursor = true;
    }
    Ok((entries_from_raw(collected), bytes_read))
}

fn sample_hash_next_key(
    fd: c_int,
    info: &libbpf_sys::bpf_map_info,
    possible_cpus: &[u32],
    budget: &bpf_observer_schema::ResourceBudget,
    deadline: Instant,
) -> std::result::Result<(Vec<MapEntry>, u64), SampleError> {
    let per_cpu = info.type_ == MapContentType::PercpuHash.kernel_type();
    let layout = value_layout(info.value_size, per_cpu, possible_cpus)?;
    let key_size = info.key_size as usize;
    ensure_staging_entry_fits(key_size, &layout, budget)?;
    let mut current: Option<Vec<u8>> = None;
    let mut collected: BTreeMap<Vec<u8>, Vec<Vec<u8>>> = BTreeMap::new();
    let mut bytes_read = 0u64;

    loop {
        if Instant::now() > deadline {
            return Err(SampleError::new(
                MapSampleStatus::TruncatedResourceLimit,
                "per-map deadline exceeded",
            ));
        }
        if collected.len() as u64 >= budget.max_map_entries {
            let mut probe = vec![0u8; key_size];
            let rc = unsafe {
                libbpf_sys::bpf_map_get_next_key(
                    fd,
                    current
                        .as_ref()
                        .map(|key| key.as_ptr() as *const c_void)
                        .unwrap_or(ptr::null()),
                    probe.as_mut_ptr() as *mut c_void,
                )
            };
            if rc == -libc::ENOENT {
                break;
            }
            if rc < 0 {
                return Err(classify_read_error(rc, "entry-budget end probe".into()));
            }
            return Err(SampleError::new(
                MapSampleStatus::TruncatedResourceLimit,
                "map contains more entries than the configured budget",
            ));
        }
        let mut next = vec![0u8; key_size];
        let rc = unsafe {
            libbpf_sys::bpf_map_get_next_key(
                fd,
                current
                    .as_ref()
                    .map(|key| key.as_ptr() as *const c_void)
                    .unwrap_or(ptr::null()),
                next.as_mut_ptr() as *mut c_void,
            )
        };
        if rc == -libc::ENOENT {
            break;
        }
        if rc < 0 {
            return Err(classify_read_error(rc, "get next key".into()));
        }
        let mut raw_value = vec![0u8; layout.total_size];
        let rc = unsafe {
            libbpf_sys::bpf_map_lookup_elem(
                fd,
                next.as_ptr() as *const c_void,
                raw_value.as_mut_ptr() as *mut c_void,
            )
        };
        if rc < 0 {
            let mut error = classify_read_error(rc, "lookup enumerated hash key".into());
            if rc == -libc::ENOENT {
                error.status = MapSampleStatus::ConcurrentMutation;
            }
            return Err(error);
        }
        let split = split_value_bytes(&raw_value, info.value_size as usize, &layout);
        let logical = logical_entry_bytes(&next, &split)?;
        let next_total = bytes_read.checked_add(logical).ok_or_else(|| {
            SampleError::new(
                MapSampleStatus::TruncatedResourceLimit,
                "byte count overflow",
            )
        })?;
        if next_total > budget.max_map_bytes {
            return Err(SampleError::new(
                MapSampleStatus::TruncatedResourceLimit,
                "map byte budget exceeded",
            ));
        }
        if let Some(previous) = collected.insert(next.clone(), split.clone()) {
            if previous != split {
                return Err(SampleError::new(
                    MapSampleStatus::ConcurrentMutation,
                    "same key appeared with different values during traversal",
                ));
            }
            return Err(SampleError::new(
                MapSampleStatus::ConcurrentMutation,
                "hash traversal revisited a key",
            ));
        }
        bytes_read = next_total;
        current = Some(next);
    }
    Ok((entries_from_raw(collected), bytes_read))
}

#[derive(Clone, Copy, Debug)]
struct ValueLayout {
    stride: usize,
    count: usize,
    total_size: usize,
}

fn retained_representation_estimate(
    key_size: usize,
    value_size: usize,
    value_count: usize,
    entry_count: u64,
) -> std::result::Result<u64, SampleError> {
    let key_cost = (key_size as u64).checked_mul(4).ok_or_else(|| {
        SampleError::new(
            MapSampleStatus::TruncatedResourceLimit,
            "retained key representation estimate overflow",
        )
    })?;
    let per_value = (value_size as u64)
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(64))
        .ok_or_else(|| {
            SampleError::new(
                MapSampleStatus::TruncatedResourceLimit,
                "retained value representation estimate overflow",
            )
        })?;
    let per_entry = (value_count as u64)
        .checked_mul(per_value)
        .and_then(|bytes| bytes.checked_add(key_cost))
        .and_then(|bytes| bytes.checked_add(128))
        .ok_or_else(|| {
            SampleError::new(
                MapSampleStatus::TruncatedResourceLimit,
                "retained entry representation estimate overflow",
            )
        })?;
    let entries = per_entry.checked_mul(entry_count).ok_or_else(|| {
        SampleError::new(
            MapSampleStatus::TruncatedResourceLimit,
            "retained Map representation estimate overflow",
        )
    })?;
    let topology = if value_count > 1 {
        (value_count as u64)
            .checked_mul(8)
            .and_then(|bytes| bytes.checked_add(64))
            .ok_or_else(|| {
                SampleError::new(
                    MapSampleStatus::TruncatedResourceLimit,
                    "per-CPU topology representation estimate overflow",
                )
            })?
    } else {
        0
    };
    entries.checked_add(topology).ok_or_else(|| {
        SampleError::new(
            MapSampleStatus::TruncatedResourceLimit,
            "retained Map representation estimate overflow",
        )
    })
}

fn retained_representation_bytes(content: &MapContentState) -> u64 {
    let entries = content.entries.iter().fold(0u64, |total, entry| {
        let entry_cost = entry.values_hex.iter().fold(
            128u64.saturating_add((entry.key_hex.len() as u64).saturating_mul(2)),
            |subtotal, value| {
                subtotal
                    .saturating_add(64)
                    .saturating_add((value.len() as u64).saturating_mul(2))
            },
        );
        total.saturating_add(entry_cost)
    });
    let topology = if content.possible_cpu_ids.is_empty() {
        0
    } else {
        (content.possible_cpu_ids.len() as u64)
            .saturating_mul(8)
            .saturating_add(64)
    };
    entries.saturating_add(topology)
}

fn value_layout(
    value_size: u32,
    per_cpu: bool,
    possible_cpus: &[u32],
) -> std::result::Result<ValueLayout, SampleError> {
    let value_size = value_size as usize;
    let count = if per_cpu { possible_cpus.len() } else { 1 };
    let stride = if per_cpu {
        value_size
            .checked_add(7)
            .map(|value| value & !7)
            .ok_or_else(|| {
                SampleError::new(
                    MapSampleStatus::TruncatedResourceLimit,
                    "value stride overflow",
                )
            })?
    } else {
        value_size
    };
    let total_size = stride.checked_mul(count).ok_or_else(|| {
        SampleError::new(
            MapSampleStatus::TruncatedResourceLimit,
            "value buffer overflow",
        )
    })?;
    Ok(ValueLayout {
        stride,
        count,
        total_size,
    })
}

fn ensure_staging_entry_fits(
    key_size: usize,
    layout: &ValueLayout,
    budget: &bpf_observer_schema::ResourceBudget,
) -> std::result::Result<usize, SampleError> {
    let raw_bytes = key_size.checked_add(layout.total_size).ok_or_else(|| {
        SampleError::new(
            MapSampleStatus::TruncatedResourceLimit,
            "staging allocation size overflow",
        )
    })?;
    let raw_bytes_u64 = u64::try_from(raw_bytes).map_err(|_| {
        SampleError::new(
            MapSampleStatus::TruncatedResourceLimit,
            "staging allocation is not representable",
        )
    })?;
    if raw_bytes == 0 || raw_bytes_u64 > budget.max_map_bytes {
        return Err(SampleError::new(
            MapSampleStatus::TruncatedResourceLimit,
            format!(
                "one raw key/value staging entry needs {raw_bytes_u64} bytes, budget is {}",
                budget.max_map_bytes
            ),
        ));
    }
    Ok(raw_bytes)
}

fn split_values(raw: &[u8], value_size: usize, layout: &ValueLayout) -> Vec<String> {
    split_value_bytes(raw, value_size, layout)
        .into_iter()
        .map(hex::encode)
        .collect()
}

fn split_value_bytes(raw: &[u8], value_size: usize, layout: &ValueLayout) -> Vec<Vec<u8>> {
    (0..layout.count)
        .map(|slot| {
            let start = slot * layout.stride;
            raw[start..start + value_size].to_vec()
        })
        .collect()
}

fn logical_entry_bytes(key: &[u8], values: &[Vec<u8>]) -> std::result::Result<u64, SampleError> {
    let mut total = key.len() as u64;
    for value in values {
        total = total.checked_add(value.len() as u64).ok_or_else(|| {
            SampleError::new(
                MapSampleStatus::TruncatedResourceLimit,
                "byte count overflow",
            )
        })?;
    }
    Ok(total)
}

fn entries_from_raw(raw: BTreeMap<Vec<u8>, Vec<Vec<u8>>>) -> Vec<MapEntry> {
    raw.into_iter()
        .map(|(key, values)| MapEntry {
            key_hex: hex::encode(key),
            values_hex: values.into_iter().map(hex::encode).collect(),
        })
        .collect()
}

fn digest_entries(entries: &[MapEntry]) -> String {
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

fn classify_read_error(rc: c_int, operation: String) -> SampleError {
    let status = match -rc {
        libc::EPERM | libc::EACCES => MapSampleStatus::ReadForbidden,
        libc::ENOENT => MapSampleStatus::ObjectDisappeared,
        _ => MapSampleStatus::ReadFailed,
    };
    SampleError::new(status, format!("{operation}: {}", errno_from_libbpf(rc)))
}

fn map_metadata_view(maps: &[MapState]) -> Vec<(&ObjectIdentity, &MapMetadata, bool)> {
    maps.iter()
        .map(|map| (&map.identity, &map.metadata, map.excluded))
        .collect()
}

fn mark_maps_concurrent(maps: &mut [MapState]) {
    for map in maps.iter_mut().filter(|map| !map.excluded) {
        if matches!(
            map.content.status,
            MapSampleStatus::CompleteQuiescent | MapSampleStatus::BestEffortNonAtomic
        ) {
            map.content.status = MapSampleStatus::ConcurrentMutation;
            map.content.semantic_complete = false;
            map.content.entries.clear();
            map.content.digest_sha256 = None;
            map.content.bytes_read = 0;
            map.content.possible_cpu_ids.clear();
            map.content.error = Some("map metadata inventory changed during capture".into());
        }
    }
}

fn capture_links(
    boot_id: &str,
    exclusions: &ObjectExclusions,
    failures: &mut Vec<ObjectReadFailure>,
    completeness: &mut Completeness,
    optional_failure_ids: Option<&BTreeSet<u32>>,
    pass: &str,
) -> Vec<bpf_observer_schema::LinkState> {
    let ids = match enumerate_ids(libbpf_sys::bpf_link_get_next_id) {
        Ok(ids) => ids,
        Err(error) => {
            record_failure(
                failures,
                completeness,
                ObjectType::Link,
                0,
                format!("{pass}-enumerate"),
                error.to_string(),
            );
            return Vec::new();
        }
    };

    let mut links = Vec::with_capacity(ids.len());
    for id in ids {
        let excluded = exclusions.link_ids.contains(&id);
        let fd = match owned_fd(unsafe { libbpf_sys::bpf_link_get_fd_by_id(id) }) {
            Ok(fd) => fd,
            Err(error) => {
                record_failure(
                    failures,
                    completeness,
                    ObjectType::Link,
                    id,
                    format!("{pass}-get-fd"),
                    error.to_string(),
                );
                continue;
            }
        };
        match read_link(fd.as_raw_fd(), boot_id, id, excluded) {
            Ok(link) => {
                if link.target.is_none()
                    && !excluded
                    && optional_failure_ids.map_or(true, |initial_ids| initial_ids.contains(&id))
                {
                    record_failure(
                        failures,
                        completeness,
                        ObjectType::Link,
                        id,
                        format!("{pass}-target-adapter"),
                        format!("unsupported or incomplete link type {}", link.link_type),
                    );
                }
                links.push(link);
            }
            Err(error) => record_failure(
                failures,
                completeness,
                ObjectType::Link,
                id,
                format!("{pass}-get-info"),
                error.to_string(),
            ),
        }
    }
    links.sort_by_key(|link| link.identity.id);
    links
}

fn read_link(
    fd: c_int,
    boot_id: &str,
    expected_id: u32,
    excluded: bool,
) -> Result<bpf_observer_schema::LinkState> {
    let mut info = libbpf_sys::bpf_link_info::default();
    get_info(fd, &mut info)?;
    if info.id != expected_id {
        bail!(
            "link info ID {} does not match enumerated ID {expected_id}",
            info.id
        );
    }
    let target = unsafe { direct_link_target(&info) };
    Ok(bpf_observer_schema::LinkState {
        identity: ObjectIdentity {
            boot_id: boot_id.into(),
            object_type: ObjectType::Link,
            id: info.id,
        },
        link_type: info.type_,
        program_id: info.prog_id,
        target,
        excluded,
    })
}

unsafe fn direct_link_target(info: &libbpf_sys::bpf_link_info) -> Option<Value> {
    if info.prog_id == 0 {
        return None;
    }
    match info.type_ {
        libbpf_sys::BPF_LINK_TYPE_TRACING => {
            let target = info.__bindgen_anon_1.tracing;
            Some(json!({
                "kind": "TRACING",
                "attach_type": target.attach_type,
                "target_obj_id": target.target_obj_id,
                "target_btf_id": target.target_btf_id,
            }))
        }
        libbpf_sys::BPF_LINK_TYPE_CGROUP => {
            let target = info.__bindgen_anon_1.cgroup;
            if target.cgroup_id == 0 {
                return None;
            }
            Some(json!({
                "kind": "CGROUP",
                "cgroup_id": target.cgroup_id,
                "attach_type": target.attach_type,
            }))
        }
        libbpf_sys::BPF_LINK_TYPE_NETNS => {
            let target = info.__bindgen_anon_1.netns;
            if target.netns_ino == 0 {
                return None;
            }
            Some(json!({
                "kind": "NETNS",
                "netns_ino": target.netns_ino,
                "attach_type": target.attach_type,
            }))
        }
        libbpf_sys::BPF_LINK_TYPE_XDP => {
            let target = info.__bindgen_anon_1.xdp;
            if target.ifindex == 0 {
                return None;
            }
            Some(json!({"kind": "XDP", "ifindex": target.ifindex}))
        }
        _ => None,
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct PinCapture {
    roots: Vec<PinRootIdentity>,
    pins: Vec<PinState>,
}

fn capture_pins(
    scope: &ClaimScope,
    exclusions: &ObjectExclusions,
    failures: &mut Vec<ObjectReadFailure>,
    completeness: &mut Completeness,
    notes: &mut Vec<String>,
) -> PinCapture {
    if scope.bpffs_roots.is_empty() {
        return PinCapture::default();
    }
    let mount_namespace_inode = match fs::metadata("/proc/self/ns/mnt") {
        Ok(metadata) => metadata.ino(),
        Err(error) => {
            record_failure(
                failures,
                completeness,
                ObjectType::Map,
                0,
                "pin-read-mount-namespace",
                error.to_string(),
            );
            return PinCapture::default();
        }
    };
    let mut pins: BTreeMap<(u64, u64, String), PinState> = BTreeMap::new();
    let mut roots = BTreeMap::new();
    let mut canonical_roots = BTreeSet::new();
    let mut visited_items = 0usize;
    let mut retained_path_bytes = 0u64;

    for configured_root in &scope.bpffs_roots {
        match fs::symlink_metadata(configured_root) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                record_failure(
                    failures,
                    completeness,
                    ObjectType::Map,
                    0,
                    format!("pin-root-symlink:{configured_root}"),
                    "bpffs root must not be a symlink",
                );
                continue;
            }
            Ok(_) => {}
            Err(error) => {
                record_failure(
                    failures,
                    completeness,
                    ObjectType::Map,
                    0,
                    format!("pin-lstat-root:{configured_root}"),
                    error.to_string(),
                );
                continue;
            }
        }
        let root = match fs::canonicalize(configured_root) {
            Ok(root) => root,
            Err(error) => {
                record_failure(
                    failures,
                    completeness,
                    ObjectType::Map,
                    0,
                    format!("pin-canonicalize:{configured_root}"),
                    error.to_string(),
                );
                continue;
            }
        };
        if root.as_os_str().as_bytes() != configured_root.as_bytes() {
            record_failure(
                failures,
                completeness,
                ObjectType::Map,
                0,
                format!("pin-noncanonical-root:{configured_root}"),
                format!(
                    "configured bpffs root resolves to {}; use the canonical absolute path",
                    root.display()
                ),
            );
            continue;
        }
        if !canonical_roots.insert(root.clone()) {
            notes.push(format!("duplicate bpffs root ignored: {}", root.display()));
            continue;
        }
        let root_file = match File::open(&root) {
            Ok(file) => file,
            Err(error) => {
                record_failure(
                    failures,
                    completeness,
                    ObjectType::Map,
                    0,
                    format!("pin-open-root:{}", root.display()),
                    error.to_string(),
                );
                continue;
            }
        };
        if let Err(error) = ensure_bpffs(root_file.as_raw_fd()) {
            record_failure(
                failures,
                completeness,
                ObjectType::Map,
                0,
                format!("pin-verify-bpffs:{}", root.display()),
                error.to_string(),
            );
            continue;
        }
        let mount_id = match statx_mount_id(&root) {
            Ok(mount_id) => mount_id,
            Err(error) => {
                record_failure(
                    failures,
                    completeness,
                    ObjectType::Map,
                    0,
                    format!("pin-mount-id-root:{}", root.display()),
                    error.to_string(),
                );
                continue;
            }
        };
        roots.insert(
            configured_root.clone(),
            PinRootIdentity {
                path: configured_root.clone(),
                mount_namespace_inode,
                mount_id,
            },
        );
        walk_pin_root(
            &root,
            mount_namespace_inode,
            mount_id,
            scope,
            exclusions,
            &mut pins,
            &mut visited_items,
            &mut retained_path_bytes,
            failures,
            completeness,
        );
    }
    PinCapture {
        roots: roots.into_values().collect(),
        pins: pins.into_values().collect(),
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_pin_root(
    root: &Path,
    mount_namespace_inode: u64,
    mount_id: u64,
    scope: &ClaimScope,
    exclusions: &ObjectExclusions,
    pins: &mut BTreeMap<(u64, u64, String), PinState>,
    visited_items: &mut usize,
    retained_path_bytes: &mut u64,
    failures: &mut Vec<ObjectReadFailure>,
    completeness: &mut Completeness,
) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                record_failure(
                    failures,
                    completeness,
                    ObjectType::Map,
                    0,
                    format!("pin-read-dir:{}", directory.display()),
                    error.to_string(),
                );
                continue;
            }
        };
        let mut paths = Vec::new();
        for entry in entries {
            match entry {
                Ok(entry) => {
                    if *visited_items >= MAX_PIN_WALK_ITEMS {
                        record_failure(
                            failures,
                            completeness,
                            ObjectType::Map,
                            0,
                            format!("pin-resource-limit:{}", root.display()),
                            format!(
                                "bpffs traversal exceeds hard limit of {MAX_PIN_WALK_ITEMS} items"
                            ),
                        );
                        return;
                    }
                    *visited_items += 1;
                    let path = entry.path();
                    let traversal_charge = (path.as_os_str().as_bytes().len() as u64)
                        .saturating_mul(2)
                        .saturating_add(128);
                    let next_retained = retained_path_bytes.saturating_add(traversal_charge);
                    if next_retained > MAX_PIN_REPRESENTATION_BYTES {
                        record_failure(
                            failures,
                            completeness,
                            ObjectType::Map,
                            0,
                            "pin-resource-limit",
                            format!(
                                "bpffs traversal/path representation exceeded {MAX_PIN_REPRESENTATION_BYTES} bytes"
                            ),
                        );
                        return;
                    }
                    *retained_path_bytes = next_retained;
                    paths.push(path);
                }
                Err(error) => record_failure(
                    failures,
                    completeness,
                    ObjectType::Map,
                    0,
                    format!("pin-read-entry:{}", directory.display()),
                    error.to_string(),
                ),
            }
        }
        paths.sort_by(|left, right| {
            left.as_os_str()
                .as_bytes()
                .cmp(right.as_os_str().as_bytes())
        });
        for path in paths {
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    record_failure(
                        failures,
                        completeness,
                        ObjectType::Map,
                        0,
                        format!("pin-lstat:{}", path.display()),
                        error.to_string(),
                    );
                    continue;
                }
            };
            if metadata.file_type().is_symlink() {
                record_failure(
                    failures,
                    completeness,
                    ObjectType::Map,
                    0,
                    format!("pin-symlink:{}", path.display()),
                    "symlinks are not followed",
                );
                continue;
            }
            let entry_mount_id = match statx_mount_id(&path) {
                Ok(entry_mount_id) => entry_mount_id,
                Err(error) => {
                    record_failure(
                        failures,
                        completeness,
                        ObjectType::Map,
                        0,
                        format!("pin-mount-id:{}", path.display()),
                        error.to_string(),
                    );
                    continue;
                }
            };
            if entry_mount_id != mount_id {
                record_failure(
                    failures,
                    completeness,
                    ObjectType::Map,
                    0,
                    format!("pin-cross-mount:{}", path.display()),
                    "nested mount is outside the declared bpffs root",
                );
                continue;
            }
            if metadata.is_dir() {
                pending.push(path);
                continue;
            }
            match read_pin(&path, mount_namespace_inode, entry_mount_id) {
                Ok(mut pin) if scope.object_types.contains(&pin.object_type) => {
                    let retained = (pin.path.len() as u64)
                        .saturating_add(pin.path_bytes_hex.len() as u64)
                        .saturating_add(128);
                    let next_retained = retained_path_bytes.saturating_add(retained);
                    if next_retained > MAX_PIN_REPRESENTATION_BYTES {
                        record_failure(
                            failures,
                            completeness,
                            ObjectType::Map,
                            0,
                            "pin-resource-limit",
                            format!(
                                "pin representation exceeded {MAX_PIN_REPRESENTATION_BYTES} bytes"
                            ),
                        );
                        return;
                    }
                    *retained_path_bytes = next_retained;
                    pin.excluded = match pin.object_type {
                        ObjectType::Program => exclusions.program_ids.contains(&pin.object_id),
                        ObjectType::Map => exclusions.map_ids.contains(&pin.object_id),
                        ObjectType::Link => exclusions.link_ids.contains(&pin.object_id),
                    };
                    let key = (
                        pin.mount_namespace_inode,
                        pin.mount_id,
                        pin.path_bytes_hex.clone(),
                    );
                    pins.insert(key, pin);
                }
                Ok(_) => {}
                Err(error) => record_failure(
                    failures,
                    completeness,
                    ObjectType::Map,
                    0,
                    format!("pin-open:{}", path.display()),
                    error.to_string(),
                ),
            }
        }
    }
}

fn ensure_bpffs(fd: c_int) -> Result<()> {
    let mut stats = MaybeUninit::<libc::statfs>::zeroed();
    let rc = unsafe { libc::fstatfs(fd, stats.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error()).context("fstatfs");
    }
    let stats = unsafe { stats.assume_init() };
    if stats.f_type != BPF_FS_MAGIC {
        bail!("filesystem magic {:#x} is not BPF_FS_MAGIC", stats.f_type);
    }
    Ok(())
}

fn statx_mount_id(path: &Path) -> Result<u64> {
    let c_path = cstring_path(path)?;
    let mut statx = MaybeUninit::<libc::statx>::zeroed();
    let rc = unsafe {
        libc::statx(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_MNT_ID,
            statx.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error()).context("statx(STATX_MNT_ID)");
    }
    let statx = unsafe { statx.assume_init() };
    if statx.stx_mask & libc::STATX_MNT_ID == 0 {
        bail!("statx result omitted STATX_MNT_ID");
    }
    if statx.stx_mnt_id == 0 {
        bail!("statx returned a zero mount ID");
    }
    Ok(statx.stx_mnt_id)
}

fn read_pin(path: &Path, mount_namespace_inode: u64, mount_id: u64) -> Result<PinState> {
    let c_path = cstring_path(path)?;
    let fd = owned_fd(unsafe { libbpf_sys::bpf_obj_get(c_path.as_ptr()) })?;
    let object_type = fd_object_type(fd.as_raw_fd())?;
    let object_id = match object_type {
        ObjectType::Program => {
            let mut info = libbpf_sys::bpf_prog_info::default();
            get_info(fd.as_raw_fd(), &mut info)?;
            info.id
        }
        ObjectType::Map => {
            let mut info = libbpf_sys::bpf_map_info::default();
            get_info(fd.as_raw_fd(), &mut info)?;
            info.id
        }
        ObjectType::Link => {
            let mut info = libbpf_sys::bpf_link_info::default();
            get_info(fd.as_raw_fd(), &mut info)?;
            info.id
        }
    };
    Ok(PinState {
        path: path.to_string_lossy().into_owned(),
        path_bytes_hex: hex::encode(path.as_os_str().as_bytes()),
        mount_namespace_inode,
        mount_id,
        object_type,
        object_id,
        excluded: false,
    })
}

fn cstring_path(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).context("path contains NUL")
}

fn fd_object_type(fd: c_int) -> Result<ObjectType> {
    let target = fs::read_link(format!("/proc/self/fd/{fd}"))?;
    let bytes = target.as_os_str().as_bytes();
    if contains_bytes(bytes, b"bpf-prog") {
        Ok(ObjectType::Program)
    } else if contains_bytes(bytes, b"bpf-map") {
        Ok(ObjectType::Map)
    } else if contains_bytes(bytes, b"bpf-link") {
        Ok(ObjectType::Link)
    } else {
        bail!("pinned FD has unknown object type: {}", target.display())
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounded_snapshot() -> Snapshot {
        Snapshot {
            schema_version: SCHEMA_VERSION,
            snapshot_id: "test-S0".into(),
            phase: "S0".into(),
            boot_id: "test-boot".into(),
            captured_unix_ns: 1,
            capture_duration_ns: 1,
            kernel_release: "test-kernel".into(),
            byte_order: "little".into(),
            possible_cpu_ids: vec![0, 1],
            claim_scope: ClaimScope::default(),
            observer_exclusions: ObjectExclusions::default(),
            programs: Vec::new(),
            maps: Vec::new(),
            links: Vec::new(),
            pin_roots: Vec::new(),
            pins: Vec::new(),
            read_failures: Vec::new(),
            completeness: Completeness::complete(),
            notes: Vec::new(),
        }
    }

    fn sampled_hash_map(id: u32, entries: Vec<MapEntry>) -> MapState {
        let bytes_read = entries.len() as u64 * 2;
        MapState {
            identity: ObjectIdentity {
                boot_id: "test-boot".into(),
                object_type: ObjectType::Map,
                id,
            },
            metadata: MapMetadata {
                map_type: MapContentType::Hash.kernel_type(),
                name: "test".into(),
                key_size: 1,
                value_size: 1,
                max_entries: 16,
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
            content: complete_map_sample(entries, bytes_read, Vec::new(), false),
            excluded: false,
        }
    }

    fn program_with_maps(id: u32, map_ids: Vec<u32>) -> ProgramState {
        ProgramState {
            identity: ObjectIdentity {
                boot_id: "test-boot".into(),
                object_type: ObjectType::Program,
                id,
            },
            program_type: 1,
            name: "test".into(),
            tag_hex: "0000000000000000".into(),
            load_time_ns: 1,
            created_by_uid: 0,
            btf_id: 0,
            attach_btf_obj_id: 0,
            attach_btf_id: 0,
            ifindex: 0,
            netns_dev: 0,
            netns_ino: 0,
            map_ids,
            excluded: false,
        }
    }

    fn add_read_failure(
        snapshot: &mut Snapshot,
        object_type: ObjectType,
        id: u32,
        operation: &str,
    ) {
        snapshot.completeness.mark_incomplete(READ_FAILURE_REASON);
        snapshot.read_failures.push(ObjectReadFailure {
            object_type,
            id,
            operation: operation.into(),
            error: "fixture failure".into(),
        });
    }

    #[test]
    fn cpu_list_is_sorted_and_deduplicated() {
        assert_eq!(parse_cpu_list("0-2,4,2").unwrap(), vec![0, 1, 2, 4]);
        assert!(parse_cpu_list("3-1").is_err());
        assert!(parse_cpu_list("0,,2").is_err());
    }

    #[test]
    fn fdinfo_requires_matching_map_and_frozen_field() {
        let input = "pos:\t0\nflags:\t02000002\nmap_id:\t42\nfrozen:\t1\n";
        assert!(parse_frozen_fdinfo(input, 42).unwrap());
        assert!(parse_frozen_fdinfo(input, 41).is_err());
        assert!(parse_frozen_fdinfo("map_id:\t42\n", 42).is_err());
    }

    #[test]
    fn percpu_padding_is_removed() {
        let layout = ValueLayout {
            stride: 8,
            count: 2,
            total_size: 16,
        };
        let mut raw = vec![0xaau8; 16];
        raw[0..3].copy_from_slice(&[1, 2, 3]);
        raw[8..11].copy_from_slice(&[4, 5, 6]);
        assert_eq!(
            split_values(&raw, 3, &layout),
            vec!["010203".to_string(), "040506".to_string()]
        );
    }

    #[test]
    fn digest_is_order_sensitive_but_canonical_sort_is_not() {
        let first = MapEntry {
            key_hex: "01".into(),
            values_hex: vec!["aa".into()],
        };
        let second = MapEntry {
            key_hex: "02".into(),
            values_hex: vec!["bb".into()],
        };
        assert_ne!(
            digest_entries(&[first.clone(), second.clone()]),
            digest_entries(&[second.clone(), first.clone()])
        );
        let left = complete_map_sample(vec![second, first], 4, Vec::new(), true);
        assert_eq!(left.entries[0].key_hex, "01");
        assert_eq!(left.status, MapSampleStatus::CompleteQuiescent);
        assert!(left.semantic_complete);
    }

    #[test]
    fn non_quiescent_complete_read_keeps_axes_separate() {
        let sample = complete_map_sample(Vec::new(), 0, Vec::new(), false);
        assert_eq!(sample.status, MapSampleStatus::BestEffortNonAtomic);
        assert!(sample.semantic_complete);
    }

    #[test]
    fn percpu_representation_estimate_accounts_for_per_slot_allocations() {
        let estimate = retained_representation_estimate(4, 1, 256, 65_536).unwrap();
        assert!(estimate > MAX_TOTAL_RETAINED_MAP_REPRESENTATION_BYTES);
        assert!(
            retained_representation_estimate(4, 8, 1, 128).unwrap()
                < MAX_TOTAL_RETAINED_MAP_REPRESENTATION_BYTES
        );
    }

    #[test]
    fn producer_snapshot_contract_accepts_canonical_snapshot() {
        let mut snapshot = bounded_snapshot();
        snapshot
            .claim_scope
            .map_content_types
            .insert(MapContentType::Hash);
        snapshot.claim_scope.map_ids.insert(7);
        snapshot.maps.push(sampled_hash_map(
            7,
            vec![MapEntry {
                key_hex: "01".into(),
                values_hex: vec!["aa".into()],
            }],
        ));

        validate_snapshot_resource_bounds(&snapshot).unwrap();
    }

    #[test]
    fn producer_snapshot_contract_rejects_impossible_link_target() {
        let mut snapshot = bounded_snapshot();
        snapshot.programs.push(program_with_maps(12, Vec::new()));
        snapshot.links.push(LinkState {
            identity: ObjectIdentity {
                boot_id: "test-boot".into(),
                object_type: ObjectType::Link,
                id: 11,
            },
            link_type: libbpf_sys::BPF_LINK_TYPE_XDP,
            program_id: 12,
            target: Some(json!({"kind": "XDP", "ifindex": 3})),
            excluded: false,
        });
        validate_snapshot_resource_bounds(&snapshot).unwrap();

        snapshot.links[0].target = Some(json!({"kind": "XDP", "ifindex": 0}));
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());
        snapshot.links[0].target = Some(json!({"kind": "XDP", "ifindex": 3, "extra": 1}));
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());
    }

    #[test]
    fn producer_snapshot_contract_rejects_noncanonical_cpu_and_map_keys() {
        let mut snapshot = bounded_snapshot();
        snapshot.possible_cpu_ids = vec![1, 0];
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());

        let mut snapshot = bounded_snapshot();
        snapshot
            .claim_scope
            .map_content_types
            .insert(MapContentType::Hash);
        snapshot.claim_scope.map_ids.insert(7);
        snapshot.maps.push(sampled_hash_map(
            7,
            vec![
                MapEntry {
                    key_hex: "01".into(),
                    values_hex: vec!["aa".into()],
                },
                MapEntry {
                    key_hex: "01".into(),
                    values_hex: vec!["bb".into()],
                },
            ],
        ));
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());
    }

    #[test]
    fn producer_snapshot_contract_rejects_opaque_or_zero_width_complete_maps() {
        let mut snapshot = bounded_snapshot();
        snapshot
            .claim_scope
            .map_content_types
            .insert(MapContentType::Hash);
        snapshot.claim_scope.map_ids.insert(7);
        snapshot.maps.push(sampled_hash_map(
            7,
            vec![MapEntry {
                key_hex: "01".into(),
                values_hex: vec!["aa".into()],
            }],
        ));

        snapshot.maps[0].metadata.btf_value_type_id = 1;
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());
        snapshot.maps[0].metadata.btf_value_type_id = 0;
        snapshot.maps[0].metadata.btf_vmlinux_value_type_id = 1;
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());
        snapshot.maps[0].metadata.btf_vmlinux_value_type_id = 0;
        snapshot.maps[0].metadata.key_size = 0;
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());
        snapshot.maps[0].metadata.key_size = 1;
        snapshot.maps[0].metadata.max_entries = 0;
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());
    }

    #[test]
    fn metadata_only_map_requires_frozen_state_or_a_producer_failure() {
        let mut snapshot = bounded_snapshot();
        let mut map = sampled_hash_map(7, Vec::new());
        map.content = outside_scope_content();
        map.metadata.frozen = None;
        snapshot.maps.push(map);
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());
    }

    #[test]
    fn metadata_only_supported_map_rejects_impossible_kernel_shape() {
        let mut snapshot = bounded_snapshot();
        let mut map = sampled_hash_map(7, Vec::new());
        map.content = outside_scope_content();
        map.metadata.map_type = MapContentType::Array.kernel_type();
        map.metadata.key_size = 8;
        map.metadata.max_entries = 0;
        snapshot.maps.push(map);
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());
    }

    #[test]
    fn complete_snapshot_requires_closed_object_references() {
        let mut snapshot = bounded_snapshot();
        snapshot.observer_exclusions.program_ids.insert(99);
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());

        let mut snapshot = bounded_snapshot();
        snapshot.claim_scope.bpffs_roots = vec!["/sys/fs/bpf".into()];
        snapshot.pin_roots.push(PinRootIdentity {
            path: "/sys/fs/bpf".into(),
            mount_namespace_inode: 1,
            mount_id: 1,
        });
        snapshot.pins.push(PinState {
            path: "/sys/fs/bpf/missing".into(),
            path_bytes_hex: hex::encode(b"/sys/fs/bpf/missing"),
            mount_namespace_inode: 1,
            mount_id: 1,
            object_type: ObjectType::Map,
            object_id: 7,
            excluded: false,
        });
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());
    }

    #[test]
    fn producer_snapshot_contract_charges_map_errors_as_diagnostics() {
        let mut snapshot = bounded_snapshot();
        snapshot.completeness.mark_incomplete(
            "one or more selected Map contents are not semantically complete (ReadFailed)",
        );
        snapshot
            .claim_scope
            .map_content_types
            .insert(MapContentType::Hash);
        snapshot.claim_scope.map_ids.insert(7);
        let mut map = sampled_hash_map(7, Vec::new());
        map.content = map_sample_error(
            MapSampleStatus::ReadFailed,
            "x".repeat(MAX_DIAGNOSTIC_STRING_BYTES + 1),
        );
        snapshot.maps.push(map);
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());
    }

    #[test]
    fn selected_incomplete_map_cannot_hide_in_a_complete_snapshot() {
        let mut snapshot = bounded_snapshot();
        snapshot
            .claim_scope
            .map_content_types
            .insert(MapContentType::Hash);
        snapshot.claim_scope.map_ids.insert(7);
        let mut map = sampled_hash_map(7, Vec::new());
        map.content = map_sample_error(MapSampleStatus::ReadFailed, "read failed".into());
        snapshot.maps.push(map);
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());
    }

    #[test]
    fn producer_snapshot_contract_requires_complete_canonical_arrays() {
        let mut snapshot = bounded_snapshot();
        snapshot
            .claim_scope
            .map_content_types
            .insert(MapContentType::Array);
        snapshot.claim_scope.map_ids.insert(9);
        let mut map = sampled_hash_map(
            9,
            vec![
                MapEntry {
                    key_hex: "00000000".into(),
                    values_hex: vec!["aa".into()],
                },
                MapEntry {
                    key_hex: "01000000".into(),
                    values_hex: vec!["bb".into()],
                },
            ],
        );
        map.metadata.map_type = MapContentType::Array.kernel_type();
        map.metadata.key_size = 4;
        map.metadata.max_entries = 2;
        map.content = complete_map_sample(map.content.entries, 10, Vec::new(), false);
        snapshot.maps.push(map);
        validate_snapshot_resource_bounds(&snapshot).unwrap();

        snapshot.maps[0].content.entries.pop();
        snapshot.maps[0].content.bytes_read = 5;
        snapshot.maps[0].content.digest_sha256 =
            Some(digest_entries(&snapshot.maps[0].content.entries));
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());
    }

    #[test]
    fn producer_snapshot_contract_rejects_diagnostic_count_overflow() {
        let mut snapshot = bounded_snapshot();
        snapshot.completeness.status = CompletenessStatus::Incomplete;
        snapshot.completeness.reasons = (0..=MAX_SNAPSHOT_REASONS)
            .map(|index| format!("reason-{index:04}"))
            .collect();
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());
    }

    #[test]
    fn producer_snapshot_contract_uses_a_closed_diagnostic_grammar() {
        let mut snapshot = bounded_snapshot();
        snapshot
            .completeness
            .mark_incomplete("forged unknown reason");
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());

        let mut snapshot = bounded_snapshot();
        add_read_failure(&mut snapshot, ObjectType::Program, 7, "initial-invented");
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());

        let mut snapshot = bounded_snapshot();
        add_read_failure(&mut snapshot, ObjectType::Program, 7, "initial-enumerate");
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());
    }

    #[test]
    fn producer_snapshot_contract_binds_read_failures_and_truncation_reasons() {
        let mut snapshot = bounded_snapshot();
        snapshot.completeness.mark_incomplete(READ_FAILURE_REASON);
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());

        let mut snapshot = bounded_snapshot();
        snapshot
            .completeness
            .mark_incomplete("program inventory changed during capture");
        snapshot.read_failures.push(ObjectReadFailure {
            object_type: ObjectType::Program,
            id: 0,
            operation: "initial-enumerate".into(),
            error: "fixture failure".into(),
        });
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());

        let mut snapshot = bounded_snapshot();
        snapshot.completeness.mark_incomplete(READ_FAILURE_REASON);
        snapshot
            .completeness
            .mark_incomplete(READ_FAILURE_TRUNCATION_REASON);
        snapshot.read_failures.push(ObjectReadFailure {
            object_type: ObjectType::Program,
            id: 0,
            operation: "initial-enumerate".into(),
            error: "fixture failure".into(),
        });
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());
    }

    #[test]
    fn field_failures_are_bound_to_present_objects_and_missing_fields() {
        let mut snapshot = bounded_snapshot();
        let mut map = sampled_hash_map(7, Vec::new());
        map.content = outside_scope_content();
        map.metadata.frozen = None;
        snapshot.maps.push(map);
        add_read_failure(
            &mut snapshot,
            ObjectType::Map,
            7,
            "initial-read-fdinfo-frozen",
        );
        validate_snapshot_resource_bounds(&snapshot).unwrap();
        snapshot.maps[0].metadata.frozen = Some(false);
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());

        let mut snapshot = bounded_snapshot();
        let mut map = sampled_hash_map(7, Vec::new());
        map.content = outside_scope_content();
        snapshot.maps.push(map);
        add_read_failure(
            &mut snapshot,
            ObjectType::Map,
            7,
            "verification-read-fdinfo-frozen",
        );
        validate_snapshot_resource_bounds(&snapshot).unwrap();

        let mut snapshot = bounded_snapshot();
        snapshot.links.push(LinkState {
            identity: ObjectIdentity {
                boot_id: "test-boot".into(),
                object_type: ObjectType::Link,
                id: 11,
            },
            link_type: libbpf_sys::BPF_LINK_TYPE_XDP,
            program_id: 12,
            target: None,
            excluded: false,
        });
        add_read_failure(
            &mut snapshot,
            ObjectType::Link,
            11,
            "initial-target-adapter",
        );
        validate_snapshot_resource_bounds(&snapshot).unwrap();
        snapshot.links[0].target = Some(json!({"kind": "XDP", "ifindex": 3}));
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());

        let mut snapshot = bounded_snapshot();
        snapshot.links.push(LinkState {
            identity: ObjectIdentity {
                boot_id: "test-boot".into(),
                object_type: ObjectType::Link,
                id: 11,
            },
            link_type: libbpf_sys::BPF_LINK_TYPE_XDP,
            program_id: 12,
            target: Some(json!({"kind": "XDP", "ifindex": 3})),
            excluded: false,
        });
        add_read_failure(
            &mut snapshot,
            ObjectType::Link,
            11,
            "verification-target-adapter",
        );
        validate_snapshot_resource_bounds(&snapshot).unwrap();
    }

    #[test]
    fn pin_root_domains_cover_empty_and_nonempty_pin_inventories() {
        let mut snapshot = bounded_snapshot();
        snapshot.claim_scope.bpffs_roots = vec!["/sys/fs/bpf".into()];
        snapshot.pin_roots.push(PinRootIdentity {
            path: "/sys/fs/bpf".into(),
            mount_namespace_inode: 21,
            mount_id: 34,
        });
        validate_snapshot_resource_bounds(&snapshot).unwrap();

        snapshot.pins.push(PinState {
            path: "/sys/fs/bpf/example".into(),
            path_bytes_hex: hex::encode(b"/sys/fs/bpf/example"),
            mount_namespace_inode: 21,
            mount_id: 34,
            object_type: ObjectType::Map,
            object_id: 7,
            excluded: false,
        });
        snapshot.completeness.status = CompletenessStatus::Incomplete;
        snapshot
            .completeness
            .mark_incomplete("pin inventory changed during capture");
        validate_snapshot_resource_bounds(&snapshot).unwrap();

        snapshot.pins[0].mount_namespace_inode = 22;
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());

        let mut missing_domain = bounded_snapshot();
        missing_domain.claim_scope.bpffs_roots = vec!["/sys/fs/bpf".into()];
        assert!(validate_snapshot_resource_bounds(&missing_domain).is_err());
    }

    #[test]
    fn producer_snapshot_contract_exposes_all_collection_hard_limits() {
        assert!(ensure_collection_limit(
            "program inventory",
            MAX_INVENTORY_IDS_PER_TYPE + 1,
            MAX_INVENTORY_IDS_PER_TYPE
        )
        .is_err());
        assert!(ensure_collection_limit(
            "pin inventory",
            MAX_PIN_WALK_ITEMS + 1,
            MAX_PIN_WALK_ITEMS
        )
        .is_err());
        assert!(ensure_collection_limit(
            "possible CPU IDs",
            MAX_POSSIBLE_CPUS + 1,
            MAX_POSSIBLE_CPUS
        )
        .is_err());
    }

    #[test]
    fn producer_snapshot_contract_bounds_total_program_map_references() {
        let mut snapshot = bounded_snapshot();
        snapshot.claim_scope.object_types.remove(&ObjectType::Map);
        for id in 1..=5 {
            snapshot.programs.push(program_with_maps(
                id,
                (1..=MAX_INVENTORY_IDS_PER_TYPE as u32).collect(),
            ));
        }
        assert!(validate_snapshot_resource_bounds(&snapshot).is_err());
    }

    #[test]
    fn producer_snapshot_contract_charges_conservative_representation() {
        let content = complete_map_sample(
            vec![MapEntry {
                key_hex: "00000000".into(),
                values_hex: vec!["00".repeat(8), "11".repeat(8)],
            }],
            20,
            vec![0, 1],
            false,
        );
        assert_eq!(
            checked_retained_representation_bytes(&content).unwrap(),
            416
        );
    }

    #[test]
    fn scope_rejects_zero_map_ids_and_duplicate_roots() {
        let mut scope = ClaimScope::default();
        scope.map_ids.insert(0);
        assert!(validate_claim_scope(&scope).is_err());
        scope.map_ids.clear();
        scope.bpffs_roots = vec!["/sys/fs/bpf".into(), "/sys/fs/bpf".into()];
        assert!(validate_claim_scope(&scope).is_err());

        scope.bpffs_roots = vec!["/sys/fs/bpf/../escape".into()];
        assert!(validate_claim_scope(&scope).is_err());
        scope.bpffs_roots = vec!["/sys//fs/bpf".into()];
        assert!(validate_claim_scope(&scope).is_err());
        scope.bpffs_roots = vec!["/sys/fs/bpf".into(), "/sys/fs/bpf/nested".into()];
        assert!(validate_claim_scope(&scope).is_err());
    }

    #[test]
    fn attachment_target_size_check_is_bounded() {
        assert!(json_fits_limit(&[json!({"key": "value"})], 64));
        assert!(!json_fits_limit(&[json!({"key": "x".repeat(128)})], 64));
    }

    #[test]
    fn scope_exclusions_cannot_hide_an_explicit_map() {
        let mut scope = ClaimScope::default();
        scope.map_ids.insert(7);
        let mut exclusions = ObjectExclusions::default();
        exclusions.map_ids.insert(7);
        assert!(validate_claim_scope_exclusions(&scope, &exclusions).is_err());
    }

    #[test]
    fn default_scope_requires_map_object_inventory() {
        let mut scope = ClaimScope::default();
        scope.map_content_types.insert(MapContentType::Hash);
        scope.object_types.remove(&ObjectType::Map);
        assert!(validate_claim_scope(&scope).is_err());
        scope.map_content_types.clear();
        assert!(validate_claim_scope(&scope).is_ok());
    }

    #[test]
    fn empty_scope_capture_records_environment_without_bpf_privileges() {
        let mut scope = ClaimScope::default();
        scope.object_types.clear();
        scope.map_content_types.clear();
        let options = CaptureOptions {
            snapshot_id: "unit-test".into(),
            phase: "S0".into(),
            ..CaptureOptions::default()
        };
        let snapshot = capture(&scope, &options).unwrap();
        assert_eq!(snapshot.snapshot_id, "unit-test");
        assert_eq!(snapshot.phase, "S0");
        assert_eq!(snapshot.claim_scope, scope);
        assert!(!snapshot.boot_id.is_empty());
        assert!(!snapshot.kernel_release.is_empty());
        assert!(!snapshot.possible_cpu_ids.is_empty());
        assert!(snapshot.programs.is_empty());
        assert!(snapshot.maps.is_empty());
        assert!(snapshot.links.is_empty());
    }
}
