// SPDX-License-Identifier: GPL-2.0-only

//! Strict semantic assertions for the externally provisioned VM smoke gate.
//!
//! This is a separate binary so the Guest does not need Python, jq, or a Perl
//! JSON module. `verify-run` remains the authoritative integrity verifier;
//! this helper checks that a valid run exercised the exact intended fixture.

use anyhow::{bail, ensure, Context, Result};
use bpf_observer_schema::{
    Attribution, ChangeCertainty, ChangeKind, CompletenessStatus, EventKind, EvidenceEvent,
    MapContentType, MapSampleStatus, ObjectType, QuiescenceBasis, QuiescenceReport,
    QuiescenceStatus, RunManifest, RunStatus, Snapshot, StateVerdict, Verdict,
    EXCLUSIVE_VM_V1_CHECKS, FINALIZED_RUN_ARTIFACTS_V1,
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::BTreeSet;
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

const PIN_PATH: &str = "/sys/fs/bpf/bpf-state-observer-e2e/map";
const PIN_ROOT: &str = "/sys/fs/bpf/bpf-state-observer-e2e";
const EXCLUSIVE_PIN_ROOT: &str = "/sys/fs/bpf/bpf-state-observer-exclusive-e2e";
const CONTENT_DIGEST: &str = "36da99bfc72562be0526dbfdbb1e8bb21cbc44ae6628f1ab7937e35bd6790e80";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fixture {
    Ephemeral,
    Pinned,
    ExclusiveNoop,
    ExclusiveEphemeral,
    ExclusiveRestore,
}

impl Fixture {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "ephemeral" => Ok(Self::Ephemeral),
            "pinned" => Ok(Self::Pinned),
            "exclusive-noop" => Ok(Self::ExclusiveNoop),
            "exclusive-ephemeral" => Ok(Self::ExclusiveEphemeral),
            "exclusive-restore" => Ok(Self::ExclusiveRestore),
            _ => bail!(
                "fixture must be 'ephemeral', 'pinned', 'exclusive-noop', \
                 'exclusive-ephemeral', or 'exclusive-restore'"
            ),
        }
    }

    fn run_epoch(self) -> u64 {
        match self {
            Self::Ephemeral => 1001,
            Self::Pinned => 1002,
            Self::ExclusiveNoop => 1101,
            Self::ExclusiveEphemeral => 1102,
            Self::ExclusiveRestore => 1103,
        }
    }

    fn run_id(self) -> &'static str {
        match self {
            Self::Ephemeral => "e2e-ephemeral",
            Self::Pinned => "e2e-pinned",
            Self::ExclusiveNoop => "e2e-exclusive-noop",
            Self::ExclusiveEphemeral => "e2e-exclusive-ephemeral",
            Self::ExclusiveRestore => "e2e-exclusive-restore",
        }
    }

    fn is_exclusive(self) -> bool {
        matches!(
            self,
            Self::ExclusiveNoop | Self::ExclusiveEphemeral | Self::ExclusiveRestore
        )
    }

    fn expected_commands(self) -> &'static [(u32, &'static str)] {
        match self {
            Self::Ephemeral => &[(0, "BPF_MAP_CREATE"), (2, "BPF_MAP_UPDATE_ELEM")],
            Self::Pinned => &[
                (0, "BPF_MAP_CREATE"),
                (2, "BPF_MAP_UPDATE_ELEM"),
                (22, "BPF_MAP_FREEZE"),
                (6, "BPF_OBJ_PIN"),
            ],
            Self::ExclusiveNoop => &[],
            Self::ExclusiveEphemeral => &[(0, "BPF_MAP_CREATE"), (2, "BPF_MAP_UPDATE_ELEM")],
            Self::ExclusiveRestore => &[
                (0, "BPF_MAP_CREATE"),
                (2, "BPF_MAP_UPDATE_ELEM"),
                (2, "BPF_MAP_UPDATE_ELEM"),
                (2, "BPF_MAP_UPDATE_ELEM"),
            ],
        }
    }
}

fn usage(program: &str) -> ! {
    eprintln!(
        "usage: {program} ephemeral RUN_DIR OUTSIDER_PID\n\
                {program} pinned RUN_DIR\n\
                {program} exclusive-noop RUN_DIR\n\
                {program} exclusive-ephemeral RUN_DIR\n\
                {program} exclusive-restore RUN_DIR"
    );
    std::process::exit(2);
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

fn read_events(path: &Path) -> Result<Vec<EvidenceEvent>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut events = Vec::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line.with_context(|| format!("read {} line {}", path.display(), index + 1))?;
        ensure!(
            !line.is_empty(),
            "{} line {} is empty",
            path.display(),
            index + 1
        );
        events.push(
            serde_json::from_str(&line)
                .with_context(|| format!("parse {} line {}", path.display(), index + 1))?,
        );
    }
    Ok(events)
}

fn assert_complete_snapshot(snapshot: &Snapshot, expected_phase: &str) -> Result<()> {
    ensure!(
        snapshot.phase == expected_phase,
        "unexpected snapshot phase"
    );
    ensure!(
        snapshot.completeness.status == CompletenessStatus::Complete
            && snapshot.completeness.reasons.is_empty(),
        "{expected_phase} is not complete"
    );
    ensure!(
        snapshot.read_failures.is_empty(),
        "{expected_phase} has read failures"
    );
    Ok(())
}

fn assert_event_pair(
    attempt: &EvidenceEvent,
    completion: &EvidenceEvent,
    epoch: u64,
    ordinal: usize,
    command: u32,
    command_name: &str,
) -> Result<()> {
    let attempt_seq = (ordinal as u64) * 2 + 1;
    ensure!(attempt.run_epoch == epoch && completion.run_epoch == epoch);
    ensure!(attempt.kind == EventKind::SyscallAttempted);
    ensure!(completion.kind == EventKind::CommandCompleted);
    ensure!(attempt.event_seq == attempt_seq);
    ensure!(completion.event_seq == attempt_seq + 1);
    ensure!(attempt.related_attempt_seq == 0);
    ensure!(completion.related_attempt_seq == attempt_seq);
    ensure!(attempt.command == command && completion.command == command);
    ensure!(attempt.command_name == command_name && completion.command_name == command_name);
    ensure!(attempt.pid != 0 && attempt.pid == attempt.tgid);
    ensure!(completion.pid == attempt.pid && completion.tgid == attempt.tgid);
    ensure!(attempt.cgroup_id != 0 && completion.cgroup_id == attempt.cgroup_id);
    ensure!(attempt.attr_size == completion.attr_size);
    ensure!(attempt.return_value.is_none());
    ensure!(attempt.flags == 0 && completion.flags == 0);
    ensure!(attempt.argument_provenance == "RAW_SYSCALL_REGISTERS");
    ensure!(completion.argument_provenance == "PENDING_RAW_SYSCALL_CORRELATION");
    let result = completion
        .return_value
        .context("completion lacks return value")?;
    if command == 0 {
        ensure!(result >= 0, "BPF_MAP_CREATE failed: {result}");
    } else {
        ensure!(result == 0, "{command_name} failed: {result}");
    }
    Ok(())
}

fn assert_events(
    fixture: Fixture,
    events: &[EvidenceEvent],
    outsider_pid: Option<u32>,
) -> Result<()> {
    let formal_epoch = fixture.run_epoch();
    let formal: Vec<_> = events
        .iter()
        .filter(|event| event.run_epoch == formal_epoch)
        .collect();
    let canary: Vec<_> = events
        .iter()
        .filter(|event| event.run_epoch == u64::MAX)
        .collect();
    ensure!(
        events.len() == 2 + fixture.expected_commands().len() * 2,
        "unexpected total event count"
    );
    ensure!(
        canary.len() == 2,
        "native canary must have exactly two records"
    );
    ensure!(formal.len() == fixture.expected_commands().len() * 2);
    ensure!(
        events
            .iter()
            .all(|event| event.run_epoch == u64::MAX || event.run_epoch == formal_epoch),
        "raw stream contains an unexpected epoch"
    );

    let canary_attempt = canary[0];
    let canary_completion = canary[1];
    ensure!(canary_attempt.kind == EventKind::SyscallAttempted);
    ensure!(canary_completion.kind == EventKind::CommandCompleted);
    ensure!(canary_attempt.command == 0 && canary_completion.command == 0);
    ensure!(canary_attempt.command_name == "BPF_MAP_CREATE");
    ensure!(canary_completion.command_name == "BPF_MAP_CREATE");
    ensure!(canary_attempt.attr_size == 0 && canary_completion.attr_size == 0);
    ensure!(canary_attempt.return_value.is_none());
    ensure!(canary_completion.return_value == Some(-libc::EINVAL as i64));
    ensure!(canary_attempt.pid == canary_attempt.tgid && canary_attempt.pid != 0);
    ensure!(canary_completion.pid == canary_attempt.pid);
    ensure!(canary_completion.tgid == canary_attempt.tgid);
    ensure!(canary_attempt.cgroup_id == canary_completion.cgroup_id);
    ensure!(canary_attempt.event_seq == 1 && canary_completion.event_seq == 2);
    ensure!(canary_attempt.related_attempt_seq == 0);
    ensure!(canary_completion.related_attempt_seq == 1);
    ensure!(canary_attempt.flags == 0 && canary_completion.flags == 0);
    ensure!(canary_attempt.argument_provenance == "RAW_SYSCALL_REGISTERS");
    ensure!(canary_completion.argument_provenance == "PENDING_RAW_SYSCALL_CORRELATION");

    let mut target_pid = None;
    let mut attr_size = None;
    let expected_run_id = fixture.run_id();
    ensure!(canary_attempt.run_id == expected_run_id);
    ensure!(canary_completion.run_id == expected_run_id);
    for (ordinal, &(command, name)) in fixture.expected_commands().iter().enumerate() {
        let attempt = formal[ordinal * 2];
        let completion = formal[ordinal * 2 + 1];
        assert_event_pair(attempt, completion, formal_epoch, ordinal, command, name)?;
        ensure!(attempt.run_id == expected_run_id && completion.run_id == expected_run_id);
        ensure!(attempt.cgroup_id == canary_attempt.cgroup_id);
        ensure!(
            attempt.attr_size > 0,
            "formal bpf_attr size must be non-zero"
        );
        ensure!(target_pid.get_or_insert(attempt.pid) == &attempt.pid);
        ensure!(attr_size.get_or_insert(attempt.attr_size) == &attempt.attr_size);
    }
    if let Some(pid) = outsider_pid {
        ensure!(
            events
                .iter()
                .all(|event| event.pid != pid && event.tgid != pid),
            "out-of-cgroup negative-control PID {pid} leaked into the stream"
        );
        ensure!(target_pid != Some(pid));
    }
    Ok(())
}

fn assert_no_fixture(snapshot: &Snapshot) -> Result<()> {
    ensure!(
        snapshot
            .maps
            .iter()
            .all(|map| map.metadata.name != "obs_fixture"),
        "snapshot unexpectedly contains obs_fixture"
    );
    ensure!(
        snapshot.pins.iter().all(|pin| pin.path != PIN_PATH),
        "snapshot unexpectedly contains fixture pin"
    );
    Ok(())
}

fn value_u64(value: &Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .with_context(|| format!("change after.{field} is absent or not u64"))
}

fn value_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("change after.{field} is absent or not a string"))
}

fn assert_ephemeral(s0: &Snapshot, s1: &Snapshot, verdict: &Verdict) -> Result<()> {
    assert_no_fixture(s0)?;
    assert_no_fixture(s1)?;
    ensure!(s0.pin_roots.is_empty() && s1.pin_roots.is_empty());
    ensure!(verdict.state_verdict == StateVerdict::Inconclusive);
    ensure!(verdict.state_completeness.status == CompletenessStatus::Complete);
    ensure!(verdict.state_completeness.reasons.is_empty());
    ensure!(verdict.evidence_status.status == CompletenessStatus::Complete);
    ensure!(verdict.evidence_status.reasons.is_empty());
    ensure!(verdict.attribution == Attribution::Unknown);
    ensure!(verdict.quiescence.status == QuiescenceStatus::Unknown);
    ensure!(verdict.quiescence.basis == QuiescenceBasis::ObservedOnly);
    ensure!(!verdict.quiescence.exclusive_actor_attribution);
    ensure!(verdict.changes.is_empty());
    Ok(())
}

fn assert_pinned(s0: &Snapshot, s1: &Snapshot, verdict: &Verdict) -> Result<()> {
    assert_no_fixture(s0)?;
    ensure!(s0.pins.is_empty(), "S0 pin inventory is not empty");
    ensure!(s0.pin_roots.len() == 1 && s1.pin_roots.len() == 1);
    let root = &s1.pin_roots[0];
    ensure!(
        s0.pin_roots[0] == *root,
        "pin-root domain changed across S0/S1"
    );
    ensure!(root.path == PIN_ROOT);
    ensure!(root.mount_namespace_inode != 0 && root.mount_id != 0);

    let maps: Vec<_> = s1
        .maps
        .iter()
        .filter(|map| map.metadata.name == "obs_fixture")
        .collect();
    ensure!(
        maps.len() == 1,
        "S1 must contain exactly one obs_fixture Map"
    );
    let map = maps[0];
    ensure!(!map.excluded);
    ensure!(map.identity.object_type == ObjectType::Map);
    ensure!(map.metadata.map_type == 1);
    ensure!(map.metadata.key_size == 4 && map.metadata.value_size == 8);
    ensure!(map.metadata.max_entries == 4 && map.metadata.map_flags == 0);
    ensure!(map.metadata.frozen == Some(true));
    ensure!(map.content.status == MapSampleStatus::BestEffortNonAtomic);
    ensure!(map.content.semantic_complete);
    ensure!(map.content.entries.len() == 1);
    ensure!(map.content.entries[0].key_hex == "07000000");
    ensure!(
        map.content.entries[0].values_hex == ["8877665544332211"],
        "fixture value bytes differ"
    );
    ensure!(map.content.digest_sha256.as_deref() == Some(CONTENT_DIGEST));
    ensure!(map.content.bytes_read == 12);
    ensure!(map.content.possible_cpu_ids.is_empty());
    ensure!(map.content.error.is_none());

    ensure!(s1.pins.len() == 1, "S1 must contain exactly one scoped pin");
    let pin = &s1.pins[0];
    ensure!(!pin.excluded);
    ensure!(pin.path == PIN_PATH && pin.object_type == ObjectType::Map);
    let expected_path_hex = PIN_PATH
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    ensure!(pin.path_bytes_hex == expected_path_hex);
    ensure!(pin.object_id == map.identity.id);
    ensure!(pin.mount_namespace_inode == root.mount_namespace_inode);
    ensure!(pin.mount_id == root.mount_id);

    ensure!(verdict.state_verdict == StateVerdict::ChangedWithinScope);
    ensure!(verdict.state_completeness.status == CompletenessStatus::Incomplete);
    ensure!(!verdict.state_completeness.reasons.is_empty());
    ensure!(verdict.evidence_status.status == CompletenessStatus::Complete);
    ensure!(verdict.evidence_status.reasons.is_empty());
    ensure!(verdict.attribution == Attribution::UnattributedSystemChange);
    ensure!(verdict.quiescence.status == QuiescenceStatus::Unknown);
    ensure!(verdict.quiescence.basis == QuiescenceBasis::ObservedOnly);
    ensure!(!verdict.quiescence.exclusive_actor_attribution);
    ensure!(
        verdict.changes.len() == 2,
        "expected exactly Map+pin additions"
    );
    let map_changes: Vec<_> = verdict
        .changes
        .iter()
        .filter(|change| change.entity == "map")
        .collect();
    let pin_changes: Vec<_> = verdict
        .changes
        .iter()
        .filter(|change| change.entity == "pin")
        .collect();
    ensure!(map_changes.len() == 1 && pin_changes.len() == 1);
    for change in [&map_changes[0], &pin_changes[0]] {
        ensure!(change.kind == ChangeKind::Added);
        ensure!(change.certainty == ChangeCertainty::Confirmed);
        ensure!(change.field.is_none() && change.before.is_none());
        ensure!(change.after.is_some());
    }
    let map_after = map_changes[0].after.as_ref().unwrap();
    let map_identity = map_after
        .get("identity")
        .context("Map change lacks identity")?;
    ensure!(value_u64(map_identity, "id")? == u64::from(map.identity.id));
    let map_metadata = map_after
        .get("metadata")
        .context("Map change lacks metadata")?;
    ensure!(value_str(map_metadata, "name")? == "obs_fixture");
    ensure!(map_metadata.get("frozen").and_then(Value::as_bool) == Some(true));
    let map_content = map_after
        .get("content")
        .context("Map change lacks content")?;
    ensure!(value_u64(map_content, "entry_count")? == 1);
    ensure!(value_u64(map_content, "bytes_read")? == 12);
    ensure!(value_str(map_content, "digest_sha256")? == CONTENT_DIGEST);

    let pin_after = pin_changes[0].after.as_ref().unwrap();
    ensure!(value_str(pin_after, "path")? == PIN_PATH);
    ensure!(value_str(pin_after, "path_bytes_hex")? == expected_path_hex);
    ensure!(value_str(pin_after, "object_type")? == "MAP");
    ensure!(value_u64(pin_after, "object_id")? == u64::from(map.identity.id));
    ensure!(value_u64(pin_after, "mount_id")? == root.mount_id);
    ensure!(value_u64(pin_after, "mount_namespace_inode")? == root.mount_namespace_inode);
    Ok(())
}

fn assert_finalized_manifest(fixture: Fixture, manifest: &RunManifest) -> Result<()> {
    ensure!(
        manifest.run_id == fixture.run_id(),
        "unexpected manifest run_id"
    );
    ensure!(
        manifest.run_epoch == fixture.run_epoch(),
        "unexpected manifest run_epoch"
    );
    ensure!(
        manifest.run_status == RunStatus::Finalized,
        "manifest is not FINALIZED"
    );
    ensure!(
        manifest.finalized_unix_ns.is_some()
            && manifest.finalized_unix_ns >= Some(manifest.started_unix_ns),
        "manifest has no valid finalization timestamp"
    );
    let expected_artifacts = FINALIZED_RUN_ARTIFACTS_V1
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let actual_artifacts = manifest
        .artifacts
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    ensure!(
        actual_artifacts == expected_artifacts,
        "manifest does not commit the closed finalized artifact set"
    );

    if !fixture.is_exclusive() {
        return Ok(());
    }

    ensure!(
        manifest.workload_exit_code == Some(0) && manifest.workload_signal.is_none(),
        "exclusive workload did not exit normally with status zero"
    );
    ensure!(manifest.scope_accepted, "exclusive scope was not accepted");
    ensure!(
        manifest.requested_scope == manifest.effective_scope,
        "exclusive scope was reduced"
    );
    let scope = &manifest.effective_scope;
    ensure!(
        scope.event_interfaces == ["BPF_USER_SYSCALL".to_string()].into_iter().collect(),
        "exclusive event-interface scope is not exact"
    );
    ensure!(
        scope.allowed_bpf_commands == [0, 2].into_iter().collect(),
        "exclusive command scope must be exactly MAP_CREATE/MAP_UPDATE_ELEM"
    );
    ensure!(
        scope.object_types
            == [ObjectType::Program, ObjectType::Map, ObjectType::Link]
                .into_iter()
                .collect(),
        "exclusive endpoint object scope is not exact"
    );
    ensure!(
        scope.map_content_types
            == [
                MapContentType::Array,
                MapContentType::Hash,
                MapContentType::PercpuArray,
                MapContentType::PercpuHash,
            ]
            .into_iter()
            .collect(),
        "exclusive Map-content whitelist must contain the exact four enumerable types"
    );
    ensure!(
        scope.map_ids.is_empty() && scope.attachment_targets.is_empty(),
        "exclusive fixture scope contains an unexpected selector"
    );
    ensure!(scope.bpffs_roots == [EXCLUSIVE_PIN_ROOT]);

    let executable = manifest
        .workload
        .first()
        .context("exclusive manifest has no workload executable")?;
    let executable_name = Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
        .context("exclusive workload executable has no UTF-8 basename")?;
    let arguments = &manifest.workload[1..];
    match fixture {
        Fixture::ExclusiveNoop => {
            ensure!(executable_name == "exclusive-noop");
            ensure!(
                arguments == ["--exclusive-contract"],
                "exclusive-noop received an unexpected argument"
            );
        }
        Fixture::ExclusiveEphemeral => {
            ensure!(executable_name == "map-lifecycle");
            ensure!(
                arguments == ["--ephemeral", "--exclusive-contract"],
                "exclusive-ephemeral arguments do not match policy"
            );
        }
        Fixture::ExclusiveRestore => {
            ensure!(executable_name == "map-lifecycle");
            ensure!(
                arguments == ["--transient-restore", "--exclusive-contract"],
                "exclusive-restore arguments do not match policy"
            );
        }
        Fixture::Ephemeral | Fixture::Pinned => unreachable!(),
    }
    ensure!(
        !arguments
            .iter()
            .any(|argument| argument == "--freeze" || argument == "--pin"),
        "exclusive workload requested persistent/frozen fixture behavior"
    );
    ensure!(
        manifest
            .artifacts
            .get("workload.stderr")
            .map(|artifact| artifact.size_bytes)
            == Some(0),
        "exclusive workload wrote to stderr"
    );
    ensure!(
        manifest
            .artifacts
            .get("workload.stdout")
            .map(|artifact| artifact.size_bytes)
            == Some(0),
        "exclusive workload wrote unexpected stdout"
    );
    Ok(())
}

fn assert_exclusive_quiescence(report: &QuiescenceReport) -> Result<()> {
    ensure!(EXCLUSIVE_VM_V1_CHECKS.len() == 12);
    ensure!(report.status == QuiescenceStatus::QuiescentWithinModel);
    ensure!(report.basis == QuiescenceBasis::HarnessEnforced);
    ensure!(report.contract_id.as_deref() == Some("exclusive-vm-v1"));
    ensure!(report.exclusive_actor_attribution);
    ensure!(
        matches!(
            report.authentication.as_ref().and_then(Value::as_object),
            Some(authentication) if !authentication.is_empty()
        ),
        "exclusive report lacks non-empty authentication"
    );
    ensure!(
        report.checks.len() == EXCLUSIVE_VM_V1_CHECKS.len(),
        "exclusive report does not contain exactly 12 checks"
    );
    ensure!(
        report
            .checks
            .iter()
            .all(|check| check.passed && !check.evidence.trim().is_empty()),
        "exclusive report contains a failed or unsupported check"
    );
    let expected = EXCLUSIVE_VM_V1_CHECKS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let actual = report
        .checks
        .iter()
        .map(|check| check.name.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        actual == expected && actual.len() == report.checks.len(),
        "exclusive report check names are missing, duplicated, or unknown"
    );
    ensure!(
        report.supports_unchanged(),
        "exclusive report does not satisfy the schema's unchanged gate"
    );
    Ok(())
}

fn assert_exclusive_result(
    fixture: Fixture,
    s0: &Snapshot,
    s1: &Snapshot,
    quiescence: &QuiescenceReport,
    verdict: &Verdict,
) -> Result<()> {
    for snapshot in [s0, s1] {
        ensure!(
            snapshot.programs.iter().all(|program| program.excluded)
                && snapshot.maps.iter().all(|map| map.excluded)
                && snapshot.links.iter().all(|link| link.excluded),
            "exclusive clean-VM endpoint contains a non-observer BPF object"
        );
    }
    ensure!(s0.pins.is_empty() && s1.pins.is_empty());
    ensure!(s0.pin_roots.len() == 1 && s1.pin_roots.len() == 1);
    ensure!(s0.pin_roots[0] == s1.pin_roots[0]);
    ensure!(s0.pin_roots[0].path == EXCLUSIVE_PIN_ROOT);
    ensure!(s0.pin_roots[0].mount_namespace_inode != 0 && s0.pin_roots[0].mount_id != 0);
    for snapshot in [s0, s1] {
        for map in snapshot.maps.iter().filter(|map| {
            !map.excluded
                && snapshot
                    .claim_scope
                    .samples_map(map.identity.id, map.metadata.map_type)
        }) {
            ensure!(
                map.content.status == MapSampleStatus::CompleteQuiescent
                    && map.content.semantic_complete
                    && map.content.error.is_none(),
                "selected HASH Map was not captured COMPLETE_QUIESCENT"
            );
        }
    }
    assert_exclusive_quiescence(quiescence)?;
    ensure!(verdict.quiescence == *quiescence);
    ensure!(verdict.state_verdict == StateVerdict::UnchangedWithinScope);
    ensure!(verdict.state_completeness.status == CompletenessStatus::Complete);
    ensure!(verdict.state_completeness.reasons.is_empty());
    ensure!(verdict.evidence_status.status == CompletenessStatus::Complete);
    ensure!(verdict.evidence_status.reasons.is_empty());
    ensure!(verdict.attribution == Attribution::NoStateChange);
    ensure!(verdict.changes.is_empty());

    if fixture == Fixture::ExclusiveRestore {
        /*
         * EvidenceEvent intentionally records bpf() rather than close(2).
         * The exact CREATE+UPDATE+UPDATE+UPDATE history is checked by
         * assert_events; empty S0/S1 endpoints, the authenticated cgroup-empty
         * contract check, and empty stderr are the strongest close evidence
         * expressible by the current finalized schema.
         */
        ensure!(quiescence
            .checks
            .iter()
            .any(|check| check.name == "cgroup_empty" && check.passed));
    }
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    if args.len() < 3 {
        usage(args.first().map(String::as_str).unwrap_or("vm-e2e-assert"));
    }
    let fixture = Fixture::parse(&args[1])?;
    let run_dir = PathBuf::from(&args[2]);
    let outsider_pid = match fixture {
        Fixture::Ephemeral => {
            if args.len() != 4 {
                usage(&args[0]);
            }
            Some(args[3].parse::<u32>().context("parse OUTSIDER_PID")?)
        }
        Fixture::Pinned
        | Fixture::ExclusiveNoop
        | Fixture::ExclusiveEphemeral
        | Fixture::ExclusiveRestore => {
            if args.len() != 3 {
                usage(&args[0]);
            }
            None
        }
    };

    let manifest: RunManifest = read_json(&run_dir.join("manifest.json"))?;
    let s0: Snapshot = read_json(&run_dir.join("s0.json"))?;
    let s1: Snapshot = read_json(&run_dir.join("s1.json"))?;
    let quiescence: QuiescenceReport = read_json(&run_dir.join("quiescence.json"))?;
    let verdict: Verdict = read_json(&run_dir.join("verdict.json"))?;
    let events = read_events(&run_dir.join("raw-events.jsonl"))?;
    assert_finalized_manifest(fixture, &manifest)?;
    assert_complete_snapshot(&s0, "S0")?;
    assert_complete_snapshot(&s1, "S1")?;
    ensure!(s0.boot_id == s1.boot_id, "boot ID changed across snapshots");
    ensure!(verdict.run_status == RunStatus::Provisional);
    assert_events(fixture, &events, outsider_pid)?;
    match fixture {
        Fixture::Ephemeral => assert_ephemeral(&s0, &s1, &verdict),
        Fixture::Pinned => assert_pinned(&s0, &s1, &verdict),
        Fixture::ExclusiveNoop | Fixture::ExclusiveEphemeral | Fixture::ExclusiveRestore => {
            assert_exclusive_result(fixture, &s0, &s1, &quiescence, &verdict)
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("VM E2E semantic assertion failed: {error:#}");
        std::process::exit(1);
    }
}
