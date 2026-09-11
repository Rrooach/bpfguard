// SPDX-License-Identifier: GPL-2.0-only

//! Semantic gate for the diagnostic Codex + DeepSeek collection profile.
//!
//! `verify-run` remains the artifact integrity verifier. This binary adds the
//! task-specific contract: complete evidence/state, exact BPF history, and a
//! successful Codex JSONL lifecycle with the expected local-tool behavior.

use anyhow::{bail, ensure, Context, Result};
use bpf_observer_schema::{
    Attribution, CompletenessStatus, EventKind, EvidenceEvent, EvidenceHealth, QuiescenceBasis,
    QuiescenceStatus, RunManifest, RunStatus, Snapshot, StateVerdict, Verdict,
    FINALIZED_RUN_ARTIFACTS_V1,
};
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug)]
enum Task {
    TextOnly,
    FileWrite,
    EphemeralMap,
    TransientRestore,
}

impl Task {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "00-text-only" => Ok(Self::TextOnly),
            "01-file-write" => Ok(Self::FileWrite),
            "02-ephemeral-map" => Ok(Self::EphemeralMap),
            "03-transient-restore" => Ok(Self::TransientRestore),
            _ => bail!("unsupported task {value:?}"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::TextOnly => "00-text-only",
            Self::FileWrite => "01-file-write",
            Self::EphemeralMap => "02-ephemeral-map",
            Self::TransientRestore => "03-transient-restore",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::TextOnly => "TEXT_ONLY_OK",
            Self::FileWrite => "FILE_WRITE_OK",
            Self::EphemeralMap => "EPHEMERAL_MAP_OK",
            Self::TransientRestore => "TRANSIENT_RESTORE_OK",
        }
    }

    fn commands(self) -> &'static [(u32, &'static str)] {
        match self {
            Self::TextOnly | Self::FileWrite => &[],
            Self::EphemeralMap => &[(0, "BPF_MAP_CREATE"), (2, "BPF_MAP_UPDATE_ELEM")],
            Self::TransientRestore => &[
                (0, "BPF_MAP_CREATE"),
                (2, "BPF_MAP_UPDATE_ELEM"),
                (2, "BPF_MAP_UPDATE_ELEM"),
                (2, "BPF_MAP_UPDATE_ELEM"),
            ],
        }
    }

    fn expected_shell(self) -> Option<&'static [&'static str]> {
        match self {
            Self::TextOnly | Self::FileWrite => None,
            Self::EphemeralMap => Some(&[
                "/opt/bpf-state-observer/map-lifecycle",
                "--ephemeral",
                "--exclusive-contract",
            ]),
            Self::TransientRestore => Some(&[
                "/opt/bpf-state-observer/map-lifecycle",
                "--transient-restore",
                "--exclusive-contract",
            ]),
        }
    }
}

#[derive(Debug)]
struct Inputs {
    task: Task,
    model: String,
    epoch: u64,
    task_root: PathBuf,
    task_file: String,
    workspace: String,
    state_root: String,
    launcher: String,
}

#[derive(Debug, Deserialize)]
struct VerificationReport {
    schema_version: u32,
    run_id: String,
    run_epoch: u64,
    artifacts_verified: usize,
    events_verified: usize,
    recorder_digest_policy_match: bool,
    harness_authenticated: bool,
    evidence_complete: bool,
    state_verdict: StateVerdict,
}

#[derive(Debug, Deserialize)]
struct ObserveReport {
    run_id: String,
    run_epoch: u64,
    workload_exit_code: Option<i32>,
    workload_signal: Option<i32>,
    state_verdict: StateVerdict,
    output_dir: String,
}

#[derive(Debug, Serialize)]
struct ValidationErrors {
    evidence: Vec<String>,
    codex_jsonl: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ValidationReport {
    schema_version: u32,
    task: String,
    run_id: String,
    run_epoch: u64,
    status: &'static str,
    evidence_contract: &'static str,
    codex_jsonl_contract: &'static str,
    expected_formal_commands: Vec<&'static str>,
    expected_total_events: usize,
    observed_total_events: usize,
    codex_event_count: usize,
    errors: ValidationErrors,
}

/// A JSON value deserializer that rejects duplicate keys at every depth.
struct StrictValue(Value);

struct StrictValueVisitor;

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let number = Number::from_f64(value)
            .context("JSON number is not finite")
            .map_err(E::custom)?;
        Ok(StrictValue(Value::Number(number)))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(StrictValue(value)) = sequence.next_element::<StrictValue>()? {
            values.push(value);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate JSON key {key:?}")));
            }
            let StrictValue(value) = object.next_value::<StrictValue>()?;
            values.insert(key, value);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

fn strict_from_str<T: DeserializeOwned>(text: &str) -> Result<T> {
    let StrictValue(value) = serde_json::from_str(text)?;
    serde_json::from_value(value).map_err(Into::into)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    strict_from_str(&text).with_context(|| format!("parse {}", path.display()))
}

fn read_jsonl<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    ensure!(!text.is_empty(), "{} is empty", path.display());
    ensure!(
        text.ends_with('\n'),
        "{} lacks a final newline",
        path.display()
    );
    text.lines()
        .enumerate()
        .map(|(index, line)| {
            ensure!(
                !line.is_empty(),
                "{} line {} is empty",
                path.display(),
                index + 1
            );
            strict_from_str(line)
                .with_context(|| format!("parse {} line {}", path.display(), index + 1))
        })
        .collect()
}

fn assert_snapshot(snapshot: &Snapshot, phase: &str, manifest: &RunManifest) -> Result<()> {
    ensure!(
        snapshot.schema_version == 1,
        "{phase} schema version is not 1"
    );
    ensure!(snapshot.phase == phase, "unexpected {phase} phase label");
    ensure!(
        snapshot.completeness.status == CompletenessStatus::Complete
            && snapshot.completeness.reasons.is_empty()
            && snapshot.read_failures.is_empty(),
        "{phase} endpoint snapshot is incomplete"
    );
    ensure!(
        snapshot.claim_scope == manifest.effective_scope,
        "{phase} scope differs from the manifest"
    );
    ensure!(
        snapshot.observer_exclusions == manifest.observer_exclusions,
        "{phase} observer exclusions differ from the manifest"
    );
    Ok(())
}

fn assert_event_pair(
    attempt: &EvidenceEvent,
    completion: &EvidenceEvent,
    run_id: &str,
    epoch: u64,
    ordinal: usize,
    command: u32,
    command_name: &str,
) -> Result<()> {
    let attempt_seq = ordinal as u64 * 2 + 1;
    ensure!(attempt.schema_version == 1 && completion.schema_version == 1);
    ensure!(attempt.run_id == run_id && completion.run_id == run_id);
    ensure!(attempt.run_epoch == epoch && completion.run_epoch == epoch);
    ensure!(attempt.kind == EventKind::SyscallAttempted);
    ensure!(completion.kind == EventKind::CommandCompleted);
    ensure!(attempt.event_seq == attempt_seq && completion.event_seq == attempt_seq + 1);
    ensure!(attempt.related_attempt_seq == 0);
    ensure!(completion.related_attempt_seq == attempt_seq);
    ensure!(attempt.command == command && completion.command == command);
    ensure!(attempt.command_name == command_name && completion.command_name == command_name);
    ensure!(attempt.pid != 0 && attempt.pid == attempt.tgid);
    ensure!(completion.pid == attempt.pid && completion.tgid == attempt.tgid);
    ensure!(attempt.cgroup_id != 0 && completion.cgroup_id == attempt.cgroup_id);
    ensure!(attempt.attr_size > 0 && attempt.attr_size == completion.attr_size);
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

fn assert_events(inputs: &Inputs, manifest: &RunManifest, events: &[EvidenceEvent]) -> Result<()> {
    let commands = inputs.task.commands();
    let expected_count = 2 + commands.len() * 2;
    let canary_epoch = if inputs.epoch == u64::MAX {
        u64::MAX - 1
    } else {
        u64::MAX
    };
    let formal: Vec<_> = events
        .iter()
        .filter(|event| event.run_epoch == inputs.epoch)
        .collect();
    let canary: Vec<_> = events
        .iter()
        .filter(|event| event.run_epoch == canary_epoch)
        .collect();
    let run_id = format!("agent-{}", inputs.task.name());

    ensure!(
        events.len() == expected_count,
        "unexpected total event count"
    );
    ensure!(
        formal.len() == commands.len() * 2,
        "unexpected formal event count"
    );
    ensure!(
        canary.len() == 2,
        "native canary is not exactly one syscall pair"
    );
    ensure!(
        events
            .iter()
            .all(|event| event.run_epoch == inputs.epoch || event.run_epoch == canary_epoch),
        "raw stream contains an unexpected epoch"
    );

    let canary_attempt = canary[0];
    let canary_completion = canary[1];
    ensure!(canary_attempt.run_id == run_id && canary_completion.run_id == run_id);
    ensure!(canary_attempt.kind == EventKind::SyscallAttempted);
    ensure!(canary_completion.kind == EventKind::CommandCompleted);
    ensure!(canary_attempt.command == 0 && canary_completion.command == 0);
    ensure!(canary_attempt.command_name == "BPF_MAP_CREATE");
    ensure!(canary_completion.command_name == "BPF_MAP_CREATE");
    ensure!(canary_attempt.attr_size == 0 && canary_completion.attr_size == 0);
    ensure!(canary_attempt.return_value.is_none());
    ensure!(canary_completion.return_value == Some(-22));
    ensure!(canary_attempt.pid != 0 && canary_attempt.pid == canary_attempt.tgid);
    ensure!(canary_completion.pid == canary_attempt.pid);
    ensure!(canary_completion.tgid == canary_attempt.tgid);
    ensure!(canary_attempt.cgroup_id == manifest.cgroup_id);
    ensure!(canary_completion.cgroup_id == manifest.cgroup_id);
    ensure!(canary_attempt.event_seq == 1 && canary_completion.event_seq == 2);
    ensure!(canary_attempt.related_attempt_seq == 0);
    ensure!(canary_completion.related_attempt_seq == 1);
    ensure!(canary_attempt.flags == 0 && canary_completion.flags == 0);
    ensure!(canary_attempt.argument_provenance == "RAW_SYSCALL_REGISTERS");
    ensure!(canary_completion.argument_provenance == "PENDING_RAW_SYSCALL_CORRELATION");

    let mut fixture_tgid = None;
    for (ordinal, &(command, command_name)) in commands.iter().enumerate() {
        let attempt = formal[ordinal * 2];
        let completion = formal[ordinal * 2 + 1];
        assert_event_pair(
            attempt,
            completion,
            &run_id,
            inputs.epoch,
            ordinal,
            command,
            command_name,
        )?;
        ensure!(attempt.cgroup_id == manifest.cgroup_id);
        ensure!(fixture_tgid.get_or_insert(attempt.tgid) == &attempt.tgid);
    }
    Ok(())
}

fn assert_evidence(inputs: &Inputs) -> Result<usize> {
    let run_root = inputs.task_root.join("observer-run");
    let verify: VerificationReport = read_json(&inputs.task_root.join("verify.json"))?;
    let observe: ObserveReport = read_json(&inputs.task_root.join("observe.json"))?;
    let manifest: RunManifest = read_json(&run_root.join("manifest.json"))?;
    let health: EvidenceHealth = read_json(&run_root.join("health.json"))?;
    let s0: Snapshot = read_json(&run_root.join("s0.json"))?;
    let s1: Snapshot = read_json(&run_root.join("s1.json"))?;
    let verdict: Verdict = read_json(&run_root.join("verdict.json"))?;
    let events: Vec<EvidenceEvent> = read_jsonl(&run_root.join("raw-events.jsonl"))?;
    let run_id = format!("agent-{}", inputs.task.name());
    let expected_event_count = 2 + inputs.task.commands().len() * 2;

    ensure!(
        verify.schema_version == 1,
        "verification schema version is not 1"
    );
    ensure!(verify.run_id == run_id && verify.run_epoch == inputs.epoch);
    ensure!(verify.artifacts_verified == FINALIZED_RUN_ARTIFACTS_V1.len());
    ensure!(verify.events_verified == expected_event_count);
    ensure!(verify.recorder_digest_policy_match);
    ensure!(!verify.harness_authenticated);
    ensure!(
        verify.evidence_complete,
        "verify-run evidence_complete is false"
    );
    ensure!(verify.state_verdict == StateVerdict::Inconclusive);

    ensure!(observe.run_id == run_id && observe.run_epoch == inputs.epoch);
    ensure!(observe.workload_exit_code == Some(0) && observe.workload_signal.is_none());
    ensure!(observe.state_verdict == StateVerdict::Inconclusive);
    ensure!(observe.output_dir == run_root.to_string_lossy());

    ensure!(manifest.schema_version == 1);
    ensure!(manifest.run_id == run_id && manifest.run_epoch == inputs.epoch);
    ensure!(manifest.run_status == RunStatus::Finalized);
    ensure!(
        manifest.finalized_unix_ns.is_some()
            && manifest.finalized_unix_ns >= Some(manifest.started_unix_ns)
    );
    let expected_workload = vec![
        inputs.launcher.clone(),
        inputs.model.clone(),
        inputs.task_file.clone(),
        inputs.workspace.clone(),
        inputs.state_root.clone(),
    ];
    ensure!(
        manifest.workload == expected_workload,
        "unexpected workload argv"
    );
    ensure!(manifest.workload_exit_code == Some(0) && manifest.workload_signal.is_none());
    ensure!(manifest.scope_accepted);
    ensure!(manifest.requested_scope == manifest.effective_scope);
    ensure!(
        !manifest
            .notes
            .iter()
            .any(|note| note.to_ascii_lowercase().contains("truncat")),
        "workload output or evidence was truncated"
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
    ensure!(actual_artifacts == expected_artifacts);

    ensure!(health.is_complete(), "health.json is incomplete");
    let command_count = inputs.task.commands().len() as u64;
    let formal_event_count = command_count * 2;
    ensure!(health.syscall_attempted == command_count);
    ensure!(health.syscall_completed == command_count);
    ensure!(health.event_attempted == formal_event_count);
    ensure!(health.event_published == formal_event_count);
    ensure!(health.events_persisted == formal_event_count);

    assert_snapshot(&s0, "S0", &manifest)?;
    assert_snapshot(&s1, "S1", &manifest)?;
    ensure!(s0.boot_id == s1.boot_id, "boot ID changed across snapshots");

    ensure!(verdict.schema_version == 1);
    ensure!(verdict.run_status == RunStatus::Provisional);
    ensure!(verdict.state_verdict == StateVerdict::Inconclusive);
    ensure!(
        verdict.state_completeness.status == CompletenessStatus::Complete
            && verdict.state_completeness.reasons.is_empty(),
        "state completeness is not COMPLETE"
    );
    ensure!(
        verdict.evidence_status.status == CompletenessStatus::Complete
            && verdict.evidence_status.reasons.is_empty(),
        "evidence status is not COMPLETE"
    );
    ensure!(verdict.attribution == Attribution::Unknown);
    ensure!(
        verdict.changes.is_empty(),
        "task left a persistent in-scope change"
    );
    ensure!(verdict.quiescence.status == QuiescenceStatus::Unknown);
    ensure!(verdict.quiescence.basis == QuiescenceBasis::ObservedOnly);
    ensure!(!verdict.quiescence.exclusive_actor_attribution);

    assert_events(inputs, &manifest, &events)?;
    Ok(events.len())
}

fn value_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("Codex event field {field:?} is absent or not a string"))
}

fn command_is_exact(command: &str, expected: &[&str]) -> bool {
    let direct = expected.join(" ");
    command == direct || command == format!("/usr/bin/bash -lc '{direct}'")
}

fn assert_provider_auth_events(events: &[Value]) -> Result<()> {
    const EXPECTED_TYPES: [&str; 4] = ["thread.started", "turn.started", "error", "turn.failed"];
    const STATUS: &str = "401 Unauthorized";
    const ENDPOINT: &str = "https://api.deepseek.com/responses";

    ensure!(
        events.len() == EXPECTED_TYPES.len(),
        "provider authentication probe must contain exactly four events"
    );
    for (index, expected_type) in EXPECTED_TYPES.iter().enumerate() {
        ensure!(
            value_str(&events[index], "type")? == *expected_type,
            "provider authentication probe event {} is not {expected_type}",
            index + 1
        );
    }
    ensure!(!value_str(&events[0], "thread_id")?.is_empty());

    let error_message = value_str(&events[2], "message")?;
    let turn_error = events[3]
        .get("error")
        .and_then(Value::as_object)
        .context("turn.failed has no error object")?;
    let turn_error_message = turn_error
        .get("message")
        .and_then(Value::as_str)
        .context("turn.failed error has no message string")?;
    for (label, message) in [
        ("error", error_message),
        ("turn.failed", turn_error_message),
    ] {
        ensure!(
            message.contains(STATUS) && message.contains(ENDPOINT),
            "{label} does not bind the expected status and endpoint"
        );
    }
    ensure!(
        error_message == turn_error_message,
        "error and turn.failed diagnostics differ"
    );
    Ok(())
}

fn assert_provider_auth_probe(jsonl_path: &Path, stderr_path: &Path) -> Result<usize> {
    let jsonl_size = fs::metadata(jsonl_path)
        .with_context(|| format!("inspect {}", jsonl_path.display()))?
        .len();
    ensure!(
        (1..=64 * 1024).contains(&jsonl_size),
        "provider authentication JSONL has an unsafe size"
    );
    let events: Vec<Value> = read_jsonl(jsonl_path)?;
    assert_provider_auth_events(&events)?;
    let stderr_size = fs::metadata(stderr_path)
        .with_context(|| format!("inspect {}", stderr_path.display()))?
        .len();
    ensure!(
        stderr_size == 0,
        "provider authentication probe wrote unexpected stderr"
    );
    Ok(events.len())
}

fn assert_codex_events(task: Task, events: &[Value]) -> Result<()> {
    let event_types = events
        .iter()
        .map(|event| value_str(event, "type"))
        .collect::<Result<Vec<_>>>()?;
    let allowed = [
        "thread.started",
        "turn.started",
        "item.started",
        "item.updated",
        "item.completed",
        "turn.completed",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    ensure!(
        event_types
            .iter()
            .all(|event_type| allowed.contains(event_type)),
        "Codex JSONL contains an unexpected or failed event type"
    );
    ensure!(event_types.first() == Some(&"thread.started"));
    ensure!(event_types.get(1) == Some(&"turn.started"));
    ensure!(event_types.last() == Some(&"turn.completed"));
    for required in ["thread.started", "turn.started", "turn.completed"] {
        ensure!(
            event_types
                .iter()
                .filter(|event_type| **event_type == required)
                .count()
                == 1,
            "Codex JSONL must contain exactly one {required}"
        );
    }
    ensure!(!value_str(&events[0], "thread_id")?.is_empty());

    let non_tools = ["reasoning", "agent_message", "todo_list"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let local_tools = ["command_execution", "file_change"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut started_tools = BTreeMap::new();
    let mut completed_tools = BTreeMap::new();
    let mut started_commands = BTreeMap::new();
    let mut completed_commands = Vec::new();
    let mut agent_messages = Vec::new();
    let mut active_todo_lists = BTreeSet::new();
    let mut completed_todo_lists = BTreeSet::new();

    for event in events {
        let event_type = value_str(event, "type")?;
        if event_type != "item.started"
            && event_type != "item.updated"
            && event_type != "item.completed"
        {
            continue;
        }
        let item = event
            .get("item")
            .and_then(Value::as_object)
            .context("Codex item event has no object payload")?;
        let item_value = Value::Object(item.clone());
        let item_id = value_str(&item_value, "id")?;
        let item_type = value_str(&item_value, "type")?;
        ensure!(!item_id.is_empty() && !item_type.is_empty());

        if event_type == "item.updated" {
            ensure!(
                item_type == "todo_list",
                "only todo_list may appear in an item.updated event"
            );
            ensure!(
                item_value.get("items").and_then(Value::as_array).is_some(),
                "todo_list update has no items array"
            );
            ensure!(
                active_todo_lists.contains(item_id),
                "todo_list update has no matching start"
            );
            continue;
        }
        if item_type == "todo_list" {
            ensure!(
                item_value.get("items").and_then(Value::as_array).is_some(),
                "todo_list event has no items array"
            );
            if event_type == "item.started" {
                ensure!(
                    active_todo_lists.insert(item_id.to_owned()),
                    "duplicate todo_list start"
                );
            } else {
                ensure!(
                    active_todo_lists.remove(item_id),
                    "todo_list completion has no matching start"
                );
                ensure!(
                    completed_todo_lists.insert(item_id.to_owned()),
                    "duplicate todo_list completion"
                );
            }
            continue;
        }
        if item_type == "agent_message" && event_type == "item.completed" {
            agent_messages.push(value_str(&item_value, "text")?.to_owned());
        }
        if non_tools.contains(item_type) {
            continue;
        }
        ensure!(
            local_tools.contains(item_type),
            "forbidden or unknown Codex tool item {item_type:?}"
        );
        let destination = if event_type == "item.started" {
            &mut started_tools
        } else {
            &mut completed_tools
        };
        ensure!(
            destination
                .insert(item_id.to_owned(), item_type.to_owned())
                .is_none(),
            "duplicate {event_type} for item {item_id}"
        );

        if item_type == "command_execution" {
            let command = value_str(&item_value, "command")?;
            if event_type == "item.started" {
                ensure!(value_str(&item_value, "status")? == "in_progress");
                ensure!(
                    started_commands
                        .insert(item_id.to_owned(), command.to_owned())
                        .is_none(),
                    "duplicate started command payload"
                );
            } else {
                ensure!(value_str(&item_value, "status")? == "completed");
                ensure!(item_value.get("exit_code").and_then(Value::as_i64) == Some(0));
                ensure!(
                    started_commands.get(item_id).map(String::as_str) == Some(command),
                    "started and completed command payloads differ"
                );
                completed_commands.push(command.to_owned());
            }
        }
        if item_type == "file_change" && event_type == "item.completed" {
            ensure!(value_str(&item_value, "status")? == "completed");
        }
    }

    ensure!(
        agent_messages.last().map(String::as_str) == Some(task.message()),
        "Codex final agent message does not match the requested token"
    );
    ensure!(
        active_todo_lists.is_empty(),
        "todo_list lifecycle did not complete"
    );
    for (item_id, item_type) in &started_tools {
        if item_type == "command_execution" {
            ensure!(completed_tools.get(item_id) == Some(item_type));
        }
    }
    for (item_id, item_type) in &completed_tools {
        if item_type == "command_execution" {
            ensure!(started_tools.get(item_id) == Some(item_type));
        }
    }

    match task {
        Task::TextOnly => {
            ensure!(started_tools.is_empty() && completed_tools.is_empty());
        }
        Task::FileWrite => {
            ensure!(
                !completed_tools.is_empty(),
                "file task completed no local tool"
            );
        }
        Task::EphemeralMap | Task::TransientRestore => {
            ensure!(started_tools.len() == 1 && completed_tools.len() == 1);
            ensure!(completed_commands.len() == 1);
            ensure!(
                command_is_exact(
                    &completed_commands[0],
                    task.expected_shell()
                        .context("map task has no shell contract")?,
                ),
                "shell command differs from the fixed fixture argv"
            );
        }
    }
    Ok(())
}

fn assert_codex(inputs: &Inputs) -> Result<usize> {
    let path = inputs.task_root.join("observer-run/workload.stdout");
    let events: Vec<Value> = read_jsonl(&path)?;
    assert_codex_events(inputs.task, &events)?;
    Ok(events.len())
}

fn self_test() -> Result<()> {
    let expected = ["/fixture", "--ephemeral", "--exclusive-contract"];
    ensure!(command_is_exact(
        "/fixture --ephemeral --exclusive-contract",
        &expected
    ));
    ensure!(command_is_exact(
        "/usr/bin/bash -lc '/fixture --ephemeral --exclusive-contract'",
        &expected
    ));
    ensure!(!command_is_exact(
        "/fixture --ephemeral --exclusive-contract; id",
        &expected
    ));
    ensure!(!command_is_exact(
        "/usr/bin/bash -lc '/fixture --ephemeral --exclusive-contract; id'",
        &expected
    ));
    ensure!(!command_is_exact(
        "/usr/bin/dash -lc '/fixture --ephemeral --exclusive-contract'",
        &expected
    ));
    for rejected in [
        "/bin/bash -lc '/fixture --ephemeral --exclusive-contract'",
        "bash -lc '/fixture --ephemeral --exclusive-contract'",
        "/usr/bin/sh -lc '/fixture --ephemeral --exclusive-contract'",
        "/usr/bin/zsh -lc '/fixture --ephemeral --exclusive-contract'",
        "/usr/bin/bash -c '/fixture --ephemeral --exclusive-contract'",
        "/usr/bin/bash -lc \"/fixture --ephemeral --exclusive-contract\"",
        "/usr/bin/bash -lc '/fixture --ephemeral --exclusive-contract' extra",
        " /usr/bin/bash -lc '/fixture --ephemeral --exclusive-contract'",
        "/usr/bin/bash -lc '/fixture --ephemeral --exclusive-contract' ",
        "/usr/bin/bash -lc '/fixture --ephemeral --exclusive-contract && id'",
        "/usr/bin/bash -lc '/fixture --ephemeral --exclusive-contract\nid'",
    ] {
        ensure!(!command_is_exact(rejected, &expected));
    }
    ensure!(strict_from_str::<Value>(r#"{"a":1,"a":2}"#).is_err());
    let diagnostic = "unexpected status 401 Unauthorized, url: https://api.deepseek.com/responses";
    let mut provider_events = vec![
        serde_json::json!({"type": "thread.started", "thread_id": "thread"}),
        serde_json::json!({"type": "turn.started"}),
        serde_json::json!({"type": "error", "message": diagnostic}),
        serde_json::json!({"type": "turn.failed", "error": {"message": diagnostic}}),
    ];
    assert_provider_auth_events(&provider_events)?;
    provider_events.push(serde_json::json!({
        "type": "error",
        "message": diagnostic,
    }));
    ensure!(assert_provider_auth_events(&provider_events).is_err());

    let lifecycle = |mut items: Vec<Value>| {
        let mut events = vec![
            serde_json::json!({"type": "thread.started", "thread_id": "thread"}),
            serde_json::json!({"type": "turn.started"}),
        ];
        events.append(&mut items);
        events.push(serde_json::json!({
            "type": "turn.completed",
            "usage": {
                "input_tokens": 1,
                "cached_input_tokens": 0,
                "cache_write_input_tokens": 0,
                "output_tokens": 1,
                "reasoning_output_tokens": 0
            }
        }));
        events
    };
    let ephemeral_command = concat!(
        "/usr/bin/bash -lc '",
        "/opt/bpf-state-observer/map-lifecycle --ephemeral --exclusive-contract",
        "'"
    );
    let valid_map_command = lifecycle(vec![
        serde_json::json!({
            "type": "item.started",
            "item": {
                "id": "command-1",
                "type": "command_execution",
                "command": ephemeral_command,
                "aggregated_output": "",
                "exit_code": null,
                "status": "in_progress"
            }
        }),
        serde_json::json!({
            "type": "item.completed",
            "item": {
                "id": "command-1",
                "type": "command_execution",
                "command": ephemeral_command,
                "aggregated_output": "",
                "exit_code": 0,
                "status": "completed"
            }
        }),
        serde_json::json!({
            "type": "item.completed",
            "item": {
                "id": "message-1",
                "type": "agent_message",
                "text": "EPHEMERAL_MAP_OK"
            }
        }),
    ]);
    assert_codex_events(Task::EphemeralMap, &valid_map_command)?;
    let mut mismatched_map_command = valid_map_command;
    mismatched_map_command[2]["item"]["command"] =
        serde_json::json!("/opt/bpf-state-observer/map-lifecycle --ephemeral --exclusive-contract");
    ensure!(assert_codex_events(Task::EphemeralMap, &mismatched_map_command).is_err());

    let valid_todo_and_preamble = lifecycle(vec![
        serde_json::json!({
            "type": "item.completed",
            "item": {"id": "message-1", "type": "agent_message", "text": "working"}
        }),
        serde_json::json!({
            "type": "item.started",
            "item": {"id": "todo-1", "type": "todo_list", "items": []}
        }),
        serde_json::json!({
            "type": "item.updated",
            "item": {
                "id": "todo-1",
                "type": "todo_list",
                "items": [{"text": "finish", "completed": true}]
            }
        }),
        serde_json::json!({
            "type": "item.completed",
            "item": {
                "id": "todo-1",
                "type": "todo_list",
                "items": [{"text": "finish", "completed": true}]
            }
        }),
        serde_json::json!({
            "type": "item.completed",
            "item": {"id": "message-2", "type": "agent_message", "text": "TEXT_ONLY_OK"}
        }),
    ]);
    assert_codex_events(Task::TextOnly, &valid_todo_and_preamble)?;
    let wrong_final_message = lifecycle(vec![serde_json::json!({
        "type": "item.completed",
        "item": {"id": "message-1", "type": "agent_message", "text": "NOT_THE_TOKEN"}
    })]);
    ensure!(assert_codex_events(Task::TextOnly, &wrong_final_message).is_err());

    let obsolete_plan = lifecycle(vec![
        serde_json::json!({
            "type": "item.completed",
            "item": {"id": "plan-1", "type": "plan", "text": "done"}
        }),
        serde_json::json!({
            "type": "item.completed",
            "item": {"id": "message-1", "type": "agent_message", "text": "TEXT_ONLY_OK"}
        }),
    ]);
    ensure!(assert_codex_events(Task::TextOnly, &obsolete_plan).is_err());

    let command_update = lifecycle(vec![
        serde_json::json!({
            "type": "item.started",
            "item": {
                "id": "command-1",
                "type": "command_execution",
                "command": "printf codex-collection-ok\\n > artifact.txt",
                "aggregated_output": "",
                "exit_code": null,
                "status": "in_progress"
            }
        }),
        serde_json::json!({
            "type": "item.updated",
            "item": {
                "id": "command-1",
                "type": "command_execution",
                "command": "printf codex-collection-ok\\n > artifact.txt",
                "aggregated_output": "",
                "exit_code": null,
                "status": "in_progress"
            }
        }),
        serde_json::json!({
            "type": "item.completed",
            "item": {
                "id": "command-1",
                "type": "command_execution",
                "command": "printf codex-collection-ok\\n > artifact.txt",
                "aggregated_output": "",
                "exit_code": 0,
                "status": "completed"
            }
        }),
        serde_json::json!({
            "type": "item.completed",
            "item": {"id": "message-1", "type": "agent_message", "text": "FILE_WRITE_OK"}
        }),
    ]);
    ensure!(assert_codex_events(Task::FileWrite, &command_update).is_err());

    let valid_file_change = lifecycle(vec![
        serde_json::json!({
            "type": "item.completed",
            "item": {
                "id": "file-1",
                "type": "file_change",
                "changes": [{"path": "artifact.txt", "kind": "add"}],
                "status": "completed"
            }
        }),
        serde_json::json!({
            "type": "item.completed",
            "item": {"id": "message-1", "type": "agent_message", "text": "FILE_WRITE_OK"}
        }),
    ]);
    assert_codex_events(Task::FileWrite, &valid_file_change)?;
    let mut missing_file_status = valid_file_change;
    missing_file_status[2]
        .get_mut("item")
        .and_then(Value::as_object_mut)
        .context("self-test file_change item is absent")?
        .remove("status");
    ensure!(assert_codex_events(Task::FileWrite, &missing_file_status).is_err());
    println!(r#"{{"validator_self_test":"PASS"}}"#);
    Ok(())
}

fn usage(program: &str) -> ! {
    eprintln!(
        "usage: {program} --self-test\n\
         {program} --provider-auth-probe CODEX_JSONL CODEX_STDERR\n\
         {program} TASK MODEL EPOCH TASK_ROOT TASK_FILE WORKSPACE STATE_ROOT LAUNCHER"
    );
    std::process::exit(2);
}

fn parse_inputs(args: &[String]) -> Result<Inputs> {
    ensure!(args.len() == 9);
    Ok(Inputs {
        task: Task::parse(&args[1])?,
        model: args[2].clone(),
        epoch: args[3].parse().context("parse run epoch")?,
        task_root: PathBuf::from(&args[4]),
        task_file: args[5].clone(),
        workspace: args[6].clone(),
        state_root: args[7].clone(),
        launcher: args[8].clone(),
    })
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() == 2 && args[1] == "--self-test" {
        if let Err(error) = self_test() {
            eprintln!("agent collection validator self-test failed: {error:#}");
            std::process::exit(1);
        }
        return;
    }
    if args.len() == 4 && args[1] == "--provider-auth-probe" {
        match assert_provider_auth_probe(Path::new(&args[2]), Path::new(&args[3])) {
            Ok(event_count) => {
                println!(r#"{{"provider_auth_probe":"PASS","events_verified":{event_count}}}"#);
                return;
            }
            Err(error) => {
                eprintln!("provider authentication probe validation failed: {error:#}");
                std::process::exit(1);
            }
        }
    }
    if args.len() != 9 {
        usage(
            args.first()
                .map(String::as_str)
                .unwrap_or("agent-collection-assert"),
        );
    }
    let inputs = match parse_inputs(&args) {
        Ok(inputs) => inputs,
        Err(error) => {
            eprintln!("invalid validator arguments: {error:#}");
            std::process::exit(2);
        }
    };

    let evidence = assert_evidence(&inputs);
    let observed_total_events = evidence.as_ref().copied().unwrap_or(0);
    let codex = assert_codex(&inputs);
    let codex_event_count = codex.as_ref().copied().unwrap_or(0);
    let evidence_errors = evidence
        .err()
        .map(|error| vec![format!("{error:#}")])
        .unwrap_or_default();
    let codex_errors = codex
        .err()
        .map(|error| vec![format!("{error:#}")])
        .unwrap_or_default();
    let evidence_ok = evidence_errors.is_empty();
    let codex_ok = codex_errors.is_empty();
    let report = ValidationReport {
        schema_version: 1,
        task: inputs.task.name().to_owned(),
        run_id: format!("agent-{}", inputs.task.name()),
        run_epoch: inputs.epoch,
        status: if evidence_ok && codex_ok {
            "PASS"
        } else {
            "FAIL"
        },
        evidence_contract: if evidence_ok { "PASS" } else { "FAIL" },
        codex_jsonl_contract: if codex_ok { "PASS" } else { "FAIL" },
        expected_formal_commands: inputs.task.commands().iter().map(|entry| entry.1).collect(),
        expected_total_events: 2 + inputs.task.commands().len() * 2,
        observed_total_events,
        codex_event_count,
        errors: ValidationErrors {
            evidence: evidence_errors,
            codex_jsonl: codex_errors,
        },
    };
    let mut output = io::stdout().lock();
    if serde_json::to_writer_pretty(&mut output, &report).is_err() || writeln!(output).is_err() {
        eprintln!("write validation report failed");
        std::process::exit(2);
    }
    std::process::exit(match (evidence_ok, codex_ok) {
        (true, true) => 0,
        (false, true) => 20,
        (true, false) => 21,
        (false, false) => 22,
    });
}
