#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-only

"use strict";

const fs = require("fs");
const path = require("path");

const CASES = [
  { label: "correctness", threads: 8, iterations: 64 },
  { label: "parallel64", threads: 64, iterations: 64 },
];

function fail(message) {
  throw new Error(message);
}

function expect(condition, message) {
  if (!condition) {
    fail(message);
  }
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function readJsonLines(file) {
  const content = fs.readFileSync(file, "utf8");
  expect(content.endsWith("\n"), `${file}: JSONL is not newline terminated`);
  return content
    .split("\n")
    .filter((line) => line.length !== 0)
    .map((line, index) => {
      try {
        return JSON.parse(line);
      } catch (error) {
        fail(`${file}:${index + 1}: ${error.message}`);
      }
    });
}

function expectZeroFields(object, fields, context) {
  for (const field of fields) {
    expect(object[field] === 0, `${context}: ${field}=${object[field]}`);
  }
}

function sameArguments(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function pairEvents(events, syscallName, worker, expectedPairs) {
  const selected = events.filter((event) => event.syscall_name === syscallName);
  const attempts = selected.filter((event) => event.kind === "OPERATION_ATTEMPT");
  const results = selected.filter((event) => event.kind === "OPERATION_RESULT");
  const bySequence = new Map();

  expect(attempts.length === expectedPairs,
    `${worker.comm}/${syscallName}: attempts=${attempts.length}, expected=${expectedPairs}`);
  expect(results.length === expectedPairs,
    `${worker.comm}/${syscallName}: results=${results.length}, expected=${expectedPairs}`);
  for (const attempt of attempts) {
    expect(attempt.related_attempt_seq === 0,
      `${worker.comm}/${syscallName}: attempt has a related sequence`);
    expect(!bySequence.has(attempt.event_seq),
      `${worker.comm}/${syscallName}: duplicate attempt sequence ${attempt.event_seq}`);
    bySequence.set(attempt.event_seq, { attempt, result: null });
  }
  for (const result of results) {
    const pair = bySequence.get(result.related_attempt_seq);
    expect(pair !== undefined,
      `${worker.comm}/${syscallName}: result ${result.event_seq} has no attempt`);
    expect(pair.result === null,
      `${worker.comm}/${syscallName}: attempt ${result.related_attempt_seq} has two results`);
    expect(result.pid === pair.attempt.pid && result.tgid === pair.attempt.tgid,
      `${worker.comm}/${syscallName}: pair crossed a task identity`);
    expect(result.operation === pair.attempt.operation,
      `${worker.comm}/${syscallName}: pair crossed an operation`);
    expect(sameArguments(result.raw_arguments, pair.attempt.raw_arguments),
      `${worker.comm}/${syscallName}: pair arguments differ`);
    expect(result.ktime_ns >= pair.attempt.ktime_ns,
      `${worker.comm}/${syscallName}: result precedes attempt`);
    expect(result.return_value === 1 && result.result_status === "RETURNED_SUCCESS",
      `${worker.comm}/${syscallName}: result was not a successful one-byte write`);
    pair.result = result;
  }
  for (const [sequence, pair] of bySequence) {
    expect(pair.result !== null,
      `${worker.comm}/${syscallName}: attempt ${sequence} is not closed`);
  }
  return [...bySequence.values()];
}

function regularFileIdentity(result, worker) {
  const resolution = result.object_resolution;
  expect(resolution && resolution.quality === "KERNEL_RESOLVED",
    `${worker.comm}: pwrite64 object is not kernel resolved`);
  expect(resolution.operation_attempt_seq === result.related_attempt_seq,
    `${worker.comm}: object join points at another attempt`);
  const object = resolution.objects.find((candidate) =>
    candidate.role === "PRIMARY" && candidate.identity.kind === "FILE_OBJECT");
  expect(object !== undefined, `${worker.comm}: missing primary FILE_OBJECT`);
  const identity = object.identity;
  expect(identity.mount_id_unique === worker.mount_id_unique,
    `${worker.comm}: mount identity crossed threads`);
  expect(identity.device_major === worker.device_major &&
    identity.device_minor === worker.device_minor,
  `${worker.comm}: device identity crossed threads`);
  expect(identity.inode === worker.inode,
    `${worker.comm}: inode identity crossed threads`);
}

function analyzeCase(root, specification) {
  const caseDir = path.join(root, specification.label);
  const runDir = path.join(caseDir, "artifacts");
  const truth = readJson(path.join(runDir, "workload.stdout"));
  const events = readJsonLines(path.join(runDir, "system-effects.jsonl"));
  const health = readJson(path.join(runDir, "system-effects.health.json"));
  const lifecycleEvents = readJsonLines(path.join(runDir, "process-lifecycle.jsonl"));
  const lifecycleHealth = readJson(path.join(runDir,
    "process-lifecycle.health.json"));
  const verification = readJson(path.join(caseDir, "verify.json"));
  const manifest = readJson(path.join(runDir, "system-effects.manifest.json"));

  expect(truth.schema_version === 1, `${specification.label}: bad truth schema`);
  expect(truth.threads === specification.threads,
    `${specification.label}: truth thread count changed`);
  expect(truth.iterations === specification.iterations,
    `${specification.label}: truth iteration count changed`);
  expect(truth.expected_pwrite_pairs === truth.threads * truth.iterations,
    `${specification.label}: invalid expected pwrite count`);
  expect(truth.expected_blocking_write_pairs === truth.threads,
    `${specification.label}: invalid expected blocked-write count`);
  expect(truth.overlap_confirmed_by_proc === truth.threads,
    `${specification.label}: /proc did not independently confirm all blocked writes`);
  expect(Array.isArray(truth.workers) && truth.workers.length === truth.threads,
    `${specification.label}: incomplete worker truth`);
  const tids = new Set(truth.workers.map((worker) => worker.tid));
  expect(tids.size === truth.threads, `${specification.label}: worker TIDs are not unique`);
  const inodeKeys = new Set(truth.workers.map((worker) =>
    `${worker.mount_id_unique}:${worker.device_major}:${worker.device_minor}:${worker.inode}`));
  expect(inodeKeys.size === truth.threads,
    `${specification.label}: per-thread file identities are not unique`);

  expect(manifest.run_status === "FINALIZED",
    `${specification.label}: recorder did not finalize`);
  expect(health.transport_status === "COMPLETE",
    `${specification.label}: system-effect transport is ${health.transport_status}`);
  expect(health.operation_attempted === health.operation_completed,
    `${specification.label}: operation counts are unbalanced`);
  expect(health.event_attempted === health.event_published,
    `${specification.label}: kernel event publication is incomplete`);
  expect(health.event_published === health.events_persisted,
    `${specification.label}: persisted event count differs`);
  expect(health.events_persisted === events.length,
    `${specification.label}: JSONL count differs from health`);
  expectZeroFields(health, [
    "event_dropped", "pending_insert_failed", "pending_missing",
    "pending_remaining", "userspace_failures", "fatal_kernel_flags",
    "task_read_failed", "object_join_missing", "object_join_ambiguous",
    "object_read_failed", "object_delete_failed", "object_pending_remaining",
  ], `${specification.label}/system-health`);
  expect(health.producer_barrier_complete === true &&
    health.drain_completed === true && health.wal_durable === true,
  `${specification.label}: system-effect barrier/drain/WAL is incomplete`);
  expect(Array.isArray(health.reasons) && health.reasons.length === 0,
    `${specification.label}: system-effect health has failure reasons`);

  expect(lifecycleHealth.status === "PARTIAL",
    `${specification.label}: lifecycle must honestly remain PARTIAL`);
  expect(lifecycleHealth.event_attempted === lifecycleHealth.event_published &&
    lifecycleHealth.event_published === lifecycleHealth.events_persisted,
  `${specification.label}: lifecycle counts are unbalanced`);
  expect(lifecycleHealth.events_persisted === lifecycleEvents.length,
    `${specification.label}: lifecycle JSONL count differs from health`);
  expectZeroFields(lifecycleHealth, [
    "event_dropped", "task_read_failed", "exec_path_read_failed",
    "exec_path_truncated", "userspace_failures",
  ], `${specification.label}/lifecycle-health`);
  expect(lifecycleHealth.producer_barrier_complete === true &&
    lifecycleHealth.drain_completed === true && lifecycleHealth.wal_durable === true,
  `${specification.label}: lifecycle barrier/drain/WAL is incomplete`);
  expect(Array.isArray(lifecycleHealth.reasons) && lifecycleHealth.reasons.length === 0,
    `${specification.label}: lifecycle health has failure reasons`);

  expect(verification.transport_complete === true,
    `${specification.label}: offline verifier rejected transport`);
  expect(verification.external_recorder_digest_checked === true,
    `${specification.label}: recorder digest was not externally checked`);
  expect(verification.events_verified === health.events_persisted,
    `${specification.label}: verifier event count differs`);
  expect(verification.policy_profile === "balanced" &&
    verification.object_resolution_mode === "KERNEL_OBJECT_EXPANDED_PARTIAL",
  `${specification.label}: verifier binding differs`);
  expect(verification.process_lifecycle_status === "PARTIAL" &&
    verification.process_lifecycle_artifacts_verified === true,
  `${specification.label}: lifecycle artifacts were not independently verified`);
  expect(verification.syscall_lifecycle_identity_correlation_verified === true,
    `${specification.label}: syscall/lifecycle identity correlation failed`);
  expect(verification.direct_event_attribution_validated === true,
    `${specification.label}: direct cgroup attribution failed`);

  const allSequences = events.map((event) => event.event_seq).sort((a, b) => a - b);
  for (let index = 0; index < allSequences.length; index++) {
    expect(allSequences[index] === index + 1,
      `${specification.label}: event sequence has a gap or duplicate at ${index + 1}`);
  }

  const blockingPairs = [];
  let pwritePairs = 0;
  for (const worker of truth.workers) {
    expect(worker.tid !== truth.tgid, `${worker.comm}: worker TID equals TGID`);
    const workerEvents = events.filter((event) => event.pid === worker.tid);
    expect(workerEvents.length === 2 * (truth.iterations + 1),
      `${worker.comm}: unexpected selected syscall event count ${workerEvents.length}`);
    for (const event of workerEvents) {
      expect(event.tgid === truth.tgid, `${worker.comm}: event has another TGID`);
      expect(event.comm === worker.comm, `${worker.comm}: event comm differs`);
      expect(event.operation === "FD_WRITE",
        `${worker.comm}: unexpected operation ${event.operation}`);
      expect(event.syscall_name === "pwrite64" || event.syscall_name === "write",
        `${worker.comm}: unexpected syscall ${event.syscall_name}`);
    }

    const workerPwritePairs = pairEvents(workerEvents, "pwrite64", worker,
      truth.iterations);
    const offsets = new Set();
    for (const pair of workerPwritePairs) {
      expect(pair.attempt.raw_arguments[2] === 1,
        `${worker.comm}: pwrite64 length differs`);
      offsets.add(pair.attempt.raw_arguments[3]);
      regularFileIdentity(pair.result, worker);
    }
    expect(offsets.size === truth.iterations,
      `${worker.comm}: pwrite64 offsets are not unique`);
    for (let offset = 0; offset < truth.iterations; offset++) {
      expect(offsets.has(offset), `${worker.comm}: missing pwrite64 offset ${offset}`);
    }
    pwritePairs += workerPwritePairs.length;

    const workerBlockingPairs = pairEvents(workerEvents, "write", worker, 1);
    expect(workerBlockingPairs[0].attempt.raw_arguments[2] === 1,
      `${worker.comm}: blocked write length differs`);
    blockingPairs.push(workerBlockingPairs[0]);

    const workerLifecycle = lifecycleEvents.filter((event) =>
      event.subject.pid === worker.tid);
    const forks = workerLifecycle.filter((event) => event.kind === "FORK");
    const exits = workerLifecycle.filter((event) => event.kind === "EXIT");
    const execs = workerLifecycle.filter((event) => event.kind === "EXEC");
    expect(forks.length === 1 && exits.length === 1 && execs.length === 0,
      `${worker.comm}: lifecycle is not exactly FORK+EXIT`);
    expect(forks[0].subject.tgid === truth.tgid && exits[0].subject.tgid === truth.tgid,
      `${worker.comm}: lifecycle has another TGID`);
    expect(forks[0].subject.start_boottime_ns === exits[0].subject.start_boottime_ns,
      `${worker.comm}: lifecycle identity changed`);
    expect(exits[0].subject.comm === worker.comm,
      `${worker.comm}: EXIT comm differs`);
    expect(exits[0].group_dead === false,
      `${worker.comm}: non-leader EXIT incorrectly marks group_dead`);
  }

  expect(pwritePairs === truth.expected_pwrite_pairs,
    `${specification.label}: total pwrite64 pairs differ`);
  expect(blockingPairs.length === truth.expected_blocking_write_pairs,
    `${specification.label}: total blocked-write pairs differ`);
  const latestAttemptTime = Math.max(...blockingPairs.map((pair) =>
    pair.attempt.ktime_ns));
  const earliestResultTime = Math.min(...blockingPairs.map((pair) =>
    pair.result.ktime_ns));
  const latestAttemptSequence = Math.max(...blockingPairs.map((pair) =>
    pair.attempt.event_seq));
  const earliestResultSequence = Math.min(...blockingPairs.map((pair) =>
    pair.result.event_seq));
  expect(latestAttemptTime < earliestResultTime,
    `${specification.label}: kernel timestamps do not prove all writes overlapped`);
  expect(latestAttemptSequence < earliestResultSequence,
    `${specification.label}: event sequence does not prove all writes overlapped`);

  return {
    label: specification.label,
    status: "PASS",
    threads: truth.threads,
    iterations_per_thread: truth.iterations,
    pwrite64_pairs_verified: pwritePairs,
    simultaneous_blocked_writes_verified: blockingPairs.length,
    system_effect_events_verified: health.events_persisted,
    lifecycle_events_verified: lifecycleHealth.events_persisted,
    system_callback_queue_high_water: health.callback_queue_high_water,
    system_maximum_events_per_poll: health.maximum_events_per_poll,
    lifecycle_callback_queue_high_water: lifecycleHealth.callback_queue_high_water,
    lifecycle_status: lifecycleHealth.status,
    offline_verifier: "PASS",
    fixture_wall_ms: (truth.finished_ns - truth.started_ns) / 1000000,
  };
}

function analyzeOverload(root) {
  const specification = { label: "overload", threads: 64, iterations: 512 };
  const caseDir = path.join(root, specification.label);
  const runDir = path.join(caseDir, "artifacts");
  const health = readJson(path.join(runDir, "system-effects.health.json"));
  const recorded = readJson(path.join(caseDir, "overload-result.json"));

  if (health.transport_status === "COMPLETE") {
    const complete = analyzeCase(root, specification);
    complete.load_outcome = "COMPLETE";
    return complete;
  }

  const truth = readJson(path.join(runDir, "workload.stdout"));
  const outcome = readJson(path.join(caseDir, "outcome.json"));
  const manifest = readJson(path.join(runDir, "system-effects.manifest.json"));
  const lifecycleHealth = readJson(path.join(runDir,
    "process-lifecycle.health.json"));
  const verifyStdout = fs.readFileSync(path.join(caseDir, "verify.json"), "utf8");
  const verifyStderr = fs.readFileSync(path.join(caseDir, "verify.stderr"), "utf8");

  expect(truth.threads === specification.threads &&
    truth.iterations === specification.iterations,
  "overload: fixture dimensions changed");
  expect(truth.overlap_confirmed_by_proc === truth.threads,
    "overload: /proc did not independently confirm 64 simultaneous writes");
  expect(new Set(truth.workers.map((worker) => worker.tid)).size === truth.threads,
    "overload: worker TIDs are not unique");
  expect(recorded.outcome === "INCOMPLETE_FAIL_CLOSED",
    `overload: unexpected recorded outcome ${recorded.outcome}`);
  expect(health.transport_status === "INCOMPLETE",
    `overload: unexpected transport ${health.transport_status}`);
  expect(outcome.transport_status === "INCOMPLETE",
    "overload: CLI outcome did not retain INCOMPLETE");
  expect(manifest.transport_status === "INCOMPLETE" &&
    manifest.run_status === "FINALIZED",
  "overload: diagnostic manifest is not closed and marked incomplete");
  expect(health.operation_attempted + health.operation_completed ===
    health.event_attempted,
  "overload: attempted operation accounting differs");
  expect(health.event_published + health.event_dropped === health.event_attempted,
    "overload: published/drop accounting differs");
  expect(health.events_persisted === health.event_published,
    "overload: persisted/published accounting differs");
  expect(health.event_dropped > 0 || health.userspace_failures > 0,
    "overload: incomplete result has no explicit loss/failure counter");
  expect(recorded.event_dropped === health.event_dropped &&
    recorded.userspace_failures === health.userspace_failures,
  "overload: Guest summary differs from health evidence");
  expect(health.pending_remaining === 0 && health.object_pending_remaining === 0,
    "overload: recorder left pending state behind");
  expect(health.producer_barrier_complete === true &&
    health.drain_completed === true && health.wal_durable === true,
  "overload: diagnostic evidence did not reach a closed boundary");
  expect(Array.isArray(health.reasons) && health.reasons.length > 0,
    "overload: incomplete health has no reason");
  expect(lifecycleHealth.status === "PARTIAL" &&
    lifecycleHealth.event_dropped === 0 &&
    lifecycleHealth.event_published === lifecycleHealth.events_persisted,
  "overload: lifecycle stream was unexpectedly lossy");
  expect(verifyStdout.length === 0 && verifyStderr.length > 0,
    "overload: strict offline verifier did not reject incomplete evidence");

  return {
    label: specification.label,
    status: "INCOMPLETE_FAIL_CLOSED",
    threads: truth.threads,
    iterations_per_thread: truth.iterations,
    attempted_events: health.event_attempted,
    persisted_events: health.events_persisted,
    dropped_events: health.event_dropped,
    userspace_failures: health.userspace_failures,
    system_callback_queue_high_water: health.callback_queue_high_water,
    system_callback_queue_capacity: health.callback_queue_capacity,
    simultaneous_blocked_writes_confirmed_by_proc: truth.overlap_confirmed_by_proc,
    lifecycle_status: lifecycleHealth.status,
    strict_offline_verifier: "REJECTED_AS_REQUIRED",
  };
}

function main() {
  if (process.argv.length !== 3) {
    console.error("usage: analyze-concurrency-e2e.js EVIDENCE_ROOT");
    process.exit(2);
  }
  const root = path.resolve(process.argv[2]);
  const cases = CASES.map((specification) => analyzeCase(root, specification));
  cases.push(analyzeOverload(root));
  process.stdout.write(`${JSON.stringify({
    schema_version: 1,
    status: "PASS",
    cases,
    conclusion: "Lossless per-thread pairing and file-object identity were required at 8 and 64 threads; the larger unpaced burst was separately classified as complete or explicitly fail-closed.",
    limitation: "Process lifecycle remains PARTIAL because the product contract lacks an S0 all-thread ledger and cgroup migration/CLONE_INTO_CGROUP enrollment hooks.",
  }, null, 2)}\n`);
}

try {
  main();
} catch (error) {
  console.error(error.stack || error.message);
  process.exit(1);
}
