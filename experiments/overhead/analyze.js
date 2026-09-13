#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-only

"use strict";

const fs = require("fs");
const path = require("path");

if (process.argv.length !== 5) {
  process.stderr.write("usage: analyze.js RESULTS_ROOT REPORT_JSON REPORT_MD\n");
  process.exit(2);
}

const [resultsRoot, reportJson, reportMarkdown] = process.argv.slice(2);
const bpfBatchSize = 128;
const bpfPauseUs = 1000;
const bootstrapResamples = 20000;
const cases = [
  { name: "noop-0", mode: "noop", iterations: 0 },
  { name: "getpid-100000", mode: "getpid", iterations: 100000 },
  { name: "bpf-update-0", mode: "bpf-update", iterations: 0 },
  { name: "bpf-update-4096", mode: "bpf-update", iterations: 4096 },
  { name: "bpf-update-16384", mode: "bpf-update", iterations: 16384 },
  { name: "bpf-update-32768", mode: "bpf-update", iterations: 32768 },
];

function fail(message) {
  throw new Error(message);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function readJsonLine(file) {
  const lines = fs.readFileSync(file, "utf8").trim().split(/\n/);
  if (lines.length !== 1) fail(`${file} does not contain exactly one JSON line`);
  return JSON.parse(lines[0]);
}

function readEnvironment(file) {
  const result = {};
  for (const line of fs.readFileSync(file, "utf8").trim().split(/\n/)) {
    const separator = line.indexOf("=");
    if (separator <= 0) fail(`invalid environment line: ${line}`);
    result[line.slice(0, separator)] = line.slice(separator + 1);
  }
  return result;
}

function sorted(values) {
  return [...values].sort((left, right) => left - right);
}

function quantile(values, probability) {
  if (!values.length) fail("cannot calculate a quantile of an empty sample");
  const ordered = sorted(values);
  const index = Math.max(0, Math.ceil(probability * ordered.length) - 1);
  return ordered[index];
}

function median(values) {
  if (!values.length) fail("cannot calculate a median of an empty sample");
  const ordered = sorted(values);
  const middle = Math.floor(ordered.length / 2);
  return ordered.length % 2
    ? ordered[middle]
    : (ordered[middle - 1] + ordered[middle]) / 2;
}

function mad(values) {
  const center = median(values);
  return median(values.map((value) => Math.abs(value - center)));
}

function summary(values) {
  return {
    count: values.length,
    median: median(values),
    nearest_rank_p95: quantile(values, 0.95),
    min: Math.min(...values),
    max: Math.max(...values),
    mad: mad(values),
  };
}

function nsToMs(value) {
  return value / 1e6;
}

function nsSummaryMs(values) {
  const value = summary(values);
  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [key, key === "count" ? entry : nsToMs(entry)]),
  );
}

function fixed(value, digits = 3) {
  return Number(value).toFixed(digits);
}

function sampleName(sample) {
  return `sample-${String(sample).padStart(3, "0")}`;
}

function sampleDirectories(caseRoot, expectedCount) {
  const entries = fs.readdirSync(caseRoot, { withFileTypes: true });
  if (entries.some((entry) => !entry.isDirectory())) {
    fail(`non-directory entry in ${caseRoot}`);
  }
  const actual = entries.map((entry) => entry.name).sort();
  const expected = Array.from({ length: expectedCount }, (_, index) => sampleName(index + 1));
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`sample set mismatch in ${caseRoot}`);
  }
  return actual.map((entry) => path.join(caseRoot, entry));
}

function validateClassLayout(className, expectedCount) {
  const classRoot = path.join(resultsRoot, className);
  const entries = fs.readdirSync(classRoot, { withFileTypes: true });
  if (entries.some((entry) => !entry.isDirectory())) {
    fail(`non-directory entry in ${classRoot}`);
  }
  const actualCases = entries.map((entry) => entry.name).sort();
  const expectedCases = cases.map((entry) => entry.name).sort();
  if (JSON.stringify(actualCases) !== JSON.stringify(expectedCases)) {
    fail(`${className} case set mismatch`);
  }
  for (const spec of cases) {
    sampleDirectories(path.join(classRoot, spec.name), expectedCount);
  }
}

function binomialCoefficient(n, k) {
  let result = 1;
  const terms = Math.min(k, n - k);
  for (let index = 1; index <= terms; index++) {
    result = (result * (n - terms + index)) / index;
  }
  return result;
}

function distributionFreeMedianInterval(values, requestedCoverage = 0.95) {
  const ordered = sorted(values);
  const denominator = 2 ** ordered.length;
  let cumulative = 0;
  let selected = 0;
  let achievedCoverage = Math.max(0, 1 - 2 / denominator);
  for (let index = 0; index < Math.floor(ordered.length / 2); index++) {
    cumulative += binomialCoefficient(ordered.length, index) / denominator;
    const coverage = Math.max(0, 1 - 2 * cumulative);
    if (coverage >= requestedCoverage) {
      selected = index;
      achievedCoverage = coverage;
    } else {
      break;
    }
  }
  return {
    lower: ordered[selected],
    upper: ordered[ordered.length - 1 - selected],
    coverage: achievedCoverage,
    lower_order_statistic: selected + 1,
    upper_order_statistic: ordered.length - selected,
  };
}

function bootstrapMedianInterval(values) {
  let state = 0x6d2b79f5;
  const next = () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
  const estimates = [];
  for (let repetition = 0; repetition < bootstrapResamples; repetition++) {
    const resample = [];
    for (let index = 0; index < values.length; index++) {
      resample.push(values[next() % values.length]);
    }
    estimates.push(median(resample));
  }
  return {
    lower: quantile(estimates, 0.025),
    upper: quantile(estimates, 0.975),
    resamples: bootstrapResamples,
    seed: "xorshift32:0x6d2b79f5",
  };
}

function assessPositiveEstimate(values, shape = null) {
  const estimate = median(values);
  const descriptive = summary(values);
  const distributionFree = distributionFreeMedianInterval(values);
  const bootstrap = bootstrapMedianInterval(values);
  const outer = {
    lower: Math.min(distributionFree.lower, bootstrap.lower),
    upper: Math.max(distributionFree.upper, bootstrap.upper),
  };
  const leaveOneOut = values.map((_, omitted) =>
    median(values.filter((_value, index) => index !== omitted)),
  );
  const maximumLeaveOneOutRelativeDeviation = Math.max(
    ...leaveOneOut.map((value) => Math.abs(value - estimate) / Math.max(1, Math.abs(estimate))),
  );
  const positiveCount = values.filter((value) => value > 0).length;
  const requiredPositiveCount = Math.ceil(values.length * 0.8);
  const inferenceAccepted =
    values.length >= 12 &&
    estimate > 0 &&
    outer.lower > 0 &&
    outer.upper - outer.lower <= 0.5 * Math.abs(estimate) &&
    maximumLeaveOneOutRelativeDeviation <= 0.25 &&
    positiveCount >= requiredPositiveCount;
  let status = "LOW_CONFIDENCE";
  if (inferenceAccepted) {
    status = shape && !shape.accepted ? "RANGE_AVERAGE_ONLY" : "USABLE_ESTIMATE";
  }
  return {
    status,
    accepted_median: status === "LOW_CONFIDENCE" ? null : estimate,
    exploratory_summary: descriptive,
    bootstrap_95_interval: bootstrap,
    distribution_free_median_interval: distributionFree,
    outer_interval: outer,
    positive_count: positiveCount,
    required_positive_count: requiredPositiveCount,
    maximum_leave_one_out_relative_deviation: maximumLeaveOneOutRelativeDeviation,
    inference_acceptance_rule:
      "n >= 12; outer CI lower > 0; CI width <= 50% of median; all leave-one-out medians within 25%; >= 80% positive blocks",
    shape,
  };
}

function expectedWorkload(spec) {
  const argumentsList = [
    "/opt/bpf-overhead/overhead-bench",
    "--mode",
    spec.mode,
    "--iterations",
    String(spec.iterations),
    "--cpu",
    "1",
  ];
  if (spec.mode === "bpf-update") {
    argumentsList.push(
      "--batch-size",
      String(bpfBatchSize),
      "--pause-us",
      String(bpfPauseUs),
    );
  }
  return argumentsList;
}

function validateWorkload(workload, spec, sampleRoot) {
  const expectedBatchSize = spec.mode === "bpf-update" ? bpfBatchSize : 0;
  const expectedPauseUs = spec.mode === "bpf-update" ? bpfPauseUs : 0;
  const expectedSleeps =
    spec.mode === "bpf-update" && spec.iterations > 0
      ? Math.floor((spec.iterations - 1) / bpfBatchSize)
      : 0;
  const expectedBpfSyscalls = spec.mode === "bpf-update" ? spec.iterations + 1 : 0;
  const expectedOrdinarySyscalls = spec.mode === "getpid" ? spec.iterations : 0;
  if (
    workload.schema_version !== 1 ||
    workload.mode !== spec.mode ||
    workload.iterations !== spec.iterations ||
    workload.cpu !== 1 ||
    workload.batch_size !== expectedBatchSize ||
    workload.pause_us !== expectedPauseUs ||
    workload.pacing_sleeps !== expectedSleeps ||
    workload.bpf_syscalls !== expectedBpfSyscalls ||
    workload.ordinary_syscalls !== expectedOrdinarySyscalls ||
    workload.elapsed_ns < 0 ||
    workload.pacing_sleep_ns < 0 ||
    workload.active_elapsed_ns !== workload.elapsed_ns - workload.pacing_sleep_ns
  ) {
    fail(`workload contract mismatch in ${sampleRoot}`);
  }
  if (spec.mode !== "bpf-update" && workload.pacing_sleep_ns !== 0) {
    fail(`unexpected pacing time in ${sampleRoot}`);
  }
}

function loadCase(spec, repetitions) {
  const root = path.join(resultsRoot, "samples", spec.name);
  const pairs = sampleDirectories(root, repetitions).map((sampleRoot, index) => {
    const sample = index + 1;
    const directRoot = path.join(sampleRoot, "direct");
    const observedRoot = path.join(sampleRoot, "observed");
    const observerRun = path.join(observedRoot, "observer-run");
    const directCommand = readJson(path.join(directRoot, "command.json"));
    const observedCommand = readJson(path.join(observedRoot, "command.json"));
    const directWorkload = readJsonLine(path.join(directRoot, "workload.json"));
    const observedWorkload = readJsonLine(path.join(observerRun, "workload.stdout"));
    const health = readJson(path.join(observerRun, "health.json"));
    const s0 = readJson(path.join(observerRun, "s0.json"));
    const s1 = readJson(path.join(observerRun, "s1.json"));
    const manifest = readJson(path.join(observerRun, "manifest.json"));
    const verify = readJson(path.join(observedRoot, "verify.json"));
    const order = fs.readFileSync(path.join(sampleRoot, "order.txt"), "utf8").trim();
    const position = Number(
      fs.readFileSync(path.join(sampleRoot, "case-position.txt"), "utf8").trim(),
    );
    const expectedOrder = sample % 2 === 1 ? "direct-first" : "observed-first";
    const expectedBpfSyscalls = spec.mode === "bpf-update" ? spec.iterations + 1 : 0;
    const expectedFormalEvents = 2 * expectedBpfSyscalls;
    const expectedVerifiedEvents = expectedFormalEvents + 2;
    const expectedRunId = `oh-samples-${spec.name}-${sample}`;
    const expectedEpoch = 100000 + sample + spec.iterations;
    validateWorkload(directWorkload, spec, sampleRoot);
    validateWorkload(observedWorkload, spec, sampleRoot);
    for (const command of [directCommand, observedCommand]) {
      if (
        command.schema_version !== 1 ||
        command.exit_code !== 0 ||
        command.signal !== 0 ||
        command.wall_ns <= 0 ||
        command.user_cpu_ns < 0 ||
        command.system_cpu_ns < 0 ||
        command.max_rss_kb <= 0
      ) {
        fail(`measured command contract mismatch in ${sampleRoot}`);
      }
    }
    if (order !== expectedOrder || !Number.isInteger(position)) {
      fail(`pair order metadata mismatch in ${sampleRoot}`);
    }
    if (
      manifest.run_status !== "FINALIZED" ||
      manifest.run_id !== expectedRunId ||
      manifest.run_epoch !== expectedEpoch ||
      manifest.workload_exit_code !== 0 ||
      manifest.workload_signal != null ||
      JSON.stringify(manifest.workload) !== JSON.stringify(expectedWorkload(spec))
    ) {
      fail(`finalized manifest contract mismatch in ${sampleRoot}`);
    }
    if (
      verify.schema_version !== 1 ||
      !verify.evidence_complete ||
      verify.run_id !== expectedRunId ||
      verify.run_epoch !== expectedEpoch ||
      verify.events_verified !== expectedVerifiedEvents ||
      verify.artifacts_verified !== 10 ||
      verify.recorder_digest_policy_match !== true
    ) {
      fail(`offline verification contract mismatch in ${sampleRoot}`);
    }
    const exactHealth = {
      syscall_attempted: expectedBpfSyscalls,
      syscall_completed: expectedBpfSyscalls,
      last_event_seq: expectedFormalEvents,
      event_attempted: expectedFormalEvents,
      event_published: expectedFormalEvents,
      event_dropped: 0,
      events_persisted: expectedFormalEvents,
      pending_insert_failed: 0,
      pending_missing: 0,
      pending_remaining: 0,
      outside_cgroup_syscall_attempted: 0,
      parse_failed: 0,
    };
    for (const [field, expected] of Object.entries(exactHealth)) {
      if (health[field] !== expected) fail(`health.${field} mismatch in ${sampleRoot}`);
    }
    for (const field of [
      "recorder_loaded",
      "run_registered",
      "producer_barrier_complete",
      "drain_completed",
      "wal_durable",
      "native_transport_canary_passed",
    ]) {
      if (health[field] !== true) fail(`health.${field} is not true in ${sampleRoot}`);
    }
    if (
      !Array.isArray(health.unsupported_commands) ||
      health.unsupported_commands.length !== 0 ||
      !Array.isArray(health.reasons) ||
      health.reasons.length !== 0
    ) {
      fail(`unexpected health diagnostics in ${sampleRoot}`);
    }
    const jsonlBytes = manifest.artifacts["raw-events.jsonl"].size_bytes;
    const walBytes = manifest.artifacts["raw-events.bin"].size_bytes;
    if (
      fs.statSync(path.join(observerRun, "raw-events.jsonl")).size !== jsonlBytes ||
      fs.statSync(path.join(observerRun, "raw-events.bin")).size !== walBytes
    ) {
      fail(`raw event artifact size mismatch in ${sampleRoot}`);
    }
    return {
      sample: sampleName(sample),
      order,
      position,
      direct: { command: directCommand, workload: directWorkload },
      observed: { command: observedCommand, workload: observedWorkload },
      health,
      snapshot_ns: Number(s0.capture_duration_ns) + Number(s1.capture_duration_ns),
      full_wall_delta_ns: observedCommand.wall_ns - directCommand.wall_ns,
      command_cpu_delta_ns:
        observedCommand.user_cpu_ns +
        observedCommand.system_cpu_ns -
        directCommand.user_cpu_ns -
        directCommand.system_cpu_ns,
      workload_elapsed_delta_ns: observedWorkload.elapsed_ns - directWorkload.elapsed_ns,
      workload_active_delta_ns:
        observedWorkload.active_elapsed_ns - directWorkload.active_elapsed_ns,
      command_ru_maxrss_difference_kb:
        observedCommand.max_rss_kb - directCommand.max_rss_kb,
      raw_jsonl_bytes: jsonlBytes,
      raw_wal_bytes: walBytes,
      verified_events: expectedVerifiedEvents,
    };
  });
  const collect = (selector) => pairs.map(selector);
  return {
    mode: spec.mode,
    iterations: spec.iterations,
    pairs,
    statistics: {
      direct_wall_ms: nsSummaryMs(collect((pair) => pair.direct.command.wall_ns)),
      observed_wall_ms: nsSummaryMs(collect((pair) => pair.observed.command.wall_ns)),
      paired_observe_wall_delta_ms: nsSummaryMs(collect((pair) => pair.full_wall_delta_ns)),
      paired_command_cpu_delta_ms: nsSummaryMs(collect((pair) => pair.command_cpu_delta_ns)),
      direct_workload_elapsed_ms: nsSummaryMs(
        collect((pair) => pair.direct.workload.elapsed_ns),
      ),
      observed_workload_elapsed_ms: nsSummaryMs(
        collect((pair) => pair.observed.workload.elapsed_ns),
      ),
      paired_workload_elapsed_delta_ms: nsSummaryMs(
        collect((pair) => pair.workload_elapsed_delta_ns),
      ),
      paired_workload_active_delta_ms: nsSummaryMs(
        collect((pair) => pair.workload_active_delta_ns),
      ),
      direct_command_ru_maxrss_kb: summary(
        collect((pair) => pair.direct.command.max_rss_kb),
      ),
      observed_command_ru_maxrss_kb: summary(
        collect((pair) => pair.observed.command.max_rss_kb),
      ),
      paired_command_ru_maxrss_difference_kb: summary(
        collect((pair) => pair.command_ru_maxrss_difference_kb),
      ),
      s0_plus_s1_capture_ms: nsSummaryMs(collect((pair) => pair.snapshot_ns)),
      raw_jsonl_bytes: summary(collect((pair) => pair.raw_jsonl_bytes)),
      raw_wal_bytes: summary(collect((pair) => pair.raw_wal_bytes)),
      events_verified: summary(collect((pair) => pair.verified_events)),
    },
  };
}

function alignedEndpointSlopes(loaded, bpfCases, valueField) {
  const zeroPairs = loaded[bpfCases[0].name].pairs;
  const maximum = bpfCases[bpfCases.length - 1];
  const maximumPairs = loaded[maximum.name].pairs;
  return zeroPairs.map((zeroPair, index) => {
    const maximumPair = maximumPairs[index];
    if (!maximumPair || maximumPair.sample !== zeroPair.sample) {
      fail(`BPF endpoint sample alignment mismatch at ${zeroPair.sample}`);
    }
    return (maximumPair[valueField] - zeroPair[valueField]) / maximum.iterations;
  });
}

function shapeAssessment(loaded, bpfCases, valueField) {
  const points = bpfCases.map((spec) => ({
    iterations: spec.iterations,
    median_delta_ns: median(loaded[spec.name].pairs.map((pair) => pair[valueField])),
  }));
  const first = points[0];
  const last = points[points.length - 1];
  const span = last.median_delta_ns - first.median_delta_ns;
  const strictlyMonotonic = points.every(
    (point, index) => index === 0 || point.median_delta_ns > points[index - 1].median_delta_ns,
  );
  let maximumRelativeDeviation = null;
  if (span !== 0) {
    maximumRelativeDeviation = Math.max(
      ...points.slice(1, -1).map((point) => {
        const expected =
          first.median_delta_ns + (span * point.iterations) / last.iterations;
        return Math.abs(point.median_delta_ns - expected) / Math.abs(span);
      }),
    );
  }
  return {
    accepted:
      span > 0 &&
      strictlyMonotonic &&
      maximumRelativeDeviation !== null &&
      maximumRelativeDeviation <= 0.2,
    point_medians: points,
    strictly_monotonic: strictlyMonotonic,
    maximum_relative_deviation_from_endpoint_line: maximumRelativeDeviation,
    acceptance_rule:
      "positive endpoint span; strictly monotonic point medians; maximum intermediate deviation <= 20% of endpoint span",
  };
}

if (!fs.statSync(resultsRoot).isDirectory()) fail("RESULTS_ROOT is not a directory");
if (fs.existsSync(reportJson) || fs.existsSync(reportMarkdown)) {
  fail("refusing to overwrite an existing report");
}
const status = fs.readFileSync(path.join(resultsRoot, "status.txt"), "utf8").trim();
if (status !== "collection=PASS") fail("Guest evidence collection did not report PASS");
const environment = readEnvironment(path.join(resultsRoot, "environment.txt"));
const repetitions = Number(environment.repetitions);
const warmups = Number(environment.warmups);
if (
  !Number.isInteger(repetitions) ||
  repetitions < 12 ||
  repetitions > 48 ||
  repetitions % cases.length !== 0 ||
  !Number.isInteger(warmups) ||
  warmups !== 3 ||
  environment.online_cpus !== "0-1" ||
  environment.reported_cpus !== "2" ||
  environment.controller_cpu !== "0" ||
  environment.workload_cpu !== "1" ||
  environment.bpf_batch_size !== String(bpfBatchSize) ||
  environment.bpf_pause_us !== String(bpfPauseUs) ||
  environment.case_order !== "cyclic-latin-square-v1"
) {
  fail("benchmark environment contract mismatch");
}
validateClassLayout("samples", repetitions);
validateClassLayout("warmup", warmups);

const loaded = Object.fromEntries(
  cases.map((spec) => [spec.name, loadCase(spec, repetitions)]),
);
for (let specIndex = 0; specIndex < cases.length; specIndex++) {
  for (let sample = 1; sample <= repetitions; sample++) {
    const offset = (sample - 1) % cases.length;
    const expectedPosition = (specIndex - offset + cases.length) % cases.length;
    if (loaded[cases[specIndex].name].pairs[sample - 1].position !== expectedPosition) {
      fail(`Latin-square position mismatch for ${cases[specIndex].name}/${sampleName(sample)}`);
    }
  }
}

const bpfCases = cases.filter((spec) => spec.mode === "bpf-update");
const bpfMaximum = bpfCases[bpfCases.length - 1];
const fullWallSlopes = alignedEndpointSlopes(loaded, bpfCases, "full_wall_delta_ns");
const activeWorkloadSlopes = alignedEndpointSlopes(
  loaded,
  bpfCases,
  "workload_active_delta_ns",
);
const commandCpuSlopes = alignedEndpointSlopes(
  loaded,
  bpfCases,
  "command_cpu_delta_ns",
);
const fullWallAssessment = assessPositiveEstimate(
  fullWallSlopes,
  shapeAssessment(loaded, bpfCases, "full_wall_delta_ns"),
);
const activeWorkloadAssessment = assessPositiveEstimate(
  activeWorkloadSlopes,
  shapeAssessment(loaded, bpfCases, "workload_active_delta_ns"),
);
const commandCpuAssessment = assessPositiveEstimate(
  commandCpuSlopes,
  shapeAssessment(loaded, bpfCases, "command_cpu_delta_ns"),
);
const getpid = loaded["getpid-100000"];
const getpidPerCall = getpid.pairs.map(
  (pair) => pair.workload_active_delta_ns / getpid.iterations,
);
const getpidAssessment = assessPositiveEstimate(getpidPerCall);
const noopPairs = loaded["noop-0"].pairs;
const fixedEnvelope = noopPairs.map((pair) => pair.full_wall_delta_ns);
const fixedCpu = noopPairs.map((pair) => pair.command_cpu_delta_ns);
const fixedRss = noopPairs.map((pair) => pair.command_ru_maxrss_difference_kb);
const fixedOrderStrata = Object.fromEntries(
  ["direct-first", "observed-first"].map((order) => [
    order,
    nsSummaryMs(
      noopPairs.filter((pair) => pair.order === order).map((pair) => pair.full_wall_delta_ns),
    ),
  ]),
);
const maximumPairs = loaded[bpfMaximum.name].pairs;
const maximumUpdateRate = maximumPairs.map(
  (pair) => (bpfMaximum.iterations * 1e9) / pair.observed.workload.elapsed_ns,
);
const maximumEventRate = maximumPairs.map(
  (pair) => (pair.health.events_persisted * 1e9) / pair.observed.workload.elapsed_ns,
);
const storageBytesPerVerifiedEvent = maximumPairs.map(
  (pair) => (pair.raw_jsonl_bytes + pair.raw_wal_bytes) / pair.verified_events,
);

const report = {
  schema_version: 3,
  collection_status: "COMPLETE",
  methodology: {
    pairing: "adjacent direct/observed pairs with alternating A/B direction",
    case_order: "cyclic Latin-square rotation across all six cases",
    repetitions,
    warmups_excluded: warmups,
    controller_cpu: 0,
    workload_cpu: 1,
    core_metric_clock: "CLOCK_MONOTONIC_RAW",
    bpf_batch_size: bpfBatchSize,
    bpf_pause_us: bpfPauseUs,
    bpf_primary_estimator:
      "median per-block endpoint contrast: ((observed-direct) at max N - (observed-direct) at N=0) / max N",
    bpf_slope_denominator:
      "one update is one BPF_MAP_UPDATE_ELEM syscall; the one Map-create syscall is present at both endpoints and cancels",
    full_observe_includes:
      "recorder load, canary, cgroup, S0/S1, workload, drain/fsync, compare, and manifest",
    verify_run_timing: "excluded",
  },
  headline: {
    fixed_observe_only_wall_ms: nsSummaryMs(fixedEnvelope),
    fixed_observe_only_wall_by_pair_order_ms: fixedOrderStrata,
    fixed_observe_command_cpu_ms: nsSummaryMs(fixedCpu),
    paired_command_ru_maxrss_difference_kb: summary(fixedRss),
    getpid_pass_through_ns_per_call: getpidAssessment,
    bpf_update_synchronous_active_ns_per_syscall: activeWorkloadAssessment,
    bpf_update_aggregate_command_cpu_ns_per_syscall: commandCpuAssessment,
    bpf_update_full_pipeline_wall_ns_per_syscall: fullWallAssessment,
    maximum_zero_loss_case: {
      updates: bpfMaximum.iterations,
      formal_events: 2 * (bpfMaximum.iterations + 1),
      verified_events_including_canary: 2 * (bpfMaximum.iterations + 1) + 2,
      observed_update_rate_per_second: summary(maximumUpdateRate),
      observed_formal_event_rate_per_second: summary(maximumEventRate),
      raw_jsonl_plus_wal_bytes_per_verified_event: summary(storageBytesPerVerifiedEvent),
      event_loss_observed: false,
    },
  },
  cases: Object.fromEntries(
    Object.entries(loaded).map(([name, value]) => [name, value.statistics]),
  ),
  endpoint_slopes: {
    full_wall_ns_per_syscall: fullWallSlopes,
    synchronous_active_ns_per_syscall: activeWorkloadSlopes,
    aggregate_command_cpu_ns_per_syscall: commandCpuSlopes,
  },
  raw_pairs: Object.fromEntries(
    Object.entries(loaded).map(([name, value]) => [name, value.pairs]),
  ),
  limitations: [
    "This is one disposable 2-vCPU systemd KVM Guest, not an isolated bare-metal benchmark or a universal constant; Host QEMU threads were not CPU-pinned.",
    "The fixed observe-only wall result includes durability and lifecycle work but excludes offline verify-run.",
    "The ordinary-syscall result is a getpid loop proxy; other syscall paths can differ.",
    "BPF pacing sleep is measured and removed only from the synchronous active-path metric; the full wall and aggregate CPU metrics retain their natural command boundaries.",
    "wait4 rusage CPU is reported at microsecond source resolution; nanosecond units do not imply nanosecond measurement resolution.",
    "The paired command ru_maxrss difference subtracts historical process-tree peaks from separate commands; it is not a simultaneous resident-memory delta.",
    "A LOW_CONFIDENCE metric has no accepted estimate even when an exploratory median is retained for auditability.",
    "No Codex or model API latency is included.",
  ],
};

function acceptedMetricLine(label, assessment, unit) {
  if (assessment.status === "LOW_CONFIDENCE") {
    return `- ${label}: **not accepted** (\`${assessment.status}\`); exploratory median is retained only in report.json.`;
  }
  const qualifier =
    assessment.status === "RANGE_AVERAGE_ONLY" ? "0-to-max range-average" : "accepted median";
  return `- ${label}: ${fixed(assessment.accepted_median, 2)} ${unit} (${qualifier}, \`${assessment.status}\`).`;
}

const maximumCase = loaded[bpfMaximum.name].statistics;
const markdown =
  `# BPF State Observer overhead measurement\n\n` +
  `## Accepted results\n\n` +
  `- Evidence collection and offline verification: **COMPLETE**; no event loss was observed.\n` +
  `- Fixed observe-only wall envelope: median ${fixed(report.headline.fixed_observe_only_wall_ms.median)} ms, range ${fixed(report.headline.fixed_observe_only_wall_ms.min)}-${fixed(report.headline.fixed_observe_only_wall_ms.max)} ms; verify-run excluded.\n` +
  `- Fixed observe command CPU: median ${fixed(report.headline.fixed_observe_command_cpu_ms.median)} ms.\n` +
  acceptedMetricLine(
    "getpid raw-tracepoint pass-through increment",
    report.headline.getpid_pass_through_ns_per_call,
    "ns/call",
  ) +
  `\n` +
  acceptedMetricLine(
    "BPF update synchronous active-path increment",
    report.headline.bpf_update_synchronous_active_ns_per_syscall,
    "ns/update",
  ) +
  `\n` +
  acceptedMetricLine(
    "BPF update aggregate command CPU increment",
    report.headline.bpf_update_aggregate_command_cpu_ns_per_syscall,
    "ns/update",
  ) +
  `\n` +
  `- Paired difference in command ru_maxrss peaks (no-op): median ${fixed(report.headline.paired_command_ru_maxrss_difference_kb.median / 1024, 2)} MiB.\n` +
  `- Largest tested zero-loss offered workload case: ${bpfMaximum.iterations} updates, ${report.headline.maximum_zero_loss_case.formal_events} formal records; median ${fixed(report.headline.maximum_zero_loss_case.observed_update_rate_per_second.median, 0)} offered updates/s. This is not a maximum-throughput claim.\n` +
  `- Raw JSONL + WAL footprint at the maximum case: median ${fixed(report.headline.maximum_zero_loss_case.raw_jsonl_plus_wal_bytes_per_verified_event.median, 2)} bytes/verified record.\n\n` +
  `## Rejected metric\n\n` +
  `- BPF full-pipeline wall slope: **not accepted** (\`${fullWallAssessment.status}\`). Its exploratory median is ${fixed(fullWallAssessment.exploratory_summary.median, 2)} ns/update, but the outer interval is ${fixed(fullWallAssessment.outer_interval.lower, 2)} to ${fixed(fullWallAssessment.outer_interval.upper, 2)} ns/update and therefore cannot support a positive per-update wall estimate.\n` +
  `- Fixed wall cost is split by pair direction: direct-first median ${fixed(fixedOrderStrata["direct-first"].median)} ms; observed-first median ${fixed(fixedOrderStrata["observed-first"].median)} ms.\n\n` +
  `## Cases\n\n` +
  `| Case | Direct wall median (ms) | Observed wall median (ms) | Paired observe delta median (ms) | Nearest-rank p95 / sample max (ms) | Active workload delta median (ms) | S0+S1 median (ms) | Verified events |\n` +
  `|---|---:|---:|---:|---:|---:|---:|---:|\n` +
  cases
    .map((spec) => {
      const value = loaded[spec.name].statistics;
      return `| ${spec.name} | ${fixed(value.direct_wall_ms.median)} | ${fixed(value.observed_wall_ms.median)} | ${fixed(value.paired_observe_wall_delta_ms.median)} | ${fixed(value.paired_observe_wall_delta_ms.nearest_rank_p95)} | ${fixed(value.paired_workload_active_delta_ms.median)} | ${fixed(value.s0_plus_s1_capture_ms.median)} | ${value.events_verified.median} |`;
    })
    .join("\n") +
  `\n\nWith n=${repetitions}, nearest-rank p95 is the sample maximum and is shown only as a descriptive tail, not a stable p95 estimate. The maximum BPF case used ${fixed(maximumCase.raw_jsonl_bytes.median / (1024 * 1024), 2)} MiB JSONL and ${fixed(maximumCase.raw_wal_bytes.median / (1024 * 1024), 2)} MiB WAL per run.\n\n` +
  `## Interpretation boundary\n\n` +
  report.limitations.map((entry) => `- ${entry}`).join("\n") +
  "\n";

fs.writeFileSync(reportJson, `${JSON.stringify(report, null, 2)}\n`, {
  flag: "wx",
  mode: 0o600,
});
fs.writeFileSync(reportMarkdown, markdown, { flag: "wx", mode: 0o600 });
process.stdout.write(
  `${JSON.stringify({ collection_status: report.collection_status, headline: report.headline })}\n`,
);
