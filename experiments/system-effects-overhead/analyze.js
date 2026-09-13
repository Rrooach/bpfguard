#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-only

"use strict";

const fs = require("fs");
const path = require("path");

if (process.argv.length !== 5) {
  process.stderr.write("usage: analyze.js RESULTS_ROOT REPORT_JSON REPORT_MD\n");
  process.exit(2);
}

const [root, reportJson, reportMarkdown] = process.argv.slice(2);
const arms = ["quiet-direct", "quiet-observed", "effect-direct", "effect-observed"];

function fail(message) {
  throw new Error(message);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function readJsonLine(file) {
  const text = fs.readFileSync(file, "utf8").trim();
  const lines = text ? text.split(/\n/) : [];
  if (lines.length !== 1) fail(`${file} must contain exactly one JSON line`);
  return JSON.parse(lines[0]);
}

function requireNumber(value, name, minimum = 0) {
  if (!Number.isFinite(value) || value < minimum) fail(`invalid ${name}: ${value}`);
}

function sorted(values) {
  return [...values].sort((left, right) => left - right);
}

function median(values) {
  if (!values.length) fail("median of empty sample");
  const ordered = sorted(values);
  const middle = Math.floor(ordered.length / 2);
  return ordered.length % 2
    ? ordered[middle]
    : (ordered[middle - 1] + ordered[middle]) / 2;
}

function quantile(values, probability) {
  const ordered = sorted(values);
  return ordered[Math.max(0, Math.ceil(probability * ordered.length) - 1)];
}

function choose(n, k) {
  let value = 1;
  for (let index = 1; index <= Math.min(k, n - k); index++) {
    value = (value * (n - Math.min(k, n - k) + index)) / index;
  }
  return value;
}

function medianInterval(values, requestedCoverage = 0.95) {
  const ordered = sorted(values);
  let selectedIndex = 0;
  let tail = 0;
  let coverage = 1 - 2 / 2 ** ordered.length;
  for (let k = 1; k <= Math.floor(ordered.length / 2); k++) {
    tail += choose(ordered.length, k - 1);
    const candidate = 1 - (2 * tail) / 2 ** ordered.length;
    if (candidate >= requestedCoverage) {
      selectedIndex = k - 1;
      coverage = candidate;
    } else {
      break;
    }
  }
  return {
    requested_coverage: requestedCoverage,
    achieved_coverage: coverage,
    lower: ordered[selectedIndex],
    upper: ordered[ordered.length - selectedIndex - 1],
    order_statistic: selectedIndex + 1,
  };
}

function summary(values) {
  return {
    count: values.length,
    median: median(values),
    p95_nearest_rank: quantile(values, 0.95),
    min: Math.min(...values),
    max: Math.max(...values),
  };
}

function sampleDirectory(block) {
  return `block-${String(block).padStart(3, "0")}`;
}

const config = readJson(path.join(root, "config.json"));
if (config.schema_version !== 1 || !Array.isArray(config.iterations)) {
  fail("unsupported or malformed config.json");
}
if (config.repetitions < 4 || config.repetitions > 48 || config.repetitions % 4 !== 0 ||
    config.iterations.length < 2 || config.iterations[0] !== 0) {
  fail("invalid benchmark design in config.json");
}
if (fs.readFileSync(path.join(root, "status.txt"), "utf8").trim() !== "collection=PASS") {
  fail("batch does not have a collection PASS marker");
}

const samples = new Map();
let collectorIdentity = null;
for (let block = 1; block <= config.repetitions; block++) {
  const byLoad = new Map();
  for (const iterations of config.iterations) {
    const byArm = new Map();
    for (const arm of arms) {
      const armRoot = path.join(root, "samples", sampleDirectory(block), `n-${iterations}`, arm);
      const command = readJsonLine(path.join(armRoot, "command.json"));
      const workload = readJsonLine(path.join(armRoot, "workload.json"));
      const expectedProfile = arm.startsWith("quiet-") ? "quiet" : "file";
      if (command.schema_version !== 1 || command.exit_code !== 0 || command.signal !== 0) {
        fail(`unsuccessful command: ${armRoot}`);
      }
      for (const [name, value] of Object.entries({
        wall_ns: command.wall_ns,
        user_cpu_ns: command.user_cpu_ns,
        system_cpu_ns: command.system_cpu_ns,
        max_rss_kb: command.max_rss_kb,
        active_elapsed_ns: workload.active_elapsed_ns,
      })) requireNumber(value, `${armRoot}/${name}`);
      if (workload.schema_version !== 1 || workload.profile !== expectedProfile ||
          workload.iterations !== iterations ||
          workload.syscalls_per_iteration !== 5) {
        fail(`workload identity mismatch: ${armRoot}`);
      }
      let metrics = null;
      if (arm.endsWith("-observed")) {
        metrics = readJsonLine(path.join(armRoot, "observer", "metrics.json"));
        if (metrics.schema_version !== 1 || metrics.evidence_status !== "complete") {
          fail(`incomplete observer evidence: ${armRoot}`);
        }
        if (typeof metrics.collector_identity !== "string" || !metrics.collector_identity) {
          fail(`missing collector identity: ${armRoot}`);
        }
        if (collectorIdentity === null) collectorIdentity = metrics.collector_identity;
        if (collectorIdentity !== metrics.collector_identity) {
          fail(`collector identity changed within batch: ${armRoot}`);
        }
        for (const name of ["events_persisted", "events_dropped", "bytes_persisted"]) {
          requireNumber(metrics[name], `${armRoot}/${name}`);
          if (!Number.isSafeInteger(metrics[name])) fail(`non-integer ${name}: ${armRoot}`);
        }
        if (metrics.events_dropped !== 0) fail(`event loss invalidates batch: ${armRoot}`);
      }
      byArm.set(arm, {
        wall: command.wall_ns,
        cpu: command.user_cpu_ns + command.system_cpu_ns,
        rss: command.max_rss_kb,
        active: workload.active_elapsed_ns,
        metrics,
      });
    }
    byLoad.set(iterations, byArm);
  }
  samples.set(block, byLoad);
}

function contrast(byArm, field) {
  const qd = byArm.get("quiet-direct")[field];
  const qo = byArm.get("quiet-observed")[field];
  const ed = byArm.get("effect-direct")[field];
  const eo = byArm.get("effect-observed")[field];
  return {
    quiet: qo - qd,
    effect: eo - ed,
    event_increment: (eo - ed) - (qo - qd),
  };
}

const points = [];
for (const iterations of config.iterations) {
  const wall = [];
  const cpu = [];
  const quietEventCounts = [];
  const effectEventCounts = [];
  const effectByteCounts = [];
  const eventCounts = [];
  const offeredRates = [];
  const armWall = Object.fromEntries(arms.map((arm) => [arm, []]));
  const armCpu = Object.fromEntries(arms.map((arm) => [arm, []]));
  const rss = Object.fromEntries(arms.map((arm) => [arm, []]));
  for (let block = 1; block <= config.repetitions; block++) {
    const byArm = samples.get(block).get(iterations);
    wall.push(contrast(byArm, "wall"));
    cpu.push(contrast(byArm, "cpu"));
    for (const arm of arms) {
      armWall[arm].push(byArm.get(arm).wall);
      armCpu[arm].push(byArm.get(arm).cpu);
      rss[arm].push(byArm.get(arm).rss);
    }
    const quietEvents = byArm.get("quiet-observed").metrics.events_persisted;
    const effectEvents = byArm.get("effect-observed").metrics.events_persisted;
    quietEventCounts.push(quietEvents);
    effectEventCounts.push(effectEvents);
    effectByteCounts.push(byArm.get("effect-observed").metrics.bytes_persisted);
    eventCounts.push(effectEvents - quietEvents);
    if (effectEvents > quietEvents && byArm.get("effect-observed").active > 0) {
      offeredRates.push((effectEvents - quietEvents) * 1e9 /
        byArm.get("effect-observed").active);
    }
  }
  points.push({
    iterations,
    command_wall_ns: Object.fromEntries(arms.map((arm) => [arm, summary(armWall[arm])])),
    aggregate_cpu_ns: Object.fromEntries(arms.map((arm) => [arm, summary(armCpu[arm])])),
    quiet_wall_overhead_ns: summary(wall.map((entry) => entry.quiet)),
    effect_wall_overhead_ns: summary(wall.map((entry) => entry.effect)),
    event_increment_wall_ns: summary(wall.map((entry) => entry.event_increment)),
    quiet_cpu_overhead_ns: summary(cpu.map((entry) => entry.quiet)),
    effect_cpu_overhead_ns: summary(cpu.map((entry) => entry.effect)),
    event_increment_cpu_ns: summary(cpu.map((entry) => entry.event_increment)),
    quiet_events_persisted: summary(quietEventCounts),
    effect_events_persisted: summary(effectEventCounts),
    effect_bytes_persisted: summary(effectByteCounts),
    incremental_events: summary(eventCounts),
    offered_events_per_second: offeredRates.length ? summary(offeredRates) : null,
    max_rss_kb: Object.fromEntries(arms.map((arm) => [arm, summary(rss[arm])])),
  });
}

const firstLoad = config.iterations[0];
const lastLoad = config.iterations[config.iterations.length - 1];
const wallSlopes = [];
const cpuSlopes = [];
for (let block = 1; block <= config.repetitions; block++) {
  const first = samples.get(block).get(firstLoad);
  const last = samples.get(block).get(lastLoad);
  const firstEvents = first.get("effect-observed").metrics.events_persisted -
    first.get("quiet-observed").metrics.events_persisted;
  const lastEvents = last.get("effect-observed").metrics.events_persisted -
    last.get("quiet-observed").metrics.events_persisted;
  const eventDelta = lastEvents - firstEvents;
  if (eventDelta <= 0) continue;
  wallSlopes.push((contrast(last, "wall").event_increment -
    contrast(first, "wall").event_increment) / eventDelta);
  cpuSlopes.push((contrast(last, "cpu").event_increment -
    contrast(first, "cpu").event_increment) / eventDelta);
}

const eventMedians = points.map((point) => point.incremental_events.median);
const countsMonotonic = eventMedians.slice(1).every((value, index) => value > eventMedians[index]);
let quietCountsInvariant = true;
for (let block = 1; block <= config.repetitions; block++) {
  const firstQuiet = samples.get(block).get(firstLoad)
    .get("quiet-observed").metrics.events_persisted;
  for (const iterations of config.iterations.slice(1)) {
    if (samples.get(block).get(iterations)
      .get("quiet-observed").metrics.events_persisted !== firstQuiet) {
      quietCountsInvariant = false;
    }
  }
}

function inference(values) {
  if (!values.length) {
    return { status: "LOW_CONFIDENCE", accepted_median: null, reason: "no positive event-count denominator" };
  }
  const estimate = median(values);
  const interval = medianInterval(values);
  const positive = values.filter((value) => value > 0).length;
  const gates = {
    at_least_12_blocks: values.length >= 12,
    at_least_80_percent_positive: positive >= Math.ceil(0.8 * values.length),
    interval_excludes_zero: interval.lower > 0,
    interval_width_at_most_estimate: interval.upper - interval.lower <= Math.abs(estimate),
    event_counts_strictly_increase: countsMonotonic,
    quiet_event_count_invariant: quietCountsInvariant,
  };
  const accepted = Object.values(gates).every(Boolean);
  return {
    status: accepted ? "USABLE_ESTIMATE" : "LOW_CONFIDENCE",
    accepted_median: accepted ? estimate : null,
    exploratory_median: estimate,
    interval_95: interval,
    positive_blocks: positive,
    gates,
  };
}

const report = {
  schema_version: 1,
  benchmark: "system-effects-overhead-v1",
  collector_identity: collectorIdentity,
  evidence_collection: "PASS",
  events_dropped: 0,
  repetitions: config.repetitions,
  load_range: { first: firstLoad, last: lastLoad },
  points,
  full_pipeline_wall_ns_per_persisted_event: inference(wallSlopes),
  aggregate_cpu_ns_per_persisted_event: inference(cpuSlopes),
  caveats: [
    "quiet and file treatments have equal syscall counts but different syscall types",
    "per-event estimates include collector drain and finalization",
    "results apply only to the tested file-effect profile and load range",
  ],
};

const wallResult = report.full_pipeline_wall_ns_per_persisted_event;
const cpuResult = report.aggregate_cpu_ns_per_persisted_event;
const markdown = [
  "# System-effects overhead result",
  "",
  `Evidence collection: **${report.evidence_collection}** (all ${config.repetitions} paired blocks complete and lossless).`,
  "",
  `Full-pipeline wall/event: **${wallResult.status}**` +
    (wallResult.accepted_median === null ? "" : `, median ${wallResult.accepted_median.toFixed(1)} ns/event`) + ".",
  `Aggregate CPU/event: **${cpuResult.status}**` +
    (cpuResult.accepted_median === null ? "" : `, median ${cpuResult.accepted_median.toFixed(1)} ns/event`) + ".",
  "",
  `Tested logical-iteration range: ${firstLoad} to ${lastLoad}. See report.json for fixed empty-hit costs, RSS, throughput, intervals, and confidence gates.`,
  "",
  "The quiet and effect profiles match syscall count, not syscall type. This is a full-pipeline file-effect estimate, not a kernel-probe-only or maximum-throughput claim.",
  "",
].join("\n");

fs.writeFileSync(reportJson, JSON.stringify(report, null, 2) + "\n");
fs.writeFileSync(reportMarkdown, markdown);
process.stdout.write(`${wallResult.status}: system-effects overhead analysis complete\n`);
