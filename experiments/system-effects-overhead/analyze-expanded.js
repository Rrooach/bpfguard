#!/usr/bin/env node
// SPDX-License-Identifier: GPL-2.0-only

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");

function fail(message) {
  throw new Error(message);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function readJsonLines(file) {
  const text = fs.readFileSync(file, "utf8").trim();
  return text ? text.split(/\n/).map((line, index) => {
    try {
      return JSON.parse(line);
    } catch (error) {
      fail(`${file}:${index + 1}: ${error.message}`);
    }
  }) : [];
}

function requireSafeInteger(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) fail(`invalid ${name}: ${value}`);
}

function gcd(left, right) {
  left = left < 0n ? -left : left;
  right = right < 0n ? -right : right;
  while (right !== 0n) [left, right] = [right, left % right];
  return left;
}

function rational(numerator, denominator) {
  numerator = BigInt(numerator);
  denominator = BigInt(denominator);
  if (denominator <= 0n) fail(`non-positive rational denominator: ${denominator}`);
  const divisor = gcd(numerator, denominator);
  return { numerator: numerator / divisor, denominator: denominator / divisor };
}

function compareRational(left, right) {
  const delta = left.numerator * right.denominator -
    right.numerator * left.denominator;
  return delta < 0n ? -1 : delta > 0n ? 1 : 0;
}

function addRational(left, right) {
  return rational(left.numerator * right.denominator +
    right.numerator * left.denominator, left.denominator * right.denominator);
}

function subtractRational(left, right) {
  return rational(left.numerator * right.denominator -
    right.numerator * left.denominator, left.denominator * right.denominator);
}

function divideRational(value, divisor) {
  return rational(value.numerator, value.denominator * BigInt(divisor));
}

function absoluteRational(value) {
  return rational(value.numerator < 0n ? -value.numerator : value.numerator,
    value.denominator);
}

function jsonRational(value) {
  return {
    numerator_ns: value.numerator.toString(),
    denominator_events: value.denominator.toString(),
    exact_fraction_ns_per_event: `${value.numerator}/${value.denominator}`,
    value_ns_per_event: Number(value.numerator) / Number(value.denominator),
  };
}

function choose(n, k) {
  let value = 1n;
  k = Math.min(k, n - k);
  for (let index = 1; index <= k; index++) {
    value = value * BigInt(n - k + index) / BigInt(index);
  }
  return value;
}

function medianRational(values) {
  if (!values.length) fail("median of empty sample");
  const ordered = [...values].sort(compareRational);
  const middle = Math.floor(ordered.length / 2);
  return ordered.length % 2
    ? ordered[middle]
    : divideRational(addRational(ordered[middle - 1], ordered[middle]), 2);
}

function exactMedianInterval(values, requestedCoverageNumerator = 95n,
  requestedCoverageDenominator = 100n) {
  if (!values.length) fail("median interval of empty sample");
  const ordered = [...values].sort(compareRational);
  const possibilities = 1n << BigInt(ordered.length);
  let tail = 0n;
  let selected = 0;
  let coverageNumerator = possibilities - 2n;
  for (let k = 1; k <= Math.floor(ordered.length / 2); k++) {
    tail += choose(ordered.length, k - 1);
    const candidate = possibilities - 2n * tail;
    if (candidate * requestedCoverageDenominator >=
        requestedCoverageNumerator * possibilities) {
      selected = k - 1;
      coverageNumerator = candidate;
    } else {
      break;
    }
  }
  const coverage = rational(coverageNumerator, possibilities);
  return {
    method: "EXACT_DISTRIBUTION_FREE_SIGN_ORDER_STATISTIC",
    requested_coverage: "95/100",
    achieved_coverage_fraction: `${coverage.numerator}/${coverage.denominator}`,
    achieved_coverage: Number(coverage.numerator) / Number(coverage.denominator),
    lower: ordered[selected],
    upper: ordered[ordered.length - selected - 1],
    order_statistic: selected + 1,
  };
}

function medianNumber(values) {
  if (!values.length) fail("numeric median of empty sample");
  const ordered = [...values].sort((left, right) => left - right);
  const middle = Math.floor(ordered.length / 2);
  return ordered.length % 2 ? ordered[middle] :
    (ordered[middle - 1] + ordered[middle]) / 2;
}

function numberSummary(values) {
  return {
    count: values.length,
    median: medianNumber(values),
    min: Math.min(...values),
    max: Math.max(...values),
  };
}

const expectedFields = [
  "wall_ns", "user_cpu_ns", "system_cpu_ns", "max_rss_kb",
  "voluntary_context_switches", "involuntary_context_switches",
  "system_effect_events", "system_effect_raw_bytes",
  "system_effect_jsonl_bytes", "system_effect_health_bytes",
  "process_lifecycle_events", "process_lifecycle_raw_bytes",
  "process_lifecycle_jsonl_bytes", "process_lifecycle_health_bytes",
  "socket_state_events", "socket_state_raw_bytes", "socket_state_jsonl_bytes",
  "socket_state_health_bytes",
];

function expectedOrder(block) {
  const rows = [
    [[0, "user-input"], [0, "expanded-lifecycle"],
      [1024, "expanded-lifecycle"], [1024, "user-input"]],
    [[1024, "user-input"], [1024, "expanded-lifecycle"],
      [0, "expanded-lifecycle"], [0, "user-input"]],
    [[0, "expanded-lifecycle"], [0, "user-input"],
      [1024, "user-input"], [1024, "expanded-lifecycle"]],
    [[1024, "expanded-lifecycle"], [1024, "user-input"],
      [0, "user-input"], [0, "expanded-lifecycle"]],
  ];
  return rows[(block - 1) % rows.length];
}

function validateRecords(records, expectedClass, expectedBlocks) {
  if (records.length !== expectedBlocks * 4) {
    fail(`${expectedClass} must contain exactly ${expectedBlocks * 4} arms`);
  }
  const blocks = new Map();
  for (const record of records) {
    if (record.schema_version !== 1 || record.class !== expectedClass ||
        !Number.isSafeInteger(record.block) || record.block < 1 ||
        record.block > expectedBlocks ||
        !Number.isSafeInteger(record.order_position) ||
        record.order_position < 1 || record.order_position > 4 ||
        ![0, 1024].includes(record.iterations) ||
        !["user-input", "expanded-lifecycle"].includes(record.mode) ||
        record.lossless !== true || record.offline_verified !== true) {
      fail(`invalid ${expectedClass} record identity`);
    }
    for (const field of expectedFields) {
      requireSafeInteger(record[field], `${expectedClass}/${record.block}/${field}`);
    }
    if (record.mode === "user-input") {
      if (record.socket_state_health !== "DISABLED" ||
          record.process_lifecycle_events !== 0 || record.socket_state_events !== 0 ||
          record.process_lifecycle_raw_bytes !== 0 ||
          record.process_lifecycle_jsonl_bytes !== 0 ||
          record.process_lifecycle_health_bytes !== 0 ||
          record.socket_state_raw_bytes !== 0 ||
          record.socket_state_jsonl_bytes !== 0 ||
          record.socket_state_health_bytes !== 0) {
        fail(`user-input arm contains expanded streams in block ${record.block}`);
      }
    } else if (record.socket_state_health !== "COMPLETE" ||
        record.process_lifecycle_events <= 0 ||
        record.process_lifecycle_health_bytes <= 0 ||
        record.socket_state_health_bytes <= 0) {
      fail(`expanded arm lacks closed lifecycle/socket health in block ${record.block}`);
    }
    const key = `${record.iterations}/${record.mode}`;
    if (!blocks.has(record.block)) blocks.set(record.block, new Map());
    if (blocks.get(record.block).has(key)) {
      fail(`duplicate ${expectedClass} arm ${record.block}/${key}`);
    }
    blocks.get(record.block).set(key, record);
  }
  for (let block = 1; block <= expectedBlocks; block++) {
    const byArm = blocks.get(block);
    if (!byArm || byArm.size !== 4) fail(`incomplete ${expectedClass} block ${block}`);
    for (const [index, [iterations, mode]] of expectedOrder(block).entries()) {
      const record = byArm.get(`${iterations}/${mode}`);
      if (!record || record.order_position !== index + 1) {
        fail(`counterbalance mismatch in ${expectedClass} block ${block}`);
      }
    }
  }
  return blocks;
}

function arm(block, iterations, mode) {
  return block.get(`${iterations}/${mode}`);
}

function metric(record, name) {
  if (name === "aggregate_cpu_ns") return record.user_cpu_ns + record.system_cpu_ns;
  return record[name];
}

function inference(blockPoints, metricName, commonGates) {
  if (blockPoints.some((point) => point.primary_system_event_delta <= 0)) {
    return {
      status: "EXPLORATORY_INVALID_DENOMINATOR",
      accepted_median: null,
      exploratory_median: null,
      exact_median_interval_95: null,
      positive_blocks: null,
      total_blocks: blockPoints.length,
      gates: {
        ...commonGates,
        at_least_80_percent_positive: false,
        interval_excludes_zero: false,
        interval_width_at_most_absolute_median: false,
      },
    };
  }
  const estimates = blockPoints.map((point) =>
    rational(point.contrasts[metricName], point.primary_system_event_delta));
  const estimate = medianRational(estimates);
  const interval = exactMedianInterval(estimates);
  const positiveBlocks = estimates.filter((value) => value.numerator > 0n).length;
  const intervalWidth = subtractRational(interval.upper, interval.lower);
  const gates = {
    ...commonGates,
    at_least_80_percent_positive:
      positiveBlocks >= Math.ceil(0.8 * estimates.length),
    interval_excludes_zero: interval.lower.numerator > 0n,
    interval_width_at_most_absolute_median:
      compareRational(intervalWidth, absoluteRational(estimate)) <= 0,
  };
  const accepted = Object.values(gates).every(Boolean);
  return {
    status: accepted ? "USABLE_ESTIMATE" : "EXPLORATORY_LOW_CONFIDENCE",
    accepted_median: accepted ? jsonRational(estimate) : null,
    exploratory_median: jsonRational(estimate),
    exact_median_interval_95: {
      method: interval.method,
      requested_coverage: interval.requested_coverage,
      achieved_coverage_fraction: interval.achieved_coverage_fraction,
      achieved_coverage: interval.achieved_coverage,
      lower: jsonRational(interval.lower),
      upper: jsonRational(interval.upper),
      order_statistic: interval.order_statistic,
    },
    positive_blocks: positiveBlocks,
    total_blocks: estimates.length,
    gates,
  };
}

function analyze(root) {
  const design = readJson(path.join(root, "design.json"));
  const collection = readJson(path.join(root, "collection-status.json"));
  if (design.schema_version !== 1 ||
      design.benchmark !== "expanded-system-effects-overhead-v1" ||
      design.warmup_blocks !== 4 || design.measured_blocks !== 12 ||
      JSON.stringify(design.loads) !== "[0,1024]" ||
      typeof design.recorder_object_sha256 !== "string" ||
      !/^[0-9a-f]{64}$/.test(design.recorder_object_sha256) ||
      typeof design.process_lifecycle_object_sha256 !== "string" ||
      !/^[0-9a-f]{64}$/.test(design.process_lifecycle_object_sha256) ||
      design.primary_system_event_delta !==
        "expanded-lifecycle@1024-expanded-lifecycle@0" ||
      collection.schema_version !== 1 || collection.collection_status !== "PASS" ||
      collection.inference_status !== "PENDING_HOST_ANALYZER" ||
      collection.warmup_blocks !== 4 || collection.measured_blocks !== 12 ||
      collection.arms_per_block !== 4) {
    fail("unsupported expanded-overhead design or incomplete collection marker");
  }
  validateRecords(readJsonLines(path.join(root, "warmup-summary.jsonl")),
    "warmup", 4);
  const blocks = validateRecords(readJsonLines(path.join(root, "summary.jsonl")),
    "measured", 12);

  const blockPoints = [];
  for (let blockNumber = 1; blockNumber <= 12; blockNumber++) {
    const byArm = blocks.get(blockNumber);
    const user0 = arm(byArm, 0, "user-input");
    const user1024 = arm(byArm, 1024, "user-input");
    const expanded0 = arm(byArm, 0, "expanded-lifecycle");
    const expanded1024 = arm(byArm, 1024, "expanded-lifecycle");
    const primaryDelta = expanded1024.system_effect_events -
      expanded0.system_effect_events;
    const userDelta = user1024.system_effect_events - user0.system_effect_events;
    const contrasts = {};
    for (const name of ["wall_ns", "aggregate_cpu_ns"]) {
      contrasts[name] = (metric(expanded1024, name) - metric(user1024, name)) -
        (metric(expanded0, name) - metric(user0, name));
    }
    blockPoints.push({
      block: blockNumber,
      primary_system_event_delta: primaryDelta,
      user_input_system_event_delta: userDelta,
      mode_system_event_deltas_equal: primaryDelta === userDelta,
      expanded_lifecycle_event_delta:
        expanded1024.process_lifecycle_events - expanded0.process_lifecycle_events,
      expanded_socket_state_event_delta:
        expanded1024.socket_state_events - expanded0.socket_state_events,
      contrasts,
      wall_ns_per_system_event: primaryDelta > 0 ?
        jsonRational(rational(contrasts.wall_ns, primaryDelta)) : null,
      aggregate_cpu_ns_per_system_event: primaryDelta > 0 ?
        jsonRational(rational(contrasts.aggregate_cpu_ns, primaryDelta)) : null,
    });
  }

  const commonGates = {
    collection_complete_lossless_offline_verified: true,
    at_least_12_complete_blocks: blockPoints.length >= 12,
    four_row_load_and_mode_order_balanced: true,
    primary_system_event_delta_positive:
      blockPoints.every((point) => point.primary_system_event_delta > 0),
    user_system_event_delta_positive:
      blockPoints.every((point) => point.user_input_system_event_delta > 0),
    user_and_expanded_system_event_deltas_equal:
      blockPoints.every((point) => point.mode_system_event_deltas_equal),
  };
  const records = [...blocks.values()].flatMap((byArm) => [...byArm.values()]);
  const armSummaries = {};
  for (const iterations of [0, 1024]) {
    for (const mode of ["user-input", "expanded-lifecycle"]) {
      const selected = records.filter((record) =>
        record.iterations === iterations && record.mode === mode);
      const key = `${mode}@${iterations}`;
      armSummaries[key] = {};
      for (const field of ["wall_ns", "user_cpu_ns", "system_cpu_ns",
        "max_rss_kb", "voluntary_context_switches",
        "involuntary_context_switches", "system_effect_events",
        "process_lifecycle_events", "socket_state_events",
        "system_effect_raw_bytes", "system_effect_jsonl_bytes",
        "system_effect_health_bytes", "process_lifecycle_raw_bytes",
        "process_lifecycle_jsonl_bytes", "process_lifecycle_health_bytes",
        "socket_state_raw_bytes", "socket_state_jsonl_bytes",
        "socket_state_health_bytes"]) {
        armSummaries[key][field] = numberSummary(selected.map((entry) => entry[field]));
      }
    }
  }

  return {
    schema_version: 1,
    benchmark: design.benchmark,
    recorder_object_sha256: design.recorder_object_sha256,
    process_lifecycle_object_sha256: design.process_lifecycle_object_sha256,
    evidence_collection: "PASS",
    inference_scope: "EXPLORATORY_SINGLE_DISPOSABLE_VM_BATCH",
    warmup_blocks_excluded: 4,
    measured_blocks: 12,
    primary_denominator:
      "expanded-lifecycle persisted system-effect events at N=1024 minus N=0",
    contrast:
      "[(expanded-lifecycle - user-input) at N=1024] - [(expanded-lifecycle - user-input) at N=0]",
    block_estimates: blockPoints,
    full_pipeline_wall_ns_per_system_event:
      inference(blockPoints, "wall_ns", commonGates),
    aggregate_cpu_ns_per_system_event:
      inference(blockPoints, "aggregate_cpu_ns", commonGates),
    arm_summaries: armSummaries,
    caveats: [
      "This is one exploratory batch in one disposable VM, not a production-wide overhead bound.",
      "The primary denominator is the expanded mode system-effect stream; lifecycle and socket-state deltas are reported separately.",
      "Collector startup, drain, canonical JSONL projection, health finalization, and offline-verifiable persistence are included.",
      "A low-confidence result is retained without outlier deletion or relabeling as an accepted estimate.",
    ],
  };
}

function selfTest() {
  const values = Array.from({ length: 12 }, (_, index) => rational(index + 1, 1));
  const interval = exactMedianInterval(values);
  if (interval.order_statistic !== 3 ||
      interval.lower.numerator !== 3n || interval.upper.numerator !== 10n ||
      interval.achieved_coverage_fraction !== "1969/2048" ||
      medianRational(values).numerator !== 13n ||
      medianRational(values).denominator !== 2n) {
    fail("exact median interval self-test failed");
  }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "analyze-expanded-test."));
  try {
    fs.writeFileSync(path.join(root, "design.json"), JSON.stringify({
      schema_version: 1,
      benchmark: "expanded-system-effects-overhead-v1",
      recorder_object_sha256: "a".repeat(64),
      process_lifecycle_object_sha256: "b".repeat(64),
      warmup_blocks: 4,
      measured_blocks: 12,
      loads: [0, 1024],
      modes: ["user-input", "expanded-lifecycle"],
      primary_system_event_delta:
        "expanded-lifecycle@1024-expanded-lifecycle@0",
    }));
    fs.writeFileSync(path.join(root, "collection-status.json"), JSON.stringify({
      schema_version: 1,
      collection_status: "PASS",
      inference_status: "PENDING_HOST_ANALYZER",
      warmup_blocks: 4,
      measured_blocks: 12,
      arms_per_block: 4,
    }));
    for (const [file, sampleClass, blockCount] of [
      ["warmup-summary.jsonl", "warmup", 4],
      ["summary.jsonl", "measured", 12],
    ]) {
      const records = [];
      for (let block = 1; block <= blockCount; block++) {
        for (const [index, [iterations, mode]] of expectedOrder(block).entries()) {
          const expanded = mode === "expanded-lifecycle";
          const baseWall = 1000000 + iterations * 1000 + block * 100;
          const baseCpu = 500000 + iterations * 500 + block * 50;
          const incremental = iterations === 0 ? 0 : iterations * block;
          records.push({
            schema_version: 1,
            class: sampleClass,
            block,
            order_position: index + 1,
            iterations,
            mode,
            wall_ns: baseWall + (expanded ? 10000 + iterations * 80 + incremental : 0),
            user_cpu_ns: baseCpu + (expanded ? 5000 + iterations * 40 + incremental : 0),
            system_cpu_ns: baseCpu,
            max_rss_kb: 1000 + (expanded ? 100 : 0),
            voluntary_context_switches: 10,
            involuntary_context_switches: 1,
            system_effect_events: 100 + iterations,
            system_effect_raw_bytes: 1000 + iterations,
            system_effect_jsonl_bytes: 2000 + iterations,
            system_effect_health_bytes: 100,
            process_lifecycle_events: expanded ? 3 : 0,
            process_lifecycle_raw_bytes: expanded ? 300 : 0,
            process_lifecycle_jsonl_bytes: expanded ? 600 : 0,
            process_lifecycle_health_bytes: expanded ? 100 : 0,
            socket_state_events: 0,
            socket_state_raw_bytes: 0,
            socket_state_jsonl_bytes: 0,
            socket_state_health_bytes: expanded ? 100 : 0,
            socket_state_health: expanded ? "COMPLETE" : "DISABLED",
            lossless: true,
            offline_verified: true,
          });
        }
      }
      fs.writeFileSync(path.join(root, file),
        `${records.map((record) => JSON.stringify(record)).join("\n")}\n`);
    }
    const report = analyze(root);
    if (report.block_estimates.length !== 12 ||
        report.full_pipeline_wall_ns_per_system_event.status !==
          "USABLE_ESTIMATE" ||
        report.aggregate_cpu_ns_per_system_event.status !==
          "USABLE_ESTIMATE" ||
        report.full_pipeline_wall_ns_per_system_event
          .exact_median_interval_95.achieved_coverage_fraction !== "1969/2048") {
      fail("complete synthetic batch self-test failed");
    }
  } finally {
    fs.rmSync(root, { recursive: true });
  }
  process.stdout.write("analyze-expanded self-test PASS\n");
}

function formatEstimate(result) {
  return result.exploratory_median === null ? "not computable" :
    `${result.exploratory_median.value_ns_per_event.toFixed(1)} ns/event`;
}

function formatInterval(result) {
  if (result.exact_median_interval_95 === null) return "not computable";
  const interval = result.exact_median_interval_95;
  return `${interval.achieved_coverage_fraction} coverage: ` +
    `[${interval.lower.value_ns_per_event.toFixed(1)}, ` +
    `${interval.upper.value_ns_per_event.toFixed(1)}] ns/event`;
}

function main() {
  if (process.argv.length === 3 && process.argv[2] === "--self-test") {
    selfTest();
    return;
  }
  if (process.argv.length !== 5) {
    process.stderr.write("usage: analyze-expanded.js RESULTS_ROOT REPORT_JSON REPORT_MD\n");
    process.exit(2);
  }
  const [root, reportJson, reportMarkdown] = process.argv.slice(2);
  if (!path.isAbsolute(root) || !path.isAbsolute(reportJson) ||
      !path.isAbsolute(reportMarkdown) || fs.existsSync(reportJson) ||
      fs.existsSync(reportMarkdown)) {
    fail("paths must be absolute and report outputs must be new");
  }
  const report = analyze(root);
  const wall = report.full_pipeline_wall_ns_per_system_event;
  const cpu = report.aggregate_cpu_ns_per_system_event;
  const markdown = [
    "# Expanded system-effects overhead result",
    "",
    `Collection: **${report.evidence_collection}**; inference scope: **${report.inference_scope}**.`,
    "",
    `Wall/event: **${wall.status}**, exploratory median ${formatEstimate(wall)}.`,
    `Aggregate CPU/event: **${cpu.status}**, exploratory median ${formatEstimate(cpu)}.`,
    `Exact wall median interval: ${formatInterval(wall)}.`,
    `Exact CPU median interval: ${formatInterval(cpu)}.`,
    "",
    "The report retains every block, exact rational estimates, all gates, per-stream event/byte counts, RSS, and context switches. A collection PASS is not itself an accepted overhead estimate.",
    "",
  ].join("\n");
  fs.writeFileSync(reportJson, `${JSON.stringify(report, null, 2)}\n`,
    { encoding: "utf8", mode: 0o600, flag: "wx" });
  fs.writeFileSync(reportMarkdown, markdown,
    { encoding: "utf8", mode: 0o600, flag: "wx" });
}

main();
