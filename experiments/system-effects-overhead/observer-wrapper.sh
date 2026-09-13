#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

# Adapter from the generic paired-benchmark contract to `observe-effects`.
# The complete batch should run as root so direct and observed treatments use
# the same privilege level.

set -euo pipefail
umask 0077

RESULT_DIR=
WORKLOAD_STDOUT=
WORKLOAD_STDERR=

usage()
{
	echo "usage: $0 --result-dir DIR --workload-stdout FILE --workload-stderr FILE -- COMMAND ARG..." >&2
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--result-dir) RESULT_DIR="$2"; shift 2 ;;
	--workload-stdout) WORKLOAD_STDOUT="$2"; shift 2 ;;
	--workload-stderr) WORKLOAD_STDERR="$2"; shift 2 ;;
	--) shift; break ;;
	-h|--help) usage; exit 0 ;;
	*) usage; exit 2 ;;
	esac
done

[[ -n "$RESULT_DIR" && -n "$WORKLOAD_STDOUT" && -n "$WORKLOAD_STDERR" && $# -gt 0 ]] || {
	usage
	exit 2
}

readonly BIN="${BPF_STATE_OBSERVER_BIN:-}"
readonly OBJECT="${BPF_STATE_OBSERVER_EFFECTS_OBJECT:-}"
readonly EXPECTED_SHA256="${BPF_STATE_OBSERVER_EFFECTS_SHA256:-}"
readonly PROFILE="${BPF_STATE_OBSERVER_EFFECTS_PROFILE:-balanced}"
readonly OBJECT_RESOLUTION="${BPF_STATE_OBSERVER_EFFECTS_OBJECT_RESOLUTION:-user-input}"
readonly CGROUP_ROOT="${BPF_STATE_OBSERVER_EFFECTS_CGROUP_ROOT:-/sys/fs/cgroup/bpf-state-observer-effects}"
readonly TIMEOUT_MS="${BPF_STATE_OBSERVER_EFFECTS_TIMEOUT_MS:-30000}"
readonly DRAIN_TIMEOUT_MS="${BPF_STATE_OBSERVER_EFFECTS_DRAIN_TIMEOUT_MS:-5000}"

[[ "$BIN" == /* && -f "$BIN" && ! -L "$BIN" && -x "$BIN" ]] || {
	echo "BPF_STATE_OBSERVER_BIN must name an absolute executable regular file" >&2
	exit 2
}
[[ "$OBJECT" == /* && -f "$OBJECT" && ! -L "$OBJECT" ]] || {
	echo "BPF_STATE_OBSERVER_EFFECTS_OBJECT must name an absolute regular file" >&2
	exit 2
}
[[ "$EXPECTED_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
	echo "BPF_STATE_OBSERVER_EFFECTS_SHA256 must be a canonical SHA-256" >&2
	exit 2
}
[[ "$PROFILE" == control || "$PROFILE" == balanced || "$PROFILE" == full ]] || {
	echo "BPF_STATE_OBSERVER_EFFECTS_PROFILE must be control, balanced, or full" >&2
	exit 2
}
[[ "$OBJECT_RESOLUTION" == user-input ||
	"$OBJECT_RESOLUTION" == kernel-file-open-partial ||
	"$OBJECT_RESOLUTION" == kernel-file-open-write-partial ]] || {
	echo "BPF_STATE_OBSERVER_EFFECTS_OBJECT_RESOLUTION must be user-input, kernel-file-open-partial, or kernel-file-open-write-partial" >&2
	exit 2
}

readonly BIN_SHA256="$(sha256sum "$BIN" | awk '{print $1}')"
readonly OBJECT_SHA256="$(sha256sum "$OBJECT" | awk '{print $1}')"
[[ "$OBJECT_SHA256" == "$EXPECTED_SHA256" ]] || {
	echo "system-effect object does not match the trusted SHA-256" >&2
	exit 2
}
[[ "$CGROUP_ROOT" == /* && "$TIMEOUT_MS" =~ ^[1-9][0-9]*$ &&
	"$DRAIN_TIMEOUT_MS" =~ ^[1-9][0-9]*$ ]] || {
	echo "invalid cgroup root or timeout configuration" >&2
	exit 2
}
[[ "$RESULT_DIR" == /* && ! -e "$RESULT_DIR" && ! -L "$RESULT_DIR" ]] || {
	echo "result directory must be a new absolute path" >&2
	exit 2
}
for output in "$WORKLOAD_STDOUT" "$WORKLOAD_STDERR"; do
	[[ "$output" == /* && ! -e "$output" && ! -L "$output" && -d "$(dirname "$output")" ]] || {
		echo "workload output must be a new absolute path below an existing directory: $output" >&2
		exit 2
	}
done

mkdir -m 0700 "$RESULT_DIR"
readonly EVIDENCE_DIR="$RESULT_DIR/evidence"
readonly OBSERVER_STDOUT="$RESULT_DIR/observer.stdout"
readonly OBSERVER_STDERR="$RESULT_DIR/observer.stderr"

set +e
"$BIN" observe-effects \
	--recorder-object "$OBJECT" \
	--expected-recorder-sha256 "$EXPECTED_SHA256" \
	--output-dir "$EVIDENCE_DIR" \
	--cgroup-root "$CGROUP_ROOT" \
	--profile "$PROFILE" \
	--object-resolution "$OBJECT_RESOLUTION" \
	--timeout-ms "$TIMEOUT_MS" \
	--drain-timeout-ms "$DRAIN_TIMEOUT_MS" \
	-- "$@" > "$OBSERVER_STDOUT" 2> "$OBSERVER_STDERR"
observer_status=$?
set -e

if (( observer_status != 0 )); then
	echo "observe-effects failed; see $OBSERVER_STDERR" >&2
	exit "$observer_status"
fi
[[ "$(sha256sum "$BIN" | awk '{print $1}')" == "$BIN_SHA256" &&
	"$(sha256sum "$OBJECT" | awk '{print $1}')" == "$OBJECT_SHA256" ]] || {
	echo "Observer binary or recorder object changed during collection" >&2
	exit 1
}

cp -- "$EVIDENCE_DIR/workload.stdout" "$WORKLOAD_STDOUT"
cp -- "$EVIDENCE_DIR/workload.stderr" "$WORKLOAD_STDERR"

readonly METRICS="$RESULT_DIR/metrics.json"
status_fields=$(node -e '
const fs = require("fs");
const path = require("path");
const evidence = process.argv[1];
const metricsPath = process.argv[2];
const binaryDigest = process.argv[3];
const expectedObjectDigest = process.argv[4];
const expectedProfile = process.argv[5];
const expectedResolution = process.argv[6];
const health = JSON.parse(fs.readFileSync(path.join(evidence, "system-effects.health.json"), "utf8"));
const manifest = JSON.parse(fs.readFileSync(path.join(evidence, "system-effects.manifest.json"), "utf8"));
const policy = JSON.parse(fs.readFileSync(path.join(evidence, "system-effects.policy.json"), "utf8"));
function fail(message) { throw new Error(message); }
function counter(name, value) {
  if (!Number.isSafeInteger(value) || value < 0) fail(`invalid ${name}`);
  return value;
}
const resolutionWire = expectedResolution === "user-input"
  ? "USER_INPUT"
  : (expectedResolution === "kernel-file-open-partial"
      ? "KERNEL_FILE_OPEN_PARTIAL"
      : (expectedResolution === "kernel-file-open-write-partial"
          ? "KERNEL_FILE_OPEN_WRITE_PARTIAL" : null));
const attribution = manifest.attribution_contract;
if (resolutionWire === null || !attribution || Object.keys(attribution).length !== 8 ||
    attribution.protocol_version !== 1 ||
    attribution.direct_claim !== "SELECTED_NATIVE_SYSCALL_CALLER_IN_EXACT_CGROUP_AT_ENTRY" ||
    attribution.mode !== "DIRECT" ||
    attribution.authority !== "KERNEL_CURRENT_CGROUP_ID_AT_SYSCALL_ENTRY" ||
    attribution.subject !== "RUN_EXECUTION_DOMAIN" ||
    attribution.component !== "UNCLASSIFIED_CGROUP_MEMBER" ||
    attribution.delegated_effects !== "NOT_OBSERVED" ||
    attribution.causal_status !== "CAUSAL_NOT_ESTABLISHED") {
  fail("observer attribution contract is absent or unsupported");
}
if (manifest.run_status !== "FINALIZED" || manifest.transport_status !== "COMPLETE" ||
    health.transport_status !== "COMPLETE" ||
    health.coverage_status !== "PARTIAL" || health.object_resolution_status !== "PARTIAL" ||
    !health.producer_barrier_complete || !health.drain_completed || !health.wal_durable ||
    manifest.operation_events_are_state_diff !== undefined ||
    manifest.coverage.operation_events_are_state_diff !== false ||
    manifest.expected_recorder_object_sha256 !== expectedObjectDigest ||
    manifest.loaded_recorder_object_sha256 !== expectedObjectDigest ||
    manifest.policy_profile !== expectedProfile ||
    manifest.object_resolution_mode !== resolutionWire ||
    health.profile !== expectedProfile || policy.profile !== expectedProfile ||
    health.object_resolution_mode !== resolutionWire ||
    policy.policy_sha256 !== manifest.policy_sha256 ||
    health.run_id !== manifest.run_id || health.run_epoch !== manifest.run_epoch) {
  fail("observer evidence is incomplete or internally inconsistent");
}
const persisted = counter("events_persisted", health.events_persisted);
const dropped = counter("event_dropped", health.event_dropped);
counter("event_published", health.event_published);
if (dropped !== 0 || persisted !== health.event_published ||
    health.pending_remaining !== 0 || health.userspace_failures !== 0 ||
    health.fatal_kernel_flags !== 0) {
  fail("observer evidence is lossy or unhealthy");
}
const bytes = counter("bytes_persisted",
  fs.statSync(path.join(evidence, "system-effects.raw.bin")).size +
  fs.statSync(path.join(evidence, "system-effects.jsonl")).size);
const metrics = {
  schema_version: 1,
  collector_identity: `observer=${binaryDigest};object=${expectedObjectDigest};policy=${policy.policy_sha256};profile=${expectedProfile};resolution=${expectedResolution}`,
  evidence_status: "complete",
  events_persisted: persisted,
  events_dropped: dropped,
  bytes_persisted: bytes,
};
const exitCode = manifest.workload_exit_code;
const signal = manifest.workload_signal;
if (!((Number.isInteger(exitCode) && exitCode >= 0 && exitCode <= 255 && signal === null) ||
      (exitCode === null && Number.isInteger(signal) && signal > 0 && signal < 128))) {
  fail("invalid workload termination in manifest");
}
fs.writeFileSync(metricsPath, JSON.stringify(metrics) + "\n", {flag: "wx", mode: 0o600});
process.stdout.write(`${exitCode === null ? "null" : exitCode} ${signal === null ? "null" : signal}`);
' "$EVIDENCE_DIR" "$METRICS" "$BIN_SHA256" \
	"$EXPECTED_SHA256" "$PROFILE" "$OBJECT_RESOLUTION")

read -r workload_exit workload_signal <<< "$status_fields"
if [[ "$workload_signal" != null ]]; then
	exit $((128 + workload_signal))
fi
exit "$workload_exit"
