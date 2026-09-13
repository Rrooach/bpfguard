#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

readonly HERE="$(cd "$(dirname "$0")" && pwd)"
readonly TEMP_ROOT="$(mktemp -d)"
cleanup()
{
	rm -f "$TEMP_ROOT/workload" "$TEMP_ROOT/measure" "$TEMP_ROOT/measurement.json" \
		"$TEMP_ROOT/wrapper-measurement.json" "$TEMP_ROOT/wrapped.json" \
		"$TEMP_ROOT/wrapped.stderr" "$TEMP_ROOT/wrapper.stdout" \
		"$TEMP_ROOT/wrapper.stderr" "$TEMP_ROOT/observer/metrics.json" \
		"$TEMP_ROOT/quiet.json" "$TEMP_ROOT/file.json" "$TEMP_ROOT/quiet.stderr" \
		"$TEMP_ROOT/file.stderr"
	rm -f "$TEMP_ROOT/effects-wrapper.stdout" "$TEMP_ROOT/effects-wrapper.stderr" \
		"$TEMP_ROOT/effects-workload.json" "$TEMP_ROOT/effects-workload.stderr" \
		"$TEMP_ROOT/effects-observer/metrics.json" \
		"$TEMP_ROOT/effects-observer/observer.stdout" \
		"$TEMP_ROOT/effects-observer/observer.stderr" \
		"$TEMP_ROOT/effects-observer/evidence/system-effects.manifest.json" \
		"$TEMP_ROOT/effects-observer/evidence/system-effects.policy.json" \
		"$TEMP_ROOT/effects-observer/evidence/system-effects.health.json" \
		"$TEMP_ROOT/effects-observer/evidence/system-effects.raw.bin" \
		"$TEMP_ROOT/effects-observer/evidence/system-effects.jsonl" \
		"$TEMP_ROOT/effects-observer/evidence/workload.stdout" \
		"$TEMP_ROOT/effects-observer/evidence/workload.stderr"
	rmdir "$TEMP_ROOT/effects-observer/evidence" 2>/dev/null || true
	rmdir "$TEMP_ROOT/effects-observer" 2>/dev/null || true
	rmdir "$TEMP_ROOT/observer" 2>/dev/null || true
	rmdir "$TEMP_ROOT/scratch" 2>/dev/null || true
	rmdir "$TEMP_ROOT" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

cc -O2 -std=c11 -Wall -Wextra -Werror "$HERE/system-effects-workload.c" \
	-o "$TEMP_ROOT/workload"
cc -O2 -std=c11 -Wall -Wextra -Werror "$HERE/measure-command.c" \
	-o "$TEMP_ROOT/measure"
bash -n "$HERE/run.sh"
bash -n "$HERE/passthrough-wrapper.sh"
bash -n "$HERE/observer-wrapper.sh"
bash -n "$HERE/mock-observer-fixture.sh"
node --check "$HERE/analyze.js"
mkdir -m 0700 "$TEMP_ROOT/scratch"
"$TEMP_ROOT/workload" --profile quiet --iterations 4 \
	--scratch-dir "$TEMP_ROOT/scratch" --batch-size 2 --pause-us 1 \
	> "$TEMP_ROOT/quiet.json" 2> "$TEMP_ROOT/quiet.stderr"
"$TEMP_ROOT/measure" "$TEMP_ROOT/measurement.json" -- \
	"$TEMP_ROOT/workload" --profile file --iterations 4 \
	--scratch-dir "$TEMP_ROOT/scratch" --batch-size 2 --pause-us 1 \
	> "$TEMP_ROOT/file.json" 2> "$TEMP_ROOT/file.stderr"
grep -Fq '"profile":"quiet"' "$TEMP_ROOT/quiet.json"
grep -Fq '"profile":"file"' "$TEMP_ROOT/file.json"
grep -Fq '"exit_code":0' "$TEMP_ROOT/measurement.json"
"$TEMP_ROOT/measure" "$TEMP_ROOT/wrapper-measurement.json" -- \
	"$HERE/passthrough-wrapper.sh" --result-dir "$TEMP_ROOT/observer" \
	--workload-stdout "$TEMP_ROOT/wrapped.json" \
	--workload-stderr "$TEMP_ROOT/wrapped.stderr" -- \
	"$TEMP_ROOT/workload" --profile quiet --iterations 1 \
	--scratch-dir "$TEMP_ROOT/scratch" \
	> "$TEMP_ROOT/wrapper.stdout" 2> "$TEMP_ROOT/wrapper.stderr"
grep -Fq '"collector_identity":"passthrough-wiring-fixture-v1"' \
	"$TEMP_ROOT/observer/metrics.json"
grep -Fq '"profile":"quiet"' "$TEMP_ROOT/wrapped.json"
grep -Fq '"exit_code":0' "$TEMP_ROOT/wrapper-measurement.json"
env \
	BPF_STATE_OBSERVER_BIN="$HERE/mock-observer-fixture.sh" \
	BPF_STATE_OBSERVER_EFFECTS_OBJECT="$TEMP_ROOT/workload" \
	BPF_STATE_OBSERVER_EFFECTS_SHA256="$(sha256sum "$TEMP_ROOT/workload" | awk '{print $1}')" \
	BPF_STATE_OBSERVER_EFFECTS_PROFILE=balanced \
	BPF_STATE_OBSERVER_EFFECTS_OBJECT_RESOLUTION=kernel-file-open-write-partial \
	"$HERE/observer-wrapper.sh" \
	--result-dir "$TEMP_ROOT/effects-observer" \
	--workload-stdout "$TEMP_ROOT/effects-workload.json" \
	--workload-stderr "$TEMP_ROOT/effects-workload.stderr" -- \
	"$TEMP_ROOT/workload" --profile quiet --iterations 1 \
	--scratch-dir "$TEMP_ROOT/scratch" \
	> "$TEMP_ROOT/effects-wrapper.stdout" 2> "$TEMP_ROOT/effects-wrapper.stderr"
grep -Fq '"evidence_status":"complete"' \
	"$TEMP_ROOT/effects-observer/metrics.json"
grep -Fq '"events_persisted":2' "$TEMP_ROOT/effects-observer/metrics.json"
grep -Fq 'resolution=kernel-file-open-write-partial' \
	"$TEMP_ROOT/effects-observer/metrics.json"
grep -Fq '"profile":"quiet"' "$TEMP_ROOT/effects-workload.json"
[[ -z "$(find "$TEMP_ROOT/scratch" -mindepth 1 -print -quit)" ]]
echo "system-effects overhead helper checks PASS"
