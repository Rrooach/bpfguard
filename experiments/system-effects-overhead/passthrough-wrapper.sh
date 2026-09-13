#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail
umask 0077

RESULT_DIR=
WORKLOAD_STDOUT=
WORKLOAD_STDERR=
while [[ $# -gt 0 ]]; do
	case "$1" in
	--result-dir)
		RESULT_DIR="$2"
		shift 2
		;;
	--workload-stdout)
		WORKLOAD_STDOUT="$2"
		shift 2
		;;
	--workload-stderr)
		WORKLOAD_STDERR="$2"
		shift 2
		;;
	--)
		shift
		break
		;;
	*)
		echo "unknown argument: $1" >&2
		exit 2
		;;
	esac
done

[[ -n "$RESULT_DIR" && -n "$WORKLOAD_STDOUT" && -n "$WORKLOAD_STDERR" && $# -gt 0 ]] || {
	echo "invalid passthrough wrapper invocation" >&2
	exit 2
}
mkdir -m 0700 "$RESULT_DIR"
set +e
"$@" > "$WORKLOAD_STDOUT" 2> "$WORKLOAD_STDERR"
status=$?
set -e
printf '%s\n' '{"schema_version":1,"collector_identity":"passthrough-wiring-fixture-v1","evidence_status":"complete","events_persisted":0,"events_dropped":0,"bytes_persisted":0}' > "$RESULT_DIR/metrics.json"
exit "$status"
