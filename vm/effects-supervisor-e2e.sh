#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

# Exercise the production Allox effects-supervisor protocol against a real
# cgroup v2 leaf.  This is a VM acceptance driver: it deliberately keeps
# workload ownership outside the Observer and verifies both response MACs.

set -euo pipefail

usage()
{
	cat >&2 <<'EOF'
usage: effects-supervisor-e2e.sh OBSERVER BPF_OBJECT EXPECTED_SHA256 EVIDENCE_DIR CGROUP_PATH WORKLOAD WORKLOAD_ARGUMENT

EVIDENCE_DIR and CGROUP_PATH must not already exist. The workload is expected
to exit successfully and to leave its cgroup empty.
EOF
	exit 2
}

[[ $# -eq 7 ]] || usage
[[ ${EUID} -eq 0 ]] || { echo "this acceptance test requires root" >&2; exit 2; }

observer=$1
bpf_object=$2
expected_sha256=$3
evidence_directory=$4
cgroup_path=$5
workload=$6
workload_argument=$7
profile=balanced

[[ ${observer} == /* && -x ${observer} ]] || { echo "OBSERVER must be an executable absolute path" >&2; exit 2; }
[[ ${bpf_object} == /* && -f ${bpf_object} ]] || { echo "BPF_OBJECT must be an absolute regular-file path" >&2; exit 2; }
[[ ${workload} == /* && -x ${workload} ]] || { echo "WORKLOAD must be an executable absolute path" >&2; exit 2; }
[[ ${expected_sha256} =~ ^[0-9a-f]{64}$ ]] || { echo "EXPECTED_SHA256 must be lowercase hex" >&2; exit 2; }
[[ ${evidence_directory} =~ ^/[A-Za-z0-9_./-]+$ ]] || { echo "unsafe EVIDENCE_DIR" >&2; exit 2; }
[[ ${cgroup_path} =~ ^/sys/fs/cgroup/[A-Za-z0-9_./-]+$ ]] || { echo "unsafe CGROUP_PATH" >&2; exit 2; }
[[ ! -e ${evidence_directory} ]] || { echo "EVIDENCE_DIR already exists" >&2; exit 2; }
[[ ! -e ${cgroup_path} ]] || { echo "CGROUP_PATH already exists" >&2; exit 2; }
[[ -d $(dirname "${cgroup_path}") ]] || { echo "CGROUP_PATH parent does not exist" >&2; exit 2; }

actual_sha256=$(sha256sum "${bpf_object}")
actual_sha256=${actual_sha256%% *}
[[ ${actual_sha256} == "${expected_sha256}" ]] || { echo "BPF object digest mismatch" >&2; exit 2; }

stderr_path=${evidence_directory}.supervisor.stderr
[[ ! -e ${stderr_path} ]] || { echo "supervisor stderr path already exists" >&2; exit 2; }

cgroup_created=0
supervisor_pid=
cleanup()
{
	if [[ -n ${supervisor_pid} ]] && kill -0 "${supervisor_pid}" 2>/dev/null; then
		kill "${supervisor_pid}" 2>/dev/null || true
		wait "${supervisor_pid}" 2>/dev/null || true
	fi
	if [[ ${cgroup_created} -eq 1 && -d ${cgroup_path} ]]; then
		if [[ -f ${cgroup_path}/cgroup.kill ]]; then
			echo 1 > "${cgroup_path}/cgroup.kill" 2>/dev/null || true
		fi
		echo 0 > "${cgroup_path}/cgroup.freeze" 2>/dev/null || true
		rmdir "${cgroup_path}" 2>/dev/null || true
	fi
}
trap cleanup EXIT

mkdir "${cgroup_path}"
cgroup_created=1
echo 0 > "${cgroup_path}/cgroup.max.depth"
echo 0 > "${cgroup_path}/cgroup.max.descendants"
mkdir -m 0700 "${evidence_directory}"

cgroup_id=$(stat -c %i "${cgroup_path}")
[[ ${cgroup_id} =~ ^[1-9][0-9]*$ ]] || { echo "invalid cgroup ID" >&2; exit 1; }
printf -v run_id '%032x' "${cgroup_id}"
auth_challenge=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
auth_capability=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')

binding=$(printf '{"run_id":"%s","run_epoch":1,"cgroup_path":"%s","cgroup_id":%s,"profile":"%s","expected_recorder_sha256":"%s"}' \
	"${run_id}" "${cgroup_path}" "${cgroup_id}" "${profile}" "${expected_sha256}")
start=$(printf '{"protocol":"allox.system-effects-supervisor","version":1,"type":"START","binding":%s,"evidence_directory":"%s","auth_challenge":"%s","auth_capability":"%s"}' \
	"${binding}" "${evidence_directory}" "${auth_challenge}" "${auth_capability}")

verify_response()
{
	local encoded=$1
	local expected_type=$2
	local canonical_binding canonical proof expected_encoded
	canonical_binding=$(printf '{"cgroup_id":%s,"cgroup_path":"%s","expected_recorder_sha256":"%s","profile":"%s","run_epoch":1,"run_id":"%s"}' \
		"${cgroup_id}" "${cgroup_path}" "${expected_sha256}" "${profile}" "${run_id}")
	if [[ ${expected_type} == READY ]]; then
		canonical=$(printf '{"auth_challenge":"%s","binding":%s,"protocol":"allox.system-effects-supervisor","type":"READY","version":1}' \
			"${auth_challenge}" "${canonical_binding}")
		proof=$(printf 'READY\0%s' "${canonical}" \
			| openssl dgst -sha256 -mac HMAC -macopt "hexkey:${auth_capability}" -binary \
			| od -An -tx1 | tr -d ' \n')
		expected_encoded=$(printf '{"protocol":"allox.system-effects-supervisor","version":1,"type":"READY","binding":%s,"auth_challenge":"%s","proof":"%s"}' \
			"${binding}" "${auth_challenge}" "${proof}")
		[[ ${encoded} == "${expected_encoded}" ]] || {
			echo "READY binding or authentication mismatch" >&2
			return 1
		}
		return 0
	fi

	[[ ${expected_type} == FINALIZED ]] || { echo "unknown response type" >&2; return 1; }
	if [[ ${encoded} =~ \"manifest_sha256\":\"([0-9a-f]{64})\" ]]; then
		local manifest_sha256=${BASH_REMATCH[1]}
	else
		echo "FINALIZED lacks a canonical manifest digest" >&2
		return 1
	fi
	local quiescence serialized_result canonical_result
	quiescence=$(printf '{"status":"QUIESCENT_WITHIN_CGROUP","basis":"CGROUP_V2_EMPTY_FROZEN_VERIFIED","cgroup_id":%s}' "${cgroup_id}")
	serialized_result=$(printf '{"evidence_status":"COMPLETE","verification_status":"VERIFIED","manifest_path":"manifest.json","manifest_sha256":"%s"}' "${manifest_sha256}")
	canonical_result=$(printf '{"evidence_status":"COMPLETE","manifest_path":"manifest.json","manifest_sha256":"%s","verification_status":"VERIFIED"}' "${manifest_sha256}")
	canonical=$(printf '{"auth_challenge":"%s","binding":%s,"outcome":"completed","protocol":"allox.system-effects-supervisor","quiescence":{"basis":"CGROUP_V2_EMPTY_FROZEN_VERIFIED","cgroup_id":%s,"status":"QUIESCENT_WITHIN_CGROUP"},"result":%s,"type":"FINALIZED","version":1}' \
		"${auth_challenge}" "${canonical_binding}" "${cgroup_id}" "${canonical_result}")
	proof=$(printf 'FINALIZED\0%s' "${canonical}" \
		| openssl dgst -sha256 -mac HMAC -macopt "hexkey:${auth_capability}" -binary \
		| od -An -tx1 | tr -d ' \n')
	expected_encoded=$(printf '{"protocol":"allox.system-effects-supervisor","version":1,"type":"FINALIZED","binding":%s,"auth_challenge":"%s","outcome":"completed","quiescence":%s,"result":%s,"proof":"%s"}' \
		"${binding}" "${auth_challenge}" "${quiescence}" "${serialized_result}" "${proof}")
	[[ ${encoded} == "${expected_encoded}" ]] || {
		echo "FINALIZED binding, result, or authentication mismatch" >&2
		return 1
	}
	printf '%s' "${manifest_sha256}"
}

coproc EFFECTS_SUPERVISOR {
	"${observer}" supervise-effects --recorder-object "${bpf_object}" --drain-timeout-ms 5000 2> "${stderr_path}"
}
supervisor_out=${EFFECTS_SUPERVISOR[0]}
supervisor_in=${EFFECTS_SUPERVISOR[1]}
supervisor_pid=${EFFECTS_SUPERVISOR_PID}

printf '%s\n' "${start}" >&"${supervisor_in}"
if ! IFS= read -r -t 20 -u "${supervisor_out}" ready; then
	echo "supervisor did not return READY" >&2
	[[ ! -s ${stderr_path} ]] || sed -n '1,80p' "${stderr_path}" >&2
	exit 1
fi
verify_response "${ready}" READY >/dev/null

bash -c 'printf "%s\n" "$$" > "$1/cgroup.procs"; exec "$2" "$3"' \
	allox-effects-workload "${cgroup_path}" "${workload}" "${workload_argument}"

echo 1 > "${cgroup_path}/cgroup.freeze"
for _ in $(seq 1 100); do
	if grep -qx 'populated 0' "${cgroup_path}/cgroup.events" \
		&& grep -qx 'frozen 1' "${cgroup_path}/cgroup.events"; then
		break
	fi
	sleep 0.01
done
grep -qx 'populated 0' "${cgroup_path}/cgroup.events"
grep -qx 'frozen 1' "${cgroup_path}/cgroup.events"

finish=$(printf '{"protocol":"allox.system-effects-supervisor","version":1,"type":"FINISH","binding":%s,"auth_challenge":"%s","outcome":"completed","quiescence":{"status":"QUIESCENT_WITHIN_CGROUP","basis":"CGROUP_V2_EMPTY_FROZEN_VERIFIED","cgroup_id":%s}}' \
	"${binding}" "${auth_challenge}" "${cgroup_id}")
printf '%s\n' "${finish}" >&"${supervisor_in}"
if ! IFS= read -r -t 30 -u "${supervisor_out}" finalized; then
	echo "supervisor did not return FINALIZED" >&2
	[[ ! -s ${stderr_path} ]] || sed -n '1,120p' "${stderr_path}" >&2
	exit 1
fi
manifest_sha256=$(verify_response "${finalized}" FINALIZED)
wait "${supervisor_pid}"
supervisor_pid=

actual_manifest_sha256=$(sha256sum "${evidence_directory}/manifest.json")
actual_manifest_sha256=${actual_manifest_sha256%% *}
[[ ${actual_manifest_sha256} == "${manifest_sha256}" ]] || { echo "manifest digest mismatch" >&2; exit 1; }

expected_names=$'manifest.json\nsystem-effects.health.json\nsystem-effects.jsonl\nsystem-effects.policy.json\nsystem-effects.raw.bin'
actual_names=$(find "${evidence_directory}" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort)
[[ ${actual_names} == "${expected_names}" ]] || { echo "supervisor artifact set is not closed" >&2; exit 1; }

printf 'SUPERVISOR_E2E_OK run_id=%s cgroup_id=%s manifest_sha256=%s\n' \
	"${run_id}" "${cgroup_id}" "${manifest_sha256}"
