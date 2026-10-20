#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

# External A/B/C recovery fixture, executed directly by Observer outside the
# frozen Agent cgroup.  It is intentionally NOT a generic rollback mechanism.
# It touches only test-owned names, which must be absent before snapshot A.

set -euo pipefail

usage()
{
	echo "usage: $0 CHECKPOINT-ID full|leave-file|fail-before STATE-DIR" >&2
	exit 2
}

[[ $# -eq 3 && ${EUID} -eq 0 ]] || usage
checkpoint_id=$1
mode=$2
state_dir=$3
[[ $checkpoint_id =~ ^abc-[a-z0-9-]{1,48}$ ]] || usage
[[ $mode == full || $mode == leave-file || $mode == fail-before ]] || usage
[[ $state_dir == /* && -d $state_dir && ! -L $state_dir ]] || usage
[[ $(stat -Lc %u "$state_dir") == 0 ]] || usage
(( ((8#$(stat -Lc %a "$state_dir")) & 8#077) == 0 )) || usage
[[ -f $state_dir/checkpoint-id && ! -L $state_dir/checkpoint-id ]] || usage
[[ $(<"$state_dir/checkpoint-id") == "$checkpoint_id" ]] || usage

cgroup_root=/sys/fs/cgroup/bpf-observer-recovery-$checkpoint_id
residual_child=$cgroup_root/residual-child
filesystem_root=/tmp/bpf-observer-recovery-$checkpoint_id
bpffs_root=/sys/fs/bpf/bpf-observer-recovery-$checkpoint_id
mountpoint=/mnt/bpf-observer-expanded-e2e
interface=bpfobse2e0
module=bpf_observer_e2e_state

[[ -d $cgroup_root && ! -L $cgroup_root ]] || usage
[[ $(<"$state_dir/boot-id") == "$(< /proc/sys/kernel/random/boot_id)" ]] || {
	echo "Guest boot identity changed" >&2
	exit 1
}
[[ $(<"$state_dir/mount-ns-id") == "$(stat -Lc %i /proc/self/ns/mnt)" ]] || {
	echo "mount namespace identity changed" >&2
	exit 1
}
[[ $(<"$state_dir/network-ns-id") == "$(stat -Lc %i /proc/self/ns/net)" ]] || {
	echo "network namespace identity changed" >&2
	exit 1
}
self_cgroup=$(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup)
case $self_cgroup in
	"/bpf-observer-recovery-$checkpoint_id"|"/bpf-observer-recovery-$checkpoint_id/"*)
		echo "recovery helper entered the Agent cgroup" >&2
		exit 1
		;;
esac
awk '$1 == "frozen" && $2 == 1 { found=1 } END { exit(found ? 0 : 1) }' \
	"$cgroup_root/cgroup.events" || {
	echo "Agent cgroup is not frozen" >&2
	exit 1
}

[[ -f $state_dir/ip-forward.before && ! -L $state_dir/ip-forward.before ]] || usage
original_ip_forward=$(<"$state_dir/ip-forward.before")
[[ $original_ip_forward == 0 || $original_ip_forward == 1 ]] || usage

if [[ $mode == fail-before ]]; then
	echo "intentional recovery failure before any mutation" >&2
	exit 73
fi

# Removing the Link pin detaches the test program after its last FD closes.
# Only exact, fixture-owned pin names are removed; unexpected directory entries
# make rmdir fail closed instead of being swept away.
if [[ -d $bpffs_root && ! -L $bpffs_root ]]; then
	rm -f -- "$bpffs_root/persistent-link" "$bpffs_root/persistent-program" \
		"$bpffs_root/persistent-map"
	rmdir "$bpffs_root"
fi

if [[ -d $residual_child && ! -L $residual_child ]]; then
	printf '1\n' >"$residual_child/cgroup.kill"
	for (( attempt=0; attempt<500; attempt++ )); do
		awk '$1 == "populated" && $2 == 0 { found=1 } END { exit(found ? 0 : 1) }' \
			"$residual_child/cgroup.events" && break
		sleep 0.01
	done
	awk '$1 == "populated" && $2 == 0 { found=1 } END { exit(found ? 0 : 1) }' \
		"$residual_child/cgroup.events"
	rmdir "$residual_child"
fi

if grep -q "^$module " /proc/modules; then
	/usr/sbin/rmmod "$module"
fi

if /usr/sbin/nft list table inet bpf_observer_e2e >/dev/null 2>&1; then
	/usr/sbin/nft delete table inet bpf_observer_e2e
fi
if /usr/sbin/ip link show dev "$interface" >/dev/null 2>&1; then
	/usr/sbin/tc qdisc del dev "$interface" root
	/usr/sbin/ip route del 198.51.100.0/24 dev "$interface"
	/usr/sbin/ip address del 192.0.2.1/32 dev "$interface"
	/usr/sbin/ip link del dev "$interface"
fi
if mountpoint -q "$mountpoint"; then
	[[ $(findmnt -n -o FSTYPE,SOURCE --target "$mountpoint") == 'tmpfs bpf-observer-e2e' ]] || {
		echo "refusing to unmount a non-fixture filesystem" >&2
		exit 1
	}
	/usr/bin/umount "$mountpoint"
fi
if [[ -d $mountpoint && ! -L $mountpoint ]]; then
	rmdir "$mountpoint"
fi
printf '%s\n' "$original_ip_forward" >/proc/sys/net/ipv4/ip_forward

if [[ $mode == full ]]; then
	rm -f -- "$filesystem_root/persistent-state"
fi
[[ -d $filesystem_root && ! -L $filesystem_root ]] || {
	echo "fixture filesystem scope disappeared" >&2
	exit 1
}

printf '{"recovery_fixture":"%s","checkpoint_id":"%s"}\n' \
	"$mode" "$checkpoint_id"
