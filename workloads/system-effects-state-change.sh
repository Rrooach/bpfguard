#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

# Deliberately leave one bounded change in every Linux endpoint-state domain.
# This fixture must run only in a disposable VM: it changes a sysctl, mounts a
# tmpfs, creates local network configuration, and loads a test-only module.

set -euo pipefail

if [[ $# -ne 1 || $1 != /* || ! -f $1 ]]; then
	echo "usage: $0 /absolute/path/to/bpf_observer_e2e_state.ko" >&2
	exit 2
fi

module=$1
mountpoint=/mnt/bpf-observer-expanded-e2e
interface=bpfobse2e0

[[ ! -e $mountpoint ]] || {
	echo "fixture mountpoint already exists: $mountpoint" >&2
	exit 2
}
! /usr/sbin/ip link show dev "$interface" >/dev/null 2>&1 || {
	echo "fixture interface already exists: $interface" >&2
	exit 2
}
! /usr/sbin/nft list table inet bpf_observer_e2e >/dev/null 2>&1 || {
	echo "fixture nftables table already exists" >&2
	exit 2
}
! grep -q '^bpf_observer_e2e_state ' /proc/modules || {
	echo "fixture module is already loaded" >&2
	exit 2
}

current=$(tr -d '\n' </proc/sys/net/ipv4/ip_forward)
case "$current" in
0) replacement=1 ;;
1) replacement=0 ;;
*)
	echo "unexpected net.ipv4.ip_forward value: $current" >&2
	exit 1
	;;
esac
printf '%s\n' "$replacement" >/proc/sys/net/ipv4/ip_forward

mkdir "$mountpoint"
/usr/bin/mount -t tmpfs -o mode=0700,size=1m bpf-observer-e2e "$mountpoint"

/usr/sbin/ip link add "$interface" type dummy
/usr/sbin/ip address add 192.0.2.1/32 dev "$interface"
/usr/sbin/ip link set dev "$interface" up
/usr/sbin/ip route add 198.51.100.0/24 dev "$interface"
/usr/sbin/tc qdisc add dev "$interface" root fq_codel

/usr/sbin/nft add table inet bpf_observer_e2e
/usr/sbin/nft add chain inet bpf_observer_e2e output '{ type filter hook output priority 0; policy accept; }'
/usr/sbin/nft add counter inet bpf_observer_e2e observed_packets

/usr/sbin/insmod "$module"

printf '%s\n' '{"system_effects_state_change":"ok","changes_left_for_s1":true}'
