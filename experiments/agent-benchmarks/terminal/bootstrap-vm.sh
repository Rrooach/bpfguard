#!/bin/bash
# Create a dedicated benchmark VM; all disk writes target its new private copy.
set -euo pipefail
base=${1:?unused raw ext4 base}
kernel=${2:?kernel bzImage}
output=${3:?new output directory}
port=${4:-10089}
[[ -f $base && -f $kernel && ! -e $output ]] || exit 2
[[ $port =~ ^[1-9][0-9]{0,4}$ && $port -le 65535 ]] || exit 2
base=$(realpath -e "$base")
kernel=$(realpath -e "$kernel")
output=$(realpath -m "$output")
fuser -s "$base" 2>/dev/null && { echo 'Base is in use' >&2; exit 2; }
[[ -z $(ss -ltnH "sport = :$port") ]] || { echo 'Port is in use' >&2; exit 2; }
file "$base" | grep -q 'ext4 filesystem data'
mkdir -m 0700 -p "$output"
sha256sum "$base" > "$output/base.before.sha256"
cp --reflink=auto --sparse=always -- "$base" "$output/rootfs.raw"
chmod u+w "$output/rootfs.raw"
truncate -s 32G "$output/rootfs.raw"
# Grow the mounted filesystem inside the newer Guest with resize2fs /dev/sda.
# The Host's e2fsprogs may not understand the source's orphan_file feature.
qemu-system-x86_64 -daemonize -pidfile "$output/qemu.pid" \
  -name "agent-benchmarks-${output##*/}" -m 12288 -smp 6 -enable-kvm \
  -cpu host,migratable=off -display none -serial "file:$output/console.log" \
  -no-reboot -kernel "$kernel" \
  -append 'root=/dev/sda rw console=ttyS0,115200 net.ifnames=0 lsm=capability,selinux,bpf psi=1' \
  -drive "file=$output/rootfs.raw,format=raw,if=ide,snapshot=off" \
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$port-:22" -device e1000,netdev=net0
pid=$(<"$output/qemu.pid")
awk '{print $22}' "/proc/$pid/stat" > "$output/qemu.start_ticks"
readlink -f "/proc/$pid/exe" > "$output/qemu.exe"
sha256sum "$base" > "$output/base.after.sha256"
cmp "$output/base.before.sha256" "$output/base.after.sha256"
printf '%s\n' "$output"
