#!/bin/bash
set -euo pipefail
timeline_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "$timeline_dir/../.." && pwd)
kernel_dir=$(cd -- "$project_dir/../../.." && pwd)
native_output=${1:-"$project_dir/.output/execution-timeline-native"}
mkdir -p -- "$native_output"
native_output=$(cd -- "$native_output" && pwd)
libbpf_archive=${LIBBPF_ARCHIVE:-"$project_dir/.output/cargo-target/release/build/libbpf-sys-6600eb2a870d407c/out/libbpf.a"}
if [[ ! -f "$libbpf_archive" ]]; then
    echo 'Set LIBBPF_ARCHIVE to the existing built libbpf.a; this script does not install dependencies.' >&2
    exit 1
fi
libbpf_include=$(dirname -- "$libbpf_archive")/include
test -f "$libbpf_include/bpf/libbpf.h"
test -f "$project_dir/.output/bpf-include/bpf_helper_defs.h"
"${CLANG:-clang-14}" -g -O2 -target bpf -D__TARGET_ARCH_x86 -Wall -Wextra -Werror \
    -I"$kernel_dir/tools/include/uapi" -I"$kernel_dir/tools/lib" \
    -I"$project_dir/.output/bpf-include" -I"$project_dir/bpf" \
    -c "$project_dir/bpf/execution_timeline.bpf.c" -o "$native_output/execution_timeline.bpf.o"
"${CC:-cc}" -O2 -g -std=gnu11 -Wall -Wextra -Werror \
    -I"$libbpf_include" -I"$kernel_dir/tools/include/uapi" -I"$project_dir/bpf" \
    "$timeline_dir/collect.c" "$libbpf_archive" -lelf -lz -o "$native_output/collect"
"$native_output/collect" --self-test
printf 'Built collector and BPF object in %s\n' "$native_output"
