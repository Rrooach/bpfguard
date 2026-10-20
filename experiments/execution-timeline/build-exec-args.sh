#!/bin/bash
set -euo pipefail
exec_args_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec_args_project=$(cd -- "$exec_args_dir/../.." && pwd)
exec_args_kernel=$(cd -- "$exec_args_project/../../.." && pwd)
exec_args_output=${1:-"$exec_args_project/.output/native-exec-args"}
mkdir -p -- "$exec_args_output"
exec_args_output=$(cd -- "$exec_args_output" && pwd)
exec_args_libbpf=${LIBBPF_ARCHIVE:-"$exec_args_project/.output/cargo-target/release/build/libbpf-sys-6600eb2a870d407c/out/libbpf.a"}
test -f "$exec_args_libbpf"
exec_args_include=$(dirname -- "$exec_args_libbpf")/include
"${CLANG:-clang-14}" -g -O2 -target bpf -D__TARGET_ARCH_x86 -Wall -Wextra -Werror \
    -I"$exec_args_kernel/tools/include/uapi" -I"$exec_args_kernel/tools/lib" \
    -I"$exec_args_project/.output/bpf-include" -I"$exec_args_project/bpf" \
    -c "$exec_args_project/bpf/native_exec_args.bpf.c" -o "$exec_args_output/native_exec_args.bpf.o"
"${CC:-cc}" -O2 -g -std=gnu11 -Wall -Wextra -Werror \
    -I"$exec_args_include" -I"$exec_args_kernel/tools/include/uapi" -I"$exec_args_project/bpf" \
    "$exec_args_dir/exec_args_collect.c" "$exec_args_libbpf" -lelf -lz -o "$exec_args_output/exec-args-collect"
"$exec_args_output/exec-args-collect" --self-test
printf 'Built opt-in exec argv sidecar in %s\n' "$exec_args_output"
