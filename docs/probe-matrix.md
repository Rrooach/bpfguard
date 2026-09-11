# Implemented recorder matrix

The machine-readable description is
[`../config/probe-matrix.json`](../config/probe-matrix.json). It documents the
current object; this release does not yet load, hash, or enforce the matrix at
startup. The source identity in that file is therefore informational, not a
runtime policy assertion.

## Implemented probes

The recorder attaches exactly two tracepoints:

| Probe | Event | Captured fields |
|---|---|---|
| `raw_syscalls/sys_enter` | `SYSCALL_ATTEMPTED` | command, attr size, pid/tgid, cgroup ID, run epoch, time, sequence, flags |
| `raw_syscalls/sys_exit` | `COMMAND_COMPLETED` | correlated entry fields, related attempt sequence, signed return value |

The program filters the architecture's configured `bpf()` syscall numbers and
then requires an exact cgroup-ID entry in `run_states` with a nonzero epoch.
On x86-64 it configures native, i386, and x32 numbers; on AArch64 it configures
native and AArch32. Only the native ABI is exercised by the mandatory canary.
Compat entries are therefore configured coverage, not runtime-verified
coverage.

`command` and `attr_size` come directly from raw syscall registers. They have
`RAW_SYSCALL_REGISTERS` provenance. No `bpf_attr` pointer or payload is emitted.
The exit event gets its command/size/cgroup/epoch from the pending entry, not by
rereading userspace memory.

## Transport health

Before S0, the coordinator registers a reserved epoch in the same cgroup and
runs one deliberately invalid `BPF_MAP_CREATE` call (`uattr=NULL`, size zero).
The call cannot create state. The run proceeds only if it yields exactly one
entry, one exit, two published and persisted events, balanced pending state,
zero drops, and zero decode/routing failures.

The canary and formal workload share the raw WAL/JSONL, run ID, and cgroup ID.
They differ by epoch. Workload consumers must select `manifest.run_epoch`;
`verify-run` partitions both. The canary epoch is `u64::MAX`, or
`u64::MAX-1` when the formal epoch itself is `u64::MAX`.

For the formal epoch, health closure requires:

```text
native_transport_canary_passed
syscall_attempted == syscall_completed
last_event_seq == event_attempted
event_attempted == event_published + event_dropped
event_dropped == 0
event_published == events_persisted
pending_insert_failed == pending_missing == pending_remaining == 0
parse_failed == 0
unsupported_commands is empty
WAL durable and producer/drain barriers complete
```

`verify-run` additionally decodes the WAL, compares every record with JSONL,
checks the canary/formal epochs and cgroup identity, verifies sequence and
entry/exit pairing, and recomputes the endpoint verdict.

The userspace callback retains at most 4096 records between poll returns and
aborts consumption on overflow. Canary plus formal epochs are jointly limited
to 262144 persisted events, 32 MiB of WAL, and 128 MiB of JSONL. Reaching a
limit fails the observation rather than silently dropping it.

## What `COMPLETE` means

An `evidence_status=COMPLETE` result means the implemented native raw-syscall
transport was live, lossless, paired, and durable for the declared command
allowlist. It does **not** mean the semantic BPF operation is fully decoded.

The current event ABI does not provide:

- kernel-copied scalar fields;
- deep key/value/path/instruction bytes;
- resolved Map, Program, Link, or attachment target identity;
- per-command handler acceptance/partial-batch counts;
- non-`bpf(2)` effect paths.

Consequently a successful syscall event is not proof of a persistent effect,
and an endpoint delta is not automatically attributed to that event.

## Planned but absent handler probes

The fixed source tree contains candidate functions such as `map_create`,
`map_update_elem`, `bpf_prog_load`, `bpf_obj_pin`, and `link_create`. None is
attached by this baseline. Before adding one, the implementation must bind the
expected source/BTF/prototype and actual attachment set into the manifest,
define field-level provenance, and fail startup if a requested probe is absent.

## Excluded interfaces

The recorder does not cover bpffs unlink/rename, final FD close, inherited or
transferred FDs, writable Map mmap, perf-event/netlink/ioctl paths, or
kernel-internal/asynchronous BPF writers. Endpoint snapshots can reveal some
surviving state from those paths; the event stream cannot reconstruct them.
