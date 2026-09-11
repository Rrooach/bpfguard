# BPF State Observer

`bpf-state-observer` is a conservative eBPF observability baseline for a
cooperative Agent workload in a controlled Linux VM. It combines:

```text
native bpf() enter/exit evidence + S0/S1 kernel BPF state snapshots
```

It is an observer, not a sandbox, rollback engine, or malicious-workload
security boundary. Unreadable state, dropped events, unknown semantics, scope
mismatch, or unbound evidence always forbids `UNCHANGED_WITHIN_SCOPE`. With no
confirmed delta the result is `INCONCLUSIVE`; a reliable delta may still yield
`CHANGED_WITHIN_SCOPE` while separate completeness axes remain incomplete.

## What is implemented

- A raw-syscall eBPF recorder for native `bpf(2)` entry and exit, filtered by
  exact cgroup ID and run epoch.
- A non-LRU pending-call table, monotonic event sequences, explicit drop and
  pairing counters, a framed checksummed WAL, and a JSONL derived stream.
  The callback queue is capped at 4096 records and a run at 262144 records;
  WAL, JSONL, snapshots, manifests, and workload output also have byte caps.
- A pre-run, no-side-effect native `bpf()` canary that must traverse the loaded
  probes, cgroup filter, ring buffer, decoder, and durable WAL end to end.
- Program, Map, and Link global inventory with double enumeration.
- Optional bpffs pin traversal with a snapshot-level fingerprint for every
  declared root (canonical path, mount-namespace inode, and root mount ID),
  plus each pin's mount ID and exact pathname bytes. Empty roots remain
  observable; overlapping roots, nested mounts, and symlinks are rejected.
- Canonical content capture for ARRAY, HASH, PERCPU_ARRAY, and PERCPU_HASH.
  BTF-typed values are deliberately `OPAQUE_VALUE` until special-field
  analysis exists. Without the authenticated harness, samples are
  `BEST_EFFORT_NON_ATOMIC`: they are diagnostic, and a pure value change alone
  cannot drive a confirmed verdict. Under an authenticated `exclusive-vm-v1`
  run they are `COMPLETE_QUIESCENT`, subject to the closed-model policy.
- An authenticated `exclusive-vm-v1` path with a Host-held Ed25519 key, a
  Host Unix socket connected to a Guest virtio-serial character device, and
  strict `PRE_S0 -> S0_COMMITTED -> PRE_S1 -> FINAL` sequencing. All responses
  bind the nonce, exact run/cgroup, measured Observer/recorder/scope/workload,
  dynamic exclusion digest, policy ID/digest, and kernel identity. `FINAL`
  additionally binds snapshot, health, raw event, workload output, successful
  exit, and closing-barrier evidence.
- Typed comparison with per-delta certainty: `CONFIRMED` or `INDETERMINATE`.
  An apparent addition/removal caused by an incomplete inventory cannot become
  a confirmed change.
- Atomically replaced structured JSON, create-new/fsynced raw streams, and a
  final manifest containing a closed set of SHA-256/size bindings.
  `verify-run` checks the manifest, both raw event streams, event
  pairing/accounting, snapshot identity, and recomputes the verdict.

Five Rust library crates separate schema, state capture, event recording,
comparison, and authenticated harness protocol. A sixth workspace crate,
`crates/observerd`, coordinates a run.

## Deliberately not implemented yet

- Automatic enforcement of arbitrary Host contract statements or a hostile
  Guest security boundary. The authenticated protocol proves which Host key
  signed an exact policy and run; the VM launcher must actually enforce the 12
  policy checks. Static `--harness-evidence` remains diagnostic-only and is
  always prevented from authorizing `UNCHANGED_WITHIN_SCOPE`.
- Command-handler probes, kernel-copied `bpf_attr` fields, resolved object IDs,
  or deep pointer payload capture. Current event completeness means only that
  the native raw-syscall transport closed cleanly.
- Runtime binding to an expected source commit, kernel `.config`, BTF digest,
  or probe-matrix digest. The exact recorder bytes are checked against a
  mandatory external SHA-256 policy before load and again by `verify-run`;
  authenticity and distribution of that policy value remain the VM
  orchestrator's responsibility.
- Target-specific attachment queries, compat-ABI canaries, FD-lifetime/VFS
  event capture, writable-Map-mmap tracking, and kernel-internal writers.
- Automatic recovery after an uncatchable daemon death. The direct workload
  child gets `PR_SET_PDEATHSIG(SIGKILL)`, but descendants still require VM or
  service-manager cleanup.

These are functional boundaries, not future features that the current result
implicitly assumes.

## Build and test

Generated output stays below `.output/`.

```sh
make
make release
make bpf
make workloads
make check
make check-all
make clippy
make vm-kernel
```

The authenticated strict QEMU gate is a separate opt-in target because it
requires a maintained raw rootfs and root SSH key for its provisioning boot.
See the [VM E2E instructions](vm/README.md) and the
[strict validation record](docs/vm-strict-e2e-validation-2026-09-11.md).

The workspace declares Rust 1.67 and pins `Cargo.lock`. A current stable Rust
toolchain is recommended. The recorder build defaults to `clang-14` and the
x86 BPF target; override `CLANG` and `BPF_ARCH` for the target architecture.
The recorder uses the fixed `raw_syscalls` tracepoint ABI and does not require
CO-RE or `vmlinux.h`.

## Runtime prerequisites

Use a dedicated/disposable VM. For the kernel in this source tree, the daemon
requires effective `CAP_SYS_ADMIN`: global `BPF_*_GET_NEXT_ID` and
`GET_FD_BY_ID` are guarded by that capability. It also needs:

- writable cgroup v2 beneath the selected `--cgroup-root`, including
  `cgroup.freeze` and (for failure cleanup) `cgroup.kill`;
- raw-syscall tracepoints;
- a recorder object built for the target architecture;
- bpffs only when `bpffs_roots` is non-empty;
- an output directory the workload cannot modify.

Authenticated mode additionally requires a dedicated Host harness process,
the raw 32-byte trusted public key in the Guest, and a bidirectional Guest
character device connected to the Host Unix socket. The policy ID, canonical
policy digest, and kernel/rootfs identity must come from the trusted launcher,
not from the workload or run directory.

The coordinator does not create a user/mount namespace or drop its own UID and
capabilities before `exec`. The final prerequisite must therefore be enforced
by the VM launcher or service manager; merely choosing a pathname is not an
access-control boundary.

Run the read-only preflight first. It performs real global program/Map/Link
enumeration smoke calls rather than checking capability bits alone. Its
tracepoint test is a minimum `perf_event_open` smoke check, not a full load and
attach rehearsal. Freezer/kill files are also checked authoritatively only
after the non-root run cgroup is created; `observe` fails closed if any actual
load, attach, or cgroup-interface check fails:

```sh
BIN=.output/cargo-target/release/bpf-state-observer
sudo "$BIN" doctor --recorder-object .output/recorder.bpf.o
```

## Observe one workload

The output directory must not already exist. The observer creates it atomically
so concurrent runs cannot claim the same commit directory:

```sh
sudo "$BIN" observe \
  --scope config/default-scope.json \
  --recorder-object .output/recorder.bpf.o \
  --expected-recorder-sha256 "$TRUSTED_RECORDER_SHA256" \
  --output-dir /var/lib/bpf-observer/runs/example-1 \
  --run-id example-1 \
  -- \
  .output/workloads/map-lifecycle --ephemeral
```

Manifest v1 binds workload arguments as UTF-8 strings; `observe` rejects a
non-UTF-8 argv instead of recording a lossy substitute.

The actual order is:

1. Write a `RUNNING` manifest, load and attach the recorder, and resolve every
   observer-owned program/Map/Link ID.
2. Reject an explicit `map_ids` request that overlaps observer-owned Maps.
3. Create an exact cgroup. In authenticated mode, measure the Observer,
   recorder, effective scope, exclusion set, and workload; construct the full
   binding; and obtain the signed `PRE_S0` authorization.
4. Pass the native transport canary, register the formal
   `{cgroup_id, run_epoch}`, capture S0, and obtain `S0_COMMITTED` in
   authenticated mode.
5. Spawn the workload; its `pre_exec` moves it into the cgroup before `exec`.
6. Poll until the root exits and recursive `cgroup.events` says
   `populated=0`, then freeze the empty cgroup to close the re-entry window;
   authenticated mode requires a successful normal exit.
7. Reconcile/fsync recorder evidence and obtain signed `PRE_S1`; capture S1
   while the run remains registered, verify counters are still stable, then
   obtain signed `FINAL` over the exact snapshots, health, raw events, workload
   streams, exit status, and barriers before removing the frozen cgroup.
8. Write a provisional derived verdict, hash the closed artifact set, and
   atomically commit a `FINALIZED` manifest last.

S1 is intentionally the workload-end boundary before owned-cgroup teardown.
The verdict records that teardown can subsequently release cgroup-scoped BPF
references.

## Authenticated exclusive-VM run

The Host policy is a separate, typed JSON file. It must enumerate all 12
contract checks and authorize the exact kernel identity, Observer, recorder,
canonical scope digest, and
`{run_id, run_epoch, cgroup_path, argv, executable_sha256}` workload. The
contract descriptor in `config/exclusive-vm-v1.json` is not a serve-ready
policy.

On the Host, generate the key, calculate the canonical policy digest, and
start the signer on a new Unix socket:

```sh
HARNESSD=.output/cargo-target/release/bpf-harnessd
install -d -m 0700 /var/lib/bpf-observer/harness
"$HARNESSD" keygen \
  --secret-key /var/lib/bpf-observer/harness/host.secret \
  --public-key /var/lib/bpf-observer/harness/host.public
POLICY_SHA256=$("$HARNESSD" policy-digest \
  --policy /var/lib/bpf-observer/harness/policy.json)
"$HARNESSD" serve \
  --socket /var/lib/bpf-observer/harness/channel.sock \
  --secret-key /var/lib/bpf-observer/harness/host.secret \
  --policy /var/lib/bpf-observer/harness/policy.json \
  --max-sessions 1
```

Attach that Host socket to the Guest virtio-serial port
`org.allox.harness`; the complete QEMU invocation is kept in the
[VM E2E instructions](vm/README.md). Copy only the
public key into the Guest. Then add the complete authenticated option group to
`observe`:

```sh
WORKLOAD=$(realpath /opt/bpf-state-observer/exclusive-noop)
sudo /opt/bpf-state-observer/bpf-state-observer observe \
  --scope /opt/bpf-state-observer/exclusive-vm-scope.json \
  --recorder-object /opt/bpf-state-observer/recorder.bpf.o \
  --expected-recorder-sha256 "$TRUSTED_RECORDER_SHA256" \
  --output-dir /var/lib/bpf-observer/runs/exclusive-1 \
  --run-id exclusive-1 \
  --run-epoch 1101 \
  --harness-channel /dev/virtio-ports/org.allox.harness \
  --harness-public-key /opt/bpf-state-observer/host.public \
  --harness-policy-id "$HARNESS_POLICY_ID" \
  --expected-harness-policy-sha256 "$POLICY_SHA256" \
  --harness-kernel-identity "$HARNESS_KERNEL_IDENTITY" \
  -- \
  "$WORKLOAD" --exclusive-contract
```

The Host-held lease spans all four signed phases. The dynamic exclusion digest
cannot be pre-provisioned because recorder-owned kernel IDs exist only after
load. Policy therefore declares
`MEASURED_OBSERVER_RECORDER_OWNED_V1`, the Host signs the actual digest, and
offline verification recomputes it from the manifest. See
[Authenticated harness evidence](docs/harness-evidence.md) for the exact
binding and policy semantics.

## Verify before consuming

Never trust `verdict.json` by itself. It remains `PROVISIONAL`; only a
`FINALIZED` manifest commits a run.

```sh
"$BIN" verify-run \
  --run-dir /var/lib/bpf-observer/runs/example-1 \
  --expected-recorder-sha256 "$TRUSTED_RECORDER_SHA256"
```

For an authenticated run, `verify-run` requires the external public key,
policy ID, canonical policy digest, and kernel identity as one complete group:

```sh
"$BIN" verify-run \
  --run-dir /var/lib/bpf-observer/runs/exclusive-1 \
  --expected-recorder-sha256 "$TRUSTED_RECORDER_SHA256" \
  --harness-public-key /var/lib/bpf-observer/harness/host.public \
  --harness-policy-id "$HARNESS_POLICY_ID" \
  --expected-harness-policy-sha256 "$POLICY_SHA256" \
  --harness-kernel-identity "$HARNESS_KERNEL_IDENTITY"
```

An authenticated run is rejected when this group is absent or partial. These
values must come from outside the run directory; otherwise a replaced run can
choose its own apparent trust anchor. The verifier reconstructs the exact
binding and signed phase evidence from the finalized manifest and artifacts.

The command rejects a running/failed manifest, a missing or extra directory
entry,
digest or size mismatch, WAL truncation, WAL/JSONL disagreement, event/run
identity mismatch, broken pairing/accounting, snapshot/manifest mismatch, or a
verdict that does not recompute.

The manifest is an integrity binding, not an authenticity signature. The
mandatory recorder digest must come from a trusted policy location, not be
freshly calculated from the same untrusted object being checked.
`verify-run` returns the SHA-256 of the exact manifest bytes it verified; store
or sign that digest outside the workload's trust domain when tamper resistance
matters. Verification also assumes the run directory is trusted and remains
immutable for the duration of the command; seal or copy an externally supplied
directory before verification rather than verifying it while another process
can rename its path hierarchy.

## Artifacts

A successful committed run binds exactly:

- `canary-health.json`
- `health.json`
- `quiescence.json`
- `raw-events.bin`
- `raw-events.jsonl`
- `s0.json`
- `s1.json`
- `verdict.json`
- `workload.stderr`
- `workload.stdout`

`manifest.json` is the commit record and contains their SHA-256 hashes and
sizes. Once the initial `RUNNING` record exists, a handled failure is rewritten
as `run_status=FAILED` when that failure record can be persisted. Validation
can fail before any manifest exists, and a crash or storage failure can leave a
missing or `RUNNING` manifest; none may be consumed as a completed observation.

For an authenticated run, `quiescence.json` embeds the four signed responses.
The `FINAL` response independently binds the raw WAL/JSONL streams, both
workload output streams, S0/S1, health/canary files, successful normal exit,
and closing barriers. `verify-run` compares those signed values with the
manifest-bound artifacts rather than trusting the embedded transcript alone.

Map changes in `verdict.json` carry stable metadata plus content status,
digest, entry count, byte count, and CPU topology. They deliberately do not
duplicate the potentially large entry arrays; canonical entries remain in
`s0.json` and `s1.json`, which the verifier binds and rechecks.

Workload stdout and stderr are captured separately so command output remains
machine-readable. Each stream retains at most 16 MiB while the pipe continues
to be drained; truncation is recorded in manifest notes.

Both raw event streams contain the two-record native canary epoch as well as
the formal workload epoch. Workload consumers must select
`manifest.run_epoch`; otherwise the canary's deliberately invalid command 0
would be misattributed to the workload. `verify-run` partitions and validates
both epochs. The reserved epoch is `u64::MAX`, except when that is the formal
epoch, in which case it is `u64::MAX-1`.

## Verdict semantics

- `CHANGED_WITHIN_SCOPE`: at least one typed endpoint delta is confirmed from
  reliable inventories. This does not by itself prove workload causality.
- `UNCHANGED_WITHIN_SCOPE`: supported by the comparator only when complete
  state, complete transport health, and authenticated closed-model evidence
  are supplied. It is reachable through the four-phase authenticated harness,
  but never through static `--harness-evidence` input.
- `INCONCLUSIVE`: no confirmed delta, but a required completeness or
  quiescence condition is missing.

`UNCHANGED_WITHIN_SCOPE` means no endpoint delta was confirmed within the
declared scope and model. It does not say that no operation occurred:
`S0 == S1` cannot exclude transient create/use/delete activity. Raw syscall
events can expose some such activity, but they do not cover non-`bpf(2)` paths
or out-of-scope state. No result should be translated directly into rollback
`CLEAN`.

## Scope and limits

[`config/default-scope.json`](config/default-scope.json) is deliberately
metadata-only: it inventories Program, Map, and Link objects but samples no Map
contents and claims no pin roots or attachment targets. The implementation can
sample ARRAY, HASH, PERCPU_ARRAY, and PERCPU_HASH when explicitly opted in;
[`config/map-content-scope.example.json`](config/map-content-scope.example.json)
shows the shape and requires replacing the example Map ID.

Map sampling has validated per-Map limits plus hard snapshot-wide object,
content-entry, logical-byte, conservative retained-representation, CPU,
pin-traversal/path-representation, and time caps. Recorder objects and all
committed artifacts are size-bounded as well. Hitting any observation cap
taints completeness or fails the run; it is never interpreted as absence.
Workload stdout/stderr are the deliberate exception: capture is truncated at
16 MiB per stream, draining continues, and the manifest records a note.

Details:

- [Claim-scope semantics](docs/claim-scope.md)
- [Threat model](docs/threat-model.md)
- [Implemented recorder matrix](docs/probe-matrix.md)
- [Authenticated strict VM E2E validation](docs/vm-strict-e2e-validation-2026-09-11.md)
- [Authenticated harness evidence](docs/harness-evidence.md)
- [VM requirements](vm/README.md)
- [Codex + DeepSeek diagnostic collection VM](experiments/codex-deepseek/README.md)
