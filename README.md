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

The binary also exposes a deliberately separate `observe-effects` mode. It
records selected filesystem, network, namespace, kernel-control, security, and
I/O syscall attempts/results from one exact cgroup. Those records are useful
operation history, but are **not** a whole-kernel state diff and never support
an `UNCHANGED_WITHIN_SCOPE` claim by themselves. Optional, independently scoped
BPF-object, filesystem path-tree, and explicitly scoped Linux endpoint-state
S0/S1 confirmers publish separate per-domain results; they do not create an
aggregate whole-system verdict. See
the [system-effect recorder guide](docs/system-effects-observer.md).
The framework-independent implementation boundary and follow-up work are kept
in the
[system-effects roadmap](docs/system-effects-roadmap.md).

## What is implemented

- A raw-syscall eBPF recorder for native `bpf(2)` entry and exit, filtered by
  exact cgroup ID and run epoch.
- An independent, policy-driven `observe-effects` recorder with `control`,
  `balanced`, and `full` profiles. Its global fast path rejects unselected
  syscalls after one policy-Map lookup; only selected operations from a
  registered cgroup allocate pending state or publish ring-buffer events.
- Three explicit partial kernel object-resolution modes. The first two cover
  selected successful opens and positive-byte native write-family VFS objects.
  `kernel-object-expanded-partial` additionally joins selected path/inode LSM
  hooks for create/link/unlink/rename/chmod/chown/xattr operations, eligible
  file-backed `MAP_SHARED|PROT_WRITE` mmap establishment, single-VMA shared
  file-backed `mprotect(PROT_WRITE)` permission transitions, bind/connect
  socket objects and requested endpoints, and accepted TCP peer objects. A separate
  stream records correlated AF_INET/AF_INET6 TCP state transitions and destroy
  events. Missing, duplicate, or unreadable
  required joins fail evidence closed. This is still operation-specific rather
  than general kernel-object provenance.
- A separately built and independently attested process-lifecycle recorder in
  expanded mode. It records direct-cgroup `fork`, successful `exec`, and
  `exit`, uses PID/TGID plus task start-boottime identity to avoid PID-reuse
  ambiguity, and lets the offline verifier replay terminal lineage for events
  admitted by those hooks and correlate matching syscall identities. Schema v2
  has no authoritative S0 task/thread ledger and no cgroup migration or
  `CLONE_INTO_CGROUP` enrollment hook, so lifecycle status is capped at
  `PARTIAL`; it never claims complete process-tree association. An exec
  pathname is descriptive kernel-copied evidence, not executable file
  identity.
- Optional, independently verified S0/S1 endpoint confirmation for BPF
  objects, bounded generic filesystem path trees, explicit sysctl keys, one
  mount namespace, selected local-network address/route/rule/tc/nft state,
  selected loaded modules and readable parameters, and residual processes in
  the exact tracked cgroup tree. The observe outcome and verifier report expose
  a per-domain `state_domains` vector rather than promoting any result to a
  whole-system verdict.
- A one-shot deployment observer for an already frozen direct process tree,
  Docker container, or Kata host-side sandbox. It discovers and revalidates
  process/cgroup/namespace identity, registers all discovered exact cgroup IDs
  in one shared system recorder and one lifecycle recorder, and emits a closed,
  offline-verifiable artifact set. Kata scope is intentionally the target-Linux
  runtime/QEMU/virtiofs/disk/network backend; it never claims guest syscalls.
- A bounded delegation-ledger protocol and structural validator. No delegation
  broker, request signer/authenticator, helper-cgroup runtime, manifest
  integration, or broker-to-syscall causal chain is implemented.
- A non-LRU pending-call table, monotonic event sequences, explicit drop and
  pairing counters, a framed checksummed WAL, and a JSONL derived stream.
  Both callback queues are capped at 4096 records. The BPF-state recorder caps
  a run at 262144 records; the system-effect recorder caps it at 1000000.
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

Workspace crates separate schema, BPF/filesystem/Linux endpoint capture,
system-effect and lifecycle recording, comparison, deployment discovery, and
authenticated harness protocols. `crates/observerd` coordinates standalone
runs, while `crates/deployment-observer` coordinates already-running targets.

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
- Complete object resolution for all kernel mutation paths. In expanded mode a
  create identifies its parent rather than the not-yet-created child, hard-link
  identifies the source inode, rename identifies only the source, xattr hooks
  lack a mount identity, and mmap evidence proves only establishment of an
  eligible shared writable file mapping—not a later dirty page. The mprotect
  resolver proves only a write-permission channel for one shared file-backed
  VMA; anonymous/private, mixed, and multi-VMA ranges remain explicitly
  unresolved. `io_uring`, `SCM_RIGHTS`, socketpair/send destinations,
  non-INET/TCP socket state, delegated-daemon effects, delayed kernel workers,
  and compat/x32 coverage remain outside the object contract.
- Authentication or enforcement of a filesystem actor/quiescence contract in
  `observe-effects`. A supplied contract is external input that the observer
  validates and exact-matches during verification; the observer does not check
  its signature or prove that its `exclusive_writer_enforced` and quiescence
  assertions happened.
- A delegation broker or runtime causal chain. The library validator cannot
  create, sign, authenticate, collect, or attach a delegation ledger to an
  `observe-effects` run.
- Standalone workload credential isolation or evidence-directory write
  isolation. Mode `0700` on a newly created directory is not protection from a
  workload that inherits the observer caller's identity or capabilities.
- Automatic recovery after an uncatchable daemon death. The direct workload
  child gets `PR_SET_PDEATHSIG(SIGKILL)`, but descendants still require VM or
  service-manager cleanup.
- Unbounded ancestor-root scaling or complete lifecycle enrollment. Deployment
  adapters now install at most eight non-overlapping, FD-pinned cgroup-v2
  ancestor roots; every selected syscall and lifecycle hook uses
  `bpf_current_task_under_cgroup`, so dynamic and ephemeral descendants report
  `DYNAMIC_ANCESTOR_COMPLETE` for the selected hook set. An exact-cgroup miss
  pays a linear scan of those roots, and lifecycle remains `PARTIAL` because
  schema v2 has no authoritative S0 task/thread ledger, migration stream, or
  `CLONE_INTO_CGROUP` enrollment proof.

These are functional boundaries, not future features that the current result
implicitly assumes.

## Build and test

Generated output stays below `.output/`.

```sh
make
make release
make bpf
make system-effects-bpf
make process-lifecycle-bpf
make workloads
make check
make check-all
make clippy
make vm-kernel
make overhead-check
```

The authenticated strict QEMU gate is a separate opt-in target because it
requires a maintained raw rootfs and root SSH key for its provisioning boot.
See the [VM E2E instructions](vm/README.md) and the
[strict validation record](docs/vm-strict-e2e-validation-2026-09-11.md).
The paired overhead microbenchmark is also opt-in because it boots KVM and
retains hundreds of MiB of raw evidence. See the
[overhead benchmark instructions](experiments/overhead/README.md) and the
[latest validation record](experiments/overhead/VALIDATION.md).

The workspace declares Rust 1.67 and pins `Cargo.lock`. A current stable Rust
toolchain is recommended. The recorder build defaults to `clang-14` and the
x86 BPF target; override `CLANG` and `BPF_ARCH` for the target architecture.
The native `bpf(2)` state recorder uses the fixed `raw_syscalls` tracepoint
ABI and does not require CO-RE or `vmlinux.h`. The system-effect recorder's
three partial kernel-object modes use CO-RE BPF LSM hooks and require readable
kernel BTF plus an active `bpf` LSM. Expanded mode additionally requires the
separately attested process-lifecycle object and its
`tp_btf/sched_process_{fork,exec,exit}` ABI.

## Runtime prerequisites

Use a dedicated/disposable VM. For the kernel in this source tree, the daemon
requires effective `CAP_SYS_ADMIN`: global `BPF_*_GET_NEXT_ID` and
`GET_FD_BY_ID` are guarded by that capability. It also needs:

- writable cgroup v2 beneath the selected `--cgroup-root`, including
  `cgroup.freeze` and (for failure cleanup) `cgroup.kill`;
- raw-syscall tracepoints;
- a recorder object built for the target architecture;
- bpffs only when `bpffs_roots` is non-empty;
- an output parent that an external launcher makes inaccessible to the
  workload after the observer has opened it.

Authenticated mode additionally requires a dedicated Host harness process,
the raw 32-byte trusted public key in the Guest, and a bidirectional Guest
character device connected to the Host Unix socket. The policy ID, canonical
policy digest, and kernel/rootfs identity must come from the trusted launcher,
not from the workload or run directory.

The coordinator does not create a user/mount namespace or drop its own UID and
capabilities before `exec`, and it records
`workload_privilege_isolation_enforced=false` and
`evidence_write_isolation_enforced=false`. These prerequisites must therefore
be enforced by the VM launcher or service manager; merely choosing a pathname
or relying on the observer-created mode-`0700` directory is not an
access-control boundary. Without that external isolation, the supported threat
model is a cooperative workload only.

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

## Observe selected system-effect operations

Build the general recorder, establish the recorder digest through a trusted
build/distribution path, and run one workload in a new output directory:

```sh
make release system-effects-bpf workloads
EFFECT_OBJECT=$(realpath .output/system_effects.bpf.o)
# Local smoke-test convenience only; production must provision this digest
# independently of the object being checked.
TRUSTED_EFFECT_SHA256=$(sha256sum "$EFFECT_OBJECT" | awk '{print $1}')

sudo "$BIN" observe-effects \
  --recorder-object "$EFFECT_OBJECT" \
  --expected-recorder-sha256 "$TRUSTED_EFFECT_SHA256" \
  --output-dir /var/lib/bpf-observer/effects/example-1 \
  --run-id example-effects-1 \
  --profile balanced \
  -- \
  .output/workloads/system-effects-smoke /tmp/system-effects-smoke-1

sudo "$BIN" verify-effects \
  --run-dir /var/lib/bpf-observer/effects/example-1 \
  --expected-recorder-sha256 "$TRUSTED_EFFECT_SHA256" \
  --expected-profile balanced \
  --expected-object-resolution user-input
```

For event-time VFS identity on selected opens and positive-byte native
`write`/`pwrite64`/`writev`/`pwritev`/`pwritev2` results that reach
`file_permission`, select the
explicit mode on both collection and verification (and use `balanced` or
`full`, since `control` omits the write data path):

```sh
sudo "$BIN" doctor \
  --recorder-object "$EFFECT_OBJECT" \
  --object-resolution kernel-file-open-write-partial

sudo "$BIN" observe-effects \
  --recorder-object "$EFFECT_OBJECT" \
  --expected-recorder-sha256 "$TRUSTED_EFFECT_SHA256" \
  --output-dir /var/lib/bpf-observer/effects/write-objects-1 \
  --run-id write-objects-1 \
  --profile balanced \
  --object-resolution kernel-file-open-write-partial \
  -- /bin/sh -c "printf data > /tmp/observer-write-object"

sudo "$BIN" verify-effects \
  --run-dir /var/lib/bpf-observer/effects/write-objects-1 \
  --expected-recorder-sha256 "$TRUSTED_EFFECT_SHA256" \
  --expected-profile balanced \
  --expected-object-resolution kernel-file-open-write-partial
```

This mode requires readable kernel BTF and active BPF LSM. It never falls back
to pathname or FD-number guesses. A file-hook join that is ambiguous or fails
object reads makes the evidence incomplete. A missing required object join also
makes it incomplete; this includes `O_PATH`, whose flags are not yet captured
in the replay ABI, and open paths that invoke multiple stacked-filesystem
`file_open` hooks. Pipefs and socketfs objects reached through `write(2)` are
valid VFS `FILE_OBJECT` identities, but they are not `SOCKET_OBJECT` endpoint
evidence and do not prove persistent file state.

For the expanded partial object contract, build and independently trust both
ELFs. The separate lifecycle digest is mandatory on collection and
verification:

```sh
make system-effects-bpf process-lifecycle-bpf
LIFECYCLE_OBJECT=$(realpath .output/process_lifecycle.bpf.o)
TRUSTED_LIFECYCLE_SHA256=$(sha256sum "$LIFECYCLE_OBJECT" | awk '{print $1}')

sudo "$BIN" doctor \
  --recorder-object "$EFFECT_OBJECT" \
  --process-lifecycle-object "$LIFECYCLE_OBJECT" \
  --object-resolution kernel-object-expanded-partial

sudo "$BIN" observe-effects \
  --recorder-object "$EFFECT_OBJECT" \
  --expected-recorder-sha256 "$TRUSTED_EFFECT_SHA256" \
  --process-lifecycle-object "$LIFECYCLE_OBJECT" \
  --expected-process-lifecycle-sha256 "$TRUSTED_LIFECYCLE_SHA256" \
  --output-dir /var/lib/bpf-observer/effects/expanded-1 \
  --run-id expanded-1 \
  --profile full \
  --object-resolution kernel-object-expanded-partial \
  --confirm-process-residual \
  -- /path/to/workload

sudo "$BIN" verify-effects \
  --run-dir /var/lib/bpf-observer/effects/expanded-1 \
  --expected-recorder-sha256 "$TRUSTED_EFFECT_SHA256" \
  --expected-process-lifecycle-sha256 "$TRUSTED_LIFECYCLE_SHA256" \
  --expected-profile full \
  --expected-object-resolution kernel-object-expanded-partial \
  --confirm-process-residual
```

Expanded mode resolves only the enumerated operations. Create-family hooks
identify the parent, hard-link identifies the source, rename identifies only
the source, eligible mmap means a file-backed shared writable mapping request,
eligible mprotect means one shared file-backed VMA gained write permission,
and bind/connect endpoints are kernel-copied requested endpoints. Successful
accept/accept4 resolves the accepted socket and peer from kernel socket state.
The separate socket-state stream records AF_INET/AF_INET6 TCP accept snapshots,
state transitions, and destroy events and binds them to the originating
bind/connect/accept syscall-entry identity. It does not observe later mmap page
dirtying or prove that an mprotect-enabled page was written, guarantee an assigned ephemeral bind port without a later eligible
TCP state event, cover non-TCP sockets, or decode `io_uring` effects.

Add `--bpf-state-scope config/default-scope.json` to `observe-effects` when a
separate BPF-object S0/S1 confirmation is required, and pass the same trusted
file back to `verify-effects` as
`--expected-bpf-state-scope config/default-scope.json`. This writes
`bpf-state-s0.json`, `bpf-state-s1.json`, and `bpf-state-verdict.json`, all
hash-bound by the effects manifest and recomputed by `verify-effects`. It can
confirm a final BPF delta, but standalone mode deliberately reports an empty
diff as `INCONCLUSIVE` because it lacks the authenticated exclusive-VM
contract. The syscall JSONL remains operation history, not a state diff.

The Linux-first standalone path can also capture a bounded filesystem path
tree at S0 and S1. The
[`filesystem-scope.example.json`](config/filesystem-scope.example.json) scope
stores exact path bytes, so validate it and derive the run-bound snapshot IDs
before launch. This example enables the filesystem and BPF confirmers together;
their S1 captures are sequential, not one atomic whole-system snapshot:

```sh
FS_SCOPE=$(realpath config/filesystem-scope.example.json)
BPF_SCOPE=$(realpath config/default-scope.json)
FS_ROOT=/tmp/bpf-observer-workspace
RUN_ID=effects-filesystem-1
RUN_EPOCH=1
RUN_DIR=/var/lib/bpf-observer/effects/$RUN_ID

sudo install -d -m 0700 "$FS_ROOT"

"$BIN" filesystem-scope-info \
  --scope "$FS_SCOPE" \
  --run-id "$RUN_ID" \
  --run-epoch "$RUN_EPOCH"

sudo "$BIN" observe-effects \
  --recorder-object "$EFFECT_OBJECT" \
  --expected-recorder-sha256 "$TRUSTED_EFFECT_SHA256" \
  --output-dir "$RUN_DIR" \
  --run-id "$RUN_ID" \
  --run-epoch "$RUN_EPOCH" \
  --profile balanced \
  --object-resolution user-input \
  --bpf-state-scope "$BPF_SCOPE" \
  --filesystem-state-scope "$FS_SCOPE" \
  -- /bin/sh -c "printf '%s\\n' observed > '$FS_ROOT/result.txt'"

sudo "$BIN" verify-effects \
  --run-dir "$RUN_DIR" \
  --expected-recorder-sha256 "$TRUSTED_EFFECT_SHA256" \
  --expected-profile balanced \
  --expected-object-resolution user-input \
  --expected-bpf-state-scope "$BPF_SCOPE" \
  --expected-filesystem-state-scope "$FS_SCOPE"
```

Complete, same-environment snapshots with a typed difference report
`endpoint_difference=OBSERVED_DIFFERENT` and
`state_verdict=CHANGED_WITHIN_SCOPE`; this confirms only bounded endpoint-state
difference, while causal attribution remains `NOT_ESTABLISHED`. Identical
snapshots report `OBSERVED_IDENTICAL` but the filesystem `state_verdict` remains
`INCONCLUSIVE`: cgroup empty/frozen does not establish that no external actor
wrote the scoped tree or that both non-atomic walks were quiescent.

`filesystem-scope-info` only validates the scope and prints its SHA-256 and
the exact S0/S1 IDs used by the static v1 actor/quiescence assertion. It does
not generate, authenticate, or enforce that assertion. A caller may pass one as
`--filesystem-actor-contract`; verification must then receive the identical
external file as `--expected-filesystem-actor-contract`. Even when all three
booleans are true, its status is `ASSERTED_NOT_AUTHENTICATED`, the report marks
the input `EXTERNAL_EXACT_INPUT_NOT_AUTHENTICATED_BY_OBSERVER`, and it cannot
authorize `UNCHANGED_WITHIN_SCOPE`. Its `evidence_sha256` is syntax-checked but
not authenticated or matched to enforcement evidence. A future signed
supervisor contract must add freshness and bind boot, cgroup, and real barrier
evidence before strong negative filesystem verdicts become reachable.

`--linux-state-scope PATH` enables a separately bounded scope for explicit
sysctl keys, one mount namespace, selected local addresses/routes/rules/tc/nft
collectors, and selected loaded-module records and optional readable
parameters. Every enabled network scope must bind
`normalization: NETWORK_CONFIGURATION_ONLY_V1`; this removes only declared
volatile counters/handles while preserving configuration semantics.
`--confirm-process-residual` adds a scope bound by the observer to
the exact run cgroup and recursively checks for remaining tasks. The same
external Linux-state scope and residual flag must be supplied to
`verify-effects`. These collectors produce
`linux-state-s0.json`, `linux-state-s1.json`, and
`linux-state-comparison.json`; they execute only at the two barriers.

Both commands return `state_domains`: enabled filesystem, BPF, sysctl,
mount, local-network, module, and process-residual entries reflect only their
own confirmer; an omitted domain remains `NOT_CONFIRMED`, keyrings remain
`NOT_CONFIRMED`, and remote network effect is `NOT_CONFIRMABLE`. A complete
identical endpoint is still `INCONCLUSIVE`; only a complete observed
difference becomes `CHANGED_WITHIN_SCOPE`. Consumers must keep this vector
intact and must not fold it into “system unchanged” or rollback `CLEAN`.

Use `control` (the CLI default) for the lowest-volume control/metadata signal,
select `balanced` explicitly when file writes and network sends matter, and
select `full` only when the additional write-direction `mmap`/`mprotect`, sync,
`ioctl`, `prctl`, and `setsockopt` interfaces are required. mmap/mprotect calls
without `PROT_WRITE` are rejected before cgroup lookup and event construction.
The exact policy used is
written to `system-effects.policy.json`; never infer coverage from a profile
name alone.
`verify-effects` requires the externally trusted object digest, expected
profile, expected object-resolution mode, and every externally selected
confirmer scope. It verifies the closed operation set plus exactly the declared
extensions: three BPF files, three filesystem files, the optional copied
filesystem actor contract, three Linux-state files, and in expanded mode the
lifecycle WAL/JSONL/health triple. It checks hashes, WAL framing and CRC,
decoded projections, sequence/pairing, frozen policy, lifecycle lineage and
syscall-task correlation, health counters, snapshots, comparisons, and
coverage claims; its successful report
still says `coverage_complete=false`,
`causal_attribution_complete=false`, and
`operation_events_are_state_diff=false`.
See the [full guide](docs/system-effects-observer.md) for artifact semantics,
coverage gaps, inspection commands, and the paired overhead benchmark. The
[current privileged-VM functional validation](docs/system-effects-validation-2026-09-13.md)
records the exact-build object, filesystem, and fail-closed gates. The
[2026-09-12 validation](docs/system-effects-validation-2026-09-12.md) retains
the paired overhead measurements.

To attach the same recorder pair to an already existing direct process tree,
Docker container, or Kata host-side sandbox, use the one-shot
`deployment-observe` adapter. The caller freezes/resumes the discovered roots
around its READY/FINISH protocol; the adapter never invokes a container CLI or
enters a Kata guest. Selected hooks cover dynamic descendants through bounded,
FD-pinned cgroup-v2 ancestor roots. Optional BPF, explicit-path filesystem, and
Linux-state S0/S1 confirmers run only at the frozen barriers; expanded mode also
commits a separately verified socket-state stream. At FINISH it freezes every
producer root, detaches exactly the two asynchronous TCP state/destroy links
once, and only then drains all roots and retires owners. Expanded `COMPLETE`
requires the same complete `2/2` producer seal in every root health record. The
offline verifier replays every enabled WAL and independently recomputes endpoint
comparisons under an exact closed artifact set. Configuration, evidence, and
verification examples are in the
[deployment observer guide](crates/deployment-observer/README.md).

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
- [Observer overhead benchmark](experiments/overhead/README.md)
- [Observer overhead validation](experiments/overhead/VALIDATION.md)
- [System-effect recorder guide](docs/system-effects-observer.md)
- [System-effect recorder overhead benchmark](experiments/system-effects-overhead/README.md)
