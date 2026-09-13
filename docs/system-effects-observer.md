# System-effect operation recorder

`observe-effects` records selected native syscall operations performed by one
newly created cgroup. It produces paired entry/result evidence and attributes
it to a run epoch, PID/TGID, cgroup ID, operation domain, and syscall.

The default mode is **operation evidence, not a kernel-state oracle**. A
successful syscall does not prove that durable state changed, and an empty or
complete stream does not prove that the Agent made no system change. Explicit
`--bpf-state-scope` and `--filesystem-state-scope` options enable separate
BPF-object and bounded filesystem path-tree endpoint confirmers. They do not
turn the syscall stream into a state diff, are not atomic with each other, and
do not confirm network, sysctl, mount, module, keyring, or remote state.

The current Linux-first boundary is:

- kernel object identity is implemented only for selected successful opens
  with exactly one `file_open` join and, in the stronger mode, positive-byte
  selected native write-family results with their required `file_permission`
  join; missing/duplicate joins fail evidence closed;
- BPF and generic path-tree filesystem S0/S1 confirmation are optional and
  produce independent per-domain verdicts;
- delegation consists only of a library protocol/schema and structural
  validator. There is no broker, signature check, helper runtime, manifest
  integration, or established broker-to-syscall causal chain.

Remaining object-resolution, domain-confirmation, and delegated-attribution
work is tracked in the
[system-effects roadmap](system-effects-roadmap.md).

## Build and run

Use a dedicated/disposable VM with cgroup v2 and sufficient privilege to load
and attach eBPF programs. The output directory must not already exist. The
standalone launcher inherits its caller's credentials; if the workload is not
cooperative, an external sandbox must also drop its privilege and make the
output tree inaccessible to it. The observer creates the run directory with
mode `0700`, but that does not isolate it from a workload running with the same
UID or capabilities. Standalone manifests deliberately keep both isolation
claims false.

```sh
make release system-effects-bpf workloads

BIN=$(realpath .output/cargo-target/release/bpf-state-observer)
EFFECT_OBJECT=$(realpath .output/system_effects.bpf.o)

# Suitable only for a local smoke test. In a real deployment, provision this
# value from a trusted build manifest instead of deriving trust from the file
# that is about to be loaded.
TRUSTED_EFFECT_SHA256=$(sha256sum "$EFFECT_OBJECT" | awk '{print $1}')

sudo "$BIN" doctor \
  --recorder-object "$EFFECT_OBJECT" \
  --cgroup-root /sys/fs/cgroup/bpf-state-observer-effects \
  --object-resolution user-input

sudo "$BIN" observe-effects \
  --recorder-object "$EFFECT_OBJECT" \
  --expected-recorder-sha256 "$TRUSTED_EFFECT_SHA256" \
  --output-dir /var/lib/bpf-observer/effects/smoke-1 \
  --run-id effects-smoke-1 \
  --run-epoch 1 \
  --profile balanced \
  --object-resolution user-input \
  --timeout-ms 30000 \
  --drain-timeout-ms 5000 \
  -- \
  .output/workloads/system-effects-smoke /tmp/system-effects-smoke-1

sudo "$BIN" verify-effects \
  --run-dir /var/lib/bpf-observer/effects/smoke-1 \
  --expected-recorder-sha256 "$TRUSTED_EFFECT_SHA256" \
  --expected-profile balanced \
  --expected-object-resolution user-input
```

## Optional endpoint confirmation

### BPF object state

To confirm final BPF object state as a separate layer, pass an explicit
`ClaimScope`:

```sh
sudo "$BIN" observe-effects \
  --recorder-object "$EFFECT_OBJECT" \
  --expected-recorder-sha256 "$TRUSTED_EFFECT_SHA256" \
  --output-dir /var/lib/bpf-observer/effects/smoke-bpf-state \
  --run-id effects-smoke-bpf-state \
  --profile control \
  --bpf-state-scope config/default-scope.json \
  -- \
  .output/workloads/system-effects-smoke /tmp/system-effects-smoke-state

sudo "$BIN" verify-effects \
  --run-dir /var/lib/bpf-observer/effects/smoke-bpf-state \
  --expected-recorder-sha256 "$TRUSTED_EFFECT_SHA256" \
  --expected-profile control \
  --expected-object-resolution user-input \
  --expected-bpf-state-scope config/default-scope.json
```

The recorder is loaded first and all of its program, Map, and Link IDs are
excluded from both snapshots. S0 is captured before the workload starts. S1 is
captured only after the complete workload cgroup is empty and frozen, while
the recorder and its exclusions are still alive. The optional files are:

| File | Meaning |
|---|---|
| `bpf-state-s0.json` | Scoped BPF object state before workload execution |
| `bpf-state-s1.json` | Scoped BPF object state after the empty/frozen cgroup barrier |
| `bpf-state-verdict.json` | Comparator result for those endpoints |

Their hashes and exact scope/exclusion/verdict summary are committed by
`system-effects.manifest.json`. Enabling BPF confirmation adds exactly these
three files to the six base artifacts and can be composed with the independent
filesystem extension below. `verify-effects` requires the BPF scope again
from an external trust path, validates both snapshots, and recomputes the
verdict. This prevents removing the confirmation or substituting a narrower
self-declared scope during offline verification.

Standalone `observe-effects` does not have the authenticated `exclusive-vm-v1`
contract or the dedicated `BPF_USER_SYSCALL` evidence-health contract. It can
therefore confirm a visible final BPF delta as `CHANGED_WITHIN_SCOPE`, but an
empty diff remains `INCONCLUSIVE`; this path deliberately cannot issue
`UNCHANGED_WITHIN_SCOPE`.

### Filesystem path-tree state

`--filesystem-state-scope` enables the bounded generic path-tree v1
confirmer. The
[`filesystem-scope.example.json`](../config/filesystem-scope.example.json)
scope selects
`/tmp/bpf-observer-workspace` by exact pathname bytes and requests
regular-file content hashes, symlink target bytes, xattr name/value hashes, and
same-device traversal. Create the root before S0 and keep the output directory
outside it:

```sh
FS_SCOPE=$(realpath config/filesystem-scope.example.json)
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
  --filesystem-state-scope "$FS_SCOPE" \
  -- /bin/sh -c "printf '%s\\n' observed > '$FS_ROOT/result.txt'"

sudo "$BIN" verify-effects \
  --run-dir "$RUN_DIR" \
  --expected-recorder-sha256 "$TRUSTED_EFFECT_SHA256" \
  --expected-profile balanced \
  --expected-object-resolution user-input \
  --expected-filesystem-state-scope "$FS_SCOPE"
```

`filesystem-scope-info` validates the scope and prints `scope_sha256`,
`s0_snapshot_id`, and `s1_snapshot_id` for that exact run and epoch. It does
not capture state, create the root, inspect output separation, or establish an
actor contract.

The optional filesystem artifacts are:

| File | Meaning |
|---|---|
| `filesystem-state-s0.json` | Bounded scoped path-tree state before workload execution |
| `filesystem-state-s1.json` | State after transport drain and the empty/frozen cgroup barrier |
| `filesystem-state-comparison.json` | Recomputable endpoint difference, typed changes, completeness, actor status, and filesystem verdict |
| `filesystem-actor-contract.json` | Exact external input copied into the run only when explicitly supplied |

Both snapshots bind the boot ID, mount-namespace inode, exact scope and scope
digest. Capture records exact relative pathname bytes, type, device/inode,
mode, owner, link count, size, mtime/ctime, traversal status, and the fields
selected by the content/symlink/xattr policy. It deliberately omits atime,
statx mount ID, inode generation, birth time, file flags, project ID, and
mount-table state. Resource limits, read errors, unstable reads, a missing
root, or a procfs/sysfs/cgroup/bpffs/debugfs/tracefs/securityfs/configfs root
make the scoped capture incomplete rather than silently narrowing it.

Roots must be non-root absolute paths encoded as canonical lowercase hex,
unique, sorted, and non-overlapping. The coordinator rejects an output
directory that lexically or through its resolved existing ancestors overlaps a
selected root. Filesystem confirmer v1 accepts only
`cross_filesystems=SAME_DEVICE_ONLY`; `INCLUDE` is rejected because nested
pseudo-filesystems cannot yet be classified safely. A nested mount with a
different `st_dev` is excluded and recorded. These pathname checks prevent
ordinary lexical and symbolic-link overlap. They do **not** detect a
pre-existing bind-mount alias, prove mount identity, prevent later mount/path
replacement, or enforce evidence-directory write isolation. Under those
conditions Observer artifacts can still appear as a self-induced state delta.

Filesystem endpoint difference, actor/quiescence authority, and causality are
separate axes:

- complete same-environment differing snapshots expose
  `endpoint_difference=OBSERVED_DIFFERENT`, typed changes, and
  `state_verdict=CHANGED_WITHIN_SCOPE`; this is endpoint-state evidence only,
  and `causal_attribution_status` remains `NOT_ESTABLISHED`;
- complete identical snapshots expose `OBSERVED_IDENTICAL`, but filesystem v1
  always keeps `state_verdict=INCONCLUSIVE`;
- a supplied static contract with matching scope/snapshot bindings and all
  three booleans true is only `ASSERTED_NOT_AUTHENTICATED`, never
  `ESTABLISHED`;
- the observer only validates and copies that JSON. It does not verify a
  signature, authenticate `evidence_sha256`, or enforce any assertion.
  `verify-effects` exact-matches the same caller-supplied file but adds no
  authenticity. Its `evidence_sha256` is not compared with enforcement evidence,
  and the predictable run/snapshot IDs provide no freshness or replay defense;
- therefore filesystem protocol v1 cannot emit or verify
  `UNCHANGED_WITHIN_SCOPE`. A future authenticated contract must bind a fresh
  nonce/expiry, boot ID, exact cgroup ID, scope, and actual S0/S1 barrier
  evidence. The current report marks its trust as
  `EXTERNAL_EXACT_INPUT_NOT_AUTHENTICATED_BY_OBSERVER`.

An external launcher that really enforces those conditions can use
`filesystem-scope-info` to construct its run-bound contract, then add:

```text
observe-effects: --filesystem-actor-contract /trusted/run/actor-contract.json
verify-effects:  --expected-filesystem-actor-contract /trusted/run/actor-contract.json
```

Do not synthesize a true-valued contract: it cannot strengthen the v1 state
verdict. The safe standalone default is to omit it. Add
`--bpf-state-scope config/default-scope.json` and the matching verifier option
to the same run when both implemented confirmers are required. BPF S1 and
filesystem S1 are taken sequentially while the workload cgroup remains
empty/frozen; `atomic_with_other_confirmation_domains=false` is intentional.

### Per-domain verdicts

`observe-effects` and `verify-effects` return a `state_domains` vector, not
one aggregate system-state result:

| Domain | Current standalone result source |
|---|---|
| `filesystem` | Filesystem comparison when enabled; otherwise `NOT_CONFIRMED` |
| `bpf` | BPF comparison when enabled; otherwise `NOT_CONFIRMED` |
| `network_config`, `sysctl`, `mounts`, `modules`, `keyrings` | Always `NOT_CONFIRMED` |
| `remote_network_effect` | Always `NOT_CONFIRMABLE` from local endpoint state |

The two implemented domains may disagree, and an `INCONCLUSIVE` or
`NOT_CONFIRMED` domain must not be hidden by a change in another domain. No
vector value establishes rollback completeness or turns operation events into
a state diff.

`doctor` is a preflight, not a proof that the complete run will load and
finish; the real load, attach, cgroup, workload, and drain path remains the
authoritative test.

## Object-resolution modes

The only kernel-backed modes implemented today are the two file-specific
partial modes below. There is no generic `kernel` mode: rename, unlink,
setattr, other FD operations, socket endpoints, mmap/io_uring, delegated
services, and kernel-worker effects do not acquire authoritative object
identity. A `write(2)` to a pipefs/socketfs pseudo-file can identify that VFS
file, but it is not socket endpoint identity.

`--object-resolution user-input` is the default. It preserves bounded pathname
or sockaddr bytes read from syscall-entry userspace memory. Those bytes are
requests, not the VFS object or socket selected by the kernel, and are
therefore emitted only as `USER_INPUT_ONLY` or `UNRESOLVED`.

`--object-resolution kernel-file-open-partial` is a narrow, explicit opt-in.
For a successful selected native `open`, `openat`, `openat2`, or `creat` result
with exactly one `file_open` join, a sleepable BPF LSM hook records the actual
VFS object as boot-scoped mount/device/inode/generation/superblock identity. It also records
an at-most-127-byte path snapshot with explicit `RESOLVED_AT_HOOK` or
`UNAVAILABLE` quality. `O_PATH` does not traverse this hook and its disposition
is not encoded in the replay ABI, so it is currently unsupported and fails
evidence closed rather than being guessed from a missing join.
Stacked/re-entrant duplicate open hooks are likewise fatal. Failed opens, attempts, rename,
unlink, FD operations, and all socket operations remain `USER_INPUT_ONLY` or
`UNRESOLVED`; this mode is not a general `kernel` resolution claim.

`--object-resolution kernel-file-open-write-partial` preserves that open
contract and additionally resolves the actual `struct file` observed by the
non-sleepable BPF LSM `file_permission` hook with `MAY_WRITE`. It records the
mount/device/inode/generation/superblock identity but deliberately does not
call `bpf_d_path`; write results therefore carry `path.quality=NOT_REQUESTED`.
Coverage is limited to positive-byte results from the selected native `write`,
`pwrite64`, `writev`, `pwritev`, and `pwritev2` syscalls whose VFS `struct file`
reaches `file_permission`, so it requires the `balanced` or `full` profile.
Pipefs/socketfs pseudo-files reached through that hook receive `FILE_OBJECT`
identity, but not a socket endpoint or persistence claim. Every positive-byte
result in this selected native write family requires a `file_permission` join;
a missing hook is a transport-integrity failure, not a partial-coverage
success. Zero-byte and failed writes do not attempt object resolution. No userspace `/proc/<pid>/fd` or
post-event FD lookup is used as authoritative evidence.

`doctor` and `observe-effects` fail closed when the mode prerequisites are
absent. `observe-effects` performs its static gate before creating the output
directory or workload cgroup. The actual libbpf CO-RE load and BPF-LSM attach
are a second gate and complete before the cgroup or workload is created, so a
kernel/verifier rejection is surfaced and cannot silently fall back to
user-input evidence. Capability-schema v2 emits separate machine-readable
`object_resolution.kernel_file_open_partial` and
`object_resolution.kernel_file_open_write_partial` prerequisites and
blockers:

```sh
sudo "$BIN" doctor \
  --recorder-object "$EFFECT_OBJECT" \
  --cgroup-root /sys/fs/cgroup/bpf-state-observer-effects \
  --object-resolution kernel-file-open-partial
```

Both LSM hooks first reject threads without a selected pending operation; they
then validate resolver kind, exact cgroup, run epoch, and `attempt_seq` before
reading file or path fields. An absent, duplicate, mismatched, or undeletable
join yields only an `UNRESOLVED` diagnostic result, makes transport incomplete,
and prevents normal finalization; it is never replaced with an FD-number guess.
`--allow-incomplete-transport` can retain such evidence for diagnosis but never
upgrades it. CO-RE relocations are used for every kernel structure
field; there are no hard-coded structure offsets.
`user-input` disables autoload for the LSM program and its alternate exit
program and disables autocreation of the object-only Maps, preserving the
default raw-syscall path and its cost.

The kernel gate requires at least:

- `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`,
  `CONFIG_BPF_EVENTS=y`, `CONFIG_BPF_LSM=y`, `CONFIG_CGROUPS=y`, and
  `CONFIG_SECURITY=y`;
- `CONFIG_SECURITYFS=y` with securityfs mounted at `/sys/kernel/security`, so
  the active LSM list can be verified rather than assumed;
- `CONFIG_DEBUG_INFO_BTF=y`, a readable nonempty `/sys/kernel/btf/vmlinux`,
  and an active LSM list containing the whole token `bpf` (including after any
  boot-time `lsm=` override);
- CO-RE-visible fields including `struct file.f_path`,
  `struct mount.mnt_id_unique`, and the required inode/superblock identity
  fields. A missing `mnt_id_unique` relocation is a load failure before the
  workload cgroup is created; there is no legacy mount-ID fallback;
- one attested recorder hook ABI, an authoritative binary WAL record ABI for
  the resolved evidence, userspace attempt/result joining, and strict offline
  verifier reconstruction of the same claim.

The standard disposable VM acceptance kernel may not satisfy this contract if
it lacks BTF or an active BPF LSM; in that case the
trustworthy result is a refused partial-kernel mode, never an automatic
upgrade or downgrade. A dedicated validation kernel must enable the listed
settings and expose an active `bpf` token in `/sys/kernel/security/lsm`.

Object-identity protocol version 1 defines the complete result-side shape. A
`FILE_OBJECT` contains the boot-scoped unique mount ID,
device, inode, optional inode generation, superblock magic/class, plus a
separate bounded path observation. Path quality's closed schema vocabulary
reserves `NOT_REQUESTED`, `RESOLVED_AT_HOOK`, `TRUNCATED_AT_HOOK`,
`UNAVAILABLE`, and `UNSTABLE_AT_HOOK`. The current attested producer/verifier
contract permits only `RESOLVED_AT_HOOK` with 1..=127 bytes or `UNAVAILABLE`
on `file_open`, and only `NOT_REQUESTED` on `file_permission`; it rejects the
reserved variants for those operations. The closed schema allows a future
producer up to 512 bytes, and its `RESOLVED_AT_HOOK`, `TRUNCATED_AT_HOOK`, and
`UNSTABLE_AT_HOOK` variants may carry canonical raw hex, a derived display
string, and authority `KERNEL_PATH_SNAPSHOT`. Among frames emitted by the
current attested hook ABI, only `RESOLVED_AT_HOOK` carries that payload and
authority. It is descriptive point-in-time evidence and is separate from the
event-time kernel-derived object tuple. `NOT_REQUESTED` and `UNAVAILABLE`
carry no path payload and have authority `NONE`.
The producer includes inode generation only when the kernel field is nonzero;
zero is represented as absent rather than asserted as a meaningful filesystem
generation.

A `SOCKET_OBJECT` is a validated but currently unproduced protocol variant. It
contains boot ID, netns cookie, socket cookie, family, type, and protocol, plus
separate local and peer observations. Endpoint addresses
are a closed bounded union of IPv4, IPv6, Unix, or `OTHER`; Unix and `OTHER`
bytes are capped at 128 bytes. A populated endpoint must have authority
`KERNEL_SOCKET_STATE`. `NOT_REQUESTED` and `UNAVAILABLE` carry no address.
Fixed-size IPv4/IPv6 endpoints cannot claim truncation. In particular, the
sockaddr copied from userspace at syscall entry can never populate these
fields, even if it happens to match a later peer endpoint.

## Profiles and cost

Profiles are cumulative:

| Profile | Selected operations | Cost guidance |
|---|---|---|
| `control` | File/path metadata changes; socket creation/connect/bind/listen; mount and namespace controls; BPF/module/perf/ptrace and other kernel controls; credentials, keys, seccomp, quota, Landlock, and async-I/O setup | CLI default; lowest event volume; omits write/send data paths |
| `balanced` | Everything in `control`, plus write/pwrite/writev, allocation and FD-range transfer, and send/sendmsg operations | Appropriate for ordinary Agent effect collection when data-path events are required |
| `full` | Everything in `balanced`, plus fsync/fdatasync, mmap/mprotect, setsockopt, ioctl, and prctl | Highest and workload-sensitive volume; use only when required |

The generated `system-effects.policy.json` is authoritative. In particular,
`openat` is filtered in the kernel to create/truncate/tmpfile flags, while
`openat2` is recorded as an open request because its `open_how` pointer is not
decoded.

Both raw-syscall tracepoints are globally attached. An unselected syscall pays
one array-Map policy lookup on entry and one on exit. Cgroup lookup, pending
call state, bounded user-memory capture, and ring-buffer publication occur only
for selected calls; calls outside a registered run stop after the cgroup
lookup. Result records and attempts without captured arguments use the compact
record format. Path and sockaddr attempts capture at most 96 bytes per slot;
write buffers are never copied.

Choose the narrowest profile that answers the experiment question. The CLI
defaults to `control`; `balanced` and `full` are explicit opt-ins. Do not
compare profile timings as though they observed the same event set, and do not
enable `full` merely to maximize nominal coverage.

## Lifecycle and artifacts

The coordinator loads the exact digest-checked object, freezes its syscall
policy Map, creates and registers a fresh cgroup, then starts the workload in
that cgroup. It waits for the complete cgroup process tree to become empty,
freezes the empty cgroup as the producer barrier, drains and reconciles the
recorder, captures enabled S1 endpoints, fsyncs evidence, and commits the
manifest last. Enabled BPF/filesystem S0 snapshots are taken sequentially
before launch; their S1 snapshots are likewise sequential after drain.

A finalized operation-only output contains the manifest commit record and six
manifest-bound base artifacts:

| File | Meaning |
|---|---|
| `system-effects.manifest.json` | Run identity, workload exit, coverage limits, artifact hashes/sizes, and final commit status |
| `system-effects.policy.json` | Exact syscall/domain/operation/capture/filter policy and policy digest |
| `system-effects.health.json` | Attempt/result accounting, drops, pending state, capture failures, drain barrier, queue telemetry, and transport status |
| `system-effects.raw.bin` | Framed, checksummed binary WAL used as primary event evidence |
| `system-effects.jsonl` | Derived, line-oriented decoded attempt/result stream |
| `workload.stdout`, `workload.stderr` | Bounded workload output streams |

The manifest records
`coverage.workload_privilege_isolation_enforced=false` and
`coverage.evidence_write_isolation_enforced=false`. These values describe the
standalone coordinator itself and remain false even when an outer VM launcher
adds isolation. `verify-effects` requires those flags and the corresponding
coverage gap instead of accepting an overstated standalone claim.

`verify-effects` is intentionally strict: the caller must supply the trusted
recorder-object SHA-256, expected profile, expected object-resolution mode,
and every enabled confirmer's external scope. It accepts only a finalized,
transport-complete run. The closed set is the six base artifacts, plus exactly
three BPF artifacts when enabled, exactly three filesystem artifacts when
enabled, and the copied actor contract only when declared. The verifier checks
every digest, streams and cross-checks WAL/JSONL events, enforces sequence and
attempt/result pairing, and re-derives the compiled policy. It also validates
and recomputes each enabled endpoint comparison; a stored filesystem contract
must exact-match the external expected file. A successful report still
contains `coverage_complete=false`, `causal_attribution_complete=false`, and
`operation_events_are_state_diff=false`.

For a quick inspection:

```sh
RUN=/var/lib/bpf-observer/effects/smoke-1
jq '{run_status, transport_status, coverage}' \
  "$RUN/system-effects.manifest.json"
jq '{transport_status, operation_attempted, operation_completed,
     events_persisted, event_dropped, pending_remaining,
     producer_barrier_complete, drain_completed, coverage_gaps}' \
  "$RUN/system-effects.health.json"
jq -c '{event_seq, kind, domain, operation, syscall_name,
        result_status, return_value, captures, object_resolution, semantics}' \
  "$RUN/system-effects.jsonl"
```

An `OPERATION_ATTEMPT` carries arguments and optional bounded captures. Its
paired `OPERATION_RESULT` references `related_attempt_seq` and reports success,
error, restart, or asynchronous-pending status. Every decoded event states
`OBSERVED_OPERATION_NOT_PROOF_OF_DURABLE_STATE_CHANGE`.

The additive object-identity protocol preserves the original 152-byte compact
and 344-byte capture frames and adds one canonical 328-byte `FILE_OBJECT`
result frame. `object_resolution.source_event_seq` identifies the record
carrying the annotation and `operation_attempt_seq` joins an attempt/result
pair. In `user-input` mode the implementation emits only:

- `USER_INPUT_ONLY` with authority `SYSCALL_ENTRY_USER_MEMORY` when a bounded
  path or sockaddr capture succeeded (including explicitly truncated input);
- `UNRESOLVED` with authority `NONE` otherwise, including every result record.

In `kernel-file-open-partial` mode, eligible successful result records can
instead carry one `FILE_OBJECT`; eligible failures remain `UNRESOLVED` and are
counted separately in health. Missing/ambiguous joins, failed object reads, or
failed object-Map cleanup make transport evidence incomplete rather than
silently producing a weaker result. The offline verifier requires the
externally supplied expected mode, derives the complete object-resolution
block independently from the WAL, reproduces all object counters, and rejects
a JSON-only resolved claim. `SOCKET_OBJECT` remains unproduced. User strings,
file descriptors, raw kernel pointers, and requested socket addresses are
never accepted as kernel-resolved identities.

In `kernel-file-open-write-partial` mode the same 328-byte frame is emitted for
positive-byte selected write-family results observed by `file_permission`.
The frozen BPF policy
carries a fixed resolver selector into the per-thread pending record;
`file_permission(MAY_WRITE)` stores one bounded `FILE_OBJECT` joined to that
exact attempt. Because this LSM hook is non-sleepable, its frame contains
an event-time kernel-derived mount/device/inode tuple with
`path.quality=NOT_REQUESTED`; only the sleepable `file_open` hook renders a
kernel path snapshot. Inode generation is optional, so this tuple does not
exclude inode reuse or prove lifetime-stable identity. The independent verifier
recomputes eligibility from the attested operation and externally expected
mode. It rejects object frames on zero-byte, failed, or unrelated results;
positive writes without their required file hook set `JOIN_MISSING`, make
transport incomplete, and cannot verify as a complete run. Their retained
diagnostic result is `UNRESOLVED`, never promoted to file identity. A
pipefs/socketfs FILE_OBJECT is only VFS pseudo-file identity, not
`SOCKET_OBJECT` endpoint evidence.

By default, finalization fails closed unless transport is `COMPLETE`.
`--allow-incomplete-transport` exists only to retain diagnostic artifacts; it
does not upgrade their evidentiary value. `UNPROVEN_NO_EVENTS` means no selected
operation exercised this run's transport and is not a negative result.

## Strict interpretation boundary

Even with `run_status=FINALIZED` and `transport_status=COMPLETE`, coverage is
always `PARTIAL` in v1:

- attribution covers selected native-ABI syscalls in one exact cgroup, not all
  kernel mutation paths;
- compat/x32 calls, `clone`/`clone3` namespace creation, shared-memory writes,
  decoded io_uring operations, and delayed kernel-worker/writeback/softirq
  effects are outside the causal model;
- except for successful selected opens and, in the stronger explicit mode,
  positive-byte selected write-family results, captured paths are user-memory
  snapshots rather than kernel-resolved objects; other FD targets remain
  unresolved;
- mmap/MAP_SHARED writes, io_uring requests, descriptor transfer through
  SCM_RIGHTS, delegated daemon effects, and kernel-worker/writeback causality
  remain outside this object-attribution contract;
- ioctl and netlink payload semantics are not decoded;
- syscall success is not a durable before/after state comparison, and transient
  create/modify/restore/delete sequences are only as visible as the selected
  operations;
- an enabled filesystem confirmer covers only its explicit bounded path-tree
  field model. Its two walks are non-atomic, and its actor/quiescence contract
  is unauthenticated external input from the observer's perspective;
- the delegation module is only a protocol and structural validator. No
  current CLI path starts a broker/helper, signs a ledger, binds one into the
  manifest, or upgrades `causal_attribution_complete`;
- this is for cooperative controlled workloads. A privileged malicious task
  may escape the cgroup, tamper with observable state, or modify evidence under
  the inherited identity; the recorder is not a sandbox or enforcement
  boundary;
- offline verification assumes the evidence directory is no longer being
  concurrently replaced or mount-swapped. It rejects symlink leaves, hard links,
  unexpected files, digest changes, and ordinary metadata races, but v1 does
  not pin every lookup to one directory file descriptor against a hostile
  storage actor.

Consequently, this mode can answer “which selected operations did the Agent
attempt, and what did those syscalls return?” It cannot answer “what is the
complete final kernel diff?”, “was rollback complete?”, or “nothing changed.”

## Measure overhead

The paired four-arm benchmark separates attached-but-quiet cost from the
incremental full-pipeline cost of persisted effect events. Its Observer adapter
uses `balanced`, validates lossless `COMPLETE` health, and counts both the WAL
and JSONL bytes:

```sh
export BPF_STATE_OBSERVER_BIN="$BIN"
export BPF_STATE_OBSERVER_EFFECTS_OBJECT="$EFFECT_OBJECT"
export BPF_STATE_OBSERVER_EFFECTS_SHA256="$TRUSTED_EFFECT_SHA256"
export BPF_STATE_OBSERVER_EFFECTS_PROFILE=balanced

bash experiments/system-effects-overhead/check.sh
# Run the collection command itself as root so direct and observed arms use the
# same privilege level.
sudo --preserve-env=BPF_STATE_OBSERVER_BIN,BPF_STATE_OBSERVER_EFFECTS_OBJECT,BPF_STATE_OBSERVER_EFFECTS_SHA256,BPF_STATE_OBSERVER_EFFECTS_PROFILE \
  bash experiments/system-effects-overhead/run.sh \
  --output /var/lib/system-effects-overhead/run-001 \
  --workload "$(realpath /tmp/system-effects-workload)" \
  --measure "$(realpath /tmp/system-effects-measure)" \
  --observer-wrapper "$(realpath experiments/system-effects-overhead/observer-wrapper.sh)" \
  --scratch-parent /dev/shm \
  --repetitions 12 \
  --iterations 0,256,1024,4096
```

Build the two `/tmp` helpers first as shown in the
[benchmark README](../experiments/system-effects-overhead/README.md), then run
its analyzer. An event count includes both attempt and result records, so the
reported denominator is persisted records, not logical syscalls.

The current-build privileged-VM functional record is
[`system-effects-validation-2026-09-13.md`](system-effects-validation-2026-09-13.md).
The latest 12-block measurement record remains
[`system-effects-validation-2026-09-12.md`](system-effects-validation-2026-09-12.md).
