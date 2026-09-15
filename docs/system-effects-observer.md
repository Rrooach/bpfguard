# System-effect operation recorder

`observe-effects` records selected native syscall operations performed by one
newly created cgroup. It produces paired entry/result evidence and attributes
it to a run epoch, PID/TGID, cgroup ID, operation domain, and syscall.

The default mode is **operation evidence, not a kernel-state oracle**. A
successful syscall does not prove that durable state changed, and an empty or
complete stream does not prove that the Agent made no system change. Explicit
BPF, filesystem, and Linux-state options enable separate bounded endpoint
confirmers. They do not turn the syscall stream into a state diff, are not
atomic with each other, and never confirm remote state.

The current Linux-first boundary is:

- the two file-only modes cover selected successful opens and selected
  positive-byte native write-family results; the explicit
  `kernel-object-expanded-partial` mode additionally covers selected
  create/link/unlink/rename/chmod/chown/xattr hooks, eligible file-backed shared
  writable mmap establishment, single-VMA shared file-backed mprotect write-
  permission transitions, bind/connect socket requests, accepted TCP peer
  objects, a correlated TCP state stream, and a separate direct-cgroup
  fork/exec/exit stream;
- BPF, generic path-tree filesystem, sysctl, mount, local network, module, and
  exact-cgroup residual-process S0/S1 confirmation are optional and produce
  independent per-domain verdicts;
- a one-shot Direct/Docker/Kata-host deployment adapter exists for already
  frozen targets. Its bounded, FD-pinned cgroup-v2 ancestor filter covers
  dynamic descendants for the selected hooks and reports
  `DYNAMIC_ANCESTOR_COMPLETE`; this does not make lifecycle enrollment complete,
  which remains `PARTIAL` under schema v2;
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
make release system-effects-bpf process-lifecycle-bpf workloads

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
The verifier requires every retained non-root entry to have an immediate
retained directory parent whose traversal could have produced that child. This
closes structural path gaps, but a root-only internally consistent artifact
cannot prove that the live directory was empty: completeness of enumeration
still trusts the capture producer and is not reconstructed from a historical
kernel by offline verification.

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

### Linux endpoint state

`--linux-state-scope PATH` enables protocol-v1 S0/S1 confirmation for any
explicit combination of five bounded domains:

| Domain | Exact scope and source |
|---|---|
| `sysctl` | Sorted explicit keys beneath a bound proc-sys root |
| `mounts` | Parsed mountinfo for one PID-bound mount namespace inode |
| `network` | Selected addresses, routes, rules, qdiscs/classes/filters, and nftables state in one PID-bound network namespace |
| `modules` | All or explicitly selected records from a bound proc-modules file, with optional readable sysfs parameters |
| `process_residual` | A recursively enumerated exact cgroup-v2 tree whose kernfs inode must equal the bound cgroup ID |

Network collection executes only explicitly selected, absolute, singly linked
ELF `ip`, `tc`, and `nft` binaries whose SHA-256 values are part of the
scope. The namespace PID and namespace inode are checked for every capture;
disappearance, PID reuse, tool replacement, parse failure, truncation, timeout,
or a resource limit makes that domain incomplete instead of falling back to the
observer namespace. tc class/filter capture is restricted to the explicitly
listed interfaces.

`--confirm-process-residual` is the safe standalone shortcut: the observer
constructs a recursive residual-process scope from its newly created run
cgroup path and kernel cgroup ID. It rejects a conflicting residual scope in
the supplied file. On verification, repeat both the external scope and the
shortcut:

```text
observe-effects: --linux-state-scope /trusted/linux-state-scope.json \
                 --confirm-process-residual
verify-effects:  --expected-linux-state-scope /trusted/linux-state-scope.json \
                 --confirm-process-residual
```

The extension adds exactly `linux-state-s0.json`,
`linux-state-s1.json`, and `linux-state-comparison.json` to the closed
artifact set. S0 is taken after recorder registration and before workload
launch; S1 is taken after the exact workload cgroup is empty/frozen and both
event streams are drained. The offline verifier reconstructs the effective
scope, validates both bounded snapshots, and recomputes every domain
comparison.

These are endpoint adapters, not durability or causality proofs. Sysctl covers
only listed textual procfs keys; mountinfo does not hash mounted contents;
network excludes conntrack, transient packets, sockets, and remote services;
module state excludes built-ins, firmware, kernel text integrity, and reboot
persistence; residual-process state excludes escaped tasks, daemon work, and
kernel workers. A complete differing endpoint is
`CHANGED_WITHIN_SCOPE`; a complete identical endpoint remains
`INCONCLUSIVE` without authenticated exclusive-writer/quiescence evidence.

### Per-domain verdicts

`observe-effects` and `verify-effects` return a `state_domains` vector, not
one aggregate system-state result:

| Domain | Current standalone result source |
|---|---|
| `filesystem` | Filesystem comparison when enabled; otherwise `NOT_CONFIRMED` |
| `bpf` | BPF comparison when enabled; otherwise `NOT_CONFIRMED` |
| `network_config` | Linux-state network comparison when enabled; otherwise `NOT_CONFIRMED` |
| `sysctl`, `mounts`, `modules`, `process_residual` | Corresponding Linux-state comparison when enabled; otherwise `NOT_CONFIRMED` |
| `keyrings` | `NOT_CONFIRMED` |
| `remote_network_effect` | Always `NOT_CONFIRMABLE` from local endpoint state |

The implemented domains may disagree, and an `INCONCLUSIVE` or
`NOT_CONFIRMED` domain must not be hidden by a change in another domain. No
vector value establishes rollback completeness or turns operation events into
a state diff.

`doctor` is a preflight, not a proof that the complete run will load and
finish; the real load, attach, cgroup, workload, and drain path remains the
authoritative test.

## Object-resolution modes

Three kernel-backed partial modes are implemented. The first two are
file-specific; the third is explicitly named
`kernel-object-expanded-partial` because only enumerated operations receive
hook-derived evidence. There is no generic `kernel` mode.

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

`--object-resolution kernel-object-expanded-partial` preserves both earlier
contracts and adds these operation-specific joins:

| Selected operation | Hook-derived evidence | Deliberate limit |
|---|---|---|
| mkdir/symlink/mknod create families | destination parent `FILE_OBJECT` | the child does not yet exist at the hook |
| link | source `FILE_OBJECT` in the destination mount context | destination identity is not claimed |
| unlink/rmdir | target `FILE_OBJECT` | point-in-time identity only |
| rename | source `FILE_OBJECT` | destination object/parent is not claimed |
| chmod/chown | target `FILE_OBJECT` | no later endpoint-state claim |
| setxattr/removexattr | target `INODE_OBJECT` | inode hook supplies no mount ID |
| eligible mmap | mapped file `FILE_OBJECT` | only file-backed `MAP_SHARED|PROT_WRITE` establishment; not later writes |
| eligible mprotect/pkey_mprotect | mapped file `FILE_OBJECT` | only one shared file-backed VMA gaining `PROT_WRITE`; not a later write; anonymous/private/mixed/multi-VMA ranges are unresolved |
| connect | `SOCKET_OBJECT`, socket/net-namespace cookies, requested peer | pre-operation requested endpoint, not connection completion |
| bind | `SOCKET_OBJECT`, socket/net-namespace cookies, requested local endpoint | the syscall record preserves port zero; a later eligible TCP state event may expose the assigned local endpoint |
| accept/accept4 | accepted `SOCKET_OBJECT` and peer endpoint | AF_INET/AF_INET6 TCP only; resolved after `do_accept`, not from userspace output buffers |

The kernel-copied sockaddr decoder distinguishes IPv4, IPv6, Unix, and bounded
other-family bytes. It is not a post-operation `getsockname` or
`getpeername` snapshot. A separate socket-state WAL records accepted-socket
snapshots plus AF_INET/AF_INET6 TCP state transitions and destroy events,
retaining the syscall-entry identity that established ownership. Socketpair,
send destination state, non-INET/TCP socket state, actual mmap/mprotect dirty-
page activity, anonymous/private/mixed/multi-VMA mprotect resolution,
`io_uring`, and descriptor
transfer through `SCM_RIGHTS` remain unresolved.
At close, the coordinator first proves the complete producer cgroup set
empty/frozen, then synchronously detaches exactly `inet_sock_set_state` and
`tcp_destroy_sock`, and only then drains the shared ring and retires any
remaining socket-cookie owners. The socket-state v2 health and manifest bind a
`2/2` producer seal; expanded `COMPLETE` is impossible without it. The offline
verifier also requires the pre-retirement owner counter to equal the number of
entries retired after detach. It checks that bound attestation and every
persisted event, but cannot re-perform a historical kernel detach.
Every object record is reconstructed from the checksummed WAL; JSON cannot add
a resolved object claim.

Expanded mode also requires a separate, digest-bound
`process_lifecycle.bpf.o`. Its BTF tracepoints record direct-cgroup fork,
successful exec, and exit events with cgroup/epoch, monotonic sequence,
PID/TGID, task start-boottime, parent identity, exec old PID and a bounded
kernel-copied descriptive filename, plus exit code and group-dead state. The
offline verifier independently rebuilds terminal lineage and correlates
syscall task identities by PID/TGID/start-boottime for identities present in
that admitted event stream. It rejects drops, task identity read failures,
truncated WALs, noncanonical JSONL, nonterminal lineage, and unbound syscall
identities. It does not have an authoritative S0 task/thread enrollment ledger,
a cgroup migration hook, or `CLONE_INTO_CGROUP` enrollment coverage. Successful
nonempty lifecycle evidence is therefore always `PARTIAL`; zero admitted
events are `UNPROVEN_NO_EVENTS`, and `COMPLETE` is rejected as an overclaim.
Exec filename truncation downgrades descriptive path quality but is not
executable `FILE_OBJECT` identity.

Collection and verification must receive the lifecycle digest from the same
external trust path used for the system recorder:

```sh
LIFECYCLE_OBJECT=$(realpath .output/process_lifecycle.bpf.o)
TRUSTED_LIFECYCLE_SHA256=$(sha256sum "$LIFECYCLE_OBJECT" | awk '{print $1}')

sudo "$BIN" doctor \
  --recorder-object "$EFFECT_OBJECT" \
  --process-lifecycle-object "$LIFECYCLE_OBJECT" \
  --object-resolution kernel-object-expanded-partial

# Add these to observe-effects:
#   --process-lifecycle-object "$LIFECYCLE_OBJECT"
#   --expected-process-lifecycle-sha256 "$TRUSTED_LIFECYCLE_SHA256"
#   --object-resolution kernel-object-expanded-partial
#
# Add these to verify-effects:
#   --expected-process-lifecycle-sha256 "$TRUSTED_LIFECYCLE_SHA256"
#   --expected-object-resolution kernel-object-expanded-partial
```

`doctor` and `observe-effects` fail closed when the mode prerequisites are
absent. `observe-effects` performs its static gate before creating the output
directory or workload cgroup. The actual libbpf CO-RE load and BPF-LSM attach
are a second gate and complete before the cgroup or workload is created, so a
kernel/verifier rejection is surfaced and cannot silently fall back to
user-input evidence. Capability-schema v2 emits separate machine-readable
`object_resolution.kernel_file_open_partial` and
`object_resolution.kernel_file_open_write_partial` plus
`object_resolution.kernel_object_expanded_partial` prerequisites and
blockers:

```sh
sudo "$BIN" doctor \
  --recorder-object "$EFFECT_OBJECT" \
  --cgroup-root /sys/fs/cgroup/bpf-state-observer-effects \
  --process-lifecycle-object "$LIFECYCLE_OBJECT" \
  --object-resolution kernel-object-expanded-partial
```

Every object LSM hook first rejects threads without a selected pending
operation, then validates resolver kind, exact cgroup, run epoch, and
`attempt_seq` before
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
  `CONFIG_SECURITY=y`; expanded path hooks additionally require
  `CONFIG_SECURITY_PATH=y`;
- `CONFIG_SECURITYFS=y` with securityfs mounted at `/sys/kernel/security`, so
  the active LSM list can be verified rather than assumed;
- `CONFIG_DEBUG_INFO_BTF=y`, a readable nonempty `/sys/kernel/btf/vmlinux`,
  and an active LSM list containing the whole token `bpf` (including after any
  boot-time `lsm=` override);
- CO-RE-visible file/path/inode/mount fields and, for expanded mode, the
  required dentry, socket/sock/net, task, and binprm fields. A missing required
  relocation is a load failure before the workload cgroup is created; there is
  no legacy identity fallback;
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

A `SOCKET_OBJECT` produced in expanded mode contains boot ID, netns cookie,
socket cookie, family, type, and protocol, plus separate local and peer
observations. Endpoint addresses are a closed bounded union of IPv4, IPv6,
Unix, or `OTHER`; Unix and `OTHER` bytes are capped at 128 bytes. The
produced bind/connect endpoint authority is
`KERNEL_COPIED_SOCKADDR_AT_LSM_HOOK`: it comes from the hook's kernel
argument, not the raw-syscall userspace capture, but it remains a
pre-operation request rather than post-operation socket state.
`NOT_REQUESTED` and `UNAVAILABLE` carry no address. Fixed-size IPv4/IPv6
endpoints cannot claim truncation.

## Profiles and cost

Profiles are cumulative:

| Profile | Selected operations | Cost guidance |
|---|---|---|
| `control` | File/path metadata changes; socket creation/connect/bind/listen; mount and namespace controls; BPF/module/perf/ptrace and other kernel controls; credentials, keys, seccomp, quota, Landlock, and async-I/O setup | CLI default; lowest event volume; omits write/send data paths |
| `balanced` | Everything in `control`, plus write/pwrite/writev, allocation and FD-range transfer, and send/sendmsg operations | Appropriate for ordinary Agent effect collection when data-path events are required |
| `full` | Everything in `balanced`, plus fsync/fdatasync, write-direction mmap/mprotect, setsockopt, ioctl, and prctl | Highest and workload-sensitive volume; mmap/mprotect without `PROT_WRITE` are rejected before cgroup/event work |

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

The coordinator loads the exact digest-checked object, and in expanded mode
also the exact digest-checked lifecycle object, freezes the syscall policy Map,
creates and registers a fresh cgroup in both recorders, then starts the
workload in that cgroup. It waits for the complete cgroup process tree to
become empty, freezes the empty cgroup as the producer barrier, synchronously
detaches exactly the two asynchronous TCP-state hooks, then drains/reconciles
every enabled event stream and retires remaining socket owners. It captures
enabled S1 endpoints, fsyncs evidence, and commits the manifest last. Enabled
endpoint S0 snapshots are taken sequentially before launch; their S1 snapshots
are likewise sequential after drain.

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
and every enabled confirmer's external scope. Expanded runs additionally
require the externally trusted lifecycle-object digest. It accepts only a
finalized, transport-complete run. The closed set is the six base artifacts,
plus exactly three BPF artifacts when enabled, exactly three filesystem
artifacts when enabled, the copied actor contract only when declared, exactly
three Linux-state artifacts when enabled, and the lifecycle WAL/JSONL/health
triple in expanded mode. The verifier checks every digest, streams and
cross-checks WAL/JSONL events, enforces sequence and attempt/result pairing,
replays terminal admitted-event process lineage, correlates matching syscall
task identities, and
re-derives the compiled policy. It also validates and recomputes each enabled
endpoint comparison; a stored filesystem contract must exact-match the
external expected file. A successful report still
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
# Expanded mode only:
jq -c '{event_seq, kind, subject, parent, old_pid, group_dead,
        exec_path, exit_code}' "$RUN/process-lifecycle.jsonl"
jq '.domains' "$RUN/linux-state-comparison.json"  # when enabled
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

## Existing-process deployment adapters

The separate `deployment-observe` binary attaches the system-effect and
lifecycle recorder pair to an already existing, caller-frozen target. Its
configuration supports:

- `DIRECT`: a trusted root PID and expected dedicated cgroup;
- `DOCKER`: a full 64-hex container ID, optional trusted init PID, expected
  cgroup, and the container's host-visible namespace identities;
- `KATA_HOST`: a trusted shim PID plus expected hypervisor and optional
  backend PIDs. Discovery records target-Linux runtime/QEMU/virtiofs identities
  and QEMU-derived disk, block, TAP, and network-backend resources. It does not
  enter the Kata guest or claim guest syscalls.

The adapter does not call Docker, containerd, or Kata CLIs. The external
harness freezes every discovered root before startup, waits for the bounded
`READY` record, resumes the target, freezes it again, and returns the exact
`FINISH` nonce. READY and FINISH revalidate PID start time, executable,
cgroup, mount/PID/network namespace, and freeze identities. One system recorder
and one lifecycle recorder serve a bounded set of FD-pinned cgroup-v2 ancestor
roots under the same epoch. Every selected hook uses
`bpf_current_task_under_cgroup`, so dynamic and ephemeral descendants remain in
scope. Optional BPF, explicit-path filesystem, and Linux endpoint state are
captured only at the frozen S0/S1 barriers. Expanded object mode also commits a
separate socket-state WAL/JSONL/health tuple. Offline
`deployment-observe-verify` replays all enabled streams, recomputes every
S0/S1 comparison, and enforces the exact closed artifact set.

This establishes direct-caller observation for the selected hooks, not general
causality through host daemons or remote services. BPF inventory is host-global
within its explicit claim scope and cannot exclude unrelated host BPF actors;
filesystem confirmation is limited to explicit paths in the observer's mount
view. Kata virtual-disk discovery is never treated as authorization to scan an
image. See the
[deployment observer guide](../crates/deployment-observer/README.md) for its
configuration and protocol.

## Strict interpretation boundary

Even with `run_status=FINALIZED` and `transport_status=COMPLETE`, coverage is
always `PARTIAL` in v1:

- attribution covers selected native-ABI syscalls in one exact cgroup, not all
  kernel mutation paths;
- compat/x32 calls, `clone`/`clone3` namespace creation, shared-memory writes,
  decoded io_uring operations, and delayed kernel-worker/writeback/softirq
  effects are outside the causal model;
- expanded mode resolves only its explicit file/path/inode/mmap/socket hook
  matrix. Create child and rename destination identity, non-INET/TCP state,
  socketpair/send destinations, other FD targets, multi-VMA/private/anonymous
  mprotect, and many ioctl/netlink targets remain unresolved;
- the fork/exec/exit stream has no authoritative S0 task/thread enrollment or
  cgroup-entry stream. It cannot prove that every task in the observed subtree
  was enrolled, so its machine-readable status never exceeds `PARTIAL`;
- mmap evidence proves only establishment of an eligible file-backed shared
  writable mapping, and mprotect evidence only establishes a write-permission
  channel for one shared file-backed VMA—not a later memory write. `io_uring` requests, descriptor
  transfer through `SCM_RIGHTS`, delegated daemon effects, and
  kernel-worker/writeback causality remain outside the object contract;
- ioctl and netlink payload semantics are not decoded;
- syscall success is not a durable before/after state comparison, and transient
  create/modify/restore/delete sequences are only as visible as the selected
  operations;
- an enabled filesystem confirmer covers only its explicit bounded path-tree
  field model. Its two walks are non-atomic, and its actor/quiescence contract
  is unauthenticated external input from the observer's perspective;
- enabled Linux-state confirmers cover only explicit keys, namespaces,
  collectors, modules, and cgroup trees. Identical complete endpoints remain
  `INCONCLUSIVE`, and remote effects remain `NOT_CONFIRMABLE`;
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
attempt, which enumerated kernel objects were observed at their hooks, what did
those syscalls return, and which explicitly scoped endpoints differ?” It cannot
answer “what is the complete final kernel diff?”, “was rollback complete?”, or
“nothing changed.”

## Measure overhead

The paired four-arm benchmark separates attached-but-quiet cost from the
incremental full-pipeline cost of persisted effect events. Its Observer adapter
validates lossless health and counts both WAL and JSONL bytes. Keep
`user-input`/file-only and expanded batches separate: the expanded batch also
counts lifecycle evidence and requires the lifecycle object and digest.
Endpoint confirmers run only at S0/S1, so their cost is barrier latency and
evidence I/O rather than per-syscall hook cost.

```sh
export BPF_STATE_OBSERVER_BIN="$BIN"
export BPF_STATE_OBSERVER_EFFECTS_OBJECT="$EFFECT_OBJECT"
export BPF_STATE_OBSERVER_EFFECTS_SHA256="$TRUSTED_EFFECT_SHA256"
export BPF_STATE_OBSERVER_EFFECTS_PROFILE=balanced
# For a separate expanded-mode batch:
# export BPF_STATE_OBSERVER_EFFECTS_OBJECT_RESOLUTION=kernel-object-expanded-partial
# export BPF_STATE_OBSERVER_LIFECYCLE_OBJECT="$LIFECYCLE_OBJECT"
# export BPF_STATE_OBSERVER_LIFECYCLE_SHA256="$TRUSTED_LIFECYCLE_SHA256"

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
That historical record must not be presented as a measurement of the newer
expanded object/lifecycle mode. `make system-effects-overhead-check` also runs
the static instruction-budget guard for the expanded path/xattr/socket/mmap and
lifecycle hooks; it is a regression gate, not a runtime overhead percentage.
