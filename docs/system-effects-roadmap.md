# Linux-first system-effects roadmap

This document separates the shipped Linux-first standalone baseline from
planned work. An unchecked item, a protocol type with no runtime integration,
or a future adapter does not expand the claims made by current manifests or
verifiers.

## Current standalone baseline

- `observe-effects` records selected native syscall attempts/results from one
  exact cgroup. The stream is operation history, not a state diff.
- Kernel object resolution is limited to successful selected file opens with
  exactly one `file_open` join and, in
  `kernel-file-open-write-partial`, positive-byte selected native write-family
  results with the required `file_permission` join. Missing required joins,
  `O_PATH`, and duplicate stacked-filesystem open hooks fail evidence closed.
  No general VFS, socket, or delegated-service resolver exists.
- Optional BPF-object and bounded generic filesystem path-tree confirmers
  capture S0/S1 and report independent entries in `state_domains`. Their
  captures are sequential and there is no aggregate whole-system verdict.
- The delegation module supplies a bounded ledger schema and structural
  validator only. No broker, signer/authenticator, helper lifecycle, CLI or
  manifest integration, or runtime causal chain exists.
- The launcher does not isolate workload credentials or evidence writes. Its
  claims are cooperative unless an outer launcher supplies and enforces those
  boundaries.

The core implementation must remain independent of Agent frameworks and
sandbox products. A trusted Linux runner owns one workload lifecycle:

```text
create run cgroup
  -> load recorder and register the exact cgroup
  -> capture each enabled confirmer's S0 sequentially
  -> fork; child enters the cgroup in pre-exec
  -> exec workload only after the cgroup barrier
  -> drain operation evidence
  -> require the complete cgroup empty/frozen
  -> capture each enabled confirmer's S1 sequentially
  -> finalize a closed artifact set
```

The standalone launcher does not need a `SIGSTOP` window: the recorder is
registered before `fork`, and the child joins the already-registered cgroup in
the pre-exec hook before the workload image exists. A future broker helper
would need a different lifecycle, including remaining stopped until its
per-request cgroup had been registered; no such broker lifecycle is present
today.

Allox or another runtime may later drive this contract, but must not become an
assumption inside the recorder, object resolver, state confirmer, or offline
verifier.

## Current partial object resolution and next steps

The two kernel-backed modes are intentionally named for their exact limits.
`kernel-file-open-partial` resolves selected successful native opens through
exactly one BPF LSM `file_open` join. `O_PATH` is currently unsupported because
its disposition is not captured in the replay ABI; a missing join fails
evidence closed. Stacked/re-entrant duplicate open hooks are also fatal rather
than guessing which object is syscall-visible.
`kernel-file-open-write-partial` preserves that open-only behavior and adds event-time
`file_permission(MAY_WRITE)` VFS `struct file` identity for positive-byte
selected native write-family results. Pipefs/socketfs pseudo-files are valid
FILE_OBJECT identities but do not establish socket endpoints or persistence.
Every positive-byte result in the selected native write family requires that
join; its absence is a transport-integrity failure. Unselected paths such as
mmap and io_uring remain coverage gaps. The hook is non-sleepable, so it
records an event-time kernel-derived mount/device/inode tuple with path quality
`NOT_REQUESTED`; optional inode generation means this does not exclude inode
reuse. Kernel path snapshots remain available only from `file_open`. The 328-byte WAL
`FILE_OBJECT` frame, strict
attempt/result join, capability-schema-v2 preflight, and offline reconstruction
are implemented. Missing, ambiguous, or forged joins fail verification.
Userspace FD lookup is not authoritative evidence.

Reading a target process's descriptor from userspace can enrich evidence, but
it has several distinct authority levels:

| Mechanism | Useful result | Required limitation |
|---|---|---|
| `/proc/<pid>/fd/<n>` and `fdinfo` | path display, mount ID, flags, socket inode hints | diagnostic snapshot only; PID/FD close and reuse races remain |
| `pidfd_open` + `pidfd_getfd` + `fstat/statx` | duplicate the descriptor that exists at lookup time and inspect its object | ptrace-style permission checks apply; a later lookup does not prove which object an earlier syscall used |
| fanotify event FD/FID | filesystem object reference for supported marked filesystems and event classes | not a general syscall correlator and does not cover every FD, rename, mmap, io_uring, or socket effect |
| seccomp user notification or ptrace stop | synchronously inspect selected input descriptors while the task is blocked | mediation changes the execution model and has much higher per-syscall overhead |
| BPF LSM/VFS hook | object used by the kernel at the hook point | requires BTF/hook availability and operation-specific correlation |

The current event protocol emits only `KERNEL_RESOLVED`,
`USER_INPUT_ONLY`, or `UNRESOLVED`. Future enrichment may add blocked or
racy userspace evidence, but lower levels must never be silently promoted:

```text
KERNEL_RESOLVED
USERSPACE_BLOCKED_RESOLVED
USERSPACE_RACY_SNAPSHOT
USER_INPUT_ONLY
UNRESOLVED
```

- [x] Keep `kernel-file-open-partial` and
      `kernel-file-open-write-partial` explicit, fail-closed, and independently
      verified.
- [x] Bind the selected mode into the run manifest and require the same
      externally selected mode during `verify-effects`.
- [ ] Bind the complete capability report, required kernel features, and hook
      ABI into an authenticated control transcript.
- [ ] Add operation-specific object hooks for create, unlink, rename, and
      setattr; record explicit gaps for mmap and io_uring writes.
- [ ] Add socket cookie, network-namespace identity, and kernel-derived
      bind/connect/accept endpoint evidence.
- [ ] Use pidfds for process lifetime and userspace enrichment, but label every
      asynchronous lookup `USERSPACE_RACY_SNAPSHOT`.
- [x] Reject missing required object evidence and JSON/WAL substitutions in the
      independent verifier.
- [x] Filter by selected operation and exact cgroup before object/path work,
      retain fixed bounds, and fail evidence completeness on any loss.

## Current endpoint confirmers and remaining domains

Operation history and endpoint state are separate outputs. Each confirmer
must bind an externally trusted scope, S0, its own quiescence requirements, S1,
canonical comparison, completeness, and independent offline verification.

- [x] Integrate the existing BPF S0/S1 confirmer without turning a BPF-domain
      result into whole-system state. In standalone effects mode it may confirm
      a delta, but it never authorizes BPF `UNCHANGED_WITHIN_SCOPE`.
- [x] Implement a bounded generic filesystem path-tree v1 confirmer with
      explicit exact-byte roots, metadata plus optional content/symlink/xattr
      capture, resource limits, typed comparison, closed artifacts, and strict
      offline recomputation.
- [x] Publish a per-domain vector for filesystem, BPF, local network
      configuration, sysctl, mounts, modules, keyrings, and remote network
      effect. Unimplemented local domains remain `NOT_CONFIRMED`; remote
      network effect remains `NOT_CONFIRMABLE`.
- [ ] Implement a Btrfs confirmer for one declared workspace subvolume,
      including content, metadata, xattrs, link topology, rename, and deletion.
- [ ] Hash only the changed set derived from the filesystem-native comparison;
      do not recursively hash the entire Guest root on every run.
- [ ] Keep shared directories and external mounts as separate explicit scopes.
- [ ] Add separate local-network-configuration, sysctl, mount, module, and
      other narrowly defined adapters only where state can be enumerated.
- [ ] Treat remote network effects as an enforced-egress ledger or signed
      remote receipt, never as a locally provable final-state diff.
- [x] Keep per-domain verdict, state completeness, endpoint difference,
      actor-contract status, and causal status as independent axes.

The filesystem comparer reports `CHANGED_WITHIN_SCOPE` when complete,
same-environment S0/S1 captures contain a typed endpoint difference, while
keeping causal attribution `NOT_ESTABLISHED`. Identical captures remain
`INCONCLUSIVE`. The static v1 actor contract only validates and exact-matches
caller JSON; even all-true booleans become `ASSERTED_NOT_AUTHENTICATED` and
cannot authorize `UNCHANGED_WITHIN_SCOPE`. It has no signature or freshness,
does not verify `evidence_sha256`, and does not bind boot/cgroup/barrier proof.

Required negative tests include ephemeral create/delete, modify/restore,
external concurrent actors, scope narrowing, snapshot substitution,
truncation, budget exhaustion, and incomplete quiescence. An empty diff may
become `UNCHANGED_WITHIN_SCOPE` only under a future authenticated, fresh,
exact-domain exclusive/quiescence contract.

## Delegation protocol/validator only; broker runtime TODO

Direct attribution v1 remains unchanged: it proves only that the selected
native syscall caller belonged to the exact cgroup at syscall entry.

`crates/system-effects-recorder/src/delegation.rs` now defines a bounded
protocol-v1 ledger and `validate_against`. The validator checks external run
bindings, request IDs and ordering, TTLs, parent/helper cgroup linkage,
`ACCEPTED -> REGISTERED -> STARTED -> COMPLETED/FAILED` transitions, nesting
depth, and an empty/frozen zero-outstanding closure. This is structural
validation, not production or authentication. No current CLI command creates
or consumes the ledger, and `verify-effects` does not accept it in the closed
artifact set.

- [x] Define fields for one unique request ID per brokered operation and bind
      its
      boot ID, run ID/epoch, source cgroup, adapter/version, operation,
      canonical argument digest, sequence, expiry, and optional parent.
- [ ] Implement request generation and keep signing capability outside the
      workload; authenticate and reject replay, cross-run,
      expired, wrong-adapter, and argument-substitution attempts.
- [ ] Prefer one stopped helper and one sealed request cgroup per operation.
      Register that cgroup before resume and require it empty/frozen at finish.
- [x] Structurally validate the closed
      `ACCEPTED -> REGISTERED -> STARTED -> COMPLETED/FAILED` sequence.
- [ ] Authenticate the delegation ledger and bind its digest into the run
      manifest and verifier's closed artifact set.
- [x] Limit the protocol claim enum to
      `BROKER_REQUEST_EXECUTION_CHAIN_ESTABLISHED`; do not claim Agent
      intent, necessity, remote outcome, or generic `CAUSAL_ESTABLISHED`.
- [x] Validate explicit parent linkage, maximum depth, and child lifetime
      containment for nested ledger records.
- [ ] Make real asynchronous work remain represented by a registered child
      request until actual completion.
- [x] Require a structurally validated ledger closure with zero outstanding
      request, token, helper, and request-cgroup state.
- [ ] Implement a broker that actually enforces and produces that closure.
- [ ] Never attribute an unbrokered daemon syscall to the workload. Long-lived
      D-Bus, systemd, netlink, and thread-pool services require explicit
      adapters that propagate context to the actual worker; otherwise record
      only that a request was delivered.
- [ ] Cover forgery, replay, expiry, concurrent cross-talk, cgroup-ID reuse,
      adapter/helper crash, async leftovers, and bypass attempts in a
      privileged VM.
- [ ] Reuse the current WAL cgroup ID for userspace ledger correlation where
      possible so direct-only BPF hot-path cost does not increase.

The intended causal vocabulary remains:

```text
DIRECT_CALLER_ESTABLISHED
BROKER_REQUEST_EXECUTION_CHAIN_ESTABLISHED
CAUSAL_NOT_ESTABLISHED
```

The current runtime emits only direct exact-cgroup attribution with
`CAUSAL_NOT_ESTABLISHED`. Merely constructing a ledger that passes the
validator does not establish
`BROKER_REQUEST_EXECUTION_CHAIN_ESTABLISHED`; that requires the still-missing
authenticated broker, helper-cgroup execution, recorder integration, closure,
and manifest binding.

## Standalone boundary and later adapters

The Linux runner can provide useful, framework-independent evidence now, but
its claim remains cooperative unless an external launcher isolates workload
credentials and the evidence directory. Empty/frozen closes only the direct
run cgroup; it does not close host daemons, external actors, kernel workers,
writeback, or delayed asynchronous effects.

The coordinator's mode-`0700` output directory is a collision/permissions
default, not evidence isolation from a workload that inherits the same identity
or capabilities. The manifest deliberately keeps
`workload_privilege_isolation_enforced=false` and
`evidence_write_isolation_enforced=false`. Filesystem-scope/output overlap
checks keep observer artifacts out of the selected tree but do not change that
threat boundary.

Runtime integrations should supply lifecycle, policy, and sandbox enforcement
around the stable Linux contract. They must not reinterpret an empty event
stream as no system change or upgrade direct attribution to causality.
