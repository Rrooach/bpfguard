# Linux-first system-effects roadmap

This document distinguishes shipped, independently verifiable mechanisms from
remaining research gaps. A schema variant, discovered process, or successful
endpoint read does not enlarge the claim beyond the exact contract below.

## Shipped standalone lifecycle

`observe-effects` owns one new cgroup and executes:

```text
load and attest enabled recorders
  -> register the exact cgroup and run epoch
  -> capture enabled S0 endpoints
  -> fork; child joins the cgroup before exec
  -> record operation and optional lifecycle evidence
  -> require the recursive cgroup empty and freeze the boundary
  -> drain and reconcile every enabled recorder
  -> capture enabled S1 endpoints
  -> fsync a closed artifact set and commit the manifest last
```

This core is independent of Agent frameworks, Allox, Docker, and Kata. It is an
observer for cooperative controlled workloads, not a sandbox. The standalone
launcher does not drop workload privilege or isolate the evidence directory;
those coverage flags remain false in its manifest.

## Object-level operation evidence

Four modes are externally selected and bound into collection and verification:

- `user-input`: bounded syscall-entry bytes only;
- `kernel-file-open-partial`: selected successful open-family
  `file_open` objects;
- `kernel-file-open-write-partial`: the open contract plus selected
  positive-byte native write-family `file_permission(MAY_WRITE)` objects;
- `kernel-object-expanded-partial`: both earlier contracts plus the explicit
  path/inode/mmap/socket matrix and a separate lifecycle stream.

Expanded mode currently implements:

- [x] create-family parent evidence for mkdir, symlink, and mknod;
- [x] hard-link source, unlink/rmdir target, and rename source evidence;
- [x] chmod/chown target evidence;
- [x] setxattr/removexattr inode evidence;
- [x] file-backed `MAP_SHARED|PROT_WRITE` mmap-establishment evidence;
- [x] single shared file-backed VMA `mprotect`/x86-64 `pkey_mprotect`
      write-permission-channel evidence, with unsupported ranges explicit;
- [x] bind/connect socket cookie, network-namespace cookie, socket metadata,
      and kernel-copied requested endpoint evidence;
- [x] successful accept/accept4 accepted-socket and peer identity plus a
      separate AF_INET/AF_INET6 TCP accept/transition/destroy stream correlated
      to the originating syscall-entry identity;
- [x] independently attested fork/exec/exit WAL and JSONL, PID/TGID plus task
      start-boottime identity, terminal replay of the events admitted by those
      hooks, and correlation for syscall identities present in that stream;
- [x] strict WAL-derived reconstruction and rejection of missing, ambiguous,
      unreadable, lossy, truncated, or JSON-only object/lifecycle claims;
- [x] fail-closed BTF, active-BPF-LSM, hook-ABI, object/lifecycle digest, and
      real libbpf load/attach gates before workload launch; required kernel
      config is reported explicitly and missing facilities fail the real gate.

The word `partial` is material:

- [ ] Add an authoritative S0 task/thread enrollment ledger plus sound cgroup
      migration and `CLONE_INTO_CGROUP` enrollment coverage. Until all three
      exist, lifecycle status is capped at `PARTIAL` and does not prove a
      complete process-tree association.
- [ ] Resolve the not-yet-created child object and rename destination/parent
      where a reliable post-operation hook is available.
- [ ] Add mount identity to inode-only xattr evidence without guessing it.
- [ ] Observe actual mmap/mprotect dirtying. Current hooks prove only an
      eligible mapping request or write-permission transition; private,
      anonymous, mixed, and multi-VMA mprotect ranges are unresolved.
- [ ] Add complete post-bind/post-connect coverage beyond the current
      AF_INET/AF_INET6 TCP state stream. Bind/connect object evidence remains
      the requested endpoint; bind port zero remains zero unless a later
      eligible TCP state event exposes the assigned local endpoint.
- [ ] Decode and correlate `io_uring`, `SCM_RIGHTS`, ioctl, and netlink
      object semantics.
- [ ] Add compat/x32 coverage and define delayed kernel-worker/writeback
      attribution. Native syscall coverage does not imply either.

Userspace `/proc/<pid>/fd` or pidfd lookup may be added as explicitly racy
enrichment, but it must never be promoted to event-time kernel object identity.
Exec filename is likewise descriptive kernel-copied evidence, not executable
file identity.

## Endpoint-state confirmation

Operation history and endpoint state remain separate outputs. The following
S0/S1 confirmers are shipped and independently recomputed by
`verify-effects`:

- [x] BPF Program/Map/Link state under an explicit `ClaimScope`;
- [x] bounded generic filesystem path trees with selected metadata, content,
      symlink, and xattr evidence;
- [x] sorted explicit sysctl keys under a bound proc-sys root;
- [x] mountinfo for one PID- and inode-bound mount namespace;
- [x] selected local address, route, rule, tc, and nftables state in one
      PID- and inode-bound network namespace, using exact trusted tool paths
      and SHA-256 values;
- [x] all or explicitly selected loaded modules, with optional readable sysfs
      parameters;
- [x] recursive residual-process enumeration for an exact cgroup-v2 path and
      kernel cgroup ID.

Every domain has hard record, value, total-byte, issue, and deadline bounds.
Errors, races, namespace/PID changes, tool replacement, parse failures, and
budget exhaustion yield `INCOMPLETE`/`INCONCLUSIVE`; they never narrow the
scope silently. Omitted domains remain `NOT_CONFIRMED`.

A complete observed S0/S1 difference may yield
`CHANGED_WITHIN_SCOPE` for that one domain. A complete identical endpoint
still yields `INCONCLUSIVE`, because the standalone path lacks authenticated
exclusive-writer and per-domain atomic-quiescence proof. The per-domain vector
must never be collapsed into “all Linux unchanged” or rollback `CLEAN`.

Remaining state work:

- [ ] Implement a filesystem-native/Btrfs confirmer with typed rename,
      hard-link topology, deletion, metadata, xattr, and changed-set hashing.
- [ ] Add narrowly scoped keyring and other configuration adapters only where
      both endpoint enumeration and completeness are defensible.
- [ ] Decide whether conntrack deserves a separate local-network scope;
      transient packets and sockets must remain operation evidence.
- [ ] Treat remote service/database effects as an enforced-egress ledger or
      signed remote receipt, never as a locally provable endpoint diff.
- [ ] Authenticate fresh actor/quiescence contracts for domains where a
      negative verdict is required.

## Direct, Docker, and Kata-host deployment

The one-shot `deployment-observe` adapter is implemented for an already
existing, externally frozen target:

- [x] `DIRECT`: trusted root PID, expected dedicated cgroup, process and
      namespace identity;
- [x] `DOCKER`: full 64-hex container ID, optional trusted init PID,
      expected cgroup, and host-visible container namespaces without invoking a
      Docker/containerd CLI;
- [x] `KATA_HOST`: shim, expected hypervisor and optional backend PIDs,
      target-Linux runtime/QEMU/virtiofs identity, and QEMU-derived disk,
      block-device, TAP, and network-backend resources;
- [x] READY/FINISH freeze and identity revalidation, one shared recorder pair
      for up to eight FD-pinned ancestor roots, optional BPF/filesystem/Linux
      endpoints, expanded socket-state artifacts, a closed artifact manifest,
      and independent offline replay/comparison.

Kata means host-only observation. The adapter does not enter the Kata guest and
does not claim its syscalls; it observes only what the Kata runtime, QEMU,
virtual storage, and network backend do to the target Linux.

Discovery now registers bounded, FD-pinned cgroup-v2 ancestor roots. Every
selected syscall/object/lifecycle hook checks
`bpf_current_task_under_cgroup`, so child cgroups created and deleted entirely
between barriers remain in scope. FINISH additionally detects root inode
replacement, unexpected root processes, and root identity changes. Therefore:

```text
ancestor-root transport:       may be COMPLETE
dynamic descendant coverage:  DYNAMIC_ANCESTOR_COMPLETE
```

- [x] Add an ancestor-cgroup kernel filter before claiming dynamic subtree
      membership coverage for the selected hook matrix.
- [ ] Run and record separate privileged Direct, real Docker, and real Kata
      E2E gates. The adapter implementation and unit tests alone are not such
      validation.
- [ ] Add deployment-specific performance batches; do not extrapolate the
      standalone expanded microbenchmark to Kata block/network backend load.

## Attribution boundary

Current runtime attribution proves that the event-time caller was under one of
the FD-pinned cgroup-v2 ancestor roots at the selected kernel hook. Its causal
status remains `CAUSAL_NOT_ESTABLISHED`. An Agent request handled by systemd,
D-Bus, a long-lived daemon, a kernel worker, or a remote service is not
attributed to the Agent merely because it followed in time.

The bounded delegation-ledger schema and structural validator remain library
work only. There is no authenticated broker, helper-cgroup runtime, signer,
manifest integration, or `BROKER_REQUEST_EXECUTION_CHAIN_ESTABLISHED` result.
That work is intentionally outside the current standalone/deployment milestone
and must not be inferred from the observer's operation history.

## Overhead contract

The implementation keeps expensive work behind the narrowest available gate:

- unselected syscall entry/exit takes one policy-array lookup;
- selected calls outside registered cgroups stop after the exact-cgroup lookup;
- object hooks first require a matching selected pending operation, cgroup,
  epoch, and resolver before object/path reads;
- untracked lifecycle hooks take one current-cgroup helper and one hash lookup;
- all registered cgroups share one system recorder and one lifecycle recorder;
- endpoint confirmers run only at S0/S1, adding barrier latency and evidence
  I/O rather than syscall hot-path work;
- fixed ring buffers, bounded queues, artifact sizes, and collector deadlines
  prevent unbounded memory and capture work.

`make system-effects-overhead-check` enforces static instruction ceilings for
expanded object and lifecycle hooks. The paired benchmark supports a separate
`kernel-object-expanded-partial` batch and must not mix it with file-only or
`user-input` measurements. Static instruction counts are regression guards,
not runtime overhead percentages; runtime claims require a privileged,
lossless, same-profile paired measurement.
