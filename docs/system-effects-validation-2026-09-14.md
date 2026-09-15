# Expanded system-effect Observer validation, 2026-09-14

## Result

The current standalone Linux runner passed a fresh privileged KVM end-to-end
run:

```text
EXPANDED_EFFECTS_HOST_E2E_PASS
result=.output/validation/expanded-effects-vm/20260914T162805Z-1663157
effect_sha256=920b5155cd11e2ddf7d97b37bf196f7a5089f3973d4ab3159c7b22cf5a70055e
lifecycle_sha256=7392a29cd0237759085c312d4205e8310dba0b1cd05a289b302d0f4f4f57bada
```

The run reached every functional case, the expected residual-process failure,
all 64 benchmark arms, artifact recovery, and the Host-side overhead analyzer.
It validates the bounded contracts described below. It does not establish
whole-Linux coverage, delegated causality, hostile-workload containment, or a
real Docker/Kata runtime E2E.

## Environment and copied inputs

- Guest kernel: `7.3.0-rc2-00100-g519a81750493-dirty`
- Active boot LSMs: `capability,selinux,bpf`
- QEMU: KVM, host CPU passthrough, 2 vCPUs, 2 GiB RAM
- Root disk: external Debian Trixie raw image, QEMU `snapshot=on`
- Network: QEMU user networking with `restrict=on` and a loopback-only SSH
  forward
- Runtime preflight: `doctor.ready_for_runtime=true`; cgroup v2, raw
  syscall tracepoints, BTF, bpffs, BPF privileges/inventory, perf access,
  BPF LSM, and the expanded hook ABI passed

The archive contains a SHA-256 inventory. Important copied inputs are:

| Artifact | SHA-256 |
|---|---|
| Standalone Observer | `c404eb59659c342ff13927b74fdacd17e353f0e756b3c49b56bbd6bcfa961e3a` |
| Deployment Observer | `59e70a97f66547ef6a9c4b589cd5c864fcf166a5dda7b659d98fe77e08a3b746` |
| Deployment verifier | `de56941dec67a51235df06c02d14510ffa044701273037924b43856272e3cacb` |
| System-effect BPF object | `920b5155cd11e2ddf7d97b37bf196f7a5089f3973d4ab3159c7b22cf5a70055e` |
| Lifecycle BPF object | `7392a29cd0237759085c312d4205e8310dba0b1cd05a289b302d0f4f4f57bada` |
| Kernel `bzImage` | `2c400baf179942d7447fe7a2081143d3b1830ba3336bf63a7f14e898e65180df` |
| Effective kernel config | `c8869d1e32799bc6baee2137b8bbaf184277233bbbbe87a7c441764120616baa` |
| Guest E2E harness | `09d426d175d05d1f3287c22c41ed7b15bfe398be14a4c587d24ed4a47f30bf66` |
| External root image | `8960ffec0ada901b292255d9ffbb5d36d9c4bae7b8f39a2d0b1f46726e9dc818` |
| Host QEMU executable | `c60d4f42bb600981efacd38a00d737d61d5b435e149da693705b22b21b2cb149` |

The root-image and QEMU hashes are local harness records, not a signed
attestation. The archive also retains the exact QEMU argv, serial log, copied
inputs, run manifests, raw WALs, JSON projections, health records, endpoint
snapshots, comparisons, and offline-verifier results.

## Object and lifecycle evidence

The independent object workload completed 41 selected operations and emitted
82/82 syscall events with zero drops. Of 30 object-resolution attempts, 29
were resolved and one anonymous/private `mprotect` request was explicitly
unsupported. There were no missing or ambiguous joins, kernel fatal flags, or
remaining pending joins.

The workload independently recorded file identity
`dev=0:35, inode=12, mnt_id_unique=2147483707` while the descriptor was
live. It also recorded three distinct socket cookies and consistent
listener/client/accepted-peer ports. The E2E harness compared those values
with the WAL-derived file and socket objects rather than trusting projected
JSON.

The separate lifecycle stream persisted 7/7 fork/exec/exit events with zero
drops. Its status is deliberately `PARTIAL`: there is no authoritative S0
task ledger and no cgroup-migration or `CLONE_INTO_CGROUP` enrollment hook.

The AF_INET TCP state stream persisted 14/14 events, including three destroy
events, with zero drops, no unsupported sockets, no remaining owners, and a
2/2 detached async-producer seal. Offline verification rebuilt the projections
from WAL and accepted all 82 syscall events, 14 socket-state events, lifecycle
correlation, the exact external BPF digest, and the declared scope.

## Endpoint-state confirmation

The persistent state-change workload produced `CHANGED_WITHIN_SCOPE` in
exactly four complete domains:

- sysctl: `net/ipv4/ip_forward`
- mounts: an added mount record
- local network configuration: address, IPv4/IPv6 routes, nftables ruleset,
  and qdisc
- loaded modules: `bpf_observer_e2e_state`

The tracked process tree ended `EMPTY_WITHIN_SCOPE`. Its identical endpoint
is correctly `INCONCLUSIVE`, not `UNCHANGED_WITHIN_SCOPE`. The run
persisted 818/818 syscall events and 49/49 lifecycle events with zero drops.
Ten unsupported socket-state attempts were exactly accounted for by ten
successful AF_NETLINK bind/connect/accept operation records; netlink payload
semantics are not claimed.

A separate one-second residual-process case intentionally failed with
`run_status=FAILED` and `workload process tree exceeded timeout of 1s`.
The exact test cgroup was then killed and removed.

The Direct dynamic-descendant deployment run was independently verified with
106 syscall events, 10 lifecycle events, and 13 socket-state events. Its
filesystem and BPF endpoint domains both reported
`CHANGED_WITHIN_SCOPE`; Linux endpoint evidence was complete. Overall
evidence remains `INCOMPLETE` because lifecycle enrollment is partial.

## Deployment adapters

| Adapter case | Validated result |
|---|---|
| Direct | A frozen root was registered before resume; an ephemeral child cgroup created after READY was observed through the cgroup-v2 ancestor filter; closure and offline verification passed. |
| Docker-shaped | Live procfs, cgroup v2, PID/mount namespaces, retained namespace access, full container ID, and inner PID 1 were exercised. Filesystem and Linux endpoint captures were complete; identical endpoints remained inconclusive. |
| Kata-host-shaped | Live procfs/cgroup/sysfs plus a real TUN device were exercised. QEMU `fd=9`, multiqueue `fds=10:11`, both TAP identities/fdinfo records, and one virtual-disk file identity were resolved and revalidated. No Kata guest syscall or guest-kernel state was claimed. |

The Docker and Kata cases use real Linux kernel interfaces with synthetic
runtime identities and fixture executables. The status artifact explicitly
records `real_docker_runtime_e2e=false`,
`real_kata_runtime_e2e=false`, and `kata_guest_entered=false`. Kata
virtual-disk coverage currently binds host file identity/metadata; it is not a
content-diff or guest-filesystem confirmer.

## Exploratory overhead batch

The harness ran four excluded warm-up blocks and twelve measured blocks. Each
block contained `user-input` and `expanded-lifecycle` modes at both
`N=0` and `N=1024`, for 64 total arms. Every arm finalized losslessly and
passed offline verification. The analyzer uses a paired
difference-in-differences contrast and includes startup, drain, JSON
projection, health finalization, and persistent evidence output.

The final run's inference scope is
`EXPLORATORY_SINGLE_DISPOSABLE_VM_BATCH`:

- Aggregate CPU: `USABLE_ESTIMATE`, median **1415.10 ns/system event**;
  exact distribution-free 96.14% median interval
  **[1089.84, 1678.96] ns/event**; 12/12 blocks positive.
- Wall time: `EXPLORATORY_LOW_CONFIDENCE`, exploratory median
  **877.43 ns/system event**; interval
  **[-711.94, 2520.20] ns/event**; 9/12 blocks positive. The interval crosses
  zero and the accepted median is therefore null.

The wall result must not be presented as an accepted performance estimate.
This one-VM microbenchmark is also not a production-wide bound and does not
measure Docker/Kata block or network backend workloads.

## Strict remaining limits

- Attribution proves direct caller membership at syscall entry only.
  Delegated daemon effects remain `CAUSAL_NOT_ESTABLISHED`.
- Create hooks identify the parent object, hard-link and rename identify the
  source object, and xattr evidence omits values and mount identity.
- mmap/mprotect evidence identifies a shared-writable permission channel, not
  later dirty pages or writeback; anonymous/private and multi-VMA cases are
  unsupported.
- Async socket state is limited to directly observed AF_INET/AF_INET6 TCP.
  UDP, Unix, raw/packet, inherited, SCM_RIGHTS, io_uring, compat/x32, and
  generic netlink/ioctl payload semantics remain outside the contract.
- State snapshots are scoped and sequential rather than an atomic
  whole-kernel snapshot. Identical endpoints remain inconclusive without an
  authenticated exclusive-writer/quiescence contract; remote effects are not
  confirmable from the target Linux host.
- The standalone runner assumes a cooperative workload. It is observation,
  not containment against a privileged process that migrates cgroups,
  tampers with evidence, or uses unobserved delegation.

## Local verification gates

`make check-all` passes the complete workspace: 297 Rust unit tests, strict
Clippy with `-D warnings`, BPF compilation and fast-path checks, workload
build/smoke checks, strict-init, agent-collection helpers, shell syntax, and
Node analyzer self-tests. The ignored validation archive is local evidence,
not a repository fixture or remote attestation.
