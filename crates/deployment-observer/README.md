# Standalone deployment observer

`deployment-observe` is a one-shot Linux-host adapter for an already existing
direct process tree, Docker container, or Kata sandbox. It loads exactly one
system-effect recorder and exactly one process-lifecycle recorder. Every
cgroup ID committed by deployment discovery is registered in both recorders
under the same epoch before `READY`.

This is not a daemon. It does not invoke Docker/containerd/Kata CLIs, change
the target cgroup, or enter the Kata guest. The external harness owns
freeze/resume and supplies trusted IDs. When an endpoint confirmer is enabled,
the observer pins the selected Linux namespace FDs while the deployment is
frozen and its trusted capture thread/collector child temporarily enters those
namespaces at S0/S1; the workload is never moved.

## Build

From `tools/bpf/bpf-state-observer`:

```sh
make system-effects-bpf process-lifecycle-bpf
cargo build --release -p bpf-observer-deployment-observer
sha256sum .output/system_effects.bpf.o .output/process_lifecycle.bpf.o
```

The target kernel must expose cgroup v2, BTF, the required raw tracepoint/BPF
LSM hooks for the selected object mode, and `cgroup.freeze` plus the `frozen`
field in `cgroup.events`.

## Configuration

All fields are explicit and unknown JSON fields are rejected. A direct example
is:

```json
{
  "protocol_version": 2,
  "deployment": {
    "deployment_kind": "DIRECT",
    "configuration": {
      "root_pid": 1234,
      "expected_cgroup_path": "/allox-runs/run-1",
      "require_dedicated_cgroup": true,
      "limits": {
        "max_proc_entries": 131072,
        "max_cgroup_nodes": 4096,
        "max_cgroup_depth": 64,
        "max_open_fds_per_process": 8192
      }
    }
  },
  "recorder_object_path": "/opt/bpf-observer/system_effects.bpf.o",
  "recorder_object_sha256": "REPLACE_WITH_64_LOWERCASE_HEX",
  "lifecycle_object_path": "/opt/bpf-observer/process_lifecycle.bpf.o",
  "lifecycle_object_sha256": "REPLACE_WITH_64_LOWERCASE_HEX",
  "output_directory": "/var/lib/bpf-observer/evidence/run-1",
  "run_id": "run-1",
  "epoch": 1,
  "profile": "full",
  "object_resolution_mode": "KERNEL_OBJECT_EXPANDED_PARTIAL",
  "bpf_state_scope": null,
  "filesystem_state_scope": null,
  "filesystem_namespace_mode": "DEPLOYMENT",
  "linux_state_scope": {
    "protocol_version": 1,
    "sysctl": {
      "proc_sys_root_bytes_hex": "2f70726f632f737973",
      "keys": ["kernel/hostname", "kernel/yama/ptrace_scope"],
      "evidence": "BYTES_AND_SHA256",
      "limits": {
        "max_records": 16384,
        "max_value_bytes": 4194304,
        "max_total_value_bytes": 16777216,
        "deadline_ms": 15000
      }
    },
    "mounts": null,
    "network": null,
    "modules": null,
    "process_residual": null
  },
  "poll_interval_ms": 20,
  "drain_timeout_ms": 5000
}
```

All three state scopes are optional; use `null` or omit one to disable that
domain. `bpf_state_scope` is the existing state-oracle `ClaimScope`, and
`filesystem_state_scope` is the existing filesystem-confirmer scope. The
adapter does not infer either scope from a container ID, QEMU command line, or
virtual-disk path. Kata disk discovery is inventory evidence, not authorization
to recursively scan an image. A host path must be supplied as an explicit,
bounded scope whose stable identity was established externally. The evidence
directory must be outside every filesystem root, both lexically and after
symlink resolution.

`filesystem_namespace_mode` defaults to `DEPLOYMENT`, which retains the
authoritative target mount namespace for every filesystem capture. The
`OBSERVER` mode is accepted only by protocol v3 with both recovery and a
filesystem scope enabled. It captures A/B/C through the Observer's current
mount namespace so a host-visible Btrfs `current` subvolume replacement can be
seen at C. Offline verification then requires all three snapshots to use the
`CURRENT_PROCESS` capture source and the same nonzero mount namespace/root
identity; it does not relabel that host view as a deployment mount namespace.

For example, a bounded BPF inventory and one explicit filesystem tree can be
enabled with:

```json
{
  "bpf_state_scope": {
    "event_interfaces": ["BPF_USER_SYSCALL"],
    "allowed_bpf_commands": [0, 2, 6],
    "object_types": ["MAP"],
    "map_content_types": ["HASH"],
    "map_ids": [],
    "bpffs_roots": ["/sys/fs/bpf/experiment-run-1"],
    "attachment_targets": [],
    "budget": {
      "max_map_entries": 65536,
      "max_map_bytes": 67108864,
      "per_map_deadline_ms": 5000
    }
  },
  "filesystem_state_scope": {
    "protocol_version": 1,
    "roots": [{"path_bytes_hex": "2f746d702f6578706572696d656e742d72756e2d31"}],
    "capture": {
      "regular_file_content": "SHA256",
      "symlinks": "TARGET_BYTES",
      "xattrs": "NAMES_AND_VALUE_SHA256",
      "cross_filesystems": "SAME_DEVICE_ONLY"
    },
    "limits": {
      "max_entries": 16384,
      "max_total_path_bytes": 16777216,
      "max_file_content_bytes": 4194304,
      "max_total_content_bytes": 67108864,
      "max_xattr_list_bytes": 262144,
      "max_xattrs_per_entry": 128,
      "max_total_xattrs": 65536,
      "max_xattr_value_bytes": 1048576,
      "max_total_xattr_bytes": 16777216,
      "max_symlink_target_bytes": 4096,
      "max_depth": 64,
      "deadline_ms": 30000
    }
  }
}
```

`linux_state_scope` is the caller's explicit sysctl, mount, local-network,
module, and/or process scope. For one deployment root, the adapter adds a
recursive process-residual scope for that root. For multiple roots, it binds
every pairwise-disjoint registration root (up to eight) into one recursively
captured process-residual domain. The scans share one deadline and aggregate
record and byte limits. Multi-root record keys include their canonical root
index and cgroup ID. A conflicting caller-provided process scope is rejected.

Mount and network scopes are rebound only to a real nonzero PID committed in
the discovered deployment manifest with the requested namespace inode. A PID
of zero is only an inode selector; it is never retained as observer `self`. An
explicit nonzero PID must itself be in the manifest. Missing/mismatched
identities are a startup error. Before READY, while the roots are frozen, the
observer opens and revalidates namespace FDs. S0 and S1 use those retained FDs,
so the anchor PID may exit without silently switching mount/network views.
Snapshots commit the exact namespace kind, inode, and
`RETAINED_FILE_DESCRIPTOR` source; online and offline verification require the
same proof.

Sysctl capture binds one deployment anchor's network, UTS, and IPC namespaces
and enters all three through retained FDs before reading the explicit
`/proc/sys` allowlist. `net/*`, UTS hostname/domainname, and IPC sysctls
therefore use the target namespace context. `kernel/ns_last_pid` is rejected:
`setns(CLONE_NEWPID)` affects only future children and protocol v1 deliberately
does not claim a PID-namespace sysctl helper. Other enabled keys remain exactly
the caller's explicit bounded allowlist; this is not a whole-sysctl inventory.

For Direct and Docker, filesystem S0/S1 are likewise captured through the
retained direct-root or container-init mount namespace. Every filesystem
snapshot commits that mount namespace inode and retained-FD source, and the
offline verifier rejects a host-view snapshot substituted for target-root
evidence.

For Docker, replace `deployment` with a full, trusted 64-hex container ID and
prefer its externally obtained init PID:

```json
{
  "deployment_kind": "DOCKER",
  "configuration": {
    "container_id": "FULL_64_LOWERCASE_HEX_CONTAINER_ID",
    "init_pid": 2345,
    "expected_cgroup_path": "/system.slice/docker-FULL_64_LOWERCASE_HEX_CONTAINER_ID.scope",
    "limits": {
      "max_proc_entries": 131072,
      "max_cgroup_nodes": 4096,
      "max_cgroup_depth": 64,
      "max_open_fds_per_process": 8192
    }
  }
}
```

For Kata, `shim_pid` anchors host discovery. `expected_hypervisor_pid` and
`additional_host_pids` bind QEMU/virtiofs/backend processes that may live in
separate host cgroups:

```json
{
  "deployment_kind": "KATA_HOST",
  "configuration": {
    "sandbox_id": "trusted-kata-sandbox-id",
    "shim_pid": 3456,
    "expected_hypervisor_pid": 3457,
    "additional_host_pids": [3458],
    "expected_cgroup_path": "/system.slice/containerd.service/kata-sandbox.scope",
    "limits": {
      "max_proc_entries": 131072,
      "max_cgroup_nodes": 4096,
      "max_cgroup_depth": 64,
      "max_open_fds_per_process": 8192
    }
  }
}
```

Kata evidence contains the host QEMU/runtime identities and QEMU-derived disk,
block-device, TAP, and network-backend resources. It deliberately contains no
Kata-guest syscall claim. Protocol v1 does not yet retain both each backend
owner's mount namespace and an `O_PATH` FD for the backend object. The manifest
therefore commits `kata_host_backend_namespace_pinned=false`, records the exact
limitation, and the run-level evidence is forced `INCOMPLETE`; it cannot claim
complete backend identity after a QEMU/private-mount owner exits.

## One-shot protocol

The caller must freeze every discovered root before startup. `docker pause` is
one possible Docker harness; a direct/Kata harness can write `1` to each
trusted root's `cgroup.freeze` and wait for `frozen 1` in `cgroup.events`.

```sh
sudo deployment-observe --config /absolute/path/config.json
```

The first stdout line is a bounded JSON `READY` record. It contains a random
`finish_nonce`, deployment/identity/freeze-barrier artifact digests, both loaded
BPF object digests, every ancestor-root registration ID, the socket-state mode,
and—when enabled—the BPF, filesystem, and effective Linux-state scope/S0
digests. S0 is collected only after both recorders have registered and sealed
every root while the target roots remain frozen. Only after receiving this line
may the harness resume the target.

At the end, the harness freezes the same roots again, waits for `frozen 1`, and
writes one JSON line to the observer's stdin:

```json
{"protocol_version":2,"command":"FINISH","run_id":"run-1","finish_nonce":"NONCE_FROM_READY"}
```

The terminal stdout line is `FINISHED` and carries the externally retainable
SHA-256 values of the observation report and artifact manifest. During the run
the main thread alternates bounded polling of the system-effect and lifecycle
collectors. Expanded object mode also persists the recorder's dedicated
socket-state stream; state snapshot work is not on the syscall hot path.

All roots share two loaded BPF objects; the adapter never loads one object per
cgroup. The fixed ring allocation is 4 MiB for syscall effects, 1 MiB for
lifecycle events, and, in expanded mode, 1 MiB for socket-state events. Every
selected hook performs a bounded ancestor-root membership check before capture.
Deployment/procfs/resource enumeration runs only at READY and FINISH.
`poll_interval_ms=20` is the recommended starting point; a smaller value
reduces delivery latency but increases userspace wakeups.

After `FINISH`, the adapter first proves every registered root still frozen and
identity-stable. It then synchronously detaches exactly the recorder-global
`inet_sock_set_state` and `tcp_destroy_sock` links once, drains every root, and
retires remaining socket owners. Every expanded-mode root carries the same
complete `2/2` seal, and its owner counter must exactly equal its post-detach
retirement count; a mismatch or missing seal prevents `COMPLETE`. S1 is then
collected while the roots remain caller-frozen, followed by the final closure
identity and freeze checks. Endpoint collectors run only at S0/S1; they add
startup/finish latency and evidence I/O, but no extra hook, map lookup, or
syscall hot-path cost to the observed workload.

The report and artifact manifest also carry `diagnostic_performance`: bounded,
process-local monotonic durations for each BPF/filesystem/Linux S0 and S1
capture plus the system-effect and process-lifecycle closing drains. The
system-effect duration includes the exact TCP producer seal. The manifest
additionally records `committed_artifact_total_bytes`, the checked
sum of its closed digest entries (the self-referential manifest is excluded).
These fields are explicitly `DIAGNOSTIC_ONLY_NOT_TRUSTED_EVIDENCE`; the offline
verifier checks their closed shape, domain presence, bounds, equality across
report/manifest, and recomputes artifact bytes, but timing never affects a
completeness, attribution, or state verdict.

## Evidence and offline verification

The output directory is required not to exist before startup. It contains:

- the external observation contract and deployment identity/resource manifest;
- READY, pre-FINISH, and closure identity/freeze reports;
- CRC-framed system-effect and process-lifecycle WALs;
- canonical JSONL projections;
- in expanded object mode, exactly `socket-state.raw.bin`,
  `socket-state.jsonl`, and `socket-state.health.json`;
- when BPF state is enabled, exactly `bpf-state-s0.json`,
  `bpf-state-s1.json`, and `bpf-state-verdict.json`;
- when filesystem state is enabled, exactly `filesystem-state-s0.json`,
  `filesystem-state-s1.json`, and `filesystem-state-comparison.json`;
- when enabled, exactly `linux-state-s0.json`, `linux-state-s1.json`, and
  `linux-state-comparison.json`;
- per-cgroup and aggregate health in `deployment-observation-report.json`;
- a canonical digest list in `artifact-manifest.json`.

Keep the original config and the two terminal digests outside the evidence
directory. Construct a verification expectation:

```json
{
  "expected_config": { "COPY_THE_EXACT_ORIGINAL_CONFIG": "..." },
  "expected_artifact_manifest_sha256": "FROM_FINISHED",
  "expected_report_sha256": "FROM_FINISHED"
}
```

Then verify without loading BPF or consulting live procfs:

```sh
deployment-observe-verify \
  --artifacts /var/lib/bpf-observer/evidence/run-1 \
  --expectation /secure/run-1-expectation.json
```

The verifier checks the closed artifact set and every digest, binds the loaded
object SHA values to the external config, recomputes the compiled policy hash,
replays terminal lineage for lifecycle events admitted by the three scheduler
hooks, validates JSONL projections, and
recomputes both recorder aggregates. In expanded mode it independently replays
the socket-state WAL/JSONL/health tuple, requires the identical complete global
producer seal for every root, and requires every socket event to bind to a
system-call origin. The seal is a live-recorder attestation protected by the
committed artifact digests; offline replay cannot repeat the historical kernel
detach. For each enabled endpoint confirmer it reads S0/S1
under that confirmer's hard bounds, independently reruns the BPF, filesystem,
or Linux-state comparison, and requires the report's per-domain vector to match
exactly. It never trusts a JSON verdict merely because its digest is present.

The terminal, artifact-manifest, and offline-verifier `evidence_status` is the
conservative aggregate over all enabled domains. Lifecycle schema v2 has no
authoritative S0 task/thread enrollment ledger and no cgroup migration or
`CLONE_INTO_CGROUP` enrollment hook. Its successful nonempty status is therefore
`PARTIAL`, and the deployment-level aggregate cannot be `COMPLETE`. This does
not erase collector-specific results: the report retains
`aggregate_health.evidence_status` for lossless selected-operation transport
plus separate lifecycle, socket, BPF, filesystem, and Linux-state results. An
endpoint snapshot cannot upgrade an `UNPROVEN_NO_EVENTS` operation stream.

## Strict current boundary

The recorder installs a bounded set of FD-pinned cgroup-v2 ancestor roots and
uses `bpf_current_task_under_cgroup` in every selected kernel hook. Dynamic and
ephemeral descendants are therefore in scope even when they do not exist at a
userspace barrier. The result is direct-caller observation on the target Linux;
it does not infer that an out-of-cgroup daemon action was caused by the
deployment.

BPF inventory is host-global within its explicit claim scope. Freezing the
deployment roots does not exclude unrelated host BPF actors, so a positive
delta is retained as unattributed and an identical S0/S1 never authorizes
`UNCHANGED_WITHIN_SCOPE`. Filesystem confirmation covers only explicit paths
in its committed mount view (direct root or Docker init); Kata filesystem
coverage remains explicitly incomplete because host backends may occupy
multiple private mount namespaces. It similarly carries no authenticated
exclusive-writer contract. Regular-file content is opened with
`O_NOATIME`; lack of permission is an incomplete content observation rather
than an observer-caused atime mutation. BPF, filesystem, and Linux-state
captures are sequential, not one atomic whole-system snapshot. Linux-state
`COMPLETE` means only that every explicitly enabled endpoint domain was
collected; an identical endpoint remains `INCONCLUSIVE`.

Local-network collectors use the scope-bound
`NETWORK_CONFIGURATION_ONLY_V1` normalization contract. Runtime counters, countdown
lifetimes, and kernel-assigned nft handles are removed. Only explicit object
sets (`ip address`, tc qdisc/class/filter) are canonically sorted at the top
level. Route/rule order, nested address/multipath arrays, and nft list/rule
order are retained because equal-priority insertion, selection, or
packet-processing order can be semantic.

For Kata, the boundary is the target Linux host: shim, hypervisor, virtual-disk
backend, TAP, and other discovered host resources. The adapter neither enters
nor claims visibility into the Kata guest.
