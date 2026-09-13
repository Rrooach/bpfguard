# System-effect Observer current-build validation, 2026-09-13

## Result

The current standalone Linux runner, `kernel-file-open-write-partial` object
resolver, filesystem path-tree confirmer, and offline verifier passed a fresh
privileged KVM revalidation. According to the local validation harness, the
same copied Observer and BPF object were used for every functional
`observe-effects` case below. Each run manifest independently binds the BPF
object digest, but protocol v1 does not bind the Observer executable, kernel
image/config, workload executable, root image, or QEMU command.

This validates the declared bounded contracts. It does **not** establish
whole-kernel coverage, causal attribution through external daemons, hostile
workload containment, storage durability, or a filesystem
`UNCHANGED_WITHIN_SCOPE` verdict.

## Harness-recorded environment and inputs

- Guest kernel: `7.3.0-rc2-00100-g519a81750493-dirty`
- Guest boot ID: `c0e0c13a-118a-42ba-8f5a-c7ddb1b76d58`
- Active LSM list: `capability,selinux,bpf`
- Virtualization: KVM, host CPU passthrough, 2 vCPUs, 2 GiB RAM
- Root image: external Debian Trixie raw image with QEMU `snapshot=on`
- Control network: QEMU user networking with `restrict=on` and one
  loopback-only SSH forward
- Kernel BTF: readable at `/sys/kernel/btf/vmlinux`
- cgroup: writable cgroup v2, checked by `statfs`
- OverlayFS: built in as `CONFIG_OVERLAY_FS=y`

SHA-256 values recorded and rechecked by the local harness:

| Artifact | SHA-256 |
|---|---|
| Observer release | `62ea60da2d00604ba1e2d57bc56945273eb2035de85de6854b85c9d2b5688994` |
| System-effect BPF object | `8a4ebbdf9ff400d77609a6e5916c2383ffe6417c0cc9e25e4a9e3367f233ac76` |
| Kernel `bzImage` | `a85887c7c37b29b53a35cb9b0788bce12132fd5f375e7bd17eca880a23c77ac5` |
| Kernel `vmlinux` | `adefcc3d5366e6bff991e4d9ba027b4118d57ab365014ff90778c192d6042801` |
| Effective kernel config | `370ab8380e61bad424297e0ec01fa9ea79427f971c29820702435149d80d73f6` |
| Filesystem scope input | `a912ab56a817f84accfbd19fbd7ac0cacda25d4601fd6818988787adc72ee985` |
| Smoke workload | `04832a59cc75d968fd2b06080d040cbcfac95b684f30895fe52f22d10713a7d1` |
| `openat2(O_PATH)` workload | `38a27dc96577d832ef4d22710a6de4094b18fe34b85fe5a729ef5855feacf7cc` |
| SCM_RIGHTS workload | `50a393fc3bd79801b5075877eeb63cac9fe5c38dfe77124ce0a2622a3135a251` |

The worktree was intentionally under active implementation, so manifests have
`source_commit=null`. Only the BPF-object digest above is externally selected
and cryptographically bound into each run manifest. The other environment and
input digests are unauthenticated local harness records. They make this run
auditable in the retained workspace, but they are not a signed or hermetic
proof of exact execution inputs.

## Preflight and cgroup negative

`doctor` with the exact BPF object and
`kernel-file-open-write-partial` returned `ready_for_runtime=true`. BTF, the
active BPF LSM, raw tracepoints, bpffs, global BPF inventory, perf-event
access, capabilities, cgroup v2, recorder symbols, and both object hooks
passed.

A normal directory containing forged files named `cgroup.controllers`,
`cgroup.events`, `cgroup.freeze`, `cgroup.kill`, and `cgroup.procs` was then
passed as the cgroup root. `doctor` returned exit 1 and
`ready_for_runtime=false`; the exact check reported
`cgroup_v2=false`. Marker filenames therefore cannot substitute for the
`CGROUP2_SUPER_MAGIC` doctor `statfs` gate. The create path's anchored
`fstatfs` recheck is present and was exercised by successful VM creates, but
no separate negative raced-anchor fixture is retained.

## Functional cases

| Case | Runtime result | Offline verifier |
|---|---|---|
| Scope unchanged; smoke runs outside it | 11 pairs, 22 events, transport `COMPLETE`; object `3/3/0`; filesystem `OBSERVED_IDENTICAL`, completeness `COMPLETE`, verdict `INCONCLUSIVE` | exit 0; 9 artifacts; manifest `c4f2d24070747dcc708ee93a3e4b511a236a9dff3a07ac41df199d51702d6ee1` |
| Persistent file created inside scope | 1 pair, 2 events, transport `COMPLETE`; object `1/1/0`; filesystem `OBSERVED_DIFFERENT`, verdict `CHANGED_WITHIN_SCOPE` | exit 0; 9 artifacts; manifest `f485a6651c2dc38ef67ece684bb781f9af322c49eecded8f42b99eb2c00b535f` |
| Successful `openat2(O_PATH)` | workload exit 0; object attempted/resolved/unresolved `1/0/1`; `JOIN_MISSING=1`, fatal flag 1, transport `INCOMPLETE` | exit 1: no complete producer close boundary |
| OverlayFS create/open | workload exit 0; object `1/0/1`; `JOIN_AMBIGUOUS=1`, fatal flag 1, transport `INCOMPLETE` | exit 1: no complete producer close boundary |
| OverlayFS FD received with SCM_RIGHTS, then written | 3 pairs, 6 events, transport `COMPLETE`; object `1/1/0` | exit 0; 6 artifacts; manifest `0686fa9db5c06d0809cff9b6c905a464e7464edf8f45e76f66c4c4b5f3ad1810` |

`object A/B/C` denotes attempted/resolved/unresolved object joins. Every case
had a durable WAL, an empty/frozen producer boundary, a completed drain, and
zero ring-buffer drops. The two incomplete cases were retained only because
the runner was explicitly invoked with `--allow-incomplete-transport`; they
cannot pass normal offline verification.

The unchanged smoke case resolved the successful regular-file open, the
regular-file write, and the stdout pipe write. Write-side objects correctly
had `path.quality=NOT_REQUESTED`, `path.authority=NONE`, and no path payload.

The OverlayFS open exercised the real backing-file re-entry into
`security_file_open`; the second hook caused an ambiguity instead of silently
choosing one object. For the separate write case, a cgroup-external one-shot
test server opened the file and passed its FD with SCM_RIGHTS. The observed client
performed the positive write. Its `FILE_OBJECT` had filesystem magic
`0x794c7630` (OverlayFS), not backing ext4, and path `NOT_REQUESTED`. This
confirms that the emitted identity is the syscall-visible OverlayFS file. The
current evidence ABI does not count duplicate write-hook invocations, so this
run alone does not prove that a backing-file permission hook occurred or that
the BPF first-wins branch executed; that ordering remains a code-reviewed
contract rather than a separately attested runtime count.

## Offline trust-policy negatives

The current release verifier was invoked from the Host. The positive shape was:

```sh
BIN=.output/cargo-target/release/bpf-state-observer
RUNS=.output/validation/system-effects-current-20260913/runs

"$BIN" verify-effects \
  --run-dir "$RUNS/run-identical" \
  --expected-recorder-sha256 8a4ebbdf9ff400d77609a6e5916c2383ffe6417c0cc9e25e4a9e3367f233ac76 \
  --expected-profile balanced \
  --expected-object-resolution kernel-file-open-write-partial \
  --expected-filesystem-state-scope config/filesystem-scope.example.json
```

The identical, changed, and OverlayFS-write runs returned exit 0. The O_PATH
and duplicate-open diagnostic runs returned exit 1. Independently, verifying
the identical run with `kernel-file-open-partial` was rejected as an external
object-mode mismatch, and omitting its externally trusted filesystem scope was
rejected.

## Strict interpretation

- Direct attribution proves only that the selected syscall caller was in the
  exact run cgroup at syscall entry. Every report retains
  `CAUSAL_NOT_ESTABLISHED`; daemon-mediated effects are not attributed.
- Filesystem confirmer v1 can prove a typed difference within its explicit
  roots and field policy. Even complete identical endpoints remain
  `INCONCLUSIVE`; a caller-supplied static actor contract cannot authorize
  `UNCHANGED_WITHIN_SCOPE`.
- `FILE_OBJECT` is an event-time kernel-derived tuple. Inode generation is
  optional, so it does not rule out inode reuse or establish lifetime-stable
  identity.
- Network final state, remote effects, sysctl, mounts, modules, keyrings,
  mmap writes, io_uring, compat ABIs, delegated effects, and general
  whole-kernel state remain outside this validated contract.
- The standalone runner targets cooperative workloads. An outer sandbox is
  still required to resist a privileged adversary and isolate the evidence
  directory.

The exact copied inputs, run artifacts, doctor reports, effective config, and
serial log are retained locally under
`.output/validation/system-effects-current-20260913/`. That directory is a
local ignored and unauthenticated validation archive, not a hermetic
repository fixture or a signed harness transcript. The QEMU argv and root
image digest were not archived, so the corresponding environment bullets are
contemporaneous operator records rather than independently replayable proof.
