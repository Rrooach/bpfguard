# Historical unauthenticated VM smoke validation — 2026-09-11

This records the earlier cooperative-root smoke path. It is retained for
comparison and does not describe the current `vm-e2e` target. The current
authenticated `exclusive-vm-v1` result is documented in
[the strict validation record](vm-strict-e2e-validation-2026-09-11.md).

## Result

The current x86-64 native-ABI build passed the cooperative-root smoke gate in
a real privileged QEMU/KVM Guest. QEMU 5.0.0 used `/dev/kvm` and an explicit
per-run qcow2 overlay. The runner verified that the external raw rootfs had the
same SHA-256 before boot and after QEMU was reaped.

```text
BPF_OBSERVER_GUEST_E2E_PASS
BPF_OBSERVER_VM_E2E_PASS
```

Before boot, `make check-all` passed 94 Rust unit tests, rustfmt, Clippy with
warnings denied, and the BPF/C fixture builds. The VM scripts also passed
`bash -n`.

## Bound inputs

- Linux source: `50d05c7c76c96b90462f24debacca971d2e86713`
  (`7.3.0-rc2-00099-g50d05c7c76c9`)
- kernel bzImage SHA-256:
  `87575cfa23d6b918c7b8dcbe8a2e81b9caad35b03d78592c47bd24563d38aeb4`
- extracted effective kernel config SHA-256:
  `07796386cca912b8dfb0d1a2e7b8e522648f8f09e89d66ffce103f366fe56ed6`
- external raw Debian rootfs SHA-256:
  `8960ffec0ada901b292255d9ffbb5d36d9c4bae7b8f39a2d0b1f46726e9dc818`
- Observer binary SHA-256:
  `087462f3d05f79dde0bd9d0361d593ca781834c9ff8fcedf7ecdc4d0a6651bd2`
- recorder object SHA-256:
  `2c528bb9893b236e7fea69b4a807a8893f9f83c9cf8b4e67c750ee795bb24a87`
- semantic checker binary SHA-256:
  `5421e927dcbb06c8504821ea55e87e2bd1a1c4d5d83131fda05600f73b195377`
- gated Map workload SHA-256:
  `971dde9e7b11df8f622f59ce00fa67d94ba58a3ff31a17c96c4d7a8c4cb86aca`
- Guest runner SHA-256:
  `cdad8c0f2fbf23b15b85fc9b4389e4ca1c848055870c6f4214ac15e8dcfa303b`
- Host runner SHA-256:
  `73695ea82b1a9747b3412f2067d4c021eec30b595e2c29e075b9bf4c7e6dcc7a`

The runner copied and hashed the exact kernel, binaries, workload and checker
sources, both scope files, all three VM scripts, and both kernel-config
fragments before boot. The kernel gate required the BPF, cgroup v2/freezer,
tracepoint, perf, ext4, ATA, E1000, serial, configfs, and embedded-config
settings used by this image, and required `CONFIG_BPF_PRELOAD=n`. BTF debug
info was deliberately disabled because this fixed raw-tracepoint recorder does
not consume it; `doctor` therefore reported one non-blocking BTF warning.

## Assertions that passed

### Runtime preflight

`doctor` reported `ready_for_runtime=true`. Required cgroup v2, raw syscall
tracepoints, effective privileges, global Program/Map/Link inventory access,
tracepoint `perf_event_open`, bpffs, cgroup-root access, and recorder ELF checks
all passed.

### Exact-cgroup positive and negative control

The managed ephemeral child published readiness after `exec` in
`/bpf-state-observer/e2e-ephemeral` and remained blocked. While its formal
epoch was active, PID 339 ran the same successful Map lifecycle from the
Guest parent cgroup. The two cgroup paths were checked to differ before the
negative control was released. The finalized event stream contains only
managed PID 337 and no PID/TGID 339 record.

This proves one deterministic positive/negative check of the recorder's exact
cgroup filter. It does not prove hostile-workload isolation or attribution of
all system state changes.

### Ephemeral HASH Map run

- workload exit code: `0`
- finalized artifacts verified: `10`
- recorder events verified: `6` (two native canary records plus two complete
  create/update pairs)
- event returns, pairing, sequence, PID/TGID, cgroup ID, epoch, command, and
  non-zero formal `attr_size` checked structurally
- recorder evidence: `COMPLETE`
- S0/S1 state: `COMPLETE`, no read failures, no fixture remaining
- state result: `INCONCLUSIVE`, with no changes, because authenticated
  quiescence is intentionally absent
- manifest SHA-256:
  `347db09a9e6ed5ff2d83b3624df055efc21b2a3abe588a441963464c3287ae98`
- owned run cgroup absent after finalization

### Frozen and pinned HASH Map run

- workload exit code: `0`
- finalized artifacts verified: `10`
- recorder events verified: `10` (native canary plus complete
  create/update/freeze/pin pairs)
- recorder evidence: `COMPLETE`
- S0 contained no fixture; S1 contained exactly one `obs_fixture` Map and one
  scoped pin
- Map metadata reported `frozen=true`; the pin's object ID equals the Map ID
  (`18`), and its mount namespace/mount ID equals the declared pin root
- exactly one canonical entry, 12 key/value bytes, and digest
  `36da99bfc72562be0526dbfdbb1e8bb21cbc44ae6628f1ab7937e35bd6790e80`
- verdict: `CHANGED_WITHIN_SCOPE`, with exactly two `CONFIRMED ADDED` changes
  (Map and pin)
- manifest SHA-256:
  `64d8ff38b35df628e440da70d60902dcdb9496ed3792fe75a7353c8652928956`
- owned run cgroup and owned fixture pin root absent before Guest success

The pinned result must not be overstated: its verdict remains `PROVISIONAL`,
quiescence is `UNKNOWN`, attribution is `UNATTRIBUTED_SYSTEM_CHANGE`, state
completeness is `INCOMPLETE`, and content status is
`BEST_EFFORT_NON_ATOMIC`.

### Independent consumption and cleanup

Both copied run directories passed a second `verify-run` and a second strict
semantic check on the host. Verification with an all-zero trusted recorder
digest failed. `sha256sum -c SHA256SUMS` passed for all 29 bound inputs and key
outputs. QEMU was stopped and reaped before the Host PASS marker; no process or
listener remained for host-forward port 10029. The retained qcow2 overlay is
clean and only 11 MiB allocated for a 2 GiB virtual disk.

## Audit material and command

The ignored local audit directory is:

```text
.output/vm-e2e-final4/20260911T024122Z-4083134
```

It contains `SHA256SUMS`, the extracted kernel config, exact test inputs,
explicit rootfs overlay, QEMU logs, Guest status, both finalized run
directories, and Host verification/semantic-check reports. The privileged SSH
private key is intentionally neither copied nor hashed into this directory.

The runtime command was:

```sh
SSH_PORT=10029 vm/run-e2e.sh \
  --kernel /disk/bpfguard/linux/.output/vm-kernel-script/arch/x86/boot/bzImage \
  --rootfs /disk/zhongxing/images/trixie.img \
  --ssh-key /disk/zhongxing/images/trixie.id_rsa \
  --output-dir .output/vm-e2e-final4
```

## Remaining validation boundary

This is an externally provisioned, cooperative-root, x86-64 native-ABI smoke
test, not a hermetic release proof. The Observer, semantic checker, and fixture
all ran as root; this does not test a malicious workload's inability to alter
artifacts or kernel state. The recorder digest was calculated by the same test
runner, so the run tests policy plumbing but not externally authenticated
policy distribution.

It does not cover ARRAY/PERCPU_ARRAY/PERCPU_HASH content, persistent Program or
Link fixtures, stress/capacity and forced drops, timeout/descendant/uncatchable
daemon-death recovery, corruption matrices, compat ABIs, non-x86 targets, or
the allox-os integration. No authenticated quiescence harness was supplied, so
`UNCHANGED_WITHIN_SCOPE` remains deliberately unreachable.
