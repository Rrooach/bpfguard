# Authenticated exclusive-VM E2E validation — 2026-09-11

## Result

The current x86-64 build passed the full `exclusive-vm-v1` acceptance gate in
a real privileged QEMU/KVM Guest:

```text
BPF_OBSERVER_STRICT_GUEST_E2E_PASS
strict-init: strict suite PASS
BPF_OBSERVER_EXCLUSIVE_VM_E2E_PASS
```

Before the successful run, `make check-all` passed 114 Rust unit tests,
rustfmt, Clippy with warnings denied, the BPF recorder build, both C workload
builds, the static PID1 self-test, and shell syntax checks.

## Runtime shape that passed

The gate used two separate boots. A networked systemd boot only provisioned a
private overlay and cleanly powered off. The acceptance boot used the frozen
root through a read-only qcow2 child, a fresh 256 MiB evidence disk, the
measured static `strict-init` as PID1, `-nodefaults`, no NIC, and one
virtio-serial channel to a Host-only Ed25519 signer.

PID1 observed one userspace process before releasing the runner, empty initial
Program/Map/Link and external BPF-FD inventories, irreversible unprivileged-BPF
and module-loading disablement, a block-read-only root, and a writable
`nosuid,nodev,noexec` evidence mount. The runner executed as UID/GID 65534 from
the delegated `/bpf-state-observer` cgroup with zero effective capabilities;
only the measured Observer and Map fixture obtained their exact file
capabilities on exec.

The final supervisor report proved:

```text
runner_wait_status=0
final_userspace_processes=1
final_pid1_bpf_fds=0
final_bpffs_entries=0
final_global_inventory=VERIFIED_RUNNER_FILECAP_SNAPSHOT_EMPTY
cleanup_complete=true
result=PASS
```

## Strict fixtures and negative controls

All three authenticated runs passed Guest verification, Host verification, and
the independent semantic checker:

| Fixture | Verified events | Endpoint verdict |
|---|---:|---|
| no-op | 2 | `UNCHANGED_WITHIN_SCOPE` |
| ephemeral HASH Map create/update/destroy | 6 | `UNCHANGED_WITHIN_SCOPE` |
| HASH Map create/update/transient-update/restore/destroy | 10 | `UNCHANGED_WITHIN_SCOPE` |

For every row, state completeness and evidence status were `COMPLETE`, the
quiescence status was `QUIESCENT_WITHIN_MODEL`, its basis was
`HARNESS_ENFORCED`, and `exclusive_actor_attribution` was true. The last two
rows demonstrate that this verdict means equal scoped endpoints, not absence
of transient operations.

The production outside-actor gate was also armed around a real transient Map
creation from another TGID. It rejected the interval with the exact marker
`OUTSIDE_BPF_ACTOR_GATE_REJECTED_TRANSIENT_MAP`. Verification without external
trust inputs, with the wrong public key, and after changing one finalized
artifact byte all failed closed in both the Guest and Host checks.

The Host signer verified all three bounded `FINAL_ACK` messages and closed with
`result=COMPLETE sessions=3`.

## Bound identities and audit material

- kernel bzImage SHA-256:
  `87575cfa23d6b918c7b8dcbe8a2e81b9caad35b03d78592c47bd24563d38aeb4`
- effective kernel config SHA-256:
  `07796386cca912b8dfb0d1a2e7b8e522648f8f09e89d66ffce103f366fe56ed6`
- external raw rootfs SHA-256:
  `8960ffec0ada901b292255d9ffbb5d36d9c4bae7b8f39a2d0b1f46726e9dc818`
- Observer SHA-256:
  `de5d9406a121f8b01adc3212b3974c641e5465fdf54bab243d74fa30cfd748de`
- recorder SHA-256:
  `5f3745ce44c87d49014b0043760ee35912b7fdcca37ba07806321704f4e1f1da`
- static PID1 SHA-256:
  `3bc74d2e12163cbb565dc64ee5d1b44b726f40f8afcb2bf8c4b45d4bdf0257ca`
- canonical Host policy SHA-256:
  `acdcf41da064f3c53119cb8154954fe43755b254ff3d541509f7ac35353c24e2`

The ignored local audit directory is:

```text
.output/vm-e2e-strict-final5/20260911T091005Z-186118
```

Its 179-file closed inventory plus the inventory file, external rootfs, and
QEMU executable produced 182 `SHA256SUMS` entries; an independent
`sha256sum -c SHA256SUMS` pass succeeded. The strict root overlay SHA-256 was
identical before and after boot:
`a724bfae2cab867760e4f867f80e4470faf009febabd86cf29f61e773f8d4ee1`.
Only a copy of the frozen original evidence disk was journal-recovered and
inspected.

The successful command was:

```sh
VM_E2E_PROVISION_TIMEOUT_SECONDS=240 \
VM_E2E_STRICT_TIMEOUT_SECONDS=300 \
vm/run-e2e.sh \
  --kernel /disk/bpfguard/linux/.output/vm-kernel-script/arch/x86/boot/bzImage \
  --rootfs /disk/zhongxing/images/trixie.img \
  --ssh-key /disk/zhongxing/images/trixie.id_rsa \
  --ssh-port 10032 \
  --output-dir .output/vm-e2e-strict-final5
```

## Claim boundary

This pass validates the exact measured cooperative fixtures and VM shape. It
does not establish hostile-Guest resistance, remote attestation, rollback
correctness, arbitrary-workload isolation, crash recovery, compat ABIs,
non-x86 targets, or exhaustive Program/Link and all-Map-type behavior. The
scope supports ARRAY, HASH, PERCPU_ARRAY, and PERCPU_HASH content, while this
strict run exercised HASH fixtures only.
