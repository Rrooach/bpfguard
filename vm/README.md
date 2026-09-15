# Target VM requirements

The default recorder mode uses fixed raw-syscall tracepoint layouts and does
not consume BTF. The explicit `kernel-file-open-partial`,
`kernel-file-open-write-partial`, and `kernel-object-expanded-partial` modes
additionally require BTF and an active BPF LSM. The expanded mode also requires
the exact path/inode/mmap/socket hook ABI and a separately measured lifecycle
BPF object; it is accepted only when both objects load and every required
program attaches. All modes must still be runtime-tested on the experiment
kernel. The daemon records the actual release, boot ID,
optional BTF hash, and recorder
object hash. It enforces the recorder hash supplied by trusted policy, but does
not yet enforce a complete expected kernel image/probe-matrix manifest.

<a id="reproducible-privileged-e2e"></a>

## Authenticated `exclusive-vm-v1` acceptance gate

[`run-e2e.sh`](run-e2e.sh) is the strict x86-64 acceptance path. The raw
rootfs and its root SSH credential are external provisioning inputs, so this is
auditable rather than hermetic. The SSH key is never copied into the audit
directory and is usable only during the first of two separate boots:

1. The provisioning boot uses a private qcow2 overlay and loopback-only SSH to
   install the measured static PID1, Observer, recorder, public verification
   keys, scopes, semantic checkers, and exact fixture file capabilities. It
   never runs Observer. After a clean poweroff, the Host freezes, hashes,
   flattens, and inspects that root offline.
2. The strict boot starts from a read-only child of the frozen root, supplies a
   fresh ext4 evidence disk, has no NIC, SSH, systemd, or default QEMU devices,
   and selects the measured static `strict-init` as PID1. The only Host control
   channel is a named virtio-serial port connected to the Host-only Ed25519
   signer.

The static PID1 mounts and validates proc/sysfs/cgroup2/tracefs/bpffs itself,
requires an initially empty global Program/Map/Link and BPF-FD inventory,
irreversibly disables unprivileged BPF and module loading, delegates one cgroup
root, and launches one UID/GID 65534 runner with a closed capability bounding
set. The root disk remains block-read-only and the evidence mount is
`nosuid,nodev,noexec`.

The strict Guest must then pass all of these checks:

1. `doctor` reports `ready_for_runtime=true` with no failed prerequisite.
2. A real outside-cgroup TGID creates and destroys a transient HASH Map while
   the production recorder gate is armed; the gate must reject the interval
   with exactly one outside `bpf()` attempt.
3. Authenticated no-op, ephemeral Map, and transient-update/restore/destroy
   runs finalize with exactly 2, 6, and 10 events. All three must produce
   `UNCHANGED_WITHIN_SCOPE`, complete state/evidence, authenticated
   `QUIESCENT_WITHIN_MODEL`, and exclusive actor attribution.
4. Every workload authorization follows the ordered
   `PRE_S0 -> S0_COMMITTED -> PRE_S1 -> FINAL -> FINAL_ACK` protocol. The Host
   signer must close exactly three sessions; missing trust inputs, a wrong key,
   and a one-byte evidence mutation must all be rejected in both Guest and Host
   verification.
5. The final global inventories, bpffs root, run cgroups, process census, and
   PID1 BPF-FD census are empty. The read-only root hashes identically before
   and after strict boot.
6. The Host recovers a copy of the evidence filesystem, reruns `verify-run`
   and the semantic checker, closes an exact file inventory, and writes
   `SHA256SUMS` before printing the sole acceptance marker
   `BPF_OBSERVER_EXCLUSIVE_VM_E2E_PASS`.

Build the current source tree's disposable acceptance kernel first:

```sh
make vm-kernel
```

The builder claims only a new or empty output directory and records an
ownership marker there. A later build accepts a non-empty directory only when
that marker is valid. It refuses source directories, source-tree ancestors,
the project output root itself, and the shared temporary subtree; the Makefile
default is the dedicated `.output/vm-kernel/` child.

This build deliberately disables BTF because the baseline recorder does not
consume it, and disables `CONFIG_BPF_PRELOAD` so kernel-created iterator Links
cannot pollute the empty endpoint baseline. It enables the legacy ATA and E1000
drivers expected by the raw Debian test image.

Kernel-object tests use a separate profile; they do not silently strengthen or
slow the default baseline:

```sh
make vm-effects-kernel \
  VM_EFFECTS_PAHOLE=/absolute/path/to/pahole-1.22-or-newer \
  VM_KERNEL_JOBS=8
```

This builds into `.output/vm-kernel-effects/` and applies
[`effects-object-x86.config`](effects-object-x86.config) after the BTF-free
overlay. The builder refuses the profile unless the effective configuration
contains `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_BPF_LSM=y`, the required
security/cgroup options, `CONFIG_SECURITY_PATH=y`, built-in nftables,
dummy/veth/TAP, IPv6 multiple-table routing, representative tc
qdisc/classifier/action support, and a
`CONFIG_LSM` list containing `bpf`. It builds `modules` as well as `bzImage` so
the expanded state E2E can build its empty marker module against the exact
`Module.symvers`. It also requires the resulting `vmlinux` to contain a `.BTF`
section. Runtime
acceptance still has to verify both a readable non-empty
`/sys/kernel/btf/vmlinux` and `bpf` in `/sys/kernel/security/lsm`; a valid
build alone is not proof that the booted kernel activated BPF LSM.

## Expanded object/lifecycle/Linux-state VM acceptance

[`run-expanded-effects-e2e.sh`](run-expanded-effects-e2e.sh) is the privileged
acceptance gate for `kernel-object-expanded-partial`. It starts one uniquely
named KVM process on a caller-selected loopback SSH port and records that
process's PID, start time, and executable identity before it can ever be
signalled. The external raw root image is attached with QEMU `snapshot=on`;
the test deliberately mutates the Guest and must never run against a durable
machine or writable production image.

The Host gate rebuilds the release binary and both BPF objects, builds the
test-only module against the exact effects kernel, measures every copied
input, provisions the disposable Guest, recovers the complete evidence tree,
and powers off only its own identity-checked QEMU process. Run it with:

```sh
make vm-effects-kernel \
  VM_EFFECTS_PAHOLE=.output/toolchain/install-static/bin/pahole \
  VM_KERNEL_JOBS=64

bash vm/run-expanded-effects-e2e.sh \
  --rootfs /absolute/path/to/trixie.raw \
  --ssh-key /absolute/path/to/trixie.id_rsa \
  --ssh-port 10029
```

The Guest gate performs these bounded cases:

1. The object-v2 fixture creates directories, symlinks and a FIFO; creates,
   writes, chmods/chowns (including `fchmodat2`), changes xattrs, establishes
   shared-writable mmap and mprotect channels, records anonymous/private
   mprotect as explicitly unsupported, exercises both `unlinkat` flag forms
   under the generic `PATH_ENTRY_REMOVE` label, creates hard
   links with both `link` and `linkat`, renames and deletes files; performs
   loopback bind/connect/accept; and forks, execs and exits before restoring
   filesystem state. Every corresponding result must carry the expected
   kernel object kind/role. Independent `fstat` plus
   `statx(STATX_MNT_ID_UNIQUE)` values emitted by the workload must match the
   exact resolved open path and remain identical across the fixture's write,
   metadata, xattr, mmap/mprotect, link, rename and unlink records.
   Bind/connect/accept must resolve as `AF_INET`/`SOCK_STREAM`/TCP; their
   cookies and endpoints must match the ports and three distinct `SO_COOKIE`
   values read back by the workload, and accepted peer identity must come from
   post-accept kernel socket state.
2. The separate socket-state WAL/JSONL/health stream must contain exact
   syscall-entry owner links for bind, connect and accept, exercise
   `ACCEPT_SNAPSHOT`, `TRANSITION` and `DESTROY`, report zero unsupported
   sockets for the fixture, and close with lossless `COMPLETE` health.
   Lifecycle WAL/JSONL must be lossless and terminal for admitted events, but
   schema v2 health must remain `PARTIAL` because S0 and cgroup-entry enrollment
   are not proved. Identical Linux endpoints remain `INCONCLUSIVE`, never a
   fabricated whole-system unchanged verdict.
3. A scope containing a nonexistent sysctl must finalize honestly as
   `INCOMPLETE`/`INCONCLUSIVE`, and the offline verifier must reproduce that
   result.
4. A production `deployment-observe` Direct run discovers a pre-frozen live
   cgroup root, registers it before resume, observes an object workload in an
   ephemeral child created only after `READY`, and completes only after the
   child is gone and the root is frozen again. The same run enables BPF,
   filesystem and Linux-state S0/S1 confirmers. A pinned HASH Map and a
   persistent file must be reported `CHANGED_WITHIN_SCOPE`, all nine endpoint
   artifacts and the three socket-state artifacts must be in the closed set,
   and offline verification must bind their external scopes and digests. The
   overall evidence status deliberately remains `INCOMPLETE`: global BPF S0/S1
   has no authenticated exclusive-actor contract and the sysctl confirmer is
   not deployment-namespace complete.
5. Docker- and Kata-shaped fixtures exercise production live procfs, cgroup
   v2, namespace and sysfs discovery, dynamic descendant observation, state
   confirmation and closure revalidation. The Docker fixture uses a real
   nested PID namespace whose init has namespace PID 1. The Kata fixture uses
   real Host processes, a regular virtual-disk resource and a real TAP
   interface. The process names and runtime identities are synthetic: this is
   explicitly not a real Docker runtime, real Kata runtime or Kata Guest E2E.
6. A state fixture toggles one sysctl, leaves a tmpfs mounted, creates a dummy
   interface/address/route/qdisc/nftables table, and loads an empty test-only
   module. Sysctl, mount, local-network, and module domains must each report
   `CHANGED_WITHIN_SCOPE`; the managed process cgroup must be empty at S1.
7. A negative fixture leaves a sleeping descendant. The managed process-tree
   timeout must abort before the empty/frozen endpoint barrier, mark the run
   failed, kill the exact cgroup, and refuse a false residual-process
   confirmation.
8. After the functional cases pass, four excluded warm-up blocks and twelve
   measured blocks compare `user-input` with
   `kernel-object-expanded-partial` plus lifecycle and socket-state collection.
   Every block runs both modes at both 0 and 1024 identical file-effect
   iterations. A four-row schedule cross-balances load and mode order. Every
   arm must finalize losslessly and pass offline verification. Raw wall time,
   user/system CPU, RSS, context switches, and per-stream event and byte counts
   are retained in `overhead-paired/summary.jsonl`; warm-ups are retained only
   in `warmup-summary.jsonl` and excluded from inference. The Guest writes only
   a `collection_status=PASS` marker. After recovery, the Host analyzer computes
   each block's
   `[(expanded-user)@1024-(expanded-user)@0]/expanded_system_event_delta`,
   exact rational block estimates, and an exact distribution-free 95% median
   interval. Its statistical gates decide `USABLE_ESTIMATE` versus
   `EXPLORATORY_LOW_CONFIDENCE`; collection success is never presented as an
   accepted overhead conclusion.

Each positive run is then passed through `verify-effects`, which independently
replays the syscall, lifecycle and socket-state WALs, checks their canonical
JSONL projections and exact origin links, and recomputes enabled endpoint-state
comparisons.
The retained `.output/validation/expanded-effects-vm/<run>/` directory contains
measured inputs, QEMU argv/console, Guest stdout/stderr, recovered evidence,
external image/QEMU hashes, and `SHA256SUMS`. This is a cooperative-workload
functional gate, not a hostile-Guest containment or delegated-causality claim.

## Allox supervisor protocol VM acceptance

[`effects-supervisor-e2e.sh`](effects-supervisor-e2e.sh) exercises the
production per-run sidecar against an already-created cgroup-v2 leaf. It sends
`START` over the trusted private input channel, independently verifies the
response-authenticated `READY`, moves the fixed workload into the leaf,
enforces an empty-and-frozen barrier, sends exact-bound `FINISH`, and
independently verifies the `FINALIZED` HMAC and manifest digest. Protocol v1
does not request-MAC `START` or `FINISH`. The test also requires the exact
five-file closed set. The script depends only on Bash, OpenSSL, and standard
core utilities in the Guest.

After copying the built Observer, recorder object, workload, and this script
into a disposable privileged VM, run it with new absolute evidence and cgroup
paths:

```sh
sudo vm/effects-supervisor-e2e.sh \
  /opt/observer/bpf-state-observer \
  /opt/observer/system_effects.bpf.o \
  "$TRUSTED_EFFECT_SHA256" \
  /var/lib/allox/audit/effects-run-1 \
  /sys/fs/cgroup/allox/effects-run-1 \
  /opt/observer/system-effects-smoke \
  /tmp/system-effects-supervisor-1
```

The driver creates and later removes only the named cgroup; it retains the
evidence directory and stderr diagnostic beside it. A PASS validates the real
BPF load/attach and protocol/finalization path, but it emulates the Allox
lifecycle and is not a full Workspace daemon/Bubblewrap integration test.

The external provisioning image must satisfy all of the following:

- a maintained raw x86-64 disk image that boots from `/dev/sda` with the
  separately built kernel and has the user-space tools needed by the Guest
  script (`bash`, `grep`, `awk`, `stat`, `mount`, and coreutils);
- a private SSH key whose public key is already authorized for unattended
  `root` login in that image; protect this key as a privileged test secret;
- Guest networking configured by DHCP and an SSH service that accepts root
  public-key login during provisioning;
- `setcap`, `getcap`, `find`, `sha256sum`, and `/bin/bash`. The strict boot does
  not rely on the image's init system or pre-existing virtual-filesystem
  mounts.

Supply the image and matching private key explicitly:

```sh
make vm-e2e \
  KERNEL_BZIMAGE=.output/vm-kernel/arch/x86/boot/bzImage \
  VM_ROOTFS=/absolute/path/to/test-rootfs.img \
  VM_SSH_KEY=/absolute/path/to/root.id_rsa \
  VM_SSH_PORT=10022
```

The `vm-e2e` Make target depends on `check-all` and `release`, so its PASS also
requires the unit, formatting, Clippy, BPF-build, and C-fixture quality gates.
The latest concrete result and bound identities are in the
[strict validation record](../docs/vm-strict-e2e-validation-2026-09-11.md).

The Host needs usable `/dev/kvm`, `qemu-system-x86_64`, `qemu-img`, OpenSSH,
`debugfs`, `e2fsck`, `setcap` support in the Guest filesystem, and the remaining
dependencies checked explicitly at runner startup. Allow roughly three times
the raw rootfs apparent size, two evidence images, copied inputs, and 1 GiB of
reserve. Every SSH/SCP, signer, workload, and QEMU wait is bounded; cleanup
signals only the exact QEMU child whose PID, start time, and executable still
match.

The retained `.output/vm-e2e/<run>/` directory contains both QEMU argv records,
all non-secret measured inputs, the frozen provisioning chain, original and
recovered evidence images, consoles, Host verification results, a closed
`AUDIT_FILES.txt`, and `SHA256SUMS` (which also binds the external rootfs and
QEMU executable).

This gate remains scoped to the exact measured cooperative fixtures. It is not
a hostile-Guest boundary, remote attestation system, rollback proof, crash
recovery test, compat-ABI test, cross-architecture matrix, or exhaustive
Program/Link and all-Map-type workload suite. The scope permits content capture
for ARRAY, HASH, PERCPU_ARRAY, and PERCPU_HASH; the current strict fixtures
exercise HASH only.

## Kernel build

Start from the target architecture's normal configuration and merge the
future-ready superset fragment
[`bpf-state-observer.config`](bpf-state-observer.config). Build out of tree on a
filesystem with adequate space:

```sh
scripts/kconfig/merge_config.sh -O /disk/build/observer-kernel \
  arch/x86/configs/x86_64_defconfig \
  tools/bpf/bpf-state-observer/vm/bpf-state-observer.config
make O=/disk/build/observer-kernel olddefconfig
make O=/disk/build/observer-kernel -j8 bzImage
```

Use tool versions satisfying `Documentation/process/changes.rst`. In
particular, this source revision requires pahole 1.22 or newer to generate BTF.
Record SHA-256 for the resulting `vmlinux`, `.config`, and VM image.

No LSM or command-handler probe is attached by this baseline. The supplied
fragment enables BTF, BPF LSM, ftrace, and kprobes for later enrichment, but
those options are not baseline runtime requirements.

## Boot-time mounts

The trusted image initialization must establish:

```sh
mount -t cgroup2 none /sys/fs/cgroup
mount -t tracefs none /sys/kernel/tracing
```

Use existing mounts when already present; do not stack duplicate mounts.
Mount bpffs separately only when the selected scope has non-empty
`bpffs_roots`.
Delegate only the workload cgroup subtree to the harness. The Observer and its
artifact directory must remain outside that delegation.

Run the observer through a trusted launcher that also makes the artifact and
configuration paths inaccessible to the workload and constrains the
workload's inherited credentials. The current coordinator moves the child into
the cgroup but does not create user/mount namespaces or perform a UID/GID and
capability drop on its own.

## Preflight

Before accepting a run, verify:

- the actual kernel/image identity matches policy enforced by the VM
  orchestrator (the current `doctor` does not perform that comparison);
- the configured cgroup is v2 and `cgroup.events` is readable;
- tracefs, and bpffs when selected, have the expected filesystem types;
- effective `CAP_SYS_ADMIN` is present for this tree's global enumeration and
  get-FD-by-ID operations;
- `doctor` passes its program/Map/Link get-next-ID and minimum tracepoint
  `perf_event_open` smoke operations (actual recorder load/attach remains the
  definitive check and can still fail closed);
- both raw-syscall tracepoints are available;
- Observer-owned program, map, and link IDs are registered for exclusion;
- no background workload or BPF manager violates the selected harness model;
- requested scope equals effective scope; this version has no downgrade
  negotiation interface.

## Execution gate

The integrated coordinator registers the formal epoch and completes S0 before
it spawns the workload. In the child's `pre_exec`, it installs
`PR_SET_PDEATHSIG(SIGKILL)`, checks the parent-race condition, writes itself to
`cgroup.procs`, and only then executes the requested image. There is no
stopped-child or `clone3(CLONE_INTO_CGROUP)` implementation in this release.

At the end, the parent waits for the root and continues polling until recursive
`cgroup.events` reports `populated 0`; root exit alone is not the end barrier.
It then writes `cgroup.freeze=1` and waits for `frozen 1`. Recorder drain and S1
run while the cgroup stays frozen and registered, followed by a second stable
counter check. S1 is taken before the frozen, empty cgroup is deleted, and this
boundary is recorded as a verdict limitation.

## VM isolation caveat

A dedicated VM removes many background actors but does not automatically prove
quiescence. Startup services, host-side agents, inherited BPF FDs, writable Map
mappings, timers, workqueues, and external attachment mechanisms must still be
enforced away or represented as failed/unknown contract checks.

Run the observer under a service manager/VM supervisor that cleans stale
cgroups after daemon death. `PDEATHSIG` covers the direct child, not arbitrary
descendants, and this release has no startup recovery journal. Handled failure
cleanup uses `cgroup.kill` and reports when the cgroup cannot be removed within
its bounded cleanup interval; the supervisor must then fence and reclaim it.
