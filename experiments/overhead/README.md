# Observer overhead benchmark

This experiment measures the BPF State Observer separately from Codex or a
model provider. It makes no API request and incurs no model-token cost.

The benchmark deliberately reports several different costs instead of one
misleading percentage:

1. `observe` fixed wall and CPU cost, including recorder load, the native
   canary, cgroup barriers, S0/S1, durable event output, comparison, and the
   finalized manifest. The later offline `verify-run` is excluded.
2. Ordinary-syscall pass-through cost using 100,000 `getpid(2)` calls. This is
   the cost of globally attached raw-syscall programs taking their early
   non-`bpf(2)` return path.
3. Synchronous `BPF_MAP_UPDATE_ELEM` workload-path cost. Pacing sleep is timed
   separately and removed before the direct/observed comparison.
4. Aggregate command CPU for the recorded BPF path, including the workload,
   kernel hooks, ring-buffer consumption, JSONL/WAL serialization, and durable
   output.
5. Command `ru_maxrss` peak differences, event-file footprint, and the largest
   tested zero-loss offered workload rate. This is not a maximum-throughput
   claim.

## Method

One disposable 2-vCPU KVM Guest is used for the whole batch. The controller
and Observer are pinned to Guest CPU 0; the workload pins itself to Guest CPU
1. QEMU's Host threads are not pinned, and the Guest is a normal systemd/SSH
image rather than an exclusive benchmark appliance.

There are three excluded warmups and at least 12 measured blocks. Direct and
observed runs are adjacent and alternate A/B direction. All six cases use a
cyclic Latin-square order so workload size is not tied to time within the
batch:

| Case | Operations | Purpose |
|---|---:|---|
| `noop-0` | 0 | full fixed `observe` envelope |
| `getpid-100000` | 100,000 | ordinary-syscall pass-through proxy |
| `bpf-update-0` | 0 updates + one Map create | BPF-path intercept |
| `bpf-update-4096` | 4,096 updates | slope shape |
| `bpf-update-16384` | 16,384 updates | slope shape |
| `bpf-update-32768` | 32,768 updates | primary endpoint |

BPF updates run in batches of 128 with a 1 ms relative pause. The pause keeps
the 1 MiB ring buffer away from burst saturation. Both paths use exactly the
same pacing, and each actual sleep interval is removed from the synchronous
active-path measurement.

Every observed sample must have a finalized manifest, pass `verify-run`, have
exact syscall/event accounting, and report zero dropped, missing, pending,
outside-cgroup, and parse-failed events. A collection failure invalidates the
batch; samples are never silently discarded.

Derived per-operation metrics use the median of per-block endpoint contrasts:

```text
D_i(N) = observed_i(N) - direct_i(N)
slope_i = (D_i(32768) - D_i(0)) / 32768
estimate = median(slope_i)
```

An estimate is accepted only with at least 12 blocks, a positive outer
bootstrap/distribution-free interval, interval width no more than 50% of the
median, stable leave-one-block-out medians, and at least 80% positive blocks.
BPF slopes additionally require monotonic point medians and limited departure
from the endpoint line. Rejected exploratory numbers stay in `report.json` for
auditability but have `accepted_median: null`.

## Run

First run the local, non-privileged helper checks:

```sh
make overhead-check
```

Then provide the same kernel, raw rootfs, and root SSH key used by the VM E2E
environment:

```sh
make overhead-e2e \
  KERNEL_BZIMAGE=/absolute/path/to/bzImage \
  VM_ROOTFS=/absolute/path/to/rootfs.raw \
  VM_SSH_KEY=/absolute/path/to/rootfs.id_rsa
```

Optional settings are `OVERHEAD_SSH_PORT` (default `10044`) and
`OVERHEAD_REPETITIONS` (default `12`; allowed values `12, 18, ..., 48` so each
case occupies every Latin-square position equally). The equivalent standalone
entry point is:

```sh
bash experiments/overhead/vm/run-overhead.sh \
  --kernel /absolute/path/to/bzImage \
  --rootfs /absolute/path/to/rootfs.raw \
  --ssh-key /absolute/path/to/rootfs.id_rsa \
  --repetitions 12
```

The raw rootfs is checksum-verified before and after the run and is used only
as the backing file for a retained qcow2 overlay. A normal 12-block batch uses
roughly 0.7-0.8 GiB because it intentionally retains all raw evidence.

## Output and interpretation

Each batch is written below `.output/overhead/<batch-id>/`:

- `REPORT.md`: short accepted/rejected result.
- `report.json`: full statistics, confidence gates, and raw paired timings.
- `guest-results/`: every manifest, health file, snapshot, WAL, JSONL stream,
  workload measurement, and offline verification response.
- `host-summary.txt`: collection, overlay, and immutable-input status.
- `BATCH_SHA256SUMS`: checksum inventory for the retained batch.

“Evidence collection PASS” means the Guest run, extraction, offline verifier,
overlay validation, and input revalidation completed. It does not turn a
statistically rejected metric into a valid performance estimate.

See [the 2026-09-11 validation record](VALIDATION.md) for a concrete run.
