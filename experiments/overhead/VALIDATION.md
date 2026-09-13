# Observer overhead validation — 2026-09-11

## Outcome

The final paired KVM batch completed successfully:

```text
batch_id=20260911T164929Z-489251
guest_status=0
overlay_status=0
host_input_status=0
repetitions=12
```

The retained `BATCH_SHA256SUMS` inventory was independently rechecked after
shutdown and passed. `qemu-img check` found no overlay error, the exact
qcow2/raw backing chain passed, and every frozen benchmark input revalidated.
Analyzer, Guest, and QEMU stderr files are empty.

After the immutable batch was sealed, the worktree analyzer received stricter
closed-set input checks and claim-only wording changes. Replaying the current
analyzer over the unchanged Guest results produced the same numerical estimates
and acceptance statuses. The embedded analyzer remains available under the
batch input checksum; no retained batch file was rewritten.

This was kernel `7.3.0-rc2-00099-g50d05c7c76c9` in one 2-vCPU KVM boot, with
swap disabled. Guest CPU-frequency governors were not exposed. The recorder
object SHA-256 was
`5f3745ce44c87d49014b0043760ee35912b7fdcca37ba07806321704f4e1f1da`.

## Accepted measurements

| Metric | Median | Range / outer interval | Status |
|---|---:|---:|---|
| fixed `observe` wall, offline verify excluded | 602.603 ms | range 543.567-850.605 ms | descriptive |
| fixed `observe` command CPU | 8.903 ms | — | descriptive |
| `getpid` pass-through increment | 103.84 ns/call | 102.05-107.84 ns/call | `USABLE_ESTIMATE` |
| BPF update synchronous active-path increment | 425.30 ns/update | 414.14-600.29 ns/update | `USABLE_ESTIMATE` |
| BPF update aggregate command CPU increment | 3.418 us/update | 3.365-3.647 us/update | `USABLE_ESTIMATE` |
| paired difference in command `ru_maxrss` peaks | 5.57 MiB | — | descriptive only |

All 12 blocks were positive for the accepted per-operation estimates. The two
BPF estimates also had monotonic intermediate point medians and passed the
predeclared shape check. The active-path value excludes measured pacing sleep;
the aggregate CPU value retains the natural full-command boundary and comes
from microsecond-resolution `wait4` rusage.

The largest tested case executed 32,768 updates and produced 65,538 formal
records (65,540 including the canary). The workload offered a median 111,207
updates/s, or 222,421 formal records/s, with exact accounting and no observed
loss. Its raw JSONL plus WAL footprint was about 439.25 bytes per verified
record: roughly 22.45 MiB JSONL plus 5.00 MiB WAL per observed run.

That is a zero-loss result at the offered workload rate, not a claim that the
recorder's maximum sustainable or durable throughput has been found.
The formal-record rate includes the single Map-create enter/exit pair even
though the fixture's update-loop timer begins after Map creation; at this size
the resulting rate bias is approximately 0.003%.

The case medians for S0+S1 snapshot capture stayed near 0.44-0.57 ms.

## Rejected measurement

No full-pipeline wall-clock per-BPF-update estimate is claimed. Its diagnostic
endpoint median was `-21 ns/update`, the outer interval crossed zero widely
(`-2259` to `4206 ns/update`), only 6/12 blocks were positive, and case medians
were not monotonic. The analyzer therefore emitted:

```text
status=LOW_CONFIDENCE
accepted_median=null
```

This is expected in the tested topology: event serialization runs concurrently
on the controller vCPU, while the fixed durable lifecycle has much larger wall
jitter. Dividing the rejected syscall slope by two would not create a valid
“per-event” cost, so the report does not do that.

## Why the fixed wall cost is large

The approximately 0.6 second fixed envelope is not a 5 second drain timeout
being consumed. The timeout is only a failure bound. The no-op path performs
several 20 ms empty ring-buffer polls (a nominal, source-derived total of
roughly 120 ms) and repeatedly persists atomic JSON, WAL, JSONL, workload
streams, and the final manifest. Those writes use file `fsync`, rename,
directory `fsync`, and final output synchronization. On a qcow2-backed Guest,
those durability operations are a likely leading contributor to the mostly
blocked-time envelope; fixed command CPU was only about 9 ms. This batch did
not instrument individual phases or run a no-fsync A/B test, so it does not
attribute the remaining time or variance exactly.

## Practical reading

For an Agent turn that performs no `bpf(2)` calls, this experiment supports a
roughly 0.6 second per-run durable envelope plus about 104 ns for each `getpid`
call in the tested loop. Other ordinary syscall paths can differ even though
they take the same recorder early-return branch. One million `getpid` calls
would correspond to roughly 104 ms by linear extrapolation from the measured
100,000-call cases; one million calls were not directly tested.

As a linear scaling illustration from the accepted 0-to-32,768 endpoint
slopes, 1,000 recorded BPF updates correspond to approximately 0.43 ms of
synchronous workload-path delay, 3.42 ms of aggregate command CPU, and a
marginal 0.88 MB (0.84 MiB) of raw JSONL+WAL. The CPU value is not serial wall
delay and must not be added to the 0.43 ms value. An actual short run also has
two Map-create records and two canary records. These are scaling examples from
this VM, not universal capacity promises.

The full evidence and generated reports are retained locally at:

```text
.output/overhead/20260911T164929Z-489251/
```
