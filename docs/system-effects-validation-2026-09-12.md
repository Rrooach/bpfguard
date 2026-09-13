# System-effect recorder validation, 2026-09-12

## Result

The independent `observe-effects` path passed functional and lossless-transport
validation in a privileged KVM guest. Its offline verifier accepted the final
control, balanced, and stress evidence using externally supplied recorder
digest and profile. A deliberate profile mismatch was rejected.

The 12-block paired overhead experiment completed without a failed or lossy
sample. Aggregate CPU cost per persisted record met every acceptance gate;
wall-clock cost per record remained `LOW_CONFIDENCE` because scheduling noise
made its interval cross zero.

These results validate the documented selected-syscall operation model. They
do not turn it into a whole-kernel state diff or support an
`UNCHANGED_WITHIN_SCOPE` claim.

Later on the same date, the narrow kernel-file-object extension and the Allox
sidecar protocol also passed a separate BTF+BPF-LSM VM validation. Its matched
overhead batches are reported separately below; their numbers must not be
merged with the earlier build's measurements.

## Environment and measured build

- Guest kernel: `7.3.0-rc2-00099-g50d05c7c76c9`
- Boot ID: `9ef2d471-d9ca-46e1-8609-aab2471f17a9`
- Virtualization: KVM, host CPU passthrough, 2 vCPUs, 2 GiB RAM
- Kernel command line included `ia32_emulation=off`
- Benchmark scratch filesystem: tmpfs at `/dev/shm`
- Observer SHA-256:
  `975ddc274bd09a4a786762299bc2819cb811b16bdb3470b76bda2e6f08c2e162`
- System-effect recorder SHA-256:
  `3111970c36477712e0627f17028336fed71aca544bf299ce5a10202d3dd81dea`
- Balanced policy SHA-256:
  `95ea10557204c96aebc43596a475e4a8d41555db076030b2e4b25e0560f49902`

`doctor` reported `ready_for_runtime=true`. cgroup v2, both raw-syscall
tracepoints, global BPF inventory access, tracepoint perf access, bpffs, the
required capabilities, and the recorder ELF all passed. Kernel BTF was absent
and reported as a warning; this fixed tracepoint-ABI recorder does not require
BTF.

## Functional cases

| Case | Profile | Attempt/result pairs | Result |
|---|---:|---:|---|
| Fixed smoke workload | CLI default `control` | 9 | `COMPLETE`; 18/18 records persisted and verified |
| Fixed smoke workload | `balanced` | 11 | `COMPLETE`; 22/22 records persisted and verified |
| File-effect stress, 1024 iterations | `balanced` | 4099 | `COMPLETE`; 8198/8198 records persisted and verified |
| Verify balanced evidence as control | expected `control` | n/a | rejected with policy-profile mismatch |

The balanced smoke recorded directory create/remove, file create/truncate,
rename/unlink, two FD writes, socket create/connect, and a deliberately failing
`bpf(2)` command. The result had:

- zero kernel drops, pending failures, missing pairs, userspace failures, and
  fatal kernel flags;
- a frozen empty-cgroup producer barrier and completed drain;
- a durable WAL and matching JSONL;
- exact 11 attempts and 11 completions.

The 8198-record stress case also had zero loss and zero incomplete pairs. Its
largest userspace callback batch was 413 records against the enforced 4096
record cap. The separate boundary unit test retains record 4096, returns the
controlled yield signal, and rejects an undrained record 4097; this prevents a
continuously replenished ring from making one poll grow the queue without
bound.

`verify-effects` checked the closed six-artifact set, size/SHA-256 bindings,
WAL framing and CRC, WAL/JSONL equality, continuous event sequence, exact
attempt/result pairing, capture layout, syscall filters, compiled policy,
health accounting, and conservative coverage fields. Its successful output
explicitly retained:

```json
{
  "external_recorder_digest_checked": true,
  "transport_complete": true,
  "coverage_complete": false,
  "operation_events_are_state_diff": false
}
```

## Kernel file-object and supervisor extension

The extension used a separately built validation kernel and current release
artifacts:

- Guest kernel: `7.3.0-rc2-00100-g519a81750493-dirty`
- Boot ID: `499a9446-0c9b-462b-8215-ee1a129a9677`
- Kernel bzImage SHA-256:
  `c4f6635971a0fec5c251b53b4f56aead446b1cda85de0891afaf76dd5ee3d543`
- Kernel vmlinux SHA-256:
  `c6329e8f811fbaf6a17300cc4095242e2447d8a0d64975bce5aff8afa5b12c46`
- Effective kernel config SHA-256:
  `73ed42f96c626d903aea700ef5781f9a4654e47e737ac50abc7edbdadef4939c`
- Observer SHA-256:
  `e1d38e51d6ee16ec1731fb1e083c22e2b9eb22bc20b3539c1dadca427b2958cd`
- System-effect recorder SHA-256:
  `1e6a0cced903870046434c79b1a48aa0e9b153a029b0cbb91c79f93404b37261`

The booted Guest exposed readable `/sys/kernel/btf/vmlinux`, an active LSM list
of `capability,selinux,bpf`, writable cgroup v2, securityfs, tracefs, and
bpffs. `doctor --object-resolution kernel-file-open-partial` reported
`ready_for_runtime=true` with no blocker. The authoritative runtime gate then
successfully loaded and attached the actual CO-RE raw-tracepoint plus
sleepable BPF-LSM object; this is stronger evidence than `doctor` alone.

The balanced smoke run finalized with 22/22 records, zero drops, no pending
state, a durable WAL, and a completed empty-cgroup producer barrier. Strict
offline verification accepted all six operation artifacts using the external
digest, profile, and `kernel-file-open-partial` mode. The successful `openat`
result was joined to a `KERNEL_RESOLVED` file identity containing boot ID,
mount ID, device, inode, inode generation, filesystem magic, and a
`RESOLVED_AT_HOOK` kernel path snapshot. The other operations correctly
remained `USER_INPUT_ONLY` or `UNRESOLVED`. Replacing only `before.txt` with
`forged.txt` in a copy of JSONL was rejected with
`system-effect JSONL event does not derive from its WAL record`.

The production `supervise-effects` sidecar then passed a real
`START -> READY -> FINISH -> FINALIZED` run against an externally owned,
sealed cgroup. An independent OpenSSL path recomputed both protocol HMACs. The
workload produced 22/22 durable records with complete transport; finalization
required the same cgroup inode to be empty and frozen and committed exactly
five mode-0600, singly-linked files. The returned and independently measured
manifest SHA-256 was
`eec1c0ed493c0bd8a7420d3dbff66aaf2e35a9850d7ed0410e9ea0989071fb93`.
A separate START with the correct path but a one-off cgroup ID was refused.
This supervisor protocol-v1 run deliberately used `user-input` object
resolution; the kernel file-object result above was validated only through the
standalone path and is not yet exposed by the Allox sidecar.

A separate nine-artifact standalone run combined the operation stream with
explicit BPF S0/S1 snapshots. `verify-effects` independently checked the
trusted scope and recomputed the state verdict. Snapshot state was complete
and had no final delta, but the correct verdict remained `INCONCLUSIVE` with
`unchanged_verdict_authorized=false`: this standalone path lacks the
`exclusive-vm-v1` actor/quiescence and `BPF_USER_SYSCALL` evidence contracts.
This confirms that the layers compose without falsely promoting an empty BPF
diff to proof that the whole system was unchanged.

Both manifests bind the direct-attribution v1 contract. It proves only that a
selected native syscall caller was in the exact run cgroup at syscall entry;
it labels the component `UNCLASSIFIED_CGROUP_MEMBER` and explicitly records
`delegated_effects=NOT_OBSERVED` and
`causal_status=CAUSAL_NOT_ESTABLISHED`.

## Paired overhead result

The experiment used 4 excluded warm-up blocks and 12 measured Williams-order
blocks. Every block ran `quiet-direct`, `quiet-observed`, `effect-direct`, and
`effect-observed` at 0, 128, and 512 logical iterations. The two workloads issue
equal syscall counts but necessarily use different syscall types. The
collector profile was `balanced`, the batch size was 128, and the inter-batch
pause was 1000 microseconds.

All 192 treatments completed. All observed samples reported complete evidence
and zero drops. All 96 observed evidence directories then passed an independent
`verify-effects` replay with the trusted digest and `balanced` profile. Median
incremental persisted records were exactly 0, 1024, and 4096, and the quiet
count remained exactly 6 at every load.

| Metric | Result | Confidence gate |
|---|---:|---|
| Aggregate CPU per persisted record | **3091.7 ns** | `USABLE_ESTIMATE` |
| Distribution-free 95% CPU interval | 2631.6–4080.3 ns | excludes zero; width below estimate |
| Positive CPU block slopes | 12/12 | passes 80% requirement |
| Exploratory wall time per record | 2997.9 ns | `LOW_CONFIDENCE` |
| Distribution-free 95% wall interval | -17466.0–43150.6 ns | crosses zero |
| Positive wall block slopes | 6/12 | fails 80% requirement |
| Median offered rate at 128 iterations | 708800 records/s | descriptive only |
| Median offered rate at 512 iterations | 734605 records/s | descriptive only |

The median attached collection/finalization CPU overhead for the quiet arm was
approximately 59 ms per run across the three load points. Its wall overhead was
approximately 427–508 ms per run and was dominated by object load/attach,
barriers, draining, hashing, fsync, and VM scheduling rather than selected
events. Observed-arm maximum RSS was approximately 45.7 MiB. These are
full-command measurements, not isolated probe-instruction costs or a
maximum-throughput claim.

The wall estimate must not be promoted to an accepted number. A more stable
wall estimate requires additional blocks and CPU placement that isolates the
collector/controller from the workload.

## Matched object-resolution overhead batches

Two further batches used the same current Observer, recorder, kernel, VM, and
balanced policy. Each mode had four excluded warm-up blocks and 12 measured
Williams-order blocks at 0, 128, and 512 iterations. Every one of the 144
measured observed evidence directories across both modes was independently
replayed with `verify-effects`; all passed with complete, lossless transport.
The analyzer was rerun after copying the datasets to the Host, and its output
was byte-identical to the Guest reports.

| Mode | Aggregate CPU/record | Distribution-free 95% interval | Wall/event |
|---|---:|---:|---|
| `user-input` | **4581.2 ns** | 4415.3–5024.2 ns | `LOW_CONFIDENCE` |
| `kernel-file-open-partial` | **5194.9 ns** | 4704.1–5928.2 ns | `LOW_CONFIDENCE` |

Both CPU results passed all acceptance gates with 12/12 positive block slopes.
At the maximum point both persisted 4102 records; the partial-kernel run's
median offered rate was about 686k records/s and observed maximum RSS was
about 44.7 MiB. Its zero-load quiet attached cost had medians of 83.3 ms CPU
and 179.6 ms wall.

The object-mode CPU point estimate is descriptively 13.4% above the
`user-input` point estimate. This is not a randomized direct estimate of the
LSM hook alone: the two modes were collected as sequential matched batches,
their confidence intervals overlap, and the reported cost includes recorder
startup, userspace decode, WAL/JSON serialization, hashing, fsync, drain, and
finalization. Neither wall estimate passed its confidence gates.

## Reproduction

Build and run the functional path as documented in
[`system-effects-observer.md`](system-effects-observer.md). Strictly verify a
run with:

```sh
sudo "$BIN" verify-effects \
  --run-dir "$RUN" \
  --expected-recorder-sha256 "$TRUSTED_EFFECT_SHA256" \
  --expected-profile balanced \
  --expected-object-resolution user-input
```

Run the paired experiment as documented in
[`../experiments/system-effects-overhead/README.md`](../experiments/system-effects-overhead/README.md).
The raw local validation summaries are retained under
`.output/validation/system-effects-final-20260912/`; the full individual
benchmark evidence remains in the disposable VM image used for this run.
The later extension evidence and matched batches are retained under
`.output/validation/evidence-object-1/`,
`.output/validation/evidence-supervisor-3/`,
`.output/validation/evidence-state-5/`,
`.output/validation/object-overhead-1/`, and
`.output/validation/user-input-overhead-2/`.

## Remaining boundary

The standalone launcher inherits the caller's workload credentials and does
not make the evidence directory inaccessible to that workload. Both isolation
claims therefore remain false in the manifest. This validation used fixed,
cooperative workloads. A hostile Agent requires an outer sandbox/harness, and
the offline verifier still assumes its evidence directory is not concurrently
mount-swapped during verification.
