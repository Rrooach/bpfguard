# Codex + DeepSeek collection VM validation — 2026-09-11

## Result

The final aggregate worktree passed the authenticated real QEMU/KVM collection
gate with Codex CLI `0.154.0` calling `deepseek-flash` through DeepSeek's
Responses API:

```text
agent collection run PASS
guest_status=0
host_verify_status=0
overlay_status=0
host_input_status=0
```

The retained batch is:

```text
.output/agent-collection/20260911T152323Z-442350
```

This was a real networked Guest boot and authenticated model execution, not a
mocked provider or userspace-only test. All four fixed tasks passed their
Observer evidence, Codex JSONL, workspace postcondition, and workspace capture
contracts:

```text
00-text-only         events=2   PASS
01-file-write        events=2   PASS
02-ephemeral-map     events=6   PASS
03-transient-restore events=10  PASS
```

The two events in every run are authenticated recorder canaries. The ephemeral
Map task added one `BPF_MAP_CREATE` and one `BPF_MAP_UPDATE_ELEM` syscall pair;
the transient-restore task added one create pair and three update pairs.

The Guest payload was counted and SHA-256 checked before any deployed payload
executed. The root-filesystem file capability census found exactly the expected
fixture:

```text
/opt/bpf-state-observer/map-lifecycle cap_bpf=ep
```

No other executable could acquire one of the capabilities retained in the
Codex bounding set.

## Gates exercised

The post-`exec` split-GID `/proc` isolation test passed with
`fs.suid_dumpable=0` and a permanently zero core limit. The provider probe
workspace was an independently mounted 16 MiB/256-inode tmpfs with UID/GID
65534, mode `0700`, and `nosuid,nodev,noexec`; both the Guest runner and the
credential launcher accepted the measured mount contract. Codex state used a
separate per-batch `nosuid,nodev,noexec` tmpfs, which was successfully emptied
and unmounted.

One accountless invalid-key request reached
`https://api.deepseek.com/responses` and returned HTTP `401 Unauthorized`.
The strict validator accepted exactly four events in this order:

```text
thread.started
turn.started
error
turn.failed
```

Both failure events bound the status and exact endpoint, the messages were
identical, there was no additional retry/error event, and Codex stderr was
empty. This probe performed no authenticated model inference.

`doctor` reported `ready_for_runtime=true` with nine passing checks and one
non-blocking warning: `/sys/kernel/btf/vmlinux` was absent. This recorder uses
the available raw-syscall tracepoints and its calibration passed, so that
warning did not reduce the evidence status.

The deterministic Map calibration produced six attributed BPF events. Both
Guest and Host `verify-run` checks reported:

```text
artifacts_verified=10
events_verified=6
recorder_digest_policy_match=true
evidence_complete=true
state_verdict=INCONCLUSIVE
```

The Guest powered off cleanly. `qemu-img check` found no image error, and the
validated backing chain contained exactly the retained qcow2 overlay followed
by `/disk/zhongxing/images/trixie.img` as raw backing storage. Kernel, raw
rootfs, SSH key, QEMU, and qemu-img identities all matched their pre-boot
size/digest records at the final Host gate. The final overlay identity was:

```text
size=360972288
sha256=a50958382fe1345beeeef2b0826882c294b6af74bca0d56ba2d28a42c142153f
```

`BATCH_SHA256SUMS` was independently rechecked after the run. No QEMU process
for the batch or listener on TCP port 10042 remained.

Before the authenticated retry, rustfmt, the workspace tests, Clippy with
warnings denied, and `make agent-collection-check` passed. The earlier full
`make check-all` gate also passed: 114 Rust unit tests, C/BPF/fixture builds,
the strict-init self-test, both collection-helper self-tests, and all collection
shell syntax checks.

## Token budget

The successful batch used 60,404 input tokens, of which 53,504 were cache hits,
and 678 output tokens. Reasoning tokens (409) are already included in the
output count and are not counted twice. At the execution time, DeepSeek's
official off-peak RMB rates for `deepseek-flash` were 0.02 yuan/M cached input,
1 yuan/M uncached input, and 4 yuan/M output. The calculated successful-run
cost is therefore 0.01068208 yuan.

An initial authenticated batch
`.output/agent-collection/20260911T151134Z-433494` consumed 68,825 input and
377 output tokens. Its workloads and eBPF evidence succeeded, but its two Map
rows were rejected by an overly narrow validator that did not recognize the
Codex-emitted `/usr/bin/bash -lc` wrapper. That retained diagnostic batch cost
0.01664468 yuan at the same rates. The validator now accepts only the exact
fixed direct command or that exact wrapper, compares started/completed command
payloads, and has negative injection tests.

Both authenticated runs together used 130,284 billed tokens and cost an
estimated 0.02732676 yuan. Even applying peak rates to all of them gives only
0.05465352 yuan, far below the 5-yuan limit. Pricing source:
<https://api-docs.deepseek.com/zh-cn/quick_start/pricing/>.

## Bound identities

- kernel bzImage SHA-256:
  `87575cfa23d6b918c7b8dcbe8a2e81b9caad35b03d78592c47bd24563d38aeb4`
- external raw rootfs SHA-256:
  `8960ffec0ada901b292255d9ffbb5d36d9c4bae7b8f39a2d0b1f46726e9dc818`
- QEMU SHA-256:
  `c60d4f42bb600981efacd38a00d737d61d5b435e149da693705b22b21b2cb149`
- qemu-img SHA-256:
  `9474f1f7b0641c142a788119ac284d7963983a647dc175a986ac924bcd30d270`
- Codex SHA-256:
  `3188814c35471432d4123203e0eb38e5bddc60226e3d7ddf0e59e649ea140022`
- Observer SHA-256:
  `de5d9406a121f8b01adc3212b3974c641e5465fdf54bab243d74fa30cfd748de`
- recorder SHA-256:
  `5f3745ce44c87d49014b0043760ee35912b7fdcca37ba07806321704f4e1f1da`
- Map fixture SHA-256:
  `3196cafbdb4b2b27535f71d254d0bb6f631fa5e017bf0c58e6f2786c904f0cb0`
- credential launcher SHA-256:
  `3691522c253e9ba2232caec59246159e54338e14c539b0e13ba66125a5a4fecb`
- task/evidence validator SHA-256:
  `d7a8e4be4ca262648b147fc525e251aee27bdd9ac69390389136081404e4915b`
- Guest suite SHA-256:
  `4a95300ceba8776f2f54c37109a3b12102539292ac52d0b27c83e62e452832d9`
- frozen DeepSeek model catalog SHA-256:
  `bce20f679495809f4fa6e48672b6dcbab84b6adff5251890b6e6a21eddb9c12f`

## Validation boundary

This pass proves deployment, exact Codex/provider configuration, network/TLS
reachability, authenticated `deepseek-flash` task execution, expected invalid
credential rejection without retry, credential and workspace isolation
contracts, real-kernel BPF collection, copied-artifact verification, and final
VM/overlay cleanup. The exact real API key was not present in the exported
batch artifacts.

This networked profile is diagnostic. It is not the harness-enforced
`exclusive-vm-v1` environment, and an equal S0/S1 endpoint remains
`INCONCLUSIVE`; it must not be reported as `UNCHANGED_WITHIN_SCOPE`.
