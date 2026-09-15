# Terminal-Bench v4 Observer pilot selection

This pilot contains exactly four CPU-only, single-container Terminal-Bench
tasks. The immutable source is the official
[`v4.0.0`](https://github.com/harbor-framework/terminal-bench/releases/tag/v4.0.0)
release at commit
`452bf305c6daa62fc59061d22133a7cbc7c1572e` and dataset
`terminal-bench/terminal-bench@4.0.0`.

Do not substitute `@latest`. [`selected-tasks.json`](selected-tasks.json)
records the reviewed registry provenance and the independently calculated
Agent-visible source-input digests. The bridge pins the manifest bytes, exact
task set/order, and those local source-input bytes before a task is built or
run. It does **not** query the remote registry to re-resolve a live registry
digest; provisioning the task tree from the recorded release/registry digest
remains an external staging responsibility.
The canonical manifest itself has SHA-256
`0c7ac6d0c450a03d8ff4cca081296cda4964d912c73af76170b1b62ccdd20c20`;
pass that value via the required `--selection-manifest-sha256` argument so the
manifest cannot redefine its own trust contract.

## Exact selection

| Order | Full task name | v4 registry digest | Agent-visible input digest |
| ---: | --- | --- | --- |
| 1 | `terminal-bench/photonic-waveguide-routing` | `sha256:3fd44f4fbc5b862bc1a0b098d3c1295387134edd238ed6f12f2c98ec13e2dccc` | `b04508b623846f6b858e82e2e713f08a25cfa6b14ecde93fb5d0078bfdcf4945` |
| 2 | `terminal-bench/cargo-flight-dispatch` | `sha256:2836dfe6eb2270fcbbfdb119c7cfae8495208a03a7fc691c2efff49bda5b3c61` | `4f296c934c4e107c054f9db3625f64efb75d8dac730b24579fe49de7869ebc67` |
| 3 | `terminal-bench/bun-sourcemap-leak` | `sha256:ac0b0f77da4e8f6c3904133033ec6d8591eb0d3f18205ab28104ea3cf2a5a07f` | `c4b974aff791ca27751b2075df6e18c5c8c3ff7e06a93b5e88970790483a7f72` |
| 4 | `terminal-bench/html-js-filter` | `sha256:832a5b309edca4f1a7c728da5f1ca530c2712f20a0b7f1db6d1bb6e3171a8866` | `cdca4755ced4ed21debd1f1d2aa3440c9f56550ac060f66cd3e54ee0fc2963c0` |

The first task provides a bounded Python numerical workload; the second adds
multi-file source modification and deterministic JSON generation; the third
adds high-volume Bun build and release-file churn; the fourth retains a small
Agent change while exercising the heaviest separate verifier. This ordering is
intentional and must not be sorted alphabetically by a runner.

The declared container resources are allocations, not measured image download
sizes. The selected Agent images are `python:3.13-slim-bookworm`,
`python:3.13-slim-bookworm`, `oven/bun:1.2.15-debian`, and
`python:3.12-slim-bookworm`, respectively. None requests a GPU or privileged
mode. All use `verifier.environment_mode = "separate"`.

## Source-input hash contract

“Agent-visible source input” means exactly:

- `instruction.md`;
- `task.toml`;
- every regular file below `environment/`.

It deliberately excludes `solution/`, `tests/`, `README.md`, and `.gitignore`.
For each included file, calculate SHA-256 over its bytes. Sort POSIX-relative
paths with `LC_ALL=C`; encode each entry as lowercase hash, two ASCII spaces,
the relative path, and a newline. The task-level input digest is SHA-256 over
the concatenated entries. The JSON manifest records every per-file hash as
well as the aggregate.

From an immutable task directory, the aggregate can be reproduced with:

```sh
{
  printf '%s\n' instruction.md task.toml
  find environment -type f -print
} | LC_ALL=C sort |
while IFS= read -r relative_file; do
  sha256sum "$relative_file"
done | sha256sum
```

The first field of the final line must equal that task's
`source_input_manifest_sha256`.

## Fail-closed planned-count assertion

Before an environment build, the controller must resolve the requested inputs
and prove all of the following:

1. resolved task count is exactly `4`;
2. resolved task names are unique;
3. their names equal the four full, organization-prefixed names above;
4. their order equals the table above;
5. each local Agent-visible source-input digest matches the JSON manifest;
6. the manifest bytes supplied by the trusted caller bind the recorded dataset
   name, version, tag, commit, and task registry digests.

Any mismatch must abort before a Docker build, Observer startup, or Agent
execution. In particular, never continue after a task filter resolves zero
items: Harbor has had a documented failure mode in which a nonmatching bare
task-name filter can fall through to running the entire dataset. Use full names
such as `terminal-bench/html-js-filter`, not bare names.

## Ordered risks

1. **Unexpected full-dataset execution.** Enforce the exact planned-count,
   set, and order assertion before any build.
2. **Version drift.** Provision from the recorded dataset tag/commit and
   registry digest, then let the bridge bind the independently supplied
   manifest digest and local Agent-visible inputs. The bridge does not perform
   a live registry attestation.
3. **Build-phase contamination.** Base-image pulls and package installation
   need network access and are not Agent effects. Finish builds before
   `AGENT_START` and exclude their cgroups.
4. **Verifier contamination.** All four verifiers run separately. Close the
   observation at `AGENT_END` before verification starts.
5. **Cargo dependency installation.** A non-empty `apt-packages.txt` or
   `requirements.txt` causes verifier-side installation. The Oracle is expected
   to leave both empty; later Agent runs must report this separately.
6. **Bun event volume.** Release generation exercises many file and mmap hooks.
   Require zero recorder drops rather than extrapolating from the two Python
   tasks.
7. **Browser startup variance.** The HTML task uses a Playwright/Chromium
   verifier with a 1,800-second timeout. Run it last and distinguish verifier
   infrastructure failure from Observer failure.

This selection is intended first for deterministic Oracle integration. A
successful Oracle reward and successful Observer offline verification answer
different questions and both must be retained.
