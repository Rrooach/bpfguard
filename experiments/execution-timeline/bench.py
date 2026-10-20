#!/usr/bin/env python3
"""Small paired wall-clock overhead experiment, not a production SLA.

Same stopped launch, cgroup, input, command and output, with Observer OFF,
timeline without stacks, timeline with stacks and (optional) live JSON. The
warmup is outside the timed window. All raw repetitions are retained.
"""
import argparse
import json
from pathlib import Path
import random
import statistics
import subprocess
import sys

from common import digest, write_new


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collector", type=Path, required=True)
    parser.add_argument("--object", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--seed", type=int, default=1017)
    parser.add_argument("--compare-live-json", action="store_true")
    parser.add_argument("--workload", choices=["grep", "read16k"], default="grep")
    args = parser.parse_args()
    if not 3 <= args.repetitions <= 30:
        parser.error("3..30 paired repetitions required")
    args.output.mkdir(parents=True, exist_ok=False)
    before = digest(args.source)
    modes = {"off": ["--no-trace"], "timeline": ["--no-kernel-stacks"], "timeline-stacks": []}
    if args.compare_live_json:
        modes["timeline-live-json"] = ["--live-json"]
    rows, reference_output = [], None
    for block in range(args.repetitions):
        order = list(modes)
        random.Random(args.seed + block).shuffle(order)
        for position, mode in enumerate(order):
            # Establish warm input before starting Observer/measurement. No
            # content-hashing confirmer runs after this warmup in the window.
            subprocess.run(["dd", "if=" + str(args.source), "of=/dev/null", "bs=1048576", "status=none"], check=True)
            directory = args.output / f"block-{block:02d}-{position}-{mode}"
            command = [sys.executable, "-B", str(Path(__file__).with_name("run.py")),
                       "--collector", str(args.collector.resolve()), "--object", str(args.object.resolve()),
                       "--output", str(directory), *modes[mode], "--"]
            command += (["/usr/bin/grep", "-F", "-c", "--", "xxxx", str(args.source)] if args.workload == "grep" else
                        ["/usr/bin/dd", "if=" + str(args.source), "of=/dev/null", "bs=16384", "status=none"])
            subprocess.run(command, check=True)
            info = json.loads((directory / ("baseline.json" if mode == "off" else "manifest.json")).read_bytes())
            tool = info["tools"][0]
            if tool["result"] not in (0, 1) or not tool.get("cgroup_empty") or tool.get("cleanup"):
                raise RuntimeError("overhead repetition did not complete the fixed work naturally")
            output_identity = digest(directory / "tool-0000/stdout")
            if reference_output is not None and output_identity != reference_output:
                raise RuntimeError("paired command outputs differ")
            reference_output = output_identity
            row = {"block": block, "position": position, "mode": mode, "directory": str(directory),
                   "wall_ns": tool["end_ns"] - tool["begin_ns"], "rusage": tool.get("rusage"),
                   "stdout": output_identity, "boot_id": info["boot_id"]}
            if mode != "off":
                report = json.loads((directory / "report.json").read_bytes())
                row.update(timeline_status=report["critical_path"]["status"],
                           health=report["health"], evidence_bytes=(directory / "capture/events.bin").stat().st_size,
                           events=report["totals"]["events"])
            rows.append(row)
    if digest(args.source) != before or len({row["boot_id"] for row in rows}) != 1:
        raise RuntimeError("fixed input/boot changed during overhead experiment")
    summary = {}
    for mode in modes:
        group = [r for r in rows if r["mode"] == mode]
        ratios = [r["wall_ns"] / next(o["wall_ns"] for o in rows if o["block"] == r["block"] and o["mode"] == "off") - 1 for r in group]
        summary[mode] = {"samples": len(group), "wall_median_ns": statistics.median(r["wall_ns"] for r in group),
                         "wall_min_ns": min(r["wall_ns"] for r in group), "wall_max_ns": max(r["wall_ns"] for r in group),
                         "paired_slowdown_median": statistics.median(ratios), "paired_slowdown_all": ratios,
                         "all_timelines_reconstructed": all(r.get("timeline_status", "RECONSTRUCTED_WITHIN_SELECTED_MODEL") ==
                                                            "RECONSTRUCTED_WITHIN_SELECTED_MODEL" for r in group)}
    report = {"schema_version": 1, "scope": "WARM_SINGLE_FILE_PAIRED_MICROBENCH_NOT_TERMINAL_SCORE_OR_PRODUCTION_SLA",
              "workload": args.workload,
              "timing": "SIGCONT_RELEASE_TO_ROOT_WAIT_AND_CGROUP_EMPTY_OBSERVATION; POSTPROCESSING_EXCLUDED",
              "seed": args.seed, "source": {"path": str(args.source), **before}, "rows": rows, "summary": summary,
              "limitations": ["small sample; report every repetition and range", "shared physical Host noise not eliminated",
                              "does not measure whole Agent/LLM slowdown", "disabled mode uses same stopped launch and cgroup"]}
    write_new(args.output / "overhead.json", report)
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
