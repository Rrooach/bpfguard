#!/usr/bin/env python3
"""Fetch a bounded, genuine Verified task and a pinned official harness."""

import argparse
import hashlib
import json
import re
import urllib.parse
import urllib.request
from pathlib import Path


DATASET = "princeton-nlp/SWE-bench_Verified"
HARNESS_REVISION = "3f01bd622c0a22c00406139f69a234ef08225f22"
HARNESS_VERSION = "3.0.17"
MAX_RESPONSE = 32 * 1024 * 1024


def download(url, maximum=MAX_RESPONSE):
    request = urllib.request.Request(url, headers={"User-Agent": "observer-benchmark-pilot/1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("response exceeds bounded download size")
        return data, {"url": response.url, "etag": response.headers.get("ETag"),
                      "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def write_new(path, value):
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, ensure_ascii=False, indent=2)
        output.write("\n")


def validate_instance(row, instance_id):
    if row.get("instance_id") != instance_id:
        raise ValueError("dataset instance identity mismatch")
    for field in ("repo", "base_commit", "patch", "test_patch", "problem_statement", "version"):
        if not isinstance(row.get(field), str) or not row[field]:
            raise ValueError("missing task field: " + field)
    if not re.fullmatch(r"[0-9a-f]{40}", row["base_commit"]):
        raise ValueError("base_commit must be a full SHA-1")
    for field in ("FAIL_TO_PASS", "PASS_TO_PASS"):
        tests = json.loads(row[field])
        if not isinstance(tests, list) or not all(isinstance(test, str) for test in tests):
            raise ValueError("invalid expected tests: " + field)
    if not json.loads(row["FAIL_TO_PASS"]):
        raise ValueError("no fail-to-pass test declared")
    return row


def prepare(output, instance_id):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+__[A-Za-z0-9_.-]+-[0-9]+", instance_id):
        raise ValueError("invalid instance ID")
    output.mkdir(parents=True, exist_ok=False)
    dataset_url = "https://huggingface.co/api/datasets/" + DATASET
    before, before_source = download(dataset_url, 1024 * 1024)
    revision = json.loads(before)["sha"]
    query = urllib.parse.urlencode({"dataset": DATASET, "config": "default", "split": "test",
                                    "where": '"instance_id"=\'' + instance_id + "'", "length": 2})
    raw, row_source = download("https://datasets-server.huggingface.co/filter?" + query)
    response = json.loads(raw)
    rows = response.get("rows", [])
    if len(rows) != 1 or rows[0].get("truncated_cells"):
        raise ValueError("expected exactly one complete official dataset row")
    row = validate_instance(rows[0]["row"], instance_id)
    after, after_source = download(dataset_url, 1024 * 1024)
    if json.loads(after)["sha"] != revision:
        raise ValueError("dataset revision changed during download")
    write_new(output / "task.json", [row])
    with (output / "dataset-response.json").open("xb") as target:
        target.write(raw)
    # The model sees only the issue. Gold and test patches remain evaluator inputs.
    with (output / "issue.txt").open("x", encoding="utf-8") as target:
        target.write(row["problem_statement"] + "\n")
    archive, harness_source = download("https://codeload.github.com/SWE-bench/SWE-bench/tar.gz/" + HARNESS_REVISION)
    archive_path = output / "harness.tar.gz"
    with archive_path.open("xb") as target:
        target.write(archive)
    write_new(output / "provenance.json", {
        "schema_version": 1, "benchmark": "SWE-bench Verified", "dataset": DATASET,
        "split": "test", "instance_id": instance_id, "dataset_revision_observed": revision,
        "row_binding": "OFFICIAL_DATASET_SERVER_RESPONSE_WITH_STABLE_REVISION_BEFORE_AND_AFTER",
        "dataset_sources": [before_source, row_source, after_source],
        "task_sha256": hashlib.sha256((output / "task.json").read_bytes()).hexdigest(),
        "harness_repository": "https://github.com/SWE-bench/SWE-bench",
        "harness_version": HARNESS_VERSION, "harness_revision": HARNESS_REVISION,
        "harness_source": harness_source,
        "selection": "ONE_PREDECLARED_SMALL_REQUESTS_TASK; NO_LEADERBOARD_SCORE",
    })
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--instance-id", default="psf__requests-1142")
    args = parser.parse_args()
    prepare(args.output_dir, args.instance_id)
    print(json.dumps({"prepared": str(args.output_dir), "instance_id": args.instance_id}))


if __name__ == "__main__":
    main()
