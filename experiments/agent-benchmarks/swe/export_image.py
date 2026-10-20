#!/usr/bin/env python3
"""Bounded registry download to Docker archive; no Docker daemon on the Host."""

import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path


def checked_output(arguments, maximum=1024 * 1024):
    completed = subprocess.run(arguments, capture_output=True, timeout=60)
    if completed.returncode:
        raise RuntimeError(completed.stderr.decode("utf-8", "replace")[-4096:])
    if len(completed.stdout) > maximum:
        raise ValueError("registry response exceeds bound")
    return completed.stdout


def export(crane, reference, output, maximum_compressed=4 * 1024**3,
           maximum_archive=8 * 1024**3, timeout=1200):
    if output.exists() or output.with_suffix(output.suffix + ".part").exists():
        raise ValueError("export destination must be new")
    output.parent.mkdir(parents=True, exist_ok=True)
    digest = checked_output([str(crane), "digest", "--platform", "linux/amd64", reference]).decode().strip()
    if not digest.startswith("sha256:") or len(digest) != 71:
        raise ValueError("registry returned invalid manifest digest")
    repository = reference.split("@")[0]
    if ":" in repository.rsplit("/", 1)[-1]:
        repository = repository.rsplit(":", 1)[0]
    pinned = repository + "@" + digest
    raw = checked_output([str(crane), "manifest", "--platform", "linux/amd64", pinned])
    if hashlib.sha256(raw).hexdigest() != digest[7:]:
        raise ValueError("registry manifest bytes do not match the pinned digest")
    manifest = json.loads(raw)
    layers = manifest.get("layers")
    if not isinstance(layers, list) or not 1 <= len(layers) <= 256:
        raise ValueError("expected a bounded image manifest, not a multi-platform index")
    compressed = sum(layer["size"] for layer in layers)
    if compressed > maximum_compressed:
        raise ValueError("compressed image exceeds download budget")
    partial = output.with_suffix(output.suffix + ".part")
    log_path = output.with_suffix(output.suffix + ".download.log")
    start = time.monotonic()
    with log_path.open("xb") as log:
        process = subprocess.Popen([str(crane), "pull", "--platform", "linux/amd64", "--format", "tarball",
                                    pinned, str(partial)], stdout=log, stderr=log)
        try:
            while process.poll() is None:
                if time.monotonic() - start > timeout:
                    raise TimeoutError("registry image export timed out")
                if partial.exists() and partial.stat().st_size > maximum_archive:
                    raise ValueError("expanded Docker archive exceeds storage budget")
                time.sleep(.2)
            if process.returncode:
                raise RuntimeError("registry export failed; see " + str(log_path))
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    if partial.stat().st_size > maximum_archive:
        raise ValueError("expanded Docker archive exceeds storage budget")
    sha = hashlib.sha256()
    with partial.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            sha.update(chunk)
    partial.rename(output)
    provenance = {"reference": reference, "pinned_reference": pinned,
                  "image_config_digest": manifest["config"]["digest"],
                  "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                  "compressed_layer_bytes": compressed, "archive_bytes": output.stat().st_size,
                  "archive_sha256": sha.hexdigest(), "download_seconds": time.monotonic() - start,
                  "maximum_compressed_bytes": maximum_compressed, "maximum_archive_bytes": maximum_archive}
    with output.with_suffix(output.suffix + ".json").open("x") as stream:
        json.dump(provenance, stream, indent=2)
        stream.write("\n")
    return provenance


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--crane", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(export(args.crane.resolve(), args.image, args.output)))


if __name__ == "__main__":
    main()
