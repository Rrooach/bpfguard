#!/usr/bin/env python3
"""Fixed real search/preparation/compiler work executed only in the experiment Guest."""
import argparse
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path


def corpus_inventory(root):
    """Content identity of a fixed benchmark source snapshot, outside hot timing.

    GNU grep -r does not follow encountered symlinks. Record them as links, do
    not read their targets; exclude .git both here and in the actual command.
    Hashing warms the page cache: callers must not label this a cold-read test.
    """
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("search corpus must be a fixed directory snapshot")
    inventory, content_bytes = {}, 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name != ".git")
        for name in sorted(dirs + files):
            if name == ".git":
                continue
            path = Path(directory) / name
            relative = str(path.relative_to(root))
            if path.is_symlink():
                inventory[relative] = {"kind": "SYMLINK_NOT_FOLLOWED", "target": os.readlink(path)}
            elif path.is_file():
                digest = hashlib.sha256()
                before = path.stat()
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                after = path.stat()
                if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                        after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise RuntimeError("search corpus changed while hashing: " + relative)
                inventory[relative] = {"kind": "REGULAR_FILE", "bytes": after.st_size, "sha256": digest.hexdigest()}
                content_bytes += after.st_size
            elif not path.is_dir():
                raise ValueError("special file in search corpus: " + relative)
    if not any(value["kind"] == "REGULAR_FILE" for value in inventory.values()):
        raise ValueError("search corpus has no regular files")
    return {"root": str(root), "inventory": inventory,
        "inventory_sha256": hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest(),
        "regular_content_bytes": content_bytes,
        "scope": "FIXED_SOURCE_SNAPSHOT_EXCLUDE_GIT_NO_SYMLINK_FOLLOW",
        "cache_state": "UNCONTROLLED_WARMED_BY_INVENTORY_NOT_COLD_IO"}


def prepare_assets(root, files=128, lines=2048, units=16, functions=192):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=False)
    corpus, source = root / "corpus", root / "source"
    corpus.mkdir()
    source.mkdir()
    for index in range(files):
        text = "".join("record_%04d_%05d payload data range include constexpr value %s\n" %
                       (index, row, "TARGET_731" if row % 257 == 0 else "regular") for row in range(lines))
        (corpus / ("file-%04d.cpp" % index)).write_text(text)
    for index in range(units):
        text = "#include <cstdint>\n"
        for function in range(functions):
            text += "extern \"C\" uint64_t function_%d_%d(uint64_t x){" % (index, function)
            text += "".join("x=(x*%dULL+%dULL)^(x>>%d);" % (2 * row + 3, row + index, row % 17 + 1)
                            for row in range(24))
            text += "return x;}\n"
        (source / ("unit-%03d.cpp" % index)).write_text(text)
    inventory = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in sorted(root.rglob("*")) if path.is_file()}
    metadata = {"files": files, "lines_per_file": lines, "compile_units": units,
                "functions_per_unit": functions, "inventory": inventory,
                "inventory_sha256": hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest()}
    (root / "inventory.json").write_text(json.dumps(metadata, indent=2) + "\n")
    return metadata


def work(mode, root, repeats, search_corpus=None, query="TARGET_731"):
    if mode == "search":
        corpus = Path(search_corpus) if search_corpus is not None else root / "corpus"
        digests, queries = [], []
        for index in range(repeats):
            started = time.monotonic_ns()
            result = subprocess.run(["grep", "-r", "--exclude-dir=.git", "--exclude=.git", "-F", "--", query, str(corpus)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            ended = time.monotonic_ns()
            if result.returncode not in (0, 1):
                raise RuntimeError("grep failed: " + result.stderr.decode(errors="replace")[:2048])
            digests.append(hashlib.sha256(result.stdout).hexdigest())
            queries.append({"query_index": index, "begin_ns": started, "end_ns": ended,
                "duration_ns": ended - started, "returncode": result.returncode,
                "stdout_sha256": digests[-1], "matches": len(result.stdout.splitlines())})
        if len(set(digests)) != 1:
            raise RuntimeError("fixed search output changed")
        return {"work": "GNU_GREP_FIXED_RECURSIVE_LITERAL_QUERY", "repeats": repeats,
                "stdout_sha256": digests[0], "matches": len(result.stdout.splitlines()), "queries": queries,
                "query_sha256": hashlib.sha256(query.encode()).hexdigest(), "corpus": str(corpus)}
    if mode == "prepare":
        # Real CPU input preparation: fixed cryptographic normalization, not simulated inference.
        value = (root / "corpus/file-0000.cpp").read_bytes()
        for _ in range(repeats):
            value = hashlib.sha256(value).digest() + value[:65504]
        return {"work": "FIXED_INPUT_SHA256_NORMALIZATION", "rounds": repeats,
                "output_sha256": hashlib.sha256(value).hexdigest()}
    raise ValueError("unknown fixed workload")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["search", "prepare"])
    parser.add_argument("root", type=Path)
    parser.add_argument("repeats", type=int)
    parser.add_argument("--search-corpus", type=Path)
    parser.add_argument("--search-query", default="TARGET_731")
    args = parser.parse_args()
    begin = time.monotonic_ns()
    if not args.search_query or "\x00" in args.search_query or len(args.search_query.encode()) > 4096:
        parser.error("nonempty bounded literal search query required")
    result = work(args.mode, args.root, args.repeats, args.search_corpus, args.search_query)
    result.update(begin_ns=begin, end_ns=time.monotonic_ns(), pid=os.getpid())
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
