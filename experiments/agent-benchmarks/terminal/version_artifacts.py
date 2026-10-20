#!/usr/bin/env python3
"""Create a new artifact config for versioned Observer/verifier binaries."""
import argparse
import hashlib
import json
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument("--input", type=Path, required=True)
parser.add_argument("--binary-dir", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
config = json.loads(args.input.read_text())
directory = args.binary_dir.resolve(strict=True)
if directory == Path(config["observer_binary"]).parent:
    raise ValueError("Use a new version directory; historic binaries must remain intact")
for key, filename in (("observer", "deployment-observe"), ("verifier", "deployment-observe-verify")):
    path = directory / filename
    if not path.is_file() or path.is_symlink():
        raise ValueError("Versioned artifact must be a regular binary")
    config[key + "_binary"] = str(path)
    config[key + "_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
with args.output.open("x") as output:
    json.dump(config, output, indent=2)
print(json.dumps({key: value for key, value in config.items() if key.startswith(("observer_", "verifier_"))}))
