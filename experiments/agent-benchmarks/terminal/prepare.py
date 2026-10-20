#!/usr/bin/env python3
"""Record locally provisioned artifact identities before benchmark execution."""
import hashlib
import json
import shutil
import subprocess
import argparse
from pathlib import Path


root = Path("/opt/bpf-observer")
parser = argparse.ArgumentParser()
parser.add_argument("--output", type=Path, default=Path("/opt/agent-benchmarks/terminal/bridge-config.json"))
args = parser.parse_args()
config = {}
for name, filename in (("observer", "deployment-observe"), ("verifier", "deployment-observe-verify"),
                       ("recorder", "system_effects.bpf.o"), ("lifecycle", "process_lifecycle.bpf.o")):
    path = root / filename
    config[name + ("_object" if name in ("recorder", "lifecycle") else "_binary")] = str(path)
    config[name + "_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
for name in ("ip", "tc", "nft"):
    source = Path(shutil.which(name)).resolve()
    destination = root / (name + "-collector")
    if destination.exists():
        if destination.read_bytes() != source.read_bytes():
            raise RuntimeError("Existing collector differs from provisioned system binary")
    else:
        shutil.copyfile(source, destination)
    destination.chmod(0o755)
    config[name + "_binary"] = str(destination)
    config[name + "_sha256"] = hashlib.sha256(destination.read_bytes()).hexdigest()
config.update({"ready_timeout": 180, "finish_timeout": 300, "docker_timeout": 60})
sampler = root / "allox-load-sampler"
config.update({"sampler_binary": str(sampler), "sampler_sha256": hashlib.sha256(sampler.read_bytes()).hexdigest()})
destination = args.output
with destination.open("x") as output:
    json.dump(config, output, indent=2)
print(json.dumps(config, sort_keys=True))
