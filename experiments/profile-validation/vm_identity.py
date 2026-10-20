#!/usr/bin/env python3
"""Record/check the exact owned snapshot=on QEMU; no broad process matching."""
import argparse
import hashlib
import json
import os
from pathlib import Path


def identity(pid, name, base, port):
    proc = Path('/proc', str(pid))
    argv = (proc / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
    argv = [value.decode() for value in argv]
    executable = (proc / 'exe').resolve(strict=True)
    text = (proc / 'stat').read_text()
    start = int(text[text.rfind(')') + 2:].split()[19])
    if (executable.name != 'qemu-system-x86_64' or '-name' not in argv
            or argv[argv.index('-name') + 1] != name
            or 'file=%s,format=raw,if=ide,snapshot=on' % base not in argv
            or not any('hostfwd=tcp:127.0.0.1:%d-:22' % port in value for value in argv)):
        raise ValueError('PID is not the exact owned snapshot QEMU')
    return {'pid': pid, 'start_ticks': start, 'name': name, 'base': str(base), 'port': port,
            'executable': str(executable), 'executable_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
            'argv': argv, 'host_boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid-file', type=Path, required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--check', type=Path)
    args = parser.parse_args()
    current = identity(int(args.pid_file.read_text()), args.name, args.base.resolve(strict=True), args.port)
    if args.check:
        if current != json.loads(args.check.read_text()):
            raise ValueError('owned QEMU identity changed; do not stop it')
    if args.output:
        with args.output.open('x') as stream:
            json.dump(current, stream, indent=2)
            stream.write('\n')
    print(json.dumps({'pid': current['pid'], 'identity_verified': True}))


if __name__ == '__main__':
    main()
