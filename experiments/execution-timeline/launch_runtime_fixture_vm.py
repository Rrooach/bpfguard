"""Own one fresh-overlay fixture VM; never write or stop existing images/VMs."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time

from common import digest, write_new


def launch(args):
    output=args.output.resolve()
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    base=args.base.resolve(strict=True)
    kernel=args.kernel.resolve(strict=True)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",args.port))
    busy=subprocess.run(["fuser",str(base)],capture_output=True)
    if busy.returncode!=1:
        raise RuntimeError("new backing must be unused; no existing VM is modified")
    chain=json.loads(subprocess.check_output(["qemu-img","info","--backing-chain","--output=json",str(base)]))
    if chain[0]["format"]!="qcow2" or any(row.get("dirty-flag") for row in chain):
        raise ValueError("clean qcow2 backing chain required")
    before={"identity":digest(base),"size":base.stat().st_size,"mtime_ns":base.stat().st_mtime_ns}
    overlay=output/"rootfs-overlay.qcow2"
    subprocess.run(["qemu-img","create","-f","qcow2","-F","qcow2","-b",str(base),str(overlay)],check=True)
    name="runtime-native-fixture-"+output.name
    command=["qemu-system-x86_64","-daemonize","-pidfile",str(output/"qemu.pid"),"-name",name,
        "-m","8192","-smp","4","-enable-kvm","-cpu","host,migratable=off","-display","none",
        "-serial","file:"+str(output/"console.log"),"-no-reboot","-kernel",str(kernel),"-append",
        "root=/dev/sda rw console=ttyS0,115200 net.ifnames=0 lsm=capability,selinux,bpf psi=1 schedstats=enable",
        "-device","virtio-scsi-pci,id=scsi0","-drive","file="+str(overlay)+",format=qcow2,if=none,id=rootdisk",
        "-device","scsi-hd,drive=rootdisk,bus=scsi0.0","-device","virtio-rng-pci",
        "-netdev","user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:"+str(args.port)+"-:22",
        "-device","e1000,netdev=net0"]
    subprocess.run(command,check=True)
    pid=int((output/"qemu.pid").read_text())
    proc=Path("/proc")/str(pid)
    stat=(proc/"stat").read_text()
    actual=(proc/"cmdline").read_bytes().rstrip(b"\0").split(b"\0")
    actual=[value.decode() for value in actual]
    if actual!=command:
        raise RuntimeError("new VM argv identity differs; do not guess a shutdown target")
    receipt={"schema_version":1,"status":"STARTED","name":name,"pid":pid,
        "start_ticks":int(stat[stat.rfind(")")+2:].split()[19]),"argv":actual,
        "base":str(base),"base_before":before,"kernel":str(kernel),"kernel_identity":digest(kernel),
        "overlay":str(overlay),"ssh_port":args.port,"vcpus":4,"memory_mib":8192,
        "host_boot_id":Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "launch_unix_ns":time.time_ns(),"scope":"NEW_OVERLAY_ONLY_NO_OLD_VM_OR_DISK_WRITE"}
    write_new(output/"vm-start.json",receipt)
    return receipt


def check(receipt):
    proc=Path("/proc")/str(receipt["pid"])
    text=(proc/"stat").read_text()
    current_ticks=int(text[text.rfind(")")+2:].split()[19])
    argv=[value.decode() for value in (proc/"cmdline").read_bytes().rstrip(b"\0").split(b"\0")]
    if current_ticks!=receipt["start_ticks"] or argv!=receipt["argv"]:
        raise RuntimeError("owned VM process identity changed; no signal may be sent")
    return True


def record_shutdown(directory, ssh_returncode):
    """Record a completed graceful shutdown; never send a Host signal."""
    directory=Path(directory).resolve(strict=True)
    receipt=json.loads((directory/"vm-start.json").read_text())
    if Path("/proc",str(receipt["pid"])).exists():
        raise RuntimeError("owned QEMU PID has not disappeared; no shutdown success is inferred")
    with socket.socket() as sock:
        if sock.connect_ex(("127.0.0.1",receipt["ssh_port"]))==0:
            raise RuntimeError("owned SSH listener remains; shutdown unconfirmed")
    current=digest(Path(receipt["base"]))
    if current!=receipt["base_before"]["identity"]:
        raise RuntimeError("preserved backing image identity changed")
    console=(directory/"console.log").read_bytes()
    if b"reboot: Power down" not in console[-32768:]:
        raise RuntimeError("serial console lacks graceful power-down confirmation")
    result={"schema_version":1,"status":"OWNED_FIXTURE_VM_GRACEFULLY_POWERED_OFF",
        "pid":receipt["pid"],"start_ticks":receipt["start_ticks"],"ssh_port":receipt["ssh_port"],
        "pre_shutdown_exact_identity_check":True,"shutdown_method":"GUEST_SYSTEMCTL_POWEROFF",
        "ssh_returncode":ssh_returncode,"qemu_pid_absent":True,"ssh_listener_absent":True,
        "serial_console":digest(directory/"console.log"),"base_after":current,
        "backing_image_unchanged":True,"other_vms_or_host_processes_signalled":False,
        "overlay_preserved":receipt["overlay"],"finished_unix_ns":time.time_ns()}
    write_new(directory/"vm-stop.json",result)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base",type=Path,required=True)
    parser.add_argument("--kernel",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--port",type=int,required=True)
    args=parser.parse_args()
    if not 1024<=args.port<=65535:raise ValueError("bounded dedicated SSH port required")
    print(json.dumps(launch(args),sort_keys=True))


if __name__=="__main__":main()
