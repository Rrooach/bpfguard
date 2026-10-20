#!/usr/bin/env python3
"""Serial replay of recorded native shell *text*, not a replacement Agent."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import time

from common import digest, write_new


def execute_plan(plan, workspace, output):
    workspace=Path(workspace).resolve(strict=True)
    output=Path(output).resolve(strict=True)
    rows=[]
    for index,tool in enumerate(plan["commands"]):
        relative=Path(tool["relative_cwd"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("replay cwd must remain in the cloned task workspace")
        cwd=(workspace/relative).resolve(strict=True)
        if cwd!=workspace and workspace not in cwd.parents:
            raise ValueError("replay cwd escaped workspace")
        path=output/("command-%04d.output"%index)
        begin=time.monotonic_ns()
        with path.open("xb") as stream:
            # Explicit harness shell, not a claim of identical Codex internal
            # exec argv. Same exact shell/command/environment in both arms.
            process=subprocess.Popen([plan["shell"],"--noprofile","--norc","-c",tool["command"]],
                cwd=cwd,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,
                env={"PATH":plan["path"],"LANG":"C.UTF-8","LC_ALL":"C.UTF-8","HOME":str(workspace)})
            timed_out=False
            try:code=process.wait(timeout=plan["command_timeout"])
            except subprocess.TimeoutExpired:
                timed_out=True;process.kill();code=process.wait(timeout=5)
            stream.flush();os.fsync(stream.fileno())
        rows.append({"call_id":tool["call_id"],"command":tool["command"],"relative_cwd":tool["relative_cwd"],
            "begin_ns":begin,"end_ns":time.monotonic_ns(),"return_code":code,"timed_out":timed_out,
            "output":digest(path),"output_artifact":path.name,"original_return_code":tool["source_exit_code"]})
        if timed_out:break
    result={"scope":"RECORDED_NATIVE_SHELL_TEXT_REPLAY_NOT_WHOLE_AGENT", "commands":rows,
        "complete":len(rows)==len(plan["commands"]) and not any(row["timed_out"] for row in rows)}
    write_new(output/"replay-result.json",result)
    print(json.dumps({"scope":result["scope"],"commands":len(rows),"complete":result["complete"]}),flush=True)
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan",type=Path,required=True)
    parser.add_argument("--workspace",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args(argv)
    execute_plan(json.loads(args.plan.read_text()),args.workspace,args.output)


if __name__=="__main__":main()
