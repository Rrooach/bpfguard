#!/usr/bin/env python3
"""Independent post-campaign offline smoke, never an official benchmark score."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import time

from common import digest,write_new


TESTS=("test_basic_building","test_path_is_not_double_encoded","test_params_are_added_before_fragment",
    "test_content_length_empty_body","test_content_length_explicit_and_nonempty")


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--real-source-workspace",type=Path)
    args=parser.parse_args(argv);workspace=args.workspace.resolve(strict=True)
    command=["./run-python","-m","unittest","-v"]+["test_requests.RequestsTestCase."+name for name in TESTS]
    files={name:digest(workspace/name) for name in ("requests/models.py","test_requests.py","run-python",".observer-python-compat/cgi.py")}
    begin=time.monotonic_ns()
    result=subprocess.run(command,cwd=workspace,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    end=time.monotonic_ns()
    receipt={"scope":"POST_CAMPAIGN_INDEPENDENT_SMOKE_NOT_OFFICIAL_SCORE","command":command,"cwd":str(workspace),
        "begin_ns":begin,"end_ns":end,"wall_ms":(end-begin)/1000000,"exit_code":result.returncode,
        "stdout":result.stdout.decode("utf-8","replace"),"stderr":result.stderr.decode("utf-8","replace"),
        "files_before":files,"files_after":{name:digest(workspace/name) for name in files},
        "test_case_count":len(TESTS),"paid_api_calls":0,
        "limitations":["Runs the recorded two regression tests and three pre-existing offline tests after profiling; not a fresh Agent inference",
            "The historical repository uses an explicit cgi compatibility shim and launcher for the current Guest Python; their hashes are retained",
            "Does not certify a full Requests test suite or an official SWE-bench score"]}
    if args.real_source_workspace is not None:
        source=args.real_source_workspace.resolve(strict=True)
        names=("requests/models.py","test_requests.py")
        source_files={name:digest(source/name) for name in names}
        matches=all(files[name]==source_files[name] for name in names)
        receipt["real_source_files"]={"source_workspace":str(source),"source_files":source_files,
            "status":"SAME_REAL_RUN_SOURCE_FILES" if matches else "DIFFERENT_REAL_RUN_SOURCE_FILES"}
        if not matches:receipt["source_file_check_failed"]=True
    write_new(args.output,receipt)
    print(receipt["scope"],result.returncode,receipt["wall_ms"])
    return result.returncode if not receipt.get("source_file_check_failed") else 1


if __name__=="__main__":raise SystemExit(main())
