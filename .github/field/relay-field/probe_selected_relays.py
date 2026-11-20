"""One identity-pinned native probe per explicitly approved public candidate."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import urlsplit

import run_wan as w

TARGETS = [
    "relay://136.243.38.220:22067?id=XJEGS3E-J2GFZ2Q-HA7OVDL-MDRN5CQ-54MREDK-RBZBWI2-P7KNOH6-EDT52AQ",
    "relay://123.122.44.8:9298?id=ALQHVME-AJ5JR6N-SJBUV3J-NGY22EZ-LTIPG37-P4AP2CM-4ZDLJ4X-XQAICAU",
]


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("mode",choices=["mac","linux"])
    for arg in ("engine","example","control","receipt"):
        parser.add_argument("--"+arg,type=Path,required=True)
    parser.add_argument("--sha",required=True)
    args=parser.parse_args()
    os.umask(0o077)
    assert w.digest(args.engine.read_bytes())==args.sha
    receipt={"role":args.mode,"stable_source":"99ee1036b70b9b115df26ca76c57559e7dc038a3",
             "fixed_native_version":"v2.33.2","no_synthetic_files_sent":True,"exact_candidate_count":len(TARGETS),
             "cases":[]}
    try:
        with tempfile.TemporaryDirectory(prefix="vsel.",dir="/private/tmp" if args.mode=="mac" else None) as scratch:
            for index, url in enumerate(TARGETS,1):
                root=Path(scratch)/str(index)
                root.mkdir(mode=0o700)
                args.external_tcp_port=urlsplit(url).port
                report={"candidate":index,"hostname":urlsplit(url).hostname,"port":args.external_tcp_port,
                        "explicit_native_probe_requested":False}
                receipt["cases"].append(report)
                try:
                    with w.node(args,root,report) as (node,_,control):
                        w.write_private(node/'relay_probe.json',url)
                        report["explicit_native_probe_requested"]=True
                        report.update(control('relay_probe'))
                except (RuntimeError, OSError, AssertionError, subprocess.SubprocessError) as error:
                    report["failure_type"]=type(error).__name__
                    if type(error)==RuntimeError:
                        report["failure_reason"]=str(error)
    finally:
        w.write_private(args.receipt,receipt)
        print(json.dumps(receipt))
    return 0 if all(row.get("normal_exit") and row.get("exact_engine_gone") for row in receipt["cases"]) else 1


if __name__=="__main__":
    raise SystemExit(main())
