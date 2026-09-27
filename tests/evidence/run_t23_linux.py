#!/usr/bin/env python3
"""Launch only the T23 real Product collector in an isolated network namespace."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument("--build",type=Path,required=True);p.add_argument("--stage",type=Path,required=True);p.add_argument("--output",type=Path,required=True);p.add_argument("extra",nargs=argparse.REMAINDER);a=p.parse_args()
out=a.output.resolve();assert out.is_relative_to(ROOT/"build-output") and not out.exists()
args=["docker","run","--rm","--name","t23-"+hashlib.sha256(str(out).encode()).hexdigest()[:12],"--network","none","--cap-add","NET_ADMIN","--cap-add","NET_RAW",
    "-v",str(ROOT)+":"+str(ROOT),"-w",str(ROOT),"-e","T23_HOST_NETNS="+os.readlink("/proc/self/ns/net"),
    "-e","GIT_CONFIG_COUNT=1","-e","GIT_CONFIG_KEY_0=safe.directory","-e","GIT_CONFIG_VALUE_0="+str(ROOT),
    "sakamoto-vpp-nfq-poc:dev","python3","tests/device/t23-linux-attribution.py","--build",str(a.build.resolve()),"--stage",str(a.stage.resolve()),"--output",str(out),*(a.extra[1:] if a.extra[:1]==["--"] else a.extra)]
r=subprocess.run(args)
if out.is_dir():
    subprocess.run(["docker","run","--rm","--network","none","-v",str(out)+":/evidence","sakamoto-vpp-nfq-poc:dev","chown","-R",f"{os.getuid()}:{os.getgid()}","/evidence"],check=True)
raise SystemExit(r.returncode)
