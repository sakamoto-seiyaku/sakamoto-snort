#!/usr/bin/env python3
"""Run source-bound Product C observation boundary tests in Android root context."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import time

ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument("--serial-from",type=Path,required=True);p.add_argument("--native",type=Path,required=True);p.add_argument("--stage",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
serial=json.loads(a.serial_from.read_text())["serial"];out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
files=[a.native/"transport_test-arm64",a.native/"handshake_test-arm64",a.stage/"lib/libsvm.so",a.stage/"lib/libvppinfra.so"]
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
result=dict(status="HOLD",started_ns=time.time_ns(),source_artifact_hashes={str(f.resolve()):digest(f) for f in files},commands=[])
(out/"runner.py").write_bytes(Path(__file__).read_bytes())
def adb(label,*args):
    r=subprocess.run([str(ROOT/"dev/adb"),"-s",serial,*map(str,args)],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=40)
    (out/(label+".txt")).write_text(r.stdout);result["commands"].append(dict(label=label,argv=list(map(str,args)),exit_code=r.returncode));assert r.returncode==0,label;return r.stdout.strip()
def root(label,command):return adb(label,"shell","su","-c",shlex.quote(command))
scratch=None
try:
    state=adb("before-state","shell","run-as","com.sakamoto.snort.androidruntime","cat","files/runtime-state/snapshot.properties")
    assert "state=stopped" in state and "mayBeActive=false" in state
    scratch=root("scratch","mktemp -d /data/local/tmp/t23-native.XXXXXX");assert scratch.startswith("/data/local/tmp/t23-native.")
    root("scratch-owner","chown shell:shell "+scratch)
    for f in files:adb("push-"+f.name,"push",f,scratch+"/"+f.name)
    names=" ".join(scratch+"/"+f.name for f in files)
    root("modes","chmod 755 "+names)
    installed=root("installed-sha256","sha256sum "+names)
    assert {Path(line.split()[1]).name:line.split()[0] for line in installed.splitlines()}=={f.name:digest(f) for f in files}
    assert "uid=0" in root("root-context","id")
    root("transport-test","LD_LIBRARY_PATH="+scratch+" "+scratch+"/transport_test-arm64")
    root("handshake-test","LD_LIBRARY_PATH="+scratch+" "+scratch+"/handshake_test-arm64 "+scratch+"/test.sock")
    result["status"]="PASS"
finally:
    if scratch:
        root("cleanup-files","rm -f "+" ".join(scratch+"/"+f.name for f in files)+" "+scratch+"/test.sock")
        root("cleanup-directory","rmdir "+scratch)
    result["completed_ns"]=time.time_ns();result["files"]={str(f.relative_to(out)):digest(f) for f in out.rglob("*") if f.is_file()};(out/"result.json").write_text(json.dumps(result,indent=2)+"\n")
print(result["status"])
