#!/usr/bin/env python3
"""Build/run the external T23 public-store fault probe against current Rust."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);a=p.parse_args()
out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
paths=["crates/product-core/src/observation.rs","crates/product-core/src/observation_store.rs","tests/host/t23_store_fault_probe.rs","tests/evidence/t23_store_faults.py"]
result=dict(status="HOLD",started_ns=time.time_ns(),source_hashes={name:digest(ROOT/name) for name in paths},commands=[])
for name in paths:(out/Path(name).name).write_bytes((ROOT/name).read_bytes())
env={k:v for k,v in os.environ.items() if not k.startswith("SAKAMOTO_PRODUCT_VAPI_")}
def run(label,command):
    with (out/(label+".log")).open("w") as log:r=subprocess.run(list(map(str,command)),cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT)
    result["commands"].append(dict(label=label,argv=list(map(str,command)),code=r.returncode));assert r.returncode==0,label
try:
    run("cargo",["cargo","build","-p","sakamoto-product-core","--lib","--message-format=json"])
    artifacts=[json.loads(line) for line in (out/"cargo.log").read_text().splitlines() if line.startswith("{")]
    dependencies={}
    for item in artifacts:
        if item.get("reason")=="compiler-artifact" and item["target"]["name"] in ("rusqlite","serde_json"):
            dependencies[item["target"]["name"]]=next(name for name in item["filenames"] if name.endswith(".rlib"))
    command=["rustc","--edition=2021",ROOT/paths[2],"--extern","sakamoto_product_core="+str(ROOT/"target/debug/libsakamoto_product_core.rlib"),"-L","dependency="+str(ROOT/"target/debug/deps"),"-o",out/"probe"]
    for name,path in dependencies.items():command.extend(["--extern",name+"="+path])
    assert len(dependencies)==2
    run("build",command);run("run",[out/"probe",out])
    assert result["source_hashes"]=={name:digest(ROOT/name) for name in paths}
    result["status"]="PASS"
finally:
    result["completed_ns"]=time.time_ns();result["files"]={str(f.relative_to(out)):digest(f) for f in out.rglob("*") if f.is_file()};(out/"result.json").write_text(json.dumps(result,indent=2)+"\n")
print(json.dumps({"status":result["status"]}))
