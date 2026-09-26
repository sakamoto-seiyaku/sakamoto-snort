#!/usr/bin/env python3
"""Filesystem-boundary regression for durable directory establishment on retry."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
out = a.output.resolve(); out.mkdir(parents=True, exist_ok=False)
digest = lambda file: hashlib.sha256(Path(file).read_bytes()).hexdigest()
result = dict(started_ns=time.time_ns(), commands=[], status="HOLD")
sources = [ROOT/"crates/product-core/src/observation_store.rs",
           ROOT/"tests/host/t22_interrupt_store.c", ROOT/"tests/host/t22_store_fault_probe.rs", Path(__file__)]
result["source_hashes"] = {str(f.relative_to(ROOT)):digest(f) for f in sources}
for source in sources: (out/source.name).write_bytes(source.read_bytes())
env = {k:v for k,v in os.environ.items() if not k.startswith("SAKAMOTO_PRODUCT_VAPI_")}
commands = [
    ["cargo", "build", "-p", "sakamoto-product-core", "--lib"],
    ["cc", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror", str(sources[1]), "-ldl", "-o", str(out/"fault.so")],
    ["rustc", "--edition=2021", str(sources[2]), "--extern",
     "sakamoto_product_core="+str(ROOT/"target/debug/libsakamoto_product_core.rlib"),
     "-L", "dependency="+str(ROOT/"target/debug/deps"), "-o", str(out/"probe")],
]
try:
    for index, command in enumerate(commands):
        with (out/f"build-{index}.log").open("w") as log:
            completed = subprocess.run(command, env=env, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        result["commands"].append(dict(argv=command, code=completed.returncode))
        assert completed.returncode == 0, "fault probe build"
    marker = out/"fail.arm"; marker.touch()
    run_env = dict(env, LD_PRELOAD=str(out/"fault.so"), SAKAMOTO_T22_FAIL_DIRECTORY=str(out),
                   SAKAMOTO_T22_FAIL_DIRECTORY_MARKER=str(marker), SAKAMOTO_T22_FSYNC_LOG=str(out/"fsync.txt"))
    with (out/"run.log").open("w") as log:
        completed = subprocess.run([str(out/"probe"), str(out/"new-store/overall.json")],
                                  env=run_env, stdout=log, stderr=subprocess.STDOUT)
    assert completed.returncode == 0, "fault probe API result"
    parent = [s for s in (out/"fsync.txt").read_text().splitlines() if s.endswith("path="+str(out))]
    result["parent_fsync_calls"] = parent
    assert parent == ["fsync result=-1 path="+str(out), "fsync result=0 path="+str(out)], \
        "retry acknowledged a snapshot without syncing its directory entry"
    result["status"] = "PASS"
finally:
    result["completed_ns"] = time.time_ns()
    result["files"] = {str(f.relative_to(out)):digest(f) for f in out.rglob("*") if f.is_file()}
    (out/"result.json").write_text(json.dumps(result, indent=2)+"\n")
print(json.dumps({k:result[k] for k in ("status", "parent_fsync_calls")}, indent=2))
