#!/usr/bin/env python3
"""Rebuild Java-only T21 changes, proving the reused native closure is unchanged."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time
import zipfile
import hashlib
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("chain", ROOT/"tests/evidence/product_chain.py")
chain = importlib.util.module_from_spec(spec); spec.loader.exec_module(chain)
p = argparse.ArgumentParser()
p.add_argument("--native-build", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
a = p.parse_args(); out = a.output.resolve(); out.mkdir(parents=True, exist_ok=False)
old = json.loads(a.native_build.read_text())
current = chain.source_files()
changed = [name for name in current.keys() | old["files"].keys() if current.get(name) != old["files"].get(name)]
assert changed and all(name.startswith("app/android-runtime/src/main/java/") and name.endswith(".java") for name in changed), changed
stage = a.native_build.resolve().parent/"stage"
assert chain.digest(stage/"product-stage.properties") == old["product_stage_sha256"]
for name, expected in old["native_sha256"].items(): assert chain.digest(stage/"lib/arm64-v8a"/name) == expected, name
witness = dict(schema=chain.SCHEMA, started_ns=time.time_ns(), **chain.source_snapshot(out),
               reused_native_build=str(a.native_build.resolve()), reused_native_build_sha256=chain.digest(a.native_build),
               unchanged_native_source=True, java_changes=changed)
env = dict(os.environ, SAKAMOTO_ANDROID_PRODUCT_STAGE_DIR=str(stage),
           SAKAMOTO_ANDROID_VERSION_STATE_FILE=str(out/"version-code"), SAKAMOTO_ANDROID_APK_OUTPUT_DIR=str(out/"apk"))
with (out/"apk-only.log").open("w") as log:
    subprocess.run(["bash", str(ROOT/"app/android-runtime/scripts/build-debug-apk.sh"), "--apk-only"],
                   env=env, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
assert chain.source_files() == current
apk = out/"apk/sakamoto-runtime-debug.apk"
with zipfile.ZipFile(apk) as z:
    native = {Path(n).name:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist()
              if n.startswith("lib/arm64-v8a/") and n.endswith(".so")}
assert native == old["native_sha256"]
witness.update(completed_ns=time.time_ns(), apk=str(apk), apk_sha256=chain.digest(apk), native_sha256=native,
               product_stage_sha256=old["product_stage_sha256"], vpp_stage_sha256=old["vpp_stage_sha256"])
chain.write(out/"build.json", witness)
print(json.dumps({k:witness[k] for k in ("source_sha256", "apk_sha256", "java_changes")}, indent=2))
