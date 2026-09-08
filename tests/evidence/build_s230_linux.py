#!/usr/bin/env python3
"""Bind the actual Linux Product build and acceptance control client to source."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('chain', ROOT/'tests/evidence/product_chain.py')
chain = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chain)
p = argparse.ArgumentParser()
p.add_argument('--output', type=Path, required=True)
p.add_argument('--artifact', type=Path, required=True)
p.add_argument('--stage', type=Path, required=True)
a = p.parse_args()
a.output = a.output.resolve(); a.artifact = a.artifact.resolve(); a.stage = a.stage.resolve()
a.output.mkdir(parents=True, exist_ok=False)
witness = dict(started_ns=time.time_ns(), **chain.source_snapshot(a.output))
env = dict(os.environ, PYTHONPATH='/tmp/sakamoto-pydeps', VPP_HOST_STAGE_DIR=str(a.stage),
           PRODUCT_ARTIFACT_DIR=str(a.artifact), SAKAMOTO_PRODUCT_HOST_EVIDENCE='OFF')
with (a.output/'build.log').open('w') as log:
    subprocess.run(['bash', str(ROOT/'tools/product/build-host-artifact.sh')],
                   cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
assert chain.source_files() == witness['files'], 'source changed during Linux build'
control = a.output/'control'
control.mkdir()
shutil.copy2(ROOT/'target/release/libsakamoto_product_core.so', control)
helper = ROOT/'tests/device/helpers/s230-policy.c'
subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-I', str(ROOT/'src/product/include'),
                str(helper), '-L', str(control), '-lsakamoto_product_core',
                '-Wl,-rpath,$ORIGIN', '-Wl,-rpath-link,'+str(a.artifact/'lib'),
                '-o', str(control/'s230-policy')], check=True)
witness.update(completed_ns=time.time_ns(), artifact=str(a.artifact),
               host_evidence=False, stage=str(a.stage),
               stage_manifest_sha256=chain.digest(a.stage/'host-vpp-stage.properties'),
               policy_client=str(control/'s230-policy'),
               control_hashes={str(f.relative_to(a.output)):chain.digest(f) for f in control.iterdir()},
               artifact_hashes={str(f.relative_to(a.artifact)):chain.digest(f)
                 for f in a.artifact.rglob('*') if f.is_file() and 'plugin-build' not in f.parts})
reproduction = ['tools/product/build-host-artifact.sh', 'tools/product/run-host-vpp.sh',
                'tests/device/helpers/s230-policy.c', 'tests/evidence/build_s230_linux.py']
witness['build_inputs'] = {n:chain.digest(ROOT/n) for n in reproduction}
for n in reproduction:
    dest = a.output/'source'/n
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT/n, dest)
chain.write(a.output/'build.json', witness)
print(json.dumps({k:witness[k] for k in ('source_sha256','artifact','completed_ns')}, indent=2))
