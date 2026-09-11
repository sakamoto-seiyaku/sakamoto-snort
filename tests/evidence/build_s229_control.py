#!/usr/bin/env python3
"""Freeze S229 test helpers separately from an unchanged Product build."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument('--build', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
a.output = a.output.resolve()
a.output.mkdir(parents=True, exist_ok=False)
build = json.loads(a.build.read_text())
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
core = a.build.resolve().parent/'control/libsakamoto_product_core.so'
assert digest(core) == build['control_hashes']['control/libsakamoto_product_core.so']
shutil.copy2(core, a.output/core.name)
sources = [ROOT/'tests/device/helpers'/name for name in
           ('s229-nfq-policy.c', 's217-policy.c', 's219-policy.c', 's219-network.c')]
inputs = sources + sorted((ROOT/'src/product/include').glob('*.h')) + [Path(__file__)]
source_hashes = {}
for source in inputs:
    relative = source.resolve().relative_to(ROOT)
    dest = a.output/'source'/relative
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, dest)
    source_hashes[str(relative)] = digest(dest)
commands = []
for source in sources:
    argv = ['cc', '-Wall', '-Wextra', '-Werror', '-I', str(a.output/'source/src/product/include'),
            str(a.output/'source'/source.relative_to(ROOT)), '-L', str(a.output),
            '-lsakamoto_product_core', '-Wl,-rpath,$ORIGIN',
            '-Wl,-rpath-link,'+str(Path(build['artifact'])/'lib'),
            '-o', str(a.output/source.stem)]
    subprocess.run(argv, check=True)
    commands.append(argv)
env = dict(os.environ, LD_LIBRARY_PATH=str(Path(build['artifact'])/'lib'))
dependencies = subprocess.check_output(['ldd', str(a.output/'s229-nfq-policy')], env=env, text=True)
(a.output/'dependencies.txt').write_text(dependencies)
witness = dict(build=str(a.build.resolve()), build_sha256=digest(a.build),
               product_source_sha256=build['source_sha256'], commands=commands,
               compiler=subprocess.check_output(['cc', '--version'], text=True),
               source_hashes=source_hashes,
               outputs={f.name:digest(f) for f in a.output.iterdir() if f.is_file()})
(a.output/'helper-build.json').write_text(json.dumps(witness, indent=2)+'\n')
print(json.dumps(witness['outputs'], indent=2))
