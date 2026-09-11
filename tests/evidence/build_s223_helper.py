#!/usr/bin/env python3
"""Bind the standalone UDP endpoint to a completed current Product build."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
p = argparse.ArgumentParser()
p.add_argument('--build', type=Path, required=True)
a = p.parse_args(); a.build = a.build.resolve()
build = json.loads(a.build.read_text())
source = ROOT/'tests/device/helpers/s223-udp.c'
output = a.build.parent/'s223-helper'; output.mkdir(exist_ok=False)
compiler = build['s221_compiler']['path']
assert digest(compiler) == build['s221_compiler']['sha256']
command = [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', str(source), '-o', str(output/'s223-udp')]
subprocess.run(command, check=True)
shutil.copy2(source, output/source.name)
shutil.copy2(__file__, output/Path(__file__).name)
witness = dict(build=str(a.build), build_sha256=digest(a.build),
               source_sha256=build['source_sha256'], command=command,
               compiler=build['s221_compiler'], files={f.name:digest(f) for f in output.iterdir()})
(output/'helper.json').write_text(json.dumps(witness, indent=2)+'\n')
print(json.dumps(witness, indent=2))
