#!/usr/bin/env python3
"""Extend immutable S242 Linux endpoint helpers with the S235 control client."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
p = argparse.ArgumentParser()
p.add_argument('--base', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args(); a.base = a.base.resolve(); a.output = a.output.resolve()
manifest = json.loads(a.base.read_text()); assert manifest['platform'] == 'linux'
a.output.mkdir(parents=True, exist_ok=False)
for name, expected in manifest['files'].items():
    assert digest(a.base.parent/name) == expected
    shutil.copy2(a.base.parent/name, a.output/name)
build = json.loads(Path(manifest['build']).read_text())
source = ROOT/'tests/device/helpers/s235-policy.c'
command = [manifest['compiler']['path'], '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
           str(source), '-I', str(ROOT/'src/product/include'), '-L', str(a.output),
           '-lsakamoto_product_core', '-Wl,-rpath,$ORIGIN',
           '-Wl,-rpath-link,'+str(Path(build['artifact'])/'lib'), '-o', str(a.output/'s235-policy')]
subprocess.run(command, check=True)
manifest['commands'].append(command)
for name in ('tests/device/helpers/s235-policy.c', 'tests/evidence/build_s235_helpers.py'):
    manifest['sources'][name] = digest(ROOT/name)
    shutil.copy2(ROOT/name, a.output/Path(name).name)
manifest['files'] = {f.name: digest(f) for f in a.output.iterdir()}
(a.output/'helpers.json').write_text(json.dumps(manifest, indent=2)+'\n')
print(a.output/'helpers.json')
