#!/usr/bin/env python3
"""Bind the test-only persistent VAPI client to the Product Host artifact."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()

parser = argparse.ArgumentParser()
parser.add_argument('--artifact', type=Path, required=True)
parser.add_argument('--archive', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
artifact, archive, output = (p.resolve() for p in (args.artifact, args.archive, args.output))
output.mkdir(parents=True, exist_ok=False)
source = ROOT/'tests/device/helpers/t18_persistent_config.c'
shutil.copy2(source, output/source.name)
shutil.copy2(archive, output/archive.name)
compiler = shutil.which('cc')
assert compiler and (artifact/'lib/libvapiclient.so').is_file() and archive.is_file()
binary = output/'persistent-control'
command = [compiler, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
           '-I'+str(ROOT/'src/product/include'), str(source), str(output/archive.name),
           '-L'+str(artifact/'lib'), '-Wl,-rpath,'+str(artifact/'lib'),
           '-lvapiclient', '-lvppinfra', '-lpthread', '-o', str(binary)]
started = time.time_ns()
with (output/'build.log').open('w') as log:
    subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
assert digest(source) == digest(output/source.name)
result = dict(started_ns=started, completed_ns=time.time_ns(), command=command,
              source_sha256=digest(source), archive=str(output/archive.name), archive_sha256=digest(archive),
              artifact=str(artifact),
              artifact_manifest_sha256=digest(artifact/'product-vpp-artifact.properties'),
              binary=str(binary), binary_sha256=digest(binary))
(output/'build.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps({key:result[key] for key in ('source_sha256','archive_sha256','binary_sha256')}))
