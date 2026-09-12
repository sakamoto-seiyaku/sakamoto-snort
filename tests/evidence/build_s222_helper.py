#!/usr/bin/env python3
"""Bind the independent kernel TCP test endpoint to a completed Product build."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[2]
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);a=p.parse_args()
a.build=a.build.resolve();build=json.loads(a.build.read_text())
out=a.build.parent/'s222-helper';out.mkdir(exist_ok=False)
compiler=('/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang'
          if 'apk' in build else shutil.which('cc'))
source=ROOT/'tests/device/helpers/s222-tcp.c';binary=out/'s222-tcp'
subprocess.run([compiler,'-std=c11','-Wall','-Wextra','-Werror','-O2',str(source),'-o',str(binary)],check=True)
shutil.copy2(source,out/'s222-tcp.c')
witness=dict(build_sha256=digest(a.build),source_sha256=digest(source),files={'s222-tcp':digest(binary),'s222-tcp.c':digest(source)},
             compiler=dict(path=compiler,sha256=digest(compiler),version=subprocess.check_output([compiler,'--version'],text=True)))
(out/'helper.json').write_text(json.dumps(witness,indent=2)+'\n')
print(json.dumps(witness,indent=2))
