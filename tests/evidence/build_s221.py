#!/usr/bin/env python3
"""Build the current Product plus separately attributed S221 test endpoints."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('chain',ROOT/'tests/evidence/product_chain.py')
chain=importlib.util.module_from_spec(spec);spec.loader.exec_module(chain)
p=argparse.ArgumentParser()
p.add_argument('--platform',choices=['linux','pixel'],required=True)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--artifact',type=Path)
p.add_argument('--stage',type=Path)
a=p.parse_args();a.output=a.output.resolve()
if a.platform=='linux':
    assert a.artifact and a.stage
    subprocess.run(['python3',str(ROOT/'tests/evidence/build_s230_linux.py'),
                    '--output',str(a.output),'--artifact',str(a.artifact),
                    '--stage',str(a.stage)],check=True)
    manifest=json.loads((a.output/'build.json').read_text())
    compiler=shutil.which('cc');libraries=a.output/'control'
    extra=['-Wl,-rpath,$ORIGIN','-Wl,-rpath-link,'+str(a.artifact.resolve()/'lib')]
else:
    if a.stage:os.environ['SAKAMOTO_VPP_STAGE_DIR']=str(a.stage.resolve())
    manifest=chain.build(a.output)
    ndk=Path(os.environ.get('SAKAMOTO_ANDROID_NDK_ROOT','/home/js/.local/share/android-sdk/ndk/29.0.14206865'))
    compiler=str(ndk/'toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang')
    libraries=a.output/'stage/lib/arm64-v8a';extra=[]
helpers=a.output/'helpers';helpers.mkdir()
inputs=['tests/device/helpers/s221-flow-client.c','tests/device/helpers/s207-echo.c',
        'tests/device/helpers/s217-policy.c','tests/evidence/build_s221.py']
for name in inputs[:3]:
    source=ROOT/name
    command=[compiler,'-Wall','-Wextra','-Werror','-O2',str(source),'-o',str(helpers/source.stem)]
    if source.stem=='s217-policy':
        command+=['-I',str(ROOT/'src/product/include'),'-L',str(libraries),'-lsakamoto_product_core',*extra]
    subprocess.run(command,check=True)
    destination=a.output/'source'/name;destination.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(source,destination)
shutil.copy2(libraries/'libsakamoto_product_core.so',helpers)
manifest['s221_helpers']={str(f.relative_to(a.output)):chain.digest(f) for f in helpers.iterdir()}
manifest['s221_helper_inputs']={name:chain.digest(ROOT/name) for name in inputs}
manifest['s221_compiler']=dict(path=compiler,sha256=chain.digest(compiler),
                              version=subprocess.check_output([compiler,'--version'],text=True))
destination=a.output/'source/tests/evidence/build_s221.py';destination.parent.mkdir(parents=True,exist_ok=True)
shutil.copy2(__file__,destination)
assert chain.source_files()==manifest['files'],'source changed during build'
chain.write(a.output/'build.json',manifest)
print(json.dumps(dict(platform=a.platform,source_sha256=manifest['source_sha256'],helpers=manifest['s221_helpers']),indent=2))
