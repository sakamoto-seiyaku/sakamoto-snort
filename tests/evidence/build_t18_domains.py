#!/usr/bin/env python3
"""Build the actual Product domain binding against a pinned VPP stage."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--platform',choices=['host','android'],required=True)
    p.add_argument('--stage',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--ndk',type=Path)
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    stage=a.stage.resolve()
    sources=['tests/host/product_domains_test.c','src/product/vpp/product_domains.c',
             'src/product/vpp/product_domains_memory.c','src/product/vpp/product_domains_rax.c']
    closure=sources+['src/product/vpp/product_domains.h','src/product/vpp/product_domains_memory.h',
        'src/product/vpp/product_domains_rax.h','src/product/include/sakamoto_product_domains.h',
        'third_party/rax/rax.c','third_party/rax/rax.h','third_party/rax/serverassert.h',
        'third_party/rax/rax_malloc.h','third_party/rax/UPSTREAM.json',
        'tests/evidence/build_t18_domains.py']
    files={name:digest(ROOT/name) for name in closure}
    for name in closure:
        target=out/'source'/name;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(ROOT/name,target)
    if a.platform=='android':
        assert a.ndk
        manifest=stage/'android-vpp-stage.properties'
        api=next(line.split('=',1)[1] for line in manifest.read_text().splitlines()
                 if line.startswith('api='))
        assert api.isdecimal() and int(api)>=29
        compiler=a.ndk.resolve()/f'toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android{api}-clang'
        include=stage/'include';library=stage/'lib/libvppinfra.so'
    else:
        compiler=Path(shutil.which('cc'))
        prefix=stage/'source/build-root/install-vpp-native/vpp'
        include=prefix/'include';library=next(prefix.rglob('libvppinfra.so'))
        manifest=stage/'host-vpp-stage.properties'
    assert library.is_file()
    shutil.copy2(library,out/library.name)
    binary=out/'domain-test'
    command=[str(compiler),'-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror',
             '-DPRODUCT_DOMAINS_VPP_HEAP=1','-isystem',str(include),
             '-I'+str(ROOT/'src/product/vpp'),'-I'+str(ROOT/'src/product/include'),
             *[str(ROOT/name) for name in sources],'-L'+str(library.parent),
             '-Wl,-rpath,$ORIGIN','-lvppinfra','-lm',
             '-Wl,--wrap=product_domains_memory_alloc','-Wl,--wrap=product_domains_memory_free',
             '-o',str(binary)]
    started=time.time_ns()
    with (out/'build.log').open('w') as log:
        subprocess.run(command,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,check=True)
    assert files=={name:digest(ROOT/name) for name in closure}
    result=dict(platform=a.platform,started_ns=started,completed_ns=time.time_ns(),
                command=command,files=files,binary_sha256=digest(binary),
                library_sha256=digest(out/library.name),stage_manifest_sha256=digest(manifest))
    (out/'build.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({key:result[key] for key in ('platform','binary_sha256','library_sha256')}))
if __name__=='__main__': main()
