#!/usr/bin/env python3
"""Build isolated T20 programs and retain exact source/dependency witnesses."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
p=argparse.ArgumentParser()
p.add_argument('--target',choices=['host','android'],required=True)
p.add_argument('--aeron',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
if (out/'build.json').exists():
    raise SystemExit('Completed build exists; choose a fresh output directory.')
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(args):
    commands.append([str(x) for x in args])
    subprocess.run(commands[-1],check=True)
commands=[]
revision=subprocess.check_output(['git','-C',str(a.aeron),'rev-parse','HEAD'],text=True).strip()
assert revision=='664f58e705f850dfb926f6293707b204ba804726'
assert not subprocess.check_output(['git','-C',str(a.aeron),'status','--porcelain'],text=True).strip()
android=a.target=='android'
ndk=Path(os.environ.get('SAKAMOTO_ANDROID_NDK_ROOT','/home/js/.local/share/android-sdk/ndk/29.0.14206865'))
cc=str(ndk/'toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang') if android else 'cc'
ar=str(ndk/'toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar') if android else 'ar'
stage=ROOT/'build-output/s220-20260913/android-stage-b' if android else ROOT/'build-output/s220-20260913/host-stage-b/source/build-root/install-vpp-native/vpp'
libs=stage/'lib' if android else ROOT/'build-output/product-vpp-host-t19-final/lib'
include=stage/'include'
aeron=a.aeron.resolve()/'aeron-client/src/main/c'
source=out/'source';source.mkdir(exist_ok=True)
for f in HERE.iterdir():
    if f.is_file():shutil.copy2(f,source/f.name)
common=['-O2','-g','-std=gnu11','-Wall','-Wextra','-Werror','-fPIC','-ffunction-sections','-fdata-sections','-I'+str(source)]
for candidate in ['aeron','vpp','minimal']:
    dest=out/candidate;dest.mkdir(exist_ok=True)
    flags=common+(['-DT20_VPP','-isystem',str(include)] if candidate=='vpp' else ['-DT20_MINIMAL'] if candidate=='minimal' else ['-I'+str(aeron)])
    run([cc,*flags,'-c',source/'ipc.c','-o',dest/'ipc.o'])
    objects=[dest/'ipc.o']
    if candidate=='aeron':
        run([cc,*flags,'-c',aeron/'concurrent/aeron_spsc_rb.c','-o',dest/'aeron.o'])
        objects.append(dest/'aeron.o')
    if candidate=='minimal':
        run([cc,*flags,'-c',source/'minimal_ring.c','-o',dest/'minimal_ring.o'])
        objects.append(dest/'minimal_ring.o')
        run([cc,*flags,source/'minimal_ring_test.c',dest/'minimal_ring.o',dest/'ipc.o','-o',dest/'minimal-test'])
    run([ar,'rcs',dest/'libt20.a',*objects])
    link=['-L'+str(dest),'-lt20']
    if candidate=='vpp':
        for name in ['libsvm.so','libvppinfra.so']:
            shutil.copy2(libs/name,dest/name)
            if not android:shutil.copy2(libs/name,dest/(name+'.26.02'))
        link+=['-lsvm','-lvppinfra','-lm','-pthread']
    run([cc,*flags,source/'producer.c',*link,'-Wl,--gc-sections','-Wl,-rpath,$ORIGIN','-o',dest/'producer'])
    run([cc,*flags,source/'query.c',*link,'-Wl,--gc-sections','-Wl,-rpath,$ORIGIN','-o',dest/'query'])
    rust=['rustc','--edition=2021','-D','warnings','-O',source/'consumer.rs','-L',dest,'-l','static=t20','-C','link-arg=-Wl,-rpath,$ORIGIN']
    if android:rust+=['--target','aarch64-linux-android','-C','linker='+cc]
    if candidate=='vpp':rust+=['-l','svm','-l','vppinfra','-l','m','-l','pthread'] if not android else ['-l','svm','-l','vppinfra','-l','m']
    run([*rust,'-o',dest/'consumer'])
deps={}
for base,prefix in [(aeron,'aeron'),(include/'svm','vpp/svm'),(include/'vppinfra','vpp/vppinfra')]:
    for f in base.rglob('*'):
        if f.is_file() and (f.suffix in ['.h','.c']):deps[prefix+'/'+str(f.relative_to(base))]=digest(f)
manifest={'schema':'t20-build/v1','target':a.target,'time_ns':time.time_ns(),
          'aeron_revision':revision,'vpp_revision':'9258530f3804a152578ce11cc7c8a1e9eab88ed0',
          'compiler':subprocess.check_output([cc,'--version'],text=True),
          'rustc':subprocess.check_output(['rustc','-Vv'],text=True),'commands':commands,
          'source':{f.name:digest(f) for f in source.iterdir() if f.is_file()},'dependencies':deps,
          'artifacts':{str(f.relative_to(out)):digest(f) for candidate in ['aeron','vpp','minimal'] for f in (out/candidate).iterdir() if f.is_file()}}
stage_properties=ROOT/'build-output/s220-20260913'/('android-stage-b/android-vpp-stage.properties' if android else 'host-stage-b/host-vpp-stage.properties')
shutil.copy2(stage_properties,out/'stage.properties')
manifest['stage_properties_sha256']=digest(out/'stage.properties')
manifest['profile_inputs']={str(f.relative_to(ROOT)):digest(f) for f in (ROOT/'src/product/vpp/android').rglob('*') if f.is_file() and f.suffix in ['.patch','.sh']}
(out/'build.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'target':a.target,'manifest_sha256':digest(out/'build.json')}))
