#!/usr/bin/env python3
"""Build unchanged rax with explicit VPP allocation, binding actual inputs."""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BASE = HERE.parent / 't17-domain-matcher'
sys.path.insert(0, str(BASE))
from provenance import closure, RAX


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('out', type=Path)
    parser.add_argument('--android', action='store_true')
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    upstream = ROOT / 'build-output/t17-20260926/upstream'
    for name in ('rax.c', 'rax.h'):
        shutil.copyfile(upstream / ('valkey-' + RAX) / 'src' / name, args.out / name)
    snapshot = args.out / 'source-snapshot'
    snapshot.mkdir()
    for path in HERE.iterdir():
        if path.is_file():
            shutil.copyfile(path, snapshot / path.name)
    shutil.copyfile(BASE / 'serverassert.h', snapshot / 'serverassert.h')
    sources = closure(upstream, args.out, args.android)
    (args.out / 'source-closure.json').write_text(json.dumps(sources, indent=2) + '\n')
    stage = ROOT / 'build-output/s220-20260913'
    if args.android:
        cc = str(Path.home() / '.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang')
        prefix = stage / 'android-stage-b'
        lib = prefix / 'lib'
    else:
        cc = 'gcc'
        prefix = stage / 'host-stage-b/source/build-root/install-vpp-native/vpp'
        lib = prefix / 'lib/x86_64-linux-gnu'
    cmd = [cc, '-O2', '-g', '-std=gnu11', '-Wall', '-Wextra',
           '-DRAX_MALLOC_INCLUDE="allocator.h"', '-I' + str(snapshot.resolve()),
           '-I' + str(args.out.resolve()), '-I' + str(prefix / 'include'),
           str(snapshot / 'recovery.c'), str(args.out / 'rax.c'),
           '-L' + str(lib), '-lvppinfra', '-Wl,-rpath,' + str(lib), '-lm', '-ldl']
    if args.sanitize:
        cmd += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-no-pie']
    cmd += ['-o', str(args.out / 'recovery')]
    result = subprocess.run(cmd, capture_output=True, text=True)
    (args.out / 'compile.log').write_text(result.stdout + result.stderr)
    meta = {'schema': 't17-5-build-v1', 'android': args.android, 'sanitize': args.sanitize,
            'compiler': subprocess.check_output([cc, '--version'], text=True),
            'command': cmd, 'returncode': result.returncode,
            'source_closure_sha256': digest(args.out / 'source-closure.json'),
            'experiment_sources': {p.name: digest(p) for p in snapshot.iterdir()},
            'vpp_library': {'path': str(lib / 'libvppinfra.so'), 'sha256': digest(lib / 'libvppinfra.so')}}
    if result.returncode == 0:
        meta['binary_sha256'] = digest(args.out / 'recovery')
        meta['binary_bytes'] = (args.out / 'recovery').stat().st_size
    (args.out / 'build.json').write_text(json.dumps(meta, indent=2) + '\n')
    if result.returncode:
        raise SystemExit(result.stdout + result.stderr)
    print(json.dumps({'binary_bytes': meta['binary_bytes'], 'android': args.android}))


if __name__ == '__main__':
    main()
