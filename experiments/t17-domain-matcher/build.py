#!/usr/bin/env python3
"""Build experimental adapters against pinned public sources and Product VPP stage."""
import argparse
import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path
from provenance import closure

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
DAT = '665edc5ec1639a81df004d4f92f07a73d5b96aba'
RAX = '05a9c29c62538519d870d6512978f80ac58a758f'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('out', type=Path)
    p.add_argument('--upstream', type=Path, required=True)
    p.add_argument('--android', action='store_true')
    p.add_argument('--sanitize', action='store_true')
    p.add_argument('--failure-probe', action='store_true')
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    snapshot = args.out / 'source-snapshot'
    snapshot.mkdir()
    for path in HERE.iterdir():
        if path.is_file():
            shutil.copyfile(path, snapshot / path.name)
    dat = args.upstream.resolve() / ('libdatrie-' + DAT)
    rax = args.upstream.resolve() / ('valkey-' + RAX) / 'src'
    # Copy only this exact upstream source pair so its quoted assertion include
    # resolves to the experiment's explicit adapter rather than server internals.
    for name in ('rax.c', 'rax.h'):
        shutil.copyfile(rax / name, args.out / name)
    consumed_sources = closure(args.upstream, args.out, args.android)
    (args.out / 'source-closure.json').write_text(json.dumps(consumed_sources, indent=2) + '\n')
    stage = ROOT / 'build-output/s220-20260913'
    if args.android:
        cc = str(Path.home() / '.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang')
        prefix = stage / 'android-stage-b'
        lib = prefix / 'lib'
    else:
        cc = 'gcc'
        prefix = stage / 'host-stage-b/source/build-root/install-vpp-native/vpp'
        lib = prefix / 'lib/x86_64-linux-gnu'
    metadata = {'schema': 't17-build-v1', 'android': args.android,
                'compiler': subprocess.check_output([cc, '--version'], text=True),
                'pins': {'libdatrie': DAT, 'valkey': RAX,
                         'vpp': '9258530f3804a152578ce11cc7c8a1e9eab88ed0'},
                'sources': {str(x.relative_to(ROOT)): digest(x) for x in HERE.glob('*') if x.is_file()},
                'upstream_archives': {x.name: digest(x) for x in args.upstream.glob('*.tar.gz')},
                'candidates': {}}
    metadata['source_closure_sha256'] = digest(args.out / 'source-closure.json')
    for candidate in ('datrie', 'rax', 'vpp'):
        source = 'failure_probe.c' if args.failure_probe else 'bench.c'
        cmd = [cc, '-O2', '-g', '-std=gnu11', '-Wall', '-Wextra', '-I' + str(snapshot.resolve()),
               str(snapshot / source), '-Wl,--wrap=malloc', '-Wl,--wrap=calloc', '-Wl,--wrap=realloc']
        if args.sanitize:
            cmd += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-no-pie']
        if candidate == 'datrie':
            cmd += ['-DDATRIE', '-I' + str(dat)]
            cmd += [str(dat / 'datrie' / (x + '.c')) for x in
                    ('alpha-map', 'darray', 'dstring', 'fileutils', 'tail', 'trie', 'trie-string')]
        elif candidate == 'rax':
            cmd += ['-DRAX', '-DRAX_MALLOC_INCLUDE="allocator.h"', '-I' + str(args.out.resolve()),
                    str(args.out / 'rax.c')]
        else:
            cmd += ['-I' + str(prefix / 'include'), '-L' + str(lib), '-lvppinfra',
                    '-Wl,-rpath,' + str(lib), '-lm', '-ldl']
            if not args.android:
                cmd += ['-lpthread']
        binary = args.out / candidate
        cmd += ['-lm', '-o', str(binary)]
        start = time.monotonic_ns()
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        (args.out / (candidate + '-compile.log')).write_text(result.stdout)
        metadata['candidates'][candidate] = {'command': cmd, 'build_ns': time.monotonic_ns() - start,
                                             'returncode': result.returncode}
        if not result.returncode:
            metadata['candidates'][candidate].update(binary_sha256=digest(binary), binary_bytes=binary.stat().st_size)
        (args.out / 'build.json').write_text(json.dumps(metadata, indent=2) + '\n')
        if result.returncode:
            raise SystemExit(result.stdout)
    metadata['vpp_library'] = {'path': str(lib / 'libvppinfra.so'),
                               'sha256': digest(lib / 'libvppinfra.so'),
                               'bytes': (lib / 'libvppinfra.so').stat().st_size}
    (args.out / 'build.json').write_text(json.dumps(metadata, indent=2) + '\n')


if __name__ == '__main__':
    main()
