#!/usr/bin/env python3
"""Bind independent kernel endpoints/control clients to a completed build.

Do not edit the original Product build witness when adding acceptance tools.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--platform', choices=('linux', 'pixel'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    build_path, output = args.build.resolve(), args.output.resolve()
    build = json.loads(build_path.read_text())
    output.mkdir(parents=True, exist_ok=False)
    if args.platform == 'pixel':
        compiler = '/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang'
        libraries = build_path.parent/'stage/lib/arm64-v8a'
        extra = []
    else:
        compiler = shutil.which('cc')
        libraries = build_path.parent/'control'
        extra = ['-Wl,-rpath,$ORIGIN', '-Wl,-rpath-link,'+str(Path(build['artifact'])/'lib')]
    commands = []
    sources = ['tests/device/helpers/s223-udp.c', 'tests/device/helpers/s217-policy.c',
               'tests/evidence/build_s233_helpers.py']
    for source_name in sources[:2]:
        source = ROOT/source_name
        command = [compiler, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                   str(source), '-o', str(output/source.stem)]
        if source.stem == 's217-policy':
            command += ['-I', str(ROOT/'src/product/include'), '-L', str(libraries),
                        '-lsakamoto_product_core', *extra]
        subprocess.run(command, check=True)
        commands.append(command)
    shutil.copy2(libraries/'libsakamoto_product_core.so', output)
    for name in sources:
        shutil.copy2(ROOT/name, output/Path(name).name)
    witness = dict(platform=args.platform, build=str(build_path), build_sha256=digest(build_path),
                   source_sha256=build['source_sha256'], commands=commands,
                   compiler=dict(path=compiler, sha256=digest(compiler),
                                 version=subprocess.check_output([compiler, '--version'], text=True)),
                   sources={name: digest(ROOT/name) for name in sources},
                   files={p.name: digest(p) for p in output.iterdir()})
    (output/'helpers.json').write_text(json.dumps(witness, indent=2)+'\n')
    print(json.dumps(dict(platform=args.platform, output=str(output),
                         source_sha256=build['source_sha256']), indent=2))


if __name__ == '__main__':
    main()
