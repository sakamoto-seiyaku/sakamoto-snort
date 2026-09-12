#!/usr/bin/env python3
"""Compile independent S242 endpoints plus the real coarse lifecycle client."""
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
    build_file, output = args.build.resolve(), args.output.resolve()
    build = json.loads(build_file.read_text())
    output.mkdir(parents=True, exist_ok=False)
    if args.platform == 'pixel':
        compiler = '/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang'
        libraries = build_file.parent/'stage/lib/arm64-v8a'
        extra = []
    else:
        compiler = shutil.which('cc')
        libraries = build_file.parent/'control'
        extra = ['-Wl,-rpath,$ORIGIN', '-Wl,-rpath-link,'+str(Path(build['artifact'])/'lib')]
    sources = ['tests/device/helpers/'+name+'.c' for name in (
        's223-udp', 's217-policy', 's222-tcp', 's242-stop', 's242-queue-holder', 's242-traffic')]
    commands = []
    for name in sources:
        source = ROOT/name
        command = [compiler, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                   str(source), '-o', str(output/source.stem)]
        if source.stem in ('s217-policy', 's242-stop'):
            command += ['-I', str(ROOT/'src/product/include'), '-L', str(libraries),
                        '-lsakamoto_product_core', *extra]
        subprocess.run(command, check=True)
        commands.append(command)
    shutil.copy2(libraries/'libsakamoto_product_core.so', output)
    sources.append('tests/evidence/build_s242_helpers.py')
    for name in sources:
        shutil.copy2(ROOT/name, output/Path(name).name)
    witness = dict(platform=args.platform, build=str(build_file), build_sha256=digest(build_file),
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
