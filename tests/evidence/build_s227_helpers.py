#!/usr/bin/env python3
"""Source-bound S227 real timed-UDP helper and existing endpoint clients."""
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
    output = args.output.resolve()
    subprocess.run(['python', str(ROOT/'tests/evidence/build_s242_helpers.py'),
        '--build', str(args.build), '--platform', args.platform, '--output', str(output)], check=True)
    witness = json.loads((output/'helpers.json').read_text())
    source = ROOT/'tests/device/helpers/s227-udp.c'
    command = [witness['compiler']['path'], '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
               str(source), '-o', str(output/'s227-udp')]
    subprocess.run(command, check=True)
    witness['commands'].append(command)
    witness['files']['s227-udp'] = digest(output/'s227-udp')
    for name in ('tests/device/helpers/s227-udp.c', 'tests/evidence/build_s227_helpers.py'):
        shutil.copy2(ROOT/name, output/Path(name).name)
        witness['sources'][name] = digest(ROOT/name)
        witness['files'][Path(name).name] = digest(output/Path(name).name)
    (output/'helpers.json').write_text(json.dumps(witness, indent=2)+'\n')


if __name__ == '__main__':
    main()
