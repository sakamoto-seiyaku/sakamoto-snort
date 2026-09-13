#!/usr/bin/env python3
"""Bind independent TCP/ICMP/UDP expiry endpoints to one Product build."""
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
    sources = ['tests/evidence/build_s236_helpers.py']
    for name in ('s236-tcp', 's224-icmp', 's227-udp', 's236-mixed', 's236-wire'):
        source = ROOT/'tests/device/helpers'/(name+'.c')
        command = [witness['compiler']['path'], '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                   str(source), '-o', str(output/name)]
        subprocess.run(command, check=True)
        witness['commands'].append(command)
        witness['files'][name] = digest(output/name)
        sources.append(source.relative_to(ROOT).as_posix())
    for name in sources:
        shutil.copy2(ROOT/name, output/Path(name).name)
        witness['sources'][name] = digest(ROOT/name)
        witness['files'][Path(name).name] = digest(output/Path(name).name)
    (output/'helpers.json').write_text(json.dumps(witness, indent=2)+'\n')


if __name__ == '__main__':
    main()
