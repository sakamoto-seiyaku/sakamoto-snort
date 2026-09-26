#!/usr/bin/env python3
"""Ensure the native oracle and retained-source checks can reject bad inputs."""
import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'experiments/t17-domain-matcher'))
from provenance import closure


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('build', type=Path)
    parser.add_argument('workload', type=Path)
    parser.add_argument('out', type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    entries = (args.workload / 'entries.tsv').read_text()
    queries = (args.workload / 'queries.tsv').read_text().splitlines()
    records = []
    for case in ('wrong-mask', 'wrong-status', 'bad-hex', 'duplicate-key'):
        directory = args.out / case
        directory.mkdir()
        altered = queries.copy()
        fields = altered[0].split('\t')
        if case == 'wrong-mask':
            fields[2] = format(int(fields[2], 16) ^ 1, 'x')
        elif case == 'wrong-status':
            fields[1] = '-1'
        elif case == 'bad-hex':
            fields[0] = 'gg' + fields[0][2:]
        altered[0] = '\t'.join(fields)
        (directory / 'entries.tsv').write_text(entries + (entries.splitlines()[0] + '\n' if case == 'duplicate-key' else ''))
        (directory / 'queries.tsv').write_text('\n'.join(altered) + '\n')
        result = subprocess.run([str(args.build / 'recovery'), 'cost', str(directory / 'entries.tsv'),
                                 str(directory / 'queries.tsv'), case], capture_output=True, text=True, timeout=30)
        expected = {'wrong-mask': 'independent oracle mismatch', 'wrong-status': 'independent oracle mismatch',
                    'bad-hex': 'bad hex', 'duplicate-key': 'unexpected duplicate or logical insertion failure'}[case]
        records.append({'case': case, 'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
        assert result.returncode == 3 and expected in result.stderr and not result.stdout
    source = args.out / 'changed-source'
    source.mkdir()
    for name in ('rax.c', 'rax.h'):
        shutil.copyfile(args.build / name, source / name)
    with (source / 'rax.c').open('a') as output:
        output.write('\n/* intentionally changed source */\n')
    try:
        closure(ROOT / 'build-output/t17-20260926/upstream', source, False)
    except AssertionError as error:
        assert 'compiled rax copy differs' in str(error)
        records.append({'case': 'changed-source', 'rejected': True, 'reason': str(error)})
    else:
        raise AssertionError('changed source accepted')
    (args.out / 'results.json').write_text(json.dumps(records, indent=2) + '\n')
    print('rejected 4 native mutations and 1 source mutation')


if __name__ == '__main__':
    main()
