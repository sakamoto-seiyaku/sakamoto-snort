#!/usr/bin/env python3
"""Prove the offline verifier rejects a forged normal-history winner."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    original = args.input.resolve()
    verifier = Path(__file__).with_name('verify_s313_dns_tcp.py')
    with tempfile.TemporaryDirectory(prefix='s313-forged-winner-') as temporary:
        directory = Path(temporary)
        for path in original.iterdir():
            if path.is_file(): (directory / path.name).symlink_to(path)
        result = json.loads((original / 'result.json').read_text())
        case = result['cases'][0]
        label = case['label']
        observation_name = label + '-observation.json'
        observation = json.loads((original / observation_name).read_text())
        changed = 0
        for row in observation['consumer']['persistent']['dns']['recent'].values():
            record = row['record']
            if (record['source_port'] == case['source_port']
                    and record['generation'] == case['generation']
                    and record['stage'] == 2 and record['coverage'] == 1
                    and not record['tcp_continuation']):
                record['winner'] ^= 1 << 32
                changed += 1
        assert changed, 'negative fixture needs a complete response decision'
        case['records'] = [row['record'] for row in
            observation['consumer']['persistent']['dns']['recent'].values()
            if row['record']['source_port'] == case['source_port']
            and row['record']['generation'] == case['generation']]
        # Forge both the runner summary and raw normal-history snapshot together.
        # A mere equality check between those two files would wrongly accept it.
        for name, value in (('result.json', result), (observation_name, observation)):
            target = directory / name
            target.unlink()
            target.write_text(json.dumps(value))
        check = subprocess.run([sys.executable, str(verifier), str(directory), '--output',
                                str(directory / 'forged-report.json')],
                               capture_output=True, text=True)
        assert check.returncode != 0 and 'record[\'winner\']' in check.stderr, check.stdout + check.stderr
        args.output.write_text(json.dumps(dict(status='PASS', input=str(original),
            mutation='same forged response winner in result and normal SQLite query snapshot',
            changed_decisions=changed, verifier_exit=check.returncode,
            verifier_error=check.stderr), indent=2) + '\n')
        print('PASS forged normal-history winner rejected')


if __name__ == '__main__': main()
