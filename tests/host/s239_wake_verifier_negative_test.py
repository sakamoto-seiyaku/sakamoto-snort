#!/usr/bin/env python3
"""Negative controls for the bounded device wake evidence verifier."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--build', type=Path, required=True)
parser.add_argument('--run', type=Path, required=True)
args = parser.parse_args()
verifier = ROOT / 'tests/device/verify-s239-wake.py'
original = (args.run / 'native-stop.log').read_text()
def verify(directory):
    return subprocess.run(['python3', str(verifier), '--build', str(args.build),
                           '--run', str(directory)], capture_output=True, text=True).returncode
assert verify(args.run) == 0, 'positive control failed'
mutations = {
    'missing-credit-release': re.sub(r'^s239 event=return_credit_released[^\n]*\n', '', original, count=1, flags=re.M),
    'wrong-owner-thread': re.sub(r'(s216 stage=policy source=FLOW_STACK_RETURN[^\n]*? thread=)2\b', r'\g<1>1', original, count=1),
}
def delayed(match):
    return match.group(1) + str(int(match.group(2)) + 2000000000)
mutations['late-completion'] = re.sub(
    r'(s204 event=completion_consume[^\n]* token=138\d+[^\n]* mono_ns=)(\d+)',
    delayed, original, count=1)
for name, text in mutations.items():
    assert text != original, 'negative mutation did not match: ' + name
    with tempfile.TemporaryDirectory(prefix='s239-negative-') as temporary:
        run = Path(temporary)
        (run / 'result.json').symlink_to((args.run / 'result.json').resolve())
        (run / 'test-source').symlink_to((args.run / 'test-source').resolve(), target_is_directory=True)
        (run / 'native-stop.log').write_text(text)
        assert verify(run) != 0, 'verifier accepted ' + name
    print('PASS rejected ' + name)
