#!/usr/bin/env python3
"""Ensure W2 witness rejection is caused by each corrupted boundary."""
import argparse
import importlib.util
from pathlib import Path
import re
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--build', type=Path, required=True)
parser.add_argument('--run', type=Path, required=True)
args = parser.parse_args()
spec = importlib.util.spec_from_file_location('w2', ROOT / 'tests/device/verify-s239-w2.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
assert verifier.verify(args.build, args.run)['status'] == 'PASS'
original = (args.run / 'native-stop.log').read_text()
mutations = {
    'missing-credit': re.sub(r'^s239 event=return_credit_released[^\n]*\n', '', original, count=1, flags=re.M),
    'wrong-return-worker': re.sub(r'(s216 stage=policy source=FLOW_STACK_RETURN[^\n]*? thread=)2\b', r'\g<1>1', original, count=1),
    'wrong-pbuf-owner': re.sub(r'(s237 event=pbuf_free[^\n]*? owner=)1\b', r'\g<1>0', original, count=1),
    'duplicate-native-free': re.sub(r'(^s203 event=buffer_free[^\n]*\n)', r'\1\1', original, count=1, flags=re.M),
    'early-credit': re.sub(r'(s239 event=return_credit_released[^\n]*? after_native_free=)1', r'\g<1>0', original, count=1),
    'cross-generation': re.sub(r'(s237 event=input_copy[^\n]*? generation=)\d+', r'\g<1>1', original, count=1),
}
for name, changed in mutations.items():
    assert changed != original, 'mutation did not match: ' + name
    with tempfile.TemporaryDirectory(prefix='s239-w2-negative-') as temporary:
        directory = Path(temporary)
        for source in args.run.iterdir():
            if source.name != 'native-stop.log':
                (directory / source.name).symlink_to(source.resolve(), target_is_directory=source.is_dir())
        (directory / 'native-stop.log').write_text(changed)
        try:
            verifier.verify(args.build, directory)
        except AssertionError:
            pass
        else:
            raise AssertionError('verifier accepted ' + name)
    print('PASS rejected ' + name)
