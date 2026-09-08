#!/usr/bin/env python3
"""Reject semantic mutations of an otherwise accepted network-event run."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument('--build', type=Path, required=True)
p.add_argument('--run', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
verifier = ROOT / 'tests/device/verify-s232-network.py'
def verify(run):
    return subprocess.run(['python3', str(verifier), '--build', str(a.build),
                           '--run', str(run)], capture_output=True, text=True)
baseline = verify(a.run)
assert baseline.returncode == 0, baseline.stdout + baseline.stderr
mutations = {
    'wrong_platform_category': ('android-events.log', lambda s: re.sub(
        r'(interfaces=\{\d+=)1', r'\g<1>2', s)),
    'publication_not_acknowledged': ('android-events.log', lambda s: s.replace('code=0', 'code=9')),
    'wrong_snapshot_generation': ('vpp.log', lambda s: re.sub(
        r'(s232 event=packet_snapshot generation=)\d+', r'\g<1>999999', s, count=1)),
    'duplicate_verdict': ('vpp.log', lambda s: s + '\n' + next(
        l for l in s.splitlines() if l.startswith('s203 event=verdict ')) + '\n'),
    'wrong_packet_context': ('vpp.log', lambda s: re.sub(
        r'(s217 event=nfq_facts [^\n]*context=)1', r'\g<1>2', s, count=1)),
    'missing_callback_stop': ('android-events.log', lambda s: s.replace(
        'event=subscription_stopped thread_alive=false',
        'event=subscription_stopped thread_alive=true')),
    'wrong_canonical_owner': ('vpp.log', lambda s: re.sub(
        r'(s207 stage=admit [^\n]*owner=)[01]', r'\g<1>9', s, count=1)),
}
results = []
for name, (filename, mutate) in mutations.items():
    with tempfile.TemporaryDirectory(prefix='s232-negative-') as tmp:
        dest = Path(tmp) / 'run'
        shutil.copytree(a.run, dest)
        path = dest / filename
        old = path.read_text()
        new = mutate(old)
        assert old != new, name
        path.write_text(new)
        checked = verify(dest)
        assert checked.returncode != 0, name
        result = json.loads((dest / 'verification.json').read_text())
        assert result['status'] == 'HOLD' and result['errors'], name
        results.append(dict(name=name, rejected=True, errors=result['errors']))
a.output.write_text(json.dumps(results, indent=2) + '\n')
print(f'PASS: {len(results)} semantic evidence mutations rejected')
