#!/usr/bin/env python3
"""Reject semantic mutations of an otherwise accepted native-TUN run."""
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
verifier = ROOT / 'tests/device/verify-s213-pixel-tun.py'
def verify(run):
    return subprocess.run(['python3', str(verifier), '--build', str(a.build),
                           '--run', str(run)], capture_output=True, text=True)
baseline = verify(a.run)
assert baseline.returncode == 0, baseline.stdout + baseline.stderr
record=json.loads((a.run/'result.json').read_text())
nonce=record['generations'][0]['cases'][0]['nonce'].encode().hex()
log=(a.run/'g0-vpp.log').read_text()
capture=next(l for l in log.splitlines() if l.startswith('s213 event=capture ') and nonce in l)
token=re.search(r'token=(\d+)',capture).group(1)
def wrong_owner(s):
    return re.sub(r'(s207 stage=admit token='+token+r' [^\n]*owner=)0',r'\g<1>1',s,count=1)
def wrong_rule(s):
    return re.sub(r'(s203 event=policy [^\n]*obligation='+token+r' [^\n]*rule=)\d+',r'\g<1>0',s,count=1)
mutations = {
    'spoofed_ingress_source': ('g0-vpp.log', lambda s: s.replace('event=capture source=TUN_CAPTURED','event=capture source=NFQ_CAPTURED',1)),
    'fabricated_nfqueue_identity': ('g0-vpp.log', lambda s: re.sub(r'(s216 stage=admit [^\n]*packet_id=)0',r'\g<1>999',s,count=1)),
    'duplicate_parser': ('g0-vpp.log', lambda s: s+'\n'+next(l for l in s.splitlines() if l.startswith('s203 event=admit '))+'\n'),
    'lost_physical_return': ('g0-vpp.log', lambda s: re.sub(r'^s203 event=buffer_free [^\n]*\n','',s,count=1,flags=re.M)),
    'wrong_canonical_owner': ('g0-vpp.log', wrong_owner),
    'wrong_policy_rule': ('g0-vpp.log', wrong_rule),
    'live_tun_after_stop': ('g0-final.txt', lambda s: re.sub(r'(tun.status [^\n]*fd=)-1',r'\g<1>18',s,count=1)),
}

results = []
for name, (filename, mutate) in mutations.items():
    with tempfile.TemporaryDirectory(prefix='s213-negative-') as tmp:
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
