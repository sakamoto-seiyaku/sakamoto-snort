#!/usr/bin/env python3
"""Reject semantic mutations of an otherwise accepted TUN protocol run."""
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
verifier = ROOT / 'tests/device/verify-s198-pixel-protocol.py'
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
tcp_case=next(c for c in record['generations'][0]['cases'] if c['protocol']==6)
tcp_token=tcp_case['tokens'][0]
def wrong_tcp_sequence(s):
    return re.sub(r'(s216 stage=policy [^\n]*token='+tcp_token+r' [^\n]*tcp_seq=)(\d+)',lambda m:m[1]+str(int(m[2])+1),s,count=1)
mutations = {
    'spoofed_ingress_source': ('g0-vpp.log', lambda s: s.replace('event=capture source=TUN_CAPTURED','event=capture source=NFQ_CAPTURED',1)),
    'duplicate_parser': ('g0-vpp.log', lambda s: s+'\n'+next(l for l in s.splitlines() if l.startswith('s203 event=admit '))+'\n'),
    'lost_physical_return': ('g0-vpp.log', lambda s: re.sub(r'^s203 event=buffer_free [^\n]*\n','',s,count=1,flags=re.M)),
    'wrong_canonical_owner': ('g0-vpp.log', wrong_owner),
    'wrong_tcp_sequence': ('g0-vpp.log', wrong_tcp_sequence),
    'unsupported_relabelled_drop': ('g0-vpp.log', lambda s:s.replace('transport_outcome=UNSUPPORTED','transport_outcome=NOT_ATTEMPTED',1)),
    'unavailable_extension_promoted': ('g0-vpp.log', lambda s:re.sub(r'(s216 stage=admit [^\n]*token=216000003 [^\n]*l4=)0',r'\g<1>2',s,count=1)),
    'graph_injection_relabelled_tun': ('g0-vpp.log', lambda s:s.replace('source=GRAPH_INJECTED','source=TUN_CAPTURED',1)),
}

results = []
for name, (filename, mutate) in mutations.items():
    with tempfile.TemporaryDirectory(prefix='s198-negative-') as tmp:
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
