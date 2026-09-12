#!/usr/bin/env python3
"""Verify the supervisor's actual dual-stack rule installer, not test hooks."""
import argparse
import hashlib
import json
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('run', type=Path)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
result = json.loads((a.run/'result.json').read_text())
assert result['status'] == 'RAW_COMPLETE' and len(result['generations']) == 4
report = dict(status='HOLD', generations=[], apk_sha256=result['apk_sha256'],
              native_sha256=result['native_sha256'], runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
for index, generation in enumerate(result['generations']):
    file = a.run/f'g{index}-production-hooks.txt'
    text = file.read_text()
    rules = [line for line in text.splitlines() if line.startswith('-A SAKAMOTO_PRODUCT_')]
    assert len(rules) == 16 and all('-j NFQUEUE' in line and '--queue-bypass' in line for line in rules)
    for span in ('176:177', '178:179'):
        family = [line for line in rules if '--queue-balance '+span in line]
        assert len(family) == 8
        for chain in ('SAKAMOTO_PRODUCT_S176_OUTPUT', 'SAKAMOTO_PRODUCT_S178_INPUT'):
            selected = [line for line in family if line.startswith('-A '+chain+' ')]
            assert len(selected) == 4
            assert sum('-p udp ' in line for line in selected) == 1
            assert sum('-p tcp ' in line for line in selected) == 1
            assert sum(('-p icmp ' if span == '176:177' else '-p ipv6-icmp ') in line for line in selected) == 2
            if chain.endswith('OUTPUT'):
                assert all('--uid-owner '+str(result['uid'])+' ' in line for line in selected)
    for hook, chain in (('INPUT', 'SAKAMOTO_PRODUCT_S178_INPUT'), ('OUTPUT', 'SAKAMOTO_PRODUCT_S176_OUTPUT')):
        assert text.splitlines().count('-A '+hook+' -j '+chain) == 2
    report['generations'].append(dict(generation=generation, verified_rules=len(rules),
                                      readback_sha256=hashlib.sha256(file.read_bytes()).hexdigest()))
report['status'] = 'PASS'
a.output.write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report, indent=2))
