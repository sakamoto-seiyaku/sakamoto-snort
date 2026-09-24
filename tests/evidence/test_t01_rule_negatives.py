#!/usr/bin/env python3
"""Prove the T01 reader rejects contradictory raw witnesses without a device."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile
from verify_t01_rule import verify

p=argparse.ArgumentParser();p.add_argument('input',type=Path);p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
assert verify(a.input)['status']=='PASS'
pixel=(a.input/'installed-apk.txt').exists()
results=[]
with tempfile.TemporaryDirectory(prefix='t01-negative-') as temporary:
    for scenario in ('winner','source','verdict','endpoint','cleanup'):
        d=Path(temporary)/scenario;shutil.copytree(a.input,d)
        run=json.loads((d/'result.json').read_text());allow,drop,_=run['cases']
        if scenario=='winner':
            path=d/('allow-query.properties' if pixel else 'allow-query.txt')
            key='winnerVersion' if pixel else 'query.winner_version'
            path.write_text(path.read_text().replace(key+'='+str(allow['rule_version']),key+'=1'))
        elif scenario=='source':
            path=d/'drop-source.conf';path.write_text(path.read_text().replace(' 3 2 32000',' 3 1 32000'))
        elif scenario=='verdict':
            path=d/('stop-vpp.log' if pixel else 'vpp.log')
            path.write_text('\n'.join(line for line in path.read_text().splitlines()
                if not (line.startswith('s242 event=verdict_syscall ') and 'verdict=0 ' in line))+'\n')
        elif scenario=='endpoint':
            if pixel:
                path=d/'drop-endpoint.txt';path.write_text(path.read_text()+'\n'+drop['nonce']+'\n')
            else:
                path=d/'endpoint.json';data=json.loads(path.read_text());data.append(drop['nonce']);path.write_text(json.dumps(data))
        else:
            if pixel:(d/'queues-after.txt').write_text('176 queue still owned\n')
            else:(d/'queues-free.json').write_text('{"176":-16}\n')
        checked=verify(d)
        assert checked['status']=='HOLD',(scenario,checked)
        results.append(dict(scenario=scenario,status=checked['status'],errors=checked['errors']))
a.output.write_text(json.dumps(results,indent=2)+'\n')
print('T01 verifier rejected all five contradictory witnesses')
