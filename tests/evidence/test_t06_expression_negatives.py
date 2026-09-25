#!/usr/bin/env python3
"""Falsify T06 evidence without changing actual device or source configuration."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import tempfile

spec=importlib.util.spec_from_file_location('verify',Path(__file__).with_name('verify_t06_expressions.py'))
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
p=argparse.ArgumentParser();p.add_argument('directory',type=Path);a=p.parse_args()
v.verify(a.directory)
rejected=[]
for fault in ['process','winner','logical_hits','mode','actual_action','rank','endpoint','expression','runtime_generation','availability','artifact_binding']:
    with tempfile.TemporaryDirectory(prefix='t06-negative-') as temporary:
        target=Path(temporary)/'run';shutil.copytree(a.directory,target,ignore=shutil.ignore_patterns('configuration'))
        result_path=target/'result.json';run=json.loads(result_path.read_text());case=next(c for c in run['cases'] if not c['delivered']);pixel='serial' in run
        if fault=='process':run['process_absent']=False;result_path.write_text(json.dumps(run))
        elif fault in ['winner','logical_hits']:
            name=('winnerVersion' if pixel else 'query.winner_version') if fault=='winner' else ('logicalHits' if pixel else 'query.logical_hits')
            q=target/case['query'];lines=q.read_text().splitlines();q.write_text('\n'.join(name+'=0' if line.startswith(name+'=') else line for line in lines)+'\n')
        elif fault in ['mode','actual_action','rank','availability']:
            trace=target/(case['lifetime']+('-stop.log' if pixel else '-vpp.log'))
            old,new={'mode':('mode=0 actual_action=2','mode=1 actual_action=2'),
                     'actual_action':('actual_action=2','actual_action=1'),
                     'rank':('rank=1','rank=2'),
                     'availability':('availability=3','availability=7')}[fault]
            text=trace.read_text();assert old in text;trace.write_text(text.replace(old,new))
        elif fault=='endpoint':
            if pixel and case['profile']=='root':
                endpoint=target/case['endpoint'];endpoint.write_text(endpoint.read_text()+case['nonce']+'\n')
            else:
                endpoint=target/('lan-endpoint.json' if pixel else 'endpoint.json')
                values=json.loads(endpoint.read_text());values.append(case['nonce']);endpoint.write_text(json.dumps(values))
        elif fault=='expression':
            file=target/case['source_file'];raw=bytearray(file.read_bytes())
            _,_,retained=struct.unpack_from('<QII',raw,8)
            at=24+8*retained+116
            raw[at+1]^=1;file.write_bytes(raw)
        elif fault=='artifact_binding':
            run['build_sha256']='0'*64;result_path.write_text(json.dumps(run))
        else:
            case['generation']+=1;result_path.write_text(json.dumps(run))
        try:v.verify(target)
        except (AssertionError,KeyError,ValueError,OSError,struct.error):rejected.append(fault)
        else:raise AssertionError('falsified witness accepted: '+fault)
print(json.dumps(dict(status='PASS',platform='pixel' if pixel else 'linux',rejected=rejected,verifier_sha256=v.digest(v.__file__)),indent=2))
