#!/usr/bin/env python3
"""Semantic corruptions of real evidence; raw accepted files stay untouched."""
import argparse
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('capacity', ROOT/'tests/device/s210-capacity-verify.py')
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)
parser = argparse.ArgumentParser()
parser.add_argument('run', type=Path)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
case = json.loads((args.run/'g0/case.json').read_text())
trace = (args.run/'g0/vpp.log').read_text()
runtime = (args.run/'g0/runtime.txt').read_text()
endpoint = json.loads((args.run/'g0/endpoint.json').read_text())
oracle.verify_case(case, trace, runtime, endpoint)
lines = trace.splitlines()
bypass = next(r['token'] for r in oracle.rows(trace,'s210 ') if r.get('event') == 'primary_rejected')
deferred = next(r['token'] for r in oracle.rows(trace,'s210 ') if r.get('event') == 'completion_deferred')


def record(prefix, token):
    field = 'obligation' if prefix.startswith('s203 ') else 'token'
    return next(line for line in lines if line.startswith(prefix) and re.search(r'\b'+field+'='+token+r'\b', line))


origin = record('s210 event=origin_completion ', bypass)
free = record('s203 event=buffer_free ', bypass)
verdict = record('s203 event=verdict ', bypass)
drop_origin = record('s210 event=origin_completion ', deferred)
normal_policy = next(line for line in lines if line.startswith('s203 event=policy '))
normal_primary = next(line for line in lines if line.startswith('s205 event=primary_accepted '))
corruptions = {
    'wrong_generation': trace.replace(origin, re.sub(r'\bgeneration=\d+', 'generation=999999', origin), 1),
    'missing_buffer_free': trace.replace(free+'\n', '', 1),
    'duplicate_nfqueue_verdict': trace+verdict+'\n',
    'bypass_without_reason': trace.replace(origin, re.sub(r'\bbypass_reason=\d+', 'bypass_reason=0', origin), 1),
    'policy_drop_becomes_accept': trace.replace(drop_origin, drop_origin.replace('verdict=0','verdict=1'), 1),
    'bypass_fabricates_policy': trace+re.sub(r'\bobligation=\d+', 'obligation='+bypass, normal_policy)+'\n',
    'rejected_carrier_transferred': trace+re.sub(r'\btoken=\d+', 'token='+bypass, normal_primary)+'\n',
}
results = []
for name, changed in corruptions.items():
    try:
        oracle.verify_case(case, changed, runtime, endpoint)
    except AssertionError as error:
        results.append(dict(name=name, status='EXPECTED_HOLD', reason=str(error)))
    else:
        raise AssertionError('corruption accepted: '+name)
result = dict(status='PASS', negatives=results)
args.output.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
