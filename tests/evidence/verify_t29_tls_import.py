#!/usr/bin/env python3
"""Join independent T14 TCP/SNI and T19 import oracles on T29 Pixel evidence."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

p = argparse.ArgumentParser()
p.add_argument('--run', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
run = a.run.resolve()
data = json.loads((run/'result.json').read_text())
assert data['task'] == 'T29' and data['ordinary_history_unchanged'] is True
assert data['cleared_profiles'] == ['root','vpn']
assert json.loads((run/'before-ordinary-hashes.json').read_text()) == json.loads((run/'after-ordinary-hashes.json').read_text())
assert data['import_policy_sha256'] == hashlib.sha256((run/'import-policy.py').read_bytes()).hexdigest()
assert data['domain_policy_sha256'] == hashlib.sha256((run/'domain-policy.py').read_bytes()).hexdigest()

tcp = module('t29_tcp', ROOT/'tests/evidence/verify_t14_sni.py').verify(run)
imports = module('t29_imports', ROOT/'tests/evidence/verify_t19_import.py').verify(run,packet_check=False)
assert tcp['status'] == imports['status'] == 'PASS'
assert set(tcp['profiles']) == set(imports['profiles']) == {'root','vpn'}
assert tcp['source_sha256'] == imports['source_sha256'] == data['source_sha256']
assert imports['import_operations'] >= 90 and imports['rejected_inputs'] == 28
answer = dict(status='VALID',source_sha256=data['source_sha256'],
              apk_sha256=json.loads(Path(data['build']).read_text())['apk_sha256'],
              profiles={name:tcp['profiles'][name] for name in ('root','vpn')},
              import_operations=imports['import_operations'],
              rejected_inputs=imports['rejected_inputs'],
              ordinary_history_unchanged=True,cleared_profiles=data['cleared_profiles'],
              packet_verifier_sha256=hashlib.sha256((ROOT/'tests/evidence/verify_t14_sni.py').read_bytes()).hexdigest(),
              import_verifier_sha256=imports['verifier_sha256'],
              verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
a.output.write_text(json.dumps(answer,indent=2)+'\n')
print(json.dumps({key:answer[key] for key in ('status','source_sha256','apk_sha256',
                                             'import_operations','rejected_inputs')},indent=2))
