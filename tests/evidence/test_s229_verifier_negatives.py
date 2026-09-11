#!/usr/bin/env python3
"""Mutate separate copies of real S229 evidence; never overwrite the source run."""
import argparse
import json
import re
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument('--build', type=Path, required=True)
p.add_argument('--run', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--platform', choices=('linux','pixel'), default='linux')
p.add_argument('--suite', default='basic')
p.add_argument('--policy-helper', type=Path, required=True)
p.add_argument('--nfq-family', choices=('4','6'))
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
records = []
def execute(name, mutate=None, expected=None, build_mutation=False):
    dest = a.output/name
    shutil.copytree(a.run, dest)
    if mutate:
        mutate(dest)
    report = dest/'negative-verification.json'
    build = a.build
    if build_mutation:
        build = dest/'wrong-build.json'
        data = json.loads(a.build.read_text())
        data['files'][next(iter(data['files']))] = '0'*64
        build.write_text(json.dumps(data))
    if a.nfq_family:
        verifier = 'verify-s212-linux-reassembly.py' if a.nfq_family == '4' else 'verify-s228-linux-reassembly.py'
        extra = ['--policy-drop-reason', '8']
    else:
        verifier = 'verify-s229-reassembly.py'
        extra = ['--platform', a.platform, '--suite', a.suite, '--policy-helper', str(a.policy_helper)]
    argv = [sys.executable, '-B', str(ROOT/'tests/device'/verifier),
            '--build', str(build), '--run', str(dest), *extra,
            '--verification-output', str(report)]
    result = subprocess.run(argv, text=True, capture_output=True)
    (dest/'verifier-output.txt').write_text(result.stdout+result.stderr)
    assert report.exists(), name+': verifier crashed instead of reporting HOLD'
    observed = json.loads(report.read_text())
    if expected is None:
        assert result.returncode == 0 and observed['status'] == 'PASS', observed
    else:
        assert result.returncode != 0 and any(expected in e for e in observed['errors']), observed
    records.append(dict(case=name, expected=expected or 'PASS', observed=observed))

def remove_rows(file, prefix):
    def mutate(dest):
        path = dest/file
        path.write_text(''.join(line for line in path.read_text().splitlines(True)
                               if not line.startswith(prefix)))
    return mutate
def change_result(key, value):
    def mutate(dest):
        path = dest/'result.json'
        result = json.loads(path.read_text()); result[key] = value
        path.write_text(json.dumps(result))
    return mutate
def extra_free(dest):
    path = dest/'vpp.log'; log = path.read_text()
    line = next(l for l in log.splitlines() if l.startswith('s203 event=buffer_free ') and 'obligation=212' in l)
    path.write_text(log+line+'\n')
def residue(dest):
    path=dest/'runtime.txt'
    path.write_text(path.read_text().replace('contexts=0 originals=0 retained=0',
                                           'contexts=1 originals=0 retained=0'))
def wrong_adapter(dest):
    path=dest/'vpp.log'
    path.write_text(path.read_text().replace('kind=2 intent=', 'kind=1 intent=', 1))
def drop_bypass(dest):
    path=dest/'vpp.log'
    path.write_text(path.read_text().replace('intent=2 drop_reason=7 bypass_reason=0',
                                           'intent=3 drop_reason=0 bypass_reason=3', 1))
if a.nfq_family:
    execute('positive')
    execute('missing-completion-status',remove_rows('g0/runtime.txt','completion.status '),'missing completion status')
    execute('missing-lanes',remove_rows('g0/runtime.txt','root.lane '),'missing lane status')
    execute('missing-completion',remove_rows('g0/vpp.log','s212 event=completion_publish '),'completion_publish is not once')
    execute('wrong-helper',change_result('policy_helper_sha256','0'*64),'policy helper/library identity mismatch')
    execute('wrong-core',change_result('policy_core_sha256','0'*64),'policy helper/library identity mismatch')
    execute('wrong-source',change_result('source','GRAPH_INJECTED'),'missing real NFQUEUE source identity')
    execute('wrong-build',expected='current source differs',build_mutation=True)
    execute('wrong-policy-expectation',change_result('expected_policy_drop_reason',7),'policy expectation mismatch')
    (a.output/'results.json').write_text(json.dumps(records,indent=2)+'\n')
    print(f'PASS: {len(records)} NFQUEUE positive/negative evidence checks')
    sys.exit(0)
execute('positive')
def missing_runtime(dest):
    (dest/'runtime.txt').unlink()
execute('missing-runtime-file',missing_runtime,'incomplete evidence')
execute('missing-cases',change_result('cases',None),'missing cases/generation')
for prefix, error in [('reassembly.status ', 'missing reassembly status'),
                      ('completion.status ', 'missing completion status'),
                      ('root.lane ', 'missing lane status')]:
    execute('missing-status-'+prefix.split('.')[0], remove_rows('runtime.txt',prefix), error)
execute('missing-completion',remove_rows('vpp.log','s212 event=completion_publish '),'completion_publish is not exactly once')
execute('extra-free',extra_free,'physical buffer free is not exactly once')
execute('wrong-generation',change_result('generation',99999),'generation changed')
execute('wrong-helper',change_result('policy_helper_sha256','0'*64),'policy helper identity mismatch')
execute('wrong-source',change_result('source','NFQ_CAPTURED'),'source label')
execute('wrong-build',expected='current Product source differs',build_mutation=True)
execute('wrong-adapter',wrong_adapter,'adapter kind changed')
if a.suite == 'basic':
    execute('drop-to-bypass',drop_bypass,'basic disposition matrix changed')
elif a.suite == 'policy-return':
    execute('drop-to-bypass',drop_bypass,'policy return rewrote DROP disposition')
elif a.suite == 'sendout-handoff':
    execute('missing-prepared-rejection',remove_rows('vpp.log','s229 event=product_handoff_rejected '),
            'sendout handoff prepared path not covered')
    def mutate_handoff(transform):
        def mutate(dest):
            path = dest/'vpp.log'
            path.write_text(''.join(transform(line) if line.startswith('s229 event=product_handoff_rejected ')
                                    else line for line in path.read_text().splitlines(True)))
        return mutate
    execute('prepared-false',mutate_handoff(lambda line:line.replace('prepared=1','prepared=0')),
            'sendout handoff prepared path not covered')
    execute('missing-ipv6-rejection',mutate_handoff(lambda line:'' if 'family=6 ' in line else line),
            'sendout handoff prepared path not covered')
    execute('empty-ring-rejection',mutate_handoff(lambda line:re.sub(r'occupancy=\d+','occupancy=0',line)),
            'prepared rejection did not hit a full remote native ring')
execute('stop-with-debt',residue,'native reassembly debt')
(a.output/'results.json').write_text(json.dumps(records,indent=2)+'\n')
print(f'PASS: {len(records)} positive/negative evidence checks')
