#!/usr/bin/env python3
"""Reject re-sealed false app/JNI/native/endpoint lifecycle evidence."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s242_supervisor', ROOT/'tests/device/verify-s242-supervisor.py')
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def line_edit(path, select, edit):
    lines = path.read_text().splitlines()
    index = next(i for i, line in enumerate(lines) if select(line))
    lines[index] = edit(lines[index])
    path.write_text('\n'.join(lines)+'\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    baseline = oracle.verify(args.run)
    assert baseline['status'] == 'PASS', baseline
    original = json.loads((args.run/'result.json').read_text())
    generations = {r['label']: str(r['generation']) for r in original['generations']}
    report = dict(status='HOLD', baseline_sha256=oracle.digest(args.run/'result.json'),
                  verifier_sha256=oracle.digest(oracle.__file__), cases=[])

    def execute(name, mutation, expected):
        with tempfile.TemporaryDirectory(prefix='s242-supervisor-negative-') as temporary:
            copied = Path(temporary)/'run'
            shutil.copytree(args.run, copied)
            mutation(copied)
            path = copied/'result.json'
            result = json.loads(path.read_text())
            result['raw_hashes'] = {name: oracle.digest(copied/name) for name in result['raw_hashes']}
            path.write_text(json.dumps(result, indent=2)+'\n')
            answer = oracle.verify(copied)
            assert answer['status'] == 'HOLD' and any(expected in e for e in answer['errors']), (name, answer)
            report['cases'].append(dict(name=name, rejected=True, errors=answer['errors']))

    def current_claim(line):
        return 's242 native_root_drain=true' in line and 'generation='+generations['stop']+' ' in line
    execute('jni-drain-not-successful', lambda p: line_edit(p/'stop/service.log', current_claim,
        lambda line: line.replace('native_root_drain=true', 'native_root_drain=false')), 'service native drain failed')
    execute('jni-drain-over-budget', lambda p: line_edit(p/'stop/service.log', current_claim,
        lambda line: re.sub(r'elapsed_ms=\d+', 'elapsed_ms=4000', line)), 'service native drain failed')
    execute('wrong-native-owner-token', lambda p: line_edit(p/'stop/process-owner.properties',
        lambda line: line.startswith('SAKAMOTO_VPP_OWNER_TOKEN='), lambda line: line+'-wrong'), 'native process owner/generation')
    execute('native-zero-with-debt', lambda p: line_edit(p/'stop/vpp.log',
        lambda line: line.startswith('s242 event=stop_native_zero '), lambda line: line.replace('buffers=0', 'buffers=1')),
        'missing archived native zero')
    execute('no-ingress-cutoff', lambda p: line_edit(p/'stop/vpp.log',
        lambda line: line.startswith('s242 event=quiesce '), lambda _: ''), 'app closed verdict channel')
    execute('lost-buffer-return', lambda p: line_edit(p/'stop/vpp.log',
        lambda line: line.startswith('s203 event=buffer_free '), lambda _: ''), 'app stop did not return every buffer')
    execute('duplicate-native-consumption', lambda p: line_edit(p/'stop/vpp.log',
        lambda line: line.startswith('s204 event=completion_consume '), lambda line: line+'\n'+line),
        'app stop consumed an identity zero or multiple times')
    execute('physical-verdict-retry', lambda p: line_edit(p/'stop/vpp.log',
        lambda line: line.startswith('s242 event=verdict_syscall '), lambda line: line+'\n'+line),
        'capture identity reused or physical retry')
    execute('failed-native-operation', lambda p: line_edit(p/'stop/vpp.log',
        lambda line: line.startswith('s242 event=verdict_syscall '), lambda line: re.sub(r'result=\d+', 'result=-1', line)),
        'invalid app native operation')
    execute('app-stopped-with-live-ownership', lambda p: line_edit(p/'stop/stopped.properties',
        lambda line: line == 'mayBeActive=false', lambda _: 'mayBeActive=true'), 'app cleanup did not settle')
    def process_survives(p):
        path = p/'stop/processes-after.txt'
        path.write_text(path.read_text()+str(original['generations'][0]['pid'])+' 0 libvpp_runtime.so -c owned.conf\n')
    execute('actual-native-pid-survives', process_survives, 'native process survived app stop')
    def os_zero(p):
        path = p/'crash/vpp.log'
        path.write_text(path.read_text()+'\ns242 event=stop_native_zero generation='+generations['crash']+'\n')
    execute('os-reclaim-called-native-zero', os_zero, 'OS reclaim relabelled')
    def os_claim(p):
        path = p/'crash/service.log'
        path.write_text(path.read_text()+'\ns242 native_root_drain=true generation='+generations['crash']+' result=1 elapsed_ms=0\n')
    execute('crash-claimed-jni-drain', os_claim, 'crashed generation claimed graceful drain')
    execute('missing-os-classification', lambda p: line_edit(p/'crash/service.log',
        lambda line: 'product_core_close=os_reclaim_after_exit' in line and 'generation='+generations['crash']+' ' in line,
        lambda _: ''), 'missing explicit supervisor OS-reclaim')
    def endpoint_missing(p):
        nonce = original['generations'][0]['clients'][0]['nonce']
        for path in p.glob('endpoint-final-*.txt'):
            path.write_text(path.read_text().replace(nonce, 'NOT_THE_ORIGINAL_NONCE'))
    execute('echo-without-independent-endpoint', endpoint_missing, 'client echo has no independent endpoint record')
    report['status'] = 'PASS'
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
