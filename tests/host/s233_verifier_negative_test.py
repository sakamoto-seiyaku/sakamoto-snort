#!/usr/bin/env python3
"""Reject altered S233 source, origin, policy, kernel and cleanup evidence."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('oracle', ROOT/'tests/device/verify-s233-fail-open.py')
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def replace(path, before, after):
    text = path.read_text()
    assert before in text, (path, before)
    path.write_text(text.replace(before, after, 1))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    baseline = oracle.verify(args.run.resolve())
    assert baseline['status'] == 'PASS'
    report = dict(status='HOLD', platform=baseline['platform'], verifier_sha256=oracle.digest(oracle.__file__),
                  baseline_sha256=oracle.digest(args.run/'result.json'), cases=[])

    def execute(name, mutation, expected):
        with tempfile.TemporaryDirectory(prefix='s233-negative-') as temporary:
            copy = Path(temporary)/'run'
            shutil.copytree(args.run, copy)
            mutation(copy)
            try:
                oracle.verify(copy)
            except (AssertionError, KeyError, ValueError, OSError) as error:
                assert expected in str(error), (name, str(error), expected)
                report['cases'].append(dict(name=name, rejected=True, reason=str(error)))
            else:
                raise AssertionError('accepted tampered evidence: '+name)

    execute('queue-fail-open-flag', lambda p: replace(p/'pressure/vpp.log', 'flags=9', 'flags=8'), 'FAIL_OPEN configuration ACK')
    execute('no-listener-rule-flag', lambda p: replace(p/'pressure/hooks.txt', ' --queue-bypass', ''), 'no-listener flag')
    execute('wrong-small-queue', lambda p: replace(p/'pressure/vpp.log', 'maxlen=1 ', 'maxlen=1024 '), 'FAIL_OPEN configuration ACK')
    execute('forged-reserve-count', lambda p: replace(p/'resources/normal-exhausted.txt', 'reserve_accepts=2', 'reserve_accepts=3'), 'reserve_accepts delta=2')
    execute('cross-lane-pool-debt', lambda p: replace(p/'resources/normal-held.txt', 'loans=64', 'loans=63'), 'fixed pool conservation')
    execute('reserve-loss-hidden', lambda p: replace(p/'resources/reserve-exhausted.txt', 'reserve_losses=1', 'reserve_losses=0'), 'reserve_losses delta=1')
    execute('identity-loss-hidden', lambda p: replace(p/'resources/missing-identity.txt', 'identity_losses=1', 'identity_losses=0'), 'identity_losses delta=1')
    execute('kernel-bypass-counted-as-adapter', lambda p: replace(p/'pressure/kernel-full-bypass.txt', 'ingress_accepts=0', 'ingress_accepts=1'), 'ingress_accepts delta=0')
    execute('pool-not-released', lambda p: replace(p/'resources/closed.txt', 'allocated=0', 'allocated=72'), 'fixed pool conservation')
    execute('listener-not-closed', lambda p: replace(p/'pressure/closed.txt', 'fd=-1', 'fd=14'), 'lane close')

    def change_drop(p):
        path = p/'resources/vpp.log'
        text = path.read_text()
        line = next(l for l in text.splitlines() if l.startswith('s203 event=verdict ') and 'verdict=0' in l)
        path.write_text(text.replace(line, line.replace('verdict=0', 'verdict=1'), 1))
    execute('policy-drop-flipped-to-accept', change_drop, 'physical verdict preserves policy')

    def deliver_old_queue(p):
        result = json.loads((p/'result.json').read_text())
        case = next(c for run in result['runs'] for c in run['cases'] if c['phase'] == 'queued-before-close')
        path = p/f'endpoint-{case["family"]}.log'
        path.write_text(path.read_text()+f'received family={case["family"]} nonce={case["nonce"]}-0 echo=1\n')
    execute('pre-close-packet-claimed-bypass', deliver_old_queue, 'independent endpoint receipt count')

    def socket_overflow(p):
        path = p/'pressure/paused-full-netlink.txt'
        lines = path.read_text().splitlines()
        for n, line in enumerate(lines):
            fields = line.split()
            if len(fields) == 10 and fields[1] == '12' and fields[2] != '0':
                fields[8] = '1'
                lines[n] = ' '.join(fields)
                break
        else:
            raise AssertionError('missing queue socket')
        path.write_text('\n'.join(lines)+'\n')
    execute('socket-overflow-substituted-for-queue-full', socket_overflow, 'not socket overflow')

    if baseline['platform'] == 'pixel':
        def queue_not_full(p):
            path = p/'pressure/paused-full-queues.txt'
            lines = path.read_text().splitlines()
            fields = lines[0].split()
            fields[2] = '0'
            lines[0] = ' '.join(fields)
            path.write_text('\n'.join(lines)+'\n')
        execute('kernel-queue-not-full', queue_not_full, 'actual kernel queue-full')
    else:
        execute('queue-still-owned', lambda p: replace(p/'resources/closed-queue-bind.json', ': 0', ': -16'), 'queue unbind')
    report['status'] = 'PASS'
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
