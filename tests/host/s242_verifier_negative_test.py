#!/usr/bin/env python3
"""Semantic S242 mutations are re-sealed, so hash rejection is not enough."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s242_verify', ROOT/'tests/device/verify-s242-root-lifecycle.py')
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def change_line(path, prefix, field, value):
    lines = path.read_text().splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith(prefix))
    lines[index], count = re.subn(r'\b'+field+r'=\S+', field+'='+str(value), lines[index], count=1)
    assert count == 1, (path, prefix, field)
    path.write_text('\n'.join(lines)+'\n')


def omit(path, prefix):
    lines = path.read_text().splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith(prefix))
    del lines[index]
    path.write_text('\n'.join(lines)+'\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    baseline = oracle.verify(args.run)
    assert baseline['status'] == 'PASS', baseline
    report = dict(status='HOLD', baseline_sha256=oracle.digest(args.run/'result.json'),
                  verifier_sha256=oracle.digest(oracle.__file__), platform=baseline['platform'], cases=[])

    def execute(name, mutation, reason):
        with tempfile.TemporaryDirectory(prefix='s242-negative-') as temporary:
            copied = Path(temporary)/'run'
            shutil.copytree(args.run, copied)
            mutation(copied)
            path = copied/'result.json'
            result = json.loads(path.read_text())
            result['raw_hashes'] = {name: oracle.digest(copied/name) for name in result['raw_hashes']}
            path.write_text(json.dumps(result, indent=2)+'\n')
            answer = oracle.verify(copied)
            assert answer['status'] == 'HOLD' and any(reason in e for e in answer['errors']), (name, answer)
            report['cases'].append(dict(name=name, rejected=True, errors=answer['errors']))

    log = 'faults-stop/vpp.log'
    def extra_worker(p):
        path = p/'faults-stop/layout.txt'
        path.write_text(path.read_text()+'\n3 vpp_wk_2 workers 999999 other (0) 3 3 0\n')
    execute('extra-native-worker', extra_worker, 'actual VPP W2 thread layout')
    def wrong_inode(p):
        path = p/'faults-stop/initial-fds.txt'
        inode = re.search(r'socket:\[(\d+)\]\s+sakamoto-root-nfqueue-', (p/'faults-stop/layout.txt').read_text())[1]
        path.write_text(path.read_text().replace('socket:['+inode+']', 'socket:[999999999]', 1))
    execute('wrong-live-fd-inode', wrong_inode, 'worker file ownership')
    def retained_fd(p):
        path = p/'faults-stop/native-closed-fds.txt'
        inode = re.search(r'socket:\[(\d+)\]\s+sakamoto-root-nfqueue-', (p/'faults-stop/layout.txt').read_text())[1]
        path.write_text(path.read_text()+'14 -> socket:['+inode+']\n')
    execute('queue-fd-survives-native-stop', retained_fd, 'retired queue socket still exists')
    execute('original-fd-swapped', lambda p: change_line(p/log, 's242 event=verdict_syscall ', 'fd', 123456), 'syscall redirected')
    execute('wrong-origin-thread', lambda p: change_line(p/log, 's231 event=nfq_payload ', 'thread', 0), 'capture lane/generation/thread')
    execute('wrong-native-generation', lambda p: change_line(p/log, 's242 event=verdict_syscall ', 'generation', 24209), 'syscall redirected')
    execute('lost-origin-buffer-return', lambda p: omit(p/log, 's203 event=buffer_free source=NFQ_CAPTURED '), 'origin buffer returned')
    execute('missing-native-operation', lambda p: omit(p/log, 's242 event=verdict_syscall '), 'normal stop lost')
    def retry(p):
        path = p/log
        line = next(l for l in path.read_text().splitlines() if l.startswith('s242 event=verdict_syscall '))
        path.write_text(path.read_text().replace(line, line+'\n'+line, 1))
    execute('physical-verdict-retry', retry, 'physical verdict retried')
    execute('premature-fd-retirement', lambda p: change_line(p/log, 's242 event=lane_retire ', 'pending', 1), 'lane retired before origin settlement')
    execute('wrong-drain-fd', lambda p: change_line(p/log, 's242 event=quiesce ', 'fd', 999), 'drain did not preserve')
    execute('false-native-zero', lambda p: change_line(p/log, 's242 event=stop_native_zero ', 'buffers', 1), 'native stop falsely reported zero')
    execute('retained-native-pool', lambda p: change_line(p/'faults-stop/native-closed.txt', 'root.receive ', 'allocated', 72), 'native receive storage')
    execute('retained-owner-credit', lambda p: change_line(p/'faults-stop/native-closed.txt', 'primary.status ', 'credit0', 31), 'outstanding handoff credits')
    execute('stale-stop-accepted', lambda p: change_line(p/'faults-stop/stale-stop.txt', 'stop_step ', 'code', 0), 'stale stop request')
    execute('query-close-stopped-runtime', lambda p: change_line(p/'faults-stop/after-query-and-stale-stop.txt', 'root.lane ', 'ready', 0), 'query close or stale generation')
    execute('replay-wrong-origin', lambda p: change_line(p/log, 's204 event=completion_reject ', 'thread', 0), 'replay did not reach its own origin')
    execute('missing-replay-return', lambda p: omit(p/log, 's203 event=buffer_free source=COMPLETION_REPLAY '), 'all replay carriers')
    def no_busy(p):
        path = p/'restart/native-stop.txt'
        path.write_text('\n'.join(l for l in path.read_text().splitlines()
            if not (l.startswith('stop_step ') and 'stopped=0 ' in l))+'\n')
    execute('busy-path-not-exercised', no_busy, 'busy drain path')
    def change_result(p, callback):
        path = p/'result.json'
        result = json.loads(path.read_text())
        callback(result)
        path.write_text(json.dumps(result)+'\n')
    execute('forged-case-owner', lambda p: change_result(p, lambda r:
        r['generations'][1]['cases'][0].update(owner=1-r['generations'][1]['cases'][0]['owner'])), 'case owner identity')
    execute('foreign-holder-killed', lambda p: change_result(p, lambda r: r['generations'][0].update(holder_survived_rollback=False)), 'partial startup process ownership')
    execute('missing-lifecycle-phase', lambda p: change_result(p, lambda r: r['generations'].pop()), 'missing required lifecycle phase')
    execute('endpoint-process-survives', lambda p: change_result(p, lambda r: r['endpoint_cleanup'][0].update(process_absent=False)), 'independent endpoint cleanup')
    def old_delivered(p):
        result = json.loads((p/'result.json').read_text())
        case = next(c for c in result['generations'][1]['cases'] if c['phase'] == 'definite-failure')
        path = p/'endpoint-final-0.txt'
        path.write_text(path.read_text()+'received nonce='+case['nonce']+'-0\n')
    execute('failed-verdict-late-delivery', old_delivered, 'actual endpoint delivery/late delivery')
    def fake_graceful(p):
        path = p/'abnormal/vpp.log'
        path.write_text(path.read_text()+'\ns242 event=stop_native_zero generation=24212\n')
    execute('os-reclaim-called-native-drain', fake_graceful, 'OS reclamation misrepresented')
    report['status'] = 'PASS'
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
