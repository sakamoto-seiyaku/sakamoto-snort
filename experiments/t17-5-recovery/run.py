#!/usr/bin/env python3
"""Serial bounded recovery probes; all Android access uses the repo wrapper."""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'experiments/t17-domain-matcher'
sys.path.insert(0, str(BASE))
from generate import generate


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('build', type=Path)
    parser.add_argument('out', type=Path)
    parser.add_argument('--android', action='store_true')
    parser.add_argument('--focused', action='store_true', help='small/edge cost plus failures for sanitizers')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    nonce = uuid.uuid4().hex
    remote = '/data/local/tmp/t175-' + nonce
    env = os.environ.copy()
    env.setdefault('ASAN_OPTIONS', 'detect_leaks=0')
    device = None
    if args.android:
        device = json.loads((ROOT / 'build-output/t16-20260926/pixel-sni-c/result.json').read_text())['serial']
        env['SAKAMOTO_ADB'] = '/tmp/sakamoto-r3-platform-tools/adb-client'

    def adb(*words, timeout=120):
        return subprocess.run([str(ROOT / 'dev/adb'), '-s', device, *words], env=env,
                              capture_output=True, text=True, timeout=timeout)

    small = args.out / 'small-shared'
    generate(small, 32, 'shared')
    workloads = {'small-shared': small,
                 'edges': ROOT / 'build-output/t17-20260926/edge-workloads/edges'}
    if not args.focused:
        for shape in ('shared', 'entropy', 'deep'):
            workloads[shape] = ROOT / 'build-output/t17-20260926/workloads' / (shape + '-100000')
    cases = [('cost', shape, repeat) for repeat in range(3) for shape in ('shared', 'entropy', 'deep')]
    if args.focused:
        cases = [('cost', 'small-shared', 0)]
    cases += [('cost', 'edges', 0), ('faults', 'small-shared', 0), ('faults', 'edges', 0), ('exhaustion', 'small-shared', 0)]
    if not args.focused:
        cases += [('targeted', shape, 0) for shape in ('shared', 'entropy', 'deep')]
    build = json.loads((args.build / 'build.json').read_text())
    assert sha(args.build / 'recovery') == build['binary_sha256']
    library = Path(build['vpp_library']['path'])
    assert sha(library) == build['vpp_library']['sha256']
    meta = {'schema': 't17-5-run-v1', 'nonce': nonce, 'android': args.android,
            'focused': args.focused, 'build_sha256': sha(args.build / 'build.json'),
            'runner_sha256': sha(Path(__file__)), 'started_ns': time.time_ns(),
            'workloads': {name: {'path': str(path.resolve()),
                                 'files': {p.name: sha(p) for p in path.glob('*.tsv')}}
                          for name, path in workloads.items()}, 'runs': []}
    shutil.copyfile(Path(__file__), args.out / 'runner.py')

    def persist():
        (args.out / 'index.json').write_text(json.dumps(meta, indent=2) + '\n')

    persist()
    if args.android:
        info = adb('shell', 'uname -a; getprop ro.product.model; getprop ro.build.fingerprint; getprop ro.product.cpu.abi; dumpsys battery')
        require_success(info)
        (args.out / 'device-before.txt').write_text(info.stdout)
        require_success(adb('shell', 'mkdir', remote))
        payload = args.out / 'payload'
        payload.mkdir()
        shutil.copyfile(args.build / 'recovery', payload / 'recovery')
        shutil.copyfile(library, payload / 'libvppinfra.so')
        for name, path in workloads.items():
            shutil.copytree(path, payload / name)
        require_success(adb('push', str(payload) + '/.', remote))
        require_success(adb('shell', 'chmod', '755', remote + '/recovery'))
        hashes = adb('shell', 'sha256sum', remote + '/recovery', remote + '/libvppinfra.so')
        require_success(hashes)
        meta['device_hashes'] = hashes.stdout
        actual = {Path(line.split()[1]).name: line.split()[0] for line in hashes.stdout.splitlines()}
        assert actual == {'recovery': build['binary_sha256'], 'libvppinfra.so': build['vpp_library']['sha256']}
        workload_paths = [remote + '/' + name + '/' + file for name, item in meta['workloads'].items()
                          for file in item['files']]
        hashes = adb('shell', 'sha256sum', *workload_paths)
        require_success(hashes)
        meta['device_workload_hashes'] = hashes.stdout
        actual = {line.split()[1]: line.split()[0] for line in hashes.stdout.splitlines()}
        expected = {remote + '/' + name + '/' + file: digest for name, item in meta['workloads'].items()
                    for file, digest in item['files'].items()}
        assert actual == expected, 'device workload digest mismatch'
        require_success(adb('shell', 'timeout', '1', 'true'))
    else:
        meta['host'] = subprocess.check_output(['uname', '-a'], text=True)
    for mode, workload, repeat in cases:
        run_id = f'{nonce}-{mode}-{workload}-{repeat}'
        record = {'run_id': run_id, 'mode': mode, 'workload': workload, 'repeat': repeat}
        try:
            if args.android:
                command = ['shell', 'LD_LIBRARY_PATH=' + remote, 'timeout', '-k', '2', '90',
                           remote + '/recovery', mode, remote + '/' + workload + '/entries.tsv',
                           remote + '/' + workload + '/queries.tsv', run_id]
                result = adb(*command, timeout=100)
            else:
                command = [str(args.build / 'recovery'), mode, str(workloads[workload] / 'entries.tsv'),
                           str(workloads[workload] / 'queries.tsv'), run_id]
                result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=90)
            record.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        except subprocess.TimeoutExpired:
            record['failure'] = 'timeout'
            meta['runs'].append(record)
            persist()
            if args.android:
                processes = adb('shell', 'ps', '-A', '-o', 'ARGS')
                (args.out / 'timeout-processes.txt').write_text(processes.stdout + processes.stderr)
            raise RuntimeError('timeout; series stopped, inspect retained remote state')
        if args.android:
            processes = adb('shell', 'ps', '-A', '-o', 'ARGS')
            record['remote_exit_confirmed'] = processes.returncode == 0 and remote + '/recovery' not in processes.stdout
        if result.returncode == 0:
            record['measurement'] = json.loads(result.stdout)
            assert record['measurement']['run_id'] == run_id
        meta['runs'].append(record)
        persist()
        print(mode, workload, repeat, result.returncode, flush=True)
        if args.android and not record['remote_exit_confirmed']:
            raise RuntimeError('remote exit not confirmed')
        if result.returncode:
            raise RuntimeError('failed probe retained; series stopped')
    if args.android:
        info = adb('shell', 'dumpsys battery')
        require_success(info)
        (args.out / 'device-after.txt').write_text(info.stdout)
        cleanup = adb('shell', 'rm', '-rf', remote)
        meta['cleanup_returncode'] = cleanup.returncode
        require_success(cleanup)
    meta['completed_ns'] = time.time_ns()
    persist()


def require_success(result):
    if result.returncode:
        raise RuntimeError(result.stderr)


if __name__ == '__main__':
    main()
