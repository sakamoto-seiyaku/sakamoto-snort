#!/usr/bin/env python3
"""Serial fresh-process measurements; device operations exclusively repo dev/adb."""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('build', type=Path)
    p.add_argument('workloads', type=Path)
    p.add_argument('out', type=Path)
    p.add_argument('--android', action='store_true')
    p.add_argument('--repeat', type=int, default=3)
    p.add_argument('--only', default='')
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    nonce = uuid.uuid4().hex
    env = os.environ.copy()
    device = None
    remote = '/data/local/tmp/t17-' + nonce
    if args.android:
        device = json.loads((ROOT / 'build-output/t16-20260926/pixel-sni-c/result.json').read_text())['serial']
        env['SAKAMOTO_ADB'] = '/tmp/sakamoto-r3-platform-tools/adb-client'
    def adb(*words, timeout=120):
        return subprocess.run([str(ROOT / 'dev/adb'), '-s', device, *words], env=env,
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    metadata = {'schema': 't17-run-v1', 'nonce': nonce, 'android': args.android,
                'build_sha256': sha(args.build / 'build.json'), 'started_ns': time.time_ns(),
                'runner_sha256': sha(Path(__file__)), 'runs': []}
    def persist():
        (args.out / 'index.json').write_text(json.dumps(metadata, indent=2) + '\n')
    shutil.copyfile(Path(__file__), args.out / 'runner.py')
    if args.android:
        # No selector in public evidence. Hardware/software identity is adequate.
        info = adb('shell', 'uname -a; getprop ro.product.model; getprop ro.build.fingerprint; getprop ro.product.cpu.abi; cat /proc/cpuinfo; dumpsys battery')
        (args.out / 'device-before.txt').write_text(info.stdout + info.stderr)
        if adb('shell', 'mkdir', remote).returncode:
            raise RuntimeError('remote mkdir failed')
        staging = args.out / 'payload'
        staging.mkdir()
        for name in ('datrie', 'rax', 'vpp'):
            shutil.copyfile(args.build / name, staging / name)
        shutil.copyfile(ROOT / 'build-output/s220-20260913/android-stage-b/lib/libvppinfra.so', staging / 'libvppinfra.so')
        result = adb('push', str(staging) + '/.', remote)
        (args.out / 'push.txt').write_text(result.stdout + result.stderr)
        if result.returncode or adb('shell', 'chmod', '755', remote + '/datrie', remote + '/rax', remote + '/vpp').returncode:
            raise RuntimeError('deployment failed')
        metadata['device_binary_hashes'] = adb('shell', 'sha256sum', remote + '/datrie', remote + '/rax', remote + '/vpp', remote + '/libvppinfra.so').stdout
        hashes = {Path(line.split()[1]).name: line.split()[0]
                  for line in metadata['device_binary_hashes'].splitlines()}
        for name in ('datrie', 'rax', 'vpp', 'libvppinfra.so'):
            if hashes.get(name) != sha(staging / name):
                raise RuntimeError('device artifact digest mismatch: ' + name)
        if adb('shell', 'timeout', '1', 'true').returncode:
            raise RuntimeError('device timeout command unavailable')
    else:
        metadata['host'] = subprocess.check_output(['uname', '-a'], text=True)
    persist()
    for workload in sorted(args.workloads.iterdir()):
        if not workload.is_dir() or (args.only and workload.name != args.only):
            continue
        if args.android:
            result = adb('push', str(workload), remote)
            if result.returncode:
                raise RuntimeError(result.stderr)
        for repeat in range(args.repeat):
            candidates = ['datrie', 'rax', 'vpp']
            candidates = candidates[repeat % 3:] + candidates[:repeat % 3]
            for candidate in candidates:
                run_id = f'{nonce}-{workload.name}-{candidate}-{repeat}'
                record = {'run_id': run_id, 'candidate': candidate, 'workload': workload.name,
                          'repeat': repeat, 'manifest_sha256': sha(workload / 'manifest.json')}
                started = time.monotonic_ns()
                try:
                    if args.android:
                        command = ['shell', f'LD_LIBRARY_PATH={remote}', 'timeout', '-k', '2', '120', remote + '/' + candidate,
                                   remote + '/' + workload.name + '/entries.tsv',
                                   remote + '/' + workload.name + '/queries.tsv', run_id]
                        result = adb(*command, timeout=130)
                    else:
                        command = [str(args.build / candidate), str(workload / 'entries.tsv'),
                                   str(workload / 'queries.tsv'), run_id]
                        result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE, timeout=120)
                    record.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
                    if result.returncode == 0:
                        record['measurement'] = json.loads(result.stdout)
                        if record['measurement']['run_id'] != run_id:
                            raise RuntimeError('run identity mismatch')
                except subprocess.TimeoutExpired:
                    record['failure'] = '120-second timeout'
                    # A client transport failure is not proof of device exit.
                    # Stop this series rather than allow measurement overlap.
                    metadata['runs'].append(record)
                    persist()
                    raise RuntimeError('ADB client timed out; remote state requires inspection')
                if args.android:
                    processes = adb('shell', 'ps', '-A', '-o', 'ARGS')
                    if processes.returncode or any(remote + '/' + name in processes.stdout
                                                   for name in ('datrie', 'rax', 'vpp')):
                        metadata['runs'].append(record)
                        persist()
                        raise RuntimeError('remote benchmark exit not confirmed')
                    record['remote_exit_confirmed'] = True
                record['elapsed_ns'] = time.monotonic_ns() - started
                metadata['runs'].append(record)
                persist()
                print(workload.name, candidate, repeat, record.get('returncode', record.get('failure')), flush=True)
    if args.android:
        (args.out / 'device-after.txt').write_text(adb('shell', 'dumpsys battery').stdout)
        # Remove only this runner's nonce-owned native experiment deployment.
        metadata['cleanup_returncode'] = adb('shell', 'rm', '-rf', remote).returncode
    metadata['completed_ns'] = time.time_ns()
    persist()


if __name__ == '__main__':
    main()
