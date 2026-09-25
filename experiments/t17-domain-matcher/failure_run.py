#!/usr/bin/env python3
"""Run isolated build-failure probes serially, including expected process exits."""
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
    p.add_argument('out', type=Path)
    p.add_argument('--android', action='store_true')
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    nonce = uuid.uuid4().hex
    remote = '/data/local/tmp/t17-failure-' + nonce
    env = dict(os.environ, SAKAMOTO_ADB='/tmp/sakamoto-r3-platform-tools/adb-client')
    serial = json.loads((ROOT / 'build-output/t16-20260926/pixel-sni-c/result.json').read_text())['serial'] if args.android else None
    def adb(*words):
        return subprocess.run([str(ROOT / 'dev/adb'), '-s', serial, *words], env=env,
                              capture_output=True, text=True, timeout=40)
    data = {'nonce': nonce, 'android': args.android, 'build_sha256': sha(args.build / 'build.json'),
            'started_ns': time.time_ns(), 'runs': []}
    shutil.copyfile(Path(__file__), args.out / 'runner.py')
    if args.android:
        payload = args.out / 'payload'; payload.mkdir()
        for name in ('datrie', 'rax', 'vpp'):
            shutil.copyfile(args.build / name, payload / name)
        shutil.copyfile(ROOT / 'build-output/s220-20260913/android-stage-b/lib/libvppinfra.so', payload / 'libvppinfra.so')
        assert adb('shell', 'mkdir', remote).returncode == 0
        assert adb('push', str(payload) + '/.', remote).returncode == 0
        assert adb('shell', 'chmod', '755', remote + '/datrie', remote + '/rax', remote + '/vpp').returncode == 0
        hashes = adb('shell', 'sha256sum', remote + '/datrie', remote + '/rax', remote + '/vpp', remote + '/libvppinfra.so')
        data['device_hashes'] = hashes.stdout
        for line in hashes.stdout.splitlines():
            value, path = line.split()
            assert value == sha(payload / Path(path).name)
    for candidate in ('datrie', 'rax', 'vpp'):
        for fail_at in ([0, 1, 5, 50, 500] if candidate != 'vpp' else [0]):
            if args.android:
                result = adb('shell', 'ulimit -c 0; LD_LIBRARY_PATH=' + remote,
                             'timeout', '-k', '2', '30', remote + '/' + candidate, str(fail_at))
                processes = adb('shell', 'ps', '-A', '-o', 'ARGS')
                assert processes.returncode == 0 and remote + '/' + candidate not in processes.stdout
            else:
                result = subprocess.run([str(args.build / candidate), str(fail_at)],
                                        capture_output=True, text=True, timeout=30)
            data['runs'].append({'candidate': candidate, 'fail_at': fail_at,
                                 'returncode': result.returncode, 'stdout': result.stdout,
                                 'stderr': result.stderr, 'remote_exit_confirmed': args.android})
            (args.out / 'index.json').write_text(json.dumps(data, indent=2) + '\n')
    if args.android:
        data['cleanup_returncode'] = adb('shell', 'rm', '-rf', remote).returncode
    data['completed_ns'] = time.time_ns()
    (args.out / 'index.json').write_text(json.dumps(data, indent=2) + '\n')
    print([(r['candidate'], r['fail_at'], r['returncode']) for r in data['runs']])


if __name__ == '__main__':
    main()
