#!/usr/bin/env python3
"""S303: Pixel startup rejects invalid owner and VPN I/O placements before capture."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SERIAL = '28201JEGR0XPAJ'
PKG = 'com.sakamoto.snort.androidruntime'
STATE = 'files/runtime-state/snapshot.properties'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def props(value):
    return dict(line.split('=', 1) for line in value.splitlines()
                if '=' in line and not line.startswith('#'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    apk = args.apk.resolve()
    result = dict(status='HOLD', task='SAKAMOTO-303', serial=SERIAL,
                  apk_sha256=digest(apk), runner_sha256=digest(__file__), cases=[])

    def save(name, value):
        (args.output / name).write_text(value)
        return value

    def adb(*command, check=True):
        process = subprocess.run([str(ROOT / 'dev/adb'), '-s', SERIAL, *map(str, command)],
                                 capture_output=True, text=True, errors='replace', timeout=45)
        value = (process.stdout + process.stderr).replace('\r', '')
        if process.returncode and check:
            raise RuntimeError(value)
        return value

    def app(path):
        return adb('shell', 'run-as', PKG, 'cat', path, check=False)

    def root(command):
        return adb('shell', 'su', '-c', shlex.quote(command))

    def action(*extras):
        return adb('shell', 'am', 'start', '-n', PKG + '/.DebugControlActivity', *extras)

    try:
        assert props(save('initial-state.properties', app(STATE))).get('mayBeActive') == 'false'
        save('cpu-online.txt', adb('shell', 'cat', '/sys/devices/system/cpu/online'))
        save('allowed.txt', adb('shell', 'cat', '/proc/self/status'))
        save('wifi.txt', adb('shell', 'cmd', 'wifi', 'status'))
        save('install.txt', adb('install', '-r', apk))
        package = save('package.txt', adb('shell', 'dumpsys', 'package', PKG))
        code = re.search(r'codePath=(\S+)', package).group(1)
        assert save('installed-apk.txt', adb('shell', 'sha256sum',
                    code + '/base.apk')).split()[0] == result['apk_sha256']
        with zipfile.ZipFile(apk) as archive:
            native = {Path(name).name: hashlib.sha256(archive.read(name)).hexdigest()
                      for name in archive.namelist()
                      if name.startswith('lib/arm64-v8a/') and name.endswith('.so')}
        installed = save('installed-native.txt', adb('shell', 'sha256sum',
            *(code + '/lib/arm64/' + name for name in sorted(native))))
        assert {Path(line.split()[1]).name: line.split()[0]
                for line in installed.splitlines()} == native
        result['native_sha256'] = native

        cases = [
            ('root-malformed', 'root', '1,', None, 'invalid_worker_cpu_ids',
             'requires ordered decimal'),
            ('root-main-conflict', 'root', '0', None, 'invalid_worker_cpu_ids',
             'conflicts with main-core'),
            ('root-absent', 'root', '1,9', None, 'invalid_worker_cpu_ids',
             'CPU 9 absent or offline'),
            ('vpn-missing-io', 'vpn', '1,2,1', '', 'invalid_tun_io_cpu_id',
             'requires one decimal'),
            ('vpn-owner-conflict', 'vpn', '1,2,1', '1', 'invalid_tun_io_cpu_id',
             'conflicts with a FlowOwner'),
            ('vpn-main-conflict', 'vpn', '1', '0', 'invalid_tun_io_cpu_id',
             'conflicts with main-core'),
            ('vpn-absent-io', 'vpn', '1,2,1', '9', 'invalid_tun_io_cpu_id',
             'CPU 9 absent or offline'),
            ('vpn-limit', 'vpn', ','.join(['1'] * 62), '3',
             'invalid_worker_cpu_ids', 'pinned VPP worker slot'),
        ]
        for name, profile, owners, io, expected_code, expected_message in cases:
            before = props(app(STATE))
            extras = ['--ez', 'runtimeStart', 'true', '--es', 'runtimeProfile', profile,
                      '--es', 'runtimeWorkerCpuIds', owners]
            if io is not None:
                extras += ['--es', 'runtimeTunIoCpuId', io]
            if io == '':
                # ADB's argv transport drops an empty final value. Preserve the
                # shell quotes so Android's Intent parser receives an empty string.
                save(name + '-request.txt', adb('shell', 'am start -n '
                    + PKG + '/.DebugControlActivity '
                    + shlex.join(extras)))
            else:
                save(name + '-request.txt', action(*extras))
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                current = save(name + '-poll.properties', app(STATE))
                state = props(current)
                if state.get('errorCode') == expected_code and \
                        expected_message in state.get('errorMessage', '') and \
                        state.get('mayBeActive') == 'false':
                    break
                time.sleep(.2)
            else:
                raise RuntimeError(f'{name}: rejected state missing: {state}')
            save(name + '-state.properties', current)
            processes = save(name + '-processes.txt',
                adb('shell', 'ps', '-A', '-o', 'PID,UID,ARGS'))
            assert not [line for line in processes.splitlines()
                        if len(parts := line.split(None, 3)) >= 3
                        and Path(parts[2]).name == 'libvpp_runtime.so'], processes
            hooks = save(name + '-hooks.txt',
                root('iptables-save -t mangle; ip6tables-save -t mangle'))
            assert 'SAKAMOTO_PRODUCT_S176_OUTPUT' not in hooks
            queues = save(name + '-queues.txt',
                root('cat /proc/net/netfilter/nfnetlink_queue'))
            assert not queues.strip(), queues
            save(name + '-service.log', app('files/logs/runtime-service.log'))
            if name == 'root-absent':
                archived = save(name + '-native.log', app(
                    'files/product-state/root-last-failure.log'))
                assert expected_message in archived, archived
            result['cases'].append(dict(name=name, profile=profile, owners=owners, io=io,
                                        code=expected_code, generation=state['generation'],
                                        prior_generation=before.get('generation')))
        result['status'] = 'RAW_COMPLETE'
    except Exception as error:
        result['error'] = repr(error)
        save('failure-state.properties', app(STATE))
        raise
    finally:
        result['completed_ns'] = time.time_ns()
        save('result.json', json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
