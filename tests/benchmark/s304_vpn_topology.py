#!/usr/bin/env python3
"""Frozen Pixel Product A/B/B/A plus N=1/N=3 VPN topology campaign.

Start the prepared socket-load-host server first. Every arm uses the same
ordinary Product TCP download suite and leaves its raw collector directory.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import time
import zipfile

import pixel_quick as quick

ROOT = Path(__file__).resolve().parents[2]
SCHEDULE = (
    ('A1-local-n2', 'old', [1, 2], None, 32000),
    ('B1-io-n2', 'new', [1, 2], 3, 32100),
    ('B2-io-n2', 'new', [1, 2], 3, 32200),
    ('A2-local-n2', 'old', [1, 2], None, 32300),
    ('C1-io-n1', 'new', [1], 3, 32400),
    ('C3-io-n3', 'new', [1, 2, 1], 3, 32500),
)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def install(device, candidate, folder, expected_uid):
    candidate = candidate.resolve()
    folder.mkdir(exist_ok=False)
    apk_hash = quick.digest(candidate)
    state = device.state()
    save(folder / 'before.json', state)
    if state.get('state') != 'stopped' or state.get('mayBeActive') != 'false':
        raise RuntimeError('APK install requires a stopped Product runtime')
    (folder / 'install.txt').write_text(device.command('install', '-r', '-d', candidate, timeout=60))
    uid = device.command('shell', 'run-as', quick.PACKAGE, 'id', '-u').strip()
    if uid != str(expected_uid):
        raise RuntimeError('APK replacement changed app UID')
    installed = device.command('shell', 'pm', 'path', quick.PACKAGE).strip().removeprefix('package:')
    if device.root('sha256sum ' + shlex.quote(installed)).split()[0] != apk_hash:
        raise RuntimeError('installed APK bytes differ from local artifact')
    with zipfile.ZipFile(candidate) as archive:
        expected = {Path(name).name: hashlib.sha256(archive.read(name)).hexdigest()
                    for name in archive.namelist() if name.startswith('lib/arm64-v8a/') and name.endswith('.so')}
    native = str(Path(installed).parent / 'lib/arm64')
    raw = device.command('shell', 'sha256sum', *[native + '/' + name for name in sorted(expected)])
    (folder / 'native-sha256.txt').write_text(raw)
    actual = {Path(line.split()[1]).name: line.split()[0] for line in raw.splitlines()}
    if actual != expected:
        raise RuntimeError('installed native payload differs from APK ZIP members')
    save(folder / 'identity.json', dict(apk=str(candidate), apk_sha256=apk_hash,
                                        installed_apk=installed, uid=int(uid), native_sha256=actual))
    return installed, apk_hash


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', type=Path, required=True)
    parser.add_argument('--old-apk', type=Path, required=True)
    parser.add_argument('--new-apk', type=Path, required=True)
    parser.add_argument('--restore-apk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    prepared = json.loads(args.prepared.read_text())
    suite = prepared.get('suite')
    if (suite not in quick.VPN_SINGLE_SUITES
            or prepared.get('cell_ms') != (20000 if suite == quick.VPN_TCP_SUITE else 5000)
            or prepared.get('profiling') is not False or prepared.get('threads') != 4
            or prepared.get('flows_per_thread') != 16):
        raise RuntimeError('S304 requires frozen 20s TCP or 5s UDP, 4×16, no profiling')
    if prepared.get('collector_sha256') != quick.digest(quick.__file__):
        raise RuntimeError('collector differs from prepared artifact')
    device = quick.Device(prepared['serial'], out, control_timeout=15)
    initial = device.state()
    save(out / 'initial-runtime.json', initial)
    if initial.get('state') != 'stopped' or initial.get('mayBeActive') != 'false':
        raise RuntimeError('campaign requires a stopped runtime')
    wifi = device.command('shell', 'cmd', 'wifi', 'status')
    (out / 'initial-wifi.txt').write_text(wifi)
    if 'Wifi is connected to "Openwrt_5G"' not in wifi:
        raise RuntimeError('Pixel is not on the controlled LAN')
    quick.peer_query(prepared['peer_host'], prepared['peer_port'], 0)
    report = dict(schema='s304-vpn-topology/v1', status='INCOMPLETE',
                  started_utc_ns=time.time_ns(), prepared=str(args.prepared),
                  suite=suite,
                  schedule=[dict(label=l, artifact=a, owner_cpus=cpus, tun_io_cpu=io,
                                 source_port=p if suite == quick.VPN_TCP_SUITE else None)
                            for l, a, cpus, io, p in SCHEDULE], runs=[], errors=[])
    save(out / 'campaign.json', report)
    installed_kind = None
    try:
        for label, kind, cpus, io, source_port in SCHEDULE:
            apk = args.old_apk if kind == 'old' else args.new_apk
            if installed_kind != kind:
                installed, apk_hash = install(device, apk, out / ('install-' + label), prepared['uid'])
                installed_kind = kind
            else:
                installed = device.command('shell', 'pm', 'path', quick.PACKAGE).strip().removeprefix('package:')
                apk_hash = quick.digest(apk)
                if device.root('sha256sum ' + shlex.quote(installed)).split()[0] != apk_hash:
                    raise RuntimeError('installed APK changed between same-artifact arms')
            manifest = dict(prepared, apk=installed, apk_sha256=apk_hash,
                            worker_cpu_ids=cpus,
                            client_cpu_mask='10', system_cpu_accounting=True,
                            minimum_native_buffers=2048, expected_native_buffer_count=2048,
                            expected_native_buffer_data_bytes=10240,
                            campaign_label=label, prepared_utc_ns=time.time_ns())
            if suite == quick.VPN_TCP_SUITE:
                manifest['tcp_fixed_source_port_base'] = source_port
            if io is not None:
                manifest['tun_io_cpu_id'] = io
            path = out / ('manifest-' + label + '.json')
            save(path, manifest)
            run = out / ('run-' + label)
            with (out / ('run-' + label + '.log')).open('w') as log:
                code = subprocess.run([sys.executable, str(ROOT / 'tests/benchmark/pixel_quick.py'),
                                       'run', '--manifest', str(path), '--output', str(run)],
                                      stdout=log, stderr=subprocess.STDOUT).returncode
            result = json.loads((run / 'result.json').read_text())
            report['runs'].append(dict(label=label, returncode=code, status=result['status'],
                                       result=str(run / 'result.json')))
            save(out / 'campaign.json', report)
            print(label, result['status'], result.get('errors'), flush=True)
            if code or result['status'] != 'COMPLETE':
                report['errors'].append(label + ': collector incomplete; raw attempt retained')
                break
        if not report['errors'] and len(report['runs']) == len(SCHEDULE):
            report['status'] = 'COMPLETE'
    except Exception as error:
        report['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        try:
            installed, apk_hash = install(device, args.restore_apk, out / 'install-restore', prepared['uid'])
            report['restored_apk_sha256'] = apk_hash
            report['restored_installed_path'] = installed
            report['final_runtime'] = device.state()
            report['final_wifi'] = device.command('shell', 'cmd', 'wifi', 'status')
            report['final_vpp_pid'] = device.command('shell', 'pidof', 'libvpp_runtime.so', check=False).strip()
            if report['final_runtime'].get('state') != 'stopped' or report['final_vpp_pid']:
                report['errors'].append('final Product runtime is not stopped')
        except Exception as error:
            report['errors'].append('restoration: ' + type(error).__name__ + ': ' + str(error))
        report['completed_utc_ns'] = time.time_ns()
        save(out / 'campaign.json', report)
    print(json.dumps(dict(status=report['status'], errors=report['errors'], output=str(out)), indent=2))
    return 0 if report['status'] == 'COMPLETE' and not report['errors'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
