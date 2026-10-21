#!/usr/bin/env python3
"""Independently verify Pixel S303 startup rejection and pre-capture cleanup."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def props(path):
    return dict(line.split('=', 1) for line in path.read_text().splitlines()
                if '=' in line and not line.startswith('#'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    parser.add_argument('--apk', type=Path, required=True)
    args = parser.parse_args()
    run = args.run.resolve()
    result = json.loads((run / 'result.json').read_text())
    assert result['status'] == 'RAW_COMPLETE'
    assert result['runner_sha256'] == hashlib.sha256(
        (ROOT / 'tests/device/s303-pixel-invalid-config.py').read_bytes()).hexdigest()
    assert result['apk_sha256'] == hashlib.sha256(args.apk.read_bytes()).hexdigest()
    assert (run / 'installed-apk.txt').read_text().split()[0] == result['apk_sha256']
    with zipfile.ZipFile(args.apk) as archive:
        native = {Path(name).name: hashlib.sha256(archive.read(name)).hexdigest()
                  for name in archive.namelist()
                  if name.startswith('lib/arm64-v8a/') and name.endswith('.so')}
    installed = {Path(line.split()[1]).name: line.split()[0]
                 for line in (run / 'installed-native.txt').read_text().splitlines()}
    assert native == installed == result['native_sha256']
    expected = {
        'root-malformed': ('invalid_worker_cpu_ids', 'requires ordered decimal'),
        'root-main-conflict': ('invalid_worker_cpu_ids', 'conflicts with main-core'),
        'root-absent': ('invalid_worker_cpu_ids', 'CPU 9 absent or offline'),
        'vpn-missing-io': ('invalid_tun_io_cpu_id', 'requires one decimal'),
        'vpn-owner-conflict': ('invalid_tun_io_cpu_id', 'conflicts with a FlowOwner'),
        'vpn-main-conflict': ('invalid_tun_io_cpu_id', 'conflicts with main-core'),
        'vpn-absent-io': ('invalid_tun_io_cpu_id', 'CPU 9 absent or offline'),
        'vpn-limit': ('invalid_worker_cpu_ids', 'pinned VPP worker slot'),
    }
    assert {case['name'] for case in result['cases']} == set(expected)
    assert '0-7' in (run / 'cpu-online.txt').read_text()
    for case in result['cases']:
        name = case['name']
        state = props(run / (name + '-state.properties'))
        code, detail = expected[name]
        assert case['code'] == state['errorCode'] == code
        assert detail in state['errorMessage']
        assert state['mayBeActive'] == 'false'
        assert state['protectionRunning'] == 'false'
        assert state['adapter'] == 'unavailable'
        assert not (run / (name + '-queues.txt')).read_text().strip()
        assert 'SAKAMOTO_PRODUCT_S176_OUTPUT' not in \
            (run / (name + '-hooks.txt')).read_text()
        processes = (run / (name + '-processes.txt')).read_text()
        assert not [line for line in processes.splitlines()
                    if len(parts := line.split(None, 3)) >= 3
                    and Path(parts[2]).name == 'libvpp_runtime.so']
    native = (run / 'root-absent-native.log').read_text()
    assert 'cpu_config: ordered-workers: CPU 9 absent or offline' in native
    print('S303 Pixel 8 invalid Root/VPN placement cases, specific errors, '
          'capture not started and zero process/hook/queue residue: PASS')


if __name__ == '__main__':
    main()
