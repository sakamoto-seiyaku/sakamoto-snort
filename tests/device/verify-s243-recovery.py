#!/usr/bin/env python3
"""Independent supervisor-only evidence check. Not S243 packet acceptance."""
import argparse
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s243_build', ROOT / 'tests/device/verify-s237.py')
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)


def verify(build_path, directory):
    build = common.verify_build(build_path)
    run = json.loads((directory / 'result.json').read_text())
    assert run['scope'] == 'real-Pixel-supervisor-only'
    assert not any(run.get(k) for k in ('error', 'cleanup_error', 'product_source_changed', 'test_source_changed'))
    assert run['build_sha256'] == common.digest(build_path) and run['apk_sha256'] == build['apk_sha256']
    assert build['completed_ns'] < run['started_ns'] < run['completed_ns']
    assert run['serial'] == '28201JEGR0XPAJ' and 'aarch64' in (directory / 'device.txt').read_text()
    assert (directory / 'installed-apk.txt').read_text().split()[0] == build['apk_sha256']
    installed = {Path(line.split()[1]).name: line.split()[0]
                 for line in (directory / 'installed-native.txt').read_text().splitlines()}
    assert installed == build['native_sha256']
    assert run['test_inputs']
    for name, digest in run['test_inputs'].items():
        assert common.digest(directory / 'test-source' / name) == digest
    assert not (directory / 'crash.log').read_text().strip(), 'supervisor or unrelated crash requires investigation'
    events = {e['label']: e for e in run['events']}
    assert len(events) == len(run['events'])

    def state(label):
        value = common.props((directory / (label + '.properties')).read_text())
        assert value == events[label]['state']
        assert value['protectionRunning'] == 'false' and value['adapterReadiness'] == 'unavailable'
        return value

    initial, restarted, reset = [state(n) for n in ('initial', 'automatic-restart', 'explicit-retry')]
    generations = [int(s['generation']) for s in (initial, restarted, reset)]
    assert generations[1] == generations[0] + 1 and generations[2] == generations[1] + 1
    for value in (initial, restarted, reset):
        assert value['state'] == 'running' and value['mayBeActive'] == 'true' and not value['errorCode']
    for name in ('initial-ready.txt', 'restarted-ready.txt', 'explicit-retry-ready.txt'):
        text = (directory / name).read_text()
        assert all(f'enabled=1 owner={i} ready=1' in text for i in (0, 1))
    exhausted = state('exhausted')
    assert exhausted['mayBeActive'] == 'false' and exhausted['generation'] == restarted['generation']
    assert exhausted['errorCode'] == 'runtime_recovery_intervention_required'
    assert 'protection stopped' in exhausted['errorMessage']
    pending = state('pending-before-stop')
    assert pending['generation'] == reset['generation'] and pending['mayBeActive'] == 'false'
    assert pending['errorCode'] == 'runtime_auto_recovery_pending'
    for label, generation in [('clear-terminal-error', restarted['generation']),
                              ('cancel-recovery', reset['generation'])]:
        value = state(label)
        assert value['state'] == 'stopped' and value['mayBeActive'] == 'false'
        assert value['generation'] == generation and not value['errorCode']
    for label, generation in [('exhausted', restarted['generation']), ('cancel-recovery', reset['generation'])]:
        samples = json.loads((directory / (label + '-stable.json')).read_text())
        assert len(samples) >= 5 and samples[-1]['at_ns'] - samples[0]['at_ns'] >= 2_500_000_000
        assert all(s['state']['generation'] == generation and s['state']['mayBeActive'] == 'false' for s in samples)
        assert 'libvpp_runtime.so' not in (directory / (label + '-process-after.txt')).read_text()
        assert 'Active vpn type: -1' in (directory / (label + '-vpn.txt')).read_text()
    runtime_pids, native_pids = [], []
    package = 'com.sakamoto.snort.androidruntime'
    binary = re.search(r'codePath=(\S+)', (directory / 'package.txt').read_text()).group(1) + '/lib/arm64/libvpp_runtime.so'
    for label in ('first-crash', 'second-crash', 'cancelled-crash'):
        text = (directory / (label + '-process-before.txt')).read_text()
        runtime = [line.split() for line in text.splitlines() if line.strip().endswith(package + ':runtime')]
        assert len(runtime) == 1 and int(runtime[0][1]) == run['uid']
        runtime_pids.append(int(runtime[0][0]))
        native = [line.split() for line in text.splitlines() if 'libvpp_runtime.so -c ' in line]
        assert len(native) == 1 and int(native[0][1]) == run['uid']
        assert int(native[0][0]) == events[label]['pid']
        assert (directory / (label + '-executable.txt')).read_text().strip() == binary
        native_pids.append(int(native[0][0]))
    assert runtime_pids[0] == runtime_pids[1], 'Android supervisor died during native recovery'
    assert len(set(native_pids)) == 3 and runtime_pids[0] not in native_pids
    service = (directory / 'service.log').read_text()
    for generation in (generations[0], generations[2]):
        found = re.findall(r's243 recovery=scheduled generation=' + str(generation) + r' .*', service)
        assert len(found) == 1 and 'attempt=1 old_resources_closed=1' in found[0]
    assert len(re.findall(r's243 recovery=starting old_generation=' + str(generations[0]) + r'\b', service)) == 1
    for generation in generations[1:]:
        assert not re.search(r's243 recovery=starting old_generation=' + str(generation) + r'\b', service)
    for name, generation in [('first-failure.log', generations[0]), ('second-failure.log', generations[1])]:
        trace = (directory / name).read_text()
        assert set(re.findall(r'\bgeneration=(\d+)', trace)) == {str(generation)}
        assert not re.search(r's237 event=owner_stopped ', trace), 'crash is not native orderly drain'
        assert re.search(r'os_reclaim_after_exit .*generation=' + str(generation) + r' native_drain_claimed=0', service)
    if run.get('startup_failure'):
        startup = run['startup_failure']
        assert int(startup['generation']) == int(startup['previous_generation']) + 2
        failed = state('startup-failure-exhausted')
        assert failed['generation'] == startup['generation'] and failed['mayBeActive'] == 'false'
        assert failed['errorCode'] == 'runtime_recovery_intervention_required'
        assert 'runtime_start_failed' in failed['errorMessage']
        first_attempt = int(startup['previous_generation']) + 1
        assert len(re.findall(r's243 recovery=starting old_generation=' + str(first_attempt) + r'\b', service)) == 1
        assert not re.search(r's243 recovery=starting old_generation=' + startup['generation'] + r'\b', service)
        assert state('clear-startup-error')['errorCode'] == ''
    ordinary_count = 0
    if run.get('ordinary_connectivity'):
        assert common.digest(directory / 'ordinary-endpoint') == run['ordinary_helper']['sha256']
        for record in run['ordinary_connectivity']:
            assert (directory / record['label'] / 'lockdown.txt').read_text().strip() in ('0', 'null')
            peer = (directory / (record['label'] + '-endpoint.log')).read_text()
            assert {(p['protocol'], p['family']) for p in record['probes']} == {(p, f) for p in ('tcp', 'udp') for f in (4, 6)}
            for probe in record['probes']:
                value = common.props((directory / (probe['name'] + '.properties')).read_text())
                runtime = common.props((directory / (probe['name'] + '-runtime.properties')).read_text())
                assert value['nonce'] == probe['nonce'] and value['host'] == probe['address']
                assert value['result'] == probe['protocol'] + '_echo_matched' and int(value['uid']) == run['uid']
                assert value['bindToVpn'] == 'false' and value['bindResult'] == 'not_requested'
                size = len(probe['nonce'].encode())
                assert int(value['requestBytes']) == int(value['responseBytes']) == size
                assert runtime['generation'] == record['generation'] and runtime['mayBeActive'] == 'false'
                expected = f"echo protocol={probe['protocol']} address={probe['address']} bytes={size} sent={size} nonce={probe['nonce']}\n"
                assert peer.count(expected) == 1
                ordinary_count += 1
    return dict(status='PASS', scope='supervisor-only', generations=generations,
                automatic_restarts=1, cancelled_restarts=1, android_supervisor_pid=runtime_pids[0],
                startup_preparation_failure_checked=bool(run.get('startup_failure')),
                ordinary_app_echoes=ordinary_count)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--run', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.build, args.run), indent=2))
