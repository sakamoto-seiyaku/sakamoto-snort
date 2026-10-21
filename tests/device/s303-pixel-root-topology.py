#!/usr/bin/env python3
"""S303: Root Product N=1/N=3 Pixel topology and real NFQUEUE UDP echo."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SERIAL = '28201JEGR0XPAJ'
PKG = 'com.sakamoto.snort.androidruntime'
STATE = 'files/runtime-state/snapshot.properties'
BASE = f'/data/user/0/{PKG}/files/profiles/root/vpp/'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def props(value):
    return dict(line.split('=', 1) for line in value.splitlines()
                if '=' in line and not line.startswith('#'))


def rows(value, prefix):
    return [dict(re.findall(r'(\w+)=([^\s]+)', line))
            for line in value.splitlines() if line.startswith(prefix)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--endpoint-address', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    apk = args.apk.resolve()
    result = dict(status='HOLD', task='SAKAMOTO-303', serial=SERIAL,
                  apk_sha256=digest(apk), runner_sha256=digest(__file__), runs=[])

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

    def action(*extras):
        return adb('shell', 'am', 'start', '-n', PKG + '/.DebugControlActivity', *extras)

    def root(command):
        return adb('shell', 'su', '-c', shlex.quote(command))

    def cli(name, *commands):
        command = "printf '%s\\n' " + ' '.join(shlex.quote(c) for c in
            ['set terminal pager off', *commands, 'quit']) + \
            ' | toybox nc -U -w 2 -q 1 ' + BASE + 'runtime/cli.sock'
        return save(name + '.txt', root(command))

    def wait(name, desired, timeout=45):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = save(name + '.poll', app(STATE))
            state = props(value)
            if all(state.get(key) == expected for key, expected in desired.items()):
                save(name + '.properties', value)
                return state
            if state.get('errorCode') == 'root_authorization_required':
                raise RuntimeError('KernelSU grant must be restored')
            time.sleep(.25)
        raise RuntimeError(f'{name} state timeout: {state}')

    def settle(name):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            response = cli(name + '-settle', 'show product completion')
            line = rows(response, 'completion.status ')
            if line and all(line[0].get(k) == '0' for k in
                            ('pending', 'frames', 'buffers', 'obligations')):
                return line[0]
            time.sleep(.2)
        raise RuntimeError(f'{name} did not settle: {response}')

    def ui_tap(name, label):
        remote = '/sdcard/s303-' + name + '.xml'
        adb('shell', 'input', 'keyevent', '224')
        adb('shell', 'wm', 'dismiss-keyguard')
        adb('shell', 'uiautomator', 'dump', remote)
        adb('pull', remote, args.output / (name + '.xml'))
        tree = ET.parse(args.output / (name + '.xml'))
        matches = [node for node in tree.iter('node')
                   if node.get('text') == label and node.get('enabled') == 'true']
        assert len(matches) == 1, (name, label, matches)
        bounds = list(map(int, re.findall(r'\d+', matches[0].get('bounds'))))
        adb('shell', 'input', 'tap', (bounds[0] + bounds[2]) // 2,
            (bounds[1] + bounds[3]) // 2)

    def wait_config(name, revision):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            value = save(name + '.poll', app('files/product-state/rule-config.properties'))
            config = props(value)
            if int(config.get('savedRevision', 0)) > revision:
                save(name + '.properties', value)
                assert config['savedRevision'] == config['activeRevision']
                assert config['result'] == '0', config
                return config
            time.sleep(.15)
        raise RuntimeError(f'{name} configuration did not publish: {config}')

    with zipfile.ZipFile(apk) as archive:
        native = {Path(name).name: hashlib.sha256(archive.read(name)).hexdigest()
                  for name in archive.namelist()
                  if name.startswith('lib/arm64-v8a/') and name.endswith('.so')}
    result['apk_native_sha256'] = native
    server = None
    active = False
    log = None
    device_echo_pid = None
    try:
        save('before-state.properties', app(STATE))
        assert props(app(STATE)).get('mayBeActive') == 'false'
        save('before-wifi.txt', adb('shell', 'cmd', 'wifi', 'status'))
        save('before-route.txt', adb('shell', 'ip', '-4', 'route'))
        assert args.endpoint_address in adb('shell', 'ping', '-c', '1', '-W', '2', args.endpoint_address)
        save('install.txt', adb('install', '-r', apk))
        package = save('package.txt', adb('shell', 'dumpsys', 'package', PKG))
        code = re.search(r'codePath=(\S+)', package).group(1)
        assert save('installed-apk.txt', adb('shell', 'sha256sum', code + '/base.apk')).split()[0] == result['apk_sha256']
        installed = save('installed-native.txt', adb('shell', 'sha256sum',
            *(code + '/lib/arm64/' + name for name in sorted(native))))
        assert {Path(line.split()[1]).name: line.split()[0]
                for line in installed.splitlines()} == native
        result['uid'] = int(adb('shell', 'run-as', PKG, 'id', '-u'))
        helper = args.output / 'udp-endpoint'
        source = ROOT / 'tests/device/helpers/s206-udp-echo.c'
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-O2', str(source),
                        '-o', str(helper)], check=True)
        result['helper_source_sha256'] = digest(source)
        result['helper_sha256'] = digest(helper)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind((args.endpoint_address, 0))
            port = probe.getsockname()[1]
        result['endpoint'] = args.endpoint_address
        result['endpoint_port'] = port
        log = (args.output / 'endpoint.log').open('w')
        server = subprocess.Popen([str(helper.resolve()), str(port), args.endpoint_address],
            stdout=log, stderr=subprocess.STDOUT)
        time.sleep(.1)
        assert server.poll() is None
        compiler = Path('/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang')
        device_source = ROOT / 'tests/device/helpers/s207-echo.c'
        device_helper = args.output / 'device-echo'
        subprocess.run([str(compiler), '-O2', '-Wall', '-Wextra', '-Werror',
                        str(device_source), '-o', str(device_helper)], check=True)
        result['device_helper_source_sha256'] = digest(device_source)
        result['device_helper_sha256'] = digest(device_helper)
        save('device-echo-push.txt', adb('push', device_helper,
             '/data/local/tmp/s303-root-echo'))
        adb('shell', 'chmod', '755', '/data/local/tmp/s303-root-echo')
        device_echo_pid = root('nohup /data/local/tmp/s303-root-echo 40608 127.0.0.2 '
            '> /data/local/tmp/s303-root-echo.log 2>&1 </dev/null & echo $!').strip()
        assert device_echo_pid.isdigit(), device_echo_pid

        for number, cpus in enumerate(([1], [1, 2, 1])):
            label = f'run{number}'
            route = save(label + '-network.txt',
                adb('shell', 'ip', '-4', 'route', 'get', args.endpoint_address,
                    'uid', str(result['uid'])))
            assert re.search(r'\bsrc 192\.168\.4\.\d+\b', route), route
            active = True
            save(label + '-start.txt', action('--ez', 'runtimeStart', 'true',
                '--es', 'runtimeProfile', 'root', '--es', 'runtimeWorkerCpuIds',
                ','.join(map(str, cpus))))
            state = wait(label + '-running', {'state': 'running', 'profile': 'root',
                'protectionRunning': 'true', 'errorCode': ''})
            generation = state['generation']
            status = save(label + '-worker-status.properties',
                app('files/product-state/s187-worker-core-guardrails.properties'))
            assert props(status)['vpp_owner_cores'] == ','.join(map(str, cpus))
            assert props(status)['worker_core_config_match'] == 'true'
            topology = cli(label + '-topology', 'show product topology',
                'show product root lanes', 'show threads', 'product packet-trace limit 4096')
            assert f'topology.profile=root owner_count={len(cpus)} ' in topology, topology
            threads = dict((match.group(1), int(match.group(2)))
                for line in topology.splitlines()
                if (match := re.search(r'^\d+\s+vpp_(main|wk_\d+)\s+(?:workers\s+)?(\d+)\s+', line)))
            assert set(threads) == {'main', *(f'wk_{i}' for i in range(len(cpus)))}
            for role, cpu in [('main', 0), *((f'wk_{i}', cpu) for i, cpu in enumerate(cpus))]:
                affinity = save(f'{label}-affinity-{role}.txt',
                    root(f'cat /proc/{threads["main"]}/task/{threads[role]}/status'))
                assert re.search(r'^Cpus_allowed_list:\s*' + str(cpu) + r'\s*$',
                                 affinity, re.MULTILINE), role
            covered = set()
            probes = []
            for attempt in range(32):
                source_port = 48000 + number * 100 + attempt
                nonce = f's303-{generation}-{attempt}-{time.time_ns()}'
                save(f'{label}-send-{attempt}.txt', action('--ez', 'debugUdpTraffic', 'true',
                    '--es', 'debugUdpHost', args.endpoint_address,
                    '--ei', 'debugUdpPort', str(port), '--ei', 'debugUdpSourcePort',
                    str(source_port), '--es', 'debugUdpNonce', nonce,
                    '--ez', 'debugUdpExpectReply', 'true',
                    '--ez', 'debugTrafficBindToVpn', 'false',
                    '--ei', 'debugUdpTimeoutMillis', '5000'))
                until = time.monotonic() + 8
                while time.monotonic() < until:
                    probe_state = props(app('files/debug/udp-traffic-probe.properties'))
                    if probe_state.get('nonce') == nonce:
                        break
                    time.sleep(.1)
                assert probe_state.get('result') == 'udp_echo_matched', probe_state
                settle(label)
                trace = save(label + '-trace.log',
                    root('cat ' + BASE + 'logs/vpp-stdout.log'))
                matched = [row for row in rows(trace, 's216 ')
                    if row.get('stage') == 'admit' and nonce.encode().hex() in row.get('raw', '')]
                directions = {row.get('direction') for row in matched}
                owners = {int(row['owner']) for row in matched}
                assert len(matched) >= 2 and directions >= {'3', '1'} and len(owners) == 1, matched
                owner = owners.pop()
                assert 0 <= owner < len(cpus)
                covered.add(owner)
                probes.append(dict(nonce=nonce, source_port=source_port, owner=owner,
                                   directions=sorted(directions), captured=len(matched)))
                if len(covered) == len(cpus):
                    break
            assert covered == set(range(len(cpus))), covered
            lifecycle_before = cli(label + '-owner-lifecycle-before',
                'show product flows', 'show product flow-end',
                'show product expiry', 'show product observation',
                'show product primary')
            entries = rows(lifecycle_before, 'flow.entry ')
            end_before = rows(lifecycle_before, 'flow-end.owner=')
            expiry_before = rows(lifecycle_before, 'expiry.owner=')
            owner_status = rows(lifecycle_before, 'primary.owner=')
            channels = rows(lifecycle_before, 'observation.channel=')
            assert {int(row['owner']) for row in end_before} == set(range(len(cpus)))
            assert {int(row['owner']) for row in expiry_before} == set(range(len(cpus)))
            assert {int(row['owner']) for row in owner_status} == set(range(len(cpus)))
            assert {int(row['channel']) for row in channels} == set(range(2 * len(cpus)))
            closed_flows = []
            for owner in range(len(cpus)):
                candidate = next(probe for probe in probes if probe['owner'] == owner)
                selected = [row for row in entries if row['worker'] == str(owner)
                            and {row['port_a'], row['port_b']} ==
                            {str(candidate['source_port']), str(port)}]
                assert len(selected) == 1, selected
                entry = selected[0]
                queued = cli(f'{label}-flowend-close-{owner}',
                    f'product flow-end close owner {owner} slot {entry["slot"]} '
                    f'generation {generation} incarnation {entry["incarnation"]}')
                assert f'flow-end.close=queued owner={owner}' in queued, queued
                closed_flows.append(dict(owner=owner, slot=entry['slot'],
                                         incarnation=entry['incarnation'],
                                         source_port=candidate['source_port']))
            until = time.monotonic() + 8
            while time.monotonic() < until:
                lifecycle_after = cli(label + '-owner-lifecycle-after',
                    'show product flows', 'show product flow-end',
                    'show product expiry', 'show product observation',
                    'show product primary')
                remaining = rows(lifecycle_after, 'flow.entry ')
                after_end = rows(lifecycle_after, 'flow-end.owner=')
                if all(not any(row['worker'] == str(flow['owner'])
                                   and row['slot'] == flow['slot']
                                   and row['incarnation'] == flow['incarnation']
                                   for row in remaining) for flow in closed_flows) and \
                        all(int(next(row for row in after_end
                                     if row['owner'] == str(owner))['released']) >
                            int(next(row for row in end_before
                                     if row['owner'] == str(owner))['released'])
                            for owner in range(len(cpus))):
                    break
                time.sleep(.2)
            else:
                raise RuntimeError(label + ': owner FlowEnd did not settle')
            policy_state = props(save(label + '-policy-before.properties',
                app('files/product-state/rule-config.properties')))
            ui_tap(label + '-policy-clear', 'Clear')
            cleared = wait_config(label + '-policy-clear',
                                  int(policy_state.get('savedRevision', 0)))
            ui_tap(label + '-policy-drop', 'Drop UDP')
            dropped = wait_config(label + '-policy-drop', int(cleared['savedRevision']))
            assert dropped['action'] == '2' and int(dropped['uid']) == result['uid']
            drop_nonce = f's303-drop-{generation}-{time.time_ns()}'
            save(label + '-drop-send.txt', action('--ez', 'debugUdpTraffic', 'true',
                '--es', 'debugUdpHost', '127.0.0.2',
                '--ei', 'debugUdpPort', '40608', '--ei', 'debugUdpSourcePort',
                '32000', '--es', 'debugUdpNonce', drop_nonce,
                '--ez', 'debugUdpExpectReply', 'true',
                '--ez', 'debugTrafficBindToVpn', 'false',
                '--ei', 'debugUdpTimeoutMillis', '2000'))
            until = time.monotonic() + 5
            while time.monotonic() < until:
                drop_state = props(app('files/debug/udp-traffic-probe.properties'))
                if drop_state.get('nonce') == drop_nonce:
                    break
                time.sleep(.1)
            assert drop_state.get('result') == 'udp_datagram_failed', drop_state
            settle(label + '-drop')
            trace = save(label + '-drop-trace.log', root('cat ' + BASE + 'logs/vpp-stdout.log'))
            drop_admit = [row for row in rows(trace, 's216 ')
                if row.get('stage') == 'admit' and drop_nonce.encode().hex() in row.get('raw', '')]
            assert len(drop_admit) == 1, drop_admit
            drop_token = drop_admit[0]['token']
            drop_policy = [row for row in rows(trace, 's216 ')
                if row.get('stage') == 'policy' and row.get('token') == drop_token]
            assert len(drop_policy) == 1 and drop_policy[0]['intent'] == '2', drop_policy
            endpoint_before = save(label + '-policy-endpoint-before.txt',
                root('cat /data/local/tmp/s303-root-echo.log'))
            assert drop_nonce not in endpoint_before
            ui_tap(label + '-policy-allow', 'Allow UDP')
            allowed = wait_config(label + '-policy-allow', int(dropped['savedRevision']))
            assert allowed['action'] == '1' and int(allowed['uid']) == result['uid']
            recovery_nonce = f's303-recover-{generation}-{time.time_ns()}'
            save(label + '-recovery-send.txt', action('--ez', 'debugUdpTraffic', 'true',
                '--es', 'debugUdpHost', '127.0.0.2',
                '--ei', 'debugUdpPort', '40608', '--ei', 'debugUdpSourcePort',
                '32000', '--es', 'debugUdpNonce', recovery_nonce,
                '--ez', 'debugUdpExpectReply', 'true',
                '--ez', 'debugTrafficBindToVpn', 'false',
                '--ei', 'debugUdpTimeoutMillis', '5000'))
            until = time.monotonic() + 8
            while time.monotonic() < until:
                recovery_state = props(app('files/debug/udp-traffic-probe.properties'))
                if recovery_state.get('nonce') == recovery_nonce:
                    break
                time.sleep(.1)
            assert recovery_state.get('result') == 'udp_echo_matched', recovery_state
            settle(label + '-recovery')
            endpoint_after = save(label + '-policy-endpoint-after.txt',
                root('cat /data/local/tmp/s303-root-echo.log'))
            assert recovery_nonce in endpoint_after
            fault_case = None
            if len(cpus) > 1:
                primary_before = cli(label + '-capacity-before', 'show product primary')
                rejected_before = int(rows(primary_before, 'primary.status ')[0]['rejected'])
                capacity = cli(label + '-capacity-arm',
                    'product capacity credits 0 primary-slots 64 completion-slots 128')
                assert 'capacity.configured' in capacity, capacity
                try:
                    for attempt in range(24):
                        fault_port = 49200 + attempt
                        fault_nonce = f's303-capacity-{generation}-{attempt}-{time.time_ns()}'
                        save(f'{label}-capacity-send-{attempt}.txt', action('--ez',
                            'debugUdpTraffic', 'true', '--es', 'debugUdpHost',
                            '127.0.0.2', '--ei', 'debugUdpPort', '40608',
                            '--ei', 'debugUdpSourcePort', str(fault_port),
                            '--es', 'debugUdpNonce', fault_nonce,
                            '--ez', 'debugUdpExpectReply', 'true',
                            '--ez', 'debugTrafficBindToVpn', 'false',
                            '--ei', 'debugUdpTimeoutMillis', '5000'))
                        until = time.monotonic() + 8
                        while time.monotonic() < until:
                            fault_state = props(app('files/debug/udp-traffic-probe.properties'))
                            if fault_state.get('nonce') == fault_nonce:
                                break
                            time.sleep(.1)
                        assert fault_state.get('result') == 'udp_echo_matched', fault_state
                        settle(label + '-capacity')
                        fault_status = cli(label + '-capacity-status', 'show product primary')
                        if int(rows(fault_status, 'primary.status ')[0]['rejected']) > rejected_before:
                            fault_case = dict(nonce=fault_nonce, source_port=fault_port,
                                              rejected_before=rejected_before)
                            break
                    assert fault_case is not None, fault_status
                    save(label + '-capacity-trace.log',
                        root('cat ' + BASE + 'logs/vpp-stdout.log'))
                finally:
                    restored = cli(label + '-capacity-off', 'product capacity off')
                    assert 'capacity.configured' in restored, restored
                save(label + '-capacity-recovery-send.txt', action('--ez',
                    'debugUdpTraffic', 'true', '--es', 'debugUdpHost', '127.0.0.2',
                    '--ei', 'debugUdpPort', '40608', '--ei', 'debugUdpSourcePort',
                    str(fault_case['source_port']), '--es', 'debugUdpNonce',
                    f'{fault_case["nonce"]}-recovery', '--ez', 'debugUdpExpectReply',
                    'true', '--ez', 'debugTrafficBindToVpn', 'false',
                    '--ei', 'debugUdpTimeoutMillis', '5000'))
                until = time.monotonic() + 8
                while time.monotonic() < until:
                    recovered_state = props(app('files/debug/udp-traffic-probe.properties'))
                    if recovered_state.get('nonce') == fault_case['nonce'] + '-recovery':
                        break
                    time.sleep(.1)
                assert recovered_state.get('result') == 'udp_echo_matched', recovered_state
                settle(label + '-capacity-recovered')
                save(label + '-capacity-recovery-trace.log',
                    root('cat ' + BASE + 'logs/vpp-stdout.log'))
            before = cli(label + '-before-stop', 'show product primary',
                'show product completion', 'show product flows', 'show product root lanes')
            assert 'owner_failures=0' in before
            save(label + '-hooks.txt', root('iptables-save -t mangle; ip6tables-save -t mangle'))
            save(label + '-stop.txt', action('--ez', 'runtimeStop', 'true'))
            wait(label + '-stopped', {'state': 'stopped', 'mayBeActive': 'false',
                                    'errorCode': ''})
            active = False
            cleanup = save(label + '-cleanup.properties',
                app('files/product-state/s176-root-nfqueue-cleanup.properties'))
            assert 'productRootNfqueueResidueClean=true' in cleanup
            after = save(label + '-processes-after.txt',
                adb('shell', 'ps', '-A', '-o', 'PID,UID,ARGS'))
            assert 'libvpp_runtime.so' not in after
            save(label + '-hooks-after.txt', root('iptables-save -t mangle; ip6tables-save -t mangle'))
            queues = save(label + '-queues-after.txt', root('cat /proc/net/netfilter/nfnetlink_queue'))
            assert not queues.strip(), queues
            result['runs'].append(dict(generation=generation, cpus=cpus, probes=probes,
                                       closed_flows=closed_flows,
                                       policy_drop_nonce=drop_nonce,
                                       policy_recovery_nonce=recovery_nonce,
                                       capacity_fault=fault_case,
                                       covered=sorted(covered)))
        result['status'] = 'RAW_COMPLETE'
    except Exception as error:
        result['error'] = repr(error)
        save('failure-state.properties', app(STATE))
        save('failure-vpp.log', app('files/profiles/root/vpp/logs/vpp-stdout.log'))
        raise
    finally:
        if active:
            try:
                save('cleanup-stop.txt', action('--ez', 'runtimeStop', 'true'))
                wait('cleanup-stopped', {'state': 'stopped', 'mayBeActive': 'false'})
            except Exception as error:
                result['cleanup_error'] = repr(error)
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server.kill(); server.wait()
        if log is not None:
            log.close()
        if device_echo_pid and device_echo_pid.isdigit():
            save('device-echo-stop.txt', root('kill ' + device_echo_pid +
                '; rm -f /data/local/tmp/s303-root-echo /data/local/tmp/s303-root-echo.log'))
        result['completed_ns'] = time.time_ns()
        save('result.json', json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
