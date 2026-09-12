#!/usr/bin/env python3
"""Current Product TCP4/6 Direct on Pixel: real app sockets, TUN and LAN peers.

The independent verifier, not this runner's status string, decides acceptance.
"""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
PKG = 'com.sakamoto.snort.androidruntime'
SERIAL = '28201JEGR0XPAJ'
STATE = 'files/runtime-state/snapshot.properties'
BASE = '/data/user/0/' + PKG + '/files/profiles/vpn/vpp/'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ipv4', required=True)
    parser.add_argument('--ipv6', required=True)
    parser.add_argument('--case', choices=['smoke', 'matrix'], default='matrix')
    args = parser.parse_args()
    addresses = {4: str(ipaddress.IPv4Address(args.ipv4)), 6: str(ipaddress.IPv6Address(args.ipv6))}
    for address in addresses.values():
        value = ipaddress.ip_address(address)
        assert not (value.is_unspecified or value.is_loopback or value.is_link_local or value.is_multicast)
    chain = module('chain240', 'tests/evidence/product_chain.py')
    oracle = module('owner240', 'tests/device/s207-owner-oracle.py')
    build = json.loads(args.build.read_text())
    assert chain.source_files() == build['files'], 'Product source differs from APK'
    assert chain.digest(build['apk']) == build['apk_sha256']
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    result = dict(scope='real-Pixel-W2-TCP4-TCP6-Direct', case=args.case, status='HOLD',
                  started_ns=time.time_ns(), build_sha256=chain.digest(args.build),
                  apk_sha256=build['apk_sha256'], serial=SERIAL, addresses=addresses, runs=[])
    test_inputs = ['tests/device/s240-pixel-tcp.py', 'tests/device/helpers/s240-endpoint.c',
                   'tests/device/helpers/s217-policy.c', 'tests/device/s207-owner-oracle.py',
                   'tests/evidence/product_chain.py']
    result['test_inputs'] = {name: chain.digest(ROOT / name) for name in test_inputs}
    for name in test_inputs:
        target = args.output / 'test-source' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)

    def save(name, text):
        path = args.output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return text

    def adb(*command, check=True):
        call = subprocess.run([str(ROOT / 'dev/adb'), '-s', SERIAL, *command],
                              capture_output=True, text=True, errors='replace', timeout=30)
        if check and call.returncode:
            raise RuntimeError(call.stdout + call.stderr)
        return (call.stdout + call.stderr).replace('\r', '')

    def app(path):
        return adb('shell', 'run-as', PKG, 'cat', path, check=False)

    def props(text):
        return dict(line.split('=', 1) for line in text.splitlines()
                    if '=' in line and not line.startswith('#'))

    def action(*extras):
        return adb('shell', 'am', 'start', '-n', PKG + '/.DebugControlActivity', *extras)

    def wait_state(label, expected, old_generation=None):
        deadline = time.monotonic() + 45
        values = {}
        while time.monotonic() < deadline:
            text = save(label + '.poll', app(STATE))
            values = props(text)
            if all(values.get(k) == v for k, v in expected.items()):
                save(label + '.properties', text)
                return values
            if values.get('state') == 'error' and values.get('generation') != old_generation:
                raise RuntimeError('runtime failed: ' + str(values))
            time.sleep(.2)
        raise RuntimeError('state deadline: ' + str(values))

    def cli(label, commands):
        text = "printf '%s\\n' " + ' '.join(shlex.quote(c) for c in
                  ['set terminal pager off', *commands, 'quit'])
        text += ' | toybox nc -U -w 2 -q 1 ' + BASE + 'runtime/cli.sock'
        return save(label + '.txt', adb('shell', 'su', '-c', shlex.quote(text)))

    next_source = 45100
    active = False
    server = None
    endpoint_log = None
    current = None
    held = None
    native = None
    remote_policy = None

    def plan(mode, port):
        nonlocal next_source
        flows = []
        for family, address in addresses.items():
            source = ipaddress.ip_address('10.111.0.2' if family == 4 else 'fd00:111:111::2')
            destination = ipaddress.ip_address(address)
            for owner in (0, 1):
                while next_source < 55000:
                    source_port = next_source
                    next_source += 1
                    facts = dict(l3=1, l4=1, family=family, protocol=6,
                                 src=source.packed.rjust(16, b'\0').hex(),
                                 dst=destination.packed.rjust(16, b'\0').hex(),
                                 src_port=source_port, dst_port=port, icmp_known=0)
                    if oracle.owner(facts) == owner:
                        break
                else:
                    raise RuntimeError('source-port range exhausted')
                flows.append(dict(address=address, family=family, owner=owner,
                                  source=source_port, port=port, mode=mode, bytes=4096))
        return flows

    def launch(label, flows):
        nonlocal held
        nonce = 'Es240-' + str(time.time_ns())
        probe = dict(label=label, nonce=nonce, plan=flows, launch_ns=time.time_ns())
        current['probes'].append(probe)
        if flows[0]['mode'] in ('policy', 'hold'):
            held = probe
        prefix = current['label'] + '/' + label
        save(prefix + '-send.txt', action('--es', 's240ProbeNonce', nonce,
             '--es', 's240ProbePlan', shlex.quote(json.dumps(flows, separators=(',', ':')))))
        save(prefix + '-foreground.txt', action())
        print('probe launched: ' + prefix, flush=True)
        return probe

    def phases(probe, expected):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            values = []
            for index in range(len(probe['plan'])):
                text = app('files/product-state/s240-' + probe['nonce'] + '-' + str(index) + '.json')
                try:
                    value = json.loads(text)
                except json.JSONDecodeError:
                    value = {}
                if value.get('error'):
                    raise RuntimeError('probe phase error: ' + str(value))
                values.append(value)
            if all(v.get('nonce') == probe['nonce'] and v.get('phase') == expected for v in values):
                save(current['label'] + '/' + probe['label'] + '-' + expected + '.json', json.dumps(values, indent=2))
                return values
            time.sleep(.2)
        raise RuntimeError('probe phase deadline: ' + str(values))

    def release(probe):
        for index in range(len(probe['plan'])):
            adb('shell', 'run-as', PKG, 'touch',
                'files/product-state/s240-release-' + probe['nonce'] + '-' + str(index))

    def wait_probe(probe):
        nonlocal held
        deadline = time.monotonic() + 75
        while time.monotonic() < deadline:
            text = app('files/product-state/s240-probe.json')
            try:
                report = json.loads(text)
            except json.JSONDecodeError:
                report = {}
            if report.get('nonce') == probe['nonce']:
                save(current['label'] + '/' + probe['label'] + '.json', text)
                assert not report.get('error') and len(report['flows']) == len(probe['plan']), report
                for flow, config in zip(report['flows'], probe['plan']):
                    assert not flow.get('error'), flow
                    assert flow['source'] == config['source'] and flow['mode'] == config['mode']
                    if config['mode'] == 'refusal':
                        assert flow['outcome'] in ('refused_error', 'refused_eof') and not flow['echoes'], flow
                    else:
                        assert flow['echoes'] == (1 if config['mode'] == 'hold' else 3), flow
                        if config['mode'] == 'policy':
                            assert flow['timeouts'] >= 1, flow
                if held is probe:
                    held = None
                probe['finished_ns'] = time.time_ns()
                print('probe complete: ' + current['label'] + '/' + probe['label'], flush=True)
                return report
            time.sleep(.2)
        raise RuntimeError('probe completion deadline: ' + probe['label'])

    def policy(label, mode):
        revision = time.time_ns() // 1000000
        command = ('LD_LIBRARY_PATH=' + shlex.quote(native) + ' ' + remote_policy + ' ' + BASE +
                   'runtime/api.sock ' + str(current['generation']) + ' /data/local/tmp/s240-policy-state-' +
                   str(current['generation']) + ' ' + str(revision) + ' ' + str(mode) + ' ' + str(result['uid']) + ' 0')
        text = save(current['label'] + '/' + label + '-policy.txt',
                    adb('shell', 'su', '-c', shlex.quote(command)))
        assert 'policy rc=0' in text, text
        current.setdefault('policies', []).append(dict(label=label, mode=mode, revision=revision, applied_ns=time.time_ns()))

    def start(label):
        nonlocal current, active
        old = props(app(STATE))
        assert old.get('mayBeActive') == 'false'
        current = dict(label=label, probes=[])
        result['runs'].append(current)
        active = True
        save(label + '/start.txt', action('--ez', 'debugVpnHevValidation', 'true'))
        state = wait_state(label + '/running', dict(state='running', profile='vpn', errorCode=''), old.get('generation'))
        current['generation'] = int(state['generation'])
        assert state['protectionRunning'] == 'false'  # Validation is not release readiness.
        before = cli(label + '/before', ['product packet-trace limit 4096', 'show product flow-stack',
                                         'show product tun', 'show threads', 'show product flow'])
        assert 'packet.trace_limit=4096' in before
        assert all(f'enabled=1 owner={owner} ready=1' in before for owner in (0, 1))

    def stop_run():
        nonlocal active
        label = current['label']
        cli(label + '/before-stop', ['show product flow-stack', 'show product tun', 'show product flow'])
        save(label + '/broker.log', adb('logcat', '-d', '-s', 'SakamotoSocketBroker:I', '*:S'))
        save(label + '/stop.txt', action('--ez', 'runtimeStop', 'true'))
        state = wait_state(label + '/stopped', dict(state='stopped', mayBeActive='false', errorCode=''))
        assert int(state['generation']) == current['generation']
        save(label + '/native-stop.log', app('files/product-state/s237-last-stop.log'))
        processes = save(label + '/processes-after.txt', adb('shell', 'ps', '-A', '-o', 'PID,UID,ARGS'))
        assert 'libvpp_runtime.so' not in processes
        active = False
        current['stopped_ns'] = time.time_ns()

    try:
        previous = props(save('previous-state.txt', app(STATE)))
        assert previous.get('mayBeActive') == 'false', 'existing runtime is active'
        save('install.txt', adb('install', '-r', build['apk']))
        package = save('package.txt', adb('shell', 'dumpsys', 'package', PKG))
        code = re.search(r'codePath=(\S+)', package).group(1)
        native = code + '/lib/arm64'
        installed = save('installed-apk.txt', adb('shell', 'sha256sum', code + '/base.apk'))
        assert installed.split()[0] == build['apk_sha256']
        installed = save('installed-native.txt', adb('shell', 'sha256sum',
                        *[native + '/' + n for n in sorted(build['native_sha256'])]))
        assert {Path(line.split()[1]).name: line.split()[0] for line in installed.splitlines()} == build['native_sha256']
        save('device.txt', adb('shell', 'uname', '-a'))
        save('network.txt', adb('shell', 'ip', 'address'))
        result['uid'] = int(adb('shell', 'run-as', PKG, 'id', '-u').strip())
        remote_policy = '/data/local/tmp/s240-policy-' + str(result['started_ns'])
        helper = args.build.resolve().parent / 'helpers/s217-policy'
        assert chain.digest(helper) == build['s221_helpers']['helpers/s217-policy']
        save('policy-push.txt', adb('push', str(helper), remote_policy))
        adb('shell', 'chmod', '755', remote_policy)
        assert adb('shell', 'sha256sum', remote_policy).split()[0] == chain.digest(helper)
        result['policy_helper_sha256'] = chain.digest(helper)
        endpoint = args.output / 'tcp-endpoint'
        compiler = shutil.which('cc')
        subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                        str(ROOT / 'tests/device/helpers/s240-endpoint.c'), '-o', str(endpoint)], check=True)
        result['endpoint_sha256'] = chain.digest(endpoint)
        result['endpoint_compiler'] = dict(path=compiler, sha256=chain.digest(compiler),
                                          version=subprocess.check_output([compiler, '--version'], text=True))
        with socket.socket() as reservation:
            reservation.bind((addresses[4], 0))
            port = reservation.getsockname()[1]
        assert port <= 65533
        result['endpoint_port'] = port
        endpoint_log = (args.output / 'endpoint.log').open('w')
        server = subprocess.Popen([str(endpoint), str(port), addresses[4], addresses[6]],
                                  stdout=endpoint_log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 5
        while 'event=ready' not in (args.output / 'endpoint.log').read_text():
            assert server.poll() is None, 'endpoint failed to bind'
            assert time.monotonic() < deadline
            time.sleep(.05)
        start('normal')
        wait_probe(launch('fin', plan('fin', port)))
        if args.case == 'matrix':
            wait_probe(launch('client-rst', plan('rst', port)))
            wait_probe(launch('connect-refusal', plan('refusal', port + 2)))
            wait_probe(launch('server-rst', plan('refusal', port + 1)))
            policy('syn-drop', 6)
            probe = launch('syn-retransmit', plan('fin', port))
            time.sleep(3.5)
            cli('normal/syn-dropped', ['show product flow-stack', 'show product tun'])
            policy('syn-recover', 0)
            wait_probe(probe)
            probe = launch('return-policy', plan('policy', port))
            phases(probe, 'first_echo')
            policy('data-drop', 6)
            release(probe)
            phases(probe, 'return_timeout')
            cli('normal/data-dropped', ['show product flow-stack', 'show product tun'])
            policy('data-recover', 0)
            wait_probe(probe)
            probe = launch('active-stop', plan('hold', port))
            phases(probe, 'holding')
            stop_run()
            release(probe)
            wait_probe(probe)
            start('restart')
            wait_probe(launch('fin', plan('fin', port)))
        stop_run()
        result['status'] = 'CAPTURE_COMPLETE'
    except Exception as error:
        result['error'] = repr(error)
        save('failure-state.txt', app(STATE))
        save('failure-vpp.log', app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
        save('failure-service.log', app('files/logs/runtime-service.log'))
        raise
    finally:
        if active:
            try:
                if current and 'generation' in current:
                    stop_run()
                else:
                    action('--ez', 'runtimeStop', 'true')
                    wait_state('cleanup', dict(mayBeActive='false'))
            except Exception as error:
                result['cleanup_error'] = repr(error)
        if held:
            try:
                release(held)
            except Exception as error:
                result['probe_cleanup_error'] = repr(error)
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server.kill(); server.wait()
                result['endpoint_forced_stop'] = True
            result['endpoint_returncode'] = server.returncode
        if endpoint_log is not None:
            endpoint_log.close()
        if any(chain.digest(ROOT / name) != value for name, value in result['test_inputs'].items()):
            result['test_source_changed'] = True
        result['completed_ns'] = time.time_ns()
        save('result.json', json.dumps(result, indent=2) + '\n')
    assert result['status'] == 'CAPTURE_COMPLETE' and not result.get('cleanup_error')
    print(json.dumps(dict(status=result['status'], run=str(args.output),
                         generations=[r['generation'] for r in result['runs']]), indent=2))


if __name__ == '__main__':
    main()
