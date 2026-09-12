#!/usr/bin/env python3
"""Real Pixel owner-local processing/transport pressure; independent verdict later.

Only the dedicated Pixel and task-owned test endpoints/routes are changed.
"""
import argparse
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
CASES = ('flow-capacity', 'session-capacity', 'pcb-capacity', 'socket-capacity',
         'packet-credit', 'pbuf-capacity', 'protect', 'bind', 'refusal', 'unreachable', 'drop')
LIMITS = {'session-capacity': '1,258,256,1024,8192', 'pcb-capacity': '256,3,256,1024,8192',
          'socket-capacity': '256,258,1,1024,8192', 'packet-credit': '256,258,256,1,8192',
          'pbuf-capacity': '256,258,256,1024,8', 'drop': '1,258,256,1024,8192'}
FAULTS = {'session-capacity': 'SESSION_CAPACITY', 'pcb-capacity': 'PCB_CAPACITY',
          'socket-capacity': 'SOCKET_CAPACITY', 'packet-credit': 'PACKET_CREDIT',
          'pbuf-capacity': 'PBUF_CAPACITY', 'protect': 'PROTECT', 'bind': 'BIND',
          'refusal': 'CONNECT_REFUSED', 'unreachable': 'NETWORK_UNREACHABLE'}


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--ipv4', required=True)
    p.add_argument('--ipv6', required=True)
    p.add_argument('--case', choices=['all', *CASES], default='all')
    p.add_argument('--family', choices=['both', '4', '6'], default='both')
    p.add_argument('--protocol', choices=['tcp', 'udp', 'both'], default='both')
    p.add_argument('--owner', type=int, choices=[0, 1], default=0)
    p.add_argument('--completion-slots', type=int, choices=[2, 128], default=128)
    args = p.parse_args()
    assert args.completion_slots == 128 or (args.case == 'drop' and args.protocol == 'udp' and args.owner == 1)
    chain = module('chain241', 'tests/evidence/product_chain.py')
    oracle = module('owner241', 'tests/device/s207-owner-oracle.py')
    args.build = args.build.resolve()
    build = json.loads(args.build.read_text())
    assert chain.source_files() == build['files'], 'Product source differs from build'
    assert chain.digest(build['apk']) == build['apk_sha256']
    addresses = {4: str(ipaddress.IPv4Address(args.ipv4)), 6: str(ipaddress.IPv6Address(args.ipv6))}
    for address in addresses.values():
        a = ipaddress.ip_address(address)
        assert not (a.is_unspecified or a.is_loopback or a.is_link_local or a.is_multicast)
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    inputs = ['tests/device/s241-pixel-capacity.py', 'tests/device/helpers/s241-policy.c',
              'tests/device/helpers/s240-endpoint.c', 'tests/device/helpers/s223-udp.c',
              'tests/device/s207-owner-oracle.py', 'tests/evidence/product_chain.py']
    result = dict(status='HOLD', scope='real-Pixel-W2-processing-and-transport-capacity',
                  started_ns=time.time_ns(), serial=SERIAL, build_sha256=chain.digest(args.build),
                  apk_sha256=build['apk_sha256'], addresses=addresses, runs=[],
                  test_inputs={n: chain.digest(ROOT / n) for n in inputs})
    for name in inputs:
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

    def wait_state(label, expected):
        deadline = time.monotonic() + 45
        state = {}
        while time.monotonic() < deadline:
            text = app(STATE)
            state = props(text)
            save(label + '.poll', text)
            if all(state.get(k) == v for k, v in expected.items()):
                save(label + '.properties', text)
                return state
            if state.get('state') == 'error':
                raise RuntimeError('runtime failed: ' + str(state))
            time.sleep(.2)
        raise RuntimeError('runtime deadline: ' + str(state))

    def cli(label, commands):
        command = "printf '%s\\n' " + ' '.join(shlex.quote(c) for c in
            ['set terminal pager off', *commands, 'quit'])
        command += ' | toybox nc -U -w 2 -q 1 ' + BASE + 'runtime/cli.sock'
        text = save(label + '.txt', adb('shell', 'su', '-c', shlex.quote(command)))
        assert 'unknown input' not in text and 'unknown command' not in text, text
        return text

    active = False
    current = None
    native = None
    remote_helper = None
    processes, logs, routes, held, policy_paths = [], [], [], [], []
    source_serial = 46100

    def flow(family, protocol, owner, mode='fin', port=None, address=None):
        nonlocal source_serial
        address = address or addresses[family]
        port = port or ports[protocol][family]
        source = ipaddress.ip_address('10.111.0.2' if family == 4 else 'fd00:111:111::2')
        destination = ipaddress.ip_address(address)
        while source_serial < 62000:
            source_port = source_serial
            source_serial += 1
            facts = dict(l3=1, l4=1, family=family, protocol=6 if protocol == 'tcp' else 17,
                         src=source.packed.rjust(16, b'\0').hex(), dst=destination.packed.rjust(16, b'\0').hex(),
                         src_port=source_port, dst_port=port, icmp_known=0)
            if oracle.owner(facts) == owner:
                return dict(address=address, family=family, owner=owner, source=source_port, port=port,
                            mode=mode, bytes=256, packets=1, intervalMs=0)
        raise RuntimeError('source port range exhausted')

    def launch(label, protocol, plan):
        nonce = 'Es241-' + str(time.time_ns())
        probe = dict(label=label, protocol=protocol, nonce=nonce, plan=plan, launched_ns=time.time_ns())
        current['probes'].append(probe)
        held.append(probe)
        field = 's240' if protocol == 'tcp' else 's239'
        save(current['label'] + '/' + label + '-launch.txt', action('--es', field + 'ProbeNonce', nonce,
             '--es', field + 'ProbePlan', shlex.quote(json.dumps(plan, separators=(',', ':')))))
        action()  # Keep the real traffic application's Activity foreground.
        return probe

    def phase(probe, index, expected):
        deadline = time.monotonic() + 25
        value = {}
        while time.monotonic() < deadline:
            try:
                text = app('files/product-state/s240-' + probe['nonce'] + '-' + str(index) + '.json')
                value = json.loads(text)
            except json.JSONDecodeError:
                value = {}
            if value.get('error'):
                raise RuntimeError('probe phase failure: ' + str(value))
            if value.get('phase') == expected and value.get('nonce') == probe['nonce']:
                save(current['label'] + '/' + probe['label'] + f'-phase-{index}-{expected}.json', text)
                return value
            time.sleep(.1)
        raise RuntimeError('probe phase deadline: ' + str(value))

    def release(probe, indices, connect=False):
        for index in indices:
            adb('shell', 'run-as', PKG, 'touch', 'files/product-state/s240-' +
                ('connect-' if connect else 'release-') + probe['nonce'] + '-' + str(index))

    def wait_probe(probe):
        deadline = time.monotonic() + 95
        field = 's240' if probe['protocol'] == 'tcp' else 's239'
        while time.monotonic() < deadline:
            try:
                text = app('files/product-state/' + field + '-probe.json')
                report = json.loads(text)
            except json.JSONDecodeError:
                report = {}
            if report.get('nonce') == probe['nonce']:
                save(current['label'] + '/' + probe['label'] + '.json', text)
                assert not report.get('error') and len(report['flows']) == len(probe['plan']), report
                assert all(not f.get('error') for f in report['flows']), report
                probe['finished_ns'] = time.time_ns()
                held.remove(probe)
                return report
            time.sleep(.2)
        raise RuntimeError('probe completion deadline: ' + probe['label'])

    def snapshot(label):
        return cli(current['label'] + '/' + label,
                   ['show product flow-stack', 'show product tun', 'show product flows', 'show product primary'])

    def policy(protocol, source):
        revision = time.time_ns() // 1000000
        path = '/data/local/tmp/s241-policy-state-' + str(result['started_ns']) + '-' + str(current['generation'])
        if path not in policy_paths: policy_paths.append(path)
        command = 'LD_LIBRARY_PATH=' + shlex.quote(native) + ' ' + shlex.join([
            remote_helper, BASE + 'runtime/api.sock', str(current['generation']),
            path, str(revision),
            str(protocol), str(result['uid']), str(source)])
        text = save(current['label'] + '/policy-' + str(revision) + '.txt',
                    adb('shell', 'su', '-c', shlex.quote(command)))
        assert 'policy rc=0' in text, text
        current.setdefault('policies', []).append(dict(protocol=protocol, source=source,
            revision=revision, applied_ns=time.time_ns()))

    def start(case, family, protocol):
        nonlocal active, current
        label = f'{protocol}{family}-{case}'
        current = dict(label=label, case=case, family=family, protocol=protocol, probes=[],
                       completion_slots=args.completion_slots,
                       expected=dict(fault=FAULTS.get(case, 'NONE'), owner=args.owner,
                           no_spill=True, preserve_existing=True, policy_drop=case == 'drop',
                           processing_bypass=case == 'flow-capacity', zero_residue=True))
        current['limits'] = LIMITS.get(case, '256,258,256,1024,8192')
        current['flow_entries'] = 1 if case == 'flow-capacity' else 1024
        result['runs'].append(current)
        save('result.json', json.dumps(result, indent=2))  # Expected card precedes traffic.
        assert props(app(STATE)).get('mayBeActive') == 'false'
        active = True
        save(label + '/start.txt', action('--ez', 'debugVpnHevValidation', 'true',
             '--es', 'debugVpnHevLimits', current['limits'],
             '--ei', 'debugVpnFlowEntries', str(current['flow_entries'])))
        state = wait_state(label + '/running', dict(state='running', profile='vpn', errorCode=''))
        assert state['protectionRunning'] == 'false'
        current['generation'] = int(state['generation'])
        cli(label + '/trace', ['product packet-trace limit 4096'])
        snapshot('before')
        print('case started: ' + label, flush=True)

    def stop():
        nonlocal active
        label = current['label']
        snapshot('before-stop')
        save(label + '/broker.log', adb('logcat', '-d', '-s', 'SakamotoSocketBroker:I', '*:S'))
        save(label + '/stop.txt', action('--ez', 'runtimeStop', 'true'))
        state = wait_state(label + '/stopped', dict(state='stopped', mayBeActive='false', errorCode=''))
        assert int(state['generation']) == current['generation']
        save(label + '/native-stop.log', app('files/product-state/s237-last-stop.log'))
        ps = save(label + '/processes-after.txt', adb('shell', 'ps', '-A', '-o', 'PID,UID,ARGS'))
        assert 'libvpp_runtime.so' not in ps
        active = False
        current['stopped_ns'] = time.time_ns()
        print('case collected: ' + label, flush=True)

    def unreachable_route(family, add):
        target = '198.18.241.1/32' if family == 4 else '2001:db8:241::1/128'
        prefix = ['ip'] + (['-6'] if family == 6 else []) + ['route']
        if add:
            existing = adb('shell', 'su', '-c', shlex.quote(shlex.join(
                [*prefix, 'show', 'table', 'wlan0', 'exact', target])))
            assert not existing.strip(), 'test route already exists: ' + existing
        command = shlex.join([*prefix, 'add' if add else 'del', 'unreachable', target, 'table', 'wlan0'])
        text = adb('shell', 'su', '-c', shlex.quote(command))
        assert not text.strip(), text
        if add:
            routes.append(family)
            save(current['label'] + '/unreachable-route.txt', adb('shell', 'su', '-c', shlex.quote(
                shlex.join([*prefix, 'show', 'table', 'wlan0', 'exact', target]))))
        else:
            routes.remove(family)
            save(current['label'] + '/route-restored.txt', adb('shell', 'su', '-c', shlex.quote(
                shlex.join([*prefix, 'show', 'table', 'wlan0', 'exact', target]))))
        return target.split('/')[0]

    def tcp_case(case, family):
        start(case, family, 'tcp')
        pressure = case in ('packet-credit', 'pbuf-capacity')
        victim = flow(family, 'tcp', args.owner, 'policy')
        witness = flow(family, 'tcp', 1 - args.owner, 'policy')
        if pressure:
            victim['writeChunkBytes'] = 16
            probe = launch('pressure', 'tcp', [victim, witness])
            phase(probe, 0, 'first_echo'); phase(probe, 1, 'first_echo')
            snapshot('warm')
            cli(current['label'] + '/hold', [f'product flow-stack hold owner {args.owner} 3000'])
            release(probe, [0, 1])
            time.sleep(.4)
            snapshot('pressure')
            cli(current['label'] + '/resume', [f'product flow-stack hold owner {args.owner} 0'])
            report = wait_probe(probe)
            assert all(f['echoes'] == 3 for f in report['flows']), report
        else:
            address = unreachable_route(family, True) if case == 'unreachable' else None
            port = ports['tcp'][family] + 2 if case == 'refusal' else None
            candidate = flow(family, 'tcp', args.owner, 'fin' if case == 'flow-capacity' else 'failure', port, address)
            candidate.update(waitToConnect=True, connectTimeoutMs=3000)
            probe = launch('pressure', 'tcp', [victim, candidate, witness])
            phase(probe, 0, 'first_echo'); phase(probe, 2, 'first_echo')
            phase(probe, 1, 'waiting_to_connect')
            snapshot('warm')
            if case in ('protect', 'bind'):
                cli(current['label'] + '/broker-fault', [f'product flow-stack broker-fault owner {args.owner} {case} after 1'])
            if case == 'drop':
                policy(6, candidate['source'])
            release(probe, [1], connect=True)
            candidate_result = phase(probe, 1, 'finished')
            if case == 'flow-capacity':
                assert candidate_result.get('echoes') == 3
            else:
                assert candidate_result.get('outcome', '').startswith('failed_') and not candidate_result['echoes']
            snapshot('pressure')
            if case == 'drop': policy(0, 0)
            if case == 'unreachable': unreachable_route(family, False)
            release(probe, [0, 2])
            report = wait_probe(probe)
            assert report['flows'][0]['echoes'] == report['flows'][2]['echoes'] == 3
        snapshot('recovered')
        # Old app FINs release the transport's real capacity; FlowEntry may
        # remain independently alive. A fresh tuple must recover without resize.
        time.sleep(.3)
        recovery = launch('new-flow-recovery', 'tcp', [flow(family, 'tcp', args.owner)])
        report = wait_probe(recovery)
        assert report['flows'][0]['echoes'] == 3
        stop()

    def udp_case(case, family):
        if case == 'refusal': return  # UDP connect has no TCP-style refusal handshake.
        start(case, family, 'udp')
        victim, witness = flow(family, 'udp', args.owner), flow(family, 'udp', 1 - args.owner)
        report = wait_probe(launch('warm', 'udp', [victim, witness]))
        assert all(f['echoes'] == 1 for f in report['flows'])
        snapshot('warm')
        if args.completion_slots == 2:
            text = cli(current['label'] + '/completion-capacity',
                       ['product capacity credits 32 primary-slots 64 completion-slots 2'])
            assert 'capacity.configured' in text
        pressure = case in ('packet-credit', 'pbuf-capacity')
        if pressure:
            cli(current['label'] + '/hold', [f'product flow-stack hold owner {args.owner} 2000'])
            burst = dict(victim, packets=32, burst=True, intervalMs=2)
            probe = launch('pressure', 'udp', [burst, dict(witness, packets=8, intervalMs=50)])
            time.sleep(.4)
            snapshot('pressure')
            cli(current['label'] + '/resume', [f'product flow-stack hold owner {args.owner} 0'])
            report = wait_probe(probe)
            assert 0 < report['flows'][0]['echoes'] < 32 and report['flows'][1]['echoes'] == 8, report
        else:
            address = unreachable_route(family, True) if case == 'unreachable' else None
            candidate = flow(family, 'udp', args.owner, address=address)
            if args.completion_slots == 2:
                candidate.update(packets=16, burst=True, intervalMs=0)
            if case in ('protect', 'bind'):
                cli(current['label'] + '/broker-fault', [f'product flow-stack broker-fault owner {args.owner} {case} after 1'])
            if case == 'drop': policy(17, candidate['source'])
            report = wait_probe(launch('pressure', 'udp', [candidate, witness]))
            assert report['flows'][0]['echoes'] == (1 if case == 'flow-capacity' else 0), report
            assert report['flows'][1]['echoes'] == 1
            snapshot('pressure')
            if args.completion_slots == 2:
                text = cli(current['label'] + '/completion-recovery',
                           ['product capacity credits 32 primary-slots 64 completion-slots 128'])
                assert 'capacity.configured' in text
            if case == 'drop': policy(0, 0)
            if case == 'unreachable': unreachable_route(family, False)
        report = wait_probe(launch('same-flow-recovery', 'udp', [victim, witness]))
        assert all(f['echoes'] == 1 for f in report['flows'])
        snapshot('recovered')
        if case in ('session-capacity', 'pcb-capacity', 'socket-capacity', 'drop'):
            # Native UDP idle expiry, not a test-only close command or restart,
            # releases the limiting resource before a new flow is attempted.
            print('waiting for real UDP idle resource release: ' + current['label'], flush=True)
            deadline = time.monotonic() + 66
            while time.monotonic() < deadline:
                time.sleep(1)
            snapshot('idle-released')
        report = wait_probe(launch('new-flow-recovery', 'udp', [flow(family, 'udp', args.owner)]))
        assert report['flows'][0]['echoes'] == 1
        stop()

    ports = {'tcp': {}, 'udp': {}}
    try:
        assert props(save('previous-state.txt', app(STATE))).get('mayBeActive') == 'false'
        save('install.txt', adb('install', '-r', build['apk']))
        package = save('package.txt', adb('shell', 'dumpsys', 'package', PKG))
        code = re.search(r'codePath=(\S+)', package).group(1)
        native = code + '/lib/arm64'
        installed = save('installed-apk.txt', adb('shell', 'sha256sum', code + '/base.apk'))
        assert installed.split()[0] == build['apk_sha256']
        installed = save('installed-native.txt', adb('shell', 'sha256sum',
                        *[native + '/' + n for n in sorted(build['native_sha256'])]))
        assert {Path(l.split()[1]).name: l.split()[0] for l in installed.splitlines()} == build['native_sha256']
        save('device.txt', adb('shell', 'uname', '-a'))
        save('network.txt', adb('shell', 'ip', 'address'))
        save('routes-before.txt', adb('shell', 'su', '-c', shlex.quote('ip route show table all; ip -6 route show table all')))
        result['uid'] = int(adb('shell', 'run-as', PKG, 'id', '-u').strip())
        ndk = '/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang'
        helper = args.output / 's241-policy'
        subprocess.run([ndk, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                        str(ROOT / inputs[1]), '-I', str(ROOT / 'src/product/include'),
                        '-L', str(args.build.parent / 'stage/lib/arm64-v8a'),
                        '-lsakamoto_product_core', '-o', str(helper)], check=True)
        result['policy_helper'] = dict(sha256=chain.digest(helper), compiler=ndk,
                                      compiler_sha256=chain.digest(ndk))
        remote_helper = '/data/local/tmp/s241-policy-' + str(result['started_ns'])
        save('helper-push.txt', adb('push', str(helper), remote_helper))
        adb('shell', 'chmod', '755', remote_helper)
        assert save('helper-installed.txt', adb('shell', 'sha256sum', remote_helper)).split()[0] == chain.digest(helper)
        compiler = shutil.which('cc')
        result['endpoint_compiler'] = dict(path=compiler, sha256=chain.digest(compiler),
            version=subprocess.check_output([compiler, '--version'], text=True))
        result['endpoint_sha256'] = {}
        for protocol, source in [('tcp', inputs[2]), ('udp', inputs[3])]:
            binary = args.output / (protocol + '-endpoint')
            subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                            str(ROOT / source), '-o', str(binary)], check=True)
            result['endpoint_sha256'][protocol] = chain.digest(binary)
            if protocol == 'tcp':
                with socket.socket() as reservation:
                    reservation.bind((addresses[4], 0)); port = reservation.getsockname()[1]
                assert port <= 65533
                ports['tcp'] = {4: port, 6: port}
                log = (args.output / 'tcp-endpoint.log').open('w'); logs.append(log)
                processes.append(subprocess.Popen([str(binary), str(port), addresses[4], addresses[6]],
                    stdout=log, stderr=subprocess.STDOUT))
            else:
                for family, address in addresses.items():
                    with socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_DGRAM) as reservation:
                        reservation.bind((address, 0)); port = reservation.getsockname()[1]
                    ports['udp'][family] = port
                    log = (args.output / f'udp{family}-endpoint.log').open('w'); logs.append(log)
                    processes.append(subprocess.Popen([str(binary), 'server', str(os.getuid()), str(family), address, str(port)],
                        stdout=log, stderr=subprocess.STDOUT))
        result['ports'] = ports
        time.sleep(.2)
        assert all(p.poll() is None for p in processes), 'endpoint startup failed'
        for protocol in (['tcp', 'udp'] if args.protocol == 'both' else [args.protocol]):
            for family in ([4, 6] if args.family == 'both' else [int(args.family)]):
                for case in (CASES if args.case == 'all' else [args.case]):
                    (tcp_case if protocol == 'tcp' else udp_case)(case, family)
        result['status'] = 'COLLECTED'
    except Exception as error:
        result['error'] = repr(error)
        print('HOLD: ' + repr(error), flush=True)
        if active and current:
            save(current['label'] + '/failure-native.log', app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
    finally:
        for probe in held:
            if probe['protocol'] == 'tcp':
                try:
                    release(probe, range(len(probe['plan'])), connect=True)
                    release(probe, range(len(probe['plan'])))
                except Exception as error: result.setdefault('cleanup_errors', []).append(str(error))
        for family in list(routes):
            try: unreachable_route(family, False)
            except Exception as error: result.setdefault('cleanup_errors', []).append(str(error))
        if active:
            try: stop()
            except Exception as error: result.setdefault('cleanup_errors', []).append(str(error))
        if remote_helper:
            save('helper-cleanup.txt', adb('shell', 'rm', '-f', remote_helper, check=False))
        for path in policy_paths:
            assert re.fullmatch(r'/data/local/tmp/s241-policy-state-[0-9]+-[0-9]+', path)
            save('policy-cleanup-' + Path(path).name + '.txt',
                 adb('shell', 'su', '-c', shlex.quote('rm -rf -- ' + path)))
        for process in processes:
            process.terminate()
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=3)
        for log in logs: log.close()
        result['finished_ns'] = time.time_ns()
        save('result.json', json.dumps(result, indent=2))
    if result['status'] != 'COLLECTED' or result.get('cleanup_errors'):
        raise SystemExit(1)
    print(json.dumps(dict(status='COLLECTED', runs=len(result['runs']), output=str(args.output)), indent=2))


if __name__ == '__main__':
    main()
