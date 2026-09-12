#!/usr/bin/env python3
"""W2 real TCP/UDP4/6 held-app sockets during Stop, broker loss and native crash.

The explicit underlay case also retains the same app UDP sockets across real
Wi-Fi loss, no-network rejection and a newly created Android Wi-Fi Network.
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
    parser.add_argument('--cases', default='stop,crash,broker0,broker1')
    parser.add_argument('--underlay-drop', action='store_true')
    args = parser.parse_args()
    cases = args.cases.split(',')
    assert cases and len(cases) == len(set(cases)) and set(cases) <= {'stop', 'crash', 'broker0', 'broker1', 'underlay'}
    assert not args.underlay_drop or cases == ['underlay']
    addresses = {4: str(ipaddress.IPv4Address(args.ipv4)), 6: str(ipaddress.IPv6Address(args.ipv6))}
    for address in addresses.values():
        ip = ipaddress.ip_address(address)
        assert not (ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_multicast)
    chain = module('active_chain243', 'tests/evidence/product_chain.py')
    oracle = module('active_owner243', 'tests/device/s207-owner-oracle.py')
    build = json.loads(args.build.read_text())
    assert chain.source_files() == build['files'] and chain.digest(build['apk']) == build['apk_sha256']
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    result = dict(scope='real-Pixel-W2-active-TCP-UDP-lifecycle', status='HOLD', serial=SERIAL,
                  started_ns=time.time_ns(), build_sha256=chain.digest(args.build),
                  apk_sha256=build['apk_sha256'], addresses=addresses, runs=[])
    names = ['tests/device/s243-pixel-active.py', 'tests/device/s207-owner-oracle.py',
             'tests/device/helpers/s240-endpoint.c', 'tests/device/helpers/s223-udp.c',
             'tests/evidence/product_chain.py']
    if args.underlay_drop:
        names.append('tests/device/helpers/s241-policy.c')
    result['test_inputs'] = {name: chain.digest(ROOT / name) for name in names}
    for name in names:
        target = args.output / 'test-source' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)

    def save(name, value):
        path = args.output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
        return value

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

    def wait_state(label, predicate):
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            text = save(label + '.poll', app(STATE))
            value = props(text)
            if predicate(value):
                save(label + '.properties', text)
                return value
            if value.get('state') == 'starting':
                native = app('files/profiles/vpn/vpp/logs/vpp-stdout.log')
                if 's237' in native:
                    save('generations/' + value['generation'] + '-startup.log', native)
            time.sleep(.1)
        raise RuntimeError('runtime state deadline: ' + str(value))

    def cli(label, commands):
        text = "printf '%s\\n' " + ' '.join(shlex.quote(c) for c in
                ['set terminal pager off', *commands, 'quit'])
        text += ' | toybox nc -U -w 2 -q 1 ' + BASE + 'runtime/cli.sock'
        return save(label + '.txt', adb('shell', 'su', '-c', shlex.quote(text)))

    def ready(label, old_generation):
        value = wait_state(label, lambda s: s.get('state') == 'running' and
                           s.get('generation') != old_generation and not s.get('errorCode'))
        assert value['profile'] == 'vpn' and value['protectionRunning'] == 'false'
        before = cli(label + '-ready', ['product packet-trace limit 4096', 'show product flow-stack',
                                        'show product tun', 'show threads', 'show files'])
        assert all(f'enabled=1 owner={i} ready=1' in before for i in (0, 1))
        return value

    def stop(label):
        save(label + '-stop.txt', action('--ez', 'runtimeStop', 'true'))
        value = wait_state(label + '-stopped', lambda s: s.get('state') == 'stopped' and
                           s.get('mayBeActive') == 'false' and s.get('errorCode') == '')
        save(label + '-native-stop.log', app('files/product-state/s237-last-stop.log'))
        processes = save(label + '-process-after.txt', adb('shell', 'ps', '-A', '-o', 'PID,UID,ARGS'))
        assert 'libvpp_runtime.so' not in processes
        return value

    next_source = 47000
    held = []

    def plan(protocol, hold):
        nonlocal next_source
        flows = []
        for family, address in addresses.items():
            port = ports[protocol][family]
            tun = ipaddress.ip_address('10.111.0.2' if family == 4 else 'fd00:111:111::2')
            destination = ipaddress.ip_address(address)
            for owner in (0, 1):
                while next_source < 57000:
                    source = next_source
                    next_source += 1
                    facts = dict(l3=1, l4=1, family=family, protocol=protocol,
                                 src=tun.packed.rjust(16, b'\0').hex(), dst=destination.packed.rjust(16, b'\0').hex(),
                                 src_port=source, dst_port=port, icmp_known=0)
                    if oracle.owner(facts) == owner:
                        break
                else:
                    raise RuntimeError('source ports exhausted')
                flow = dict(address=address, port=port, source=source, family=family, owner=owner)
                flow.update(dict(mode='hold' if hold else 'fin', bytes=4096) if protocol == 6
                            else dict(packets=1 if hold else 3, intervalMs=100, holdAfterFirst=hold))
                if current['case'] == 'underlay' and hold:
                    if protocol == 6:
                        flow['holdTimeoutMs'] = 60000
                    else:
                        flow.update(packets=4 if args.underlay_drop else 3,
                                    underlaySequence=True, underlayDrop=args.underlay_drop)
                flows.append(flow)
        return flows

    def launch(label, protocol, hold):
        nonce = 'Es243-' + str(time.time_ns())
        probe = dict(label=label, nonce=nonce, protocol=protocol, plan=plan(protocol, hold),
                     started_ns=time.time_ns())
        current['probes'].append(probe)
        if hold:
            held.append(probe)
        prefix = 's240' if protocol == 6 else 's239'
        save(label + '-launch.txt', action('--es', prefix + 'ProbeNonce', nonce,
             '--es', prefix + 'ProbePlan', shlex.quote(json.dumps(probe['plan'], separators=(',', ':')))))
        save(label + '-foreground.txt', action())
        return probe

    def holding(probe, packet=0):
        deadline = time.monotonic() + 15
        prefix = 's240-' if probe['protocol'] == 6 else 's243-udp-'
        while time.monotonic() < deadline:
            values = []
            for index in range(4):
                text = app('files/product-state/' + prefix + probe['nonce'] + '-' + str(index) + '.json')
                try:
                    values.append(json.loads(text))
                except json.JSONDecodeError:
                    values.append({})
            if all(v.get('phase') == 'holding' and v.get('echoes') == 1
                   and (probe['protocol'] == 6 or v.get('packet') == packet) for v in values):
                save(probe['label'] + ('-holding' if packet == 0 else '-holding-' + str(packet)) + '.json',
                     json.dumps(values, indent=2))
                return
            time.sleep(.1)
        raise RuntimeError('held app socket deadline: ' + str(values))

    def release(probe, packet=0):
        prefix = 's240-release-' if probe['protocol'] == 6 else 's243-udp-release-'
        for index in range(4):
            adb('shell', 'run-as', PKG, 'touch', 'files/product-state/' + prefix + probe['nonce'] + '-' + str(index)
                + ('' if packet == 0 else '-' + str(packet)))

    def finish(probe):
        deadline = time.monotonic() + 35
        prefix = 's240' if probe['protocol'] == 6 else 's239'
        while time.monotonic() < deadline:
            text = app('files/product-state/' + prefix + '-probe.json')
            try:
                report = json.loads(text)
            except json.JSONDecodeError:
                report = {}
            if report.get('nonce') == probe['nonce']:
                save(probe['label'] + '-result.json', text)
                assert not report.get('error') and len(report['flows']) == 4
                for value, config in zip(report['flows'], probe['plan']):
                    assert not value.get('error') and value['source'] == config['source'], value
                    expected = 2 if config.get('underlaySequence') else (
                        1 if config.get('mode') == 'hold' or config.get('holdAfterFirst') else 3)
                    assert value['echoes'] == expected, value
                    if config.get('underlaySequence'):
                        expected_outcomes = ['echo', 'timeout', 'timeout', 'echo'] if config.get('underlayDrop') else ['echo', 'timeout', 'echo']
                        assert value['outcomes'] == expected_outcomes, value
                if probe in held:
                    held.remove(probe)
                probe['completed_ns'] = time.time_ns()
                return
            time.sleep(.1)
        raise RuntimeError('probe completion deadline: ' + probe['label'])

    servers, logs = [], []
    ports = {6: {}, 17: {}}
    active = False
    wifi_disabled = False
    remote_helper = None
    policy_paths = []
    current = None

    def policy(probe, drop):
        ports = [p['source'] for p in probe['plan']]
        revision = time.time_ns() // 1000000
        path = '/data/local/tmp/s243-policy-state-' + str(result['started_ns'])
        if path not in policy_paths:
            policy_paths.append(path)
        command = 'LD_LIBRARY_PATH=' + shlex.quote(code + '/lib/arm64') + ' ' + shlex.join([
            remote_helper, BASE + 'runtime/api.sock', str(current['generation']), path, str(revision),
            '17' if drop else '0', str(result['uid']), str(min(ports)) if drop else '0',
            str(max(ports)) if drop else '0'])
        output = save('underlay/policy-' + ('drop' if drop else 'clear') + '.txt',
                      adb('shell', 'su', '-c', shlex.quote(command)))
        assert 'policy rc=0' in output
        current.setdefault('policies', []).append(dict(drop=drop, revision=revision,
                                                      first=min(ports), last=max(ports)))
    try:
        previous = props(save('previous-state.txt', app(STATE)))
        assert previous.get('mayBeActive') == 'false'
        package = save('package.txt', adb('shell', 'dumpsys', 'package', PKG))
        code = re.search(r'codePath=(\S+)', package).group(1)
        binary = code + '/lib/arm64/libvpp_runtime.so'
        installed = save('installed-apk.txt', adb('shell', 'sha256sum', code + '/base.apk'))
        assert installed.split()[0] == build['apk_sha256']
        installed = save('installed-native.txt', adb('shell', 'sha256sum',
                        *[code + '/lib/arm64/' + n for n in sorted(build['native_sha256'])]))
        assert {Path(line.split()[1]).name: line.split()[0] for line in installed.splitlines()} == build['native_sha256']
        result['uid'] = int(adb('shell', 'run-as', PKG, 'id', '-u').strip())
        if args.underlay_drop:
            ndk = '/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang'
            helper = args.output / 's243-policy'
            subprocess.run([ndk, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                            str(ROOT / 'tests/device/helpers/s241-policy.c'), '-I', str(ROOT / 'src/product/include'),
                            '-L', str(args.build.parent / 'stage/lib/arm64-v8a'),
                            '-lsakamoto_product_core', '-o', str(helper)], check=True)
            result['policy_helper'] = dict(sha256=chain.digest(helper), compiler=ndk,
                                          compiler_sha256=chain.digest(ndk))
            remote_helper = '/data/local/tmp/s243-policy-' + str(result['started_ns'])
            save('helper-push.txt', adb('push', str(helper), remote_helper))
            adb('shell', 'chmod', '755', remote_helper)
            assert save('helper-installed.txt', adb('shell', 'sha256sum', remote_helper)).split()[0] == chain.digest(helper)
        save('device.txt', adb('shell', 'uname', '-a'))
        save('network-before.txt', adb('shell', 'ip', 'address'))
        compiler = shutil.which('cc')
        result['endpoint_compiler'] = dict(path=compiler, sha256=chain.digest(compiler))
        result['endpoints'] = {}
        for protocol, source in [(6, 'tests/device/helpers/s240-endpoint.c'), (17, 'tests/device/helpers/s223-udp.c')]:
            target = args.output / ('tcp-endpoint' if protocol == 6 else 'udp-endpoint')
            subprocess.run([compiler, '-Wall', '-Wextra', '-Werror', '-O2', str(ROOT / source), '-o', str(target)], check=True)
            result['endpoints'][target.name] = chain.digest(target)
            for family, address in addresses.items():
                if protocol == 6 and family == 6:
                    ports[6][6] = ports[6][4]
                    continue
                with socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6,
                                   socket.SOCK_STREAM if protocol == 6 else socket.SOCK_DGRAM) as reservation:
                    reservation.bind((address, 0))
                    port = reservation.getsockname()[1]
                assert port <= 65533
                ports[protocol][family] = port
                log = (args.output / (target.name + '-' + str(family) + '.log')).open('w')
                logs.append(log)
                command = [str(target), str(port), addresses[4], addresses[6]] if protocol == 6 else [
                    str(target), 'server', str(os.getuid()), str(family), address, str(port)]
                servers.append(subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT))
        time.sleep(.2)
        assert all(server.poll() is None for server in servers)
        result['ports'] = ports
        for case in cases:
            current = dict(case=case, probes=[], started_ns=time.time_ns())
            result['runs'].append(current)
            old = props(app(STATE))
            assert old.get('mayBeActive') == 'false'
            active = True
            save(case + '/start.txt', action('--ez', 'debugVpnHevValidation', 'true'))
            state = ready(case + '/initial', old.get('generation'))
            current['generation'] = int(state['generation'])
            tcp, udp = launch(case + '/held-tcp', 6, True), launch(case + '/held-udp', 17, True)
            holding(tcp)
            holding(udp)
            before = cli(case + '/active', ['show product flow-stack', 'show product tun', 'show product flows'])
            owners = [dict(re.findall(r'(\w+)=([^\s]+)', line)) for line in before.splitlines()
                      if line.startswith('flow_stack.status ')]
            assert len(owners) == 2 and all(int(o['sessions']) == 4 for o in owners), owners
            save(case + '/native-before.log', app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
            if case == 'underlay':
                current['sim_state'] = save(case + '/sim-state.txt', adb('shell', 'getprop', 'gsm.sim.state')).strip()
                assert current['sim_state'] == 'ABSENT', 'this collector requires a real no-underlay interval'
                current['wifi_before'] = save(case + '/wifi-before.txt', adb('shell', 'settings', 'get', 'global', 'wifi_on')).strip()
                assert current['wifi_before'] == '1'
                save(case + '/networks-before.txt', adb('shell', 'dumpsys', 'connectivity'))
                wifi_disabled = True
                save(case + '/wifi-disable.txt', adb('shell', 'svc', 'wifi', 'disable'))
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    native = save(case + '/native-lost.log', app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
                    # Android may abort TCP sockets before onLost reaches our
                    # callback. Require all eight old transports closed and
                    # both real epoch notifications, not eight identical causes.
                    if (native.count('event=underlay_invalidation ') == 2
                            and native.count('event=session_closing ') == 8):
                        break
                    time.sleep(.1)
                else:
                    raise RuntimeError('old underlay invalidation deadline')
                save(case + '/networks-lost.txt', adb('shell', 'dumpsys', 'connectivity'))
                release(udp)
                holding(udp, 1)  # Same app socket sent a new datagram with no available underlay.
                lost = cli(case + '/lost', ['show product flow-stack', 'show product tun', 'show product flows'])
                owner_states = [dict(re.findall(r'(\w+)=([^\s]+)', line)) for line in lost.splitlines()
                                if line.startswith('flow_stack.status ')]
                assert len(owner_states) == 2 and all(o['sessions'] == '0' for o in owner_states)
                save(case + '/native-unavailable.log', app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
                release(tcp)
                finish(tcp)
                save(case + '/wifi-enable.txt', adb('shell', 'svc', 'wifi', 'enable'))
                wifi_disabled = False
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline:
                    log = save(case + '/android-restored.log', adb('logcat', '-d', '-s', 'SakamotoSocketBroker:I', '*:S'))
                    updates = [dict(re.findall(r'(\w+)=([^\s]+)', line)) for line in log.splitlines()
                               if 's243 underlay ' in line and 'generation=' + state['generation'] + ' ' in line]
                    latest = {int(v['owner']): v for v in updates}
                    if set(latest) == {0, 1} and all(int(v['selected']) > 1 for v in latest.values()):
                        break
                    time.sleep(.1)
                else:
                    raise RuntimeError('new Android underlay deadline')
                save(case + '/networks-restored.txt', adb('shell', 'dumpsys', 'connectivity'))
                if args.underlay_drop:
                    policy(udp, True)
                release(udp, 1)
                if args.underlay_drop:
                    holding(udp, 2)
                    save(case + '/native-drop.log', app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
                    policy(udp, False)
                    release(udp, 2)
                finish(udp)
                current['replacement_generation'] = int(state['generation'])
                current['network_epochs'] = latest
                stable = props(save(case + '/after-replacement.properties', app(STATE)))
                assert stable['generation'] == state['generation'] and stable['state'] == 'running'
                assert not stable.get('errorCode')
                cli(case + '/same-tuple-restored', ['show product flow-stack', 'show product flows'])
            elif case == 'stop':
                stopped = stop(case + '/old')
                assert stopped['generation'] == state['generation']
                active = False
            elif case == 'crash':
                ps = save(case + '/process-before.txt', adb('shell', 'ps', '-A', '-o', 'PID,UID,ARGS'))
                matches = [line.split() for line in ps.splitlines() if 'libvpp_runtime.so -c ' + BASE + 'startup.conf' in line]
                assert len(matches) == 1 and int(matches[0][1]) == result['uid']
                pid = int(matches[0][0])
                assert pid > 1
                executable = save(case + '/executable.txt', adb('shell', 'run-as', PKG, 'readlink', '/proc/' + str(pid) + '/exe'))
                assert executable.strip() == binary
                current['crashed_pid'] = pid
                save(case + '/kill.txt', adb('shell', 'run-as', PKG, 'kill', '-KILL', str(pid)))
            else:
                save(case + '/fault.txt', action('--es', 'runtimeVpnFaultEvent', 'broker_close' + case[-1]))
                save(case + '/fault-foreground.txt', action())
            if case not in ('stop', 'underlay'):
                replacement = ready(case + '/replacement', state['generation'])
                current['replacement_generation'] = int(replacement['generation'])
                save(case + '/old-native-failure.log', app('files/product-state/s237-last-failure.log'))
                save(case + '/recovery-service.log', app('files/logs/runtime-service.log'))
            if case != 'underlay':
                for probe in (tcp, udp):
                    release(probe)
                    finish(probe)
            if case == 'stop':
                save(case + '/restart.txt', action('--ez', 'debugVpnHevValidation', 'true'))
                active = True
                replacement = ready(case + '/replacement', state['generation'])
                current['replacement_generation'] = int(replacement['generation'])
            fresh_tcp = launch(case + '/fresh-tcp', 6, False)
            fresh_udp = launch(case + '/fresh-udp', 17, False)
            finish(fresh_tcp)
            finish(fresh_udp)
            cli(case + '/fresh-complete', ['show product flow-stack', 'show product tun'])
            stopped = stop(case + '/replacement')
            assert int(stopped['generation']) == current['replacement_generation']
            active = False
            save(case + '/service.log', app('files/logs/runtime-service.log'))
            current['completed_ns'] = time.time_ns()
            print('captured active lifecycle: ' + case, flush=True)
        result['status'] = 'CAPTURE_COMPLETE'
    except Exception as error:
        result['error'] = repr(error)
        save('failure-state.txt', app(STATE))
        save('failure-native.log', app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
        raise
    finally:
        if wifi_disabled:
            try:
                save('cleanup-wifi-enable.txt', adb('shell', 'svc', 'wifi', 'enable'))
            except Exception as error:
                result.setdefault('cleanup_errors', []).append(repr(error))
        for probe in held[:]:
            try:
                release(probe)
                if any(p.get('underlaySequence') for p in probe['plan']):
                    release(probe, 1)
                    release(probe, 2)
                finish(probe)
            except Exception as error:
                result.setdefault('cleanup_errors', []).append(repr(error))
        if active:
            try:
                stop('cleanup')
            except Exception as error:
                result.setdefault('cleanup_errors', []).append(repr(error))
        if remote_helper:
            save('helper-cleanup.txt', adb('shell', 'rm', '-f', remote_helper))
        for path in policy_paths:
            assert re.fullmatch(r'/data/local/tmp/s243-policy-state-[0-9]+', path)
            save('policy-cleanup.txt', adb('shell', 'su', '-c', shlex.quote('rm -rf -- ' + path)))
        for server in servers:
            server.terminate()
            try:
                server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
                result['endpoint_forced_stop'] = True
        for log in logs:
            log.close()
        save('service.log', app('files/logs/runtime-service.log'))
        save('android.log', adb('logcat', '-d', '-s', 'SakamotoSocketBroker:I', 'SakamotoNetwork:I', '*:S'))
        if chain.source_files() != build['files']:
            result['product_source_changed'] = True
        if any(chain.digest(ROOT / name) != value for name, value in result['test_inputs'].items()):
            result['test_source_changed'] = True
        result['completed_ns'] = time.time_ns()
        save('result.json', json.dumps(result, indent=2) + '\n')
    assert result['status'] == 'CAPTURE_COMPLETE' and not result.get('cleanup_errors')
    print(json.dumps(dict(status=result['status'], run=str(args.output), cases=cases), indent=2))


if __name__ == '__main__':
    main()
