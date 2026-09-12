#!/usr/bin/env python3
"""Real Pixel supervisor lifecycle evidence; no packet-transport PASS claim."""
import argparse
import importlib.util
import ipaddress
import json
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ipv4')
    parser.add_argument('--ipv6')
    parser.add_argument('--startup-failure', action='store_true')
    args = parser.parse_args()
    assert bool(args.ipv4) == bool(args.ipv6)
    spec = importlib.util.spec_from_file_location('chain243', ROOT / 'tests/evidence/product_chain.py')
    chain = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(chain)
    build = json.loads(args.build.read_text())
    assert chain.source_files() == build['files'], 'Product source differs from APK'
    assert chain.digest(build['apk']) == build['apk_sha256']
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    result = dict(scope='real-Pixel-supervisor-only', status='HOLD', serial=SERIAL,
                  started_ns=time.time_ns(), build_sha256=chain.digest(args.build),
                  apk_sha256=build['apk_sha256'], events=[])
    result['crash_log_since'] = time.strftime('%m-%d %H:%M:%S.000')
    names = ['tests/device/s243-pixel-recovery.py', 'tests/evidence/product_chain.py']
    if args.ipv4:
        names.append('tests/device/helpers/s207-echo.c')
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

    def wait(label, predicate, timeout=45, capture_native=True):
        deadline = time.monotonic() + timeout
        samples = []
        while time.monotonic() < deadline:
            text = save(label + '.poll', app(STATE))
            values = props(text)
            samples.append(dict(at_ns=time.time_ns(), state=values))
            save(label + '-samples.json', json.dumps(samples, indent=2))
            if capture_native and values.get('generation'):
                native = app('files/profiles/vpn/vpp/logs/vpp-stdout.log')
                if 's237' in native or 'vlib' in native or 'error' in native.lower():
                    save('generations/' + values['generation'] + '-startup.log', native)
            if predicate(values):
                save(label + '.properties', text)
                result['events'].append(dict(label=label, at_ns=time.time_ns(), state=values))
                print(label + ': ' + values.get('state', '?') + ' generation=' +
                      values.get('generation', '?') + ' error=' + values.get('errorCode', ''), flush=True)
                return values
            time.sleep(.05 if not capture_native else .2)
        raise RuntimeError('state deadline ' + label + ': ' + str(values))

    def cli(label, commands):
        text = "printf '%s\\n' " + ' '.join(shlex.quote(c) for c in
                ['set terminal pager off', *commands, 'quit'])
        text += ' | toybox nc -U -w 2 -q 1 ' + BASE + 'runtime/cli.sock'
        return save(label + '.txt', adb('shell', 'su', '-c', shlex.quote(text)))

    def start(label):
        old = props(app(STATE))
        assert old.get('mayBeActive') == 'false'
        save(label + '-start.txt', action('--ez', 'debugVpnHevValidation', 'true'))
        current = wait(label, lambda s: s.get('state') == 'running' and
                       s.get('generation') != old.get('generation') and not s.get('errorCode'))
        assert current['profile'] == 'vpn' and current['protectionRunning'] == 'false'
        text = cli(label + '-ready', ['show threads', 'show product flow-stack', 'show product tun'])
        assert all(f'enabled=1 owner={i} ready=1' in text for i in (0, 1))
        return current

    def crash(label):
        processes = save(label + '-process-before.txt', adb('shell', 'ps', '-A', '-o', 'PID,UID,ARGS'))
        matches = [line.split() for line in processes.splitlines()
                   if 'libvpp_runtime.so -c ' + BASE + 'startup.conf' in line]
        assert len(matches) == 1, matches
        pid, uid = int(matches[0][0]), int(matches[0][1])
        assert pid > 1 and uid == result['uid']
        executable = save(label + '-executable.txt',
                          adb('shell', 'run-as', PKG, 'readlink', '/proc/' + str(pid) + '/exe')).strip()
        assert executable == binary
        result['events'].append(dict(label=label, at_ns=time.time_ns(), pid=pid, uid=uid))
        save(label + '-kill.txt', adb('shell', 'run-as', PKG, 'kill', '-KILL', str(pid)))

    def no_restart(label, generation):
        deadline = time.monotonic() + 3
        observations = []
        while time.monotonic() < deadline:
            value = props(app(STATE))
            observations.append(dict(at_ns=time.time_ns(), state=value))
            assert value.get('generation') == generation and value.get('mayBeActive') == 'false', value
            time.sleep(.2)
        save(label + '-stable.json', json.dumps(observations, indent=2))
        processes = save(label + '-process-after.txt', adb('shell', 'ps', '-A', '-o', 'PID,UID,ARGS'))
        assert 'libvpp_runtime.so' not in processes
        save(label + '-vpn.txt', adb('shell', 'dumpsys', 'vpn_management'))

    def stop(label):
        save(label + '-stop.txt', action('--ez', 'runtimeStop', 'true'))
        return wait(label, lambda s: s.get('state') == 'stopped' and
                    s.get('mayBeActive') == 'false' and s.get('errorCode') == '')

    def ordinary_connectivity(label, generation):
        if not args.ipv4:
            return
        addresses = {4: str(ipaddress.IPv4Address(args.ipv4)), 6: str(ipaddress.IPv6Address(args.ipv6))}
        for address in addresses.values():
            ip = ipaddress.ip_address(address)
            assert not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified)
        lockdown = save(label + '/lockdown.txt', adb('shell', 'settings', 'get', 'secure', 'always_on_vpn_lockdown')).strip()
        assert lockdown in ('0', 'null'), 'ordinary connectivity cannot be promised under Android lockdown'
        helper = args.output / 'ordinary-endpoint'
        if not helper.exists():
            compiler = shutil.which('cc')
            subprocess.run([compiler, '-Wall', '-Wextra', '-Werror', '-O2',
                            str(ROOT / 'tests/device/helpers/s207-echo.c'), '-o', str(helper)], check=True)
            result['ordinary_helper'] = dict(sha256=chain.digest(helper), compiler=compiler,
                                             compiler_sha256=chain.digest(compiler))
        with socket.socket() as reservation:
            reservation.bind((addresses[4], 0))
            port = reservation.getsockname()[1]
        log = (args.output / (label + '-endpoint.log')).open('w')
        peer = subprocess.Popen([str(helper), str(port), addresses[4], addresses[6]],
                                stdout=log, stderr=subprocess.STDOUT)
        try:
            time.sleep(.2)
            assert peer.poll() is None
            probes = []
            for family, address in addresses.items():
                for protocol in ('tcp', 'udp'):
                    nonce = 'ordinary-' + str(time.time_ns())
                    prefix = 'debugTraffic' if protocol == 'tcp' else 'debugUdp'
                    flag = 'debugTraffic' if protocol == 'tcp' else 'debugUdpTraffic'
                    extra = ['--ez', flag, 'true', '--es', prefix + 'Host', address,
                             '--ei', prefix + 'Port', str(port), '--ei', prefix + 'SourcePort', str(59000 + len(probes)),
                             '--es', prefix + 'Nonce', nonce, '--ei', prefix + 'TimeoutMillis', '3000',
                             '--ez', 'debugTrafficBindToVpn', 'false']
                    if protocol == 'udp':
                        extra += ['--ez', 'debugUdpExpectReply', 'true']
                    name = label + '/' + protocol + str(family)
                    save(name + '-launch.txt', action(*extra))
                    save(name + '-foreground.txt', action())
                    path = 'files/debug/' + ('traffic-probe.properties' if protocol == 'tcp' else 'udp-traffic-probe.properties')
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        text = save(name + '.poll', app(path))
                        values = props(text)
                        if values.get('nonce') == nonce:
                            break
                        time.sleep(.1)
                    assert values.get('nonce') == nonce and values['result'] == protocol + '_echo_matched', values
                    assert values['bindToVpn'] == 'false' and values['bindResult'] == 'not_requested'
                    assert int(values['uid']) == result['uid']
                    save(name + '.properties', text)
                    value = props(save(name + '-runtime.properties', app(STATE)))
                    assert value['generation'] == generation and value['mayBeActive'] == 'false'
                    probes.append(dict(name=name, nonce=nonce, protocol=protocol, family=family, address=address, port=port))
            result.setdefault('ordinary_connectivity', []).append(dict(label=label, generation=generation, probes=probes))
        finally:
            peer.terminate()
            peer.wait(timeout=3)
            log.close()

    active = False
    try:
        previous = props(save('previous-state.txt', app(STATE)))
        assert previous.get('mayBeActive') == 'false'
        package = save('package.txt', adb('shell', 'dumpsys', 'package', PKG))
        code = re.search(r'codePath=(\S+)', package).group(1)
        native = code + '/lib/arm64'
        binary = native + '/libvpp_runtime.so'
        installed = save('installed-apk.txt', adb('shell', 'sha256sum', code + '/base.apk'))
        assert installed.split()[0] == build['apk_sha256']
        installed = save('installed-native.txt', adb('shell', 'sha256sum',
                        *[native + '/' + n for n in sorted(build['native_sha256'])]))
        assert {Path(line.split()[1]).name: line.split()[0] for line in installed.splitlines()} == build['native_sha256']
        save('device.txt', adb('shell', 'uname', '-a'))
        result['uid'] = int(adb('shell', 'run-as', PKG, 'id', '-u').strip())
        active = True
        initial = start('initial')
        crash('first-crash')
        restarted = wait('automatic-restart', lambda s: s.get('state') == 'running' and
                         s.get('generation') != initial['generation'] and not s.get('errorCode'))
        save('first-failure.log', app('files/product-state/s237-last-failure.log'))
        cli('restarted-ready', ['show product flow-stack', 'show product tun'])
        crash('second-crash')
        exhausted = wait('exhausted', lambda s: s.get('mayBeActive') == 'false' and
                         s.get('errorCode') == 'runtime_recovery_intervention_required')
        assert exhausted['generation'] == restarted['generation']
        save('second-failure.log', app('files/product-state/s237-last-failure.log'))
        no_restart('exhausted', exhausted['generation'])
        ordinary_connectivity('after-exhaustion', exhausted['generation'])
        stopped = stop('clear-terminal-error')
        assert stopped['generation'] == exhausted['generation']
        reset = start('explicit-retry')
        crash('cancelled-crash')
        pending = wait('pending-before-stop', lambda s: s.get('errorCode') ==
                       'runtime_auto_recovery_pending', timeout=10, capture_native=False)
        assert pending['generation'] == reset['generation']
        stopped = stop('cancel-recovery')
        assert stopped['generation'] == reset['generation']
        no_restart('cancel-recovery', stopped['generation'])
        if args.startup_failure:
            save('startup-failure-start.txt', action('--ez', 'debugVpnHevValidation', 'true',
                 '--es', 'debugVpnHevLimits', '0,3,1,1,1'))
            failed = wait('startup-failure-exhausted', lambda s: s.get('mayBeActive') == 'false' and
                          s.get('errorCode') == 'runtime_recovery_intervention_required')
            assert int(failed['generation']) == int(stopped['generation']) + 2
            assert 'runtime_start_failed' in failed['errorMessage']
            no_restart('startup-failure-exhausted', failed['generation'])
            ordinary_connectivity('after-startup-failure', failed['generation'])
            result['startup_failure'] = dict(previous_generation=stopped['generation'], generation=failed['generation'])
            stop('clear-startup-error')
        active = False
        result['status'] = 'CAPTURE_COMPLETE'
    except Exception as error:
        result['error'] = repr(error)
        save('failure-state.txt', app(STATE))
        save('failure-native.log', app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
        raise
    finally:
        if active:
            try:
                stop('cleanup')
            except Exception as error:
                result['cleanup_error'] = repr(error)
        save('service.log', app('files/logs/runtime-service.log'))
        save('android.log', adb('logcat', '-d', '-s', 'SakamotoRuntime:I',
                               'SakamotoSocketBroker:I', 'SakamotoNetwork:I', '*:S'))
        save('crash.log', adb('logcat', '-b', 'crash', '-d', '-T',
                              result['crash_log_since'], check=False))
        if chain.source_files() != build['files']:
            result['product_source_changed'] = True
        if any(chain.digest(ROOT / name) != digest for name, digest in result['test_inputs'].items()):
            result['test_source_changed'] = True
        result['completed_ns'] = time.time_ns()
        save('result.json', json.dumps(result, indent=2) + '\n')
    assert result['status'] == 'CAPTURE_COMPLETE' and not result.get('cleanup_error')
    print(json.dumps(dict(status=result['status'], run=str(args.output)), indent=2))


if __name__ == '__main__':
    main()
