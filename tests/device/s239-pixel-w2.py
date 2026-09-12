#!/usr/bin/env python3
"""Controlled real-app W2 UDP matrix; independent verification is separate."""
import argparse
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
import importlib.util

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
    parser.add_argument('--ipv4', required=True)
    parser.add_argument('--ipv6', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', choices=['concurrent', 'quota0', 'quota1', 'stop0', 'stop1', 'notify', 'doze'], required=True)
    a = parser.parse_args()
    chain = module('chain', 'tests/evidence/product_chain.py')
    oracle = module('oracle', 'tests/device/s207-owner-oracle.py')
    build = json.loads(a.build.read_text())
    assert chain.source_files() == build['files'], 'source no longer matches APK'
    assert chain.digest(build['apk']) == build['apk_sha256']
    a.output.mkdir(parents=True, exist_ok=False)
    result = dict(status='HOLD', scope='real-app-w2-dual-stack', case=a.case,
                  started_ns=time.time_ns(), build_sha256=chain.digest(a.build),
                  apk_sha256=build['apk_sha256'], serial=SERIAL)
    sources = ['tests/device/s239-pixel-w2.py', 'tests/device/s207-owner-oracle.py',
               'tests/device/helpers/s223-udp.c', 'tests/evidence/product_chain.py']
    if a.case == 'notify':
        sources.append('tests/device/s239-notify-observer.py')
    result['test_inputs'] = {name: chain.digest(ROOT / name) for name in sources}
    for name in sources:
        target = a.output / 'test-source' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)

    def save(name, text):
        (a.output / name).write_text(text)
        return text

    def adb(*args, check=True):
        r = subprocess.run([str(ROOT / 'dev/adb'), '-s', SERIAL, *args],
                           capture_output=True, text=True, errors='replace', timeout=30)
        if check and r.returncode:
            raise RuntimeError(r.stdout + r.stderr)
        return (r.stdout + r.stderr).replace('\r', '')

    def app(path):
        return adb('shell', 'run-as', PKG, 'cat', path, check=False)

    def props(text):
        return dict(line.split('=', 1) for line in text.splitlines()
                    if '=' in line and not line.startswith('#'))

    def action(*args):
        return adb('shell', 'am', 'start', '-n', PKG + '/.DebugControlActivity', *args)

    def wait_state(name, wanted):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            text = save(name + '.poll', app(STATE))
            values = props(text)
            if all(values.get(k) == v for k, v in wanted.items()):
                save(name + '.properties', text)
                return values
            if values.get('state') == 'error' and values.get('generation') != previous.get('generation'):
                raise RuntimeError(str(values))
            time.sleep(.2)
        raise RuntimeError('state deadline: ' + str(values))

    def cli(name, commands):
        command = "printf '%s\\n' " + ' '.join(shlex.quote(c) for c in
            ['set terminal pager off', *commands, 'quit']) + ' | toybox nc -U -w 2 -q 1 ' + BASE + 'runtime/cli.sock'
        return save(name + '.txt', adb('shell', 'su', '-c', shlex.quote(command)))

    def launch(name, plan):
        nonce = 'Es239-' + str(time.time_ns())
        result.setdefault('probes', []).append(dict(name=name, nonce=nonce, plan=plan))
        save(name + '-send.txt', action('--es', 's239ProbeNonce', nonce,
            '--es', 's239ProbePlan', shlex.quote(json.dumps(plan, separators=(',', ':')))))
        # The traffic generator lives in the UI process, not :runtime. Keep its
        # ordinary Activity visible during sustained traffic; otherwise Android
        # may freeze that cached process while the VPN service remains healthy.
        save(name + '-foreground.txt', action())
        return nonce

    def wait_probe(name, nonce):
        deadline = time.monotonic() + 105
        while time.monotonic() < deadline:
            try:
                text = app('files/product-state/s239-probe.json')
                report = json.loads(text)
                if report.get('nonce') == nonce:
                    save(name + '.json', text)
                    assert 'error' not in report and all('error' not in f for f in report['flows']), report
                    return report
            except json.JSONDecodeError:
                pass
            time.sleep(.5)
        raise RuntimeError('probe deadline: ' + name)

    def require_echo(report, plan):
        for flow, config in zip(report['flows'], plan):
            assert flow['sent'] == flow['echoes'] == config['packets'], flow
            assert flow['wrong'] == flow['duplicates'] == 0, flow

    servers, logs, active = [], [], False
    power_changed = False
    try:
        previous = props(save('previous-state.txt', app(STATE)))
        assert previous.get('mayBeActive') == 'false', 'existing runtime is active'
        save('install.txt', adb('install', '-r', build['apk']))
        package = save('package.txt', adb('shell', 'dumpsys', 'package', PKG))
        code = re.search(r'codePath=(\S+)', package).group(1)
        installed = save('installed-apk.txt', adb('shell', 'sha256sum', code + '/base.apk'))
        assert installed.split()[0] == build['apk_sha256']
        hashes = save('installed-native.txt', adb('shell', 'sha256sum',
            *[code + '/lib/arm64/' + n for n in sorted(build['native_sha256'])]))
        assert {Path(line.split()[1]).name: line.split()[0] for line in hashes.splitlines()} == build['native_sha256']
        save('device.txt', adb('shell', 'uname', '-a'))
        result['uid'] = int(adb('shell', 'run-as', PKG, 'id', '-u').strip())
        helper = a.output / 'udp-endpoint'
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-O2',
                        str(ROOT / sources[2]), '-o', str(helper)], check=True)
        result['endpoint_sha256'] = chain.digest(helper)
        flows = []
        for family, address in [(4, a.ipv4), (6, a.ipv6)]:
            endpoint = ipaddress.ip_address(address)
            assert endpoint.version == family and not (endpoint.is_loopback or endpoint.is_unspecified
                or endpoint.is_link_local or endpoint.is_multicast)
            with socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_DGRAM) as reservation:
                reservation.bind((address, 0))
                port = reservation.getsockname()[1]
            log = (a.output / f'endpoint{family}.log').open('w')
            logs.append(log)
            servers.append(subprocess.Popen([str(helper.resolve()), 'server', str(os.getuid()),
                str(family), address, str(port)], stdout=log, stderr=subprocess.STDOUT))
            tun = ipaddress.ip_address('10.111.0.2' if family == 4 else 'fd00:111:111::2')
            for owner in (0, 1):
                for source in range(43000 + family * 100 + owner * 40, 43040 + family * 100 + owner * 40):
                    facts = dict(l3=1, l4=1, family=family, protocol=17,
                        src=tun.packed.rjust(16, b'\0').hex(), dst=endpoint.packed.rjust(16, b'\0').hex(),
                        src_port=source, dst_port=port, icmp_known=0)
                    if oracle.owner(facts) == owner:
                        break
                else:
                    raise RuntimeError('no canonical source port')
                flows.append(dict(address=address, port=port, source=source,
                                  owner=owner, family=family, packets=3, intervalMs=100))
        result['flows'] = flows
        active = True
        save('start.txt', action('--ez', 'debugVpnHevValidation', 'true'))
        state = wait_state('running', dict(state='running', profile='vpn', errorCode=''))
        result['generation'] = int(state['generation'])
        before = cli('before', ['product packet-trace limit 4096', 'show product flow-stack',
                                'show product tun', 'show threads'])
        assert 'packet.trace_limit=4096' in before
        assert all(f'enabled=1 owner={i} ready=1' in before for i in (0, 1))
        assert all(server.poll() is None for server in servers)
        if a.case in ('concurrent', 'notify', 'doze'):
            plan = [dict(flow, packets=10 if index == 0 else 330,
                         intervalMs=100 if index == 0 else 200)
                    for index, flow in enumerate(flows)]
            observer = None
            if a.case == 'doze':
                assert adb('shell', 'cmd', 'deviceidle', 'get', 'force').strip() == 'false'
                assert adb('shell', 'cmd', 'deviceidle', 'get', 'screen').strip() == 'true'
                save('power-before.txt', adb('shell', 'dumpsys', 'power'))
                save('idle-before.txt', adb('shell', 'dumpsys', 'deviceidle'))
                plan = [dict(flow, packets=50, intervalMs=500) for flow in flows]
            if a.case == 'notify':
                plan = [dict(flow, packets=12, intervalMs=10) for flow in flows]
                pid = int(re.search(r'^0\s+vpp_main\s+(\d+)', before, re.M).group(1))
                maps = save('native-maps.txt', adb('shell', 'su', '-c', shlex.quote(f'cat /proc/{pid}/maps')))
                library = next(line.split()[-1] for line in maps.splitlines() if line.endswith('/libvlib.so'))
                files = cli('native-files', ['show files'])
                wake_fds = {}
                for line in files.splitlines():
                    if 'wakeup thread ' in line:
                        columns = line.split()
                        wake_fds[int(columns[-1])] = int(columns[0])
                assert set(wake_fds) == {0, 1, 2}, files
                observer = module('notify_observer', 'tests/device/s239-notify-observer.py').NativeTrace(
                    a.output, build, pid, result['generation'], library, wake_fds)
            nonce = launch(a.case, plan)
            time.sleep(5)
            if a.case == 'doze':
                # Temporary controlled power-policy test. No whitelist, battery
                # simulation or persistent device setting is changed.
                power_changed = True
                save('screen-off.txt', adb('shell', 'input', 'keyevent', '223'))
                save('force-idle.txt', adb('shell', 'cmd', 'deviceidle', 'force-idle', 'deep'))
                assert save('idle-confirmed.txt', adb('shell', 'cmd', 'deviceidle', 'get', 'deep')).strip() == 'IDLE'
                save('power-idle.txt', adb('shell', 'dumpsys', 'power'))
                time.sleep(10)
                assert save('idle-end.txt', adb('shell', 'cmd', 'deviceidle', 'get', 'deep')).strip() == 'IDLE'
                save('unforce.txt', adb('shell', 'cmd', 'deviceidle', 'unforce'))
                save('screen-on.txt', adb('shell', 'input', 'keyevent', '224'))
                assert adb('shell', 'cmd', 'deviceidle', 'get', 'force').strip() == 'false'
                power_changed = False
                save('power-restored.txt', adb('shell', 'dumpsys', 'power'))
                save('idle-restored.txt', adb('shell', 'dumpsys', 'deviceidle'))
            cli('during', ['show product flow-stack', 'show product tun'])
            report = wait_probe(a.case, nonce)
            require_echo(report, plan)
            if observer:
                time.sleep(2)
                tids = [int(re.search(r'^' + str(i + 1) + r'\s+vpp_wk_' + str(i)
                                     + r'\s+workers\s+(\d+)', before, re.M).group(1)) for i in (0, 1)]
                quiet = save('native-quiet.wchan', adb('shell', 'su', '-c',
                    shlex.quote('cat ' + ' '.join(f'/proc/{pid}/task/{tid}/wchan' for tid in tids))))
                assert quiet.count('epoll') + quiet.count('ep_poll') >= 2, quiet
                last_plan = [dict(flows[1], packets=1, intervalMs=0)]
                last_nonce = launch('after-quiet', last_plan)
                require_echo(wait_probe('after-quiet', last_nonce), last_plan)
                result['notification_trace'] = observer.finish()
            elif a.case == 'concurrent':
                early = report['flows'][0]
                assert all(f['lastEchoMs'] > early['endMs'] + 60000 for f in report['flows'][1:])
        else:
            warm = launch('warm', flows)
            require_echo(wait_probe('warm', warm), flows)
            cli('warm-after', ['show product flow-stack', 'show product tun'])
            selected = int(a.case[-1])
            plan = [dict(flows[selected], packets=160, burst=True, intervalMs=2),
                    dict(flows[1 - selected], packets=20, intervalMs=100)]
            armed = cli('hold', [f'product tun return-hold {selected} 10000'])
            assert f'tun.return_hold owner={selected} milliseconds=10000' in armed
            nonce = launch('quota', plan)
            time.sleep(2.5)
            mid = cli('held', ['show product flow-stack', 'show product tun'])
            rows = {int(m['owner']): m for line in mid.splitlines() if line.startswith('tun.return ')
                    for m in [dict(re.findall(r'(\w+)=([^\s]+)', line))]}
            assert rows[selected]['in_use'] == rows[selected]['capacity'] == '128', rows
            assert rows[1 - selected]['in_use'] == '0', rows
            result['held_rows'] = rows
            if a.case.startswith('quota'):
                report = wait_probe('quota', nonce)
                assert report['flows'][0]['sent'] == 160
                assert report['flows'][0]['echoes'] == 128, report
                require_echo(dict(flows=report['flows'][1:]), plan[1:])
                assert report['flows'][1]['endMs'] < report['flows'][0]['lastEchoMs'], report
                recovery = launch('recovery', flows)
                require_echo(wait_probe('recovery', recovery), flows)
        cli('after', ['show product flow-stack', 'show product tun', 'show runtime'])
        save('vpp.log', app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
        result['status'] = 'WITNESS_COMPLETE'
    except Exception as error:
        result['error'] = repr(error)
        save('failure-state.txt', app(STATE))
        save('failure-vpp.log', app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
        raise
    finally:
        if power_changed:
            try:
                save('cleanup-unforce.txt', adb('shell', 'cmd', 'deviceidle', 'unforce'))
                save('cleanup-screen-on.txt', adb('shell', 'input', 'keyevent', '224'))
                save('cleanup-power.txt', adb('shell', 'dumpsys', 'power'))
            except Exception as error:
                result['power_cleanup_error'] = repr(error)
                result['status'] = 'HOLD'
        if active:
            try:
                save('stop.txt', action('--ez', 'runtimeStop', 'true'))
                wait_state('stopped', dict(state='stopped', mayBeActive='false', errorCode=''))
                save('native-stop.log', app('files/product-state/s237-last-stop.log'))
                save('processes-after.txt', adb('shell', 'ps', '-A', '-o', 'PID,UID,ARGS'))
                if a.case.startswith('stop') and result.get('status') == 'WITNESS_COMPLETE':
                    wait_probe('quota', nonce)
            except Exception as error:
                result['cleanup_error'] = repr(error)
                result['status'] = 'HOLD'
        for server in servers:
            server.terminate()
            try:
                server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
        for log in logs:
            log.close()
        result['finished_ns'] = time.time_ns()
        save('result.json', json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ('probes', 'test_inputs')}, indent=2))
    if result['status'] != 'WITNESS_COMPLETE':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
