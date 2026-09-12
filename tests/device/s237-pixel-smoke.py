#!/usr/bin/env python3
"""Fresh Product UDP4 app/TUN/HEV/Android-broker/underlay echo witness.

This is one smoke case, not the complete S237 failure/stop acceptance matrix.
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
import zipfile

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
    parser.add_argument('--endpoint-address', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fault', choices=['none', 'input-reject', 'output-alloc', 'pre-accept', 'write', 'stale-output'], default='none')
    parser.add_argument('--return-drop', action='store_true')
    parser.add_argument('--overlap-stop', action='store_true')
    parser.add_argument('--unknown-identity', action='store_true')
    parser.add_argument('--unknown-context', action='store_true')
    parser.add_argument('--owner', type=int, choices=[0, 1], default=0)
    parser.add_argument('--verify-sleep', action='store_true',
                        help='Observe selected worker in epoll before the probe; no CLI wake during this window')
    parser.add_argument('--diagnostic-clear-stale-iif', action='store_true',
                        help='Authorized UID 12632/interface 952 diagnosis only; not acceptance')
    a = parser.parse_args()
    assert not a.return_drop or a.fault == 'none'
    assert not a.overlap_stop or (a.fault == 'none' and not a.return_drop)
    endpoint_ip = ipaddress.ip_address(a.endpoint_address)
    assert not (endpoint_ip.is_loopback or endpoint_ip.is_unspecified
                or endpoint_ip.is_link_local or endpoint_ip.is_multicast)
    family = endpoint_ip.version
    tun_ip = ipaddress.ip_address('10.111.0.2' if family == 4 else 'fd00:111:111::2')
    chain = module('chain', 'tests/evidence/product_chain.py')
    build = json.loads(a.build.read_text())
    assert chain.source_files() == build['files'], 'source no longer matches APK'
    assert chain.digest(build['apk']) == build['apk_sha256']
    a.output.mkdir(parents=True, exist_ok=False)
    def save(name, text):
        (a.output / name).write_text(text)
        return text
    def adb(*args, check=True):
        r = subprocess.run([str(ROOT / 'dev/adb'), '-s', SERIAL, *args],
            capture_output=True, text=True, errors='replace', timeout=30)
        if check and r.returncode: raise RuntimeError(r.stdout + r.stderr)
        return (r.stdout + r.stderr).replace('\r', '')
    def app(path): return adb('shell', 'run-as', PKG, 'cat', path, check=False)
    def props(text): return dict(line.split('=', 1) for line in text.splitlines()
                                 if '=' in line and not line.startswith('#'))
    def action(*args): return adb('shell', 'am', 'start', '-n', PKG + '/.DebugControlActivity', *args)
    def wait(name, path, wanted):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            text = save(name + '.poll', app(path)); values = props(text)
            if (wanted.get('state') == 'running' and values.get('state') == 'error'
                    and values.get('generation') != previous.get('generation')):
                raise RuntimeError(name + ': ' + str(values))
            if all(values.get(k) == v for k, v in wanted.items()):
                save(name + '.properties', text); return values
            time.sleep(.2)
        raise RuntimeError(name + ': ' + str(values))
    def cli(name, commands):
        command = "printf '%s\\n' " + ' '.join(shlex.quote(c) for c in
            ['set terminal pager off', *commands, 'quit']) + ' | toybox nc -U -w 2 -q 1 ' + BASE + 'runtime/cli.sock'
        return save(name + '.txt', adb('shell', 'su', '-c', shlex.quote(command)))

    result = dict(status='HOLD', scope='single-active-owner-udp4-smoke',
                  fault=a.fault,
                  identity_available=not a.unknown_identity, context_available=not a.unknown_context,
                  started_ns=time.time_ns(), build_sha256=chain.digest(a.build),
                  apk_sha256=build['apk_sha256'], serial=SERIAL)
    result['diagnostic_clear_stale_iif'] = a.diagnostic_clear_stale_iif
    result['family'] = family
    result['owner'] = a.owner
    result['verify_sleep'] = a.verify_sleep
    test_inputs = ['tests/device/s237-pixel-smoke.py', 'tests/device/s207-owner-oracle.py',
                   'tests/device/helpers/s223-udp.c', 'tests/device/helpers/s217-policy.c',
                   'tests/evidence/product_chain.py', 'tests/device/verify-s237.py']
    result['test_inputs'] = {name: chain.digest(ROOT / name) for name in test_inputs}
    for name in test_inputs:
        destination = a.output / 'test-source' / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, destination)
    server = None
    active = False
    log = None
    try:
        previous = props(save('previous-state.txt', app(STATE)))
        assert previous.get('mayBeActive') == 'false', 'stop the existing runtime before this test'
        save('install.txt', adb('install', '-r', build['apk']))
        package = save('package.txt', adb('shell', 'dumpsys', 'package', PKG))
        code = re.search(r'codePath=(\S+)', package).group(1)
        native = code + '/lib/arm64'
        save('installed-apk.txt', adb('shell', 'sha256sum', code + '/base.apk'))
        assert (a.output / 'installed-apk.txt').read_text().split()[0] == build['apk_sha256']
        hashes = save('installed-native.txt', adb('shell', 'sha256sum',
            *[native + '/' + n for n in sorted(build['native_sha256'])]))
        assert {Path(line.split()[1]).name: line.split()[0] for line in hashes.splitlines()} == build['native_sha256']
        with zipfile.ZipFile(build['apk']) as apk:
            notices = apk.read('assets/hev-notices.txt')
            assert b'Swedish Institute of Computer Science' in notices
            result['notices_sha256'] = hashlib.sha256(notices).hexdigest()
        save('device.txt', adb('shell', 'uname', '-a'))
        save('network.txt', adb('shell', 'ip', '-4', 'route'))
        result['uid'] = int(adb('shell', 'run-as', PKG, 'id', '-u').strip())
        helper = a.output / 'udp-endpoint'
        source = ROOT / 'tests/device/helpers/s223-udp.c'
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-O2', str(source), '-o', str(helper)], check=True)
        result['endpoint_source_sha256'] = chain.digest(source)
        result['endpoint_sha256'] = chain.digest(helper)
        with socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_DGRAM) as reservation:
            reservation.bind((str(endpoint_ip), 0)); endpoint_port = reservation.getsockname()[1]
        log = (a.output / 'endpoint.log').open('w')
        server = subprocess.Popen([str(helper.resolve()), 'server', str(os.getuid()), str(family),
            str(endpoint_ip), str(endpoint_port)], stdout=log, stderr=subprocess.STDOUT)
        oracle = module('oracle', 'tests/device/s207-owner-oracle.py')
        for port in range(42000, 42100):
            facts = dict(l3=1, l4=1, family=family, protocol=17,
                src=tun_ip.packed.rjust(16, b'\0').hex(),
                dst=endpoint_ip.packed.rjust(16, b'\0').hex(), src_port=port,
                dst_port=endpoint_port, icmp_known=0)
            if oracle.owner(facts) == a.owner: break
        else: raise RuntimeError('no source port for requested canonical owner')
        result.update(endpoint=str(endpoint_ip), endpoint_port=endpoint_port, source_port=port)
        active = True
        save('start.txt', action('--ez', 'debugVpnHevValidation', 'true',
            '--ez', 'debugVpnHevUnknownIdentity', str(a.unknown_identity).lower(),
            '--ez', 'debugVpnHevUnknownContext', str(a.unknown_context).lower()))
        state = wait('running', STATE, dict(state='running', profile='vpn',
                     protectionRunning='false', errorCode=''))
        result['generation'] = int(state['generation'])
        if a.diagnostic_clear_stale_iif:
            assert result['uid'] == 12632
            save('diagnostic-iif-before.txt', adb('shell', 'su', '-c',
                shlex.quote('/data/local/tmp/s237-clear-stale-iif')))
            save('diagnostic-iif-clear.txt', adb('shell', 'su', '-c',
                shlex.quote('/data/local/tmp/s237-clear-stale-iif --clear-authorized')))
        cli('before', ['show product flow-stack', 'show product tun', 'show threads'])
        assert all(f'enabled=1 owner={i} ready=1' in (a.output / 'before.txt').read_text()
                   for i in (0, 1))
        if a.fault != 'none':
            armed = cli('fault', [f'product tun fault owner {a.owner} ' + a.fault + ' 2'])
            assert 'tun.fault armed=' in armed
        if a.verify_sleep:
            before_text = (a.output / 'before.txt').read_text()
            pid = int(re.search(r'^0\s+vpp_main\s+(\d+)', before_text, re.M).group(1))
            tid = int(re.search(r'^' + str(a.owner + 1) + r'\s+vpp_wk_' + str(a.owner)
                                + r'\s+workers\s+(\d+)', before_text, re.M).group(1))
            # Kernel observation does not execute a VPP CLI command or barrier.
            stat_command = shlex.quote(f'cat /proc/{pid}/stat /proc/{pid}/task/{tid}/stat')
            before_stats = save('idle-before.stat', adb('shell', 'su', '-c', stat_command))
            idle_begin = time.monotonic_ns()
            time.sleep(2)
            after_stats = save('idle-after.stat', adb('shell', 'su', '-c', stat_command))
            idle_end = time.monotonic_ns()
            def cpu_ticks(text):
                rows = [line.split(') ', 1)[1].split() for line in text.splitlines()]
                assert len(rows) == 2
                return [int(row[11]) + int(row[12]) for row in rows]
            first_ticks, last_ticks = cpu_ticks(before_stats), cpu_ticks(after_stats)
            result['idle_diagnostic'] = dict(elapsed_ns=idle_end - idle_begin,
                process_cpu_ticks=last_ticks[0] - first_ticks[0],
                selected_worker_cpu_ticks=last_ticks[1] - first_ticks[1],
                claim='short diagnostic sample, not formal CPU or energy qualification')
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                wchan = save('worker-before-probe.wchan', adb('shell', 'su', '-c',
                    shlex.quote(f'cat /proc/{pid}/task/{tid}/wchan'))).strip()
                if 'ep_poll' in wchan or 'epoll' in wchan: break
                time.sleep(.05)
            else: raise RuntimeError('selected worker was not observed sleeping: ' + wchan)
            result['sleep_observation'] = dict(pid=pid, tid=tid, wchan=wchan,
                                               observed_ns=time.time_ns())
        nonce = 'Es237-' + str(time.time_ns())
        result['nonce'] = nonce
        assert server.poll() is None, 'endpoint failed to bind'
        save('send.txt', action('--es', 's237ProbeNonce', nonce, '--ei', 's237SourcePort', str(port),
            '--es', 's237Endpoint', str(endpoint_ip), '--ei', 's237EndpointPort', str(endpoint_port),
            '--ei', 's237Packets', '3'))
        probe = wait('probe', 'files/product-state/s237-probe.properties', dict(nonce=nonce))
        save('vpp.log', app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
        if a.diagnostic_clear_stale_iif:
            save('diagnostic-iif-after-probe.txt', adb('shell', 'su', '-c',
                shlex.quote('/data/local/tmp/s237-clear-stale-iif')))
        save('broker.log', adb('logcat', '-d', '-s', 'SakamotoSocketBroker:I', '*:S'))
        cli('after', ['show product flow-stack', 'show product tun', 'show runtime'])
        assert all(probe.get('packet.' + str(i)) ==
                   ('timeout' if a.fault != 'none' and i == 1 else 'echo') for i in range(3)), probe
        endpoint_text = (a.output / 'endpoint.log').read_text()
        assert all((nonce[1:] + ':' + str(i) in endpoint_text) ==
                   (a.fault != 'input-reject' or i != 1) for i in range(3))
        after = (a.output / 'after.txt').read_text()
        returns = [dict(re.findall(r'(\w+)=([^\s]+)', line))
                   for line in (a.output / 'vpp.log').read_text().splitlines()
                   if line.startswith('s237 event=return_copy ')]
        assert returns
        for returned in returns:
            assert int(returned['availability']) == (0 if a.unknown_identity else 1) + (0 if a.unknown_context else 4)
            assert int(returned['uid']) == (0 if a.unknown_identity else result['uid'])
            assert int(returned['context']) == (0 if a.unknown_context else 1)
        transport = 2 if a.fault == 'input-reject' else 3
        outputs = 3 if a.fault in ('none', 'write') else 2
        written = 3 if a.fault == 'none' else 2
        assert f'sent={transport} received={transport} outputs={outputs}' in after
        assert f'write_attempts={outputs} write_succeeded={written} write_failed={int(a.fault == "write")}' in after
        # One session/socket and one authorization request: replacement cannot
        # mask a receive-path failure in the second datagram.
        assert 'sockets_created=1 sockets_closed=0 broker_requests=1 broker_replies=1' in after
        result['status'] = 'SMOKE_ECHO_COMPLETE' if a.fault == 'none' else 'SAME_SESSION_RECOVERY_COMPLETE'
        if a.return_drop:
            compiler = Path('/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang')
            policy_source = ROOT / 'tests/device/helpers/s217-policy.c'
            policy_helper = a.output / 'policy-helper'
            subprocess.run([str(compiler), '-Wall', '-Wextra', '-Werror', '-O2',
                '-I', str(ROOT / 'src/product/include'), str(policy_source),
                '-L', str(a.build.resolve().parent / 'stage/lib/arm64-v8a'),
                '-lsakamoto_product_core', '-o', str(policy_helper)], check=True)
            result['policy_source_sha256'] = chain.digest(policy_source)
            result['policy_helper_sha256'] = chain.digest(policy_helper)
            remote_helper = '/data/local/tmp/s237-policy-' + str(result['generation'])
            adb('push', str(policy_helper.resolve()), remote_helper)
            adb('shell', 'chmod', '755', remote_helper)
            revision = time.time_ns() // 1000000
            result['policy_rounds'] = []
            for index, (label, mode, outcome) in enumerate([('return-drop', 5, 'timeout'), ('recover', 0, 'echo')]):
                command = f'LD_LIBRARY_PATH={shlex.quote(native)} {remote_helper} {BASE}runtime/api.sock {result["generation"]} /data/local/tmp/s237-policy-state-{result["generation"]} {revision + index} {mode} {result["uid"]} 0'
                applied = save(label + '-policy.txt', adb('shell', 'su', '-c', shlex.quote(command)))
                assert 'policy rc=0' in applied, applied
                next_nonce = 'Es237-' + label + '-' + str(time.time_ns())
                save(label + '-send.txt', action('--es', 's237ProbeNonce', next_nonce,
                    '--ei', 's237SourcePort', str(port), '--es', 's237Endpoint', str(endpoint_ip),
                    '--ei', 's237EndpointPort', str(endpoint_port), '--ei', 's237Packets', '3'))
                observed = wait(label + '-probe', 'files/product-state/s237-probe.properties', dict(nonce=next_nonce))
                assert all(observed.get('packet.' + str(i)) == outcome for i in range(3)), observed
                text = cli(label + '-after', ['show product flow-stack', 'show product tun'])
                datagrams = 6 + index * 3
                writes = 3 + index * 3
                assert f'sent={datagrams} received={datagrams} outputs={datagrams}' in text
                assert f'write_attempts={writes} write_succeeded={writes} write_failed=0' in text
                assert 'policy_drops=3' in text
                assert 'sockets_created=1 sockets_closed=0 broker_requests=1 broker_replies=1' in text
                assert all(next_nonce[1:] + ':' + str(i) in (a.output / 'endpoint.log').read_text() for i in range(3))
                result['policy_rounds'].append(dict(nonce=next_nonce, revision=revision + index, mode=mode))
            result['status'] = 'RETURN_DROP_RECOVERY_COMPLETE'
        if a.overlap_stop:
            assert f'flow_stack.hold owner={a.owner} ms=5000' in cli(
                'hold', [f'product flow-stack hold owner {a.owner} 5000'])
            held_nonce = 'Es237-held-' + str(time.time_ns())
            result['held_nonce'] = held_nonce
            save('held-send.txt', action('--es', 's237ProbeNonce', held_nonce,
                '--ei', 's237SourcePort', str(port), '--es', 's237Endpoint', str(endpoint_ip),
                '--ei', 's237EndpointPort', str(endpoint_port), '--ei', 's237Packets', '1'))
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                text = cli('held', ['show product flow-stack'])
                line = next(line for line in text.splitlines()
                            if line.startswith('flow_stack.status ') and f'owner={a.owner} ' in line)
                held = dict(re.findall(r'(\w+)=([^\s]+)', line))
                if int(held['inputs']) > 0: break
                time.sleep(.1)
            else: raise RuntimeError('no actual HEV queued input before stop')
            assert held['sent'] == held['outputs'] == '3'
            result['queued_before_stop'] = int(held['inputs'])
            result['status'] = 'OVERLAP_STOP_PENDING'
    except Exception as error:
        result['error'] = repr(error)
        save('failure-state.txt', app(STATE))
        save('failure-vpp.log', app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
        save('failure-archived-vpp.log', app('files/product-state/s237-last-failure.log'))
        save('failure-service.log', app('files/logs/runtime-service.log'))
        try:
            processes = save('failure-processes.txt', adb('shell', 'ps', '-A', '-o', 'PID,UID,ARGS'))
            native_processes = [line.split() for line in processes.splitlines()
                                if 'libvpp_runtime.so' in line and 'startup.conf' in line]
            if len(native_processes) == 1:
                pid = int(native_processes[0][0])
                uid = int(native_processes[0][1])
                traffic = adb('shell', 'dumpsys', 'connectivity', 'trafficcontroller')
                save('failure-uid-policy.txt', '\n'.join(line for line in traffic.splitlines()
                    if re.search(r'\b' + str(uid) + r'\b', line)
                    or 'configuration:' in line or line.strip().endswith(':')) + '\n')
                save('failure-snmp.txt', adb('shell', 'su', '-c',
                    shlex.quote('cat /proc/net/snmp')))
                descriptors = save('failure-fds.txt', adb('shell', 'su', '-c',
                    shlex.quote(f'ls -l /proc/{pid}/fd')))
                inodes = set(re.findall(r'socket:\[(\d+)\]', descriptors))
                udp = adb('shell', 'su', '-c', shlex.quote(f'cat /proc/{pid}/net/udp'))
                save('failure-udp.txt', '\n'.join(line for line in udp.splitlines()
                    if 'local_address' in line or (len(line.split()) > 9 and line.split()[9] in inodes)) + '\n')
                save('failure-fdinfo.txt', adb('shell', 'su', '-c',
                    shlex.quote(f'grep -H . /proc/{pid}/fdinfo/*')))
                cli('failure-files', ['show files', 'show product flow-stack'])
        except Exception as diagnostic_error:
            result['diagnostic_error'] = repr(diagnostic_error)
        save('failure-logcat.txt', adb('logcat', '-d', '-t', '300', check=False))
        raise
    finally:
        try:
            if active and 'generation' not in result and props(app(STATE)).get('mayBeActive') == 'false':
                processes = save('startup-failure-processes.txt', adb('shell', 'ps', '-A', '-o', 'PID,UID,ARGS'))
                if 'libvpp_runtime.so' not in processes:
                    active = False  # An inactive error is not a running generation to drain.
        except Exception as error:
            result['cleanup_error'] = repr(error)
        if active:
            try:
                save('stop.txt', action('--ez', 'runtimeStop', 'true'))
                wait('stopped', STATE, dict(state='stopped', mayBeActive='false', errorCode=''))
                processes = save('processes-after.txt', adb('shell', 'ps', '-A', '-o', 'PID,UID,ARGS'))
                assert not any('libvpp_runtime.so' in line for line in processes.splitlines())
                final = save('native-stop.log', app('files/product-state/s237-last-stop.log'))
                stopped = [dict(re.findall(r'(\w+)=([^\s]+)', line)) for line in final.splitlines()
                           if line.startswith('s237 event=owner_stopped ')]
                assert len(stopped) == 2 and {s['owner'] for s in stopped} == {'0', '1'}
                for shard in stopped:
                    assert shard['generation'] == str(result['generation'])
                    assert all(shard[k] == '0' for k in ['sessions', 'inputs', 'pbufs', 'buffers', 'obligations', 'frames'])
                    assert shard['sockets_created'] == shard['sockets_closed']
                    assert shard['timer_fd'] == shard['broker_fd'] == '-1'
                assert 'event=owner_destroyed ' in final
                # pbuf addresses can be reused: validate allocation intervals,
                # not address uniqueness across the entire run.
                live = {}
                for line in final.splitlines():
                    if not line.startswith(('s237 event=pbuf_alloc ', 's237 event=pbuf_free ')): continue
                    event = dict(re.findall(r'(\w+)=([^\s]+)', line))
                    key = event['object']
                    if event['event'] == 'pbuf_alloc':
                        assert key not in live
                        live[key] = event['kind']
                    else:
                        assert live.pop(key) == event['kind']
                assert not live, live
                if a.overlap_stop:
                    lines = final.splitlines()
                    begins = [(i, dict(re.findall(r'(\w+)=([^\s]+)', line)))
                              for i, line in enumerate(lines) if line.startswith('s237 event=quiesce_begin ')]
                    begins = [(i, event) for i, event in begins if event['owner'] == str(a.owner)]
                    assert len(begins) == 1 and int(begins[0][1]['inputs']) > 0
                    assert begins[0][1]['sent'] == begins[0][1]['outputs'] == '3'
                    after_gate = '\n'.join(lines[begins[0][0] + 1:])
                    assert not any('event=' + event + ' ' in after_gate for event in
                                   ['return_copy', 'output', 'pbuf_alloc', 'socket_created'])
                    assert result['held_nonce'][1:] not in (a.output / 'endpoint.log').read_text()
                    result['status'] = 'OVERLAP_STOP_COMPLETE'
            except Exception as error:
                result['cleanup_error'] = repr(error); result['status'] = 'HOLD'
        if server is not None:
            server.terminate()
            try: server.wait(timeout=3)
            except subprocess.TimeoutExpired: server.kill(); server.wait()
        if log is not None: log.close()
        result['completed_ns'] = time.time_ns()
        if any(chain.digest(ROOT / name) != digest for name, digest in result['test_inputs'].items()):
            result['status'] = 'HOLD'; result['cleanup_error'] = 'test source changed during run'
        save('result.json', json.dumps(result, indent=2) + '\n')
    if result['status'] == 'HOLD':
        raise RuntimeError(result.get('cleanup_error', 'incomplete smoke evidence'))

if __name__ == '__main__':
    main()
