#!/usr/bin/env python3
"""S298 Product UDP4 return path through a dedicated VPN TUN I/O worker."""
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
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--endpoint-address', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fault', choices=['none', 'write'], default='none')
    parser.add_argument('--owner', type=int, choices=[0, 1], default=0)
    parser.add_argument('--owner-count', type=int, choices=[1, 2], default=2)
    parser.add_argument('--preselect-other-io-cpu', action='store_true')
    parser.add_argument('--stress-ingress', action='store_true')
    parser.add_argument('--ordinary-product', action='store_true')
    parser.add_argument('--flow-end-mode', choices=['none', 'close', 'expiry'], default='none')
    a = parser.parse_args()
    assert a.owner < a.owner_count
    assert a.flow_end_mode == 'none' or a.owner_count == 1
    assert not a.ordinary_product or a.fault == 'none'
    endpoint_ip = ipaddress.ip_address(a.endpoint_address)
    assert not (endpoint_ip.is_loopback or endpoint_ip.is_unspecified
                or endpoint_ip.is_link_local or endpoint_ip.is_multicast)
    assert endpoint_ip.version == 4
    family = 4
    tun_ip = ipaddress.ip_address('10.111.0.2')
    chain = module('chain', 'tests/evidence/product_chain.py')
    apk = a.apk.resolve()
    with zipfile.ZipFile(apk) as archive:
        native_sha256 = {Path(name).name: hashlib.sha256(archive.read(name)).hexdigest()
                         for name in archive.namelist()
                         if name.startswith('lib/arm64-v8a/') and name.endswith('.so')}
    a.output.mkdir(parents=True, exist_ok=False)
    def save(name, text):
        (a.output / name).write_text(text)
        return text
    def adb(*args, check=True):
        for attempt in range(4):
            r = subprocess.run([str(ROOT / 'dev/adb'), '-s', SERIAL, *args],
                capture_output=True, text=True, errors='replace', timeout=30)
            if (r.returncode and
                    ('UtilAcceptVsock' in r.stderr or 'UtilBindVsock' in r.stderr)
                    and attempt < 3):
                time.sleep(.3 * (attempt + 1))
                continue
            break
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

    result = dict(status='HOLD', scope='s299-vpn-n1-udp4-return' if a.owner_count == 1
                  else 's298-dedicated-io-udp4-return', owner_count=a.owner_count,
                  fault=a.fault,
                  flow_end_mode=a.flow_end_mode,
                  started_ns=time.time_ns(), apk_sha256=chain.digest(apk), serial=SERIAL)
    result['product_source_sha256'] = hashlib.sha256(
        chain.encode(chain.source_files())).hexdigest()
    result['family'] = family
    result['owner'] = a.owner
    result['stress_ingress'] = a.stress_ingress
    result['ordinary_product'] = a.ordinary_product
    test_inputs = ['tests/device/s298-pixel-udp-return.py', 'tests/device/s207-owner-oracle.py',
                   'tests/device/helpers/s223-udp.c',
                   'tests/device/helpers/s298-tun-ingress-flood.c',
                   'tests/evidence/product_chain.py',
                   'tests/evidence/verify_s298_vpn_return.py']
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
        save('install.txt', adb('install', '-r', str(apk)))
        package = save('package.txt', adb('shell', 'dumpsys', 'package', PKG))
        code = re.search(r'codePath=(\S+)', package).group(1)
        native = code + '/lib/arm64'
        save('installed-apk.txt', adb('shell', 'sha256sum', code + '/base.apk'))
        assert (a.output / 'installed-apk.txt').read_text().split()[0] == result['apk_sha256']
        hashes = save('installed-native.txt', adb('shell', 'sha256sum',
            *[native + '/' + n for n in sorted(native_sha256)]))
        assert {Path(line.split()[1]).name: line.split()[0] for line in hashes.splitlines()} == native_sha256
        with zipfile.ZipFile(apk) as archive:
            notices = archive.read('assets/hev-notices.txt')
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
            if oracle.assignment(facts, workers=a.owner_count)['owner'] == a.owner: break
        else: raise RuntimeError('no source port for requested canonical owner')
        result.update(endpoint=str(endpoint_ip), endpoint_port=endpoint_port, source_port=port)
        if a.preselect_other_io_cpu:
            save('preselect-start.txt', action('--ez', 'debugVpnGraphValidation', 'true',
                '--es', 'runtimeTunIoCpuId', '4'))
            selected = wait('preselect-running', STATE, dict(state='running', profile='vpn',
                protectionRunning='false', errorCode=''))
            result['preselect_generation'] = int(selected['generation'])
            save('preselect-stop.txt', action('--ez', 'runtimeStop', 'true'))
            wait('preselect-stopped', STATE, dict(state='stopped', mayBeActive='false', errorCode=''))
            previous = props(app(STATE))
        active = True
        placement = ('--es', 'runtimeWorkerCpuIds', '1' if a.owner_count == 1 else '1,2')
        io_cpu = str(a.owner_count + 1)
        if a.ordinary_product:
            save('start.txt', action('--ez', 'runtimeStart', 'true',
                '--es', 'runtimeProfile', 'vpn', '--es', 'runtimeTunIoCpuId', io_cpu,
                *placement))
        else:
            save('start.txt', action('--ez', 'debugVpnHevValidation', 'true',
                '--es', 'runtimeTunIoCpuId', io_cpu, *placement))
        state = wait('running', STATE, dict(state='running', profile='vpn',
                     protectionRunning='true' if a.ordinary_product else 'false', errorCode=''))
        result['generation'] = int(state['generation'])
        cli('before', ['show product topology', 'show product flow-stack',
                       'show product tun', 'show threads'])
        before_topology = (a.output / 'before.txt').read_text()
        lane = next(line for line in before_topology.splitlines()
                    if line.startswith('topology.tun_io_lane='))
        assert f'actual_core={io_cpu}' in lane and f'thread_index={a.owner_count + 1}' in lane, lane
        assert f'origin_thread={a.owner_count + 1}' in before_topology, before_topology
        assert all(f'enabled=1 owner={i} ready=1' in (a.output / 'before.txt').read_text()
                   for i in range(a.owner_count))
        assert f'enabled=1 owner={a.owner_count} ' not in before_topology
        threads = dict((match.group(1), int(match.group(2)))
                       for line in before_topology.splitlines()
                       if (match := re.search(r'^\d+\s+vpp_(main|wk_\d+)\s+(?:workers\s+)?(\d+)\s+', line)))
        assert set(threads) == {'main', *(f'wk_{i}' for i in range(a.owner_count + 1))}, threads
        for role, cpu in [('main', 0), *( (f'wk_{i}', i + 1)
                                              for i in range(a.owner_count + 1))]:
            lwp = threads[role]
            affinity = save('affinity-' + role + '.txt', adb('shell', 'su', '-c',
                shlex.quote(f'cat /proc/{threads["main"]}/task/{lwp}/status')))
            assert re.search(r'^Cpus_allowed_list:\s*' + str(cpu) + r'\s*$',
                             affinity, re.MULTILINE), (role, affinity)
        if not a.ordinary_product:
            cli('trace', ['product packet-trace limit 4096'])
        flood = None
        if a.stress_ingress:
            compiler = Path('/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang')
            flood_source = ROOT / 'tests/device/helpers/s298-tun-ingress-flood.c'
            flood_binary = a.output / 'tun-ingress-flood'
            subprocess.run([str(compiler), '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                            str(flood_source), '-o', str(flood_binary)], check=True)
            result['flood_sha256'] = chain.digest(flood_binary)
            adb('push', str(flood_binary.resolve()), '/data/local/tmp/s298-tun-ingress-flood')
            adb('shell', 'chmod', '755', '/data/local/tmp/s298-tun-ingress-flood')
            log_before = app('files/profiles/vpn/vpp/logs/vpp-stdout.log')
            interface = re.search(r's213 event=attach .* interface=(\S+)', log_before).group(1)
            command = '/data/local/tmp/s298-tun-ingress-flood ' + shlex.quote(interface) + ' 1500 1000'
            flood = subprocess.Popen([str(ROOT / 'dev/adb'), '-s', SERIAL, 'shell',
                                      'su', '-c', shlex.quote(command)],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True)
            time.sleep(.2)
        if a.fault != 'none':
            armed = cli('fault', [f'product tun fault owner {a.owner} ' + a.fault + ' 2'])
            assert 'tun.fault armed=' in armed
        nonce = 'Es237-' + str(time.time_ns())
        result['nonce'] = nonce
        assert server.poll() is None, 'endpoint failed to bind'
        save('send.txt', action('--es', 's237ProbeNonce', nonce, '--ei', 's237SourcePort', str(port),
            '--es', 's237Endpoint', str(endpoint_ip), '--ei', 's237EndpointPort', str(endpoint_port),
            '--ei', 's237Packets', '3'))
        probe = wait('probe', 'files/product-state/s237-probe.properties', dict(nonce=nonce))
        if flood is not None:
            flood_output, _ = flood.communicate(timeout=30)
            save('flood.txt', flood_output)
            assert flood.returncode == 0, flood_output
        save('vpp.log', app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
        save('broker.log', adb('logcat', '-d', '-s', 'SakamotoSocketBroker:I', '*:S'))
        cli('after', ['show product flow-stack', 'show product tun', 'show runtime'])
        assert all(probe.get('packet.' + str(i)) ==
                   ('timeout' if a.fault != 'none' and i == 1 else 'echo') for i in range(3)), probe
        endpoint_text = (a.output / 'endpoint.log').read_text()
        assert all(nonce[1:] + ':' + str(i) in endpoint_text for i in range(3))
        after = (a.output / 'after.txt').read_text()
        returns = [dict(re.findall(r'(\w+)=([^\s]+)', line))
                   for line in (a.output / 'vpp.log').read_text().splitlines()
                   if line.startswith('s237 event=return_copy ')]
        if not a.ordinary_product: assert returns
        if not a.ordinary_product:
            for returned in returns:
                assert int(returned['availability']) == 5
                assert int(returned['uid']) == result['uid']
                assert int(returned['context']) == 1
        written = 3 if a.fault == 'none' else 2
        if not a.ordinary_product:
            assert 'sent=3 received=3 outputs=3' in after
            assert f'write_attempts=3 write_succeeded={written} write_failed={int(a.fault == "write")}' in after
        # One session/socket and one authorization request: replacement cannot
        # mask a receive-path failure in the second datagram.
        if not a.ordinary_product:
            assert 'sockets_created=1 sockets_closed=0 broker_requests=1 broker_replies=1' in after
        if a.flow_end_mode != 'none':
            before_flow = cli('flow-before', ['show product flows', 'show product flow-end',
                                              'show product expiry'])
            entries = [dict(re.findall(r'(\w+)=([^\s]+)', line))
                       for line in before_flow.splitlines() if line.startswith('flow.entry ')]
            matches = [entry for entry in entries if entry.get('worker') == '0'
                       and {entry.get('port_a'), entry.get('port_b')} ==
                           {str(port), str(endpoint_port)}]
            assert len(matches) == 1, matches
            target = matches[0]
            result['flow_slot'] = target['slot']
            result['flow_incarnation'] = target['incarnation']
            assert int(target['orig_packets']) >= 3 and int(target['reply_packets']) >= 3
            if a.flow_end_mode == 'close':
                requested = cli('flow-close', [f'product flow-end close owner 0 '
                    f'slot {target["slot"]} generation {result["generation"]} '
                    f'incarnation {target["incarnation"]}'])
                assert 'flow-end.close=queued owner=0' in requested, requested
            deadline = time.monotonic() + (50 if a.flow_end_mode == 'expiry' else 8)
            while time.monotonic() < deadline:
                after_flow = cli('flow-after', ['show product flows', 'show product flow-end',
                                                'show product expiry'])
                if not any(line.startswith('flow.entry worker=0 ')
                           and f'slot={target["slot"]} ' in line
                           and f'incarnation={target["incarnation"]} ' in line
                           for line in after_flow.splitlines()):
                    break
                time.sleep(.25)
            else:
                raise RuntimeError('FlowEntry did not reach FlowEnd/expiry')
            assert 'flow-end.owner=0 ' in after_flow and 'expiry.owner=0 ' in after_flow
            assert 'flow-end.owner=1 ' not in after_flow and 'expiry.owner=1 ' not in after_flow
        result['status'] = 'SMOKE_ECHO_COMPLETE' if a.fault == 'none' else 'SAME_SESSION_RECOVERY_COMPLETE'
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
                if not a.ordinary_product:
                    final = save('native-stop.log', app('files/product-state/s237-last-stop.log'))
                    stopped = [dict(re.findall(r'(\w+)=([^\s]+)', line)) for line in final.splitlines()
                               if line.startswith('s237 event=owner_stopped ')]
                    assert len(stopped) == a.owner_count and \
                        {s['owner'] for s in stopped} == {str(i) for i in range(a.owner_count)}
                    for shard in stopped:
                        assert shard['generation'] == str(result['generation'])
                        assert all(shard[k] == '0' for k in ['sessions', 'inputs', 'pbufs', 'buffers', 'obligations', 'frames'])
                        assert shard['sockets_created'] == shard['sockets_closed']
                        assert shard['timer_fd'] == shard['broker_fd'] == '-1'
                    assert 'event=owner_destroyed ' in final
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
