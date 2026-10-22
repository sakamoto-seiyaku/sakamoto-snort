#!/usr/bin/env python3
"""Qualify one real native completion-ring-full cause with an external I/O pause.

No Product memory is written. The helper stops only the verified I/O TID for at
most two seconds; CLI requests resume only after detach. One already admitted
UDP request gates 65 unique responses. Every exit stops and restores the APK.
"""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import shlex
import socket
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests/benchmark'))
import pixel_quick as quick
from s304_vpn_topology import install

NDK = Path('/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin')
FROZEN = ROOT / 'build-output/s308-final-unified64-20261022'
INCLUDE = ROOT / 'build-output/product-build-cache/android-vpp/08ffa19dd72d3d5c8db41df65ec9f3c34e4a6c01d90d5e922f62243bba9aaedc/install/include'
PKG = quick.PACKAGE
BASE = '/data/data/' + PKG + '/files/'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def native_layout(symbol, name):
    raw = subprocess.check_output([str(NDK / 'llvm-dwarfdump'), '--name=' + name,
                                   '--show-children', str(symbol)], text=True)
    match = re.search(r'DW_AT_type\s+\((0x[0-9a-f]+)', raw)
    if match:
        raw = subprocess.check_output([str(NDK / 'llvm-dwarfdump'),
             '--debug-info=' + match[1], '--show-children', str(symbol)], text=True)
    size = int(re.search(r'DW_AT_byte_size\s+\((0x[0-9a-f]+|\d+)\)', raw)[1], 0)
    fields = {}
    for block in re.split(r'0x[0-9a-f]+:\s+DW_TAG_member', raw)[1:]:
        n = re.search(r'DW_AT_name\s+\("([^"]+)"\)', block)
        location = re.search(r'DW_AT_data_member_location\s+\((0x[0-9a-f]+|\d+)\)', block)
        if n and location:
            fields[n[1]] = int(location[1], 0)
    return dict(size=size, fields=fields)


def symbol_address(path, name, dynamic=False):
    args = [str(NDK / 'llvm-nm'), '--defined-only']
    if dynamic:
        args.append('--dynamic')
    text = subprocess.check_output([*args, str(path)], text=True)
    matches = [int(line.split()[0], 16) for line in text.splitlines()
               if len(line.split()) == 3 and line.split()[2] == name]
    assert len(matches) == 1, (name, matches)
    return matches[0]


def load_bias(maps, library):
    values = [int(parts[0].split('-')[0], 16) for line in maps.splitlines()
              if len(parts := line.split()) >= 6 and Path(parts[-1]).name == library
              and int(parts[2], 16) == 0]
    assert len(values) == 1, (library, values)
    return values[0]


def prepare(a, out):
    helper = out / 's308-io-consumer-pause'
    evidence_source = out / 'test-source'
    evidence_source.mkdir()
    for source in [Path(__file__), ROOT / 'tests/device/helpers/s308-io-consumer-pause.c']:
        shutil.copy2(source, evidence_source / source.name)
    command = [str(NDK / 'aarch64-linux-android31-clang'), '-std=gnu11', '-O2',
        '-Wall', '-Wextra', '-Werror', '-isystem', str(a.vpp_include.resolve()),
        '-I', str(ROOT / 'src/product/vpp'), str(ROOT / 'tests/device/helpers/s308-io-consumer-pause.c'),
        '-o', str(helper)]
    compile_result = subprocess.run(command, capture_output=True, text=True)
    (out / 'helper-compile.log').write_text(compile_result.stdout + compile_result.stderr)
    assert compile_result.returncode == 0, 'helper compile failed'
    graph = native_layout(a.plugin_symbol, 'product_packet_graph_main_t')
    layouts = {name: native_layout(a.vlib_symbol, name) for name in (
        'vlib_thread_main_t', 'vlib_frame_queue_main_t', 'vlib_frame_queue_t', 'vlib_frame_queue_elt_t')}
    with zipfile.ZipFile(a.apk) as archive:
        native = {Path(n).name: hashlib.sha256(archive.read(n)).hexdigest()
                  for n in archive.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}
    stripped = out / 'verified-plugin-stripped.so'
    subprocess.run([str(NDK / 'llvm-strip'), '--strip-unneeded', '-o', str(stripped),
                    str(a.plugin_symbol)], check=True)
    assert digest(stripped) == native['libproduct_core_plugin.so']
    assert digest(a.vlib) == native['libvlib.so']
    stripped_vlib = out / 'verified-vlib-stripped.so'
    subprocess.run([str(NDK / 'llvm-strip'), '--strip-unneeded', '-o', str(stripped_vlib), str(a.vlib_symbol)], check=True)
    assert digest(stripped_vlib) == native['libvlib.so']
    report = dict(command=command, helper_sha256=digest(helper), graph=graph,
        layouts=layouts, native_sha256=native, apk_sha256=digest(a.apk),
        restore_apk_sha256=digest(a.restore_apk), symbol_sha256=digest(a.plugin_symbol),
        vlib_symbol_sha256=digest(a.vlib_symbol),
        sources={str(p): digest(p) for p in [ROOT / 'tests/device/helpers/s308-io-consumer-pause.c',
                    Path(__file__), a.vpp_include / 'vlib/threads.h']},
        graph_symbol=symbol_address(a.plugin_symbol, 'product_packet_graph_main'),
        tm_symbol=symbol_address(a.vlib, 'vlib_thread_main', True))
    save(out / 'offline-identity.json', report)
    return helper, report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--apk', type=Path, default=FROZEN / 'apk-cache-proof/first/sakamoto-runtime-debug.apk')
    p.add_argument('--restore-apk', type=Path, required=True)
    p.add_argument('--plugin-symbol', type=Path, default=FROZEN / 'symbols/product_core_plugin.so')
    p.add_argument('--vlib', type=Path, default=FROZEN / 'cache-proof/stage-repeat/lib/arm64-v8a/libvlib.so')
    p.add_argument('--vlib-symbol', type=Path, default=ROOT / 'build-output/product-build-cache/android-vpp/08ffa19dd72d3d5c8db41df65ec9f3c34e4a6c01d90d5e922f62243bba9aaedc/build/lib/libvlib.so')
    p.add_argument('--vpp-include', type=Path, default=INCLUDE)
    p.add_argument('--endpoint-address', required=True)
    p.add_argument('--owners', type=int, choices=[1, 3], required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--prepare-only', action='store_true')
    p.add_argument('--response-spacing-ms', type=int, choices=[0, 5], default=5)
    a = p.parse_args()
    endpoint = ipaddress.ip_address(a.endpoint_address)
    assert endpoint.version == 4 and not any((endpoint.is_loopback, endpoint.is_unspecified,
                                              endpoint.is_multicast, endpoint.is_link_local))
    out = a.output.resolve();out.mkdir(parents=True, exist_ok=False)
    helper, identity = prepare(a, out)
    if a.prepare_only:
        print(json.dumps(dict(status='OFFLINE_READY', identity=str(out / 'offline-identity.json'))))
        return 0
    d = quick.Device(quick.SERIAL, out, control_timeout=15)
    result = dict(status='HOLD', owner_count=a.owners, owner=a.owners - 1,
                  started_ns=time.time_ns(), response_spacing_ms=a.response_spacing_ms, **identity)
    pause_process = None
    client_process = None
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    active = False;uid = None
    remote = '/data/local/tmp/s308-io-consumer-pause'
    def record(name, text):
        (out / name).write_text(text);return text
    def state(wanted):
        end = time.monotonic() + 30
        while time.monotonic() < end:
            value = d.state(cleanup=wanted == 'stopped')
            if value.get('state') == wanted and value.get('mayBeActive') == ('false' if wanted == 'stopped' else 'true'):
                return value
            if value.get('errorCode') == 'root_authorization_required':
                raise RuntimeError('KernelSU grant required; no security policy changes authorized')
            time.sleep(.1)
        raise RuntimeError('runtime state deadline: ' + repr(value))
    def cli(name, commands):
        assert pause_process is None or pause_process.poll() is not None, 'no CLI during I/O ptrace pause'
        return record(name + '.txt', d.cli('vpn', commands))
    try:
        initial = d.state();save(out / 'initial-state.json', initial)
        assert initial.get('state') == 'stopped' and initial.get('mayBeActive') == 'false'
        uid = int(d.command('shell', 'run-as', PKG, 'id', '-u').strip())
        install(d, a.apk, out / 'install', uid)
        d.command('push', helper, remote);d.command('shell', 'chmod', '755', remote)
        raw_layout = record('target-layout.txt', d.root(shlex.join([remote, 'layout'])))
        actual_layout = quick.properties(raw_layout)
        fields = {
            'vlib_thread_main_t': ['frame_queue_mains'],
            'vlib_frame_queue_main_t': ['vlib_frame_queues'],
            'vlib_frame_queue_t': ['elts', 'head', 'tail', 'nelts'],
            'vlib_frame_queue_elt_t': ['valid', 'n_vectors']}
        for name, names in fields.items():
            for field in names:
                assert int(actual_layout['layout.' + name + '.' + field]) == identity['layouts'][name]['fields'][field]
        assert int(actual_layout['layout.fqm_size']) == identity['layouts']['vlib_frame_queue_main_t']['size']
        assert int(actual_layout['layout.elt_size']) == identity['layouts']['vlib_frame_queue_elt_t']['size']
        server.bind((str(endpoint), 0));server.settimeout(5)
        port = server.getsockname()[1]
        spec = importlib.util.spec_from_file_location('owner_oracle', ROOT / 'tests/device/s207-owner-oracle.py')
        oracle = importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
        for source_port in range(42300, 42400):
            facts = dict(l3=1, l4=1, family=4, protocol=17,
                src=ipaddress.ip_address('10.111.0.2').packed.rjust(16, b'\0').hex(),
                dst=endpoint.packed.rjust(16, b'\0').hex(), src_port=source_port, dst_port=port, icmp_known=0)
            if oracle.assignment(facts, workers=a.owners)['owner'] == a.owners - 1:
                break
        else:
            raise RuntimeError('no target canonical owner tuple')
        active = True
        record('start.txt', d.action('--ez', 'debugVpnHevValidation', 'true',
            '--es', 'runtimeWorkerCpuIds', '1' if a.owners == 1 else '1,2,1',
            '--es', 'runtimeTunIoCpuId', '3'))
        running = state('running');generation = int(running['generation'])
        save(out / 'running.json', running);result['generation'] = generation
        before = cli('before', ['show product topology', 'show threads',
            'product capacity credits 48 primary-slots 64 completion-slots 2',
            'product packet-trace limit 4096', 'show product completion', 'show product tun'])
        assert f'topology.tun_io_lane=0 worker={a.owners} thread_index={a.owners + 1}' in before
        threads = {m[1]: int(m[2]) for line in before.splitlines()
                   if (m := re.search(r'^\d+\s+vpp_(main|wk_\d+)\s+(?:workers\s+)?(\d+)\s+', line))}
        assert set(threads) == {'main', *(f'wk_{i}' for i in range(a.owners + 1))}, threads
        pid, tid = threads['main'], threads[f'wk_{a.owners}']
        maps = record('maps.txt', d.root(f'cat /proc/{pid}/maps'))
        graph_address = load_bias(maps, 'libproduct_core_plugin.so') + identity['graph_symbol']
        tm_address = load_bias(maps, 'libvlib.so') + identity['tm_symbol']
        offsets = identity['graph']['fields']
        command = [remote, str(pid), str(tid), str(generation), str(a.owners),
            hex(graph_address), hex(tm_address), *[str(offsets[name]) for name in (
                'generation', 'owner_count', 'adapter_kind', 'completion_return_frame_queue',
                'completion_deferred', 'completion_pending_returns', 'lifecycle_obligations',
                'lifecycle_buffers', 'lifecycle_handoffs', 'lifecycle_completion_frames')]]
        result['pause_command'] = command
        probe = record('ptrace-probe.txt', d.root(shlex.join([*command, 'probe']), check=False))
        assert 'event=paused ' in probe and 'event=resumed result=PASS' in probe and 'detach_success=1' in probe, probe
        nonce = 'Ering' + str(time.time_ns())
        result.update(nonce=nonce, endpoint=str(endpoint), endpoint_port=port, source_port=source_port)
        client_command = [remote, 'client', str(uid), str(source_port), str(endpoint), str(port), nonce, '65']
        record('request.txt', shlex.join(client_command) + '\n')
        client_process = subprocess.Popen(d.prefix + ['shell', '-T', 'su', '-c', shlex.quote(shlex.join(client_command))],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        record('udp-before.txt', d.root(f'cat /proc/{pid}/net/udp; cat /proc/{pid}/net/snmp'))
        request, peer = server.recvfrom(256)
        assert request == (nonce + ':0').encode(), (request, nonce)
        record('server-request.txt', repr(dict(request=request.decode(), peer=peer)) + '\n')
        # No CLI or barrier occurs from this point until the pause helper exits.
        pause_process = subprocess.Popen(d.prefix + ['shell', '-T', 'su', '-c', shlex.quote(shlex.join(command))],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        data = b'';selector = selectors.DefaultSelector();selector.register(pause_process.stdout, selectors.EVENT_READ)
        end = time.monotonic() + 3;released = False
        try:
            while time.monotonic() < end:
                if selector.select(.02):
                    chunk = os.read(pause_process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    data += chunk
                    if b'event=paused ' in data and not released:
                        sent = []
                        for i in range(65):
                            payload = request if i == 0 else request + ('|ring-' + str(i)).encode()
                            assert server.sendto(payload, peer) == len(payload)
                            sent.append(payload.decode())
                            if i != 64 and a.response_spacing_ms:
                                time.sleep(a.response_spacing_ms / 1000)
                        save(out / 'server-responses.json', sent);released = True
            remainder, _ = pause_process.communicate(timeout=1);data += remainder
        finally:
            selector.close()
        record('pause-and-ring.txt', data.decode(errors='replace'))
        assert pause_process.returncode == 0 and released
        assert b'event=resumed result=PASS full=1' in data, data
        snapshots = [dict(re.findall(r'(\w+)=([^\s]+)', line)) for line in data.decode().splitlines()
                     if line.startswith('event=snapshot ')]
        assert any(int(s['tail']) - int(s['head']) == 1 and s['valid'] == '1'
                   and int(s['deferred']) > 0 and int(s['pending']) > 0 for s in snapshots)
        resumed = next(dict(re.findall(r'(\w+)=([^\s]+)', line)) for line in data.decode().splitlines()
                       if line.startswith('event=resumed '))
        assert int(resumed['elapsed_ns']) <= 2_000_000_000
        assert resumed['seized'] == resumed['stopped'] == resumed['detach_success'] == '1'
        record('udp-after.txt', d.root(f'cat /proc/{pid}/net/udp; cat /proc/{pid}/net/snmp'))
        record('vpp.log', d.command('shell', 'run-as', PKG, 'cat', 'files/profiles/vpn/vpp/logs/vpp-stdout.log'))
        client_output, _ = client_process.communicate(timeout=8)
        record('client.txt', client_output.decode(errors='replace'))
        record('udp-final.txt', d.root(f'cat /proc/{pid}/net/udp; cat /proc/{pid}/net/snmp'))
        cli('return-diagnostic', ['show product flow-stack', 'show product tun', 'show product primary', 'show runtime', 'show files'])
        record('vpp.log', d.command('shell', 'run-as', PKG, 'cat', 'files/profiles/vpn/vpp/logs/vpp-stdout.log'))
        assert client_process.returncode == 0 and b'event=client_complete unique=65' in client_output
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            after = cli('after', ['show product completion', 'show product tun', 'show product primary'])
            text = record('vpp.log', d.command('shell', 'run-as', PKG, 'cat',
                'files/profiles/vpn/vpp/logs/vpp-stdout.log'))
            returns = [dict(re.findall(r'(\w+)=([^\s]+)', line)) for line in text.splitlines()
                       if line.startswith('s213 event=completion source=FLOW_STACK_RETURN ')
                       and f'generation={generation} ' in line]
            if len(returns) >= 65 and 'pending=0' in after and 'buffers=0' in after:
                break
            time.sleep(.1)
        assert len(returns) == 65 and len({r['token'] for r in returns}) == 65
        assert all(r['transport_outcome'] == 'TUN_WRITE_SUCCEEDED' for r in returns)
        assert re.search(r'\bretries=[1-9]\d*', after), after
        record('queue-drained.txt', d.root(shlex.join([*command, 'snapshot'])))
        result.update(status='PASS', unique_return_completions=len(returns), ring_snapshots=snapshots)
    except Exception as error:
        result['error'] = repr(error)
        raise
    finally:
        cleanup_errors = []
        if client_process is not None and client_process.poll() is None:
            try:
                raw_client, _ = client_process.communicate(timeout=6)
                record('client-finally.txt', raw_client.decode(errors='replace'))
            except Exception as error:
                cleanup_errors.append('client: ' + repr(error))
        try:
            if pause_process is not None and pause_process.poll() is None:
                pause_process.communicate(timeout=3)
        except Exception as error:
            cleanup_errors.append('pause: ' + repr(error))
        try:
            if active:
                record('stop.txt', d.action('--ez', 'runtimeStop', 'true', cleanup=True))
                save(out / 'stopped.json', state('stopped'))
                d.wait_process_gone('libvpp_runtime.so', cleanup=True)
                stopped_log = record('native-stop.log', d.command('shell', 'run-as', PKG, 'cat',
                    'files/product-state/s237-last-stop.log', check=False, cleanup=True))
                if 'generation' in result:
                    quick.validate_vpn_stop(stopped_log, result['generation'], a.owners)
        except Exception as error:
            cleanup_errors.append('stop: ' + repr(error))
        try:
            if uid is not None:
                install(d, a.restore_apk, out / 'restore', uid)
                result['restored_apk_sha256'] = digest(a.restore_apk)
                result['final_state'] = d.state(cleanup=True)
                assert result['final_state'].get('state') == 'stopped'
        except Exception as error:
            cleanup_errors.append('restore: ' + repr(error))
        if cleanup_errors:
            result['status'] = 'HOLD';result['cleanup_errors'] = cleanup_errors
        server.close();result['completed_ns'] = time.time_ns();save(out / 'result.json', result)
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
