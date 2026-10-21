#!/usr/bin/env python3
"""S301: bounded Product TUN allocation fault, owner handoff and recovery."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]
PKG = 'com.sakamoto.snort.androidruntime'
SERIAL = '28201JEGR0XPAJ'
BASE = '/data/user/0/' + PKG + '/files/profiles/vpn/vpp/'
STATE = 'files/runtime-state/snapshot.properties'


def props(text):
    return dict(line.split('=', 1) for line in text.splitlines()
                if '=' in line and not line.startswith('#'))


def fields(text, prefix):
    lines = [line for line in text.splitlines() if line.startswith(prefix)]
    assert len(lines) == 1, (prefix, text)
    return {key: value for key, value in re.findall(r'(\w+)=([^\s]+)', lines[0])}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--apk', type=Path, required=True)
    p.add_argument('--restore-apk', type=Path, required=True)
    p.add_argument('--helper', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--ordinary-product', action='store_true')
    p.add_argument('--stop-during-congestion', action='store_true')
    p.add_argument('--prestop-draining', action='store_true')
    a = p.parse_args()
    assert not (a.stop_during_congestion or a.prestop_draining) or not a.ordinary_product
    assert not (a.stop_during_congestion and a.prestop_draining)
    a.output.mkdir(parents=True, exist_ok=False)
    apk, restore, helper = (path.resolve() for path in (a.apk, a.restore_apk, a.helper))
    def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
    result = dict(status='HOLD', started_ns=time.time_ns(), ordinary_product=a.ordinary_product,
                  apk_sha256=digest(apk), restore_sha256=digest(restore),
                  helper_sha256=digest(helper),
                  source_sha256=digest(Path(__file__)),
                  helper_source_sha256=digest(ROOT / 'tests/device/helpers/s301-tun-packets.c'))
    def save(name, content):
        (a.output / name).write_text(content)
        return content
    def adb(*args, check=True):
        for attempt in range(4):
            command = subprocess.run([str(ROOT / 'dev/adb'), '-s', SERIAL, *map(str, args)],
                                     text=True, errors='replace', capture_output=True, timeout=30)
            if command.returncode and ('UtilAcceptVsock' in command.stderr or
                                       'UtilBindVsock' in command.stderr) and attempt < 3:
                time.sleep(.3 * (attempt + 1))
                continue
            break
        output = (command.stdout + command.stderr).replace('\r', '')
        if check and command.returncode: raise RuntimeError(output)
        return output
    def app(path): return adb('shell', 'run-as', PKG, 'cat', path, check=False)
    def action(*args): return adb('shell', 'am', 'start', '-n', PKG + '/.DebugControlActivity', *args)
    def root(command): return adb('shell', 'su', '-c', shlex.quote(command))
    def cli(name, *commands):
        command = "printf '%s\\n' " + ' '.join(shlex.quote(value) for value in
            ['set terminal pager off', *commands, 'quit']) + \
            ' | toybox nc -U -w 2 -q 1 ' + BASE + 'runtime/cli.sock'
        return save(name + '.txt', root(command))
    def wait_state(name, wanted):
        until = time.monotonic() + 45
        while time.monotonic() < until:
            value = app(STATE)
            state = props(value)
            save(name + '.poll', value)
            if all(state.get(key) == expected for key, expected in wanted.items()):
                save(name + '.properties', value)
                return state
            if state.get('state') == 'error': raise RuntimeError(str(state))
            time.sleep(.2)
        raise RuntimeError(name + ': state timeout ' + str(state))
    def status(name):
        text = cli(name, 'show product tun', 'show product primary',
                   'show product completion', 'show product flows')
        return fields(text, 'tun.status '), fields(text, 'tun.capture_capacity '), \
            fields(text, 'primary.status ')
    def drain(name, captured):
        until = time.monotonic() + 10
        while time.monotonic() < until:
            tun, capacity, primary = status(name)
            if (int(tun['captured']) >= captured and
                all(tun[key] == '0' for key in ('pending', 'frames', 'buffers', 'obligations')) and
                primary['handoff_debt'] == primary['pending_returns'] == '0'):
                return tun, capacity, primary
            time.sleep(.1)
        raise RuntimeError(name + ': native debt did not drain ' + str(tun))
    def capacity(name, command):
        until = time.monotonic() + 5
        while time.monotonic() < until:
            response = cli(name, command)
            if 'capacity.configured' in response: return response
            time.sleep(.1)
        raise RuntimeError(name + ': capacity configuration stayed busy')
    initial_path = adb('shell', 'pm', 'path', PKG).strip().removeprefix('package:')
    result['initial_installed_sha256'] = adb('shell', 'sha256sum', initial_path).split()[0]
    assert result['initial_installed_sha256'] == result['restore_sha256']
    result['initial_wifi'] = save('wifi-before.txt', adb('shell', 'cmd', 'wifi', 'status'))
    result['initial_route'] = save('route-before.txt', adb('shell', 'ip', 'route'))
    active = False
    try:
        save('install.txt', adb('install', '-r', apk))
        package = save('package.txt', adb('shell', 'dumpsys', 'package', PKG))
        code_path = re.search(r'codePath=(\S+)', package).group(1)
        result['installed_apk_sha256'] = adb('shell', 'sha256sum',
                                              code_path + '/base.apk').split()[0]
        assert result['installed_apk_sha256'] == result['apk_sha256']
        with zipfile.ZipFile(apk) as archive:
            native = {Path(name).name: hashlib.sha256(archive.read(name)).hexdigest()
                      for name in archive.namelist()
                      if name.startswith('lib/arm64-v8a/') and name.endswith('.so')}
        result['apk_native_sha256'] = native
        installed = save('installed-native.txt', adb('shell', 'sha256sum',
            *(code_path + '/lib/arm64/' + name for name in sorted(native))))
        result['installed_native_sha256'] = {
            Path(line.split()[1]).name: line.split()[0] for line in installed.splitlines()}
        assert result['installed_native_sha256'] == native
        adb('push', helper, '/data/local/tmp/s301-tun-packets')
        adb('shell', 'chmod', '755', '/data/local/tmp/s301-tun-packets')
        active = True
        if a.ordinary_product:
            save('start.txt', action('--ez', 'runtimeStart', 'true', '--es',
                'runtimeProfile', 'vpn', '--es', 'runtimeWorkerCpuIds', '1,2,1',
                '--es', 'runtimeTunIoCpuId', '3'))
        else:
            save('start.txt', action('--ez',
                                     'debugVpnHevValidation' if (a.stop_during_congestion or
                                                                  a.prestop_draining)
                                     else 'debugVpnGraphValidation', 'true',
                                     '--es', 'runtimeTunIoCpuId', '3'))
        state = wait_state('running', dict(state='running', profile='vpn', errorCode='',
            protectionRunning='true' if a.ordinary_product else 'false'))
        generation = state['generation']
        result['generation'] = generation
        result['running_state'] = state
        until = time.monotonic() + 30
        attached_ok = False
        if a.ordinary_product:
            while time.monotonic() < until:
                native = cli('attach-check', 'show product tun')
                attached = fields(native, 'tun.status ')
                if attached['generation'] == generation and attached['attached'] == '1':
                    attached_ok = True
                    break
                time.sleep(.2)
        else:
            while time.monotonic() < until:
                attached = props(app('files/product-state/s213-tun-graph.properties'))
                if attached.get('generation') == generation and attached.get('tunAttached') == '1':
                    attached_ok = True
                    break
                time.sleep(.2)
        if not attached_ok: raise RuntimeError('TUN did not attach')
        if not a.ordinary_product:
            save('attached.properties', app('files/product-state/s213-tun-graph.properties'))
        log = app('files/profiles/vpn/vpp/logs/vpp-stdout.log')
        interface = re.search(r's213 event=attach .* interface=(\S+)', log).group(1)
        result['interface'] = interface
        if not a.ordinary_product: cli('trace', 'product packet-trace limit 4096')
        if a.prestop_draining:
            fault = cli('prestop-draining', 'product tun fault pre-stop-draining')
            assert 'tun.fault armed=pre-stop-draining generation=' + generation in fault
            save('stop-prestaged-draining.txt', action('--ez', 'runtimeStop', 'true'))
            wait_state('stopped', dict(state='stopped', mayBeActive='false', errorCode=''))
            active = False
            log = save('vpp.log', app('files/product-state/s237-last-stop.log'))
            lines = log.splitlines()
            markers = ['s301 event=tun_read_pause ', 's302 event=tun_read_quiesced ',
                       's302 event=graph_quiesced ', 's213 event=stop ']
            positions = [next(i for i, line in enumerate(lines) if line.startswith(marker))
                         for marker in markers]
            assert positions == sorted(positions), positions
            assert 'pending=0 buffers=0 frames=0 obligations=0 tun_fd=-1' in log
            result['prestop_draining'] = dict(generation=generation, positions=positions)
            result['status'] = 'RAW_COMPLETE'
            return
        before = status('before')
        assert 'tun.fault armed=' in cli('arm-capture-alloc',
            'product tun fault capture-alloc 1')
        save('invalid-send.txt', root('/data/local/tmp/s301-tun-packets ' +
                                       shlex.quote(interface) + ' invalid 1'))
        after = drain('after-capture-alloc', int(before[0]['captured']) + 1)
        assert int(after[1]['alloc_failures']) == int(before[1]['alloc_failures']) + 1
        assert int(after[1]['read_pauses']) == int(before[1]['read_pauses']) + 1
        assert int(after[1]['read_resumes']) == int(before[1]['read_resumes']) + 1
        assert after[1]['read_paused'] == '0'
        assert int(after[0]['runtime_drops']) >= int(before[0]['runtime_drops']) + 1
        # No busy loop once the fd is readable but native allocation fails.
        if not a.ordinary_product:
            time.sleep(.3)
            idle = status('idle-after-recovery')
            assert int(idle[1]['alloc_attempts']) - int(after[1]['alloc_attempts']) <= 2
        capacity('capacity-zero',
            'product capacity credits 0 primary-slots 2 completion-slots 128')
        save('handoff-send.txt', root('/data/local/tmp/s301-tun-packets ' +
                                      shlex.quote(interface) + ' valid 1'))
        rejected = drain('handoff-rejected', int(after[0]['captured']) + 1)
        assert int(rejected[2]['rejected']) >= int(after[2]['rejected']) + 1
        assert int(rejected[0]['runtime_drops']) >= int(after[0]['runtime_drops']) + 1
        assert rejected[2]['owner_failures'] == '0'
        capacity('capacity-restore', 'product capacity off')
        save('recovery-send.txt', root('/data/local/tmp/s301-tun-packets ' +
                                       shlex.quote(interface) + ' valid 1'))
        recovered = drain('recovered', int(rejected[0]['captured']) + 1)
        assert int(recovered[2]['published']) >= int(rejected[2]['published']) + 1
        assert int(recovered[2]['received']) >= int(rejected[2]['received']) + 1
        assert recovered[2]['owner_failures'] == '0'
        capacity('completion-capacity',
            'product capacity credits 32 primary-slots 64 completion-slots 2')
        if a.stop_during_congestion:
            held = cli('original-hold', 'product tun original-hold 5000')
            assert 'tun.original_hold milliseconds=5000' in held
            command = ('for i in $(seq 1 30); do /data/local/tmp/s301-tun-packets '
                       + shlex.quote(interface) + ' valid 64; sleep 0.03; done')
            flood = subprocess.Popen([str(ROOT / 'dev/adb'), '-s', SERIAL,
                'shell', 'su', '-c', shlex.quote(command)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            time.sleep(.12)
            save('stop-during-congestion.txt', action('--ez', 'runtimeStop', 'true'))
            wait_state('stopped', dict(state='stopped', mayBeActive='false', errorCode=''))
            active = False
            flood_output, _ = flood.communicate(timeout=10)
            save('flood.txt', flood_output)
            log = save('vpp.log', app('files/product-state/s237-last-stop.log'))
            lines = log.splitlines()
            cutoff = [i for i, line in enumerate(lines)
                if line.startswith('s302 event=tun_read_quiesced ')]
            graph_cutoff = [i for i, line in enumerate(lines)
                if line.startswith('s302 event=graph_quiesced ')]
            assert len(cutoff) == len(graph_cutoff) == 1 and cutoff[0] < graph_cutoff[0]
            captures = [dict(re.findall(r'(\w+)=([^\s]+)', line)) | {'line': i}
                for i, line in enumerate(lines)
                if line.startswith('s213 event=capture source=TUN_CAPTURED ')]
            completed = [dict(re.findall(r'(\w+)=([^\s]+)', line)) | {'line': i}
                for i, line in enumerate(lines)
                if line.startswith('s213 event=completion source=TUN_CAPTURED ')]
            freed = [dict(re.findall(r'(\w+)=([^\s]+)', line)) | {'line': i}
                for i, line in enumerate(lines)
                if line.startswith('s203 event=buffer_free source=TUN_CAPTURED ')]
            deferred = [dict(re.findall(r'(\w+)=([^\s]+)', line)) | {'line': i}
                for i, line in enumerate(lines)
                if line.startswith('s210 event=completion_deferred ')]
            assert captures and all(row['line'] < cutoff[0] for row in captures)
            capture_tokens = [row['token'] for row in captures]
            assert len(capture_tokens) == len(set(capture_tokens))
            assert sorted(capture_tokens) == sorted(row['token'] for row in completed)
            assert sorted(capture_tokens) == sorted(row['obligation'] for row in freed)
            assert all(row['generation'] == generation for row in completed)
            cutoff_state = dict(re.findall(r'(\w+)=([^\s]+)', lines[cutoff[0]]))
            assert deferred and int(cutoff_state['pending']) > 0
            assert any(row['line'] > cutoff[0] for row in completed)
            assert 's213 event=stop generation=' + generation in log
            assert 'pending=0 buffers=0 frames=0 obligations=0 tun_fd=-1' in log
            result['congestion'] = dict(captures=len(captures), deferred=len(deferred),
                pending_at_cutoff=int(cutoff_state['pending']),
                completion_after_cutoff=sum(row['line'] > cutoff[0] for row in completed))
            result['status'] = 'RAW_COMPLETE'
            return
        save('completion-burst-send.txt', root('/data/local/tmp/s301-tun-packets ' +
                                               shlex.quote(interface) + ' valid 64'))
        congested = drain('completion-congested', int(recovered[0]['captured']) + 64)
        assert int(congested[2]['deferred']) > int(recovered[2]['deferred'])
        assert int(congested[2]['retries']) > int(recovered[2]['retries'])
        assert congested[2]['pending_returns'] == congested[2]['handoff_debt'] == '0'
        capacity('completion-restore', 'product capacity off')
        fragment_before = fields(cli('fragment-before', 'show product reassembly'),
                                 'reassembly.status ')
        save('fragment-send.txt', root('/data/local/tmp/s301-tun-packets ' +
                                       shlex.quote(interface) + ' fragment 1'))
        fragmented = drain('fragmented', int(congested[0]['captured']) + 2)
        fragment_after = fields(cli('fragment-after', 'show product reassembly'),
                                'reassembly.status ')
        assert all(fragment_after[key] == '0' for key in ('contexts', 'originals', 'retained'))
        assert int(fragment_after['completed']) >= int(fragment_before['completed']) + 1
        save('vpp.log', app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
        result['status'] = 'RAW_COMPLETE'
        result['before'] = before
        result['after_capture_alloc'] = after
        result['handoff_rejected'] = rejected
        result['recovered'] = recovered
        result['completion_congested'] = congested
        result['fragmented'] = fragmented
        result['fragment_before'] = fragment_before
        result['fragment_after'] = fragment_after
    except Exception as error:
        result['error'] = repr(error)
        save('failure-state.txt', app(STATE))
        save('failure-vpp.log', app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
        raise
    finally:
        if active:
            save('stop.txt', action('--ez', 'runtimeStop', 'true'))
            try:
                wait_state('stopped', dict(state='stopped', mayBeActive='false', errorCode=''))
                processes = save('processes-after-stop.txt', adb('shell', 'ps', '-A', '-o', 'PID,UID,ARGS'))
                assert not any('libvpp_runtime.so' in line for line in processes.splitlines())
            except Exception as error: result['stop_error'] = repr(error)
        save('restore.txt', adb('install', '-r', '-d', restore))
        restored_path = adb('shell', 'pm', 'path', PKG).strip().removeprefix('package:')
        result['restored_sha256'] = adb('shell', 'sha256sum', restored_path).split()[0]
        result['final_route'] = save('route-after.txt', adb('shell', 'ip', 'route'))
        result['final_wifi'] = save('wifi-after.txt', adb('shell', 'cmd', 'wifi', 'status'))
        assert result['restored_sha256'] == result['restore_sha256']
        assert result['final_route'] == result['initial_route']
        assert re.search(r'Wifi is connected to "([^"]+)"', result['initial_wifi']).group(1) == \
            re.search(r'Wifi is connected to "([^"]+)"', result['final_wifi']).group(1)
        assert 'stop_error' not in result, result.get('stop_error')
        result['completed_ns'] = time.time_ns()
        save('result.json', json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
