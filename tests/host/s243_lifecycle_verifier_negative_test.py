#!/usr/bin/env python3
"""Tampered lifecycle evidence must fail independent acceptance checks."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--mode', choices=['active', 'recovery', 'underlay'], required=True)
parser.add_argument('--build', type=Path, required=True)
parser.add_argument('--run', type=Path, required=True)
args = parser.parse_args()
spec = importlib.util.spec_from_file_location('verify243negative', ROOT / ('tests/device/verify-s243-' + args.mode + '.py'))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
verifier.verify(args.build, args.run)
baseline = json.loads((args.run / 'result.json').read_text())


def change(path, old, new):
    text = path.read_text()
    assert old in text, str(path)
    path.write_text(text.replace(old, new, 1))


def alter_state(directory, label, key, value):
    path = directory / (label + '.properties')
    text = path.read_text()
    text, count = re.subn(r'^' + key + r'=.*$', key + '=' + value, text, count=1, flags=re.M)
    assert count == 1
    path.write_text(text)
    result = json.loads((directory / 'result.json').read_text())
    next(e for e in result['events'] if e['label'] == label)['state'][key] = value
    (directory / 'result.json').write_text(json.dumps(result))


mutations = [('wrong_installed_apk', lambda d: change(d / 'installed-apk.txt', baseline['apk_sha256'], '0' * 64))]
if args.mode == 'recovery':
    states = {e['label']: e.get('state', {}) for e in baseline['events']}
    cancelled = states['cancel-recovery']['generation']
    initial = states['initial']['generation']
    mutations += [
        ('old_generation_reused', lambda d: alter_state(d, 'automatic-restart', 'generation', initial)),
        ('stale_retry_after_stop', lambda d: (d / 'service.log').write_text((d / 'service.log').read_text()
             + '\ns243 recovery=starting old_generation=' + cancelled + ' request_epoch=1\n')),
        ('vpn_not_withdrawn', lambda d: change(d / 'exhausted-vpn.txt', 'Active vpn type: -1', 'Active vpn type: 2')),
        ('native_process_left', lambda d: (d / 'exhausted-process-after.txt').write_text('123 12632 libvpp_runtime.so\n')),
        ('terminal_error_not_cleared', lambda d: alter_state(d, 'clear-terminal-error', 'errorCode', 'cleanup_failed')),
    ]
    if baseline.get('ordinary_connectivity'):
        probe = baseline['ordinary_connectivity'][0]['probes'][0]
        mutations.append(('ordinary_echo_missing', lambda d: change(d / (probe['name'] + '.properties'),
                           'result=tcp_echo_matched', 'result=tcp_connect_failed')))
elif args.mode == 'underlay':
    native = 'underlay/replacement-native-stop.log'
    text = (args.run / native).read_text()
    free = next(line for line in text.splitlines() if line.startswith('s203 event=buffer_free '))
    invalidation = next(line for line in text.splitlines() if line.startswith('s243 event=underlay_invalidation '))
    rebound = next(line for line in text.splitlines() if line.startswith('s237 event=broker_reply ') and ' epoch=2 ' in line)
    new_output = next(line for line in text.splitlines() if line.startswith('s237 event=output ') and ' session=7 ' in line)
    update = next(line for line in text.splitlines() if line.startswith('s223 event=udp_update ') and ' created=0 ' in line
                  and ' source=TUN_CAPTURED ' in line)
    incarnation = re.search(r' incarnation=(\d+)', update).group(1)
    stopped = next(line for line in text.splitlines() if line.startswith('s237 event=owner_stopped '))
    probe = next(p for p in baseline['runs'][0]['probes'] if '/held-udp' in p['label'])
    mutations += [
        ('buffer_release_missing', lambda d: change(d / native, free + '\n', '')),
        ('epoch_invalidation_missing', lambda d: change(d / native, invalidation + '\n', '')),
        ('old_binding_reused', lambda d: change(d / native, rebound, rebound.replace('epoch=2', 'epoch=1'))),
        ('old_udp_session_reused', lambda d: change(d / native, new_output, new_output.replace('session=7', 'session=3'))),
        ('vpp_flow_recreated', lambda d: change(d / native, update, update.replace('incarnation=' + incarnation, 'incarnation=9999'))),
        ('unclosed_socket', lambda d: change(d / native, stopped, stopped.replace('sockets_closed=12', 'sockets_closed=11'))),
        ('no_underlay_packet_leaked', lambda d: (d / 'udp-endpoint-4.log').write_text(
            (d / 'udp-endpoint-4.log').read_text() + '\nnonce=' + probe['nonce'][1:] + '_0:1 echo=1\n')),
    ]
else:
    record = next(r for r in baseline['runs'] if r['case'] != 'crash')
    case = record['case']
    native = case + ('/old-native-stop.log' if case == 'stop' else '/old-native-failure.log')
    text = (args.run / native).read_text()
    free = next(line for line in text.splitlines() if line.startswith('s203 event=buffer_free '))
    pbuf = next(line for line in text.splitlines() if line.startswith('s237 event=pbuf_free '))
    changed_pbuf = pbuf.replace('tls=1', 'tls=2') if 'tls=1' in pbuf else pbuf.replace('tls=2', 'tls=1')
    stopped = next(line for line in text.splitlines() if line.startswith('s237 event=owner_stopped '))
    def early_platform_close(directory):
        path = directory / case / 'service.log'
        lines = path.read_text().splitlines()
        closed = next(i for i, line in enumerate(lines) if
                      'network_subscription_closed generation=' + str(record['generation']) + ' ' in line)
        drained = max(i for i, line in enumerate(lines[:closed]) if 's213 native_tun_drain=' in line)
        lines[drained], lines[closed] = lines[closed], lines[drained]
        path.write_text('\n'.join(lines) + '\n')
    mutations += [
        ('buffer_release_missing', lambda d: change(d / native, free + '\n', '')),
        ('wrong_callback_tls', lambda d: change(d / native, pbuf, changed_pbuf)),
        ('unclosed_socket', lambda d: change(d / native, stopped, stopped.replace('sockets_closed=4', 'sockets_closed=3'))),
        ('stale_generation', lambda d: change(d / native, 'generation=' + str(record['generation']), 'generation=1')),
        ('peer_echo_changed', lambda d: change(d / 'tcp-endpoint-4.log', 'raw=45', 'raw=46')),
        ('platform_facts_cleared_early', early_platform_close),
    ]
for name, mutate in mutations:
    with tempfile.TemporaryDirectory(prefix='s243-evidence-negative-') as temporary:
        directory = Path(temporary) / 'run'
        shutil.copytree(args.run, directory)
        mutate(directory)
        try:
            verifier.verify(args.build, directory)
        except (AssertionError, KeyError, ValueError, StopIteration):
            print(name + ': rejected')
        else:
            raise AssertionError(name + ': corrupted evidence passed')
print('S243 ' + args.mode + ' verifier negative cases: PASS')
