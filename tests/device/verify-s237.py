#!/usr/bin/env python3
"""Offline cross-check of actual S237 packet, callback and resource witnesses.

Does not accept the runner's status string as proof. Requires the current
Product source, built APK, installed hashes, saved test sources and raw trace.
"""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[2]

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def fields(line):
    return dict(re.findall(r'(\w+)=([^\s]+)', line))

def rows(text, prefix):
    return [(i, fields(line)) for i, line in enumerate(text.splitlines()) if line.startswith(prefix)]

def props(text):
    return dict(line.split('=', 1) for line in text.splitlines() if '=' in line and not line.startswith('#'))

def verify_build(path):
    b = json.loads(path.read_text())
    assert digest(b['apk']) == b['apk_sha256'], 'APK changed'
    assert digest(path.parent / 'dirty.diff') == b['dirty_diff_sha256'], 'dirty source witness changed'
    spec = importlib.util.spec_from_file_location('chain', ROOT / 'tests/evidence/product_chain.py')
    chain = importlib.util.module_from_spec(spec); spec.loader.exec_module(chain)
    assert chain.source_files() == b['files'], 'current Product differs from build'
    assert hashlib.sha256(chain.encode(b['files'])).hexdigest() == b['source_sha256']
    for name, value in b['files'].items():
        if value is not None: assert digest(path.parent / 'source' / name) == value, name
    with zipfile.ZipFile(b['apk']) as apk:
        actual = {Path(n).name: hashlib.sha256(apk.read(n)).hexdigest()
                  for n in apk.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}
        assert actual == b['native_sha256']
        assert b'Swedish Institute of Computer Science' in apk.read('assets/hev-notices.txt')
    return b

def verify_run(build_path, b, directory):
    r = json.loads((directory / 'result.json').read_text())
    assert not r.get('diagnostic_clear_stale_iif'), 'platform-mutating diagnosis is not acceptance'
    assert r['build_sha256'] == digest(build_path), 'different build witness'
    assert r['apk_sha256'] == b['apk_sha256']
    assert b['completed_ns'] < r['started_ns'] < r['completed_ns']
    assert not r.get('error') and not r.get('cleanup_error'), 'failed run'
    assert r['serial'] == '28201JEGR0XPAJ'
    assert (directory / 'installed-apk.txt').read_text().split()[0] == b['apk_sha256']
    installed = {Path(line.split()[1]).name: line.split()[0]
                 for line in (directory / 'installed-native.txt').read_text().splitlines()}
    assert installed == b['native_sha256'], 'installed native mismatch'
    assert r.get('test_inputs'), 'missing test-source closure'
    for name, value in r['test_inputs'].items():
        assert digest(directory / 'test-source' / name) == value, name
    assert digest(directory / 'udp-endpoint') == r['endpoint_sha256']
    assert 'aarch64' in (directory / 'device.txt').read_text()
    generation = str(r['generation'])
    trace = (directory / 'native-stop.log').read_text()
    lines = trace.splitlines()
    heap = {}
    allocations = 0
    for _, event in rows(trace, 's237 event='):
        if 'generation' in event: assert event['generation'] == generation, 'mixed generations'
        if 'thread' in event: assert event['thread'] == '1', 'wrong callback thread'
        if 'tls' in event: assert event['tls'] == '1', 'wrong callback TLS'
        if event['event'] == 'pbuf_alloc':
            assert event['object'] not in heap, 'overlapping pbuf allocations'
            heap[event['object']] = event['kind']; allocations += 1
        elif event['event'] == 'pbuf_free':
            assert heap.pop(event['object']) == event['kind'], 'wrong pbuf free'
    assert allocations and not heap, 'unreleased pbuf interval'
    stopped = rows(trace, 's237 event=owner_stopped ')
    assert len(stopped) == 1
    end = stopped[0][1]
    assert all(end[k] == '0' for k in ['sessions', 'inputs', 'pbufs', 'buffers', 'obligations', 'frames'])
    assert end['sockets_created'] == end['sockets_closed'] == '1'
    assert end['timer_fd'] == end['broker_fd'] == '-1'
    destroyed = rows(trace, 's237 event=owner_destroyed ')
    assert len(destroyed) == 1 and destroyed[0][0] < stopped[0][0]
    assert destroyed[0][1]['bytes'] == destroyed[0][1]['kind'] == '0'
    assert len(rows(trace, 's237 event=session_created ')) == 1, 'session replaced'
    assert len(rows(trace, 's237 event=socket_created ')) == 1, 'socket replaced'
    broker = rows(trace, 's237 event=broker_reply ')
    assert len(broker) == 1 and broker[0][1]['success'] == '1' and broker[0][1]['result'] == '0'
    uid_known, context_known = r.get('identity_available', True), r.get('context_available', True)
    expected_availability = int(uid_known) + 4 * int(context_known)
    fault = r.get('fault', 'none')
    names = {'input-reject': 'fault_input_capacity', 'output-alloc': 'fault_output_allocation',
             'pre-accept': 'fault_pre_accept', 'write': 'fault_tun_write', 'stale-output': 'fault_stale_output'}
    if fault != 'none': assert len(rows(trace, 's237 event=' + names[fault] + ' ')) == 1
    if fault == 'stale-output':
        stale = rows(trace, 's237 event=fault_stale_output ')[0][1]
        assert stale['current_generation'] == generation and int(stale['supplied_generation']) != int(generation)
    after = (directory / 'after.txt').read_text()
    input_copies = rows(after, 'flow_stack.copies ')[0][1]
    output_copies = rows(after, 'tun.copies ')[0][1]
    expected_inputs = 2 if fault == 'input-reject' else 3
    expected_copies = 2 if fault in ('input-reject', 'output-alloc', 'stale-output') else 3
    family = r.get('family', 4)
    assert family in (4, 6)
    size = len(r['nonce']) + (30 if family == 4 else 50)
    assert int(input_copies['calls']) == expected_inputs and int(input_copies['bytes']) == expected_inputs * size
    assert int(output_copies['calls']) == expected_copies and int(output_copies['bytes']) == expected_copies * size
    endpoint = (directory / 'endpoint.log').read_text()
    rounds = [(r['nonce'], directory / 'probe.properties', False)]
    for index, entry in enumerate(r.get('policy_rounds', [])):
        label = 'return-drop' if index == 0 else 'recover'
        assert 'policy rc=0' in (directory / (label + '-policy.txt')).read_text()
        rounds.append((entry['nonce'], directory / (label + '-probe.properties'), index == 0))
    for nonce, path, policy_drop in rounds:
        probe = props(path.read_text())
        assert probe['nonce'] == nonce
        for i in range(3):
            failed = policy_drop or (fault != 'none' and i == 1)
            assert probe['packet.' + str(i)] == ('timeout' if failed else 'echo')
            expected_receipt = not (fault == 'input-reject' and i == 1)
            assert endpoint.count('nonce=' + nonce[1:] + ':' + str(i) + ' echo=1') == int(expected_receipt)
    rejected = {e['token'] for _, e in rows(trace, 's237 event=fault_pre_accept ')}
    for token in rejected:
        freed = [e for _, e in rows(trace, 's237 event=return_rejected_free ') if e['token'] == token]
        assert len(freed) == 1, 'missing pre-admission VPP free witness'
    copies = rows(trace, 's237 event=return_copy ')
    assert copies and any(int(c['spans']) > 1 for _, c in copies), 'no actual multi-span copy'
    expected_outputs = 3 * len(rounds) - int(fault in ('input-reject', 'output-alloc', 'pre-accept', 'stale-output'))
    admitted_returns = rows(trace, 's216 stage=admit source=FLOW_STACK_RETURN ')
    assert len(admitted_returns) == expected_outputs
    copy_tokens = [c['token'] for _, c in copies]
    admitted_tokens = [e['token'] for _, e in admitted_returns]
    assert len(copy_tokens) == len(set(copy_tokens)), 'duplicate return copy'
    assert len(admitted_tokens) == len(set(admitted_tokens)), 'duplicate return admission'
    assert set(copy_tokens) == set(admitted_tokens) | rejected, 'unmatched return copy/admission'
    for copy_index, copy in copies:
        assert int(copy['availability']) == expected_availability
        assert int(copy['uid']) == (r['uid'] if uid_known else 0)
        assert int(copy['context']) == (1 if context_known else 0)
        token = copy['token']
        admitted = [(i, e) for i, e in admitted_returns if e['token'] == token]
        if token in rejected:
            assert not admitted
            continue
        assert len(admitted) == 1 and admitted[0][0] > copy_index
        position, event = admitted[0]
        assert event['provenance'] == '3' and event['direction'] == '1'
        assert event['owner'] == '0' and event['thread'] == '1' and event['ifindex'] == '0'
        assert event['generation'] == generation and event['buffer'] == copy['buffer']
        for key in ['uid', 'availability', 'context']:
            assert event[key] == copy[key], 'return admission changed ' + key
        endpoint_ip = ipaddress.ip_address(r['endpoint'])
        assert endpoint_ip.version == family and event['family'] == str(family)
        assert event['protocol'] == '17'
        assert event['src'] == endpoint_ip.packed.rjust(16, b'\0').hex()
        tun_ip = ipaddress.ip_address('10.111.0.2' if family == 4 else 'fd00:111:111::2')
        assert event['dst'] == tun_ip.packed.rjust(16, b'\0').hex()
        assert int(event['src_port']) == r['endpoint_port'] and int(event['dst_port']) == r['source_port']
        # Submission callback completes before the shared graph executes.
        assert any(line.startswith('s237 event=output ') for line in lines[copy_index + 1:position])
        for stage in ['policy', 'terminal']:
            matched = [(i, e) for i, e in rows(trace, 's216 stage=' + stage + ' source=FLOW_STACK_RETURN ')
                       if e['token'] == token]
            assert len(matched) == 1 and matched[0][0] > position
            assert matched[0][1]['owner'] == '0' and matched[0][1]['thread'] == '1'
            for key in ['uid', 'availability', 'context', 'provenance', 'generation',
                        'direction', 'buffer', 'src', 'dst', 'src_port', 'dst_port',
                        'family', 'protocol', 'packet_length', 'ifindex']:
                assert matched[0][1][key] == event[key], stage + ' changed ' + key
            position = matched[0][0]
        completions = [(i, e) for i, e in rows(trace, 's213 event=completion source=FLOW_STACK_RETURN ')
                       if e['token'] == token]
        frees = [(i, e) for i, e in rows(trace, 's203 event=buffer_free ') if e['obligation'] == token]
        assert len(completions) == len(frees) == 1
        assert position < completions[0][0] < frees[0][0], 'completion/free order'
        assert completions[0][1]['buffer'] == frees[0][1]['buffer'] == copy['buffer']
        assert completions[0][1]['generation'] == generation
        if completions[0][1]['policy_drop'] == '1': assert completions[0][1]['transport_outcome'] == 'NOT_ATTEMPTED'
        assert not any(e['token'] == token for _, e in rows(trace, 's237 event=input_copy ')), 'return re-entered HEV'
    begins = rows(trace, 's237 event=quiesce_begin ')
    assert len(begins) == 1 and begins[0][0] < destroyed[0][0]
    tail = '\n'.join(lines[begins[0][0] + 1:])
    assert not any('event=' + name + ' ' in tail for name in ['return_copy', 'output', 'pbuf_alloc', 'socket_created'])
    if 'held_nonce' in r:
        assert int(begins[0][1]['inputs']) > 0 and r['held_nonce'][1:] not in endpoint
    state = props((directory / 'stopped.properties').read_text())
    assert state['state'] == 'stopped' and state['mayBeActive'] == 'false' and state['errorCode'] == ''
    assert state['generation'] == generation
    assert 'libvpp_runtime.so' not in (directory / 'processes-after.txt').read_text()
    return {'run': str(directory), 'generation': generation, 'returns': len(admitted_returns), 'pbuf_allocations': allocations}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('runs', nargs='+', type=Path)
    args = parser.parse_args()
    build = verify_build(args.build)
    results = [verify_run(args.build, build, run) for run in args.runs]
    print(json.dumps({'status': 'PASS', 'scope': 'specified S237 runs only', 'runs': results}, indent=2))
