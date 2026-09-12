#!/usr/bin/env python3
"""Independent S233 verifier: derive origins from raw kernel/endpoint evidence."""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def need(value, message):
    if not value:
        raise AssertionError(message)


def rows(text, prefix):
    return [dict(part.split('=', 1) for part in line.split()[1:] if '=' in part)
            for line in text.splitlines() if line.startswith(prefix)]


def udp(raw):
    data = bytes.fromhex(raw)
    family = data[0] >> 4
    if family == 4:
        offset, protocol = (data[0] & 15)*4, data[9]
        source, destination = data[12:16], data[16:20]
        need(struct.unpack_from('!H', data, 2)[0] == len(data), 'IPv4 captured length')
    else:
        need(family == 6, 'IP family')
        offset, protocol = 40, data[6]
        source, destination = data[8:24], data[24:40]
        need(struct.unpack_from('!H', data, 4)[0]+40 == len(data), 'IPv6 captured length')
    need(protocol == 17 and len(data) >= offset+8, 'kernel UDP packet')
    sport, dport, size = struct.unpack_from('!HHH', data, offset)
    need(size == len(data)-offset, 'UDP captured length')
    return dict(family=family, source=str(ipaddress.ip_address(source)), destination=str(ipaddress.ip_address(destination)),
                source_port=sport, destination_port=dport, payload=data[offset+8:])


def netlink_packet(raw):
    data = bytes.fromhex(raw)
    length, kind = struct.unpack_from('<IH', data)
    need(length == len(data) and kind == 0x300 and data[17] == 0, 'native NFQUEUE envelope')
    queue = struct.unpack_from('!H', data, 18)[0]
    offset, packet_id, packet = 20, None, None
    while offset+4 <= length:
        size, kind = struct.unpack_from('<HH', data, offset)
        need(size >= 4 and offset+size <= length, 'complete NFQA attribute')
        if kind & 0x3fff == 1:
            need(size >= 11 and packet_id is None, 'one mandatory identity')
            packet_id = struct.unpack_from('!I', data, offset+4)[0]
        if kind & 0x3fff == 10:
            need(packet is None, 'one NFQA payload')
            packet = udp(data[offset+4:offset+size].hex())
        offset += (size+3) & ~3
    need(packet_id is not None and packet is not None, 'real identity and payload')
    return queue, packet_id, packet


def netlink_sockets(path):
    result = {}
    for line in path.read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) == 10 and fields[1] == '12' and fields[2] != '0':
            result[fields[9]] = dict(rmem=int(fields[4]), drops=int(fields[8]))
    return result


def check_run(base, record, result):
    label, generation = record['label'], str(record['generation'])
    run = base/label
    text = (run/'vpp.log').read_text()
    need(record.get('raw_complete'), label+' raw completion')
    need('GRAPH_INJECTED' not in text and 'COMPLETION_REPLAY' not in text, label+' real ingress only')
    config = [r for r in rows(text, 's233 ') if r.get('event') == 'queue_config']
    need(len(config) == 4 and {r['lane'] for r in config} == set('0123'), label+' four configuration ACKs')
    for r in config:
        lane = int(r['lane'])
        need(r['generation'] == generation and r['ack'] == '0' and r['flags'] == '9'
             and int(r['maxlen']) == record['maxlen'] and int(r['queue']) == 176+lane
             and int(r['family']) == (4 if lane < 2 else 6), label+' FAIL_OPEN configuration ACK')
    hooks = [l for l in (run/'hooks.txt').read_text().splitlines() if 'SAKAMOTO_S233_' in l]
    need(len(hooks) == 4 and all('--queue-bypass' in l and '-j NFQUEUE' in l for l in hooks), label+' no-listener flag')
    need(sum('--queue-balance 176:177' in l for l in hooks) == 2 and
         sum('--queue-balance 178:179' in l for l in hooks) == 2, label+' Q2 per family')
    need('SAKAMOTO_S233_' not in (run/'hooks-after.txt').read_text(), label+' hook cleanup')

    def state(phase, prefix):
        parsed = rows((run/(phase+'.txt')).read_text(), prefix)
        need(len(parsed) == 4 and {r['lane'] for r in parsed} == set('0123'), phase+' all lanes')
        return {int(r['lane']): r for r in parsed}

    def equal_delta(before, after, prefix, fields, expected):
        left, right = state(before, prefix), state(after, prefix)
        for lane in range(4):
            for field in fields:
                need(int(right[lane][field])-int(left[lane][field]) == expected,
                     f'{label}/{after} lane={lane} {field} delta={expected}')

    def pools(phase, normal=64, reserve=8, withheld=0, allocated=72):
        for r in state(phase, 'root.receive ').values():
            need(int(r['allocated']) == allocated and int(r['normal_free']) == normal
                 and int(r['reserve_free']) == reserve and int(r['withheld']) == withheld
                 and int(r['loans']) == withheld, label+'/'+phase+' fixed pool conservation')

    initial = state('initial', 'root.lane ')
    pools('initial')
    final_lanes, final_receive = state('final', 'root.lane '), state('final', 'root.receive ')
    for lane in range(4):
        native, receive = final_lanes[lane], final_receive[lane]
        need(native['failed'] == '0' and native['verdicts'] == native['succeeded']
             and native['captured'] == native['submitted'] == native['returns'], label+' physical completion conservation')
        need(int(native['verdicts']) == int(native['captured'])+int(receive['ingress_accepts']), label+' distinct verdict origins')
        need(int(receive['datagrams']) == int(native['captured'])+int(receive['ingress_accepts'])
             +int(receive['reserve_losses'])+int(receive['identity_losses']), label+' datagram outcome conservation')
    fd_map = dict(re.findall(r'\s(\d+) -> socket:\[(\d+)\]', (run/'fds-before.txt').read_text()))
    inodes = {fd_map[r['fd']] for r in initial.values()}
    need(len(inodes) == 4, label+' distinct native queue sockets')
    for phase in ('initial', 'baseline', 'final', 'closed'):
        c = rows((run/(phase+'.txt')).read_text(), 'completion.status ')
        need(len(c) == 1 and c[0]['generation'] == generation and
             all(c[0][k] == '0' for k in ('pending', 'frames', 'buffers', 'obligations')), label+'/'+phase+' settled graph')
    pools('closed', normal=0, reserve=0, allocated=0)
    closed = state('closed', 'root.lane ')
    need(all(r['fd'] == '-1' and r['ready'] == '0' and r['pending'] == '0' for r in closed.values()), label+' lane close')
    after_fds = (run/'fds-closed.txt').read_text()
    need(all('socket:['+inode+']' not in after_fds for inode in inodes), label+' queue descriptor release')
    need(json.loads((run/'stop.json').read_text())['process_absent'], label+' process release')
    if result['platform'] == 'linux':
        busy, free = [json.loads((run/(phase+'-queue-bind.json')).read_text()) for phase in ('initial', 'closed')]
        need(set(busy) == {str(q) for q in range(176, 180)} and all(v in (-1, -16) for v in busy.values()), label+' occupied queues')
        need(set(free) == set(busy) and all(v == 0 for v in free.values()), label+' queue unbind')
    else:
        for phase, depth in (('initial', 0), ('closed', None)):
            q = [l.split() for l in (run/(phase+'-queues.txt')).read_text().splitlines() if l.strip()]
            own = [r for r in q if int(r[0]) in range(176, 180)]
            need(not own if depth is None else len(own) == 4 and all(int(r[2]) == depth for r in own), label+'/'+phase+' kernel queue state')

    packets = []
    for r in rows(text, 's231 '):
        if r.get('event') == 'nfq_payload':
            need(r['source'] == 'NFQ_CAPTURED' and r['generation'] == generation and
                 int(r['queue']) == 176+int(r['lane']), label+' captured provenance')
            packets.append((r, udp(r['raw'])))
    ingress = []
    for r in rows(text, 's233 '):
        if r.get('event') == 'ingress_verdict':
            queue, packet_id, packet = netlink_packet(r['raw'])
            need(r['generation'] == generation and r['source'] == 'NFQ_CAPTURED'
                 and int(r['queue']) == queue and int(r['packet']) == packet_id
                 and r['verdict'] == '1' and r['syscall_success'] == '1', label+' one real origin ingress verdict')
            ingress.append((r, packet))
    verdicts = [r for r in rows(text, 's203 ') if r.get('event') == 'verdict']
    gates = [r for r in rows(text, 's209 ') if r.get('event') == 'gate']
    mandatory = {'policy-drop', 'policy-allow-recovery'}
    if label == 'resources':
        mandatory |= {'normal-exhausted', 'normal-recovery-drop', 'reserve-exhausted',
                      'reserve-recovery-drop', 'missing-identity', 'identity-recovery-drop'}
    elif label == 'pressure':
        mandatory.remove('policy-allow-recovery')
        mandatory |= {'queued-before-full', 'kernel-full-bypass', 'pressure-recovery-drop', 'queued-before-close', 'no-listener-bypass'}
    phases = {c['phase'] for c in record['cases']}
    need(phases == mandatory | {'seed'}, label+' exact fault/recovery matrix')
    for phase in mandatory:
        need({c['lane'] for c in record['cases'] if c['phase'] == phase} == set(range(4)), label+'/'+phase+' four-lane coverage')
    need(len({c['source_port'] for c in record['cases']}) == len(record['cases']), label+' fresh flow ports')
    for number, case in enumerate(record['cases']):
        phase = case['phase']
        expected = phase in ('seed', 'policy-allow-recovery', 'normal-exhausted', 'kernel-full-bypass', 'no-listener-bypass')
        nonce = case['nonce']+'-0'
        payload = ('E'+nonce).encode()
        client = (run/f'client-{number}.txt').read_text()
        endpoint = (base/f'endpoint-{case["family"]}.log').read_text()
        received = [r for r in rows(endpoint, 'received ') if r.get('nonce') == nonce]
        need(case['expected'] is expected and case['delivered'] is expected and case['endpoint_observed'] is expected,
             label+'/'+phase+' derived delivery result')
        need(len(received) == int(expected), label+'/'+phase+' independent endpoint receipt count')
        if expected:
            answer = rows(client, 'endpoint ')
            need(case['returncode'] == 0 and len(answer) == 1 and answer[0]['nonce'] == nonce
                 and answer[0]['received'] == '1' and answer[0]['sent'] == '1', label+'/'+phase+' matching endpoint echo')
        else:
            need(case['returncode'] != 0 and not rows(client, 'endpoint '), label+'/'+phase+' no endpoint echo')
        normal = [(r, packet) for r, packet in packets if packet['payload'] == payload and r['hook'] == '3']
        fallback = [(r, packet) for r, packet in ingress if packet['payload'] == payload and packet['destination_port'] == 40633]
        bypass = phase in ('kernel-full-bypass', 'no-listener-bypass', 'reserve-exhausted', 'missing-identity', 'queued-before-close')
        if phase == 'normal-exhausted':
            need(not normal and len(fallback) == 1 and fallback[0][0]['reason'] == 'normal_exhausted', label+' reserve origin, not graph policy')
            continue
        need(not fallback, label+'/'+phase+' no invented ingress verdict')
        if bypass:
            need(not normal, label+'/'+phase+' no userspace capture/verdict')
            continue
        need(len(normal) == 1, label+'/'+phase+' one real kernel capture')
        r, packet = normal[0]
        need(int(r['lane']) == case['lane'] and packet['family'] == case['family']
             and packet['destination'] == case['host'] and packet['source_port'] == case['source_port']
             and packet['destination_port'] == 40633, label+'/'+phase+' raw packet identity')
        physical = [v for v in verdicts if v['generation'] == generation and v['lane'] == r['lane'] and v['packet'] == r['packet']]
        need(len(physical) == 1 and physical[0]['verdict'] == ('1' if expected else '0')
             and physical[0]['source'] == 'NFQ_CAPTURED' and physical[0]['obligation'] == r['token'], label+'/'+phase+' physical verdict preserves policy')
        if not expected:
            decision = [g for g in gates if g['generation'] == generation and g['token'] == r['token']]
            need(len(decision) == 1 and decision[0]['action'] == '2' and decision[0]['rule'] == '21701', label+'/'+phase+' actual policy DROP')
    facts = [r for r in rows(text, 's217 ') if r.get('event') == 'nfq_facts' and r['raw_hook'] == '3']
    need(facts and all(r['fault'] == '0' and r['raw_uid_present'] == '1' and
         r['raw_uid'] == result['policy_uid'] and r['normalized_uid'] == result['policy_uid'] for r in facts), label+' unmodified kernel subject identity')

    if label == 'resources':
        pools('normal-held', normal=0, withheld=64)
        pools('normal-exhausted', normal=0, withheld=64)
        equal_delta('normal-held', 'normal-exhausted', 'root.receive ', ('datagrams', 'ingress_accepts', 'reserve_accepts'), 2)
        equal_delta('normal-held', 'normal-exhausted', 'root.lane ', ('captured', 'submitted'), 0)
        equal_delta('normal-held', 'normal-exhausted', 'root.lane ', ('verdicts', 'succeeded'), 2)
        for before, after, loss in (('reserve-held', 'reserve-exhausted', 'reserve_losses'), ('identity-armed', 'missing-identity', 'identity_losses')):
            equal_delta(before, after, 'root.receive ', ('datagrams', loss), 1)
            equal_delta(before, after, 'root.receive ', ('ingress_accepts', 'reserve_accepts'), 0)
            equal_delta(before, after, 'root.lane ', ('captured', 'submitted', 'verdicts', 'succeeded'), 0)
        pools('reserve-held', normal=0, reserve=0, withheld=72)
        pools('reserve-exhausted', normal=0, reserve=0, withheld=72)
        for phase in ('normal-recovery-drop', 'reserve-recovery-drop', 'identity-recovery-drop', 'final'):
            pools(phase)
        losses = [r for r in rows(text, 's233 ') if r.get('event') == 'ingress_loss']
        for reason in ('reserve_exhausted', 'missing_identity'):
            chosen = [r for r in losses if r['reason'] == reason]
            need(len(chosen) == 4 and {r['lane'] for r in chosen} == set('0123') and
                 all(r['verdict_attempted'] == '0' and 'packet' not in r and int(r['bytes']) > 0 for r in chosen), label+'/'+reason+' explicit identity-safe loss')
    elif label == 'pressure':
        for before, after in (('paused-empty', 'paused-full'), ('paused-full', 'kernel-full-bypass'), ('listeners-closed', 'no-listener-bypass')):
            equal_delta(before, after, 'root.receive ', ('datagrams', 'ingress_accepts', 'reserve_accepts', 'reserve_losses', 'identity_losses'), 0)
            equal_delta(before, after, 'root.lane ', ('captured', 'submitted', 'verdicts', 'succeeded'), 0)
        for phase in ('paused-empty', 'paused-full', 'kernel-full-bypass', 'close-queued'):
            need(all(r['paused'] == '1' for r in state(phase, 'root.receive ').values()), phase+' consumer paused')
            need(all(r['ready'] == '1' and int(r['fd']) >= 0 for r in state(phase, 'root.lane ').values()), phase+' listener remains bound')
        for phase in ('paused-full', 'kernel-full-bypass', 'close-queued'):
            sockets = netlink_sockets(run/(phase+'-netlink.txt'))
            need(all(inode in sockets and 0 < sockets[inode]['rmem'] <= 4096 and sockets[inode]['drops'] == 0 for inode in inodes), phase+' one small netlink message, not socket overflow')
        before, after = [netlink_sockets(run/(phase+'-netlink.txt')) for phase in ('paused-full', 'kernel-full-bypass')]
        need(all(before[inode] == after[inode] for inode in inodes), 'kernel bypass leaves queued socket message unchanged')
        equal_delta('kernel-full-bypass', 'unpaused-drop', 'root.lane ', ('captured', 'submitted', 'verdicts', 'succeeded'), 1)
        for phase in ('listeners-closed', 'no-listener-bypass'):
            pools(phase, normal=0, reserve=0, allocated=0)
            need(all(r['ready'] == '0' and r['fd'] == '-1' for r in state(phase, 'root.lane ').values()), phase+' true no listener')
        if result['platform'] == 'pixel':
            for phase in ('paused-full', 'kernel-full-bypass', 'close-queued'):
                q = [line.split() for line in (run/(phase+'-queues.txt')).read_text().splitlines() if line.strip()]
                own = [r for r in q if int(r[0]) in range(176, 180)]
                need(len(own) == 4 and all(r[2] == '1' for r in own), phase+' actual kernel queue-full')
        else:
            for phase in ('paused-full', 'kernel-full-bypass'):
                need(all(v in (-1, -16) for v in json.loads((run/(phase+'-queue-bind.json')).read_text()).values()), phase+' queue ownership retained')
            for phase in ('listeners-closed', 'no-listener-bypass'):
                need(all(v == 0 for v in json.loads((run/(phase+'-queue-bind.json')).read_text()).values()), phase+' no queue owner')
    return dict(label=label, generation=int(generation), cases=len(record['cases']))


def verify(base):
    result = json.loads((base/'result.json').read_text())
    build_path, helper_path = Path(result['build']), Path(result['helpers'])
    need(digest(build_path) == result['build_sha256'] and digest(helper_path) == result['helpers_sha256'], 'immutable build/helper witnesses')
    build, helper = json.loads(build_path.read_text()), json.loads(helper_path.read_text())
    spec = importlib.util.spec_from_file_location('chain', ROOT/'tests/evidence/product_chain.py')
    chain = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(chain)
    need(build['files'] == chain.source_files() and build['source_sha256'] == result['source_sha256'], 'current Product source')
    need(hashlib.sha256(chain.encode(build['files'])).hexdigest() == build['source_sha256'], 'canonical Product source hash')
    need(digest(build_path.parent/'dirty.diff') == build['dirty_diff_sha256'], 'build dirty diff witness')
    for name, expected in build['files'].items():
        if expected is not None:
            need(digest(build_path.parent/'source'/name) == expected, 'frozen Product source '+name)
    need(build['started_ns'] < build['completed_ns'] < result['started_ns'] < result['completed_ns'], 'fresh build/run order')
    need(helper['build_sha256'] == digest(build_path), 'helper belongs to this build')
    need(result['runner_sha256'] == digest(ROOT/'tests/device/s233-fail-open.py'), 'collector source identity')
    for name, expected in helper['files'].items():
        need(digest(helper_path.parent/name) == expected, 'helper binary/source '+name)
    if result['platform'] == 'pixel':
        need(digest(build['apk']) == build['apk_sha256'], 'built APK')
        need((base/'installed-apk.txt').read_text().split()[0] == build['apk_sha256'], 'installed APK')
        installed = {Path(l.split()[1]).name: l.split()[0] for l in (base/'installed-native.txt').read_text().splitlines()}
        need(installed == build['native_sha256'], 'installed native objects')
        need(result['uid'] == result['policy_uid'], 'Pixel policy subject')
    else:
        for name, expected in build['artifact_hashes'].items():
            need(digest(Path(build['artifact'])/name) == expected, 'Linux artifact '+name)
        mapping = (base/'uid-map.txt').read_text().split()
        need(mapping == ['0', result['policy_uid'], '1'] and result['uid'] == '0', 'explicit namespace UID mapping')
    need(result['status'] == 'RAW_COMPLETE' and [r['label'] for r in result['runs']] == ['resources', 'pressure', 'restart'], 'complete three-generation matrix')
    need(len({r['generation'] for r in result['runs']}) == 3, 'distinct generation recovery')
    checked = [check_run(base, record, result) for record in result['runs']]
    need(result['endpoint_cleanup'] and all(r['process_absent'] for r in result['endpoint_cleanup']), 'endpoint cleanup')
    need('SAKAMOTO_S233_' not in (base/'hooks-after.txt').read_text(), 'final hook cleanup')
    need('fd20:6233:' not in (base/'addresses-after.txt').read_text(), 'owned IPv6 address cleanup')
    return dict(status='PASS', platform=result['platform'], source_sha256=result['source_sha256'],
                build_sha256=result['build_sha256'], verifier_sha256=digest(__file__), runs=checked,
                origins=['kernel_no_listener', 'kernel_queue_full', 'origin_ingress_reserve'],
                explicit_losses=['reserve_exhausted', 'missing_identity'])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    args = parser.parse_args()
    try:
        report = verify(args.run.resolve())
    except (AssertionError, KeyError, ValueError, OSError, struct.error) as error:
        report = dict(status='HOLD', error=str(error))
    (args.run/'verification.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report['status'] == 'PASS' else 1)


if __name__ == '__main__':
    main()
