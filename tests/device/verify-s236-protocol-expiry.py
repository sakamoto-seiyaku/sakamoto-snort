#!/usr/bin/env python3
"""Raw wire -> pinned tracker oracle -> actual deadline -> unique native END."""
import argparse
from collections import Counter, defaultdict
import copy
import ctypes
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
MAX_U64, NO_SLOT = 2**64-1, 2**32-1
DURATIONS = {1: 60000000, 2: 60000000, 3: 30000000, 4: 30000000, 5: 30000000,
    6: 86400000000, 7: 900000000, 8: 45000000, 9: 30000000, 10: 60000000, 11: 30000000}
CLASSES = {'tcp-first': 4, 'tcp-opening': 5, 'tcp-fin-wait': 8, 'tcp-closed': 9,
    'tcp-invalid': 4, 'icmp-first': 10, 'icmp-reply': 11, 'icmp-renew': 10, 'icmp-shorten': 11, 'long': 6}


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


icmp = module('s236_icmp_oracle', 'tests/device/verify-s224-icmp-tracker.py')
udp = module('s236_expiry_oracle', 'tests/device/verify-s227-udp-expiry.py')
native, owner_oracle = icmp.native, icmp.oracle
need, digest, rows, checksum = icmp.need, icmp.digest, icmp.rows, icmp.checksum


def identity(row):
    return int(row.get('worker', row.get('owner'))), int(row['slot']), int(row['incarnation'])


def packet(raw):
    data = bytes.fromhex(raw)
    need(28 <= len(data) <= 512, 'bounded complete raw packet')
    family = data[0] >> 4
    offset = (data[0] & 15)*4 if family == 4 else 40
    protocol = data[9] if family == 4 else data[6]
    if protocol in (1, 58): return icmp.packet(raw)
    p = native.packet(raw)
    need(protocol in (6, 17), 'protocol matrix contains unexpected protocol')
    source = data[12:16] if family == 4 else data[8:24]
    destination = data[16:20] if family == 4 else data[24:40]
    if family == 4: need(checksum(data[:offset]) == 0, 'IPv4 header checksum')
    if protocol == 17:
        segment = data[offset:]
        need(len(segment) >= 8 and struct.unpack_from('!H', segment, 4)[0] == len(segment), 'UDP datagram length')
        pseudo = source+destination+(struct.pack('!BBH', 0, 17, len(segment)) if family == 4 else struct.pack('!I3xB', len(segment), 17))
        need(checksum(pseudo+segment) == 0, 'captured UDP checksum')
        facts = dict(l3=1, l4=1, family=family, protocol=17, src=source.rjust(16, b'\0').hex(),
            dst=destination.rjust(16, b'\0').hex(), src_port=p['sport'], dst_port=p['dport'], icmp_known=0)
        a = owner_oracle.assignment(facts)
        p.update(size=len(data), facts=facts, assigned=a, header=8, offset=offset,
            key=(family, 17, a['key_a'], a['key_b'], a['port_a'], a['port_b']))
        return p
    tcp = data[offset:]; header = (tcp[12] >> 4)*4
    pseudo = source+destination+(struct.pack('!BBH', 0, 6, len(tcp)) if family == 4 else struct.pack('!I3xB', len(tcp), 6))
    need(checksum(pseudo+tcp) == 0, 'captured TCP checksum')
    seq, ack = struct.unpack_from('!II', tcp, 4)
    window = struct.unpack_from('!H', tcp, 14)[0]
    known, scale, cursor = 0, 0, 20
    while cursor < header:
        kind = tcp[cursor]
        if not kind: break
        if kind == 1: cursor += 1; continue
        need(cursor+1 < header, 'TCP option header')
        length = tcp[cursor+1]
        need(length >= 2 and cursor+length <= header, 'TCP option length')
        if kind == 3 and length == 3: known, scale = 1, min(tcp[cursor+2], 14)
        cursor += length
    facts = dict(l3=1, l4=1, family=family, protocol=6, src=source.rjust(16, b'\0').hex(),
        dst=destination.rjust(16, b'\0').hex(), src_port=p['sport'], dst_port=p['dport'], icmp_known=0)
    a = owner_oracle.assignment(facts)
    p.update(size=len(data), facts=facts, assigned=a, seq=seq, ack=ack, window=window,
        flags=tcp[13], scale=scale, known=known, header=header, offset=offset,
        key=(family, 6, a['key_a'], a['key_b'], a['port_a'], a['port_b']))
    return p


class TcpOracle:
    def __init__(self, ovs):
        timeout_file = Path(ovs)/'lib/conntrack-tp.c'
        need(digest(timeout_file) == 'bdf813dbe6d356f8d605225454fa381121ff1f0cb12ed65616250f4d93a3a44a', 'pinned OVS timeout policy source')
        defaults = {name: math.prod(int(n.strip()) for n in value.split('*'))*1000000
                    for name, value in re.findall(r'\[CT_DPIF_TP_ATTR_([A-Z_]+)\] = ([0-9 *]+),', timeout_file.read_text())}
        names = ['UDP_FIRST', 'UDP_SINGLE', 'UDP_MULTIPLE', 'TCP_SYN_SENT', 'TCP_SYN_RECV',
                 'TCP_ESTABLISHED', 'TCP_FIN_WAIT', 'TCP_TIME_WAIT', 'TCP_CLOSE', 'ICMP_FIRST', 'ICMP_REPLY']
        need({index: defaults[name] for index, name in enumerate(names, 1)} == DURATIONS, 'verifier durations differ from pinned OVS')
        self.temporary = tempfile.TemporaryDirectory(prefix='s236-ovs-')
        library = Path(self.temporary.name)/'oracle.so'
        subprocess.run(['python', str(ROOT/'tests/host/product_flow_tcp_ovs_test.py'),
            '--ovs', str(ovs), '--library-output', str(library)], check=True)
        self.ref = ctypes.CDLL(str(library))
        self.ref.oracle_create.restype = ctypes.c_void_p
        self.ref.oracle_destroy.argtypes = [ctypes.c_void_p]
        self.ref.oracle_step.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
        self.contexts = []

    def create(self):
        context = self.ref.oracle_create(); need(context, 'OVS oracle allocation')
        self.contexts.append(context); return context

    def step(self, context, p, side):
        incoming = (ctypes.c_uint32*8)(p['flags'], p['seq'], p['ack'], p['window'],
            len(p['payload']), p['known'], p['scale'], side)
        expected = (ctypes.c_uint32*15)()
        self.ref.oracle_step(context, incoming, expected)
        return list(expected)

    def close(self):
        for context in self.contexts: self.ref.oracle_destroy(context)
        self.temporary.cleanup()


def authority(run, result):
    need(result['status'] == 'RAW_COMPLETE' and not result.get('error') and not result.get('cleanup_error'), 'collector incomplete or unsafe')
    need(result['source'] == 'NFQ_CAPTURED' and result['platform'] in ('linux', 'pixel'), 'actual endpoint scope')
    build_file, helper_file = Path(result['build']), Path(result['helpers'])
    need(digest(build_file) == result['build_sha256'] and digest(helper_file) == result['helpers_sha256'], 'build/helper manifest identity')
    build, helper = json.loads(build_file.read_text()), json.loads(helper_file.read_text())
    chain = module('s236_chain_check', 'tests/evidence/product_chain.py')
    need(chain.source_files() == build['files'], 'current Product source differs from executed artifact')
    need(hashlib.sha256(chain.encode(build['files'])).hexdigest() == build['source_sha256'] == result['source_sha256'], 'source closure')
    need(digest(build_file.parent/'dirty.diff') == build['dirty_diff_sha256'], 'frozen dirty diff')
    for name, expected in build['files'].items():
        if expected is not None: need(digest(build_file.parent/'source'/name) == expected, 'frozen source '+name)
    need(build['completed_ns'] < result['started_ns'] < result['completed_ns'], 'build/run time order')
    need(helper['build_sha256'] == result['build_sha256'] and helper['source_sha256'] == result['source_sha256']
         and helper['platform'] == result['platform'], 'helper build lineage')
    for name, expected in helper['files'].items(): need(digest(helper_file.parent/name) == expected, 'helper file '+name)
    for name, expected in helper['sources'].items():
        need(digest(helper_file.parent/Path(name).name) == expected, 'frozen helper source '+name)
    need(digest(helper['compiler']['path']) == helper['compiler']['sha256'], 'helper compiler')
    for name, expected in result['test_sources'].items():
        need(digest(run/'test-source'/name) == expected, 'frozen collector/plan '+name)
        if name not in ('tests/device/s236-protocol-expiry.py', 'tests/device/s236-mixed-expiry.py') and not name.startswith('docs/'):
            need(digest(ROOT/name) == expected, 'shared collector dependency changed '+name)
    need(result['raw_hashes'], 'raw inventory absent')
    for name, expected in result['raw_hashes'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts and digest(run/name) == expected, 'raw file '+name)
    need(result['endpoints'] and all(e['process_absent'] for e in result['endpoints']), 'endpoint process residue')
    need('SAKAMOTO_S236_' not in (run/'hooks-after.txt').read_text()
         and 'SAKAMOTO_S236_' not in (run/'filter-after.txt').read_text(), 'private rule residue')
    need(('fd20:6236::2/128' in (run/'addresses-before.txt').read_text()) ==
         ('fd20:6236::2/128' in (run/'addresses-after.txt').read_text()), 'temporary address residue')
    if result['platform'] == 'linux':
        need(not build['host_evidence'] and (run/'uid-map.txt').read_text().split() == ['0', str(result['policy_uid']), '1']
             and str(result['policy_uid']) != '0', 'real rootless Product namespace')
        for name, expected in build['artifact_hashes'].items(): need(digest(Path(build['artifact'])/name) == expected, 'Linux artifact '+name)
    else:
        need(result['controls_removed'], 'UID-owned control directory residue')
        need(digest(build['apk']) == build['apk_sha256'] == (run/'installed-apk.txt').read_text().split()[0], 'installed APK identity')
        installed = {Path(line.split()[1]).name: line.split()[0] for line in (run/'installed-native.txt').read_text().splitlines()}
        need(installed == build['native_sha256'], 'installed native closure')
        with zipfile.ZipFile(build['apk']) as apk:
            need({Path(name).name: hashlib.sha256(apk.read(name)).hexdigest() for name in apk.namelist()
                if name.startswith('lib/arm64-v8a/') and name.endswith('.so')} == installed, 'APK native bytes')
        for name in ('s236-tcp', 's224-icmp', 's227-udp', 's222-tcp', 's217-policy'):
            need((run/(name+'-installed.txt')).read_text().split()[0] == helper['files'][name], 'installed endpoint '+name)
        if any(e['case'].startswith('mixed-') for e in result['generations']):
            extra = ['s223-udp', 's236-mixed']
            if any(e.get('wire_targets') for e in result['generations']): extra.append('s236-wire')
            for name in extra:
                need((run/(name+'-installed.txt')).read_text().split()[0] == helper['files'][name], 'installed mixed endpoint '+name)
        for name in ('app-before.properties', 'app-after.properties'):
            state = icmp.props((run/name).read_text())
            need(state['state'] == 'stopped' and state['mayBeActive'] == state['protectionRunning'] == 'false'
                 and not state['errorCode'], 'RuntimeService not safely stopped')
    return build


def replay(log, generation, ref):
    logical = {(int(e['owner']), int(e['new_slot']), int(e['new_incarnation'])): e
               for e in rows(log, 's227 event=logical_expiry ')}
    cap_list = rows(log, 's231 event=nfq_payload ')
    captures = {e['token']: e for e in cap_list}
    need(len(captures) == len(cap_list) and captures, 'missing/duplicate raw capture')
    packets = {token: packet(cap['raw']) for token, cap in captures.items()}
    observations = rows(log, 's208 event=observe ')
    updates = [e for line in log.splitlines() if line.startswith(('s222 event=tcp_update ', 's223 event=udp_update ', 's224 event=icmp_update '))
               for e in rows(line, line.split()[0])]
    need(Counter(e['token'] for e in observations) == Counter(e['token'] for e in updates) == Counter(captures.keys()), 'raw/observe/tracker conservation')
    observed = {e['token']: e for e in observations}
    states, versions = {}, {}
    for u in updates:
        p, e = packets[u['token']], observed[u['token']]
        a, key = p['assigned'], identity(u)
        need(key[0] == a['owner'] and int(e['owner']) == int(e['worker']) == int(e['pool_worker']) == key[0]
             and int(u['owner']) == int(u['worker']) == key[0] and int(e['thread']) == int(u['thread']) == key[0]+1,
             'tracker mutated outside canonical owner')
        need(e['source'] == u['source'] == 'NFQ_CAPTURED' and int(e['generation']) == int(u['generation']) == generation
             and int(e['policy_generation']) == generation and e['slot'] == u['slot'] and e['buffer'] == u['buffer'], 'tracker instance/carrier/generation')
        need(int(e['hash']) == int(e['stored_hash']) == a['hash'] and int(e['key_kind']) == int(e['stored_kind']) == a['key_kind'], 'typed key hash storage')
        created = key not in states
        need(int(e['created']) == int(u['created']) == created and int(e['reused']) == (not created), 'creation/reuse truth')
        if created:
            states[key] = dict(key=key, tuple=p['key'], assignment=a, origin=a['source_is_a'], first=int(e['first_seen']),
                last=0, packets=[0, 0], bytes=[0, 0], flags=[0, 0], phase=0 if p['protocol'] == 17 else 1, request=0, reply=0,
                deadline_us=0, timeout=0, context=ref.create() if p['protocol'] == 6 else None)
        s = states[key]
        need(s['tuple'] == p['key'] and int(e['origin_is_a']) == s['origin'], 'instance tuple/orientation changed')
        side = int(a['source_is_a'] != s['origin'])
        if p['protocol'] == 6:
            out = ref.step(s['context'], p, side)
            update = {11: 2, 12: 3, 14: 1}[out[0]]
            timeout, refresh = out[2]-41+4 if out[2] else 0, out[1]
            need((int(u['update']), int(u['ct_state']), int(u['timeout']), int(u['refresh'])) == (update, update, timeout, refresh), 'pinned OVS TCP result')
            previous = int(logical[key]['old_incarnation']) if created and key in logical else 0
            need(not out[4] and u['close'] == u['replacement'] == '0' and int(u['previous_incarnation']) == previous,
                 'unexpected TCP replacement/expired predecessor')
            if update != 3: s['flags'][side] |= p['flags']
            for peer, name in enumerate(('orig', 'reply')):
                actual = [int(u[name+'_'+field]) for field in ('seqlo', 'seqhi', 'maxwin', 'scale', 'state')]
                need(actual == out[5+peer*5:10+peer*5] and int(u[name+'_flags']) == s['flags'][peer], 'pinned TCP peer state/invalid rollback')
            s['peers'] = out[5:]
        elif p['protocol'] == 17:
            s['phase'] = 1 if not s['phase'] else 3 if side else 2 if s['phase'] == 1 else s['phase']
            update, timeout, refresh = 2 if s['phase'] == 3 else 1, s['phase'], 1
            need(int(u['phase']) == s['phase'] and tuple(int(u[field]) for field in ('update', 'ct_state', 'timeout', 'refresh')) ==
                 (update, update, timeout, refresh), 'pinned UDP result')
        else:
            need(all(int(u[k]) == p[k] for k in ('family', 'protocol', 'type', 'code', 'identifier', 'sequence')), 'ICMP tracker wire facts')
            if side: s['phase'] = 2
            s['request'] |= p['type'] in (8, 128); s['reply'] |= p['type'] in (0, 129)
            update, timeout, refresh = s['phase'], s['phase']+9, 1
            need(tuple(int(u[field]) for field in ('phase', 'seen_request', 'seen_reply')) == (s['phase'], s['request'], s['reply']), 'ICMP phase/seen facts')
            need(tuple(int(u[field]) for field in ('update', 'ct_state', 'timeout', 'refresh')) == (update, update, timeout, refresh), 'ICMP result')
        need(int(u['flow_dir']) == int(e['flow_dir']) == side+1 and e['invalidated'] == u['invalidated'] == '0', 'packet direction/invalidation')
        s['packets'][side] += 1; s['bytes'][side] += p['size']
        s['last'] = int(e['last_seen'])
        need(int(e['first_seen']) == s['first'] <= s['last'] and int(e['packets']) == sum(s['packets'])
             and int(e['bytes']) == sum(s['bytes']) and [int(u[n]) for n in ('orig_packets', 'reply_packets')] == s['packets'], 'packet/byte/time history')
        if refresh: s.update(deadline_us=s['last']+DURATIONS[timeout], timeout=timeout)
        versions[(key, sum(s['packets']))] = copy.deepcopy(s)
    return states, versions, packets, captures


def snapshot(text, versions, generation, wanted=None):
    entries, timers = rows(text, 'flow.entry '), rows(text, 'flow.timer ')
    need(len({identity(e) for e in entries}) == len(entries) and len(timers) == len(entries), 'snapshot entry/timer cardinality')
    if wanted is not None: need(len(entries) == wanted, 'snapshot expected instance count')
    indexed = {identity(e): e for e in timers}; result = {}
    protocols = {identity(e): e for prefix in ('flow.tcp ', 'flow.udp ', 'flow.icmp ') for e in rows(text, prefix)}
    need(protocols.keys() == {identity(e) for e in entries}, 'protocol state snapshot membership')
    for e in entries:
        key = identity(e); version = key, int(e['packets'])
        need(version in versions, 'snapshot has no actual packet history')
        s = versions[version]; a = s['assignment']; timer = indexed[key]
        expected = dict(kind=a['key_kind'], family=a['key_family'], protocol=a['key_protocol'], hash=a['hash'],
            key_a=a['key_a'], key_b=a['key_b'], port_a=a['port_a'], port_b=a['port_b'], query_class=a['query_class'],
            identifier=a['query_id'], origin_is_a=s['origin'], first_seen=s['first'], last_seen=s['last'],
            packets=sum(s['packets']), bytes=sum(s['bytes']), orig_packets=s['packets'][0], reply_packets=s['packets'][1],
            orig_bytes=s['bytes'][0], reply_bytes=s['bytes'][1], policy_generation=generation, revision=1, snapshot_hash=1)
        for field, value in expected.items(): need(e[field] == str(value), 'snapshot differs from wire history '+field)
        need(int(timer['deadline_us']) == s['deadline_us'] and int(timer['timeout']) == s['timeout']
             and int(timer['heap_position']) != NO_SLOT, 'actual timer differs from accepted packet deadline')
        protocol = protocols[key]
        if a['key_protocol'] == 6:
            for peer, label in enumerate(('orig', 'reply')):
                values = [int(protocol[label+'_'+field]) for field in ('seqlo', 'seqhi', 'maxwin', 'scale', 'state')]
                need(values == s['peers'][peer*5:peer*5+5] and int(protocol[label+'_flags']) == s['flags'][peer], 'TCP snapshot peer state')
        elif a['key_protocol'] == 17:
            need(int(protocol['phase']) == s['phase'], 'UDP snapshot phase')
        else:
            need([int(protocol[k]) for k in ('phase', 'seen_request', 'seen_reply')] == [s['phase'], s['request'], s['reply']], 'ICMP snapshot state')
        result[key] = dict(e, deadline_us=s['deadline_us'], timeout=s['timeout'])
    need(sum(int(e['timers']) for e in rows(text, 'expiry.owner=')) == len(entries), 'heap membership count')
    return result


def packet_ledger(log, generation, packets, captures, lanes):
    groups = {'admit': 's216 stage=admit ', 'policy': 's216 stage=policy ', 'consumer': 's225 event=consumer_packet ',
        'terminal': 's216 stage=terminal ', 'completion': 's204 event=completion_consume ',
        'syscall': 's242 event=verdict_syscall ', 'origin': 's203 event=verdict ', 'free': 's203 event=buffer_free '}
    maps, positions = {}, {}
    for name, prefix in groups.items():
        values = rows(log, prefix)
        token = lambda e: e['obligation'] if name in ('origin', 'free') else e['token']
        need(Counter(token(e) for e in values) == Counter(captures.keys()), 'complete packet '+name+' conservation')
        maps[name] = {token(e): e for e in values}
        positions[name] = {token(rows(line, prefix)[0]): index for index, line in enumerate(log.splitlines()) if line.startswith(prefix)}
    need(len(captures) == sum(int(e['captured']) for e in lanes), 'capture trace truncated or bypassed')
    placements = set()
    for token, cap in captures.items():
        p, a = packets[token], packets[token]['assigned']
        lane, owner = int(cap['lane']), a['owner']
        need(int(cap['generation']) == generation and cap['source'] == 'NFQ_CAPTURED' and cap['hook'] == '3'
             and int(cap['queue']) == 176+lane and int(cap['thread']) == lane % 2+1
             and lane//2 == (p['family'] == 6), 'original capture placement')
        placements.add((p['family'], owner, lane % 2 == owner))
        admission = maps['admit'][token]
        need(admission['raw'] == cap['raw'] and int(admission['thread']) == lane % 2+1
             and int(admission['owner']) == owner and int(admission['packet_length']) == p['size'], 'wire/admit identity')
        for field, value in p['facts'].items(): need(admission[field] == str(value), 'parsed wire fact '+field)
        parsed = dict(tcp_seq=p['seq'], tcp_ack=p['ack'], tcp_window=p['window'], tcp_flags=p['flags'],
                      wscale=p['scale'], wscale_known=p['known'], l4_length=p['header']) if p['protocol'] == 6 else dict(l4_length=8) if p['protocol'] == 17 else dict(icmp_seq=p['sequence'], l4_length=8)
        for field, value in parsed.items(): need(admission[field] == str(value), 'parsed protocol fact '+field)
        for name in ('policy', 'consumer', 'terminal'):
            e = maps[name][token]
            need(int(e['thread']) == owner+1 and int(e['owner']) == owner and int(e['generation']) == generation
                 and e['buffer'] == cap['buffer'], 'owner graph placement/carrier')
        need(maps['consumer'][token]['is_flow_end'] == '0' and maps['terminal'][token]['intent'] == '1', 'ordinary consumer/terminal intent')
        for name in ('completion', 'syscall', 'origin'):
            e = maps[name][token]
            need(int(e['generation']) == generation and int(e['thread']) == lane % 2+1 and int(e['lane']) == lane
                 and e['packet'] == cap['packet'], 'original completion route')
        syscall, freed = maps['syscall'][token], maps['free'][token]
        need(int(syscall['queue']) == 176+lane and syscall['fd'] == next(e['fd'] for e in lanes if int(e['lane']) == lane)
             and syscall['verdict'] == '1' and int(syscall['result']) > 0 and syscall['errno'] == '0', 'real NF_ACCEPT syscall/FD')
        need(freed['buffer'] == cap['buffer'] and int(freed['thread']) == lane % 2+1, 'original buffer return')
        order = [positions[name][token] for name in ('admit', 'policy', 'consumer', 'terminal', 'completion', 'origin', 'syscall', 'free')]
        need(order == sorted(order) and len(set(order)) == len(order), 'ordinary graph/terminal/free order')
    return sorted(placements)


def fd_lifecycle(read, generation):
    initial = rows(read('initial.txt'), 'expiry.owner=')
    armed = rows(read('armed-expiry.txt'), 'expiry.owner=')
    need(len(initial) == len(armed) == 2 and {int(e['expiry.owner']) for e in initial} == {0, 1}, 'two owner-local timer attachments')
    actual = udp.timer_fds(read('initial-fds.txt'))
    descriptors = {int(e['timer_fd']) for e in initial}
    need(len(descriptors) == 2 and len(actual) == 4 and descriptors <= actual.keys(), 'distinct actual timerfd backing')
    for e in initial:
        owner = int(e['expiry.owner'])
        need(int(e['generation']) == generation and e['mode'] == '2' and e['experiment'] == e['initialize'] == '0'
             and e['timers'] == '0' and e['next_us'] == str(MAX_U64) and int(e['timer_file']) != NO_SLOT,
             'default-on initially disarmed shared driver')
        later = next(row for row in armed if int(row['expiry.owner']) == owner)
        need((e['timer_fd'], e['timer_file']) == (later['timer_fd'], later['timer_file']), 'timer backing replaced during arm')
        udp.fdinfo(read('initial-fdinfo-'+str(owner)+'.txt'), False)
        udp.fdinfo(read('armed-fdinfo-'+str(owner)+'.txt'), True)
    need(not udp.timer_fds(read('closed-fds.txt')), 'timer descriptors survived stop')


def verifier_closure():
    names = ['tests/device/verify-s236-protocol-expiry.py', 'tests/device/verify-s236-mixed-expiry.py',
        'tests/device/verify-s236-mixed-lookup.py', 'tests/device/verify-s224-icmp-tracker.py',
        'tests/device/verify-s227-udp-expiry.py', 'tests/device/verify-s226-expiry-ab.py',
        'tests/device/verify-s242-root-lifecycle.py', 'tests/device/s207-owner-oracle.py',
        'tests/host/product_flow_tcp_ovs_test.py']
    return {name: digest(ROOT/name) for name in names}


def case(run, record, platform, ref):
    name, generation = record['case'], record['generation']
    need(name in CLASSES and record['label'] == name and record['process_closed'] and record['clients_closed'], 'case/cleanup identity')
    folder = run/name; read = lambda filename: (folder/filename).read_text()
    need('product-flow-expiry { trace-all }' in read('startup.conf') and 'experiment' not in read('startup.conf'), 'production default driver configuration')
    fd_lifecycle(read, generation)
    log = read('vpp.log')
    need('SIGABRT' not in log and 'infrastructure_failure' not in log and 'event=logical_expiry' not in log, 'unexpected crash/logical close')
    states, versions, packets, captures = replay(log, generation, ref)
    seeded = snapshot(read('seeded.txt'), versions, generation, 8 if name == 'long' else 4)
    original = snapshot(read('refreshed.txt'), versions, generation, 4) if name in ('icmp-renew', 'icmp-shorten') else seeded
    if name == 'tcp-invalid':
        invalid = snapshot(read('invalid.txt'), versions, generation, 4)
        need(invalid.keys() == seeded.keys() and all(invalid[k]['deadline_us'] == seeded[k]['deadline_us'] for k in seeded), 'INVALID refreshed/replaced instance')
        original = invalid
        need(sum(e['update'] == '3' for e in rows(log, 's222 event=tcp_update ')) == 4, 'missing real INVALID packets')
    for key, entry in original.items():
        expected_class = 7 if name == 'long' and states[key]['timeout'] == 7 else CLASSES[name]
        need(entry['timeout'] == expected_class, 'resulting pinned class coverage')
    if name in ('icmp-renew', 'icmp-shorten'):
        need(original.keys() == seeded.keys(), 'refresh changed instance')
        need(all((original[k]['deadline_us'] > seeded[k]['deadline_us']) == (name == 'icmp-renew') for k in original), 'deadline refresh/shortening direction')
        if name == 'icmp-renew': need(snapshot(read('past-original.txt'), versions, generation, 4) == original, 'expired at old deadline')
    completed, closed = read('completed.txt'), read('closed.txt')
    snapshot(completed, versions, generation, 0); snapshot(closed, versions, generation, 0)
    releases = rows(log, 's227 event=release ')
    need(len(releases) == len(original) and {identity(e) for e in releases} == original.keys(), 'missing/duplicate/extra automatic release')
    latencies = []
    for release in releases:
        key = identity(release); e = original[key]
        need(int(release['generation']) == generation and int(release['thread']) == key[0]+1 and release['linked'] == '0'
             and int(release['heap_position']) == NO_SLOT and int(release['deadline_us']) == e['deadline_us']
             and int(release['timeout']) == e['timeout'] and release['packets'] == e['packets'], 'released stale or wrong deadline/instance')
        elapsed = int(release['release_us'])-e['deadline_us']
        need(elapsed >= 0, 'early automatic release'); latencies.append(elapsed/1000)
    normal = udp.quantiles(latencies)
    need(normal['p99_ms'] <= 1100 and normal['max_ms'] <= 1500, 'normal release latency gate')
    batches = udp.batch_ledger(log, generation, original, {}, {})
    end_events = defaultdict(list)
    for e in rows(log, 's225 '):
        if e.get('event') != 'consumer_packet': end_events[identity(e)].append(e)
    need(end_events.keys() == original.keys(), 'unique END graph instance set')
    for key, events in end_events.items():
        need([e['event'] for e in events] == ['unlink_allocate', 'consumer_end', 'terminal_end', 'free_callback'], 'END graph/free order or duplicate callback')
        need(len({e['buffer'] for e in events}) == 1 and events[0]['node'] == events[1]['node'], 'END carrier/consumer identity')
        for e in events:
            need(int(e['generation']) == generation and int(e['thread']) == key[0]+1 and e['reason'] == '2'
                 and e['linked'] == e['length'] == e['obligation'] == '0' and e['allocated'] == '1', 'END lifetime/obligation/owner')
            for field in ('hash', 'protocol', 'orig_packets', 'reply_packets', 'orig_bytes', 'reply_bytes', 'first_seen', 'last_seen'):
                need(e[field] == original[key][field], 'END retained state '+field)
    final_lanes = rows(closed, 'root.lane ')
    need(len(final_lanes) == 4 and all(e['fd'] == '-1' and e['ready'] == e['pending'] == '0' for e in final_lanes), 'native queue attachment residue')
    zero = rows(log, 's242 event=stop_native_zero ')
    need(len(zero) == 1 and int(zero[0]['generation']) == generation and all(zero[0][k] == '0' for k in
        ('ready_mask', 'graph_enabled', 'graph_accepting', 'pending', 'buffers', 'obligations', 'handoffs', 'completion_frames')), 'orderly native stop absent')
    need('root.stop=ok' in read('stop.txt'), 'explicit Root stop failed')
    running_lanes = rows(completed if name != 'long' else read('post-expiry-echo.txt'), 'root.lane ')
    placements = packet_ledger(log, generation, packets, captures, running_lanes)
    for text, stopped in ((completed, False), (closed, True)):
        runtime = rows(text, 'flow.runtime ')
        need(len(runtime) == 2 and all(e['capacity'] == '64' and e['entry_bytes'] == '232' and e['capacity_misses'] == '0' for e in runtime),
             'one shared short/long owner pool capacity')
        need(all(e['capacity_drops'] == e['wrong_owner'] == e['early_drops'] == '0' for e in rows(text, 'flow.pool ')), 'flow admission/owner failure')
        lanes = rows(text, 'root.lane ')
        need(len(lanes) == 4 and all(e['captured'] == e['submitted'] == e['verdicts'] == e['succeeded']
             and e['pending'] == e['failed'] == e['duplicate'] == '0' for e in lanes), 'NFQUEUE settlement conservation')
        c = rows(text, 'completion.status ')
        need(len(c) == 1 and all(c[0][k] == '0' for k in ('pending', 'frames', 'buffers', 'obligations', 'duplicate', 'stale')), 'ordinary completion debt')
        for owner in rows(text, 'flow-end.owner='):
            n, admin = (4 if name == 'long' else 2), (2 if name == 'long' and stopped else 0)
            need(all(int(owner[k]) == n for k in ('allocated', 'consumers', 'terminals', 'released'))
                 and int(owner['pool_releases']) == n+admin and int(owner['administrative_releases']) == admin, 'END release/administrative conservation')
            need(all(owner[k] == '0' for k in ('active_entries', 'linked', 'ending', 'early_frees')), 'entry/END residue')
        need('flow-end.buffers=0' in text, 'END carrier residue')
        for e in rows(text, 'expiry.owner='):
            need(e['timers'] == '0' and int(e['generation']) == generation and int(e['released']) == (4 if name == 'long' else 2), 'expiry timer/release counters')
            if stopped: need(e['mode'] == '0' and e['timer_fd'] == '-1' and int(e['timer_file']) == NO_SLOT, 'timer backing still attached')
        need(udp.pool(text)['used'] == (0 if stopped else 288), 'native buffer residue')
    need(not udp.timer_fds(read('closed-fds.txt')), 'closed timer FDs')
    native.queue_state(folder, 'closed', platform, set())
    for owner in (0, 1): udp.fdinfo(read('disarmed-fdinfo-'+str(owner)+'.txt'), False)
    need({(f['family'], f['owner']) for f in record['flows']} == {(f, o) for f in (4, 6) for o in (0, 1)}, 'family/owner coverage')
    all_packets = list(packets.values())
    for flow in record['flows']:
        selected = [p for p in all_packets if p['family'] == flow['family'] and
            (flow['value'] in (p['sport'], p['dport']) if p['protocol'] == 6 else p['identifier'] == flow['value'])]
        need(selected and all(p['assigned']['owner'] == flow['owner'] for p in selected), 'endpoint flow/owner missing')
        if flow['protocol'] == 6:
            client = read(flow['label']+'-client.txt')
            need('keepalive=0' in client and 'ready nonce='+flow['nonce'] in client and 'Permission denied' not in client, 'real quiet TCP endpoint')
            receipts = rows(client, 'received ')
            need(len(receipts) == (2 if name == 'long' and not flow['closing'] else 1)
                 and all(e['nonce'] == flow['nonce'] for e in receipts) and
                 [int(e['phase']) for e in receipts] == list(range(len(receipts))), 'TCP kernel nonce receipt')
            if len(receipts) == 2:
                need(int(receipts[1]['mono_ms'])-int(receipts[0]['mono_ms']) >= 86400000,
                     'real endpoint monotonic 24-hour interval absent')
            server = ''.join(p.read_text() for p in run.glob('s236-tcp-'+str(flow['family'])+'-*.log'))
            for receipt in receipts:
                payload = (flow['nonce']+':'+receipt['phase']).encode().hex()
                need(sum(payload == e['data'] for e in rows(server, 'echo ')) == 1,
                     'independent TCP server did not receive exact nonce once')
            if name not in ('tcp-first', 'tcp-opening', 'tcp-invalid'):
                need(any(p['payload'] == (flow['nonce']+':0').encode() for p in selected), 'TCP payload not actually captured')
        else:
            for echo in flow['echoes']:
                client = rows(read(flow['label']+'-'+echo['phase']+'-client.txt'), 'endpoint ')
                need(len(client) == 1 and client[0]['nonce'] == echo['nonce']+'-0' and
                     int(client[0]['identifier']) == flow['value'] and int(client[0]['family']) == flow['family'] and
                     client[0]['echo'] == '1' and int(client[0]['reply_ns']) > int(client[0]['sent_ns']) > 0, 'Echo endpoint nonce/real receipt')
                need(any(p['payload'] == (echo['nonce']+'-0').encode() for p in selected), 'Echo nonce not actually captured')
                endpoint = rows((run/('s224-icmp-'+str(flow['family'])+'.log')).read_text(), 'received ')
                need(sum(e['checksum_valid'] == '1' and bytes.fromhex(e['raw'])[8:] ==
                         (echo['nonce']+'-0').encode() for e in endpoint) == 1, 'independent ICMP kernel receipt/checksum')
    if name == 'long':
        hooks = [line for line in read('hooks.txt').splitlines() if 'SAKAMOTO_S236_long' in line]
        need(len(hooks) == 16 and all('--tcp-flags' not in line for line in hooks), 'long quiet capture had packet exclusions')
        before = snapshot(read('established-before-deadline.txt'), versions, generation, 4)
        need(all(e['timeout'] == 6 for e in before.values()), 'established did not survive before actual 24-hour deadline')
        renewed = snapshot(read('post-expiry-echo.txt'), versions, generation, 4)
        need(not renewed.keys() & original.keys(), 'post-expiry echo reused old instance')
        need([i['label'] for i in record['quiet_intervals']] == ['closing-actual-900s',
             'established-before-86400s', 'established-actual-86400s'] and
             all(i['actual_s'] >= i['seconds'] for i in record['quiet_intervals']), 'long quiet interval plan/elapsed time')
    return dict(case=name, generation=generation, expired=len(original), packets=len(captures),
                latency=udp.quantiles(latencies), batches=len(batches), placements=placements)


def verify(run, ovs, selected=None):
    run = Path(run).resolve(); result = json.loads((run/'result.json').read_text())
    authority(run, result)
    need([r['case'] for r in result['generations']] == result['requested_cases'] and
         len(set(result['requested_cases'])) == len(result['requested_cases']), 'case selection/completeness')
    selected = result['requested_cases'] if selected is None else selected
    need(selected and len(set(selected)) == len(selected) and set(selected) <= set(result['requested_cases']), 'requested verifier subset absent/duplicate')
    ref = TcpOracle(ovs)
    try: summary = [case(run, record, result['platform'], ref) for record in result['generations'] if record['case'] in selected]
    finally: ref.close()
    return dict(status='VALID_PARTIAL', scope='protocol-default-deadlines-not-full-S236', platform=result['platform'],
        source_sha256=result['source_sha256'], cases=summary, result_sha256=digest(run/'result.json'),
        unverified_cases=[name for name in result['requested_cases'] if name not in selected],
        verifier_sha256=digest(__file__), verifier_files=verifier_closure(),
        ovs_tcp_sha256=digest(Path(ovs)/'lib/conntrack-tcp.c'), ovs_timeout_sha256=digest(Path(ovs)/'lib/conntrack-tp.c'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--ovs', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--cases', help='explicit partial verification; omitted cases remain unverified')
    args = parser.parse_args()
    try: value = verify(args.run, args.ovs, args.cases.split(',') if args.cases else None)
    except (AssertionError, KeyError, ValueError, OSError, subprocess.SubprocessError) as error:
        value = dict(status='HOLD', error=repr(error))
    if args.output: args.output.write_text(json.dumps(value, indent=2)+'\n')
    print(json.dumps(value, indent=2))
    if value['status'] == 'HOLD': raise SystemExit(1)
