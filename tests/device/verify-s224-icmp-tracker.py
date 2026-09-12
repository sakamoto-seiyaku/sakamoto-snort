#!/usr/bin/env python3
"""Independent Echo packet, typed identity, tracker and native cleanup oracle."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[2]
MAX_U64 = 2**64-1
LOCAL = {4: '127.0.0.1', 6: '::1'}
REMOTE = {4: '127.0.0.2', 6: 'fd20:6224::2'}
PING = {4: '127.0.0.3', 6: 'fd20:6224::3'}


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT/relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


native = module('s224_native_oracle', 'tests/device/verify-s242-root-lifecycle.py')
oracle = module('s224_owner_oracle', 'tests/device/s207-owner-oracle.py')
digest, need = native.digest, native.need


def rows(text, prefix):
    return [dict(part.split('=', 1) for part in line.split() if '=' in part)
            for line in text.splitlines() if line.startswith(prefix)]


def props(text):
    return dict(line.split('=', 1) for line in text.splitlines() if '=' in line and not line.startswith('#'))


def checksum(data):
    padded = data+b'\0'*(len(data) % 2)
    value = sum(struct.unpack('!%dH' % (len(padded)//2), padded))
    while value >> 16:
        value = (value & 65535)+(value >> 16)
    return (~value) & 65535


def packet(raw):
    data = bytes.fromhex(raw)
    need(28 <= len(data) <= 512, 'complete bounded captured Echo packet')
    family = data[0] >> 4
    if family == 4:
        offset, protocol = (data[0] & 15)*4, data[9]
        need(20 <= offset <= len(data)-8 and struct.unpack_from('!H', data, 2)[0] == len(data), 'IPv4 envelope length')
        need(struct.unpack_from('!H', data, 6)[0] & 0x3fff == 0 and checksum(data[:offset]) == 0, 'IPv4 fragment/header checksum')
        source, destination = data[12:16], data[16:20]
    else:
        need(family == 6 and len(data) >= 48 and len(data) == 40+struct.unpack_from('!H', data, 4)[0], 'IPv6 envelope length')
        offset, protocol = 40, data[6]
        source, destination = data[8:24], data[24:40]
    need(protocol == (1 if family == 4 else 58), 'not a baseline Echo terminal protocol')
    icmp = data[offset:]
    kind, code, _, identifier, sequence = struct.unpack_from('!BBHHH', icmp)
    need(code == 0 and kind in ((0, 8) if family == 4 else (128, 129)), 'non-Echo/error packet in tracker matrix')
    pseudo = b'' if family == 4 else source+destination+struct.pack('!I3xB', len(icmp), 58)
    need(checksum(pseudo+icmp) == 0, 'captured Echo checksum')
    facts = dict(l3=1, l4=2, family=family, protocol=protocol,
        src=source.rjust(16, b'\0').hex(), dst=destination.rjust(16, b'\0').hex(),
        src_port=0, dst_port=0, icmp_known=1, icmp_type=kind, icmp_code=code, icmp_id=identifier)
    assigned = oracle.assignment(facts)
    return dict(family=family, protocol=protocol, type=kind, code=code, identifier=identifier, sequence=sequence,
        source=str(ipaddress.ip_address(source)), destination=str(ipaddress.ip_address(destination)),
        payload=icmp[8:], icmp=icmp, size=len(data), facts=facts, assigned=assigned,
        key=(family, protocol, assigned['key_a'], assigned['key_b'], 1, identifier))


def authority(directory, result):
    need(result['status'] == 'RAW_COMPLETE' and not result.get('error') and not result.get('cleanup_error')
         and result['cleanup_errors'] == [], 'incomplete or unsafe collector')
    need(result['source'] == 'NFQ_CAPTURED' and result['platform'] in ('linux', 'pixel'), 'actual Root endpoint scope')
    build_file = Path(result['build'])
    need(digest(build_file) == result['build_sha256'], 'build witness changed')
    build = json.loads(build_file.read_text())
    chain = module('s224_source_chain', 'tests/evidence/product_chain.py')
    need(chain.source_files() == build['files'], 'current Product source differs from executed build')
    need(hashlib.sha256(chain.encode(build['files'])).hexdigest() == result['source_sha256'] == build['source_sha256'], 'Product source closure')
    need(digest(build_file.parent/'dirty.diff') == build['dirty_diff_sha256'], 'frozen dirty source diff')
    for name, expected in build['files'].items():
        if expected is not None:
            need(digest(build_file.parent/'source'/name) == expected, 'frozen source '+name)
    need(build['completed_ns'] < result['started_ns'] < result['completed_ns'], 'build/run time order')
    helper_file = Path(result['helpers'])
    need(digest(helper_file) == result['helpers_sha256'], 'helper build witness')
    helper = json.loads(helper_file.read_text())
    need(helper['platform'] == result['platform'] and helper['build_sha256'] == result['build_sha256']
         and helper['source_sha256'] == build['source_sha256'], 'helper platform/source binding')
    for name, expected in helper['files'].items():
        need(digest(helper_file.parent/name) == expected, 'helper artifact '+name)
    for name, expected in helper['sources'].items():
        need(digest(ROOT/name) == expected, 'helper source '+name)
    need(digest(helper['compiler']['path']) == helper['compiler']['sha256'], 'helper compiler')
    for name, expected in result['test_inputs'].items():
        need(digest(directory/'test-source'/name) == expected, 'frozen collector/registration '+name)
        if not name.startswith('docs/') and name != 'tests/device/s224-icmp-tracker.py':
            need(digest(ROOT/name) == expected, 'current shared collector dependency '+name)
    need(result['raw_hashes'], 'missing raw evidence manifest')
    for name, expected in result['raw_hashes'].items():
        need(digest(directory/name) == expected, 'raw evidence changed '+name)
    need(len(result['endpoints']) == 6 and all(e['process_absent'] for e in result['endpoints']), 'independent endpoint process residue')
    need({(e['family'], e['address']) for e in result['endpoints']} ==
         {(f, address) for f in (4, 6) for address in (LOCAL[f], REMOTE[f], PING[f])}, 'endpoint address coverage')
    need('SAKAMOTO_S224_' not in (directory/'hooks-after.txt').read_text(), 'private capture hook residue')
    for address in (REMOTE[6], PING[6]):
        need((address+'/128' in (directory/'addresses-before.txt').read_text()) ==
             (address+'/128' in (directory/'addresses-after.txt').read_text()), 'temporary address residue')
    if result['platform'] == 'linux':
        need(not build['host_evidence'], 'host fixture substituted for native Product')
        need((directory/'uid-map.txt').read_text().split() == ['0', str(result['policy_uid']), '1']
             and str(result['policy_uid']) != '0' and str(result['uid']) == '0', 'rootless UID mapping')
        need((directory/'namespace.txt').read_text().startswith('net:['), 'isolated Linux namespace')
        for name, expected in build['artifact_hashes'].items():
            need(digest(Path(build['artifact'])/name) == expected, 'actual Linux artifact '+name)
        for name, expected in build['control_hashes'].items():
            need(digest(build_file.parent/name) == expected, 'actual Linux control library '+name)
    else:
        need(digest(build['apk']) == build['apk_sha256'] == (directory/'installed-apk.txt').read_text().split()[0], 'installed APK')
        installed = {Path(line.split()[1]).name: line.split()[0] for line in (directory/'installed-native.txt').read_text().splitlines()}
        need(installed == build['native_sha256'], 'installed native closure')
        with zipfile.ZipFile(build['apk']) as apk:
            need({Path(name).name: hashlib.sha256(apk.read(name)).hexdigest() for name in apk.namelist()
                  if name.startswith('lib/arm64-v8a/') and name.endswith('.so')} == installed, 'APK native contents')
        for name in ('s223-udp', 's217-policy', 's222-tcp', 's242-stop', 's242-queue-holder', 's242-traffic', 's224-icmp'):
            need((directory/(name+'-installed.txt')).read_text().split()[0] == helper['files'][name], 'installed helper '+name)
        for name in ('app-before.properties', 'app-after.properties'):
            state = props((directory/name).read_text())
            need(state['state'] == 'stopped' and state['mayBeActive'] == 'false' and state['protectionRunning'] == 'false'
                 and not state['errorCode'], 'native validation must leave app stopped')
    return build


def replay(log, generation, hook):
    captures = rows(log, 's231 event=nfq_payload ')
    need(len({e['token'] for e in captures}) == len(captures), 'duplicate captured token')
    packets = {e['token']: packet(e['raw']) for e in captures}
    capture = {e['token']: e for e in captures}
    observed = rows(log, 's208 ')
    updates = rows(log, 's224 event=icmp_update ')
    need(Counter(e['token'] for e in observed) == Counter(e['token'] for e in updates) == Counter(capture.keys()), 'missing or extra per-packet tracker update')
    observation = {e['token']: e for e in observed}
    states, slots = {}, set()
    for update in updates:
        token = update['token']
        p, e, cap = packets[token], observation[token], capture[token]
        a = p['assigned']
        owner = a['owner']
        need(e['event'] == 'observe' and e['status'] == '0' and e['source'] == update['source'] == cap['source'] == 'NFQ_CAPTURED', 'not a successful real observation')
        need(all(int(r['generation']) == generation for r in (e, update, cap)) and int(e['policy_generation']) == generation, 'tracker generation mismatch')
        need(all(int(r['owner']) == int(r['worker']) == owner and int(r['thread']) == owner+1 for r in (e, update))
             and int(e['pool_worker']) == owner, 'tracker mutated outside its canonical owner')
        need(e['buffer'] == update['buffer'] and e['slot'] == update['slot'] and
             e['key_kind'] == e['stored_kind'] == '3' and int(e['hash']) == int(e['stored_hash']) == a['hash'], 'stored typed identity/hash/carrier')
        need(int(cap['hook']) == hook and int(e['device_dir']) == int(e['flow_origin_dir']) == hook,
             'device hook substituted for first observation')
        created = p['key'] not in states
        if created:
            slot = owner, int(update['slot'])
            need(slot not in slots and int(update['incarnation']) > 0, 'new session overwrote an existing slot')
            slots.add(slot)
            states[p['key']] = dict(owner=owner, slot=slot[1], incarnation=int(update['incarnation']),
                origin=a['source_is_a'], phase=1, request=0, reply=0, packets=[0, 0], bytes=[0, 0],
                first=int(e['first_seen']), last=0, hash=a['hash'], key=p['key'], uid=None, device=hook)
        state = states[p['key']]
        direction = 1 if a['source_is_a'] == state['origin'] else 2
        if direction == 2:
            state['phase'] = 2
        state['request'] |= p['type'] in (8, 128)
        state['reply'] |= p['type'] in (0, 129)
        state['packets'][direction-1] += 1
        state['bytes'][direction-1] += p['size']
        need(int(update['slot']) == state['slot'] and int(update['incarnation']) == state['incarnation'], 'sequence/type split session identity')
        need(int(e['created']) == int(update['created']) == created and int(e['reused']) == (not created), 'tracker creation/reuse truth')
        need(int(e['source_is_a']) == a['source_is_a'] and int(e['origin_is_a']) == state['origin'], 'ORIG redefined from Echo type')
        need(int(update['family']) == p['family'] and int(update['protocol']) == p['protocol'] and
             int(update['type']) == p['type'] and update['code'] == '0' and int(update['identifier']) == p['identifier']
             and int(update['sequence']) == p['sequence'], 'tracker facts differ from captured Echo')
        need(int(update['phase']) == state['phase'] and int(update['seen_request']) == state['request']
             and int(update['seen_reply']) == state['reply'], 'Echo phase/seen facts invented or lost')
        need(int(update['ct_state']) == int(update['update']) == state['phase'] and int(update['timeout']) == 9+state['phase']
             and int(update['flow_dir']) == int(e['flow_dir']) == direction, 'pinned ICMP facts/update/timeout/direction')
        need(update['refresh'] == '1' and update['close'] == update['replacement'] == update['invalidated'] == e['invalidated'] == '0', 'unexpected tracker side effect')
        need([int(update[k]) for k in ('orig_packets', 'reply_packets')] == state['packets'] and
             int(e['packets']) == sum(state['packets']) and int(e['bytes']) == sum(state['bytes']), 'per-observation packet/byte accounting')
        need(int(e['first_seen']) == state['first'] <= int(e['last_seen']) and int(e['last_seen']) >= state['last'], 'entry observation clock/history')
        state['last'] = int(e['last_seen'])
    return states, packets, capture


def packet_ledger(log, generation, hook, packets, captures, states):
    groups = {
        'admit': rows(log, 's216 stage=admit '),
        'consumer': rows(log, 's225 event=consumer_packet '),
        'completion': rows(log, 's204 event=completion_consume '),
        'syscall': rows(log, 's242 event=verdict_syscall '),
        'origin': rows(log, 's203 event=verdict '),
        'free': rows(log, 's203 event=buffer_free '),
    }
    expected = Counter(captures.keys())
    for name, values in groups.items():
        need(Counter(e['obligation'] if name in ('free', 'origin') else e['token'] for e in values) == expected,
             'full original packet '+name+' conservation')
    maps = {name: {e['obligation'] if name in ('free', 'origin') else e['token']: e for e in values} for name, values in groups.items()}
    need(len({e['node'] for e in groups['consumer']}) == 1, 'packets did not share one consumer entry')
    observed = {e['token']: e for e in rows(log, 's208 ')}
    placements = set()
    for token, cap in captures.items():
        p, a = packets[token], packets[token]['assigned']
        admit, consumer, completion, syscall, origin, freed = [maps[name][token] for name in groups]
        lane, owner = int(cap['lane']), a['owner']
        need(lane in ((0, 1) if p['family'] == 4 else (2, 3)) and int(cap['queue']) == 176+lane
             and int(cap['thread']) == lane % 2+1, 'capture lane/family/initial placement')
        placements.add((p['family'], owner, lane % 2 == owner))
        for e in (completion, syscall, origin):
            need(int(e['lane']) == lane and e['packet'] == cap['packet'] and int(e['generation']) == generation
                 and int(e['thread']) == lane % 2+1 and e['source'] == 'NFQ_CAPTURED', 'original queue/thread/generation return')
        need(int(syscall['queue']) == 176+lane and syscall['verdict'] == '1' and int(syscall['result']) > 0
             and syscall['errno'] == '0' and completion['intent'] == '1', 'actual NF_ACCEPT syscall/terminal intent')
        need(freed['thread'] == completion['thread'] and freed['buffer'] == completion['buffer'], 'original native buffer free identity')
        need(int(consumer['owner']) == owner and int(consumer['thread']) == owner+1 and consumer['is_flow_end'] == '0'
             and int(consumer['generation']) == generation and consumer['buffer'] == admit['buffer'], 'shared consumer owner/carrier')
        need(admit['raw'] == cap['raw'] and int(admit['owner']) == owner and int(admit['thread']) == lane % 2+1
             and int(admit['generation']) == generation and admit['packet_id'] == cap['packet']
             and int(admit['origin_lane']) == lane and int(admit['direction']) == hook
             and admit['provenance'] == admit['completion_kind'] == '1', 'shared parser/admission identity')
        for name, value in p['facts'].items():
            need(admit[name] == (value if name in ('src', 'dst') else str(value)), 'shared parser fact '+name)
        need(admit['icmp_seq'] == str(p['sequence']) and admit['l4_length'] == '8'
             and admit['packet_length'] == str(p['size']), 'Echo parsed sequence/length')
        if observed[token]['created'] == '1':
            states[p['key']]['uid'] = int(admit['uid']) if int(admit['availability']) & 1 else 2**32-1
    need(placements == {(f, o, local) for f in (4, 6) for o in (0, 1) for local in (False, True)}, 'dual-stack W2 local/remote placement coverage')
    return placements


def pool_used(text):
    found = re.findall(r'^default-numa-\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$', text, re.M)
    need(len(found) == 1, 'one native NUMA pool witness')
    index, numa, size, data, total, available, cached, used = map(int, found[0])
    need(index == numa == 0 and size == 2304 and data == 2048 and available+cached+used == total, 'native buffer layout/conservation')
    return used


def snapshot(text, states, generation, closed=False):
    entries, phases = rows(text, 'flow.entry '), rows(text, 'flow.icmp ')
    wanted = {(s['owner'], s['slot'], s['incarnation']): s for s in states.values()}
    identity = lambda e: (int(e['worker']), int(e['slot']), int(e['incarnation']))
    need(len(entries) == len(phases) == (0 if closed else len(states)), 'snapshot entry/ICMP count')
    need(len({identity(e) for e in entries}) == len(entries), 'duplicate snapshot identity')
    phase = {identity(e): e for e in phases}
    if not closed:
        need({identity(e) for e in entries} == phase.keys() == wanted.keys(), 'snapshot slot/incarnation identity')
    for entry in entries:
        state = wanted[identity(entry)]
        family, protocol, a, b, query, identifier = state['key']
        expected = dict(kind=3, family=family, protocol=protocol, hash=state['hash'], key_a=a, key_b=b,
            query_class=query, identifier=identifier, port_a=0, port_b=0, origin_is_a=state['origin'],
            flow_origin_dir=state['device'], device_dir=state['device'], policy_generation=generation,
            packets=sum(state['packets']), bytes=sum(state['bytes']), first_seen=state['first'], last_seen=state['last'],
            orig_packets=state['packets'][0], reply_packets=state['packets'][1],
            orig_bytes=state['bytes'][0], reply_bytes=state['bytes'][1], revision=0, snapshot_hash=0, decision=0, rule=0)
        if state['uid'] is not None:
            expected['uid'] = state['uid']
        for name, value in expected.items():
            need(entry[name] == str(value), 'snapshot typed identity/history '+name)
        need(phase[identity(entry)]['phase'] == str(state['phase']) and
             phase[identity(entry)]['seen_request'] == str(int(state['request'])) and
             phase[identity(entry)]['seen_reply'] == str(int(state['reply'])), 'snapshot accepted Echo state')
    need(not rows(text, 'flow.timer ') and not rows(text, 'flow.udp ') and not rows(text, 'flow.tcp '), 'parallel protocol/timer state appeared')
    for prefix in ('flow.pool ', 'flow.runtime ', 'flow-end.owner=', 'expiry.owner='):
        values = rows(text, prefix)
        field = 'expiry.owner' if prefix.startswith('expiry') else 'flow-end.owner' if prefix.startswith('flow-end') else 'worker'
        need(len(values) == 2 and {e[field] for e in values} == {'0', '1'}, 'both native owner snapshots '+prefix)
        for e in values:
            owner = int(e[field])
            original_count = sum(s['owner'] == owner for s in states.values())
            count = 0 if closed else original_count
            packets = sum(sum(s['packets']) for s in states.values() if s['owner'] == owner)
            if prefix == 'flow.pool ':
                need(int(e['entries']) == count and int(e['allocations']) == original_count
                     and int(e['reused']) == packets-original_count, 'owner pool allocation/hit counts')
                need(all(e[k] == '0' for k in ('early_drops', 'wrong_owner', 'capacity_drops', 'invalidations', 'revision_mismatches', 'unavailable')), 'owner mutation error/bypass')
                need(int(e['flushes']) == int(closed), 'management flush count')
            elif prefix == 'flow.runtime ':
                need(int(e['generation']) == generation and e['capacity'] == '32' and e['entry_bytes'] == '232'
                     and int(e['allocated_bytes']) > 32*232 and int(e['high_watermark']) == original_count
                     and e['capacity_misses'] == '0', 'shared bounded FlowRuntime allocation')
            elif prefix == 'flow-end.owner=':
                need(int(e['generation']) == generation and int(e['active_entries']) == int(e['linked']) == count
                     and all(e[k] == '0' for k in ('allocated', 'consumers', 'terminals', 'released', 'early_frees', 'ending', 'control')), 'END debt or fake automatic cleanup')
                need(int(e['pool_releases']) == int(e['administrative_releases']) == (original_count if closed else 0), 'management release accounting')
            else:
                need(int(e['generation']) == generation and int(e['mode']) == (0 if closed else 2)
                     and e['experiment'] == '0' and e['trace_all'] == '0', 'default scheduler mode/isolation changed')
                need(all(e[k] == '0' for k in ('initialize', 'calls', 'checks', 'wakes', 'batches', 'closed', 'released', 'timers',
                    'due_backlog', 'oldest_overdue_us', 'budget_exhausted', 'stale_wakes', 'logical_expired')), 'ICMP timer enabled before S236 or scheduler residue')
                need(int(e['next_us']) == int(e['scheduled_us']) == MAX_U64, 'ICMP runtime did not stay disarmed')
                if closed:
                    need(e['timer_fd'] == '-1' and e['timer_file'] == str(2**32-1), 'timer FD not closed')
                else:
                    need(int(e['timer_fd']) >= 0 and int(e['timer_file']) != 2**32-1, 'normal UDP scheduler binding absent')
    protocols = rows(text, 'flow.protocol ')
    need(len(protocols) == 6 and {(e['worker'], e['protocol']) for e in protocols} ==
         {(str(o), p) for o in (0, 1) for p in ('tcp', 'udp', 'icmp_query')}, 'one shared per-protocol capacity accounting')
    for e in protocols:
        count = sum(s['owner'] == int(e['worker']) for s in states.values()) if e['protocol'] == 'icmp_query' else 0
        packets = sum(sum(s['packets']) for s in states.values() if s['owner'] == int(e['worker'])) if count else 0
        need(int(e['active']) == (0 if closed else count) and int(e['creates']) == count and int(e['hits']) == packets-count
             and all(e[k] == '0' for k in ('capacity_misses', 'invalid_packets', 'closed')), 'protocol state/counter scope')
    need('flow-end.buffers=0' in text and pool_used(text) == (0 if closed else 288), 'native END/receive buffer residue')
    completion = rows(text, 'completion.status ')
    need(len(completion) == 1 and all(completion[0][k] == '0' for k in ('pending', 'frames', 'buffers', 'obligations', 'duplicate', 'stale')),
         'original packet obligation/completion residue')


def receipts(directory, result):
    values = Counter()
    for endpoint in result['endpoints']:
        text = (directory/endpoint['output']).read_text()
        listener = rows(text, 'listen ')
        need(len(listener) == 1 and listener[0]['family'] == str(endpoint['family']) and
             listener[0]['local'] == endpoint['address'] and listener[0]['uid'] == str(result['uid']), 'independent raw listener identity')
        for e in rows(text, 'received '):
            raw = bytes.fromhex(e['raw'])
            family = int(e['family'])
            need(family == endpoint['family'] and e['local'] == endpoint['address'] and e['uid'] == str(result['uid'])
                 and int(e['bytes']) == len(raw) and 8 <= len(raw) <= 256 and int(e['mono_ns']) > 0, 'independent receiver metadata')
            need((int(e['type']), int(e['code']), int(e['identifier']), int(e['sequence'])) ==
                 (raw[0], raw[1], int.from_bytes(raw[4:6], 'big'), int.from_bytes(raw[6:8], 'big')), 'receiver decoded Echo facts')
            source, destination = ipaddress.ip_address(e['source']).packed, ipaddress.ip_address(e['local']).packed
            pseudo = b'' if family == 4 else source+destination+struct.pack('!I3xB', len(raw), 58)
            need(e['checksum_valid'] == '1' and checksum(pseudo+raw) == 0, 'independent receiver checksum')
            values[(family, e['source'], e['local'], raw[0], int(e['identifier']), int(e['sequence']), raw[8:])] += 1
    return values


def wire_identity(p):
    return p['family'], p['source'], p['destination'], p['type'], p['identifier'], p['sequence'], p['payload']


def hook_rules(text, record, case, request_only):
    selected = [line for line in text.splitlines() if 'SAKAMOTO_S224_' in line]
    need(len(selected) == (1 if request_only else 2), 'exact private Echo rule count')
    family = case['family']
    need(all(line.startswith('-A '+record['hook']+' ') and 'SAKAMOTO_S224_'+record['label'] in line
             and '--queue-num '+str(176+(family == 6)*2+case['placement']) in line
             and '--queue-bypass' in line and '-j NFQUEUE' in line for line in selected), 'private hook/queue placement contract')
    for reply in (False, True):
        if request_only and reply:
            continue
        kind = (0 if reply else 8) if family == 4 else (129 if reply else 128)
        source, destination = (REMOTE[family], LOCAL[family]) if reply else (LOCAL[family], REMOTE[family])
        need(any(re.search(r'--icmp(?:v6)?-type '+str(kind)+r'(?:/0)?(?:\s|$)', line)
                 and '-s '+source+'/' in line and '-d '+destination+'/' in line for line in selected), 'request/reply private address/type scope')


def endpoint_matrix(folder, record, result, packets, capture, received, full_log):
    cases = record['cases']
    need(len(cases) == 16 and {(e['family'], e['owner'], e['placement'], e['reply_first']) for e in cases} ==
         {(f, o, placement, reply) for f in (4, 6) for o in (0, 1) for placement in (0, 1) for reply in (False, True)}, 'complete fixed tracker matrix')
    need(len({(e['family'], e['identifier']) for e in cases}) == 16, 'different sessions reused a manifest identifier')
    need(len(record['pings']) == 2 and {e['family'] for e in record['pings']} == {4, 6}, 'system ping dual-stack coverage')
    expected, packet_case = Counter(), {}
    for index, case in enumerate(cases):
        need(case['label'] == 'case-'+str(index), 'case collection order')
        family = case['family']
        phases = [('first-reply', 10, 2, True), ('bidir', 20, 1, False)] if case['reply_first'] else [
                  ('first', 10, 1, False), ('repeat', 65535, 2, False), ('bidir', 20, 2, False)]
        need([(e['label'], e['sequence'], e['count'], e['reply']) for e in case['phases']] == phases, 'fixed endpoint phase/sequence matrix')
        hook_rules((folder/(case['label']+'-first-hooks.txt')).read_text(), record, case, not case['reply_first'])
        hook_rules((folder/(case['label']+'-bidir-hooks.txt')).read_text(), record, case, False)
        for phase in case['phases']:
            need(phase['returncode'] == 0, 'endpoint process failed')
            values = rows((folder/(phase['path']+'-client.txt')).read_text(), 'endpoint ')
            need(len(values) == phase['count'] and len({e['fd'] for e in values}) == 1, 'same raw endpoint socket sequence count')
            for i, e in enumerate(values):
                source, destination = (REMOTE[family], LOCAL[family]) if phase['reply'] else (LOCAL[family], REMOTE[family])
                kind = (0 if phase['reply'] else 8) if family == 4 else (129 if phase['reply'] else 128)
                nonce = phase['nonce']+'-'+str(i)
                need(e['family'] == str(family) and e['source'] == source and e['destination'] == destination and
                     e['uid'] == str(result['uid']) and e['identifier'] == str(case['identifier']) and
                     int(e['sequence']) == (phase['sequence']+i) % 65536 and int(e['type']) == kind
                     and e['nonce'] == nonce and e['bytes'] == str(8+len(nonce)), 'endpoint tuple/sequence/nonce')
                need(int(e['sent_ns']) > 0 and int(e['echo']) == (not phase['reply']) and
                     (e['reply_ns'] == '0' if phase['reply'] else int(e['reply_ns']) >= int(e['sent_ns'])), 'endpoint real reply/timestamp evidence')
                identity = (family, source, destination, kind, case['identifier'], int(e['sequence']), nonce.encode())
                need(received[identity] == 1, 'independent destination did not receive unique Echo packet')
                expected[identity] += 1
                packet_case[identity] = case
                if not phase['reply']:
                    reverse = (family, destination, source, 0 if family == 4 else 129, case['identifier'], int(e['sequence']), nonce.encode())
                    need(received[reverse] == 1, 'independent source did not receive physical kernel reply')
                    if phase['label'] == 'bidir':
                        expected[reverse] += 1
                        packet_case[reverse] = case
            prefix = (folder/(phase['path']+'-vpp.log')).read_text()
            need(full_log.startswith(prefix), 'phase trace is not an immutable prefix of this generation')
            states, _, _ = replay(prefix, record['generation'], 3 if record['hook'] == 'OUTPUT' else 1)
            snapshot((folder/(phase['path']+'.txt')).read_text(), states, record['generation'])
            wanted = [s for s in states.values() if s['key'][0] == family and s['key'][-1] == case['identifier']]
            need(len(wanted) == 1 and wanted[0]['owner'] == case['owner'], 'phase lacks original canonical session')
            if phase['label'] != 'bidir':
                need(wanted[0]['phase'] == 1 and bool(wanted[0]['request']) == (not case['reply_first'])
                     and bool(wanted[0]['reply']) == case['reply_first'], 'request-only/reply-first snapshot facts')
            else:
                need(wanted[0]['phase'] == 2 and wanted[0]['request'] and wanted[0]['reply'], 'actual round-trip state absent')
    custom = [p for p in packets.values() if p['destination'] != PING[p['family']] and p['source'] != PING[p['family']]]
    need(Counter(wire_identity(p) for p in custom) == expected, 'captured custom Echo packet matrix')
    for token, p in packets.items():
        identity = wire_identity(p)
        need(received[identity] == 1, 'captured packet lacks independent kernel receiver')
        if identity in packet_case:
            case = packet_case[identity]
            need(p['assigned']['owner'] == case['owner'] and int(capture[token]['lane']) % 2 == case['placement'], 'owner or explicit initial placement differs')
    for ping in record['pings']:
        family = ping['family']
        need(ping['returncode'] == 0 and ping['destination'] == PING[family] and
             re.search(r'3 (?:packets )?received', (folder/(ping['path']+'-client.txt')).read_text()), 'system ping did not receive three replies')
        selected = [(token, p) for token, p in packets.items() if p['family'] == family and
                    (p['source'] == PING[family] or p['destination'] == PING[family])]
        need(len(selected) == 6 and len({p['identifier'] for _, p in selected}) == 1
             and {p['sequence'] for _, p in selected} == {1, 2, 3}, 'system ping one-identifier multi-sequence capture')
        for sequence in (1, 2, 3):
            pair = [p for _, p in selected if p['sequence'] == sequence]
            need(len(pair) == 2 and {p['type'] for p in pair} == ({0, 8} if family == 4 else {128, 129})
                 and pair[0]['payload'] == pair[1]['payload'] and bytes.fromhex(ping['pattern']) in pair[0]['payload'], 'system ping request/reply pattern')
        need(all(int(capture[token]['lane']) == (0 if family == 4 else 2) for token, _ in selected), 'system ping initial lane')
        prefix = (folder/(ping['path']+'-vpp.log')).read_text()
        need(full_log.startswith(prefix), 'system ping snapshot prefix')
        states, _, _ = replay(prefix, record['generation'], 3 if record['hook'] == 'OUTPUT' else 1)
        snapshot((folder/(ping['path']+'.txt')).read_text(), states, record['generation'])


def verify(directory):
    directory = Path(directory)
    result = json.loads((directory/'result.json').read_text())
    build = authority(directory, result)
    need([(e['label'], e['generation'], e['hook']) for e in result['generations']] ==
         [('output', 22410, 'OUTPUT'), ('input', 22411, 'INPUT')], 'two fresh generations and exact capture hooks')
    received = receipts(directory, result)
    summary = []
    for record in result['generations']:
        need(record['raw_complete'] and record['process_absent'], 'native collector/cleanup incomplete')
        folder = directory/record['label']
        read = lambda name: (folder/name).read_text()
        generation, hook = record['generation'], 3 if record['hook'] == 'OUTPUT' else 1
        need(re.search(r'product-flow-runtime\s*\{\s*entries 32\s*\}', read('startup.conf')) and
             'product-flow-expiry' not in read('startup.conf'), 'actual capacity/default scheduler startup')
        log = read('vpp.log')
        need(not any(term in log for term in ('source=GRAPH_INJECTED', 'event=icmp_error_update', 'event=fatal_allocation_failure')),
             'synthetic input/unscoped error handling/runtime failure')
        need(not any(e.get('event') in ('unlink_allocate', 'consumer_end', 'terminal_end', 'free_callback') for e in rows(log, 's225 ')),
             'automatic END substituted for the registered management cleanup')
        states, packets, captures = replay(log, generation, hook)
        need(len(packets) == 100 and len(states) == 18, 'complete real packet/session matrix')
        placements = packet_ledger(log, generation, hook, packets, captures, states)
        endpoint_matrix(folder, record, result, packets, captures, received, log)
        snapshot(read('initial.txt'), {}, generation)
        snapshot(read('final.txt'), states, generation)
        snapshot(read('before-stop.txt'), states, generation)
        snapshot(read('closed.txt'), states, generation, closed=True)
        initial = rows(read('initial.txt'), 'root.lane ')
        native.worker_layout(read('layout.txt'), read('fds-before.txt'), initial)
        initial_by_lane = {e['lane']: e for e in initial}
        for event in rows(log, 's242 event=verdict_syscall '):
            need(event['fd'] == initial_by_lane[event['lane']]['fd'], 'terminal syscall used another queue FD')
        for lane in initial:
            inode = re.search(r'\b'+lane['fd']+r' -> (socket:\[\d+\])', read('fds-before.txt'))
            need(inode and inode[1] not in read('fds-closed.txt'), 'old queue socket inode survived Root stop')
        native.queue_state(folder, 'initial', result['platform'], set(range(176, 180)))
        native.queue_state(folder, 'closed', result['platform'], set())
        need('SAKAMOTO_S224_' not in read('hooks-after.txt'), 'generation hook residue')
        need(read('fds-before.txt').count('anon_inode:[timerfd') == 4 and 'anon_inode:[timerfd' not in read('fds-closed.txt'), 'timer FD ownership/residue')
        original_fds = rows(read('initial.txt'), 'expiry.owner=')
        need(len({e['timer_fd'] for e in original_fds}) == 2, 'owners share timer FD')
        for owner in (0, 1):
            timer = read(f'timer-{owner}.txt')
            need(re.search(r'^clockid:\s*1$', timer, re.M) and
                 re.search(r'^it_value:\s*\(0,\s*0\)$', timer, re.M) and
                 re.search(r'^it_interval:\s*\(0,\s*0\)$', timer, re.M), 'actual disarmed one-shot timerfd')
        final_lanes = rows(read('final.txt'), 'root.lane ')
        closed_lanes = rows(read('closed.txt'), 'root.lane ')
        need(len(final_lanes) == len(closed_lanes) == 4 and {e['lane'] for e in final_lanes} == {'0', '1', '2', '3'}, 'four native final lanes')
        for lane in final_lanes:
            number = int(lane['lane'])
            selected = [token for token, cap in captures.items() if int(cap['lane']) == number]
            local = sum(packets[token]['assigned']['owner'] == number % 2 for token in selected)
            need(0 < len(selected) <= 64 and all(int(lane[k]) == len(selected) for k in ('captured', 'submitted', 'verdicts', 'succeeded', 'returns'))
                 and int(lane['local']) == local and int(lane['remote']) == len(selected)-local
                 and lane['pending'] == lane['failed'] == lane['duplicate'] == '0', 'exact local/remote native lane accounting')
            after = next(e for e in closed_lanes if e['lane'] == lane['lane'])
            need(after['fd'] == '-1' and after['ready'] == after['pending'] == '0' and
                 all(after[k] == lane[k] for k in ('captured', 'submitted', 'verdicts', 'succeeded', 'returns', 'local', 'remote')), 'queue lifecycle residue/counter change')
        zero = rows(log, 's242 event=stop_native_zero ')
        need(len(zero) == 1 and int(zero[0]['generation']) == generation and all(zero[0][k] == '0' for k in
             ('ready_mask', 'graph_enabled', 'graph_accepting', 'pending', 'buffers', 'obligations', 'handoffs', 'completion_frames')), 'orderly graph drain incomplete')
        lanes = rows(log, 's242 event=lane_closed ')
        need(len(lanes) == 4 and {e['lane'] for e in lanes} == {'0', '1', '2', '3'} and
             all(e['fd'] == '-1' and all(e[k] == '0' for k in ('pending', 'allocated', 'loans', 'listener', 'socket')) for e in lanes), 'native queue/receive pool release')
        primary = rows(read('closed.txt'), 'primary.status ')
        remote = sum(packets[token]['assigned']['owner'] != int(cap['lane']) % 2 for token, cap in captures.items())
        need(len(primary) == 1 and int(primary[0]['owner_checks']) == len(packets) and
             int(primary[0]['published']) == int(primary[0]['received']) == int(primary[0]['returns']) == remote and
             primary[0]['credit0'] == primary[0]['credit1'] == '32' and all(primary[0][k] == '0' for k in
             ('rejected', 'owner_failures', 'pending_returns', 'handoff_debt', 'flows')), 'worker handoff ownership/debt residue')
        completion = rows(read('closed.txt'), 'completion.status ')[0]
        need(int(completion['generation']) == generation and int(completion['verdicts']) == len(packets) and
             int(completion['remote']) == remote and int(completion['local']) == len(packets)-remote,
             'final original completion route counts')
        summary.append(dict(hook=record['hook'], generation=generation, sessions=len(states), packets=len(packets),
            controlled_reply_first=8, system_ping_replies=6, placement_combinations=len(placements),
            administrative_releases=len(states), automatic_expiry=0, entry_bytes=232))
    return dict(status='PASS', platform=result['platform'], source_sha256=build['source_sha256'],
        build_sha256=result['build_sha256'], run_result_sha256=digest(directory/'result.json'),
        verifier_sha256=digest(__file__), scope='real-Root-Echo-tracker-not-VPN-ICMP-or-auto-expiry', generations=summary)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    answer = json.dumps(verify(args.run), indent=2)+'\n'
    if args.output:
        args.output.write_text(answer)
    print(answer, end='')
