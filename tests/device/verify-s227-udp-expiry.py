#!/usr/bin/env python3
"""Independently verify actual UDP observations, default deadlines and ENDs."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[2]
COUNTS = {'first': 2, 'renew-first': 2, 'shorten': 2, 'renew-bidir': 2,
          'bulk': 512, 'lookup': 4096, 'stop': 2}
PORT = 40627
MAX_U64, NO_SLOT = 2**64-1, 2**32-1


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT/relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


shared = module('s227_common', 'tests/device/verify-s226-expiry-ab.py')
need, rows, digest, pool, timer_fds = shared.require, shared.records, shared.digest, shared.pool, shared.timer_fds


def authority(run, result):
    need(result['status'] == 'RAW_COMPLETE' and not result.get('error') and not result.get('cleanup_error'),
         'collector did not complete safely')
    need(result['source'] == 'NFQ_CAPTURED' and result['platform'] in ('linux', 'pixel'), 'actual endpoint scope')
    build_file = Path(result['build'])
    need(digest(build_file) == result['build_sha256'], 'build witness changed')
    build = json.loads(build_file.read_text())
    chain = module('s227_chain_check', 'tests/evidence/product_chain.py')
    need(chain.source_files() == build['files'], 'current Product source differs')
    need(hashlib.sha256(chain.encode(build['files'])).hexdigest() == build['source_sha256'] == result['source_sha256'],
         'source closure hash')
    need(digest(build_file.parent/'dirty.diff') == build['dirty_diff_sha256'], 'frozen source diff')
    for name, expected in build['files'].items():
        if expected is not None: need(digest(build_file.parent/'source'/name) == expected, 'frozen source '+name)
    need(build['completed_ns'] < result['started_ns'] < result['completed_ns'], 'build/run ordering')
    helpers_file = Path(result['helpers'])
    need(digest(helpers_file) == result['helpers_sha256'], 'helper witness changed')
    helper = json.loads(helpers_file.read_text())
    need(helper['source_sha256'] == build['source_sha256'] and helper['build_sha256'] == digest(build_file)
         and helper['platform'] == result['platform'], 'helper source/platform lineage')
    for name, expected in helper['files'].items(): need(digest(helpers_file.parent/name) == expected, 'helper artifact '+name)
    for name, expected in helper['sources'].items():
        need(digest(helpers_file.parent/Path(name).name) == expected, 'frozen helper source '+name)
    need(digest(helper['compiler']['path']) == helper['compiler']['sha256'], 'helper compiler')
    for name, expected in result['test_sources'].items():
        need(digest(run/'test-source'/name) == expected, 'frozen collector dependency '+name)
        if name not in ('tests/device/s227-udp-expiry.py', 'docs/testing/2026-09-13_S227_UDP_EXPIRY.md'):
            need(digest(ROOT/name) == expected, 'verifier dependency differs '+name)
    need(result['raw_hashes'], 'raw inventory absent')
    for name, expected in result['raw_hashes'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'raw path escaped run')
        need(digest(run/name) == expected, 'raw hash mismatch '+name)
    if result['platform'] == 'linux':
        need((run/'uid-map.txt').read_text().split() == ['0', str(result['policy_uid']), '1']
             and str(result['policy_uid']) != '0', 'rootless network namespace')
        need(build['host_evidence'] is False, 'host fixture is not Product')
        for name, expected in build['artifact_hashes'].items(): need(digest(Path(build['artifact'])/name) == expected, 'Linux artifact '+name)
        if build.get('debug_strip'):
            strip = build['debug_strip']
            original_file = Path(strip['original_build'])
            need(digest(original_file) == strip['original_build_sha256'], 'original symbol build')
            original = json.loads(original_file.read_text())
            need(original['files'] == build['files'] and original['source_sha256'] == build['source_sha256'], 'strip source lineage')
            parser = module('s227_strip_check', 'tests/evidence/strip_s226_linux.py')
            need(digest(parser.__file__) == strip['script_sha256'] and strip['operation'] == '--strip-debug'
                 and digest(strip['strip_path']) == strip['strip_sha256'], 'strip tool/operation')
            need(digest(build_file.parent/'strip-audit.json') == strip['audit_sha256'], 'strip audit identity')
            for row in json.loads((build_file.parent/'strip-audit.json').read_text()):
                old, new = Path(original['artifact'])/row['path'], Path(build['artifact'])/row['path']
                need(digest(old) == row['before_sha256'] == original['artifact_hashes'][row['path']]
                     and digest(new) == row['after_sha256'], 'strip file identity')
                need(parser.allocated_sections(old) == parser.allocated_sections(new) == row['allocated_sections'],
                     'strip changed runtime sections')
    else:
        need(digest(build['apk']) == build['apk_sha256'] == (run/'installed-apk.txt').read_text().split()[0], 'installed APK')
        installed = {Path(line.split()[1]).name: line.split()[0] for line in (run/'installed-native.txt').read_text().splitlines()}
        need(installed == build['native_sha256'], 'installed native closure')
        with zipfile.ZipFile(build['apk']) as apk:
            need({Path(name).name: hashlib.sha256(apk.read(name)).hexdigest() for name in apk.namelist()
                  if name.startswith('lib/arm64-v8a/') and name.endswith('.so')} == installed, 'APK native content')
        for name in ('s227-udp', 's223-udp', 's217-policy'):
            need((run/(name+'-installed.txt')).read_text().split()[0] == helper['files'][name], 'installed endpoint '+name)
    need('Linux' in (run/'kernel.txt').read_text(), 'kernel witness')
    need('SAKAMOTO_S227_' not in (run/'hooks-after.txt').read_text(), 'final private hook residue')
    need(('fd20:6227::2' in (run/'addresses-before.txt').read_text()) ==
         ('fd20:6227::2' in (run/'addresses-after.txt').read_text()), 'temporary address residue')
    return build


def identity(entry):
    return int(entry.get('worker', entry.get('owner'))), int(entry['slot']), int(entry['incarnation'])


def snapshot(text, generation, expected_count, oracle):
    entries = {identity(e): e for e in rows(text, 'flow.entry ')}
    need(len(entries) == len(rows(text, 'flow.entry ')) == expected_count, 'snapshot entry identity/count')
    phases = {identity(e): e for e in rows(text, 'flow.udp ')}
    timers = {identity(e): e for e in rows(text, 'flow.timer ')}
    need(entries.keys() == phases.keys() == timers.keys(), 'entry/UDP/timer index differs')
    for key, e in entries.items():
        facts = dict(l3=1, l4=1, family=int(e['family']), protocol=17, src=e['key_a'], dst=e['key_b'],
                     src_port=int(e['port_a']), dst_port=int(e['port_b']), icmp_known=0)
        assigned = oracle.assignment(facts)
        need(assigned['owner'] == key[0] and assigned['hash'] == int(e['hash'])
             and e['protocol'] == '17' and e['kind'] == '2' and int(e['policy_generation']) == generation,
             'full typed key/owner/generation differs')
        phase = int(phases[key]['phase'])
        need(phase in (1, 2, 3) and int(timers[key]['timeout']) == phase, 'UDP timeout class differs')
        deadline = int(e['last_seen'])+(30000000 if phase == 3 else 60000000)
        need(int(timers[key]['deadline_us']) == deadline and int(timers[key]['heap_position']) != NO_SLOT, 'not actual pinned deadline')
        e['deadline_us'], e['timeout'] = deadline, phase
        need(int(e['packets']) == int(e['orig_packets'])+int(e['reply_packets']), 'flow packet accounting')
        need(int(e['bytes']) == int(e['orig_bytes'])+int(e['reply_bytes']), 'flow byte accounting')
    return entries


def fdinfo(text, armed):
    need(re.search(r'^clockid:\s*1$', text, re.M), 'timerfd clock is not MONOTONIC')
    value = re.search(r'^it_value:\s*\((\d+),\s*(\d+)\)$', text, re.M)
    interval = re.search(r'^it_interval:\s*\((\d+),\s*(\d+)\)$', text, re.M)
    need(value is not None and interval is not None, 'timerfd backing details missing')
    need(tuple(map(int, interval.groups())) == (0, 0), 'timerfd became periodic')
    need(any(map(int, value.groups())) == armed, 'actual timerfd armed/disarmed state')


def quantiles(values):
    ordered = sorted(values)
    return {**{f'p{q}_ms': ordered[math.ceil(len(ordered)*q/100)-1] for q in (50, 95, 99)}, 'max_ms': max(ordered)} if ordered else {}


def packet_ledger(log, generation, entries, endpoints, lanes, oracle):
    captures = rows(log, 's231 event=nfq_payload ')
    consumed = rows(log, 's204 event=completion_consume ')
    syscalls = rows(log, 's242 event=verdict_syscall ')
    returned = rows(log, 's203 event=buffer_free ')
    origin = rows(log, 's203 event=verdict ')
    key = lambda e: (e['lane'], e['packet'], e.get('token', e.get('obligation')))
    total = sum(int(e['echo'])+1 for e in endpoints)
    expected_capture = sum(min(int(l['captured']), 64) for l in lanes)
    need(len(captures) == len(origin) == expected_capture, 'capture/origin sample count')
    need(len(consumed) == min(total, 256), 'ordinary graph sample count')
    for name, records in (('capture', captures), ('completion', consumed), ('syscall', syscalls), ('origin', origin)):
        need(len({key(e) for e in records}) == len(records), 'duplicate '+name+' identity')
    need({key(e) for e in syscalls} == {key(e) for e in origin} | {key(e) for e in consumed}, 'sample syscall identity union')
    need(Counter((e['thread'], e['buffer'], e['token']) for e in consumed) ==
         Counter((e['thread'], e['buffer'], e['obligation']) for e in returned), 'ordinary buffer return identity')
    for e in syscalls:
        need(e['source'] == 'NFQ_CAPTURED' and int(e['generation']) == generation
             and int(e['queue']) == 176+int(e['lane']) and int(e['thread']) == int(e['lane'])%2+1
             and int(e['result']) > 0 and e['errno'] == '0' and e['verdict'] == '1', 'original native verdict syscall')
    for e in consumed:
        need(e['source'] == 'NFQ_CAPTURED' and int(e['generation']) == generation
             and int(e['thread']) == int(e['lane'])%2+1 and e['intent'] == '1', 'original completion route')
    parser = module('s227_packet_parser', 'tests/device/verify-s242-root-lifecycle.py')
    requests = {(int(e['family']), int(e['port']), ('E' if e['echo'] == '1' else 'S')+e['nonce']) for e in endpoints}
    for e in captures:
        need(e['source'] == 'NFQ_CAPTURED' and int(e['generation']) == generation, 'capture generation/source')
        packet = parser.packet(e['raw'])
        need(packet['protocol'] == 17 and PORT in (packet['sport'], packet['dport']), 'captured packet is not test UDP')
        port = packet['sport'] if packet['dport'] == PORT else packet['dport']
        need((packet['family'], port, packet['payload'].decode()) in requests, 'captured endpoint nonce')
    admissions = rows(log, 's216 stage=admit ')
    consumers = rows(log, 's225 event=consumer_packet ')
    need(Counter(e['token'] for e in admissions) == Counter(e['token'] for e in consumers) ==
         Counter(e['token'] for e in consumed), 'ordinary shared consumer path')
    consumer = {e['token']: e for e in consumers}
    for e in admissions:
        facts = {name: e[name] if name in ('src', 'dst') else int(e[name]) for name in
                 ('l3', 'l4', 'family', 'protocol', 'src', 'dst', 'src_port', 'dst_port', 'icmp_known')}
        assigned = oracle.assignment(facts)
        c = consumer[e['token']]
        need(int(e['owner']) == int(c['owner']) == assigned['owner'] and int(c['thread']) == assigned['owner']+1
             and int(c['generation']) == generation and c['buffer'] == e['buffer'] and c['is_flow_end'] == '0',
             'ordinary owner/consumer carrier')
    end_events = {}
    for e in rows(log, 's225 '):
        if e.get('event') in ('unlink_allocate', 'consumer_end', 'terminal_end', 'free_callback', 'consumer_early_free'):
            end_events.setdefault(identity(e), []).append(e)
    expected_end_samples = sum(min(sum(key[0] == owner for key in entries), 256) for owner in (0, 1))
    need(len(end_events) == expected_end_samples, 'bounded END graph sample count')
    nodes = {e['node'] for e in consumers}
    for key, events in end_events.items():
        need(key in entries and [e['event'] for e in events] ==
             ['unlink_allocate', 'consumer_end', 'terminal_end', 'free_callback'], 'END graph/free order')
        need(len({e['buffer'] for e in events}) == 1 and events[0]['node'] == events[1]['node']
             and events[0]['node'] in nodes, 'END not the same shared consumer/carrier')
        for e in events:
            need(int(e['generation']) == generation and int(e['thread']) == key[0]+1 and e['reason'] == '2'
                 and e['allocated'] == '1' and e['linked'] == e['length'] == e['obligation'] == '0', 'END owner/obligation/lifetime')
            for field in ('hash', 'protocol', 'orig_packets', 'reply_packets', 'orig_bytes', 'reply_bytes', 'first_seen', 'last_seen'):
                need(e[field] == str(entries[key][field]), 'END retained snapshot '+field)
    return dict(captured=total, capture_samples=len(captures), completion_samples=len(consumed),
                syscall_samples=len(syscalls), end_graph_samples=len(end_events))


def endpoint_ledger(record, read, servers, selected):
    text = read('client-closed.txt')
    need(record.get('client_closed') and text == read('client-final.txt'), 'client still active or sent after final snapshot')
    endpoints = rows(text, 'endpoint ')
    need(endpoints and len({e['nonce'] for e in endpoints}) == len(endpoints), 'endpoint nonce missing/duplicated')
    prepared = rows(text, 'prepared ')
    need(len(prepared) == 1 and int(prepared[0]['count']) == int(prepared[0]['retained_fds']) == len(selected)
         and prepared[0]['mode'] == record['case'], 'same retained socket set')
    need(len(rows(text, 'holding ')) == 1, 'endpoint did not enter final quiet holding state')
    by_tuple = {(e['family'], e['port']): e for e in selected}
    need(len(by_tuple) == len(selected), 'duplicate tuple manifest')
    name = record['case']
    phases = (0, 1, 2) if name == 'lookup' else (0, 1) if name in ('renew-first', 'shorten', 'renew-bidir') else (0,)
    need([int(e['phase']) for e in rows(text, 'stage ')] == list(phases), 'endpoint phase sequence')
    payload_bytes = {}
    targets = set()
    for e in endpoints:
        family, port, phase = int(e['family']), int(e['port']), int(e['phase'])
        need((family, port) in by_tuple and int(e['owner']) == by_tuple[(family, port)]['owner'], 'endpoint owner manifest')
        expected_echo = name in ('bulk', 'lookup', 'renew-bidir') or (name == 'shorten' and phase == 1)
        need(int(e['echo']) == expected_echo and e['nonce'] == f'{record["nonce"]}-{phase}-{family}-{port}', 'endpoint request mode/nonce')
        need(servers[(e['nonce'], e['echo'])] == 1, 'server did not observe unique endpoint request')
        if expected_echo: need(int(e['received_ns']) >= int(e['sent_ns']) > 0, 'endpoint did not observe reply')
        else: need(e['received_ns'] == '0' and int(e['sent_ns']) > 0, 'unexpected reply or missing send')
        if e['target'] == '1': targets.add((family, port))
        payload_bytes[(phase, family, port)] = len(e['nonce'])+1
    for phase in phases:
        current = [e for e in endpoints if int(e['phase']) == phase]
        expected = len(selected) if name != 'lookup' or phase == 0 else 4
        need(len(current) == expected and len({(e['family'], e['port']) for e in current}) == expected, 'phase endpoint count')
    need(len(targets) == 4, 'one retained target per owner/family')
    start = int(prepared[0]['mono_ns'])
    if name in ('renew-first', 'shorten', 'renew-bidir'):
        interval = 10 if name == 'shorten' else 20
        sent = [int(e['sent_ns']) for e in endpoints if e['phase'] == '1']
        need(start+interval*10**9 <= min(sent) <= max(sent) <= start+(interval+2)*10**9, 'real timed refresh interval')
    if name == 'lookup':
        first = max(int(e['received_ns']) for e in endpoints if e['phase'] == '1')
        last = min(int(e['sent_ns']) for e in endpoints if e['phase'] == '2')
        need(first+30*10**9 <= last <= first+32*10**9, 'lookup did not wait real BIDIR deadline')
    return endpoints, targets, payload_bytes


def batch_ledger(log, generation, original, replacements, logical):
    active = dict(original)
    closed, previous, budgets = set(), {}, {0: 0, 1: 0}
    owner_results = []
    for event in rows(log, 's227 '):
        kind = event.get('event')
        if kind not in ('batch', 'logical_expiry'): continue
        owner = int(event['owner'])
        need(owner in (0, 1) and int(event['thread']) == owner+1 and int(event['generation']) == generation,
             'expiry batch/lookup owner or generation')
        if kind == 'logical_expiry':
            old = (owner, int(event['old_slot']), int(event['old_incarnation']))
            new = (owner, int(event['new_slot']), int(event['new_incarnation']))
            need(old in active and old in logical and new in replacements, 'logical lookup did not precede physical cleanup')
            del active[old]
            active[new] = replacements[new]
            continue
        now, count = int(event['now_us']), int(event['closed'])
        need(1 <= count <= 100 and (owner not in previous or now-previous[owner] >= 100000), 'bounded expiry work pacing')
        current = sorted((key for key in active if key[0] == owner), key=lambda key: (active[key]['deadline_us'], key[1]))
        need(len(current) >= count and active[current[0]]['deadline_us'] == int(event['oldest_us']), 'batch did not pop the real minimum')
        for key in current[:count]:
            need(active[key]['deadline_us'] <= now and key not in closed, 'early or duplicate batch close')
            del active[key]
            closed.add(key)
        remaining = [e['deadline_us'] for key, e in active.items() if key[0] == owner]
        minimum = min(remaining, default=MAX_U64)
        due = minimum != MAX_U64 and minimum <= now
        if count == 100 and due: budgets[owner] += 1
        need(int(event['timers']) == len(remaining) and int(event['next_us']) == minimum, 'batch timer/backlog accounting')
        need(int(event['due_backlog']) == due and int(event['budget_exhausted']) == budgets[owner], 'due backlog/budget exhaustion accounting')
        previous[owner] = now
        owner_results.append(dict(owner=owner, now_us=now, closed=count,
            oldest_overdue_ms=(now-int(event['oldest_us']))/1000, remaining=len(remaining), budget_exhausted=budgets[owner]))
    need(not active and closed | set(logical) == set(original) | set(replacements), 'unaccounted expiry or final timer residue')
    return owner_results


def case(run, record, pixel, oracle, servers):
    name, generation, count = record['case'], record['generation'], COUNTS[record['case']]
    folder = run/record['label']
    read = lambda filename: (folder/filename).read_text()
    need(record['label'] == name and record['count_per_owner'] == count and record.get('process_closed'), 'case identity/process cleanup')
    capacity = 4096 if name == 'lookup' else 1024
    config = read('startup.conf')
    need(f'product-flow-runtime {{ entries {capacity} }}' in config and 'product-flow-expiry { trace-all }' in config
         and 'experiment' not in config and 'buffers-per-numa' not in config, 'production startup configuration')
    log = read('vpp.log')
    need(not re.search(r'event=(?:infrastructure_failure|fatal_allocation_failure)|Assertion.*failed|clib_panic', log), 'native infrastructure failure')
    initial, complete, final = map(read, ('initial.txt', 'completed.txt', 'closed.txt'))
    need('root.stop=ok' in read('stop.txt'), 'normal stop missing')
    initial_expiry = rows(initial, 'expiry.owner=')
    need([e['expiry.owner'] for e in initial_expiry] == ['0', '1'] and all(e['mode'] == '2' and e['experiment'] == '0'
         and e['initialize'] == '0' and e['timers'] == '0' and int(e['scheduled_us']) == MAX_U64
         and int(e['generation']) == generation for e in initial_expiry), 'driver not default-on and initially disarmed')
    backing = timer_fds(read('initial-fds.txt'))
    owner_fds = {int(e['timer_fd']) for e in initial_expiry}
    need(len(backing) == 4 and len(owner_fds) == 2 and owner_fds <= backing.keys(), 'actual initial owner timerfd backing')
    for owner in (0, 1):
        fdinfo(read('initial-fdinfo-'+str(owner)+'.txt'), False)
        fdinfo(read('armed-fdinfo-'+str(owner)+'.txt'), True)
    selected = json.loads(read('tuples.json'))
    need(len(selected) == count*2 and Counter(e['owner'] for e in selected) == {0: count, 1: count}, 'W2 tuple distribution')
    endpoints, targets, lengths = endpoint_ledger(record, read, servers, selected)
    seeded = snapshot(read('seeded.txt'), generation, count*2, oracle)
    expected_tuples = {(e['family'], e['port']): e for e in selected}
    for key, entry in seeded.items():
        port = int(entry['port_a']) if int(entry['port_b']) == PORT else int(entry['port_b'])
        need(PORT in (int(entry['port_a']), int(entry['port_b'])) and (int(entry['family']), port) in expected_tuples
             and expected_tuples[(int(entry['family']), port)]['owner'] == key[0], 'flow is outside endpoint tuple set')
    original = seeded
    if name in ('renew-first', 'shorten', 'renew-bidir'):
        original = snapshot(read('refreshed.txt'), generation, count*2, oracle)
        need(original.keys() == seeded.keys(), 'refresh replaced an unexpired instance')
        for key, entry in original.items():
            need(entry['first_seen'] == seeded[key]['first_seen'], 'refresh reset flow lifetime')
            if name == 'shorten': need(entry['deadline_us'] < seeded[key]['deadline_us'], 'BIDIR did not shorten deadline')
            else: need(entry['deadline_us'] > seeded[key]['deadline_us'], 'valid packet did not renew deadline')
        if name != 'shorten':
            retained = snapshot(read('past-original-deadline.txt'), generation, count*2, oracle)
            need(retained == original, 'state changed without a new packet after renewal')
            need(all(e['released'] == '0' and e['wakes'] == '0' for e in rows(read('past-original-deadline.txt'), 'expiry.owner=')),
                 'old deadline still triggered expiry notification')
    replacements = snapshot(read('backlog-drained.txt'), generation, 4, oracle) if name == 'lookup' else {}
    logical = {}
    for event in rows(log, 's227 event=logical_expiry '):
        old = (int(event['owner']), int(event['old_slot']), int(event['old_incarnation']))
        new = (int(event['owner']), int(event['new_slot']), int(event['new_incarnation']))
        need(name == 'lookup' and old in original and new in replacements and old not in logical, 'unexpected logical expiry identity')
        need(old[1] != new[1] and old[2] != new[2] and event['created'] == '1'
             and int(event['generation']) == generation and int(event['thread']) == old[0]+1, 'old END slot overwritten or wrong owner')
        need(int(event['old_deadline_us']) == original[old]['deadline_us'] <= int(event['now_us'])
             and int(replacements[new]['first_seen']) == int(event['now_us']), 'logical expiry was not at real observation time')
        for field in ('key_a', 'key_b', 'port_a', 'port_b', 'family', 'hash'):
            need(original[old][field] == replacements[new][field], 'logical expiry changed typed tuple')
        logical[old] = event
    need(len(logical) == (4 if name == 'lookup' else 0) and (not logical or Counter(k[0] for k in logical) == {0: 2, 1: 2}),
         'both owner/family logical-expiry coverage')
    entries = {**original, **replacements}
    for key, entry in entries.items():
        family = int(entry['family'])
        port = int(entry['port_a']) if int(entry['port_b']) == PORT else int(entry['port_b'])
        packets = [e for e in endpoints if int(e['family']) == family and int(e['port']) == port
                   and (name != 'lookup' or (e['phase'] == '2') == (key in replacements))]
        request_count = len(packets)
        reply_count = sum(int(e['echo']) for e in packets)
        overhead = 28 if family == 4 else 48
        request_bytes = sum(overhead+lengths[(int(e['phase']), family, port)] for e in packets)
        reply_bytes = sum(overhead+lengths[(int(e['phase']), family, port)] for e in packets if e['echo'] == '1')
        need(int(entry['orig_packets']) == request_count and int(entry['reply_packets']) == reply_count
             and int(entry['orig_bytes']) == request_bytes and int(entry['reply_bytes']) == reply_bytes, 'full endpoint flow accounting')
    releases = rows(log, 's227 event=release ')
    expected_ends = {} if name == 'stop' else entries
    need(len(releases) == len(expected_ends), 'missing/extra native final release')
    released, latencies = {}, []
    for release in releases:
        key = identity(release)
        need(key in expected_ends and key not in released, 'stale or duplicate final release identity')
        entry = entries[key]
        need(int(release['generation']) == generation and int(release['thread']) == key[0]+1, 'release owner/generation')
        need(int(release['deadline_us']) == entry['deadline_us'] and int(release['timeout']) == entry['timeout']
             and release['packets'] == entry['packets'] and release['linked'] == '0'
             and int(release['heap_position']) == NO_SLOT, 'release deadline/retained timer snapshot')
        when = int(release['release_us'])
        need(when >= entry['deadline_us'], 'entry released before real deadline')
        if key in logical: need(when >= int(logical[key]['now_us']), 'logical END released before lookup')
        released[key] = when
        latencies.append((when-entry['deadline_us'])/1000)
    batches = batch_ledger(log, generation, original, replacements, logical) if name != 'stop' else []
    stale = rows(log, 's227 event=stale_wake ')
    need(len(stale) == (2 if name == 'stop' else 0), 'unexpected stale-wake evidence count')
    if name == 'stop':
        need({int(e['owner']) for e in stale} == {0, 1} and all(int(e['thread']) == int(e['owner'])+1
             and int(e['generation']) == generation and int(e['received_generation']) == generation-1
             and e['accepted'] == '0' for e in stale), 'old generation callback accepted or wrong owner')
        retained = snapshot(read('after-stale.txt'), generation, 4, oracle)
        need(retained == seeded and not rows(log, 's227 event=batch '), 'stale wake mutated current entries')
    else:
        need(not rows(complete, 'flow.entry '), 'entries remain after deadline')
        for owner in (0, 1): fdinfo(read('disarmed-fdinfo-'+str(owner)+'.txt'), False)
    owners = []
    for owner in (0, 1):
        original_keys = [key for key in original if key[0] == owner]
        current_batches = [row for row in batches if row['owner'] == owner]
        if name == 'stop': continue
        earliest = min(original[key]['deadline_us'] for key in original_keys)
        finish = (max(released[key] for key in original_keys)-earliest)/1000
        oldest = max((row['oldest_overdue_ms'] for row in current_batches), default=0)
        spread = (max(original[key]['deadline_us'] for key in original_keys)-earliest)/1000
        if name == 'bulk':
            need(spread <= 1000 and oldest <= 2000 and finish <= 3000, 'bulk input/tail latency gate')
            need(current_batches and current_batches[-1]['budget_exhausted'] > 0, 'bulk did not exercise budget exhaustion')
        if name == 'lookup': need(oldest <= 6000 and finish <= 7000, 'lookup original backlog latency gate')
        owners.append(dict(owner=owner, timers=count, spread_ms=spread, all_original_released_ms=finish,
                           oldest_overdue_ms=oldest, batches=len(current_batches),
                           budget_exhausted=current_batches[-1]['budget_exhausted'] if current_batches else 0))
    normal = [(released[key]-entry['deadline_us'])/1000 for key, entry in expected_ends.items()
              if name not in ('bulk', 'lookup') or key in replacements]
    normal_quantiles = quantiles(normal)
    if normal_quantiles:
        need(normal_quantiles['p99_ms'] <= 1100 and normal_quantiles['max_ms'] <= 1500, 'normal release latency gate')
    if name == 'shorten': need(all(released[key] < seeded[key]['deadline_us'] for key in original), 'shortened entry waited for old FIRST deadline')
    expected_packets = sum(1+int(e['echo']) for e in endpoints)
    for text, stopped in ((complete, False), (final, True)):
        lanes = rows(text, 'root.lane ')
        need(len(lanes) == 4 and sum(int(l['captured']) for l in lanes) == expected_packets, 'captured packet total')
        need(all(l['captured'] == l['submitted'] == l['verdicts'] == l['succeeded']
                 and l['pending'] == l['failed'] == l['duplicate'] == '0' for l in lanes), 'original NFQUEUE settlement conservation')
        completion = rows(text, 'completion.status ')
        need(len(completion) == 1 and all(completion[0][key] == '0' for key in
             ('pending', 'frames', 'buffers', 'obligations', 'duplicate', 'stale')), 'packet completion debt')
        end = rows(text, 'flow-end.owner=')
        need(len(end) == 2 and 'flow-end.buffers=0' in text, 'pending END carrier')
        for row in end:
            n = count+(2 if name == 'lookup' else 0) if name != 'stop' else 0
            administrative = count if name == 'stop' and stopped else 0
            need(all(int(row[key]) == n for key in ('allocated', 'consumers', 'terminals', 'released'))
                 and int(row['pool_releases']) == n+administrative, 'END allocation/consumer/free conservation')
            need(row['early_frees'] == row['ending'] == '0'
                 and int(row['administrative_releases']) == administrative, 'substitute cleanup or END residue')
            remaining = count if name == 'stop' and not stopped else 0
            need(int(row['active_entries']) == int(row['linked']) == remaining, 'entry visibility/lifetime residue')
        need(all(row[key] == '0' for row in rows(text, 'flow.pool ') for key in
                 ('capacity_drops', 'wrong_owner', 'revision_mismatches')), 'flow bypass or identity error')
        expiry = rows(text, 'expiry.owner=')
        need([e['expiry.owner'] for e in expiry] == ['0', '1']
             and all(int(e['generation']) == generation for e in expiry), 'expiry owner/generation identity')
        for e in expiry:
            owner = int(e['expiry.owner'])
            owner_batches = [r for r in rows(log, 's227 event=batch ') if int(r['owner']) == owner]
            expected_budget = int(owner_batches[-1]['budget_exhausted']) if owner_batches else 0
            peak = max((int(r['now_us'])-int(r['oldest_us']) for r in owner_batches), default=0)
            need(int(e['batches']) == int(e['checks']) == len(owner_batches)
                 and int(e['closed']) == sum(int(r['closed']) for r in owner_batches)
                 and int(e['budget_exhausted']) == expected_budget and int(e['oldest_overdue_us']) == peak,
                 'final expiry counters differ from actual batches')
            expected_releases = count+(2 if name == 'lookup' else 0) if name != 'stop' else 0
            need(int(e['released']) == expected_releases and int(e['logical_expired']) == (2 if name == 'lookup' else 0),
                 'expiry release/logical counters')
            need(int(e['stale_wakes']) == (1 if name == 'stop' else 0), 'stale-wake rejection counter')
            need(int(e['timers']) == (count if name == 'stop' and not stopped else 0), 'timer residue')
            if stopped:
                need(e['mode'] == '0' and e['timer_fd'] == '-1' and int(e['timer_file']) == NO_SLOT
                     and int(e['scheduled_us']) == MAX_U64, 'timer backing not detached')
            else:
                need(e['mode'] == '2' and (name == 'stop' or int(e['scheduled_us']) == MAX_U64), 'expiry did not remain interrupt/disarm')
    initial_pool, completed_pool, closed_pool = map(pool, (initial, complete, final))
    need(initial_pool['total'] == completed_pool['total'] == closed_pool['total']
         and initial_pool['used'] == completed_pool['used'] == 288 and closed_pool['used'] == 0, 'native buffer pool residue')
    need(not timer_fds(read('closed-fds.txt')) and 'SAKAMOTO_S227_' not in read('hooks-after.txt'), 'closed FD/private hook residue')
    if pixel:
        need(not any(parts and parts[0] in ('176', '177', '178', '179')
                     for parts in map(str.split, read('closed-queues.txt').splitlines())), 'queue still bound after stop')
    else: need(set(json.loads(read('closed-queue-bind.json')).values()) == {0}, 'queue could not be rebound after stop')
    ledger = packet_ledger(log, generation, expected_ends, endpoints, rows(complete, 'root.lane '), oracle)
    return dict(case=name, generation=generation, entries=len(entries), releases=len(releases),
                logical_expirations=len(logical), stale_wakes=len(stale), packets=expected_packets,
                latency=quantiles(latencies), normal_latency=normal_quantiles, owners=owners, ledger=ledger)


def verify(run):
    run = Path(run).resolve()
    result = json.loads((run/'result.json').read_text())
    authority(run, result)
    oracle = module('s227_owner_check', 'tests/device/s207-owner-oracle.py')
    servers = Counter((row['nonce'], row['echo']) for path in run.glob('s227-server-*.log')
                      for row in rows(path.read_text(), 'received '))
    records = result['generations']
    need([r['case'] for r in records] == result['requested_cases'] and len({r['case'] for r in records}) == len(records), 'case matrix/order')
    need([r['generation'] for r in records] == list(range(22710, 22710+len(records))), 'generation sequence')
    outcomes = [case(run, record, result['platform'] == 'pixel', oracle, servers) for record in records]
    complete = {r['case'] for r in outcomes} == set(COUNTS)
    dependencies = ['tests/device/verify-s226-expiry-ab.py', 'tests/device/verify-s242-root-lifecycle.py',
                    'tests/device/s207-owner-oracle.py', 'tests/evidence/strip_s226_linux.py', 'tests/evidence/product_chain.py']
    return dict(status='PASS' if complete else 'VALID_PARTIAL', platform=result['platform'],
        scope='real-UDP-default-owner-local-expiry-not-TCP-ICMP-matrix', matrix_complete=complete,
        source_sha256=result['source_sha256'], build_sha256=result['build_sha256'], run_result_sha256=digest(run/'result.json'),
        verifier_sha256=digest(__file__), verifier_dependencies={p: digest(ROOT/p) for p in dependencies}, outcomes=outcomes)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    outcome = verify(args.run)
    (args.output or args.run/'verified.json').write_text(json.dumps(outcome, indent=2)+'\n')
    print(json.dumps(outcome, indent=2))


if __name__ == '__main__':
    main()
