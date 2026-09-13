#!/usr/bin/env python3
"""Large lookup: bounded native packet samples plus independent target wire."""
from collections import Counter, defaultdict
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s236_lookup_base', ROOT/'tests/device/verify-s236-protocol-expiry.py')
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
need, rows, identity = base.need, base.rows, base.identity
PORT = 40636


def wire(read, record):
    text = read('wire-final.txt')
    windows, listeners = rows(text, 'window '), rows(text, 'listen ')
    need(len(windows) == len(listeners) == 1 and listeners[0]['source'] == 'AF_PACKET' and
         listeners[0]['selected'] == '12' and windows[0]['full'] == '1', 'independent target capture/window absent')
    window = int(windows[0]['mono_ns'])
    selected = {(e['family'], e['protocol'], e['value']) for e in record['wire_targets']}
    need(len(selected) == 12, 'independent capture selection')
    groups = defaultdict(list); excluded = 0
    for e in rows(text, 'wire '):
        key = tuple(int(e[k]) for k in ('family', 'protocol', 'value'))
        need(key in selected and int(e['mono_ns']) >= int(listeners[0]['mono_ns']) and
             (int(e['mono_ns']) >= window) == bool(int(e['full'])), 'wire escaped selected tuple/window')
        data = bytes.fromhex(e['raw']); offset = (data[0] & 15)*4 if data[0] >> 4 == 4 else 40
        # The kernel handshake/data outside the explicit SYN-only window is
        # not Product input. AF_PACKET may expose offloaded checksums there.
        if key[1] == 6 and e['full'] == '0' and data[offset+13] & 18 != 2:
            excluded += 1; continue
        p = base.packet(e['raw'])  # Complete checksum verification for actual captured-window traffic.
        value = p['sport'] if p.get('dport') == PORT else p['dport'] if key[1] in (6, 17) else p['identifier']
        need((p['family'], p['protocol'], value) == key, 'wire header/selection identity')
        p.update(full=int(e['full']), wire_ns=int(e['mono_ns']))
        groups[key].append(p)
    need(groups.keys() == selected, 'target missing from independent wire')
    return groups, excluded


def endpoint_requests(run, record, read):
    client = read('client-final.txt')
    need(client == read('client-closed.txt') and record['client_closed'], 'large endpoint not retained until final snapshot')
    prepared, stages = rows(client, 'prepared '), rows(client, 'mixed_stage ')
    need(len(prepared) == 1 and prepared[0]['mode'] == 'lookup' and prepared[0]['udp'] == '8192' and
         prepared[0]['mixed'] == '8' and [e['phase'] for e in stages] == ['0', '1'] and len(rows(client, 'holding ')) == 1,
         'actual large prepared/stage/holding population')
    need(int(stages[1]['mono_ns'])-int(stages[0]['mono_ns']) >= 30001000000, 'actual 30.001s lookup delay')
    expected = {(e['family'], e['port']): e for e in record['udp']}
    need(len(expected) == 8192, 'unique bulk tuple inventory')
    requests = [e for e in rows(client, 'endpoint ') if 'port' in e]
    need(len(requests) == 8200 and len({e['nonce'] for e in requests}) == len(requests), 'UDP request/reply phase cardinality')
    servers = Counter((int(e['family']), e['nonce']) for family in (4, 6)
        for e in rows((run/f's236-udp-{family}.log').read_text(), 'received '))
    grouped = defaultdict(list)
    for e in requests:
        family, port, phase = (int(e[k]) for k in ('family', 'port', 'phase'))
        key = family, port
        need(key in expected and int(e['owner']) == expected[key]['owner'] and e['echo'] == '1' and
             e['nonce'] == f'{record["nonce"]}-{phase}-{family}-{port}' and
             int(e['received_ns']) >= int(e['sent_ns']) > 0 and servers[(family, e['nonce'])] == 1,
             'independent bulk socket/server nonce identity')
        grouped[key].append(e)
    targets = {(e['family'], e['value']) for e in record['wire_targets'] if e['protocol'] == 17}
    for key, values in grouped.items():
        need([int(e['phase']) for e in values] == ([0, 1, 2] if key in targets else [0]), 'bulk/retained target phases')
    need(grouped.keys() == expected.keys(), 'missing bulk endpoint tuple')
    return client, requests, grouped


def snapshot(text, record, wires, requests, ref, original=None):
    entries = rows(text, 'flow.entry ')
    timers = {identity(e): e for e in rows(text, 'flow.timer ')}
    protocols = {identity(e): e for prefix in ('flow.tcp ', 'flow.udp ', 'flow.icmp ') for e in rows(text, prefix)}
    need(len(entries) == len(timers) == len(protocols) and {identity(e) for e in entries} == timers.keys() == protocols.keys(), 'large snapshot entry/heap/protocol identity')
    manifest = {(e['family'], 17, e['port']): e for e in record['udp']}
    manifest.update({(e['family'], e['protocol'], e['value']): e for e in record['flows']})
    result, native = {}, {}
    for e in entries:
        key = identity(e); timer = timers[key]; protocol = int(e['protocol']); family = int(e['family'])
        value = int(e['port_a']) if protocol in (6, 17) else int(e['identifier'])
        tuple_key = family, protocol, value
        need(tuple_key in manifest, 'unmanifested large snapshot tuple')
        declared = manifest[tuple_key]
        expected = declared['expected']
        facts = dict(l3=1, l4=1 if protocol in (6, 17) else 2, family=family, protocol=protocol,
            src=e['key_a'], dst=e['key_b'], src_port=value, dst_port=PORT,
            icmp_known=protocol not in (6, 17), icmp_type=8 if family == 4 else 128,
            icmp_code=0, icmp_id=value, icmp_seq=0)
        a = base.owner_oracle.assignment(facts)
        need(a == expected and key[0] == a['owner'] == declared['owner'] and int(e['hash']) == a['hash'] and
             int(e['kind']) == a['key_kind'] and int(e['origin_is_a']) == a['source_is_a'], 'independent large typed key/owner/origin')
        new = original is not None and key not in original
        state = dict(key=key, assignment=a, tuple=tuple_key, origin=a['source_is_a'], first=int(e['first_seen']),
            last=int(e['last_seen']), packets=[0, 0], bytes=[0, 0], timeout=0, deadline_us=0)
        details = protocols[key]
        if protocol == 17:
            phases = [r for r in requests[(family, value)] if (int(r['phase']) == 2) == new]
            need(phases, 'snapshot has no actual UDP phase')
            state['packets'] = [len(phases)]*2
            state['bytes'] = [sum((20 if family == 4 else 40)+8+1+len(r['nonce']) for r in phases)]*2
            state['timeout'] = 3
            need(details['phase'] == '3', 'large UDP not actually bidirectional')
        else:
            candidates = wires[tuple_key]
            if protocol == 6: candidates = [p for p in candidates if bool(p['full']) == new]
            else:
                marker = f'{record["nonce"]}-p{protocol}-f{family}-v{value}-{1 if new else 0}-0'.encode()
                candidates = [p for p in candidates if p['payload'] == marker]
            total = int(e['packets'])
            need(0 < total <= len(candidates), 'snapshot has no independent wire prefix')
            candidates = candidates[:total]
            context, flags, output = ref.create() if protocol == 6 else None, [0, 0], None
            for p in candidates:
                side = int(p['assigned']['source_is_a'] != state['origin'])
                state['packets'][side] += 1; state['bytes'][side] += p['size']
                if protocol == 6:
                    output = ref.step(context, p, side)
                    need(output[0] != 12 and not output[4], 'unexpected INVALID/replacement in wire oracle')
                    flags[side] |= p['flags']
                    state['timeout'] = output[2]-41+4
            if protocol == 6:
                need(total == 1 if not new else total >= 2, 'FIRST or midstream actual packet population')
                for peer, label in enumerate(('orig', 'reply')):
                    need([int(details[label+'_'+field]) for field in ('seqlo', 'seqhi', 'maxwin', 'scale', 'state')] ==
                         output[5+peer*5:10+peer*5] and int(details[label+'_flags']) == flags[peer], 'pinned TCP state differs from independent wire')
            else:
                need(total == 2 and [int(details[k]) for k in ('phase', 'seen_request', 'seen_reply')] == [2, 1, 1], 'real ICMP request/reply phase')
                state['timeout'] = 11
        need(state['first'] <= state['last'] and int(e['packets']) == sum(state['packets']) and
             int(e['bytes']) == sum(state['bytes']) and [int(e[k]) for k in ('orig_packets', 'reply_packets')] == state['packets'] and
             [int(e[k]) for k in ('orig_bytes', 'reply_bytes')] == state['bytes'], 'large packet/byte accounting differs from real endpoints')
        need(int(e['policy_generation']) == record['generation'] and e['revision'] == e['snapshot_hash'] == '1', 'large policy generation/revision')
        state['deadline_us'] = state['last']+base.DURATIONS[state['timeout']]
        need(int(timer['deadline_us']) == state['deadline_us'] and int(timer['timeout']) == state['timeout'] and
             int(timer['heap_position']) != base.NO_SLOT, 'large pinned deadline/heap membership')
        result[key] = state; native[key] = dict(e, deadline_us=state['deadline_us'], timeout=state['timeout'])
    for owner in (0, 1):
        positions = {int(e['heap_position']) for key, e in timers.items() if key[0] == owner}
        need(positions == set(range(sum(key[0] == owner for key in timers))), 'owner heap positions not unique/compact')
    need(sum(int(e['timers']) for e in rows(text, 'expiry.owner=')) == len(entries), 'one physical heap membership per entry')
    return result, native


def heap(log, original, replacements, generation):
    active, closed, logical, batches = dict(original), {}, {}, []
    previous, budgets = {}, {0: 0, 1: 0}
    for e in rows(log, 's227 '):
        if e['event'] not in ('batch', 'logical_expiry'): continue
        owner = int(e['owner'])
        need(owner in (0, 1) and int(e['thread']) == owner+1 and int(e['generation']) == generation, 'large owner/generation')
        if e['event'] == 'logical_expiry':
            old = owner, int(e['old_slot']), int(e['old_incarnation'])
            new = owner, int(e['new_slot']), int(e['new_incarnation'])
            need(old in original and old in active and old not in closed and new in replacements and new != old,
                 'large logical lookup did not precede physical cleanup')
            s = active.pop(old)
            need(s['deadline_us'] == int(e['old_deadline_us']) <= int(e['now_us']) and e['created'] == '1' and
                 replacements[new]['first'] == int(e['now_us']) and s['tuple'] == replacements[new]['tuple'], 'logical old/new tuple or actual deadline/time')
            closed[old] = s; logical[old] = e; active[new] = replacements[new]
            continue
        now, count = int(e['now_us']), int(e['closed'])
        need(1 <= count <= 100 and (owner not in previous or now-previous[owner] >= 100000), 'large 100 END / 100ms pacing')
        ordered = sorted((key for key in active if key[0] == owner), key=lambda key: (active[key]['deadline_us'], key[1]))
        need(len(ordered) >= count and active[ordered[0]]['deadline_us'] == int(e['oldest_us']), 'large shared heap minimum')
        for key in ordered[:count]:
            s = active.pop(key)
            need(s['deadline_us'] <= now and key not in closed, 'large early/duplicate expiry')
            closed[key] = s
        deadlines = [s['deadline_us'] for key, s in active.items() if key[0] == owner]
        minimum = min(deadlines, default=base.MAX_U64)
        due = minimum != base.MAX_U64 and minimum <= now
        if count == 100 and due: budgets[owner] += 1
        need(int(e['timers']) == len(deadlines) and int(e['next_us']) == minimum and int(e['due_backlog']) == due and
             int(e['budget_exhausted']) == budgets[owner], 'large shared heap/backlog accounting')
        previous[owner] = now; batches.append(dict(owner=owner, count=count, due_backlog=due))
    need(len(logical) == 12 and {(key[0], s['tuple'][0], 'icmp' if s['tuple'][1] in (1, 58) else str(s['tuple'][1]))
         for key, s in closed.items() if key in logical} == {(o, f, p) for o in (0, 1) for f in (4, 6) for p in ('6', '17', 'icmp')},
         'all twelve actual protocol/family/owner logical lookups')
    need(all(budgets[o] > 0 for o in (0, 1)), 'both owners must exercise real due backlog')
    need(active.keys() == {key for key, s in replacements.items() if s['tuple'][1] == 6} and
         all(s['timeout'] == 6 for s in active.values()), 'only real new established TCP may remain')
    return active, closed, logical, batches


def target_endpoints(run, record, wires, client):
    for flow in record['wire_targets']:
        key = flow['family'], flow['protocol'], flow['value']
        packets = wires[key]
        if flow['protocol'] == 17:
            expected = [f'E{record["nonce"]}-{phase}-{flow["family"]}-{flow["value"]}'.encode() for phase in (0, 1, 2)]
            need(Counter(p['payload'] for p in packets) == Counter({payload: 2 for payload in expected}), 'UDP target independent wire phases')
            continue
        nonce = f'{record["nonce"]}-p{flow["protocol"]}-f{flow["family"]}-v{flow["value"]}'
        if flow['protocol'] == 6:
            receipts = [e for e in rows(client, 'received ') if e['nonce'] == nonce]
            connected = [e for e in rows(client, 'tcp_connected ') if e['nonce'] == nonce]
            need(len(connected) == 1 and connected[0]['keepalive'] == '0' and [e['phase'] for e in receipts] == ['0', '1'], 'held real TCP socket/nonce')
            server = rows((run/f's236-tcp-{flow["family"]}-close.log').read_text(), 'echo ')
            for phase in (0, 1):
                need(sum(e['data'] == (nonce+':'+str(phase)).encode().hex() for e in server) == 1, 'independent retained TCP server')
            need(sum(p['payload'] == (nonce+':1').encode() for p in packets) == 2, 'post-lookup actual TCP data pair')
        else:
            expected = [(nonce+'-'+str(phase)+'-0').encode() for phase in (0, 1)]
            need(Counter(p['payload'] for p in packets) == Counter({payload: 2 for payload in expected}), 'ICMP target independent wire phases')
            receipts = [e for e in rows(client, 'endpoint ') if 'identifier' in e and int(e['identifier']) == flow['value'] and int(e['family']) == flow['family']]
            need(len(receipts) == 2 and all(int(e['reply_ns']) > int(e['sent_ns']) > 0 for e in receipts), 'kernel ICMP target replies')
            server = rows((run/f's224-icmp-{flow["family"]}.log').read_text(), 'received ')
            need(all(sum(bytes.fromhex(e['raw'])[8:] == payload and e['checksum_valid'] == '1' for e in server) == 1
                     for payload in expected), 'independent ICMP target server checksum/nonce')


def verify_lookup(run, record, platform, ref, release_ledger, settlement):
    folder, generation = run/record['case'], record['generation']
    read = lambda name: (folder/name).read_text()
    log = read('vpp.log')
    need(record['capacity'] == 4160 and record['trace_limit'] == 256 and 'experiment' not in read('startup.conf') and
         'product-flow-expiry { trace-all }' in read('startup.conf'), 'large production configuration/sample scope')
    need('SIGABRT' not in log and 'infrastructure_failure' not in log, 'large runtime failure')
    base.fd_lifecycle(read, generation)
    wires, excluded = wire(read, record)
    client, requests, by_tuple = endpoint_requests(run, record, read)
    target_endpoints(run, record, wires, client)
    original, native_original = snapshot(read('seeded.txt'), record, wires, by_tuple, ref)
    need(len(original) == 8200 and Counter(key[0] for key in original) == {0: 4100, 1: 4100}, 'complete large original population')
    after, native_after = snapshot(read('refreshed.txt'), record, wires, by_tuple, ref, original)
    completed, native_completed = snapshot(read('completed.txt'), record, wires, by_tuple, ref, original)
    stopped, _ = snapshot(read('closed.txt'), record, wires, by_tuple, ref, original)
    need(not stopped and len(completed) == 4, 'large stop residue or missing held TCP')
    replacements = {key: s for key, s in after.items() if key not in original}
    replacements.update(completed)
    need(len(replacements) == 12, 'complete actual replacement snapshot')
    active, closed, logical, batches = heap(log, original, replacements, generation)
    need(active == completed, 'large heap and final retained state differ')
    released = release_ledger(log, closed, logical, generation)
    need(released['latency']['max_ms'] <= 5600, 'bounded large backlog release latency')
    native_entries = dict(native_original)
    native_entries.update({key: e for key, e in native_after.items() if key not in original})
    native_entries.update(native_completed)
    base.udp.PORT = PORT  # Reuse the protocol-neutral S227 sample ledger at this test port.
    samples = base.udp.packet_ledger(log, generation, native_entries, requests,
        rows(read('completed.txt'), 'root.lane '), base.owner_oracle)
    samples['bulk_udp_packets'] = samples.pop('captured')
    routing = {lane: dict(packets=0, remote=0) for lane in range(4)}
    ports = [e['port'] for e in record['udp']]; middle = (min(ports)+max(ports))//2
    manifest = {(e['family'], e['port']): e for e in record['udp']}
    for e in requests:
        family, port = int(e['family']), int(e['port'])
        lane = (family == 6)*2+(port > middle); owner = manifest[(family, port)]['owner']
        routing[lane]['packets'] += 2; routing[lane]['remote'] += 2*(owner != lane % 2)
    for flow in record['flows']:
        key = flow['family'], flow['protocol'], flow['value']
        placement = flow['placement'] if flow['protocol'] == 6 else next(f['placement'] for f in record['flows'] if f['family'] == flow['family'] and f['protocol'] != 6)
        lane = (flow['family'] == 6)*2+placement
        routing[lane]['packets'] += len(wires[key]); routing[lane]['remote'] += len(wires[key])*(flow['owner'] != placement)
    settlement(read, log, generation, {}, {}, closed, active, platform, folder, routing=routing)
    for text in (read('seeded.txt'), read('completed.txt'), read('closed.txt')):
        runtime = rows(text, 'flow.runtime ')
        need(len(runtime) == 2 and all(e['capacity'] == '4160' and e['entry_bytes'] == '232' and e['capacity_misses'] == '0' for e in runtime), 'one shared large capacity')
        need(all(e['capacity_drops'] == e['wrong_owner'] == e['early_drops'] == '0' for e in rows(text, 'flow.pool ')), 'large allocation/owner failure')
    need(all(e['logical_expired'] == '6' for e in rows(read('closed.txt'), 'expiry.owner=')), 'large logical counters')
    return dict(case=record['case'], generation=generation, instances=8212, logical=12, administrative=4,
        actual_packets=sum(e['packets'] for e in routing.values()), target_wire_packets=sum(map(len, wires.values())),
        explicitly_uncaptured_tcp_packets=excluded, native_packet_samples=samples, batches=len(batches), **released)
