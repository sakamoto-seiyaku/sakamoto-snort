#!/usr/bin/env python3
"""Independent wire/tracker replay and one shared mixed-protocol heap ledger."""
import argparse
from collections import Counter, defaultdict
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s236_default_verifier', ROOT/'tests/device/verify-s236-protocol-expiry.py')
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
need, rows, digest, identity = base.need, base.rows, base.digest, base.identity
CASES = ['mixed-batch', 'mixed-renew', 'mixed-lookup']


def protocol(s):
    value = s['assignment']['key_protocol']
    return 'tcp' if value == 6 else 'udp' if value == 17 else 'icmp'


def heap_ledger(log, versions, generation):
    active, closed, logical, batches = {}, {}, {}, []
    previous, budgets = {}, {0: 0, 1: 0}
    expected_new = set()
    for line in log.splitlines():
        if line.startswith(('s222 event=tcp_update ', 's223 event=udp_update ', 's224 event=icmp_update ')):
            e = rows(line, line.split()[0])[0]
            key = identity(e)
            need(key not in closed, 'tracker reused an expired incarnation')
            packets = int(e['orig_packets'])+int(e['reply_packets'])
            state = versions[(key, packets)]
            need((key not in active) == (e['created'] == '1'), 'heap update/create membership')
            active[key] = state
            expected_new.discard(key)
            continue
        if not line.startswith('s227 event='): continue
        e = rows(line, 's227 ')[0]
        if e['event'] not in ('batch', 'logical_expiry'): continue
        owner = int(e['owner'])
        need(owner in (0, 1) and int(e['thread']) == owner+1 and int(e['generation']) == generation, 'heap owner/generation')
        if e['event'] == 'logical_expiry':
            old = owner, int(e['old_slot']), int(e['old_incarnation'])
            new = owner, int(e['new_slot']), int(e['new_incarnation'])
            need(old in active and old not in closed and new not in active and new not in closed
                 and e['created'] == '1' and new != old, 'logical lookup not a live physical expired instance')
            s = active.pop(old)
            need(s['deadline_us'] == int(e['old_deadline_us']) <= int(e['now_us']), 'logical lookup before actual deadline')
            closed[old] = s; logical[old] = dict(e, replacement=new)
            expected_new.add(new)
            continue
        now, count = int(e['now_us']), int(e['closed'])
        need(1 <= count <= 100 and (owner not in previous or now-previous[owner] >= 100000), '100 END / 100ms bound')
        candidates = sorted((key for key in active if key[0] == owner), key=lambda key: (active[key]['deadline_us'], key[1]))
        need(len(candidates) >= count and active[candidates[0]]['deadline_us'] == int(e['oldest_us']), 'shared heap minimum')
        selected = candidates[:count]
        kinds = set()
        for key in selected:
            s = active.pop(key)
            need(s['deadline_us'] <= now and key not in closed, 'early or duplicate batch expiry')
            kinds.add(protocol(s)); closed[key] = s
        deadlines = [s['deadline_us'] for key, s in active.items() if key[0] == owner]
        minimum = min(deadlines, default=base.MAX_U64)
        due = minimum != base.MAX_U64 and minimum <= now
        if count == 100 and due: budgets[owner] += 1
        need(int(e['timers']) == len(deadlines) and int(e['next_us']) == minimum and
             int(e['due_backlog']) == due and int(e['budget_exhausted']) == budgets[owner], 'heap accounting/backlog/budget')
        previous[owner] = now
        batches.append(dict(owner=owner, count=count, protocols=sorted(kinds), now_us=now))
    need(not expected_new, 'logical expiry did not create its promised instance')
    return active, closed, logical, batches


def release_ledger(log, closed, logical, generation):
    events = rows(log, 's227 event=release ')
    need(len(events) == len(closed) and {identity(e) for e in events} == closed.keys(), 'unique complete release callback set')
    latency = []
    for e in events:
        key = identity(e); s = closed[key]
        need(int(e['generation']) == generation and int(e['thread']) == key[0]+1 and
             int(e['deadline_us']) == s['deadline_us'] and int(e['timeout']) == s['timeout'] and
             int(e['packets']) == sum(s['packets']) and e['linked'] == '0' and
             int(e['heap_position']) == base.NO_SLOT, 'release callback retained wrong state/deadline')
        elapsed = int(e['release_us'])-s['deadline_us']
        need(elapsed >= 0, 'release before actual deadline')
        if key in logical: need(int(e['release_us']) >= int(logical[key]['now_us']), 'logical release before lookup')
        latency.append(elapsed/1000)
    ends = defaultdict(list)
    for e in rows(log, 's225 '):
        if e.get('event') != 'consumer_packet': ends[identity(e)].append(e)
    expected = sum(min(256, sum(key[0] == owner for key in closed)) for owner in (0, 1))
    need(len(ends) == expected, 'explicit END graph sample bound')
    for key, events in ends.items():
        need(key in closed and [e['event'] for e in events] ==
             ['unlink_allocate', 'consumer_end', 'terminal_end', 'free_callback'], 'END graph/free uniqueness/order')
        need(len({e['buffer'] for e in events}) == 1 and events[0]['node'] == events[1]['node'], 'shared END carrier/consumer')
        s = closed[key]
        expected = dict(protocol=s['assignment']['key_protocol'], hash=s['assignment']['hash'],
            orig_packets=s['packets'][0], reply_packets=s['packets'][1], orig_bytes=s['bytes'][0],
            reply_bytes=s['bytes'][1], first_seen=s['first'], last_seen=s['last'])
        for e in events:
            need(int(e['generation']) == generation and int(e['thread']) == key[0]+1 and e['reason'] == '2'
                 and e['allocated'] == '1' and e['linked'] == e['length'] == e['obligation'] == '0', 'END ownership/lifetime/obligation')
            need(all(int(e[k]) == value for k, value in expected.items()), 'END retained protocol state')
    return dict(releases=len(closed), end_graph_samples=len(ends), latency=base.udp.quantiles(latency))


def settlement(read, log, generation, packets, captures, expired, retained, platform, folder, routing=None):
    before, after = read('completed.txt'), read('closed.txt')
    lanes = rows(before, 'root.lane ')
    placements = base.packet_ledger(log, generation, packets, captures, lanes) if routing is None else []
    total = len(packets) if routing is None else sum(e['packets'] for e in routing.values())
    for text, stopped in ((before, False), (after, True)):
        for e in rows(text, 'root.lane '):
            n = sum(int(cap['lane']) == int(e['lane']) for cap in captures.values()) if routing is None else routing[int(e['lane'])]['packets']
            need(all(int(e[k]) == n for k in ('captured', 'submitted', 'verdicts', 'succeeded', 'returns'))
                 and e['pending'] == e['failed'] == e['duplicate'] == '0', 'all captured packets traversed Product exactly once')
            if stopped: need(e['fd'] == '-1' and e['ready'] == '0', 'NFQUEUE descriptor residue')
        c = rows(text, 'completion.status ')
        need(len(c) == 1 and all(c[0][k] == '0' for k in ('pending', 'frames', 'buffers', 'obligations', 'duplicate', 'stale')), 'completion residue')
        for e in rows(text, 'flow-end.owner='):
            owner = int(e['flow-end.owner'])
            closed = sum(key[0] == owner for key in expired)
            admin = sum(key[0] == owner for key in retained) if stopped else 0
            active = 0 if stopped else sum(key[0] == owner for key in retained)
            need(all(int(e[k]) == closed for k in ('allocated', 'consumers', 'terminals', 'released')) and
                 int(e['pool_releases']) == closed+admin and int(e['administrative_releases']) == admin and
                 int(e['active_entries']) == int(e['linked']) == active and e['ending'] == e['early_frees'] == '0', 'END/pool/administrative conservation')
        need('flow-end.buffers=0' in text, 'END buffer residue')
        need(base.udp.pool(text)['used'] == (0 if stopped else 288), 'native buffer residue')
        for e in rows(text, 'expiry.owner='):
            owner = int(e['expiry.owner'])
            need(int(e['timers']) == (0 if stopped else sum(key[0] == owner for key in retained)) and
                 int(e['released']) == sum(key[0] == owner for key in expired), 'shared expiry counters')
            if stopped: need(e['timer_fd'] == '-1' and int(e['timer_file']) == base.NO_SLOT and e['mode'] == '0', 'timer attachment residue')
    zero = rows(log, 's242 event=stop_native_zero ')
    need(len(zero) == 1 and int(zero[0]['generation']) == generation and all(zero[0][k] == '0' for k in
        ('ready_mask', 'graph_enabled', 'graph_accepting', 'pending', 'buffers', 'obligations', 'handoffs', 'completion_frames')), 'orderly native stop absent')
    remote = sum(packets[token]['assigned']['owner'] != int(cap['lane']) % 2 for token, cap in captures.items()) if routing is None else sum(e['remote'] for e in routing.values())
    p = rows(after, 'primary.status ')
    need(len(p) == 1 and int(p[0]['owner_checks']) == (total if routing is None else 256) and
         int(p[0]['published']) == int(p[0]['received']) == int(p[0]['returns']) == remote and
         p[0]['credit0'] == p[0]['credit1'] == '32' and all(p[0][k] == '0' for k in
         ('rejected', 'owner_failures', 'pending_returns', 'handoff_debt', 'flows')), 'owner handoff credit/debt')
    c = rows(after, 'completion.status ')[0]
    need(int(c['verdicts']) == total and int(c['remote']) == remote and int(c['local']) == total-remote, 'completion route counters')
    need(not base.udp.timer_fds(read('closed-fds.txt')), 'timer FD survived stop')
    base.native.queue_state(folder, 'closed', platform, set())
    for owner in (0, 1): base.udp.fdinfo(read('closed-fdinfo-'+str(owner)+'.txt'), False) if (folder/('closed-fdinfo-'+str(owner)+'.txt')).exists() else None
    return placements


def endpoints(run, record, packets, read):
    client = read('client-closed.txt')
    need(client == read('client-final.txt') and record['client_closed'], 'endpoint sent after final capture')
    prepared = rows(client, 'prepared ')
    need(len(prepared) == 1 and prepared[0]['mode'] == record['case'].removeprefix('mixed-') and
         int(prepared[0]['udp']) == len(record['udp']) and int(prepared[0]['mixed']) == len(record['flows']), 'independent prepared population')
    stages = rows(client, 'mixed_stage ')
    need([e['phase'] for e in stages] == (['0'] if record['case'] == 'mixed-batch' else ['0', '1']) and
         len(rows(client, 'holding ')) == 1, 'real endpoint stage/quiet sequence')
    if len(stages) == 2:
        need(int(stages[1]['mono_ns'])-int(stages[0]['mono_ns']) >=
             (30001000000 if record['case'] == 'mixed-lookup' else 10000000000), 'real scheduled stimulus duration')
    requests = [e for e in rows(client, 'endpoint ') if 'port' in e]
    need(len({e['nonce'] for e in requests}) == len(requests), 'duplicate UDP endpoint receipt')
    wanted_udp = len(record['udp']) + (8 if record['case'] == 'mixed-lookup' else len(record['udp']) if record['case'] == 'mixed-renew' else 0)
    need(len(requests) == wanted_udp, 'UDP endpoint request count')
    servers = Counter((int(e['family']), e['nonce']) for family in (4, 6)
        for e in rows((run/f's236-udp-{family}.log').read_text(), 'received '))
    for e in requests:
        payload = ('E'+e['nonce']).encode()
        selected = [p for p in packets.values() if p['protocol'] == 17 and p['family'] == int(e['family']) and p['payload'] == payload]
        need(len(selected) == 2 and e['echo'] == '1' and int(e['received_ns']) > int(e['sent_ns']) > 0 and
             servers[(int(e['family']), e['nonce'])] == 1, 'UDP wire/kernel/server nonce conservation')
    phases = 1 if record['case'] == 'mixed-batch' else 2
    for flow in record['flows']:
        nonce = f'{record["nonce"]}-p{flow["protocol"]}-f{flow["family"]}-v{flow["value"]}'
        selected = [p for p in packets.values() if p['family'] == flow['family'] and p['protocol'] == flow['protocol'] and
            (flow['value'] in (p['sport'], p['dport']) if flow['protocol'] == 6 else p['identifier'] == flow['value'])]
        need(selected and all(p['assigned']['owner'] == flow['owner'] for p in selected), 'mixed family/owner tuple missing')
        if flow['protocol'] == 6:
            connected = [e for e in rows(client, 'tcp_connected ') if e['nonce'] == nonce]
            receipts = [e for e in rows(client, 'received ') if e['nonce'] == nonce]
            need(len(connected) == 1 and connected[0]['keepalive'] == '0' and len(receipts) == phases, 'real retained/reset TCP socket')
            server = rows((run/f's236-tcp-{flow["family"]}-close.log').read_text(), 'echo ')
            for phase in range(phases):
                payload = (nonce+':'+str(phase)).encode()
                need(sum(e['data'] == payload.hex() for e in server) == 1, 'independent TCP server nonce')
                if record['case'] != 'mixed-lookup' or phase:
                    need(sum(p['payload'] == payload for p in selected) == 2, 'TCP captured request/reply nonce')
        else:
            receipts = [e for e in rows(client, 'endpoint ') if 'identifier' in e and
                        int(e['identifier']) == flow['value'] and int(e['family']) == flow['family']]
            need(len(receipts) == phases and all(int(e['reply_ns']) > int(e['sent_ns']) > 0 for e in receipts), 'actual kernel ICMP replies')
            server = rows((run/f's224-icmp-{flow["family"]}.log').read_text(), 'received ')
            for phase in range(phases):
                payload = (nonce+'-'+str(phase)+'-0').encode()
                need(sum(p['payload'] == payload for p in selected) == 2 and
                     sum(bytes.fromhex(e['raw'])[8:] == payload and e['checksum_valid'] == '1' for e in server) == 1,
                     'ICMP wire/kernel/server nonce/checksum')


def case(run, record, platform, ref):
    name, generation = record['case'], record['generation']
    need(name in CASES and record['process_closed'] and record['clients_closed'], 'mixed identity/cleanup')
    if name == 'mixed-lookup' and record.get('trace_limit') == 256:
        spec = importlib.util.spec_from_file_location('s236_large_lookup', ROOT/'tests/device/verify-s236-mixed-lookup.py')
        large = importlib.util.module_from_spec(spec); spec.loader.exec_module(large)
        return large.verify_lookup(run, record, platform, ref, release_ledger, settlement)
    folder = run/name; read = lambda filename: (folder/filename).read_text()
    config, log = read('startup.conf'), read('vpp.log')
    base.fd_lifecycle(read, generation)
    need('experiment' not in config and 'product-flow-expiry { trace-all }' in config, 'default shared expiry configuration')
    need('SIGABRT' not in log and 'infrastructure_failure' not in log, 'runtime failure')
    states, versions, packets, captures = base.replay(log, generation, ref)
    seeded = base.snapshot(read('seeded.txt'), versions, generation, record['count_per_owner']*2)
    refreshed = base.snapshot(read('refreshed.txt'), versions, generation) if name != 'mixed-batch' else seeded
    completed = base.snapshot(read('completed.txt'), versions, generation, 0 if name == 'mixed-batch' else 4)
    base.snapshot(read('closed.txt'), versions, generation, 0)
    active, closed, logical, batches = heap_ledger(log, versions, generation)
    need(active.keys() == completed.keys() and all(protocol(s) == 'tcp' and s['timeout'] == 6 for s in active.values()), 'remaining actual established TCP set')
    if name == 'mixed-batch':
        need(len(closed) == 48 and not logical and {e['owner'] for e in batches if e['protocols'] == ['icmp', 'tcp', 'udp']} == {0, 1},
             'three protocols did not share a real batch on both owners')
    elif name == 'mixed-renew':
        need(not logical and seeded.keys() == refreshed.keys() and all(refreshed[k]['deadline_us'] > seeded[k]['deadline_us']
             for k in seeded), 'mixed same-instance renewal did not advance all deadlines')
        need(Counter(states[k]['assignment']['key_protocol'] for k in seeded) == {6: 4, 17: 4, 1: 2, 58: 2}, 'renew protocol population')
    else:
        coverage = {(key[0], s['assignment']['key_family'], protocol(s)) for key, s in closed.items() if key in logical}
        need(len(logical) == 12 and coverage == {(o, f, p) for o in (0, 1) for f in (4, 6) for p in ('tcp', 'udp', 'icmp')},
             'all twelve real expired-lookup cells required')
        for key, e in logical.items():
            new = e['replacement']
            need(new in states and closed[key]['tuple'] == states[new]['tuple'] and
                 states[new]['first'] == int(e['now_us']), 'logical replacement tuple/actual observation time')
    for text in (read('seeded.txt'), read('completed.txt'), read('closed.txt')):
        runtime = rows(text, 'flow.runtime ')
        need(len(runtime) == 2 and all(int(e['capacity']) == record['capacity'] and e['entry_bytes'] == '232' and
             e['capacity_misses'] == '0' for e in runtime), 'one shared owner capacity, no per-protocol pool')
        need(all(e['capacity_drops'] == e['wrong_owner'] == e['early_drops'] == '0' for e in rows(text, 'flow.pool ')), 'runtime admission/owner failures')
    released = release_ledger(log, closed, logical, generation)
    need(released['latency']['p99_ms'] <= 1100 and released['latency']['max_ms'] <= 1500, 'normal mixed release latency gate')
    placements = settlement(read, log, generation, packets, captures, closed, active, platform, folder)
    endpoints(run, record, packets, read)
    return dict(case=name, generation=generation, packets=len(packets), instances=len(states), logical=len(logical),
                administrative=len(active), batches=len(batches), placements=placements, **released)


def verify(run, ovs, selected=None):
    run = Path(run).resolve(); result = json.loads((run/'result.json').read_text())
    base.authority(run, result)
    need([e['case'] for e in result['generations']] == result['requested_cases'], 'mixed case manifest completeness')
    selected = result['requested_cases'] if selected is None else selected
    need(selected and set(selected) <= set(result['requested_cases']), 'requested mixed subset absent')
    ref = base.TcpOracle(ovs)
    try: values = [case(run, r, result['platform'], ref) for r in result['generations'] if r['case'] in selected]
    finally: ref.close()
    return dict(status='VALID_PARTIAL', scope='mixed-protocol-expiry-not-full-S236', platform=result['platform'], cases=values,
        source_sha256=result['source_sha256'], result_sha256=digest(run/'result.json'), verifier_sha256=digest(__file__),
        verifier_files=base.verifier_closure(), ovs_tcp_sha256=digest(Path(ovs)/'lib/conntrack-tcp.c'),
        ovs_timeout_sha256=digest(Path(ovs)/'lib/conntrack-tp.c'),
        unverified_cases=[name for name in result['requested_cases'] if name not in selected])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', type=Path, required=True); parser.add_argument('--ovs', type=Path, required=True)
    parser.add_argument('--output', type=Path); parser.add_argument('--cases')
    args = parser.parse_args()
    try: answer = verify(args.run, args.ovs, args.cases.split(',') if args.cases else None)
    except (AssertionError, KeyError, ValueError, OSError, subprocess.SubprocessError) as error:
        answer = dict(status='HOLD', error=repr(error))
    if args.output: args.output.write_text(json.dumps(answer, indent=2)+'\n')
    print(json.dumps(answer, indent=2))
    if answer['status'] == 'HOLD': raise SystemExit(1)
