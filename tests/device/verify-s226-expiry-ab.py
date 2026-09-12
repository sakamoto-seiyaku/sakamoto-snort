#!/usr/bin/env python3
"""Independent semantic verifier for the fixed S226 real-endpoint campaign."""
import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
REGISTRATION = 'docs/testing/2026-09-12_S226_EXPIRY_AB.md'
REGISTRATIONS = (REGISTRATION, 'docs/testing/2026-09-12_S226_EXPIRY_AB_REGISTRATION.md')
REGISTERED_SHA256 = '8231814b508fd7b5f082d3e2df2b25c6acae6fe1a61de4315fa9ad30a005e29a'
MAX_U64 = 2**64-1
COUNTS = {'empty': 0, 'long': 2, 'bulk100': 100, 'bulk1000': 1000,
          'maximum': 4096, 'screen-off': 2, 'forced-doze': 2}
DURATIONS = {'empty': 60, 'long': 45, 'bulk100': 40, 'bulk1000': 40,
             'maximum': 45, 'screen-off': 65, 'forced-doze': 65}
CPU_RAILS = {'S2M_VDD_CPUCL2', 'S3M_VDD_CPUCL1', 'S4M_VDD_CPUCL0'}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def records(text, prefix):
    return [dict(p.split('=', 1) for p in line.split() if '=' in p)
            for line in text.splitlines() if line.startswith(prefix)]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def monitor(text, pid, seconds, pixel):
    samples = {}
    for match in re.finditer(r'^S226_SAMPLE (begin|end) (.*?)\n(.*?)^S226_END_SAMPLE$', text, re.M | re.S):
        label, metadata, body = match.groups()
        require(label not in samples, 'duplicate interval endpoint')
        meta = {key: int(value) for key, value in (part.split('=') for part in metadata.split())}
        files = {m[0]: m[1] for m in re.findall(r'^S226_FILE (\S+)\n(.*?)^S226_END_FILE$', body, re.M | re.S)}
        samples[label] = dict(meta=meta, files=files)
    require(set(samples) == {'begin', 'end'}, 'missing interval endpoints')
    before, after = samples['begin'], samples['end']
    elapsed = (after['meta']['monotonic_ns']-before['meta']['monotonic_ns'])/1e9
    require(seconds <= elapsed <= seconds+2, 'interval duration differs from registration')
    require(before['meta']['ticks'] == after['meta']['ticks'] > 0, 'clock tick identity')
    ticks = before['meta']['ticks']
    suspend = (after['meta']['boottime_ns']-before['meta']['boottime_ns'])/1e9-elapsed
    require(suspend >= -.001, 'inconsistent clock domains')

    def stat(value):
        fields = value.rsplit(') ', 1)[1].split()
        return int(fields[11])+int(fields[12]), int(fields[19])

    def cpu(path):
        start_ticks, start_identity = stat(before['files'][path])
        end_ticks, end_identity = stat(after['files'][path])
        require(start_identity == end_identity and end_ticks >= start_ticks, 'process/TID reused or CPU counter regressed')
        return (end_ticks-start_ticks)/ticks/elapsed*100

    total_cpu = cpu(f'/proc/{pid}/stat')
    worker_cpu, voluntary, nonvoluntary, affinities = {}, {}, {}, {}
    for path, value in before['files'].items():
        if not re.fullmatch(r'/proc/\d+/task/\d+/status', path): continue
        name = re.search(r'^Name:\s+(\S+)', value, re.M)[1]
        if name not in ('vpp_wk_0', 'vpp_wk_1', 'vpp_main'): continue
        final = after['files'][path]
        affinity = re.search(r'^Cpus_allowed_list:\s+(\S+)', value, re.M)[1]
        require(re.search(r'^Cpus_allowed_list:\s+(\S+)', final, re.M)[1] == affinity, 'thread affinity changed')
        affinities[name] = affinity
        if name == 'vpp_main': continue
        worker_cpu[name] = cpu(path.removesuffix('status')+'stat')
        for key, output in (('voluntary_ctxt_switches', voluntary), ('nonvoluntary_ctxt_switches', nonvoluntary)):
            start = int(re.search(r'^'+key+r':\s+(\d+)', value, re.M)[1])
            end = int(re.search(r'^'+key+r':\s+(\d+)', final, re.M)[1])
            require(end >= start, 'context counter regressed')
            output[name] = (end-start)/elapsed
    require(set(worker_cpu) == {'vpp_wk_0', 'vpp_wk_1'}, 'missing actual owner TIDs')
    if pixel:
        require(affinities == {'vpp_main': '0', 'vpp_wk_0': '1', 'vpp_wk_1': '2'}, 'Pixel affinity differs from registration')
    memory, high_water = [], []
    for sample in (before, after):
        status = sample['files'][f'/proc/{pid}/status']
        memory.append(int(re.search(r'^VmRSS:\s+(\d+) kB', status, re.M)[1]))
        high_water.append(int(re.search(r'^VmHWM:\s+(\d+) kB', status, re.M)[1]))
    require(max(memory+high_water) < 256*1024, 'registered RSS bound')
    result = dict(elapsed_s=elapsed, suspend_s=max(0, suspend), process_cpu_percent=total_cpu,
        worker_cpu_percent=worker_cpu, worker_total_cpu_percent=sum(worker_cpu.values()),
        voluntary_per_second=voluntary, voluntary_total_per_second=sum(voluntary.values()),
        nonvoluntary_per_second=nonvoluntary, affinity=affinities, rss_kib=memory, rss_high_water_kib=high_water)
    if pixel:
        def rails(value):
            timestamp = int(re.search(r'^t=(\d+)', value, re.M)[1])
            channels = {m[1]: (int(m[0]), int(m[2])) for m in
                re.findall(r'^CH\d+\(T=(\d+)\)\[([^]]+)\], (\d+)$', value, re.M)}
            return timestamp, channels
        def powers_for(device):
            first, second = [rails(s['files'][f'/sys/bus/iio/devices/iio:device{device}/energy_value']) for s in (before, after)]
            require(first[1].keys() == second[1].keys() and bool(first[1]), 'energy rail identity')
            if device == 0: require(CPU_RAILS <= first[1].keys(), 'missing CPU rail')
            interval_ms = second[0]-first[0]
            require(abs(interval_ms-elapsed*1000) <= 200, 'energy timestamps disagree with interval')
            powers = {}
            for name in first[1]:
                duration, energy = first[1][name]
                final_duration, final_energy = second[1][name]
                require(final_duration-duration == interval_ms and final_energy >= energy, 'energy reset/regression')
                powers[name] = (final_energy-energy)/interval_ms
            return powers
        powers, secondary = powers_for(0), powers_for(1)
        temperatures, supplies, statuses = [], [], []
        for sample in (before, after):
            files = sample['files']
            temperatures.append(int(files['/sys/class/power_supply/battery/temp'].strip())/10)
            supplies.append(files['/sys/class/power_supply/usb/online'].strip())
            statuses.append(files['/sys/class/power_supply/battery/status'].strip())
        result.update(cpu_rails_mw=sum(powers[name] for name in CPU_RAILS), rails_mw=powers, secondary_rails_mw=secondary,
                      temperature_c=temperatures, usb_online=supplies, battery_status=statuses)
    return result


def pool(text):
    values = re.findall(r'^default-numa-\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$', text, re.M)
    require(len(values) == 1, 'one NUMA native pool required')
    result = dict(zip(('index', 'numa', 'size', 'data', 'total', 'available', 'cached', 'used'), map(int, values[0])))
    require(result['total'] == result['available']+result['cached']+result['used'], 'native pool conservation')
    return result


def timer_fds(text):
    # The registered Pixel kernel names timerfd anonymous inodes; Linux's
    # unnamed form describes the same FD type. Match symlink targets, not
    # arbitrary filenames containing the word timerfd.
    rows = re.findall(r'\b(\d+)\s+->\s+(anon_inode:\[timerfd(?:\d+:[^\]\r\n]+)?\])\r?$', text, re.M)
    require(len(re.findall(r'\b\d+\s+->\s+anon_inode:\[timerfd', text)) == len(rows),
            'unrecognized timer fd listing')
    require(len({int(fd) for fd, _ in rows}) == len(rows), 'duplicate timer fd listing')
    return {int(fd): target for fd, target in rows}


def packet_ledger(log, generation, entries, count, echo, oracle, nonce):
    capture = records(log, 's231 event=nfq_payload ')
    consume = records(log, 's204 event=completion_consume ')
    verdicts = records(log, 's242 event=verdict_syscall ')
    returned = records(log, 's203 event=buffer_free ')
    identity = lambda e: (e['lane'], e['packet'], e['token'])
    require(len({identity(e) for e in capture}) == len(capture), 'duplicate captured identity')
    # Capture is capped at 64 per lane, whereas graph tracing is capped at
    # 256 admitted packets globally. Validate each complete ledger subset;
    # do not assume these independently bounded samples contain equal IDs.
    captured = {identity(e): e for e in capture}
    require(len(capture) <= 256 and (bool(capture) == bool(count)), 'bounded capture sample')
    require(len(consume) <= 256 and (bool(consume) == bool(count)), 'bounded completion sample')
    require(len(set(map(identity, consume))) == len(consume), 'duplicate completion identity')
    require(len(set(map(identity, verdicts))) == len(verdicts), 'duplicate syscall identity')
    require(len(consume) == min(count*2*(1+echo), 256), 'incomplete bounded graph sample')
    require(Counter((e['thread'], e['buffer'], e['token']) for e in consume) ==
            Counter((e['thread'], e['buffer'], e['obligation']) for e in returned), 'sample packet buffer return')
    calls = {identity(e): e for e in verdicts}
    origin_verdicts = records(log, 's203 event=verdict ')
    origin_ids = {(e['lane'], e['packet'], e['obligation']) for e in origin_verdicts}
    require(len(origin_ids) == len(origin_verdicts), 'duplicate origin verdict sample')
    require(set(calls) == origin_ids | {identity(e) for e in consume}, 'native syscall missing its traced completion/origin identity')
    for e in verdicts:
        require(e['source'] == 'NFQ_CAPTURED' and int(e['generation']) == generation
                and int(e['result']) > 0 and e['errno'] == '0' and e['verdict'] == '1', 'sample verdict syscall failure')
        require(int(e['queue']) == 176+int(e['lane']) and int(e['thread']) == int(e['lane'])%2+1, 'verdict origin lane/thread')
    for e in consume:
        require(e['source'] == 'NFQ_CAPTURED' and int(e['generation']) == generation
                and int(e['thread']) == int(e['lane'])%2+1 and e['intent'] == '1', 'completion original lane/generation/intent')
    overlap = set(captured) & {identity(e) for e in consume} & set(calls)
    require(bool(overlap) == bool(count), 'no complete NFQUEUE identity sample')
    parser = load_module('s226_packet_parser', ROOT/'tests/device/verify-s242-root-lifecycle.py')
    for e in capture:
        require(e['source'] == 'NFQ_CAPTURED' and int(e['generation']) == generation, 'capture source/generation')
        decoded = parser.packet(e['raw'])
        port = decoded['sport'] if decoded['dport'] == 40626 else decoded['dport']
        require(decoded['protocol'] == 17 and 40626 in (decoded['sport'], decoded['dport'])
                and decoded['payload'] == (('E' if echo else 'S')+f'{nonce}-{decoded["family"]}-{port}').encode(), 'captured endpoint payload')
    admitted = records(log, 's216 stage=admit ')
    consumers = records(log, 's225 event=consumer_packet ')
    require(Counter(e['token'] for e in admitted) == Counter(e['token'] for e in consumers), 'ordinary shared consumer missing')
    require(Counter(e['token'] for e in admitted) == Counter(e['token'] for e in consume), 'admission/completion sample mismatch')
    consumer_by_token = {e['token']: e for e in consumers}
    for e in admitted:
        facts = {k: e[k] if k in ('src', 'dst') else int(e[k]) for k in
                 ('l3', 'l4', 'family', 'protocol', 'src', 'dst', 'src_port', 'dst_port', 'icmp_known')}
        assigned = oracle.assignment(facts)
        c = consumer_by_token[e['token']]
        require(int(e['owner']) == int(c['owner']) == assigned['owner']
                and int(c['thread']) == assigned['owner']+1 and int(c['generation']) == generation
                and c['buffer'] == e['buffer'] and c['is_flow_end'] == '0', 'packet owner/carrier sample mismatch')
    ends = defaultdict(list)
    for line in log.splitlines():
        if not line.startswith('s225 '): continue
        e = dict(re.findall(r'(\w+)=([^\s]+)', line))
        if e.get('event') in ('unlink_allocate', 'consumer_end', 'terminal_end', 'free_callback', 'consumer_early_free'):
            ends[(int(e['owner']), int(e['slot']), int(e['incarnation']))].append(e)
    require(len(ends) == 2*min(count, 256), 'END graph sample count')
    consumer_nodes = {e['node'] for e in consumers}
    for key, events in ends.items():
        require(key in entries and [e['event'] for e in events] ==
                ['unlink_allocate', 'consumer_end', 'terminal_end', 'free_callback'], 'END graph/free sequence')
        old = entries[key]
        require(len({e['buffer'] for e in events}) == 1, 'END carrier copied')
        require(events[0]['node'] == events[1]['node'] and events[0]['node'] in consumer_nodes, 'END shared consumer node')
        for e in events:
            require(int(e['generation']) == generation and int(e['thread']) == key[0]+1
                    and e['reason'] == '2' and e['allocated'] == '1'
                    and e['linked'] == e['length'] == e['obligation'] == '0', 'END ownership/reason/carrier')
            for field in ('hash', 'protocol', 'orig_packets', 'reply_packets', 'orig_bytes', 'reply_bytes', 'first_seen', 'last_seen'):
                require(e[field] == old[field], 'END retained snapshot '+field)
    return dict(capture_samples=len(capture), completion_samples=len(consume), origin_verdict_samples=len(origin_verdicts),
                syscall_samples=len(verdicts),
                complete_identity_samples=len(overlap), end_graph_samples=len(ends))


def environment(run, record, interval):
    errors, endpoints = [], []
    label, name = record['label'], record['case']
    for point in ('before', 'after'):
        read = lambda kind: (run/f'{label}-main-{point}-{kind}.txt').read_text()
        battery, thermal, idle, power = map(read, ('battery', 'thermalservice', 'deviceidle', 'power'))
        temperature = int(re.search(r'^\s+temperature:\s+(\d+)', battery, re.M)[1])/10
        thermal_status = int(re.search(r'^Thermal Status:\s+(\d+)', thermal, re.M)[1])
        if thermal_status != 0: errors.append(point+'_thermal')
        if not (25 <= temperature <= 35 if point == 'before' else temperature <= 38): errors.append(point+'_temperature')
        if not ('USB powered: true' in battery and re.search(r'^\s+level: 100$', battery, re.M)
                and re.search(r'^\s+status: 5$', battery, re.M)): errors.append(point+'_supply')
        off = name in ('screen-off', 'forced-doze')
        forced = name == 'forced-doze'
        if f'mScreenOn={str(not off).lower()}' not in idle: errors.append(point+'_screen')
        if f'mForceIdle={str(forced).lower()}' not in idle: errors.append(point+'_force_idle')
        if forced and not re.search(r'\bmState=IDLE\b', idle): errors.append(point+'_not_deep_idle')
        if not off and 'mWakefulness=Awake' not in power: errors.append(point+'_not_awake')
        endpoints.append(dict(temperature_c=temperature, thermal_status=thermal_status,
                              idle_state=re.search(r'\bmState=(\w+)', idle)[1]))
    if interval['usb_online'] != ['1', '1'] or interval['battery_status'] != ['Full', 'Full']:
        errors.append('monitor_supply')
    if not 25 <= interval['temperature_c'][0] <= 35 or interval['temperature_c'][1] > 38:
        errors.append('monitor_temperature')
    # A true suspend needs a resume timestamp, which this endpoint-only run
    # does not supply. Do not silently waive the registered recovery bound.
    if interval['suspend_s'] >= .01: errors.append('suspend_resume_evidence_missing')
    return dict(valid=not errors, errors=errors, endpoints=endpoints)


def case(run, record, pixel, oracle, servers):
    out = run/record['label']
    read = lambda name: (out/name).read_text()
    label, name = record['label'], record['case']
    count, generation = COUNTS[name], record['generation']
    require(record['arm'] in ('poll', 'deadline') and label == f'{name}-{record["repetition"]}-{record["arm"]}', 'arm/label identity')
    echo = name in ('bulk100', 'bulk1000', 'maximum')
    mode = 1 if record['arm'] == 'poll' else 2
    require(record['count_per_owner'] == count and record['process_closed'], label+' count/close')
    seeded, expired, closed, initialized = map(read, ('seeded.txt', 'expired.txt', 'closed.txt', 'initialized.txt'))
    log = read('vpp.log')
    require(not re.search(r'event=(?:infrastructure_failure|fatal_allocation_failure)|Assertion.*failed|clib_panic', log), label+' fatal')
    require('root.stop=ok' in read('stop.txt'), label+' orderly stop missing')
    initial_expiry = records(read('initial.txt'), 'expiry.owner=')
    require(len(initial_expiry) == 2 and all(r['mode'] == '0' and r['timer_fd'] == '-1' for r in initial_expiry), 'experiment was not default-off')
    require(not timer_fds(read('fds-before.txt')), 'default-off timer fd residue')
    require('expiry.experiment=queued' in read('enable.txt'), 'arm not enabled')
    config = read('startup.conf')
    require('product-flow-runtime { entries 4096 }' in config and 'buffers-per-numa' not in config, 'registered capacity/pool configuration')
    if name == 'maximum':
        require(int(re.search(r'^MemAvailable:\s+(\d+) kB', read('maximum-memory.txt'), re.M)[1]) >= 512*1024, 'maximum preparation memory gate')
    timers = records(initialized, 'expiry.owner=')
    require(len(timers) == 2 and all(int(r['generation']) == generation and int(r['mode']) == mode
        and r['initialize'] == '0' and int(r['timers']) == count for r in timers), label+' timer initialization')
    entries = records(seeded, 'flow.entry ')
    require(len(entries) == count*2, label+' seed count')
    selected = json.loads(read('tuples.json'))
    require(len(selected) == count*2, 'tuple count')
    endpoint = records(read('seed-client.txt'), 'seed ')
    require(len(endpoint) == len(entries), label+' missing real endpoint')
    endpoint_by_tuple = {(int(e['family']), int(e['port'])): e for e in endpoint}
    require(len(endpoint_by_tuple) == len(endpoint), 'duplicate endpoint tuple')
    expected_by_tuple = {(e['family'], e['port']): e for e in selected}
    require(endpoint_by_tuple.keys() == expected_by_tuple.keys(), 'endpoint tuple manifest mismatch')
    if count:
        require(record.get('seed_closed') and read('seed-client-final.txt') == read('seed-client.txt'), 'seed helper not silent/closed')
        summaries = records(read('seed-client.txt'), 'seed-summary ')
        require(len(summaries) == 1 and int(summaries[0]['count']) == count*2
                and int(summaries[0]['retained_fds']) == count*2, 'seed setup/send completion')
    instances = {}
    for entry in entries:
        family = int(entry['family'])
        port = int(entry['port_a']) if int(entry['port_b']) == 40626 else int(entry['port_b'])
        expected = expected_by_tuple[(family, port)]
        facts = dict(l3=1, l4=1, family=family, protocol=17, src=entry['key_a'], dst=entry['key_b'],
                     src_port=int(entry['port_a']), dst_port=int(entry['port_b']), icmp_known=0)
        assigned = oracle.assignment(facts)
        require(assigned['owner'] == int(entry['worker']) == expected['owner'], 'independent owner mismatch')
        require(assigned['hash'] == int(entry['hash']) == expected['expected']['hash'], 'full typed identity mismatch')
        require(entry['protocol'] == '17' and entry['kind'] == '2' and int(entry['policy_generation']) == generation, 'wrong seeded protocol/generation')
        require(int(entry['packets']) == 1+echo and entry['orig_packets'] == '1'
                and int(entry['reply_packets']) == echo, 'seed packet accounting')
        endpoint_row = endpoint_by_tuple[(family, port)]
        nonce = f'{record["nonce"]}-{family}-{port}'
        require(endpoint_row['nonce'] == nonce and int(endpoint_row['echo']) == echo, 'endpoint nonce/echo mismatch')
        require((int(endpoint_row['received_ns']) >= int(endpoint_row['sent_ns'])) if echo
                else endpoint_row['received_ns'] == '0', 'endpoint did not witness reply')
        require(servers[(nonce, str(int(echo)))] == 1, 'server did not receive unique real request')
        identity = int(entry['worker']), int(entry['slot']), int(entry['incarnation'])
        require(identity not in instances, 'duplicate seeded incarnation')
        instances[identity] = entry
    require([sum(int(e['worker']) == owner for e in entries) for owner in (0, 1)] == [count, count], 'owner flow counts')
    ledger = packet_ledger(log, generation, instances, count, echo, oracle, record.get('nonce'))
    phases = records(seeded, 'flow.udp ')
    require(len(phases) == len(entries) and all(int(p['phase']) == (3 if echo else 1) for p in phases), 'wrong real UDP phase')
    releases = records(log, 's226 event=release ')
    require(len(releases) == len(entries), label+' missing/extra END release')
    released, latencies, by_owner = set(), [], {0: [], 1: []}
    for release in releases:
        identity = int(release['owner']), int(release['slot']), int(release['incarnation'])
        require(identity in instances and identity not in released, 'stale/duplicate END release')
        released.add(identity)
        entry = instances[identity]
        require(int(release['generation']) == generation and int(release['thread']) == identity[0]+1, 'END worker/generation mismatch')
        deadline = int(entry['last_seen'])+(30000000 if echo else 60000000)
        require(int(release['deadline_us']) == deadline and int(release['timeout']) == (3 if echo else 1), 'not actual pinned timeout')
        require(release['linked'] == '0' and int(release['heap_position']) == 2**32-1
                and int(release['packets']) == 1+echo, 'END snapshot mutated or still indexed')
        latency = int(release['release_us'])-deadline
        require(latency >= 0, 'early release')
        latencies.append(latency/1000)
        by_owner[identity[0]].append(release)
    batch_rows = records(log, 's226 event=batch ')
    owner_results = []
    for owner in (0, 1):
        batches = [b for b in batch_rows if int(b['owner']) == owner]
        deadlines = sorted(int(e['deadline_us']) for e in by_owner[owner])
        consumed, previous = 0, None
        for batch in batches:
            at, batch_count = int(batch['now_us']), int(batch['closed'])
            require(1 <= batch_count <= 100 and int(batch['thread']) == owner+1 and int(batch['generation']) == generation, 'batch budget/owner/generation')
            require(previous is None or at-previous >= 100000, 'sustained self-requeue or changed pacing')
            require(int(batch['oldest_us']) == deadlines[consumed] and deadlines[consumed+batch_count-1] <= at, 'batch did not pop real due minimum')
            consumed += batch_count
            require(int(batch['timers']) == count-consumed, 'batch backlog counter')
            require(int(batch['next_us']) == (deadlines[consumed] if consumed < count else MAX_U64), 'next deadline mismatch')
            previous = at
        require(consumed == count, 'packet-driven or unaccounted expiry')
        if count:
            spread = (max(deadlines)-min(deadlines))/1000
            finish = (max(int(e['release_us']) for e in by_owner[owner])-min(deadlines))/1000
            oldest = max(int(b['now_us'])-int(b['oldest_us']) for b in batches)/1000
            if echo: require(spread <= 1000, 'registered simultaneous deadline spread exceeded')
            if name == 'bulk1000': require(oldest <= 2000 and finish <= 3000, '1000-flow bulk latency gate')
            if name == 'maximum': require(oldest <= 6000 and finish <= 7000, 'maximum bulk latency gate')
            owner_results.append(dict(owner=owner, count=count, spread_ms=spread,
                                      all_released_ms=finish, oldest_overdue_ms=oldest, batches=len(batches)))
    require(not records(expired, 'flow.entry '), 'entry residue before stop')
    for text in (expired, closed):
        end_owners = records(text, 'flow-end.owner=')
        require(len(end_owners) == 2 and 'flow-end.buffers=0' in text, 'END buffer residue')
        for owner in end_owners:
            require(all(int(owner[k]) == count for k in ('allocated', 'consumers', 'terminals', 'released', 'pool_releases')), 'END allocation/consumer/release conservation')
            require(all(owner[k] == '0' for k in ('early_frees', 'active_entries', 'linked', 'ending', 'administrative_releases')), 'substitute admin cleanup or residue')
        require(all(p['entries'] == '0' and p['capacity_drops'] == '0' and p['wrong_owner'] == '0'
                    and p['revision_mismatches'] == '0' for p in records(text, 'flow.pool ')), 'flow capacity/error residue')
        completion = records(text, 'completion.status ')
        require(len(completion) == 1 and all(completion[0][k] == '0' for k in ('pending', 'frames', 'buffers', 'obligations', 'duplicate', 'stale')), 'packet completion residue')
        lanes = records(text, 'root.lane ')
        require(len(lanes) == 4 and sum(int(l['captured']) for l in lanes) == len(entries)*(1+echo), 'real NFQUEUE capture total')
        require(all(l['captured'] == l['submitted'] == l['verdicts'] == l['succeeded']
                    and all(l[k] == '0' for k in ('failed', 'pending', 'duplicate')) for l in lanes), 'NFQUEUE completion conservation')
    expected_sample = sum(min(int(l['captured']), 64) for l in records(expired, 'root.lane '))
    require(ledger['capture_samples'] == expected_sample
            and ledger['origin_verdict_samples'] == expected_sample, 'per-lane bounded trace sample missing')
    native_initial, native_expired, native_closed = map(pool, (read('initial.txt'), expired, closed))
    require(native_initial['total'] == native_expired['total'] == native_closed['total']
            and native_initial['used'] == native_expired['used'] == 288 and native_closed['used'] == 0, 'native buffer residue')
    closed_timers = records(closed, 'expiry.owner=')
    require(len(closed_timers) == 2 and all(e['mode'] == '0' and e['timer_fd'] == '-1'
        and int(e['timer_file']) == 2**32-1 and e['timers'] == '0' for e in closed_timers), 'stale generation timer not detached')
    require(not timer_fds(read('fds-closed.txt')) and 'SAKAMOTO_S226_' not in read('hooks-after.txt'), 'timer fd or private hook residue')
    if pixel:
        queue_rows = read('closed-queues.txt').splitlines()
        require(not any(parts and parts[0] in ('176', '177', '178', '179') for parts in map(str.split, queue_rows)), 'live NFQUEUE after stop')
    else:
        require(set(json.loads(read('closed-queue-bind.json')).values()) == {0}, 'Linux queue binding residue')
    interval = monitor(read('main-monitor.txt'), record['pid'], DURATIONS[name], pixel)
    before, after = [records(read('main-'+point+'.txt'), 'expiry.owner=') for point in ('before', 'after')]
    require([e['expiry.owner'] for e in before] == [e['expiry.owner'] for e in after] == ['0', '1']
            and all(int(e['generation']) == generation and int(e['mode']) == mode for e in before+after), 'interval owner/generation/mode')
    before_lanes, after_lanes = [records(read('main-'+point+'.txt'), 'root.lane ') for point in ('before', 'after')]
    require([l['captured'] for l in before_lanes] == [l['captured'] for l in after_lanes], 'expiry depended on new packet')
    interval['expiry_calls'] = sum(int(a['calls'])-int(b['calls']) for b, a in zip(before, after))
    interval['expiry_wakes'] = sum(int(a['wakes'])-int(b['wakes']) for b, a in zip(before, after))
    interval['expiry_releases'] = sum(int(a['released'])-int(b['released']) for b, a in zip(before, after))
    require(interval['expiry_calls'] >= 0 and interval['expiry_wakes'] >= 0, 'node counter regression')
    idle_failures = []
    if name in ('empty', 'long'):
        require(interval['expiry_wakes'] == 0 and interval['expiry_releases'] == 0, 'idle interval contains expiry')
        if interval['process_cpu_percent'] > 5: idle_failures.append('process_cpu')
        if interval['worker_total_cpu_percent'] > 2: idle_failures.append('worker_cpu')
        if interval['voluntary_total_per_second'] > 20: idle_failures.append('voluntary_switches')
    if mode == 2 and name == 'empty': require(interval['expiry_calls'] == 0, 'empty deadline arm polling')
    if mode == 1: require(interval['expiry_calls'] > 0 and interval['expiry_wakes'] == 0, 'polling arm changed driver')
    backing = timer_fds(read('fds-enabled.txt'))
    require(len(backing) == (4 if mode == 2 else 0), 'actual per-owner timerfd backing')
    if mode == 2:
        owner_fds = {int(row['timer_fd']) for row in timers}
        require(len(owner_fds) == 2 and owner_fds <= backing.keys(), 'owner timerfd missing from actual descriptor table')
    quantiles = {}
    if latencies:
        ordered = sorted(latencies)
        quantiles = {f'p{q}_ms': ordered[math.ceil(len(ordered)*q/100)-1] for q in (50, 95, 99)}
        quantiles['max_ms'] = max(ordered)
        if count <= 100 and interval['suspend_s'] < .01:
            require(quantiles['p99_ms'] <= 1100 and quantiles['max_ms'] <= 1500, 'normal ~1s release latency gate')
    result = dict(label=label, case=name, arm=record['arm'], repetition=record['repetition'],
                generation=generation, count=count*2, latency=quantiles, owners=owner_results,
                interval=interval, idle_failures=idle_failures, ledger=ledger)
    if pixel: result['environment'] = environment(run, record, interval)
    return result


def decision(outcomes):
    """Pre-registered paired comparison; never substitute the least-bad arm."""
    expected = {(name, repetition, arm) for name in COUNTS
                for repetition in range(3) for arm in ('poll', 'deadline')}
    actual = {(r['case'], r['repetition'], r['arm']) for r in outcomes}
    require(len(outcomes) == len(expected) and actual == expected, 'incomplete or duplicate Pixel decision matrix')
    pairs, candidates, errors = [], [], []
    for row in outcomes:
        if not row['environment']['valid']:
            errors.append(dict(label=row['label'], errors=row['environment']['errors']))
    for name in COUNTS:
        for repetition in range(3):
            pair = {r['arm']: r for r in outcomes if r['case'] == name and r['repetition'] == repetition}
            require(set(pair) == {'poll', 'deadline'}, 'missing registered idle pair')
            a, b = pair['poll'], pair['deadline']
            difference = abs(a['interval']['temperature_c'][0]-b['interval']['temperature_c'][0])
            if difference > 2: errors.append(dict(case=name, repetition=repetition, errors=['pair_temperature_difference']))
            if name not in ('empty', 'long'): continue
            ap, bp = a['interval']['cpu_rails_mw'], b['interval']['cpu_rails_mw']
            require(math.isfinite(ap) and math.isfinite(bp) and ap > 0 and bp > 0,
                    'energy must be positive and finite to establish a relative advantage')
            pairs.append(dict(case=name, repetition=repetition, poll_mw=ap, deadline_mw=bp,
                              deadline_over_poll=bp/ap, start_temperature_difference_c=difference))
    arm_results = {}
    for arm in ('poll', 'deadline'):
        idle = [r for r in outcomes if r['arm'] == arm and r['case'] in ('empty', 'long')]
        ratios = [p['deadline_over_poll'] if arm == 'deadline' else 1/p['deadline_over_poll'] for p in pairs]
        failures = {r['label']: r['idle_failures'] for r in idle if r['idle_failures']}
        relative = all(ratio <= .8 for ratio in ratios)
        passed = not errors and not failures and relative
        if passed: candidates.append(arm)
        arm_results[arm] = dict(candidate=passed, absolute_idle_failures=failures,
            all_pairs_at_least_20_percent_lower=relative, ratios=ratios,
            ratio_mean=sum(ratios)/len(ratios), ratio_range=[min(ratios), max(ratios)])
    return dict(selected=candidates[0] if len(candidates) == 1 else None,
                pairs=pairs, arms=arm_results, environment_errors=errors)


def combine_retries(original, retries):
    """Apply only the preregistered, bounded retries of invalid *whole* pairs.

    Callers independently verify every raw run before combining it. No raw
    files are edited, valid pairs cannot be reselected, and every replacement
    retains its original failure reasons and both attempts' provenance.
    """
    require(original['platform'] == 'pixel' and original['matrix_complete']
            and original['status'] == 'FUNCTIONAL_PASS', 'retries require a complete original functional matrix')
    decision(original['outcomes'])  # Reject missing/duplicate cases before any replacement.
    key = lambda row: (row['case'], row['repetition'], row['arm'])
    bind = lambda run, row: dict(row, evidence_run=run['run'],
                                evidence_result_sha256=run['run_result_sha256'])
    selected = {key(row): bind(original, row) for row in original['outcomes']}
    generations = {row['generation'] for row in original['outcomes']}
    require(len(generations) == len(selected), 'original generation reused')
    result_hashes = {original['run_result_sha256']}
    completed = original['completed_ns']
    attempts, history, evidence = defaultdict(int), [], []
    witness_fields = ('run', 'run_result_sha256', 'source_sha256', 'build_sha256',
                      'helpers_sha256', 'started_ns', 'completed_ns', 'status', 'matrix_complete')
    evidence.append({field: original[field] for field in witness_fields})
    for retry in retries:
        require(retry['platform'] == 'pixel' and retry['status'] in ('VALID_PARTIAL', 'FUNCTIONAL_PASS'),
                'retry is not independently functionally verified')
        require(all(retry[field] == original[field] for field in
                    ('source_sha256', 'build_sha256', 'helpers_sha256')), 'retry artifact/helper lineage changed')
        require(completed < retry['started_ns'] < retry['completed_ns'], 'retry run ordering')
        require(retry['run_result_sha256'] not in result_hashes, 'duplicate retry run')
        current_generations = [row['generation'] for row in retry['outcomes']]
        require(len(set(current_generations)) == len(current_generations)
                and generations.isdisjoint(current_generations), 'retry generation reused')
        pairs = defaultdict(list)
        for row in retry['outcomes']: pairs[(row['case'], row['repetition'])].append(row)
        require(bool(pairs), 'empty retry run')
        for pair_key, replacement in pairs.items():
            require(len(replacement) == 2 and {row['arm'] for row in replacement} == {'poll', 'deadline'},
                    'retry must contain a complete pair')
            require(all(key(row) in selected for row in replacement), 'retry pair outside original matrix')
            previous = [selected[(*pair_key, arm)] for arm in ('poll', 'deadline')]
            reasons = [dict(label=row['label'], errors=row['environment']['errors'])
                       for row in previous if not row['environment']['valid']]
            if abs(previous[0]['interval']['temperature_c'][0]-previous[1]['interval']['temperature_c'][0]) > 2:
                reasons.append(dict(errors=['pair_temperature_difference']))
            require(bool(reasons), 'cannot retry a valid pair to improve its result')
            attempts[pair_key] += 1
            require(attempts[pair_key] <= 2, 'registered maximum of two retries per invalid pair')
            history.append(dict(case=pair_key[0], repetition=pair_key[1], attempt=attempts[pair_key],
                reasons=reasons, replaced=[dict(run=row['evidence_run'], generation=row['generation'],
                    result_sha256=row['evidence_result_sha256']) for row in previous],
                replacement_run=retry['run'], replacement_result_sha256=retry['run_result_sha256'],
                replacement_generations=[row['generation'] for row in replacement]))
            for row in replacement: selected[key(row)] = bind(retry, row)
        generations.update(current_generations)
        result_hashes.add(retry['run_result_sha256'])
        completed = retry['completed_ns']
        evidence.append({field: retry[field] for field in witness_fields})
    result = dict(original, outcomes=list(selected.values()), retry_history=history, evidence_runs=evidence,
                  scope='registered-environment-pair-retries', verifier_sha256=digest(__file__))
    result['comparison'] = decision(result['outcomes'])
    result['decision'] = 'CANDIDATE_PENDING_LINUX' if result['comparison']['selected'] else 'HOLD'
    return result


def verify(run, build_path):
    result = json.loads((run/'result.json').read_text())
    build = json.loads(build_path.read_text())
    require(result['status'] == 'RAW_COMPLETE' and not result.get('error') and not result.get('cleanup_error'), 'collector not complete')
    require(result['source'] == 'NFQ_CAPTURED' and result['platform'] in ('linux', 'pixel'), 'actual endpoint scope')
    require(result['build_sha256'] == digest(build_path) and result['source_sha256'] == build['source_sha256'], 'build/source identity')
    source_chain = load_module('s226_verify_chain', ROOT/'tests/evidence/product_chain.py')
    require(source_chain.source_files() == build['files'], 'current Product source differs')
    require(hashlib.sha256(source_chain.encode(build['files'])).hexdigest() == build['source_sha256'], 'source closure hash')
    require(digest(build_path.parent/'dirty.diff') == build['dirty_diff_sha256'], 'frozen source diff')
    for name, expected in build['files'].items():
        if expected is not None: require(digest(build_path.parent/'source'/name) == expected, 'frozen Product source '+name)
    require(build['completed_ns'] < result['started_ns'] < result['completed_ns'], 'build/run ordering')
    require(result['raw_hashes'], 'raw evidence inventory absent')
    for name, expected in result['raw_hashes'].items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts, 'raw path escaped run')
        require(digest(run/name) == expected, 'raw hash mismatch '+name)
    registration_paths = set(REGISTRATIONS) & result['test_sources'].keys()
    require(len(registration_paths) == 1, 'missing or ambiguous preregistration')
    registration = next(iter(registration_paths))
    require(result['test_sources'][registration] == REGISTERED_SHA256
            and digest(run/'test-source'/registration) == REGISTERED_SHA256, 'preregistration changed')
    for name, expected in result['test_sources'].items():
        require(digest(run/'test-source'/name) == expected, 'unbound collector source')
        # Independent verifier dependencies must match. The collector itself
        # is archived by hash so safe generator/cleanup improvements do not
        # rewrite or mislabel earlier executed raw evidence.
        if name not in (*REGISTRATIONS, 'tests/device/s226-expiry-ab.py'):
            require(digest(ROOT/name) == expected, 'verifier dependency differs '+name)
    helpers = Path(result['helpers'])
    require(digest(helpers) == result['helpers_sha256'], 'helper manifest changed')
    helper = json.loads(helpers.read_text())
    require(helper['build_sha256'] == digest(build_path) and helper['source_sha256'] == build['source_sha256'], 'helper source lineage')
    for name, expected in helper['files'].items(): require(digest(helpers.parent/name) == expected, 'helper binary/source changed')
    # Builders copy each independent helper source into the immutable helper
    # directory. Linux and Android compilation witnesses can be inspected
    # after later generator improvements without relabelling their sources.
    for name, expected in helper['sources'].items():
        require(digest(helpers.parent/Path(name).name) == expected, 'frozen helper source differs '+name)
    require(digest(helper['compiler']['path']) == helper['compiler']['sha256'], 'helper compiler identity')
    pixel = result['platform'] == 'pixel'
    if pixel:
        require(digest(build['apk']) == build['apk_sha256'], 'APK artifact identity')
        require((run/'installed-apk.txt').read_text().split()[0] == build['apk_sha256'], 'installed APK hash')
        actual = {Path(line.split()[1]).name: line.split()[0] for line in (run/'installed-native.txt').read_text().splitlines()}
        require(actual == build['native_sha256'], 'installed native identity')
        for name in ('s226-seed', 's226-monitor', 's223-udp', 's217-policy'):
            require((run/(name+'-installed.txt')).read_text().split()[0] == helper['files'][name], 'installed helper identity '+name)
        require('6.1.134-android14' in (run/'kernel.txt').read_text(), 'registered Pixel kernel')
    else:
        mapping = (run/'uid-map.txt').read_text().split()
        require(mapping == ['0', str(result['policy_uid']), '1'] and mapping[1] != '0', 'rootless Linux namespace')
        require(build['host_evidence'] is False, 'host fixture is not Product artifact')
        for name, expected in build['artifact_hashes'].items(): require(digest(Path(build['artifact'])/name) == expected, 'Linux artifact identity')
        if build.get('debug_strip'):
            stripped = build['debug_strip']
            original_path = Path(stripped['original_build'])
            require(digest(original_path) == stripped['original_build_sha256'], 'original debug build identity')
            original = json.loads(original_path.read_text())
            require(original['files'] == build['files'] and original['source_sha256'] == build['source_sha256'], 'strip changed source lineage')
            require(digest(stripped['strip_path']) == stripped['strip_sha256'] and stripped['operation'] == '--strip-debug', 'strip tool/operation')
            require(digest(build_path.parent/'strip-audit.json') == stripped['audit_sha256'], 'strip audit identity')
            audit = json.loads((build_path.parent/'strip-audit.json').read_text())
            parser = load_module('s226_strip_sections', ROOT/'tests/evidence/strip_s226_linux.py')
            require(digest(parser.__file__) == stripped['script_sha256'], 'strip parser/source identity')
            require(audit and len({e['path'] for e in audit}) == len(audit), 'strip audit coverage')
            for entry in audit:
                old, new = Path(original['artifact'])/entry['path'], Path(build['artifact'])/entry['path']
                require(digest(old) == entry['before_sha256'] == original['artifact_hashes'][entry['path']]
                        and digest(new) == entry['after_sha256'], 'strip file identity')
                require(parser.allocated_sections(old) == parser.allocated_sections(new) == entry['allocated_sections'], 'strip altered a runtime section')
    oracle = load_module('s226_verify_oracle', ROOT/'tests/device/s207-owner-oracle.py')
    servers = Counter((e['nonce'], e['echo']) for path in run.glob('s226-server-*.log')
                      for e in records(path.read_text(), 'received '))
    outcomes = [case(run, record, pixel, oracle, servers) for record in result['generations']]
    require(len({r['generation'] for r in outcomes}) == len(outcomes), 'generation reused in campaign')
    generation_start = result.get('generation_start', 22610)
    require(0 < generation_start < 2**63-len(outcomes)
            and [r['generation'] for r in outcomes] == list(range(generation_start, generation_start+len(outcomes))),
            'campaign generation sequence differs')
    require('SAKAMOTO_S226_' not in (run/'hooks-after.txt').read_text(), 'final hooks remain')
    require(('fd20:6226::2' in (run/'addresses-before.txt').read_text()) ==
            ('fd20:6226::2' in (run/'addresses-after.txt').read_text()), 'temporary address residue')
    if pixel:
        final_idle = (run/'final-deviceidle.txt').read_text()
        require('mScreenOn=true' in final_idle and 'mForceIdle=false' in final_idle, 'screen/Doze state not restored')
    expected_cases = set(COUNTS) if pixel else set(COUNTS)-{'screen-off', 'forced-doze'}
    expected_reps = 3 if pixel else 1
    actual_matrix = {(r['case'], r['repetition'], r['arm']) for r in outcomes}
    expected_matrix = {(name, repetition, arm) for name in expected_cases
                       for repetition in range(expected_reps) for arm in ('poll', 'deadline')}
    complete = actual_matrix == expected_matrix and len(outcomes) == len(expected_matrix)
    for name in result['requested_cases']:
        sequence = [r['arm'] for r in outcomes if r['case'] == name]
        expected_order = ['poll', 'deadline', 'deadline', 'poll', 'poll', 'deadline'][:2*result['repetitions']]
        require(sequence == expected_order, 'preregistered AB/BA/AB order changed')
    summary = dict(status='FUNCTIONAL_PASS' if complete else 'VALID_PARTIAL', platform=result['platform'],
                   matrix_complete=complete, outcomes=outcomes, decision='NOT_YET_EVALUATED',
                   run=str(run), started_ns=result['started_ns'], completed_ns=result['completed_ns'],
                   helpers_sha256=result['helpers_sha256'],
                   source_sha256=result['source_sha256'], build_sha256=digest(build_path),
                   run_result_sha256=digest(run/'result.json'), verifier_sha256=digest(__file__))
    if pixel and complete:
        summary['comparison'] = decision(outcomes)
        summary['decision'] = 'CANDIDATE_PENDING_LINUX' if summary['comparison']['selected'] else 'HOLD'
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--linux-run', type=Path)
    parser.add_argument('--linux-build', type=Path)
    parser.add_argument('--retry-run', type=Path, action='append', default=[])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    outcome = verify(args.run.resolve(), args.build.resolve())
    if args.retry_run:
        require(args.output is not None and args.output.resolve() != args.run.resolve()/'verified.json',
                'retry result needs a separate output; preserve the original verdict')
        outcome = combine_retries(outcome, [verify(run.resolve(), args.build.resolve()) for run in args.retry_run])
    require(bool(args.linux_run) == bool(args.linux_build), 'Linux run and build must be supplied together')
    if args.linux_run:
        require(outcome['platform'] == 'pixel', 'combined decision must start from Pixel')
        linux = verify(args.linux_run.resolve(), args.linux_build.resolve())
        require(linux['platform'] == 'linux' and linux['matrix_complete'] and outcome['matrix_complete'], 'combined matrix incomplete')
        require(linux['source_sha256'] == outcome['source_sha256'], 'cross-platform Product source differs')
        outcome['linux'] = linux
        selected = outcome['comparison']['selected']
        outcome['decision'] = ('SELECT_'+selected.upper()) if selected else 'HOLD'
        outcome['status'] = 'PASS' if selected else 'HOLD'
    output = args.output or args.run/'verified.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(outcome, indent=2)+'\n')
    print(json.dumps({k: v for k, v in outcome.items() if k not in ('outcomes', 'linux')}, indent=2))


if __name__ == '__main__':
    main()
