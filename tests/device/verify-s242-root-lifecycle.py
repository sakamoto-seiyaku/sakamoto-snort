#!/usr/bin/env python3
"""Verify real kernel packets, terminal syscalls and lifecycle conservation.

COMPLETION_REPLAY is a diagnostic carrier, never a second NFQUEUE capture.
Successful sendto is an operation result, never proof of endpoint delivery.
"""
import argparse
from collections import Counter
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


def need(condition, message):
    if not condition:
        raise AssertionError(message)


def rows(text, prefix, event=None):
    result = [dict(p.split('=', 1) for p in line.split()[1:] if '=' in p)
              for line in text.splitlines() if line.startswith(prefix)]
    return result if event is None else [r for r in result if r.get('event') == event]


def integer(row, name):
    return int(row[name])


def packet(hex_bytes):
    data = bytes.fromhex(hex_bytes)
    need(20 <= len(data) <= 512, 'nonfragment acceptance packet envelope')
    family = data[0] >> 4
    if family == 4:
        offset, protocol = (data[0] & 15)*4, data[9]
        need(offset >= 20 and len(data) == struct.unpack_from('!H', data, 2)[0], 'IPv4 packet length')
        need(struct.unpack_from('!H', data, 6)[0] & 0x3fff == 0, 'baseline cannot include IPv4 fragments')
        source, destination = data[12:16], data[16:20]
    else:
        need(family == 6 and len(data) >= 40, 'IPv6 packet header')
        need(len(data) == 40+struct.unpack_from('!H', data, 4)[0], 'IPv6 packet length')
        offset, protocol = 40, data[6]
        source, destination = data[8:24], data[24:40]
    need(protocol in (6, 17), 'baseline is ordinary kernel TCP/UDP, not fragments/injection')
    sport, dport = struct.unpack_from('!HH', data, offset)
    if protocol == 17:
        need(len(data)-offset == struct.unpack_from('!H', data, offset+4)[0], 'UDP captured length')
        payload = data[offset+8:]
    else:
        need(len(data)-offset >= 20, 'TCP header length')
        tcp_header = (data[offset+12] >> 4)*4
        need(20 <= tcp_header <= len(data)-offset, 'TCP data offset')
        payload = data[offset+tcp_header:]
    endpoints = sorted(((source, sport), (destination, dport)))
    return dict(family=family, protocol=protocol, sport=sport, dport=dport, payload=payload,
                source=str(ipaddress.ip_address(source)), destination=str(ipaddress.ip_address(destination)),
                key=(family, protocol, *endpoints))


def identity(row):
    return integer(row, 'lane'), integer(row, 'packet'), integer(row, 'token')


def worker_layout(text, descriptors, lanes):
    workers = re.findall(r'^\s*(\d+)\s+vpp_wk_(\d+)\s+workers\s+(\d+)\s+', text, re.M)
    need(len(workers) == 2 and {(i, w) for i, w, _ in workers} == {('1', '0'), ('2', '1')}
         and len({tid for _, _, tid in workers}) == 2 and all(int(tid) > 0 for _, _, tid in workers), 'actual VPP W2 thread layout')
    sockets = re.findall(r'^\s*(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+socket:\[(\d+)\]\s+sakamoto-root-nfqueue-(\d+)', text, re.M)
    need(len(sockets) == 4 and len({fd for fd, _, _, _ in sockets}) == 4
         and len({inode for _, _, inode, _ in sockets}) == 4, 'four distinct worker-owned queue sockets')
    for fd, thread, inode, queue in sockets:
        lane = next(r for r in lanes if r['queue'] == queue)
        need(lane['fd'] == fd and lane['thread'] == thread
             and re.search(r'\b'+fd+r' -> socket:\['+inode+r'\]', descriptors), 'worker file ownership does not match live fd inode')


def queue_state(run, label, platform, wanted):
    if platform == 'linux':
        values = json.loads((run/(label+'-queue-bind.json')).read_text())
        need(set(values) == {'176', '177', '178', '179'}, label+' queue witness completeness')
        for queue, error in values.items():
            need((error != 0) == (int(queue) in wanted), label+' real queue bind state '+queue)
    else:
        text = (run/(label+'-queues.txt')).read_text()
        queues = {int(line.split()[0]) for line in text.splitlines() if line.strip()}
        need(queues.intersection(range(176, 180)) == set(wanted), label+' kernel queue table')


def authority(run, result):
    need(result['status'] == 'RAW_COMPLETE', 'collector did not finish its required matrix')
    need(result['source'] == 'NFQ_CAPTURED', 'wrong evidence source')
    platform = result['platform']
    need(platform in ('linux', 'pixel'), 'unsupported platform')
    build_file = Path(result['build'])
    need(digest(build_file) == result['build_sha256'], 'Product build witness changed')
    build = json.loads(build_file.read_text())
    need(build['source_sha256'] == result['source_sha256'], 'Product source identity mismatch')
    spec = importlib.util.spec_from_file_location('product_chain', ROOT/'tests/evidence/product_chain.py')
    chain = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(chain)
    need(chain.source_files() == build['files'], 'current Product source differs from executed build')
    need(hashlib.sha256(chain.encode(build['files'])).hexdigest() == build['source_sha256'], 'source hash closure')
    need(digest(build_file.parent/'dirty.diff') == build['dirty_diff_sha256'], 'frozen dirty diff changed')
    for name, expected in build['files'].items():
        if expected is not None:
            need(digest(build_file.parent/'source'/name) == expected, 'frozen source '+name)
    need(build['completed_ns'] < result['started_ns'] < result['completed_ns'], 'build/execution time order')
    helper_file = Path(result['helpers'])
    need(digest(helper_file) == result['helpers_sha256'], 'helper witness changed')
    helper = json.loads(helper_file.read_text())
    need(helper['build_sha256'] == result['build_sha256'] and helper['platform'] == platform, 'helper links another build/platform')
    for name, expected in helper['files'].items():
        need(digest(helper_file.parent/name) == expected, 'executed helper '+name)
    for name, expected in helper['sources'].items():
        need(digest(ROOT/name) == expected, 'helper source changed '+name)
    need(digest(helper['compiler']['path']) == helper['compiler']['sha256'], 'helper compiler changed')
    need(digest(ROOT/'tests/device/s242-root-lifecycle.py') == result['runner_sha256'], 'collector changed since execution')
    need(digest(ROOT/'tests/device/s233-fail-open.py') == result['target_runner_sha256'], 'target operations changed')
    for name, expected in result['raw_hashes'].items():
        need(digest(run/name) == expected, 'raw evidence changed '+name)
    if platform == 'linux':
        mapping = (run/'uid-map.txt').read_text().split()
        need(mapping == ['0', str(result['policy_uid']), '1'] and mapping[1] != '0', 'Linux rootless identity scope')
        need(str(result['uid']) == '0' and (run/'namespace.txt').read_text().startswith('net:['), 'Linux namespace proof')
        for name, expected in build['artifact_hashes'].items():
            need(digest(Path(build['artifact'])/name) == expected, 'Linux native artifact '+name)
    else:
        need(digest(build['apk']) == build['apk_sha256'], 'built APK changed')
        need((run/'installed-apk.txt').read_text().split()[0] == build['apk_sha256'], 'installed APK mismatch')
        native = {Path(line.split()[1]).name: line.split()[0]
                  for line in (run/'installed-native.txt').read_text().splitlines()}
        need(native == build['native_sha256'], 'installed native closure mismatch')
        for name in ('s223-udp', 's217-policy', 's222-tcp', 's242-stop', 's242-queue-holder', 's242-traffic'):
            need((run/(name+'-installed.txt')).read_text().split()[0] == helper['files'][name], 'installed helper '+name)
    return build


def partial_start(run, record, platform):
    need(record['partial'] and record['process_absent'] and record['holder_process_absent']
         and record['holder_survived_rollback'], 'partial startup process ownership cleanup')
    log = (run/'vpp.log').read_text()
    failures = rows(log, 's242 ', 'lane_open_failed')
    need(len(failures) == 1 and failures[0]['lane'] == '3' and failures[0]['queue'] == '179'
         and integer(failures[0], 'errno') > 0, 'real partial lane configure rejection')
    configured = rows(log, 's233 ', 'queue_config')
    need([r['lane'] for r in configured] == ['0', '1', '2'], 'three successful lanes before partial failure')
    closed = rows(log, 's242 ', 'lane_closed')
    need([r['lane'] for r in closed] == ['3', '2', '1', '0'], 'partial startup reverse retirement order')
    for row in closed:
        need(row['fd'] == '-1' and all(row[k] == '0' for k in ('pending', 'allocated', 'loans', 'listener', 'socket')),
             'partial startup lane still owns resources')
    need('ack=0' in (run/'holder.txt').read_text(), 'independent queue holder did not bind')
    queue_state(run, 'initial', platform, {179})
    queue_state(run, 'holder-closed', platform, set())


def completions(log, record, closed_text=None, initial_lanes=None):
    captured = rows(log, 's231 ', 'nfq_payload')
    native = rows(log, 's242 ', 'verdict_syscall')
    consumes = [r for r in rows(log, 's204 ', 'completion_consume') if r['source'] == 'NFQ_CAPTURED']
    verdicts = rows(log, 's203 ', 'verdict')
    returned = [r for r in rows(log, 's203 ', 'buffer_free') if r['source'] == 'NFQ_CAPTURED']
    need(captured and native, 'missing real NFQUEUE/native syscall evidence')
    need(len({identity(r) for r in captured}) == len(captured), 'duplicate capture identity')
    need(len({identity(r) for r in native}) == len(native), 'physical verdict retried')
    need(len({identity(r) for r in consumes}) == len(consumes), 'native completion consumed twice')
    cap = {identity(r): r for r in captured}
    sends = {identity(r): r for r in native}
    consumed = {identity(r): r for r in consumes}
    owners = {(integer(r, 'lane'), integer(r, 'packet'), integer(r, 'obligation')): integer(r, 'owner') for r in verdicts}
    need(set(sends) <= set(cap) and set(sends) <= set(consumed), 'native operation lacks admitted capture/completion')
    if record['termination'] == 'DRAIN_THEN_TERM':
        need(set(cap) == set(sends) == set(consumed), 'normal stop lost an admitted completion')
        actual_returns = Counter((r['thread'], r['buffer'], r['obligation']) for r in returned)
        expected_returns = Counter((r['thread'], r['buffer'], r['token']) for r in consumes)
        need(actual_returns == expected_returns, 'origin buffer returned zero or multiple times')
    startup = {integer(r, 'lane'): r for r in initial_lanes or []}
    paths, flow_owners, decoded = set(), {}, {}
    for key, capture in cap.items():
        lane = key[0]
        need(0 <= lane < 4 and integer(capture, 'queue') == 176+lane
             and integer(capture, 'thread') == 1+lane%2
             and integer(capture, 'generation') == record['generation'], 'capture lane/generation/thread identity')
        facts = packet(capture['raw'])
        need(facts['family'] == (4 if lane < 2 else 6) == integer(capture, 'family'), 'captured queue family')
        decoded[key] = facts
        if key not in sends:
            continue  # Only abnormal process death may leave old work without an observed result.
        send = sends[key]
        need(send['source'] == 'NFQ_CAPTURED' and send['generation'] == capture['generation']
             and send['queue'] == capture['queue'] and send['thread'] == capture['thread']
             and integer(send, 'fd') >= 0
             and (not startup or send['fd'] == startup[lane]['fd']), 'syscall redirected across lane/generation')
        need(consumed[key]['thread'] == capture['thread'] and consumed[key]['buffer'] == capture['buffer'], 'wrong origin/carrier completion')
        owner = owners[key]
        need(owner in (0, 1), 'ordinary packet did not reach a final owner')
        need(flow_owners.setdefault(facts['key'], owner) == owner, 'canonical flow changed owner')
        paths.add((lane, 'local' if owner == lane%2 else 'remote'))
        if integer(send, 'result') < 0:
            need(integer(send, 'errno') > 0, 'negative syscall missing actual errno')
        else:
            need(integer(send, 'errno') == 0 and integer(send, 'flags') == 0, 'successful syscall misclassified')
    need(paths == {(lane, path) for lane in range(4) for path in ('local', 'remote')}, 'missing per-lane local/remote completion')
    if closed_text is not None:
        lanes = rows(closed_text, 'root.lane ')
        need(len(lanes) == 4, 'missing final lane audit')
        for row in lanes:
            lane = integer(row, 'lane')
            observed = [s for key, s in sends.items() if key[0] == lane]
            need(integer(row, 'captured') == sum(key[0] == lane for key in cap), 'capture trace truncated/incomplete')
            need(integer(row, 'verdicts') == integer(row, 'returns') == len(observed), 'lane terminal/return accounting')
            need(integer(row, 'succeeded') == sum(integer(s, 'result') >= 0 for s in observed), 'native success counter disagrees with syscalls')
            need(integer(row, 'failed') == sum(integer(s, 'result') < 0 for s in observed), 'native failure counter disagrees with syscalls')
    return cap, sends, decoded


def cases(run, record, cap, sends, decoded, endpoints):
    failures = set()
    drops = set()
    owners = {(integer(r, 'lane'), integer(r, 'packet'), integer(r, 'obligation')): integer(r, 'owner')
              for r in rows((run/'vpp.log').read_text(), 's203 ', 'verdict')}
    for index, case in enumerate(record['cases']):
        client = (run/f'client-{index}.txt').read_text()
        endpoint = (run/f'endpoint-{index}.txt').read_text()
        nonce = case['nonce']+'-0'
        need((case['returncode'] == 0) == case['expected'], 'endpoint outcome code '+case['phase'])
        need((nonce in endpoint) == case['expected'] and (nonce in endpoints) == case['expected'],
             'actual endpoint delivery/late delivery '+case['phase'])
        need(('endpoint ' in client) == case['expected'], 'client did not verify echo '+case['phase'])
        selected = [key for key, facts in decoded.items() if facts['payload'] == b'E'+nonce.encode()
                    and cap[key]['hook'] == '3' and facts['sport'] == case['source_port']
                    and facts['dport'] == 40642 and facts['destination'] == case['host']]
        if case['phase'] == 'no-listener-bypass':
            need(not selected, 'kernel bypass relabelled as NFQUEUE completion')
            continue
        key = case['lane'], case['packet'], case['token']
        need(selected == [key], 'case lacks unique raw NFQUEUE packet '+case['phase'])
        facts, native = decoded[key], sends[key]
        need(case['owner'] == owners[key] and case['origin_thread'] == integer(native, 'thread')
             and case['owner_path'] == ('local' if case['owner'] == case['origin_thread']-1 else 'remote'),
             'case owner identity differs from native completion')
        need(facts['family'] == case['family'] and facts['protocol'] == 17
             and facts['sport'] == case['source_port'] and facts['dport'] == 40642
             and facts['destination'] == case['host'], 'case kernel tuple mismatch')
        need(integer(native, 'result') == case['syscall_result'] and integer(native, 'errno') == case['syscall_errno']
             and integer(native, 'verdict') == case['verdict'], 'case fabricated native outcome')
        if case['phase'] == 'definite-failure':
            need(integer(native, 'result') == -1 and integer(native, 'errno') == 95
                 and integer(native, 'flags') == 1 and integer(native, 'verdict') == 1, 'real same-fd MSG_OOB rejection missing')
            failures.add(case['lane'])
        elif case['phase'] == 'policy-drop':
            need(integer(native, 'result') >= 0 and integer(native, 'verdict') == 0, 'policy DROP converted to fail-open')
            drops.add(case['lane'])
        else:
            need(integer(native, 'result') >= 0 and integer(native, 'verdict') == 1, 'ordinary allow/recovery syscall')
    if record['label'] == 'faults-stop':
        need(failures == drops == set(range(4)), 'missing per-lane definite failure/policy DROP')
        recovered = {c['lane'] for c in record['cases'] if c['phase'] == 'verdict-recovery' and c['expected']}
        need(recovered == failures, 'a failed lane did not recover for a new identity')


def replay(run, record, records, log, cap, sends):
    if record['label'] == 'abnormal':
        need(not rows(log, 's204 ', 'completion_reject'), 'unexpected replay in OS-reclaim case')
        return
    replayed = [r for r in rows(log, 's204 ', 'completion_consume') if r['source'] == 'COMPLETION_REPLAY']
    rejected = rows(log, 's204 ', 'completion_reject')
    returned = [r for r in rows(log, 's203 ', 'buffer_free') if r['source'] == 'COMPLETION_REPLAY']
    need(len(replayed) == len(rejected) == len(returned) == 8, 'all replay carriers must return exactly once')
    need({integer(r, 'buffer') for r in replayed}.isdisjoint({integer(r, 'buffer') for r in cap.values()}),
         'replay borrowed an original capture buffer')
    need(Counter(r['buffer'] for r in replayed) == Counter(r['buffer'] for r in returned), 'replay buffer return mismatch')
    need(Counter(r['reason'] for r in rejected) == {'duplicate': 4, 'stale_generation_or_lane': 4},
         'replay rejected at wrong boundary/owner')
    need(len(record['replay_identities']) == 8, 'missing replay request identity')
    for item in record['replay_identities']:
        lane = item['lane']
        mode = item['mode']
        request = rows((run/f'replay-{lane}-{mode}.txt').read_text(), 'completion.replay=accepted ')
        need(len(request) == 1, 'missing accepted replay request')
        request = request[0]
        need(integer(request, 'lane') == lane and integer(request, 'token') == item['token']
             and integer(request, 'packet') == item['packet'], 'replay request identity changed')
        selected = [r for r in rejected if identity(r) == (lane, item['packet'], item['token'])
                    and r['reason'] == ('duplicate' if mode == 'duplicate' else 'stale_generation_or_lane')]
        need(len(selected) == 1 and integer(selected[0], 'thread') == 1+lane%2, 'replay did not reach its own origin')
        if mode == 'duplicate':
            need(integer(selected[0], 'generation') == record['generation'], 'duplicate request generation')
        else:
            need(integer(selected[0], 'generation') != record['generation'], 'stale request is current generation')
            if item['old_generation'] is not None:
                need(integer(selected[0], 'generation') == item['old_generation'], 'replayed wrong previous generation')
                old = next(r for r in records if r['generation'] == item['old_generation'])
                fields = ('lane', 'packet', 'token', 'owner', 'origin_thread', 'verdict')
                need(any(c['phase'] == 'seed' and all(c[k] == item[k] for k in fields) for c in old['cases']),
                     'stale replay has no real previous-generation identity')
    before = rows((run/'before-replay.txt').read_text(), 'completion.status ')[0]
    after = rows((run/'after-replay.txt').read_text(), 'completion.status ')[0]
    need(before['verdicts'] == after['verdicts'] and after['duplicate'] == after['stale'] == '4',
         'replay caused another native operation')
    need(all(after[k] == '0' for k in ('pending', 'frames', 'buffers', 'obligations')), 'replay debt survived')


def normal_stop(run, record, log):
    text = (run/'native-closed.txt').read_text()
    old_inodes = re.findall(r'socket:\[(\d+)\]\s+sakamoto-root-nfqueue-\d+', (run/'layout.txt').read_text())
    closed_descriptors = (run/'native-closed-fds.txt').read_text()
    need(len(old_inodes) == 4 and all('socket:['+inode+']' not in closed_descriptors for inode in old_inodes),
         'retired queue socket still exists in native fd table')
    lanes = rows(text, 'root.lane ')
    pools = rows(text, 'root.receive ')
    need(len(lanes) == len(pools) == 4, 'missing closed lane/pool')
    for row in lanes:
        need(row['fd'] == '-1' and row['ready'] == row['pending'] == '0' and row['draining'] == '1',
             'lane closed before drain/incomplete close')
    for row in pools:
        need(all(row[k] == '0' for k in ('allocated', 'loans', 'withheld', 'reserve_losses', 'identity_losses')),
             'native receive storage/loss audit not clean')
    state = rows(text, 'completion.status ')[0]
    need(all(state[k] == '0' for k in ('pending', 'frames', 'buffers', 'obligations')), 'normal native debt not zero')
    primary = rows(text, 'primary.status ')[0]
    capacity = rows(text, 'capacity.status ')[0]
    need(all(primary[k] == '0' for k in ('pending_returns', 'handoff_debt', 'flows', 'owner_failures')),
         'retained return/flow/handoff survived normal stop')
    need(primary['credit0'] == primary['credit1'] == capacity['credits'], 'outstanding handoff credits after stop')
    need(primary['published'] == primary['received'], 'published primary work never consumed')
    flow_pools = rows(text, 'flow.pool ')
    need(len(flow_pools) == 2 and all(p['entries'] == p['wrong_owner'] == p['revision_mismatches'] == '0' for p in flow_pools),
         'worker-private FlowRuntime did not retire')
    closed = rows(log, 's242 ', 'lane_closed')
    need([r['lane'] for r in closed] == ['3', '2', '1', '0'], 'normal reverse lane close order')
    startup = {r['lane']: r for r in rows((run/'initial.txt').read_text(), 'root.lane ')}
    retired = rows(log, 's242 ', 'lane_retire')
    quiesced = rows(log, 's242 ', 'quiesce')
    need([r['lane'] for r in retired] == ['3', '2', '1', '0'], 'missing ordered lane retirement')
    need(len(quiesced) == 4 and {r['lane'] for r in quiesced} == set(startup), 'missing lane ingress cutoff')
    for row in retired + quiesced:
        need(all(row[k] == startup[row['lane']][k] for k in ('generation', 'fd', 'queue')),
             'drain did not preserve original lane fd/generation')
    for row in retired:
        need(row['pending'] == row['loans'] == '0'
             and row['verdicts'] == row['settlements'] == row['returns'], 'lane retired before origin settlement')
    for row in closed:
        need(row['fd'] == '-1' and all(row[k] == '0' for k in
             ('pending', 'allocated', 'loans', 'listener', 'socket')), 'closed lane retained native resources')
    zero = rows(log, 's242 ', 'stop_native_zero')
    need(len(zero) == 1 and integer(zero[0], 'generation') == record['generation'], 'missing native final stop proof')
    need(all(zero[0][k] == '0' for k in ('ready_mask', 'graph_enabled', 'graph_accepting', 'pending',
             'buffers', 'obligations', 'handoffs', 'completion_frames')), 'native stop falsely reported zero')
    lines = log.splitlines()
    quiesce = [i for i, line in enumerate(lines) if line.startswith('s242 event=quiesce ')]
    captures = [i for i, line in enumerate(lines) if line.startswith('s231 event=nfq_payload ')]
    close_lines = [i for i, line in enumerate(lines) if line.startswith('s242 event=lane_closed ')]
    syscall_lines = [i for i, line in enumerate(lines) if line.startswith('s242 event=verdict_syscall ')]
    need(len(quiesce) == 4 and max(captures) < min(quiesce) < min(close_lines), 'ingress did not quiesce before fd closure')
    need(max(syscall_lines) < min(close_lines), 'native operation used a closed lane')
    control = (run/'native-stop.txt').read_text()
    steps = rows(control, 'stop_step ')
    need(steps and all(s['code'] == '0' and integer(s, 'expected') == record['generation'] for s in steps)
         and steps[-1]['stopped'] == '1', 'typed native stop did not finish')
    need(integer(steps[-1], 'end_ns') - integer(steps[0], 'begin_ns') <= 3000000000,
         'native drain exceeded caller budget plus one UDS timeout')
    need('disconnected=0 destroyed=0 stopped=1' in control, 'control client cleanup failed')
    if record.get('stop_control'):
        need(any(s['stopped'] == '0' for s in steps), 'busy drain path was not exercised')
        need(any(integer(r, 'pending') > 0 for r in rows(log, 's242 ', 'quiesce')), 'stop had no real admitted backlog')
        need(any(max(quiesce) < i < min(close_lines) for i in syscall_lines), 'completion channel did not remain usable during drain')
    return steps


def traffic(run, record, cap, decoded, endpoints, steps):
    need(len(record['clients']) == 24, 'missing continuous endpoint cohort')
    coverage = set()
    captured_clients = 0
    if steps:
        before_stop, after_stop = integer(steps[0], 'begin_ns'), integer(steps[-1], 'end_ns')
    else:
        clocks = rows((run/'kill-clock.txt').read_text(), 'clock ')
        need(len(clocks) == 2 and integer(clocks[0], 'mono_ns') <= integer(clocks[1], 'mono_ns'), 'missing real kill time bracket')
        before_stop, after_stop = integer(clocks[0], 'mono_ns'), integer(clocks[1], 'mono_ns')
    for index, client in enumerate(record['clients']):
        need(client['process_absent'], 'endpoint helper still live')
        text = (run/f'traffic-{index}.txt').read_text()
        began, ended = rows(text, 'traffic_begin '), rows(text, 'traffic_end ')
        events = rows(text, 'traffic ')
        need(len(began) == len(ended) == 1 and events, 'missing continuous endpoint timeline')
        need(all(r['nonce'] == client['nonce'] and r['protocol'] == client['protocol']
                 and integer(r, 'family') == client['family'] and integer(r, 'source') == client['source_port'] for r in events),
             'endpoint timeline identity mismatch')
        need([integer(r, 'sequence') for r in events] == list(range(len(events))), 'missing/duplicate endpoint sequence')
        need(integer(ended[0], 'sent') == len(events)
             and integer(ended[0], 'received') == sum(integer(r, 'received') for r in events)
             and integer(ended[0], 'failed') + integer(ended[0], 'received') == len(events), 'endpoint count reconciliation')
        need(any(integer(r, 'begin_ns') > after_stop and r['received'] == '1' for r in events),
             'no successful endpoint traffic after native close/process death')
        if not record.get('stop_control') and not record.get('kill_sent'):
            need(any(integer(r, 'end_ns') < before_stop and r['received'] == '1' for r in events),
                 'stop was not under already-running traffic')
        protocol = 6 if client['protocol'] == 'tcp' else 17
        observed = [(key, facts) for key, facts in decoded.items() if facts['protocol'] == protocol
                    and facts['family'] == client['family'] and facts['sport'] == client['source_port']
                    and facts['destination'] == client['host'] and facts['dport'] == (40643 if protocol == 6 else 40642)
                    and cap[key]['hook'] == '3']
        if protocol == 17:
            observed = [(key, facts) for key, facts in observed
                        if facts['payload'].startswith(('E'+client['nonce']+':').encode())]
        # During the deliberate backlog case, TCP can finish its handshake
        # only after stop; the captured SYN is still a real packet obligation.
        if not record.get('stop_control') and not record.get('kill_sent'):
            need(observed, 'steady continuous flow did not traverse real NFQUEUE')
        # In the intentionally early-stop/death cohort, packets first sent
        # after the ingress cutoff are kernel bypass, not native captures.
        captured_clients += bool(observed)
        for event in events:
            if event['received'] == '1':
                wire = ('E'+client['nonce']+':'+format(integer(event, 'sequence'), '08d')).encode()
                need((wire[1:].decode() in endpoints) if protocol == 17 else wire.hex() in endpoints,
                     'client echo has no independent endpoint record')
        coverage.add((client['protocol'], client['family']))
    need(coverage == {('tcp', 4), ('tcp', 6), ('udp', 4), ('udp', 6)}, 'continuous dual-stack protocol coverage')
    need(captured_clients > 0, 'cohort contained no actual NFQUEUE traffic')
    return captured_clients


def clean_hooks(text):
    return [re.sub(r'\[\d+:\d+\]', '[counters]', line) for line in text.splitlines()
            if line and not line.startswith('#')]


def verify(directory):
    run = Path(directory)
    report = dict(status='HOLD', run=str(run.resolve()), verifier_sha256=digest(__file__), errors=[], generations=[])
    try:
        result = json.loads((run/'result.json').read_text())
        build = authority(run, result)
        records = result['generations']
        need([r['label'] for r in records] == ['partial-start', 'faults-stop', 'restart', 'abnormal', 'recovery'],
             'missing required lifecycle phase')
        need(len({r['generation'] for r in records}) == 5, 'generation reused')
        need(len(result['endpoint_cleanup']) > 0 and all(e['process_absent'] for e in result['endpoint_cleanup']),
             'independent endpoint cleanup incomplete')
        endpoints = '\n'.join((run/f'endpoint-final-{i}.txt').read_text() for i in range(len(result['endpoint_cleanup'])))
        for record in records:
            phase = run/record['label']
            if record['partial']:
                partial_start(phase, record, result['platform'])
                continue
            need(record['process_absent'], 'native process still live '+record['label'])
            initial = (phase/'initial.txt').read_text()
            lanes = rows(initial, 'root.lane ')
            need(len(lanes) == 4 and {integer(r, 'lane') for r in lanes} == set(range(4)), 'startup four-lane audit')
            for lane in lanes:
                i = integer(lane, 'lane')
                need(integer(lane, 'generation') == record['generation'] and lane['ready'] == '1'
                     and integer(lane, 'fd') >= 0 and integer(lane, 'thread') == 1+i%2
                     and integer(lane, 'queue') == 176+i, 'startup lane identity')
            worker_layout((phase/'layout.txt').read_text(), (phase/'initial-fds.txt').read_text(), lanes)
            state = rows(initial, 'completion.status ')[0]
            need(all(state[k] == '0' for k in ('pending', 'frames', 'buffers', 'obligations', 'verdicts', 'duplicate', 'stale')),
                 'new generation inherited old completion state')
            queue_state(phase, 'initial', result['platform'], set(range(176, 180)))
            queue_state(phase, 'process-closed', result['platform'], set())
            hooks = (phase/'hooks.txt').read_text()
            owned = [line for line in hooks.splitlines() if 'SAKAMOTO_S242_'+record['label'] in line]
            need(len(owned) == 8 and all('--queue-bypass' in line and '-j NFQUEUE' in line for line in owned), 'scoped dual-stack hooks missing')
            query = (phase/'query-only.txt').read_text()
            stale = rows((phase/'stale-stop.txt').read_text(), 'stop_step ')
            need('phase=connect code=0 ' in query and 'client_close disconnected=0 destroyed=0 stopped=0' in query,
                 'ordinary query session did not close cleanly')
            need(len(stale) == 1 and stale[0]['code'] == '5' and stale[0]['stopped'] == '0', 'stale stop request was not fenced')
            still_running = rows((phase/'after-query-and-stale-stop.txt').read_text(), 'root.lane ')
            need(len(still_running) == 4 and all(r['ready'] == '1' and r['draining'] == '0' for r in still_running),
                 'query close or stale generation stopped live lanes')
            log = (phase/'vpp.log').read_text()
            need('source=GRAPH_INJECTED' not in log and 'AddressSanitizer' not in log and 'SIGSEGV' not in log, 'invalid native run source/crash')
            steps = None
            closed_text = None
            if record['label'] == 'abnormal':
                need(record['termination'] == 'SIGKILL_OS_RECLAIM' and record['kill_sent'], 'abnormal case did not force process death')
                need(not rows(log, 's242 ', 'stop_native_zero') and not rows(log, 's242 ', 'lane_closed'),
                     'OS reclamation misrepresented as graceful native drain')
                need(rows(log, 's209 ', 'hold_begin'), 'abnormal exit had no live policy work')
                need(len([line for line in (phase/'after-kill-hooks.txt').read_text().splitlines()
                          if 'SAKAMOTO_S242_abnormal' in line]) == 8, 'new-flow bypass did not retain the old scoped hooks')
            else:
                need(record['termination'] == 'DRAIN_THEN_TERM', 'normal generation skipped native drain')
                steps = normal_stop(phase, record, log)
                closed_text = (phase/'native-closed.txt').read_text()
                queue_state(phase, 'native-closed', result['platform'], set())
            cap, sends, decoded = completions(log, record, closed_text, lanes)
            if record['label'] == 'abnormal':
                need(set(cap)-set(sends), 'OS-reclaim case contained no uncompleted real capture')
            cases(phase, record, cap, sends, decoded, endpoints)
            replay(phase, record, records, log, cap, sends)
            captured_clients = traffic(phase, record, cap, decoded, endpoints, steps)
            report['generations'].append(dict(generation=record['generation'], phase=record['label'],
                captured=len(cap), native_syscalls=len(sends), native_failures=sum(integer(s, 'result') < 0 for s in sends.values()),
                unobserved_before_process_death=len(set(cap)-set(sends)), continuous_clients=len(record['clients']),
                captured_continuous_clients=captured_clients))
        need(clean_hooks((run/'hooks-before.txt').read_text()) == clean_hooks((run/'hooks-after.txt').read_text()),
             'unrelated kernel hooks changed or owned hooks survived')
        before = re.findall(r'inet6 (\S+)', (run/'addresses-before.txt').read_text())
        after = re.findall(r'inet6 (\S+)', (run/'addresses-after.txt').read_text())
        need(before == after, 'loopback address cleanup changed unrelated state')
        need('libvpp_runtime.so' not in (run/'processes-after.txt').read_text() if result['platform'] == 'pixel' else True,
             'native Pixel VPP process survived')
        report.update(status='PASS', platform=result['platform'], source_sha256=build['source_sha256'],
                      scope='real-root-q2w2-native-lifecycle-not-android-supervisor-or-release',
                      result_sha256=digest(run/'result.json'))
    except (AssertionError, OSError, ValueError, KeyError, IndexError, StopIteration, struct.error) as error:
        report['errors'].append(str(error))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    answer = verify(args.run)
    if args.output:
        args.output.write_text(json.dumps(answer, indent=2)+'\n')
    print(json.dumps(answer, indent=2))
    raise SystemExit(answer['status'] != 'PASS')
