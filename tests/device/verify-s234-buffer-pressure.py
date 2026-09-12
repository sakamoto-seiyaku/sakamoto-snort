#!/usr/bin/env python3
"""Independent pressure, END lifetime, raw NFQUEUE and post-exit endpoint gate."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[2]
UDP = 40634
# Current Product ABI includes S226's indexed-expiry entry fields. Authority
# above/below binds every run to that source; never infer this from the log.
FLOW_ENTRY_BYTES = 232


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT/relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


end = module('s234_end_oracle', 'tests/device/verify-s225-flow-end.py')
packet_oracle = module('s234_packet_oracle', 'tests/device/verify-s242-root-lifecycle.py')
owner_oracle = module('s234_owner_oracle', 'tests/device/s207-owner-oracle.py')
digest, need, fields, rows = end.digest, end.need, end.fields, end.rows


def props(text):
    return dict(line.split('=', 1) for line in text.splitlines() if '=' in line and not line.startswith('#'))


def pool_state(text):
    found = re.findall(r'^default-numa-\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$', text, re.M)
    need(len(found) == 1, 'one native NUMA pool witness')
    value = dict(zip(('index', 'numa', 'size', 'data', 'total', 'available', 'cached', 'used'), map(int, found[0])))
    value['threads'] = {int(thread): int(count) for thread, count in re.findall(r'^\s*thread\s+(\d+)\s+(\d+)\s*$', text, re.M)}
    need(set(value['threads']) == {0, 1, 2} and sum(value['threads'].values()) == value['cached'], 'native per-thread cache accounting')
    need(value['available']+value['cached']+value['used'] == value['total'], 'native pool conservation')
    return value


def authority(directory, result):
    need(result['status'] == 'RAW_COMPLETE' and not result.get('error') and not result['cleanup_errors'], 'incomplete/unsafe collector')
    need(result['source'] == 'NFQ_CAPTURED' and result['platform'] in ('linux', 'pixel') and result['mode'] in ('native', 'supervisor'), 'real endpoint scope')
    build_file = Path(result['build'])
    need(digest(build_file) == result['build_sha256'], 'build witness changed')
    build = json.loads(build_file.read_text())
    chain = module('s234_source_chain', 'tests/evidence/product_chain.py')
    need(chain.source_files() == build['files'], 'current source differs from executed build')
    need(hashlib.sha256(chain.encode(build['files'])).hexdigest() == build['source_sha256'] == result['source_sha256'], 'Product source closure')
    need(digest(build_file.parent/'dirty.diff') == build['dirty_diff_sha256'], 'frozen dirty diff')
    for name, expected in build['files'].items():
        if expected is not None:
            need(digest(build_file.parent/'source'/name) == expected, 'frozen Product input '+name)
    need(build['completed_ns'] < result['started_ns'] < result['completed_ns'], 'build/run temporal ordering')
    helper_file = Path(result['helpers'])
    need(digest(helper_file) == result['helpers_sha256'], 'helper witness')
    helper = json.loads(helper_file.read_text())
    need(helper['build_sha256'] == result['build_sha256'] and helper['platform'] == result['platform'], 'helper source/platform binding')
    for name, expected in helper['files'].items():
        need(digest(helper_file.parent/name) == expected, 'helper artifact '+name)
    for name, expected in helper['sources'].items():
        need(digest(ROOT/name) == expected, 'helper source '+name)
    need(digest(helper['compiler']['path']) == helper['compiler']['sha256'], 'helper compiler')
    for name, expected in result['test_inputs'].items():
        need(digest(directory/'test-source'/name) == expected, 'frozen collector/preregistration '+name)
        if not name.startswith('docs/'):
            need(digest(ROOT/name) == expected, 'current collector changed '+name)
    for name, expected in result['raw_hashes'].items():
        need(digest(directory/name) == expected, 'raw evidence changed '+name)
    need(result['raw_hashes'] and len(result['endpoint_cleanup']) == 3 and
         all(e['process_absent'] for e in result['endpoint_cleanup']), 'endpoint cleanup')
    if result['platform'] == 'linux':
        need(result['mode'] == 'native' and build['host_evidence'] is False, 'real Linux native artifact')
        need((directory/'uid-map.txt').read_text().split() == ['0', str(result['policy_uid']), '1'] and result['policy_uid'] != '0', 'rootless namespace UID evidence')
        for name, expected in build['artifact_hashes'].items():
            need(digest(Path(build['artifact'])/name) == expected, 'Linux artifact '+name)
        for name, expected in build['control_hashes'].items():
            need(digest(build_file.parent/name) == expected, 'control artifact '+name)
    else:
        need(digest(build['apk']) == build['apk_sha256'] == (directory/'installed-apk.txt').read_text().split()[0], 'installed APK')
        installed = {Path(line.split()[1]).name: line.split()[0] for line in (directory/'installed-native.txt').read_text().splitlines()}
        need(installed == build['native_sha256'], 'installed native closure')
        with zipfile.ZipFile(build['apk']) as apk:
            need({Path(name).name: hashlib.sha256(apk.read(name)).hexdigest() for name in apk.namelist()
                  if name.startswith('lib/arm64-v8a/') and name.endswith('.so')} == installed, 'APK native contents')
        state = props((directory/'app-after.properties').read_text())
        need(state['state'] == 'stopped' and state['mayBeActive'] == 'false' and not state['errorCode'], 'final app stopped state')
    if result.get('lan'):
        host_path = Path(result['host_helpers'])
        need(digest(host_path) == result['host_helpers_sha256'], 'LAN helper witness')
        host = json.loads(host_path.read_text())
        need(host['platform'] == 'linux' and host['source_sha256'] == result['source_sha256'], 'LAN helper source closure')
        for name in ('s223-udp', 's222-tcp'):
            need(digest(host_path.parent/name) == host['files'][name], 'LAN endpoint binary')
        need(len(result['host_endpoint_cleanup']) == 3 and all(e['process_absent'] for e in result['host_endpoint_cleanup']), 'LAN endpoint residue')
    need('SAKAMOTO_S234_' not in (directory/'hooks-after.txt').read_text(), 'private hook residue')
    if result['mode'] == 'supervisor':
        need('SAKAMOTO_PRODUCT_' not in (directory/'hooks-after.txt').read_text(), 'production hook residue')
    need(('fd20:6234::2' in (directory/'addresses-before.txt').read_text()) ==
         ('fd20:6234::2' in (directory/'addresses-after.txt').read_text()), 'temporary address residue')
    need(int(re.search(r'^MemAvailable:\s+(\d+) kB', (directory/'memory-before.txt').read_text(), re.M)[1]) >= 512*1024, 'preregistered memory preflight')
    return build


def queue_closed(folder, label, platform):
    if platform == 'linux':
        need(json.loads((folder/(label+'-queue-bind.json')).read_text()) == {str(q): 0 for q in range(176, 180)}, 'queue did not become bindable')
    else:
        need(not (folder/(label+'-queues.txt')).read_text().strip(), 'kernel queue residue')


def verify(directory):
    directory = Path(directory)
    result = json.loads((directory/'result.json').read_text())
    build = authority(directory, result)
    records = result['generations']
    need([r['label'] for r in records] == ['normal', 'near', 'fatal', 'recovery'] and
         len({r['generation'] for r in records}) == 4, 'four distinct pressure/recovery generations')
    need([r['generation'] for r in records] == sorted(r['generation'] for r in records), 'generation ordering')
    summary = []
    for record in records:
        folder = directory/record['label']
        read = lambda name: (folder/name).read_text()
        fatal = record['label'] == 'fatal'
        need(record['closed'] and record['process_absent'] and record['termination'] == ('FATAL_OS_RECLAIM' if fatal else 'ORDERLY_DRAIN'), 'process termination classification')
        need(re.search(r'buffers\s*\{\s*buffers-per-numa 512\s*\}', read('startup.conf')), 'actual small-pool startup configuration')
        initial, seeded = read('initial.txt'), read('seed-drained.txt')
        pool = pool_state(initial)
        usable = pool['available']+pool['threads'][1]
        need(pool['used'] == 4*72 and pool['data'] == 2048 and pool['size'] == 256+2048, 'actual buffer layout and Root fixed receive budget')
        need(pool_state(seeded) == pool and usable == record['usable'], 'available pool changed during true UDP creation')
        runtime = rows(initial, 'flow.runtime ')
        need(len(runtime) == 2 and all(e['capacity'] == '1024' and int(e['entry_bytes']) == FLOW_ENTRY_BYTES
             and int(e['allocated_bytes']) > 1024*FLOW_ENTRY_BYTES for e in runtime), 'actual FlowRuntime allocation budget')
        need(all(e['generation'] == str(record['generation']) for e in runtime), 'new generation inherited runtime')
        rss = re.findall(r'^VmRSS:\s+(\d+) kB', read('memory.txt'), re.M)
        need(len(rss) == 1 and int(rss[0]) > 0 and 'Rss:' in read('memory.txt'), 'actual native RSS/smaps')
        count = 8 if record['label'] in ('normal', 'recovery') else usable+(-1 if record['label'] == 'near' else 1)
        need(count == record['batch_count'] and 1 <= count <= 256, 'registered small pressure count and complete END trace budget')
        need(len(re.findall(r'^\s*[12]\s+vpp_wk_[01]\s+workers\s+\d+', read('layout.txt'), re.M)) == 2, 'actual W2 threads')
        lanes = rows(initial, 'root.lane ')
        need(len(lanes) == 4 and {int(e['queue']) for e in lanes} == set(range(176, 180)) and
             all(e['ready'] == '1' and e['pending'] == '0' for e in lanes), 'four ready native NFQUEUE lanes')
        inodes = []
        for lane in lanes:
            match = re.search(r'\s'+lane['fd']+r' -> (socket:\[\d+\])', read('fds-before.txt'))
            need(match, 'queue native fd inode absent')
            inodes.append(match[1])
        need(len(set(inodes)) == 4, 'queue sockets aliased')
        trace = read('vpp.log')
        events = []
        for index, line in enumerate(trace.splitlines()):
            if line.startswith(('s203 ', 's204 ', 's208 ', 's216 ', 's225 ', 's231 ', 's234 ', 's242 ')):
                e = fields(line)
                e.update(_index=index, _prefix=line.split()[0])
                events.append(e)
        captures = [e for e in events if e.get('event') == 'nfq_payload']
        calls = [e for e in events if e.get('event') == 'verdict_syscall']
        identity = lambda e: (e['lane'], e['packet'], e['token'])
        captured_ids, called_ids = Counter(map(identity, captures)), Counter(map(identity, calls))
        need(captures and all(n == 1 for n in captured_ids.values()) and not called_ids-captured_ids, 'unique actual NFQUEUE identities')
        need(all(e['source'] == 'NFQ_CAPTURED' and int(e['generation']) == record['generation'] and e['verdict'] == '1'
                 and int(e['result']) > 0 and e['errno'] == '0' for e in calls), 'real allowed terminal operations')
        consumed = [e for e in events if e.get('event') == 'completion_consume']
        returned = [e for e in events if e['_prefix'] == 's203' and e.get('event') == 'buffer_free']
        need(Counter(map(identity, consumed)) == called_ids and
             Counter((e['thread'], e['buffer'], e['token']) for e in consumed) ==
             Counter((e['thread'], e['buffer'], e['obligation']) for e in returned), 'original packet completion/free conservation')
        need(sum((captured_ids-called_ids).values()) == int(fatal), 'unobserved packet count must be exactly the fatal trigger')
        decoded = {e['token']: packet_oracle.packet(e['raw']) for e in captures}
        old_entries = rows(seeded, 'flow.entry ')
        old = {(e['worker'], e['slot'], e['incarnation']): e for e in old_entries}
        # Production Root INPUT legitimately observes other applications before
        # the test seeds. Prove those entries were created in THIS generation;
        # do not suppress platform traffic or pretend startup must stay empty.
        initial_entries = rows(initial, 'flow.entry ')
        for entry in initial_entries:
            need(any(e['_prefix'] == 's208' and e.get('created') == '1' and e.get('generation') == str(record['generation'])
                     and e.get('worker') == entry['worker'] and e.get('slot') == entry['slot'] and e.get('hash') == entry['hash']
                     and e.get('first_seen') == entry['first_seen'] for e in events), 'initial entry has no current-generation creation evidence')
        other_owner_entries = sum(e['worker'] == '0' and (e['protocol'] != '17' or UDP not in (int(e['port_a']), int(e['port_b']))) for e in old_entries)
        coverage = set()
        for probe in record['probes']:
            nonce = probe['nonce']+'-0'
            packets = [e for e in captures if decoded[e['token']]['payload'] == b'E'+nonce.encode()]
            expected = 4 if result['mode'] == 'supervisor' else 2
            need(len(packets) == expected, 'probe lacks all real NFQUEUE request/reply captures')
            need({decoded[e['token']]['sport'] for e in packets} == {probe['port'], UDP}, 'captured endpoint tuple')
            client = rows(read(probe['label']+'-clients.txt'), 'endpoint ')
            need(sum(e['nonce'] == nonce and e['received'] == '1' and e['uid'] == str(result['uid']) for e in client) == 1, 'real client echo')
            endpoint = rows((directory/f'udp-{probe["family"]}.log').read_text(), 'received ')
            need(sum(e['nonce'] == nonce and e['echo'] == '1' for e in endpoint) == 1, 'independent UDP endpoint receipt')
            for capture in packets:
                packet = decoded[capture['token']]
                facts = dict(l3=1, l4=1, family=packet['family'], protocol=17,
                    src=ipaddress.ip_address(packet['source']).packed.rjust(16, b'\0').hex(),
                    dst=ipaddress.ip_address(packet['destination']).packed.rjust(16, b'\0').hex(),
                    src_port=packet['sport'], dst_port=packet['dport'], icmp_known=0)
                expected_owner = owner_oracle.owner(facts)
                consumers = [e for e in events if e.get('event') == 'consumer_packet' and e['token'] == capture['token']]
                need(len(consumers) == 1 and int(consumers[0]['owner']) == expected_owner == probe['owner'] and
                     int(consumers[0]['thread']) == expected_owner+1, 'canonical owner and shared packet consumer')
                coverage.add((packet['family'], expected_owner))
        need(coverage == {(4, 0), (4, 1), (6, 0), (6, 1)}, 'dual-stack W2 coverage')
        pressure = [e for e in events if e['_prefix'] == 's234']
        need([e['event'] for e in pressure] == ['batch_begin', 'allocator_returned_zero' if fatal else 'batch_end'], 'actual batch/allocator event sequence')
        begin, last = pressure
        need(begin['requested'] == str(count) and begin['closed'] == '0' and
             int(begin['available'])+int(begin['owner_cached']) == usable and begin['end_allocated'] == begin['end_released'] == '0', 'pre-batch actual allocation budget')
        need(all(e['owner'] == '0' and e['thread'] == '1' and int(e['generation']) == record['generation'] and
                 int(e['total']) == pool['total'] and int(e['entry_bytes']) == FLOW_ENTRY_BYTES and e['buffer_bytes'] == '256' and e['data_bytes'] == '2048' for e in pressure), 'owner-local pressure identity/layout')
        ends = [e for e in events if e.get('event') == 'unlink_allocate']
        need(len(ends) == count-int(fatal) and len({e['buffer'] for e in ends}) == len(ends), 'one new native buffer per pending END')
        need(not ({e['buffer'] for e in ends} & {e['buffer'] for e in captures}), 'END borrowed a retained packet buffer')
        nodes = {e['node'] for e in events if e.get('event') == 'consumer_packet'}
        need(len(nodes) == 1 and {e['node'] for e in ends} == nodes, 'END uses a parallel graph entry')
        for allocated in ends:
            key = allocated['owner'], allocated['slot'], allocated['incarnation']
            need(key in old, 'END does not refer to a seeded live entry')
            selected = [e for e in events if e['_prefix'] == 's225' and
                        (e.get('owner'), e.get('slot'), e.get('incarnation')) == key]
            expected = ['unlink_allocate'] if fatal else ['unlink_allocate', 'consumer_end', 'terminal_end', 'free_callback']
            need([e.get('event') for e in selected] == expected, 'END graph/free sequence or false orderly fatal cleanup')
            need(all(e['buffer'] == allocated['buffer'] and e['owner'] == '0' and e['thread'] == '1' and
                     e['length'] == e['obligation'] == e['linked'] == '0' and e['allocated'] == e['reason'] == '1' for e in selected), 'END exclusive identity/metadata')
            for e in selected:
                for name in ('hash', 'protocol', 'orig_packets', 'reply_packets', 'orig_bytes', 'reply_bytes', 'first_seen', 'last_seen'):
                    need(e[name] == old[key][name], 'immutable entry changed '+name)
            finish = len(events)+len(trace.splitlines()) if fatal else selected[-1]['_index']
            need(not any(allocated['_index'] < e['_index'] < finish and e.get('buffer') == allocated['buffer'] and e['_prefix'] != 's225' for e in events), 'END reached packet-only graph/output')
            if not fatal:
                need(selected[1]['_index'] > last['_index'], 'consumer freed a signal during the registered batch')
        need(last['linked'] == str(other_owner_entries) and last['ending'] == str(count) and last['end_released'] == '0' and
             int(last['end_allocated']) == len(ends), 'native retained-entry/END accounting at pressure boundary')
        if fatal:
            need(last['available'] == last['owner_cached'] == '0', 'allocator zero without actual exhausted owner budget')
            fault = [e for e in events if e.get('event') == 'fatal_allocation_failure']
            need(len(fault) == 1 and fault[0].get('exit_code') == '70' and fault[0]['owner'] == '0'
                 and fault[0]['thread'] == '1' and fault[0]['_index'] > last['_index'], 'checked direct fatal exit reason')
            need('received signal SIGABRT' not in trace and not rows(trace, 's242 event=stop_native_zero '), 'fatal misclassified as dump/orderly drain')
            missing = captured_ids-called_ids
            trigger = record['trigger']
            need(all(decoded[e['token']]['payload'] == b'E'+(trigger['nonce']+'-0').encode()
                     for e in captures if identity(e) in missing), 'OS reclaimed a different packet than the trigger')
            if result['platform'] == 'linux':
                need(record['exit_code'] == 70, 'actual native exit status')
            if result['mode'] == 'supervisor':
                state = props(read('failed.properties'))
                need(state['errorCode'] == 'unexpected_exit' and state['mayBeActive'] == state['protectionRunning'] == 'false'
                     and str(record['generation']) == state['generation'] and 'status 70' in state['errorMessage'], 'supervisor did not observe native failure/protection stop')
                need('SAKAMOTO_PRODUCT_' not in read('hooks-fatal.txt'), 'supervisor retained capture hooks')
            queue_closed(folder, 'fatal-closed', result['platform'])
            fatal_ns = int(last['monotonic_ns'])
            closed_ns = int(rows(read('cleanup-clock.txt'), 'clock ')[0]['mono_ns'])
            need(0 <= closed_ns-fatal_ns <= 5_000_000_000, 'platform withdrawal exceeded preregistered bound')
            responses = rows(read('trigger-and-recovery.txt'), 'traffic ')
            need(responses and all(e['received'] == '1' and int(e['end_ns']) >= int(e['begin_ns']) > fatal_ns for e in responses), 'new endpoint requests did not recover after fatal')
            first_response = min(int(e['end_ns']) for e in responses)
            need(first_response-fatal_ns <= 2_000_000_000, 'new connection recovery exceeded preregistered bound')
            need({(p['protocol'], p['family']) for p in record['recovery_probes']} == {(p, f) for p in ('tcp', 'udp') for f in (4, 6)}, 'post-fatal dual-stack TCP/UDP coverage')
            for probe in record['recovery_probes']:
                replies = [e for e in responses if e['nonce'] == probe['nonce']]
                need(replies and all(e['source'] == str(probe['port']) and e['protocol'] == probe['protocol'] and e['family'] == str(probe['family']) for e in replies), 'fresh recovered endpoint identity')
                need(all(probe['nonce'].encode() not in p['payload'] for p in decoded.values()), 'recovery relied on the old native graph')
                for reply in replies:
                    payload = f'E{probe["nonce"]}:{int(reply["sequence"]):08d}'
                    if probe['protocol'] == 'udp':
                        log = directory/f'{"lan-" if result.get("lan") else ""}udp-{probe["family"]}.log'
                        need(sum(e['nonce'] == payload[1:] for e in rows(log.read_text(), 'received ')) == 1, 'recovery UDP endpoint receipt')
                    else:
                        log = directory/('lan-tcp.log' if result.get('lan') else 'tcp.log')
                        need(sum(payload.encode().hex() in e['data'] for e in rows(log.read_text(), 'echo ')) == 1, 'recovery TCP endpoint receipt')
            summary.append(dict(phase=record['label'], generation=record['generation'], actual_buffers=pool['total'], owner_usable=usable,
                rss_kib=int(rss[0]), allocated_ends=len(ends), os_reclaimed_snapshot_entries=len(old_entries),
                unobserved_captured_packets=1, first_new_echo_ms=(first_response-fatal_ns)/1e6, withdrawal_upper_ms=(closed_ns-fatal_ns)/1e6))
        else:
            need(last['closed'] == str(count) and int(last['available'])+int(last['owner_cached']) == usable-count, 'batch did not consume actual buffer budget')
            if record['label'] == 'near':
                need(int(last['available'])+int(last['owner_cached']) == 1, 'near-exhaustion boundary not reached')
            drained = rows(read('batch-drained.txt'), 'flow-end.owner=')
            need(len(drained) == 2 and all(e[k] == str(count) for e in drained if e['owner'] == '0'
                 for k in ('allocated', 'consumers', 'terminals', 'released')) and
                 all(e['ending'] == '0' for e in drained), 'ordinary END final release conservation')
            zero = rows(trace, 's242 event=stop_native_zero ')
            need(len(zero) == 1 and all(zero[0][key] == '0' for key in
                 ('ready_mask', 'graph_enabled', 'graph_accepting', 'pending', 'buffers', 'obligations', 'handoffs', 'completion_frames')), 'orderly native drain was not completed')
            closed_lanes = rows(trace, 's242 event=lane_closed ')
            need(len(closed_lanes) == 4 and all(e['fd'] == '-1' and all(e[k] == '0' for k in
                 ('pending', 'allocated', 'loans', 'listener', 'socket')) for e in closed_lanes), 'native lane/fixed-pool cleanup')
            if result['mode'] == 'native':
                closed = read('native-closed.txt')
                need(pool_state(closed)['used'] == 0 and all(e['entries'] == '0' for e in rows(closed, 'flow.pool ')), 'native pool/entry residue')
                need(all(inode not in read('fds-closed.txt') for inode in inodes), 'old queue inode survived orderly close')
            summary.append(dict(phase=record['label'], generation=record['generation'], actual_buffers=pool['total'], owner_usable=usable,
                rss_kib=int(rss[0]), closed=count, usable_at_batch_end=usable-count, packets=len(captures), orderly_drain=True))
        queue_closed(folder, 'closed', result['platform'])
        need('SAKAMOTO_S234_' not in read('hooks-after.txt') and (result['mode'] != 'supervisor' or 'SAKAMOTO_PRODUCT_' not in read('hooks-after.txt')), 'post-phase hook residue')
    return dict(status='PASS', platform=result['platform'], mode=result['mode'], source_sha256=build['source_sha256'],
                verifier_sha256=digest(__file__), scope='real-END-allocation-failure-and-Root-recovery-not-whole-device-OOM-or-release', generations=summary)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    answer = json.dumps(verify(args.run), indent=2)+'\n'
    if args.output:
        args.output.write_text(answer)
    print(answer, end='')
