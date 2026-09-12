#!/usr/bin/env python3
"""Check real packet identities and the independent native END/free lifetime."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def need(value, message):
    if not value:
        raise AssertionError(message)


def fields(line):
    return dict(re.findall(r'(\w+)=([^\s]+)', line))


def rows(value, prefix):
    return [fields(line) for line in value.splitlines() if line.startswith(prefix)]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def authority(directory, result):
    need(result['status'] == 'RAW_COMPLETE' and not result.get('error') and not result.get('cleanup_error'),
         'collector did not complete safely')
    need(result['source'] == 'NFQ_CAPTURED' and result['platform'] in ('linux', 'pixel'), 'actual endpoint scope')
    build_file = Path(result['build'])
    need(digest(build_file) == result['build_sha256'], 'build witness changed')
    build = json.loads(build_file.read_text())
    chain = module('s225_chain', 'tests/evidence/product_chain.py')
    need(chain.source_files() == build['files'], 'current source differs from executed build')
    need(hashlib.sha256(chain.encode(build['files'])).hexdigest() == build['source_sha256'] == result['source_sha256'],
         'source closure hash')
    need(digest(build_file.parent/'dirty.diff') == build['dirty_diff_sha256'], 'frozen source diff')
    for name, expected in build['files'].items():
        if expected is not None:
            need(digest(build_file.parent/'source'/name) == expected, 'frozen source '+name)
    need(build['completed_ns'] < result['started_ns'] < result['completed_ns'], 'build/run ordering')
    helpers_file = Path(result['helpers'])
    need(digest(helpers_file) == result['helpers_sha256'], 'helper witness')
    helpers = json.loads(helpers_file.read_text())
    need(helpers['build_sha256'] == result['build_sha256'] and helpers['platform'] == result['platform'], 'helper build/platform')
    for name, expected in helpers['files'].items():
        need(digest(helpers_file.parent/name) == expected, 'helper artifact '+name)
    for name, expected in helpers['sources'].items():
        need(digest(ROOT/name) == expected, 'helper source '+name)
    need(digest(helpers['compiler']['path']) == helpers['compiler']['sha256'], 'helper compiler')
    for name, expected in result['test_sources'].items():
        need(digest(directory/'test-source'/name) == digest(ROOT/name) == expected, 'executed collector '+name)
    need(result['raw_hashes'], 'raw evidence inventory absent')
    for name, expected in result['raw_hashes'].items():
        need(digest(directory/name) == expected, 'raw evidence changed '+name)
    if result['platform'] == 'linux':
        mapping = (directory/'uid-map.txt').read_text().split()
        need(mapping == ['0', str(result['policy_uid']), '1'] and mapping[1] != '0', 'rootless Linux namespace')
        need(build['host_evidence'] is False, 'Host fixture is not the Product artifact')
        for name, expected in build['artifact_hashes'].items():
            need(digest(Path(build['artifact'])/name) == expected, 'Linux artifact '+name)
    else:
        need(digest(build['apk']) == build['apk_sha256'], 'APK identity')
        need((directory/'installed-apk.txt').read_text().split()[0] == build['apk_sha256'], 'installed APK')
        installed = {Path(line.split()[1]).name: line.split()[0]
                     for line in (directory/'installed-native.txt').read_text().splitlines()}
        need(installed == build['native_sha256'], 'installed native closure')
        with zipfile.ZipFile(build['apk']) as apk:
            need({Path(name).name: hashlib.sha256(apk.read(name)).hexdigest() for name in apk.namelist()
                  if name.startswith('lib/arm64-v8a/') and name.endswith('.so')} == installed, 'APK native content')
        for name in ('s223-udp', 's217-policy'):
            need((directory/(name+'-installed.txt')).read_text().split()[0] == helpers['files'][name], 'installed endpoint '+name)
    need('Linux' in (directory/'kernel.txt').read_text(), 'actual kernel witness')
    need('SAKAMOTO_S225_' not in (directory/'hooks-after.txt').read_text(), 'private hook residue')
    before, after = ((directory/(name+'.txt')).read_text() for name in ('addresses-before', 'addresses-after'))
    need(('fd20:6225::2' in before) == ('fd20:6225::2' in after), 'temporary address residue')
    return build


def verify(directory):
    directory = Path(directory)
    result = json.loads((directory/'result.json').read_text())
    build = authority(directory, result)
    oracle = module('s225_owner_oracle', 'tests/device/s207-owner-oracle.py')
    packet_parser = module('s225_packet_oracle', 'tests/device/verify-s242-root-lifecycle.py')
    generations = result['generations']
    need(len(generations) == 2 and len({r['generation'] for r in generations}) == 2, 'two distinct native generations')
    summary = []
    for record in generations:
        need(record['process_closed'], 'native process survived cleanup')
        folder = directory/record['label']
        trace = (folder/'vpp.log').read_text()
        events = []
        for index, line in enumerate(trace.splitlines()):
            if line.startswith(('s203 ', 's204 ', 's208 ', 's216 ', 's223 ', 's225 ', 's231 ', 's242 ')):
                e = fields(line)
                e.update(_index=index, _prefix=line.split()[0])
                events.append(e)
        ends = [e for e in events if e['_prefix'] == 's225' and e.get('event') == 'unlink_allocate']
        need(len(ends) == len(record['cases']) == 9, 'complete END matrix')
        need(Counter(c['mode'] for c in record['cases']) == {'normal': 3, 'early': 3, 'replacement': 3}, 'END modes')
        need({e['owner'] for e in ends} == {'0', '1'}, 'END did not execute on both owners')
        captured = [e for e in events if e['_prefix'] == 's231' and e.get('event') == 'nfq_payload']
        consumed = [e for e in events if e['_prefix'] == 's204' and e.get('event') == 'completion_consume']
        syscalls = [e for e in events if e['_prefix'] == 's242' and e.get('event') == 'verdict_syscall']
        returned = [e for e in events if e['_prefix'] == 's203' and e.get('event') == 'buffer_free']
        need(len(captured) == len(consumed) == len(syscalls) == len(returned) == 30, 'packet completion conservation')
        def identity(e):
            return e['lane'], e['packet'], e['token']
        need(Counter(map(identity, captured)) == Counter(map(identity, consumed)) == Counter(map(identity, syscalls)),
             'verdict/consume without its own NFQUEUE identity')
        need(len(set(map(identity, captured))) == len(captured), 'duplicate captured identity')
        need(Counter((e['thread'], e['buffer'], e['token']) for e in consumed) ==
             Counter((e['thread'], e['buffer'], e['obligation']) for e in returned), 'packet buffer return exactly once')
        need(all(e['source'] == 'NFQ_CAPTURED' and int(e['result']) > 0 and e['errno'] == '0'
                 and e['verdict'] == '1' and int(e['generation']) == record['generation'] for e in syscalls), 'real allowed verdict syscalls')
        decoded = {e['token']: packet_parser.packet(e['raw']) for e in captured}
        packets = [e for e in events if e['_prefix'] == 's216' and e.get('stage') == 'admit']
        need(len(packets) == len(captured), 'Product admit trace missing')
        packet_consumers = [e for e in events if e['_prefix'] == 's225' and e.get('event') == 'consumer_packet']
        need(Counter(e['token'] for e in packet_consumers) == Counter(e['token'] for e in packets), 'ordinary packets bypass shared consumer')
        consumer_nodes = {e['node'] for e in packet_consumers}
        need(len(consumer_nodes) == 1 and {e['node'] for e in ends} == consumer_nodes, 'END entry differs from packet consumer')
        coverage = set()
        for packet in packets:
            facts = {key: int(packet[key]) if key not in ('src', 'dst') else packet[key]
                     for key in ('l3', 'l4', 'family', 'protocol', 'src', 'dst', 'src_port', 'dst_port', 'icmp_known')}
            assignment = oracle.assignment(facts)
            consumer = next(e for e in packet_consumers if e['token'] == packet['token'])
            need(int(consumer['owner']) == int(packet['owner']) == assignment['owner'] and
                 int(consumer['thread']) == assignment['owner']+1 and consumer['is_flow_end'] == '0', 'canonical packet owner/branch')
            need(consumer['buffer'] == packet['buffer'] and consumer['generation'] == packet['generation'], 'packet carrier identity')
            coverage.add((facts['family'], assignment['owner']))
        need(coverage == {(4, 0), (4, 1), (6, 0), (6, 1)}, 'dual-stack W2 coverage')
        for probe in record['probes']:
            nonce = probe['nonce']+'-0'
            need(int(probe['nonce'].rsplit('-', 1)[-1]) > result['started_ns'], 'stale endpoint nonce')
            selected = [d for d in decoded.values() if d['payload'] == b'E'+nonce.encode()]
            need(len(selected) == 2 and {d['sport'] for d in selected} == {probe['port'], 40625}, 'real endpoint payload capture')
            client = (folder/(probe['label']+'-client.txt')).read_text()
            need(len(rows(client, 'endpoint ')) == 1 and rows(client, 'endpoint ')[0]['nonce'] == nonce and
                 rows(client, 'endpoint ')[0]['received'] == '1', 'client verified real echo')
            endpoint = (directory/f's225-endpoint-{probe["family"]}.log').read_text()
            need(sum(e['nonce'] == nonce for e in rows(endpoint, 'received ')) == 1, 'independent endpoint received once')
        identities = set()
        for case in record['cases']:
            old = case['old']
            key = (str(record['generation']), old['worker'], old['slot'], old['incarnation'])
            need(key not in identities, 'same instance ended twice')
            identities.add(key)
            selected = [e for e in events if e['_prefix'] == 's225' and
                (e.get('generation'), e.get('owner'), e.get('slot'), e.get('incarnation')) == key and
                e.get('event') != 'controlled_close']
            expected = ['unlink_allocate', 'consumer_end',
                'consumer_early_free' if case['mode'] == 'early' else 'terminal_end', 'free_callback']
            need([e['event'] for e in selected] == expected, 'END graph/free sequence '+case['label'])
            need(len({e['buffer'] for e in selected}) == 1, 'END copied to another buffer')
            bi = selected[0]['buffer']
            need(all(e['thread'] == str(int(old['worker'])+1) and e['owner'] == old['worker'] and
                     e['length'] == e['obligation'] == e['linked'] == '0' and e['allocated'] == '1'
                     for e in selected), 'END left owner or released before native free')
            need(selected[1]['node'] in consumer_nodes, 'END consumer node differs from packets')
            for e in selected:
                need(e['reason'] == ('2' if case['mode'] == 'early' else '1'), 'END reason')
                for name in ('hash', 'protocol', 'orig_packets', 'reply_packets', 'orig_bytes', 'reply_bytes', 'first_seen', 'last_seen'):
                    need(e[name] == old[name], 'retained entry changed: '+name)
            forbidden = [e for e in events if selected[0]['_index'] < e['_index'] < selected[-1]['_index']
                         and e.get('buffer') == bi and e['_prefix'] != 's225']
            need(not forbidden, 'END reached packet parser/policy/handoff/completion/output')
            before = (folder/(case['label']+'-before.txt')).read_text()
            after = (folder/(case['label']+'-after.txt')).read_text()
            if case['mode'] == 'replacement':
                replacement = [e for e in events if e['_prefix'] == 's208' and e.get('created') == '1' and
                    e.get('hash') == old['hash'] and e.get('worker') == old['worker'] and
                    selected[0]['_index'] < e['_index'] < selected[-1]['_index']]
                need(len(replacement) == 1 and replacement[0]['slot'] != old['slot'], 'same tuple did not allocate another slot while END was live')
                current = [e for e in rows(after, 'flow.entry ') if e['hash'] == old['hash'] and e['worker'] == old['worker']]
                need(len(current) == 1 and current[0]['slot'] == replacement[0]['slot'] and
                     current[0]['incarnation'] != old['incarnation'], 'new instance missing after END release')
            else:
                need({e['lane']: e['verdicts'] for e in rows(before, 'root.lane ')} ==
                     {e['lane']: e['verdicts'] for e in rows(after, 'root.lane ')}, 'END generated an extra verdict')
        rejected = [e for e in events if e['_prefix'] == 's225' and e.get('event') == 'controlled_close' and e['status'] != '0']
        need(Counter(e['status'] for e in rejected) == {'12': 1, '8': 1}, 'stale close identities not rejected')
        before = (folder/'before-stop.txt').read_text()
        closed = (folder/'closed.txt').read_text()
        need('flow-end.buffers=0' in closed, 'END buffer debt')
        end_stats = rows(closed, 'flow-end.owner=')
        need(len(end_stats) == 2 and sum(int(e['allocated']) for e in end_stats) == 9, 'END allocation accounting')
        need(sum(int(e['early_frees']) for e in end_stats) == 3 and sum(int(e['terminals']) for e in end_stats) == 6, 'END terminal modes')
        for e in end_stats:
            need(e['allocated'] == e['consumers'] == e['released'] and
                 all(e[k] == '0' for k in ('active_entries', 'linked', 'ending', 'control')), 'END/entry residue')
            need(int(e['pool_releases']) == int(e['released'])+int(e['administrative_releases']), 'common cleanup accounting')
        thread = None
        vectors = {}
        for line in (folder/'runtime.txt').read_text().splitlines():
            match = re.match(r'Thread (\d+) ', line)
            if match: thread = int(match[1])
            match = re.match(r'(product-flow-consumer|product-packet-policy|product-packet-terminal)\s+active\s+\d+\s+(\d+)', line)
            if match: vectors[thread, match[1]] = int(match[2])
        need({thread for thread, _ in vectors} == {1, 2}, 'VLIB flow graph ran off owner threads')
        for e in end_stats:
            worker_thread = int(e['owner'])+1
            packets_on_owner = sum(int(p['thread']) == worker_thread for p in packet_consumers)
            need(vectors.get((worker_thread, 'product-packet-policy')) == packets_on_owner, 'END executed packet policy')
            need(vectors.get((worker_thread, 'product-flow-consumer')) == packets_on_owner+int(e['consumers']), 'VLIB consumer vectors differ from packet/END traces')
            need(vectors.get((worker_thread, 'product-packet-terminal')) == packets_on_owner+int(e['terminals']), 'VLIB terminal/free vectors differ from END branch')
        remaining = sum(int(e['entries']) for e in rows(before, 'flow.pool '))
        need(remaining == 6 == sum(int(e['administrative_releases']) for e in end_stats), 'drained stop cleanup must not emit normal ENDs')
        need(all(e['entries'] == '0' for e in rows(closed, 'flow.pool ')), 'flow storage residue')
        need(all(e[k] == '0' for e in rows(closed, 'completion.status ') for k in ('pending', 'frames', 'buffers', 'obligations')), 'packet completion residue')
        lanes = rows(closed, 'root.lane ')
        need(len(lanes) == 4 and all(e['fd'] == '-1' and e['ready'] == e['pending'] == '0' for e in lanes), 'NFQUEUE descriptor residue')
        if result['platform'] == 'linux':
            need(json.loads((folder/'closed-queue-bind.json').read_text()) == {str(q): 0 for q in range(176, 180)}, 'queues cannot rebind')
        else:
            need(not (folder/'closed-queues.txt').read_text().strip(), 'kernel queue residue')
        summary.append(dict(generation=record['generation'], packets=len(captured), flow_ends=len(ends),
                            early_free=3, same_tuple_retained=3, administrative_cleanup=remaining,
                            coverage=sorted(coverage)))
    return dict(status='PASS', scope='controlled-owner-local-END-on-real-UDP-not-automatic-expiry',
                platform=result['platform'], source_sha256=build['source_sha256'],
                verifier_sha256=digest(__file__), generations=summary)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    answer = json.dumps(verify(args.run), indent=2)+'\n'
    if args.output:
        args.output.write_text(answer)
    print(answer, end='')
