#!/usr/bin/env python3
"""Independent source/packet/snapshot/matcher/terminal and cleanup verification."""
import argparse
from collections import Counter
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[2]
def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'tests/device'/filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value
placement = module('s235_placement_oracle', 'verify-s220-worker-placement.py')
native = placement.native
need, rows, digest = native.need, native.rows, native.digest
ANY = 0xffffffff


def netlink_platform(raw):
    """Independent Linux UAPI TLV decoder, not the Product parser's fields."""
    data = bytes.fromhex(raw)
    length, kind = struct.unpack_from('<IH', data)
    need(length == len(data) and length >= 20 and kind == 0x300, 'raw NFQUEUE header')
    attributes = {}; offset = 20
    while offset+4 <= length:
        size, kind = struct.unpack_from('<HH', data, offset); kind &= 0x3fff
        need(size >= 4 and offset+size <= length and kind not in attributes, 'raw NFQUEUE attribute bounds/duplicate')
        attributes[kind] = data[offset+4:offset+size]
        offset += (size+3) & ~3
    need(offset == (length+3) & ~3 and len(attributes[1]) == 7, 'raw NFQUEUE attribute tail/header')
    def integer(kind):
        if kind not in attributes: return 0
        need(len(attributes[kind]) == 4, 'raw NFQUEUE u32 size')
        return int.from_bytes(attributes[kind], 'big')
    return dict(packet=int.from_bytes(attributes[1][:4], 'big'), hook=attributes[1][6],
        uid_present=int(16 in attributes), uid=integer(16), indev_present=int(5 in attributes),
        indev=integer(5), outdev_present=int(6 in attributes), outdev=integer(6),
        queue=int.from_bytes(data[18:20], 'big'), payload=attributes[10])


def properties(text):
    return dict(line.split('=', 1) for line in text.splitlines() if '=' in line and not line.startswith('#'))


def completion_census(folder, record, platform):
    text = (folder/'vpp.log').read_text()
    need('source=GRAPH_INJECTED' not in text and 'SIGSEGV' not in text, 'wrong packet source or crash')
    cap_rows, send_rows = rows(text, 's231 ', 'nfq_payload'), rows(text, 's242 ', 'verdict_syscall')
    cap, sends = {native.identity(e): e for e in cap_rows}, {native.identity(e): e for e in send_rows}
    consumed = rows(text, 's204 ', 'completion_consume')
    need(cap and len(cap) == len(cap_rows) == len(send_rows) == len(sends) == len(consumed)
         and set(cap) == set(sends) == {native.identity(e) for e in consumed}, 'capture/verdict/completion census mismatch')
    returned = [e for e in rows(text, 's203 ', 'buffer_free') if e['source'] == 'NFQ_CAPTURED']
    need(Counter((e['thread'], e['buffer'], e['obligation']) for e in returned) ==
         Counter((e['thread'], e['buffer'], e['token']) for e in consumed), 'buffer was not returned exactly once')
    lane_rows = rows((folder/'initial.txt').read_text(), 'root.lane ')
    lanes = {e['lane']: e for e in lane_rows}
    native.worker_layout((folder/('trace.txt' if platform == 'pixel' else 'layout.txt')).read_text(),
                         (folder/'initial-fds.txt').read_text(), lane_rows)
    decoded = {}
    for key, capture in cap.items():
        lane, send = lanes[capture['lane']], sends[key]
        need(capture['generation'] == str(record['generation']) and
             all(capture[k] == lane[k] for k in ('thread', 'queue')) and
             all(send[k] == lane[k] for k in ('thread', 'queue', 'fd', 'generation')) and
             int(send['result']) >= 0 and send['errno'] == '0' and send['flags'] == '0', 'native verdict identity/outcome mismatch')
        try: decoded[key] = native.packet(capture['raw'])
        except AssertionError:
            need(platform == 'pixel', 'unexpected packet envelope in isolated Linux test')
    zero = rows(text, 's242 ', 'stop_native_zero')
    need(len(zero) == 1 and zero[0]['generation'] == str(record['generation']) and all(zero[0][k] == '0' for k in
         ('ready_mask', 'graph_enabled', 'graph_accepting', 'pending', 'buffers', 'obligations', 'handoffs', 'completion_frames')), 'native stop debt')
    retired, closed = rows(text, 's242 ', 'lane_retire'), rows(text, 's242 ', 'lane_closed')
    need(len(retired) == 4 and [e['lane'] for e in closed] == ['3', '2', '1', '0'] and all(e['fd'] == '-1' and
         all(e[k] == '0' for k in ('pending', 'allocated', 'loans', 'listener', 'socket')) for e in closed), 'lane resource residue')
    for entry in retired:
        count = sum(e['lane'] == entry['lane'] for e in sends.values())
        need(int(entry['verdicts']) == int(entry['settlements']) == int(entry['returns']) == count, 'trace/retirement conservation differs')
    need(record['process_absent'], 'native process survived')
    native.queue_state(folder, 'app-closed' if platform == 'pixel' else 'process-closed', platform, set())
    return text, cap, sends, decoded


def packet_owner(text, token, facts):
    expected = placement.assigned(facts)
    actual = [e for e in rows(text, 's207 ') if e.get('stage') == 'policy' and int(e['token']) == token]
    need(len(actual) == 1 and all(str(actual[0][k]) == str(v) for k, v in expected.items()) and
         int(actual[0]['thread']) == expected['owner']+1, 'canonical key/owner changed with interface/context')


def linux_snapshots(folder, record, text):
    publications = rows(text, 's232 ', 'snapshot_publish')
    need(publications and all(e['generation'] == str(record['generation']) for e in publications) and
         all(int(a['revision']) < int(b['revision']) for a, b in zip(publications, publications[1:])), 'snapshot generation/revision')
    counts = {int(e['revision']): int(e['count']) for e in publications}
    maps = {}
    if record['network_source'] == 'kernel':
        events = rows(text, 's235 ', 'platform_snapshot')
        need(len(events) == len(publications) and all(e['source'] == 'kernel' and e['generation'] == str(record['generation'])
             and int(e['count']) == counts[int(e['revision'])] for e in events), 'kernel publication identity')
        entries = rows(text, 's235 ', 'platform_interface')
        for event in events:
            revision = int(event['revision'])
            selected = [e for e in entries if int(e['revision']) == revision]
            maps[revision] = {int(e['ifindex']): int(e['context']) for e in selected}
            need(len(maps[revision]) == len(selected) == counts[revision] <= 32, 'partial/truncated/duplicate map')
            if event['reason'] != 'kernel_dump': need(not selected, 'uncertain source published known classes')
    else:
        need(record['network_source'] == 'controlled_external' and not rows(text, 's235 ', 'platform_snapshot'), 'injected classes relabelled as platform observations')
        for file in folder.glob('control-4-*.txt'):
            control = rows(file.read_text(), 'control ')[0]
            need(control['rc'] == '0' and control['mode'] == '4', 'external projection not acknowledged')
            maps[int(control['revision'])] = {int(control['ifindex']): int(control['context'])} if int(control['context']) else {}
        need(set(maps) == set(counts) and all(len(maps[k]) == counts[k] for k in maps), 'injection publication mismatch')
    return maps


def linux_cases(folder, record, result, text, cap, sends, decoded, maps, endpoints):
    facts = {int(e['token']): e for e in rows(text, 's217 ', 'nfq_facts')}
    snapshots = {int(e['token']): e for e in rows(text, 's232 ', 'packet_snapshot')}
    messages = {int(e['token']): e for e in rows(text, 's217 ', 'netlink_message')}
    need(len(facts) == len(snapshots) == len(messages) == len(cap), 'packet platform projection census')
    for key, capture in cap.items():
        token = key[2]; wire = netlink_platform(messages[token]['raw'])
        need(wire['packet'] == key[1] and wire['queue'] == int(capture['queue']) and
             wire['payload'] == bytes.fromhex(capture['raw']), 'raw netlink/captured packet binding')
        need(all(int(facts[token]['raw_'+field]) == wire[field] for field in
             ('hook', 'uid_present', 'uid', 'indev_present', 'indev', 'outdev_present', 'outdev')), 'independent raw NFQ facts differ')
    for index, case in enumerate(record['cases']):
        # Fixed semantic expectations, independent of the runner's outcome
        # fields and helper's current implementation.
        phase = case['phase']
        if record['network_source'] == 'controlled_external':
            if phase.startswith('missing-'):
                mode = 1 if phase == 'missing-gate-no-match' else 2
                mask = ANY if phase == 'missing-other-policy-drop' else 15
                expected = (mode, mask, ANY, 'loop', 0, mask != ANY, mask != ANY)
            else:
                name, stage, outcome = phase.split('-', 2)
                context = {'wifi': 1, 'mobile': 2, 'vpn': 4, 'wired': 8}[name]
                drop = outcome == 'projected-drop'
                mask = context if drop else 8 if context != 8 else 1
                expected = (1 if stage == 'gate' else 2, mask, ANY, 'loop', context, not drop, not drop)
        else:
            direct = result['direct_ifindex']
            fixed = {
                'vpn-allow': (0, ANY, ANY, 'vpn', 4, True, True),
                'direct-allow': (0, ANY, ANY, 'direct', 0, True, True),
                'unknown-other-policy-drop': (2, ANY, ANY, 'direct', 0, False, False),
                'different-network-no-match': (1, 1, ANY, 'vpn', 4, True, True),
                'exact-ifindex-drop': (1, ANY, direct, 'direct', 0, False, False),
                'other-ifindex-allow': (1, ANY, direct, 'vpn', 4, True, True),
                'disconnected-unknown-no-match': (1, 4, ANY, 'direct', 0, True, True),
                'link-recovered': (0, ANY, ANY, 'vpn', 4, True, True),
                'vpn-recreated-allow': (0, ANY, ANY, 'vpn', 4, True, True),
                'overflow-unknown-no-match': (1, 4, ANY, 'vpn', 0, True, True),
                'overflow-recovered-drop': (1, 4, ANY, 'vpn', 4, False, False),
                'receive-loss-unknown-no-match': (1, 4, ANY, 'direct', 0, True, True),
            }
            if phase in fixed: expected = fixed[phase]
            elif phase.startswith('default-'):
                vpn = phase.endswith('-vpn')
                expected = (1, 4, ANY, 'vpn' if vpn else 'direct', 4 if vpn else 0, not vpn, not vpn)
            else:
                mode = 1 if phase.startswith('gate-') else 2 if phase.startswith('l4-out-') else 3
                vpn = phase.endswith('-vpn-drop')
                expected = (mode, 4, ANY, 'vpn' if vpn else 'direct', 4 if vpn else 0, not vpn, not vpn or mode == 3)
        need((case['policy']['mode'], case['policy']['context'], case['policy']['ifindex'], case['path'],
              case['expected_context'], case['expected'], case['endpoint_expected']) == expected, 'case changed required semantics: '+phase)
        nonce = case['nonce']+'-0'
        need(int(case['nonce'].rsplit('-', 1)[1]) > result['started_ns'], 'stale endpoint nonce')
        need((case['returncode'] == 0) == case['expected'] and
             ('endpoint ' in (folder/f'client-{index}.txt').read_text()) == case['expected'], 'independent client outcome')
        need((nonce in (folder/f'endpoint-{index}.txt').read_text()) == case['endpoint_expected'] and
             (nonce in endpoints) == case['endpoint_expected'], 'peer delivery or late delivery mismatch')
        selected = [key for key, value in decoded.items() if value['payload'] == b'E'+nonce.encode()]
        requests = [key for key in selected if cap[key]['hook'] == '3' and decoded[key]['sport'] == case['source_port']]
        replies = [key for key in selected if cap[key]['hook'] == '1' and decoded[key]['dport'] == case['source_port']]
        need(len(requests) == 1 and len(replies) == int(case['endpoint_expected']) and len(selected) == len(requests)+len(replies), 'actual request/reply capture identity')
        need(sum(sends[key]['verdict'] == '0' for key in selected) == int(not case['expected']), 'endpoint failure was not the expected policy DROP')
        path = case['path']
        ifindex = result['wireguard_ifindex'] if path == 'vpn' else result['direct_ifindex'] if path == 'direct' else 1
        need(case['expected_ifindex'] == ifindex, 'case interface assertion changed')
        device = 's235wg' if path == 'vpn' else 's235host' if path == 'direct' else 'lo'
        need('dev '+device+' ' in (folder/f'route-{index}.txt').read_text(), 'kernel route contradicts actual interface')
        control = rows((folder/f'control-{case["policy"]["mode"]}-{case["policy"]["revision"]}.txt').read_text(), 'control ')[0]
        need(control['rc'] == '0' and all(int(control[k]) == case['policy'][k] for k in ('mode', 'context', 'ifindex', 'revision')), 'real policy publication differs from case')
        for key in selected:
            capture, send, wire = cap[key], sends[key], decoded[key]
            token = key[2]; fact, snapshot = facts[token], snapshots[token]
            need(wire['family'] == case['family'] and wire['protocol'] == 17 and
                 {ipaddress.ip_address(wire['source']), ipaddress.ip_address(wire['destination'])} ==
                 {ipaddress.ip_address(case['host']), ipaddress.ip_address(case['bind'])}, 'raw endpoint tuple mismatch')
            field = 'outdev' if capture['hook'] == '3' else 'indev'
            context = maps[int(snapshot['revision'])].get(ifindex, 0)
            need(fact['fault'] == '0' and fact['raw_hook'] == fact['hook'] == capture['hook'] and
                 fact['raw_'+field+'_present'] == fact[field+'_present'] == '1' and
                 int(fact['raw_'+field]) == int(fact[field]) == int(fact['normalized_ifindex']) == int(snapshot['ifindex']) == ifindex,
                 'LOCAL_IN/LOCAL_OUT does not project its own raw NFQ interface')
            need(int(fact['context']) == int(snapshot['context']) == case['expected_context'] == context and
                 bool(int(fact['availability']) & 4) == bool(context), 'snapshot/context/typed Unknown mismatch')
            uid_known = fact['raw_uid_present'] == '1'
            need(fact['uid_present'] == fact['raw_uid_present'] and bool(int(fact['availability']) & 1) == uid_known and
                 (int(fact['raw_uid']) == int(fact['normalized_uid']) == int(result['policy_uid']) if uid_known else int(fact['normalized_uid']) == 0),
                 'UID projection does not preserve actual presence/value')
            need(capture['hook'] != '3' or uid_known, 'controlled output client UID not known')
            rule = case['policy']; mode = rule['mode']
            match = mode != 0 and uid_known and (rule['context'] == ANY or bool(context & rule['context'])) and (rule['ifindex'] == ANY or ifindex == rule['ifindex'])
            match = match and (mode == 1 or capture['hook'] == ('1' if mode == 3 else '3'))
            need(int(send['verdict']) == (0 if match else 1), 'actual origin verdict differs from rule evaluation')
            stage = 'gate' if mode == 1 else 'l4'
            seen = [e for e in rows(text, 's209 ', stage) if int(e['token']) == token]
            need(len(seen) == 1 and int(seen[0]['revision']) == rule['revision'] and int(seen[0]['action']) == (2 if match else 0), 'real matcher did not evaluate current policy')
            if match:
                rule_id = 23500+mode*10+(int(case['family'] == 6) if mode != 1 else 0)
                need(int(seen[0]['rule']) == rule_id, 'DROP came from another rule')
            packet_owner(text, token, wire)
    return len(record['cases'])


def linux(run, result):
    need(result['scope'] == 'Linux-kernel-network-snapshot' and result['network_runner_sha256'] == digest(ROOT/'tests/device/s235-linux-network.py')
         and result['setup_sha256'] == digest(ROOT/'tests/device/s235-wireguard.py'), 'Linux runner/setup identity')
    records = result['generations']
    need([e['label'] for e in records] == ['kernel', 'controlled'] and
         [e['network_source'] for e in records] == ['kernel', 'controlled_external'], 'actual and injected source scopes mixed')
    need(result['actual_classes'] == {'VPN': 'REAL_KERNEL_ENDPOINT', 'Wired': 'UNVERIFIED_NO_HARDWARE',
         'Wifi': 'UNVERIFIED_NO_HARDWARE', 'Mobile': 'UNVERIFIED_NO_HARDWARE'}, 'hardware categories overstated')
    initial = {e['ifindex']: e for e in json.loads((run/'links-initial.json').read_text())}
    need(initial[result['wireguard_ifindex']]['linkinfo']['info_kind'] == 'wireguard' and
         initial[result['direct_ifindex']]['linkinfo']['info_kind'] == 'veth', 'actual Linux type/ifindex evidence')
    need(result['peer_namespace_closed'] and len(result['peer_cleanup']) == 2 and all(e['absent'] for e in result['peer_cleanup']), 'peer process/netns ownership cleanup')
    peer_ns = json.loads((run/'peer-namespace.json').read_text())['namespace']
    need(peer_ns != (run/'namespace.txt').read_text().strip(), 'VPN endpoints shared a local route namespace')
    endpoints = '\n'.join(p.read_text() for p in [*run.glob('peer-final-*.txt'), *run.glob('endpoint-final-*.txt')])
    counts = []
    for record in records:
        folder = run/record['label']
        need(record['termination'] == 'DRAIN_THEN_TERM', 'Linux did not perform native drain')
        text, cap, sends, decoded = completion_census(folder, record, 'linux')
        maps = linux_snapshots(folder, record, text)
        counts.append(linux_cases(folder, record, result, text, cap, sends, decoded, maps, endpoints))
        phases = Counter((e['phase'], e['family']) for e in record['cases'])
        need(all(value == 1 for value in phases.values()) and all((phase, family) in phases for phase, _ in phases for family in (4, 6)), 'duplicate or one-family case')
        if record['label'] == 'kernel':
            required = ['vpn-allow', 'direct-allow', 'unknown-other-policy-drop', 'different-network-no-match',
                'exact-ifindex-drop', 'other-ifindex-allow', 'disconnected-unknown-no-match', 'link-recovered',
                'vpn-recreated-allow', 'overflow-unknown-no-match', 'overflow-recovered-drop', 'receive-loss-unknown-no-match']
            required += [stage+suffix for stage in ('gate', 'l4-out', 'l4-in') for suffix in ('-vpn-drop', '-unknown-no-match')]
            required += ['default-'+dev+'-'+path for dev in ('s235wg', 's235host') for path in ('vpn', 'direct')]
            need(set(phases) == {(phase, family) for phase in required for family in (4, 6)}, 'missing real platform policy case')
            transition_names = ['initial', 'address-add', 'address-delete', 'link-down', 'link-up', 'link-delete',
                'index-reused-unknown', 'vpn-recreated', 'overflow-33-known', 'overflow-recovered', 'receive-loss-reused-unknown']
            transitions = result['transitions']
            need([e['label'] for e in transitions] == transition_names and all(a['revision'] < b['revision'] for a, b in zip(transitions, transitions[1:])), 'event transition census/order')
            unknown = {'link-down', 'link-delete', 'index-reused-unknown', 'overflow-33-known', 'receive-loss-reused-unknown'}
            for entry in transitions:
                wanted = {} if entry['label'] in unknown else {result['wireguard_ifindex']: 4}
                need(maps[entry['revision']] == wanted and {int(k): v for k, v in entry['entries'].items()} == wanted, 'stale classification after '+entry['label'])
                event = [e for e in rows(text, 's235 ', 'platform_snapshot') if int(e['revision']) == entry['revision']][0]
                need(event['reason'] == entry['reason'], 'transition reason fabricated')
                if entry['label'] == 'overflow-33-known':
                    need(entry['reason'] == 'map_overflow_unknown', 'overflow was silently truncated')
            links = json.loads((folder/'overflow-links.json').read_text())
            need(sum(e.get('linkinfo', {}).get('info_kind') == 'wireguard' and 'UP' in e['flags'] for e in links) == 33, 'overflow did not exceed actual 32-entry bound')
            reuse = json.loads((folder/'index-reuse.json').read_text())[0]
            need(reuse['ifindex'] == result['wireguard_ifindex'] and reuse['linkinfo']['info_kind'] == 'dummy', 'ifindex reuse was not real')
            loss = [line.split() for line in (folder/'loss-netlink.txt').read_text().splitlines()[1:]]
            need(any(e[1] == '0' and e[2] == str(record['pid']) and int(e[8]) > 0 for e in loss), 'kernel route socket did not actually drop notifications')
            need(rows(text, 's235 ', 'platform_snapshot') and 'reason=receive_loss ' in text and
                 re.search(r'^\s*\d+\s+0\s+\d+\s+\d+\s+[1-9]\d*\s+socket:\[\d+\]\s+sakamoto-linux-network-route', (folder/'loss-files.txt').read_text(), re.M), 'EPOLLERR did not reach the resynchronizing collector')
            opened, closed = rows(text, 's235 ', 'collector_open'), rows(text, 's235 ', 'collector_closed')
            need(len(opened) == len(closed) == 1 and opened[0]['subscriptions'] == '2' and closed[0]['subscriptions'] == '0'
                 and all(closed[0][k] == '-1' for k in ('route_fd', 'query_fd', 'timer_fd')), 'collector subscription/fd residue')
            fds = (folder/'native-closed-fds.txt').read_text()
            need(all(not re.search(r'\b'+opened[0][k]+r' ->', fds) for k in ('route_fd', 'query_fd', 'timer_fd')), 'OS fd survived collector close')
            refusal = rows((folder/'control-4-1001.txt').read_text(), 'control ')[0]
            need(refusal['rc'] != '0', 'external writer replaced active kernel collector')
        else:
            required = [name+'-'+stage+'-'+outcome for name in ('wifi', 'mobile', 'vpn', 'wired')
                        for stage in ('gate', 'l4') for outcome in ('projected-drop', 'other-no-match')]
            required += ['missing-gate-no-match', 'missing-l4-no-match', 'missing-other-policy-drop']
            need(set(phases) == {(phase, family) for phase in required for family in (4, 6)}, 'controlled projection matrix incomplete')
            need(len(rows(text, 's235 ', 'collector_external')) == 1 and not rows(text, 's235 ', 'collector_open'), 'projection silently used platform collector')
    return dict(actual_cases=counts[0], injected_cases=counts[1], actual_categories=['VPN'], hardware_unverified=['Wired', 'Wifi', 'Mobile'])


def pixel(run, result):
    need(result['scope'] == 'Pixel-Root-same-source-smoke' and result['smoke_runner_sha256'] == digest(ROOT/'tests/device/s235-pixel-smoke.py') and
         result['supervisor_runner_sha256'] == digest(ROOT/'tests/device/s242-pixel-supervisor.py'), 'Pixel smoke scope/source')
    need(len(result['generations']) == 1 and result['generations'][0]['label'] == 'smoke', 'smoke generation census')
    record = result['generations'][0]; folder = run/'smoke'
    text, cap, sends, decoded = completion_census(folder, record, 'pixel')
    need(not rows(text, 's235 ', 'collector_open') and not rows(text, 's235 ', 'platform_snapshot'), 'Linux provider ran on Android')
    endpoints = '\n'.join(p.read_text() for p in run.glob('endpoint-final-*.txt'))
    native.cases(folder, record, cap, sends, decoded, endpoints)
    for key, facts in decoded.items():
        if facts['sport'] == 40642 or facts['dport'] == 40642: packet_owner(text, key[2], facts)
    need({(e['lane'], e['owner_path']) for e in record['seeds']} == {(lane, path) for lane in range(4) for path in ('local', 'remote')}, 'Pixel dual-stack owner/lane coverage')
    need({e['lane'] for e in record['cases'] if e['phase'] == 'policy-drop'} == set(range(4)) and
         {e['lane'] for e in record['cases'] if e['phase'] == 'recover'} == set(range(4)), 'Pixel policy DROP/recovery lane coverage')
    running = properties((folder/'running.properties').read_text()); stopped = properties((folder/'stopped.properties').read_text())
    need(running['generation'] == str(record['generation']) and running['state'] == 'running' and
         running['protectionRunning'] == 'true' and not running['errorCode'], 'Root protection not running')
    need(record['termination'] == 'JNI_DRAIN_THEN_APP_STOP' and record['native_log_source'] == 'RuntimeService-stop-archive' and
         stopped['state'] == 'stopped' and stopped['mayBeActive'] == 'false' and stopped['pid'] == '-1' and not stopped['errorCode'], 'smoke did not stop through service/JNI')
    need(properties((folder/'cleanup.properties').read_text())['productRootNfqueueResidueClean'] == 'true', 'Android hook residue')
    service = [line for line in (folder/'service.log').read_text().splitlines() if 's242 native_root_drain=true' in line and
               re.search(r'\bgeneration='+str(record['generation'])+r'\b', line)]
    need(len(service) == 1 and 'result=1 ' in service[0], 'current JNI native drain not acknowledged')
    app_pids = [p[0] for line in (folder/'processes-before.txt').read_text().splitlines()
                if len(p := line.split(None, 2)) == 3 and p[2] == 'com.sakamoto.snort.androidruntime:runtime']
    need(len(app_pids) == 1, 'app PID identity missing')
    events = [line for line in (run/'network-events.log').read_text().splitlines()
              if re.search(r'\s'+app_pids[0]+r'\s+\d+\s+I SakamotoNetwork:', line)]
    need(any('event=initial_networks ' in line and 'code=0' in line for line in events) and
         sum('event=subscription_stopped thread_alive=false' in line for line in events) == 1, 'Android own network subscription failed or survived')
    publications = rows(text, 's232 ', 'snapshot_publish')
    need(any(int(e['count']) > 0 for e in publications), 'Android platform publication missing')
    return dict(cases=len(record['cases']), native_captures=len(cap), android_subscription_closed=True)


def verify(run):
    result = json.loads((run/'result.json').read_text())
    need(result['task'] == 'SAKAMOTO-235' and not result.get('error'), 'wrong/incomplete task')
    need(all(not Path(name).is_absolute() and '..' not in Path(name).parts for name in result['raw_hashes']), 'raw path escapes evidence scope')
    build = native.authority(run, result)
    detail = linux(run, result) if result['platform'] == 'linux' else pixel(run, result)
    need(result['endpoint_cleanup'] and all(e['process_absent'] for e in result['endpoint_cleanup']), 'endpoint residue')
    need(native.clean_hooks((run/'hooks-before.txt').read_text()) == native.clean_hooks((run/'hooks-after.txt').read_text()), 'test hooks survived or unrelated hooks changed')
    addresses = lambda name: set(re.findall(r'inet6\s+(\S+)', (run/name).read_text()))
    need(addresses('addresses-before.txt') == addresses('addresses-after.txt'), 'loopback test address residue')
    return dict(status='PASS', platform=result['platform'], source_sha256=build['source_sha256'],
        result_sha256=digest(run/'result.json'), scope=result['scope'], **detail,
        verifier_files={name: digest(ROOT/'tests/device'/name) for name in ('verify-s235-network.py',
            'verify-s220-worker-placement.py', 'verify-s242-root-lifecycle.py', 's207-owner-oracle.py')}, readiness_expansion=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('run', type=Path); parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try: answer = verify(args.run.resolve())
    except (AssertionError, OSError, KeyError, ValueError, IndexError, StopIteration) as error:
        answer = dict(status='HOLD', error=str(error))
    if args.output: args.output.write_text(json.dumps(answer, indent=2)+'\n')
    print(json.dumps(answer, indent=2)); raise SystemExit(answer['status'] != 'PASS')
