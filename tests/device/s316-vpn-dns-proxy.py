#!/usr/bin/env python3
"""Normal VPN local UDP DNS sessions, independent peer/wire and SQLite."""
import argparse
import importlib.util
import json
import ipaddress
import struct
from pathlib import Path
import re
import shlex
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s316_shared', ROOT/'tests/device/s315-root-dns-proxy.py')
shared = importlib.util.module_from_spec(spec); spec.loader.exec_module(shared)
peer_spec = importlib.util.spec_from_file_location('s316_peer', ROOT/'tests/device/helpers/s316_dns_peer.py')
linux_peer = importlib.util.module_from_spec(peer_spec); peer_spec.loader.exec_module(linux_peer)
PKG, SERIAL = shared.PKG, shared.SERIAL
props, digest, fixtures = shared.props, shared.digest, shared.fixtures


class Device(shared.Device):
    def upstream(self, label, address=None, port=None):
        return super().upstream(label, address, self.args.upstream_port if port is None else port)

    def start(self, owners):
        if hasattr(self, 'generation'): del self.generation
        if hasattr(self, 'selected_dns'): del self.selected_dns
        before = props(self.save(f'n{owners}-before-start-state.properties',
                                 self.app('files/runtime-state/snapshot.properties')))
        self.before_start_generation = int(before['generation'])
        assert before['state'] == 'stopped' and before['mayBeActive'] == 'false'
        self.stop_owed = True
        result = shared.tcp.Device.start(self, owners)
        state = props((self.out/f'n{owners}-running.properties').read_text())
        assert state['profile'] == 'vpn' and state['health'] == state['coreHealth'] == 'ok'
        assert self.generation > self.before_start_generation
        ledger = props(self.save(f'n{owners}-running-ledger.properties',
                                self.app('files/product-state/product-core-generation.properties')))
        assert int(ledger['generation']) == self.generation
        links = self.save(f'n{owners}-interfaces.txt', self.root('ip -o link show'))
        names = re.findall(r'(?m)^\d+: (tun\d+)(?:@[^:]+)?:', links)
        assert len(names) == 1, links
        self.tun_interface = names[0]
        self.tun_witness()
        return result

    def launch_queries(self, label, address, source, wires, **options):
        if options.get('system_name'):
            return shared.Device.launch_queries(self, label, address, source, wires, **options)
        nonce = 's316-'+label+'-'+str(time.time_ns())
        plan = dict(nonce=nonce, endpoint=address, port=53, source=source, bindDefault=True,
                    dnsQueries=[wire.hex() for wire in wires], dnsProxyTimeoutMs=options.get('timeout', 5000),
                    dnsQueryDelayMs=options.get('query_delay', 0 if options.get('pipeline') else 150),
                    dnsPipeline=options.get('pipeline', False))
        if options.get('initial_delay'): plan['dnsInitialDelayMs'] = options['initial_delay']
        if options.get('gate_reads'): plan['dnsGateAfterReads'] = True
        if 'gate_send' in options: plan['dnsGateAfterSend'] = options['gate_send']
        self.save(label+'-plan.json', json.dumps(plan, indent=2)+'\n')
        if options.get('gate_reads') or 'gate_send' in options:
            phases = ['dns_udp_read_'+str(i) for i in range(len(wires)-1)] if options.get('gate_reads') else []
            if 'gate_send' in options: phases.append('dns_udp_sent_'+str(options['gate_send']))
            self.pending_dns_gates = getattr(self, 'pending_dns_gates', []) + [(nonce, phase) for phase in phases]
        preserve = options.get('preserve_ui')
        if preserve: self.adb('shell', 'input', 'keyevent', '3')
        flags = ['-f', '0x18000000'] if preserve else []
        self.save(label+'-launch.txt', self.action(*flags, '--es', 't12ProbePlan', shlex.quote(json.dumps(plan))))
        if preserve: self.save(label+'-return-ui.txt', self.action())
        return nonce

    def phase(self, label, nonce, phase):
        return self.wait(label+'-'+phase, 'files/product-state/t12-'+nonce+'.json',
                         lambda value: value.get('phase') == phase, timeout=15, json_value=True)

    def release_phase(self, label, nonce, phase):
        self.save(label+'-'+phase+'-release.txt', self.adb('shell', 'run-as', PKG, 'touch',
                  'files/product-state/t12-release-'+nonce+'-'+phase))
        self.pending_dns_gates.remove((nonce, phase))

    def release_pending_gates(self):
        for nonce, phase in list(getattr(self, 'pending_dns_gates', [])):
            self.release_phase('cleanup', nonce, phase)

    def qualified_stop(self, label):
        if not hasattr(self, 'generation'): return shared.Device.qualified_stop(self, label)
        result = shared.tcp.Device.stop(self, label)
        raw = (self.out/(label+'-stop.log')).read_text()
        for owner in range(self.owners):
            rows = [props(line.replace(' ', '\n')) for line in raw.splitlines()
                    if f'dns.proxy event=stop generation={self.generation} owner={owner} ' in line]
            assert rows and all(row['transactions'] == row['upstream_sockets'] == row['raw_sockets'] == row['replies'] == '0'
                                and row['raw_opened'] == row['raw_closed'] for row in rows), rows
        return result

    def tun_witness(self):
        interface = self.tun_interface
        stop = '/data/local/tmp/s315-wire-'+interface+'.stop'
        log = '/data/local/tmp/s315-wire-'+interface+'.jsonl'
        self.witnesses[interface] = dict(pid=None, start=None, uid=None, exe=None,
                                         stop=stop, log=log, launch_pending=True)
        self.adb('shell', 'rm', '-f', stop, log)
        command = ('/data/local/tmp/s315-wire '+interface+' '+stop+' '+self.args.endpoint4+' '
                   +self.args.endpoint6+' 192.168.4.1 1.1.1.1 '+self.args.stale6+' > '+log
                   +' 2>&1 < /dev/null & echo $!')
        pid = int(self.save('wire-'+interface+'-start.txt', self.root(command)).strip())
        identity = self.save('wire-'+interface+'-identity.txt', self.root(
            f'cat /proc/{pid}/stat; grep "^Uid:" /proc/{pid}/status; readlink /proc/{pid}/exe'))
        rows = identity.splitlines(); assert len(rows) == 3 and ') ' in rows[0]
        item = self.witnesses[interface]
        item.update(pid=pid, launch_pending=False, start=int(rows[0].split(') ', 1)[1].split()[19]),
                    uid=int(rows[1].split()[2]), exe=rows[2])
        assert item['uid'] == 0 and item['exe'] == '/data/local/tmp/s315-wire'
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            if '"kind":"ready"' in self.adb('shell', 'cat', log, check=False): return
            time.sleep(.1)
        raise AssertionError('TUN passive witness did not become ready')


def legal_return(row, query, reply, address, source, local):
    packet = bytes.fromhex(row['packet_hex']); family = packet[0] >> 4
    header = (packet[0] & 15)*4 if family == 4 else 40
    udp = packet[header:]; length = int.from_bytes(udp[4:6], 'big')
    assert ipaddress.ip_address(row['source']) == ipaddress.ip_address(address)
    local_address = local.rsplit(':', 1)[0].strip('/[]')
    assert ipaddress.ip_address(row['destination']) == ipaddress.ip_address(local_address)
    assert udp[:4] == struct.pack('!HH', 53, source) and len(udp) == length and udp[8:] == reply
    pseudo = (packet[12:20]+b'\0\x11'+length.to_bytes(2, 'big') if family == 4
              else packet[8:40]+length.to_bytes(4, 'big')+b'\0\0\0\x11')
    if family == 4:
        assert shared.checksum(packet[:header]) == 65535 and int.from_bytes(packet[2:4], 'big') == len(packet)
    else:
        assert family == 6 and int.from_bytes(packet[4:6], 'big') == len(udp) and udp[6:8] != b'\0\0'
    if udp[6:8] != b'\0\0': assert shared.checksum(pseudo+udp) == 65535
    assert reply[:2] == query[:2]


def exchange(d, peer, result, label, address, query, reply, *, rcode=None, expected_upstream=1,
             original=False, tcp_retry=False, truncated=False, capacity=None, check=None,
             expect_reply=True, selected_port=None, hot=None, cold_label=None):
    selected_port = d.args.upstream_port if selected_port is None else selected_port
    source = d.reserve_source_port(label); cursor = peer.cursor()
    before = d.wire_coverage(label+'-before')
    # The first datagram's Unknown decision stays historical. Only the later
    # message on this exact live socket can use the normal UID lookup result.
    warm = d.question(cold_label or label+'-cold')
    warm_reply, _ = fixtures.answer(warm, 'ordinary'); peer.register(warm, warm_reply, port=selected_port)
    nonce = d.launch_queries(label, address, source, [warm, query], timeout=6000, pipeline=len(query)>=2, query_delay=150,
                             preserve_ui=hot is not None, initial_delay=3000 if hot else 0)
    if hot:
        point, gate, old = hot
        d.verify_ui_focus(label+'-hot-ready')
        d.await_peer_query(peer, label, query, port=selected_port, after=cursor, initial_delay=3000)
        d.save(label+'-hot-tap.txt', d.adb('shell', 'input', 'tap', *map(str, point)))
        applied = d.applied_status(label+'-hot', old['queryElapsedMillis'], previous_revision=int(old['activeRevision']))
        pending = d.proxy_ready(label+'-hot-pending')
        assert sum(int(row['transactions']) for row in pending) == 1, pending
        gate.touch(); d.verify_saved_source(label+'-hot')
        d.save(label+'-hot-publication.json', json.dumps(dict(applied=applied, pending=pending), indent=2)+'\n')
    client = d.client(label, nonce)
    assert client['uid'] == d.uid and len(client['dnsExchanges']) == 2, client
    cold, item = client['dnsExchanges']
    if cold.get('replyHex') != warm_reply.hex():
        d.observation(label+'-failed-cold-observation')
        d.cli(label+'-failed-cold-status', 'show product dns proxy')
    assert cold.get('sentHex') == warm.hex() and cold.get('replyHex') == warm_reply.hex(), cold
    assert item.get('sentHex') == query.hex(), item
    if expect_reply:
        assert item.get('replyHex'), item
        actual = bytes.fromhex(item['replyHex'])
        if reply is not None: assert actual == reply, (actual.hex(), reply.hex())
        shared.legal_reply(actual, query, rcode=rcode, truncated=truncated, capacity=capacity)
    else:
        assert item.get('timedOut') and not item.get('replyHex'), item
        actual = None
    identifier = int.from_bytes(query[:2], 'big') if len(query) >= 2 else 0
    selected = lambda v: [r for r in shared.dns_rows(v) if r['generation'] == d.generation
                          and r['id'] == identifier and r['source_port'] == source
                          and bool(r['proxy_flags'] & 1) != original]
    stage = (2 if original else 4) if expect_reply else 1
    observation = d.observation_matching(label, lambda v: any(r['stage'] == stage for r in selected(v)))
    records = selected(observation)
    cold_records = [r for r in shared.dns_rows(observation) if r['generation'] == d.generation
                    and r['id'] == int.from_bytes(warm[:2], 'big') and r['source_port'] == source
                    and bool(r['proxy_flags'] & 1) != original]
    assert cold_records and all(r['caller'] == 0 and r['uid'] == 4294967295 for r in cold_records), cold_records
    assert any(r['stage'] == (2 if original else 4) for r in cold_records), cold_records
    assert all(r['adapter_profile'] == 2 and r['uid'] == d.uid and r['caller'] == 1 for r in records), records
    if expect_reply and not original:
        terminal = [r for r in records if r['stage'] == 4]
        assert terminal and all(r['delivery'] == 2 and r['return_provenance'] == 3
                               and r['return_packet_uid'] == d.uid and r['transport_session'] > 0 for r in terminal), records
    if original:
        assert all(r['transport_session'] and r['underlay_epoch'] for r in records if r['stage'] == 2), records
    received = peer.received(query, port=selected_port, after=cursor)
    allowed_counts = expected_upstream if isinstance(expected_upstream, tuple) else (expected_upstream,)
    assert len(received) in allowed_counts, received
    if selected_port != 53: assert not peer.received(query, port=53, after=cursor)
    stream = peer.received(query, 'tcp', selected_port, after=cursor)
    assert len(stream) == int(tcp_retry), stream
    after = d.wire_coverage(label+'-after')
    wire = {k: rows[len(before[k]):] for k, rows in after.items()}
    original_wire = [r for r in wire['wlan0'] if r.get('kind') == 'udp'
                     and r['destination'] == address and r['destination_port'] == 53 and r['payload_hex'] == query.hex()]
    assert bool(original_wire) == original, original_wire
    returns = [r for r in wire[d.tun_interface] if r.get('kind') == 'udp' and r['source_port'] == 53
               and r['destination_port'] == source and actual is not None and r['payload_hex'] == actual.hex()]
    if expect_reply:
        assert returns, 'actual reply absent from independent TUN capture'
        for row in returns: legal_return(row, query, actual, address, source, client['local'])
    else:
        assert not any(r.get('kind') == 'udp' and r['source_port'] == 53 and r['destination_port'] == source
                       and r['payload_hex'] != warm_reply.hex() for r in wire[d.tun_interface])
    if check: check(records)
    d.expected_durable.extend(cold_records+records)
    for q, required in [(warm, [1, 2] if original else [1, 4]), (query, [1, stage])]:
        d.required_durable.append(dict(generation=d.generation, id=int.from_bytes(q[:2], 'big') if len(q) >= 2 else 0,
                                      source=source, proxy=not original, stages=sorted(set(required))))
    result['cases'].append(dict(label=label, status='PASS', generation=d.generation, owners=d.owners,
                               source='ordinary Java App same live DatagramSocket: cold Unknown then reliable caller',
                               source_port=source, query=query.hex(), reply=actual.hex() if actual is not None else None,
                               original=original, records=cold_records+records, peer_received=received,
                               peer_tcp=stream, passive_counts={k: len(v) for k, v in wire.items()}))
    d.save('progress.json', json.dumps(dict(status='IN_PROGRESS', generation=d.generation,
                                           cases=[r['label'] for r in result['cases']]), indent=2)+'\n')
    return records


def core_matrix(d, peer, result, owners):
    prefix = f'n{owners}'
    d.rules(prefix+'-allow'); d.upstream(prefix+'-selected4', d.args.endpoint4); d.proxy_ready(prefix+'-ready4')
    for family, address in [(4, d.args.endpoint4), (6, d.args.endpoint6)]:
        label = prefix+f'-client-v{family}-upstream4'; q = d.question(label); r, _ = fixtures.answer(q, 'ordinary')
        peer.register(q, r); exchange(d, peer, result, label, address, q, r)
    d.upstream(prefix+'-selected6', d.args.endpoint6); d.proxy_ready(prefix+'-ready6')
    for family, address in [(4, d.args.endpoint4), (6, d.args.endpoint6)]:
        label = prefix+f'-client-v{family}-upstream6'; q = d.question(label, 28); r, _ = fixtures.answer(q, 'ordinary')
        peer.register(q, r); exchange(d, peer, result, label, address, q, r)
    d.upstream(prefix+'-selected4-again', d.args.endpoint4); d.proxy_ready(prefix+'-ready4-again')
    kinds = (16, 15, 33, 65, 65000) if owners == 1 else (16, 65000)
    for kind in kinds:
        label = prefix+'-rr-edns-'+str(kind); q = d.question(label, kind, edns=True); r, _ = fixtures.answer(q, 'ordinary')
        peer.register(q, r); exchange(d, peer, result, label, d.args.endpoint4, q, r)
    for variant, response, mode in [('query-deny', 'ordinary', 0), ('alias-deny', 'alias', 0), ('query-deny', 'ordinary', 1)]:
        label = prefix+'-'+variant+'-mode'+str(mode); d.rules(label+'-rules', variant, mode=mode)
        q = d.question(label); r, _ = fixtures.answer(q, response); peer.register(q, r)
        denied = mode == 0
        exchange(d, peer, result, label, d.args.endpoint4, q, None if denied else r,
                 rcode=5 if denied else None, expected_upstream=0 if variant == 'query-deny' and denied else 1,
                 check=lambda rows, mode=mode: shared.assert_policy(rows, mode))
    d.rules(prefix+'-allow-after-policy')
    label = prefix+'-udp-tc-to-tcp'; q = d.question(label)
    truncated = struct.pack('!6H', int.from_bytes(q[:2], 'big'), 0x8380, 1, 0, 0, 0)+q[12:]
    r, _ = fixtures.answer(q, 'ordinary'); peer.register(q, truncated); peer.register(q, r, protocol='tcp', split=True)
    exchange(d, peer, result, label, d.args.endpoint4, q, r, tcp_retry=True, check=shared.assert_tcp)
    for edns, client_capacity in [(False, 512), (True, 1232)]:
        label = prefix+'-client-tc'+str(client_capacity); q = d.question(label, 16, edns=edns)
        name, _, end = fixtures.decode_question(q)
        r = struct.pack('!6H', int.from_bytes(q[:2], 'big'), 0x8180 | (0x10 if edns else 0), 1, 1, 0, 0)+q[12:end]+fixtures.rr(name, 16, (b'\xff'+b'Z'*255)*7)
        peer.register(q, r); exchange(d, peer, result, label, d.args.endpoint4, q, None,
                                    truncated=True, capacity=client_capacity)
    if owners == 1:
        for code in (0, 3, 5, 2):
            label = prefix+'-upstream-rcode'+str(code); q = d.question(label); _, _, end = fixtures.decode_question(q)
            r = struct.pack('!6H', int.from_bytes(q[:2], 'big'), 0x8180 | code, 1, 0, 0, 0)+q[12:end]
            peer.register(q, r); exchange(d, peer, result, label, d.args.endpoint4, q, r)
        for code in (1, 4):
            label = prefix+'-local-error'+str(code); q = d.question(label)
            q = q[:4]+bytes(8) if code == 1 else q[:2]+b'\x09\x00'+q[4:]
            exchange(d, peer, result, label, d.args.endpoint4, q, None, rcode=code, expected_upstream=0)
        label = prefix+'-no-reply-identity'; q = b'\x7b'
        exchange(d, peer, result, label, d.args.endpoint4, q, None, expected_upstream=0, expect_reply=False,
                 check=lambda rows: assert_result(rows, 10))
        label = prefix+'-transport-deadline'; q = d.question(label); r, _ = fixtures.answer(q, 'ordinary')
        peer.register(q, r, delay=3400)
        exchange(d, peer, result, label, d.args.endpoint4, q, None, rcode=2, expected_upstream=2,
                 check=lambda rows: shared.assert_resource(rows, 3))
        shared.system_unknown(d, peer, result, prefix+'-system-unknown')
    for family, address in [(4, d.args.endpoint4), (6, d.args.endpoint6)]:
        label = prefix+f'-disabled-direct-v{family}'; d.upstream(label+'-disable'); d.proxy_ready(label+'-ready', False)
        q = d.question(label); r, _ = fixtures.answer(q, 'ordinary'); peer.register(q, r, port=53)
        exchange(d, peer, result, label, address, q, r, original=True, selected_port=53)
    d.upstream(prefix+'-selected-restored', d.args.endpoint4); d.proxy_ready(prefix+'-selected-restored-ready')


def assert_result(rows, result):
    assert any(row['proxy_result'] == result and not row['output_bytes'] for row in rows), rows


def same_socket_toggle(d, peer, result, owners, family):
    label = f'n{owners}-same-socket-toggle-v{family}'
    address = d.args.endpoint4 if family == 4 else d.args.endpoint6
    d.rules(label+'-allow'); d.upstream(label+'-selected', address); d.proxy_ready(label+'-ready')
    source = d.reserve_source_port(label); before = d.wire_coverage(label+'-before'); cursor = peer.cursor()
    queries = [d.question(label+'-'+suffix) for suffix in ('cold', 'local', 'direct', 'local-again')]
    replies = [fixtures.answer(q, 'ordinary')[0] for q in queries]
    for i, (q, r) in enumerate(zip(queries, replies)): peer.register(q, r, port=53 if i == 2 else d.args.upstream_port)
    nonce = d.launch_queries(label, address, source, queries, timeout=5000, gate_reads=True, preserve_ui=True)
    for i in range(3):
        phase = 'dns_udp_read_'+str(i)
        value = d.phase(label, nonce, phase)
        assert value['dnsExchanges'][i].get('replyHex') == replies[i].hex(), value
        if i == 1:
            d.upstream(label+'-disable'); d.proxy_ready(label+'-disabled', False)
        elif i == 2:
            d.upstream(label+'-enable', address); d.proxy_ready(label+'-enabled')
        d.release_phase(label, nonce, phase)
    client = d.client(label, nonce)
    assert client['uid'] == d.uid and len(client['dnsExchanges']) == 4, client
    after = d.wire_coverage(label+'-after'); all_records = []
    for i, (q, r, item) in enumerate(zip(queries, replies, client['dnsExchanges'])):
        assert item.get('sentHex') == q.hex() and item.get('replyHex') == r.hex(), item
        original = i == 2; identifier = int.from_bytes(q[:2], 'big'); terminal = 2 if original else 4
        selected = lambda v: [row for row in shared.dns_rows(v) if row['generation'] == d.generation
                              and row['source_port'] == source and row['id'] == identifier
                              and bool(row['proxy_flags'] & 1) != original]
        observed = d.observation_matching(label+'-record-'+str(i), lambda v: any(row['stage'] == terminal for row in selected(v)))
        rows = selected(observed); all_records.extend(rows)
        # UI publication outlasts the short UDP UID-cache validity. The
        # transport session keeps its actual socket UID, but DNS policy must
        # report the caller available on each independent input packet.
        assert rows and all(row['adapter_profile'] == 2 for row in rows), rows
        if i == 0: assert all(row['caller'] == 0 and row['uid'] == 4294967295 for row in rows), rows
        if not original:
            assert all(row['delivery'] == 2 and row['return_provenance'] == 3 for row in rows if row['stage'] == 4), rows
        chosen = 53 if original else d.args.upstream_port
        assert len(peer.received(q, port=chosen, after=cursor)) == 1
        assert not peer.received(q, port=d.args.upstream_port if original else 53, after=cursor)
        wire = [row for row in after['wlan0'][len(before['wlan0']):] if row.get('kind') == 'udp'
                and row['destination'] == address and row['destination_port'] == 53 and row['payload_hex'] == q.hex()]
        assert bool(wire) == original, wire
        returned = [row for row in after[d.tun_interface][len(before[d.tun_interface]):]
                    if row.get('kind') == 'udp' and row['source_port'] == 53 and row['destination_port'] == source
                    and row['payload_hex'] == r.hex()]
        assert returned
        for row in returned: legal_return(row, q, r, address, source, client['local'])
        d.required_durable.append(dict(generation=d.generation, id=identifier, source=source,
                                      proxy=not original, stages=[1, terminal]))
    d.expected_durable.extend(all_records)
    result['cases'].append(dict(status='PASS', label=label, generation=d.generation, owners=owners,
        source='four distinct datagrams on one actual Java DatagramSocket; ordinary UI disable/enable before each first trigger',
        source_port=source, client=client, records=all_records, query_count=4, no_resend=True))


def vpn_capacity(d, peer, result, owners):
    label = f'n{owners}-capacity'; d.rules(label+'-allow'); d.upstream(label+'-selected', d.args.endpoint4)
    ready = d.proxy_ready(label+'-ready')
    assert all(row['transactions'] == row['replies'] == '0' for row in ready), ready
    source = d.reserve_source_port(label)
    before = d.wire_coverage(label+'-before'); cursor = peer.cursor()
    queries = [d.question(label+'-'+str(i)) for i in range(65)]
    for q in queries: peer.register(q, fixtures.answer(q, 'ordinary')[0], drop=True)
    nonce = d.launch_queries(label, d.args.endpoint4, source, queries, timeout=6000, pipeline=True)
    ids = {int.from_bytes(q[:2], 'big') for q in queries}
    selected = lambda v: [r for r in shared.dns_rows(v) if r['generation'] == d.generation
                          and r['source_port'] == source and r['id'] in ids and r['proxy_flags'] & 1]
    early = d.observation_matching(label+'-early', lambda v: any(r['stage'] == 3 and r['proxy_result'] == 6
                                                               for r in selected(v)), timeout=2)
    early_rows = selected(early); owner_set = {r['owner'] for r in early_rows}; assert len(owner_set) == 1, owner_set
    status_rows = d.proxy_ready(label+'-high-water'); status = status_rows[next(iter(owner_set))]
    assert int(status['transaction_high_water']) == int(status['transaction_limit']) == 64 and int(status['proxy_capacity']) >= 1, status
    for row in status_rows:
        assert int(row['proxy_high_water_bytes']) <= int(row['owner_work_bound']), row
        assert int(row['socket_high_water_bytes']) <= int(row['socket_byte_bound']), row
        assert int(row['upstream_socket_high_water']) <= int(row['upstream_socket_limit']) and int(row['sockets']) <= int(row['socket_limit']), row
    client = d.client(label, nonce)
    assert client['pipelineReceived'] == 65 and not client['pipelineUnmatched'], client
    for q, item in zip(queries, client['dnsExchanges']):
        shared.legal_reply(bytes.fromhex(item['replyHex']), q, rcode=2)
        d.required_durable.append(dict(generation=d.generation, id=int.from_bytes(q[:2], 'big'),
                                      source=source, proxy=True, stages=[1, 3, 4]))
    terminal = d.observation_matching(label+'-terminal', lambda v: any(r['stage'] == 3 and r['proxy_result'] == 3 for r in selected(v)))
    terminal_rows = selected(terminal); d.expected_durable.extend(early_rows+terminal_rows)
    received = [peer.received(q, after=cursor) for q in queries]
    assert sum(bool(rows) for rows in received) == 64 and sum(map(len, received)) == 128, list(map(len, received))
    after = d.wire_coverage(label+'-after')
    for q, item in zip(queries, client['dnsExchanges']):
        r = bytes.fromhex(item['replyHex'])
        returned = [row for row in after[d.tun_interface][len(before[d.tun_interface]):]
                    if row.get('kind') == 'udp' and row['source_port'] == 53 and row['destination_port'] == source and row['payload_hex'] == r.hex()]
        assert returned
        for row in returned: legal_return(row, q, r, d.args.endpoint4, source, client['local'])
        assert not any(row.get('kind') == 'udp' and row['destination_port'] == 53 and row['payload_hex'] == q.hex()
                       for row in after['wlan0'][len(before['wlan0']):])
    settled = d.proxy_ready(label+'-settled'); assert all(row['transactions'] == row['replies'] == '0' for row in settled), settled
    result['cases'].append(dict(status='PASS', label=label, generation=d.generation, owners=owners,
        source='65 distinct queries on one actual Java DatagramSocket, hashing to one actual owner', source_port=source,
        owner=next(iter(owner_set)), capacity_status=status_rows, settled=settled, client=client,
        early_records=early_rows, terminal_records=terminal_rows, unique_upstream_requests=64, total_upstream_datagrams=128,
        final_full_record_coverage='all65 query/error/delivery stages independently required in committed SQLite; public recent128 retained'))


def hot_policy(d, peer, result, owners):
    label = f'n{owners}-hot-policy'; d.rules(label+'-allow'); d.upstream(label+'-selected', d.args.endpoint4)
    d.proxy_ready(label+'-ready'); query = d.question(label); reply, _ = fixtures.answer(query, 'alias')
    gate = d.out/(label+'.gate'); peer.register(query, reply, gate=gate)
    point, old = d.rules(label+'-prefill', 'alias-deny', prefill=True)
    exchange(d, peer, result, label, d.args.endpoint4, query, None, rcode=5, expected_upstream=(1, 2),
             hot=(point, gate, old), check=lambda rows: shared.assert_hot(rows))
    d.rules(label+'-allow-restored')


def stop_and_late(d, peer, result, run, owners):
    """Stop an actual pending query, restart, then release its old peer reply."""
    label = f'n{owners}-stop-late'; d.rules(label+'-allow'); d.upstream(label+'-selected', d.args.endpoint4)
    d.proxy_ready(label+'-ready')
    run['durable_before_stop'] = d.durable(label+'-prior-durable')
    # The passive TUN interval ends while its interface is alive. WLAN stays
    # open to prove the old actual underlay reply after the old native stop.
    old_tun = d.tun_interface
    d.wire_stop(interfaces=[old_tun])
    before = d.wire_coverage(label+'-before')
    query = d.question(label); reply, _ = fixtures.answer(query, 'ordinary')
    # Keep the old independent reply through normal Stop/restart and full UI publication.
    # This fixture budget does not extend the Product request deadline.
    gate = d.out/(label+'.gate'); peer.register(query, reply, gate=gate, gate_seconds=120)
    source = d.reserve_source_port(label); cursor = peer.cursor(); old_generation = d.generation
    nonce = d.launch_queries(label, d.args.endpoint4, source, [query], timeout=5000, initial_delay=1000)
    d.await_peer_query(peer, label, query, port=d.args.upstream_port, after=cursor, initial_delay=1000)
    pending = d.proxy_ready(label+'-pending')
    assert sum(int(row['transactions']) for row in pending) == 1, pending
    run.update(d.stop(label))
    raw = (d.out/(label+'-stop.log')).read_text()
    quiesced = [props(line.replace(' ', '\n')) for line in raw.splitlines()
                if f'dns.proxy event=quiesce generation={old_generation} ' in line]
    assert sum(int(row['active_before']) for row in quiesced) == 1, quiesced
    assert sum(int(row['cancelled_now']) for row in quiesced) == 1, quiesced
    run['sqlite_after_stop'] = d.durable_readback(label)
    stopped_client = d.client(label, nonce)
    assert stopped_client['dnsExchanges'][0].get('timedOut') and not stopped_client['dnsExchanges'][0].get('replyHex'), stopped_client
    fresh = d.start(owners); result['runs'].append(fresh)
    assert d.generation > old_generation
    d.rules(label+'-fresh-allow'); d.upstream(label+'-fresh-selected', d.args.endpoint4); d.proxy_ready(label+'-fresh-ready')
    fresh_before = d.wire_coverage(label+'-fresh-before-old-release')
    d.forbid_udp_return(label,d.tun_interface,fresh_before[d.tun_interface],source,reply)
    gate.touch(); deadline = time.monotonic()+3
    while True:
        with peer.lock:
            sent = [row for row in peer.messages if row['kind'] == 'exchange' and row['request'] > cursor
                    and bytes.fromhex(row['request_hex'])[2:] == query[2:]]
        if sent: break
        assert time.monotonic() < deadline, 'old gated resolver did not actually write'; time.sleep(.01)
    after, arrived = shared.await_late_wire(d, label+'-late', before, sent)
    assert not any(row.get('kind') == 'udp' and row['source_port'] == 53 and row['destination_port'] == source
                   and row['payload_hex'] == reply.hex()
                   for row in after[d.tun_interface][len(fresh_before[d.tun_interface]):])
    result['cases'].append(dict(status='PASS', label=label, generation=old_generation, owners=owners,
        fresh_generation=d.generation, pending_status=pending, actual_quiesce=quiesced,
        client=stopped_client, old_peer_writes=sent, actual_late_wlan=arrived,
        scope='old TUN witness closed before pending query; actual pending stop cancels1, old App receives no reply; late old wire arrives with fresh generation active and produces no matching fresh TUN return',
        terminal_sqlite_qualification='prior completed cases independently durable; stop terminal history remains bounded and is not claimed lossless'))
    label += '-fresh-positive'; query = d.question(label); reply, _ = fixtures.answer(query, 'ordinary')
    peer.register(query, reply); exchange(d, peer, result, label, d.args.endpoint4, query, reply)
    return fresh


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('apk', 'stage', 'backup', 'output'): parser.add_argument('--'+key, type=Path, required=True)
    for key in ('endpoint4', 'endpoint6'): parser.add_argument('--'+key, required=True)
    parser.add_argument('--stale6', default='fd76:d462:c4e3::dead:beef')
    parser.add_argument('--owners', default='1', choices=('1', '3', '1,3'))
    parser.add_argument('--matrix', default='minimal', choices=('minimal', 'path-control', 'endpoint-control', 'core', 'lifecycle', 'capacity', 'full'))
    parser.add_argument('--peer', choices=('windows', 'linux'), default='windows')
    parser.add_argument('--installed', action='store_true'); parser.add_argument('--trace', action='store_true')
    parser.add_argument('--cc', default='/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang')
    args = parser.parse_args(); args.profile = 'vpn'; args.upstream_port = 53054 if args.peer == 'linux' else 53053
    for key in ('apk', 'stage', 'backup', 'output'): setattr(args, key, getattr(args, key).resolve())
    args.output.mkdir(parents=True, exist_ok=False)
    baseline = json.loads((args.backup/'manifest.json').read_text())
    assert baseline['status'] == 'PASS' and baseline['state'] == 'stopped' and int(baseline['generation']) >= 2727
    result = dict(status='HOLD', task='SAKAMOTO-316', apk_sha256=digest(args.apk),
                  backup_manifest_sha256=digest(args.backup/'manifest.json'), cases=[], runs=[], started_ns=time.time_ns())
    closure = [Path(__file__), ROOT/'tests/device/s315-root-dns-proxy.py',
               ROOT/'tests/device/s313-root-dns-tcp.py', ROOT/'tests/device/s312-dns-response.py',
               ROOT/'tests/device/s233-fail-open.py', ROOT/'tests/device/helpers/s312_dns_fixtures.py',
               ROOT/'tests/device/helpers/s315_dns_stale_return.c',
               ROOT/'tests/device/helpers/s315_dns_wire.c', ROOT/'tests/device/helpers/s315_dns_peer.ps1',
               ROOT/'tests/device/helpers/s316_dns_peer.py',
               ROOT/'tests/device/helpers/s314_adb_trace.py', ROOT/'tests/device/helpers/s314_adb_route.py', ROOT/'dev/adb']
    result['source_sha256'] = {str(p.relative_to(ROOT)): digest(p) for p in closure}
    for p in closure: (args.output/('source-'+str(p.relative_to(ROOT)).replace('/', '__'))).write_bytes(p.read_bytes())
    d = Device(args); peer = None; failure = None
    try:
        result['native'] = d.install(); d.wire_start()
        peer = shared.Peer([args.endpoint4, args.endpoint6], args.output, d.capture_deadline)
        if args.peer == 'linux': peer = linux_peer.CombinedPeer(peer, [args.endpoint4, args.endpoint6], args.output, d.capture_deadline)
        result['selected_peer'] = dict(backend=args.peer, port=args.upstream_port,
            original53='existing independently owned Windows peer', source='ordinary complete DNS config')
        for owners in map(int, args.owners.split(',')):
            run = d.start(owners); result['runs'].append(run)
            if args.matrix == 'endpoint-control':
                assert args.peer == 'linux'
                d.rules(f'n{owners}-allow')
                for backend, port in [('linux', 53054), ('windows', 53053)]:
                    label = f'n{owners}-endpoint-control-'+backend
                    d.upstream(label+'-selected', args.endpoint4, port); d.proxy_ready(label+'-ready')
                    qname_label = f'n{owners}-client-v4-upstream4'
                    query = d.question(qname_label); reply, _ = fixtures.answer(query, 'ordinary')
                    peer.register(query, reply, port=port)
                    exchange(d, peer, result, label, args.endpoint4, query, reply, selected_port=port,
                             cold_label=qname_label+'-cold')
                    run[backend+'_durable'] = d.durable(label+'-durable')
            elif args.matrix in ('minimal', 'path-control'):
                d.rules(f'n{owners}-allow'); d.upstream(f'n{owners}-selected', args.endpoint4); d.proxy_ready(f'n{owners}-ready')
                labels = ([f'n{owners}-minimal'] if args.matrix == 'minimal' else
                          [f'n{owners}-transport-control', f'n{owners}-client-v4-upstream4'])
                for label in labels:
                    query = d.question(label); reply, _ = fixtures.answer(query, 'ordinary'); peer.register(query, reply)
                    exchange(d, peer, result, label, args.endpoint4, query, reply)
            else:
                if args.matrix in ('core', 'full'): core_matrix(d, peer, result, owners)
                if args.matrix in ('lifecycle', 'full'):
                    for family in (4, 6): same_socket_toggle(d, peer, result, owners, family)
                    hot_policy(d, peer, result, owners)
                if args.matrix in ('capacity', 'full'): vpn_capacity(d, peer, result, owners)
                if args.matrix in ('lifecycle', 'full'): run = stop_and_late(d, peer, result, run, owners)
            run['durable_before_stop'] = d.durable(f'n{owners}-durable')
            d.wire_stop()  # TUN witness must finish before Android removes the interface.
            run.update(d.stop(f'n{owners}'))
            run['sqlite_after_stop'] = d.durable_readback(f'n{owners}')
            if owners != int(args.owners.split(',')[-1]): d.wire_start()
        result['status'] = 'PASS_ACTUAL_VPN_APP_'+args.matrix.upper()
    except BaseException as error:
        failure = error; result.update(error=repr(error), traceback=traceback.format_exc())
    finally:
        errors = []; envelope = shared.CleanupEnvelope(65, [('wire', 20), ('stop', 25), ('reader', 5), ('peer', 10), ('trace', 5)])
        def finish(name, action):
            try:
                with envelope.phase(d, name) as deadline: action(deadline)
            except BaseException as error: errors.append(name+': '+repr(error))
        if getattr(d, 'pending_dns_gates', []):
            try: d.release_pending_gates()
            except BaseException as error: errors.append('probe-gates: '+repr(error))
        if d.witnesses: finish('wire', lambda _: d.wire_stop())
        if (d.active or d.stop_owed) and getattr(d, 'stop_retry_authorized', True): finish('stop', lambda _: d.stop('failure-cleanup'))
        elif d.active or d.stop_owed: errors.append('runtime stop is fenced pending remote completion')
        if d.reader: finish('reader', lambda _: d.settle_reader('failure-cleanup'))
        if peer:
            def close_peer(deadline):
                peer.deadline = deadline; peer.close()
            finish('peer', close_peer)
        finish('trace', lambda _: d.close_trace())
        if errors: result.update(status='HOLD', cleanup_errors=errors)
        result['completed_ns'] = time.time_ns()
        (args.output/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k: result.get(k) for k in ('status', 'error', 'cleanup_errors')}))
    if failure or errors: raise SystemExit(1)


if __name__ == '__main__': main()
