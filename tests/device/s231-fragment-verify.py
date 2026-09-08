#!/usr/bin/env python3
"""Independent PCAP/NFQUEUE shape oracle; it never runs Product reassembly."""
import collections
import ipaddress
import struct


def rows(text, prefix):
    return [dict(x.split('=',1) for x in line.split()[1:] if '=' in x)
            for line in text.splitlines() if line.startswith(prefix)]


def checksum(data):
    if len(data)%2: data += b'\0'
    value = sum(struct.unpack('!'+str(len(data)//2)+'H',data))
    while value >> 16: value = (value & 65535)+(value >> 16)
    return (~value) & 65535


def packet(raw):
    assert raw, 'empty IP packet'
    family = raw[0] >> 4
    if family == 4:
        header = (raw[0] & 15)*4
        assert 20 <= header <= len(raw) and int.from_bytes(raw[2:4],'big') == len(raw), 'IPv4 length'
        assert checksum(raw[:header]) == 0, 'IPv4 header checksum'
        flags = int.from_bytes(raw[6:8],'big')
        offset, more = (flags & 8191)*8, bool(flags & 8192)
        protocol = raw[9]
        source, destination = raw[12:16], raw[16:20]
        identity = int.from_bytes(raw[4:6],'big')
        fragmented = bool(offset or more)
    elif family == 6:
        assert len(raw) >= 40 and int.from_bytes(raw[4:6],'big')+40 == len(raw), 'IPv6 length'
        source, destination = raw[8:24], raw[24:40]
        protocol = raw[6]
        fragmented = protocol == 44
        header, offset, more, identity = 40, 0, False, None
        if fragmented:
            assert len(raw) >= 48, 'IPv6 Fragment header'
            header = 48; protocol = raw[40]
            flags = int.from_bytes(raw[42:44],'big')
            offset, more = flags & 65528, bool(flags & 1)
            identity = int.from_bytes(raw[44:48],'big')
    else:
        raise AssertionError('unknown IP family')
    return dict(raw=raw,family=family,source=str(ipaddress.ip_address(source)),
                destination=str(ipaddress.ip_address(destination)),source_bytes=source,destination_bytes=destination,
                protocol=protocol,fragmented=fragmented,id=identity,offset=offset,more=more,
                body=raw[header:],header=header)


def pcap(data):
    assert len(data) >= 24 and data[:4] == b'\xd4\xc3\xb2\xa1', 'PCAP magic'
    magic,major,minor,zone,sigfigs,snaplen,linktype = struct.unpack_from('<IHHIIII',data)
    assert major == 2 and minor == 4 and linktype == 1 and snaplen == 8192, 'PCAP format'
    position, all_records, packets = 24, 0, []
    while position < len(data):
        assert len(data)-position >= 16, 'truncated PCAP record'
        seconds,microseconds,size,original = struct.unpack_from('<IIII',data,position); position += 16
        assert size == original and 14 <= size <= snaplen and position+size <= len(data), 'truncated link packet'
        frame = data[position:position+size]; position += size
        if frame[12:14] in (b'\x08\x00',b'\x86\xdd'):
            p = packet(frame[14:]); p.update(record=all_records,timestamp_us=seconds*1_000_000+microseconds)
            packets.append(p)
        all_records += 1
    return packets, all_records


def assemble(packets):
    assert packets, 'no pieces to compare'
    if len(packets) == 1 and not packets[0]['fragmented']: return packets[0]['body']
    assert all(p['fragmented'] for p in packets), 'mixed whole/fragment representation'
    position, result = 0, b''
    for index,p in enumerate(sorted(packets,key=lambda p:p['offset'])):
        assert p['offset'] == position, 'fragment gap/overlap/duplicate'
        assert p['more'] == (index != len(packets)-1), 'fragment final marker'
        if p['more']: assert len(p['body']) % 8 == 0, 'non-final fragment alignment'
        result += p['body']; position += len(p['body'])
    return result


def udp_valid(p, body):
    assert len(body) >= 8 and int.from_bytes(body[4:6],'big') == len(body), 'UDP declared length'
    if p['family'] == 4:
        pseudo = p['source_bytes']+p['destination_bytes']+b'\0\x11'+struct.pack('!H',len(body))
    else:
        pseudo = p['source_bytes']+p['destination_bytes']+struct.pack('!I',len(body))+b'\0\0\0\x11'
    assert checksum(pseudo+body) == 0, 'independent UDP checksum'


def verify_case(case, trace, runtime, wire_data, capture_log, send_logs, endpoint):
    generation = str(case['generation'])
    nfq_rows = rows(trace,'s231 ')
    nfq, indexed = [], {}
    for row in nfq_rows:
        assert row['event'] == 'nfq_payload' and row['source'] == 'NFQ_CAPTURED', 'actual NFQUEUE source provenance'
        assert row['generation'] == generation and row['token'] not in indexed
        p = packet(bytes.fromhex(row['raw']))
        assert len(p['raw']) == int(row['payload_bytes']) and p['family'] == int(row['family'])
        assert row['cap_len_known'] in ('0','1') and row['skb_info_known'] in ('0','1')
        if row['cap_len_known'] == '1': assert row['cap_len'] == row['payload_bytes'], 'NFQ payload truncated'
        else: assert row['cap_len'] == '0', 'absent cap length fabricated'
        if row['skb_info_known'] == '0': assert row['skb_info'] == '0', 'absent SKB flags fabricated'
        p['record'] = row; nfq.append(p); indexed[row['token']] = p
    assert nfq, 'no actual Product NFQUEUE observation'
    tables = {}
    for name,prefix,filter_key,filter_value,key in (
        ('capture','s203 ','event','capture','obligation'), ('accept','s203 ','event','frame_accept','obligation'),
        ('admit','s216 ','stage','admit','token'), ('terminal','s216 ','stage','terminal','token'),
        ('publish','s204 ','event','completion_publish','token'), ('consume','s204 ','event','completion_consume','token'),
        ('origin','s210 ','event','origin_completion','token'), ('verdict','s203 ','event','verdict','obligation'),
        ('free','s203 ','event','buffer_free','obligation')):
        table = {}
        for row in rows(trace,prefix):
            if row.get(filter_key) != filter_value: continue
            assert row[key] not in table, f'duplicate {name}'
            table[row[key]] = row
        assert set(table) == set(indexed), f'{name} NFQ carrier conservation'
        tables[name] = table
    policy_rows = [r for r in rows(trace,'s216 ') if r.get('stage') == 'policy']
    policy = {r['token']:r for r in policy_rows}
    assert len(policy) == len(policy_rows) and set(policy) <= set(indexed), 'policy carrier provenance'
    for token,p in indexed.items():
        original = p['record']
        for name in ('capture','accept','admit','terminal','publish','consume','origin','free'):
            assert tables[name][token]['buffer'] == original['buffer'], 'native buffer identity'
        for name in ('capture','accept','publish','consume','origin','verdict'):
            r = tables[name][token]
            assert r['packet'] == original['packet'] and r['lane'] == original['lane'], 'original NFQ packet ID/lane'
        for name in ('accept','admit','terminal','publish','consume','origin','verdict'):
            assert tables[name][token]['generation'] == generation, 'original generation'
        for name in ('capture','accept','consume','origin','verdict','free'):
            assert tables[name][token]['thread'] == original['thread'], 'origin lane thread'
        admit = tables['admit'][token]
        assert admit['raw'] == original['raw'], 'payload changed before graph admission'
        assert admit['direction'] == original['hook'] and admit['provenance'] == '1' and admit['completion_kind'] == '1'
        assert admit['queue_generation'] == generation and admit['packet_id'] == original['packet']
        assert int(original['queue']) == 176+int(original['lane'])
        assert int(original['thread']) == int(original['lane'])%2+1
        intent = tables['terminal'][token]['intent']
        assert intent in ('1','2'), 'unexpected capacity bypass in visibility test'
        for name in ('publish','consume','origin'): assert tables[name][token]['intent'] == intent
        verdict = '1' if intent == '1' else '0'
        assert tables['origin'][token]['verdict'] == tables['verdict'][token]['verdict'] == verdict
        p['verdict'] = int(verdict); p['drop_reason'] = int(tables['origin'][token]['drop_reason'])
        if p['family'] == 4 and p['fragmented']:
            assert token not in policy and intent == '2' and p['drop_reason'] == 1, 'current IPv4 fragment rejection mislabeled policy'
        else:
            assert token in policy and policy[token]['worker'] == admit['owner'], 'actual policy owner'
    wire, record_count = pcap(wire_data)
    assert len(rows(capture_log,'capture.packet ')) == record_count
    assert int(rows(capture_log,'capture.closed ')[0]['packets']) == record_count, 'capture not cleanly closed'
    expected_hook = '1' if case['hook'] == 'INPUT' else '3'
    results = []
    for fragment_case in case['fragments']:
        sent = [packet(bytes.fromhex(r['raw'])) for r in rows(send_logs[fragment_case['nonce']],'send ')]
        assert len(sent) == 2 and all(p['fragmented'] and p['id'] == fragment_case['id'] for p in sent), 'sent fragment identity'
        assert [p['offset'] for p in sent] == ([48,0] if fragment_case['reverse'] else [0,48]), 'sent order'
        body = assemble(sent); udp_valid(sent[0],body)
        nonce = fragment_case['nonce'].encode()
        assert body[8:].startswith(nonce+b'\n') and body[8+len(nonce)+1:] == b'~'*(96-len(nonce)-1), 'fresh fragment payload'
        match = lambda p: p['family'] == case['family'] and p['source'] == fragment_case['source'] and p['destination'] == fragment_case['destination'] and (
            p['fragmented'] and p['id'] == fragment_case['id'] or not p['fragmented'] and nonce in p['body'])
        actual = [p for p in nfq if match(p)]
        assert actual and all(p['record']['hook'] == expected_hook for p in actual), 'fragment datagram did not reach intended NFQ hook'
        if all(p['fragmented'] for p in actual):
            shape = 'ORIGINAL_FRAGMENTS'
            assert [p['raw'] for p in actual] == [p['raw'] for p in sent], 'original fragments altered/reordered at NFQ'
        else:
            shape = 'KERNEL_REASSEMBLED'
            assert len(actual) == 1 and not actual[0]['fragmented'] and actual[0]['protocol'] == 17, 'ambiguous NFQ representation'
        assert assemble(actual) == body, 'NFQ datagram bytes differ from real sender'
        wire_pieces = [p for p in wire if match(p)]
        if case['hook'] == 'OUTPUT' and case['family'] == 6 and shape == 'KERNEL_REASSEMBLED':
            # IPv6 defrag removes the Fragment header. Subsequent kernel
            # refragmentation chooses a new IP fragment ID, distinct from
            # the NFQUEUE packet ID. Bind it by the unique UDP nonce first.
            starts = [p for p in wire if p['source'] == fragment_case['source']
                      and p['destination'] == fragment_case['destination']
                      and nonce in p['body']]
            assert len(starts) == 1, 'ambiguous IPv6 refragmentation nonce'
            first = starts[0]
            wire_pieces = [p for p in wire if p['source'] == first['source']
                           and p['destination'] == first['destination']
                           and p['id'] == first['id'] and p['fragmented'] == first['fragmented']]
        if case['hook'] == 'INPUT':
            assert [p['raw'] for p in wire_pieces] == [p['raw'] for p in sent], 'independent INPUT capture lacks original fragments'
        elif all(p['verdict'] == 0 for p in actual):
            assert not wire_pieces, 'runtime-dropped OUTPUT fragment reached link'
        else:
            assert wire_pieces and assemble(wire_pieces) == body, 'OUTPUT link/sender correspondence'
        received = endpoint.count(fragment_case['nonce'])
        if case['hook'] == 'INPUT':
            assert received == int(all(p['verdict'] == 1 for p in actual)), 'INPUT echo differs from actual disposition'
        results.append(dict(id=fragment_case['id'],reverse=fragment_case['reverse'],shape=shape,
                            nfq_packets=len(actual),wire_packets=len(wire_pieces),verdicts=[p['verdict'] for p in actual],
                            wire_fragment_ids=sorted({p['id'] for p in wire_pieces if p['fragmented']}),
                            identities=[{k:p['record'][k] for k in ('generation','packet','token','lane','thread','hook','payload_bytes','skb_info_known','skb_info')} for p in actual]))
    for control in case['peer_controls']:
        nonce = control['nonce'].encode()
        actual = [p for p in nfq if nonce in p['body']]
        link = [p for p in wire if nonce in p['body'] and p['destination'] in ('198.18.231.2','fd20:6231::2')]
        assert len(actual) == len(link) == 1 and not actual[0]['fragmented'] and actual[0]['verdict'] == 1, 'complete peer control missing'
        assert actual[0]['raw'] == link[0]['raw'] and endpoint.count(control['nonce']) == 1, 'peer control preservation/delivery'
    kernel = None
    if 'kernel_nonce' in case:
        nonce = case['kernel_nonce'].encode()
        actual = [p for p in nfq if nonce in p['body']]
        assert len(actual) == 1 and not actual[0]['fragmented'] and actual[0]['verdict'] == 1, 'kernel UDP was not a whole LOCAL_OUT packet'
        start = [p for p in wire if nonce in p['body']]
        assert len(start) == 1 and start[0]['fragmented'], 'kernel UDP did not fragment on independent link'
        pieces = [p for p in wire if p['fragmented'] and p['id'] == start[0]['id'] and p['source'] == start[0]['source'] and p['destination'] == start[0]['destination']]
        body = assemble(pieces)
        assert len(pieces) >= 2 and len(body) == 1308 and body[8:].startswith(nonce+b'\n'), 'kernel fragment body'
        assert body[8:] == actual[0]['body'][8:] and body[:6] == actual[0]['body'][:6], 'LOCAL_OUT/link UDP bytes'
        udp_valid(pieces[0],body)
        kernel = dict(shape='PRE_FRAGMENTATION_PACKET',nfq_packets=1,nfq_bytes=len(actual[0]['raw']),wire_fragments=len(pieces),wire_bytes=[len(p['raw']) for p in pieces])
    for probe in case['probes']:
        actual = [p for p in nfq if probe['nonce'].encode() in p['raw']]
        if probe['expected'] == 'drop':
            assert len(actual) == 1 and actual[0]['verdict'] == 0 and actual[0]['drop_reason'] == 7, 'Gate DROP regression'
            assert probe['nonce'] not in endpoint
        else:
            assert len(actual) == 2 and {p['record']['hook'] for p in actual} == {'1','3'} and all(p['verdict'] == 1 for p in actual), 'ordinary echo regression'
            assert endpoint.count(probe['nonce']) == 1, 'ordinary endpoint echo'
    lanes = rows(runtime,'root.lane ')
    assert len(lanes) == 4 and sum(int(l['captured']) for l in lanes) == len(nfq), 'full NFQ trace coverage'
    for lane in lanes:
        assert len({lane[k] for k in ('captured','submitted','verdicts','succeeded','returns')}) == 1, 'lane conservation'
        assert lane['pending'] == lane['failed'] == lane['duplicate'] == '0'
    completion = rows(runtime,'completion.status ')[0]
    assert all(completion[k] == '0' for k in ('pending','frames','buffers','obligations','duplicate','stale'))
    native = collections.Counter(); thread = None
    for line in runtime.splitlines():
        if line.startswith('Thread '): thread = line.split()[1]
        fields = line.split()
        if thread is not None and len(fields) >= 4 and fields[0].startswith('product-packet-') and fields[2].isdigit() and fields[3].isdigit():
            native[(thread,fields[0])] = int(fields[3])
    for name, table in (('product-packet-admit',tables['admit']),('product-packet-policy',policy),
                        ('product-packet-terminal',tables['terminal']),('product-packet-origin-completi',tables['consume'])):
        expected = collections.Counter(r['thread'] for r in table.values())
        assert all(native[(str(t),name)] == expected[str(t)] for t in range(3)), 'native node/thread vectors '+name
    return dict(generation=generation,family=case['family'],hook=case['hook'],packets=len(nfq),raw=results,kernel_udp=kernel,
                wire_records=record_count,ordinary_probes=len(case['probes']))
