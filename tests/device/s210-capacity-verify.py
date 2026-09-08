#!/usr/bin/env python3
"""Independent per-carrier oracle for S210; no product implementation imports."""
import collections
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('owner_oracle', ROOT/'tests/device/s207-owner-oracle.py')
owner_oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner_oracle)


def rows(text, prefix):
    return [dict(part.split('=', 1) for part in line.split()[1:] if '=' in part)
            for line in text.splitlines() if line.startswith(prefix)]


def verify_case(case, trace, runtime, endpoint):
    generation = str(case['generation'])
    s203, s204 = rows(trace, 's203 '), rows(trace, 's204 ')
    s205, s207 = rows(trace, 's205 '), rows(trace, 's207 ')
    s208, s209 = rows(trace, 's208 '), rows(trace, 's209 ')
    s210, facts = rows(trace, 's210 '), rows(trace, 's216 ')
    tables = {}
    for name, source, field, value, token_field in (
        ('capture', s203, 'event', 'capture', 'obligation'),
        ('accept', s203, 'event', 'frame_accept', 'obligation'),
        ('admit', facts, 'stage', 'admit', 'token'),
        ('terminal', facts, 'stage', 'terminal', 'token'),
        ('policy', s203, 'event', 'policy', 'obligation'),
        ('policy_facts', facts, 'stage', 'policy', 'token'),
        ('publish', s204, 'event', 'completion_publish', 'token'),
        ('consume', s204, 'event', 'completion_consume', 'token'),
        ('origin', s210, 'event', 'origin_completion', 'token'),
        ('verdict', s203, 'event', 'verdict', 'obligation'),
        ('free', s203, 'event', 'buffer_free', 'obligation'),
        ('primary', s205, 'event', 'primary_accepted', 'token'),
        ('dequeue', s205, 'event', 'primary_dequeue', 'token'),
        ('reject', s210, 'event', 'primary_rejected', 'token'),
        ('defer', s210, 'event', 'completion_deferred', 'token'),
        ('return', s205, 'event', 'completion_return_accepted', 'token'),
    ):
        table = {}
        for row in source:
            if row.get(field) != value: continue
            token = row[token_field]
            assert token not in table, f'duplicate {name} token={token}'
            table[token] = row
        tables[name] = table
    tokens = set(tables['capture'])
    assert tokens, 'no actual NFQUEUE carriers'
    for name in ('accept', 'admit', 'terminal', 'publish', 'consume', 'origin', 'verdict', 'free'):
        assert set(tables[name]) == tokens, f'{name} carrier conservation'
    for name, table in tables.items():
        assert set(table) <= tokens, f'{name} unknown carrier'
    nonce_tokens = {}
    accepted_nonces, dropped_nonces = [], []
    dispositions = collections.Counter()
    maxima = dict(settlement_ns=0, bypass_settlement_ns=0, deferred_settlement_ns=0)
    bypass_before_held_release = 0
    hold_ends = [int(r['mono_ns']) for r in s209 if r.get('event') == 'hold_end']
    assert len(hold_ends) == 1, 'exactly one bounded owner hold'
    for token in tokens:
        packet = {name: table.get(token) for name, table in tables.items()}
        admit, terminal = packet['admit'], packet['terminal']
        origin, intent = packet['origin'], int(terminal['intent'])
        for name in ('accept', 'admit', 'terminal', 'publish', 'consume', 'origin', 'verdict'):
            assert packet[name]['generation'] == generation, f'{name} original generation token={token}'
        for name in ('capture', 'accept', 'admit', 'terminal', 'publish', 'consume', 'origin', 'free'):
            assert packet[name]['buffer'] == admit['buffer'], f'{name} retained buffer token={token}'
        for name in ('capture', 'accept', 'publish', 'consume', 'origin', 'verdict'):
            assert packet[name]['lane'] == admit['origin_lane'], f'{name} origin lane token={token}'
            assert packet[name]['packet'] == admit['packet_id'], f'{name} original packet ID token={token}'
        for name in ('capture', 'accept', 'consume', 'origin', 'verdict', 'free'):
            assert packet[name]['thread'] == admit['thread'], f'{name} origin thread token={token}'
        assert packet['capture']['tls'] == packet['capture']['polling_thread'] == admit['thread']
        assert admit['source'] == 'NFQ_CAPTURED' and admit['provenance'] == '1'
        assert admit['completion_kind'] == '1' and admit['queue_generation'] == generation
        assert int(admit['thread']) == int(admit['worker'])+1
        assert int(admit['origin_lane']) % 2 == int(admit['worker'])
        assert int(packet['capture']['queue']) == 176+int(admit['origin_lane'])
        immutable = set(admit)-{'stage', 'node', 'thread', 'worker', 'intent', 'raw', 'mono_ns'}
        for key in immutable:
            assert terminal[key] == admit[key], f'terminal facts changed {key} token={token}'
        numeric = {'l3','l4','family','protocol','icmp_known','icmp_code','icmp_type','icmp_id','src_port','dst_port'}
        assignment = owner_oracle.assignment({k: int(v) if k in numeric else v for k,v in admit.items()})
        assert int(admit['owner']) == assignment['owner'], f'independent canonical owner token={token}'
        keys = [r for r in s207 if r.get('token') == token]
        assert {r['stage'] for r in keys} == ({'admit', 'terminal'} if intent == 3 else {'admit', 'policy', 'terminal'})
        original_key = next(r for r in keys if r['stage'] == 'admit')
        assert all(original_key[k] == str(v) for k,v in assignment.items()), 'independent complete typed assignment'
        for key in keys:
            assert {k:v for k,v in key.items() if k not in ('stage','thread')} == {
                k:v for k,v in original_key.items() if k not in ('stage','thread')}, 'owner assignment changed'
        assert intent in (1, 2, 3), f'unsupported terminal intent={intent}'
        for name in ('publish', 'consume', 'origin'):
            assert int(packet[name]['intent']) == intent, f'{name} terminal disposition changed'
        assert packet['publish']['frame_bytes'] == '32'
        assert packet['consume']['producer_thread'] == terminal['thread']
        expected_verdict = 0 if intent == 2 else 1
        assert int(packet['verdict']['verdict']) == int(origin['verdict']) == expected_verdict, 'NFQUEUE verdict changed'
        elapsed = int(packet['consume']['mono_ns'])-int(admit['mono_ns'])
        assert 0 <= elapsed <= 8_000_000_000, f'bounded settlement token={token} elapsed={elapsed}'
        maxima['settlement_ns'] = max(maxima['settlement_ns'], elapsed)
        dispositions[intent] += 1
        if intent == 3:
            assert packet['reject'] is not None, 'bypass without retained rejection'
            reason = packet['reject']['reason']
            assert reason in ('1', '2') and origin['bypass_reason'] == reason, 'missing or changed processing-capacity bypass reason'
            assert origin['drop_reason'] == '0', 'bypass mislabeled runtime DROP'
            assert packet['reject']['intent'] == '3' and packet['reject']['retained'] == '1'
            assert packet['reject']['policy_evaluated'] == '0'
            assert packet['primary'] is packet['dequeue'] is packet['policy'] is packet['policy_facts'] is None, 'bypass entered policy or transferred ownership'
            assert not any(r.get('token') == token for r in s208+s209), 'bypass fabricated policy/cache activity'
            assert terminal['thread'] == admit['thread'], 'bypass left origin execution context'
            assert packet['return'] is packet['defer'] is None, 'bypass used remote completion'
            maxima['bypass_settlement_ns'] = max(maxima['bypass_settlement_ns'], elapsed)
            if reason == '2' and int(packet['consume']['mono_ns']) < hold_ends[0]:
                bypass_before_held_release += 1
        else:
            assert packet['reject'] is None and origin['bypass_reason'] == '0'
            assert packet['policy'] is not None and packet['policy_facts'] is not None, 'normal packet skipped policy'
            assert int(terminal['worker']) == assignment['owner']
            for key in immutable:
                assert packet['policy_facts'][key] == admit[key], f'policy facts changed {key}'
            assert int(packet['policy']['verdict']) == (2 if intent == 2 else 1), 'Policy Verdict disagrees with terminal'
            if intent == 2:
                assert origin['drop_reason'] in ('7', '8'), 'DROP lost original policy reason'
            else:
                assert origin['drop_reason'] == '0'
            if admit['worker'] != admit['owner']:
                assert packet['primary'] is not None and packet['dequeue'] is not None and packet['return'] is not None
                assert packet['primary']['target_thread'] == terminal['thread'] == packet['dequeue']['thread']
                assert packet['dequeue']['primary'] == '1' and packet['dequeue']['corrective'] == '0'
            else:
                assert packet['primary'] is packet['dequeue'] is packet['return'] is None
        if packet['defer'] is not None:
            assert intent == 2 and packet['defer']['intent'] == '2', 'completion pressure changed Policy DROP'
            assert packet['defer']['drop_reason'] == origin['drop_reason']
            assert 0 < int(packet['defer']['pending']) <= int(packet['defer']['capacity']) == 512
            assert packet['return'] is not None, 'retained completion never published'
            maxima['deferred_settlement_ns'] = max(maxima['deferred_settlement_ns'], elapsed)
        if admit.get('protocol') == '17':
            raw = bytes.fromhex(admit['raw'])
            nonce = raw[int(admit['l3_length'])+8:].decode(errors='replace').strip()
            if nonce.startswith(f's210-{generation}-'):
                assert nonce not in nonce_tokens, 'duplicate wire nonce'
                nonce_tokens[nonce] = token
                (dropped_nonces if intent == 2 else accepted_nonces).append(nonce)
    assert set(nonce_tokens) == set(case['sent']) and len(case['sent']) == len(nonce_tokens), 'sent/NFQUEUE nonce conservation'
    for phase, names in case['phases'].items():
        if phase == 'credit':
            assert all(tables['reject'][nonce_tokens[n]]['reason'] == '1' for n in names)
        elif phase == 'enqueue':
            assert any(tables['reject'].get(nonce_tokens[n], {}).get('reason') == '2' for n in names)
        elif phase.startswith('drop-'):
            assert all(tables['terminal'][nonce_tokens[n]]['intent'] == '2' for n in names), 'DROP phase did not reach policy'
        elif 'recovery' in phase or phase.startswith('warm-') or phase == 'held':
            assert all(tables['terminal'][nonce_tokens[n]]['intent'] == '1' for n in names), 'normal/recovery traffic bypassed policy'
    assert bypass_before_held_release > 0, 'enqueue rejection waited for held owner'
    assert tables['defer'], 'no actual completion-return pressure'
    assert collections.Counter(case['received']) == collections.Counter(accepted_nonces), 'receiver/ACCEPT correspondence'
    observed_endpoint = [n for n in endpoint if n.startswith(f's210-{generation}-')]
    assert collections.Counter(observed_endpoint) == collections.Counter(accepted_nonces), 'independent endpoint/ACCEPT correspondence'
    assert not set(dropped_nonces) & set(observed_endpoint), 'Policy DROP delivered'
    lanes = rows(runtime, 'root.lane ')
    assert len(lanes) == 4
    assert sum(int(l['captured']) for l in lanes) == len(tokens), 'trace coverage incomplete'
    for lane in lanes:
        assert len({lane[k] for k in ('captured','submitted','verdicts','succeeded','returns')}) == 1, 'lane conservation or ingress fail-open'
        assert lane['pending'] == lane['failed'] == lane['duplicate'] == '0'
    completion = rows(runtime, 'completion.status ')[0]
    assert all(completion[k] == '0' for k in ('pending','frames','buffers','obligations','duplicate','stale'))
    assert int(completion['verdicts']) == len(tokens)
    primary = rows(runtime, 'primary.status ')[0]
    assert int(primary['rejected']) == dispositions[3]
    assert int(primary['published']) == int(primary['received']) == len(tables['primary'])
    assert int(primary['deferred']) == len(tables['defer'])
    assert int(primary['returns']) == len(tables['return'])
    assert primary['pending_returns'] == primary['handoff_debt'] == primary['owner_failures'] == '0'
    assert primary['credit0'] == primary['credit1'] == '32'
    assert rows(runtime, 'capacity.status ')[0] == dict(credits='32', primary_slots='64', completion_slots='128')
    native = collections.Counter()
    thread = None
    for line in runtime.splitlines():
        if line.startswith('Thread '): thread = line.split()[1]
        columns = line.split()
        if thread is not None and len(columns) >= 4 and columns[0].startswith('product-packet-') and columns[2].isdigit() and columns[3].isdigit():
            native[(thread, columns[0])] = int(columns[3])
    for name, event_table in (('product-packet-admit','admit'), ('product-packet-policy','policy_facts'),
                              ('product-packet-terminal','terminal'), ('product-packet-origin-completi','consume')):
        expected = collections.Counter(r['thread'] for r in tables[event_table].values())
        assert all(native[(str(t), name)] == expected[str(t)] for t in range(3)), f'native node/thread vectors {name}'
    return dict(generation=generation, family=case['family'], owner=case['owner'], packets=len(tokens),
                wire_nonces=len(nonce_tokens), auxiliary_packets=len(tokens)-len(nonce_tokens),
                policy_pass=dispositions[1], policy_drop=dispositions[2], capacity_bypass=dispositions[3],
                credit_exhausted=sum(r['reason']=='1' for r in tables['reject'].values()),
                enqueue_rejected=sum(r['reason']=='2' for r in tables['reject'].values()),
                deferred_drop=len(tables['defer']), bypass_before_held_release=bypass_before_held_release, **maxima)
