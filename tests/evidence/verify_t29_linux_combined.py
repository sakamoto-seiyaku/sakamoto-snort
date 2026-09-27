#!/usr/bin/env python3
"""Independent source, packet, winner, history and cleanup oracle for T29 Linux."""
import argparse
import hashlib
import json
from pathlib import Path
import re

p = argparse.ArgumentParser()
p.add_argument('--run', type=Path, required=True)
p.add_argument('--build', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
run, build_path = a.run.resolve(), a.build.resolve()
digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
read = lambda name: (run / name).read_text()
props = lambda name: dict(line.split('=', 1) for line in read(name).splitlines() if '=' in line)
data = lambda name: json.loads(read(name))
rows = lambda name, prefix: [dict(part.split('=', 1) for part in line.split()[1:] if '=' in part)
                              for line in read(name).splitlines() if line.startswith(prefix)]
events = lambda name: [json.loads(line) for line in read(name).splitlines() if line.startswith('{')]
build = json.loads(build_path.read_text())
result = data('result.json')
assert result['status'] == 'RAW_COMPLETE' and result['process_absent'] and not result.get('cleanup_error')
assert result['task'] == 'T29' and result['source'] == 'NFQ_CAPTURED'
assert result['build_sha256'] == digest(build_path) and result['source_sha256'] == build['source_sha256']
assert result['runner_sha256'] == digest(run / 'runner.py')
assert result['fixtures_sha256'] == digest(run / 'fixtures.json')
assert result['quic_fixtures_sha256'] == digest(run / 'quic-fixtures.json')
for name, expected in build['artifact_hashes'].items():
    assert digest(Path(build['artifact']) / name) == expected, name
assert len(result['configurations']) == 3
config = {}
for expected_revision, row in enumerate(result['configurations'], 2):
    q = props(row['query'])
    assert int(q['config.saved_revision']) == int(q['config.active_revision']) == expected_revision
    assert q['config.result'] == q['config.save_error'] == q['config.compile_error'] == '0'
    assert q['config.count'] == q['config.active_count'] == '4'
    assert q['config.domain.0.name'] == 'example.test' and q['config.binding_count'] == '3'
    assert q['config.rule.3.expression'] == '1100'
    assert q['config.rule.0.expression'] == '0d020ff903000001'
    assert q['config.rule.0.action'] == q['config.rule.3.action'] == '2'
    source = (run / row['source']).read_bytes()
    assert b'domain 0 exact example.test' in (run / (row['label'] + '-request.txt')).read_bytes()
    assert source.startswith(b'SKRULE')
    config[expected_revision] = q
rtp_rule = config[2]['config.rule.0.version']
quic_rule = config[2]['config.rule.3.version']
assert all(config[revision]['config.rule.0.version'] == rtp_rule and
           config[revision]['config.rule.3.version'] == quic_rule for revision in (3, 4))
assert [r['revision'] for r in result['configurations']] == [2, 3, 4]
assert len(result['cases']) == 4 and len(result['quic_cases']) == 4

flow_identities = {}
phase_expectations = [('rtp-added', 2, 1, rtp_rule), ('rtp-blocked', 3, 2, rtp_rule),
                      ('rtp-recovered', 4, 1, rtp_rule), ('quic-allow', 2, 1, quic_rule),
                      ('quic-during-rtp-drop', 3, 1, quic_rule),
                      ('quic-after-recover', 4, 1, quic_rule)]
for label, revision, actual_action, winner in phase_expectations:
    q = props(label + '-query.txt')
    assert int(q['config.active_revision']) == revision
    assert q['query.winner_version'] == winner and q['query.winner_action'] == '2'
    matches = [row for row in rows(label + '-flow.txt', 'flow.entry ')
               if int(row['port_a']) == (45302 if label.startswith('rtp-') else 45620)]
    assert len(matches) == 1, (label, matches)
    flow = matches[0]
    assert flow['rule'] == winner and int(flow['decision']) == actual_action
    assert int(flow['revision']) == revision and int(flow['policy_generation']) == result['generation']
    key = 'rtp' if label.startswith('rtp-') else 'quic'
    identity = (flow['worker'], flow['slot'], flow['incarnation'])
    flow_identities.setdefault(key, identity)
    assert flow_identities[key] == identity, (key, identity)
    text = read(label + '-flow.txt')
    assert (f'worker={flow["worker"]} slot={flow["slot"]} incarnation={flow["incarnation"]} '
            in text)
    if key == 'quic':
        sni = props(label + '-sni.txt')
        assert sni['sni.code'] == '0' and sni['sni.result'] == '1' and sni['sni.name'] == 'example.test'
        assert 'id=1004 key=quic' in text
    else:
        assert 'id=1016 key=stun' in text and 'id=1017 key=rtp' in text
        assert 'name=-' in text  # RTP has no valid SNI; the QUIC rule cannot win it.
    observed = data(label + '-observation.json')
    assert observed['health']['generation'] == result['generation']
    assert observed['consumer']['query_fresh'] is True
    assert observed['consumer']['persistent']['save_error'] is None
    assert (run / (label + '-dashboard.json')).exists()

before = data('rtp-added-observation.json')['consumer']['persistent']
blocked = data('rtp-blocked-observation.json')['consumer']['persistent']
recovered = data('rtp-recovered-observation.json')['consumer']['persistent']
def effects(view, rule, revision, action):
    return [v for v in view['rule_windows'].values()
            if str(v['attribution']['winner']) == rule and
            v['attribution']['policy_revision'] == revision and
            v['attribution']['actual_action'] == action]
assert effects(before, rtp_rule, 2, 1)
assert effects(blocked, rtp_rule, 3, 2)
assert effects(recovered, rtp_rule, 3, 2)
assert effects(recovered, rtp_rule, 4, 1)
assert effects(before, quic_rule, 2, 1)
assert effects(recovered, quic_rule, 2, 1)
explanation_cases = [(rtp_rule,2,1,1,None), (rtp_rule,3,0,2,None),
                     (rtp_rule,4,1,1,0), (quic_rule,2,1,1,None),
                     (quic_rule,3,1,1,None), (quic_rule,4,1,1,3)]
final_view = data('final-observation.json')['consumer']['persistent']
logical_identities = {}
for winner, revision, mode, actual, source_index in explanation_cases:
    for effect in effects(final_view, winner, revision, actual):
        attr, explanation = effect['attribution'], effect['interpretation']
        assert attr['mode'] == mode and attr['declared_action'] == 2
        assert explanation['actual_action'] == actual and str(explanation['version']) == winner
        conditions = explanation['conditions']
        if source_index is None:
            assert conditions == {'status':'unavailable','reason':'matching_source_unavailable'}
        else:
            assert conditions == {'status':'available','source_rule_index':source_index}
        logical_identities.setdefault(winner,set()).add(explanation['logical_identity'])
    assert effects(final_view, winner, revision, actual)
assert all(len(names) == 1 for names in logical_identities.values())
labels = {v['protocol_id'] for v in recovered['protocol_windows'].values() if v['layer'] == 'l7'}
assert {1004, 1016, 1017} <= labels
for row in recovered['protocol_windows'].values():
    if row['layer'] == 'l7':
        assert all(n <= d for n, d in zip(row['counts']['packets'], row['denominator']['packets']))
assert int(props('rtp-blocked-query.txt')['query.actual_drops']) == 1
assert int(props('quic-during-rtp-drop-query.txt')['query.actual_drops']) == 1
assert int(props('quic-after-recover-query.txt')['query.actual_drops']) == 1

rtp_events = events('endpoint.jsonl')
quic_events = events('quic-endpoint.jsonl')
rtp_commands = [e for e in rtp_events if e['kind'] == 'command']
rtp_replies = [e for e in rtp_events if e['kind'] == 'reply']
assert len(rtp_commands) == len(rtp_replies) == 29
assert {e['index'] for e in rtp_commands} == {-1, *range(28)}
assert len([e for e in quic_events if e['kind'] == 'echo']) == 75
assert len([e for e in quic_events if e['kind'] == 'initial']) == 1
assert all(c['nonce'] == result['cases'][0]['nonce'] for c in rtp_commands)
assert 'pending=0' in read('final-drain.txt') and 'obligations=0' in read('final-drain.txt')
assert 'root.stop=ok' in read('final-stop.txt')
assert 'absent=True' in read('final-stopped.txt')
assert 'NFQUEUE' not in read('hooks-after.txt')

answer = dict(status='VALID',source_sha256=build['source_sha256'],profile='linux-root',
              generation=result['generation'],revisions=[2,3,4],
              rtp_winner=rtp_rule,quic_winner=quic_rule,actual_policy_drops=1,
              rtp_endpoint_exchanges=29,quic_echoes=75,multi_label_ids=sorted(labels),
              flow_identities=flow_identities,rule_explanations_checked=len(explanation_cases),
              verifier_sha256=digest(__file__))
a.output.write_text(json.dumps(answer,indent=2)+'\n')
print(json.dumps(answer,indent=2))
