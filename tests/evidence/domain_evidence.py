"""Independent T18 source semantics and list-only publication checks."""
import hashlib
from pathlib import Path

PIN = '05a9c29c62538519d870d6512978f80ac58a758f'

def source_lists(config):
    answer = {number: [] for number in range(config.get('domain_count', 0))}
    for entry in config.get('domains', []):
        answer[entry['list']].append(('descendants' if entry['mode'] else 'exact', entry['name']))
    return answer

def configuration(config, item):
    # Literal expected source instructions, independent of request construction.
    assert [r['expression'] for r in config['rules'][:3]] == [
        bytes([17, 0, 17, 1, 1, 12, 152, 158, 252, 158, 1]),
        bytes([17, 0, 3, 17, 2, 2]), b'']
    assert config['domain_count'] == 3
    expected = {(1, 1, 'example.test'), (1, 1, 'example'),
                (2, 1, 'test'), (2, 1, 'example')}
    if item.get('domain_variant') != 'without-exact':
        expected |= {(0, 0, 'example.test'), (0, 0, 'xn--bcher-kva.example')}
    assert {(e['list'], e['mode'], e['name']) for e in config['domains']} == expected
    assert len(config['domains']) == len(expected)

def build_binding(directory, run, build, props):
    directory = Path(directory)
    assert run.get('domain_policy') is True
    digest = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
    assert digest(directory/'domain-policy.py') == run['domain_policy_sha256']
    for name in ('rax.c', 'rax.h', 'rax_malloc.h', 'serverassert.h', 'UPSTREAM.json'):
        assert 'third_party/rax/'+name in build['files'], 'rax omitted from source closure'
    if 'serial' in run:
        stage = props(Path(run['build']).parent/'stage/product-stage.properties')
        assert stage['domainMatcher'] == 'valkey-rax-'+PIN+'-vpp-fallible'
    else:
        manifest = props(Path(run['artifact'])/'product-vpp-artifact.properties')
        assert manifest['domain.matcher'] == 'valkey-rax-'+PIN+'-vpp-fallible'

def transitions(cases, packets, configs, profile):
    changed = [case for case in cases if case['phase'] == 'changed']
    required = {case['mode'] for case in cases if
                (case['mode'].startswith('named') or case['mode'] == 'absent') and
                not case['mode'].endswith('_cutoff')}
    assert {case['mode'] for case in changed} == required
    changes = 0
    for case in changed:
        ready = next(c for c in cases if c['mode'] == case['mode'] and c['phase'] == 'ready')
        assert ready['identity'] == case['identity'], 'list update replaced the Flow'
        before = configs[(profile, ready['revision'])][0]
        after = configs[(profile, case['revision'])][0]
        assert after['revision'] == before['revision'] + 1
        for field in ('rules', 'groups', 'edges', 'bindings'):
            assert before[field] == after[field], 'list-only publication changed rules or binding modes'
        assert source_lists(before)[0] and not source_lists(after)[0]
        old = [p for p in packets if int(p['match']['revision']) == ready['revision'] and
               p['facts']['sport'] == case['port'] and p['facts'].get('sni') == 'name']
        new = [p for p in packets if int(p['match']['revision']) == case['revision'] and
               p['facts']['sport'] == case['port']]
        assert new, 'no real packet consumed the changed list snapshot'
        if case['mode'] in ('named', 'named_alabel'):
            assert old
            assert any(p['expected']['rule_id'] == before['rules'][0]['version'] for p in old)
            assert all(p['expected']['rule_id'] == after['rules'][1]['version'] for p in new)
            assert all(p['expected']['action'] == 2 and p['expected']['mode'] == 1 and
                       p['expected']['actual_action'] == 1 for p in old + new)
            changes += 1
    assert changes, 'same-action different-winner list-only transition absent'
    return changes
