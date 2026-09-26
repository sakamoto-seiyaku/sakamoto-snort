#!/usr/bin/env python3
"""Independently verify a held domain packet and two complete Product publications."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

source = load('t18_source', ROOT/'tests/evidence/verify_t06_expressions.py').source
domains = load('t18_domains', ROOT/'tests/evidence/domain_evidence.py')
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def props(path):
    return dict(line.split('=', 1) for line in Path(path).read_text().splitlines() if '=' in line)
def events(path):
    result = []
    for index, line in enumerate(Path(path).read_text().splitlines()):
        if not line.startswith(('s209 event=', 't13 event=sni ')):
            continue
        result.append((index, dict(part.split('=', 1) for part in line.split()[1:] if '=' in part)))
    return result
def one(rows, event, **fields):
    answer = [(index, row) for index, row in rows if row.get('event') == event and
              all(row.get(k) == str(v) for k, v in fields.items())]
    assert len(answer) == 1, (event, fields, len(answer))
    return answer[0]

def verify(directory):
    directory = Path(directory).resolve()
    run = json.loads((directory/'result.json').read_text())
    assert run['status'] == 'RAW_COMPLETE' and run['process_absent'] and run['domain_policy']
    assert digest(directory/'runner.py') == run['runner_sha256']
    assert digest(directory/'domain-policy.py') == run['domain_policy_sha256']
    assert digest(directory/'fixtures.json') == run['fixtures_sha256']
    assert digest(directory/'socket-peer.py') == run['peer_sha256']
    assert digest(directory/'persistent-helper') == run['persistent_helper_sha256']
    assert digest(directory/'persistent-helper.c') == run['persistent_helper_source_sha256']
    assert digest(ROOT/'tests/device/helpers/t18_persistent_config.c') == run['persistent_helper_source_sha256']
    helper_build = json.loads(Path(run['persistent_build']).read_text())
    assert digest(run['persistent_build']) == run['persistent_build_sha256']
    assert helper_build['binary_sha256'] == run['persistent_helper_sha256']
    assert helper_build['source_sha256'] == run['persistent_helper_source_sha256']
    assert digest(helper_build['archive']) == helper_build['archive_sha256']
    assert digest(helper_build['binary']) == helper_build['binary_sha256']
    build = json.loads(Path(run['build']).read_text())
    assert digest(run['build']) == run['build_sha256']
    assert build['source_sha256'] == run['source_sha256']
    assert helper_build['artifact'] == run['artifact']
    assert helper_build['artifact_manifest_sha256'] == run['manifest_sha256']
    for name, expected in build['artifact_hashes'].items():
        assert digest(Path(run['artifact'])/name) == expected, name
    assert 'NFQUEUE' not in (directory/'hooks-after.txt').read_text()
    assert props(directory/'final-stopped.txt')['absent'] == 'True'
    domains.build_binding(directory, run, build, props)

    configs = {}
    for item in run['configurations']:
        config = source(directory/item['source'])
        assert config['revision'] == item['revision']
        domains.configuration(config, item)
        if item.get('persistent'):
            text = (directory/item['query']).read_text().strip().split()
            assert text[0] == 'applied'
            reply = dict(word.split('=', 1) for word in text[1:])
            assert reply['result'] == '0' and int(reply['saved']) == config['revision']
            assert int(reply['revision']) == config['revision']
            assert int(reply['entries']) == len(config['domains'])
        else:
            status = props(directory/item['query'])
            assert status['config.result'] == '0'
            assert int(status['config.active_revision']) == config['revision']
        configs[item['label']] = config
    old, changed, restored = (configs[name] for name in
        ('overlap-initial', 'overlap-without-exact', 'overlap-restore'))
    assert old['revision'] + 1 == changed['revision'] and changed['revision'] + 1 == restored['revision']
    for field in ('rules', 'groups', 'edges', 'bindings'):
        assert old[field] == changed[field] == restored[field], field
    assert domains.source_lists(old)[0] and not domains.source_lists(changed)[0]
    assert domains.source_lists(restored) == domains.source_lists(old)
    assert [c['phase'] for c in run['cases']] == ['ready', 'recovered']
    assert len({tuple(c['identity']) for c in run['cases']}) == 1
    assert [c['revision'] for c in run['cases']] == [old['revision'], restored['revision']]

    records = events(directory/'first-vpp.log')
    begin_i, begin = one(records, 'hold_begin')
    end_i, end = one(records, 'hold_end', token=begin['token'])
    token = begin['token']
    acquire_i, acquire = one(records, 'acquire', token=token)
    sni_i, sni = one(records, 'sni', token=token)
    match_i, held = one(records, 'l4', token=token)
    release_i, release = one(records, 'release', token=token)
    publishes = {int(row['revision']): (index, row) for index, row in records if row.get('event') == 'publish'}
    old_i, old_pub = publishes[old['revision']]
    change_i, change_pub = publishes[changed['revision']]
    restore_i, restore_pub = publishes[restored['revision']]
    assert old_i < acquire_i < sni_i < begin_i < change_i < end_i < match_i < release_i < restore_i
    assert int(end['mono_ns']) - int(begin['mono_ns']) >= 450_000_000
    assert int(begin['mono_ns']) < int(change_pub['mono_ns']) < int(end['mono_ns'])
    assert int(restore_pub['mono_ns']) > int(release['mono_ns'])
    assert acquire['bank'] == release['bank'] == old_pub['bank'] == restore_pub['bank']
    assert change_pub['bank'] != old_pub['bank']
    assert acquire['revision'] == held['revision'] == release['revision'] == str(old['revision'])
    assert acquire['snapshot_hash'] == held['snapshot_hash'] == release['snapshot_hash'] == old_pub['snapshot_hash']
    assert acquire['source'] == 'NFQ_CAPTURED' and held['flow_dir'] == '1' and held['position'] == '2'
    assert sni['result'] == '1' and sni['name'] == 'example.test'
    assert held['rule'] == str(old['rules'][0]['version'])
    assert held['action'] == '2' and held['mode'] == '1' and held['actual_action'] == '1'
    assert run['overlap'] == dict(owner=int(acquire['worker']), old_revision=old['revision'],
                                  middle_revision=changed['revision'], final_revision=restored['revision'],
                                  old_winner=old['rules'][0]['version'])
    matching = [(index, row) for index, row in records if row.get('event') == 'l4' and
                row.get('revision') == str(restored['revision']) and row.get('flow_dir') == '1']
    assert matching and all(row['rule'] == str(restored['rules'][0]['version']) and
                            row['mode'] == '1' and row['actual_action'] == '1' for _, row in matching)
    client = json.loads((directory/'overlap-client.json').read_text())
    assert sum(e['kind'] == 'received' for e in client) >= 2
    return dict(status='PASS', source_sha256=run['source_sha256'], held_token=int(token),
                old_revision=old['revision'], changed_revision=changed['revision'],
                reused_revision=restored['revision'], held_ms=(int(end['mono_ns'])-int(begin['mono_ns']))/1e6,
                old_winner=old['rules'][0]['version'],
                changed_snapshot_published_during_hold=True, retired_bank_reused_after_release=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = verify(args.directory)
    if args.output: args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
