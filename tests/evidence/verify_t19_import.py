#!/usr/bin/env python3
"""Independent import/source/packet evidence reader. No production parser reuse."""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('t19_packets', HERE/'verify_t16_sni.py')
packets = importlib.util.module_from_spec(spec); spec.loader.exec_module(packets)
spec = importlib.util.spec_from_file_location('t19_source', HERE/'verify_t06_expressions.py')
source = importlib.util.module_from_spec(spec); spec.loader.exec_module(source)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def definition(text):
    fields = text.split()
    assert len(fields) in (16, 17)
    numbers = [int(value) for value in fields[:10]+fields[12:16]]
    addresses = [None if value == '*' else ipaddress.ip_interface(value) for value in fields[10:12]]
    expression = bytes.fromhex(fields[16]) if len(fields) == 17 else b''
    return fields, numbers, addresses, expression


def document_matches_source(document, saved):
    assert document['format'] == 'sakamoto-config-v1'
    assert set(document) == {'format','rules','groups','edges','bindings','lists'}
    assert len(document['rules']) == len(saved['rules'])
    for entry, rule, metadata in zip(document['rules'], saved['rules'], saved['rule_metadata']):
        fields, numbers, addresses, expression = definition(entry['definition'])
        assert numbers == [rule['version'], 0, rule['uid'], rule['network_context'], rule['ifindex'],
            rule['priority'], rule['order'], rule['protocol'], rule['direction'], rule['action'],
            rule['source_port_first'], rule['source_port_last'],
            rule['destination_port_first'], rule['destination_port_last']]
        assert expression == rule['expression']
        for address, key in zip(addresses, ('source','destination')):
            if address is None:
                assert rule['family'] == 0 and not any(rule[key]) and rule[key+'_prefix'] == 0
            else:
                assert address.version == rule['family'] and address.network.prefixlen == rule[key+'_prefix']
                assert address.ip.packed == rule[key][:4 if address.version == 4 else 16]
        assert {key:entry[key] for key in ('name','source')} == metadata
    assert document['groups'] == saved['groups']
    assert document['edges'] == list(map(list,saved['edges']))
    assert document['bindings'] == list(map(list,saved['bindings']))
    assert len(document['lists']) == saved['domain_count']
    entries = []
    for index, (item, metadata) in enumerate(zip(document['lists'], saved['list_metadata'])):
        assert item['syntax'] == 'native-v1'
        assert {key:item[key] for key in ('name','source')} == metadata
        for text in item['entries']:
            mode, name = text.split(' ')
            assert mode in ('exact','descendants')
            entries.append(dict(list=index,mode=int(mode=='descendants'),name=name))
    assert entries == saved['domains']


def verify(directory, packet_check=True, expected_cache_bytes=None):
    directory = Path(directory)
    run = json.loads((directory/'result.json').read_text())
    assert run['status'] == 'RAW_COMPLETE' and run['process_absent']
    assert run.get('import_policy') or (run.get('task') == 'T29' and run.get('import_policy_sha256'))
    assert not run.get('error') and not run.get('cleanup_error')
    assert digest(directory/'import-policy.py') == run['import_policy_sha256']
    pixel = 'serial' in run
    import_prefix = 't29-tls' if run.get('task') == 'T29' else 't19'
    generations = {life['profile']:life['generation'] for life in run['lifetimes']} if pixel else {'root':run['generation']}
    records = run['imports']; assert records
    labels = {item['label']:item for item in records}; assert len(labels) == len(records)
    replies = {}; inputs = {}
    for record in records:
        assert record['generation'] == generations[record['profile']]
        path=directory/record['reply']; assert digest(path) == record['reply_sha256']
        reply=json.loads(path.read_text()); replies[record['label']]=reply
        if reply['stage'] == 'vpp':
            assert reply['generation'] == record['generation']
        if record['input'] is not None:
            path=directory/record['input']; assert digest(path) == record['input_sha256']
            inputs[record['label']]=json.loads(path.read_text())
        else:
            assert record['expected_revision'] == 0
    if not pixel:
        assert run['startup_import_repair']
        assert (directory/'startup-invalid-source.conf').read_bytes()==b'T19 deliberately invalid source for online import repair\n'
        before=source.props(directory/'t19-startup-export-import-transport.txt')
        after=source.props(directory/'first-initial.txt')
        assert before['connect.core_ready']=='true' and before['connect.adapter_available']=='false'
        assert before['connect.protection_running']=='false' and before['connect.policy_active_revision']=='0'
        assert after['query.core_ready']==after['query.adapter_available']==after['query.protection_running']=='true'
        assert after['query.policy_active_revision']=='1'
        for label,result,save_error in (
            ('t19-startup-export',0,1),('t19-startup-reference',10,1),('t19-startup-save-failure',3,3)):
            reply=replies[label]
            assert reply['stage']=='vpp' and reply['result']==result
            assert reply['save_error']==save_error and reply['compile_error']==0
            assert reply['error_index']==4294967295 and reply['compiler_status']==0
            assert reply['saved_revision']==reply['active_revision']==0 and reply['active_versions']==[]
            assert reply['configuration'] is None and reply['export_error']
        repaired=replies['t19-startup-repair']
        assert repaired['result']==repaired['save_error']==repaired['compile_error']==0
        assert repaired['saved_revision']==repaired['active_revision']==1 and repaired['export_error'] is None
        assert repaired['configuration']==inputs['t19-startup-repair']
    for item in run['configurations']:
        if item['label'] not in inputs:
            assert run.get('task') == 'T29' and item['label'].endswith(('-ack-drop','-ack-recover'))
            continue  # T14's separate live ACK suppression scenario uses the direct test control.
        label=item['label']; original=inputs[label]; accepted=replies[label]
        assert accepted['stage'] == 'vpp' and accepted['result'] == 0
        assert accepted['saved_revision'] == accepted['active_revision']
        exported=replies[label+'-export']; repeated=replies[label+'-reimport']
        assert exported == repeated and accepted == exported
        assert inputs[label+'-reimport'] == exported['configuration']
        assert labels[label+'-reimport']['expected_revision'] == exported['saved_revision']
        assert len(original['rules']) == 3 and len(original['lists']) == 3
        for i,(before,after) in enumerate(zip(original['rules'],exported['configuration']['rules'])):
            assert before['name'] == after['name'] == f'规则 {i}'
            assert before['source'] == after['source'] == 't19-complete-source.json'
            assert before['definition'].split()[2:] == after['definition'].split()[2:]
            assert int(after['definition'].split()[0]) >> 16
        assert [entry['syntax'] for entry in original['lists']] == ['native-v1','adblock-domain-v1','clash-domain-v1']
        if item['domain_variant'] != 'without-exact':
            assert original['lists'][0]['entries'] == ['exact EXAMPLE.test.','exact BÜCHER.Example.']
            assert exported['configuration']['lists'][0]['entries'] == ['exact example.test','exact xn--bcher-kva.example']
        else:
            assert original['lists'][0]['entries'] == exported['configuration']['lists'][0]['entries'] == []
        for i,entry in enumerate(original['lists']):
            assert entry['name'] == f'名单 {i}' and entry['source'] == f't19-source-{i}.txt'
        saved=source.source(directory/item['source']); assert saved['source_schema'] == 6
        # The first configuration includes a separately recorded save/compile
        # failure-and-repair sequence before packet collection starts.
        profile=item.get('profile','root'); prefix=import_prefix+'-'+profile+'-failures'
        final=replies[prefix+'-repaired-export'] if saved['revision'] != accepted['saved_revision'] else accepted
        assert final['saved_revision'] == item['revision'] == saved['revision']
        document_matches_source(final['configuration'],saved)
    rejected=0
    for profile in generations:
        prefix=import_prefix+'-'+profile+'-failures'
        first=next(item for item in run['configurations'] if item.get('profile','root')==profile)
        baseline=replies[first['label']+'-export']; config=baseline['configuration']; revision=baseline['saved_revision']
        cases={'identity-content-conflict':2,'identity-name-conflict':2,'duplicate-identity':2,
            'missing-list-reference':10,'group-cycle':11,'mode-conflict':13}
        for name in ('invalid-name','invalid-alabel','unicode-invalid','url-path','unsupported-wildcard',
                     'filter-option','clash-extra-condition','unknown-condition'):
            cases[name]=None
        for name,result in cases.items():
            label=prefix+'-'+name; reply=replies[label]; request=inputs[label]
            assert labels[label]['expected_revision'] == revision
            assert request != config
            if result is None:
                assert reply['stage'] == 'prepare' and reply['error']
            else:
                assert reply['stage'] == 'vpp' and reply['result'] == result
                assert reply['configuration'] == config
                if name == 'missing-list-reference': assert reply['error_index'] == 0
            after=replies[label+'-readback']
            assert after['result'] == after['save_error'] == after['compile_error'] == 0
            assert after['configuration'] == config and after['active_versions'] == baseline['active_versions']
            assert after['saved_revision'] == after['active_revision'] == revision
            rejected+=1
        stale=replies[prefix+'-stale-revision']
        assert stale['result']==2 and stale['configuration']==config
        assert labels[prefix+'-stale-revision']['expected_revision']==revision-1
        failed=replies[prefix+'-save-failure']
        assert failed['result']==failed['save_error']==3 and failed['compile_error']==0
        assert failed['configuration']==config and failed['saved_revision']==failed['active_revision']==revision
        assert failed['active_versions']==baseline['active_versions']
        retry=replies[prefix+'-save-retry']
        assert retry['result']==retry['save_error']==retry['compile_error']==0
        assert retry['saved_revision']==retry['active_revision']==revision and retry['configuration']==config
        failed=replies[prefix+'-compile-failure']; readback=replies[prefix+'-compile-failure-readback']
        assert failed['result']==failed['compile_error']==4 and failed['save_error']==0 and failed['error_index']==0
        assert failed['saved_revision']==revision+1 and failed['active_revision']==revision
        assert failed['active_versions']==baseline['active_versions']
        assert failed['configuration']==readback['configuration'] and readback['compile_error']==4
        original=definition(config['rules'][0]['definition'])[0]
        changed=definition(failed['configuration']['rules'][0]['definition'])[0]
        assert int(changed[0])==int(original[0])+1 and changed[7]=='1'
        assert changed[2:7]+changed[8:]==original[2:7]+original[8:]
        corrected=replies[prefix+'-compile-retry']; repeated=replies[prefix+'-repaired-reimport']
        assert corrected==replies[prefix+'-repaired-export']==repeated
        assert corrected['result']==corrected['save_error']==corrected['compile_error']==0
        assert corrected['saved_revision']==corrected['active_revision']==revision+2
        fixed=definition(corrected['configuration']['rules'][0]['definition'])[0]
        assert int(fixed[0])==int(original[0])+2 and fixed[2:]==original[2:]
    result=dict(status='PASS',source_sha256=run['source_sha256'],profiles=sorted(generations),
        import_operations=len(records),rejected_inputs=rejected,
        startup_repair=not pixel,verifier_sha256=digest(__file__),
        packet_verifier_sha256=digest(HERE/'verify_t16_sni.py'),
        source_decoder_sha256=digest(HERE/'verify_t06_expressions.py'),
        scope='online import/export, full identity/provenance, save/compile separation and real QUIC decisions')
    if packet_check:
        result['packet_verification']=packets.verify(directory,expected_cache_bytes)
        assert result['packet_verification']['status']=='PASS'
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('directory');parser.add_argument('--output',type=Path)
    parser.add_argument('--expected-cache-bytes',type=int)
    args=parser.parse_args();result=verify(args.directory,expected_cache_bytes=args.expected_cache_bytes);text=json.dumps(result,indent=2)+'\n'
    if args.output:args.output.write_text(text)
    print(text,end='')
