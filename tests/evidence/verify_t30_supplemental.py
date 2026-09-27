#!/usr/bin/env python3
"""Independent R2/R3/R4/QUIC live-overlap oracle for T30 Linux Product path."""
import argparse
import hashlib
import json
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('--run',type=Path,required=True)
p.add_argument('--base-verdict',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();run=a.run.resolve()
def read(name):return (run/name).read_text()
def data(name):return json.loads(read(name))
def digest(name):return hashlib.sha256((run/name).read_bytes()).hexdigest()
def props(name):return dict(line.split('=',1) for line in read(name).splitlines() if '=' in line)
def rows(name,prefix):return [dict(part.split('=',1) for part in line.split()[1:] if '=' in part)
    for line in read(name).splitlines() if line.startswith(prefix+' ')]
result=data('result.json');base=json.loads(a.base_verdict.read_text())
assert result['status']=='RAW_COMPLETE' and result['process_absent']
assert not result.get('cleanup_error') and base['status']=='VALID'
assert result['runner_sha256']==digest('runner.py')
assert base['source_sha256']==result['source_sha256']
assert result['supplemental']['labels']==['smtp','openvpn']
assert result['supplemental']['flow']=='supplemental-final-live.txt'

config=props('combined-recover-apply.txt')
assert config['config.count']==config['config.active_count']=='64'
assert config['config.domain_entry_count']=='65' and config['config.binding.3']=='4,12001,2,30,1'
assert config['config.rule.4.expression']=='0d020fef03000001' # SMTP ID 1007
assert config['config.rule.5.expression']=='0d020ff303000001' # OpenVPN ID 1011
expected={
    'quic':dict(port=45620,labels={1004},winner=base['quic_winner']),
    'rtp':dict(port=45302,labels={1016,1017},winner=base['rtp_winner']),
    'smtp':dict(port=45400,labels={1007},winner=config['config.rule.4.version']),
    'openvpn':dict(port=45410,labels={1011},winner=config['config.rule.5.version']),
}
before='supplemental-all-live.txt';after='supplemental-final-live.txt'
found={}
for name,spec in expected.items():
    selected=[]
    for filename,revision in ((before,2),(after,4)):
        entries=rows(filename,'flow.entry')
        matching=[x for x in entries if spec['port'] in (int(x['port_a']),int(x['port_b']))]
        assert len(matching)==1,(name,filename,matching)
        flow=matching[0]
        assert int(flow['revision'])==revision and flow['rule']==spec['winner']
        assert flow['decision']=='1' and flow['uid']=='12001'
        identity=(flow['worker'],flow['slot'],flow['incarnation'])
        facts={int(x['id']) for x in rows(filename,'flow.protocol_fact')
            if (x['worker'],x['slot'],x['incarnation'])==identity}
        assert spec['labels']<=facts,(name,filename,facts)
        lpi=next(x for x in rows(filename,'flow.lpi')
            if (x['worker'],x['slot'],x['incarnation'])==identity)
        sni=next(x for x in rows(filename,'flow.sni')
            if (x['worker'],x['slot'],x['incarnation'])==identity)
        assert 1<=int(lpi['attempts'])<=20 and int(lpi['bytes'])<=65536
        assert int(sni['work'])<=131072 and int(sni['attempts'])<=20
        selected.append(dict(identity=identity,packets=int(flow['packets']),
            lpi_attempts=int(lpi['attempts']),lpi_bytes=int(lpi['bytes']),
            sni_attempts=int(sni['attempts']),sni_work=int(sni['work'])))
    assert selected[0]['identity']==selected[1]['identity']
    assert selected[1]['packets']>selected[0]['packets'],name
    found[name]=selected
assert len({x[0]['identity'] for x in found.values()})==4
for filename in (before,after):
    pools=rows(filename,'flow.runtime');cache=rows(filename,'policy.cache')
    assert len(pools)==len(cache)==2
    assert all(x['allocated_bytes']=='9261384' and x['entry_bytes']=='9024'
               and x['capacity_misses']=='0' for x in pools)
    assert all(x['capacity']=='128' and x['storage_bytes']=='25632' for x in cache)
    assert sum(int(x['hits']) for x in cache)>0
    snapshot=rows(filename,'policy.snapshot')
    assert len(snapshot)==1 and snapshot[0]['revision']==('2' if filename==before else '4')

window=data('supplemental-final-live-observation.json')
assert window['health']['generation']==result['generation']
assert window['consumer']['query_fresh'] is True
assert window['consumer']['persistent']['save_error'] is None
labels={x['protocol_id'] for x in window['consumer']['persistent']['protocol_windows'].values()
        if x['layer']=='l7'}
assert {1004,1007,1011,1016,1017}<=labels
rule_windows=list(window['consumer']['persistent']['rule_windows'].values())
for name in ('smtp','openvpn'):
    winner=expected[name]['winner']
    matches=[x for x in rule_windows if str(x['attribution']['winner'])==winner]
    assert {x['attribution']['policy_revision'] for x in matches}=={2,3,4}
    assert all(x['attribution']['mode']==1 and x['attribution']['declared_action']==2
               and x['attribution']['actual_action']==1 for x in matches)
    assert next(x for x in matches if x['attribution']['policy_revision']==4)[
        'interpretation']['conditions']=={'status':'available',
        'source_rule_index':4 if name=='smtp' else 5}

admissions={}
terminals={}
for line in read('first-vpp.log').splitlines():
    if not line.startswith(('s216 stage=admit ','s216 stage=terminal ')):continue
    value=dict(part.split('=',1) for part in line.split()[1:] if '=' in part)
    ports={int(value['src_port']),int(value['dst_port'])}
    if not ports.intersection((2525,1195)):continue
    token=value['token']
    target=admissions if 'stage=admit' in line else terminals
    assert token not in target
    target[token]=value
assert set(admissions)==set(terminals)
wire={name:[] for name in ('smtp','openvpn')}
for token,start in admissions.items():
    end=terminals[token]
    assert int(end['mono_ns'])>=int(start['mono_ns']) and start['generation']==end['generation']
    name='smtp' if 2525 in (int(start['src_port']),int(start['dst_port'])) else 'openvpn'
    wire[name].append(bytes.fromhex(start['raw']))
assert all(len(value)>=5 for value in wire.values())

endpoints={}
for name in ('smtp','openvpn'):
    client=data(name+'-client.json')
    assert [x['kind'] for x in client]==[
        'connected','first_ready','added_ready','received','received','closed']
    assert all(x['count']==1 for x in client if x['kind']=='received')
    events=[json.loads(line) for line in read(name+'-endpoint.jsonl').splitlines()]
    commands=[x for x in events if x['kind']=='command']
    replies=[x for x in events if x['kind']=='reply']
    assert len(commands)==(4 if name=='smtp' else 3)
    assert len(replies)==(5 if name=='smtp' else 3)
    for event in commands+replies:
        payload=bytes.fromhex(event['data'])
        assert any(payload in packet for packet in wire[name]),(name,event)
    if name=='smtp':
        assert bytes.fromhex(replies[0]['data'])==b'220 mail.example.test ESMTP R2 ready\r\n'
        assert bytes.fromhex(commands[0]['data']).startswith(b'EHLO ')
        assert sum(bytes.fromhex(x['data']).startswith(b'NOOP ') for x in commands)==2
    else:
        assert all(bytes.fromhex(x['data'])[:1]==b'\x38' for x in commands)
        assert all(bytes.fromhex(x['data'])[:1]==b'\x40' for x in replies)
    endpoints[name]=dict(commands=len(commands),replies=len(replies),admitted=len(wire[name]))
assert 'NFQUEUE' not in read('hooks-after.txt')
answer=dict(status='VALID',source_sha256=result['source_sha256'],
    generation=result['generation'],revisions=[2,3,4],flows=found,
    labels=sorted(labels),endpoints=endpoints,
    packet_oracle_sha256=hashlib.sha256(a.base_verdict.read_bytes()).hexdigest(),
    verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
a.output.write_text(json.dumps(answer,indent=2)+'\n')
print(json.dumps({k:answer[k] for k in ('status','labels','endpoints')},indent=2))
