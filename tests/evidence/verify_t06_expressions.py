#!/usr/bin/env python3
"""Independently join T06 source expressions, packet decisions and completion."""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import struct
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result
groups = module('t06_groups', ROOT/'tests/evidence/verify_t04_groups.py')
chain = module('t06_chain', ROOT/'tests/evidence/verify_t01_rule.py')
reference = module('t06_reference', ROOT/'tests/host/product_static_reference_test.py')
props, rows, effective = groups.props, groups.rows, groups.effective
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def snapshot_hash(path):
    value = 14695981039346656037
    for byte in Path(path).read_bytes(): value = ((value ^ byte) * 1099511628211) & ((1<<64)-1)
    return value or 1

def expression(raw):
    """Decode saved source into a logical AST, never a compiled plan."""
    stack=[];at=0
    while at<len(raw):
        op=raw[at];at+=1
        if op in (1,2):
            right=stack.pop();left=stack.pop();stack.append(('and' if op==1 else 'or',left,right))
        elif op==3:stack.append(('not',stack.pop()))
        elif op in (4,5,6):
            stack.append(({4:'family',5:'protocol',6:'direction'}[op],raw[at]));at+=1
        elif op == 17:
            assert raw[at] < 64; stack.append(('domain',raw[at])); at += 1
        elif op == 16:
            assert raw[at] == 1; at += 1; stack.append(('no_sni',))
        elif op == 15:
            stack.append(('lpi',struct.unpack_from('<I',raw,at)[0]));at+=4
        elif op in (13,14):
            assert raw[at] in ((1,2,3) if op==13 else (1,2))
            stack.append(('ct' if op==13 else 'flowdir',raw[at]));at+=1
        elif op in (7,8):
            stack.append(('network' if op==7 else 'interface',struct.unpack_from('<I',raw,at)[0]));at+=4
        elif op in (9,10):
            family,prefix=raw[at:at+2];assert family in (4,6)
            address=ipaddress.ip_address(raw[at+2:at+2+(4 if family==4 else 16)])
            stack.append(('src' if op==9 else 'dst',str(address)+'/'+str(prefix)));at+=18
        else:
            assert op in (11,12)
            stack.append(('sport' if op==11 else 'dport',*struct.unpack_from('<HH',raw,at)));at+=4
    assert at==len(raw) and len(stack)==1
    return stack[0]

def source(path):
    raw=Path(path).read_bytes();assert raw[:8] in (b'SKRULE04',b'SKRULE05',b'SKRULE06'),'source schema'
    revision,count,retained_count=struct.unpack_from('<QII',raw,8)
    assert count<=256 and retained_count<=4096 and revision
    retained=struct.unpack_from('<'+'Q'*retained_count,raw,24)
    assert len(set(v>>16 for v in retained))==retained_count and all(v>>16 and v&65535 for v in retained)
    at=24+8*retained_count;rules=[]
    names='uid network_context ifindex priority order family protocol direction action source_prefix destination_prefix source_port_first source_port_last destination_port_first destination_port_last reserved'.split()
    for _ in range(count):
        values=struct.unpack_from('<QQ16I16s16sI64s',raw,at);at+=180
        assert values[0] in retained and values[1]==0 and values[20]<=64
        assert not any(values[21][values[20]:])
        rules.append(dict(zip(names,values[2:18]),version=values[0],source=values[18],destination=values[19],
                          expression=values[21][:values[20]],expression_length=values[20]))
    gc,ec,bc=struct.unpack_from('<III',raw,at);at+=12
    assert gc<=64 and ec<=512 and bc<=128
    group_ids=list(struct.unpack_from('<'+'I'*gc,raw,at));at+=4*gc
    edges=[struct.unpack_from('<III',raw,at+12*i) for i in range(ec)];at+=12*ec
    bindings=[struct.unpack_from('<IIIII',raw,at+20*i) for i in range(bc)];at+=20*bc
    domain_count=0;domains=[]
    if raw[:8] in (b'SKRULE05',b'SKRULE06'):
        domain_count,entry_count=struct.unpack_from('<II',raw,at);at+=8
        assert domain_count<=64 and entry_count<=256
        for _ in range(entry_count):
            number,mode,length,name=struct.unpack_from('<III256s',raw,at);at+=268
            assert number<domain_count and mode in (0,1) and 0<length<=253 and not any(name[length:])
            text=name[:length].decode('ascii');assert text==text.lower() and not text.endswith('.')
            labels=text.split('.')
            assert all(0<len(label)<=63 and label[0]!='-' and label[-1]!='-' and
                       all(c.isascii() and (c.isalnum() or c=='-') for c in label) for label in labels)
            domains.append(dict(list=number,mode=mode,name=text))
    rule_metadata=[dict(name='',source='') for _ in range(count)]
    list_metadata=[dict(name='',source='') for _ in range(domain_count)]
    if raw[:8]==b'SKRULE06':
        for entries in (rule_metadata,list_metadata):
            for entry in entries:
                name,origin=struct.unpack_from('<64s128s',raw,at);at+=192
                for key,value in (('name',name),('source',origin)):
                    tail=value.index(0);assert not any(value[tail:])
                    text=value[:tail].decode('utf-8')
                    assert all(ord(c)>=32 and not 127<=ord(c)<=159 for c in text)
                    entry[key]=text
    assert at==len(raw) and len(set(group_ids))==gc and all(group_ids)
    return dict(revision=revision,rules=rules,groups=group_ids,edges=edges,bindings=bindings,
                domain_count=domain_count,domains=domains,source_schema=int(raw[7:8]),
                rule_metadata=rule_metadata,list_metadata=list_metadata)

def logical_rules(config, uid):
    answer=[]
    for rule,mode in effective(config,uid):
        conditions=[]
        for key,field in [('family','family'),('protocol','protocol'),('direction','direction')]:
            if rule[field]: conditions.append((key,rule[field]))
        for key,field in [('network','network_context'),('interface','ifindex')]:
            if rule[field]!=0xffffffff: conditions.append((key,rule[field]))
        if rule['family']:
            for key,field in [('src','source'),('dst','destination')]:
                address=ipaddress.ip_address(rule[field][:(4 if rule['family']==4 else 16)])
                conditions.append((key,str(address)+'/'+str(rule[field+'_prefix'])))
        for key,field in [('sport','source'),('dport','destination')]:
            first,last=rule[field+'_port_first'],rule[field+'_port_last']
            if (first,last)!=(0,65535):conditions.append((key,first,last))
        if rule['expression']:conditions.append(expression(rule['expression']))
        # A zero-predicate rule is true for every supported packet family.
        expr=('or',('family',4),('family',6)) if not conditions else conditions[0]
        for condition in conditions[1:]:expr=('and',expr,condition)
        answer.append(reference.logical(expr,identity=rule['version'],priority=rule['priority'],
                                        order=rule['order'],action=rule['action'],mode=mode,uid=uid))
    return answer

def packet_facts(admit):
    raw=bytes.fromhex(admit['raw']);assert raw[0]>>4==4 and raw[9]==17
    sp,dp=struct.unpack_from('!HH',raw,(raw[0]&15)*4)
    available=int(admit['availability'])
    return dict(uid=int(admit['uid']) if available&1 else None,
                family=4,protocol=17,direction=int(admit['direction']),
                network=int(admit['context']) if available&4 else None,
                interface=int(admit['ifindex']) if available&2 else None,
                sport=sp,dport=dp,src=str(ipaddress.ip_address(raw[12:16])),dst=str(ipaddress.ip_address(raw[16:20])))

def query_source(config, query, pixel):
    prefix='' if pixel else 'config.'
    key=lambda java,native:prefix+(java if pixel else native)
    assert int(query[key('savedRevision','saved_revision')])==config['revision']==int(query[key('activeRevision','active_revision')])
    assert query[key('result','result')]=='0' and int(query[key('count','count')])==len(config['rules'])
    for java,native,field in [('groupCount','group_count','groups'),('edgeCount','edge_count','edges'),('bindingCount','binding_count','bindings')]:
        assert int(query[key(java,native)])==len(config[field])
    if config.get('source_schema')==5:
        assert int(query[key('domainListCount','domain_list_count')])==config['domain_count']
        assert int(query[key('domainEntryCount','domain_entry_count')])==len(config['domains'])
        for i,entry in enumerate(config['domains']):
            for field in ('list','mode'): assert int(query[f'{prefix}domain.{i}.{field}'])==entry[field]
            assert query[f'{prefix}domain.{i}.name']==entry['name']
    for i,rule in enumerate(config['rules']):
        for field in ['version','uid','family','protocol','action']:
            assert int(query[f'{prefix}rule.{i}.{field}'])==rule[field]
        if pixel:
            wire=list(map(int,query[f'rule.{i}.wire'].split(',')))
            assert len(wire)==43 and wire[26]==rule['expression_length']
            assert b''.join(n.to_bytes(4,'big') for n in wire[27:43])==rule['expression'].ljust(64,b'\0')
            fields='uid network_context ifindex priority order family protocol direction action source_prefix destination_prefix source_port_first source_port_last destination_port_first destination_port_last reserved'.split()
            assert wire[2:18]==[rule[f] for f in fields]
            assert b''.join(n.to_bytes(4,'big') for n in wire[18:22])==rule['source']
            assert b''.join(n.to_bytes(4,'big') for n in wire[22:26])==rule['destination']
        else:
            assert int(query[f'config.rule.{i}.expression_length'])==rule['expression_length']
            assert query[f'config.rule.{i}.expression']==rule['expression'].hex()
    for kind in ['edge','binding']:
        for i,value in enumerate(config[kind+'s']):assert query[f'{prefix}{kind}.{i}']==','.join(map(str,value))

def packet_evidence(trace, case, config, path):
    vpn=case.get('profile')=='vpn';payload=(case['nonce']+(':0' if vpn else '')).encode()
    admitted=[p for p in rows(trace,'s216 stage=admit ') if p.get('direction')=='3' and p.get('uid')==str(case['uid']) and bytes.fromhex(p.get('raw',''))[28:]==payload]
    assert len(admitted)==1,'unique actual outbound packet'
    p=admitted[0];token=p['token'];generation=str(case['generation']);facts=packet_facts(p)
    assert p['generation']==generation and facts['uid']==case['uid']
    assert (facts['sport'],facts['dport'])==(case['source_port'],case['destination_port'])
    assert facts['src']==('10.111.0.2' if vpn else '127.0.0.1')
    assert facts['dst']==case.get('host','127.0.0.2')
    assert facts['network']==(4 if vpn else None),'controlled availability contract'
    expected=reference.ordered_reference(logical_rules(config,facts['uid']),facts)
    assert expected['rule_id']==case['rule_version'] and expected['mode']==case['mode']
    assert expected['action']==case['declared_action'] and (expected['actual_action']==1)==case['delivered']
    decisions=[r for r in rows(trace,'s209 event=l4 ') if r.get('token')==token and r.get('generation')==generation]
    assert len(decisions)==1,'one logical decision'
    decision=decisions[0]
    for name,key in [('rule_id','rule'),('winner_rank','rank'),('action','action'),('mode','mode'),('actual_action','actual_action')]:
        assert int(decision[key])==expected[name],name
    assert decision['status']=='0' and int(decision['candidates'])==len(effective(config,facts['uid']))
    assert int(decision['revision'])==config['revision']==case['revision']
    assert int(decision['snapshot_hash'])==snapshot_hash(path),'saved-source snapshot binding'
    assert len([r for r in rows(trace,'s203 event=buffer_free ') if r.get('obligation')==token])==1
    if vpn:
        assert p['source']=='TUN_CAPTURED'
        completions=[r for r in rows(trace,'s213 event=completion source=TUN_CAPTURED ') if r.get('token')==token]
        assert len(completions)==1 and int(completions[0]['policy_drop'])==int(not case['delivered'])
        copies=[r for r in rows(trace,'s237 event=input_copy ') if r.get('token')==token]
        assert len(copies)==int(case['delivered'])
        if copies:
            assert copies[0]['result']=='0' and copies[0]['owner']==p['owner']
            returned=[r for r in rows(trace,'s216 stage=admit source=FLOW_STACK_RETURN ') if bytes.fromhex(r.get('raw',''))[28:]==payload]
            assert len(returned)==1
            return_facts=packet_facts(returned[0]);assert return_facts['direction']==1
            assert (return_facts['src'],return_facts['dst'],return_facts['sport'],return_facts['dport'])==(facts['dst'],facts['src'],facts['dport'],facts['sport'])
            assert reference.ordered_reference(logical_rules(config,facts['uid']),return_facts)['rule_id']==0
            completed=[r for r in rows(trace,'s213 event=completion source=FLOW_STACK_RETURN ') if r.get('token')==returned[0]['token']]
            assert len(completed)==1 and completed[0]['policy_drop']=='0'
    else:
        assert p['source']=='NFQ_CAPTURED'
        verdicts=[r for r in rows(trace,'s242 event=verdict_syscall ') if r.get('token')==token and r.get('generation')==generation]
        assert len(verdicts)==1 and verdicts[0]['packet']==p['packet_id'] and int(verdicts[0]['result'])>=0
        assert int(verdicts[0]['verdict'])==int(case['delivered'])

def verify(directory):
    d=Path(directory);run=json.loads((d/'result.json').read_text());pixel='serial' in run
    assert run['status']=='RAW_COMPLETE' and run['process_absent'] and not run.get('error') and not run.get('cleanup_error')
    build=chain.verify_product_build(run['build'])
    assert digest(run['build'])==run['build_sha256'] and build['source_sha256']==run['source_sha256']
    assert build['completed_ns']<run['started_ns']<run['completed_ns'] and digest(d/'runner.py')==run['runner_sha256']
    phases=['and','or','not','observe']
    if pixel:
        assert digest(build['apk'])==build['apk_sha256']==(d/'installed-apk.txt').read_text().split()[0]
        assert {Path(l.split()[1]).name:l.split()[0] for l in (d/'installed-native.txt').read_text().splitlines()}==build['native_sha256']
        assert digest(d/'echo')==run['endpoint_build']['binary_sha256'] and digest(d/'echo.c')==run['endpoint_build']['source_sha256']
        expected=[f'{profile}-{op}-{port}' for profile,ports in [('root',[32000,32001]),('vpn',[42000,42001])] for op in phases for port in ports]
        assert [c['phase'] for c in run['cases']]==expected
        for life in run['lifetimes']:
            label=life['label'];running=props(d/(label+'-running.properties'));stopped=props(d/(label+'-stopped.properties'))
            assert running['generation']==str(life['generation']) and running['profile']==label and running['state']=='running'
            assert running['protectionRunning']==('true' if label=='root' else 'false')
            assert stopped['state']=='stopped' and stopped['mayBeActive']==stopped['protectionRunning']=='false' and life['process_absent']
            assert not (d/(label+'-queues-after.txt')).read_text().strip() and 'SAKAMOTO' not in (d/(label+'-hooks-after.txt')).read_text()
            process=(d/(label+'-process.txt')).read_text()
            assert set(map(int,next(l for l in process.splitlines() if l.startswith('Uid:')).split()[1:]))=={0 if label=='root' else run['uid']}
        for owner in d.glob('*-owner.txt'):assert owner.read_text().strip()==f"{run['uid']}:{run['uid']}:600"
        phase_names=[p+'-'+op for p in ['root','vpn'] for op in phases]
    else:
        for name,value in build['artifact_hashes'].items():assert digest(Path(run['artifact'])/name)==value
        assert digest(Path(run['artifact'])/'product-vpp-artifact.properties')==run['manifest_sha256']
        assert run['policy_uids']==[12001] and 'NFQUEUE' not in (d/'hooks-after.txt').read_text()
        assert [(c['phase'],c['source_port']) for c in run['cases']]==[(op,p) for op in phases for p in [65534,65535]]
        assert props(d/'first-stopped.txt')['absent']=='True' and 'root.stop=ok' in (d/'first-stop.txt').read_text()
        phase_names=phases
    prior=None
    for phase in phase_names:
        config=source(d/(phase+'-source.conf'));q=props(d/(phase+('-apply.properties' if pixel else '-apply.txt')))
        query_source(config,q,pixel)
        assert len(config['rules'])==2 and not config['rules'][1]['expression']
        # Confirm requested source is the documented Boolean case independently
        # of collector expectations or the compiler's published plan.
        profile=phase.split('-')[0] if pixel else 'linux';operator=phase.split('-')[-1]
        port={'root':32001,'vpn':42001,'linux':65535}[profile]
        expected={'and':('and',('dport',40609 if pixel else 65535,40609 if pixel else 65535),('sport',port,port)),
                  'or':('or',('not',('network',4 if profile=='vpn' else 1)),('sport',port,port)),
                  'not':('not',('sport',port,port)), 'observe':('not',('sport',port,port))}[operator]
        assert expression(config['rules'][0]['expression'])==expected
        if prior:
            assert config['revision']==prior['revision']+1
            assert config['rules'][0]['version']==prior['rules'][0]['version']+1
            assert config['rules'][1]['version']==prior['rules'][1]['version']
        prior=config
        if pixel:
            tree=ET.parse(d/(phase+'-before.xml'))
            assert any(n.get('text')=='Replace all rules' and n.get('enabled')=='true' for n in tree.iter('node'))
            assert (d/(phase+'-result.png')).read_bytes().startswith(b'\x89PNG')
    for case in run['cases']:
        assert int(case['nonce'].rsplit('-',1)[1])>run['started_ns']
        config_path=d/case['source_file'];config=source(config_path)
        query,before=props(d/case['query']),props(d/case['before']);prefix='' if pixel else 'query.'
        key=lambda java,native:prefix+(java if pixel else native)
        query_source(config,query,pixel)
        assert int(query[key('winnerVersion','winner_version')])==case['rule_version']
        assert int(query[key('winnerRevision','winner_revision')])==case['revision']
        assert int(query[key('winnerAction','winner_action')])==case['declared_action']
        assert int(query[key('logicalHits','logical_hits')])==int(before[key('logicalHits','logical_hits')])+1
        assert int(query[key('actualDrops','actual_drops')])==int(before[key('actualDrops','actual_drops')])+int(not case['delivered'])
        probe=props(d/case['probe']) if pixel else json.loads((d/case['probe']).read_text())
        assert str(probe['uid'])==str(case['uid']) and probe['nonce']==case['nonce']
        if pixel:
            vpn=case['profile']=='vpn'
            delivered=probe.get('packet.0')=='echo' if vpn else probe.get('result')=='udp_echo_matched'
            endpoint=json.loads((d/'lan-endpoint.json').read_text()) if vpn else (d/case['endpoint']).read_text()
            assert ((case['nonce']+(':0' if vpn else '')) in endpoint)==delivered==case['delivered']
        else:
            assert (probe['received']==case['nonce'])==case['delivered']==(case['nonce'] in json.loads((d/'endpoint.json').read_text()))
        trace=(d/(case['lifetime']+('-stop.log' if pixel else '-vpp.log'))).read_text()
        packet_evidence(trace,case,config,config_path)
    root_trace=(d/('root-stop.log' if pixel else 'first-vpp.log')).read_text()
    zero=rows(root_trace,'s242 event=stop_native_zero ')
    assert zero and all(zero[-1][k]=='0' for k in ['pending','buffers','obligations','handoffs','completion_frames'])
    if pixel:
        stops=rows((d/'vpn-stop.log').read_text(),'s237 event=owner_stopped ')
        assert len(stops)==2 and {s['owner'] for s in stops}=={'0','1'}
        for stop in stops:
            assert all(stop[k]=='0' for k in ['sessions','inputs','pbufs','buffers','obligations','frames'])
            assert stop['sockets_created']==stop['sockets_closed'] and stop['timer_fd']==stop['broker_fd']=='-1'
    return dict(status='PASS',platform='pixel' if pixel else 'linux',packets=len(run['cases']),source_sha256=run['source_sha256'])

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('directory',type=Path);args=parser.parse_args()
    result=verify(args.directory);result.update(verifier_sha256=digest(__file__),directory=str(args.directory))
    print(json.dumps(result,indent=2))
