#!/usr/bin/env python3
"""Independent T04 graph, ordered-winner, query and real packet verifier."""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import struct
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def props(path): return dict(line.split('=',1) for line in Path(path).read_text().splitlines() if '=' in line and not line.startswith('#'))
def rows(text,prefix): return [dict(part.split('=',1) for part in line.split()[1:] if '=' in part) for line in text.splitlines() if line.startswith(prefix)]
def source(path):
    raw=Path(path).read_bytes();assert raw[:8]==b'SKRULE03','source schema'
    revision,count,retained_count=struct.unpack_from('<QII',raw,8)
    assert count<=256 and retained_count<=4096 and revision
    retained=struct.unpack_from('<'+'Q'*retained_count,raw,24)
    assert len(set(v>>16 for v in retained))==retained_count and all(v>>16 and v&65535 for v in retained)
    at=24+8*retained_count;rules=[]
    names='uid network_context ifindex priority order family protocol direction action source_prefix destination_prefix source_port_first source_port_last destination_port_first destination_port_last reserved'.split()
    for _ in range(count):
        r=struct.unpack_from('<QQ16I16s16s',raw,at);at+=112
        assert r[0] in retained and r[1]==0
        rules.append(dict(zip(names,r[2:18]),version=r[0],source=r[18],destination=r[19]))
    gc,ec,bc=struct.unpack_from('<III',raw,at);at+=12
    assert gc<=64 and ec<=512 and bc<=128
    groups=list(struct.unpack_from('<'+'I'*gc,raw,at));at+=4*gc
    edges=[struct.unpack_from('<III',raw,at+12*i) for i in range(ec)];at+=12*ec
    bindings=[struct.unpack_from('<IIIII',raw,at+20*i) for i in range(bc)];at+=20*bc
    assert at==len(raw) and len(set(groups))==gc and all(groups)
    return dict(revision=revision,rules=rules,groups=groups,edges=edges,bindings=bindings)

def effective(config,uid):
    # Test-only set expansion, independent of the Product DFS implementation.
    resolved={g:set() for g in config['groups']}
    for _ in config['groups']:
        for owner,kind,target in config['edges']:
            assert owner in resolved
            if kind==1: assert target<len(config['rules']);resolved[owner].add(target)
            else: assert kind==2 and target in resolved;resolved[owner].update(resolved[target])
    modes={i:0 for i,r in enumerate(config['rules']) if r['uid']==uid}
    for _,subject,kind,target,mode in config['bindings']:
        if subject!=uid:continue
        selected={target} if kind==1 else resolved[target]
        for i in selected:
            assert i not in modes or modes[i]==mode,'conflicting source modes'
            modes[i]=mode
    return [(config['rules'][i],mode) for i,mode in modes.items()]

def ordered_winner(config,uid,raw):
    assert raw[0]>>4==4 and raw[9]==17
    offset=(raw[0]&15)*4;sp,dp=struct.unpack_from('!HH',raw,offset)
    applicable=[]
    for rule,mode in effective(config,uid):
        if rule['family']!=4 or rule['protocol']!=17 or rule['direction'] not in (0,3):continue
        if not (rule['source_port_first']<=sp<=rule['source_port_last'] and rule['destination_port_first']<=dp<=rule['destination_port_last']):continue
        if any(ipaddress.ip_address(raw[a:a+4]) not in ipaddress.ip_network((str(ipaddress.ip_address(rule[field][:4])),rule[field+'_prefix']),strict=False) for field,a in [('source',12),('destination',16)]):continue
        applicable.append((rule,mode))
    assert applicable,'expected an ordinary rule winner'
    rule,mode=min(applicable,key=lambda r:(r[0]['priority'],r[0]['order'],r[0]['version']>>16))
    return rule,mode,len(effective(config,uid))

def packet(trace,case,config):
    payload=(case['nonce']+(':0' if case.get('profile')=='vpn' else '')).encode()
    admitted=[r for r in rows(trace,'s216 stage=admit ') if bytes.fromhex(r.get('raw',''))[28:]==payload and r.get('direction')=='3']
    assert len(admitted)==1,'unique actual packet'
    p=admitted[0];raw=bytes.fromhex(p['raw']);token=p['token'];generation=str(case['generation'])
    assert p['generation']==generation and p['uid']==str(case['uid']) and int(p['availability'])&1
    rule,mode,candidates=ordered_winner(config,case['uid'],raw)
    assert rule['version']==case['rule_version'] and mode==case['mode']
    assert rule['action']==case['declared_action'] and (mode==1 or rule['action']==1)==case['delivered']
    decisions=[r for r in rows(trace,'s209 event=l4 ') if r.get('token')==token and r.get('generation')==generation]
    assert len(decisions)==1
    d=decisions[0]
    assert int(d['rule'])==rule['version'] and int(d['revision'])==config['revision']==case['revision']
    assert d['action']==str(rule['action']) and d['mode']==str(mode) and d['actual_action']==str(1 if case['delivered'] else 2)
    assert d['status']=='0' and int(d['candidates'])==candidates and d['rank']=='1'
    assert len([r for r in rows(trace,'s203 event=buffer_free ') if r.get('obligation')==token])==1
    if case.get('profile')=='vpn':
        assert p['source']=='TUN_CAPTURED' and struct.unpack_from('!HH',raw,20)==(42001,40609)
        assert raw[12:20]==bytes([10,111,0,2,192,168,4,5])
        completions=[r for r in rows(trace,'s213 event=completion source=TUN_CAPTURED ') if r.get('token')==token]
        assert len(completions)==1 and completions[0]['policy_drop']==str(int(not case['delivered']))
        copies=[r for r in rows(trace,'s237 event=input_copy ') if r.get('token')==token]
        assert len(copies)==int(case['delivered'])
        if case['delivered']:
            assert copies[0]['result']=='0' and copies[0]['owner']==p['owner']
            returned=[r for r in rows(trace,'s216 stage=admit source=FLOW_STACK_RETURN ') if bytes.fromhex(r.get('raw',''))[28:]==payload]
            assert len(returned)==1
            completions=[r for r in rows(trace,'s213 event=completion source=FLOW_STACK_RETURN ') if r.get('token')==returned[0]['token']]
            assert len(completions)==1 and completions[0]['policy_drop']=='0'
    else:
        assert p['source']=='NFQ_CAPTURED'
        assert raw[12:20]==bytes([127,0,0,1,127,0,0,2]) and struct.unpack_from('!HH',raw,20)==(32000+(case['uid']==12002),40608)
        verdicts=[r for r in rows(trace,'s242 event=verdict_syscall ') if r.get('token')==token and r.get('generation')==generation]
        assert len(verdicts)==1 and verdicts[0]['packet']==p['packet_id'] and int(verdicts[0]['result'])>=0
        assert verdicts[0]['verdict']==str(int(case['delivered']))

def verify(directory):
    directory=Path(directory);run=json.loads((directory/'result.json').read_text())
    assert run['status']=='RAW_COMPLETE' and run['process_absent'] and not run.get('error') and not run.get('cleanup_error')
    spec=importlib.util.spec_from_file_location('t01_verify',ROOT/'tests/evidence/verify_t01_rule.py');chain=importlib.util.module_from_spec(spec);spec.loader.exec_module(chain)
    build=chain.verify_product_build(run['build'])
    assert digest(run['build'])==run['build_sha256'] and build['source_sha256']==run['source_sha256']
    assert build['completed_ns']<run['started_ns']<run['completed_ns'] and digest(directory/'runner.py')==run['runner_sha256']
    pixel='serial' in run
    if pixel:
        assert (directory/'installed-apk.txt').read_text().split()[0]==build['apk_sha256']==digest(build['apk'])
        installed={Path(l.split()[1]).name:l.split()[0] for l in (directory/'installed-native.txt').read_text().splitlines()}
        assert installed==build['native_sha256']
        assert digest(directory/'echo')==run['endpoint_build']['binary_sha256'] and digest(directory/'echo.c')==run['endpoint_build']['source_sha256']
        expected=['root-enforce','root-observe','vpn-enforce','vpn-observe']
        assert [c['phase'] for c in run['cases']]==expected
        for life in run['lifetimes']:
            label=life['label'];running=props(directory/(label+'-running.properties'));stopped=props(directory/(label+'-stopped.properties'))
            assert running['generation']==str(life['generation']) and running['profile']==life['profile']
            assert running['state']=='running' and running['protectionRunning']==('true' if label=='root' else 'false')
            assert stopped['state']=='stopped' and stopped['mayBeActive']==stopped['protectionRunning']=='false' and life['process_absent']
            process=(directory/(label+'-process.txt')).read_text()
            assert set(map(int,next(l for l in process.splitlines() if l.startswith('Uid:')).split()[1:]))=={0 if label=='root' else run['uid']}
            assert not (directory/(label+'-queues-after.txt')).read_text().strip() and 'SAKAMOTO' not in (directory/(label+'-hooks-after.txt')).read_text()
        assert (directory/'root-final-source.conf').read_bytes()==(directory/'vpn-read-source.conf').read_bytes()
        for owner in directory.glob('*-owner.txt'):assert owner.read_text().strip()==f"{run['uid']}:{run['uid']}:600"
        for phase in expected:
            config=source(directory/(phase+'-source.conf'));q=props(directory/(phase+'-apply.properties'))
            assert config['revision']==int(q['savedRevision'])==int(q['activeRevision']) and q['result']=='0'
            assert q['groupCount']=='2' and q['edgeCount']=='4' and q['bindingCount']=='2'
            for i,r in enumerate(config['rules']):
                wire=list(map(int,q[f'rule.{i}.wire'].split(',')))
                assert len(wire)==26 and wire[0]==r['version'] and wire[1]==0
                names='uid network_context ifindex priority order family protocol direction action source_prefix destination_prefix source_port_first source_port_last destination_port_first destination_port_last reserved'.split()
                assert wire[2:18]==[r[n] for n in names]
                assert b''.join(v.to_bytes(4,'big') for v in wire[18:22])==r['source']
                assert b''.join(v.to_bytes(4,'big') for v in wire[22:26])==r['destination']
            for i,e in enumerate(config['edges']):assert q[f'edge.{i}']==','.join(map(str,e))
            for i,b in enumerate(config['bindings']):assert q[f'binding.{i}']==','.join(map(str,b))
            captures=[directory/(phase+'-before.xml'),*directory.glob(phase+'-scroll*.xml')]
            text=(directory/(phase+'-request.txt')).read_text().rstrip('\n')
            assert any(any(n.get('content-desc')=='Complete direct rules' and n.get('text')==text for n in ET.parse(f).iter('node')) for f in captures)
            assert (directory/(phase+'-result.png')).read_bytes().startswith(b'\x89PNG')
        for profile in ['root','vpn']:
            before=source(directory/(profile+'-enforce-source.conf'));after=source(directory/(profile+'-observe-source.conf'))
            assert [r['version'] for r in before['rules']]==[r['version'] for r in after['rules']]
            assert after['revision']==before['revision']+1
    else:
        assert run['policy_uids']==[12001,12002]
        for name,value in build['artifact_hashes'].items():assert digest(Path(run['artifact'])/name)==value
        assert 'NFQUEUE' not in (directory/'hooks-after.txt').read_text()
        assert [(c['phase'],c['uid']) for c in run['cases']]==[(p,u) for p in ['mixed','reordered','conflict-retained','restart','promoted'] for u in [12001,12002]]
        failed=props(directory/'conflict-apply.txt');assert failed['config.result']=='13'
        assert (directory/'conflict-source.conf').read_bytes()==(directory/'reordered-source.conf').read_bytes()
        for life in ['first','restart']:
            assert props(directory/(life+'-stopped.txt'))['absent']=='True'
            assert 'root.stop=ok' in (directory/(life+'-stop.txt')).read_text()
        for phase in ['mixed','reordered','promoted']:
            config=source(directory/(phase+'-source.conf'));q=props(directory/(phase+'-apply.txt'))
            assert config['revision']==int(q['config.saved_revision'])==int(q['config.active_revision']) and q['config.result']=='0'
            assert q['config.count']=='4' and q['config.active_count']=='8'
            for i,e in enumerate(config['edges']):assert q[f'config.edge.{i}']==','.join(map(str,e))
            for i,b in enumerate(config['bindings']):assert q[f'config.binding.{i}']==','.join(map(str,b))
    for c in run['cases']:
        phase=c['phase'] if pixel else {'conflict-retained':'reordered','restart':'reordered'}.get(c['phase'],c['phase'])
        config=source(directory/(phase+'-source.conf'));q=props(directory/c['query']);before=props(directory/c['before'])
        prefix='' if pixel else 'query.'
        winner='winnerVersion' if pixel else 'winner_version';revision='winnerRevision' if pixel else 'winner_revision';action='winnerAction' if pixel else 'winner_action'
        hits='logicalHits' if pixel else 'logical_hits';drops='actualDrops' if pixel else 'actual_drops'
        assert int(q[prefix+winner])==c['rule_version'] and int(q[prefix+revision])==c['revision'] and int(q[prefix+action])==c['declared_action']
        assert int(q[prefix+hits])==int(before[prefix+hits])+1 and int(q[prefix+drops])==int(before[prefix+drops])+int(not c['delivered'])
        probe=props(directory/c['probe']) if pixel else json.loads((directory/c['probe']).read_text())
        assert str(probe['uid'])==str(c['uid']) and probe['nonce']==c['nonce']
        assert int(c['nonce'].rsplit('-',1)[1])>run['started_ns']
        if pixel:
            delivered=probe.get('packet.0')=='echo' if c['profile']=='vpn' else probe.get('result')=='udp_echo_matched'
            endpoint=json.loads((directory/'lan-endpoint.json').read_text()) if c['profile']=='vpn' else (directory/c['endpoint']).read_text()
            assert ((c['nonce']+(':0' if c['profile']=='vpn' else '')) in endpoint)==c['delivered']==delivered
        else:assert (probe['received']==c['nonce'])==c['delivered']==(c['nonce'] in json.loads((directory/'endpoint.json').read_text()))
        trace=(directory/(c['lifetime']+('-stop.log' if pixel else '-vpp.log'))).read_text()
        packet(trace,c,config)
    for label in (['root'] if pixel else ['first','restart']):
        trace=(directory/(label+('-stop.log' if pixel else '-vpp.log'))).read_text()
        zero=rows(trace,'s242 event=stop_native_zero ');assert zero
        assert all(zero[-1][k]=='0' for k in ['pending','buffers','obligations','handoffs','completion_frames'])
    if pixel:
        stops=rows((directory/'vpn-stop.log').read_text(),'s237 event=owner_stopped ')
        assert len(stops)==2 and {s['owner'] for s in stops}=={'0','1'}
        for s in stops:
            assert all(s[k]=='0' for k in ['sessions','inputs','pbufs','buffers','obligations','frames'])
            assert s['sockets_created']==s['sockets_closed'] and s['timer_fd']==s['broker_fd']=='-1'
    return dict(status='PASS',platform='pixel' if pixel else 'linux',packets=len(run['cases']),source_sha256=run['source_sha256'])

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('directory',type=Path);a=parser.parse_args()
    result=verify(a.directory);result.update(verifier_sha256=digest(__file__),directory=str(a.directory))
    print(json.dumps(result,indent=2))
