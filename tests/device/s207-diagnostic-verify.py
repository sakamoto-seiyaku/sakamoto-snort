"""Native supplemental assignment proof, explicitly separate from NFQUEUE traffic."""
import collections, importlib.util, json, re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
base=module('base207',ROOT/'tests/device/verify-s206-root-lanes.py')
ao=module('assignment207',ROOT/'tests/device/s207-owner-oracle.py')
def vectors(text):
    thread=None;result=collections.Counter()
    for line in text.splitlines():
        m=re.match(r'Thread (\d+) ',line)
        if m:thread=int(m[1])
        m=re.match(r'(product-packet-[a-z-]+)\s+active\s+(\d+)\s+(\d+)',line)
        if m:result[(thread,m[1])]=int(m[3])
    return result

def verify(cases,trace,before,after):
    errors=[];expected_vectors=collections.Counter();rows=base.records(trace)
    assignments=base.rows(trace,'s207 ');identities={};remotes=0;valid_count=0
    def require(ok,message):
        if not ok:errors.append(message)
    require(len(cases)==14,'14 bounded diagnostic carriers')
    for c in cases:
        token=str(216000000+c['case']);arrival=c['worker'];origin_thread=arrival+1
        packet=[d for d in rows if d.get('token',d.get('obligation'))==token]
        events=[d for d in packet if 'event' in d];by={d['event']:d for d in events}
        saved=[d for d in assignments if d['token']==token]
        facts=[d for d in packet if 'stage' in d and 'event' not in d]
        require(bool(saved) and facts[0]['raw']==c['raw'],'native diagnostic bytes '+token)
        expected=dict(valid=0,owner=65535,hash=0,key_kind=0) if c['invalid'] else ao.assignment(base.oracle.facts(c['raw']))
        remote=not c['invalid'] and expected['owner']!=arrival
        remotes+=int(remote);valid_count+=int(not c['invalid'])
        policy_thread=origin_thread if c['invalid'] else expected['owner']+1
        names=['admit','terminal','completion_publish','completion_consume','buffer_free']
        if not c['invalid']:names+=['owner_delivery','policy']
        if remote:names+=['primary_publish','primary_accepted','primary_dequeue','completion_return_publish','completion_return_accepted']
        require(collections.Counter(d['event'] for d in events)==collections.Counter(names),'one diagnostic lifecycle '+token)
        require([d['stage'] for d in saved]==(['admit','terminal'] if c['invalid'] else ['admit','policy','terminal']),'diagnostic stage path '+token)
        for d in saved:
            for k,v in expected.items():require(d[k]==str(v),'diagnostic assignment '+token+' '+k)
        for d in facts:
            require(d['source']=='GRAPH_INJECTED' and d['completion_kind']=='2','diagnostic source never claimed as NFQUEUE '+token)
            require(d['uid']==str(c['case']*10000) and d['ifindex']==str(c['case']+10) and d['context']==str(c['case']+100),'injected platform variation '+token)
            require(d['availability']==str(7 if c['case']%2 else 0) and d['direction']==str(3 if c['case']%2 else 1),'explicit platform availability/direction '+token)
        require(by['admit']['thread']==str(origin_thread) and by['admit']['assignment']==str(int(not c['invalid'])),'assignment once or absent for invalid L3 '+token)
        require(by['terminal']['thread']==by['completion_publish']['thread']==str(policy_thread),'terminal execution context '+token)
        require(by['completion_consume']['thread']==by['buffer_free']['thread']==str(origin_thread),'original diagnostic lane completion '+token)
        require(by['terminal']['intent']==by['completion_publish']['intent']==by['completion_consume']['intent']==str(2 if c['invalid'] else 1),'runtime DROP only invalid L3 '+token)
        if not c['invalid']:
            semantic=tuple((k,str(v)) for k,v in expected.items())
            require(identities.get(c['name'],semantic)==semantic,'arrival/platform invariant '+c['name'])
            identities[c['name']]=semantic
            expected_vectors[(policy_thread,'product-packet-policy')]+=1
        expected_vectors[(origin_thread,'product-packet-admit')]+=1
        expected_vectors[(policy_thread,'product-packet-terminal')]+=1
        expected_vectors[(origin_thread,'product-packet-origin-completi')]+=1
    require(vectors(after)-vectors(before)==expected_vectors,'diagnostic native vector delta')
    pre=base.rows(before,'primary.status ')[0];post=base.rows(after,'primary.status ')[0]
    require(int(post['published'])-int(pre['published'])==remotes and int(post['owner_checks'])-int(pre['owner_checks'])==valid_count,'diagnostic primary/owner delta')
    require(all(post[k]=='0' for k in ('pending_returns','handoff_debt','flows')) and post['credit0']==post['credit1']=='32','diagnostic zero handoff/flow debts')
    pre=base.rows(before,'completion.status ')[0];post=base.rows(after,'completion.status ')[0]
    require(all(post[k]=='0' for k in ('pending','frames','buffers','obligations')) and post['verdicts']==pre['verdicts'],'diagnostic zero debts and no invented kernel verdict')
    return errors
