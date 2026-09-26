#!/usr/bin/env python3
"""Independent run-ledger verifier; fails closed on missing or inconsistent rows."""
import argparse
import copy
import hashlib
import json
from pathlib import Path

def rows(text):
    data=[json.loads(s) for s in text.splitlines() if s.strip()]
    assert len({r['role'] for r in data})==len(data),'duplicate role'
    return {r['role']:r for r in data}

def verify(r):
    data=rows(r['stdout']);p=data['producer'];t=data['producer_timing']
    expected_exit=6 if r['scenario']=='corrupt' else 42 if r['scenario']=='crash' else 0
    assert r['exit']==expected_exit,(r['id'],'exit',r['exit'],r['stderr'])
    assert not r['stderr'],r['stderr']
    assert r['query']['exit']==0 and not r['query']['stderr'],'query failed'
    q=rows(r['query']['stdout'])['independent_query']
    assert p['generation']==q['generation']==r['generation'],'generation'
    assert p['channels']==q['channels'],'independent counter query mismatch'
    assert r['stale_query']['exit']==3,'stale query accepted'
    assert t['count']==r['count'] and 0<t['cpu_ns']<=t['wall_ns']*2,'timing'
    assert 0<=t['attempt_p50_ns']<=t['attempt_p99_ns']<=t['attempt_max_ns'],'quantiles'
    assert sum(c['attempted'] for c in p['channels'])==r['count']+1,'offered count'
    assert p['channels'][0]['invalid']==1 and p['channels'][1]['invalid']==0,'invalid admission'
    for c in p['channels']:
        assert c['attempted']==c['accepted']+c['dropped']+c['invalid'],'partition'
    if r['scenario'] in ['absent','stopped','pause','isolation','crash']:
        assert sum(c['dropped'] for c in p['channels'])>0,'pressure did not fill'
    if r['scenario'] in ['absent','stopped','crash']:
        assert 'consumer_result' not in data,'unexpected reader'
        if r['scenario']=='crash':
            assert data['consumer_crash']['generation']==r['generation']
            assert data['consumer_crash']['seen_sequence']==1,'crash did not occur inside first read'
        return data
    c=data['consumer'];res=data['consumer_result']
    assert c['generation']==r['generation'] and c['mapping']!=p['mapping'],'mapping/generation'
    assert c['shared_bytes']==p['shared_bytes'],'mapping size'
    assert c['timeouts']==res['wait_error']==0,'notification timeout'
    assert res['stale_rejected'] is True,'stale attach'
    assert res['bad']==(1 if r['scenario']=='corrupt' else 0),'content/ordering failure'
    assert 0<=res['latency_p50_ns']<=res['latency_p95_ns']<=res['latency_p99_ns']<=res['latency_max_ns'],'latency quantiles'
    for index,(sent,received) in enumerate(zip(p['channels'],res['channels'])):
        if r['scenario']=='isolation' and index==1:
            assert received['count']==0,'debug drained during isolation'
        else:
            assert sent['accepted']==received['count'],'unexplained loss'
            for key in ['sum','xor','bytes']:assert sent[key]==received[key],key
    if r['name'] in ['steady','batch1','batch128','sparse','idle','smoke','restart','corrupt']:
        assert p['channels'][0]['dropped']==0,'loss in paced workload'
    if r['scenario']=='isolation':
        assert p['channels'][0]['dropped']==0,'debug pressure affected normal capacity'
        assert res['channels'][0]['count']==r['count']//100,'normal isolation count'
    return data

def main():
    p=argparse.ArgumentParser();p.add_argument('runs',type=Path);p.add_argument('--build',type=Path,required=True)
    a=p.parse_args();manifest=json.loads((a.runs/'runs.json').read_text())
    digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    assert digest(a.build/'build.json')==manifest['build_manifest_sha256'],'build binding'
    build=json.loads((a.build/'build.json').read_text())
    assert build['target']==manifest['target'],'target mismatch'
    expected={
        'steady':(32000,32,1000,'normal'),'batch1':(1000,1,1000,'normal'),
        'batch128':(128000,128,1000,'normal'),'sparse':(100,1,20000,'normal'),
        'idle':(1,1,0,'idle'),'burst':(200000,128,0,'normal'),
        'pause':(100000,32,0,'pause'),'stopped':(100000,32,0,'stopped'),
        'absent':(100000,32,0,'absent'),'isolation':(32000,32,1000,'isolation'),
        'crash':(100000,32,0,'crash'),'corrupt':(10,1,1000,'corrupt'),
        'restart':(1000,32,1000,'normal')}
    assert set(manifest['runs'])=={f'{rep}-{name}-{candidate}' for rep in range(3) for name in expected for candidate in ['aeron','vpp']},'incomplete matrix'
    assert len(manifest['runs'])==78,'duplicate runs'
    for path,value in build['artifacts'].items():assert digest(a.build/path)==value,('artifact',path)
    for path,value in build['source'].items():assert digest(a.build/'source'/path)==value,('source',path)
    if manifest['target']=='android':
        assert (a.runs/'installed-artifacts.json').exists(),'missing installed artifact proof'
        installed=json.loads((a.runs/'installed-artifacts.json').read_text())
        assert len(installed)==8,'incomplete device artifact readback'
        for item in installed:
            artifact_hash=build['artifacts'][item['candidate']+'/'+item['file']]
            assert item['expected_sha256']==artifact_hash==item['readback']['stdout'].split()[0]
        assert json.loads((a.runs/'cleanup.json').read_text())['clean'],'device cleanup'
    reports=[]
    generations=set()
    for name in manifest['runs']:
        r=json.loads((a.runs/(name+'.json')).read_text());data=verify(r)
        assert (r['count'],r['batch'],r['interval_us'],r['scenario'])==expected[r['name']],'workload envelope'
        assert r['id']==name==f"{r['rep']}-{r['name']}-{r['candidate']}",'run identity'
        assert r['generation'] not in generations,'reused generation'
        generations.add(r['generation'])
        timing=data['producer_timing']
        assert 0<=timing['export_p50_ns']<=timing['export_p99_ns']<=timing['export_max_ns'],'full export timing'
        assert timing['export_max_ns']>=timing['attempt_max_ns'],'omitted queue work'
        reports.append({'id':name,'candidate':r['candidate'],'name':r['name'],'rep':r['rep'],**data})
    # Mutation checks prove missing/bad witnesses cannot silently pass this verifier.
    sample=json.loads((a.runs/(next(x for x in manifest['runs'] if '-steady-' in x or '-smoke-' in x)+'.json')).read_text())
    mutations=[]
    def mutate(label,fn):
        value=copy.deepcopy(sample);fn(value)
        try:verify(value)
        except (AssertionError,KeyError,ValueError):mutations.append(label);return
        raise AssertionError('accepted mutation '+label)
    mutate('exit',lambda r:r.update(exit=9))
    mutate('stale',lambda r:r['stale_query'].update(exit=0))
    mutate('missing-consumer',lambda r:r.update(stdout='\n'.join(x for x in r['stdout'].splitlines() if 'consumer_result' not in x)))
    def change_role(r,role,key,value):
        d=rows(r['stdout']);d[role][key]=value;r['stdout']='\n'.join(json.dumps(x) for x in d.values())
    mutate('content',lambda r:change_role(r,'consumer_result','bad',1))
    mutate('wake',lambda r:change_role(r,'consumer_result','wait_error',1))
    mutate('same-address',lambda r:change_role(r,'consumer','mapping',rows(r['stdout'])['producer']['mapping']))
    def loss(r):
        d=rows(r['stdout']);d['consumer_result']['channels'][0]['count']-=1;r['stdout']='\n'.join(json.dumps(x) for x in d.values())
    mutate('loss',loss)
    def query(r):
        d=rows(r['query']['stdout']);d['independent_query']['channels'][0]['dropped']+=1;r['query']['stdout']=json.dumps(next(iter(d.values())))
    mutate('independent-counter',query)
    result={'status':'PASS','runs':len(reports),'mutations_rejected':mutations,'verifier_sha256':digest(Path(__file__)),'reports':reports}
    (a.runs/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='reports'}))
if __name__=='__main__':main()
