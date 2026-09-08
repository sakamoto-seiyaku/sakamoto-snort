"""Independent S209 snapshot identity, content lifetime and worker-progress oracle."""
import collections, importlib.util
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('s208_flow',ROOT/'tests/device/s208-flow-verify.py')
flow=importlib.util.module_from_spec(spec);spec.loader.exec_module(flow)
rows=flow.rows

def verify(trace,runtime,flow_dump,generation,case):
 out=flow.verify(trace,runtime,flow_dump,generation)
 errors=out['errors'];events=rows(trace,'s209 ');pubs=[d for d in events if d['event']=='publish'];by_token=collections.defaultdict(list)
 def require(ok,msg):
  if not ok:errors.append(msg)
 controls={(str(p['revision']),str(p['hash'])):p for p in case['publications']}
 if case.get('drop_policy'):
  p=case['drop_policy'];controls[(str(p['revision']),str(p['hash']))]=p
 published={d['sequence']:d for d in pubs}
 require(len(published)==len(pubs),'unique publication sequence')
 require(set(controls)<= {(d['revision'],d['snapshot_hash']) for d in pubs},'all requested publications completed')
 for d in pubs:
  require(d['generation']==str(generation) and d['thread']=='0','main-thread same-generation publisher')
  require(int(d['reuse_begin_ns'])<=int(d['publish_begin_ns'])<=int(d['mono_ns']),'recorded bank reuse/publication interval')
 for d in events:
  if 'token' in d:by_token[d['token']].append(d)
 require(set(by_token)==set(out['by_token']),'one acquired snapshot per actual packet')
 flow_events={d['token']:d for d in rows(trace,'s208 ')}
 progress={w:[] for w in (0,1)};retired=collections.Counter();holds=[]
 for token,packet in out['by_token'].items():
  raw,assignment,facts,lifecycle=packet;owner=assignment['owner'];records=by_token[token]
  names=[d['event'] for d in records];expected=['acquire','gate','l4','release'] if 'l4' in names else ['acquire','gate','release']
  if 'hold_begin' in names:expected=['acquire','gate','hold_begin','hold_end','l4','release'];holds.append(token)
  require(names==expected,'single ordered protected policy path '+token)
  d={x['event']:x for x in records};acq=d['acquire'];release=d['release'];pub=published[acq['sequence']]
  identity=(str(generation),acq['revision'],acq['snapshot_hash'])
  require(tuple(pub[k] for k in ('generation','revision','snapshot_hash'))==identity and acq['bank']==pub['bank'],'acquired published bank '+token)
  control=controls[(acq['revision'],acq['snapshot_hash'])]
  for event in [acq,d['gate'],release]+([d['l4']] if 'l4' in d else []):
   require(tuple(event[k] for k in ('generation','revision','snapshot_hash'))==identity,'same snapshot through every stage '+token)
   require(event['thread']==str(owner+1),'snapshot executed by canonical worker '+token)
  require(release['content_generation']==identity[0] and release['content_revision']==identity[1] and release['content_hash']==identity[2],'acquired bank content survives release '+token)
  require(acq['worker']==release['worker']==acq['owner']==release['owner']==str(owner),'owner-local reader provenance '+token)
  require(release['bank']==acq['bank'] and release['sequence']==acq['sequence'],'same reader claim released '+token)
  times=[int(x['mono_ns']) for x in records];require(times==sorted(times),'causal snapshot clock '+token)
  for later in pubs:
   if later['bank']==acq['bank'] and int(later['sequence'])>int(acq['sequence']):
    require(int(later['reuse_begin_ns'])>=int(release['mono_ns']),'bank never overwritten while packet holds reader '+token)
   # Outside the short publication interval, an acquisition must use the
   # latest completed publication. The sequence proves the exact choice at
   # the atomic boundary without guessing from printf order.
  completed=[p for p in pubs if int(p['mono_ns'])<=int(acq['mono_ns'])]
  future=[p for p in pubs if int(p['publish_begin_ns'])>int(acq['mono_ns'])]
  if completed:
   latest=max(completed,key=lambda p:int(p['sequence']))
   require(int(acq['sequence'])>=int(latest['sequence']),'no stale snapshot acquisition after publication '+token)
  if future:require(int(acq['sequence'])<min(int(p['sequence']) for p in future),'no acquisition before publication began '+token)
  known=int(facts['availability'])&1 and int(facts['uid'])==int(case['uid'])
  gate_drop=control.get('mode')=='gate-drop' and known
  gate_rule=(control['rule'] if gate_drop else control['rule']+100) if known else 0
  l4_rule=control['rule']+(0 if raw['family']==4 else 2)+(raw['protocol']==17) if known else 0
  require(d['gate']['rule']==str(gate_rule) and d['gate']['action']==str(2 if gate_drop else int(bool(known))),'Gate evaluates acquired content '+token)
  if gate_drop:
   require('l4' not in d and lifecycle['policy']['rule']==str(gate_rule) and flow_events[token]['event']=='early_drop','Gate DROP terminates before L4 and allocation '+token)
  else:
   require('l4' in d and d['l4']['status']=='0' and d['l4']['rule']==str(l4_rule) and d['l4']['action']==str(int(bool(known))),'L4 evaluates acquired content '+token)
   require(lifecycle['policy']['rule']==str(l4_rule),'terminal policy attribution comes from acquired view '+token)
  mutation=flow_events[token]
  require((mutation['policy_generation'],mutation['revision'],mutation['snapshot_hash'])==identity,'decision cache carries complete acquired identity '+token)
  progress[owner].append((int(acq['mono_ns']),acq['revision'],acq['snapshot_hash'],token))
  retired[owner]+=acq['sequence']!=release['published_sequence']
 require(len(holds)==1,'one bounded held real packet')
 if holds:
  held={d['event']:d for d in by_token[holds[0]]};old=held['acquire'];end=held['release']
  overlapping=[p for p in pubs if int(old['mono_ns'])<int(p['mono_ns'])<int(end['mono_ns'])]
  require(bool(overlapping),'new publication completes while old packet remains acquired')
  require(any(d['event']=='acquire' and d['worker']=='1' and int(old['mono_ns'])<int(d['mono_ns'])<int(end['mono_ns']) and int(d['sequence'])>int(old['sequence']) for d in events),'other worker acquires new bank while old bank remains held')
 pools=rows(flow_dump,'flow.pool ');entries=rows(flow_dump,'flow.entry ')
 require(all(e['policy_generation']==str(generation) for e in entries),'stored cache generation')
 require(all(p['unavailable']==p['revision_mismatches']=='0' for p in pools),'owner-private flow diagnostics have no rejected mutation')
 workers=rows(flow_dump,'policy.worker ');snapshot=rows(flow_dump,'policy.snapshot ')[0]
 require(snapshot['packet_lock_acquisitions']==snapshot['readers0']==snapshot['readers1']=='0','no packet writer-lock acquisition or leaked readers')
 require(len(workers)==2,'two private worker reader ledgers')
 metrics={}
 for w in workers:
  owner=int(w['worker']);observed=progress[owner]
  require(int(w['acquired'])==int(w['released'])==len(observed) and int(w['retired'])==retired[owner] and w['mismatches']=='0','actual per-worker reader conservation')
  last=max(observed,key=lambda p:p[0])
  require((w['generation'],w['revision'],w['snapshot_hash'])==(str(generation),last[1],last[2]),'worker epoch only advances on its own acquired packet')
  steady_tokens=set()
  for nonce in case['nonces'][str(owner)] if str(owner) in case['nonces'] else case['nonces'][owner]:
   if '-steady-' not in nonce:continue
   tokens=[t for t,(raw,a,f,b) in out['by_token'].items() if nonce.encode().hex() in f['raw']]
   require(len(tokens)>=2 and {out['by_token'][t][1]['source_is_a'] for t in tokens}=={0,1},'fresh steady nonce traverses actual kernel and reverse echo '+nonce)
   require(all(out['by_token'][t][1]['owner']==owner for t in tokens),'steady traffic remains assigned to selected worker')
   steady_tokens.update(tokens)
  steady=sorted(p for p in observed if p[3] in steady_tokens)
  require(len(steady)>20 and len({(p[1],p[2]) for p in steady})>=4,'both workers progress through continuous revisions')
  span=(steady[-1][0]-steady[0][0])/1e9 if steady else 0
  gap=max((b[0]-a[0])/1e9 for a,b in zip(steady,steady[1:])) if len(steady)>1 else 999
  require(span>=1 and gap<=8,'bounded functional progress without long stall')
  metrics[owner]=dict(packets=len(observed),steady_span_seconds=span,max_steady_gap_seconds=gap,observed_epochs=len({(p[1],p[2]) for p in steady}),retired_packets=retired[owner])
 require(any(a['revision']==b['revision'] and a['snapshot_hash']!=b['snapshot_hash'] for a,b in zip(pubs,pubs[1:])),'same revision different hash published')
 out['worker_progress']=metrics;out['publications']=len(pubs)
 return out
