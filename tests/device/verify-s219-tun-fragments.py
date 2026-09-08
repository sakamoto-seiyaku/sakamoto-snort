#!/usr/bin/env python3
"""Reconstruct actual kernel/TUN originals and verify native fragment settlement."""
import argparse,collections,importlib.util,json,re,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--run',type=Path,required=True);a=p.parse_args()
def module(name,path):
 s=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
chain=module('chain','tests/evidence/product_chain.py');oracle=module('oracle','tests/device/s207-owner-oracle.py');vectors=module('vectors','tests/device/s219-fragment-matrix.py')
def rows(text,prefix):return [dict(re.findall(r'(\w+)=([^\s]+)',l)) for l in text.splitlines() if l.startswith(prefix)]
def props(text):return dict(l.split('=',1) for l in text.splitlines() if '=' in l and not l.startswith('#'))
errors=[]
def need(ok,message):
 if not ok:errors.append(message)
b=json.loads(a.build.read_text());r=json.loads((a.run/'result.json').read_text())
need(r['status']=='RAW_COMPLETE' and not r.get('cleanup_error'),'run/cleanup incomplete')
need(b['files']==chain.source_files(),'current source differs from build')
need(r['apk_sha256']==b['apk_sha256']==chain.digest(Path(b['apk'])) and r['native_sha256']==b['native_sha256'],'installed artifact binding')
need(b['started_ns']<b['completed_ns']<r['started_ns']<r['completed_ns'],'build/run ordering')
need(len(r['generations'])==2 and r['generations'][0]['generation']<r['generations'][1]['generation'],'fresh restart generations')
for name in ('ordinary-before','ordinary-resume'):
 state=props((a.run/(name+'.properties')).read_text());need(state.get('errorCode')=='vpn_flow_stack_not_ready' and state.get('mayBeActive')=='false','ordinary VPN readiness '+name)
total=0;fragment_count=0;datagrams=0;accepted=[]
for index,epoch in enumerate(r['generations']):
 label=f'g{index}';generation=str(epoch['generation']);log=(a.run/(label+'-vpp.log')).read_text();android=(a.run/(label+'-android-events.log')).read_text()
 capture=rows(log,'s213 event=capture ');total+=len(capture);by_token={e['token']:e for e in capture};need(len(by_token)==len(capture),'capture token reused')
 fragments={e['token']:e for e in rows(log,'s212 event=fragment_ingress ')};fragment_count+=len(fragments)
 published=rows(log,'s204 event=completion_publish ')+rows(log,'s212 event=completion_publish ');consumed=rows(log,'s204 event=completion_consume ');completed=rows(log,'s213 event=completion ');freed=rows(log,'s203 event=buffer_free ')
 snapshots=rows(log,'s218 event=packet_snapshot ');publications={e['revision']:e for e in rows(log,'s232 event=snapshot_publish ')}
 def one(records,token,name):
  found=[e for e in records if e.get('token',e.get('obligation'))==token];need(len(found)==1,name+' cardinality '+token);return found[0] if len(found)==1 else {}
 decoded={}
 for token,c in by_token.items():
  raw=bytes.fromhex(c['raw']);need(len(raw)==int(c['bytes']),'original span '+token)
  need(c['source']=='TUN_CAPTURED' and c['generation']==generation and c['thread']==c['tls']=='1' and c['lane']=='0' and c['uid_source']=='CONTROLLED_TEST_PROVIDER','actual native TUN origin '+token)
  frame=one(published,token,'frame');consume=one(consumed,token,'consume');done=one(completed,token,'adapter');free=one(freed,token,'free')
  need(frame.get('buffer')==consume.get('buffer')==done.get('buffer')==free.get('buffer')==c['buffer'],'original buffer conservation '+token)
  need(frame.get('generation')==consume.get('generation')==done.get('generation')==generation,'original generation '+token)
  need(frame.get('packet')==consume.get('packet')=='0' and frame.get('lane')==consume.get('lane')=='0','original TUN obligation '+token)
  need(consume.get('source')==done.get('source')==free.get('source')=='TUN_CAPTURED','fabricated capture source '+token)
  need(consume.get('thread')==done.get('thread')==free.get('thread')=='1','origin completion/free worker '+token)
  need(frame.get('intent')==consume.get('intent')==done.get('intent'),'intent changed '+token)
  need(all(done.get(k)=='0' for k in ('tun_writes','nfq_verdicts','flow_stack_admissions')),'unexpected endpoint routing '+token)
  snap=one(snapshots,token,'snapshot');publication=publications.get(snap.get('revision'),{})
  need(bool(publication) and publication.get('generation')==generation and publication.get('event_elapsed_ns')==snap.get('event_elapsed_ns'),'unpublished snapshot '+token)
  event=[l for l in android.splitlines() if f" revision={snap.get('revision')} " in l and f" event_elapsed_ns={snap.get('event_elapsed_ns')} " in l and ' code=0' in l]
  need(len(event)==1,'Android event binding '+token)
  mapping=dict(re.findall(r'(\d+)=(\d+)',re.search(r'interfaces=\{([^}]*)\}',event[0]).group(1))) if event else {}
  context=mapping.get(str(epoch['interface_index']),'0');need(snap.get('context')==context and snap.get('ifindex')=='0','snapshot facts '+token)
  if token in fragments:
   need(frame.get('kind')=='3' and frame.get('refs')=='1','typed fragment completion '+token)
   family=raw[0]>>4
   if family==4:
    offset=(int.from_bytes(raw[6:8],'big')&0x1fff)*8;header=(raw[0]&15)*4;key=(family,raw[12:20],raw[4:6]);more=bool(int.from_bytes(raw[6:8],'big')&0x2000)
    need(int.from_bytes(raw[2:4],'big')==len(raw) and vectors.checksum(raw[:header])==0,'original IPv4 header '+token)
   else:
    need(family==6 and raw[6]==44 and raw[40]==17,'original IPv6 Fragment Header '+token)
    offset=int.from_bytes(raw[42:44],'big')&0xfff8;header=48;key=(family,raw[8:40],raw[44:48]);more=bool(raw[43]&1)
    need(int.from_bytes(raw[4:6],'big')+40==len(raw),'original IPv6 length '+token)
   decoded[token]=dict(family=family,key=key,offset=offset,more=more,header=header,data=raw[header:])
   e=fragments[token];need(e.get('kind')=='3' and e.get('generation')==generation and e.get('buffer')==c['buffer'] and e.get('offset')==str(offset),'native fragment admission '+token)
   for k,v in dict(uid=str(r['uid']),ifindex='0',context=context,availability='5' if context!='0' else '1',direction='3',provenance='2').items():need(e.get(k)==v,'captured fragment platform '+token+'/'+k)
   release=one(rows(log,'s212 event=origin_release '),token,'fragment release');need(release.get('kind')=='3' and release.get('refs')=='1' and release.get('thread')=='1','fragment pin ownership '+token)
  else:
   admitted=one(rows(log,'s216 stage=admit '),token,'control admission');need(admitted.get('raw')==c['raw'],'control materialization '+token)
 targets=set();heads=[]
 for case_index,case in enumerate(epoch['cases']):
  matching=[t for t,c in by_token.items() if case['nonce'].encode() in bytes.fromhex(c['raw'])];need(len(matching)==1,'kernel UDP nonce '+case['nonce'])
  if len(matching)!=1:continue
  head=matching[0];first=decoded.get(head);need(first is not None and first['offset']==0,'target was not fragmented '+head)
  if not first:continue
  members=[t for t,d in decoded.items() if d['key']==first['key']];need(len(members)==2,'kernel originals per datagram '+head);targets.update(members);heads.append(head);datagrams+=1
  ordered=sorted(members,key=lambda t:decoded[t]['offset']);end=0;payload=b''
  for token in ordered:
   d=decoded[token];need(d['offset']==end and d['more']==(token!=ordered[-1]),'fragment coverage/flags '+token);payload+=d['data'];end+=len(d['data'])
  expected=bytearray(i%251 for i in range(1800));expected[:len(case['nonce'])]=case['nonce'].encode()
  need(payload[8:]==expected and len(payload)==1808,'actual kernel payload reconstruction '+head)
  sport,dport,length=struct.unpack_from('!HHH',payload);need(sport==case['port'] and dport==40633 and length==len(payload),'actual UDP tuple '+head)
  family=case['family'];lead=bytes.fromhex(by_token[head]['raw']);source=bytes(12)+lead[12:16] if family==4 else lead[8:24];destination=bytes(12)+lead[16:20] if family==4 else lead[24:40]
  pseudo=lead[12:20]+struct.pack('!BBH',0,17,len(payload)) if family==4 else lead[8:40]+struct.pack('!I3xB',len(payload),17)
  need(vectors.checksum(pseudo+payload)==0,'actual kernel UDP checksum '+head)
  success=one(rows(log,'s212 event=native_success '),head,'native success');need(success.get('originals')=='2' and success.get('survivor')==by_token[head]['buffer'] and success.get('family')==str(family),'native survivor '+head)
  m=one(rows(log,'s216 stage=admit '),head,'reassembled admit');pf=one(rows(log,'s216 stage=policy '),head,'policy');tf=one(rows(log,'s216 stage=terminal '),head,'terminal')
  data=bytes.fromhex(m.get('raw',''));header=20 if family==4 else 40
  need(len(data)==header+len(payload) and data[header:]==payload,'native assembled bytes '+head)
  need(m.get('l3')==m.get('l4')=='1' and m.get('family')==str(family) and m.get('protocol')=='17','complete native shared facts '+head)
  for stage in (m,pf,tf):
   need(stage.get('src')==source.hex() and stage.get('dst')==destination.hex(),'native shared address identity '+head)
   for field,value in dict(family=family,protocol=17,src_port=sport,dst_port=dport,packet_length=len(data),transport_offset=header,transport_length=len(payload)).items():need(stage.get(field)==str(value),'native shared transport fact '+head+'/'+field)
  if family==4:need(len(data)>=20 and data[12:20]==lead[12:20] and vectors.checksum(data[:20])==0 and int.from_bytes(data[2:4],'big')==len(data) and int.from_bytes(data[6:8],'big')&0x3fff==0,'native IPv4 reconstruction '+head)
  else:need(len(data)>=40 and data[8:40]==lead[8:40] and data[6]==17 and int.from_bytes(data[4:6],'big')+40==len(data),'native IPv6 reconstruction '+head)
  for k,v in dict(uid=r['uid'],ifindex=0,context=4,availability=5,direction=3,provenance=2).items():
   for stage in (success,m,pf,tf):need(stage.get(k)==str(v),'first platform restoration '+head+'/'+k)
  assigned=oracle.assignment(dict(l3=1,l4=1,family=family,protocol=17,src=source.hex(),dst=destination.hex(),src_port=sport,dst_port=dport,icmp_known=0));need(assigned['owner']==case['owner'],'independent final owner '+head)
  for stage in ('admit','policy','terminal'):
   own=one(rows(log,'s207 stage='+stage+' '),head,'assignment '+stage)
   for k,v in assigned.items():need(own.get(k)==str(v),'canonical assignment changed '+head+'/'+k)
  need(pf.get('thread')==tf.get('thread')==str(case['owner']+1),'final policy worker '+head)
  parser=one(rows(log,'s203 event=admit '),head,'shared parse');need(parser.get('parse')==parser.get('assignment')=='1','post-reassembly parse/selector count '+head)
  decision=one(rows(log,'s203 event=policy '),head,'decision');rule=21800+case['mode']+(1 if case['mode']==2 and family==6 else 0)
  need(decision.get('verdict')=='2' and decision.get('rule')==str(rule),'actual reassembled DROP '+head)
  for token in members:
   done=one(completed,token,'fragment DROP');need(done.get('policy_drop')=='1' and done.get('transport_outcome')=='NOT_ATTEMPTED','original TUN DROP settlement '+token)
  receipt=(a.run/f'{label}-c{case_index}-probe.txt').read_text();need(f'uid={r["uid"]} family={family} source_port={case["port"]} destination_port=40633 bytes=1800 outcome=timeout source=KERNEL_UDP nonce={case["nonce"]}' in receipt,'kernel endpoint receipt '+head)
 need(targets==set(fragments) and len(targets)==16 and len(heads)==8,'dual-stack real fragment matrix')
 need({(c['family'],c['mode'],c['owner']) for c in epoch['cases']}=={(f,m,o) for f in (4,6) for m in (1,2) for o in (0,1)},'family/policy/owner coverage')
 need(collections.Counter(e['token'] for e in rows(log,'s212 event=native_success '))==collections.Counter(heads),'unexpected native success')
 need(collections.Counter(e['token'] for e in rows(log,'s212 event=pin '))==collections.Counter(e['token'] for e in rows(log,'s212 event=completion_publish ') if e['pinned']=='1'),'fragment pin conservation')
 for token in set(fragments)-set(heads):need(not any(e['token']==token for e in rows(log,'s216 stage=admit ')),'non-first fragment independently parsed')
 stopped=rows(log,'s213 event=stop ');need(bool(stopped) and all(e.get('captured')==e.get('completed')==str(len(capture)) and e.get('tun_fd')=='-1' and all(e.get(k)=='0' for k in ('pending','frames','buffers','obligations','pregraph_returns')) for e in stopped),'native TUN stop residue')
 final=(a.run/(label+'-final.txt')).read_text();reassembly=rows(final,'reassembly.status ');need(len(reassembly)==1 and all(reassembly[0][k]=='0' for k in ('contexts','originals','retained')),'fragment residue')
 state=props((a.run/(label+'-stopped.properties')).read_text());need(state.get('state')=='stopped' and state.get('errorCode')=='' and state.get('mayBeActive')=='false','service cleanup')
 need('libvpp_runtime.so' not in (a.run/(label+'-processes.txt')).read_text(),'VPP process residue')
 link=(a.run/(label+'-interface-after.txt')).read_text();need('does not exist' in link or 'Cannot find device' in link,'TUN interface residue')
 need('event=subscription_stopped thread_alive=false' in android,'snapshot reader residue')
 accepted.append(dict(generation=generation,originals=len(capture),fragment_originals=len(fragments),datagrams=len(heads)))
out=dict(status='HOLD' if errors else 'PASS',originals=total,fragment_originals=fragment_count,datagrams=datagrams,generations=accepted,errors=errors)
(a.run/'verification.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2));raise SystemExit(bool(errors))
