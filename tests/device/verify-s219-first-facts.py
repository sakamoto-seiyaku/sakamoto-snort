#!/usr/bin/env python3
"""Independent first-offset facts, native reassembly and original ownership."""
import argparse,collections,hashlib,importlib.util,json,re,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--run',type=Path,required=True);p.add_argument('--verification-output',type=Path);a=p.parse_args()
def module(name,path):
 s=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
chain=module('chain','tests/evidence/product_chain.py');oracle=module('oracle','tests/device/s207-owner-oracle.py');vectors=module('vectors','tests/device/s219-fragment-matrix.py')
def rows(text,prefix):return [dict(re.findall(r'(\w+)=([^\s]+)',l)) for l in text.splitlines() if l.startswith(prefix)]
errors=[]
def need(ok,message):
 if not ok:errors.append(message)
b=json.loads(a.build.read_text());r=json.loads((a.run/'result.json').read_text());generation=str(r['generation']);log=(a.run/'vpp.log').read_text()
need(r['status']=='RAW_COMPLETE' and not r.get('cleanup_error') and not r.get('forced_kill'),'run/cleanup incomplete')
need(r['source']=='GRAPH_INJECTED','controlled source mislabelled')
need(b['files']==chain.source_files(),'current source differs from build')
need(b['started_ns']<b['completed_ns']<r['started_ns']<r['completed_ns'],'build/run chronology')
if r['platform']=='pixel':
 need(r['apk_sha256']==b['apk_sha256']==chain.digest(Path(b['apk'])),'APK binding')
 need(r['native_sha256']==b['native_sha256'],'installed native binding')
 need('productRootNfqueueResidueClean=true' in (a.run/'complete-cleanup.properties').read_text(),'Pixel native residue')
 need('libvpp_runtime.so' not in (a.run/'complete-process-after.txt').read_text(),'Pixel process residue')
 android=(a.run/'android-events-after-stop.log').read_text()
 need('event=subscription_stopped thread_alive=false' in android,'Pixel snapshot subscription residue')
else:
 need(not b['host_evidence'],'Host fixture is not Product')
 need(all(chain.digest(Path(b['artifact'])/n)==h for n,h in b['artifact_hashes'].items()),'Linux artifact bytes changed')
 need(r['process_absent'] and all(v==0 for v in json.loads((a.run/'queues-free.json').read_text()).values()),'Linux process/queue residue')
plans=vectors.matrix();need(len(r['cases'])==len(plans)==16,'controlled matrix incomplete')
for case,plan in zip(r['cases'],plans):
 for key,value in plan.items():need(case.get(key)==value,'declared input differs '+plan['label']+'/'+key)
events=collections.defaultdict(list)
for e in rows(log,'s212 '):events[e['event']].append(e)
reassembled=rows(log,'s229 event=product_reassembled ')
packets={str(212000000+p['case']):p for c in r['cases'] for p in c['packets']}
need(len(packets)==30,'original count')
def one(records,token,name):
 matches=[e for e in records if e.get('token',e.get('obligation'))==token]
 need(len(matches)==1,name+' cardinality '+token);return matches[0] if len(matches)==1 else {}
for name in ('fragment_ingress','completion_publish','origin_release'):
 need(collections.Counter(e['token'] for e in events[name])==collections.Counter({t:1 for t in packets}),name+' original conservation')
controlled=rows(log,'s219 event=controlled_fragment ');admit=rows(log,'s216 stage=admit ');policy=rows(log,'s216 stage=policy ');terminal=rows(log,'s216 stage=terminal ')
for token,packet in packets.items():
 ingress=one(events['fragment_ingress'],token,'native ingress');published=one(events['completion_publish'],token,'completion');released=one(events['origin_release'],token,'origin release');freed=one(rows(log,'s203 event=buffer_free '),token,'physical free');control=one(controlled,token,'controlled input');consumed=one(rows(log,'s204 event=completion_consume '),token,'frame consume')
 for e in (ingress,published,released,control,consumed):need(e.get('generation')==generation,'generation changed '+token)
 for e in (ingress,published,released):need(e.get('kind')=='2','fabricated adapter identity '+token)
 need(ingress.get('buffer')==published.get('buffer')==released.get('buffer')==freed.get('buffer')==consumed.get('buffer'),'original buffer changed '+token)
 need(ingress.get('thread')==released.get('thread')==freed.get('thread')==consumed.get('thread')==str(packet['worker']+1),'origin worker changed '+token)
 need(published.get('origin_worker')==published.get('lane')==str(packet['worker']) and published.get('packet')==str(packet['case']),'original obligation changed '+token)
 need(ingress.get('refs')==published.get('refs')==released.get('refs')=='1','native reference debt '+token)
 need(consumed.get('source')==freed.get('source')=='GRAPH_INJECTED','graph witness relabelled '+token)
 need(ingress.get('offset')==str(packet['offset']) and ingress.get('bytes')==str(len(bytes.fromhex(packet['hex']))),'wire fragment identity '+token)
 for key,value in packet['facts'].items():need(ingress.get(key)==control.get(key)==str(value),'ingress field mismatch '+token+'/'+key)
 need('reassembly.inject=accepted source=GRAPH_INJECTED' in (a.run/f'inject-{packet["case"]}.txt').read_text(),'injection receipt '+token)
need(not rows(log,'s203 event=verdict '),'controlled fragments generated NFQUEUE verdicts')
need(collections.Counter(e['token'] for e in events['pin'])==collections.Counter(e['token'] for e in events['completion_publish'] if e['pinned']=='1'),'lifetime pin imbalance')
successes=[];owner_pairs=set()
publications={e['revision']:e for e in rows(log,'s232 event=snapshot_publish ')}
for case in r['cases']:
 tokens=[str(212000000+e['case']) for e in case['packets']];found=[e for e in reassembled if e['token'] in tokens]
 if case['no_first']:
  need(not found and not any(e['token'] in tokens for e in admit+policy+terminal),'missing offset zero produced policy/success '+case['label'])
  for token in tokens:
   c=one(events['completion_publish'],token,'timeout');need(c.get('intent')=='2' and c.get('drop_reason')=='13','no-first timeout '+token)
  continue
 need(len(found)==1,'one native success '+case['label'])
 if len(found)!=1:continue
 success=found[0];token=success['token'];first=next(e for e in case['packets'] if e['offset']==0);expected=first['facts']
 need(token==str(212000000+first['case']),'survivor is not offset zero '+case['label'])
 need(success.get('originals')=='2','success original count '+token)
 metadata=one(admit,token,'shared parser');pf=one(policy,token,'policy facts');tf=one(terminal,token,'terminal facts')
 for field,value in expected.items():
  for stage in (metadata,pf,tf):need(stage.get(field)==str(value),'first facts overwritten/merged '+token+'/'+field)
 wire=[bytes.fromhex(e['hex']) for e in case['packets']];family=case['family'];header=20 if family==4 else 48
 parts=sorted(((int.from_bytes(w[6:8],'big')&0x1fff)*8 if family==4 else int.from_bytes(w[42:44],'big')&0xfff8,w[header:]) for w in wire)
 payload=b''.join(part for offset,part in parts);need([offset for offset,part in parts]==[0,16],'wire offsets '+token)
 data=bytes.fromhex(metadata.get('raw',''));offset=20 if family==4 else 40
 need(len(data)==offset+len(payload) and data[offset:]==payload,'native payload reconstruction '+token)
 if len(data)<offset:continue
 source=bytes(12)+data[12:16] if family==4 else data[8:24];destination=bytes(12)+data[16:20] if family==4 else data[24:40]
 pseudo=data[12:20]+struct.pack('!BBH',0,17,len(payload)) if family==4 else data[8:40]+struct.pack('!I3xB',len(payload),17)
 need(vectors.checksum(pseudo+payload)==0,'reconstructed UDP checksum '+token)
 if family==4:need(vectors.checksum(data[:20])==0 and int.from_bytes(data[6:8],'big')&0x3fff==0,'reassembled IPv4 header '+token)
 else:need(data[6]==17 and int.from_bytes(data[4:6],'big')==len(payload),'reassembled IPv6 header '+token)
 sport,dport,length=struct.unpack_from('!HHH',payload);need(sport==case['port'] and dport==40639 and length==len(payload),'reassembled transport tuple '+token)
 owner=oracle.assignment(dict(l3=1,l4=1,family=family,protocol=17,src=source.hex(),dst=destination.hex(),src_port=sport,dst_port=dport,icmp_known=0))
 for stage in ('admit','policy','terminal'):
  assigned=one(rows(log,'s207 stage='+stage+' '),token,'canonical '+stage)
  for field,value in owner.items():need(assigned.get(field)==str(value),'canonical assignment differs '+token+'/'+field)
 need(pf.get('thread')==tf.get('thread')==str(owner['owner']+1),'policy missed canonical owner '+token)
 parser=one(rows(log,'s203 event=admit '),token,'parse count');need(parser.get('parse')==parser.get('assignment')=='1','parse/selector repeated '+token)
 decision=one(rows(log,'s203 event=policy '),token,'actual decision')
 need(decision.get('verdict')==('2' if case['blocked'] else '1') and decision.get('rule')==str(21900+case['mode']+(1 if case['mode']==2 and family==6 else 0) if case['blocked'] else 0),'first facts actual matcher '+token)
 for original in tokens:
  completion=one(events['completion_publish'],original,'original disposition')
  need(completion.get('intent')==('2' if case['blocked'] else '1') and completion.get('drop_reason')==str((7 if case['mode']==1 else 8) if case['blocked'] else 0) and completion.get('bypass_reason')=='0','datagram policy not shared across original obligations '+original)
 if case['snapshot_change']:
  before=one(controlled,tokens[0],'before snapshot');after=one(controlled,tokens[1],'after snapshot')
  need(int(before.get('snapshot_revision','0'))==case['snapshot_before'] and int(after.get('snapshot_revision','0'))==case['snapshot_after']>case['snapshot_before'],'snapshot did not change between held originals '+case['label'])
  for revision in (before.get('snapshot_revision'),after.get('snapshot_revision')):
   publication=publications.get(revision,{});need(bool(publication),'missing actual snapshot publication '+str(revision))
   if r['platform']=='pixel' and publication:
    need(f"revision={revision} event_elapsed_ns={publication['event_elapsed_ns']}" in android,'Android event missing '+str(revision))
  if r['platform']=='linux':need('network rc=0' in (a.run/(case['label']+'-snapshot-change.txt')).read_text(),'controlled publication failed')
 owner_pairs.add((int(success.get('thread','0'))-1,owner['owner']));successes.append(token)
need(len(successes)==14 and len(reassembled)==14,'successful datagram count')
for stage in (admit,policy,terminal):need(collections.Counter(e['token'] for e in stage)==collections.Counter(successes),'extra/missing post-reassembly graph stage')
status=(a.run/'runtime.txt').read_text();reassembly=rows(status,'reassembly.status ');completion=rows(status,'completion.status ')
need(len(reassembly)==1 and all(reassembly[0][k]=='0' for k in ('contexts','originals','retained')),'fragment stop debt')
need(len(completion)==1 and all(completion[0][k]=='0' for k in ('pending','frames','buffers','obligations','verdicts')),'graph completion/NFQUEUE debt')
need('product-reassembly' in status,'actual Product reassembly node evidence missing')
out=dict(status='HOLD' if errors else 'PASS',platform=r['platform'],generation=generation,originals=len(packets),datagrams=len(successes),no_first_timeouts=2,memory_final_owner_pairs=sorted(owner_pairs),errors=errors)
with (a.verification_output or a.run/'verification.json').open('x') as output:output.write(json.dumps(out,indent=2)+'\n')
print(json.dumps(out,indent=2));raise SystemExit(bool(errors))
