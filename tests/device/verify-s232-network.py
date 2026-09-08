#!/usr/bin/env python3
"""Independently bind Android events to raw NFQUEUE facts and policy."""
import argparse,collections,hashlib,importlib.util,json,re,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--run',type=Path,required=True);a=p.parse_args()
spec=importlib.util.spec_from_file_location('chain',ROOT/'tests/evidence/product_chain.py');chain=importlib.util.module_from_spec(spec);spec.loader.exec_module(chain)
def rows(text,prefix):return [dict(re.findall(r'(\w+)=([^\s]+)',l)) for l in text.splitlines() if l.startswith(prefix)]
errors=[]
def need(ok,message):
 if not ok:errors.append(message)
def netlink(raw):
 data=bytes.fromhex(raw);length,kind=struct.unpack_from('<IH',data)
 assert length==len(data) and kind==0x300,'NFQUEUE message header'
 pos=20;attrs={}
 while pos+4<=length:
  size,typ=struct.unpack_from('<HH',data,pos);assert size>=4 and pos+size<=length
  assert (typ&0x3fff) not in attrs,'duplicate netlink attribute'
  attrs[typ&0x3fff]=data[pos+4:pos+size];pos+=(size+3)&~3
 def u32(typ):
  if typ not in attrs:return 0
  assert len(attrs[typ])==4,'attribute size';return int.from_bytes(attrs[typ],'big')
 header=attrs[1];assert len(header)==7
 return dict(packet=int.from_bytes(header[:4],'big'),hook=header[6],
  uid_present=int(16 in attrs),uid=u32(16),indev_present=int(5 in attrs),indev=u32(5),
  outdev_present=int(6 in attrs),outdev=u32(6),queue=int.from_bytes(data[18:20],'big'),payload=attrs[10])
b=json.loads(a.build.read_text());r=json.loads((a.run/'result.json').read_text());generation=str(r['generation'])
need(r['status']=='RAW_COMPLETE' and not r.get('cleanup_error'),'run or cleanup incomplete')
need(b['files']==chain.source_files(),'current Product source differs from build')
need(b['started_ns']<b['completed_ns']<r['started_ns']<r['completed_ns'],'build/run ordering')
if r['platform']=='pixel':
 need(r['apk_sha256']==b['apk_sha256']==chain.digest(Path(b['apk'])),'APK binding')
 need(r['native_sha256']==b['native_sha256'],'installed native binding')
 need('productRootNfqueueResidueClean=true' in (a.run/'complete-cleanup.properties').read_text(),'Root residue')
else:
 need(not b['host_evidence'],'fixture is not native evidence')
 need(all(chain.digest(Path(b['artifact'])/n)==h for n,h in b['artifact_hashes'].items()),'artifact bytes changed')
 need(r['process_absent'] and all(v==0 for v in json.loads((a.run/'queues-free.json').read_text()).values()),'process/queue residue')
log=(a.run/'vpp.log').read_text();facts=rows(log,'s217 event=nfq_facts ')
messages=rows(log,'s217 event=netlink_message ');by_message={e['token']:e for e in messages}
need(len(by_message)==len(messages)==len(facts)>0,'netlink/facts cardinality')
verdicts=collections.defaultdict(list);frees=collections.Counter()
for e in rows(log,'s203 event=verdict '):verdicts[e['obligation']].append(e)
for e in rows(log,'s203 event=buffer_free '):frees[e['obligation']]+=1
metadata={e['token']:e for e in rows(log,'s216 stage=admit ')}
packet_snapshots={e['token']:e for e in rows(log,'s232 event=packet_snapshot ')}
publications={e['revision']:e for e in rows(log,'s232 event=snapshot_publish ')}
android={}
for line in (a.run/'android-events.log').read_text().splitlines():
 match=re.search(r's232 event=(\w+) revision=(\d+) event_elapsed_ns=(\d+) interfaces=\{([^}]*)\} code=(\d+)',line)
 if match:
  event,rev,ts,pairs,code=match.groups()
  mapping={int(k):int(v) for k,v in re.findall(r'(\d+)=(\d+)',pairs)}
  android[ts]=dict(event=event,revision=rev,mapping=mapping,code=code)
need(len(packet_snapshots)==len(facts),'packet snapshot cardinality')
for rev,event in publications.items():
 platform=android.get(event['event_elapsed_ns'],{})
 need(event['generation']==generation,'publication generation')
 need(platform.get('revision')==rev and platform.get('code')=='0','Android publication acknowledgement '+rev)
 need(len(platform.get('mapping',{}))==int(event['count']),'published interface count '+rev)
active_events=[android[e['event_elapsed_ns']] for e in publications.values() if e['event_elapsed_ns'] in android]
need(any(e.get('event')=='lost' and not e['mapping'] for e in active_events),'real network lost event missing')
need(any(e.get('event')=='controlled_missing' and not e['mapping'] for e in active_events),'controlled unknown event missing')
need('event=subscription_stopped thread_alive=false' in (a.run/'android-events.log').read_text(),'callback thread not stopped')
oracle_spec=importlib.util.spec_from_file_location('owner_oracle',ROOT/'tests/device/s207-owner-oracle.py')
oracle=importlib.util.module_from_spec(oracle_spec);oracle_spec.loader.exec_module(oracle)
assignments={e['token']:e for e in rows(log,'s207 stage=admit ')}
policy_facts={e['token']:e for e in rows(log,'s216 stage=policy ')}
decoded={};coverage=set();raw_uids=set()
for e in facts:
 token=e['token'];wire=netlink(by_message[token]['raw']);decoded[token]=wire
 need(e['generation']==generation and int(e['packet'])==wire['packet'],'generation/packet binding '+token)
 need(int(e['lane'])==wire['queue']-176,'queue/lane binding '+token)
 for key in ('hook','uid_present','uid','indev_present','indev','outdev_present','outdev'):
  need(int(e['raw_'+key])==wire[key],'raw TLV parser differs: '+token+' '+key)
 effective={k:wire[k] for k in ('hook','uid_present','uid','indev_present','indev','outdev_present','outdev')}
 fault=int(e['fault'])
 if fault==1:effective.update(uid_present=0,uid=0)
 elif fault==2:effective.update(uid_present=1,uid=0)
 elif fault==3:effective.update(indev_present=0,outdev_present=0)
 elif fault==4:effective.update(indev=0,outdev=0)
 elif fault==5:
  if wire['hook']==3:effective.update(indev_present=1,indev=33333)
  elif wire['hook']==1:effective.update(outdev_present=1,outdev=33334)
 elif fault==6:effective['hook']=255
 for key,value in effective.items():need(int(e[key])==value,'undeclared attribute mutation '+token+' '+key)
 uid=effective['uid'] if effective['uid_present'] else 0
 key='outdev' if effective['hook']==3 else 'indev' if effective['hook']==1 else None
 index=effective[key] if key and effective[key+'_present'] and 0<effective[key]<=0x7fffffff else 0
 ps=packet_snapshots.get(token,{})
 need(ps.get('generation')==generation,'packet snapshot generation '+token)
 pub=publications.get(ps.get('revision'),{})
 mapping=android.get(pub.get('event_elapsed_ns'),{}).get('mapping',{})
 context=mapping.get(index,0) if index else 0
 need(ps.get('revision')=='0' or pub,'unknown snapshot revision '+token)
 need(ps.get('event_elapsed_ns')==pub.get('event_elapsed_ns','0'),'snapshot timestamp '+token)
 availability=int(bool(effective['uid_present']))+(2 if index else 0)+(4 if context else 0)
 direction=effective['hook'] if effective['hook'] in (1,3) else 0
 expected={'uid':uid,'ifindex':index,'availability':availability,'direction':direction,'context':context,'provenance':1}
 need(int(e['normalized_uid'])==uid and int(e['normalized_ifindex'])==index,'normalization mismatch '+token)
 for name in ('availability','direction','context','provenance'):need(int(e[name])==expected[name],'wrong normalized '+name+' '+token)
 m=metadata.get(token,{})
 for name,value in expected.items():need(m.get(name)==str(value),'shared packet facts differ '+token+' '+name)
 vs=verdicts[token];need(len(vs)==1 and frees[token]==1,'completion not exactly once '+token)
 if len(vs)==1:need(vs[0]['thread']==e['thread'] and vs[0]['packet']==e['packet'] and vs[0]['lane']==e['lane'],'completion missed origin '+token)
 raw=wire['payload'];family=raw[0]>>4
 offset=(raw[0]&15)*4 if family==4 else 40
 source=(bytes(12)+raw[12:16]) if family==4 else raw[8:24]
 destination=(bytes(12)+raw[16:20]) if family==4 else raw[24:40]
 protocol=raw[9] if family==4 else raw[6]
 sport,dport=struct.unpack_from('!HH',raw,offset)
 need(protocol==17,'unexpected main-matrix transport '+token)
 key=oracle.assignment(dict(l3=1,l4=1,family=family,protocol=protocol,
  src=source.hex(),dst=destination.hex(),src_port=sport,dst_port=dport,icmp_known=0))
 for name,value in key.items():need(assignments.get(token,{}).get(name)==str(value),'canonical owner differs '+token+' '+name)
 pf=policy_facts.get(token,{})
 for name,value in expected.items():need(pf.get(name)==str(value),'policy facts differ '+token+' '+name)
 need(pf.get('thread')==str(key['owner']+1),'policy missed canonical worker '+token)
 coverage.add((family,wire['hook'],fault))
 if wire['uid_present']:raw_uids.add(wire['uid'])
need(coverage>={(family,hook,fault) for family in (4,6) for hook in (1,3) for fault in (0,)},'dual-stack hook/fault matrix incomplete')
for case in r['cases']:
 matched=[t for t,v in decoded.items() if case['nonce'].encode() in v['payload']]
 need(bool(matched),'missing real case payload '+case['label'])
 for token in matched:need(metadata[token]['context']==str(case['context']),'case context '+case['label'])
 for token in matched:
  need(len(verdicts[token])==1 and verdicts[token][0]['verdict']==str(int(not case['blocked'])),'matcher verdict '+case['label'])
 # The helper performs an independent socket send/receive, including DROP timeout.
 text=(a.run/(case['label']+'-probe.txt')).read_text()
 need(('probe.blocked' if case['blocked'] else 'probe uid=') in text,'endpoint result '+case['label'])
final=(a.run/'runtime.txt').read_text()
status=rows(final,'completion.status ')
need(len(status)==1 and all(status[0][k]=='0' for k in ('pending','frames','buffers','obligations')),'native completion debt')
need(all(e[k]=='0' for e in rows(final,'reassembly.status ') for k in ('contexts','originals','retained')),'reassembly debt')
out=dict(status='HOLD' if errors else 'PASS',platform=r['platform'],packets=len(facts),cases=len(r['cases']),generation=generation,raw_uids=sorted(raw_uids),coverage=sorted(coverage),errors=errors)
(a.run/'verification.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2));raise SystemExit(bool(errors))
