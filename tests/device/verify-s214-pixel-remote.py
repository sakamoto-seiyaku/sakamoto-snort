#!/usr/bin/env python3
"""S214 retained remote TUN handoff and immutable origin completion."""
import argparse,collections,hashlib,importlib.util,json,re,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--run',type=Path,required=True);a=p.parse_args()
def module(name,path):
 s=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
chain=module('chain','tests/evidence/product_chain.py');oracle=module('oracle','tests/device/s207-owner-oracle.py')
def rows(text,prefix):return [dict(re.findall(r'(\w+)=([^\s]+)',l)) for l in text.splitlines() if l.startswith(prefix)]
def props(text):return dict(l.split('=',1) for l in text.splitlines() if '=' in l and not l.startswith('#'))
errors=[]
def need(value,detail):
 if not value:errors.append(detail)
b=json.loads(a.build.read_text());r=json.loads((a.run/'result.json').read_text())
need(r['status']=='RAW_COMPLETE' and not r.get('cleanup_error'),'incomplete run')
need(b['files']==chain.source_files(),'current source differs from artifact')
need(b['started_ns']<b['completed_ns']<r['started_ns']<r['completed_ns'],'build/run ordering')
need(r['apk_sha256']==b['apk_sha256']==chain.digest(Path(b['apk'])),'APK binding')
need(r['native_sha256']==b['native_sha256'],'installed native binding')
need(len(r['generations'])==2 and r['generations'][0]['generation']<r['generations'][1]['generation'],'restart generation')
for name in ('ordinary-before','ordinary-resume'):
 state=props((a.run/(name+'.properties')).read_text())
 need(state.get('errorCode')=='vpn_flow_stack_not_ready' and state.get('mayBeActive')=='false' and state.get('protectionRunning')=='false','ordinary VPN readiness '+name)
 need('libvpp_runtime.so' not in (a.run/(name+'-processes.txt')).read_text(),'ordinary launch created VPP '+name)
accepted=[];targets=0;total=0
for index,epoch in enumerate(r['generations']):
 label=f'g{index}';generation=str(epoch['generation']);log=(a.run/(label+'-vpp.log')).read_text()
 captured=rows(log,'s213 event=capture ');total+=len(captured)
 by_token={e['token']:e for e in captured};need(len(by_token)==len(captured)>0,'capture identity '+label)
 admit=rows(log,'s216 stage=admit ');admission=rows(log,'s203 event=admit ')
 policy=rows(log,'s216 stage=policy ');decisions=rows(log,'s203 event=policy ')
 owners=rows(log,'s207 stage=admit ');pub=rows(log,'s204 event=completion_publish ')
 consume=rows(log,'s204 event=completion_consume ');completion=rows(log,'s213 event=completion ')
 free=rows(log,'s203 event=buffer_free ')
 snapshots=rows(log,'s218 event=packet_snapshot ')
 publications=rows(log,'s232 event=snapshot_publish ')
 android=(a.run/(label+'-android-events.log')).read_text()
 def one(events,token,kind):
  matched=[e for e in events if e.get('token',e.get('obligation'))==token]
  need(len(matched)==1,kind+' cardinality '+label+'/'+token)
  return matched[0] if len(matched)==1 else {}
 for token,c in by_token.items():
  raw=bytes.fromhex(c['raw']);need(len(raw)==int(c['bytes']),'capture length '+token)
  need(c['source']=='TUN_CAPTURED' and c['generation']==generation and c['thread']==c['tls']=='1' and c['lane']=='0','real TUN lane '+token)
  need(c['uid_source']=='CONTROLLED_TEST_PROVIDER','UID evidence boundary '+token)
  m=one(admit,token,'admit');ad=one(admission,token,'parser');frame=one(pub,token,'publish');origin=one(consume,token,'consume');done=one(completion,token,'adapter');freed=one(free,token,'free')
  need(m.get('raw')==c['raw'],'materialization bytes changed '+token)
  snap=one(snapshots,token,'snapshot')
  context=snap.get('context','0');availability='5' if context!='0' else '1'
  need(snap.get('generation')==generation and snap.get('ifindex')=='0' and snap.get('availability')==availability,'snapshot facts '+token)
  if int(snap.get('revision','0')):
   published=[e for e in publications if e['revision']==snap['revision'] and e['event_elapsed_ns']==snap['event_elapsed_ns']]
   need(len(published)==1,'native snapshot publication '+token)
   event=[line for line in android.splitlines() if f" revision={snap['revision']} " in line and f" event_elapsed_ns={snap['event_elapsed_ns']} " in line and ' code=0' in line]
   need(len(event)==1,'actual Android event '+token)
   mapping=dict(re.findall(r'(\d+)=(\d+)',re.search(r'interfaces=\{([^}]*)\}',event[0]).group(1))) if event else {}
   need(mapping.get(str(epoch['interface_index']),'0')==context,'event interface context projection '+token)
  else:need(context=='0','unpublished snapshot fabricated facts '+token)
  need(snap.get('attachment_interface')==str(epoch['interface_index']),'fd attachment identity '+token)
  for name,value in dict(uid=str(r['uid']),ifindex='0',context=context,availability=availability,direction='3',provenance='2',completion_kind='3',packet_id='0',origin_lane='0',queue_generation=generation).items():need(m.get(name)==value,'platform/obligation '+token+' '+name)
  need(ad.get('parse')=='1' and ad.get('assignment')=='1','parse/selector count '+token)
  need(frame.get('frame_bytes')=='32' and frame.get('packet')=='0' and frame.get('lane')=='0','shared frame '+token)
  for event in (m,ad,frame,origin,done):need(event.get('source')=='TUN_CAPTURED' and event.get('generation')==generation,'mislabelled event '+token)
  need(origin.get('thread')==done.get('thread')==freed.get('thread')=='1','origin return thread '+token)
  need(frame.get('buffer')==origin.get('buffer')==done.get('buffer')==freed.get('buffer')==c['buffer'],'original buffer conservation '+token)
  need(origin.get('intent')==done.get('intent')==frame.get('intent'),'terminal intent changed '+token)
  need(all(done.get(k)=='0' for k in ('tun_writes','nfq_verdicts','flow_stack_admissions')),'TUN DROP routing invariant '+token)
 need(not rows(log,'s203 event=verdict '),'NFQUEUE verdict in TUN generation')
 target_tokens=[]
 for case in epoch['cases']:
  tokens=[t for t,c in by_token.items() if case['nonce'].encode() in bytes.fromhex(c['raw'])]
  need(len(tokens)==1,'real app nonce '+case['nonce'])
  if len(tokens)!=1:continue
  token=tokens[0];target_tokens.append(token);targets+=1
  raw=bytes.fromhex(by_token[token]['raw']);m=one(admit,token,'target admit');pf=one(policy,token,'target policy');decision=one(decisions,token,'decision');owner=one(owners,token,'owner');done=one(completion,token,'target completion')
  need(raw[0]>>4==4 and raw[9]==17,'actual IPv4 UDP '+token)
  offset=(raw[0]&15)*4;source=bytes(12)+raw[12:16];destination=bytes(12)+raw[16:20]
  sport,dport,length=struct.unpack_from('!HHH',raw,offset)
  need(int.from_bytes(raw[2:4],'big')==len(raw) and length==len(raw)-offset,'complete original datagram '+token)
  need(sport==case['port'] and dport==40633,'bound app ports '+token)
  d=dict(l3=1,l4=1,family=4,protocol=17,src=source.hex(),dst=destination.hex(),src_port=sport,dst_port=dport,icmp_known=0)
  expected=oracle.assignment(d);need(expected['owner']==1,'test tuple is not canonical remote '+token)
  for name,value in expected.items():need(owner.get(name)==str(value),'independent canonical key '+token+' '+name)
  fields=dict(l3=1,l4=1,family=4,protocol=17,packet_length=len(raw),l3_length=offset,l4_length=8,transport_offset=offset,transport_length=length,src_port=sport,dst_port=dport,uid=r['uid'],ifindex=0,context=case["context"],availability=5 if case["context"] else 1,direction=3,provenance=2,completion_kind=3,packet_id=0,origin_lane=0,queue_generation=int(generation),owner=1)
  for name,value in fields.items():need(m.get(name)==pf.get(name)==str(value),'shared facts retained '+token+' '+name)
  need(m.get('src')==pf.get('src')==source.hex() and m.get('dst')==pf.get('dst')==destination.hex(),'shared addresses '+token)
  need(decision.get('rule')==str(21800+case['mode'] if case['blocked'] else 0) and decision.get('verdict')==('2' if case['blocked'] else '1'),'actual context/ifindex matcher '+token)
  need(int(one(snapshots,token,'target snapshot').get('revision','0'))>=case['snapshot_revision'],'packet predates selected snapshot '+token)
  need(done.get('policy_drop')=='1' and done.get('transport_unavailable')=='0' and done.get('thread')=='1' and done.get('producer')=='2','remote DROP origin completion '+token)
  need(m.get('thread')=='1' and pf.get('thread')=='2','parse/policy worker boundary '+token)
  need(case['probe']['outcome']=='timeout' and case['probe']['uid']==str(r['uid']),'independent app send outcome '+token)
  terminal=one(rows(log,'s216 stage=terminal '),token,'terminal facts')
  terminal_event=one(rows(log,'s203 event=terminal '),token,'terminal operation')
  need(terminal.get('thread')==terminal_event.get('thread')=='2' and terminal.get('owner')=='1','terminal owner '+token)
  for name,value in fields.items():need(terminal.get(name)==str(value),'terminal retained facts '+token+' '+name)
  sequence=[('primary_publish','1','2'),('primary_accepted','1','2'),('primary_dequeue','2',None),('completion_return_publish','2','1'),('completion_return_accepted','2','1')]
  for event_name,thread,target in sequence:
   e=one(rows(log,'s205 event='+event_name+' '),token,event_name)
   need(e.get('generation')==generation and e.get('buffer')==by_token[token]['buffer'] and e.get('thread')==thread,'retained original handoff '+token+' '+event_name)
   if target:need(e.get('target_thread')==target,'handoff target '+token+' '+event_name)
   if event_name.startswith('primary'):
    need(e.get('owner')=='1','handoff immutable owner '+token)
    if event_name!='primary_accepted':need(e.get('primary')=='1' and e.get('corrective')=='0','one primary/no corrective '+token)
  delivery=one(rows(log,'s205 event=owner_delivery '),token,'owner delivery')
  need(delivery.get('thread')=='2' and delivery.get('owner')==delivery.get('actual_worker')=='1' and delivery.get('match')=='1','actual remote worker '+token)
  need(one(pub,token,'remote frame publish').get('thread')=='2','remote frame producer '+token)
  for line in log.splitlines():
   if re.search(r'\b(?:token|obligation)='+token+r'\b',line):
    need(not any(k in line for k in ('event=completion_return_retry ','stage=owner_guard ','event=corrective_','Corrective')),'unexpected corrective/retry route '+token)
 need(len(target_tokens)==16 and {c['mode'] for c in epoch['cases']}=={1,2},'remote Gate/L4 target matrix '+label)
 need(all(c['context']==4 and c['blocked'] for c in epoch['cases']),'fixed remote DROP matrix '+label)
 need(bool(publications),'snapshot publications absent '+label)
 for publication in publications:
  event=[line for line in android.splitlines() if f" revision={publication['revision']} " in line and f" event_elapsed_ns={publication['event_elapsed_ns']} " in line and ' code=0' in line]
  need(len(event)==1,'publication acknowledgement '+label+'/'+publication['revision'])
 if publications:
  last=publications[-1]
  marker=f"event=stop_unknown revision={last['revision']} event_elapsed_ns={last['event_elapsed_ns']} interfaces={{}} code=0"
  need(last['count']=='0' and marker in android,'stop snapshot not cleared '+label)
  need(marker in android and 'event=subscription_stopped thread_alive=false' in android.split(marker,1)[-1],'current subscription residue '+label)
 if 's213 event=stop ' in log:
  after_stop=log.split('s213 event=stop ',1)[1].split('\n',1)[-1]
  need(not any(l.startswith(('s218 event=packet_snapshot ','s213 event=capture ')) for l in after_stop.splitlines()),'TUN snapshot read after stop '+label)
 primary=rows((a.run/(label+'-final.txt')).read_text(),'primary.status ')
 need(len(primary)==1,'primary status '+label)
 if primary:
  state=primary[0]
  need(state['generation']==generation and state['credit0']==state['credit1']=='32','handoff credits not restored '+label)
  need(all(state[k]=='0' for k in ('rejected','owner_failures','deferred','retries','pending_returns','handoff_debt')),'handoff debt/failures '+label)
  need(state['published']==state['received']==state['returns'] and int(state['returns'])>=16,'primary/return conservation '+label)
 final=rows((a.run/(label+'-final.txt')).read_text(),'tun.status ');need(len(final)==1,'native status '+label)
 if final:
  f=final[0];need(f['generation']==generation and f['captured']==f['submitted']==f['completed'] and int(f['completed'])<=len(captured),'native conservation counters '+label)
  need(all(f[k]=='0' for k in ('pending','frames','buffers','obligations','errors','rejected','pregraph_returns','tun_writes','nfq_verdicts','flow_stack_admissions','direct_egress_ready')),'native residue '+label)
  need(f['attached']=='1' and int(f['fd'])>=0,'pre-stop TUN identity '+label)
  stopped_native=rows(log,'s213 event=stop ')
  need(bool(stopped_native) and all(e.get('generation')==generation and all(e.get(k)=='0' for k in ('pending','buffers','frames','obligations')) and e.get('tun_fd')=='-1' and e.get('captured')==e.get('completed')==str(len(captured)) and e.get('pregraph_returns')=='0' for e in stopped_native),'native stop settlement '+label)
 stopped=props((a.run/(label+'-stopped.properties')).read_text())
 need(stopped.get('state')=='stopped' and stopped.get('mayBeActive')=='false' and stopped.get('errorCode')=='','service cleanup '+label)
 before=(a.run/(label+'-processes-before.txt')).read_text()
 processes=[l.split() for l in before.splitlines() if 'libvpp_runtime.so' in l and 'startup.conf' in l]
 need(len(processes)==1 and processes[0][0]==str(epoch['pid']) and processes[0][1]==str(r['uid']),'actual VPP app-UID process '+label)
 need('libvpp_runtime.so' not in (a.run/(label+'-processes.txt')).read_text(),'VPP process residue '+label)
 link=(a.run/(label+'-interface-after.txt')).read_text();need('does not exist' in link or 'Cannot find device' in link,'TUN interface residue '+label)
 need('/dev/tun' not in (a.run/(label+'-fds-after-drain.txt')).read_text() and '/dev/net/tun' not in (a.run/(label+'-fds-after-drain.txt')).read_text(),'TUN fd inode residue '+label)
 accepted.append(dict(generation=generation,packets=len(captured),target_packets=len(target_tokens)))
out=dict(status='HOLD' if errors else 'PASS',packets=total,target_packets=targets,generations=accepted,errors=errors)
(a.run/'verification.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2));raise SystemExit(bool(errors))
