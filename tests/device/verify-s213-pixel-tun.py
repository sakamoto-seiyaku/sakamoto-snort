#!/usr/bin/env python3
"""Independent original-TUN bytes, canonical owner and completion conservation."""
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
  for name,value in dict(uid=str(r['uid']),ifindex='0',context='0',availability='1',direction='3',provenance='2',completion_kind='3',packet_id='0',origin_lane='0',queue_generation=generation).items():need(m.get(name)==value,'platform/obligation '+token+' '+name)
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
  expected=oracle.assignment(d);need(expected['owner']==0,'test tuple is not canonical local '+token)
  for name,value in expected.items():need(owner.get(name)==str(value),'independent canonical key '+token+' '+name)
  fields=dict(l3=1,l4=1,family=4,protocol=17,packet_length=len(raw),l3_length=offset,l4_length=8,transport_offset=offset,transport_length=length,src_port=sport,dst_port=dport,uid=r['uid'],ifindex=0,context=0,availability=1,direction=3,provenance=2,completion_kind=3,packet_id=0,origin_lane=0,queue_generation=int(generation),owner=0,thread=1)
  for name,value in fields.items():need(m.get(name)==pf.get(name)==str(value),'shared facts retained '+token+' '+name)
  need(m.get('src')==pf.get('src')==source.hex() and m.get('dst')==pf.get('dst')==destination.hex(),'shared addresses '+token)
  need(decision.get('rule')==str(21700+case['mode']) and decision.get('verdict')=='2','actual Gate/L4 DROP '+token)
  need(done.get('policy_drop')=='1' and done.get('transport_unavailable')=='0' and done.get('thread')==done.get('producer')=='1','owner-local DROP completion '+token)
  need(case['probe']['outcome']=='timeout' and case['probe']['uid']==str(r['uid']),'independent app send outcome '+token)
  for line in log.splitlines():
   if re.search(r'\btoken='+token+r'\b',line):need(not any(k in line for k in ('event=primary_publish ','event=completion_return_publish ','Corrective')),'unexpected handoff '+token)
 need(len(target_tokens)==8 and {c['mode'] for c in epoch['cases']}=={1,4},'Gate/L4 target matrix '+label)
 final=rows((a.run/(label+'-final.txt')).read_text(),'tun.status ');need(len(final)==1,'native status '+label)
 if final:
  f=final[0];need(f['generation']==generation and f['captured']==f['submitted']==f['completed']==str(len(captured)),'native conservation counters '+label)
  need(all(f[k]=='0' for k in ('attached','pending','frames','buffers','obligations','errors','rejected','pregraph_returns','tun_writes','nfq_verdicts','flow_stack_admissions','direct_egress_ready')),'native residue '+label)
  need(f['fd']=='-1','native TUN fd not closed '+label)
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
