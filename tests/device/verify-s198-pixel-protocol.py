#!/usr/bin/env python3
"""Independent TUN protocol facts, policy verdicts and unsupported completion outcomes."""
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
accepted=[];targets=0;total=0;injected_total=0
for index,epoch in enumerate(r['generations']):
 label=f'g{index}';generation=str(epoch['generation']);log=(a.run/(label+'-vpp.log')).read_text()
 captured=rows(log,'s213 event=capture ');total+=len(captured)
 by_token={e['token']:e for e in captured};need(len(by_token)==len(captured)>0,'capture identity '+label)
 admit=rows(log,'s216 stage=admit ');admission=rows(log,'s203 event=admit ')
 terminal_facts=rows(log,'s216 stage=terminal ')
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
 target_tokens=[];coverage=set();icmp_keys={}
 def decode(raw):
  family=raw[0]>>4;offset=(raw[0]&15)*4 if family==4 else 40
  source=(bytes(12)+raw[12:16]) if family==4 else raw[8:24]
  destination=(bytes(12)+raw[16:20]) if family==4 else raw[24:40]
  protocol=raw[9] if family==4 else raw[6]
  return family,offset,source,destination,protocol
 def checksum(data):
  if len(data)%2:data+=b'\0'
  value=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
  while value>>16:value=(value&65535)+(value>>16)
  return (~value)&65535
 for case in epoch['cases']:
  tokens=[]
  for token,capture in by_token.items():
   raw=bytes.fromhex(capture['raw']);family,offset,source,destination,protocol=decode(raw)
   if family!=case['family'] or protocol!=case['protocol']:continue
   if protocol==6:
    if len(raw)>=offset+20 and struct.unpack_from('!HH',raw,offset)==(case['port'],40634):tokens.append(token)
   elif case['nonce'].encode() in raw:tokens.append(token)
  need(bool(tokens),'real kernel packet for case '+case['nonce'])
  need(set(tokens)==set(case['tokens']),'collector token binding '+case['nonce'])
  coverage.add((case['family'],case['protocol'],case['mode']))
  for token in tokens:
   target_tokens.append(token);targets+=1
   raw=bytes.fromhex(by_token[token]['raw']);family,offset,source,destination,protocol=decode(raw)
   m=one(admit,token,'target admit');pf=one(policy,token,'target policy');tf=one(terminal_facts,token,'target terminal')
   decision=one(decisions,token,'decision');owner=one(owners,token,'owner');done=one(completion,token,'target completion')
   packet_length=int.from_bytes(raw[2:4],'big') if family==4 else 40+int.from_bytes(raw[4:6],'big')
   need(packet_length==len(raw),'complete original L3 '+token)
   fields=dict(l3=1,family=family,protocol=protocol,packet_length=len(raw),l3_length=offset,transport_offset=offset,transport_length=len(raw)-offset,uid=r['uid'],ifindex=0,context=0,availability=1,direction=3,provenance=2,completion_kind=3,packet_id=0,origin_lane=0,queue_generation=int(generation),owner=0,thread=1)
   d=dict(l3=1,family=family,protocol=protocol,src=source.hex(),dst=destination.hex(),icmp_known=0,src_port=0,dst_port=0)
   if protocol in (6,17):
    sport,dport=struct.unpack_from('!HH',raw,offset);d.update(l4=1,src_port=sport,dst_port=dport)
    need(sport==case['port'] and dport==40634,'bound app socket tuple '+token)
    fields.update(l4=1,src_port=sport,dst_port=dport)
    need(case['probe']['outcome']=='timeout' and case['probe']['uid']==str(r['uid']) and case['probe']['nonce']==case['nonce'],'app socket receipt '+token)
    if protocol==17:
     length=int.from_bytes(raw[offset+4:offset+6],'big');need(length==len(raw)-offset,'UDP length '+token);fields['l4_length']=8
     need(case['nonce'].encode()==raw[offset+8:],'UDP wire nonce '+token)
    else:
     header=(raw[offset+12]>>4)*4;seq,ack=struct.unpack_from('!II',raw,offset+4);window=int.from_bytes(raw[offset+14:offset+16],'big')
     need(20<=header<=len(raw)-offset and raw[offset+13]&2,'actual kernel TCP SYN '+token)
     scale=0;known=0;pos=20
     while pos<header:
      kind=raw[offset+pos]
      if kind==0:break
      if kind==1:pos+=1;continue
      size=raw[offset+pos+1];need(size>=2 and pos+size<=header,'TCP option bounds '+token)
      if size<2 or pos+size>header:break
      if kind==3:scale=min(raw[offset+pos+2],14);known=1
      pos+=size
     fields.update(l4_length=header,tcp_seq=seq,tcp_ack=ack,tcp_window=window,tcp_flags=raw[offset+13],wscale=scale,wscale_known=known)
   else:
    identifier,sequence=struct.unpack_from('!HH',raw,offset+4);itype=raw[offset];icode=raw[offset+1]
    need(identifier==case['identifier'] and sequence==case['sequence'] and itype==(8 if family==4 else 128) and icode==0,'ICMP identity '+token)
    need(case['nonce'].encode()==raw[offset+8:],'ICMP wire nonce '+token)
    checked=raw[offset:]
    if family==6:checked=source+destination+struct.pack('!I3xB',len(checked),58)+checked
    need(checksum(checked)==0,'legal ICMP checksum '+token)
    fields.update(l4=2,l4_length=8,src_port=0,dst_port=0,icmp_type=itype,icmp_code=icode,icmp_id=identifier,icmp_seq=sequence,icmp_known=1)
    d.update(l4=2,icmp_known=1,icmp_type=itype,icmp_code=icode,icmp_id=identifier)
   expected=oracle.assignment(d);need(expected['owner']==0,'target canonical owner '+token)
   for name,value in expected.items():need(owner.get(name)==str(value),'independent key '+token+' '+name)
   for name,value in fields.items():need(m.get(name)==pf.get(name)==tf.get(name)==str(value),'shared facts '+token+' '+name)
   need(m.get('src')==pf.get('src')==tf.get('src')==source.hex() and m.get('dst')==pf.get('dst')==tf.get('dst')==destination.hex(),'shared addresses '+token)
   if case['blocked']:
    need(decision.get('verdict')=='2' and decision.get('rule')==str(case['revision']),'actual policy DROP '+token)
    need(done.get('intent')=='2' and done.get('policy_drop')=='1' and done.get('transport_outcome')=='NOT_ATTEMPTED','DROP is not transport '+token)
   else:
    need(protocol in (1,58) and decision.get('verdict')=='1' and decision.get('rule')=='0','legal other-protocol policy allow '+token)
    need(done.get('intent')=='1' and done.get('drop_reason')=='0' and done.get('policy_drop')=='0' and done.get('transport_outcome')=='UNSUPPORTED' and done.get('transport_unavailable')=='0','unsupported is not malformed/failed '+token)
   need(done.get('producer')==done.get('thread')=='1','owner-local completion '+token)
   if protocol in (1,58):icmp_keys.setdefault(family,set()).add(owner.get('hash'))
 expected_coverage={(f,p,mode) for f in (4,6) for p in (6,17) for mode in (1,2)}|{(f,1 if f==4 else 58,mode) for f in (4,6) for mode in (0,1)}
 need(coverage==expected_coverage,'real protocol matrix '+label)
 need(all(len(hashes)==1 for hashes in icmp_keys.values()) and len(icmp_keys)==2,'ICMP sequence changed owner key '+label)
 # Classify every real packet outcome from the shared facts, including the
 # incidental IPv6 extension/control packets, without copying the Product parser.
 outcomes=collections.Counter()
 for token,capture in by_token.items():
  m=one(admit,token,'outcome facts');done=one(completion,token,'outcome completion')
  family,offset,source,destination,protocol=decode(bytes.fromhex(capture['raw']))
  extension=family==6 and protocol in (0,43,44,50,51,60,135,139,140)
  if extension:need(m.get('l4')=='0' and m.get('src_port')==m.get('dst_port')=='0','unwalked real extension facts '+token)
  expected_outcome='NOT_ATTEMPTED' if done.get('intent')=='2' else 'UNSUPPORTED' if protocol not in (6,17) and not extension and m.get('l4')=='2' else 'UNAVAILABLE'
  need(done.get('transport_outcome')==expected_outcome,'outcome from shared facts '+token);outcomes[expected_outcome]+=1
 transport=rows((a.run/(label+'-final.txt')).read_text(),'tun.transport ')
 need(len(transport)==1 and transport[0]['unsupported']==str(outcomes['UNSUPPORTED']) and transport[0]['unavailable']==str(outcomes['UNAVAILABLE']),'native outcome counters '+label)
 need(len(epoch['injected'])==4,'supplemental matrix '+label)
 for injected in epoch['injected']:
  token=injected['token'];injected_total+=1;m=one(admit,token,'injected admit');ad=one(admission,token,'injected parser');tf=one(terminal_facts,token,'injected terminal')
  frame=one(pub,token,'injected publish');origin=one(consume,token,'injected consume');freed=one(free,token,'injected free')
  need(token not in by_token and not any(e['token']==token for e in completion),'injection spoofed a TUN original '+token)
  need(m.get('raw')==injected['raw'] and m.get('completion_kind')=='2' and m.get('provenance')=='4','explicit graph source '+token)
  for event in (m,ad,tf,frame,origin,freed):need(event.get('source')=='GRAPH_INJECTED','injection source label '+token)
  need(frame.get('buffer')==origin.get('buffer')==freed.get('buffer')==m.get('buffer'),'injection physical return '+token)
  need(ad.get('parse')=='1' and m.get('l4')=='0' and m.get('src_port')==m.get('dst_port')=='0','unavailable facts were fabricated '+token)
  malformed=injected['case'] in (1,4)
  need(m.get('l3')==('0' if malformed else '1') and tf.get('intent')==('2' if malformed else '1'),'malformed versus unavailable '+token)
  need(ad.get('assignment')==('0' if malformed else '1'),'invalid L3 acquired owner '+token)
  if malformed:need(not any(e.get('obligation')==token for e in decisions),'malformed L3 became a policy DROP '+token)
 need(len(pub)==len(consume)==len(free)==len(captured)+4,'all original and diagnostic carriers conserved '+label)
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
out=dict(status='HOLD' if errors else 'PASS',packets=total,target_packets=targets,graph_injected=injected_total,generations=accepted,errors=errors)
(a.run/'verification.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2));raise SystemExit(bool(errors))
