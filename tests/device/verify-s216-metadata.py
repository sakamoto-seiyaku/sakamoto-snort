#!/usr/bin/env python3
"""Independent wire-format oracle for S216; graph injection is never NFQ evidence."""
import argparse, collections, hashlib, importlib.util, ipaddress, json, re, struct, zipfile
from pathlib import Path

def checksum(b):
 if len(b)%2:b+=b'\0'
 n=sum(struct.unpack('!%dH'%(len(b)//2),b))
 while n>>16:n=(n&65535)+(n>>16)
 return (~n)&65535

def facts(raw):
 b=bytes.fromhex(raw);family=b[0]>>4
 h=(b[0]&15)*4 if family==4 else 40
 length=int.from_bytes(b[2:4],'big') if family==4 else 40+int.from_bytes(b[4:6],'big')
 protocol=b[9] if family==4 else b[6]
 src=(b'\0'*12+b[12:16]) if family==4 else b[8:24]
 dst=(b'\0'*12+b[16:20]) if family==4 else b[24:40]
 d=dict(l3=1,l4=0,family=family,protocol=protocol,packet_length=length,l3_length=h,l4_length=0,transport_offset=h,transport_length=length-h,src_port=0,dst_port=0,tcp_seq=0,tcp_ack=0,tcp_window=0,tcp_flags=0,wscale=0,wscale_known=0,icmp_type=0,icmp_code=0,icmp_id=0,icmp_seq=0,icmp_known=0,src=src.hex(),dst=dst.hex())
 t=b[h:length]
 if protocol==6:
  if len(t)<20:return d
  th=(t[12]>>4)*4
  if th<20 or th>len(t):return d
  scale=None;i=20
  while i<th:
   kind=t[i]
   if kind==0:break
   if kind==1:i+=1;continue
   if i+2>th or t[i+1]<2 or i+t[i+1]>th:return d
   if kind==3:
    if t[i+1]!=3 or scale is not None:return d
    scale=min(t[i+2],14)
   i+=t[i+1]
  d.update(l4=1,l4_length=th,src_port=int.from_bytes(t[:2],'big'),dst_port=int.from_bytes(t[2:4],'big'),tcp_seq=int.from_bytes(t[4:8],'big'),tcp_ack=int.from_bytes(t[8:12],'big'),tcp_window=int.from_bytes(t[14:16],'big'),tcp_flags=t[13],wscale=scale or 0,wscale_known=int(scale is not None))
 elif protocol==17:
  if len(t)>=8 and 8<=int.from_bytes(t[4:6],'big')<=len(t):
   d.update(l4=1,l4_length=8,src_port=int.from_bytes(t[:2],'big'),dst_port=int.from_bytes(t[2:4],'big'))
 elif (family,protocol) in [(4,1),(6,58)]:
  if len(t)>=8:
   d.update(l4=2,l4_length=8,icmp_type=t[0],icmp_code=t[1])
   if t[1]==0 and t[0] in ([0,8] if family==4 else [128,129]):
    d.update(icmp_known=1,icmp_id=int.from_bytes(t[4:6],'big'),icmp_seq=int.from_bytes(t[6:8],'big'))
 else:d['l4']=2
 return d

def owner(d):
 endpoints=sorted([(bytes.fromhex(d['src']),d['src_port']),(bytes.fromhex(d['dst']),d['dst_port'])])
 b=struct.pack('!IBB',7,d['family'],d['protocol'])+b''.join(addr+struct.pack('!H',port) for addr,port in endpoints)
 h=14695981039346656037^0x6f776e65722d3137
 for byte in b:h=((h^byte)*1099511628211)&((1<<64)-1)
 return h%2

def fixtures():
 result=[]
 tcp=bytearray(struct.pack('!HHIIBBHHH',30001,40403,0x10203040,0xa0b0c0d0,0x60,0x12,65534,0,0)+bytes([3,3,7,0])+b'TCP')
 for case,(name,family,protocol,transport,options) in enumerate([
  ('tcp4-wscale',4,6,tcp,b''),('tcp6-wscale',6,6,tcp,b''),
  ('icmp4-echo',4,1,bytearray(struct.pack('!BBHHH',8,0,0,0xbeef,0x1234)),b''),
  ('icmp6-echo',6,58,bytearray(struct.pack('!BBHHH',128,0,0,0xcafe,0x5678)),b''),
  ('tcp4-unavailable',4,6,tcp[:10],b''),('tcp6-unavailable',6,6,tcp[:10],b''),
  ('udp4-invalid-length',4,17,bytearray(struct.pack('!HHHH',30001,40403,7,0)),b''),
  ('ipv6-no-next-header',6,59,bytearray(),b''),
  ('tcp4-ip-options',4,6,tcp,bytes([1,1,0,0])),
  ('tcp6-invalid-option',6,6,tcp[:20]+bytes([3,1,7,0]),b''),
  ('icmp4-error',4,1,bytearray(struct.pack('!BBHI',3,1,0,0)),b''),
  ('icmp6-unavailable',6,58,bytearray([128,0,0,0]),b''),
 ],1):
  for tail in range(1,255):
   t=bytearray(transport)
   if family==4:
    src=ipaddress.IPv4Address('192.0.2.'+str(tail)).packed;dst=ipaddress.IPv4Address('198.51.100.7').packed
    h=bytearray(struct.pack('!BBHHHBBH4s4s',0x45+len(options)//4,0,20+len(options)+len(t),case,0,64,protocol,0,src,dst)+options)
    pseudo=src+dst+struct.pack('!BBH',0,protocol,len(t))
   else:
    src=ipaddress.IPv6Address('2001:db8::'+format(tail,'x')).packed;dst=ipaddress.IPv6Address('2001:db8:1::7').packed
    h=bytearray(struct.pack('!IHBB16s16s',6<<28,len(t),protocol,64,src,dst));pseudo=src+dst+struct.pack('!I3xB',len(t),protocol)
   if protocol==6 and len(t)>=20:t[16:18]=struct.pack('!H',checksum(pseudo+t))
   elif protocol in (1,58) and len(t)>=4:t[2:4]=struct.pack('!H',checksum((pseudo if protocol==58 else b'')+t))
   if family==4:h[10:12]=struct.pack('!H',checksum(h))
   raw=(h+t).hex();expected=facts(raw)
   if owner(expected)==0:break
  assert owner(expected)==0
  result.append(dict(case=case,name=name,raw=raw,expected=expected,owner=0,availability=7 if case%2 else 0))
 return result

def props(p):return dict(l.split('=',1) for l in Path(p).read_text().splitlines() if '=' in l)
def verify(directory, request=None):
 root=Path(directory);errors=[]
 def require(ok,message):
  if not ok:errors.append(message)
 try:
  result=json.loads((root/'result.json').read_text());require(result['status']=='RAW_COMPLETE','runner incomplete')
  if request:
   q=json.loads(Path(request).read_text());bp=Path(q['build']);b=json.loads(bp.read_text())
   def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
   require(q['run_dir']==str(root.resolve()),'request run directory')
   require(q['scope']=='Root UDP4 owner-local plus GRAPH_INJECTED metadata only','request scope')
   require(digest(bp)==q['build_sha256'],'build witness hash')
   spec=importlib.util.spec_from_file_location('product_chain',Path(__file__).resolve().parents[1]/'evidence/product_chain.py');chain=importlib.util.module_from_spec(spec);spec.loader.exec_module(chain)
   require(chain.source_files()==b['files'],'current source differs from build')
   require(hashlib.sha256(chain.encode(b['files'])).hexdigest()==b['source_sha256'],'source closure')
   require(digest(bp.parent/'dirty.diff')==b['dirty_diff_sha256'],'dirty source witness')
   for name,h in b['files'].items():
    if h is not None:require(digest(bp.parent/'source'/name)==h,'source snapshot '+name)
   require(b['started_ns']<b['completed_ns']<q['created_ns'],'build/request order')
   require(digest(b['apk'])==b['apk_sha256']==result['apk_sha256'],'artifact identity')
   require((root/'installed-apk-sha256.txt').read_text().split()[0]==b['apk_sha256'],'installed APK identity')
   installed={Path(l.split()[1]).name:l.split()[0] for l in (root/'installed-native-sha256.txt').read_text().splitlines()}
   require(installed==b['native_sha256']==result['native_sha256'],'native closure')
   with zipfile.ZipFile(b['apk']) as z:
    require({Path(n).name:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}==installed,'APK native closure')
   stage=props(bp.parent/'stage/product-stage.properties');running=props(root/'first.properties')
   require(running['artifact']==stage['artifactId'] and running['version']==stage['vppRevision'],'running artifact identity')
   require(running['adapterReadiness']=='root-nfqueue-udp4-owner-local','readiness scope')
   for key in ['allow_nonce','unknown_context_nonce','recover_nonce']:
    require(int(result[key].rsplit('-',1)[1])>q['created_ns'],'fresh packet '+key)
   require(result['serial']==q['serial'],'device identity')

  lines=(root/'before-stop-vpp-stdout.log').read_text().splitlines();records=[]
  for line in lines:
   if line.startswith('s216 stage='):
    d=dict(token.split('=',1) for token in line.split()[1:]);records.append(d)
  groups=collections.defaultdict(list)
  for d in records:groups[d['token']].append(d)
  expected_fixtures=json.loads((root/'fixtures.json').read_text());require(expected_fixtures==fixtures(),'fixture manifest differs from controlled oracle')
  require(len(groups)==3+len(expected_fixtures),'packet group count')
  runtime=(root/'before-stop-vpp-runtime.txt').read_text();thread=None;vectors={}
  for line in runtime.splitlines():
   m=re.match(r'Thread (\d+) ',line)
   if m:thread=int(m[1])
   m=re.match(r'(product-packet-(?:admit|policy|terminal|owner-guard))\s+active\s+(\d+)\s+(\d+)',line)
   if m:vectors[(thread,m[1])]=(int(m[2]),int(m[3]))
  require(vectors=={(1,'product-packet-'+name):(15,15) for name in ['admit','policy','terminal']},'actual VLIB nodes and vector counts')

  for token,stages in groups.items():
   require([d['stage'] for d in stages]==['admit','policy','terminal'],'node sequence '+token)
   first=stages[0];oracle=facts(first['raw']);is_injected=first['source']=='GRAPH_INJECTED'
   require(first['source'] in ['GRAPH_INJECTED','NFQ_CAPTURED'],'source label '+token)
   for stage in stages:
    for k,v in oracle.items():require(stage[k]==str(v),token+' '+stage['stage']+' '+k)
    require(stage['thread']=='1' and stage['worker']=='0' and stage['owner']=='0','actual worker/owner '+token)
    require(stage['generation']==result['generation']==stage['queue_generation'],'generation '+token)
    for k in ['source','buffer','token','uid','ifindex','context','availability','direction','provenance','completion_kind','packet_id','origin_lane']:
     require(stage[k]==first[k],'roundtrip '+token+' '+k)
   require(first['origin_lane']=='0','origin lane '+token)
   if is_injected:
    case=int(token)-216000000;fixture=next(f for f in expected_fixtures if f['case']==case)
    require(first['raw']==fixture['raw'],'injected bytes '+token)
    require(first['availability']==str(fixture['availability']),'known/unknown zero '+token)
    require(first['uid']==first['ifindex']==first['context']=='0','zero values '+token)
    require(first['provenance']=='4' and first['completion_kind']=='2' and first['packet_id']==str(case),'injection obligation '+token)
   else:
    require(oracle['family']==4 and oracle['protocol']==17,'NFQ scope '+token)
    require(first['uid']==result['uid'] and int(first['availability'])&1,'real UID '+token)
    require(first['ifindex']=='1' and int(first['availability'])&2,'real loopback ifindex '+token)
    require(not int(first['availability'])&4,'unknown context '+token)
    require(first['provenance']=='1' and first['completion_kind']=='1','real obligation '+token)
   frees=[l for l in lines if l.startswith('s203 event=buffer_free ') and 'obligation='+token+' ' in l]
   require(len(frees)==1,'one buffer return '+token)
  verdicts=[l for l in lines if l.startswith('s203 event=verdict ')]
  require(len(verdicts)==3,'injection must not send NFQUEUE verdict')
  status=props(root/'before-stop-status.properties')
  require(status['origin_verdict_attempts']=='3' and status['last_packet_id']=='3','NFQ settlement count')
  for key in ['allow_nonce','unknown_context_nonce','recover_nonce']:
   require(result[key] in (root/'before-stop-endpoint.log').read_text(),'endpoint '+key)
  for k in ['productRootNfqueueResidueClean=true']:
   require(k in (root/'first-cleanup.properties').read_text(),'stop residue')
  require('buffer_debt=0 obligation_debt=0' in [l for l in lines if l.startswith('s203 event=buffer_free ')][-1],'final graph debt')
  require('roundtrip=1 data_guard=1 length_guard=1 generation_guard=1 buffer_return=1' in (root/'metadata-check.txt').read_text(),'native span/generation guards')
 except (OSError,KeyError,ValueError,StopIteration,IndexError) as e:errors.append('incomplete evidence '+str(e))
 return dict(status='HOLD' if errors else 'PASS',errors=errors,verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--fixtures',type=Path);p.add_argument('--verify',type=Path);p.add_argument('--output',type=Path);p.add_argument('--request',type=Path);a=p.parse_args()
 if a.fixtures:a.fixtures.write_text(json.dumps(fixtures(),indent=2)+'\n')
 if a.verify:
  r=verify(a.verify,a.request);text=json.dumps(r,indent=2)+'\n'
  if a.output:a.output.write_text(text)
  print(text);raise SystemExit(r['status']!='PASS')
