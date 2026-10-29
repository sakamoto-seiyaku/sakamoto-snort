#!/usr/bin/env python3
"""S319 wire-name cache qualification through ordinary App and normal SQLite.

Expected cache/source assertions occur after normal Stop and independent MAIN
readback, so a genuine RED retains the complete wire/observation/resource chain.
"""
import argparse,importlib.util,ipaddress,json,re,shlex,sqlite3,struct,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('s319_shared',ROOT/'tests/device/s319-dns-cache.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
previous,root,shared,fixtures=base.previous,base.root,base.shared,base.fixtures
props,digest,PKG,SERIAL,Device=base.props,base.digest,base.PKG,base.SERIAL,base.Device
start_run,finish_run,preserve_sqlite_history=base.start_run,base.finish_run,base.preserve_sqlite_history

def soa(owner,ttl=30,minimum=7,klass=1):
 data=fixtures.name('ns.test')+fixtures.name('hostmaster.test')+struct.pack('!5I',1,2,3,4,minimum)
 return owner+struct.pack('!HHIH',6,klass,ttl,len(data))+data

def vector(d,label,variant):
 q=d.question(label,33 if variant=='underscore'else 1)
 if variant=='question-dot':
  name=b'literal.test';q=q[:12]+bytes([len(name)])+name+b'\0'+struct.pack('!HH',1,1)
 elif variant=='question-nul':
  name=b'com\0evil';q=q[:12]+bytes([len(name)])+name+b'\0'+struct.pack('!HH',1,1)
 elif variant=='underscore':q=fixtures.question(int.from_bytes(q[:2],'big'),'_sip._tcp.'+fixtures.decode_question(q)[0],33)
 name,kind,end=fixtures.decode_question(q);rcode=0 if variant=='parent'else 3
 answer=[];authority=[];cached=True
 if variant in('question-dot','question-nul'):
  answer=[b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+bytes([192,0,2,44])];rcode=0;cached=False
 elif variant=='underscore':a,_=fixtures.answer(q,'ordinary');return q,a,True
 else:
  owner=fixtures.name('qname.test')
  if variant=='root':owner=b'\0'
  elif variant=='dot':
   encoded=name.encode('ascii');assert len(encoded)<=63;owner=bytes([len(encoded)])+encoded+b'\0';cached=False
  elif variant=='nul':owner=b'\x08test\0bad\0';cached=False
  elif variant in('cname','cname-backslash','cname-dot-parent'):
   target=fixtures.name('alias.test')if variant=='cname'else b'\x0aalias.test\0'
   answer=[fixtures.name(name)+struct.pack('!HHIH',5,1,30,len(target))+target]
   owner=fixtures.name('test')if variant!='cname-backslash'else b'\x06alias\\\x04test\0'
   cached=variant=='cname'
  authority=[soa(owner)]
 a=q[:2]+struct.pack('!5H',0x8180|rcode,1,len(answer),len(authority),0)+q[12:end]+b''.join(answer+authority)
 return q,a,cached

def compression_vector(d,label,variant):
 q=d.question(label);end=fixtures.decode_question(q)[2]
 header=q[:2]+struct.pack('!5H',0x8180,1,1,0,1)
 a=header+q[12:end]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,0x01610000,4)+bytes([192,0,2,44])
 ttl=end+6;pointer=lambda n:struct.pack('!H',0xc000|n)
 def record(owner,kind,data):return owner+struct.pack('!HHIH',kind,1,30,len(data))+data
 if variant=='owner-ttl':extra=record(pointer(ttl),16,b'\x01x');cached=False
 elif variant=='nested':extra=record(pointer(end),16,b'\x01x');cached=True
 elif variant in('cname-ttl','soa-ttl','mx-ttl'):
  kind={'cname-ttl':5,'soa-ttl':6,'mx-ttl':15}[variant]
  data=pointer(ttl)
  if kind==6:data+=b'\0'+struct.pack('!5I',1,2,3,4,7)
  if kind==15:data=b'\0\0'+data
  extra=record(pointer(12),kind,data);cached=False
 elif variant in('opaque-pointer','opaque-plain'):
  extra=record(pointer(12),65000,pointer(12)if variant=='opaque-pointer'else b'\xa5\xa5');cached=variant=='opaque-plain'
 elif variant=='srv-anchor':
  data=struct.pack('!3H',1,2,443)+fixtures.name('server.test')
  extra=record(pointer(12),33,data);target=len(a)+12+6
  extra+=record(pointer(target),16,b'\x01x');a=a[:10]+struct.pack('!H',2)+a[12:];cached=True
 else:raise AssertionError(variant)
 return q,a+extra,cached

def qualify(d,peer,result,label,resolver,q,a,cached,protocol):
 follow=base.duplicate(q);source=d.reserve_source_port(label);cursor=peer.cursor();before=d.wire_coverage(label+'-before')
 peer.register(q,a);began=time.monotonic();client=None
 if protocol==6:
  d.forbid_original_tcp(label,before,source,resolver);nonce=d.launch_tcp(label,resolver,source,[q,follow],pipeline=False,hold=True)
 else:nonce=d.launch_queries(label,resolver,source,[q,follow],pipeline=False,timeout=6000)
 try:
  if protocol==6:
   client=d.wait(label+'-reads','files/product-state/t12-'+nonce+'.json',lambda c:c.get('phase')in('dns_tcp_read_complete','finished'),timeout=30,json_value=True)
   assert client['phase']=='dns_tcp_read_complete'and not client.get('error'),client
  else:client=d.client(label,nonce)
  assert client['uid']==d.uid and len(client['dnsExchanges'])==2
  actual=[bytes.fromhex(x['replyHex'])for x in client['dnsExchanges']];elapsed=time.monotonic()-began
  assert actual[0]==a,'uncached upstream wire must stay complete and exact'
  ids={int.from_bytes(x[:2],'big')for x in(q,follow)}
  select=lambda v:[r for r in shared.dns_rows(v)if r['generation']==d.generation and r['source_port']==source and r['id']in ids and r['protocol']==protocol]
  observed=d.observation_matching(label,lambda v:len([r for r in select(v)if r['stage']==4])==2,timeout=15)
  records=select(observed);d.verify_test_source(label,records);delivered=[r for r in records if r['stage']==4]
  assert len({r['token']for r in delivered})==2
  for r in records:
   assert r['adapter_profile']==(2 if d.args.profile=='vpn'else 1)
   assert (r['caller']==0 and r['uid']==4294967295)or(r['caller']==1 and r['uid']==d.uid)
  sources=[bool(next(r for r in delivered if r['id']==int.from_bytes(x[:2],'big'))['proxy_flags']&16)for x in(q,follow)]
  wire_error=None
  try:
   origin=base.response_row(records,q)['mono_us']
   for x,e,is_cached in zip(actual,(q,follow),(False,cached)):
    age=base.response_row(records,e)['mono_us']-origin if is_cached else None
    base.verify_data_reply(x,a,e,elapsed,cached=is_cached,cache_age_us=age)
  except AssertionError as error:wire_error=repr(error)
  requests=peer.received(q,after=cursor)
  after=d.wire_coverage(label+'-after');wire={k:v[len(before[k]):]for k,v in after.items()};interface=d.tun_interface if d.args.profile=='vpn'else'lo'
  dispatches=base.dispatch_reader.qualify_udp_dispatches(q,requests,wire[d.physical_interface],records,
   expected_port=d.args.upstream_port)
  check=dict(label=label,expected_upstream_requests=1 if cached else 2,actual_upstream_requests=dispatches['logical_dispatches'],
   actual_upstream_datagrams=len(requests),dispatch_qualification=dispatches,
   expected_cache_sources=[False,cached],actual_cache_sources=sources,cache_source_correct=sources==[False,cached],wire_correct=wire_error is None,wire_error=wire_error,peer_receipts=requests)
  result.setdefault('cache_checks',[]).append(check)
  if protocol==6:assert previous.stream(wire[interface],53,source)==b''.join(struct.pack('!H',len(x))+x for x in actual)
  else:
   for x in actual:assert any(r.get('kind')=='udp'and r['source_port']==53 and r['destination_port']==source and r['payload_hex']==x.hex()for r in wire[interface])
   assert not any(r.get('kind')=='udp'and r['source_port']==source and r['destination_port']==53 and ipaddress.ip_address(r['destination'])==ipaddress.ip_address(resolver)for r in wire[d.physical_interface])
  d.expected_durable.extend(records)
  result['cases'].append(dict(status='PASS_CAPTURED_WIRE_AND_NORMAL_OBSERVATION',label=label,generation=d.generation,
   ordinary_app=True,protocol=protocol,family=ipaddress.ip_address(resolver).version,source_port=source,
   queries=[q.hex(),follow.hex()],replies=[x.hex()for x in actual],records=records,qualification=check,cache_status=base.cache_status(d,label)))
  d.save('progress.json',json.dumps(result,indent=2)+'\n')
  return {r['owner']for r in delivered}
 finally:
  if protocol==6:
   d.release_probe(label,nonce);d.active_probe=None
   if client and client.get('phase')=='dns_tcp_read_complete':assert d.client(label,nonce)['dnsExchanges']==client['dnsExchanges']

def dispatch(d,peer,result,owners):
 result['scope']='ordinary App complete wire→cache qualification; core expectations evaluated only after normal Stop and independent SQLite'
 d.rules('qualification-allow')
 compression=d.args.matrix.startswith('compression')
 variants=(('owner-ttl','nested')if d.args.matrix=='compression-red'else('owner-ttl','nested','cname-ttl','soa-ttl','mx-ttl','opaque-pointer','opaque-plain','srv-anchor'))if compression else (('parent','dot')if d.args.matrix=='smoke'else(('root','parent','cname','dot','nul','cname-backslash','cname-dot-parent','question-dot','question-nul','underscore')if owners==1 else('parent','dot','nul','cname-dot-parent')))
 vectors=compression_vector if compression else vector
 for family,resolver,upstream in base.paths(d):
  if d.args.matrix=='compression-ipv6'and family!=6:continue
  if d.args.matrix=='compression-red'and family!=4:continue
  d.upstream(f'qual{family}-upstream',upstream);d.proxy_ready(f'qual{family}-ready')
  for protocol in((6,)if d.args.matrix=='compression-red'else(6,17)):
   preflight_label=f'preflight-{protocol}-{family}';preflight_query=d.question(preflight_label)
   preflight_answer=base.ttl_reply(preflight_query,0);peer.register(preflight_query,preflight_answer)
   preflight=dict(cases=[],cache_checks=[])
   base.exchange(d,peer,preflight,preflight_label,resolver,[preflight_query],[preflight_answer],1,
    protocol=protocol,expected_cached=[False])
   result.setdefault('ordinary_app_ttl0_transport_preconditions',[]).extend(preflight['cases'])
   coverage=set()
   for index,variant in enumerate(variants):
    label=f'q-{protocol}-{family}-{variant}';q,a,cached=vectors(d,label,variant);coverage|=qualify(d,peer,result,label,resolver,q,a,cached,protocol)
   for index in range(9):
    if coverage==set(range(owners)):break
    variant=('nested'if index%2==0 else'owner-ttl')if compression else('parent'if index%2==0 else'dot');label=f'q-{protocol}-{family}-owner-{index}';q,a,cached=vectors(d,label,variant);coverage|=qualify(d,peer,result,label,resolver,q,a,cached,protocol)
   assert coverage==set(range(owners)),(family,protocol,coverage)
def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for k in('apk','stage','backup','output'):parser.add_argument('--'+k,type=Path,required=True)
 for k in('endpoint4','endpoint6'):parser.add_argument('--'+k,required=True)
 parser.add_argument('--profile',choices=('root','vpn'),default='vpn')
 parser.add_argument('--owners',choices=('1','3'),default='1');parser.add_argument('--trace',action='store_true');parser.add_argument('--installed',action='store_true')
 parser.add_argument('--matrix',choices=('smoke','semantics','policy','capacity','stop-late','view','compression','compression-red','compression-ipv6'),default='smoke');parser.add_argument('--replace-preserved',type=Path)
 parser.add_argument('--cc',default='/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang')
 args=parser.parse_args();args.upstream_port=53053

 for k in('apk','stage','backup','output'):setattr(args,k,getattr(args,k).resolve())
 args.output.mkdir(parents=True,exist_ok=False)
 baseline=json.loads((args.backup/'manifest.json').read_text());assert baseline['status']=='PASS'and baseline['all_nodes_archived_exact']
 result=dict(status='HOLD',task='SAKAMOTO-319',apk_sha256=digest(args.apk),source_sha256=digest(Path(__file__)),cases=[],runs=[],started_monotonic_ns=time.monotonic_ns())
 d=(Device if args.profile=='vpn'else base.RootDevice)(args);d.capture_deadline=time.monotonic()+900;peer=None
 try:
  peer=root.Peer([args.endpoint4,args.endpoint6],args.output,d.capture_deadline);assert [r['ports']for r in peer.messages if r.get('kind')=='ready']==[[53053]]
  result['native']=d.install();d.wire_start();owners=int(args.owners);d.owners=owners
  result['runs'].append(start_run(d,owners))
  if args.profile=='root':
   dispatch(d,peer,result,owners)
  else:dispatch(d,peer,result,owners)
  if args.profile=='vpn':
   final=finish_run(d,result,f'n{owners}')
   for case in result['cases']:
    if 'stopped_local_wire_identity'in case:
     revived=[r for r in final['sqlite_after_stop']['current_generation_records']if r['protocol']==6
      and r['source_port']==case['source_port']and r['id']==int.from_bytes(bytes.fromhex(case['query_hex'])[:2],'big')]
     assert not revived,revived
     case['new_generation_old_identity_records']=0
   d.wire_stop()
  else:
   root.finish_run(d,result,f'n{owners}');preserve_sqlite_history(d,f'n{owners}',result['runs'][-1]['sqlite_after_stop']);d.wire_stop()
  for check in result.get('timer_progress_checks',[]):assert check['deltas']['timer_wakes']<=check['allowed_timer_wakes'],check
  assert all(c['actual_upstream_requests']==c['expected_upstream_requests'] and c['cache_source_correct'] and c['wire_correct'] for c in result['cache_checks']),result['cache_checks']
  result['status']='PASS_ACTUAL_APP_'+args.profile.upper()+'_'+args.matrix.upper()
 except BaseException as error:result.update(error=repr(error),traceback=traceback.format_exc())
 finally:
  cleanup=[]
  try:d.begin_capture_cleanup()
  except BaseException as error:cleanup.append('route-cleanup-reserve:'+repr(error))
  envelope=shared.CleanupEnvelope(90,[('wire',20),('stop',35),('reader',5),('peer',20),('trace',10)])
  def phase(name,action):
   try:
    with envelope.phase(d,name)as deadline:action(deadline)
   except BaseException as error:cleanup.append(name+':'+repr(error))
  if d.witnesses or getattr(d,'deferred_wire_files',[]):phase('wire',lambda _:(d.wire_stop()if d.witnesses else None,d.settle_deferred_wire_files()))
  if(d.stop_owed or d.active)and getattr(d,'stop_retry_authorized',True):phase('stop',lambda _:d.stop('failure-cleanup'))
  if d.reader or getattr(d,'prepared_stop_capture',None):phase('reader',lambda _:d.settle_reader('final'))
  if peer:phase('peer',lambda deadline:(setattr(peer,'cleanup_deadline',deadline),peer.close()))
  phase('trace',lambda _:d.close_trace())
  if cleanup:result.update(cleanup_errors=cleanup,status='HOLD')
  result['completed_monotonic_ns']=time.monotonic_ns();(args.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
  print(json.dumps({k:result.get(k)for k in('status','error','cleanup_errors')}),flush=True)
 return 0 if result['status'].startswith('PASS_')else 1
if __name__=='__main__':raise SystemExit(main())
