"""Ordinary App S320 policy and lifecycle cases at existing public seams.

The owner provides the shared UI/peer/wire/normal SQLite harness. No Product
container or private coalescing layout is inspected by these cases.
"""
import ipaddress,json,shlex,struct,time

def save(d,result,case):
 result['cases'].append(case);d.save('progress.json',json.dumps(result,indent=2)+'\n');return case

def selected(B,d,value,ctx):
 ids={int.from_bytes(q[:2],'big')for q in ctx['queries']};ports=set(ctx['sources'])
 return[r for r in B.shared.dns_rows(value)if r['generation']==ctx['generation']and r['protocol']==ctx['protocol']
  and r['id']in ids and r['source_port']in ports]

def collect(B,d,ctx,label,terminal,delivered):
 def complete(value):
  records=selected(B,d,value,ctx);proxy=[r for r in records if r['proxy_flags']&1]
  return len([r for r in proxy if r['stage']in(2,3)and r['name_index']==0])==terminal and len([r for r in proxy if r['stage']==4])==delivered
 observed=d.observation_matching(label,complete,timeout=15);records=selected(B,d,observed,ctx)
 d.verify_test_source(label,records)
 abi=d.coalescing_abi(records)
 d.save(label+'-native-abi-qualification.json',json.dumps(abi,indent=2)+'\n')
 proxy=[r for r in records if r['proxy_flags']&1]
 for q,source in zip(ctx['queries'],ctx['sources']):
  identity=int.from_bytes(q[:2],'big');own=[r for r in proxy if r['id']==identity]
  assert own and all(r['source_port']==source for r in own),own
  queries=[r for r in own if r['stage']==1];ends=[r for r in own if r['stage']in(2,3)and r['name_index']==0]
  assert len(queries)==len(ends)==1,(queries,ends)
  first,end=queries[0],ends[0]
  for key in('generation','owner','token','incarnation','id','source_port','transport_session','request_attempt','network_revision','route_revision'):
   assert first[key]==end[key],(key,first,end)
  assert end['query_token']==end['token']and end['query_incarnation']==end['incarnation']
 ctx['records']=records
 d.expected_durable.extend(records);return records

def prepare(B,d,peer,label,resolver,protocol=6,*,query=None,answer=None):
 q=d.question(label)if query is None else query;a=B.ttl_reply(q)if answer is None else answer
 queries=[q,B.duplicate(q)];source=d.reserve_source_port(label);cursor=peer.cursor();gate=d.out/(label+'.gate')
 peer.register(q,a,gate=gate,gate_seconds=120)
 before=d.wire_coverage(label+'-before')
 status=d.save(label+'-status-before.txt',d.cli(label+'-status-before','show product dns proxy'))
 if protocol==6:d.forbid_original_tcp(label,before,source,resolver)
 return dict(label=label,query=q,answer=a,queries=queries,sources=[source,source],source=source,resolver=resolver,
  protocol=protocol,cursor=cursor,gate=gate,before=before,generation=d.generation,status_before=status)

def launch(B,d,ctx,*,preserve_ui=False,options=None):
 if ctx['protocol']==6:
  ctx['nonce']=d.launch_tcp(ctx['label'],ctx['resolver'],ctx['source'],ctx['queries'],pipeline=True,hold=True,
   options=options,preserve_ui=preserve_ui)
 else:ctx['nonce']=d.launch_queries(ctx['label'],ctx['resolver'],ctx['source'],ctx['queries'],pipeline=True,timeout=6000)

def pending(B,d,peer,ctx,*,initial_delay=0,wait_for_both=0):
 d.await_peer_query(peer,ctx['label'],ctx['query'],after=ctx['cursor'],initial_delay=initial_delay)
 deadline=time.monotonic()+wait_for_both;samples=[]
 while True:
  number=len(samples);text=d.cli(ctx['label']+f'-pending-status-{number}','show product dns proxy')
  d.save(ctx['label']+f'-pending-status-{number}.txt',text)
  rows=[dict(part.split('=',1)for part in line.split()[1:])for line in text.splitlines()if line.startswith('dns.proxy ')]
  samples.append(dict(monotonic_ns=time.monotonic_ns(),rows=rows))
  if any(int(r['waiters'])>=2 and int(r['transactions'])>=1 for r in rows):break
  assert time.monotonic()<deadline,rows
  time.sleep(min(.05,max(0,deadline-time.monotonic())))
 d.save(ctx['label']+'-pending-status.txt',text)
 received=peer.received(ctx['query'],after=ctx['cursor']);assert received and len({r['request_hex']for r in received})==1
 ctx['pending']=rows;ctx['pending_samples']=samples;return rows

def client(B,d,ctx):
 if ctx['protocol']==6:
  value=d.wait(ctx['label']+'-reads','files/product-state/t12-'+ctx['nonce']+'.json',
   lambda c:c.get('phase')in('dns_tcp_read_complete','finished'),timeout=30,json_value=True)
  assert value['phase']=='dns_tcp_read_complete'and not value.get('error'),value
 else:value=d.client(ctx['label'],ctx['nonce'])
 assert value['uid']==d.uid and len(value['dnsExchanges'])==len(ctx['queries']),value
 return value

def release(d,ctx):
 ctx['gate'].touch()
 if ctx.get('nonce')and ctx['protocol']==6:
  d.release_probe(ctx['label'],ctx['nonce'])
  if getattr(d,'active_probe',None)==ctx['nonce']:d.active_probe=None

def wire(B,d,peer,ctx,clients):
 after=d.wire_coverage(ctx['label']+'-after');delta={k:v[len(ctx['before'][k]):]for k,v in after.items()}
 received=peer.received(ctx['query'],after=ctx['cursor'])
 qualified=d.coalescing_wire_abi(ctx['query'],received,delta[d.physical_interface],ctx['records'])
 interface=d.tun_interface if d.args.profile=='vpn'else'lo'
 for source,value in clients:
  replies=[bytes.fromhex(x['replyHex'])for x in value['dnsExchanges']if x.get('replyHex')]
  if ctx['protocol']==6:assert B.previous.stream(delta[interface],53,source)==b''.join(struct.pack('!H',len(a))+a for a in replies)
  else:
   for answer in replies:assert any(r.get('kind')=='udp'and r['source_port']==53 and r['destination_port']==source and r['payload_hex']==answer.hex()for r in delta[interface])
 return qualified


def replies(B,ctx,value,rcode=None):
 queries={int.from_bytes(q[:2],'big'):q for q in ctx['queries']};actual={}
 for exchange in value['dnsExchanges']:
  a=bytes.fromhex(exchange['replyHex']);identity=int.from_bytes(a[:2],'big');assert identity in queries and identity not in actual
  q=queries[identity]
  code=rcode.get(identity)if isinstance(rcode,dict)else rcode
  if code is None:B.verify_data_reply(a,ctx['answer'],q,0)
  else:
   B.shared.legal_reply(a,q,rcode=code);end=B.fixtures.decode_question(q)[2];assert a[12:end]==q[12:end]
  actual[identity]=a
 assert set(actual)==set(queries);return actual

def prepare_view_change(d,label,address):
 old=d.query_rules(label+'-new-view-before-config')
 text=f'udp {address} {d.args.upstream_port}'
 d.save(label+'-new-view-prefill.txt',d.action('--es','completeRuleText',shlex.quote(text)))
 d.foreground_ui(label+'-new-view-prepared')
 point=d.tap(label+'-new-view-point','Set DNS upstream',click=False)
 return dict(old=old,point=point)

def apply_view_change(d,label,address,prepared):
 point=prepared['point'];old=prepared['old']
 d.save(label+'-new-view-tap.txt',d.adb('shell','input','tap',*map(str,point)))
 status=d.applied_status(label+'-new-view',old['queryElapsedMillis'],previous_revision=int(old['activeRevision']))
 revision=int(status['activeRevision']);assert revision>int(old['activeRevision'])
 ip=ipaddress.ip_address(address);packed=ip.packed+bytes(12)if ip.version==4 else ip.packed
 for prefix in('dns','dns.active'):
  assert status[prefix+'.enabled']=='1'and status[prefix+'.family']==str(ip.version)
  assert status[prefix+'.port']==str(d.args.upstream_port)and status[prefix+'.address']==packed.hex(),status
 d.selected_dns=dict(endpoint=(address,d.args.upstream_port),route_revision=revision,active_revision=revision)
 return status

def policy_variants(reliable,scope,family):
 if reliable and scope=='remaining':
  assert family in(4,6),family
  return () if family==4 else ('query-deny',)
 return ('alias-deny','query-deny')

def policy(B,d,peer,result,owners):
 assert owners==1
 reliable=d.args.profile=='root'
 for family,resolver,upstream in B.paths(d):
  # Original HOLDs already contain qualified Root IPv4 controls and query
  # denial, plus IPv6 INPUT. Continue only missing IPv6 OUTPUT and new denial.
  variants=policy_variants(reliable,d.args.policy_scope,family)
  # OUTPUT query rules and INPUT answer rules are distinct real control points.
  # A later publication never rewrites the already admitted query decision.
  for variant in variants:
   label=f'n{owners}-hot-coalesced-{variant}-v{family}'
   d.rules(label+'-allow');d.upstream(label+'-upstream',upstream);d.proxy_ready(label+'-ready')
   point,old=d.rules(label+'-prefill',variant,prefill=True)
   q=d.question(label);answer=B.fixtures.answer(q,'alias'if variant=='alias-deny'else'ordinary')[0]
   ctx=prepare(B,d,peer,label,resolver,query=q,answer=answer)
   launch(B,d,ctx,preserve_ui=True,options=dict(B.previous.UI_TCP_WRITE_OPTIONS))
   try:
    pending(B,d,peer,ctx,initial_delay=B.previous.UI_TCP_PRE_SEND_MS)
    d.save(label+'-tap.txt',d.adb('shell','input','tap',*map(str,point)))
    applied=d.applied_status(label+'-hot',old['queryElapsedMillis'],previous_revision=int(old['activeRevision']))
    assert applied['count']==applied['activeCount']=='2'and applied['binding.0']==f'1,{d.uid},2,10,0'
    ctx['gate'].touch()
    value=client(B,d,ctx);records=collect(B,d,ctx,label,2,2)
    expected={};policy_abi=[]
    for first in[r for r in records if r['stage']==1]:
     known=first['caller']==1
     if reliable:assert known,'Root per-App policy requires the actual reliable query caller'
     deny=known and variant=='alias-deny';expected[first['id']]=5 if deny else None
     own=[r for r in records if r['token']==first['token']and r['incarnation']==first['incarnation']]
     policy_abi.append(d.coalescing_policy_abi(own,revision=int(applied['activeRevision']),denied=deny,reliable=known,uid=d.uid))
    actual=replies(B,ctx,value,expected)
    observed=wire(B,d,peer,ctx,[(ctx['source'],value)]);d.verify_saved_source(label+'-published')
    save(d,result,dict(status='PASS',label=label,generation=d.generation,ordinary_app=True,family=family,protocol=6,
     queries=[q.hex()for q in ctx['queries']],replies=[a.hex()for a in actual.values()],source_port=ctx['source'],
     records=records,pending_status=ctx['pending'],published=applied,wire=observed,current_policy_rechecked_per_waiter=True,policy_abi=policy_abi,
     control_point='INPUT answer CNAME'if variant=='alias-deny'else'OUTPUT query rule inapplicable to INPUT answer',
     caller_scope='actual caller of each independent query; Unknown permits DNS App policy',historical_query_unchanged=True))
   finally:release(d,ctx)
   if reliable and variant=='query-deny':
    # Fresh requests now fail their own query policy before cache lookup/join.
    denied_case=B.exchange(d,peer,result,label+'-query-denied-before-join',resolver,
     [B.duplicate(ctx['query'],10),B.duplicate(ctx['query'],11)],[None,None],0,
     expected_cached=[False,False],rcodes=[5,5],reliable_app=True)
    denied_case['query_denied_abi']=d.coalescing_query_denied_abi(denied_case['records'])


def cancellations(B,d,peer,result,owners):
 assert owners==1
 for family,resolver,upstream in B.paths(d):
  for all_cancel in(False,True):
   label=f'n{owners}-cancel-{"all"if all_cancel else"one"}-v{family}'
   d.rules(label+'-allow');d.upstream(label+'-upstream',upstream);d.proxy_ready(label+'-ready')
   ctx=prepare(B,d,peer,label,resolver);source2=d.reserve_source_port(label+'-second');ctx['sources']=[ctx['source'],source2]
   d.forbid_original_tcp(label+'-second',ctx['before'],source2,resolver)
   nonces=[];clients=[]
   options=dict(B.previous.UI_TCP_WRITE_OPTIONS,dnsTcpShutdownOutput=True,dnsTcpResetAfterWrite=True,dnsTcpGate=True)
   try:
    # Do both ordinary network checks before starting either App socket. The
    # per-probe checks themselves previously staggered complete writes by 1.4s.
    d.verify_test_network(label+'-first-before-app');d.verify_test_network(label+'-second-before-app')
    first=d.launch_tcp_preverified(label+'-first',resolver,ctx['source'],[ctx['queries'][0]],pipeline=True,options=options)
    nonces.append(first)
    second_options=options if all_cancel else dict(B.previous.UI_TCP_WRITE_OPTIONS)
    second=d.launch_tcp_preverified(label+'-second',resolver,source2,[ctx['queries'][1]],pipeline=True,hold=not all_cancel,options=second_options)
    nonces.append(second);ctx['nonce']=second
    pending(B,d,peer,ctx,initial_delay=B.previous.UI_TCP_PRE_SEND_MS,wait_for_both=1.25)
    d.release_tcp_phase(label+'-first',first,'dns_tcp_written')
    first_client=d.client(label+'-first',first);assert first_client['resetAfterWrite']and first_client['outputShutdown']
    assert not any(x.get('replyHex')for x in first_client['dnsExchanges']);clients.append((ctx['source'],first_client))
    d.forbid_tcp_return(label+'-first-no-output',ctx['before'],ctx['source'])
    if all_cancel:
     d.release_tcp_phase(label+'-second',second,'dns_tcp_written')
     second_client=d.client(label+'-second',second);assert second_client['resetAfterWrite']and second_client['outputShutdown']
     assert not any(x.get('replyHex')for x in second_client['dnsExchanges']);clients.append((source2,second_client))
     d.forbid_tcp_return(label+'-second-no-output',ctx['before'],source2)
     records=collect(B,d,ctx,label,2,0)
     assert all(r['proxy_result']==7 for r in records if r['stage']==3)
     arrival=B.shared.late_peer_arrival(d,peer,label+'-late',ctx['query'],ctx['gate'],ctx['cursor'],ctx['before'])
     later=selected(B,d,d.observation(label+'-after-late'),ctx);assert later==records
    else:
     first_observed=d.observation_matching(label+'-first-cancelled',lambda v:any(r['stage']==3 and r['proxy_result']==7
      and r['source_port']==ctx['source']for r in selected(B,d,v,ctx)),timeout=5)
     assert not any(r['stage']in(2,4)and r['source_port']==ctx['source']for r in selected(B,d,first_observed,ctx))
     ctx['gate'].touch();second_ctx=dict(ctx,queries=[ctx['queries'][1]],source=source2,nonce=second)
     second_client=client(B,d,second_ctx);replies(B,second_ctx,second_client);clients.append((source2,second_client))
     records=collect(B,d,ctx,label,2,1)
     assert any(r['stage']==3 and r['proxy_result']==7 and r['source_port']==ctx['source']for r in records)
     assert any(r['stage']==2 and r['proxy_result']==1 and r['source_port']==source2 for r in records)
     arrival=None
    observed=wire(B,d,peer,ctx,clients)
    admitted=[r for r in records if r['stage']==1]
    terminals=[r for r in records if r['stage']in(2,3)and r['name_index']==0]
    assert len(admitted)==len(terminals)==2 and len({r['token']for r in admitted})==2
    overlap=min(r['mono_us']for r in terminals)-max(r['mono_us']for r in admitted)
    assert overlap>0,(admitted,terminals)
    save(d,result,dict(status='PASS',label=label,generation=d.generation,ordinary_app=True,protocol=6,family=family,
     queries=[q.hex()for q in ctx['queries']],sources=ctx['sources'],records=records,clients=[c for _,c in clients],
     pending_status=ctx['pending'],pending_samples=ctx['pending_samples'],target_overlap_us=overlap,
     wire=observed,late=arrival,all_cancelled=all_cancel))
   finally:
    ctx['gate'].touch()
    for index,nonce in enumerate(nonces):d.release_probe(label+f'-cleanup-{index}',nonce)
    d.active_probe=None
   if all_cancel:
    cold=B.duplicate(ctx['query'],100);peer.register(cold,ctx['answer'])
    B.exchange(d,peer,result,label+'-late-cannot-populate-cache',resolver,[cold],[ctx['answer']],1,expected_cached=[False])


def timeouts(B,d,peer,result,owners):
 assert owners==1;d.rules('coalesced-timeout-allow')
 for family,resolver,upstream in B.paths(d):
  d.upstream(f'timeout-v{family}-upstream',upstream);d.proxy_ready(f'timeout-v{family}-ready')
  for protocol in(6,17):
   label=f'n{owners}-coalesced-deadline-{protocol}-v{family}';ctx=prepare(B,d,peer,label,resolver,protocol)
   launch(B,d,ctx)
   try:
    pending(B,d,peer,ctx)
    value=client(B,d,ctx);actual=replies(B,ctx,value,2);records=collect(B,d,ctx,label,2,2)
    assert all(r['proxy_result']==3 and not r['winner']for r in records if r['stage']==3)
    if protocol==6:
     for q in ctx['queries']:d.forbid_tcp_return(label+'-old-'+q[:2].hex(),ctx['before'],ctx['source'],q[:2]+ctx['answer'][2:])
    arrival=B.shared.late_peer_arrival(d,peer,label+'-late',ctx['query'],ctx['gate'],ctx['cursor'],ctx['before'])
    later=selected(B,d,d.observation(label+'-after-late'),ctx);assert later==records
    observed=wire(B,d,peer,ctx,[(ctx['source'],value)])
    save(d,result,dict(status='PASS',label=label,generation=d.generation,ordinary_app=True,protocol=protocol,family=family,
     queries=[q.hex()for q in ctx['queries']],replies=[a.hex()for a in actual.values()],source_port=ctx['source'],
     records=records,pending_status=ctx['pending'],wire=observed,late=arrival,deadline_scope='fixed3s candidate qualified by actual shared Core/Adapter; raw Device clocks retained without inferred exact send duration'))
   finally:release(d,ctx)
   cold=B.duplicate(ctx['query'],100);peer.register(cold,ctx['answer'])
   B.exchange(d,peer,result,label+'-late-cannot-populate-cache',resolver,[cold],[ctx['answer']],1,expected_cached=[False])


def view_change(B,d,peer,result,owners):
 assert owners==1;label='coalesced-view-change';d.rules(label+'-allow');d.upstream(label+'-old',d.args.endpoint4);d.proxy_ready(label+'-ready')
 prepared=prepare_view_change(d,label,d.args.endpoint6)
 ctx=prepare(B,d,peer,label,'1.1.1.1');launch(B,d,ctx,preserve_ui=True,options=dict(B.previous.UI_TCP_WRITE_OPTIONS))
 try:
  pending(B,d,peer,ctx,initial_delay=B.previous.UI_TCP_PRE_SEND_MS)
  applied=apply_view_change(d,label,d.args.endpoint6,prepared);d.proxy_ready(label+'-new-ready')
  value=client(B,d,ctx);actual=replies(B,ctx,value,2);records=collect(B,d,ctx,label,2,2)
  assert all(r['proxy_result']==9 for r in records if r['stage']==3),records
  for q in ctx['queries']:d.forbid_tcp_return(label+'-old-'+q[:2].hex(),ctx['before'],ctx['source'],q[:2]+ctx['answer'][2:])
  arrival=B.shared.late_peer_arrival(d,peer,label+'-late',ctx['query'],ctx['gate'],ctx['cursor'],ctx['before'])
  later=selected(B,d,d.observation(label+'-after-late'),ctx);assert later==records
  observed=wire(B,d,peer,ctx,[(ctx['source'],value)])
  save(d,result,dict(status='PASS',label=label,generation=d.generation,ordinary_app=True,protocol=6,family=4,
   queries=[q.hex()for q in ctx['queries']],replies=[a.hex()for a in actual.values()],source_port=ctx['source'],
   records=records,pending_status=ctx['pending'],wire=observed,late=arrival,published=applied))
 finally:release(d,ctx)
 cold=B.duplicate(ctx['query'],100);changed=bytearray(ctx['answer']);changed[-1]=99;changed=bytes(changed);peer.register(cold,changed)
 case=B.exchange(d,peer,result,label+'-new-view-cold','1.1.1.1',[cold],[changed],1,expected_cached=[False])
 assert all(r['upstream_family']==6 for r in case['records']if r['proxy_flags']&1)


def stop_late(B,d,peer,result,owners):
 assert owners==1
 for family,resolver,upstream,protocol in((4,'1.1.1.1',d.args.endpoint4,6),(6,'2606:4700:4700::1111',d.args.endpoint6,17)):
  label=f'n{owners}-coalesced-pending-stop-{protocol}-v{family}'
  d.rules(label+'-allow');d.upstream(label+'-upstream',upstream);d.proxy_ready(label+'-ready')
  ctx=prepare(B,d,peer,label,resolver,protocol);old=d.generation
  d.prepare_stop_capture(label)
  options=dict(B.previous.UI_TCP_WRITE_OPTIONS)if protocol==6 else None
  launch(B,d,ctx,options=options)
  try:
   pending(B,d,peer,ctx,initial_delay=B.previous.UI_TCP_PRE_SEND_MS if protocol==6 else 0)
   if protocol==6:d.forbid_tcp_return(label+'-old-channel',ctx['before'],ctx['source'])
   for q in ctx['queries']:d.required_durable.append(dict(generation=old,id=int.from_bytes(q[:2],'big'),source=ctx['source'],proxy=True,stages=[1,3]))
   if protocol==6:
    # The ordinary App is still blocked on its response, before its optional
    # post-read gate. Keep that exact socket open until Product Stop settles it.
    assert d.active_probe==ctx['nonce'];d.active_probe=None
   try:stopped=B.previous.finish_run(d,result,label,pending=True)
   finally:
    if protocol==6 and getattr(d,'active',False):d.active_probe=ctx['nonce']
   ids={int.from_bytes(q[:2],'big')for q in ctx['queries']}
   records=[r for r in stopped['sqlite_after_stop']['current_generation_records']if r['id']in ids and r['source_port']==ctx['source']and r['protocol']==protocol and r['proxy_flags']&1]
   abi=d.coalescing_abi(records)
   assert len(records)==4 and len([r for r in records if r['stage']==1])==len([r for r in records if r['stage']==3 and r['proxy_result']==8])==2,records
   assert not any(r['stage']==4 for r in records)
   for identity in ids:
    own=[r for r in records if r['id']==identity];assert len(own)==2
    for key in('generation','owner','token','incarnation','transport_session','request_attempt','network_revision','route_revision'):
     assert own[0][key]==own[1][key]
   quiesced=stopped['actual_before_free_quiesce_counters'];assert sum(int(r['active_before'])for r in quiesced)>=2
   value=d.wait(label+'-old-client','files/product-state/t12-'+ctx['nonce']+'.json',lambda c:c.get('phase')=='finished',timeout=10,json_value=True)
   assert not any(x.get('replyHex')for x in value['dnsExchanges']),value
   d.expected_durable.extend(records)
   result['runs'].append(B.start_run(d,owners));assert d.generation>old
   d.upstream(label+'-new-generation-upstream',upstream);d.proxy_ready(label+'-new-generation-ready')
   restarted=d.wire_coverage(label+'-new-generation-before-late')
   if protocol==6:d.forbid_tcp_return(label+'-new-generation-old-channel',restarted,ctx['source'])
   arrival=B.shared.late_peer_arrival(d,peer,label+'-late',ctx['query'],ctx['gate'],ctx['cursor'],ctx['before'])
   observed=d.observation(label+'-new-generation-after-late')
   revived=[r for r in B.shared.dns_rows(observed)if r['generation']==d.generation and r['id']in ids and r['source_port']==ctx['source']and r['protocol']==protocol]
   assert not revived,revived
   cold=B.duplicate(ctx['query'],100);peer.register(cold,ctx['answer'])
   positive=B.exchange(d,peer,result,label+'-old-question-cold',resolver,[cold],[ctx['answer']],1,expected_cached=[False])
   assert time.monotonic()-arrival['released_monotonic']<60,'late data still has positive TTL during the cold-query proof'
   save(d,result,dict(status='PASS',label=label,generation=old,new_generation=d.generation,ordinary_app=True,
    protocol=protocol,family=family,queries=[q.hex()for q in ctx['queries']],source_port=ctx['source'],records=records,
    pending_status=ctx['pending'],actual_before_free=quiesced,old_client=value,late=arrival,
    new_generation_old_identity_records=0,cold_question_case=positive['label']))
  finally:release(d,ctx)


def capacity(B,d,peer,result,owners):
 assert owners==1
 d.rules('capacity-allow');d.upstream('capacity-upstream',d.args.endpoint4);d.proxy_ready('capacity-ready')
 # Distinct questions fill actual upstream transactions independently of the
 # larger waiter allowance. Background traffic is retained, never subtracted.
 label='distinct-exchange-capacity';queries=[d.question(label+'-'+str(i))for i in range(65)]
 for q in queries:peer.register(q,B.ttl_reply(q),drop=True)
 source=d.reserve_source_port(label);before=d.wire_coverage(label+'-before');cursor=peer.cursor();d.forbid_original_tcp(label,before,source,'1.1.1.1')
 nonce=d.launch_tcp(label,'1.1.1.1',source,queries,pipeline=True,hold=True,options=dict(B.previous.UI_TCP_WRITE_OPTIONS));value=None
 try:
  value=d.wait(label+'-reads','files/product-state/t12-'+nonce+'.json',lambda c:c.get('phase')in('dns_tcp_read_complete','finished'),timeout=30,json_value=True)
  assert value['phase']=='dns_tcp_read_complete'and not value.get('error')and len(value['dnsExchanges'])==65,value
  by_id={int.from_bytes(q[:2],'big'):q for q in queries};actual={}
  for item in value['dnsExchanges']:
   a=bytes.fromhex(item['replyHex']);identity=int.from_bytes(a[:2],'big');assert identity in by_id and identity not in actual
   B.shared.legal_reply(a,by_id[identity],rcode=2);actual[identity]=a
  assert set(actual)==set(by_id)
  text=d.save(label+'-status.txt',d.cli(label+'-status','show product dns proxy'))
  status=[dict(part.split('=',1)for part in line.split()[1:])for line in text.splitlines()if line.startswith('dns.proxy ')]
  assert len(status)==1 and int(status[0]['transaction_high_water'])==64 and int(status[0]['proxy_capacity'])>=1,status
  assert int(status[0]['waiter_high_water'])<=128 and int(status[0]['proxy_high_water_bytes'])<=int(status[0]['owner_work_bound'])
  receipts={str(identity):peer.received(q,after=cursor)for identity,q in by_id.items()}
  assert 0<sum(bool(x)for x in receipts.values())<=64 and any(not x for x in receipts.values())
  after=d.wire_coverage(label+'-after');interface=d.tun_interface if d.args.profile=='vpn'else'lo'
  assert B.previous.stream(after[interface][len(before[interface]):],53,source)==b''.join(struct.pack('!H',len(bytes.fromhex(x['replyHex'])))+bytes.fromhex(x['replyHex'])for x in value['dnsExchanges'])
  case=dict(status='PASS_PENDING_CLOSED_MAIN_VALIDATION',kind='transaction_capacity',label=label,generation=d.generation,
   ordinary_app=True,protocol=6,family=4,source_port=source,queries=[q.hex()for q in queries],client=value,
   expected_rcodes={str(k):2 for k in by_id},peer_receipts=receipts,public_status=status,records=[])
  d.closed_coalescing_cases=getattr(d,'closed_coalescing_cases',[])+[case]
  for identity in by_id:d.required_durable.append(dict(generation=d.generation,id=identity,source=source,proxy=True,stages=[1,3,4]))
  save(d,result,case)
 finally:
  d.release_probe(label,nonce);d.active_probe=None
 # One safe full Question has129 actual App message IDs. At most128 waiter
 # obligations may be owned; an Adapter can retain the final bounded frame or
 # return an explicit capacity error. Every observed result is checked below.
 label='shared-waiter-capacity';q=d.question(label);queries=[B.duplicate(q,i)for i in range(129)];answer=B.ttl_reply(q)
 gate=d.out/(label+'.gate');peer.register(q,answer,gate=gate,gate_seconds=120)
 source=d.reserve_source_port(label);cursor=peer.cursor();before=d.wire_coverage(label+'-before');d.forbid_original_tcp(label,before,source,'1.1.1.1')
 nonce=d.launch_tcp(label,'1.1.1.1',source,queries,pipeline=True,hold=True,options=dict(B.previous.UI_TCP_WRITE_OPTIONS));value=None
 try:
  d.await_peer_query(peer,label,q,after=cursor,initial_delay=B.previous.UI_TCP_PRE_SEND_MS)
  text=d.save(label+'-pending.txt',d.cli(label+'-pending','show product dns proxy'))
  status=[dict(part.split('=',1)for part in line.split()[1:])for line in text.splitlines()if line.startswith('dns.proxy ')]
  assert len(status)==1 and int(status[0]['waiter_high_water'])==128 and 1<=int(status[0]['waiters'])<=128,status
  assert 1<=int(status[0]['transactions'])<=64 and int(status[0]['proxy_high_water_bytes'])<=int(status[0]['owner_work_bound'])
  held=peer.received(q,after=cursor);assert held and len({r['request_hex']for r in held})==1
  gate.touch()
  value=d.wait(label+'-reads','files/product-state/t12-'+nonce+'.json',lambda c:c.get('phase')in('dns_tcp_read_complete','finished'),timeout=30,json_value=True)
  assert value['phase']=='dns_tcp_read_complete'and not value.get('error')and len(value['dnsExchanges'])==129,value
  by_id={int.from_bytes(query[:2],'big'):query for query in queries};codes={}
  for item in value['dnsExchanges']:
   actual=bytes.fromhex(item['replyHex']);identity=int.from_bytes(actual[:2],'big');assert identity in by_id and identity not in codes
   code=actual[3]&15;assert code in(0,2)
   # The retained129th frame may use the answer just cached by the first128
   # replies. Its full data/TTL check needs its actual normal source record.
   if code:B.shared.legal_reply(actual,by_id[identity],rcode=code)
   else:
    assert actual[:2]==by_id[identity][:2] and actual[2]&0x80
    assert B.fixtures.decode_question(actual)==B.fixtures.decode_question(by_id[identity])
   codes[identity]=code
  assert set(codes)==set(by_id)and any(code==0 for code in codes.values())
  received=peer.received(q,after=cursor);assert 1<=len(received)<=2 and len({r['request_hex']for r in received})==1
  after=d.wire_coverage(label+'-after');interface=d.tun_interface if d.args.profile=='vpn'else'lo'
  assert B.previous.stream(after[interface][len(before[interface]):],53,source)==b''.join(struct.pack('!H',len(bytes.fromhex(x['replyHex'])))+bytes.fromhex(x['replyHex'])for x in value['dnsExchanges'])
  case=dict(status='PASS_PENDING_CLOSED_MAIN_VALIDATION',kind='waiter_capacity',label=label,generation=d.generation,
   ordinary_app=True,protocol=6,family=4,source_port=source,queries=[query.hex()for query in queries],client=value,
   expected_rcodes={str(k):v for k,v in codes.items()},answer_hex=answer.hex(),
   peer_receipts=received,public_status=status,records=[])
  d.closed_coalescing_cases=getattr(d,'closed_coalescing_cases',[])+[case]
  for identity,code in codes.items():d.required_durable.append(dict(generation=d.generation,id=identity,source=source,proxy=True,stages=[1,3 if code else 2,4]))
  save(d,result,case)
 finally:
  gate.touch();d.release_probe(label,nonce);d.active_probe=None


def capacity_reply_data(B,case,records):
 queries={int.from_bytes(bytes.fromhex(q)[:2],'big'):bytes.fromhex(q)for q in case['queries']}
 assert len(queries)==len(case['queries'])
 exchanges=case['client']['dnsExchanges'];assert len(exchanges)==len(queries)
 assert [e['sentHex'] for e in exchanges]==case['queries']
 origins={}
 for row in records:
  if row['stage']==2 and row['name_index']==0 and row['proxy_flags']==5:
   assert row['proxy_result']==1 and row['id']in queries
   key=B.resolution_key(queries[row['id']],row)
   origins[key]=min(origins.get(key,row['mono_us']),row['mono_us'])
 proofs=[];seen=set()
 for exchange in exchanges:
  actual=bytes.fromhex(exchange['replyHex']);identity=int.from_bytes(actual[:2],'big')
  assert identity in queries and identity not in seen
  query=queries[identity]
  seen.add(identity);code=case['expected_rcodes'][str(identity)]
  if code:
   B.shared.legal_reply(actual,query,rcode=code);continue
  row=B.response_row(records,query);cached=row['proxy_flags']==17
  assert row['proxy_result']==(11 if cached else 1)
  age=None
  if cached:
   key=B.resolution_key(query,row);assert key in origins,'cache reply requires the actual same-view resolution'
   age=row['mono_us']-origins[key];assert age>=0
   proofs.append(dict(id=identity,first_resolution_mono_us=origins[key],
    cache_reply_mono_us=row['mono_us'],full_cache_age_us=age))
  B.verify_data_reply(actual,bytes.fromhex(case['answer_hex']),query,0,cached=cached,cache_age_us=age)
 assert seen==set(queries)
 return proofs

def validate_closed(B,d,report):
 for case in getattr(d,'closed_coalescing_cases',[]):
  if case.get('validated_closed_main'):continue
  source_records=[r for r in report['current_generation_records']if r['generation']==case['generation']and r['protocol']==6
   and r['source_port']==case['source_port']and r['proxy_flags']&1]
  case['normal_abi_qualification']=d.coalescing_abi(source_records)
  # A packet admission gap can lack a safely parsed DNS identity. Preserve
  # those actual resource observations separately from accepted waiters.
  additional=[r for r in source_records if r['proxy_flags']&8 and not r['request_attempt']]
  assert all(r['stage']==3 and r['proxy_result']==6 and r['delivery']==6 for r in additional)
  case['additional_source_records']=additional
  records=[r for r in source_records if r not in additional]
  expected={int(k):v for k,v in case['expected_rcodes'].items()};assert len(records)==3*len(expected),(len(records),len(expected))
  cached=0
  for identity,rcode in expected.items():
   own=[r for r in records if r['id']==identity];assert len(own)==3
   query,terminal,delivery=sorted(own,key=lambda r:r['stage'])
   assert query['stage']==1 and terminal['stage']==(3 if rcode else 2)and delivery['stage']==4
   for key in('generation','owner','token','incarnation','id','source_port','transport_session','request_attempt','network_revision','route_revision','caller','uid','packet_uid','packet_availability'):
    assert query[key]==terminal[key]==delivery[key],(key,own)
   assert terminal['query_token']==delivery['query_token']==query['token']
   assert terminal['reply_rcode']==delivery['reply_rcode']==rcode and delivery['delivery']==2
   if rcode:
    required=3 if case['kind']=='transaction_capacity'and case['peer_receipts'][str(identity)]else 6
    assert terminal['proxy_result']==delivery['proxy_result']==required,(required,own)
    assert terminal['actual_action']!=2 and delivery['actual_action']!=2
   else:
    assert terminal['proxy_result']==delivery['proxy_result']in(1,11)
    assert terminal['proxy_flags']==delivery['proxy_flags']in(5,17)
    cached+=bool(terminal['proxy_flags']&16)
  if case['kind']=='waiter_capacity'and all(code==0 for code in expected.values()):
   assert cached>=1,'129successful requests cannot all have held the128 simultaneous waiter slots'
  case['full_cache_age_evidence']=capacity_reply_data(B,case,records)
  case.update(status='PASS',records=records,validated_closed_main=True,cached_reply_count=cached,
   closed_main_scope='all target whole records from normal closed MAIN;128 publicquery/4096history limits unchanged')


def semantics(B,d,peer,result,owners):
 cancellations(B,d,peer,result,owners)
 timeouts(B,d,peer,result,owners)
