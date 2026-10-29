#!/usr/bin/env python3
"""S320 simultaneous ordinary App DNS requests, independent replies and SQLite.

The peer withholds its real answer while public owner status proves two live
waiters and one exchange. A serial cache hit cannot satisfy that precondition.
"""
import argparse,importlib.util,ipaddress,json,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('s320_base',ROOT/'tests/device/s319-dns-cache.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
shared,previous,fixtures=base.shared,base.previous,base.fixtures
spec=importlib.util.spec_from_file_location('s320_verify',ROOT/'tests/evidence/s320_dns_coalescing_verify.py')
verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
spec=importlib.util.spec_from_file_location('s320_cases',ROOT/'tests/device/helpers/s320_coalescing_cases.py')
cases=importlib.util.module_from_spec(spec);spec.loader.exec_module(cases)
class StopCounters:
 def launch_tcp_preverified(self,label,*args,**options):
  # Cancellation cases validate the same network twice before starting both
  # ordinary App probes, so the two admissions can overlap within 3 seconds.
  return super(base.UiState,self).launch_tcp(label,*args,**options)
 def upstream(self,label,address=None,port=None):
  return super().upstream(label,address,self.args.upstream_port if port is None else port)
 def await_peer_query(self,peer,label,query,*,port=None,after=0,initial_delay=0):
  return super().await_peer_query(peer,label,query,port=self.args.upstream_port if port is None else port,
   after=after,initial_delay=initial_delay)
 def coalescing_wire_abi(self,query,received,wire,records):
  return verifier.qualify_exchange_wire(query,received,wire,records,expected_port=self.args.upstream_port)
 def coalescing_query_denied_abi(self,records):
  return verifier.qualify_query_denied(records,uid=self.uid)
 def coalescing_policy_abi(self,records,**expected):
  return verifier.qualify_current_policy(records,**expected)
 def coalescing_abi(self,records):
  return verifier.qualify_waiter_records(records)
 def durable_readback(self,label):
  report=super().durable_readback(label)
  cases.validate_closed(base,self,report)
  return report
 def qualified_stop(self,label):
  result=super().qualified_stop(label)
  if hasattr(self,'generation'):
   actual=verifier.quiesce_rows((self.out/(label+'-stop.log')).read_text(),generation=self.generation,owners=self.owners)
   self.save(label+'-actual-before-free-counters.json',json.dumps(actual,indent=2)+'\n')
   result['actual_before_free_quiesce_counters']=actual
  return result
class Device(StopCounters,base.Device):pass
class RootDevice(StopCounters,base.RootDevice):pass

def rows(text,prefix):
 return [dict(item.split('=',1)for item in line.split()[1:])for line in text.splitlines()if line.startswith(prefix+' ')]

def simultaneous(d,peer,result,label,resolver,protocol):
 q=d.question(label);follow=base.duplicate(q);answer=base.ttl_reply(q);queries=[q,follow]
 source=d.reserve_source_port(label);cursor=peer.cursor();gate=d.out/(label+'.gate')
 peer.register(q,answer,gate=gate)
 before=d.wire_coverage(label+'-before')
 status_before=d.save(label+'-status-before.txt',d.cli(label+'-status-before','show product dns proxy'))
 cache_before=rows(status_before,'dns.cache');proxy_before=rows(status_before,'dns.proxy')
 # Owner counters also include unrelated normal traffic. Keep them exact;
 # only this full Question's identities/wire can qualify its cache/exchange.
 began=time.monotonic();client=None
 if protocol==6:
  d.forbid_original_tcp(label,before,source,resolver)
  nonce=d.launch_tcp(label,resolver,source,queries,pipeline=True,hold=True)
 else:nonce=d.launch_queries(label,resolver,source,queries,pipeline=True,timeout=6000)
 try:
  # Read just the public CLI in this finite pending window; large history
  # captures happen after release and do not consume the query deadline.
  pending=d.save(label+'-pending-status.txt',d.cli(label+'-pending-status','show product dns proxy'))
  owners=rows(pending,'dns.proxy')
  candidates=[r for r in owners if int(r['waiters'])>=2 and int(r['transactions'])>=1
   and int(r['coalesced'])-int(proxy_before[int(r['owner'])]['coalesced'])>=1]
  assert candidates,owners
  held=peer.received(q,after=cursor)
  assert held and len({r['request_hex']for r in held})==1,held
  assert not gate.exists()
  precondition=dict(host_monotonic_ns=time.monotonic_ns(),held_peer_receipts=held,
   pending_owners=owners,query_hex=q.hex(),follow_hex=follow.hex(),
   target_waiters=2,shared_exchanges=1,peer_answer_withheld=True,
   unique_question_scope='new unique full question in this fresh owner run; no earlier request or valid cached answer')
  d.save(label+'-concurrent-precondition.json',json.dumps(precondition,indent=2)+'\n')
  gate.touch()
  if protocol==6:
   client=d.wait(label+'-reads','files/product-state/t12-'+nonce+'.json',
    lambda c:c.get('phase')in('dns_tcp_read_complete','finished'),timeout=30,json_value=True)
   assert client['phase']=='dns_tcp_read_complete'and not client.get('error'),client
  else:client=d.client(label,nonce)
  assert client['uid']==d.uid and len(client['dnsExchanges'])==2,client
  actual=[bytes.fromhex(x['replyHex'])for x in client['dnsExchanges']]
  for a,question in zip(actual,queries):base.verify_data_reply(a,answer,question,time.monotonic()-began)
  ids={int.from_bytes(question[:2],'big')for question in queries}
  selected=lambda v:[r for r in shared.dns_rows(v)if r['generation']==d.generation
   and r['source_port']==source and r['protocol']==protocol and r['id']in ids]
  observed=d.observation_matching(label,lambda v:len([r for r in selected(v)if r['stage']==4])==2,timeout=15)
  records=selected(observed);d.verify_test_source(label,records)
  delivered=[r for r in records if r['stage']==4]
  admitted=[r for r in records if r['stage']==1]
  assert len(admitted)==len(delivered)==2 and len({r['token']for r in delivered})==2
  target_owners={r['owner']for r in records};assert len(target_owners)==1,target_owners
  owner=next(iter(target_owners));actual_pending=owners[owner]
  assert actual_pending in candidates,(owner,actual_pending,candidates)
  responses=[r for r in records if r['stage']==2 and r['name_index']==0 and r['proxy_flags']&4 and not r['proxy_flags']&16]
  assert len(responses)==2 and max(r['mono_us']for r in admitted)<min(r['mono_us']for r in responses)
  precondition.update(pending_owner=actual_pending,target_query_observations=admitted,
   target_overlap_before_first_response_us=min(r['mono_us']for r in responses)-max(r['mono_us']for r in admitted))
  d.save(label+'-concurrent-precondition.json',json.dumps(precondition,indent=2)+'\n')
  for r in records:
   assert r['adapter_profile']==(2 if d.args.profile=='vpn'else 1)
   assert (r['caller']==0 and r['uid']==4294967295)or(r['caller']==1 and r['uid']==d.uid),r
  for question in queries:
   response=base.response_row(records,question)
   assert response['proxy_flags']&4 and not response['proxy_flags']&16,response
   assert response['query_token']==response['token'] and response['query_incarnation']==response['incarnation']
  after=d.wire_coverage(label+'-after');wire={k:v[len(before[k]):]for k,v in after.items()}
  peer_rows=peer.received(q,after=cursor)
  primary=min(admitted,key=lambda row:row['request_attempt'])
  primary_records=[row for row in records if row['token']==primary['token'] and row['request_attempt']==primary['request_attempt']]
  dispatch=base.dispatch_reader.qualify_udp_dispatches(q,peer_rows,wire[d.physical_interface],primary_records,
   expected_port=d.args.upstream_port)
  dispatch['native_clock_scope']='earliest admitted exchange leader; all independent waiter records retained separately'
  assert dispatch['logical_dispatches']==1,dispatch
  interface=d.tun_interface if d.args.profile=='vpn'else'lo'
  if protocol==6:
   assert previous.stream(wire[interface],53,source)==b''.join(struct.pack('!H',len(a))+a for a in actual)
  else:
   for a in actual:assert any(r.get('kind')=='udp'and r['source_port']==53 and r['destination_port']==source
    and r['payload_hex']==a.hex()for r in wire[interface])
   assert not any(r.get('kind')=='udp'and r['source_port']==source and r['destination_port']==53
    and ipaddress.ip_address(r['destination'])==ipaddress.ip_address(resolver)for r in wire[d.physical_interface])
  final_status=d.save(label+'-status-after.txt',d.cli(label+'-status-after','show product dns proxy'))
  cache_after=rows(final_status,'dns.cache');final_owners=rows(final_status,'dns.proxy')
  # Exact target completion comes from both normal identities and wire above.
  # Preserve unmodified aggregate counters and unrelated normal records: an
  # Android background request can legitimately add another miss/hit/work item.
  aggregate_deltas={str(i):{key:int(cache_after[i][key])-int(cache_before[i][key])
   for key in('hits','misses','skipped')}for i in range(len(cache_after))}
  other=[r for r in shared.dns_rows(observed)if r['generation']==d.generation and r not in records]
  known={json.dumps(r,sort_keys=True)for r in d.expected_durable}
  for r in other:
   raw=json.dumps(r,sort_keys=True)
   if raw not in known:d.expected_durable.append(r);known.add(raw)
  d.expected_durable.extend(records)
  case=dict(status='PASS',label=label,generation=d.generation,ordinary_app=True,protocol=protocol,
   family=ipaddress.ip_address(resolver).version,source_port=source,queries=[q.hex()for q in queries],
   replies=[a.hex()for a in actual],records=records,concurrent_precondition=precondition,
   dispatch_qualification=dispatch,actual_upstream_datagrams=len(peer_rows),peer_receipts=peer_rows,
   cache_before=cache_before,cache_after=cache_after,aggregate_counter_deltas=aggregate_deltas,
   non_target_generation_records=other,target_cache_hits=0,elapsed=time.monotonic()-began)
  result['cases'].append(case);d.save('progress.json',json.dumps(result,indent=2)+'\n');return case
 finally:
  gate.touch()
  if protocol==6:
   d.release_probe(label,nonce);d.active_probe=None
   if client and client.get('phase')=='dns_tcp_read_complete':assert d.client(label,nonce)['dnsExchanges']==client['dnsExchanges']

def dispatch(d,peer,result,owners):
 result.update(task='SAKAMOTO-320',source_sha256=base.digest(Path(__file__)),policy_scope=POLICY_SCOPE,
  peer_backend=PEER_BACKEND,selected_upstream_port=d.args.upstream_port)
 if PEER_BACKEND=='linux':
  ready=[row for row in peer.messages if row.get('kind')=='ready'];assert len(ready)==1
  assert ready[0]['port']==d.args.upstream_port and ready[0]['transports']==['udp']
  result['selected_peer_scope']=dict(ready=ready[0],upstream_transports=['udp'],
   client_transport_scope='ordinary App UDP and TCP are independently exercised; UDP-only fixture does not claim TCP upstream')
 d.args.policy_scope=POLICY_SCOPE
 if d.args.matrix=='policy'and POLICY_SCOPE=='remaining'and d.args.profile=='root':
  proof=ROOT/'build-output/s320-dns-coalescing-20261027/coordination/policy-expanded-actual-abi-r3/qualified-policy-captures-r4.json'
  assert base.digest(proof)=='84a6c47a2153494950de0372d12b9ed0cd53e6d9ee24b73a7a12a22f5a76c351'
  prior=json.loads(proof.read_text());assert prior['status']=='PASS_EXISTING_ROOT_IPV4_POLICY_CONTROLS_AND_IPV6_INPUT_DENIAL'
  assert prior['new_ipv4_query_denied']['current_query_denied_before_join']
  assert any(case['generation']==2876 and case['status']=='PASS_FINITE_REAL_POLICY_CONTROL' for case in prior['cases'])
  independent=ROOT/'build-output/s314-vpn-tcp-20261023/coordination/root-s320-g2876-existing-policy-controls-independent-audit.json'
  assert base.digest(independent)=='02104479097bf0369257b9a9084c6b0d45ee1799688735b8a79f429be443b0be'
  result['reused_qualified_policy']=dict(path=str(proof),sha256=base.digest(proof),
   independent_audit=str(independent),independent_audit_sha256=base.digest(independent),original_whole_runs_remain_HOLD=True)
 if d.args.matrix!='smoke':
  selected={'policy':cases.policy,'semantics':cases.semantics,'view':cases.view_change,
   'stop-late':cases.stop_late,'capacity':cases.capacity}
  return selected[d.args.matrix](base,d,peer,result,owners)
 d.rules('n'+str(owners)+'-allow')
 for family,resolver,upstream in base.paths(d):
  d.upstream(f'coalescing{family}-upstream',upstream);d.proxy_ready(f'coalescing{family}-ready')
  for protocol in(6,17):
   coverage=set()
   for repetition in range(1 if owners==1 else 12):
    label=f'n{owners}-coalesce-{protocol}-{family}-{repetition}'
    case=simultaneous(d,peer,result,label,resolver,protocol)
    coverage|={r['owner']for r in case['records']if r['stage']==4}
    if coverage==set(range(owners)):break
   assert coverage==set(range(owners)),(family,protocol,coverage)

if __name__=='__main__':
 parser=argparse.ArgumentParser(add_help=False);parser.add_argument('--policy-scope',choices=('all','remaining'),default='all')
 parser.add_argument('--peer-backend',choices=('windows','linux'),default='windows')
 scope,remaining=parser.parse_known_args();POLICY_SCOPE=scope.policy_scope;PEER_BACKEND=scope.peer_backend
 if PEER_BACKEND=='linux':
  assert '--upstream-port' not in remaining,'Linux peer owns the explicitly selected 53054 endpoint'
  peer_spec=importlib.util.spec_from_file_location('s316_linux_peer',ROOT/'tests/device/helpers/s316_dns_peer.py')
  linux_peer=importlib.util.module_from_spec(peer_spec);peer_spec.loader.exec_module(linux_peer)
  base.root.Peer=lambda addresses,out,deadline:linux_peer.Peer(addresses,out,deadline,port=53054,transports=('udp',))
  remaining.extend(['--upstream-port','53054'])
 sys.argv=[sys.argv[0],*remaining]
 base.dispatch=dispatch;base.Device=Device;base.RootDevice=RootDevice
 raise SystemExit(base.main())
