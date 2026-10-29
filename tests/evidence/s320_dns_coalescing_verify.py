"""Read actual public native quiesce counters before proxy storage is freed."""
import argparse,importlib.util,ipaddress,json
from pathlib import Path
_dispatch_path=Path(__file__).resolve().parents[2]/'tests/device/helpers/s319_dns_dispatch.py'
_dispatch_spec=importlib.util.spec_from_file_location('s319_dispatch_clock',_dispatch_path)
_dispatch=importlib.util.module_from_spec(_dispatch_spec);_dispatch_spec.loader.exec_module(_dispatch)

def quiesce_rows(text,*,generation=None,owners=None):
 rows=[]
 for line in text.splitlines():
  if not line.startswith('dns.proxy event=quiesce '):continue
  row=dict(part.split('=',1)for part in line.split()[1:])
  if generation is not None and int(row['generation'])!=generation:continue
  assert row['event']=='quiesce'
  for key in('waiters_after','exchanges_after','cache_entries_after','accepting_after'):
   assert int(row[key])==0,(key,row)
  assert int(row['proxy_retained_bytes'])==int(row['proxy_baseline_bytes']),row
  assert int(row['cache_retained_bytes'])==int(row['cache_baseline_bytes']),row
  assert int(row['cancelled_now'])==int(row['active_before']),row
  rows.append(row)
 assert rows,'no actual before-free quiesce counters'
 if owners is not None:assert {int(r['owner'])for r in rows}==set(range(owners)),rows
 return rows

from collections import Counter,defaultdict

def qualify_waiter_records(records,*,complete=True):
 proxy=[r for r in records if r['proxy_flags']&1];assert proxy
 groups=defaultdict(list)
 key_fields=('generation','owner','token','incarnation','request_attempt','transport_session','protocol','source_port','id','family','adapter_profile')
 stable=('generation','owner','token','incarnation','request_attempt','transport_session','protocol','source_port','id','family','resolver_port','route_revision','network_revision','adapter_profile','caller','uid','packet_uid','packet_availability')
 policies=(('policy_generation','query_policy_generation'),('policy_revision','query_policy_revision'),('policy_hash','query_policy_hash'),('winner','query_winner'))
 for r in proxy:
  assert r['stage']in(1,2,3,4)and 0<=r['proxy_result']<=11,r
  assert r['direction']==(1 if r['stage']in(2,4)else 3),r
  assert r['query_incarnation']==r['incarnation'],r
  if r['caller']==0:assert not r['availability']&8,r
  else:assert r['caller']==1 and r['availability']&8,r
  if r['stage']==1:
   assert r['query_token']==0 and all(r[lineage]==0 for _,lineage in policies),r
  else:assert r['query_token']==r['token'],r
  groups[tuple(r[k]for k in key_fields)].append(r)
 matched=0;orphan=0
 for identity,own in groups.items():
  queries=[r for r in own if r['stage']==1];assert len(queries)<=1,(identity,own)
  if not queries:
   # Pre-admission capacity/no-channel records can precede a Core request.
   orphan+=len(own);continue
  first=queries[0];matched+=1
  for r in own:
   for field in stable:assert r[field]==first[field],(field,first,r)
   if r['stage']!=1:
    for original,lineage in policies:assert r[lineage]==first[original],(lineage,first,r)
  terminals=[r for r in own if r['stage']in(2,3)and r['name_index']==0]
  deliveries=[r for r in own if r['stage']==4]
  assert len(terminals)<=1 and len(deliveries)<=1,(identity,own)
  if complete and first['proxy_result']==0:assert len(terminals)==1,(identity,own)
  if terminals:
   terminal=terminals[0]
   if terminal['proxy_result']in(7,8):assert not deliveries,(identity,own)
   if complete and terminal['proxy_result']not in(7,8):assert len(deliveries)==1,(identity,own)
   if terminal['stage']==3:assert terminal['actual_action']!=2,(identity,own)
   if deliveries:
    final=deliveries[0]
    assert terminal['proxy_result']==final['proxy_result']and terminal['reply_rcode']==final['reply_rcode'],(identity,own)
 return dict(proxy_records=len(proxy),groups=len(groups),admitted_groups=matched,pre_admission_records=orphan,stages=dict(Counter(str(r['stage'])for r in proxy)),results=dict(Counter(str(r['proxy_result'])for r in proxy)))


def qualify_current_policy(records,*,revision,denied,reliable,uid):
 abi=qualify_waiter_records(records)
 own=[r for r in records if r['proxy_flags']&1]
 admitted=[r for r in own if r['stage']==1]
 delivered=[r for r in own if r['stage']==4]
 assert admitted and len(admitted)==len(delivered)
 if reliable:
  assert all(r['caller']==1 and r['uid']==r['packet_uid']==uid and r['packet_availability']&8 for r in own)
 else:
  assert all(r['caller']==0 and not r['availability']&8 for r in own)
 for final in delivered:
  assert final['proxy_result']==(2 if denied else 1)and final['reply_rcode']==(5 if denied else 0)
  assert final['policy_revision']==revision>final['query_policy_revision']
  if denied:assert final['winner']and final['actual_action']==2
 for first in admitted:
  assert first['direction']==3 and first['actual_action']!=2 and first['policy_revision']<revision
  final=next(r for r in delivered if r['token']==first['token']and r['incarnation']==first['incarnation'])
  assert final['direction']==1 and final['query_policy_revision']==first['policy_revision']
 return dict(abi=abi,current_revision=revision,denied=denied,reliable_product_caller=reliable,historical_query_unchanged=True)


def qualify_query_denied(records,*,uid):
 abi=qualify_waiter_records(records)
 own=[r for r in records if r['proxy_flags']&1]
 assert own and all(r['caller']==1 and r['uid']==r['packet_uid']==uid and r['packet_availability']&8 for r in own)
 assert all(r['stage']in(1,4)and r['proxy_result']==2 and r['reply_rcode']==5 and r['actual_action']==2 for r in own)
 queries=[r for r in own if r['stage']==1];delivered=[r for r in own if r['stage']==4]
 assert queries and len(queries)==len(delivered)
 assert all(not r['proxy_flags']&16 for r in own)
 return dict(abi=abi,current_query_denied_before_join=True,successful_response_stage_not_required=True)


def qualify_exchange_wire(query,received,wire,records,*,expected_port=53053):
 assert 1<=len(received)<=2
 requests={r['request_hex']for r in received};assert len(requests)==1
 first=received[0];request=bytes.fromhex(first['request_hex']);assert request[2:]==query[2:]
 assert first['resolver'][1]==expected_port
 assert all(r['kind']=='received'and r['protocol']=='udp'and r['peer']==first['peer']and r['resolver']==first['resolver']for r in received)
 outgoing=[r for r in wire if r.get('kind')=='udp'and r['destination_port']in(53053,53054,expected_port) and bytes.fromhex(r['payload_hex'])[2:]==query[2:]]
 assert all(r['destination_port']==expected_port for r in outgoing),'target Question escaped to another test port'
 assert outgoing and all(r['payload_hex']==first['request_hex']for r in outgoing)
 for r in outgoing:
  assert ipaddress.ip_address(r['source'])==ipaddress.ip_address(first['peer'][0])and r['source_port']==first['peer'][1]
  assert ipaddress.ip_address(r['destination'])==ipaddress.ip_address(first['resolver'][0])and r['destination_port']==first['resolver'][1]
  assert r['timestamp_scope']=='userspace_after_recv'
 # Packet witnesses may contain repeated observations. Preserve every raw row;
 # no physical-row count is claimed to measure the number of send operations.
 retry=None
 if len(received)==2:
  assert received[1]['request']>first['request']
  peer_clock=_dispatch.peer_observation_gap(first,received[1])
  assert len(outgoing)>=2
  start=min(r['mono_us']for r in records if r['stage']==1)
  answers=[r for r in records if r['stage']==2 and r['name_index']==0 and r['proxy_flags']&4 and not r['proxy_flags']&16]
  if answers:
   elapsed=min(r['mono_us']for r in answers)-start
   assert 1500000<=elapsed<3000000,elapsed
   assert len({r['upstream_session']for r in answers})==1 and answers[0]['upstream_session']>0
   clock=dict(native_answer_elapsed_us=elapsed,answer_before_original3s_candidate=True)
  else:
   ends=[r for r in records if r['stage']==3 and r['name_index']==0];assert ends
   elapsed=max(r['mono_us']for r in ends)-start;assert elapsed>=1500000,elapsed
   clock=dict(native_settlement_span_us=elapsed,exact_failure_send_deadline_scope='Fixed3s candidate separately exercised by frozen public Core, actual POSIX and controlled Adapter evidence; settlement after deadline is not a send-time measurement')
  retry=dict(**peer_clock,physical_observation_rows=len(outgoing),**clock)
 return dict(logical_exchanges=1,raw_peer_datagrams=len(received),peer_receipts=received,physical_sender_observations=outgoing,
  physical_observation_count=len(outgoing),raw_observations_preserved=True,same_upstream_wire_identity=True,bounded_retry=retry,exact_send_times_unobserved=True)


if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('log',type=Path);parser.add_argument('--generation',type=int);parser.add_argument('--owners',type=int)
 args=parser.parse_args();rows=quiesce_rows(args.log.read_text(),generation=args.generation,owners=args.owners)
 print(json.dumps(dict(status='PASS_ACTUAL_BEFORE_FREE_QUIESCE_COUNTERS',rows=rows),indent=2))
