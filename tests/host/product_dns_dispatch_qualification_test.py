#!/usr/bin/env python3
"""Reject unproved duplicate dispatches while preserving the one UDP retry."""
import copy
import importlib.util
from pathlib import Path
import unittest
import struct
import tempfile
import types

path=Path(__file__).resolve().parents[1]/'device/helpers/s319_dns_dispatch.py'
spec=importlib.util.spec_from_file_location('dns_dispatch_qualification',path)
reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)


def cohort():
 query=bytes.fromhex('12340100000100000000000001780000010001')
 received=[dict(kind='received',protocol='udp',request_hex=query.hex(),request=n,
                received_mono_ms=1000+(n-1)*1504,resolver=['192.0.2.1',53053],peer=['192.0.2.2',40000])for n in(1,2)]
 wire=[dict(kind='udp',payload_hex=query.hex(),source='192.0.2.2',source_port=40000,
            destination='192.0.2.1',destination_port=53053,mono_ns=n,timestamp_scope='userspace_after_recv')
       for n in(1_000_000_000,2_504_000_000)]
 records=[dict(stage=1,token=9,request_attempt=7,mono_us=10),
          dict(stage=2,token=9,request_attempt=7,mono_us=1_580_010,name_index=0,proxy_flags=5,upstream_session=3)]
 for row in records:row.update(generation=10,owner=0,incarnation=2,transport_session=4,id=0x1234,
                               source_port=20000,protocol=6,network_revision=5,route_revision=6)
 records.append(dict(records[-1],stage=4,mono_us=1_580_011))
 return [query,received,wire,records]


class DispatchQualification(unittest.TestCase):
 def test_one_real_bounded_retry_is_one_logical_dispatch(self):
  value=reader.qualify_udp_dispatches(*cohort())
  self.assertEqual((value['logical_dispatches'],value['received_datagrams']),(1,2))
  self.assertEqual(len(value['bounded_retries']),1)

 def test_zero_and_single_dispatch_do_not_require_retry_evidence(self):
  args=cohort();args[1]=[];args[2]=[]
  self.assertEqual(reader.qualify_udp_dispatches(*args)['logical_dispatches'],0)
  args=cohort();args[1]=args[1][:1];args[2]=args[2][:1]
  self.assertEqual(reader.qualify_udp_dispatches(*args)['received_datagrams'],1)

 def test_two_fresh_proxy_ids_remain_two_dispatches(self):
  args=cohort();second=bytes.fromhex(args[1][1]['request_hex']);second=b'\x12\x35'+second[2:]
  args[1][1]['request_hex']=second.hex();args[2][1]['payload_hex']=second.hex()
  self.assertEqual(reader.qualify_udp_dispatches(*args)['logical_dispatches'],2)

 def test_observation_gaps_have_no_native_timer_authority(self):
  for gap in(0,1,1_499_995_891,9_000_000_000):
   with self.subTest(physical_observation_gap_ns=gap):
    args=cohort();args[2][1]['mono_ns']=args[2][0]['mono_ns']+gap
    args[1][1]['received_mono_ms']=args[1][0]['received_mono_ms']+(gap//1_000_000)
    self.assertEqual(reader.qualify_udp_dispatches(*args)['logical_dispatches'],1)

 def test_counterexamples_are_rejected(self):
  changes={
   'third_peer_datagram':lambda a:a[1].append(dict(a[1][-1],request=3)),
   'peer_tuple_changes':lambda a:a[1][1].__setitem__('peer',['192.0.2.2',40001]),
   'wire_tuple_changes':lambda a:a[2][1].__setitem__('source_port',40001),
   'wire_missing':lambda a:a[2].clear(),
   'peer_missing':lambda a:a[1].clear(),
   'physical_clock_backwards':lambda a:a[2][1].__setitem__('mono_ns',999_999_999),
   'physical_retry_observation_missing':lambda a:a[2].pop(),
   'physical_wrong_clock_scope':lambda a:a[2][1].__setitem__('timestamp_scope','send_time'),
   'peer_clock_backwards':lambda a:a[1][1].__setitem__('received_mono_ms',999),
   'native_before_retry':lambda a:a[3][1].__setitem__('mono_us',1_500_009),
   'native_expired':lambda a:a[3][1].__setitem__('mono_us',3_000_010),
   'native_identity_changes':lambda a:a[3][1].__setitem__('request_attempt',8),
   'native_socket_unproved':lambda a:a[3][1].__setitem__('upstream_session',0),
   'native_identity_ambiguous':lambda a:a[3].append(dict(a[3][1],token=10)),
   'native_delivered_twice':lambda a:a[3].append(dict(a[3][-1])),
   'native_delivered_missing':lambda a:a[3].pop(),
   'native_view_changed':lambda a:a[3][-1].__setitem__('network_revision',10),
   'native_session_changed':lambda a:a[3][-1].__setitem__('upstream_session',4),
   'cache_cannot_explain_dispatch':lambda a:a[3][1].__setitem__('proxy_flags',17),
  }
  for label,change in changes.items():
   with self.subTest(label=label):
    args=copy.deepcopy(cohort());change(args)
    with self.assertRaises(AssertionError):reader.qualify_udp_dispatches(*args)


class DelegatedDispatchQualification(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  path=Path(__file__).resolve().parents[1]/'device/s319-dns-cache.py'
  spec=importlib.util.spec_from_file_location('delegated_cache',path)
  cls.cache=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.cache)

 def exercise(self,profile,change=None,legacy=False):
  query,received,outgoing,records=cohort();cache=self.cache
  reply=cache.ttl_reply(query,60)
  for row in records:
   row.update(caller=1,uid=12632,delivery=2 if row['stage']==4 else 0,reply_capacity=65535,
    message_sequence=row['token'],return_provenance=3 if profile=='vpn'else 0,
    return_policy_revision=1 if profile=='vpn'else 0,packet_uid=12632,
    packet_availability=cache.previous.DNS_APP_RELIABLE)
  if change:change(received,outgoing,records)
  class Fixture(cache.UiState):
   generation=10;uid=12632;physical_interface='wlan1';tun_interface='tun0'
   def reserve_source_port(self,_):return 20000
   def forbid_original_tcp(self,*_):pass
   def launch_tcp(self,*_,**__):self.active_probe='owned';return 'owned'
   def wait(self,*_,**__):return self.client('',None)
   def client(self,*_):return dict(phase='dns_tcp_read_complete',dnsExchanges=[dict(replyHex=reply.hex())])
   def observation_matching(self,_,predicate,**__):
    value=dict(consumer=dict(persistent=dict(dns=dict(recent={str(i):dict(record=r)for i,r in enumerate(records)}))))
    assert predicate(value);return value
   def observation(self,label):return self.observation_matching(label,lambda _:True)
   def wire_coverage(self,label):
    wire=dict(wlan1=[],lo=[],tun0=[])
    if label.endswith('-after'):
     wire['wlan1']=outgoing
     wire['tun0'if profile=='vpn'else'lo']=[dict(kind='tcp',packet_type=4,source_port=53,
      destination_port=20000,sequence=100,payload_hex=(struct.pack('!H',len(reply))+reply).hex())]
    return wire
   def release_probe(self,*_):pass
   def save(self,name,text):(self.out/name).write_text(text);return text
  with tempfile.TemporaryDirectory(prefix='dns-delegated-dispatch-')as temporary:
   device=Fixture();device.out=Path(temporary);device.args=types.SimpleNamespace(profile=profile)
   device.expected_durable=[];result=dict(cases=[])
   if legacy:device.qualify_peer_dispatches=None
   peer=types.SimpleNamespace(cursor=lambda:0,received=lambda *_args,**_kwargs:received)
   method=cache.previous.paired_exchange if profile=='vpn'else cache.root.paired_exchange
   case=method(device,peer,result,'delegated','1.1.1.1',[query],[reply],rcodes=[0])
   self.assertEqual(case['records'],records)
   return case

 def test_delegated_root_and_vpn_accept_one_proved_retry(self):
  for profile in('root','vpn'):
   with self.subTest(profile=profile):
    case=self.exercise(profile)
    self.assertEqual(case['dispatch_qualifications'][0]['received_datagrams'],2)
    self.assertEqual(case['dispatch_qualifications'][0]['logical_dispatches'],1)

 def test_legacy_root_and_vpn_default_datagram_assertion_stays_exact(self):
  for profile in('root','vpn'):
   with self.subTest(profile=profile):
    with self.assertRaises(AssertionError):self.exercise(profile,legacy=True)

 def test_delegated_counterexamples_remain_rejected(self):
  changes={
   'third_datagram':lambda p,w,n:p.append(dict(p[-1],request=3)),
   'tuple_changes':lambda p,w,n:p[1].__setitem__('peer',['192.0.2.2',40001]),
   'before_native_retry':lambda p,w,n:n[1].__setitem__('mono_us',1_500_009),
   'native_socket_missing':lambda p,w,n:n[1].__setitem__('upstream_session',0),
   'native_view_changes':lambda p,w,n:n[-1].__setitem__('network_revision',7),
   'peer_missing':lambda p,w,n:p.clear(),
   'cache_cannot_explain_dispatch':lambda p,w,n:n[1].__setitem__('proxy_flags',17),
   'peer_identity_not_new':lambda p,w,n:p[1].__setitem__('request',1),
  }
  for profile in('root','vpn'):
   for label,change in changes.items():
    with self.subTest(profile=profile,label=label):
     with self.assertRaises(AssertionError):self.exercise(profile,change)


if __name__=='__main__':unittest.main()
