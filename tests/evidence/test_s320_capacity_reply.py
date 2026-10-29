#!/usr/bin/env python3
"""Capacity replies retain exact data and use their actual normal cache source."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path)
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
B=load('s320_capacity_base','tests/device/s319-dns-cache.py')
cases=load('s320_capacity_cases','tests/device/helpers/s320_coalescing_cases.py')
QUERY=bytes.fromhex('123401000001000000000000076578616d706c6503636f6d0000010001')
ANSWER=bytes.fromhex('123481800001000100000000076578616d706c6503636f6d0000010001c00c000100010000003c0004c0000209')

def fixture():
 second=b'\xab\xcd'+QUERY[2:]
 cached=bytearray(ANSWER);cached[:2]=second[:2];cached[-10:-6]=(59).to_bytes(4,'big')
 case=dict(queries=[QUERY.hex(),second.hex()],answer_hex=ANSWER.hex(),
  expected_rcodes={'4660':0,'43981':0},client=dict(dnsExchanges=[
   dict(sentHex=QUERY.hex(),replyHex=ANSWER.hex()),dict(sentHex=second.hex(),replyHex=cached.hex())]))
 records=[]
 for token,identity,flags,mono in [(1,4660,5,1000000),(2,43981,17,1000100)]:
  record=dict(generation=77,owner=0,route_revision=3,network_revision=5,
   upstream_family=4,upstream_address=[192,0,2,53]+[0]*12,upstream_port=53054,upstream_transport=1,
   token=token,incarnation=7,request_attempt=token,transport_session=70,protocol=6,
   source_port=40000,id=identity,name_index=0,proxy_flags=flags,proxy_result=11 if flags==17 else 1,
   mono_us=mono,correlation=1,coverage=1,query_token=token,query_incarnation=7)
  records.extend([dict(record,stage=2),dict(record,stage=4)])
 return case,records

class CapacityReplies(unittest.TestCase):
 def test_reply_id_matches_when_pipeline_answers_arrive_out_of_order(self):
  case,records=fixture();first,second=case['client']['dnsExchanges']
  first['replyHex'],second['replyHex']=second['replyHex'],first['replyHex']
  proof=cases.capacity_reply_data(B,case,records)
  self.assertEqual([p['id'] for p in proof],[43981])

 def test_real_cache_source_uses_full_monotonic_age(self):
  case,records=fixture();proof=cases.capacity_reply_data(B,case,records)
  self.assertEqual(proof,[dict(id=43981,first_resolution_mono_us=1000000,
   cache_reply_mono_us=1000100,full_cache_age_us=100)])

 def test_unchanged_ttl_is_rejected_for_cache_reply(self):
  case,records=fixture();case['client']['dnsExchanges'][1]['replyHex']='abcd'+ANSWER.hex()[4:]
  with self.assertRaises(AssertionError):cases.capacity_reply_data(B,case,records)

 def test_no_source_or_another_resolution_view_is_rejected(self):
  case,records=fixture()
  for changed in [records[2:],copy.deepcopy(records)]:
   if len(changed)==4:changed[2]['route_revision']+=1
   with self.assertRaises(AssertionError):cases.capacity_reply_data(B,case,changed)

 def test_duplicate_identity_or_changed_reply_data_is_rejected(self):
  case,records=fixture()
  duplicate=copy.deepcopy(case);duplicate['client']['dnsExchanges'][1]=duplicate['client']['dnsExchanges'][0]
  changed=copy.deepcopy(case);wire=bytearray.fromhex(changed['client']['dnsExchanges'][1]['replyHex']);wire[-1]^=1
  changed['client']['dnsExchanges'][1]['replyHex']=wire.hex()
  for invalid in [duplicate,changed]:
   with self.assertRaises(AssertionError):cases.capacity_reply_data(B,invalid,records)

if __name__=='__main__':unittest.main()
