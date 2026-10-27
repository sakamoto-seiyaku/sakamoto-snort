#!/usr/bin/env python3
"""Reader qualification controls for normal DNS history capacity and receipts."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

path=Path(__file__).resolve().parents[1]/'device/helpers/s319_dns_retention.py'
spec=importlib.util.spec_from_file_location('dns_history_qualification',path)
reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)

def row(index,boot='one'):
 return json.dumps(dict(record=dict(value=index),received_clock=dict(boot_id=boot,uptime_us=index)),sort_keys=True)

def cohort():
 before={f'k{x:05}':row(x)for x in range(4096)}
 after=dict(before);del after['k00000'];del after['k00001']
 after.update({f'k{x:05}':row(x)for x in(4096,4097)})
 return [dict(dns_accepted=4096,dns_evicted=0,dns_rejected=0),before,
         dict(dns_accepted=4098,dns_evicted=2,dns_rejected=0),after]

class HistoryQualification(unittest.TestCase):
 def test_exact_oldest_prefix_retained_and_all_new_survive(self):
  result=reader.qualify_history(*cohort())
  self.assertEqual(result['retired_old_rows'],2)
  self.assertEqual(result['surviving_old_raw_and_clock_exact'],4094)
  self.assertEqual(result['oldest_retired_cutoff_uptime_us'],1)
 def test_no_retirement_below_capacity(self):
  result=reader.qualify_history(dict(dns_accepted=0,dns_evicted=0,dns_rejected=0),{},
   dict(dns_accepted=1,dns_evicted=0,dns_rejected=0),{'k':row(0)})
  self.assertEqual(result['new_rows'],1)
 def test_equal_receipts_use_canonical_key(self):
  args=cohort();args[1]={k:row(0)for k in args[1]}
  args[3]={k:(args[1][k]if k in args[1]else row(4096))for k in args[3]}
  self.assertEqual(reader.qualify_history(*args)['removed_keys'],['k00000','k00001'])
 def test_corrupt_or_unexplained_history_is_rejected(self):
  changes={
   'surviving_payload_changed':lambda a:a[3].__setitem__('k00002',row(9000)),
   'surviving_clock_changed':lambda a:a[3].__setitem__('k00002',row(2,'other')),
   'new_row_missing':lambda a:a[3].pop('k04096'),
   'acceptance_mismatch':lambda a:a[2].__setitem__('dns_accepted',4099),
   'eviction_mismatch':lambda a:a[2].__setitem__('dns_evicted',3),
   'new_rejection':lambda a:a[2].__setitem__('dns_rejected',1),
   'newer_old_row_retired':lambda a:(a[3].__setitem__('k00000',a[1]['k00000']),a[3].pop('k00002')),
   'mixed_receipt_boots':lambda a:a[3].__setitem__('k04096',row(4096,'other')),
   'clock_unavailable':lambda a:a[3].__setitem__('k04096',json.dumps(dict(record={}))),
   'capacity_exceeded':lambda a:a[3].__setitem__('extra',row(9999)),
  }
  for label,change in changes.items():
   with self.subTest(label=label):
    args=copy.deepcopy(cohort());change(args)
    with self.assertRaises(AssertionError):reader.qualify_history(*args)

if __name__=='__main__':unittest.main()
