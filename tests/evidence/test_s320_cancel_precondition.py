#!/usr/bin/env python3
"""The test controller must wait for, and never invent, two live waiters."""
import importlib.util
import unittest
from pathlib import Path

path=Path(__file__).resolve().parents[2]/'tests/device/helpers/s320_coalescing_cases.py'
spec=importlib.util.spec_from_file_location('s320_cases',path)
cases=importlib.util.module_from_spec(spec);spec.loader.exec_module(cases)

class FakeDevice:
    def __init__(self,waiters):self.waiters=list(waiters);self.last=self.waiters[-1];self.reads=0
    def await_peer_query(self,*args,**kwargs):return [{'request_hex':'1234'}]
    def cli(self,*args):
        self.reads+=1
        value=self.waiters.pop(0) if self.waiters else self.last
        return f'dns.proxy owner=0 waiters={value} transactions=1\n'
    def save(self,label,value):return value

class FakePeer:
    def received(self,*args,**kwargs):return [{'request_hex':'1234'}]

class CancelPrecondition(unittest.TestCase):
    def test_two_actual_snapshots_required_before_continue(self):
        device=FakeDevice([1,2]);ctx=dict(label='cancel',query=b'query',cursor=0)
        rows=cases.pending(None,device,FakePeer(),ctx,wait_for_both=0.2)
        self.assertEqual(rows[0]['waiters'],'2');self.assertEqual(device.reads,2)

    def test_one_waiter_never_qualifies(self):
        device=FakeDevice([1]);ctx=dict(label='cancel',query=b'query',cursor=0)
        with self.assertRaises(AssertionError):cases.pending(None,device,FakePeer(),ctx,wait_for_both=0.05)

if __name__=='__main__':unittest.main()
