#!/usr/bin/env python3
"""Prepare the ordinary UI control before a pending view-change query."""
import importlib.util
import ipaddress
import unittest
from pathlib import Path
from types import SimpleNamespace

path=Path(__file__).resolve().parents[2]/'tests/device/helpers/s320_coalescing_cases.py'
spec=importlib.util.spec_from_file_location('s320_cases',path)
cases=importlib.util.module_from_spec(spec);spec.loader.exec_module(cases)

class Device:
    def __init__(self,address):
        self.args=SimpleNamespace(upstream_port=53054);self.address=address;self.events=[]
    def query_rules(self,label):self.events.append('query');return {'queryElapsedMillis':'1','activeRevision':'10'}
    def action(self,*args):self.events.append(('prefill',args));return 'prefilled'
    def foreground_ui(self,label):self.events.append('foreground')
    def tap(self,label,text,*,click=True):self.events.append(('find',text,click));return (1,2)
    def adb(self,*args):self.events.append(('tap',args));return 'tapped'
    def save(self,label,value):return value
    def applied_status(self,label,old,*,previous_revision):
        self.events.append(('read',old,previous_revision))
        return {'activeRevision':'11','dns.enabled':'1','dns.active.enabled':'1',
                'dns.family':'6','dns.active.family':'6','dns.port':'53054','dns.active.port':'53054',
                'dns.address':ipaddress.ip_address(self.address).packed.hex(),
                'dns.active.address':ipaddress.ip_address(self.address).packed.hex()}

class ViewPrecondition(unittest.TestCase):
    def test_prepare_then_apply_exact_selected_endpoint(self):
        address='2001:db8::53';d=Device(address)
        prepared=cases.prepare_view_change(d,'view',address)
        self.assertNotIn('tap',[event[0] if isinstance(event,tuple) else event for event in d.events])
        status=cases.apply_view_change(d,'view',address,prepared)
        self.assertEqual(status['activeRevision'],'11')
        self.assertEqual(d.selected_dns['endpoint'],(address,53054))
        self.assertEqual(d.events[-2][0],'tap');self.assertEqual(d.events[-1][0],'read')

    def test_wrong_applied_endpoint_is_rejected(self):
        d=Device('2001:db8::54');prepared=cases.prepare_view_change(d,'view','2001:db8::53')
        with self.assertRaises(AssertionError):cases.apply_view_change(d,'view','2001:db8::53',prepared)

if __name__=='__main__':unittest.main()
