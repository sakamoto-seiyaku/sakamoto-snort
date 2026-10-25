#!/usr/bin/env python3
"""Shared late-wire observer and terminal no-return fences with independent rows."""
import importlib.util
from contextlib import contextmanager
from pathlib import Path
import tempfile
import json

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('wire_shared',ROOT/'tests/device/s315-root-dns-proxy.py')
shared=importlib.util.module_from_spec(spec);spec.loader.exec_module(shared)

# The 80-byte late answer and endpoint shape come from the preserved actual
# one-shot snapshot failure; they do not depend on the matching predicate.
reply='0233818000010001000000000c6e312d73746f702d6c61746505716e616d65047465737400000100010c6e312d73746f702d6c61746505716e616d65047465737400000100010000003c0004c000022c'
write=dict(resolver=['192.168.4.5',53054],peer=['192.168.4.151',43513],reply_hex=reply)
packet=dict(kind='udp',source='192.168.4.5',source_port=53054,destination='192.168.4.151',destination_port=43513,payload_hex=reply)
ready=dict(kind='ready')
before={'wlan0':[ready],'lo':[ready],'tun0':[ready]}

class Clock:
    value=0
    def monotonic(self):self.value+=.1;return self.value
    def sleep(self,_):self.value+=.1

class Device:
    generation=77;capture_deadline=100
    def __init__(self,samples):self.samples=samples;self.calls=0;self.saved={}
    def wire_coverage(self,label):
        result=self.samples[min(self.calls,len(self.samples)-1)];self.calls+=1;return result
    def save(self,label,value):self.saved[label]=value
    @contextmanager
    def control_budget(self,seconds):
        previous=self.capture_deadline
        self.capture_deadline=min(previous,shared.time.monotonic()+seconds)
        try:yield
        finally:self.capture_deadline=previous

def snapshot(rows):return dict(before,wlan0=[ready,*rows])

for changes in ({'payload_hex':'ffff'+reply[4:]},{'source':'192.0.2.1'},{'source_port':53053},{'destination':'192.0.2.2'},{'destination_port':43514}):
    wrong=dict(packet,**changes);shared.time=Clock()
    d=Device([snapshot([wrong]),snapshot([wrong,packet])])
    after,arrived=shared.await_late_wire(d,'delayed',before,[write])
    assert d.calls==2 and arrived==[packet] and after['wlan0'][-1]==packet
shared.time=Clock();d=Device([snapshot([])])
try:shared.await_late_wire(d,'absent',before,[write])
except AssertionError:assert d.calls>1
else:raise AssertionError('absent exact Device wire was accepted')

# A matching packet returned by a slow read cannot escape the local deadline.
class SlowDevice(Device):
    def wire_coverage(self,label):
        self.observed_budget=self.capture_deadline
        shared.time.value=3
        return snapshot([packet])
shared.time=Clock();d=SlowDevice([])
try:shared.await_late_wire(d,'slow-match',before,[write])
except AssertionError:
    assert d.observed_budget<100 and d.capture_deadline==100
    saved=json.loads(d.saved['slow-match-arrival-observation.json'])
    assert saved['status']=='HOLD_OBSERVER_DEADLINE' and saved['arrived_exact']==[packet]
else:raise AssertionError('matching snapshot accepted after local observation deadline')
shared.time=Clock();d=Device([snapshot([packet])]);d.capture_deadline=.6
shared.await_late_wire(d,'cohort-min',before,[write]);assert d.capture_deadline==.6

with tempfile.TemporaryDirectory(prefix='dns-wire-fence-') as tmp:
    d=object.__new__(shared.Device);d.generation=77;d.forbidden_udp_returns=[]
    d.witnesses={'tun0':dict(pid=12,start=34,uid=0,exe='/owned/wire')}
    d.save=lambda name,value:(Path(tmp)/name).write_text(value)
    shared.Device.forbid_udp_return(d,'old','tun0',[ready],20000,bytes.fromhex(reply))
    shared.Device.verify_udp_return_fences(d,'tun0',[ready,dict(kind='stopped')])
    assert not d.forbidden_udp_returns
    shared.Device.forbid_udp_return(d,'old-again','tun0',[ready],20000,bytes.fromhex(reply))
    returned=dict(kind='udp',source_port=53,destination_port=20000,payload_hex=reply)
    try:shared.Device.verify_udp_return_fences(d,'tun0',[ready,returned,dict(kind='stopped')])
    except AssertionError:pass
    else:raise AssertionError('terminal capture ignored a forbidden late return')
    d.forbidden_udp_returns=[]
    shared.Device.forbid_udp_return(d,'identity','tun0',[ready],20000,None)
    d.witnesses['tun0']['pid']=13
    try:shared.Device.verify_udp_return_fences(d,'tun0',[ready,dict(kind='stopped')])
    except AssertionError:pass
    else:raise AssertionError('different witness identity supplied negative coverage')
for rows in ([],[ready,dict(kind='stopped')]):
    d=object.__new__(shared.Device);d.witnesses={'wlan0':{}};d.wire=lambda *_:rows
    try:shared.Device.wire_coverage(d,'unusable')
    except AssertionError:pass
    else:raise AssertionError('missing/closed wire capture was accepted as live coverage')
print('strict delayed exact wire/timeout/context/witness lifecycle/full-interval forbidden-return contract: PASS')
