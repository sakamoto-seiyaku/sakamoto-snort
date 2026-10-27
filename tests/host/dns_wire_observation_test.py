#!/usr/bin/env python3
"""Shared late-wire observer and terminal no-return fences with independent rows."""
import importlib.util
from contextlib import contextmanager
from pathlib import Path
import tempfile
import json
import threading
import types

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('wire_shared',ROOT/'tests/device/s315-root-dns-proxy.py')
shared=importlib.util.module_from_spec(spec);spec.loader.exec_module(shared)

def qualify_terminal_clock():
    spec=importlib.util.spec_from_file_location('s319_terminal_clock',ROOT/'tests/device/s319-dns-cache.py')
    cache=importlib.util.module_from_spec(spec);spec.loader.exec_module(cache)
    class Parent:
        def wire_stop(self,*_,**__):self.witnesses.clear()
    class Fixture(cache.UiState,Parent):pass
    with tempfile.TemporaryDirectory(prefix='dns-wire-clock-')as temporary:
        for terminal_ns,scope,valid in((100,'userspace_after_socket_close',True),
                (80,'userspace_after_socket_close',False),(100,'unknown',False),(0,'userspace_after_socket_close',False)):
            device=Fixture();device.out=Path(temporary);device.witnesses={'wlan1':{}}
            rows=[dict(kind='udp',mono_ns=90),dict(kind='stopped',mono_ns=terminal_ns,timestamp_scope=scope)]
            (device.out/'wire-final-wlan1.jsonl').write_text(''.join(json.dumps(row)+'\n'for row in rows))
            try:device.wire_stop()
            except AssertionError:
                assert not valid
            else:assert valid,'invalid terminal clock accepted'

qualify_terminal_clock()

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
    physical_interface='wlan0'
    generation=77;capture_deadline=100
    def __init__(self,samples):self.samples=samples;self.calls=0;self.scopes=[];self.saved={}
    def wire_coverage(self,label,interfaces=None):
        self.scopes.append(interfaces)
        result=self.samples[min(self.calls,len(self.samples)-1)];self.calls+=1;return {k:v for k,v in result.items()if interfaces is None or k in interfaces}
    def late_wire_coverage(self,label):return self.wire_coverage(label,interfaces=[self.physical_interface])
    def prepare_late_wire(self,label):return self.wire_coverage(label+'-before-late-release')
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
    assert d.scopes==[['wlan0'],['wlan0'],None]and arrived==[packet]and after['wlan0'][-1]==packet
shared.time=Clock();d=Device([snapshot([])])
try:shared.await_late_wire(d,'absent',before,[write])
except AssertionError:assert d.calls>1
else:raise AssertionError('absent exact Device wire was accepted')

# A matching packet returned by a slow read cannot escape the local deadline.
class SlowDevice(Device):
    def wire_coverage(self,label,interfaces=None):
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

# A later Android Wi-Fi handover can keep the LAN while changing wlan index.
# The actual observer key must carry through the same exact packet predicate.
shared.time=Clock();d=Device([dict(wlan1=[ready,packet])]);d.physical_interface='wlan1'
_,arrived=shared.await_late_wire(d,'physical-wlan1',dict(wlan1=[ready]),[write])
assert arrived==[packet]
shared.time=Clock();d=Device([dict(wlan1=[ready])]);d.physical_interface='wlan1'
try:shared.await_late_wire(d,'physical-wlan1-absent',dict(wlan1=[ready]),[write])
except AssertionError:pass
else:raise AssertionError('new physical interface accepted without its exact packet')

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
# A full lo/TUN read may take longer than the physical-arrival window. It
# must remain required, after the physical packet has met the unchanged bound.
class SlowFullCoverage(Device):
    def wire_coverage(self,label,interfaces=None):
        if interfaces is None:shared.time.value+=3
        else:shared.time.value+=.1
        self.last_scope=interfaces
        return super().wire_coverage(label,interfaces)
shared.time=Clock();d=SlowFullCoverage([snapshot([packet])])
after,arrived=shared.await_late_wire(d,'slow-full-scope',before,[write])
assert arrived==[packet]and set(after)==set(before)and d.capture_deadline==100
receipt=json.loads(d.saved['slow-full-scope-arrival-observation.json'])
assert receipt['status']=='PASS'and receipt['physical_only_arrival_boundary']
assert shared.time.value>3,'full coverage was silently omitted'

# Exercise both real TCP callers: release preparation and full return/fence
# reads may each cost 3s, while the exact physical match still has only 2s.
spec=importlib.util.spec_from_file_location('late_callers',ROOT/'tests/device/s319-dns-cache.py')
callers=importlib.util.module_from_spec(spec);spec.loader.exec_module(callers)
class ExactClock:
    value=0
    def monotonic(self):return self.value
    def sleep(self,seconds):self.value+=seconds
class Gate:
    released=False
    def touch(self):self.released=True
class CallerDevice(Device):
    def __init__(self,clock,gate,mode):
        super().__init__([]);self.clock=clock;self.gate=gate;self.mode=mode
    def wire_coverage(self,label,interfaces=None):
        self.scopes.append(interfaces)
        if interfaces is None:
            self.clock.value+=3
            if self.gate.released and self.mode=='full-fence-failure':raise AssertionError('full interval fence rejected')
        else:self.clock.value+=2.1 if self.mode=='slow-physical'else .2
        rows=[packet]if self.gate.released and self.mode!='missing-physical'else[]
        result=snapshot(rows)
        return {k:v for k,v in result.items()if interfaces is None or k in interfaces}
query=b'\x12\x34complete-question'
for module in(callers.root,callers.previous):
    for mode in('valid','slow-physical','missing-physical','full-fence-failure'):
        clock=ExactClock();gate=Gate();gate.released=False
        shared.time=clock;module.shared.time=clock
        device=CallerDevice(clock,gate,mode)
        sent=dict(write,kind='exchange',request=1,request_hex=query.hex())
        peer=types.SimpleNamespace(lock=threading.Lock(),messages=[sent])
        try:result=module.late_arrival(device,peer,'caller-'+mode,query,gate,0,before)
        except AssertionError:
            assert mode!='valid'
            boundary=json.loads(device.saved['caller-'+mode+'-release-boundary.json'])
            assert boundary['status']=='GATE_RELEASED'
            saved=json.loads(device.saved['caller-'+mode+'-lifecycle-observation.json'])
            assert saved['status']==('HOLD_FULL_INTERVAL_COVERAGE'if mode=='full-fence-failure'else'HOLD_PHYSICAL_ARRIVAL')
        else:
            assert mode=='valid'and result['observed_monotonic']-result['released_monotonic']<2
            assert result['full_coverage_completed_monotonic']-result['released_monotonic']>3
            assert device.scopes==[None,['wlan0'],None]
            assert set(result['full_coverage_interfaces'])==set(before)
        assert device.capture_deadline==100

clock=ExactClock();shared.time=clock
class FailedGate:
    def touch(self):raise RuntimeError('gate filesystem failure')
device=Device([])
try:shared.record_late_release(device,'failed-gate',FailedGate())
except RuntimeError:
    assert json.loads(device.saved['failed-gate-release-boundary.json'])['status']=='HOLD_GATE_RELEASE'
else:raise AssertionError('failed gate release was accepted')
print('strict delayed exact wire/timeout/context/witness lifecycle/full-interval forbidden-return contract: PASS')
