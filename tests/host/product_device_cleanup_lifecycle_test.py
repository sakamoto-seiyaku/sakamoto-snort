#!/usr/bin/env python3
"""Exercise S315 cleanup ownership at the actual Device-driver seam."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
from contextlib import contextmanager
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

s312 = load('s312_cleanup_driver', 'tests/device/s312-dns-response.py')
s233 = load('s233_cleanup_driver', 'tests/device/s233-fail-open.py')
s313 = load('s313_cleanup_driver', 'tests/device/s313-root-dns-tcp.py')
s315 = load('s315_cleanup_driver', 'tests/device/s315-root-dns-proxy.py')
REAL_CLEANUP_BUDGET = s315.Device.cleanup_budget

class Reader:
    def __init__(self, stream):
        stream.write(b'opened\n'); stream.flush(); self.returncode=None; self.terminated=False
    def poll(self): return self.returncode
    def terminate(self): self.terminated=True; self.returncode=143
    def kill(self): self.returncode=-9
    def wait(self, timeout):
        if self.returncode is None: self.returncode=143
        return self.returncode

class StalledReader(Reader):
    def wait(self, timeout): raise subprocess.TimeoutExpired(['adb','tail'],timeout)

class CleanupLifecycleTest(unittest.TestCase):
    def test_full_matrix_reaches_capacity_after_both_client_capacities(self):
        class Device:
            args=types.SimpleNamespace(endpoint4='192.168.4.5',endpoint6='fd76:d462:c4e3::1')
            def rules(self,*_args,**_kwargs): pass
            def upstream(self,*_): pass
            def proxy_ready(self,*_): pass
            def question(self,label,qtype=1,**options):
                return s315.fixtures.question(31500,label+'.qname.test',qtype,**options)
        peer=types.SimpleNamespace(register=lambda *_args,**_kwargs:None)
        for owners in (1,3):
            with self.subTest(owners=owners),patch.object(s315,'ordinary_rr'),\
                 patch.object(s315,'exchange') as exchange,patch.object(s315,'hot_policy'),\
                 patch.object(s315,'hot_upstream'),patch.object(s315,'padded_off_original'),\
                 patch.object(s315,'system_unknown'),patch.object(s315,'capacity') as run_capacity:
                device=Device();result={'cases':[]}
                s315.matrix(device,peer,result,owners)
                if owners==1:
                    self.assertEqual([call.kwargs['capacities'] for call in exchange.call_args_list
                        if call.args[3].startswith('n1-client-tc')],[[512],[1232]])
                    run_capacity.assert_called_once_with(device,peer,result,'n1-capacity')
                else:
                    run_capacity.assert_not_called()

    def test_cli_setup_failure_retains_primary_error_receipt(self):
        target=s233.Target.__new__(s233.Target); target.pixel=True
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(s233.subprocess,'Popen',side_effect=OSError('cli launch failed')):
                with self.assertRaisesRegex(OSError,'cli launch failed'):
                    target.cli('/runtime',['show product dns'],deadline=10,capture_output=temporary)
            captures=list((Path(temporary)/'cli-captures').glob('*.json'))
            self.assertEqual(len(captures),1)
            receipt=json.loads(captures[0].read_text())
            self.assertIn('cli launch failed',receipt['error'])
            self.assertIsNone(receipt['local_pid'])

    def test_cli_created_child_expiry_retains_owned_process_and_primary_error(self):
        class Process:
            pid=211; stdout=object()
            class Input:
                def write(self,_): pass
                def flush(self): pass
            stdin=Input()
            def __init__(self): self.terminated=False; self.returncode=None
            def poll(self): return None
            def terminate(self): self.terminated=True
            def wait(self, timeout): self.timeout=timeout; raise subprocess.TimeoutExpired(['cli'],timeout)
        class Selector:
            def register(self,*_): pass
            def select(self,_): return []
            def close(self): pass
        target=s233.Target.__new__(s233.Target); target.pixel=True
        process=Process()
        with tempfile.TemporaryDirectory() as temporary:
            clock=iter((0,.2,.2,.2,.2,.2))
            with patch.object(s233.subprocess,'Popen',return_value=process),\
                 patch.object(s233.selectors,'DefaultSelector',return_value=Selector()),\
                 patch.object(s233.time,'monotonic',side_effect=lambda:next(clock)):
                with self.assertRaisesRegex(RuntimeError,'CLI timed out'):
                    target.cli('/runtime',['show product dns'],timeout=.1,deadline=1,capture_output=temporary)
            self.assertTrue(process.terminated)
            self.assertIs(target.children[211],process)
            self.assertGreater(process.timeout,0)
            receipt,=list((Path(temporary)/'cli-captures').glob('*.json'))
            self.assertIn('CLI timed out',json.loads(receipt.read_text())['error'])

    def test_cli_termination_failure_retains_owned_process_and_primary_error(self):
        class Process:
            pid=212; stdout=object()
            class Input:
                def write(self,_): pass
                def flush(self): pass
            stdin=Input()
            def __init__(self): self.returncode=None
            def poll(self): return None
            def terminate(self): raise RuntimeError('terminate failed')
        class Selector:
            def register(self,*_): pass
            def select(self,_): return []
            def close(self): pass
        target=s233.Target.__new__(s233.Target); target.pixel=True; process=Process()
        with tempfile.TemporaryDirectory() as temporary:
            clock=iter((0,.2,.2,.2))
            with patch.object(s233.subprocess,'Popen',return_value=process),\
                 patch.object(s233.selectors,'DefaultSelector',return_value=Selector()),\
                 patch.object(s233.time,'monotonic',side_effect=lambda:next(clock)):
                with self.assertRaisesRegex(RuntimeError,'CLI timed out'):
                    target.cli('/runtime',['show product dns'],timeout=.1,deadline=1,capture_output=temporary)
            self.assertIs(target.children[212],process)
            receipt,=list((Path(temporary)/'cli-captures').glob('*.json'))
            self.assertIn('terminate failed',json.loads(receipt.read_text())['error'])

    def test_trace_option_activates_the_actual_s313_supervisor(self):
        with tempfile.TemporaryDirectory() as temporary:
            def base_init(device, _): device.out=Path(temporary)
            with patch.object(s313.support.Device,'__init__',base_init):
                device=s313.Device(types.SimpleNamespace(trace=True))
            self.assertIsNotNone(device.adb_trace)
            self.assertEqual(device.adb_trace.output,Path(temporary))

    def test_s313_close_trace_propagates_the_helper_hold(self):
        class Trace:
            def close(self, _): raise RuntimeError('trace hold')
        device=s313.Device.__new__(s313.Device); device.adb_trace=Trace(); device.capture_deadline=None
        with self.assertRaisesRegex(RuntimeError,'trace hold'): device.close_trace()

    def test_prepared_stop_capture_reuses_reader_and_keeps_cleanup_stop_independent(self):
        for actual_label in ('pending','cleanup'):
            with self.subTest(actual_label=actual_label),tempfile.TemporaryDirectory() as temporary:
                out=Path(temporary);device=s312.Device.__new__(s312.Device)
                device.out=out;device.profile='root';device.reader=None
                calls=[];device.app=lambda path:calls.append(('read',path)) or 'before query\n'
                device.save=lambda name,value:((out/name).write_text(value),value)[1]
                device.action=lambda *_:calls.append(('stop',)) or (_ for _ in ()).throw(RuntimeError('action witness'))
                readers=[]
                def launch(*_args,**kwargs):
                    reader=Reader(kwargs['stdout']);readers.append(reader);return reader
                with patch.object(s312.subprocess,'Popen',side_effect=launch):
                    device.prepare_stop_capture('pending')
                    calls.append(('query',))
                    with self.assertRaisesRegex(RuntimeError,'action witness'):device.stop(actual_label)
                self.assertEqual(calls,[('read','files/profiles/root/vpp/logs/vpp-stdout.log'),('query',),('stop',)])
                self.assertEqual(len(readers),1);self.assertFalse(readers[0].terminated)
                self.assertIsNone(device.reader);self.assertIsNone(device.prepared_stop_capture)
                self.assertTrue((out/(actual_label+'-stop.log')).read_bytes())
                self.assertEqual(json.loads((out/(actual_label+'-stop-reader-settlement.json')).read_text())['status'],'PASS')

    def test_stop_timeout_settles_the_owned_reader(self):
        with tempfile.TemporaryDirectory() as temporary:
            out=Path(temporary); device=s312.Device.__new__(s312.Device)
            device.out=out; device.args=type('Args',(),{'profile':'root'})(); device.profile='root'
            device.owners=1; device.active=True; device.reader=None; device.app=lambda _: ''
            device.action=lambda *_: (_ for _ in ()).throw(subprocess.TimeoutExpired(['adb','am','start'],10))
            device.wait=lambda *_args,**_kwargs: None
            device.save=lambda name,value: (out/name).write_text(value) or value
            readers=[]
            def launch(*_args,**kwargs):
                reader=Reader(kwargs['stdout']); readers.append(reader); return reader
            with patch.object(s312.subprocess,'Popen',side_effect=launch):
                with self.assertRaises(subprocess.TimeoutExpired): device.stop('timeout')
            self.assertFalse(readers[0].terminated); self.assertIsNone(device.reader)
            settlement=json.loads((out/'timeout-stop-reader-settlement.json').read_text())
            self.assertEqual(settlement['status'],'PASS'); self.assertTrue(settlement['natural_tail_wait'])

    def test_stop_timeout_retains_reader_when_natural_tail_wait_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            out=Path(temporary); device=s312.Device.__new__(s312.Device)
            device.out=out; device.args=type('Args',(),{'profile':'root'})(); device.profile='root'
            device.owners=1; device.active=True; device.reader=None; device.app=lambda _: ''
            device.action=lambda *_: (_ for _ in ()).throw(subprocess.TimeoutExpired(['adb','am','start'],10))
            device.wait=lambda *_args,**_kwargs: None; device.save=lambda name,value: (out/name).write_text(value) or value
            readers=[]
            def launch(*_args,**kwargs):
                reader=StalledReader(kwargs['stdout']); readers.append(reader); return reader
            with patch.object(s312.subprocess,'Popen',side_effect=launch):
                with self.assertRaises(subprocess.TimeoutExpired): device.stop('timeout')
            self.assertIs(device.reader,readers[0])
            settlement=json.loads((out/'timeout-stop-reader-settlement.json').read_text())
            self.assertEqual(settlement['status'],'HOLD'); self.assertEqual(settlement['remote_completion'],'unknown')

    def test_identity_capture_failure_keeps_pending_wire_obligation(self):
        with tempfile.TemporaryDirectory() as temporary:
            device=s315.Device.__new__(s315.Device); device.out=Path(temporary)
            device.args=types.SimpleNamespace(cc='cc',endpoint4='192.168.4.5',endpoint6='fd76:d462:c4e3::1',stale6='fd76:d462:c4e3::dead:beef')
            device.witnesses={}
            def save(name,value):
                (device.out/name).write_text(value)
                return value
            device.save=save
            device.adb=lambda *args,**_: 'hash' if 'sha256sum' in args else ''
            calls=[]
            def root(command):
                calls.append(command)
                if len(calls)==1:return '77\n'
                raise subprocess.TimeoutExpired(['adb','identity'],5)
            device.root=root
            with patch.object(s315.subprocess,'run'),patch.object(s315,'digest',return_value='hash'):
                with self.assertRaises(subprocess.TimeoutExpired): device.wire_start()
            pending=device.witnesses['wlan0']
            self.assertEqual(pending['pid'],77)
            self.assertIsNone(pending['start'])

    def test_lost_wire_launch_ack_keeps_pre_pid_obligation(self):
        with tempfile.TemporaryDirectory() as temporary:
            device=s315.Device.__new__(s315.Device); device.out=Path(temporary)
            device.args=types.SimpleNamespace(cc='cc',endpoint4='192.168.4.5',endpoint6='fd76:d462:c4e3::1',stale6='fd76:d462:c4e3::dead:beef')
            device.witnesses={}
            device.save=lambda name,value: ((device.out/name).write_text(value),value)[1]
            device.adb=lambda *args,**_: 'hash' if 'sha256sum' in args else ''
            device.root=lambda _: (_ for _ in ()).throw(subprocess.TimeoutExpired(['adb','wire-launch'],5))
            with patch.object(s315.subprocess,'run'),patch.object(s315,'digest',return_value='hash'):
                with self.assertRaises(subprocess.TimeoutExpired): device.wire_start()
            pending=device.witnesses['wlan0']
            self.assertTrue(pending['launch_pending'])
            self.assertIsNone(pending['pid'])

    def test_unresolved_wire_launch_gets_only_cooperative_marker(self):
        device=s315.Device.__new__(s315.Device); device.capture_deadline=10**9
        device.witnesses={'wlan0':dict(pid=None,start=None,uid=None,exe=None,stop='/tmp/owned.stop',log='/tmp/owned.log',launch_pending=True)}
        calls=[]; device.adb=lambda *args,**_: calls.append(args) or ''
        with self.assertRaises(BaseExceptionGroup): device.wire_stop()
        self.assertEqual(calls,[('shell','touch','/tmp/owned.stop')])
        self.assertIn('wlan0',device.witnesses)

    def test_timed_trace_stop_is_collected_and_read_before_retry_is_decided(self):
        class Trace:
            def __init__(self):
                self.items=[dict(original_argv=['shell','am','start','-n','pkg','--ez','runtimeStop','true'])]
            def collect(self,item,*_):
                self.collected=item
                item['witness']=dict(gaps=[],exit_code=0)
        with tempfile.TemporaryDirectory() as temporary:
            device=s315.Device.__new__(s315.Device); device.out=Path(temporary); device.capture_deadline=0; device.generation=2708
            device.adb_trace=Trace(); device.app=lambda path: ('state=stopped\nmayBeActive=false\ngeneration=2708\n'if path.endswith('snapshot.properties')else'generation=2708\n')
            device.root=lambda command: ''
            def save(name,value):
                (device.out/name).write_text(value)
                return value
            device.save=save
            self.assertTrue(device.reconcile_stop_timeout('timeout'))
            self.assertIs(device.adb_trace.collected,device.adb_trace.items[0])
            self.assertFalse(device.active); self.assertFalse(device.stop_retry_owed)
            receipt=json.loads((device.out/'timeout-stop-timeout-reconciliation.json').read_text())
            self.assertEqual(receipt['status'],'STOPPED_CONFIRMED')

    def test_unreconciled_timed_stop_fences_finally_from_replay(self):
        device=s315.Device.__new__(s315.Device); device.active=True; device.stop_owed=True
        device.qualified_stop=lambda _: (_ for _ in ()).throw(subprocess.TimeoutExpired(['adb','stop'],10))
        device.reconcile_stop_timeout=lambda _: (_ for _ in ()).throw(AssertionError('missing witness'))
        with self.assertRaises(subprocess.TimeoutExpired): device.stop('stop')
        self.assertTrue(device.active); self.assertTrue(device.stop_owed); self.assertFalse(device.stop_retry_authorized)

    def test_grouped_real_stop_timeout_reaches_reconciliation(self):
        device=s315.Device.__new__(s315.Device); device.active=True; device.stop_owed=True
        timeout=subprocess.TimeoutExpired(['adb','stop'],10)
        device.qualified_stop=lambda _: (_ for _ in ()).throw(ExceptionGroup('stop',[timeout]))
        calls=[]
        def reconcile(label):
            calls.append(label); device.stop_retry_owed=False; device.stop_retry_authorized=False; device.active=False
        device.reconcile_stop_timeout=reconcile
        with self.assertRaises(ExceptionGroup): device.stop('stop')
        self.assertEqual(calls,['stop']); self.assertFalse(device.stop_owed)

    def test_actual_s315_s313_s312_grouped_stop_path_reconciles_once(self):
        class Trace:
            def __init__(self): self.items=[dict(original_argv=['shell','am','start','-n','pkg','--ez','runtimeStop','true'])]
            @staticmethod
            def handles(_): return False
            def collect(self,item,*_): self.collected=item; item['witness']=dict(gaps=[],exit_code=0)
        with tempfile.TemporaryDirectory() as temporary:
            out=Path(temporary); device=s315.Device.__new__(s315.Device)
            device.out=out; device.profile='root'; device.owners=1; device.active=True; device.stop_owed=True
            device.reader=None; device.capture_deadline=10**9; device.generation=2708; device.adb_trace=Trace()
            device.app=lambda path: ('state=stopped\nmayBeActive=false\ngeneration=2708\n' if path.endswith('snapshot.properties') else 'generation=2708\n')
            device.root=lambda command: ''
            device.save=lambda name,value: ((out/name).write_text(value),value)[1]
            device.action=lambda *_: (_ for _ in ()).throw(subprocess.TimeoutExpired(['adb','stop'],10))
            device.wait=lambda *_args,**_kwargs: None
            reader=[]
            def launch(*_args,**kwargs):
                value=Reader(kwargs['stdout']); reader.append(value); return value
            with patch.object(s315.tcp.support.subprocess,'Popen',side_effect=launch):
                with self.assertRaises(ExceptionGroup): device.stop('actual')
            self.assertIs(device.adb_trace.collected,device.adb_trace.items[0])
            self.assertFalse(device.active); self.assertFalse(device.stop_owed)
            self.assertFalse(reader[0].terminated)

    def test_running_stop_reconciliation_rejects_a_stale_generation(self):
        class Trace:
            def __init__(self): self.items=[dict(original_argv=['shell','am','start','-n','pkg','--ez','runtimeStop','true'])]
            def collect(self,item,*_): item['witness']=dict(gaps=[],exit_code=0)
        with tempfile.TemporaryDirectory() as temporary:
            device=s315.Device.__new__(s315.Device); device.out=Path(temporary); device.capture_deadline=0; device.generation=2708
            device.adb_trace=Trace(); device.app=lambda _: 'state=running\nmayBeActive=true\ngeneration=2707\n'; device.root=lambda command: ''
            device.save=lambda name,value: ((device.out/name).write_text(value),value)[1]
            with self.assertRaisesRegex(AssertionError,'validated terminal/runtime state'):
                device.reconcile_stop_timeout('stale')

    def test_failure_cleanup_gets_a_fresh_bounded_deadline(self):
        device=s315.Device.__new__(s315.Device); device.capture_deadline=0
        with patch.object(s315.time,'monotonic',return_value=100):
            with device.cleanup_budget(): self.assertEqual(device.capture_deadline,145)
        self.assertEqual(device.capture_deadline,0)

    def test_untraced_device_rejects_short_budget_before_external_spawn(self):
        with tempfile.TemporaryDirectory() as temporary:
            out=Path(temporary); (out/'dev').mkdir(); calls=out/'calls'
            adb=out/'dev/adb'; adb.write_text('#!/bin/sh\nprintf called >> "'+str(calls)+'"\n')
            adb.chmod(0o755)
            device=s313.Device.__new__(s313.Device); device.out=out; device.adb_trace=None
            device.capture_deadline=time.monotonic()+.068
            with patch.object(s313,'ROOT',out):
                with self.assertRaises(TimeoutError): device.adb('exec-out','cat','owned-file')
            self.assertFalse(calls.exists())

    def test_peer_short_lived_transport_retains_timeout_and_reaps_local_client(self):
        with tempfile.TemporaryDirectory() as temporary:
            peer=s312.Peer.__new__(s312.Peer);peer.out=Path(temporary);peer.deadline=time.monotonic()+1.1
            marker=peer.out/'started'
            command=[sys.executable,'-c',"from pathlib import Path;import time;Path("+repr(str(marker))+").touch();time.sleep(10)"]
            with self.assertRaises(subprocess.TimeoutExpired):peer.external(command,maximum=2,cwd=None)
            self.assertTrue(marker.exists())
            row=json.loads((peer.out/'operations.jsonl').read_text().splitlines()[-1])
            self.assertEqual(row['outcome'],'timeout');self.assertTrue(row['local_reaped'])
            self.assertNotIn('local_cleanup_error',row)

    def test_peer_expiry_is_checked_before_winpath_or_launcher(self):
        for module in (s312,s313):
            with self.subTest(module=module.__name__),tempfile.TemporaryDirectory() as temporary:
                with patch.object(module if module is s312 else module.support,'winpath',side_effect=RuntimeError('external winpath launched')):
                    with self.assertRaises(TimeoutError): module.Peer(['127.0.0.1'],Path(temporary),deadline=time.monotonic()+.068)

    def test_positive_expired_case_deadline_does_not_block_cleanup(self):
        device=s315.Device.__new__(s315.Device); device.capture_deadline=90
        with patch.object(s315.time,'monotonic',return_value=100):
            with device.cleanup_budget(): self.assertEqual(device.capture_deadline,145)
        self.assertEqual(device.capture_deadline,90)

    def test_nested_cleanup_honors_the_reserved_phase_deadline(self):
        device=s315.Device.__new__(s315.Device); device.capture_deadline=90
        envelope=s315.CleanupEnvelope(65,[('stop',25),('wire',20),('trace',20)])
        with patch.object(s315.time,'monotonic',return_value=100):
            envelope.end=165
            with envelope.phase(device,'stop'):
                with device.cleanup_budget(45): self.assertEqual(device.capture_deadline,125)
        self.assertEqual(device.capture_deadline,90)

    def test_cleanup_envelope_preserves_later_wire_reservation(self):
        device=types.SimpleNamespace(capture_deadline=0)
        envelope=s315.CleanupEnvelope(65,[('stop',25),('reader',5),('wire',20),('peer',10),('trace',5)])
        clock=iter((0,0,0,25,25))
        with patch.object(s315.time,'monotonic',side_effect=lambda:next(clock)):
            with envelope.phase(device,'stop') as stop: self.assertEqual(stop,25)
            with envelope.phase(device,'wire') as wire: self.assertEqual(wire,45)
        self.assertEqual(device.capture_deadline,0)

    def test_s312_wait_narrows_nested_capture_deadline(self):
        device=s312.Device.__new__(s312.Device); device.capture_deadline=100
        observed=[]
        device.app=lambda _: observed.append(device.capture_deadline) or 'ready=1\n'
        device.save=lambda _name,value:value
        clock=iter((10,10,10,10))
        with patch.object(s312.time,'monotonic',side_effect=lambda:next(clock)):
            self.assertEqual(device.wait('ready','state',lambda value:value.get('ready')=='1',timeout=30),{'ready':'1'})
        self.assertEqual(observed,[40]); self.assertEqual(device.capture_deadline,100)

    def test_s315_rule_query_has_one_bounded_control_scope(self):
        device=s315.Device.__new__(s315.Device); device.capture_deadline=100
        observed=[]
        device.app=lambda _: observed.append(('read',device.capture_deadline)) or 'queryElapsedMillis=1\n'
        device.foreground_ui=lambda _: observed.append(('foreground',device.capture_deadline))
        device.tap=lambda *_: observed.append(('tap',device.capture_deadline))
        device.wait=lambda *_args,**kwargs: observed.append(('wait',device.capture_deadline,kwargs['timeout'])) or {'queryElapsedMillis':'2'}
        device.valid_config=lambda _: None
        with patch.object(s315.time,'monotonic',return_value=10):
            self.assertEqual(device.query_rules('rules'),{'queryElapsedMillis':'2'})
        self.assertEqual(observed,[('read',70),('foreground',70),('tap',70),('wait',70,60)])
        self.assertEqual(device.capture_deadline,100)

    def delayed_peer_acquisition(self, initial_delay, capture_deadline):
        device=s315.Device.__new__(s315.Device);device.capture_deadline=capture_deadline
        clock=types.SimpleNamespace(now=0.0);saved={}
        device.save=lambda name,value:saved.setdefault(name,value)
        peer=types.SimpleNamespace(received=lambda *_args,**_kwargs:
            [{'request':17}]if clock.now>=3 else[])
        def sleep(seconds):clock.now+=seconds
        with patch.object(s315.time,'monotonic',side_effect=lambda:clock.now),patch.object(s315.time,'sleep',side_effect=sleep):
            try:rows=device.await_peer_query(peer,'delayed',b'query',initial_delay=initial_delay)
            except AssertionError as error:rows=error
        return rows,clock.now,json.loads(saved['delayed-peer-acquisition.json'])

    def test_peer_acquisition_reaches_a_deliberately_delayed_first_datagram(self):
        rows,elapsed,receipt=self.delayed_peer_acquisition(3000,100)
        self.assertEqual(rows,[{'request':17}]);self.assertGreaterEqual(elapsed,3)
        self.assertLess(elapsed,5);self.assertEqual(receipt['status'],'PASS')

    def test_undeclared_pre_send_delay_reproduces_the_original_acquisition_failure(self):
        error,elapsed,receipt=self.delayed_peer_acquisition(0,100)
        self.assertIsInstance(error,AssertionError);self.assertAlmostEqual(elapsed,2)
        self.assertEqual(receipt['status'],'HOLD')

    def test_matrix_deadline_clips_delayed_peer_acquisition(self):
        error,elapsed,receipt=self.delayed_peer_acquisition(3000,2.5)
        self.assertIsInstance(error,AssertionError);self.assertAlmostEqual(elapsed,2.5)
        self.assertEqual(receipt['status'],'HOLD');self.assertEqual(receipt['deadline_monotonic'],2.5)

    def test_s313_observation_narrows_nested_capture_deadline(self):
        with tempfile.TemporaryDirectory() as temporary:
            out=Path(temporary); device=s313.Device.__new__(s313.Device); device.out=out; device.capture_deadline=100
            observed=[]
            def observation(label):
                observed.append(device.capture_deadline)
                (out/(label+'-observation.json')).write_text('{}')
                return dict(ready=True)
            device.observation=observation; device.save=lambda name,value: ((out/name).write_text(value),value)[1]
            clock=iter((10,10))
            with patch.object(s313.time,'monotonic',side_effect=lambda:next(clock)):
                self.assertEqual(device.observation_matching('obs',lambda value:value['ready'],timeout=5),dict(ready=True))
            self.assertEqual(observed,[15]); self.assertEqual(device.capture_deadline,100)

    def test_orchestrator_retains_hold_and_settles_after_expired_case_deadline(self):
        class Device:
            instance=None
            def __init__(self,args):
                self.args=args; self.capture_deadline=0; self.active=False; self.stop_owed=False
                self.witnesses={'wire':object()}; self.adb_trace=object(); Device.instance=self
            @contextmanager
            def cleanup_budget(self,seconds=45):
                self.scopes=getattr(self,'scopes',[])+[seconds]
                with REAL_CLEANUP_BUDGET(self,seconds): yield
            def install(self): return {}
            def wire_start(self): pass
            def start(self,owners):
                self.active=True; self.stop_owed=True; self.owners=owners
                return dict(owners=owners,generation=2708,profile='root')
            def stop(self,_):
                self.stop_deadline=self.capture_deadline; self.active=False; self.stop_owed=False
                return dict(stopped=True)
            def wire_stop(self): self.wire_deadline=self.capture_deadline; self.witnesses={}
            def close_trace(self): self.trace_closed=True
        class Peer:
            instance=None
            def __init__(self,*_): Peer.instance=self
            def close(self): self.closed=True
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); apk=root/'test.apk'; apk.write_bytes(b'apk')
            stage=root/'stage'; stage.mkdir(); (stage/'product-stage.properties').write_text('stage=ok\n')
            backup=root/'backup'; backup.mkdir()
            (backup/'manifest.json').write_text(json.dumps(dict(status='PASS',state='stopped',serial=s315.SERIAL,generation=2697)))
            (backup/'runtime.properties').write_text('generation=2697\n')
            (backup/'generation.properties').write_text('generation=2697\n')
            output=root/'output'
            argv=['s315-root-dns-proxy.py','--apk',str(apk),'--stage',str(stage),'--backup',str(backup),
                '--output',str(output),'--endpoint4','192.168.4.5','--endpoint6','fd76:d462:c4e3::1',
                '--owners','1','--trace']
            def expired(device,*_):
                device.capture_deadline=0
                raise subprocess.TimeoutExpired(['adb','control'],10)
            with patch.object(s315,'Device',Device),patch.object(s315,'Peer',Peer),\
                 patch.object(s315,'matrix',expired),patch.object(sys,'argv',argv):
                with self.assertRaises(SystemExit) as exited: s315.main()
            self.assertEqual(exited.exception.code,1)
            result=json.loads((output/'result.json').read_text())
            self.assertEqual(result['status'],'HOLD')
            self.assertEqual(result['trace'],dict(requested=True,active=True))
            self.assertGreater(Device.instance.stop_deadline,0)
            self.assertGreater(Device.instance.wire_deadline,0)
            self.assertFalse(Device.instance.witnesses)
            self.assertTrue(Device.instance.trace_closed)
            self.assertTrue(Peer.instance.closed)

    def test_s315_main_turns_trace_close_failure_into_hold(self):
        class Device:
            def __init__(self,args):
                self.args=args; self.capture_deadline=10**9; self.active=False; self.stop_owed=False
                self.witnesses={}; self.adb_trace=object()
            def install(self): return {}
            def wire_start(self): pass
            def start(self,owners): self.active=True; self.owners=owners; return dict(owners=owners,generation=2708,profile='root')
            def durable(self,_): return {}
            def stop(self,_): self.active=False; self.stop_owed=False; return {}
            def durable_readback(self,_): return {}
            def wire_stop(self): self.witnesses={}
            def close_trace(self): raise RuntimeError('trace close hold')
        class Peer:
            def __init__(self,*_): pass
            def close(self): pass
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); apk=root/'test.apk'; apk.write_bytes(b'apk')
            stage=root/'stage'; stage.mkdir(); (stage/'product-stage.properties').write_text('stage=ok\n')
            backup=root/'backup'; backup.mkdir()
            (backup/'manifest.json').write_text(json.dumps(dict(status='PASS',state='stopped',serial=s315.SERIAL,generation=2697)))
            (backup/'runtime.properties').write_text('generation=2697\n'); (backup/'generation.properties').write_text('generation=2697\n')
            output=root/'output'
            argv=['s315-root-dns-proxy.py','--apk',str(apk),'--stage',str(stage),'--backup',str(backup),'--output',str(output),
                '--endpoint4','192.168.4.5','--endpoint6','fd76:d462:c4e3::1','--owners','1','--matrix','smoke','--trace']
            with patch.object(s315,'Device',Device),patch.object(s315,'Peer',Peer),patch.object(s315,'smoke',lambda *_:None),patch.object(sys,'argv',argv):
                with self.assertRaises(SystemExit) as exited: s315.main()
            self.assertEqual(exited.exception.code,1)
            result=json.loads((output/'result.json').read_text())
            self.assertEqual(result['status'],'HOLD')
            self.assertIn('trace close hold',result['cleanup_errors'][0])

    def test_s315_main_persists_hold_after_expired_stop_phase_entry(self):
        class Device:
            instance=None
            def __init__(self,args):
                self.args=args; self.capture_deadline=10**9; self.active=False; self.stop_owed=False; self.witnesses={}; self.adb_trace=object(); Device.instance=self
            def install(self): return {}
            def wire_start(self): pass
            def start(self,owners): self.active=True; self.stop_owed=True; self.owners=owners; return dict(owners=owners,generation=2708,profile='root')
            def close_trace(self): self.trace_closed=True
        class Peer:
            def __init__(self,*_): pass
            def close(self): pass
        class Envelope:
            def __init__(self,*_): pass
            @contextmanager
            def phase(self,_device,name):
                if name=='stop': raise TimeoutError('expired stop phase')
                yield 10**9
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); apk=root/'test.apk'; apk.write_bytes(b'apk')
            stage=root/'stage'; stage.mkdir(); (stage/'product-stage.properties').write_text('stage=ok\n')
            backup=root/'backup'; backup.mkdir()
            (backup/'manifest.json').write_text(json.dumps(dict(status='PASS',state='stopped',serial=s315.SERIAL,generation=2697)))
            (backup/'runtime.properties').write_text('generation=2697\n'); (backup/'generation.properties').write_text('generation=2697\n')
            output=root/'output'; argv=['s315-root-dns-proxy.py','--apk',str(apk),'--stage',str(stage),'--backup',str(backup),'--output',str(output),'--endpoint4','192.168.4.5','--endpoint6','fd76:d462:c4e3::1','--owners','1','--matrix','smoke','--trace']
            with patch.object(s315,'Device',Device),patch.object(s315,'Peer',Peer),patch.object(s315,'CleanupEnvelope',Envelope),patch.object(s315,'smoke',side_effect=RuntimeError('primary failure')),patch.object(sys,'argv',argv):
                with self.assertRaises(SystemExit): s315.main()
            result=json.loads((output/'result.json').read_text())
            self.assertEqual(result['status'],'HOLD')
            self.assertIn('primary failure',result['error'])
            self.assertIn('expired stop phase',result['cleanup_errors'][0])
            self.assertTrue(Device.instance.trace_closed)

    def test_peer_close_uses_its_absolute_phase_deadline(self):
        class Process:
            returncode=0
            def wait(self, timeout): self.timeout=timeout
        class Thread:
            def join(self, timeout): self.timeout=timeout
        with tempfile.TemporaryDirectory() as temporary:
            peer=s312.Peer.__new__(s312.Peer); peer.deadline=0; peer.cleanup_deadline=15; peer.stop_path=Path(temporary)/'peer.stop'
            peer.process=Process(); peer.thread=Thread(); peer.messages=[dict(kind='stopped')]
            with patch.object(s312.time,'monotonic',return_value=10): peer.close()
            self.assertEqual(peer.process.timeout,5)
            self.assertEqual(peer.thread.timeout,2)

    def test_peer_constructor_cleanup_failure_retains_unassigned_actor_receipt(self):
        class Process:
            pid=91; stdout=[]
            def poll(self): return None
            def wait(self, timeout): raise subprocess.TimeoutExpired(['peer'],timeout)
        class Thread:
            def __init__(self,*_,**__): pass
            def start(self): pass
            def is_alive(self): return True
            def join(self, timeout): pass
        with tempfile.TemporaryDirectory() as temporary:
            out=Path(temporary); clock=iter([0]*6+[12]*12)
            with (patch.object(s313.support,'winpath',side_effect=lambda value,**_:str(value)),
                  patch.object(s313.subprocess,'Popen',return_value=Process()),
                  patch.object(s313.threading,'Thread',Thread),
                  patch.object(s313.Peer,'cleanup_failed_start',side_effect=RuntimeError('cleanup exhausted')),
                  patch.object(s313.time,'monotonic',side_effect=lambda:next(clock))):
                with self.assertRaisesRegex(TimeoutError,'peer lifecycle budget exhausted'): s313.Peer(['127.0.0.1'],out,deadline=12)
            receipt=json.loads((out/'peer-failed-0-unresolved.json').read_text())
            self.assertEqual(receipt['local_pid'],91)
            self.assertTrue(receipt['reader_alive'])
            self.assertIn('cleanup exhausted',receipt['cleanup_error'])

if __name__ == '__main__': unittest.main()
