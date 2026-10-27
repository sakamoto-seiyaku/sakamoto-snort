#!/usr/bin/env python3
"""Replay captured stopped local TCP wire at the ordinary collector boundary."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('s318_stop_wire',ROOT/'tests/device/s318-vpn-dns-tcp-proxy.py')
driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
FIXTURE=json.loads((ROOT/'tests/host/fixtures/s318_tcp_stop_wire.json').read_text())
SHARED_FIXTURE=json.loads((ROOT/'tests/host/fixtures/s319_tcp_stop_shared_scope.json').read_text())

class StoppedLocalTcpWireTest(unittest.TestCase):
    def device(self):
        device=driver.Device.__new__(driver.Device)
        identity=dict(pid=1221,start=382645215,uid=0,exe='/data/local/tmp/s317-wire')
        device.witnesses={'wlan0':identity};device.save=lambda _name,value:value
        device.tcp_route_fences=[dict(label='captured-old-app',generation=2793,source=20000,resolver='1.1.1.1',
            baseline_rows=0,witness=identity,stop_boundary_rows=0,stopped_local=dict(
                source='10.111.0.2',source_port=20000,resolver='1.1.1.1',sequence=3100075100,acknowledgement=6511,
                pending_query_proved=True,native_original_tcp_fd_absent=True,normal_stop_resource_zero=True,
                app_finished_no_reply=True,normal_sqlite_query_stopped=True))]
        return device

    def test_exact_old_app_terminal_control_is_qualified_without_dns_escape(self):
        device=self.device()
        device.verify_tcp_route_fences(FIXTURE['wlan'])

    def test_ordinary_on_fence_still_rejects_the_same_control(self):
        device=self.device();fence=device.tcp_route_fences[0]
        del fence['stop_boundary_rows'];del fence['stopped_local']
        with self.assertRaises(AssertionError):device.verify_tcp_route_fences(FIXTURE['wlan'])

    def test_control_inside_the_strict_prefix_is_rejected(self):
        device=self.device();device.tcp_route_fences[0]['stop_boundary_rows']=1
        with self.assertRaises(AssertionError):device.verify_tcp_route_fences(FIXTURE['wlan'])

    def test_stopped_boundary_requires_each_independent_lifecycle_fact(self):
        for key in('pending_query_proved','native_original_tcp_fd_absent','normal_stop_resource_zero',
                   'app_finished_no_reply','normal_sqlite_query_stopped'):
            with self.subTest(key=key):
                device=self.device();device.tcp_route_fences[0]['stopped_local'][key]=False
                with self.assertRaises(AssertionError):device.verify_tcp_route_fences(FIXTURE['wlan'])

    def test_syn_data_wrong_identity_or_more_than_one_control_is_rejected(self):
        for change in('syn','fin','payload','source','port','sequence','acknowledgement','duplicate','incoming'):
            with self.subTest(change=change):
                rows=copy.deepcopy(FIXTURE['wlan']);row=rows[0];packet=bytearray.fromhex(row['packet_hex'])
                if change=='syn':row['flags']=packet[33]=2
                if change=='fin':row['flags']=packet[33]=17
                if change=='payload':row['payload_hex']='00';packet+=b'\0'
                if change=='source':row['source']='10.111.0.3';packet[12:16]=bytes([10,111,0,3])
                if change=='port':row['source_port']=20001;packet[20:22]=(20001).to_bytes(2,'big')
                if change=='sequence':row['sequence']+=1;packet[24:28]=row['sequence'].to_bytes(4,'big')
                if change=='acknowledgement':packet[28:32]=(6512).to_bytes(4,'big')
                if change=='incoming':row['packet_type']=0
                row['packet_hex']=packet.hex()
                if change=='duplicate':rows.append(copy.deepcopy(row))
                with self.assertRaises(AssertionError):self.device().verify_tcp_route_fences(rows)

    def test_wire_identity_comes_from_complete_old_query_and_handshake(self):
        identity=driver.stopped_tcp_identity(FIXTURE['tun'],20000,'1.1.1.1',bytes.fromhex(FIXTURE['query_hex']))
        self.assertEqual(identity,dict(source='10.111.0.2',source_port=20000,resolver='1.1.1.1',sequence=3100075100,acknowledgement=6511))
        with self.assertRaises(AssertionError):driver.stopped_tcp_identity(FIXTURE['tun'],20000,'1.1.1.1',b'different-query')

class PendingStopLifecycleTest(unittest.TestCase):
    def device(self,stop_error,cleanup_error=None):
        class Device:
            witnesses={'tun0':{}};tun_interface='tun0';durable_target=0
            def __init__(self):self.events=[]
            def wire_stop(self,interfaces,*,defer_files=False):
                self.events.append(('capture-complete',interfaces,defer_files))
            def stop(self,_label):
                self.events.append(('normal-stop',));raise stop_error
            def settle_deferred_wire_files(self):
                self.events.append(('retire-archived-files',))
                if cleanup_error:raise cleanup_error
        return Device()

    def test_stop_failure_still_retires_completed_capture_without_repeating_stop(self):
        primary=TimeoutError('normal Stop unknown');device=self.device(primary)
        with self.assertRaises(TimeoutError)as failure:driver.finish_run(device,{'runs':[{}]},'pending',pending=True)
        self.assertIs(failure.exception,primary)
        self.assertEqual(device.events,[('capture-complete',['tun0'],True),('normal-stop',),('retire-archived-files',)])

    def test_stop_and_retirement_failures_are_both_retained(self):
        primary=TimeoutError('normal Stop unknown');cleanup=RuntimeError('trace fences file retirement')
        device=self.device(primary,cleanup)
        with self.assertRaises(BaseExceptionGroup)as failure:driver.finish_run(device,{'runs':[{}]},'pending',pending=True)
        self.assertEqual(failure.exception.exceptions,(primary,cleanup))
        self.assertEqual([event[0]for event in device.events],['capture-complete','normal-stop','retire-archived-files'])

class SharedStopRouteScopeTest(unittest.TestCase):
    def device(self):
        device=driver.Device.__new__(driver.Device)
        device.physical_interface='wlan0'
        witness=dict(pid=7875,start=393422615,uid=0,exe='/data/local/tmp/s317-wire')
        device.witnesses={'wlan0':witness};device.save=lambda _name,value:value
        common=dict(generation=SHARED_FIXTURE['old_generation'],resolver='1.1.1.1',
                    baseline_rows=0,witness=witness)
        device.tcp_route_fences=[
            dict(common,label='before-stop-cache',source=SHARED_FIXTURE['prior_warm_source']),
            dict(common,label='pending-stop',source=20001,stop_boundary_rows=0,
                 stopped_local=copy.deepcopy(SHARED_FIXTURE['stopped_identity']))]
        return device

    def test_prior_global_fence_uses_same_proved_stop_interval(self):
        self.device().verify_tcp_route_fences(SHARED_FIXTURE['wlan'])

    def test_other_generation_witness_or_resolver_cannot_supply_stop_scope(self):
        for field in ('generation','witness','resolver'):
            with self.subTest(field=field):
                device=self.device();pending=device.tcp_route_fences[1]
                if field=='generation':pending[field]+=1
                elif field=='witness':pending[field]=dict(pending[field],start=1)
                else:pending[field]='1.0.0.1'
                with self.assertRaises(AssertionError):device.verify_tcp_route_fences(SHARED_FIXTURE['wlan'])

    def test_shared_scope_requires_every_independent_stopped_fact(self):
        for field in ('pending_query_proved','native_original_tcp_fd_absent','normal_stop_resource_zero',
                      'app_finished_no_reply','normal_sqlite_query_stopped'):
            with self.subTest(field=field):
                device=self.device();device.tcp_route_fences[1]['stopped_local'][field]=False
                with self.assertRaises(AssertionError):device.verify_tcp_route_fences(SHARED_FIXTURE['wlan'])

    def test_explicit_earlier_end_keeps_its_own_interval(self):
        device=self.device();device.tcp_route_fences[0]['end_rows']=0
        device.verify_tcp_route_fences(SHARED_FIXTURE['wlan'])

    def test_inherited_scope_keeps_global_resolver_and_exact_control_checks(self):
        for change in ('syn','fin','payload','source','port','sequence','acknowledgement','duplicate','incoming'):
            with self.subTest(change=change):
                rows=copy.deepcopy(SHARED_FIXTURE['wlan']);row=rows[0];packet=bytearray.fromhex(row['packet_hex'])
                if change=='syn':row['flags']=packet[33]=2
                if change=='fin':row['flags']=packet[33]=17
                if change=='payload':row['payload_hex']='00';packet+=b'\0'
                if change=='source':row['source']='10.111.0.3';packet[12:16]=bytes([10,111,0,3])
                if change=='port':row['source_port']=40009;packet[20:22]=(40009).to_bytes(2,'big')
                if change=='sequence':row['sequence']+=1;packet[24:28]=row['sequence'].to_bytes(4,'big')
                if change=='acknowledgement':packet[28:32]=(6512).to_bytes(4,'big')
                if change=='incoming':row['packet_type']=0
                row['packet_hex']=packet.hex()
                if change=='duplicate':rows.append(copy.deepcopy(row))
                with self.assertRaises(AssertionError):self.device().verify_tcp_route_fences(rows)

    def test_ambiguous_shared_stop_boundary_is_rejected(self):
        device=self.device();duplicate=copy.deepcopy(device.tcp_route_fences[1]);duplicate['label']='other-pending'
        duplicate['stopped_local']['acknowledgement']+=1;device.tcp_route_fences.append(duplicate)
        with self.assertRaisesRegex(AssertionError,'ambiguous shared Stop boundary'):
            device.verify_tcp_route_fences(SHARED_FIXTURE['wlan'])

    def test_actual_control_inside_shared_strict_prefix_still_fails(self):
        device=self.device();device.tcp_route_fences[1]['stop_boundary_rows']=1
        with self.assertRaises(AssertionError):device.verify_tcp_route_fences(SHARED_FIXTURE['wlan'])

if __name__=='__main__':unittest.main()
