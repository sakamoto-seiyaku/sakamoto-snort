#!/usr/bin/env python3
"""Keep foreground UI staging bounded after one slow diagnostic read."""
import importlib.util
from pathlib import Path
import subprocess
import json
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s313_ui_budget', ROOT / 'tests/device/s313-root-dns-tcp.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ForegroundUiBudgetTest(unittest.TestCase):
    def capture_device(self,reply='ack',code=0):
        class Recorder:
            operation_deadline=None
            def __init__(self):self.commands=[];self.closed=[]
            def execute(self,command,wire_command,timeout,**_):
                self.commands.append((command,timeout))
                if 'uiautomator'in command:
                    value='UI hierchary dumped to: '+command[-1]if reply=='ack'else'ERROR: could not get idle state.'
                    return value.encode(),b'',code,{}
                if command[:2]==('exec-out','cat'):return b'<hierarchy/>',b'',0,{}
                return b'',b'',0,{}
            def close(self,budget):self.closed.append(budget)
        device=module.Device.__new__(module.Device)
        device.capture_deadline=1000;device.adb_trace=None;device.local_adb_recorder=Recorder()
        device.save=lambda *_:None
        return device

    def test_ui_capture_waits_with_margin_and_reads_only_acknowledged_owned_xml(self):
        device=self.capture_device()
        with patch.object(module.time,'monotonic',return_value=0),patch.object(module.time,'monotonic_ns',return_value=12345):
            device.adb('shell','uiautomator','dump','/sdcard/s312-ui.xml')
            self.assertEqual(device.adb('shell','cat','/sdcard/s312-ui.xml'),'<hierarchy/>')
        path='/data/local/tmp/s313-ui-12345.xml'
        commands=device.local_adb_recorder.commands
        self.assertEqual(commands[0][0],('shell','rm','-f',path))
        self.assertEqual(commands[1],(('shell','timeout','15','uiautomator','dump',path),17))
        self.assertEqual(commands[2][0],('exec-out','cat',path))

    def test_idle_error_with_zero_exit_cannot_read_an_older_xml(self):
        device=self.capture_device(reply='idle-error')
        with patch.object(module.time,'monotonic',return_value=0):
            with self.assertRaisesRegex(RuntimeError,'not acknowledged'):
                device.adb('shell','uiautomator','dump','/sdcard/s312-ui.xml')
            with self.assertRaisesRegex(AssertionError,'acknowledged fresh capture'):
                device.adb('shell','cat','/sdcard/s312-ui.xml')
        self.assertFalse(device.ui_capture_ready)
        self.assertEqual(len(device.local_adb_recorder.commands),2)

    def test_ui_helper_nonzero_exit_is_retained_without_dump_retry(self):
        device=self.capture_device(code=124)
        with patch.object(module.time,'monotonic',return_value=0):
            with self.assertRaises(RuntimeError):device.adb('shell','uiautomator','dump','/sdcard/s312-ui.xml')
        self.assertEqual(sum('uiautomator'in command for command,_ in device.local_adb_recorder.commands),1)
        self.assertFalse(device.ui_capture_ready)

    def test_insufficient_ui_budget_does_not_start_remote_capture(self):
        device=self.capture_device();device.capture_deadline=17
        with patch.object(module.time,'monotonic',return_value=0):
            with self.assertRaisesRegex(AssertionError,'insufficient remaining UI'):
                device.adb('shell','uiautomator','dump','/sdcard/s312-ui.xml')
        self.assertEqual(device.local_adb_recorder.commands,[])

    def test_trace_cleanup_retires_only_this_owned_xml(self):
        device=self.capture_device();device.ui_capture_path='/data/local/tmp/s313-ui-12345.xml';device.ui_capture_ready=True
        saved={};device.save=lambda name,value:saved.update({name:value})
        with patch.object(module.time,'monotonic',return_value=0):device.close_trace()
        self.assertEqual(device.local_adb_recorder.commands[0][0],('shell','rm','-f','/data/local/tmp/s313-ui-12345.xml'))
        self.assertIsNone(device.ui_capture_path);self.assertFalse(device.ui_capture_ready)
        self.assertEqual(json.loads(saved['ui-capture-cleanup.json'])['status'],'PASS_EXACT_OWNED_UI_XML_RETIRED')
        self.assertEqual(device.local_adb_recorder.closed,[30])

    def test_one_slow_state_read_leaves_room_for_the_existing_retry(self):
        device = module.Device.__new__(module.Device)
        device.capture_deadline = 1200
        device.save = lambda *_: None
        device.adb = lambda *_: ''
        device.action = lambda: ''
        deadlines = []

        def verify(_):
            deadlines.append(device.capture_deadline)
            if len(deadlines) == 1:
                raise subprocess.TimeoutExpired(['dumpsys', 'window', 'policy'], 10)

        device.verify_ui_state = verify
        clock = iter((0, 10, 10, 10))
        with patch.object(module.time, 'monotonic', side_effect=lambda: next(clock)), \
             patch.object(module.time, 'sleep'):
            device.foreground_ui('budget')

        self.assertEqual(deadlines, [30, 30])
        self.assertEqual(device.capture_deadline, 1200)


if __name__ == '__main__':
    unittest.main()
