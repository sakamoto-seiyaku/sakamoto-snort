#!/usr/bin/env python3
"""Exercise the shared Root/VPN stop path with owned real reader processes."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


root = load('s320_stop_root', ROOT/'tests/device/s315-root-dns-proxy.py')
vpn = load('s320_stop_vpn', ROOT/'tests/device/s316-vpn-dns-proxy.py')


class Controller:
    def __init__(self, out, profile):
        self.out, self.profile = Path(out), profile
        self.reader = None
        self.active, self.stop_owed = True, True
        self.generation, self.owners = 123, 1
        self.stop_actions = 0
        self.signal = self.out/'stop-signal'

    def app(self, path): return 'prior log\n'
    def budget_timeout(self, seconds): return min(seconds, 2)
    def root(self, command): return ''
    def save(self, name, value):
        (self.out/name).write_text(value)
        return value
    def action(self, *args):
        assert args == ('--ez', 'runtimeStop', 'true')
        self.stop_actions += 1
        self.signal.touch()
        return 'stop requested'
    def wait(self, label, path, predicate, **kwargs):
        value = {'state': 'stopped', 'mayBeActive': 'false'}
        assert predicate(value)
        return value


class RootController(Controller, root.Device): pass
class VpnController(Controller, vpn.Device): pass


STOP_ROWS = '''dns event=stop generation=123 owner=0 requests=0 codec_live_bytes=0 active_operations=0 tcp_active=0 tcp_owned_bytes=0
dns.proxy event=stop generation=123 owner=0 transactions=0 upstream_sockets=0 raw_sockets=0 replies=0 raw_opened=2 raw_closed=2
s242 event=stop_native_zero generation=123 ready_mask=0 graph_enabled=0 graph_accepting=0 pending=0 buffers=0 obligations=0 handoffs=0 completion_frames=0
s213 event=stop generation=123 pending=0 buffers=0 frames=0 obligations=0 tun_fd=-1
s237 event=owner_stopped generation=123 owner=0 sessions=0 inputs=0 pbufs=0 sockets_created=0 sockets_closed=0 timer_fd=-1 broker_fd=-1 buffers=0 obligations=0 frames=0
'''


class StopCaptureLifecycle(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.original_popen = subprocess.Popen
        self.children = []

        def spawn_owned_reader(argv, *, stdout, stderr):
            self.assertIn('tail', argv)
            code = ('import pathlib,sys,time\n'
                    'print("capture opened",flush=True)\n'
                    'while not pathlib.Path(sys.argv[1]).exists(): time.sleep(.01)\n'
                    'print(sys.argv[2],end="",flush=True)\n')
            process = self.original_popen([sys.executable, '-u', '-c', code,
                                          str(self.controller.signal), STOP_ROWS],
                                         stdout=stdout, stderr=stderr)
            self.children.append(process)
            return process

        self.patcher = patch.object(subprocess, 'Popen', side_effect=spawn_owned_reader)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.addCleanup(self.reap)

    def reap(self):
        for child in self.children:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=3)
        capture = getattr(getattr(self, 'controller', None), 'prepared_stop_capture', None)
        if capture:
            capture['log'].close()
            capture['errors'].close()

    def controller_for(self, cls, profile):
        self.controller = cls(self.directory.name, profile)
        return self.controller

    def wait_capture_open(self, d):
        deadline = time.monotonic()+2
        while time.monotonic() < deadline:
            if (d.out/'pending-stop.log').stat().st_size: return
            time.sleep(.01)
        self.fail('owned reader did not open its log')

    def test_prepared_capture_survives_root_and_vpn_stop(self):
        for cls, profile in ((RootController, 'root'), (VpnController, 'vpn')):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory(dir=self.directory.name) as out:
                self.controller = cls(out, profile)
                d = self.controller
                d.prepare_stop_capture('pending')
                self.wait_capture_open(d)
                reader = d.reader
                result = d.stop('pending')
                self.assertEqual(d.stop_actions, 1)
                self.assertEqual(reader.returncode, 0)
                self.assertIsNone(d.reader)
                self.assertTrue(result['process_absent'])
                self.assertIn('dns.proxy event=stop', (d.out/'pending-stop.log').read_text())
                settlement = json.loads((d.out/'pending-stop-reader-settlement.json').read_text())
                self.assertTrue(settlement['local_reader_started'])
                self.assertFalse((d.out/'pending-previous-reader.json').exists())

    def test_unprepared_previous_reader_is_reaped_before_new_stop(self):
        d = self.controller_for(RootController, 'root')
        old = self.original_popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        self.children.append(old)
        d.reader = old
        d.stop('normal')
        self.assertIsNotNone(old.returncode)
        self.assertEqual(d.stop_actions, 1)
        self.assertEqual(json.loads((d.out/'normal-previous-reader.json').read_text())['pid'], old.pid)
        self.assertIn('dns.proxy event=stop', (d.out/'normal-stop.log').read_text())

    def test_mismatched_prepared_reader_rejects_stop_before_action(self):
        for cls, profile in ((RootController, 'root'), (VpnController, 'vpn')):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory(dir=self.directory.name) as out:
                self.controller = cls(out, profile)
                d = self.controller
                d.prepare_stop_capture('pending')
                self.wait_capture_open(d)
                original = d.reader
                capture = d.prepared_stop_capture
                other = self.original_popen([sys.executable, '-c', 'import time; time.sleep(30)'])
                self.children.append(other)
                d.reader = other
                with self.assertRaises(Exception): d.stop('pending')
                self.assertEqual(d.stop_actions, 0)
                self.assertIsNone(original.poll())
                self.assertIsNone(other.poll())
                with self.assertRaises(RuntimeError): d.settle_reader('cleanup')
                self.assertIsNotNone(original.returncode)
                self.assertIsNone(other.poll())
                self.assertIs(d.reader, other)
                self.assertIsNone(d.prepared_stop_capture)
                self.assertTrue(capture['log'].closed and capture['errors'].closed)
                receipt = json.loads((d.out/'cleanup-reader-settlement.json').read_text())
                self.assertEqual(receipt['status'], 'HOLD')
                self.assertEqual(receipt['pid'], original.pid)

    def test_expired_prepared_reader_rejects_stop_and_is_settled(self):
        for cls, profile in ((RootController, 'root'), (VpnController, 'vpn')):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory(dir=self.directory.name) as out:
                self.controller = cls(out, profile)
                d = self.controller
                d.prepare_stop_capture('pending')
                self.wait_capture_open(d)
                capture = d.prepared_stop_capture
                d.reader.terminate()
                d.reader.wait(timeout=3)
                with self.assertRaises(Exception): d.stop('pending')
                self.assertEqual(d.stop_actions, 0)
                self.assertIsNone(d.reader)
                self.assertIsNone(d.prepared_stop_capture)
                self.assertTrue(capture['log'].closed and capture['errors'].closed)
                self.assertTrue(d.stop_retry_authorized and d.active and d.stop_owed)
                d.stop('failure-cleanup')
                self.assertEqual(d.stop_actions, 1)
                self.assertFalse(d.active or d.stop_owed)

    def test_missing_current_reader_still_reaps_owned_capture_without_stop(self):
        d = self.controller_for(RootController, 'root')
        d.prepare_stop_capture('pending')
        self.wait_capture_open(d)
        capture = d.prepared_stop_capture
        original = d.reader
        d.reader = None
        with self.assertRaises(Exception): d.stop('pending')
        self.assertEqual(d.stop_actions, 0)
        with self.assertRaises(RuntimeError): d.settle_reader('cleanup')
        self.assertIsNotNone(original.returncode)
        self.assertIsNone(d.prepared_stop_capture)
        self.assertTrue(capture['log'].closed and capture['errors'].closed)


if __name__ == '__main__': unittest.main()
