#!/usr/bin/env python3
"""Retire only persisted test exports and share complete capture files."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


trace = load('capture_trace', 'tests/device/helpers/s314_adb_trace.py')
device = load('capture_device', 'tests/device/s312-dns-response.py')


class CaptureTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.output = Path(self.temporary.name)
        self.recorder = trace.AdbTrace(self.output, [sys.executable])

    def tearDown(self):
        self.temporary.cleanup()

    def test_trace_and_business_output_share_one_immutable_file(self):
        command = ['-c', 'print("complete observation")']
        raw, _, _, record = self.recorder.execute(command, command, 5)
        capture = self.output / 'observation.json'
        self.recorder.save_capture(capture, raw)
        self.assertTrue(os.path.samefile(capture, self.output / record['stdout_path']))
        self.recorder.save_capture(capture, b'next observation')
        self.assertEqual((self.output / record['stdout_path']).read_bytes(), raw)
        self.assertEqual(capture.read_bytes(), b'next observation')

    def subject(self):
        value = object.__new__(device.Device)
        value.out = self.output
        value.local_adb_recorder = self.recorder
        value.action = Mock(return_value='requested')
        value.adb = Mock(return_value='')
        return value

    def test_success_retires_exact_nonce_after_local_save(self):
        value = self.subject()
        result = {'consumer': {'query_fresh': True}}
        value.app = Mock(return_value=json.dumps(result))
        def retire(*args):
            self.assertEqual(json.loads((self.output / 'case-observation.json').read_text()), result)
            self.assertEqual(args, ('shell', 'run-as', device.PKG, 'rm', '--',
                                   'files/product-state/observation-s312-123.json'))
            return ''
        value.adb.side_effect = retire
        with patch.object(device.time, 'time_ns', return_value=123):
            self.assertEqual(value.observation('case'), result)
        value.adb.assert_called_once()

    def test_failed_read_retains_remote_export(self):
        value = self.subject()
        value.wait = Mock(side_effect=RuntimeError('incomplete response'))
        with self.assertRaises(RuntimeError):
            value.observation('case')
        value.adb.assert_not_called()

    def test_failed_local_write_retains_remote_export(self):
        value = self.subject()
        value.app = Mock(return_value=json.dumps({'consumer': {'query_fresh': True}}))
        save = value.save
        def save_result(name, content):
            if name.endswith('-observation.json'):
                raise OSError('disk full')
            return save(name, content)
        value.save = save_result
        with self.assertRaises(OSError):
            value.observation('case')
        value.adb.assert_not_called()


if __name__ == '__main__':
    unittest.main()
