#!/usr/bin/env python3
"""Keep foreground UI staging bounded after one slow diagnostic read."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s313_ui_budget', ROOT / 'tests/device/s313-root-dns-tcp.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ForegroundUiBudgetTest(unittest.TestCase):
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
