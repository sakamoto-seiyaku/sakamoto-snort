#!/usr/bin/env python3
"""Small regressions for the actual S227 collector's parser/IO seams."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('collector', ROOT/'tests/device/s227-udp-expiry.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class CollectorTests(unittest.TestCase):
    def test_native_owner_field_preserved_for_fdinfo(self):
        campaign = object.__new__(collector.Campaign)
        saved = {}
        campaign.target = SimpleNamespace(run=lambda *args, **kwargs: SimpleNamespace(stdout='raw\n'))
        campaign.write = lambda record, name, value: saved.setdefault(name, value)
        campaign.cli = lambda *args: 'expiry.owner=0 timer_fd=19\nexpiry.owner=1 timer_fd=21\n'
        campaign.fds(dict(pid=123), 'initial')
        self.assertEqual(set(saved), {'initial-fds.txt', 'initial-fdinfo-0.txt', 'initial-fdinfo-1.txt'})

    def test_large_socket_preparation_has_a_separate_bound(self):
        clock = SimpleNamespace(value=0.0)
        clock.monotonic = lambda: clock.value
        clock.sleep = lambda seconds: setattr(clock, 'value', clock.value+seconds)
        campaign = object.__new__(collector.Campaign)
        campaign.target = SimpleNamespace(read=lambda path: 'stage phase=1 count=4\n' if clock.value >= 90 else '',
                                         alive=lambda pid: True)
        campaign.write = lambda *args: None
        record = dict(client_log='client', client_pid=1)
        with patch.object(collector, 'time', clock):
            campaign.wait_phase(record, 1, timeout=180)
        self.assertGreaterEqual(clock.value, 90)
        self.assertLess(clock.value, 91)

    def test_later_phase_keeps_its_shorter_bound(self):
        clock = SimpleNamespace(value=0.0)
        clock.monotonic = lambda: clock.value
        clock.sleep = lambda seconds: setattr(clock, 'value', clock.value+seconds)
        campaign = object.__new__(collector.Campaign)
        campaign.target = SimpleNamespace(read=lambda path: '', alive=lambda pid: True)
        campaign.write = lambda *args: None
        with patch.object(collector, 'time', clock):
            with self.assertRaisesRegex(RuntimeError, 'phase deadline'):
                campaign.wait_phase(dict(client_log='client', client_pid=1), 2)
        self.assertLess(clock.value, 76)


if __name__ == '__main__':
    unittest.main()
