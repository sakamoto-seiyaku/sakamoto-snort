#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('end_collector', ROOT/'tests/device/s225-flow-end.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class CleanupTests(unittest.TestCase):
    def test_native_is_stopped_even_when_end_counter_assertion_fails(self):
        campaign = object.__new__(collector.Campaign)
        with tempfile.TemporaryDirectory(prefix='s227-end-cleanup-') as temporary:
            campaign.args = SimpleNamespace(output=Path(temporary))
            (Path(temporary)/'generation-0').mkdir()
            stopped = []
            campaign.target = SimpleNamespace(alive=lambda pid: True, read=lambda path: 'native log',
                stop_process=lambda pid: stopped.append(pid) or True, queue_witness=lambda *args: None)
            campaign.remove_rules = lambda: None
            campaign.hooks = lambda: ''
            campaign.cli = lambda *args: 'root.stop=ok'
            campaign.snapshot = lambda record, label: 'flow.pool entries=0\nflow-end.buffers=0\n'+\
                'flow-end.owner=0 allocated='+('1' if label == 'drain-before-stop' else '2')+' ending=0 active_entries=0\n'
            record = dict(label='generation-0', pid=123, log='native.log')
            with self.assertRaises(AssertionError): campaign.stop(record)
            self.assertEqual(stopped, [123])
            self.assertTrue(record['process_closed'])


if __name__ == '__main__': unittest.main()
