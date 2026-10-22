"""Live no-probe warm attribution remains strict and joins its bounded client."""
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import pixel_quick as quick


class LiveWarmTests(unittest.TestCase):
    def exercise(self, *, uid=2000, peer='c0a80405', cli_error=False, closes_during_cli=False):
        done = threading.Event()
        started = threading.Event()
        manifest = dict(peer_host='192.168.4.5', peer_port=41723, threads=1, flows_per_thread=1)
        diagnostic = (f'flow.entry protocol=6 uid={uid} key_a={"0"*24}{peer} port_a=41723 '
                      f'key_b={"0"*24}0a470002 port_b=40000\n')
        class Device:
            def command(self, *args, **kwargs):
                started.set()
                time.sleep(.08 if closes_during_cli else .25)
                done.set()
                return json.dumps(dict(bytes=3000000,uid=2000,pid=123, tcp_download_connections=1,
                                       tcp_download_streams_with_data=1,tcp_probe_connections=0))
            def cli(self, *args):
                if cli_error:
                    raise RuntimeError('injected CLI failure')
                if closes_during_cli:
                    done.wait(1)
                return diagnostic
        def peer_query(*args):
            if args[-1] != 'R':
                self.assertTrue(started.wait(1))
            return dict(tcp_download_connections=1,tcp_echo_connections=0)
        with tempfile.TemporaryDirectory() as directory, patch.object(quick, 'peer_query', peer_query):
            cell=Path(directory)
            try:
                result=quick.live_tcp_warmup(Device(),'vpn',['shell','helper','client'],manifest,cell)
                self.assertTrue(done.is_set())
                self.assertTrue(json.loads((cell/'warm-lifecycle.json').read_text())['joined_before_measurement'])
                return result
            finally:
                self.assertTrue(done.is_set(), 'warm helper escaped the synchronous join')
                self.assertTrue((cell/'warm.json').exists())

    def test_live_actual_uid_peer_survives_postclose_cleanup(self):
        self.assertEqual(len(self.exercise()),1)

    def test_unknown_uid_and_wrong_peer_cannot_pass(self):
        with self.assertRaisesRegex(RuntimeError,'actual traffic UID and peer'):
            self.exercise(uid=-1)
        with self.assertRaisesRegex(RuntimeError,'actual traffic UID and peer'):
            self.exercise(peer='c0a80406')

    def test_cli_failure_still_joins_warm_helper(self):
        with self.assertRaisesRegex(RuntimeError,'injected CLI failure'):
            self.exercise(cli_error=True)

    def test_client_must_still_be_live_after_cli(self):
        with self.assertRaisesRegex(RuntimeError,'ended before live CLI'):
            self.exercise(closes_during_cli=True)


if __name__=='__main__':
    unittest.main()
