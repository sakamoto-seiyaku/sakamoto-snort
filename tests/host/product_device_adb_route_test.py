#!/usr/bin/env python3
"""Exercise the task-local route through real TCP streams and connect faults."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s314_route', ROOT/'tests/device/helpers/s314_adb_route.py')
route_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(route_module)


def receive(stream):
    value = bytearray()
    while data := stream.recv(16384):
        value.extend(data)
    return bytes(value)


class RouteTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='s314 route ')
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)/'evidence'

    def upstream(self, response=b'reply-without-final-newline'):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(4)
        listener.settimeout(2)
        self.addCleanup(listener.close)
        received, errors = [], []
        def serve():
            try:
                stream, address = listener.accept()
                with stream:
                    stream.settimeout(2)
                    received.append(receive(stream))
                    stream.sendall(response)
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=serve)
        thread.start()
        self.addCleanup(lambda: thread.join(timeout=3))
        return listener, thread, received, errors

    def exchange(self, route, request=b'one exact request'):
        with socket.create_connection(route.endpoint, timeout=2) as client:
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            return receive(client)

    def test_connect_timeout_recovers_before_one_exact_request(self):
        listener, thread, received, errors = self.upstream()
        endpoint, original = listener.getsockname(), socket.socket.connect
        failed = []
        def connect(stream, address):
            if address == endpoint and len(failed) < 4:
                failed.append(address)
                raise TimeoutError('injected SYN establishment timeout')
            return original(stream, address)
        with patch.object(socket.socket, 'connect', connect):
            with route_module.AdbRoute(self.output, Path('/bin/true'), endpoint) as route:
                self.assertEqual(self.exchange(route), b'reply-without-final-newline')
        thread.join(timeout=2)
        self.assertFalse(errors)
        self.assertEqual(received, [b'one exact request'])
        self.assertEqual(len(failed), 4)
        rows = [json.loads(line) for line in (self.output/'connections.jsonl').read_text().splitlines()]
        attempts = [row for row in rows if row['event'] == 'connect-attempt']
        self.assertEqual([row['status'] for row in attempts], ['connect-failed']*4+['connected'])
        self.assertTrue(all(row['forwarded_request_bytes'] == 0 for row in attempts))

    def test_no_reconnect_or_replay_after_request_forwarded(self):
        listener, thread, received, errors = self.upstream(response=b'')
        with route_module.AdbRoute(self.output, Path('/bin/true'), listener.getsockname()) as route:
            self.assertEqual(self.exchange(route, b'mutate exactly once'), b'')
        thread.join(timeout=2)
        self.assertFalse(errors)
        self.assertEqual(received, [b'mutate exactly once'])
        listener.settimeout(.05)
        with self.assertRaises(socket.timeout):
            listener.accept()
        rows = [json.loads(line) for line in (self.output/'connections.jsonl').read_text().splitlines()]
        self.assertEqual(sum(row['event'] == 'connect-attempt' for row in rows), 1)

    def test_exhausted_connect_attempts_forward_nothing(self):
        endpoint, original = ('127.0.0.1', 1), socket.socket.connect
        attempts = []
        def connect(stream, address):
            if address == endpoint:
                attempts.append(address)
                raise TimeoutError('injected connection failure')
            return original(stream, address)
        with patch.object(socket.socket, 'connect', connect):
            with route_module.AdbRoute(self.output, Path('/bin/true'), endpoint) as route:
                with socket.create_connection(route.endpoint, timeout=2) as client:
                    # No request has been written before the failed upstream.
                    self.assertEqual(client.recv(1), b'')
        self.assertEqual(len(attempts), 6)
        rows = [json.loads(line) for line in (self.output/'connections.jsonl').read_text().splitlines()]
        self.assertTrue(all(row.get('forwarded_request_bytes') == 0 for row in rows))

    def test_bounded_buffers_and_half_close_preserve_large_stream(self):
        response, request = b'R'*262145, b'Q'*131073
        listener, thread, received, errors = self.upstream(response)
        with route_module.AdbRoute(self.output, Path('/bin/true'), listener.getsockname()) as route:
            self.assertEqual(self.exchange(route, request), response)
        thread.join(timeout=2)
        self.assertFalse(errors)
        self.assertEqual(received, [request])
        receipt = json.loads((self.output/'receipt.json').read_text())
        self.assertEqual(receipt['remaining_sockets'], 0)
        self.assertEqual(receipt['live_threads'], [])

    def test_close_settles_owned_pending_connect(self):
        endpoint, original = ('127.0.0.1', 1), socket.socket.connect
        entered = threading.Event()
        def connect(stream, address):
            if address == endpoint:
                entered.set()
                time.sleep(.1)
                raise TimeoutError('injected pending connect')
            return original(stream, address)
        with patch.object(socket.socket, 'connect', connect):
            with route_module.AdbRoute(self.output, Path('/bin/true'), endpoint) as route:
                client = socket.create_connection(route.endpoint, timeout=2)
                self.addCleanup(client.close)
                self.assertTrue(entered.wait(timeout=1))
        receipt = json.loads((self.output/'receipt.json').read_text())
        self.assertEqual(receipt['remaining_sockets'], 0)
        self.assertEqual(receipt['live_threads'], [])

    def test_wrapper_keeps_exact_argument_boundaries(self):
        client = Path(self.temp.name)/'fake client'
        client.write_text('#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n')
        client.chmod(0o700)
        original = ['shell', 'sh', '-c', "printf '%s' 'literal $() `text`'", 'argument with space']
        # The later restore caller retains its existing120s transfer deadline;
        # its local route may remain alive125s without changing that deadline.
        with route_module.AdbRoute(self.output, client, connection_lifetime=125) as route:
            result = subprocess.run([str(route.wrapper), *original], capture_output=True, text=True, timeout=2, check=True)
            argv = json.loads(result.stdout)
            self.assertEqual(argv[:4], ['-H', '127.0.0.1', '-P', str(route.endpoint[1])])
            self.assertEqual(argv[4:], original)
        self.assertEqual(json.loads((self.output/'receipt.json').read_text())['connection_lifetime'],125)

    def test_partial_bind_failure_closes_allocated_listener(self):
        before = set(os.listdir('/proc/self/fd'))
        with patch.object(socket.socket, 'bind', side_effect=OSError('injected bind failure')):
            with self.assertRaisesRegex(OSError, 'injected bind failure'):
                with route_module.AdbRoute(self.output, Path('/bin/true')):
                    self.fail('startup must fail')
        receipt = json.loads((self.output/'receipt.json').read_text())
        self.assertEqual(receipt['status'], 'HOLD')
        self.assertEqual(receipt['remaining_sockets'], 0)
        self.assertEqual(receipt['live_threads'], [])
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)

    def test_partial_wrapper_failure_closes_bound_listener(self):
        before, original = set(os.listdir('/proc/self/fd')), Path.write_text
        def write(path, *args, **kwargs):
            if path.name == 'adb-client':
                raise OSError('injected wrapper write failure')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'write_text', write):
            with self.assertRaisesRegex(OSError, 'injected wrapper write failure'):
                with route_module.AdbRoute(self.output, Path('/bin/true')):
                    self.fail('startup must fail')
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)
        self.assertEqual(json.loads((self.output/'receipt.json').read_text())['status'], 'HOLD')

    def test_worker_start_failure_closes_client_and_retains_hold(self):
        original = threading.Thread.start
        def start(thread):
            if thread.name.startswith('s314-adb-route-') and thread.name.rsplit('-', 1)[-1].isdigit():
                raise RuntimeError('injected worker start failure')
            return original(thread)
        with patch.object(threading.Thread, 'start', start):
            with self.assertRaisesRegex(AssertionError, 'HOLD'):
                with route_module.AdbRoute(self.output, Path('/bin/true')) as route:
                    with socket.create_connection(route.endpoint, timeout=2) as client:
                        self.assertEqual(client.recv(1), b'')
        receipt = json.loads((self.output/'receipt.json').read_text())
        self.assertEqual(receipt['remaining_sockets'], 0)
        self.assertEqual(receipt['live_threads'], [])
        self.assertTrue(any(row.get('stage') == 'worker-start' for row in receipt['errors']))

    def test_connect_record_failure_closes_both_owned_sockets(self):
        listener, thread, received, errors = self.upstream(response=b'')
        original = Path.open
        def open_file(path, *args, **kwargs):
            if path.name == 'connections.jsonl':
                raise OSError('injected record failure')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', open_file):
            with self.assertRaisesRegex(AssertionError, 'HOLD'):
                with route_module.AdbRoute(self.output, Path('/bin/true'), listener.getsockname()) as route:
                    with socket.create_connection(route.endpoint, timeout=2) as client:
                        self.assertEqual(client.recv(1), b'')
        thread.join(timeout=2)
        receipt = json.loads((self.output/'receipt.json').read_text())
        self.assertEqual(receipt['remaining_sockets'], 0)
        self.assertEqual(receipt['live_threads'], [])
        self.assertEqual(received, [b''])
        self.assertIn('injected record failure', str(receipt['errors']))

    def test_receipt_hash_failure_keeps_primary_exception_and_hold(self):
        original = Path.read_bytes
        def read_bytes(path):
            if path.name == 'connections.jsonl':
                raise OSError('injected log read failure')
            return original(path)
        with patch.object(Path, 'read_bytes', read_bytes):
            with self.assertRaisesRegex(ValueError, 'original primary failure'):
                with route_module.AdbRoute(self.output, Path('/bin/true')):
                    (self.output/'connections.jsonl').write_text('')
                    raise ValueError('original primary failure')
        receipt = json.loads((self.output/'receipt.json').read_text())
        self.assertEqual(receipt['status'], 'HOLD')
        self.assertIn('original primary failure', receipt['primary_error'])
        self.assertTrue(any(row.get('stage') == 'receipt-log-hash' for row in receipt['errors']))
        self.assertEqual(receipt['remaining_sockets'], 0)

    def test_owned_child_cancellation_keeps_route_for_finally(self):
        listener, thread, received, errors = self.upstream(response=b'cleanup-ack')
        ready, finished = Path(self.temp.name)/'ready', Path(self.temp.name)/'finished'
        script = Path(self.temp.name)/'child.py'
        script.write_text('import os,socket,time\nfrom pathlib import Path\ntry:\n Path(os.environ["READY"]).write_text("ready")\n while True: time.sleep(.1)\nexcept KeyboardInterrupt: pass\nfinally:\n s=socket.create_connection(("127.0.0.1",int(os.environ["ROUTE_PORT"])),timeout=2)\n s.sendall(b"cleanup");s.shutdown(socket.SHUT_WR)\n value=s.recv(100);s.close()\n Path(os.environ["FINISHED"]).write_bytes(value)\n')
        cancel, receipt = threading.Event(), {}
        def trigger():
            deadline = time.monotonic()+2
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(.01)
            cancel.set()
        with route_module.AdbRoute(self.output, Path('/bin/true'), listener.getsockname()) as route:
            trigger_thread = threading.Thread(target=trigger)
            trigger_thread.start()
            with (Path(self.temp.name)/'child.log').open('wb') as log:
                code = route_module.run_owned(['python3', str(script)], env=dict(os.environ, READY=str(ready), FINISHED=str(finished), ROUTE_PORT=str(route.endpoint[1])), stdout=log, cancel=cancel, receipt=receipt, cleanup_timeout=2)
            trigger_thread.join(timeout=2)
            self.assertEqual(code, 0)
            self.assertEqual(finished.read_bytes(), b'cleanup-ack')
        thread.join(timeout=2)
        self.assertFalse(errors)
        self.assertEqual(received, [b'cleanup'])
        self.assertTrue(receipt['cancelled'] and receipt['local_reaped'])
        self.assertEqual(receipt['cancellation_signal'], 'SIGINT')
        self.assertNotIn('forced_termination', receipt)

    def test_owned_child_forced_exit_retains_unproved_cleanup(self):
        ready = Path(self.temp.name)/'ready'
        script = Path(self.temp.name)/'ignore.py'
        script.write_text('import signal,time,sys\nfrom pathlib import Path\nsignal.signal(signal.SIGINT,signal.SIG_IGN)\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\nPath(sys.argv[1]).write_text("ready")\nwhile True:time.sleep(.1)\n')
        cancel, receipt = threading.Event(), {}
        def trigger():
            deadline = time.monotonic()+2
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(.01)
            cancel.set()
        thread = threading.Thread(target=trigger)
        thread.start()
        with (Path(self.temp.name)/'ignore.log').open('wb') as log:
            code = route_module.run_owned(['python3', str(script), str(ready)], env=os.environ.copy(), stdout=log, cancel=cancel, receipt=receipt, cleanup_timeout=.1)
        thread.join(timeout=2)
        self.assertEqual(code, -9)
        self.assertTrue(receipt['cancelled'] and receipt['local_reaped'])
        self.assertIn('Android cleanup remains unproved', receipt['forced_termination'])

    def test_cancel_before_child_launch_starts_nothing(self):
        marker = Path(self.temp.name)/'must-not-exist'
        cancel, receipt = threading.Event(), {}
        cancel.set()
        with (Path(self.temp.name)/'not-started.log').open('wb') as log:
            code = route_module.run_owned(['python3', '-c', 'from pathlib import Path;Path('+repr(str(marker))+').touch()'], env=os.environ.copy(), stdout=log, cancel=cancel, receipt=receipt)
        self.assertEqual(code, 130)
        self.assertFalse(marker.exists())
        self.assertIsNone(receipt['local_pid'])
        self.assertTrue(receipt['cancelled'] and receipt['local_reaped'])

    def test_forced_stream_close_retains_hold_after_forwarding(self):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0));listener.listen(1);listener.settimeout(2)
        self.addCleanup(listener.close)
        forwarded, release = threading.Event(), threading.Event()
        def hold():
            stream, address = listener.accept()
            with stream:
                stream.settimeout(2)
                if stream.recv(100) == b'pending operation':forwarded.set()
                release.wait(timeout=2)
        thread = threading.Thread(target=hold);thread.start()
        try:
            with self.assertRaisesRegex(AssertionError, 'HOLD'):
                with route_module.AdbRoute(self.output, Path('/bin/true'), listener.getsockname()) as route:
                    client = socket.create_connection(route.endpoint, timeout=2)
                    self.addCleanup(client.close)
                    client.sendall(b'pending operation')
                    self.assertTrue(forwarded.wait(timeout=1))
        finally:
            release.set();thread.join(timeout=2)
        receipt = json.loads((self.output/'receipt.json').read_text())
        self.assertEqual(receipt['status'], 'HOLD')
        self.assertEqual(receipt['remaining_sockets'], 0)
        self.assertEqual(receipt['live_threads'], [])
        self.assertTrue(any(row.get('stage') == 'forced-stream-close' for row in receipt['errors']))

    def test_expired_stream_lifetime_closes_resources_with_hold(self):
        listener = socket.socket()
        listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(2)
        self.addCleanup(listener.close)
        release=threading.Event()
        def hold():
            stream,address=listener.accept()
            with stream:
                release.wait(timeout=2)
        thread=threading.Thread(target=hold);thread.start()
        try:
            with self.assertRaisesRegex(AssertionError,'HOLD'):
                with route_module.AdbRoute(self.output,Path('/bin/true'),listener.getsockname(),connection_lifetime=.05) as route:
                    with socket.create_connection(route.endpoint,timeout=2) as client:
                        self.assertEqual(client.recv(1),b'')
        finally:
            release.set();thread.join(timeout=2)
        receipt=json.loads((self.output/'receipt.json').read_text())
        self.assertEqual(receipt['connection_lifetime'],.05)
        self.assertEqual(receipt['remaining_sockets'],0)
        self.assertEqual(receipt['live_threads'],[])
        self.assertIn('exceeded bounded lifetime',str(receipt['errors']))


if __name__ == '__main__':
    unittest.main()
