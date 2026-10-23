#!/usr/bin/env python3
"""Exercise real subprocess quoting and remote completion despite a lost ACK."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s314_trace_test', ROOT / 'tests/device/helpers/s314_adb_trace.py')
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)


class CompletionWitnessTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='s314-adb-trace-')
        self.path = Path(self.temporary.name)
        self.fake = self.path / 'fake_adb.py'
        self.fake.write_text('''import os,pathlib,subprocess,sys,time
os.environ['PATH']=str(pathlib.Path(__file__).parent)+os.pathsep+os.environ['PATH']
args=sys.argv[1:]
if args[0]=='shell':
    result=subprocess.run(' '.join(args[1:]),shell=True)
    if pathlib.Path(__file__).with_suffix('.hold').exists():time.sleep(1)
    raise SystemExit(result.returncode)
if args[:3]==['exec-out','su','-c']:
    if args[3].startswith('ps -A'):print('PID PPID UID ARGS');raise SystemExit(0)
    raise SystemExit(subprocess.run(args[3],shell=True).returncode)
raise SystemExit(subprocess.run(args[1:]).returncode)
''')
        fake_input = self.path / 'input'
        fake_input.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
        fake_input.chmod(0o755)
        self.client = trace.AdbTrace(self.path, [sys.executable, str(self.fake)], str(self.path))

    def tearDown(self):
        self.client.close()
        self.temporary.cleanup()

    def test_existing_shell_quoting_and_canonical_command_are_preserved(self):
        payload = "literal $(printf unsafe) 'quotes' and spaces"
        original = ('shell', 'sh', '-c', shlex.quote('printf "%s\\n" ' + shlex.quote(payload)))
        self.assertEqual(self.client.run(original, None), payload + '\n')
        operations = [json.loads(line) for line in (self.path / 'operations.jsonl').read_text().splitlines()]
        actual, = [row for row in operations if row['trace_kind'] == 'traced-control']
        self.assertEqual(actual['argv'], list(original))
        self.assertEqual(actual['code'], 0)
        self.assertLess(actual['started_monotonic_ns'], actual['completed_monotonic_ns'])
        self.client.close()
        receipt = json.loads((self.path / 'adb-trace.json').read_text())
        self.assertEqual(receipt['operations'][0]['witness']['exit_code'], 0)

    def test_remote_exit_is_not_replayed_when_client_acknowledgement_times_out(self):
        counter = self.path / 'executions.txt'
        self.fake.with_suffix('.hold').touch()
        original = ('shell', 'sh', '-c', shlex.quote('printf once >> ' + shlex.quote(str(counter))))
        with self.assertRaises(subprocess.TimeoutExpired):
            self.client.run(original, time.monotonic() + .3)
        self.assertEqual(counter.read_text(), 'once')
        item, = self.client.items
        self.assertEqual(item['outcome'], 'timeout')
        self.assertNotIn('witness', item)  # No independent reads inside the caller deadline.
        self.assertGreater(item['host_operation']['completed_monotonic_ns'], item['host_operation']['started_monotonic_ns'])
        operations = [json.loads(line) for line in (self.path / 'operations.jsonl').read_text().splitlines()]
        attempted, = [row for row in operations if row['trace_kind'] == 'traced-control']
        self.assertEqual(attempted['argv'], list(original))
        self.assertEqual(attempted['outcome'], 'timeout')
        self.client.close()
        self.assertEqual(item['witness']['exit_code'], 0)
        self.assertFalse(Path(self.client.remote).exists())

    def test_command_output_without_final_newline_is_unchanged(self):
        original = ('shell', 'sh', '-c', shlex.quote('printf %s original-output'))
        self.assertEqual(self.client.run(original, None), 'original-output')

    def test_tap_coordinates_have_the_existing_string_receipt_contract(self):
        original = ('shell', 'input', 'tap', 291, 1728)
        self.assertEqual(self.client.run(original, None), 'tap\n291\n1728\n')
        row, = [json.loads(line) for line in (self.path / 'operations.jsonl').read_text().splitlines()
                if json.loads(line)['trace_kind'] == 'traced-control']
        self.assertEqual(row['argv'], ['shell', 'input', 'tap', '291', '1728'])

    def test_bootstrap_respects_the_remaining_deadline(self):
        real = self.client.execute
        observed = []
        def bounded(original, wire, timeout, **options):
            observed.append(timeout)
            return real(original, wire, timeout, **options)
        with patch.object(self.client, 'execute', side_effect=bounded):
            self.client.run(('shell', 'sh', '-c', shlex.quote('printf ready')), time.monotonic() + .8)
        self.assertLessEqual(observed[0], .8)

    def test_missing_exit_or_identity_is_an_explicit_gap(self):
        self.client.run(('shell', 'sh', '-c', shlex.quote('printf ready')), None)
        self.client.collect(self.client.items[0])
        item = self.client.items[0]
        self.assertEqual(item['witness']['gaps'], [])
        item['remote_meta']['text'] = item['remote_meta']['text'].replace('exit\n0\n', 'exit\n\n')
        self.assertIn('exit', trace.witness(item)['gaps'])
        item['remote_meta']['text'] = item['remote_meta']['text'].replace('child_uid', 'missing_uid')
        self.assertIn('child_identity', trace.witness(item)['gaps'])

    def test_reparenting_preserves_actor_identity_but_pid_reuse_does_not(self):
        actor = dict(pid=123, start=456, uid=2000, parent=7)
        self.assertTrue(trace.same_actor(dict(actor, parent=1), actor))
        self.assertFalse(trace.same_actor(dict(actor, start=457), actor))
        self.assertFalse(trace.same_actor(dict(actor, uid=2001), actor))

    def test_nonzero_exit_is_completion_without_semantic_success(self):
        self.client.run(('shell', 'sh', '-c', shlex.quote('exit 7')), None, check=False)
        self.client.collect(self.client.items[0])
        result = self.client.items[0]['witness']
        self.assertEqual(result['gaps'], [])
        self.assertEqual(result['exit_code'], 7)
        self.assertFalse(result['semantic_success'])

    def test_pipe_drain_timeout_still_reaps_and_records_partial_output(self):
        real = subprocess.Popen
        processes = []
        def stalled(*args, **kwargs):
            process = real(*args, **kwargs)
            def timeout(*a, **kw):
                raise subprocess.TimeoutExpired(args[0], .1, output=b'partial-output', stderr=b'partial-error')
            process.communicate = timeout
            processes.append(process)
            return process
        with patch.object(trace.subprocess, 'Popen', side_effect=stalled):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.client.execute(['shell', 'input', 'tap', 1, 2], ['exec-out', 'true'], .1)
        process, = processes
        self.assertIsNotNone(process.poll())
        self.assertTrue(process.stdout.closed)
        row = json.loads((self.path / 'operations.jsonl').read_text().splitlines()[-1])
        self.assertTrue(row['local_reaped'])
        self.assertEqual((self.path / row['stdout_path']).read_bytes(), b'partial-output')

    def test_cancellation_reaps_local_client_and_keeps_the_attempt(self):
        self.fake.with_suffix('.hold').touch()
        real = subprocess.Popen
        processes = []
        def interrupted(*args, **kwargs):
            process = real(*args, **kwargs)
            communicate = process.communicate
            calls = 0
            def cancel_once(*a, **kw):
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise KeyboardInterrupt()
                return communicate(*a, **kw)
            process.communicate = cancel_once
            processes.append(process)
            return process
        with patch.object(trace.subprocess, 'Popen', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                self.client.execute(['shell', 'input', 'tap', 1, 2], ['exec-out', 'sleep', '1'], .5)
        self.assertIsNotNone(processes[0].poll())
        row = json.loads((self.path / 'operations.jsonl').read_text().splitlines()[-1])
        self.assertTrue(row['local_reaped'])
        self.assertEqual(row['argv'], ['shell', 'input', 'tap', '1', '2'])


if __name__ == '__main__':
    unittest.main()
