#!/usr/bin/env python3
"""Historical cleanup preserves active inputs, conclusions and exact dirty source."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/product'))
spec = importlib.util.spec_from_file_location('output_cleanup', ROOT / 'tools/product/clean-build-output.py')
cleanup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cleanup)


class CleanupTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.output = Path(self.temporary.name)
        self.task = self.output / 'old-task'
        self.task.mkdir()
        self.retained = self.output / 'storage-retained'

    def tearDown(self):
        self.temporary.cleanup()

    def run_cleanup(self, keep=(), apply=True):
        if apply:
            self.retained.mkdir(exist_ok=True)
        return cleanup.cleanup_group(self.task, self.output, set(keep), None,
                                     apply, self.retained)

    def test_preview_has_no_side_effect(self):
        path = self.task / 'old.apk'
        path.write_bytes(b'old binary')
        result = self.run_cleanup(apply=False)
        self.assertEqual(result['selected_files'], 1)
        self.assertTrue(path.exists())
        self.assertFalse(self.retained.exists())

    def test_clean_retain_and_restore_then_repeat(self):
        (self.task / 'old.apk').write_bytes(b'old binary')
        source = self.task / 'source/src'
        source.mkdir(parents=True)
        (source / 'main.c').write_bytes(b'int dirty_source = 42;\n')
        (source / 'settings.json').write_text('{"dirty":true}\n')
        (self.task / 'result.json').write_text(json.dumps({
            'status': 'FAIL', 'error': 'actual business failure', 'measured_ms': 21,
            'cases': [{'status': 'FAIL', 'expected': 4, 'actual': 3}], 'raw': 'x' * 10000}))
        with zipfile.ZipFile(self.task / 'run-source.zip', 'w') as archive:
            archive.writestr('new-helper.py', 'print("new untracked source")\n')
            archive.writestr('config.json', '{"unique":true}')
        result = self.run_cleanup()
        self.assertEqual(result['errors'], [])
        self.assertFalse(self.task.exists())
        records = [json.loads(line) for line in Path(result['records']).read_text().splitlines()]
        report = records[0]['record']
        self.assertEqual(report['status'], 'FAIL')
        self.assertEqual(report['measured_ms'], 21)
        self.assertEqual(report['cases'][0]['actual'], 3)
        self.assertNotIn('x' * 100, json.dumps(report))
        restored = self.output / 'restored-source'
        cleanup.restore_sources(Path(result['source_index']).parent, restored)
        self.assertEqual((restored / 'source/src/main.c').read_bytes(), b'int dirty_source = 42;\n')
        self.assertEqual((restored / 'source/src/settings.json').read_text(), '{"dirty":true}\n')
        self.assertEqual((restored / 'run-source.zip.sources/config.json').read_text(), '{"unique":true}')
        self.task.mkdir()
        repeated = self.run_cleanup()
        self.assertEqual(repeated['selected_files'], 0)

    def test_protected_subtree_survives_with_its_parent(self):
        baseline = self.task / 'baseline'
        baseline.mkdir()
        (baseline / 'app-data.tar').write_bytes(b'irreplaceable user data')
        (self.task / 'obsolete.apk').write_bytes(b'old binary')
        self.run_cleanup(keep=[baseline])
        self.assertEqual((baseline / 'app-data.tar').read_bytes(), b'irreplaceable user data')
        self.assertFalse((self.task / 'obsolete.apk').exists())

    def test_cache_identity_retains_external_stage_inputs(self):
        cache = self.output / 'product-build-cache'
        key = cache / 'android/key'
        key.mkdir(parents=True)
        (cache / '.sakamoto-product-build-cache').write_text('owned')
        stage = self.task / 'vpp-input'
        stage.mkdir()
        (key / 'build-inputs.json').write_text(json.dumps({'inputs': {'vpp_stage': str(stage)}}))
        keep = cleanup.cache_inputs(self.output)
        self.assertIn(cache, keep)
        self.assertIn(stage, keep)
        self.assertIn(self.output / '.product-build-cache-init.lock', keep)

    def test_invalid_summary_retains_original_diagnostic_text(self):
        (self.task / 'result.json').write_text('partial json {')
        result = self.run_cleanup()
        self.assertEqual(result['errors'], [])
        record = json.loads(Path(result['records']).read_text())['record']
        self.assertEqual(record['unparsed_result'], 'partial json {')
        self.assertIn('parse_error', record)

    def test_readonly_directory_is_retired_without_changing_shared_file(self):
        file = self.task / 'helper.py'
        file.write_text('print("sealed")\n')
        file.chmod(0o444)
        witness = self.output / 'other-source-witness.py'
        witness.hardlink_to(file)
        self.task.chmod(0o555)
        result = self.run_cleanup()
        self.assertEqual(result['errors'], [])
        self.assertFalse(self.task.exists())
        self.assertEqual(witness.stat().st_mode & 0o777, 0o444)
        self.assertEqual(witness.read_text(), 'print("sealed")\n')

    def test_restore_rejects_corrupt_source_object(self):
        (self.task / 'dirty.py').write_text('print("original")\n')
        result = self.run_cleanup()
        item = json.loads(Path(result['source_index']).read_text())
        stored = self.retained / 'source-objects' / item['object']
        stored.chmod(0o644)
        stored.write_bytes(b'changed source')
        with self.assertRaisesRegex(ValueError, 'source content changed'):
            cleanup.restore_sources(Path(result['source_index']).parent, self.output / 'restore-corrupt')

    def test_helper_owned_log_in_owned_directory_can_be_retired(self):
        path = self.task / 'wire.pcap'
        path.write_bytes(b'old capture')
        original = Path.lstat
        def info(item):
            value = original(item)
            if item == path:
                fields = {name: getattr(value, name) for name in (
                    'st_mode', 'st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_mtime', 'st_blocks')}
                return SimpleNamespace(**fields, st_uid=65534)
            return value
        with patch.object(Path, 'lstat', info):
            result = self.run_cleanup()
        self.assertEqual(result['errors'], [])
        self.assertFalse(path.exists())


if __name__ == '__main__':
    unittest.main()
