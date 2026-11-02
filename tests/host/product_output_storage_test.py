#!/usr/bin/env python3
"""Publication reuse must preserve old witnesses and mutable build outputs."""
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('output_storage', ROOT / 'tools/product/output_storage.py')
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)


class PublicationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.output = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def distribution(self, name, contents=b'payload'):
        root = self.output / name
        root.mkdir()
        file = root / 'runtime.so'
        file.write_bytes(contents)
        file.chmod(0o755)
        return root, file

    def test_repeat_shares_readonly_files_but_not_mutable_inputs(self):
        compiler = self.output / 'compiler.so'
        compiler.write_bytes(b'payload')
        first, a = self.distribution('first', compiler.read_bytes())
        second, b = self.distribution('repeat', compiler.read_bytes())
        storage.publish_tree(first, self.output)
        storage.publish_tree(second, self.output)
        self.assertTrue(os.path.samefile(a, b))
        self.assertFalse(os.path.samefile(a, compiler))
        self.assertEqual(a.stat().st_mode & 0o777, 0o555)
        compiler.write_bytes(b'changed')
        self.assertEqual(a.read_bytes(), b'payload')

    def test_republication_preserves_old_alias_and_same_size_change(self):
        first, a = self.distribution('first')
        second, b = self.distribution('second')
        storage.publish_tree(first, self.output)
        storage.publish_tree(second, self.output)
        replacement = second / 'new'
        replacement.write_bytes(b'changed')
        replacement.chmod(0o755)
        replacement.replace(b)
        storage.publish_tree(second, self.output)
        self.assertEqual(a.read_bytes(), b'payload')
        self.assertEqual(b.read_bytes(), b'changed')
        self.assertFalse(os.path.samefile(a, b))

    def test_prune_keeps_referenced_payload(self):
        first, a = self.distribution('first')
        storage.publish_tree(first, self.output)
        self.assertEqual(storage.prune_store(self.output), 0)
        shutil.rmtree(first)
        self.assertGreater(storage.prune_store(self.output), 0)
        self.assertEqual(list((self.output / 'product-published').iterdir()),
                         [self.output / 'product-published' / storage.MARKER])

    def test_symlinks_remain_relative_and_cannot_escape(self):
        first, a = self.distribution('first')
        alias = first / 'runtime-link.so'
        alias.symlink_to(a.name)
        storage.publish_tree(first, self.output)
        self.assertEqual(os.readlink(alias), a.name)
        alias.unlink()
        alias.symlink_to('../outside')
        (self.output / 'outside').write_text('external')
        with self.assertRaises(ValueError):
            storage.publish_tree(first, self.output)

    def test_compilation_cache_is_rejected_including_override(self):
        cache, file = self.distribution('custom-cache')
        (cache / '.sakamoto-product-build-cache').write_text('owned')
        with self.assertRaises(ValueError):
            storage.publish_tree(cache, self.output)
        self.assertEqual(file.stat().st_mode & 0o777, 0o755)

    def test_changed_shared_payload_is_rejected(self):
        first, a = self.distribution('first')
        storage.publish_tree(first, self.output)
        a.chmod(0o755)
        a.write_bytes(b'corrupt')
        a.chmod(0o555)
        second, _ = self.distribution('second')
        with self.assertRaisesRegex(ValueError, 'sealed publication changed'):
            storage.publish_tree(second, self.output)


if __name__ == '__main__':
    unittest.main()
