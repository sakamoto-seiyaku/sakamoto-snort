#!/usr/bin/env python3
"""Hand-authored semantic anchors and deliberate expectation corruption."""
import tempfile
import unittest
from pathlib import Path
from generate import normalize, oracle, generate


class OracleTests(unittest.TestCase):
    def test_independent_named_examples(self):
        exact = {('example', 'com'): {1}, ('a', 'example', 'com'): {3}}
        descendants = {('example', 'com'): {2}, ('a', 'example', 'com'): {4}, ('com',): {5}}
        for name, expected in [('EXAMPLE.COM', 38), ('a.example.com', 60),
                               ('b.a.example.com', 52), ('badexample.com', 32),
                               ('example.com.invalid', 0)]:
            self.assertEqual(oracle(name, exact, descendants), (0, expected))

    def test_normalization_boundaries(self):
        self.assertEqual(normalize('EXAMPLE.COM.', True), 'example.com')
        self.assertIsNone(normalize('EXAMPLE.COM.'))
        self.assertEqual(normalize('xn--bcher-kva.example'), 'xn--bcher-kva.example')
        for value in ['', '.', 'a..b', '-a.b', 'a-.b', '*.com', 'https://a.com',
                      'ü.com', 'a\0.com', 'a' * 64 + '.com', 'a' * 254]:
            self.assertEqual(oracle(value, {}, {}), (-1, 0))
        self.assertIsNotNone(normalize('.'.join(['a' * 63] * 3 + ['a' * 61])))

    def test_generation_is_reproducible(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            generate(Path(first), 1000, 'shared')
            generate(Path(second), 1000, 'shared')
            for name in ('entries.tsv', 'queries.tsv', 'manifest.json'):
                self.assertEqual((Path(first) / name).read_bytes(), (Path(second) / name).read_bytes())


if __name__ == '__main__':
    unittest.main()
