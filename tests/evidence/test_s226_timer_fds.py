#!/usr/bin/env python3
"""Linux and actual Pixel named timerfd symlinks must retain the same gates."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s226_verify', ROOT/'tests/device/verify-s226-expiry-ab.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class TimerDescriptors(unittest.TestCase):
    def test_linux_unnamed(self):
        value = ''.join(f'lrwx------ 1 root root 64 Sep 12 22:44 {fd} -> anon_inode:[timerfd]\n'
                        for fd in (20, 21, 22, 23))
        self.assertEqual(set(verifier.timer_fds(value)), {20, 21, 22, 23})

    def test_pixel_named_originals_and_clib_duplicates(self):
        value = ''.join(f'lrwx------ 1 root root 64 2026-09-12 23:54 {fd} -> anon_inode:[timerfd{tag}:vpp_main]\n'
                        for fd, tag in ((19, 596), (20, 596), (21, 597), (22, 597)))
        result = verifier.timer_fds(value)
        self.assertEqual(set(result), {19, 20, 21, 22})
        self.assertEqual(result[19], result[20])
        self.assertNotEqual(result[19], result[21])

    def test_named_residue_is_not_invisible(self):
        self.assertEqual(set(verifier.timer_fds('999 -> anon_inode:[timerfd598:vpp_main]\n')), {999})

    def test_other_descriptor_and_regular_path_are_not_timerfds(self):
        self.assertEqual(verifier.timer_fds('10 -> anon_inode:[eventfd]\n'
            '11 -> /tmp/anon_inode:[timerfd]\n'), {})

    def test_unrecognized_timer_prefix_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, 'unrecognized timer fd'):
            verifier.timer_fds('12 -> anon_inode:[timerfd_fake]\n')

    def test_duplicate_descriptor_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, 'duplicate timer fd'):
            verifier.timer_fds('19 -> anon_inode:[timerfd]\n19 -> anon_inode:[timerfd]\n')


if __name__ == '__main__':
    unittest.main()
