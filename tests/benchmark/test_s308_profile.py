"""Offline boundary and exclusive attribution regression checks."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace as NS
import unittest

spec = importlib.util.spec_from_file_location('s308_profile', Path(__file__).with_name('s308_profile.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def frames(*names):
    return [('test.so', name) for name in names]


class AttributionTests(unittest.TestCase):
    def test_nearest_anchor_and_mixed_barrier(self):
        self.assertEqual(p.classify(frames('vlib_buffer_alloc', 'tun_read_ready', 'vlib_file_poll'))[0], 'buffer_parse_selector')
        self.assertEqual(p.classify(frames('memcpy', 'tun_read_ready', 'vlib_file_poll'))[0], 'other_unknown')
        self.assertEqual(p.classify(frames('vlib_buffer_free', 'tun_read_ready'))[0], 'completion_write_free')

    def test_syscall_requires_observed_tun_ancestry(self):
        self.assertEqual(p.classify(frames('tun_do_read', 'read', 'tun_read_ready'))[0], 'read_readiness')
        self.assertEqual(p.classify(frames('tun_do_read', 'vlib_file_poll'))[0], 'other_unknown')
        self.assertEqual(p.classify(frames('read', 'hev_task_io_read'))[0], 'other_unknown')
        self.assertEqual(p.classify(frames('write', 'product_vpn_tun_complete_from_graph'))[0], 'completion_write_free')
        self.assertEqual(p.classify(frames('write'))[0], 'other_unknown')

    def test_exact_names_and_runtime_leaf(self):
        self.assertEqual(p.classify(frames('fake_product_packet_admit'))[0], 'other_unknown')
        self.assertEqual(p.classify(frames('product_packet_admit.llvm.1AB'))[0], 'buffer_parse_selector')
        self.assertEqual(p.classify(frames('vlib_file_poll'))[0], 'dispatch_runtime')
        self.assertEqual(p.classify(frames('unknown', 'vlib_file_poll'))[0], 'other_unknown')

    def test_kernel_groups_need_kernel_leaf_and_exact_chain_anchor(self):
        self.assertIsNone(p.kernel_group(frames('eventfd_write')))
        self.assertEqual(p.kernel_group([('[kernel.kallsyms]', '_raw_spin_unlock_irq'),
                                        ('[kernel.kallsyms]', 'eventfd_write')]),
                         'eventfd_write_publication')
        self.assertEqual(p.kernel_group([('[kernel.kallsyms]', 'ipt_do_table'),
                                        ('[kernel.kallsyms]', 'tun_get_user')]), 'tun_write_return')
        self.assertEqual(p.kernel_group([('[kernel.kallsyms]', 'fake_tun_get_user')]), 'other_kernel')

    def test_window_pid_period_and_inclusive_recursion(self):
        class FakeLib:
            def __init__(self):
                self.samples = iter([NS(pid=9, tid=9, thread_comm='tun', time=time, period=period)
                                     for time, period in [(99, 900), (100, 7), (199, 11), (200, 500)]] +
                                    [NS(pid=8, tid=8, thread_comm='other', time=150, period=300)])
            def GetNextSample(self):
                return next(self.samples, None)
            def GetEventOfCurrentSample(self):
                return NS(name='cpu-clock')
            def GetSymbolOfCurrentSample(self):
                return NS(dso_name='test.so', symbol_name='vlib_buffer_alloc')
            def GetCallChainOfCurrentSample(self):
                return NS(nr=1, entries=[NS(symbol=self.GetSymbolOfCurrentSample())])
        result = p.analyze(FakeLib(), dict(vpp_pid=9, client=dict(start_monotonic_ns=100, end_monotonic_ns=200)))
        thread, = result['threads']
        self.assertEqual((thread['samples'], thread['period_ns']), (2, 18))
        self.assertEqual(thread['top_inclusive'][0]['period_ns'], 18)
        self.assertEqual(sum(x['period_ns'] for x in thread['phases'].values()), 18)
        self.assertEqual(result['excluded_samples'], dict(outside_window=2, different_pid=1))


if __name__ == '__main__':
    unittest.main()
