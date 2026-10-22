"""Offline flame weights and ELF identity checks, independent of device runs."""
import unittest
import xml.etree.ElementTree as ET

import s308_download_profiles as p


class DownloadProfileTests(unittest.TestCase):
    def test_build_id_padding_is_exact(self):
        self.assertTrue(p.matches_recorded_id('1234', '0x1234' + '0' * 36))
        self.assertFalse(p.matches_recorded_id('1234', '0x1234' + '0' * 35 + '1'))
        self.assertFalse(p.matches_recorded_id('1234', '0x1234'))
        self.assertFalse(p.matches_recorded_id('1' * 42, '0x' + '1' * 40))

    def test_folded_uses_periods_and_preserves_stack_order(self):
        thread = dict(period_ns=10, symbol_chains=[
            dict(samples=99, period_ns=3, frames=[dict(dso='a.so', symbol='leaf;&<'), dict(dso='b.so', symbol='root')]),
            dict(samples=1, period_ns=7, frames=[dict(dso='a.so', symbol='other'), dict(dso='b.so', symbol='root')])])
        folded = p.folded_stacks(thread)
        self.assertEqual(folded[('b.so!root', 'a.so!leaf%3B&<')], 3)
        self.assertEqual(folded[('b.so!root', 'a.so!other')], 7)
        svg = p.flame_svg(folded, 'A & <thread>')
        root = ET.fromstring(svg)
        titles = [node.text for node in root.iter('{http://www.w3.org/2000/svg}title')]
        self.assertTrue(any('10 period ns' in title for title in titles))
        self.assertTrue(any('70.000%' in title for title in titles))
        self.assertIn('A &amp; &lt;thread&gt;', svg)

    def test_roles_use_layout_tid_instead_of_comm_guess(self):
        case = dict(worker_layout=[dict(id=0,tid=1),dict(id=1,tid=2),dict(id=2,tid=3),dict(id=3,tid=4)], _owners=[1,2])
        self.assertEqual([p.role(dict(tid=i),case) for i in range(1,5)], ['main','owner0','owner1','io'])
        self.assertEqual(p.role(dict(tid=99, name='vpp_wk_2'),case),'other')


if __name__ == '__main__':
    unittest.main()
