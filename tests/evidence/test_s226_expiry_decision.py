#!/usr/bin/env python3
"""Synthetic unit vectors for S226 decision logic, NOT Pixel acceptance data."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('expiry_decision', ROOT/'tests/device/verify-s226-expiry-ab.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def synthetic_rows():
    return [dict(label=f'{name}-{repetition}-{arm}', case=name, repetition=repetition, arm=arm,
                 environment=dict(valid=True, errors=[]), idle_failures=[],
                 interval=dict(cpu_rails_mw=100 if arm == 'poll' else 50,
                               temperature_c=[30, 30]))
            for name in verifier.COUNTS for repetition in range(3) for arm in ('poll', 'deadline')]


def select(rows, name='empty', repetition=0, arm='deadline'):
    return next(r for r in rows if r['case'] == name and r['repetition'] == repetition and r['arm'] == arm)


class DecisionTests(unittest.TestCase):
    def test_unique_deadline_candidate(self):
        result = verifier.decision(synthetic_rows())
        self.assertEqual(result['selected'], 'deadline')
        self.assertEqual(len(result['pairs']), 6)
        self.assertEqual(result['arms']['deadline']['ratios'], [.5]*6)
        self.assertEqual(result['arms']['deadline']['ratio_range'], [.5, .5])

    def test_unique_poll_candidate_without_driver_bias(self):
        rows = synthetic_rows()
        for row in rows:
            row['interval']['cpu_rails_mw'] = 50 if row['arm'] == 'poll' else 100
        self.assertEqual(verifier.decision(rows)['selected'], 'poll')

    def test_exact_relative_boundary(self):
        rows = synthetic_rows()
        for row in rows:
            if row['arm'] == 'deadline': row['interval']['cpu_rails_mw'] = 80
        self.assertEqual(verifier.decision(rows)['selected'], 'deadline')

    def test_one_pair_outside_boundary_cannot_hide_in_mean(self):
        rows = synthetic_rows()
        select(rows, 'long', 2)['interval']['cpu_rails_mw'] = 80.001
        result = verifier.decision(rows)
        self.assertLess(result['arms']['deadline']['ratio_mean'], .8)
        self.assertIsNone(result['selected'])

    def test_equal_energy_holds(self):
        rows = synthetic_rows()
        for row in rows: row['interval']['cpu_rails_mw'] = 100
        self.assertIsNone(verifier.decision(rows)['selected'])

    def test_inconsistent_pair_advantage_holds(self):
        rows = synthetic_rows()
        select(rows, 'long', 1)['interval']['cpu_rails_mw'] = 150
        self.assertIsNone(verifier.decision(rows)['selected'])

    def test_winner_absolute_cpu_failure_does_not_choose_loser(self):
        rows = synthetic_rows()
        select(rows)['idle_failures'] = ['process_cpu']
        self.assertIsNone(verifier.decision(rows)['selected'])

    def test_both_absolute_failures_hold(self):
        rows = synthetic_rows()
        for row in rows: row['idle_failures'] = ['worker_cpu']
        self.assertIsNone(verifier.decision(rows)['selected'])

    def test_voluntary_switch_gate_holds(self):
        rows = synthetic_rows()
        select(rows)['idle_failures'] = ['voluntary_switches']
        self.assertIsNone(verifier.decision(rows)['selected'])

    def test_invalid_environment_in_non_idle_case_holds(self):
        rows = synthetic_rows()
        select(rows, 'forced-doze')['environment'] = dict(valid=False, errors=['after_thermal'])
        result = verifier.decision(rows)
        self.assertIsNone(result['selected'])
        self.assertEqual(result['environment_errors'][0]['errors'], ['after_thermal'])

    def test_pair_temperature_exact_boundary(self):
        rows = synthetic_rows()
        select(rows)['interval']['temperature_c'] = [32, 32]
        self.assertEqual(verifier.decision(rows)['selected'], 'deadline')

    def test_pair_temperature_outside_boundary(self):
        rows = synthetic_rows()
        select(rows)['interval']['temperature_c'] = [32.01, 32.01]
        self.assertIsNone(verifier.decision(rows)['selected'])

    def test_missing_idle_pair_rejected(self):
        rows = synthetic_rows()
        rows.remove(select(rows))
        with self.assertRaisesRegex(AssertionError, 'matrix'): verifier.decision(rows)

    def test_missing_non_idle_case_rejected(self):
        rows = synthetic_rows()
        rows.remove(select(rows, 'maximum'))
        with self.assertRaisesRegex(AssertionError, 'matrix'): verifier.decision(rows)

    def test_duplicate_cannot_replace_missing_pair(self):
        rows = synthetic_rows()
        rows[-1] = dict(rows[0])
        with self.assertRaisesRegex(AssertionError, 'matrix'): verifier.decision(rows)

    def test_extra_pair_rejected(self):
        rows = synthetic_rows()
        rows.append(dict(rows[0]))
        with self.assertRaisesRegex(AssertionError, 'matrix'): verifier.decision(rows)

    def test_invalid_energy_rejected(self):
        for value in (0, -1, float('nan'), float('inf')):
            with self.subTest(value=value):
                rows = synthetic_rows()
                select(rows)['interval']['cpu_rails_mw'] = value
                with self.assertRaisesRegex(AssertionError, 'energy'): verifier.decision(rows)


if __name__ == '__main__':
    unittest.main()
