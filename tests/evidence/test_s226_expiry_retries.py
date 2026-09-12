#!/usr/bin/env python3
"""Synthetic checks for registered invalid-pair retries, not device evidence."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('decision_tests', ROOT/'tests/evidence/test_s226_expiry_decision.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
verifier = fixtures.verifier


def base_run():
    rows = fixtures.synthetic_rows()
    for index, row in enumerate(rows): row['generation'] = 22610+index
    return dict(platform='pixel', status='FUNCTIONAL_PASS', matrix_complete=True,
        outcomes=rows, run='/base', run_result_sha256='original', source_sha256='source',
        build_sha256='build', helpers_sha256='helpers', started_ns=100, completed_ns=200)


def invalidate(run, name='screen-off', repetition=0):
    for row in run['outcomes']:
        if row['case'] == name and row['repetition'] == repetition:
            row['environment'] = dict(valid=False, errors=['before_screen'])


def retry_run(number=1, name='screen-off', repetition=0):
    run = base_run()
    run.update(run='/retry-'+str(number), run_result_sha256='retry-'+str(number),
        started_ns=200+number*100, completed_ns=250+number*100,
        status='VALID_PARTIAL', matrix_complete=False)
    run['outcomes'] = [r for r in run['outcomes'] if r['case'] == name and r['repetition'] == repetition]
    for index, row in enumerate(run['outcomes']): row['generation'] = 23000+number*10+index
    return run


class RetryTests(unittest.TestCase):
    def test_replace_only_invalid_pair_preserving_original(self):
        base, retry = base_run(), retry_run()
        invalidate(base)
        original = copy.deepcopy(base)
        result = verifier.combine_retries(base, [retry])
        self.assertEqual(base, original)
        self.assertEqual(result['comparison']['selected'], 'deadline')
        self.assertEqual(len(result['outcomes']), 42)
        self.assertEqual(len(result['retry_history']), 1)
        self.assertEqual(result['retry_history'][0]['attempt'], 1)
        self.assertEqual(sum(r['evidence_run'] == '/retry-1' for r in result['outcomes']), 2)
        self.assertEqual(sum(r['evidence_run'] == '/base' for r in result['outcomes']), 40)

    def test_cannot_retry_valid_pair_for_better_results(self):
        with self.assertRaisesRegex(AssertionError, 'valid pair'):
            verifier.combine_retries(base_run(), [retry_run()])

    def test_one_invalid_arm_still_requires_both_arms(self):
        base, retry = base_run(), retry_run()
        invalidate(base)
        retry['outcomes'].pop()
        with self.assertRaisesRegex(AssertionError, 'complete pair'):
            verifier.combine_retries(base, [retry])

    def test_duplicate_retry_arm_rejected(self):
        base, retry = base_run(), retry_run()
        invalidate(base)
        retry['outcomes'].append(copy.deepcopy(retry['outcomes'][0]))
        with self.assertRaises(AssertionError): verifier.combine_retries(base, [retry])

    def test_artifact_helper_and_source_must_match(self):
        for field in ('source_sha256', 'build_sha256', 'helpers_sha256'):
            with self.subTest(field=field):
                base, retry = base_run(), retry_run()
                invalidate(base)
                retry[field] = 'different'
                with self.assertRaisesRegex(AssertionError, 'lineage'):
                    verifier.combine_retries(base, [retry])

    def test_retry_must_follow_previous_run(self):
        base, retry = base_run(), retry_run()
        invalidate(base)
        retry['started_ns'] = 150
        with self.assertRaisesRegex(AssertionError, 'ordering'):
            verifier.combine_retries(base, [retry])

    def test_generation_cannot_be_reused_across_attempts(self):
        base, retry = base_run(), retry_run()
        invalidate(base)
        retry['outcomes'][0]['generation'] = base['outcomes'][0]['generation']
        with self.assertRaisesRegex(AssertionError, 'generation'):
            verifier.combine_retries(base, [retry])

    def test_second_retry_allowed_only_after_another_invalid_pair(self):
        base, first, second = base_run(), retry_run(1), retry_run(2)
        invalidate(base)
        invalidate(first)
        result = verifier.combine_retries(base, [first, second])
        self.assertEqual(result['comparison']['selected'], 'deadline')
        self.assertEqual([r['attempt'] for r in result['retry_history']], [1, 2])
        self.assertEqual(len(result['evidence_runs']), 3)

    def test_third_retry_rejected_even_if_successful(self):
        base, first, second = base_run(), retry_run(1), retry_run(2)
        for run in (base, first, second): invalidate(run)
        with self.assertRaisesRegex(AssertionError, 'two retries'):
            verifier.combine_retries(base, [first, second, retry_run(3)])

    def test_still_invalid_retry_holds(self):
        base, retry = base_run(), retry_run()
        invalidate(base)
        invalidate(retry)
        self.assertIsNone(verifier.combine_retries(base, [retry])['comparison']['selected'])

    def test_incomplete_baseline_rejected(self):
        base = base_run()
        base['matrix_complete'] = False
        with self.assertRaisesRegex(AssertionError, 'complete original'):
            verifier.combine_retries(base, [retry_run()])

    def test_non_idle_pair_temperature_gate_is_not_waived(self):
        base = base_run()
        fixtures.select(base['outcomes'], 'screen-off')['interval']['temperature_c'] = [33, 33]
        self.assertIsNone(verifier.decision(base['outcomes'])['selected'])
        self.assertEqual(verifier.combine_retries(base, [retry_run()])['comparison']['selected'], 'deadline')


if __name__ == '__main__':
    unittest.main()
