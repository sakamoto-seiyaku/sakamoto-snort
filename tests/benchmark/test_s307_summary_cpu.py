"""CPU schema compatibility keeps raw tick accounting and interval checks strict."""
import copy
import json
import unittest

import pixel_quick as quick
import s307_summary as summary


class CpuSummaryCompatibility(unittest.TestCase):
    def setUp(self):
        self.client = dict(start_monotonic_ns=100, end_monotonic_ns=400)
        self.raw = '\n'.join(json.dumps(dict(monotonic_ns=t, clock_ticks=100,
            page_size=4096, threads=[dict(tid=7, utime=u, stime=0, rss_pages=2, last_cpu=3)]))
            for t, u in ((50, 1), (150, 3), (350, 9), (450, 10)))

    def test_historical_schema_matches_without_extra_fields(self):
        recorded = quick.monitor_summary(self.raw, self.client)
        self.assertNotIn('begin_monotonic_ns', recorded)
        self.assertEqual(summary.verify_cpu_summary(self.raw, self.client, recorded), recorded)

    def test_new_schema_verifies_both_exact_sample_endpoints(self):
        recorded = quick.monitor_summary(self.raw, self.client, include_interval=True)
        self.assertEqual((recorded['begin_monotonic_ns'], recorded['end_monotonic_ns']), (150, 350))
        self.assertEqual(summary.verify_cpu_summary(self.raw, self.client, recorded), recorded)
        for key in ('begin_monotonic_ns', 'end_monotonic_ns'):
            changed = copy.deepcopy(recorded)
            changed[key] += 1
            with self.assertRaises(AssertionError):
                summary.verify_cpu_summary(self.raw, self.client, changed)
            del changed[key]
            with self.assertRaises(AssertionError):
                summary.verify_cpu_summary(self.raw, self.client, changed)

    def test_original_cpu_evidence_cannot_be_ignored(self):
        for metadata in (False, True):
            recorded = quick.monitor_summary(self.raw, self.client, include_interval=metadata)
            for field in ('cpu_seconds', 'sample_coverage_seconds', 'rss_peak_bytes'):
                changed = copy.deepcopy(recorded)
                changed[field] += 1
                with self.assertRaises(AssertionError):
                    summary.verify_cpu_summary(self.raw, self.client, changed)
            recorded['threads'][0]['cpu_seconds'] += 1
            with self.assertRaises(AssertionError):
                summary.verify_cpu_summary(self.raw, self.client, recorded)


if __name__ == '__main__':
    unittest.main()
