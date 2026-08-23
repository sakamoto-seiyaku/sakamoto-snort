import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "verify-s139-a2-6.py"
SPEC = importlib.util.spec_from_file_location("verify_s139_a2_6", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VERIFIER)


class VerifyA26Tests(unittest.TestCase):
    def test_replay_assertion_parses_case_and_state(self):
        record = {
            "schema": "uid-attribution-contract/v1",
            "outcome": "REPLAY_ASSERTION",
            "stage_id": "A2-6-replay",
            "reason": (
                "case=accepted;outcome=COMPLETION_ACCEPTED;pending-before=1;"
                "pending-after=0;cache-before=2;cache-after=3;unchanged=false"
            ),
        }
        parsed = VERIFIER.replay_assertion(record)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed["case"], "accepted")
        self.assertEqual(parsed["outcome"], "COMPLETION_ACCEPTED")
        self.assertEqual(parsed["pending-before"], 1)
        self.assertFalse(parsed["unchanged"])

    def test_cleanup_reason_records_zero_residue_and_high_water(self):
        records = [{
            "outcome": "CLEANUP",
            "reason": "pending=0;cache=0;max-pending=4;max-cache=4;"
                      "flow-ids=0;max-flow-ids=8",
        }]
        self.assertEqual(
            VERIFIER.parse_cleanup_reason(records),
            [{"pending": 0, "cache": 0, "max_pending": 4,
              "max_cache": 4, "flow_ids": 0, "max_flow_ids": 8}],
        )

    def test_wrong_uid_case_is_not_marked_unchanged(self):
        record = {
            "outcome": "REPLAY_ASSERTION",
            "reason": (
                "case=wrong-uid;outcome=COMPLETION_WRONG_UID;pending-before=1;"
                "pending-after=0;cache-before=0;cache-after=0;unchanged=false"
            ),
        }
        parsed = VERIFIER.replay_assertion(record)
        assert parsed is not None
        expected_outcome, expected_unchanged = VERIFIER.EXPECTED_REPLAY["wrong-uid"]
        self.assertEqual(parsed["outcome"], expected_outcome)
        self.assertEqual(parsed["unchanged"], expected_unchanged)


if __name__ == "__main__":
    unittest.main()
