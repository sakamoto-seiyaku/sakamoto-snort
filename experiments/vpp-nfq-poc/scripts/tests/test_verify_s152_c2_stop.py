import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OI3 = ROOT / "overlay/src/plugins/hev_external_driver_poc/owner_inline_oi3.c"


class VerifyS152C2StopContractTest(unittest.TestCase):
    def setUp(self):
        self.source = OI3.read_text(encoding="utf-8")

    def test_normal_stop_has_distinct_state_and_terminal_outcome(self):
        self.assertIn("normal_stop_requested", self.source)
        self.assertIn('return "EXPECTED_STOP"', self.source)
        self.assertIn('"PASS_EXPECTED_STOP"', self.source)
        self.assertIn("normal-stop-requested=%u", self.source)

    def test_stop_marks_reason_before_owner_token(self):
        marker = "oi3_main.normal_stop_requested = 1;"
        enqueue = "(void)oi3_enqueue_owner (vm, 0);"
        start = self.source.index("oi3_stop_command_fn")
        end = self.source.index("VLIB_CLI_COMMAND (oi3_stop_command", start)
        stop = self.source[start:end]
        self.assertIn(marker, stop)
        self.assertLess(stop.index(marker), stop.index(enqueue))

    def test_positive_tun_reply_gate_does_not_override_explicit_stop(self):
        self.assertIn("!tm->underlay_invalidated", self.source)
        self.assertIn("!tm->normal_stop_requested", self.source)
        self.assertIn("tm->normal_stop_requested ||", self.source)

    def test_normal_stop_preserves_resource_failure_signals(self):
        self.assertIn("unexpected-normal-stop", self.source)
        self.assertIn("tm->broker_duplicate_closes != 0", self.source)
        self.assertIn("tm->infrastructure_failures != 0", self.source)


if __name__ == "__main__":
    unittest.main()
