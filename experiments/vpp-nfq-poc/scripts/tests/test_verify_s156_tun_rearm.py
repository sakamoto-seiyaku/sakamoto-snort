import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OI3 = ROOT / "overlay/src/plugins/hev_external_driver_poc/owner_inline_oi3.c"


class VerifyS156TunRearmContractTest(unittest.TestCase):
    def setUp(self):
        self.source = OI3.read_text(encoding="utf-8")

    def test_successful_flow_keeps_session_resources(self):
        self.assertIn("static void\noi3_rearm_tun_flow", self.source)
        self.assertIn("bool keep_tun;", self.source)
        self.assertIn("!keep_tun && tm->tun_file_index >= 0", self.source)
        self.assertIn("!tm->multi_mode && tm->tun_fd >= 0", self.source)
        self.assertIn("if (keep_tun)\n    oi3_rearm_tun_flow (vm, tm);",
                      self.source)

    def test_rearm_starts_fresh_generation(self):
        self.assertIn("tm->finish_requested = 0;", self.source)
        self.assertIn("tm->phase = OI3_DONE;", self.source)
        self.assertIn("tm->tun_flow_count++;", self.source)
        self.assertIn("tm->generation++;", self.source)
        self.assertIn("tm->completion_file_index = -1;", self.source)

    def test_idle_tun_read_is_single_packet_and_terminal_read_is_blocked(self):
        self.assertIn("!tm->active || tm->finish_requested", self.source)
        self.assertIn("tm->phase == OI3_STOPPING || tm->phase == OI3_FAULT", self.source)
        self.assertIn(
            "unsigned int limit = (tm->context || tm->tun_pending_count) ? 8U : 1U",
            self.source,
        )

    def test_idle_fault_closes_rearmed_session(self):
        start = self.source.index("oi3_fault_command_fn")
        end = self.source.index("VLIB_CLI_COMMAND (oi3_fault_command", start)
        fault = self.source[start:end]
        self.assertIn("else if (oi3_main.tun_mode)", fault)
        self.assertIn("oi3_finish (vm);", fault)

    def test_fault_is_not_misclassified_by_positive_output_gate(self):
        self.assertIn(
            "!tm->fault_injected && !tm->underlay_invalidated",
            self.source,
        )


if __name__ == "__main__":
    unittest.main()
