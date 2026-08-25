import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / (
    "android-run-s181-b2-full-device-transport-explore.sh"
)


class S181B2FullDeviceTransportRunnerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_no_reply_cell_uses_explicit_native_expectation(self):
        self.assertIn('run_cell "no-reply-udp-dns"', self.source)
        self.assertIn('"real-no-reply"', self.source)
        self.assertIn("EXPECTED_REAL_NO_REPLY", self.source)

    def test_tcp_closed_port_cell_is_timeout_not_refusal(self):
        self.assertIn('run_cell "closed-tcp-timeout"', self.source)
        self.assertIn("tcp_timeout_port_unbound", self.source)
        self.assertIn("TCP closed-port cell is treated", self.source)
        self.assertNotIn('run_cell "refused-tcp"', self.source)
        self.assertNotIn('"real-refused"', self.source)
        self.assertNotIn("EXPECTED_REAL_TRANSPORT_REFUSAL", self.source)

    def test_tcp_timeout_requires_proxy_handshake_and_native_expected_timeout(self):
        self.assertIn('record.get("send_connect_outcome") == "tcp_connect_succeeded"', self.source)
        self.assertIn('record.get("return_outcome") == "dns_response_timeout"', self.source)
        self.assertIn('stats["ambient_timeout"] >= 1', self.source)
        self.assertIn('stats["handshake_cleanup"] >= 1', self.source)
        self.assertIn('stats["rewritten_cleanup"] >= 1', self.source)
        self.assertIn('stats["direct_cleanup"] == 0', self.source)
        self.assertIn('"EXPECTED_TIMEOUT"', self.source)

    def test_declares_bounded_non_claims(self):
        self.assertIn("not policy-drop closure", self.source)
        self.assertIn("not public internet", self.source)
        self.assertIn("not long soak/performance", self.source)


if __name__ == "__main__":
    unittest.main()
