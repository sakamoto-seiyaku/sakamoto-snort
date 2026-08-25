import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/android-run-s180-b1-dns-fallback.sh"
APP = ROOT / (
    "android/a2-traffic-adapter/src/main/java/com/sakamoto/snort/a2traffic/"
    "TrafficAdapterActivity.java"
)


class S180B1DnsFallbackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = RUNNER.read_text(encoding="utf-8")
        cls.app = APP.read_text(encoding="utf-8")

    def test_app_fallback_is_explicit_and_truncated_only(self):
        self.assertIn("b1FallbackTcpOnTruncated", self.app)
        self.assertIn("dnsResponseTruncated", self.app)
        self.assertIn("fallbackTcpOnTruncated requires udp protocol", self.app)
        self.assertIn("fallbackTcpOnTruncated requires DNS probe", self.app)
        self.assertIn("dns_tcp_fallback_response_received", self.app)

    def test_app_records_fallback_evidence_fields(self):
        for field in [
            "fallback_tcp_on_truncated",
            "fallback_source_port",
            "fallback_attempted",
            "fallback_reason",
            "fallback_return_outcome",
            "udp_truncated",
            "tcp_response_valid",
        ]:
            self.assertIn(field, self.app)

    def test_runner_uses_fixture_and_rejects_independent_requests(self):
        self.assertIn("udp_truncated_response", self.runner)
        self.assertIn("tcp_full_response", self.runner)
        self.assertIn("same_query_id", self.runner)
        self.assertIn("Independent UDP/TCP cells are not", self.runner)

    def test_runner_requires_app_fixture_native_and_residue_evidence(self):
        self.assertIn("app_valid", self.runner)
        self.assertIn("fixture_valid", self.runner)
        self.assertIn("native_valid", self.runner)
        self.assertIn('if [[ "$tun0_text" == *"tun0:"* ]]; then', self.runner)


if __name__ == "__main__":
    unittest.main()
