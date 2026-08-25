import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "scripts/android-run-s184-b2-real-rst.sh"
FIXTURE = ROOT / "scripts/s184-rst-fixture.py"
BASE_RUNNER = ROOT / "scripts/android-run-s181-b2-full-device-transport-explore.sh"
PLUGIN = ROOT / "overlay/src/plugins/hev_external_driver_poc/owner_inline_oi3.c"
APP = ROOT / "android/a2-traffic-adapter/src/main/java/com/sakamoto/snort/a2traffic/TrafficAdapterActivity.java"
HEV_PATCH = ROOT / "patches/hev-owner-context-transport-event.patch"
HEV_RESET_PATCH = ROOT / "patches/hev-owner-context-downstream-reset.patch"
HEV_BUILD = ROOT / "scripts/android-build-hev-poc7.sh"


class S184B2RealRstTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wrapper = WRAPPER.read_text(encoding="utf-8")
        cls.fixture = FIXTURE.read_text(encoding="utf-8")
        cls.base_runner = BASE_RUNNER.read_text(encoding="utf-8")
        cls.plugin = PLUGIN.read_text(encoding="utf-8")
        cls.app = APP.read_text(encoding="utf-8")
        cls.hev_patch = HEV_PATCH.read_text(encoding="utf-8")
        cls.hev_reset_patch = HEV_RESET_PATCH.read_text(encoding="utf-8")
        cls.hev_build = HEV_BUILD.read_text(encoding="utf-8")

    def test_wrapper_selects_only_positive_and_real_rst_cell(self):
        self.assertIn('INCLUDE_NO_REPLY="false"', self.wrapper)
        self.assertIn('INCLUDE_TCP_TIMEOUT="true"', self.wrapper)
        self.assertIn('INCLUDE_POLICY_DROP="false"', self.wrapper)
        self.assertIn('INCLUDE_UID_DROP="false"', self.wrapper)
        self.assertIn('TCP_EXPECTED_FAILURE="real-reset"', self.wrapper)
        self.assertIn('STAGE_PREFIX="S184"', self.wrapper)
        self.assertIn("android-run-s181-b2-full-device-transport-explore.sh", self.wrapper)

    def test_wrapper_waits_for_unbound_precondition_before_rst_bind(self):
        self.assertIn("tcp_timeout_port_unbound", self.wrapper)
        self.assertIn("s184-rst-fixture.py", self.wrapper)
        self.assertIn("tcp_rst_ready", self.wrapper)
        self.assertIn("tcp_rst_connection", self.wrapper)
        self.assertIn("rst_connection_observed", self.wrapper)

    def test_fixture_emits_rst_with_zero_linger(self):
        self.assertIn("socket.SO_LINGER", self.fixture)
        self.assertIn("struct.pack(\"ii\", 1, 0)", self.fixture)
        self.assertIn('log("tcp_rst_sent"', self.fixture)

    def test_base_runner_keeps_default_transport_expectation_empty(self):
        self.assertIn('TCP_EXPECTED_FAILURE="${TCP_EXPECTED_FAILURE:-}"', self.base_runner)
        self.assertIn('"$TCP_EXPECTED_FAILURE"', self.base_runner)

    def test_hev_publishes_socket_result_on_the_owner_thread(self):
        self.assertIn("transport_event", self.hev_patch)
        self.assertIn("HEV_SOCKS5_TCP_TRANSPORT_READ_ERROR", self.hev_patch)
        self.assertIn("HEV_SOCKS5_TCP_TRANSPORT_PEER_EOF", self.hev_patch)
        self.assertIn("hev-owner-context-transport-event.patch", self.hev_build)

    def test_hev_maps_only_real_econnreset_to_owner_local_downstream_rst(self):
        self.assertIn("tcp_send_reset_ctx", self.hev_reset_patch)
        self.assertIn("TCP_RST | TCP_ACK", self.hev_reset_patch)
        self.assertIn("socket_error == ECONNRESET", self.hev_reset_patch)
        self.assertIn("pcb_reset_attempted", self.hev_reset_patch)
        self.assertIn("pcb_reset_sent", self.hev_reset_patch)
        self.assertIn("hev-owner-context-downstream-reset.patch", self.hev_build)

    def test_native_has_a_distinct_observed_reset_outcome(self):
        self.assertIn("oi3_connector_transport_event", self.plugin)
        self.assertIn("expected_real_reset", self.plugin)
        self.assertIn("connector_reset_observed", self.plugin)
        self.assertIn("connector_downstream_reset_observed", self.plugin)
        self.assertIn("downstream-transport result=RST", self.plugin)
        self.assertIn("connector_downstream_reset_observed == 1", self.plugin)
        self.assertIn("direct_send_events > 0", self.plugin)
        self.assertIn("EXPECTED_REAL_TRANSPORT_RESET", self.plugin)
        self.assertNotIn("oi3_sample_connector_event", self.plugin)
        self.assertNotIn('"post-connect-reset-eof"', self.plugin)

    def test_runner_and_app_do_not_rename_timeout_as_reset(self):
        self.assertIn("tcp_expected_failure", self.base_runner)
        self.assertIn('"real-reset"', self.base_runner)
        self.assertIn('"transport_reset"', self.base_runner)
        self.assertIn('"downstream_reset"', self.base_runner)
        self.assertIn('"dns_response_reset"', self.app)

    def test_runner_deduplicates_reset_events_mirrored_across_native_logs(self):
        self.assertIn('"transport_reset": int(re.search(', self.base_runner)
        self.assertIn('"downstream_reset": int(re.search(', self.base_runner)


if __name__ == "__main__":
    unittest.main()
