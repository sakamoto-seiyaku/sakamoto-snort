import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/android-run-s181-b2-full-device-transport-explore.sh"
WRAPPER = ROOT / "scripts/android-run-s182-b2-real-policy-drop.sh"
PLUGIN = ROOT / "overlay/src/plugins/hev_external_driver_poc/owner_inline_oi3.c"
NATIVE = ROOT / "android/vpn-lite/native/vpn_fd_probe.c"


class S182B2RealPolicyDropTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = RUNNER.read_text(encoding="utf-8")
        cls.wrapper = WRAPPER.read_text(encoding="utf-8")
        cls.plugin = PLUGIN.read_text(encoding="utf-8")
        cls.native = NATIVE.read_text(encoding="utf-8")

    def test_wrapper_enables_policy_drop_without_renaming_s181(self):
        self.assertIn("INCLUDE_POLICY_DROP", self.wrapper)
        self.assertIn('INCLUDE_NO_REPLY="${INCLUDE_NO_REPLY:-false}"', self.wrapper)
        self.assertIn('INCLUDE_TCP_TIMEOUT="${INCLUDE_TCP_TIMEOUT:-false}"', self.wrapper)
        self.assertIn("s182-b2-real-policy-drop", self.wrapper)
        self.assertIn("android-run-s181-b2-full-device-transport-explore.sh", self.wrapper)

    def test_runner_policy_drop_cell_is_optional_and_no_transport(self):
        self.assertIn('INCLUDE_POLICY_DROP="${INCLUDE_POLICY_DROP:-false}"', self.runner)
        self.assertIn('run_cell "policy-drop-udp-dns"', self.runner)
        self.assertIn("dispatcher target itself is the policy expectation", self.runner)
        self.assertIn('--es blockIp4Dst "$block_ip4_dst"', self.runner)
        self.assertIn('"policy_drop_udp_ready"', self.runner)
        self.assertIn('not any(e.get("event") == "policy_drop_udp_query"', self.runner)
        self.assertIn('stats["broker_success"] == 0', self.runner)
        self.assertIn('stats["direct_send"] == 0', self.runner)
        self.assertIn('"EXPECTED_REAL_POLICY_DROP"', self.runner)

    def test_native_passes_block_ip_to_oi3_multi_only(self):
        self.assertIn("use_oi3_multi && block_dst", self.native)
        self.assertIn("SAKAMOTO_OI3_POLICY_DROP_IP4", self.native)
        self.assertIn("unsetenv(\"SAKAMOTO_OI3_POLICY_DROP_IP4\")", self.native)

    def test_plugin_drops_before_broker_socket_path(self):
        self.assertIn("SAKAMOTO_OI3_POLICY_DROP_IP4", self.plugin)
        self.assertIn("oi4 multi-policy-drop result=DROP", self.plugin)
        self.assertIn("no-transport=1 broker=0 socket=0", self.plugin)
        self.assertIn("EXPECTED_REAL_POLICY_DROP", self.plugin)
        self.assertIn("PASS_EXPECTED_REAL_POLICY_DROP", self.plugin)

    def test_plugin_policy_filter_is_before_owner_lookup(self):
        read_ready = self.plugin.index("oi3_multi_tun_read_ready")
        body = self.plugin[read_ready:]
        drop = body.index("if (oi3_multi_should_policy_drop")
        owner = body.index("oi3_multi_owner_for_packet")
        self.assertLess(drop, owner)
        self.assertIn("stage=pre-owner", body)
        self.assertNotIn("oi3_enqueue_tun_packet_for", body[drop:body.index("uint32_t active_valid", drop)])
        self.assertNotIn("oi3_enqueue_owner_for", body[drop:body.index("uint32_t active_valid", drop)])
        self.assertNotIn("oi3_parse_tun_packet", body[drop:body.index("uint32_t active_valid", drop)])


if __name__ == "__main__":
    unittest.main()
