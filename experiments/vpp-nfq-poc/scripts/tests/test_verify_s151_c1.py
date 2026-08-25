import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
JAVA = ROOT / "android/vpn-lite/src/main/java/com/sakamoto/snort/vpnlite/SnortVpnService.java"
NATIVE = ROOT / "android/vpn-lite/native/vpn_fd_probe.c"
OI3 = ROOT / "overlay/src/plugins/hev_external_driver_poc/owner_inline_oi3.c"


class VerifyS151C1ContractTest(unittest.TestCase):
    def test_java_network_callback_publishes_underlay_epoch(self):
        source = JAVA.read_text(encoding="utf-8")
        self.assertIn("registerNetworkCallback", source)
        self.assertIn("ConnectivityManager.NetworkCallback", source)
        self.assertIn("nativeSetVppUnderlayEpoch", source)
        self.assertIn("unregisterNetworkCallback", source)
        self.assertIn("onLost", source)
        self.assertIn("onCapabilitiesChanged", source)

    def test_native_bridges_epoch_to_oi3_cli(self):
        source = NATIVE.read_text(encoding="utf-8")
        self.assertIn("nativeSetVppUnderlayEpoch", source)
        self.assertIn("sakamoto-oi3 underlay epoch", source)
        self.assertIn("underlay epoch", source)

    def test_c2_control_seam_is_bounded(self):
        java = JAVA.read_text(encoding="utf-8")
        native = NATIVE.read_text(encoding="utf-8")
        self.assertIn("EXTRA_OI3_CONTROL", java)
        self.assertIn("nativeRunVppOi3Control", java)
        self.assertIn('strcmp(control, "show")', native)
        self.assertIn('strcmp(control, "stop")', native)
        self.assertIn('strcmp(control, "fault")', native)
        self.assertIn("sakamoto-oi3 %s", native)

    def test_oi3_invalidates_owner_on_underlay_change(self):
        source = OI3.read_text(encoding="utf-8")
        self.assertIn("oi3_underlay_epoch_command_fn", source)
        self.assertIn("underlay_invalidated", source)
        self.assertIn("EXPECTED_UNDERLAY_INVALIDATION", source)
        self.assertIn("PASS_EXPECTED_UNDERLAY_INVALIDATION", source)
        self.assertIn("epoch-invalidated", source)
        self.assertNotIn("tm->underlay_epoch = tm->generation;", source)


if __name__ == "__main__":
    unittest.main()
