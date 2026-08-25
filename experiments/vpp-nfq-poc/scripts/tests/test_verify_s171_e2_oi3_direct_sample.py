import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/android-run-s171-e2-oi3-direct-sample.sh"
SERVICE = ROOT / "android/vpn-lite/src/main/java/com/sakamoto/snort/vpnlite/SnortVpnService.java"
ACTIVITY = ROOT / "android/vpn-lite/src/main/java/com/sakamoto/snort/vpnlite/MainActivity.java"
OWNER = ROOT / "overlay/src/plugins/hev_external_driver_poc/owner_inline_oi3.c"


class VerifyS171E2Oi3DirectSampleTest(unittest.TestCase):
    def setUp(self):
        self.runner = RUNNER.read_text(encoding="utf-8")
        self.service = SERVICE.read_text(encoding="utf-8")
        self.activity = ACTIVITY.read_text(encoding="utf-8")
        self.owner = OWNER.read_text(encoding="utf-8")

    def test_runner_explicitly_drives_oi3_multi_cleanup(self):
        self.assertIn('run_oi3_control "multi-stop"', self.runner)
        self.assertIn("wait_oi3_cleanup()", self.runner)
        self.assertIn("oi3_cleanup result=", self.runner)
        self.assertIn('cleanup-pre-stop.log', self.runner)
        self.assertIn('cleanupPass,cleanupFail,ownerBusy,tcpTailReject,multiRejectNonTail,valid',
                      self.runner)

    def test_runner_filters_validity_dumps_on_host_not_device_pipe(self):
        self.assertIn("dumpsys connectivity 2>/dev/null || true", self.runner)
        self.assertIn("NetworkAgentInfo|TRANSPORT_VPN|NOT_VPN", self.runner)
        self.assertNotIn("dumpsys connectivity | grep", self.runner)

    def test_runner_does_not_treat_tcp_tail_reject_as_owner_busy(self):
        self.assertIn("reason=owner-busy", self.runner)
        self.assertIn("reason=tcp-tail", self.runner)
        self.assertIn("multi_reject_non_tail", self.runner)
        self.assertIn('"$multi_reject_non_tail" == 0', self.runner)
        self.assertNotIn('"$multi_reject" == 0', self.runner)

    def test_l4_tcp_read_timeout_is_poc_configurable_and_recorded(self):
        self.assertIn('TCP_READ_TIMEOUT_MS="${TCP_READ_TIMEOUT_MS:-5000}"',
                      self.runner)
        self.assertIn('--ei tcpReadTimeoutMs "$TCP_READ_TIMEOUT_MS"', self.runner)
        self.assertIn('"tcpReadTimeoutMs":$TCP_READ_TIMEOUT_MS', self.runner)
        self.assertIn('EXTRA_TCP_READ_TIMEOUT_MS = "tcpReadTimeoutMs"', self.service)
        self.assertIn("TCP_READ_TIMEOUT_MS = 1000", self.service)
        self.assertIn("config.tcpReadTimeoutMs", self.service)
        self.assertIn("tcp.setSoTimeout(config.tcpReadTimeoutMs)", self.service)
        self.assertIn("tcpReadTimeoutMs=\" + config.tcpReadTimeoutMs", self.service)
        self.assertIn("SnortVpnService.EXTRA_TCP_READ_TIMEOUT_MS", self.activity)

    def test_oi3_multi_tcp_deadline_is_refreshed_by_activity(self):
        self.assertIn("oi3_refresh_tun_flow_deadline", self.owner)
        self.assertIn("tm->protocol == 17 || tm->protocol == 6", self.owner)
        self.assertIn("if (tm->protocol == 6 && (tcp_flags & 0x05U))",
                      self.owner)
        self.assertIn("if (flags & 0x05U)", self.owner)
        self.assertGreaterEqual(self.owner.count("oi3_refresh_tun_flow_deadline (tm)"),
                                4)

    def test_oi3_multi_tcp_fin_complete_stops_before_poll_rearm(self):
        self.assertIn("oi3_tcp_positive_fin_complete", self.owner)
        self.assertIn("tm->tcp_fin_submitted", self.owner)
        self.assertIn("tm->output_direct != 0", self.owner)
        self.assertIn("tm->return_rewritten != 0", self.owner)
        self.assertIn("!result.running_task_count", self.owner)
        self.assertIn("oi3 tcp-positive-fin-complete", self.owner)
        self.assertIn("tm->phase = OI3_STOPPING;", self.owner)
        self.assertIn("tm->finish_requested = 1;", self.owner)


if __name__ == "__main__":
    unittest.main()
