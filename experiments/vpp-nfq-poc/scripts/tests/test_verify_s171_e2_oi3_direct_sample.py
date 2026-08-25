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

    def test_oi3_multi_connector_wake_runs_on_owner_thread(self):
        self.assertIn("current_thread == tm->target_thread", self.owner)
        self.assertIn("oi3_worker_run_for (vm, NULL, 0, tm);", self.owner)
        self.assertIn("tm->target_thread < vlib_get_n_threads ()", self.owner)
        self.assertIn("? tm->target_thread : 0", self.owner)
        self.assertIn("current-thread=%u target-thread=%u", self.owner)

    def test_oi3_multi_tcp_payload_submit_is_logged_for_timing_diagnosis(self):
        self.assertIn("oi3_tun_packet_tcp_payload_length", self.owner)
        self.assertIn("tcp-payload=%zu", self.owner)
        self.assertIn("tcp_payload_length", self.owner)
        self.assertNotIn("oi3 tcp-payload-kick", self.owner)

    def test_oi3_multi_connector_poll_includes_write_interest_after_tcp_payload(self):
        self.assertIn("connector_write_pending", self.owner)
        self.assertIn("tcp_payload_length > 0", self.owner)
        self.assertIn("tm->direct_send_events == 0", self.owner)
        self.assertIn("p.events |= POLLOUT;", self.owner)
        self.assertIn("token.reserved", self.owner)
        self.assertIn("revents=0x%x", self.owner)
        self.assertIn("atomic_store_explicit (&tm->connector_write_pending, 0",
                      self.owner)

    def test_oi3_multi_tun_handoff_uses_owner_thread_fd_not_frame_queue(self):
        self.assertIn("tun_handoff_pair", self.owner)
        self.assertIn("SOCK_SEQPACKET", self.owner)
        self.assertIn("oi3_tun_handoff_ready", self.owner)
        self.assertIn("file.polling_thread_index = tm->target_thread",
                      self.owner)
        self.assertIn("oi3_send_tun_handoff_for", self.owner)
        self.assertIn("oi3_owner_accept_tun_packet", self.owner)
        self.assertIn("handoff=owner-fd", self.owner)
        self.assertIn("oi3 tun-handoff recv", self.owner)
        self.assertIn("oi3_multi_dispatch_depth_complete", self.owner)
        self.assertNotIn("oi3_wake_owner_thread", self.owner)

    def test_oi3_multi_broker_completion_is_handed_to_owner_thread(self):
        self.assertIn("completion_poll_thread", self.owner)
        self.assertIn("oi3_multi_completion_poll_main", self.owner)
        self.assertIn("oi3_send_completion_handoff_for", self.owner)
        self.assertIn("OI3_BROKER_COMPLETION_KIND", self.owner)
        self.assertIn("oi3_owner_accept_broker_completion", self.owner)
        self.assertIn("oi4 completion-handoff send", self.owner)
        self.assertIn("oi3 broker-completion wall-ms", self.owner)
        self.assertIn("oi3_multi_completion_poll_stop", self.owner)

    def test_oi3_underlay_tcp_disables_nagle_for_latency_probe(self):
        self.assertIn("#include <netinet/tcp.h>", self.owner)
        self.assertIn("TCP_NODELAY", self.owner)
        self.assertIn("oi3 connector-socket-option", self.owner)

    def test_oi3_post_send_readiness_observer_arms_while_task_running(self):
        self.assertIn("oi3_connector_poll_arm_after_direct_send", self.owner)
        self.assertIn("direct_send_events == 0", self.owner)
        self.assertIn("direct_recv_events != 0", self.owner)
        self.assertIn("connector-poll-arm-after-direct-send", self.owner)
        self.assertIn("OI3 connector post-send readiness arm failed",
                      self.owner)


if __name__ == "__main__":
    unittest.main()
