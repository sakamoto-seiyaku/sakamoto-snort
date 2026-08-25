import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OI3 = ROOT / "overlay/src/plugins/hev_external_driver_poc/owner_inline_oi3.c"
DEFERRED_STOP = ROOT / "patches/hev-owner-context-deferred-stop.patch"
DESTROY_GUARD = ROOT / "patches/hev-owner-context-destroy-guard.patch"
UDP_CONNECTOR = ROOT / "patches/hev-owner-context-udp-connector-persistent.patch"
SERVICE = ROOT / "android/vpn-lite/src/main/java/com/sakamoto/snort/vpnlite/SnortVpnService.java"
MAIN_ACTIVITY = ROOT / "android/vpn-lite/src/main/java/com/sakamoto/snort/vpnlite/MainActivity.java"
HEV_POC7_BUILDER = ROOT / "scripts/android-build-hev-poc7.sh"
S125_RUNNER = ROOT / "scripts/android-run-s125-poc7.sh"
S125_PARSER = ROOT / "scripts/s125-parse-results.py"
S169_DOC = ROOT / "S169_UDP_PERSISTENT_CONNECTOR_AND_CAPACITY_EXECUTION.md"
LEDGER = ROOT / "POC_FINDING_LEDGER.md"


def load_s125_parser():
    spec = importlib.util.spec_from_file_location("s125_parse_results",
                                                  S125_PARSER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VerifyS168OwnerTeardownLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.oi3 = OI3.read_text(encoding="utf-8")
        self.deferred_stop = DEFERRED_STOP.read_text(encoding="utf-8")
        self.destroy_guard = DESTROY_GUARD.read_text(encoding="utf-8")
        self.udp_connector = UDP_CONNECTOR.read_text(encoding="utf-8")
        self.service = SERVICE.read_text(encoding="utf-8")
        self.main_activity = MAIN_ACTIVITY.read_text(encoding="utf-8")
        self.hev_poc7_builder = HEV_POC7_BUILDER.read_text(encoding="utf-8")
        self.s125_runner = S125_RUNNER.read_text(encoding="utf-8")
        self.s125_parser = S125_PARSER.read_text(encoding="utf-8")
        self.s169_doc = S169_DOC.read_text(encoding="utf-8")
        self.ledger = LEDGER.read_text(encoding="utf-8")

    def test_oi3_must_not_destroy_until_owner_stop_is_ready(self):
        start = self.oi3.index("static void\noi3_finish_for")
        end = self.oi3.index("static void\noi3_finish (", start)
        finish = self.oi3[start:end]
        self.assertIn("oi3_stop_context_for", finish)
        self.assertIn("OI3_OWNER_STOP_READY", finish)
        self.assertIn("OI3_OWNER_STOP_PENDING", finish)
        self.assertLess(finish.index("oi3_stop_context_for"),
                        finish.index("tm->api.destroy"))

    def test_hev_destroy_must_preserve_context_when_stop_is_not_ready(self):
        self.assertIn("if (flow_stack_owner_stop(context) != FLOW_STACK_OWNER_OK)",
                      self.destroy_guard)
        self.assertIn("return;", self.destroy_guard)

    def test_hev_udp_connector_must_not_be_one_shot(self):
        self.assertIn("External-driver UDP direct egress is a flow/window",
                      self.udp_connector)
        self.assertIn("return 0;", self.udp_connector)
        self.assertIn("One protected UDP response completes one datagram",
                      self.udp_connector)
        self.assertIn("return 1;", self.udp_connector)
        self.assertIn("hev-owner-context-udp-connector-persistent.patch",
                      self.hev_poc7_builder)
        self.assertIn("UDP connector persistent-session seam was not applied",
                      self.hev_poc7_builder)

    def test_multi_owner_finish_must_run_on_owner_thread(self):
        finish_start = self.oi3.index("static void\noi3_finish_for")
        finish_end = self.oi3.index("static void\noi3_finish (", finish_start)
        finish = self.oi3[finish_start:finish_end]
        helper_start = self.oi3.index("oi3_defer_finish_to_owner_thread")
        helper_end = self.oi3.index("static void\noi3_finish_for", helper_start)
        helper = self.oi3[helper_start:helper_end]

        self.assertIn("oi3_defer_finish_to_owner_thread", finish)
        self.assertLess(finish.index("oi3_defer_finish_to_owner_thread"),
                        finish.index("oi3_stop_context_for"))
        self.assertIn("vlib_get_thread_index", helper)
        self.assertIn("tm->target_thread", helper)
        self.assertIn("oi3_enqueue_owner_for", helper)

    def test_multi_owner_worker_tail_does_not_finish_foreign_owner(self):
        worker_start = self.oi3.index("VLIB_NODE_FN (oi3_worker_node)")
        worker_end = self.oi3.index("VLIB_NODE_FN (oi3_trigger_node)",
                                    worker_start)
        worker = self.oi3[worker_start:worker_end]
        tail_start = worker.index("if (oi3_multi.active) {",
                                  worker.index("!oi3_multi.active"))
        tail = worker[tail_start:]

        self.assertIn("current_thread", tail)
        self.assertIn("owner_tm->target_thread == current_thread", tail)
        self.assertIn("oi3_enqueue_owner_for (owner_tm, vm, 0)", tail)

    def test_oi3_tun_return_rewrite_restores_original_app_source(self):
        parse_start = self.oi3.index("oi3_parse_tun_packet")
        parse_end = self.oi3.index("static void\noi3_prepare_underlay_address",
                                   parse_start)
        parse = self.oi3[parse_start:parse_end]
        rewrite_start = self.oi3.index("oi3_rewrite_return")
        rewrite_end = self.oi3.index("static void\noi3_output", rewrite_start)
        rewrite = self.oi3[rewrite_start:rewrite_end]

        self.assertIn("source_address", self.oi3)
        self.assertIn("source_port", self.oi3)
        self.assertIn("memcpy (&s->sin_addr, packet + 12", parse)
        self.assertIn("packet[ihl] << 8", parse)
        self.assertIn("memcpy (&s6->sin6_addr, packet + 8", parse)
        self.assertIn("packet[40] << 8", parse)
        self.assertIn("memcpy (tm->last_output + 16, &s->sin_addr, 4)",
                      rewrite)
        self.assertIn("l4[2] = source_port >> 8", rewrite)
        self.assertIn("l4[3] = source_port", rewrite)
        self.assertIn("memcpy (tm->last_output + 24, &s6->sin6_addr, 16)",
                      rewrite)

    def test_oi3_rearm_preserves_pending_tun_packets(self):
        rearm_start = self.oi3.index("static void\noi3_rearm_tun_flow")
        rearm_end = self.oi3.index("static void\noi3_stop_context_for",
                                   rearm_start)
        rearm = self.oi3[rearm_start:rearm_end]

        self.assertIn("tm->tun_pending_count != 0", rearm)
        self.assertIn("oi3_enqueue_owner_for (tm, vm, 0)", rearm)
        self.assertNotIn("tm->tun_pending_head = 0", rearm)
        self.assertNotIn("tm->tun_pending_count = 0", rearm)
        self.assertNotIn("memset (tm->tun_pending", rearm)

    def test_oi3_multi_udp_uses_per_datagram_inflight_guard(self):
        step_start = self.oi3.index("oi3_worker_run_for")
        step_end = self.oi3.index("VLIB_NODE_FN (oi3_worker_node)",
                                  step_start)
        step = self.oi3[step_start:step_end]
        submit_start = self.oi3.index("oi3_submit_pending_tun")
        submit_end = self.oi3.index("static clib_error_t *\noi3_tun_read_ready",
                                    submit_start)
        submit = self.oi3[submit_start:submit_end]
        output_start = self.oi3.index("oi3_output")
        output_end = self.oi3.index("static void\noi3_recv", output_start)
        output = self.oi3[output_start:output_end]

        self.assertIn("tm->multi_mode && tm->protocol == 17", step)
        self.assertIn("udp_datagram_inflight", self.oi3)
        self.assertIn("oi3_submit_next_udp_datagram_if_idle", step)
        self.assertIn("cumulative ledger; udp_datagram_inflight", step)
        self.assertIn("reason=udp-datagram-inflight", submit)
        self.assertIn("tun-udp-window submit-next", submit)
        self.assertIn("tun-udp-window complete", output)
        self.assertIn("tun-udp-window idle", step)
        self.assertIn("OI3 TUN UDP packet submit failed", step)
        self.assertNotIn("tm->packet_submitted != 0", step)
        self.assertNotIn("reason=udp-generation-busy", step)

    def test_oi4_multi_capacity_is_four_owner_capable(self):
        self.assertIn("OI3_MULTI_OWNER_CAPACITY 4U", self.oi3)
        self.assertIn("target-thread-c", self.oi3)
        self.assertIn("target-thread-d", self.oi3)
        self.assertIn("owners[OI3_MULTI_OWNER_CAPACITY]", self.oi3)
        self.assertIn("route=%u/%u/%u/%u", self.oi3)
        self.assertIn("reject=%u/%u/%u/%u", self.oi3)
        self.assertIn("target-thread-c 3", self.s169_doc)
        self.assertIn("127931250090287", self.s169_doc)
        self.assertIn("zero `owner-busy`", self.s169_doc)
        self.assertIn("CLOSED_FOR_FOUR_OWNER_UDP_CLOSED_ECHO", self.ledger)
        self.assertIn("VPN-F046", self.ledger)
        self.assertNotIn("OPEN_DESIGN_REQUIRED_MULTI_FLOW_CAPACITY",
                         self.ledger)

    def test_l4_udp_stress_source_ports_are_runner_configurable(self):
        self.assertIn('EXTRA_SOURCE_PORT_BASE = "sourcePortBase"', self.service)
        self.assertIn('EXTRA_UDP_CLOSED_TIMEOUT_MS = "udpClosedTimeoutMs"',
                      self.service)
        self.assertIn('EXTRA_UDP_SATURATING_TIMEOUT_MS =',
                      self.service)
        self.assertIn("getIntExtra(EXTRA_SOURCE_PORT_BASE", self.service)
        self.assertIn("getIntExtra(EXTRA_UDP_CLOSED_TIMEOUT_MS",
                      self.service)
        self.assertIn("config.udpClosedTimeoutMs", self.service)
        self.assertIn("65535 - normalizedFlows", self.service)
        self.assertIn("sourcePortBase=",
                      self.service[self.service.index("runL4StressProbe"):])
        self.assertIn("config.sourcePortBase + flow", self.service)
        self.assertNotIn('"tcp".equals(config.protocol) ? 41000 : 40000',
                         self.service)
        self.assertIn("copyIntExtra(source, serviceIntent,"
                      " SnortVpnService.EXTRA_SOURCE_PORT_BASE)",
                      self.main_activity)
        self.assertIn("copyIntExtra(source, serviceIntent,"
                      " SnortVpnService.EXTRA_UDP_CLOSED_TIMEOUT_MS)",
                      self.main_activity)

    def test_l4_stress_source_port_base_reaches_formal_runner_and_parser(self):
        self.assertIn('UDP_SOURCE_PORT_BASE="${UDP_SOURCE_PORT_BASE:-43000}"',
                      self.s125_runner)
        self.assertIn('TCP_SOURCE_PORT_BASE="${TCP_SOURCE_PORT_BASE:-44000}"',
                      self.s125_runner)
        self.assertIn('UDP_CLOSED_TIMEOUT_MS="${UDP_CLOSED_TIMEOUT_MS:-1000}"',
                      self.s125_runner)
        self.assertIn("--ei udpClosedTimeoutMs \"$UDP_CLOSED_TIMEOUT_MS\"",
                      self.s125_runner)
        self.assertIn("validate_source_port_base \"$UDP_SOURCE_PORT_BASE\"",
                      self.s125_runner)
        self.assertIn("--ei sourcePortBase \"$source_port_base\"",
                      self.s125_runner)
        self.assertIn('"sourcePortBase":%d', self.s125_runner)
        self.assertIn('"udpSourcePortBase":%d', self.s125_runner)
        self.assertIn('"tcpSourcePortBase":%d', self.s125_runner)
        self.assertIn('"udpClosedTimeoutMs":%d', self.s125_runner)
        self.assertIn('expected_port_base = manifest.get("sourcePortBase")',
                      self.s125_parser)
        self.assertIn('"sourcePortBase", "burst"', self.s125_parser)

    def test_s125_parser_accepts_manifest_configured_udp_source_port_base(self):
        parser = load_s125_parser()
        with tempfile.TemporaryDirectory() as tmp:
            cell = Path(tmp)
            (cell / "manifest.json").write_text(json.dumps({
                "schema": "s125-poc7/v2",
                "label": "source-port-base-regression",
                "arm": "full",
                "workers": 1,
                "protocol": "udp",
                "flows": 2,
                "sourcePortBase": 43000,
                "payloadBytes": 64,
                "burst": 1,
                "load": "closed",
                "expectEcho": True,
                "observe": "full",
                "reconnectEvery": 0,
                "repeat": 1,
            }), encoding="utf-8")
            (cell / "app.log").write_text(
                "start protocol=udp host=192.168.4.5 port=42185 flows=2 "
                "runId=123 sourcePortBase=43000 expectEcho=true\n"
                "phase runId=123 setup-start-nanos=100 setup-end-nanos=200 "
                "warmup-start-nanos=300 steady-start-nanos=400 "
                "steady-end-nanos=500 drain-end-nanos=600\n"
                "app flow=0 localPort=43000 sent=1 received=1 errors=0 "
                "mismatches=0 unexpected=0 late=0 reordered=0 fatal=false "
                "runId=123\n"
                "app flow=1 localPort=43001 sent=1 received=1 errors=0 "
                "mismatches=0 unexpected=0 late=0 reordered=0 fatal=false "
                "runId=123\n"
                "app done runId=123 sent=2 received=2 errors=0 mismatches=0 "
                "unexpected=0 late=0 reordered=0 fatalFlows=0 "
                "executorTimeout=false setupStartNanos=100 setupEndNanos=200 "
                "teardownStartNanos=700 teardownEndNanos=800 "
                "tcpConnectedFlows=0 tcpFirstEchoFlows=0 "
                "tcpHandshakeReady=true\n",
                encoding="utf-8")
            summary = parser.parse_cell(cell)

        self.assertNotIn("flow-correctness-failure", summary["reasons"])
        self.assertNotIn("flow-closed-correctness-failure",
                         summary["reasons"])
        self.assertNotIn("closed-correctness-failure", summary["reasons"])
        self.assertEqual(summary["config"]["sourcePortBase"], 43000)


if __name__ == "__main__":
    unittest.main()
