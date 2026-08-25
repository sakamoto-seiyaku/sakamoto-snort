import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OI3 = ROOT / "overlay/src/plugins/hev_external_driver_poc/owner_inline_oi3.c"
PROBE = ROOT / "android/vpn-lite/native/vpn_fd_probe.c"
SERVICE = ROOT / "android/vpn-lite/src/main/java/com/sakamoto/snort/vpnlite/SnortVpnService.java"


class VerifyS158MultiOwnerContractTest(unittest.TestCase):
    def setUp(self):
        self.oi3 = OI3.read_text(encoding="utf-8")
        self.probe = PROBE.read_text(encoding="utf-8")
        self.service = SERVICE.read_text(encoding="utf-8")

    def test_final_artifact_has_bounded_multi_owner_seam(self):
        for marker in (
            "OI3_MULTI_OWNER_CAPACITY 4U",
            "struct oi3_multi_main",
            "oi3_main_t owners[OI3_MULTI_OWNER_CAPACITY]",
            "tm->owner_id",
            "tm->multi_mode = 1",
            "oi3_multi_flow_hash",
            "oi3_multi_owner_for_packet",
            "oi3_multi_completion_poll_main",
            "sakamoto-oi3 multi tun",
            "target-thread-a",
            "target-thread-b",
            "target-thread-c",
            "target-thread-d",
        ):
            self.assertIn(marker, self.oi3)

    def test_dispatcher_has_explicit_admission_and_wrong_owner_ledgers(self):
        for marker in (
            "multi_admission_rejects",
            "owner-busy",
            "tcp-non-syn-busy",
            "reason=queue-full",
            "reason=admission-rollback",
            "reason=owner-submit",
            "tun_submit_rejects",
            "tun_queue_rejects",
            "owner-queue-full",
            "queue-rejects",
            "overload_expected",
            "EXPECTED_PACKET_OVERLOAD",
            "PASS_EXPECTED_OVERLOAD",
            "expected_transport_timeout",
            "PASS_EXPECTED_AMBIENT_TIMEOUT",
            "ambient transport outcome=EXPECTED_TIMEOUT",
            "oi3 credit-ledger",
            "multi_tcp_tombstone_hash",
            "tcp-tail",
            "tcp-non-syn",
            "wrong_owner_events",
            "oi4 multi-session state=STOPPED",
            "show sakamoto-oi3 multi",
        ):
            self.assertIn(marker, self.oi3)

    def test_multi_admission_is_closed_while_teardown_publishes_tcp_tombstone(self):
        self.assertIn("Close owner-local admission before teardown starts", self.oi3)
        self.assertIn("same-flow TCP tail packets can enter the", self.oi3)
        self.assertIn("Reopen owner-local admission only after the completed TCP tuple", self.oi3)
        self.assertIn("published its tombstone/wait-SYN state", self.oi3)
        self.assertLess(
            self.oi3.index("Close owner-local admission before teardown starts"),
            self.oi3.index("deferred = oi3_defer_finish_to_owner_thread"),
        )
        self.assertLess(
            self.oi3.index("atomic_store_explicit (&tm->multi_tcp_wait_syn"),
            self.oi3.index("Reopen owner-local admission only after the completed TCP tuple"),
        )

    def test_multi_owner_hash_applies_final_avalanche_before_owner_modulo(self):
        for marker in (
            "oi3_multi_hash_mix",
            "0xff51afd7ed558ccdULL",
            "0xc4ceb9fe1a85ec53ULL",
            "oi3_multi_hash_mix (oi3_multi_fnv1a",
            "hash=fnv1a+mix",
        ):
            self.assertIn(marker, self.oi3)

    def test_multi_owner_defers_successor_syn_on_busy_canonical_owner(self):
        for marker in (
            "OI3_TUN_DEFERRED_KIND",
            "multi_deferred",
            "oi3_send_tun_handoff_for_kind",
            "oi3_owner_accept_deferred_tun_packet",
            "oi3_tun_deferred_enqueue",
            "oi3_admit_deferred_tun_flow",
            "owner-busy-deferred",
            "result=DEFER",
            "handoff=owner-fd",
            "oi3_finish_if_ready_on_owner",
            "successor SYN forces completed active",
            "owner toward rearm",
            "tcp-rearm-stale-tail",
            "must not be submitted into the next deferred successor context",
            "route_deferred",
            "deferred=%u/%u/%u/%u",
        ):
            self.assertIn(marker, self.oi3)
        self.assertLess(
            self.oi3.index("owner-busy-deferred"),
            self.oi3.index("tcp-non-syn-busy"),
        )
        self.assertNotIn("oi3_enqueue_deferred_tun_packet_for", self.oi3)

    def test_udp_multi_flow_uses_idle_owner_route_pinning(self):
        for marker in (
            "OI3_MULTI_FLOW_ROUTE_CAPACITY",
            "oi3_multi_flow_route_lookup",
            "oi3_multi_flow_route_insert",
            "oi3_multi_udp_idle_owner",
            "reason=udp-idle-owner",
            "flow_routes",
            "route_reassigned",
            "route-pinned=%u",
        ):
            self.assertIn(marker, self.oi3)
        self.assertLess(
            self.oi3.index("oi3_multi_flow_route_lookup"),
            self.oi3.index("hash % oi3_multi.owner_count"),
        )

    def test_shared_resources_are_not_closed_by_one_owner(self):
        self.assertIn("if (!tm->multi_mode && !keep_tun && tm->tun_file_index >= 0)", self.oi3)
        self.assertIn("if (!tm->multi_mode && tm->tun_fd >= 0)", self.oi3)
        self.assertIn("oi3_multi_maybe_teardown", self.oi3)

    def test_android_selects_four_workers_and_external_broker_for_multi_mode(self):
        self.assertIn('MODE_VPP_OI3_MULTI = "vpp-oi3-multi"', self.service)
        self.assertIn("vppMode = 27", self.service)
        self.assertIn("oi3_multi_mode ? 4 : 1", self.probe)
        self.assertIn("sakamoto-oi3 multi tun fd", self.probe)
        self.assertIn("target-thread-a 1", self.probe)
        self.assertIn("target-thread-b 2", self.probe)
        self.assertIn("target-thread-c 3", self.probe)
        self.assertIn("target-thread-d 4", self.probe)
        self.assertIn('setenv("SAKAMOTO_OI3_EXTERNAL_BROKER", "1", 1)', self.probe)


if __name__ == "__main__":
    unittest.main()
