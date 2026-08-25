import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/android-run-s181-b2-full-device-transport-explore.sh"
WRAPPER = ROOT / "scripts/android-run-s183-b2-real-uid-drop.sh"
NATIVE = ROOT / "android/vpn-lite/native/vpn_fd_probe.c"


class S183B2RealUidDropTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = RUNNER.read_text(encoding="utf-8")
        cls.wrapper = WRAPPER.read_text(encoding="utf-8")
        cls.native = NATIVE.read_text(encoding="utf-8")

    def test_wrapper_runs_only_positive_and_uid_drop_cells(self):
        self.assertIn('INCLUDE_UID_DROP="${INCLUDE_UID_DROP:-true}"', self.wrapper)
        self.assertIn('INCLUDE_POLICY_DROP="${INCLUDE_POLICY_DROP:-false}"', self.wrapper)
        self.assertIn('INCLUDE_NO_REPLY="${INCLUDE_NO_REPLY:-false}"', self.wrapper)
        self.assertIn('INCLUDE_TCP_TIMEOUT="${INCLUDE_TCP_TIMEOUT:-false}"', self.wrapper)
        self.assertIn('STAGE_PREFIX="${STAGE_PREFIX:-S183}"', self.wrapper)
        self.assertIn("s183-b2-real-uid-drop", self.wrapper)
        self.assertIn("android-run-s181-b2-full-device-transport-explore.sh", self.wrapper)

    def test_native_reuses_tun_gate_for_oi3_multi_uid_drop_without_legacy_hev(self):
        self.assertIn("bool use_legacy_owner_gate = vpp_mode == 3;", self.native)
        self.assertIn("bool use_oi3_uid_gate = use_oi3_multi && block_owner_uid >= 0;", self.native)
        self.assertIn("bool use_tun_gate = use_legacy_owner_gate || use_oi3_uid_gate;", self.native)
        self.assertIn("query_owner_uid_with_bounded_wait", self.native)
        self.assertIn("sentinel-first", self.native)
        self.assertIn("lookup-attempts=%d", self.native)
        self.assertIn("use_legacy_owner_gate ||", self.native)
        self.assertIn("vpp_mode == 2 || use_legacy_owner_gate", self.native)
        self.assertIn("if (use_tun_gate && socketpair", self.native)
        self.assertIn("int tun_fd = use_tun_gate ? gate_fds[1] : fd;", self.native)
        self.assertIn("if (use_tun_gate) {", self.native)
        self.assertIn("close(gate_fds[1]);", self.native)

    def test_runner_uid_drop_cell_is_pre_oi3_broker_socket_claim(self):
        self.assertIn('INCLUDE_UID_DROP="${INCLUDE_UID_DROP:-false}"', self.runner)
        self.assertIn('UID_DROP_PORT="${UID_DROP_PORT:-53545}"', self.runner)
        self.assertIn('"uid_drop_udp_ready"', self.runner)
        self.assertIn('not any(e.get("event") == "uid_drop_udp_query"', self.runner)
        self.assertIn('run_cell "uid-drop-udp-dns"', self.runner)
        self.assertIn('--ei blockOwnerUid "$block_owner_uid"', self.runner)
        self.assertIn('capture_remote_tail "$REMOTE_OWNER_GATE_LOG"', self.runner)
        self.assertIn('uid-attribution-contract.jsonl', self.runner)
        self.assertIn('stats["gate_uid_drop"] >= 1', self.runner)
        self.assertIn('stats["broker_success"] == 0', self.runner)
        self.assertIn('stats["direct_send"] == 0', self.runner)
        self.assertIn('stats["tun_output"] == 0', self.runner)
        self.assertIn("not VPP-internal UID policy", self.runner)


if __name__ == "__main__":
    unittest.main()
