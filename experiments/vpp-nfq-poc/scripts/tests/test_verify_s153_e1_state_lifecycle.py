import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/android-run-s153-e1-state-lifecycle.sh"
DOC = ROOT / "S153_E1_RESIDUAL_EXECUTION_JOURNAL.md"


class VerifyS153E1StateLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.runner = RUNNER.read_text(encoding="utf-8")
        self.doc = DOC.read_text(encoding="utf-8")

    def test_runner_uses_repo_local_adb_and_owned_fixture(self):
        self.assertIn('export ADB="${ADB:-$REPO_ROOT/dev/adb}"',
                      self.runner)
        self.assertIn('FIXTURE_BIND="${FIXTURE_BIND:-0.0.0.0}"',
                      self.runner)
        self.assertIn("fixture listening udp=", self.runner)
        self.assertIn("start_fixture", self.runner)
        self.assertIn("stop_fixture", self.runner)

    def test_runner_drives_cleanup_control_before_product_stop(self):
        self.assertIn("stop_oi3_multi()", self.runner)
        self.assertIn('mkdir -p "$phase_dir"', self.runner)
        self.assertIn("run_oi3_control multi-stop", self.runner)
        self.assertIn("wait_oi3_cleanup", self.runner)
        self.assertIn("cleanup-pre-stop.log", self.runner)
        self.assertIn("stop_vpn", self.runner)

    def test_multi_stop_phases_aggregate_all_cleanup_segments(self):
        self.assertIn("write_phase_cleanup_log()", self.runner)
        self.assertIn(
            'write_phase_cleanup_log "$phase_dir/cleanup.log" '
            '"$phase_dir/first" "$phase_dir/restart"',
            self.runner)
        self.assertIn(
            'write_phase_cleanup_log "$phase_dir/cleanup.log" '
            '"$phase_dir" "$phase_dir/restart"',
            self.runner)
        self.assertIn("cleanup_pass", self.runner)
        self.assertIn("cleanup_fail", self.runner)

    def test_runner_registers_device_state_epoch_and_fault_cells(self):
        for token in [
                "run_normal_restart",
                "run_foreground_state screen-off screen-off",
                "run_foreground_state forced-doze doze",
                "run_fault_restart",
                "run_epoch_restart",
                "dumpsys deviceidle force-idle",
                "svc wifi disable",
                "multi-fault-0",
        ]:
            self.assertIn(token, self.runner)

    def test_journal_declares_tuple_correction(self):
        self.assertIn("Status: `FOREGROUND_RESOURCE_PASS_CONTINUING`", self.doc)
        self.assertIn("resource-foreground", self.doc)
        self.assertIn("dualstack-dns", self.doc)
        self.assertIn("state-screen-off", self.doc)
        self.assertIn("state-forced-doze", self.doc)
        self.assertIn("epoch-restart", self.doc)
        self.assertIn("fault-restart", self.doc)
        self.assertIn("cleanup-fix-smoke", self.doc)
        self.assertIn("UDP exact closed-echo", self.doc)
        self.assertIn("fire-and-count", self.doc)

    def test_udp_state_driver_defaults_to_fire_and_count(self):
        self.assertIn('UDP_EXPECT_ECHO="${UDP_EXPECT_ECHO:-false}"',
                      self.runner)
        self.assertIn('expect_echo="$UDP_EXPECT_ECHO"', self.runner)
        self.assertIn('--ez expectEcho "$expect_echo"', self.runner)
        self.assertIn('"udpExpectEcho":$UDP_EXPECT_ECHO', self.runner)

    def test_runner_does_not_assign_shell_readonly_uid(self):
        self.assertIn('PACKAGE_UID="$(package_uid)"', self.runner)
        self.assertNotRegex(self.runner, r'(?m)^UID=')

    def test_runner_does_not_reference_local_phase_before_assignment(self):
        self.assertNotIn('local phase="$1" state="$2" phase_dir="$RESULT_DIR/$phase"',
                         self.runner)
        self.assertNotIn('local phase=fault-restart phase_dir="$RESULT_DIR/$phase"',
                         self.runner)
        self.assertNotIn('local phase=epoch-restart phase_dir="$RESULT_DIR/$phase"',
                         self.runner)

    def test_epoch_rule_check_normalizes_wifi_netid_replacement(self):
        self.assertIn("normalize_ip_rules()", self.runner)
        self.assertIn('"$expected" == epoch', self.runner)
        self.assertIn("baseline-ip-rules.normalized.txt", self.runner)
        self.assertIn("after-ip-rules.normalized.txt", self.runner)
        self.assertIn("lookup wlan0$", self.runner)


if __name__ == "__main__":
    unittest.main()
