import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/android-run-s229-oi3-idle-cpu.sh"


class VerifyS229Oi3IdleCpuTest(unittest.TestCase):
    def setUp(self):
        self.runner = RUNNER.read_text(encoding="utf-8")

    def test_runner_declares_idle_hotspot_scope_not_full_e2(self):
        self.assertIn("S229 / E2 OI3 idle CPU diagnostic", self.runner)
        self.assertIn("hotspot isolation probe", self.runner)
        self.assertIn("not a full E2 performance verdict", self.runner)
        self.assertIn("oi3_idle_cpu_hotspot_isolation_not_full_e2", self.runner)
        self.assertIn('"schema":"s229-oi3-idle-cpu/v1"', self.runner)
        self.assertIn("git_status_short_begin", self.runner)
        self.assertIn("git_status_short_end", self.runner)

    def test_runner_uses_repo_adb_wrapper_and_device_helper(self):
        self.assertIn('ADB="${ADB:-$REPO_ROOT/dev/adb}"', self.runner)
        self.assertIn('source "$REPO_ROOT/dev/dev-android-device-lib.sh"', self.runner)
        self.assertIn("device_preflight", self.runner)
        self.assertIn("adb_target_desc", self.runner)

    def test_runner_starts_current_oi3_multi_without_traffic_probe(self):
        self.assertIn("--ez start true --es mode vpp-oi3-multi --es allowedPackage \"$PACKAGE\"",
                      self.runner)
        self.assertNotIn("--ez appHttpProbe true", self.runner)
        self.assertNotIn("--ez appUdpProbe true", self.runner)
        self.assertNotIn("--ez appTcpProbe true", self.runner)
        self.assertIn('SAMPLE_SECONDS="${SAMPLE_SECONDS:-10}"', self.runner)
        self.assertIn("idle=sleep seconds=$SAMPLE_SECONDS", self.runner)

    def test_runner_captures_vpp_per_thread_cpu_and_schedstat(self):
        self.assertIn("capture_vpp_tasks()", self.runner)
        self.assertIn("/proc/\\$p/task/*", self.runner)
        self.assertIn('cat \\"\\$t/comm\\"', self.runner)
        self.assertIn("awk '{print \\$14 + \\$15}'", self.runner)
        self.assertIn("awk '{print \\$1}'", self.runner)
        self.assertIn("/^Cpus_allowed_list:/", self.runner)
        self.assertIn("/^voluntary_ctxt_switches:/", self.runner)
        self.assertIn("/^nonvoluntary_ctxt_switches:/", self.runner)
        self.assertIn("thread-delta-$RUN_ID.csv", self.runner)
        self.assertIn("schedRuntimeNsDelta", self.runner)
        self.assertIn("cpuTicksDelta", self.runner)

    def test_runner_records_startup_config_and_logs(self):
        self.assertIn("capture_startup_files()", self.runner)
        self.assertIn("startup.conf", self.runner)
        self.assertIn("startup.exec", self.runner)
        self.assertIn("vpp-cli.log", self.runner)
        self.assertIn("vpp-stdout.log", self.runner)
        self.assertIn("logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I", self.runner)

    def test_runner_drives_explicit_oi3_cleanup_and_residue_checks(self):
        self.assertIn('run_oi3_control "multi-stop"', self.runner)
        self.assertIn("wait_oi3_cleanup", self.runner)
        self.assertIn("oi4 multi-session state=STOPPED", self.runner)
        self.assertIn("oi3_cleanup result=PASS", self.runner)
        self.assertIn("pidof vpp", self.runner)
        self.assertIn("ip link show tun0", self.runner)
        self.assertIn("rules_match", self.runner)


if __name__ == "__main__":
    unittest.main()
