import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/android-run-s172-e2-http-baseline-sample.sh"
SERVICE = ROOT / "android/vpn-lite/src/main/java/com/sakamoto/snort/vpnlite/SnortVpnService.java"
BUILD_DEBUG_APK = ROOT / "android/vpn-lite/scripts/build-debug-apk.sh"


class VerifyS172E2HttpBaselineSampleTest(unittest.TestCase):
    def setUp(self):
        self.runner = RUNNER.read_text(encoding="utf-8")
        self.service = SERVICE.read_text(encoding="utf-8")
        self.build_debug_apk = BUILD_DEBUG_APK.read_text(encoding="utf-8")

    def test_runner_declares_bounded_comparison_scope_not_full_e2(self):
        self.assertIn("S172 / E2 bounded matched HTTP baseline sample", self.runner)
        self.assertIn("not a full E2 verdict", self.runner)
        self.assertIn("scope=bounded_matched_http_baseline_not_full_e2", self.runner)
        self.assertIn('"scope":"bounded_matched_http_baseline_not_full_e2"', self.runner)

    def test_runner_preflights_comparison_apk_members(self):
        self.assertIn("preflight_apk()", self.runner)
        self.assertIn('require_apk_member "lib/arm64-v8a/libhev_external_driver_poc_plugin.so"',
                      self.runner)
        self.assertIn('require_apk_member "lib/arm64-v8a/libhev-socks5-tunnel.so"',
                      self.runner)
        self.assertIn('require_any_apk_member "hev-baseline-tun-poc"', self.runner)
        self.assertIn('"lib/arm64-v8a/libtun_poc_plugin.so"', self.runner)
        self.assertIn('"lib/arm64-v8a/tun_poc_plugin.so"', self.runner)
        self.assertIn('ARMS="${ARMS:-direct hev oi3}"', self.runner)

    def test_runner_uses_same_http_stream_probe_for_all_arms(self):
        self.assertIn("run_http_probe()", self.runner)
        self.assertIn("--ez appHttpProbe true", self.runner)
        self.assertIn('--ei durationSeconds "$DURATION_SECONDS"', self.runner)
        self.assertIn("latencyMsP50", self.runner)
        self.assertIn("latencyMsP95", self.runner)
        self.assertIn("latencyMsP99", self.runner)
        self.assertIn("readTimeoutAfterBytes", self.runner)
        self.assertIn('MAX_REQUESTS="${MAX_REQUESTS:-1}"', self.runner)
        self.assertIn('--ei count "$MAX_REQUESTS"', self.runner)
        self.assertIn('REQUEST_INTERVAL_MS="${REQUEST_INTERVAL_MS:-0}"', self.runner)
        self.assertIn('--ei requestIntervalMs "$REQUEST_INTERVAL_MS"', self.runner)
        self.assertIn("contentLengthCompletions", self.runner)
        self.assertIn('${content_length_completions:-0}" == "${successes:-0}', self.runner)
        self.assertIn("--es mode vpp-hev", self.runner)
        self.assertIn("--es mode vpp-oi3-multi", self.runner)

    def test_runner_supports_device_state_cells(self):
        self.assertIn('DEVICE_STATE="${DEVICE_STATE:-foreground}"', self.runner)
        self.assertIn("capture_device_state()", self.runner)
        self.assertIn("apply_device_state()", self.runner)
        self.assertIn("recover_device_state()", self.runner)
        self.assertIn("device_state_valid()", self.runner)
        self.assertIn("state-screen-off.txt", self.runner)
        self.assertIn("state-forced-doze.txt", self.runner)
        self.assertIn("dumpsys deviceidle force-idle", self.runner)
        self.assertIn("mScreenOn=false|mInteractive=false", self.runner)
        self.assertIn("mState=IDLE|mState=IDLE_MAINTENANCE", self.runner)
        self.assertIn("stateValid", self.runner)
        self.assertIn('"deviceState":"$DEVICE_STATE"', self.runner)

    def test_runner_keeps_cell_evidence_per_run(self):
        self.assertIn('CELL_ROOT="$RESULT_DIR/cells/$RUN_ID"', self.runner)
        self.assertIn('local cell="$CELL_ROOT/$label"', self.runner)
        self.assertIn('"cellRoot":"$CELL_ROOT"', self.runner)

    def test_hev_arm_starts_android_socks_smoke_server(self):
        self.assertIn("start_socks_server()", self.runner)
        self.assertIn("android-build-socks5-smoke-server.sh", self.runner)
        self.assertIn("android-socks5-smoke-server", self.runner)
        self.assertIn("socksConnectCount", self.runner)
        self.assertIn('"$socks_connect_count" -gt 0', self.runner)

    def test_runner_drives_oi3_explicit_cleanup(self):
        self.assertIn('run_oi3_control "multi-stop"', self.runner)
        self.assertIn("wait_oi3_cleanup", self.runner)
        self.assertIn("oi4 multi-session state=STOPPED", self.runner)
        self.assertIn("cleanup_total", self.runner)
        self.assertIn("oi3_cleanup result=PASS", self.runner)
        self.assertIn("cleanupPass,cleanupFail", self.runner)

    def test_runner_normalizes_zero_match_counts(self):
        self.assertIn("count_matches()", self.runner)
        self.assertIn('printf \'%s\\n\' "${count:-0}"', self.runner)
        self.assertIn("cleanup_fail=\"$(count_matches 'oi3_cleanup result=FAIL'", self.runner)
        self.assertIn('socks_connect_count="$(count_matches "connect $HOST:$HTTP_PORT"', self.runner)

    def test_vpp_hev_start_provenance_requires_tun_poc(self):
        self.assertIn("boolean requiresTunPocPlugin = vppMode >= 1 && vppMode <= 12;",
                      self.service)
        self.assertIn('"libtun_poc_plugin.so|tun_poc_plugin.so"', self.service)
        self.assertIn("requiresTunPocPlugin", self.service)
        self.assertNotIn("String requiredArtifact = vppMode == 5", self.service)

    def test_http_stream_probe_accepts_response_bytes_before_late_eof(self):
        self.assertIn("SocketTimeoutException", self.service)
        self.assertIn("readTimeoutAfterBytes", self.service)
        self.assertIn("if (total > 0)", self.service)
        self.assertIn("readTimeoutAfterBytes++", self.service)

    def test_http_stream_probe_is_content_length_aware_and_count_bounded(self):
        self.assertIn("maxRequests", self.service)
        self.assertIn("intent.getIntExtra(EXTRA_COUNT, 0)", self.service)
        self.assertIn("EXTRA_REQUEST_INTERVAL_MS", self.service)
        self.assertIn("requestIntervalMs", self.service)
        self.assertIn("Thread.sleep(sleepMs)", self.service)
        self.assertIn("requests < maxRequests", self.service)
        self.assertIn("findHttpHeaderEnd", self.service)
        self.assertIn("parseHttpContentLength", self.service)
        self.assertIn("contentLengthCompletions++", self.service)
        self.assertIn("Content-Length", self.service)

    def test_build_script_supports_explicit_comparison_tun_poc_packaging(self):
        self.assertIn('tun_poc_plugin="${VPP_TUN_POC_PLUGIN:-}"',
                      self.build_debug_apk)
        self.assertIn("vpp-tun-poc-plugin-provenance/v1", self.build_debug_apk)
        self.assertIn("libtun_poc_plugin.so", self.build_debug_apk)
        self.assertIn("tun_poc_plugin.so", self.build_debug_apk)


if __name__ == "__main__":
    unittest.main()
