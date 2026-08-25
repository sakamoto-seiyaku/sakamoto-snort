import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/android-run-s170-e1-resource-trend.sh"
DOC = ROOT / "S170_E1_RESOURCE_TREND_EXECUTION.md"


class VerifyS170E1ResourceTrendTest(unittest.TestCase):
    def setUp(self):
        self.runner = RUNNER.read_text(encoding="utf-8")
        self.doc = DOC.read_text(encoding="utf-8")

    def test_runner_owns_the_udp_fixture(self):
        self.assertIn('FIXTURE_BIND="${FIXTURE_BIND:-0.0.0.0}"',
                      self.runner)
        self.assertIn('FIXTURE_LOG="$RESULT_DIR/udp-fixture.log"',
                      self.runner)
        self.assertIn("start_fixture()", self.runner)
        self.assertIn("stop_fixture()", self.runner)
        self.assertIn("sock.bind((bind_host, port))", self.runner)
        self.assertIn('grep -c \' RX \' "$FIXTURE_LOG"', self.runner)
        self.assertIn("start_fixture\n", self.runner)

    def test_runner_preserves_device_apk_provenance_paths(self):
        self.assertIn("base.apk\\$#\\1/base.apk#p", self.runner)
        self.assertIn("base.apk\\$#\\1/lib/arm64#p", self.runner)
        self.assertIn("device_plugin_sha256", self.runner)
        self.assertIn("device_hev_sha256", self.runner)
        self.assertIn("expected_hash_policy=current-artifact-by-default",
                      self.runner)

    def test_wait_vpp_ready_does_not_block_on_log_paths(self):
        self.assertIn("tail -n 80", self.runner)
        self.assertIn("[ -f \\\"\\$f\\\" ]", self.runner)
        self.assertNotIn(
            "grep -E 'oi4 multi enabled|oi3 multi enabled|show plugins' "
            "'$REMOTE_STDOUT_LOG' '$REMOTE_CLI_LOG'",
            self.runner)

    def test_adb_read_has_bounded_retry_for_wsl_transport_flakes(self):
        self.assertIn('ADB_READ_RETRY_ATTEMPTS="${ADB_READ_RETRY_ATTEMPTS:-3}"',
                      self.runner)
        self.assertIn("adb_read retry attempt=", self.runner)
        self.assertIn("adb_read_once()", self.runner)
        self.assertIn("had_errexit", self.runner)

    def test_runner_parses_current_app_l4_summary_shape(self):
        self.assertIn("done runId=.* sent=", self.runner)
        self.assertIn("done runId=.* received=", self.runner)
        self.assertIn("done runId=.* errors=", self.runner)
        self.assertNotIn("flows-done .*sent", self.runner)

    def test_doc_records_bounded_post_f046_result_and_non_claims(self):
        self.assertIn("PASS_FOR_BOUNDED_POST_F046_E1_WINDOW", self.doc)
        self.assertIn("20260825-112255-922529", self.doc)
        self.assertIn("fixtureRx=12762 fixtureTx=12762", self.doc)
        self.assertIn("13049571877470", self.doc)
        self.assertIn("134103890013440", self.doc)
        self.assertIn("E2 performance", self.doc)
        self.assertIn("not a production capacity claim", self.doc)
        self.assertIn("first attempted S170 run was rejected as runner-invalid",
                      self.doc)


if __name__ == "__main__":
    unittest.main()
