import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE_RUNNER = ROOT / "scripts/android-run-s181-b2-full-device-transport-explore.sh"
WRAPPER = ROOT / "scripts/android-run-s185-b2-infrastructure-failures.sh"
PLUGIN = ROOT / "overlay/src/plugins/hev_external_driver_poc/owner_inline_oi3.c"


class S185B2InfrastructureFailureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = BASE_RUNNER.read_text(encoding="utf-8")
        cls.wrapper = WRAPPER.read_text(encoding="utf-8")
        cls.plugin = PLUGIN.read_text(encoding="utf-8")

    def test_wrapper_selects_only_positive_and_infrastructure_cells(self):
        self.assertIn('INCLUDE_INFRA_FAILURES="${INCLUDE_INFRA_FAILURES:-true}"', self.wrapper)
        self.assertIn('INCLUDE_POLICY_DROP="${INCLUDE_POLICY_DROP:-false}"', self.wrapper)
        self.assertIn('INCLUDE_UID_DROP="${INCLUDE_UID_DROP:-false}"', self.wrapper)
        self.assertIn('INCLUDE_NO_REPLY="${INCLUDE_NO_REPLY:-false}"', self.wrapper)
        self.assertIn('INCLUDE_TCP_TIMEOUT="${INCLUDE_TCP_TIMEOUT:-false}"', self.wrapper)
        self.assertIn('STAGE_PREFIX="${STAGE_PREFIX:-S185}"', self.wrapper)
        self.assertIn("android-run-s181-b2-full-device-transport-explore.sh", self.wrapper)

    def test_runner_executes_all_three_infrastructure_cells(self):
        self.assertIn('INCLUDE_INFRA_FAILURES="${INCLUDE_INFRA_FAILURES:-false}"', self.runner)
        self.assertIn('run_cell "bind-failure-udp-dns"', self.runner)
        self.assertIn('"bind-failure"', self.runner)
        self.assertIn('"$REMOTE_FORCE_BIND"', self.runner)
        self.assertIn('run_cell "protect-failure-udp-dns"', self.runner)
        self.assertIn('"protect-failure"', self.runner)
        self.assertIn('"$REMOTE_FORCE_PROTECT"', self.runner)
        self.assertIn('run_cell "broker-unavailable-udp-dns"', self.runner)
        self.assertIn('"broker-unavailable"', self.runner)

    def test_runner_requires_distinct_native_infra_results(self):
        self.assertIn('"broker_bind_failure"', self.runner)
        self.assertIn('"broker_protect_failure"', self.runner)
        self.assertIn('"broker_unavailable"', self.runner)
        self.assertIn('"EXPECTED_BIND_FAILURE"', self.runner)
        self.assertIn('"EXPECTED_PROTECT_FAILURE"', self.runner)
        self.assertIn('"EXPECTED_BROKER_UNAVAILABLE"', self.runner)
        self.assertIn('"PASS_EXPECTED_INFRA_FAILURE"', self.runner)

    def test_plugin_maps_expected_failures_to_broker_flags(self):
        self.assertIn('!strcmp (expected_failure, "bind-failure")', self.plugin)
        self.assertIn("OI2_FLAG_BIND_FAILURE", self.plugin)
        self.assertIn('!strcmp (expected_failure, "protect-failure")', self.plugin)
        self.assertIn("OI2_FLAG_PROTECT_FAILURE", self.plugin)
        self.assertIn('!strcmp (expected_failure, "broker-unavailable")', self.plugin)
        self.assertIn("OI2_FLAG_BROKER_UNAVAILABLE", self.plugin)

    def test_plugin_keeps_exact_bind_protect_accounting_per_result(self):
        self.assertIn("expected_broker_bind_calls", self.plugin)
        self.assertIn("expected_broker_protect_calls", self.plugin)
        self.assertIn("case OI2_RESULT_BIND_FAILURE", self.plugin)
        self.assertIn("expected_broker_bind_calls = 1", self.plugin)
        self.assertIn("expected_broker_protect_calls = 0", self.plugin)
        self.assertIn("case OI2_RESULT_PROTECT_FAILURE", self.plugin)
        self.assertIn("expected_broker_protect_calls = 1", self.plugin)
        self.assertIn("case OI2_RESULT_BROKER_UNAVAILABLE", self.plugin)
        self.assertIn("expected_broker_bind_calls = 0", self.plugin)

    def test_external_completion_counts_protect_failure_as_protect_attempt(self):
        self.assertIn("completion.result != OI2_RESULT_BROKER_UNAVAILABLE", self.plugin)
        self.assertIn("completion.result == OI2_RESULT_PROTECT_FAILURE", self.plugin)


if __name__ == "__main__":
    unittest.main()
