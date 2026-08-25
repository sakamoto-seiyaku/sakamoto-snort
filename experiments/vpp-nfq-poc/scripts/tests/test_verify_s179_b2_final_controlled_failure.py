import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / (
    "android-run-s179-b2-final-controlled-failure.sh"
)


class S179B2FinalControlledFailureRunnerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SCRIPT.read_text(encoding="utf-8")

    def test_uses_current_artifact_policy_and_s146_verifier(self):
        self.assertIn(
            "expected_hash_policy=current-artifact-by-default-no-static-historical-hashes",
            self.source,
        )
        self.assertIn("verify-s146-b2.py", self.source)

    def test_runs_all_three_controlled_negative_modes(self):
        self.assertIn("vpp-oi3-controlled-refused", self.source)
        self.assertIn("vpp-oi3-controlled-no-reply", self.source)
        self.assertIn("vpp-oi3-controlled-policy-drop", self.source)

    def test_declares_bounded_claim_boundary(self):
        self.assertIn("not external/default-route B2 closure", self.source)
        self.assertIn("controlled full-TUN negative semantics regression", self.source)

    def test_requires_app_and_native_expected_outcomes(self):
        self.assertIn("EXPECTED_TRANSPORT_FAILURE", self.source)
        self.assertIn("EXPECTED_NO_REPLY_TIMEOUT", self.source)
        self.assertIn("EXPECTED_POLICY_DROP_NO_TRANSPORT", self.source)
        self.assertIn("PASS_EXPECTED_FAILURE", self.source)

    def test_tun0_residue_uses_output_not_exit_code(self):
        self.assertIn('if [[ "$tun0_text" == *"tun0:"* ]]; then', self.source)


if __name__ == "__main__":
    unittest.main()
