import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "verify-s146-b2.py"
SPEC = importlib.util.spec_from_file_location("verify_s146_b2", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class VerifyS146B2Test(unittest.TestCase):
    def test_tun_cleanup_uses_cell_aware_verdict(self):
        source = (
            Path(__file__).resolve().parents[2]
            / "overlay/src/plugins/hev_external_driver_poc/owner_inline_oi3.c"
        ).read_text(encoding="utf-8")
        self.assertNotIn("if (!tm->tun_mode) oi3_classify_result (tm);", source)
        self.assertIn("oi3_is_expected_negative_cell", source)
        self.assertIn("tm->cell == OI3_CELL_NO_REPLY", source)
        self.assertIn("unexpected-no-reply-output", source)
        self.assertIn("tm->tun_flow_deadline_ns != 0", source)

    def test_old_refusal_evidence_is_rejected(self):
        app = "cell=refused result=OK sent=22 received=0"
        native = (
            "oi3_cleanup result=FAIL outcome=EXPECTED_TRANSPORT_REFUSAL "
            "output=1 direct=0 rewritten=1 endpoint=0/0 broker=1/1 "
            "transport-failures=1 infrastructure-failures=0 buffers=5/5 residue=0"
        )
        ok, errors = MODULE.verify("refused", app, native)
        self.assertFalse(ok)
        self.assertTrue(any("app result" in error for error in errors))
        self.assertTrue(any("native result" in error for error in errors))

    def test_refusal_contract_passes(self):
        app = "cell=refused result=EXPECTED_TRANSPORT_FAILURE sent=22 received=0"
        native = (
            "oi3_cleanup result=PASS_EXPECTED_FAILURE "
            "outcome=EXPECTED_TRANSPORT_REFUSAL output=1 direct=0 rewritten=1 "
            "endpoint=0/0 broker=1/1 transport-failures=1 "
            "infrastructure-failures=0 buffers=5/5 residue=0"
        )
        ok, errors = MODULE.verify("refused", app, native)
        self.assertTrue(ok, errors)

    def test_policy_drop_requires_zero_transport(self):
        app = "cell=policy-drop result=EXPECTED_POLICY_DROP_NO_TRANSPORT sent=22 received=0"
        native = (
            "oi3_cleanup result=PASS_EXPECTED_FAILURE outcome=EXPECTED_POLICY_DROP "
            "output=0 direct=0 rewritten=0 endpoint=0/0 broker=0/0 "
            "transport-failures=0 infrastructure-failures=0 buffers=0/0 residue=0"
        )
        ok, errors = MODULE.verify("policy-drop", app, native)
        self.assertTrue(ok, errors)


if __name__ == "__main__":
    unittest.main()
