#!/usr/bin/env python3
"""Regression tests for the A2-0 resolver tri-state policy."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1]
VERIFIER_PATH = SCRIPT_DIR / "verify-s139-a2.py"
SPEC = importlib.util.spec_from_file_location("verify_s139_a2", VERIFIER_PATH)
if SPEC is None or SPEC.loader is None:
    raise ImportError("unable to load A2-0 verifier")
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class ResolverVerdictTest(unittest.TestCase):
    HOST = "198.51.100.7"
    SOURCE_PORT = 40000
    PORT = 9
    EXPECTED_UID = 12629

    def verdict(self, *uid_lines: int) -> str:
        resolver = "\n".join(
            "resolver query=1 proto=17 src=10.111.0.2:{} -> {}:{} uid={}"
            .format(self.SOURCE_PORT, self.HOST, self.PORT, uid)
            for uid in uid_lines
        )
        return VERIFIER.resolver_verdict(
            resolver,
            self.HOST,
            self.SOURCE_PORT,
            self.PORT,
            self.EXPECTED_UID,
            17,
            "ip4",
        )

    def test_initial_miss_then_expected_uid_is_pass(self) -> None:
        self.assertEqual(
            VERIFIER.PASS,
            self.verdict(-1, self.EXPECTED_UID),
        )

    def test_any_wrong_positive_uid_is_fail(self) -> None:
        # Policy is deliberately strict: a wrong non-negative completion
        # remains FAIL even when a later line reports the expected UID.
        self.assertEqual(
            VERIFIER.FAIL,
            self.verdict(10180, self.EXPECTED_UID),
        )

    def test_only_initial_miss_is_inconclusive(self) -> None:
        self.assertEqual(VERIFIER.INCONCLUSIVE, self.verdict(-1))

    def test_non_numeric_allowed_scope_uid_is_invalid(self) -> None:
        manifest = {
            "schema": VERIFIER.MANIFEST_SCHEMA,
            "profile": VERIFIER.PROFILE_A20,
            "cellId": "A2-0",
            "vpnPackage": "com.example.vpn",
            "allowedPackage": "com.example.allowed",
            "mode": "vpp",
            "host": self.HOST,
            "port": self.PORT,
            "sourcePort": self.SOURCE_PORT,
            "requiredFiles": ["uid-attribution-contract.jsonl"],
        }
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            (evidence / "uid-attribution-contract.jsonl").write_text(
                '{"outcome":"ALLOWED_UID_SCOPE",'
                '"reason":"uids=[not-a-number] enforced=true"}\n',
                encoding="utf-8",
            )
            result = VERIFIER.verify_a20(manifest, evidence)
        scope_checks = [
            check for check in result["checks"]
            if check["name"] == "allowed-uid-scope-contract"
        ]
        self.assertEqual(1, len(scope_checks))
        self.assertEqual(VERIFIER.INVALID, scope_checks[0]["status"])

    def test_main_turns_manifest_type_error_into_result(self) -> None:
        manifest = {
            "schema": VERIFIER.MANIFEST_SCHEMA,
            "profile": VERIFIER.PROFILE_A20,
            "cellId": "A2-0",
            "vpnPackage": "com.example.vpn",
            "allowedPackage": "com.example.allowed",
            "mode": "vpp",
            "host": self.HOST,
            "port": self.PORT,
            "sourcePort": self.SOURCE_PORT,
            "protocol": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = root / "manifest.json"
            evidence = root / "evidence"
            evidence.mkdir()
            output = evidence / "result.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            rc = VERIFIER.main([
                "--manifest", str(manifest_path),
                "--evidence-dir", str(evidence),
                "--output", str(output),
            ])
            self.assertNotEqual(0, rc)
            self.assertEqual(VERIFIER.INVALID, json.loads(
                output.read_text(encoding="utf-8"))["status"])


if __name__ == "__main__":
    unittest.main()
