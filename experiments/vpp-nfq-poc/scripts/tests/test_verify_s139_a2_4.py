#!/usr/bin/env python3
"""Host-only regression tests for the bounded A2-4 verifier."""

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1]
VERIFIER_PATH = SCRIPT_DIR / "verify-s139-a2-4.py"
SPEC = importlib.util.spec_from_file_location("verify_s139_a2_4", VERIFIER_PATH)
if SPEC is None or SPEC.loader is None:
    raise ImportError("unable to load A2-4 verifier")
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class A24VerifierUnitTest(unittest.TestCase):
    def test_canonical_key_is_direction_independent(self) -> None:
        forward = VERIFIER.canonical_key(
            "ip4", "10.111.0.2", 45941, "1.1.1.1", 53)
        reverse = VERIFIER.canonical_key(
            "ip4", "1.1.1.1", 53, "10.111.0.2", 45941)
        self.assertEqual(forward, reverse)
        self.assertEqual("ip4/UDP/1.1.1.1:53-10.111.0.2:45941", forward)

    def test_app_adapter_key_is_joined_without_rewriting_its_envelope(self) -> None:
        record = {
            "family": "ip4",
            "protocol": "udp",
            "source_port": 45941,
            "destination_address": "1.1.1.1",
            "destination_port": 53,
        }
        self.assertEqual("ip4|udp|45941|1.1.1.1:53",
                         VERIFIER.app_adapter_key(record))

    def test_native_parser_keeps_stale_gap_explicit(self) -> None:
        observations, has_stale = VERIFIER.parse_native(
            "resolver query=1 proto=17 10.111.0.2:45941 -> "
            "1.1.1.1:53 uid=-1\n")
        self.assertEqual(1, len(observations))
        self.assertEqual(-1, observations[0]["uid"])
        self.assertFalse(has_stale)

    def test_native_parser_reads_stage_and_generation_tail(self) -> None:
        observations, has_stale = VERIFIER.parse_native(
            "resolver query=2 proto=17 10.111.0.2:45943 -> "
            "1.1.1.1:53 uid=-1 cell=A2-4 stage=A2-4-runtime-stale "
            "generation=7 stale=true\n")
        self.assertTrue(has_stale)
        self.assertEqual("A2-4-runtime-stale", observations[0]["stage_id"])
        self.assertEqual(7, observations[0]["generation"])
        self.assertTrue(observations[0]["stale"])

    def test_missing_bundle_is_invalid_not_pass(self) -> None:
        manifest = {
            "schema": VERIFIER.MANIFEST_SCHEMA,
            "profile": "a2-4",
            "cellId": "A2-4",
            "mode": "vpp-hev-owner-resolver",
            "vppMode": 5,
            "appPackage": "com.example.appa",
            "expectedAllowedUid": 10123,
            "family": "ip4",
            "protocol": "udp",
            "destinationPort": 53,
            "architecture_interruption": False,
            "stages": [],
            "evidence": {},
        }
        with tempfile.TemporaryDirectory() as directory:
            result = VERIFIER.verify(manifest, Path(directory))
        self.assertEqual(VERIFIER.INVALID, result["status"])
        self.assertFalse(result["architecture_interruption"])


if __name__ == "__main__":
    unittest.main()
