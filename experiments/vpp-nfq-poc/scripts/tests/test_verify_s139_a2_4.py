#!/usr/bin/env python3
"""Host-only regression tests for the bounded A2-4 verifier."""

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1]
VERIFIER_PATH = SCRIPT_DIR / "verify-s139-a2-4.py"
OVERLAY_PATH = SCRIPT_DIR / "apply-vpp-android-overlay.sh"
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

    def test_s156_guardrails_reject_public_destination(self) -> None:
        invalid = []
        VERIFIER.verify_s156_guardrails({
            "uidContractCellId": "A2-4",
            "resolverCorrelationSchema": VERIFIER.RESOLVER_CORRELATION_SCHEMA,
            "destinationHost": "1.1.1.1",
            "destinationPort": 53,
            "fixture": {
                "schema": "s152-a2-1-fixture/v1",
                "host4": "192.168.4.5",
                "host6": "fd76:d462:c4e3::1",
                "tcpPort": 55443,
                "udpPort": 55553,
                "publicInternetClaim": False,
            },
        }, invalid)
        self.assertIn("destinationHost uses public resolver endpoint", invalid)

    def test_android_overlay_carries_s156_native_resolver_correlation(self) -> None:
        overlay = OVERLAY_PATH.read_text(encoding="utf-8")
        self.assertIn("tun_poc_ledger_cell", overlay)
        self.assertIn("SAKAMOTO_A2_STAGE_CELL", overlay)
        self.assertIn("cell %s stage %s ", overlay)
        self.assertIn("request %llu", overlay)

    def test_android_overlay_allows_worker_idle_despite_cloned_polling_inputs(self) -> None:
        overlay = OVERLAY_PATH.read_text(encoding="utf-8")
        self.assertIn("SAKAMOTO_ANDROID_WORKER_IDLE_IGNORES_CLONED_POLLING_INPUTS",
                      overlay)
        self.assertIn("if (is_main && nm->input_node_counts_by_state"
                      "[VLIB_NODE_STATE_POLLING])", overlay)
        self.assertIn("Android VPN workers receive owner work through frame queues",
                      overlay)
        self.assertNotIn("wakeup_epoch", overlay)
        self.assertNotIn("vlib_frame_queue_wakeup_mode", overlay)
        self.assertNotIn("VLIB_WAKE_PHASE", overlay)

    def test_android_overlay_exposes_idle_skip_reason_diagnostics(self) -> None:
        overlay = OVERLAY_PATH.read_text(encoding="utf-8")
        self.assertIn("show sakamoto android-idle", overlay)
        self.assertIn("skip_vectors", overlay)
        self.assertIn("skip_polling_inputs", overlay)
        self.assertIn("skip_barrier_recent", overlay)
        self.assertIn("interrupt_pending_epoll", overlay)
        self.assertIn("last_timeout_ms", overlay)


if __name__ == "__main__":
    unittest.main()
