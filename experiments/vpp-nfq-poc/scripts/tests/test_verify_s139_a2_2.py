"""Regression tests for the revised A2-2 cache/concurrency verifier."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


TESTS_DIR = Path(__file__).resolve().parent
VERIFIER_PATH = TESTS_DIR.parent / "verify-s139-a2.py"
SPEC = importlib.util.spec_from_file_location("verify_s139_a2_a22", VERIFIER_PATH)
if SPEC is None or SPEC.loader is None:
    raise ImportError("unable to load A2 verifier")
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)

BASE_TEST_PATH = TESTS_DIR / "test_verify_s139_a2.py"
BASE_SPEC = importlib.util.spec_from_file_location("test_verify_s139_a2_base", BASE_TEST_PATH)
if BASE_SPEC is None or BASE_SPEC.loader is None:
    raise ImportError("unable to load A2-1 fixture helper")
BASE_TESTS = importlib.util.module_from_spec(BASE_SPEC)
BASE_SPEC.loader.exec_module(BASE_TESTS)


class A22CacheBoundsVerdictTest(unittest.TestCase):
    """Use the A2-1 provenance fixture so this suite guards the common gate too."""

    def setUp(self) -> None:
        self.base = BASE_TESTS.A21MatrixVerdictTest()
        self.base.setUp()

    def manifest(self) -> dict:
        manifest = self.base.manifest()
        manifest.update({
            "schema": VERIFIER.MANIFEST_SCHEMA_A22,
            "profile": VERIFIER.PROFILE_A22,
            "cellId": "A2-2",
            "blockOwnerUid": 99999,
            "runtimeFiles": {
                self.base.APP_A: "a2-2-runtime-appa.jsonl",
                self.base.APP_B: "a2-2-runtime-appb.jsonl",
            },
            "contractFile": "uid-attribution-contract.jsonl",
            "contractFinalFile": "uid-attribution-contract-final.jsonl",
            "requiredFiles": [
                "package-list-packages-U.txt",
                "apk-provenance.tsv",
                "vpn-session-provenance.json",
                "vpp-start-provenance.json",
                "uid-attribution-contract.jsonl",
                "uid-attribution-contract-final.jsonl",
                "a2-2-runtime-appa.jsonl",
                "a2-2-runtime-appb.jsonl",
                "vpp-owner-resolver.log",
                "launch-window.json",
                "source-provenance.properties",
                "cleanup.txt",
            ],
        })
        # Ports are intentionally in the A2-2 range, distinct from the
        # checked-in A2-1 matrix.
        for index, item in enumerate(manifest["tuples"]):
            item["sourcePort"] = 45741 + (index if index < 4 else index + 4)
        return manifest

    @staticmethod
    def event(outcome: str, key: str, uid: int, pending: int, cache: int,
              token: int = -1, flow_id: int = -1, monotonic_ns: int = 0,
              reason: str = "") -> dict:
        return {
            "schema": "uid-attribution-contract/v1",
            "outcome": outcome,
            "key": key,
            "uid": uid,
            "owner": 0,
            "generation": 2,
            "network_epoch": 1,
            "app_epoch": 1,
            "token": token,
            "flow_id": flow_id,
            "pending": pending,
            "cache": cache,
            "provider_available": True,
            "monotonic_ns": monotonic_ns,
            "reason": reason,
        }

    def write_fixture(self, root: Path, manifest: dict,
                      omit_sequence_for: str = "",
                      wrong_cache_key: str = "",
                      capacity_violation: bool = False,
                      concurrent: bool = True) -> None:
        self.base.write_fixture(root, manifest)
        (root / "launch-window.json").write_text(json.dumps({
            "schema": "s139-a2-2-launch-window/v1",
            "launchCount": 8,
            "windowStartMonotonicNs": 1000,
            "windowEndMonotonicNs": 2000,
        }) + "\n", encoding="utf-8")
        records = [self.event(
            "CONTRACT_START", "-1", -1, 0, 0, reason="pending-capacity=4;cache-capacity=4")]
        records.append(self.event(
            "ALLOWED_UID_SCOPE", "-", -1, 0, 0,
            reason="enforced=true;uids=[{}, {}]".format(
                self.base.UID_A, self.base.UID_B)))
        cache = 0
        for index, item in enumerate(manifest["tuples"], 1):
            key = VERIFIER.canonical_tuple_key(item)
            uid = manifest["expectedAllowedUids"][item["package"]]
            token = index
            flow_id = index
            # Keep the first two misses live at once: this is the decisive
            # concurrency proof, while never exceeding pending capacity.
            pending = 2 if concurrent and index == 2 else 1
            records.append(self.event(
                "MISS_SUBMITTED", key, -1, pending, cache, token, flow_id,
                100 + index, "owner-sentinel-progress"))
            if index == 1:
                continue
            if index == 2:
                records.append(self.event(
                    "COMPLETION_ACCEPTED", key, uid, 1, cache + 1,
                    token, flow_id, 200 + index, "android-api-completion"))
                cache = min(cache + 1, 4)
            else:
                if cache == 4:
                    records.append(self.event(
                        "CACHE_EVICTED", key, uid, 0, 4, token, flow_id,
                        200 + index, "cache-capacity"))
                records.append(self.event(
                    "COMPLETION_ACCEPTED", key, uid, 0, min(cache + 1, 4),
                    token, flow_id, 200 + index, "android-api-completion"))
                cache = min(cache + 1, 4)
            if key != omit_sequence_for:
                cache_uid = self.base.UID_B if key == wrong_cache_key else uid
                records.append(self.event(
                    "CACHE_HIT", key, cache_uid, 0, cache, token, flow_id,
                    300 + index, "cache-hit"))
            if index == 2:
                # Complete the first live request after the second miss, so
                # the two intervals overlap even though it was emitted first.
                first = manifest["tuples"][0]
                first_key = VERIFIER.canonical_tuple_key(first)
                first_uid = manifest["expectedAllowedUids"][first["package"]]
                records.append(self.event(
                    "COMPLETION_ACCEPTED", first_key, first_uid, 0, cache,
                    1, 1, 250, "android-api-completion"))
                if first_key != omit_sequence_for:
                    cache_uid = self.base.UID_B if first_key == wrong_cache_key else first_uid
                    records.append(self.event(
                        "CACHE_HIT", first_key, cache_uid, 0, cache, 1, 1,
                        350, "cache-hit"))
            if capacity_violation and index == 3:
                records.append(self.event(
                    "STATE_SAMPLE", key, -1, 5, cache, token, flow_id,
                    360, "test-capacity-violation"))
        (root / "uid-attribution-contract.jsonl").write_text(
            "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
        final_records = records + [self.event(
            "CLEANUP", "-", -1, 0, 0,
            reason="pending=0;cache=0;flow-ids=0;max-pending={};max-cache=4".format(
                2 if concurrent else 1))]
        (root / "uid-attribution-contract-final.jsonl").write_text(
            "".join(json.dumps(record) + "\n" for record in final_records), encoding="utf-8")

    def verdict(self, omit_sequence_for: str = "", wrong_cache_key: str = "",
                capacity_violation: bool = False, remove_final: bool = False,
                concurrent: bool = True) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.manifest()
            self.write_fixture(root, manifest, omit_sequence_for,
                               wrong_cache_key, capacity_violation, concurrent)
            if remove_final:
                (root / "uid-attribution-contract-final.jsonl").unlink()
            return VERIFIER.verify_a22(manifest, root)

    def test_complete_bounded_concurrent_run_is_pass(self) -> None:
        result = self.verdict()
        self.assertEqual(VERIFIER.PASS, result["status"])
        self.assertTrue(result["summary"]["concurrent"])
        self.assertEqual(2, result["summary"]["boundedState"]["maxPendingObserved"])

    def test_cross_app_cache_hit_is_fail(self) -> None:
        key = VERIFIER.canonical_tuple_key(self.manifest()["tuples"][1])
        self.assertEqual(VERIFIER.FAIL, self.verdict(wrong_cache_key=key)["status"])

    def test_bounded_sequential_run_is_valid_but_inconclusive(self) -> None:
        self.assertEqual(
            VERIFIER.INCONCLUSIVE,
            self.verdict(concurrent=False)["status"],
        )

    def test_capacity_violation_is_fail(self) -> None:
        self.assertEqual(VERIFIER.FAIL, self.verdict(capacity_violation=True)["status"])

    def test_only_miss_without_completion_or_hit_is_inconclusive(self) -> None:
        key = VERIFIER.canonical_tuple_key(self.manifest()["tuples"][0])
        self.assertEqual(
            VERIFIER.INCONCLUSIVE,
            self.verdict(omit_sequence_for=key)["status"],
        )

    def test_missing_post_cleanup_final_contract_is_invalid(self) -> None:
        self.assertEqual(VERIFIER.INVALID, self.verdict(remove_final=True)["status"])


if __name__ == "__main__":
    unittest.main()
