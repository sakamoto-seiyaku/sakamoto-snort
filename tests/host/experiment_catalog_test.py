#!/usr/bin/env python3
"""Check experiment classification and retirement without running any POC."""

import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
CATALOG = json.loads((ROOT / "experiments/catalog.json").read_text())


def tracked_and_new(*paths):
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", *paths],
        cwd=ROOT,
    ).decode().split("\0")
    return sorted({name for name in names if name and (ROOT / name).is_file()})


def classify(path):
    candidate = PurePosixPath(path)
    for group in CATALOG["groups"]:
        if path in group.get("files", ()):
            return group
        if any(candidate.is_relative_to(directory) for directory in group.get("directories", ())):
            return group
        if str(candidate.parent) in group.get("children", ()):
            return group
    return None


def git_blob(path):
    data = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


class ExperimentCatalogTest(unittest.TestCase):
    def test_every_tracked_experiment_and_reference_tool_is_classified(self):
        names = tracked_and_new("experiments", "tools/protocol_identification")
        self.assertGreaterEqual(len(names), 540)
        ids = [group["id"] for group in CATALOG["groups"]]
        self.assertEqual(len(ids), len(set(ids)))
        used = set()
        for name in names:
            with self.subTest(path=name):
                group = classify(name)
                self.assertIsNotNone(group, "new path requires an explicit catalog classification")
                if group is not None:
                    self.assertTrue(group["purpose"])
                    self.assertTrue(group["classification"])
                    used.add(group["id"])
        self.assertEqual(used, set(ids), "empty/stale catalog group")
        self.assertFalse(CATALOG["policy"]["product_import_allowed"])
        self.assertFalse(CATALOG["policy"]["default_product_gate"])

    def test_new_experiment_directory_does_not_silently_become_history(self):
        self.assertIsNone(classify("experiments/unregistered-new-poc/run.sh"))
        self.assertIsNone(classify("experiments/vpp-nfq-poc/unregistered-subproject/run.sh"))

    def test_known_historical_references_keep_targets_and_original_bytes(self):
        for reference in CATALOG["retained_references"]:
            with self.subTest(target=reference["target"]):
                target = ROOT / reference["target"]
                self.assertTrue(target.is_file())
                consumer = (ROOT / reference["consumer"]).read_text()
                self.assertIn(reference["target"], consumer)
                self.assertEqual(git_blob(target), reference["target_blob"])

    def test_retired_cpp_gates_reject_before_any_work(self):
        for name in CATALOG["retired_entrypoints"]:
            with self.subTest(path=name):
                script = ROOT / name
                # Tiny guards, not hidden build/replay implementations.
                self.assertLessEqual(len(script.read_text().splitlines()), 10)
                for args in ([], ["--help"]):
                    result = subprocess.run(
                        ["bash", str(script), *args], cwd=ROOT,
                        text=True, capture_output=True, timeout=5,
                    )
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("RETIRED", result.stderr)
                    self.assertNotIn("PASS", result.stdout + result.stderr)

    def test_product_sources_do_not_import_experiment_paths(self):
        for name in tracked_and_new("src/product", "crates/product-core",
                                    "app/android-runtime/scripts", "tools/product"):
            path = ROOT / name
            if path.suffix in (".md", ".patch"):
                continue
            data = path.read_bytes()
            with self.subTest(path=name):
                self.assertNotIn(b"experiments/vpp-nfq-poc", data)
                self.assertNotIn(b"experiments/handcrafted-direct-bridge", data)
        cmake = (ROOT / "CMakeLists.txt").read_text()
        self.assertNotIn('add_subdirectory(experiments', cmake)
        self.assertNotIn("s61-vpp-reference-inventory-contract-test.sh", cmake)


if __name__ == "__main__":
    unittest.main()
