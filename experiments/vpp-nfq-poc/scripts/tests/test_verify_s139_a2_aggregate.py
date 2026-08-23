import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "verify-s139-a2-aggregate.py"
SPEC = importlib.util.spec_from_file_location("verify_s139_a2_aggregate", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VERIFIER)


def cell_result(cell: str) -> dict:
    return {
        "schema": VERIFIER.EXPECTED_SCHEMAS[cell],
        "status": "PASS",
        "reason": "fixture",
        "checks": [{"name": "cleanup", "status": "PASS", "detail": "clean"}],
        "failures": [],
        "invalid": [],
        "inconclusive": [],
    }


class VerifyA2AggregateTests(unittest.TestCase):
    def test_all_registered_cells_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bindings = {}
            for cell in VERIFIER.REQUIRED_CELLS:
                path = root / (cell + ".json")
                path.write_text(json.dumps(cell_result(cell)), encoding="utf-8")
                bindings[cell] = path
            result = VERIFIER.aggregate(bindings)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["errors"], [])
        self.assertEqual(len(result["cells"]), 7)

    def test_missing_cell_keeps_aggregate_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bindings = {}
            for cell in VERIFIER.REQUIRED_CELLS[:-1]:
                path = root / (cell + ".json")
                path.write_text(json.dumps(cell_result(cell)), encoding="utf-8")
                bindings[cell] = path
            result = VERIFIER.aggregate(bindings)
        self.assertEqual(result["status"], "A2_INCOMPLETE")
        self.assertTrue(any("A2-6 is missing" == error for error in result["errors"]))

    def test_non_pass_check_cannot_be_hidden_by_result_status(self):
        result = cell_result("A2-6")
        result["checks"][0]["status"] = "FAIL"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "a26.json"
            path.write_text(json.dumps(result), encoding="utf-8")
            aggregate = VERIFIER.aggregate(
                {cell: path for cell in VERIFIER.REQUIRED_CELLS}
            )
        self.assertEqual(aggregate["status"], "A2_INCOMPLETE")
        self.assertTrue(any("A2-6: cleanup=FAIL" == error
                            for error in aggregate["errors"]))

    def test_out_of_scope_inconclusive_is_retained_not_promoted(self):
        result = cell_result("A2-4")
        result["checks"] = [{
            "name": "native-stale-join",
            "status": "INCONCLUSIVE",
            "detail": "native stale completion is outside the registered claim",
        }, {"name": "cleanup", "status": "PASS", "detail": "clean"}]
        with tempfile.TemporaryDirectory() as directory:
            bindings = {}
            for cell in VERIFIER.REQUIRED_CELLS:
                path = Path(directory) / (cell + ".json")
                path.write_text(json.dumps(
                    result if cell == "A2-4" else cell_result(cell)),
                    encoding="utf-8")
                bindings[cell] = path
            aggregate = VERIFIER.aggregate(bindings)
        self.assertEqual(aggregate["status"], "PASS")
        a24 = next(item for item in aggregate["cells"] if item["cellId"] == "A2-4")
        self.assertEqual(a24["outOfScopeInconclusiveChecks"], ["native-stale-join"])


if __name__ == "__main__":
    unittest.main()
