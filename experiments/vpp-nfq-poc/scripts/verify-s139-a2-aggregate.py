#!/usr/bin/env python3
"""Aggregate the seven registered S139 A2 cell verdicts.

Cell verifiers remain authoritative for their individual claims.  This small
auditor only joins their retained ``result.json`` files, refuses missing or
internally inconsistent inputs, and emits the design-level ``PASS`` versus
``A2_INCOMPLETE`` state.  It deliberately does not turn a cell failure into a
new behavioural claim.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


SCHEMA = "s139-a2-aggregate/v1"
PASS = "PASS"
INCOMPLETE = "A2_INCOMPLETE"
REQUIRED_CELLS = ("A2-0", "A2-1", "A2-2", "A2-3", "A2-4", "A2-5", "A2-6")
EXPECTED_SCHEMAS = {
    "A2-0": "s139-a2-verifier/v1",
    "A2-1": "s139-a2-verifier/v1",
    "A2-2": "s139-a2-verifier/v1",
    "A2-3": "s139-a2-3-result/v1",
    "A2-4": "s139-a2-4-result/v1",
    "A2-5": "s139-a2-5-result/v1",
    "A2-6": "s139-a2-6-result/v1",
}


def read_result(path: Path) -> Tuple[Optional[Dict[str, Any]], str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        return None, "unreadable: " + str(error)
    except json.JSONDecodeError as error:
        return None, "malformed JSON: " + str(error)
    if not isinstance(value, dict):
        return None, "result is not an object"
    return value, ""


def parse_bindings(values: Iterable[str]) -> Tuple[Dict[str, Path], List[str]]:
    bindings: Dict[str, Path] = {}
    errors: List[str] = []
    for raw in values:
        cell, separator, filename = raw.partition("=")
        if not separator or cell not in REQUIRED_CELLS or not filename:
            errors.append("invalid --cell-result: " + raw)
            continue
        if cell in bindings:
            errors.append("duplicate cell binding: " + cell)
            continue
        bindings[cell] = Path(filename)
    return bindings, errors


def check_cell(cell: str, path: Path, result: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    errors: List[str] = []
    expected_schema = EXPECTED_SCHEMAS[cell]
    if result.get("schema") != expected_schema:
        errors.append("schema=" + str(result.get("schema")))

    embedded_cell = result.get("cellId")
    # The A2-5/A2-6 result schemas identify the cell in their manifest, not in
    # result.json.  The CLI binding is therefore the authoritative cell key
    # for those two schemas.
    if embedded_cell is not None and embedded_cell != cell:
        errors.append("cellId=" + str(embedded_cell))

    status = result.get("status")
    if status != PASS:
        errors.append("status=" + str(status))

    checks = result.get("checks")
    check_names: List[str] = []
    inconclusive_checks: List[str] = []
    check_errors: List[str] = []
    if not isinstance(checks, list) or not checks:
        errors.append("checks missing or empty")
    else:
        for index, check in enumerate(checks):
            if not isinstance(check, dict):
                check_errors.append("check[" + str(index) + "] is not an object")
                continue
            name = check.get("name")
            check_names.append(str(name))
            check_status = check.get("status")
            if check_status == PASS:
                continue
            if (check_status == "INCONCLUSIVE" and
                    "outside the registered claim" in
                    str(check.get("detail", "")).lower()):
                inconclusive_checks.append(str(name))
                continue
            check_errors.append(str(name) + "=" + str(check_status))
        if check_errors:
            errors.extend(check_errors)

    failures = result.get("failures", [])
    invalid = result.get("invalid", [])
    inconclusive = result.get("inconclusive", [])
    for field, value in (("failures", failures), ("invalid", invalid),
                         ("inconclusive", inconclusive)):
        if value not in ([], None):
            errors.append(field + " is non-empty")

    cleanup_checks = sorted({
        name for name in check_names
        if any(token in name.lower() for token in
               ("cleanup", "settle", "residue"))
    })
    if not cleanup_checks:
        errors.append("no cleanup/settlement check")

    summary = {
        "cellId": cell,
        "path": str(path),
        "schema": result.get("schema"),
        "status": status,
        "checkCount": len(check_names),
        "cleanupChecks": cleanup_checks,
        "outOfScopeInconclusiveChecks": inconclusive_checks,
        "reason": result.get("reason", ""),
    }
    if errors:
        summary["errors"] = errors
    return summary, errors


def aggregate(bindings: Dict[str, Path], binding_errors: Sequence[str] = ()) -> Dict[str, Any]:
    cells: List[Dict[str, Any]] = []
    errors: List[str] = list(binding_errors)
    for cell in REQUIRED_CELLS:
        path = bindings.get(cell)
        if path is None:
            summary = {
                "cellId": cell,
                "path": None,
                "schema": None,
                "status": "MISSING",
                "checkCount": 0,
                "cleanupChecks": [],
                "errors": ["missing cell binding"],
            }
            cells.append(summary)
            errors.append(cell + " is missing")
            continue
        result, read_error = read_result(path)
        if result is None:
            summary = {
                "cellId": cell,
                "path": str(path),
                "schema": None,
                "status": "UNREADABLE",
                "checkCount": 0,
                "cleanupChecks": [],
                "errors": [read_error],
            }
            cells.append(summary)
            errors.append(cell + ": " + read_error)
            continue
        summary, cell_errors = check_cell(cell, path, result)
        cells.append(summary)
        errors.extend(cell + ": " + error for error in cell_errors)

    status = PASS if not errors else INCOMPLETE
    return {
        "schema": SCHEMA,
        "status": status,
        "reason": (
            "all registered A2 cells passed and cleanup checks are retained"
            if status == PASS else
            "one or more required A2 cells are missing, non-PASS, or invalid"
        ),
        "requiredCells": list(REQUIRED_CELLS),
        "architectureInterruption": False,
        "cells": cells,
        "errors": errors,
        "claims": [
            "A2-0 through A2-6 each passed at their registered bounded scope",
            "cell-level cleanup/settlement checks were present in every input",
        ] if status == PASS else [],
        "nonClaims": [
            "B1/B2 external-connect behavior or Internet reachability",
            "production capacity, long-lifecycle capacity, or underlay handover",
        ],
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cell-result", action="append", default=[], metavar="CELL=PATH",
        help="retained result.json binding; repeat once for each A2 cell",
    )
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    bindings, binding_errors = parse_bindings(args.cell_result)
    result = aggregate(bindings, binding_errors)
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                                encoding="utf-8")
    except OSError as error:
        print("aggregate verifier: unable to write output: " + str(error),
              file=sys.stderr)
        return 2
    print("A2 aggregate status=" + str(result["status"]) +
          " result=" + str(args.output))
    return 0 if result["status"] == PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
