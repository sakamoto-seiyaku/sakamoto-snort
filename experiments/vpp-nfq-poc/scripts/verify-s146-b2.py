#!/usr/bin/env python3
"""Verify the durable negative-outcome contract for the S146 B2 cells.

The verifier deliberately joins the app and native records by the controlled
cell and consumes the last record for that cell.  It is a small evidence gate,
not a replacement for the Android runner: missing or ambiguous records are
invalid rather than silently accepted.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


EXPECTED = {
    "refused": {
        "outcome": "EXPECTED_TRANSPORT_REFUSAL",
        "app_result": "EXPECTED_TRANSPORT_FAILURE",
    },
    "no-reply": {
        "outcome": "EXPECTED_TIMEOUT",
        "app_result": "EXPECTED_NO_REPLY_TIMEOUT",
    },
    "policy-drop": {
        "outcome": "EXPECTED_POLICY_DROP",
        "app_result": "EXPECTED_POLICY_DROP_NO_TRANSPORT",
    },
}


def _last_matching(lines: list[str], pattern: str) -> str | None:
    matches = [line.strip() for line in lines if re.search(pattern, line)]
    return matches[-1] if matches else None


def _fields(line: str) -> dict[str, str]:
    return dict(re.findall(r"([A-Za-z][A-Za-z0-9_-]*)=([^\s]+)", line))


def verify(cell: str, app_text: str, native_text: str) -> tuple[bool, list[str]]:
    if cell not in EXPECTED:
        return False, [f"unsupported negative cell: {cell}"]

    app_line = _last_matching(app_text.splitlines(), rf"\bcell={re.escape(cell)}\b")
    native_line = _last_matching(
        native_text.splitlines(),
        rf"\boi3_cleanup\b.*\boutcome={re.escape(EXPECTED[cell]['outcome'])}\b",
    )
    errors: list[str] = []
    if app_line is None:
        errors.append(f"missing app record for cell={cell}")
    if native_line is None:
        errors.append(f"missing native cleanup for outcome={EXPECTED[cell]['outcome']}")
    if errors:
        return False, errors

    app = _fields(app_line or "")
    native = _fields(native_line or "")
    if app.get("result") != EXPECTED[cell]["app_result"]:
        errors.append(
            f"app result={app.get('result', '<missing>')} "
            f"expected={EXPECTED[cell]['app_result']}"
        )
    if native.get("result") != "PASS_EXPECTED_FAILURE":
        errors.append(
            f"native result={native.get('result', '<missing>')} "
            "expected=PASS_EXPECTED_FAILURE"
        )
    if native.get("outcome") != EXPECTED[cell]["outcome"]:
        errors.append(
            f"native outcome={native.get('outcome', '<missing>')} "
            f"expected={EXPECTED[cell]['outcome']}"
        )

    def require(name: str, expected: str | None = None) -> None:
        value = native.get(name)
        if value is None:
            errors.append(f"native missing {name}")
        elif expected is not None and value != expected:
            errors.append(f"native {name}={value} expected={expected}")

    require("residue", "0")
    require("infrastructure-failures", "0")
    if cell == "refused":
        require("broker", "1/1")
        require("endpoint", "0/0")
        require("direct", "0")
        try:
            if int(native.get("transport-failures", "0")) <= 0:
                errors.append("refused cell has no transport failure")
        except ValueError:
            errors.append("refused transport-failures is not numeric")
    elif cell == "no-reply":
        require("broker", "1/1")
        require("direct", "0")
        endpoint = native.get("endpoint", "")
        if not re.fullmatch(r"[1-9][0-9]*/0", endpoint):
            errors.append(f"no-reply endpoint={endpoint or '<missing>'} expected=positive/0")
    else:
        require("output", "0")
        require("direct", "0")
        require("broker", "0/0")
        require("transport-failures", "0")

    return not errors, errors


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cell", required=True, choices=sorted(EXPECTED))
    parser.add_argument("--app-log", required=True, type=Path)
    parser.add_argument("--native-log", required=True, type=Path)
    args = parser.parse_args(argv)
    ok, errors = verify(
        args.cell,
        args.app_log.read_text(encoding="utf-8"),
        args.native_log.read_text(encoding="utf-8"),
    )
    if ok:
        print(f"PASS cell={args.cell} negative-outcome-contract=1")
        return 0
    for error in errors:
        print(f"FAIL cell={args.cell} {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
