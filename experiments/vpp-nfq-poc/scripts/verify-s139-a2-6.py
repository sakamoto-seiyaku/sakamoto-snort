#!/usr/bin/env python3
"""Verify the S139 A2-6 replay and settlement aggregate.

The replay control exercises the live Android UID contract state machine.  A
real AppA UDP tuple is also admitted through the current VPP -> HEV protect
seam so the aggregate proves both replay rejection and resource settlement;
synthetic replay events never stand in for that transport evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PASS = "PASS"
FAIL = "FAIL"
INVALID = "INVALID"
INCONCLUSIVE = "INCONCLUSIVE"
MANIFEST_SCHEMA = "s139-a2-6-manifest/v1"
RESULT_SCHEMA = "s139-a2-6-result/v1"
CONTRACT_SCHEMA = "uid-attribution-contract/v1"
APP_SCHEMA = "s139-a2-1-runtime/v1"
RESOLVER_CORRELATION_SCHEMA = "a2-1-resolver-cell-stage-request/v1"
PUBLIC_RESOLVER_HOSTS = {"1.1.1.1", "2606:4700:4700::1111"}

EXPECTED_REPLAY = {
    "wrong-owner": ("COMPLETION_WRONG_OWNER", True),
    "wrong-uid": ("COMPLETION_WRONG_UID", False),
    "wrong-generation": ("COMPLETION_WRONG_GENERATION", True),
    "wrong-scope": ("COMPLETION_WRONG_SCOPE", True),
    "accepted": ("COMPLETION_ACCEPTED", False),
    "duplicate": ("COMPLETION_DUPLICATE", True),
    "stale-after-refresh": ("COMPLETION_STALE", True),
}


def read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def read_json(path: Path) -> Tuple[Optional[Dict[str, Any]], str]:
    text = read_text(path)
    if text is None:
        return None, "unreadable"
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        return None, str(error)
    return value if isinstance(value, dict) else None, "not an object"


def read_jsonl(path: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
    text = read_text(path)
    if text is None:
        return [], ["unreadable"]
    records: List[Dict[str, Any]] = []
    errors: List[str] = []
    for line_no, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            errors.append(f"line {line_no}: {error}")
            continue
        if not isinstance(value, dict):
            errors.append(f"line {line_no}: not an object")
            continue
        records.append(value)
    return records, errors


def sha256(path: Path) -> str:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def parse_properties(path: Path) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for raw in (read_text(path) or "").splitlines():
        if "=" in raw:
            key, value = raw.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def as_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def verify_s156_guardrails(manifest: Dict[str, Any],
                           invalid: List[str]) -> None:
    if manifest.get("uidContractCellId") != "A2-6":
        invalid.append("uidContractCellId is not A2-6")
    if manifest.get("resolverCorrelationSchema") != RESOLVER_CORRELATION_SCHEMA:
        invalid.append("resolverCorrelationSchema is not " + RESOLVER_CORRELATION_SCHEMA)
    fixture = manifest.get("fixture")
    if not isinstance(fixture, dict):
        invalid.append("controlled fixture is missing")
        return
    if fixture.get("schema") != "s152-a2-1-fixture/v1":
        invalid.append("controlled fixture schema is invalid")
    if fixture.get("publicInternetClaim") is not False:
        invalid.append("controlled fixture must mark publicInternetClaim=false")
    for field in ("host4", "host6"):
        value = fixture.get(field)
        if not isinstance(value, str) or not value:
            invalid.append(f"controlled fixture {field} is missing")
        elif value.strip("[]") in PUBLIC_RESOLVER_HOSTS:
            invalid.append(f"controlled fixture {field} uses public resolver endpoint")
    for field in ("tcpPort", "udpPort"):
        port = as_int(fixture.get(field))
        if port is None or port < 1 or port > 65535:
            invalid.append(f"controlled fixture {field} is invalid")
    destination_host = manifest.get("destinationHost")
    destination_port = as_int(manifest.get("destinationPort"))
    if not isinstance(destination_host, str) or not destination_host:
        invalid.append("destinationHost is missing")
    elif destination_host.strip("[]") in PUBLIC_RESOLVER_HOSTS:
        invalid.append("destinationHost uses public resolver endpoint")
    if destination_port is None or destination_port < 1 or destination_port > 65535:
        invalid.append("destinationPort is invalid")


def check(checks: List[Dict[str, str]], name: str, status: str,
          detail: str) -> None:
    checks.append({"name": name, "status": status, "detail": detail})


def ledger_events(text: str, event: str, stage: str, key: str) -> List[Dict[str, str]]:
    result: List[Dict[str, str]] = []
    for raw in text.splitlines():
        if "ledger event=" not in raw or f"event={event}" not in raw:
            continue
        fields: Dict[str, str] = {}
        for token in raw.split():
            if "=" in token:
                name, value = token.split("=", 1)
                fields[name] = value
        if fields.get("stage-id") == stage and fields.get("canonical-key") == key:
            result.append(fields)
    return result


def replay_assertion(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if record.get("outcome") != "REPLAY_ASSERTION":
        return None
    reason = str(record.get("reason", ""))
    fields: Dict[str, Any] = {}
    for token in reason.split(";"):
        if "=" not in token:
            continue
        name, value = token.split("=", 1)
        fields[name] = value
    case = fields.get("case")
    outcome = fields.get("outcome")
    if not isinstance(case, str) or not isinstance(outcome, str):
        return None
    for name in ("pending-before", "pending-after", "cache-before", "cache-after"):
        try:
            fields[name] = int(fields[name])
        except (KeyError, TypeError, ValueError):
            return None
    fields["unchanged"] = str(fields.get("unchanged", "")).lower() == "true"
    fields["case"] = case
    fields["outcome"] = outcome
    fields["record"] = record
    return fields


def parse_cleanup_reason(records: Iterable[Dict[str, Any]]) -> List[Dict[str, int]]:
    result: List[Dict[str, int]] = []
    pattern = re.compile(
        r"pending=(\d+);cache=(\d+);max-pending=(\d+);max-cache=(\d+);"
        r"flow-ids=(\d+);max-flow-ids=(\d+)"
    )
    for record in records:
        if record.get("outcome") != "CLEANUP":
            continue
        match = pattern.search(str(record.get("reason", "")))
        if match:
            names = ("pending", "cache", "max_pending", "max_cache",
                     "flow_ids", "max_flow_ids")
            result.append({name: int(value) for name, value in zip(names, match.groups())})
    return result


def cleanup_file_ok(path: Path) -> Tuple[bool, str]:
    doc, error = read_json(path)
    if doc is None:
        return False, error
    expected = (doc.get("cleanupObservedBeforeForceStop") is True
                and doc.get("nativeCleanupObserved") is True
                and doc.get("contractCleanupObserved") is True
                and doc.get("forceStopFallback") is False)
    return expected, "orderly cleanup observed before force-stop" if expected else str(doc)


def process_cleanup_ok(path: Path) -> Tuple[bool, str]:
    text = read_text(path)
    if text is None:
        return False, "unreadable"
    sections: Dict[str, List[str]] = {}
    current = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.endswith(":") and line[:-1] in ("processes", "tun0"):
            current = line[:-1]
            sections[current] = []
        elif current and line:
            sections[current].append(line)
    if "processes" not in sections or "tun0" not in sections:
        return False, "cleanup sections missing"
    if sections["processes"] or sections["tun0"]:
        return False, "process or tun0 residue present"
    return True, "no VPP/VpnLite process or tun0 residue"


def verify(manifest: Dict[str, Any], evidence: Path) -> Dict[str, Any]:
    checks: List[Dict[str, str]] = []
    failures: List[str] = []
    invalid: List[str] = []
    inconclusive: List[str] = []

    if manifest.get("schema") != MANIFEST_SCHEMA:
        invalid.append(f"manifest schema is not {MANIFEST_SCHEMA}")
    if manifest.get("profile") != "a2-6" or manifest.get("cellId") != "A2-6":
        invalid.append("manifest is not A2-6")
    verify_s156_guardrails(manifest, invalid)

    required = manifest.get("requiredFiles")
    if not isinstance(required, list) or not all(isinstance(item, str) and item for item in required):
        invalid.append("requiredFiles is not a string array")
        required = []
    else:
        missing = [item for item in required if not (evidence / item).is_file()]
        if missing:
            invalid.append("required raw evidence missing: " + ",".join(missing))

    props = parse_properties(evidence / str(manifest.get("sourceProvenanceFile",
                                                        "source-provenance.properties")))
    if props.get("gitDirty") == "true":
        invalid.append("source provenance is dirty")
    for field in ("vpnApkSha256", "appAApkSha256", "tunPluginSha256"):
        expected = str(manifest.get(field, ""))
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            invalid.append(f"manifest {field} is missing/invalid")
        elif props.get(field) != expected:
            invalid.append(f"{field} provenance mismatch")
    apk_provenance = read_text(evidence / str(manifest.get("apkProvenanceFile",
                                                            "apk-provenance.tsv"))) or ""
    for package in (manifest.get("vpnPackage"), manifest.get("allowedPackage")):
        if not isinstance(package, str) or package not in apk_provenance:
            invalid.append("installed APK provenance is incomplete")

    contract_name = str(manifest.get("contractFile", "uid-attribution-contract.jsonl"))
    final_contract_name = str(manifest.get("contractFinalFile",
                                           "uid-attribution-contract-final.jsonl"))
    contract, contract_errors = read_jsonl(evidence / contract_name)
    final_contract, final_errors = read_jsonl(evidence / final_contract_name)
    if contract_errors or final_errors:
        invalid.append("contract JSONL has parse/read errors")
    all_contract = contract + final_contract
    if any(item.get("schema") != CONTRACT_SCHEMA for item in all_contract):
        invalid.append("contract schema mismatch")

    replay_stage = str(manifest.get("replayStage", "A2-6-replay"))
    transport_stage = str(manifest.get("transportStage", "A2-6-transport"))
    stage_markers = [item for item in contract
                     if item.get("outcome") == "STAGE_BEGIN"
                     and item.get("stage_id") == replay_stage]
    if len(stage_markers) != 1:
        invalid.append(f"expected one {replay_stage} STAGE_BEGIN")
    else:
        check(checks, "replay-stage", PASS, "replay stage is durably registered")

    replay_records = []
    for record in contract:
        if record.get("stage_id") != replay_stage:
            continue
        parsed = replay_assertion(record)
        if parsed is not None:
            replay_records.append(parsed)
    by_case: Dict[str, List[Dict[str, Any]]] = {}
    for item in replay_records:
        by_case.setdefault(str(item["case"]), []).append(item)
    for case, (expected_outcome, expected_unchanged) in EXPECTED_REPLAY.items():
        entries = by_case.get(case, [])
        if len(entries) != 1:
            invalid.append(f"replay case {case} count {len(entries)} != 1")
            continue
        entry = entries[0]
        if entry["outcome"] != expected_outcome:
            failures.append(f"replay {case} outcome {entry['outcome']} != {expected_outcome}")
        if entry["unchanged"] != expected_unchanged:
            failures.append(f"replay {case} unchanged={entry['unchanged']} != {expected_unchanged}")
        if any(entry[name] < 0 or entry[name] > 4
               for name in ("pending-before", "pending-after", "cache-before", "cache-after")):
            failures.append(f"replay {case} exceeded pending/cache capacity")
    extra_cases = sorted(set(by_case) - set(EXPECTED_REPLAY))
    if extra_cases:
        invalid.append("unexpected replay cases: " + ",".join(extra_cases))
    mutation = [item for item in contract
                 if item.get("stage_id") == replay_stage
                 and item.get("outcome") == "FLOW_OWNER_KEY_MUTATION_REJECTED"]
    cross_app = [item for item in contract
                 if item.get("stage_id") == replay_stage
                 and item.get("outcome") == "CROSS_APP_CACHE_HIT_REJECTED"]
    if len(mutation) != 1:
        invalid.append(f"FLOW_OWNER_KEY_MUTATION_REJECTED count {len(mutation)} != 1")
    if len(cross_app) != 1:
        invalid.append(f"CROSS_APP_CACHE_HIT_REJECTED count {len(cross_app)} != 1")
    if len(replay_records) == len(EXPECTED_REPLAY) and len(mutation) == 1 and len(cross_app) == 1:
        check(checks, "replay-falsifiers", PASS,
              "wrong-owner/UID/generation/scope, accepted, duplicate, and stale replay cases joined")

    cleanup_states = parse_cleanup_reason(all_contract)
    if not cleanup_states:
        invalid.append("contract CLEANUP state is missing")
    elif any(item["pending"] != 0 or item["cache"] != 0 or item["flow_ids"] != 0
             for item in cleanup_states):
        failures.append("contract cleanup left pending/cache/flow residue")
    else:
        max_pending = max(item["max_pending"] for item in cleanup_states)
        max_cache = max(item["max_cache"] for item in cleanup_states)
        max_flow_ids = max(item["max_flow_ids"] for item in cleanup_states)
        if max_pending > 4 or max_cache > 4 or max_flow_ids > 8:
            failures.append("contract high-water exceeded declared capacity")
        else:
            check(checks, "contract-bounds-settlement", PASS,
                  f"max_pending={max_pending} max_cache={max_cache} max_flow_ids={max_flow_ids}; final residue zero")

    cleanup_ok, cleanup_detail = cleanup_file_ok(
        evidence / str(manifest.get("cleanupFile", "cleanup-wait.json")))
    if cleanup_ok:
        check(checks, "orderly-cleanup", PASS, cleanup_detail)
    else:
        invalid.append("cleanup wait evidence invalid: " + cleanup_detail)
    process_ok, process_detail = process_cleanup_ok(
        evidence / str(manifest.get("processCleanupFile", "cleanup.txt")))
    if process_ok:
        check(checks, "process-tun-settlement", PASS, process_detail)
    else:
        invalid.append("process/tun cleanup invalid: " + process_detail)

    app_file = evidence / str(manifest.get("appEvidenceFile", "app-runtime.jsonl"))
    app_records, app_errors = read_jsonl(app_file)
    expected_uid = manifest.get("expectedAllowedUid")
    source_port = int(manifest.get("sourcePort", 0))
    destination_port = int(manifest.get("destinationPort", 0))
    destination_host = str(manifest.get("destinationHost", ""))
    candidates = [item for item in app_records
                  if item.get("schema") == APP_SCHEMA
                  and item.get("stage_id") == transport_stage
                  and item.get("app_package") == manifest.get("allowedPackage")
                  and item.get("uid") == expected_uid
                  and item.get("source_port") == source_port
                  and item.get("destination_port") == destination_port
                  and item.get("destination_address", destination_host) == destination_host]
    if not candidates:
        invalid.append("AppA transport tuple evidence is missing")
    else:
        # A2-6 deliberately sends a bounded repeat burst on one socket.  The
        # runtime ledger may contain several records for that exact key; the
        # verifier joins the final record while requiring every candidate to
        # stay within the same package/UID/tuple identity.
        app = candidates[-1]
        candidate_keys = {str(item.get("canonical_key", "")) for item in candidates}
        candidate_uids = {item.get("uid") for item in candidates}
        if len(candidate_keys) != 1 or len(candidate_uids) != 1:
            failures.append("AppA repeated transport records diverged in UID or canonical key")
        if app.get("bind_result") != "bound" or app.get("tuple_attempted") is not True:
            failures.append("AppA transport tuple was not VPN-bound and attempted")
        expected_key = str(app.get("canonical_key", ""))
        resolver = read_text(evidence / str(manifest.get("resolverFile",
                                                            "vpp-owner-resolver.log"))) or ""
        stdout = read_text(evidence / str(manifest.get("stdoutFile", "vpp-stdout.log"))) or ""
        protect = read_text(evidence / str(manifest.get("protectFile", "vpp-protect.log"))) or ""
        policy = ledger_events(resolver, "POLICY_DECISION", transport_stage, expected_key)
        admitted = ledger_events(stdout, "TRANSPORT_ADMITTED", transport_stage, expected_key)
        downstream = {name: ledger_events(protect, name, transport_stage, expected_key)
                      for name in ("BROKER_REQUEST", "BROKER_COMPLETION",
                                   "SOCKET_CREATED", "SOCKET_SETTLED")}
        if len(policy) != 1 or policy[0].get("decision") != "ALLOW":
            invalid.append("transport policy allow evidence is missing")
        if len(admitted) != 1:
            failures.append(f"transport admitted count {len(admitted)} != 1")
        if any(len(events) != 1 for events in downstream.values()):
            failures.append("transport broker/socket lifecycle is not exactly one each")
        if len(policy) == 1 and len(admitted) == 1 and all(len(events) == 1 for events in downstream.values()):
            check(checks, "real-transport-settlement", PASS,
                  "one real AppA allow flow crossed policy and settled broker/socket lifecycle")
        if app_errors:
            invalid.append("AppA runtime JSONL has parse errors")

    cli = read_text(evidence / str(manifest.get("cliFile", "vpp-cli.log"))) or ""
    if not re.search(r"resolver enabled 1 .*queries [1-9][0-9]* .*errors 0", cli):
        invalid.append("native resolver query evidence is missing")
    if not re.search(r"owner-cache enabled [01] .*hits [0-9]+ .*misses [0-9]+ .*stores [0-9]+", cli):
        invalid.append("native owner-cache bounds evidence is missing")
    else:
        check(checks, "native-ledger-bounds", PASS,
              "native resolver/owner-cache counters are present and bounded by the live show ledger")

    if failures:
        status = FAIL
        reason = "; ".join(failures)
    elif invalid:
        status = INVALID
        reason = "; ".join(invalid)
    elif inconclusive:
        status = INCONCLUSIVE
        reason = "; ".join(inconclusive)
    elif len(checks) < 6:
        status = INCONCLUSIVE
        reason = "A2-6 evidence is incomplete"
    else:
        status = PASS
        reason = "A2-6 replay and settlement aggregate passed"
    return {"schema": RESULT_SCHEMA, "status": status, "reason": reason,
            "checks": checks, "failures": failures, "invalid": invalid,
            "inconclusive": inconclusive, "claims": manifest.get("claims", {})}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    manifest, error = read_json(args.manifest)
    if manifest is None:
        result = {"schema": RESULT_SCHEMA, "status": INVALID,
                  "reason": f"manifest unreadable: {error}"}
    else:
        result = verify(manifest, args.evidence_dir)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(json.dumps({"status": result.get("status"), "reason": result.get("reason")},
                     sort_keys=True))
    return {PASS: 0, FAIL: 1, INVALID: 2, INCONCLUSIVE: 3}.get(result.get("status"), 2)


if __name__ == "__main__":
    sys.exit(main())
