#!/usr/bin/env python3
"""Verify the S139 A2-5 known-UID allow/drop admission ledger.

The AppA JSONL is the UID/package and exact-tuple authority.  The resolver,
VPP shim, and Android protect broker are the downstream authorities.  A PASS
requires one fresh allow key with a real broker/socket lifecycle and one fresh
drop key with a policy decision but zero downstream events.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PASS = "PASS"
FAIL = "FAIL"
INVALID = "INVALID"
INCONCLUSIVE = "INCONCLUSIVE"
MANIFEST_SCHEMA = "s139-a2-5-manifest/v1"
STAGE_SCHEMA = "s139-a2-5-stage/v1"
APP_SCHEMA = "s139-a2-1-runtime/v1"
RESOLVER_CORRELATION_SCHEMA = "a2-1-resolver-cell-stage-request/v1"
PUBLIC_RESOLVER_HOSTS = {"1.1.1.1", "2606:4700:4700::1111"}


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
        if isinstance(value, dict):
            records.append(value)
        else:
            errors.append(f"line {line_no}: not an object")
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
    text = read_text(path) or ""
    for raw in text.splitlines():
        if "=" in raw:
            key, value = raw.split("=", 1)
            result[key] = value
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
    if manifest.get("uidContractCellId") != "A2-5":
        invalid.append("uidContractCellId is not A2-5")
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


def ledger_events(text: str, event: str, stage: str, key: str) -> List[Dict[str, str]]:
    events: List[Dict[str, str]] = []
    for raw in text.splitlines():
        if "ledger event=" not in raw or f"event={event}" not in raw:
            continue
        fields: Dict[str, str] = {}
        for token in raw.split():
            if "=" in token:
                name, value = token.split("=", 1)
                fields[name] = value
        if fields.get("stage-id") == stage and fields.get("canonical-key") == key:
            events.append(fields)
    return events


def check(checks: List[Dict[str, str]], name: str, status: str, detail: str) -> None:
    checks.append({"name": name, "status": status, "detail": detail})


def app_record(stage: Dict[str, Any], evidence: Path, manifest: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], str]:
    records, errors = read_jsonl(evidence / str(stage["appEvidenceFile"]))
    expected_uid = manifest.get("expectedAllowedUid")
    expected_pkg = manifest.get("allowedPackage")
    expected_port = int(stage["sourcePort"])
    candidates = [item for item in records
                  if item.get("schema") == APP_SCHEMA
                  and item.get("stage_id") == stage["stageId"]
                  and item.get("app_package") == expected_pkg
                  and item.get("uid") == expected_uid
                  and item.get("family") == stage["family"]
                  and item.get("protocol") == stage["protocol"]
                  and item.get("source_port") == expected_port
                  and item.get("destination_port") == stage["destinationPort"]]
    if not candidates:
        return None, "AppA has no exact stage/package/UID/tuple record"
    item = candidates[-1]
    if item.get("bind_result") != "bound" or item.get("tuple_attempted") is not True:
        return item, "AppA did not bind and attempt the exact VPN tuple"
    destination = item.get("destination_address") or stage["destinationHost"]
    expected_key = (f"{stage['family']}|{stage['protocol']}|{expected_port}|"
                    f"{destination}:{stage['destinationPort']}")
    if item.get("canonical_key") != expected_key:
        return item, f"AppA canonical key {item.get('canonical_key')} != {expected_key}"
    if errors:
        return item, "AppA JSONL has parse errors: " + "; ".join(errors)
    return item, "exact AppA UID/tuple record is bound and canonical"


def verify_stage(manifest: Dict[str, Any], evidence: Path,
                  stage: Dict[str, Any], checks: List[Dict[str, str]],
                  failures: List[str], invalid: List[str]) -> None:
    stage_id = str(stage.get("stageId", ""))
    policy = str(stage.get("policy", ""))
    stage_dir = evidence / str(stage.get("evidenceDir", ""))
    stage_doc, stage_error = read_json(stage_dir / "stage.json")
    if stage_doc is None or stage_doc.get("schema") != STAGE_SCHEMA:
        invalid.append(f"{stage_id}: missing/invalid stage document ({stage_error})")
        return
    start_observed = bool(stage_doc.get("startObserved"))
    stage_control_observed = bool(stage_doc.get("stageControlObserved"))
    traffic_observed = bool(stage_doc.get("trafficObserved"))
    if not start_observed:
        invalid.append(f"{stage_id}: native VPP start was not observed")
    if not stage_control_observed:
        invalid.append(f"{stage_id}: stage-control barrier was not observed")
    if not traffic_observed:
        invalid.append(f"{stage_id}: traffic/resolver boundary was not observed")
    cleanup, cleanup_error = read_json(stage_dir / str(stage_doc.get("cleanupFile", "cleanup-wait.json")))
    if cleanup is None:
        invalid.append(f"{stage_id}: cleanup evidence missing ({cleanup_error})")
    elif cleanup.get("forceStopFallback"):
        invalid.append(f"{stage_id}: cleanup required force-stop fallback")
    else:
        check(checks, f"{stage_id}.cleanup", PASS, "orderly cleanup observed before force-stop")

    # A stage that never reached the native/traffic boundary is a preflight
    # invalidation, not a policy FAIL.  Do not let missing downstream records
    # manufacture a false behavioral verdict.
    if not start_observed or not stage_control_observed or not traffic_observed:
        return

    app, app_detail = app_record(stage_doc, stage_dir, manifest)
    if app is None:
        invalid.append(f"{stage_id}: {app_detail}")
        return
    expected_key = str(app.get("canonical_key"))
    if app_detail.startswith("exact AppA"):
        check(checks, f"{stage_id}.app-uid-tuple", PASS, app_detail)
    else:
        failures.append(f"{stage_id}: {app_detail}")

    resolver = read_text(stage_dir / str(stage_doc.get("resolverFile"))) or ""
    stdout = read_text(stage_dir / str(stage_doc.get("stdoutFile"))) or ""
    protect = read_text(stage_dir / str(stage_doc.get("protectFile"))) or ""
    cli = read_text(stage_dir / str(stage_doc.get("cliFile"))) or ""
    policy_events = ledger_events(resolver, "POLICY_DECISION", stage_id, expected_key)
    if len(policy_events) != 1:
        invalid.append(f"{stage_id}: expected one resolver POLICY_DECISION, got {len(policy_events)}")
    else:
        event = policy_events[0]
        expected_uid = int(manifest["expectedAllowedUid"])
        if event.get("uid") != str(expected_uid):
            failures.append(f"{stage_id}: resolver UID {event.get('uid')} != {expected_uid}")
        if event.get("decision") != policy.upper():
            failures.append(f"{stage_id}: resolver decision {event.get('decision')} != {policy.upper()}")
        else:
            check(checks, f"{stage_id}.policy-decision", PASS,
                  f"known AppA UID {expected_uid} decision={policy.upper()}")

    admitted = ledger_events(stdout, "TRANSPORT_ADMITTED", stage_id, expected_key)
    downstream = {name: ledger_events(protect, name, stage_id, expected_key)
                  for name in ("BROKER_REQUEST", "BROKER_COMPLETION",
                               "SOCKET_CREATED", "SOCKET_SETTLED")}
    if policy == "allow":
        if len(admitted) != 1:
            failures.append(f"{stage_id}: TRANSPORT_ADMITTED count {len(admitted)} != 1")
        else:
            check(checks, f"{stage_id}.transport-admitted", PASS,
                  "real tun_poc shim write crossed post-policy boundary")
        for event_name, events in downstream.items():
            if len(events) != 1:
                failures.append(f"{stage_id}: {event_name} count {len(events)} != 1")
        completion = downstream["BROKER_COMPLETION"]
        settled = downstream["SOCKET_SETTLED"]
        if completion and completion[0].get("result") != "1":
            failures.append(f"{stage_id}: broker completion result is not 1")
        if settled and settled[0].get("result") != "1":
            failures.append(f"{stage_id}: socket settlement result is not 1")
        if all(len(events) == 1 for events in downstream.values()):
            check(checks, f"{stage_id}.real-downstream", PASS,
                  "broker request/completion and socket create/settle joined exact key")
        match = re.findall(r"uid-block enabled \d+ uid (-?\d+) packets (\d+)", cli)
        if match and any(int(packets) != 0 for _, packets in match):
            failures.append(f"{stage_id}: allow stage reports UID-blocked packets")
    elif policy == "drop":
        if admitted:
            failures.append(f"{stage_id}: dropped key crossed TRANSPORT_ADMITTED")
        if any(downstream.values()):
            failures.append(f"{stage_id}: dropped key has downstream broker/socket events")
        if not admitted and not any(downstream.values()):
            check(checks, f"{stage_id}.zero-downstream", PASS,
                  "fresh dropped key has zero transport/broker/socket events")
        match = re.findall(r"uid-block enabled \d+ uid (-?\d+) packets (\d+)", cli)
        if not match or max(int(packets) for _, packets in match) < 1:
            invalid.append(f"{stage_id}: show tun-poc lacks uid-blocked packet evidence")
        else:
            check(checks, f"{stage_id}.uid-block", PASS, "known UID packet was blocked at tun_poc")
    else:
        invalid.append(f"{stage_id}: unknown policy {policy}")


def verify(manifest: Dict[str, Any], evidence: Path) -> Dict[str, Any]:
    checks: List[Dict[str, str]] = []
    failures: List[str] = []
    invalid: List[str] = []
    if manifest.get("schema") != MANIFEST_SCHEMA:
        invalid.append(f"manifest schema is not {MANIFEST_SCHEMA}")
    if manifest.get("profile") != "a2-5" or manifest.get("cellId") != "A2-5":
        invalid.append("manifest is not A2-5")
    verify_s156_guardrails(manifest, invalid)
    stages = manifest.get("stages")
    if not isinstance(stages, list) or len(stages) != 2:
        invalid.append("manifest must register exactly allow and drop stages")
    props = parse_properties(evidence / str(manifest.get("buildProvenanceFile", "source-provenance.properties")))
    if props.get("gitDirty") == "true":
        invalid.append("source provenance is dirty")
    for key in ("vpnApkSha256", "appAApkSha256", "tunPluginSha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(manifest.get(key, ""))):
            invalid.append(f"manifest {key} is missing/invalid")
    if props.get("vpnApkSha256") != manifest.get("vpnApkSha256"):
        invalid.append("VPN APK provenance mismatch")
    if props.get("appAApkSha256") != manifest.get("appAApkSha256"):
        invalid.append("AppA APK provenance mismatch")
    if props.get("tunPluginSha256") != manifest.get("tunPluginSha256"):
        invalid.append("tun_poc plugin provenance mismatch")
    apk_provenance = read_text(evidence / str(manifest.get("apkProvenanceFile", "apk-provenance.tsv"))) or ""
    if manifest.get("allowedPackage") not in apk_provenance or manifest.get("vpnPackage") not in apk_provenance:
        invalid.append("installed APK provenance is incomplete")
    if isinstance(stages, list):
        for stage in stages:
            if isinstance(stage, dict):
                verify_stage(manifest, evidence, stage, checks, failures, invalid)
            else:
                invalid.append("stage entry is not an object")
    stage_list = stages if isinstance(stages, list) else []
    if not any(isinstance(item, dict) and item.get("policy") == "allow"
               for item in stage_list):
        invalid.append("allow stage is not registered")
    if not any(isinstance(item, dict) and item.get("policy") == "drop"
               for item in stage_list):
        invalid.append("drop stage is not registered")
    if failures:
        status = FAIL
        reason = "; ".join(failures)
    elif invalid:
        status = INVALID
        reason = "; ".join(invalid)
    elif len(checks) < 6:
        status = INCONCLUSIVE
        reason = "A2-5 ledger evidence is incomplete"
    else:
        status = PASS
        reason = "A2-5 known-UID allow/drop admission ledger passed"
    return {"schema": "s139-a2-5-result/v1", "status": status, "reason": reason,
            "checks": checks, "failures": failures, "invalid": invalid,
            "claims": manifest.get("claims", {})}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    manifest, error = read_json(args.manifest)
    if manifest is None:
        result = {"schema": "s139-a2-5-result/v1", "status": INVALID,
                  "reason": f"manifest unreadable: {error}"}
    else:
        result = verify(manifest, args.evidence_dir)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result.get("status"), "reason": result.get("reason")}, sort_keys=True))
    return {PASS: 0, FAIL: 1, INVALID: 2, INCONCLUSIVE: 3}.get(result.get("status"), 2)


if __name__ == "__main__":
    sys.exit(main())
