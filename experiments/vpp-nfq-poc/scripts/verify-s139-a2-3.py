#!/usr/bin/env python3
"""Verify the bounded S139 A2-3 controlled reverse-return evidence bundle.

The App JSONL is the UID/package authority.  OI3/VPP is the packet-path
authority.  A result is PASS only when the two ledgers join on stage,
direction-independent canonical key, and exact payload; counters alone are
never sufficient.
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
INVALID = "INVALID"
INCONCLUSIVE = "INCONCLUSIVE"
SCHEMA = "s139-a2-3-manifest/v1"
APP_SCHEMA = "s139-a2-3-return/v1"
OI3_SCHEMA = "s139-a2-3-oi3/v1"


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
        return None, f"invalid JSON: {error}"
    return value if isinstance(value, dict) else None, "not an object"


def read_jsonl(path: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
    text = read_text(path)
    if text is None:
        return [], ["unreadable"]
    records: List[Dict[str, Any]] = []
    errors: List[str] = []
    for line_number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            errors.append(f"line {line_number}: invalid JSON: {error}")
            continue
        if isinstance(value, dict):
            records.append(value)
        else:
            errors.append(f"line {line_number}: JSON value is not an object")
    return records, errors


def parse_kv_lines(text: str, prefix: str) -> List[Dict[str, str]]:
    result: List[Dict[str, str]] = []
    for raw in text.splitlines():
        if prefix not in raw:
            continue
        fields: Dict[str, str] = {}
        for token in raw.split():
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            fields[key] = value
        result.append(fields)
    return result


def append_check(checks: List[Dict[str, str]], name: str, status: str,
                 detail: str) -> None:
    checks.append({"name": name, "status": status, "detail": detail})


def sha256(path: Path) -> str:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def verify(manifest: Dict[str, Any], evidence: Path) -> Dict[str, Any]:
    checks: List[Dict[str, str]] = []
    invalid: List[str] = []
    failures: List[str] = []
    inconclusive: List[str] = []
    expected_uid = manifest.get("expectedAllowedUid")

    if manifest.get("schema") != SCHEMA:
        invalid.append(f"manifest schema is not {SCHEMA}")
    if manifest.get("profile") != "a2-3":
        invalid.append("manifest profile is not a2-3")
    if manifest.get("cellId") != "A2-3":
        invalid.append("manifest cellId is not A2-3")
    required_fields = (
        "vpnPackage", "allowedPackage", "expectedAllowedUid", "mode",
        "vppMode", "stageId", "family", "protocol", "sourcePort",
        "destinationHost", "destinationPort", "appEvidenceFile",
        "oi3EvidenceFile", "contractFile", "cleanupFile",
        "vpnReceiptFile", "vppStartFile", "apkProvenanceFile",
        "buildProvenanceFile", "installVpnFile", "installAppAFile",
        "expectedOi3PluginSha256", "oi3PluginAsset",
    )
    for field in required_fields:
        if field not in manifest:
            invalid.append(f"manifest field missing: {field}")
    append_check(checks, "manifest", INVALID if invalid else PASS,
                 "; ".join(invalid) if invalid else "A2-3 manifest is registered")

    paths = {
        name: evidence / str(manifest[name])
        for name in ("appEvidenceFile", "oi3EvidenceFile", "contractFile",
                     "cleanupFile", "vpnReceiptFile", "vppStartFile",
                     "apkProvenanceFile", "buildProvenanceFile",
                     "installVpnFile", "installAppAFile")
        if name in manifest and isinstance(manifest[name], str)
    }
    missing = [name for name, path in paths.items() if not path.is_file()]
    if missing:
        invalid.append("required evidence missing: " + ", ".join(missing))
    append_check(checks, "required-evidence", INVALID if missing else PASS,
                 "required raw evidence is present" if not missing
                 else "; ".join(missing))

    vpn_receipt, vpn_receipt_error = read_json(
        paths.get("vpnReceiptFile", Path("/")))
    start_receipt, start_receipt_error = read_json(
        paths.get("vppStartFile", Path("/")))
    provenance_text = read_text(paths.get("buildProvenanceFile", Path("/"))) or ""
    apk_provenance_text = read_text(paths.get("apkProvenanceFile", Path("/"))) or ""
    install_vpn_text = read_text(paths.get("installVpnFile", Path("/"))) or ""
    install_app_text = read_text(paths.get("installAppAFile", Path("/"))) or ""
    provenance_values = {
        key: value.strip() for key, value in
        (line.split("=", 1) for line in provenance_text.splitlines()
         if "=" in line)
    }
    provenance_hashes = [value for key, value in provenance_values.items()
                         if key.endswith("Sha256")]
    installed_by_package: Dict[str, List[str]] = {}
    for line in apk_provenance_text.splitlines():
        fields = line.split("\t", 2)
        if len(fields) == 3:
            installed_by_package.setdefault(fields[0], []).append(fields[2].strip())
    installed_hashes = [value for values in installed_by_package.values()
                        for value in values]
    provenance_ok = (isinstance(vpn_receipt, dict)
                     and vpn_receipt.get("schema") == "vpn-session-provenance/v1"
                     and vpn_receipt.get("receiptType") == "success"
                     and manifest.get("allowedPackage") in
                     vpn_receipt.get("normalizedAllowedPackages", [])
                     and expected_uid in vpn_receipt.get("resolvedAllowedUids", []))
    start_ok = (isinstance(start_receipt, dict)
                and start_receipt.get("schema") == "vpp-start-provenance/v1"
                and start_receipt.get("success") is True
                and start_receipt.get("rc") == 0
                and start_receipt.get("vppMode") == manifest.get("vppMode"))
    vpn_hash = provenance_values.get("vpnApkSha256", "")
    app_hash = provenance_values.get("appAApkSha256", "")
    plugin_hash = provenance_values.get("oi3PluginSha256", "")
    expected_plugin_hash = manifest.get("expectedOi3PluginSha256", "")
    hashes_ok = (len(provenance_hashes) >= 3
                 and all(len(value) == 64 for value in provenance_hashes)
                 and len(installed_hashes) >= 2
                 and all(len(value) == 64 for value in installed_hashes)
                 and vpn_hash in installed_by_package.get(manifest.get("vpnPackage"), [])
                 and app_hash in installed_by_package.get(manifest.get("allowedPackage"), [])
                 and len(expected_plugin_hash) == 64
                 and plugin_hash == expected_plugin_hash)
    install_ok = "Success" in install_vpn_text and "Success" in install_app_text
    if not provenance_ok:
        invalid.append("VPN session provenance receipt is not a successful allowed-UID join")
    if not start_ok:
        invalid.append("native VPP start provenance is not successful for the manifest mode")
    if not hashes_ok:
        invalid.append("APK/build provenance hashes are incomplete")
    if not install_ok:
        invalid.append("exact APK install receipts are not successful")
    append_check(checks, "build-and-session-provenance",
                 PASS if provenance_ok and start_ok and hashes_ok and install_ok else INVALID,
                 "APK install receipts, hashes, VPN receipt, and native-start receipt are durable"
                 if provenance_ok and start_ok and hashes_ok and install_ok
                 else "build/session provenance is incomplete or mismatched")

    app_records, app_errors = read_jsonl(paths.get("appEvidenceFile", Path("/")))
    if app_errors and paths.get("appEvidenceFile", Path("/")).is_file():
        invalid.append("App JSONL contains malformed records")
    app_matches = [record for record in app_records
                   if record.get("schema") == APP_SCHEMA
                   and record.get("cell_id") == "A2-3"
                   and record.get("stage_id") == manifest.get("stageId")
                   and record.get("uid") == expected_uid
                   and record.get("app_package") == manifest.get("allowedPackage")
                   and record.get("family") == manifest.get("family")
                   and record.get("protocol") == "udp"
                   and record.get("bind_result") == "bound"
                   and record.get("tuple_attempted") is True
                   and record.get("send_connect_outcome") == "udp_roundtrip_received"
                   and record.get("return_received") is True
                   and record.get("received_payload_hex") == record.get("payload_hex")
                   and record.get("received_length") == record.get("payload_length")]
    if not app_matches:
        inconclusive.append("no correct-UID same-socket UDP return record")
    append_check(checks, "app-same-socket-return",
                 PASS if app_matches else INCONCLUSIVE,
                 "correct App UID received exact payload on the bound socket"
                 if app_matches else "waiting for decisive App return record")

    app = app_matches[-1] if app_matches else {}
    canonical = app.get("canonical_key", "")
    payload_hex = app.get("payload_hex", "")
    if app and (not canonical or not payload_hex):
        invalid.append("App return record lacks canonical key or payload")
    if app and app.get("android_lookup_count") != 0:
        failures.append("App return record reports an Android lookup")

    if app and (app.get("source_port") != manifest.get("sourcePort")
                or app.get("destination_port") != manifest.get("destinationPort")
                or app.get("destination_host") != manifest.get("destinationHost")):
        failures.append("App return tuple differs from the manifest")

    oi3_text = read_text(paths.get("oi3EvidenceFile", Path("/"))) or ""
    oi3_events = parse_kv_lines(oi3_text, "oi3 a2-3 schema=")
    starts = [item for item in oi3_events if item.get("event") == "START"]
    ingresses = [item for item in oi3_events if item.get("event") == "INGRESS"]
    outputs = [item for item in oi3_events if item.get("event") == "OUTPUT"]
    cleanups = [item for item in oi3_events if item.get("event") == "CLEANUP"]
    owner_identity_threads = re.findall(
        r"oi3 owner-identity .* owner-pthread=([0-9]+)", oi3_text)
    if any(item.get("schema") != OI3_SCHEMA for item in oi3_events):
        invalid.append("OI3 ledger schema mismatch")
    if not starts:
        inconclusive.append("OI3 A2-3 START event missing")
    if not ingresses or not outputs:
        inconclusive.append("OI3 ingress/output return seam is incomplete")
    append_check(checks, "oi3-return-seam",
                 PASS if ingresses and outputs else INCONCLUSIVE,
                 "OI3 durable ingress and owner-output events are present"
                 if ingresses and outputs else "OI3 durable return events not observed")

    joined = bool(app and ingresses and outputs)
    if joined:
        ingress = ingresses[-1]
        output = outputs[-1]
        expected_native_family = "6" if manifest.get("family") == "ip6" else "4"
        for label, item in (("ingress", ingress), ("output", output)):
            if item.get("stage-id") != manifest.get("stageId"):
                invalid.append(f"OI3 {label} stage mismatch")
            if item.get("family") != expected_native_family:
                invalid.append(f"OI3 {label} family mismatch")
            if item.get("protocol") != "UDP":
                invalid.append(f"OI3 {label} protocol mismatch")
            if item.get("canonical-key") != canonical:
                failures.append(f"OI3 {label} canonical key differs from App")
            if item.get("payload-hex") != payload_hex:
                failures.append(f"OI3 {label} payload differs from App")
            if item.get("android-lookup-count") != "0":
                failures.append(f"OI3 {label} Android lookup count is not zero")
            if item.get("transport-reentry") != "0":
                failures.append(f"OI3 {label} transport re-entry is nonzero")
            if item.get("uid-join") != "app-jsonl:canonical-key":
                invalid.append(f"OI3 {label} UID join marker missing")
            if item.get("package-join") != "app-jsonl:canonical-key":
                invalid.append(f"OI3 {label} package join marker missing")
        if ingress.get("direction") != "ORIG":
            invalid.append("OI3 ingress is not ORIG")
        if output.get("direction") != "REPLY":
            invalid.append("OI3 output is not REPLY")
        if ingress.get("owner") != output.get("owner"):
            failures.append("OI3 reverse event changed owner")
        output_owner_pthread = output.get("owner-pthread", "")
        if not output_owner_pthread.isdigit() or int(output_owner_pthread) <= 0:
            invalid.append("OI3 OUTPUT lacks a nonzero owner-pthread identity")
        if not owner_identity_threads:
            invalid.append("OI3 owner-identity context marker is missing")
        elif output_owner_pthread != owner_identity_threads[-1]:
            failures.append("OI3 OUTPUT owner-pthread differs from owner-identity")
        if cleanups and cleanups[-1].get("stage-id") != manifest.get("stageId"):
            invalid.append("OI3 cleanup stage mismatch")
        if cleanups and cleanups[-1].get("canonical-key") != canonical:
            failures.append("OI3 cleanup canonical key differs from App")
    append_check(checks, "canonical-payload-uid-stage-join",
                 INVALID if any("join" in item for item in invalid)
                 else PASS if joined and not failures else INCONCLUSIVE,
                 "App UID/package joins to native stage/canonical/payload"
                 if joined and not failures else "join is incomplete or mismatched")

    owner_context_status = INCONCLUSIVE
    owner_context_detail = "owner context is not available without a joined OUTPUT"
    if joined:
        output_owner_pthread = outputs[-1].get("owner-pthread", "")
        owner_context_ok = (output_owner_pthread.isdigit()
                            and int(output_owner_pthread) > 0
                            and bool(owner_identity_threads)
                            and output_owner_pthread == owner_identity_threads[-1])
        owner_context_status = PASS if owner_context_ok else INVALID
        owner_context_detail = ("OUTPUT owner-pthread matches durable owner-identity"
                                if owner_context_ok
                                else "OUTPUT owner-pthread does not match durable owner-identity")
    append_check(checks, "owner-context-identity", owner_context_status,
                 owner_context_detail)

    native_path = paths.get("oi3EvidenceFile", Path("/"))
    if native_path.is_file():
        startup = "shared-graph=flow-stack-owner" in oi3_text and \
            "return=owner-output" in oi3_text and "reentry=0" in oi3_text
        append_check(checks, "owner-output-no-reentry",
                     PASS if startup else INVALID,
                     "owner Flow Stack return seam is explicitly recorded"
                     if startup else "owner-output/reentry marker missing")
        broker_request = "oi3 broker-request" in oi3_text
        broker_success = "oi3 broker-completion result=SUCCESS" in oi3_text
        append_check(checks, "broker-settlement",
                     PASS if broker_request and broker_success else INCONCLUSIVE,
                     "one broker request and successful completion observed"
                     if broker_request and broker_success
                     else "broker request/completion not decisive")

    cleanup_text = read_text(paths.get("cleanupFile", Path("/"))) or ""
    cleanup_wait, cleanup_error = read_json(paths.get("cleanupFile", Path("/")))
    cleanup_observed = isinstance(cleanup_wait, dict) and \
        cleanup_wait.get("cleanupObservedBeforeForceStop") is True
    native_cleanup = False
    if cleanups:
        try:
            native_cleanup = (cleanups[-1].get("residue") == "0"
                              and int(cleanups[-1].get("ingress", "0")) >= 1
                              and int(cleanups[-1].get("output", "0")) >= 1)
        except (TypeError, ValueError):
            native_cleanup = False
    if not cleanup_observed or not native_cleanup:
        invalid.append("durable cleanup before force-stop is missing")
    append_check(checks, "cleanup",
                 PASS if cleanup_observed and native_cleanup else INVALID,
                 "OI3 cleanup and bounded residue settlement observed"
                 if cleanup_observed and native_cleanup
                 else "cleanup wait/native CLEANUP did not settle")

    contract_text = read_text(paths.get("contractFile", Path("/"))) or ""
    contract_events = []
    for raw in contract_text.splitlines():
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            contract_events.append(value)
    lookup_events = [event for event in contract_events
                     if str(event.get("event", "")).startswith("MISS_")
                     or str(event.get("event", "")).startswith("LOOKUP_")]
    append_check(checks, "no-android-uid-lookup",
                 PASS if not lookup_events else INVALID,
                 "A2-3 uses no UID resolver lookup; broker bind/protect remains separate"
                 if not lookup_events else "UID resolver events were emitted")

    if failures:
        status = "FAIL"
    elif invalid:
        status = INVALID
    elif inconclusive:
        status = INCONCLUSIVE
    else:
        status = PASS
    reason_parts = failures + invalid + inconclusive
    return {
        "schema": "s139-a2-3-result/v1",
        "profile": "a2-3",
        "cellId": "A2-3",
        "status": status,
        "reason": "; ".join(reason_parts) if reason_parts else
        "controlled reverse return joined and settled",
        "checks": checks,
        "claims": {
            "sameSocketPayload": status == PASS,
            "canonicalOwnerReuse": status == PASS,
            "androidUidLookupCount": 0 if not lookup_events else None,
            "cleanupObservedBeforeForceStop": cleanup_observed,
            "architectureInterruption": False,
        },
        "architecture_interruption": False,
    }


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(list(argv) if argv is not None else None)
    manifest, error = read_json(args.manifest)
    if manifest is None:
        result = {"schema": "s139-a2-3-result/v1", "profile": "a2-3",
                  "cellId": "A2-3", "status": INVALID,
                  "reason": "manifest " + error, "checks": []}
    else:
        result = verify(manifest, args.evidence_dir)
    output = args.output or args.evidence_dir / "result.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("status") == PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
