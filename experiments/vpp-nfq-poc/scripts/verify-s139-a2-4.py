#!/usr/bin/env python3
"""Verify the bounded S139 A2-4 lifecycle/native UID-join bundle.

This verifier deliberately keeps the Java contract and the native resolver as
separate authorities.  AppA proves the real application tuple and UID; the
Java JSONL proves scope/cache state; the resolver ledger proves the native
query observed the same tuple.  Stage IDs are test-only metadata emitted by
the bounded Java/native seams and are required for a decisive join.

The runtime-stale stage is a real delayed Java completion crossing a generation
refresh.  Synthetic replay assertions remain auxiliary and never satisfy this
stage by themselves.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


PASS = "PASS"
FAIL = "FAIL"
INVALID = "INVALID"
INCONCLUSIVE = "INCONCLUSIVE"

MANIFEST_SCHEMA = "s139-a2-4-manifest/v1"
RESULT_SCHEMA = "s139-a2-4-result/v1"
STAGE_SCHEMA = "s139-a2-4-stage/v1"
APP_SCHEMA = "s139-a2-1-runtime/v1"
CONTRACT_SCHEMA = "uid-attribution-contract/v1"

EXPECTED_STAGES = (
    "A2-4-baseline",
    "A2-4-baseline-hit",
    "A2-4-refresh",
    "A2-4-refresh-hit",
    "A2-4-network-restart",
    "A2-4-unavailable",
    "A2-4-restore-miss",
    "A2-4-restore-hit",
    "A2-4-runtime-stale",
)

NATIVE_LINE = re.compile(
    r"resolver query=(?P<query>[0-9]+) proto=(?P<proto>[0-9]+) "
    r"(?P<src>\S+):(?P<src_port>[0-9]+) -> "
    r"(?P<dst>\S+):(?P<dst_port>[0-9]+) uid=(?P<uid>-?[0-9]+)"
    r"(?P<tail>.*)$"
)


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
    if not isinstance(value, dict):
        return None, "JSON value is not an object"
    return value, ""


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
        if not isinstance(value, dict):
            errors.append(f"line {line_number}: JSON value is not an object")
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


def as_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalized_address(value: Any) -> str:
    text = str(value or "").strip().strip("[]")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def canonical_key(family: str, source: Any, source_port: Any,
                  destination: Any, destination_port: Any,
                  protocol: str = "UDP") -> str:
    source_address = normalized_address(source)
    destination_address = normalized_address(destination)
    source_endpoint = f"{source_address}:{int(source_port)}"
    destination_endpoint = f"{destination_address}:{int(destination_port)}"
    first, second = sorted((source_endpoint, destination_endpoint))
    return f"{family}/{protocol.upper()}/{first}-{second}"


def path_from(evidence: Path, value: Any) -> Path:
    path = Path(str(value))
    return path if path.is_absolute() else evidence / path


def append_check(checks: List[Dict[str, str]], name: str, status: str,
                 detail: str) -> None:
    checks.append({"name": name, "status": status, "detail": detail})


def parse_tsv(path: Path) -> Dict[str, str]:
    text = read_text(path)
    if text is None:
        return {}
    values: Dict[str, str] = {}
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if "\t" in raw:
            key, value = raw.split("\t", 1)
        elif "=" in raw:
            key, value = raw.split("=", 1)
        else:
            continue
        values[key.strip()] = value.strip()
    return values


def zip_member_sha256(path: Path, member: str) -> Tuple[str, str]:
    try:
        with zipfile.ZipFile(path) as archive:
            data = archive.read(member)
    except (OSError, KeyError, zipfile.BadZipFile) as error:
        return "", str(error)
    return hashlib.sha256(data).hexdigest(), ""


def parse_native(text: str) -> Tuple[List[Dict[str, Any]], bool]:
    """Parse resolver observations and report whether generation/stale fields exist."""
    observations: List[Dict[str, Any]] = []
    has_native_stale = False
    for raw in text.splitlines():
        lowered = raw.lower()
        if "stale" in lowered and "generation" in lowered:
            has_native_stale = True
        match = NATIVE_LINE.search(raw)
        if not match:
            continue
        source = normalized_address(match.group("src"))
        destination = normalized_address(match.group("dst"))
        source_port = int(match.group("src_port"))
        destination_port = int(match.group("dst_port"))
        protocol_number = int(match.group("proto"))
        family = "ip6" if ":" in source or ":" in destination else "ip4"
        extras: Dict[str, str] = {}
        for token in match.group("tail").strip().split():
            if "=" in token:
                name, value = token.split("=", 1)
                extras[name] = value
        observations.append({
            "query": int(match.group("query")),
            "protocol": protocol_number,
            "family": family,
            "source": source,
            "source_port": source_port,
            "destination": destination,
            "destination_port": destination_port,
            "uid": int(match.group("uid")),
            "key": canonical_key(family, source, source_port,
                                  destination, destination_port),
            "cell_id": extras.get("cell", ""),
            "stage_id": extras.get("stage", ""),
            "generation": as_int(extras.get("generation")),
            "stale": extras.get("stale", "").lower() in ("1", "true", "yes"),
            "raw": raw,
        })
    return observations, has_native_stale


def stage_boundary(stage: Dict[str, Any], channel: str,
                   total: int) -> Tuple[Optional[int], Optional[int], str]:
    before = stage.get("before", {})
    after = stage.get("after", {})
    if not isinstance(before, dict) or not isinstance(after, dict):
        return None, None, "stage boundary lacks before/after objects"
    start = as_int(before.get(channel))
    end = as_int(after.get(channel))
    if start is None or end is None:
        return None, None, f"stage boundary lacks {channel} line counts"
    if start < 0 or end < start or end > total:
        return None, None, f"invalid {channel} boundary {start}:{end}/{total}"
    return start, end, ""


def stage_slice(values: Sequence[Any], stage: Dict[str, Any],
                channel: str) -> Tuple[List[Any], str]:
    start, end, error = stage_boundary(stage, channel, len(values))
    if error:
        # A metadata-only runner may omit line counts while the Java and
        # native ledgers carry a durable stage_id.  Prefer line ranges when
        # available, but accept that explicit identity join as the bounded
        # fallback; an untagged ledger remains inconclusive later.
        stage_id = str(stage.get("stage_id", ""))
        if channel in ("app", "contract") and stage_id:
            tagged = [item for item in values
                      if isinstance(item, dict)
                      and item.get("stage_id") == stage_id]
            if tagged:
                return tagged, ""
        if channel == "resolver" and stage_id:
            raw_text = "\n".join(str(item) for item in values)
            parsed, _ = parse_native(raw_text)
            tagged_raw = [item.get("raw", "") for item in parsed
                          if item.get("stage_id") == stage_id]
            if tagged_raw:
                return tagged_raw, ""
        return [], error
    assert start is not None and end is not None
    return list(values[start:end]), ""


def app_key(record: Dict[str, Any]) -> Optional[str]:
    try:
        return canonical_key(
            str(record["family"]), record["source_address"],
            int(record["source_port"]), record["destination_address"],
            int(record["destination_port"]), str(record["protocol"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


def app_adapter_key(record: Dict[str, Any]) -> Optional[str]:
    """Return TrafficAdapter's durable AppA canonical-key representation.

    TrafficAdapter intentionally keeps its source-compatible A2-1 key in a
    different envelope from the UID contract key.  The verifier joins the two
    representations through the exact family/protocol/tuple fields; it must
    not demand that the AppA string be rewritten into the Java key format.
    """
    try:
        family = str(record["family"])
        protocol = str(record["protocol"]).lower()
        source_port = int(record["source_port"])
        destination = normalized_address(record["destination_address"])
        destination_port = int(record["destination_port"])
        return f"{family}|{protocol}|{source_port}|{destination}:{destination_port}"
    except (KeyError, TypeError, ValueError):
        return None


def event_for(events: Sequence[Dict[str, Any]], outcome: str,
              key: Optional[str] = None) -> List[Dict[str, Any]]:
    result = [event for event in events
              if str(event.get("outcome", "")) == outcome]
    if key is not None:
        result = [event for event in result if str(event.get("key", "")) == key]
    return result


def event_uid_ok(events: Sequence[Dict[str, Any]], outcome: str,
                 key: str, expected_uid: int) -> bool:
    return any(as_int(event.get("uid")) == expected_uid
               for event in event_for(events, outcome, key))


def verify_provenance(manifest: Dict[str, Any], evidence: Path,
                      checks: List[Dict[str, str]],
                      invalid: List[str]) -> None:
    expected_uid = as_int(manifest.get("expectedAllowedUid"))
    package = str(manifest.get("appPackage", ""))
    mode = str(manifest.get("mode", ""))
    vpp_mode = as_int(manifest.get("vppMode"))
    receipt_path = path_from(
        evidence, manifest.get("vpnProvenance", "vpn-session-provenance.json"))
    receipt, receipt_error = read_json(receipt_path)
    receipt_ok = (receipt is not None
                  and receipt.get("schema") == "vpn-session-provenance/v1"
                  and receipt.get("receiptType") == "success"
                  and receipt.get("mode") == mode
                  and package in receipt.get("normalizedAllowedPackages", [])
                  and expected_uid is not None
                  and expected_uid in receipt.get("resolvedAllowedUids", []))
    append_check(checks, "vpn-session-provenance", PASS if receipt_ok else INVALID,
                 "VPN receipt joins allowed package and UID"
                 if receipt_ok else f"invalid VPN receipt: {receipt_error or receipt_path}")
    if not receipt_ok:
        invalid.append("VPN session provenance does not prove the registered AppA UID")

    start_path = path_from(
        evidence, manifest.get("vppStartProvenance", "vpp-start-provenance.json"))
    start, start_error = read_json(start_path)
    artifact_sha = "" if start is None else str(start.get("artifactSha256", ""))
    start_ok = (start is not None
                and start.get("schema") == "vpp-start-provenance/v1"
                and start.get("receiptType") == "native-start-outcome"
                and start.get("mode") == mode
                and as_int(start.get("vppMode")) == vpp_mode == 5
                and as_int(start.get("rc")) == 0
                and start.get("success") is True
                and start.get("artifactPresent") is True
                and bool(re.fullmatch(r"[0-9a-fA-F]{64}", artifact_sha)))
    append_check(checks, "vpp-start-provenance", PASS if start_ok else INVALID,
                 "vppMode=5 native start and tun plugin are durable"
                 if start_ok else f"invalid VPP start receipt: {start_error or start_path}")
    if not start_ok:
        invalid.append("VPP mode-5/plugin start provenance is missing or invalid")

    apk = manifest.get("apkProvenance")
    apk_ok = isinstance(apk, dict)
    if not apk_ok:
        invalid.append("apkProvenance is missing")
        append_check(checks, "apk-provenance", INVALID,
                     "manifest has no local/installed APK provenance")
        return

    required_hashes = (
        "vpnApkSha256", "appApkSha256", "pluginSha256",
        "installedVpnApkSha256", "installedAppApkSha256",
    )
    for field in required_hashes:
        value = str(apk.get(field, ""))
        if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            invalid.append(f"apk provenance field {field} is not a SHA-256")
    vpn_apk = path_from(evidence, apk.get("vpnApkPath", ""))
    app_apk = path_from(evidence, apk.get("appApkPath", ""))
    local_hash_ok = (bool(sha256(vpn_apk)) and sha256(vpn_apk).lower()
                     == str(apk.get("vpnApkSha256", "")).lower()
                     and bool(sha256(app_apk)) and sha256(app_apk).lower()
                     == str(apk.get("appApkSha256", "")).lower())
    installed_hash_ok = (str(apk.get("installedVpnApkSha256", "")).lower()
                         == str(apk.get("vpnApkSha256", "")).lower()
                         and str(apk.get("installedAppApkSha256", "")).lower()
                         == str(apk.get("appApkSha256", "")).lower())
    append_check(checks, "apk-local-hashes", PASS if local_hash_ok else INVALID,
                 "local APK bytes match manifest hashes"
                 if local_hash_ok else "local APK hash mismatch or file missing")
    append_check(checks, "apk-installed-hashes",
                 PASS if installed_hash_ok else INVALID,
                 "installed package hashes match local APKs"
                 if installed_hash_ok else "installed APK hash equality is not proven")
    if not local_hash_ok:
        invalid.append("local APK hashes do not match apkProvenance")
    if not installed_hash_ok:
        invalid.append("installed APK hashes do not match local APK hashes")

    tsv_path = path_from(evidence, manifest.get("apkProvenanceFile",
                                                "apk-provenance.tsv"))
    tsv = parse_tsv(tsv_path)
    tsv_ok = all(tsv.get(field, "").lower() == str(apk.get(field, "")).lower()
                 for field in required_hashes)
    append_check(checks, "apk-provenance-ledger", PASS if tsv_ok else INVALID,
                 "apk-provenance.tsv binds local, installed, and plugin hashes"
                 if tsv_ok else "apk-provenance.tsv is missing or disagrees")
    if not tsv_ok:
        invalid.append("APK provenance ledger disagrees with manifest")

    manifest_plugin_sha = str(apk.get("pluginSha256", "")).lower()
    embedded_asset = ""
    embedded_plugin = ""
    asset_error = ""
    plugin_error = ""
    try:
        with zipfile.ZipFile(vpn_apk) as archive:
            embedded_asset = archive.read("assets/vpp-tun-poc-plugin.sha256") \
                .decode("utf-8", errors="replace").strip().splitlines()[0]
            plugin_member = str(apk.get("pluginMember", "lib/arm64-v8a/libtun_poc_plugin.so"))
            embedded_plugin = hashlib.sha256(archive.read(plugin_member)).hexdigest()
    except (OSError, KeyError, IndexError, zipfile.BadZipFile) as error:
        asset_error = str(error)
    plugin_ok = (embedded_asset.lower() == manifest_plugin_sha
                 and embedded_plugin.lower() == manifest_plugin_sha
                 and artifact_sha.lower() == manifest_plugin_sha)
    append_check(checks, "tun-plugin-hash-join", PASS if plugin_ok else INVALID,
                 "APK asset, native-start receipt, and plugin member agree"
                 if plugin_ok else "tun plugin hash join failed: " + (asset_error or plugin_error))
    if not plugin_ok:
        invalid.append("tun plugin hash is not bound across APK and native receipt")

    installs_path = path_from(evidence, manifest.get("installProvenanceFile",
                                                    "install-provenance.json"))
    installs, installs_error = read_json(installs_path)
    install_ok = (installs is not None and installs.get("vpnInstallRc") == 0
                  and installs.get("appInstallRc") == 0
                  and installs.get("vpnInstallOutcome") == "Success"
                  and installs.get("appInstallOutcome") == "Success")
    append_check(checks, "apk-install-receipts", PASS if install_ok else INVALID,
                 "both APK install receipts report Success"
                 if install_ok else f"install receipt missing/failed: {installs_error}")
    if not install_ok:
        invalid.append("APK installation receipts are not successful")


def verify(manifest: Dict[str, Any], evidence: Path) -> Dict[str, Any]:
    checks: List[Dict[str, str]] = []
    invalid: List[str] = []
    failures: List[str] = []
    inconclusive: List[str] = []

    expected_uid = as_int(manifest.get("expectedAllowedUid"))
    app_package = str(manifest.get("appPackage", ""))
    family = str(manifest.get("family", ""))
    protocol = str(manifest.get("protocol", ""))
    destination_host = normalized_address(manifest.get("destinationHost", ""))
    destination_port = as_int(manifest.get("destinationPort"))
    evidence_map = manifest.get("evidence")

    if manifest.get("schema") != MANIFEST_SCHEMA:
        invalid.append(f"manifest schema is not {MANIFEST_SCHEMA}")
    if manifest.get("profile") != "a2-4":
        invalid.append("manifest profile is not a2-4")
    if manifest.get("cellId") != "A2-4":
        invalid.append("manifest cellId is not A2-4")
    if manifest.get("architecture_interruption") is not False:
        invalid.append("architecture_interruption must be false")
    if not app_package or expected_uid is None or expected_uid < 0:
        invalid.append("registered AppA package/UID is missing")
    if family != "ip4" or protocol != "udp" or destination_port != 53:
        invalid.append("bounded fixture must be IPv4/UDP destination port 53")
    if manifest.get("mode") != "vpp-hev-owner-resolver":
        invalid.append("manifest mode is not vpp-hev-owner-resolver")
    if as_int(manifest.get("vppMode")) != 5:
        invalid.append("manifest vppMode is not 5")
    registration = manifest.get("registration")
    registration_ok = (isinstance(registration, dict)
                       and registration.get("status") == "registered"
                       and registration.get("appPackage") == app_package
                       and as_int(registration.get("expectedAllowedUid")) == expected_uid
                       and registration.get("mode") == manifest.get("mode")
                       and as_int(registration.get("vppMode")) == 5)
    append_check(checks, "baseline-registration",
                 PASS if registration_ok else INVALID,
                 "baseline package/UID/mode registration is durable"
                 if registration_ok else "baseline registration is missing or disagrees")
    if not registration_ok:
        invalid.append("baseline registration is missing or disagrees with manifest")
    if not isinstance(evidence_map, dict):
        invalid.append("manifest evidence map is missing")
        evidence_map = {}

    stages_value = manifest.get("stages")
    stages: List[Dict[str, Any]] = [stage for stage in stages_value
                                    if isinstance(stage, dict)] \
        if isinstance(stages_value, list) else []
    stage_map = {str(stage.get("stage_id", stage.get("id", ""))): stage
                 for stage in stages}
    missing_stages = [stage for stage in EXPECTED_STAGES if stage not in stage_map]
    if missing_stages:
        invalid.append("missing stage descriptors: " + ",".join(missing_stages))
    append_check(checks, "registered-stages", PASS if not missing_stages else INVALID,
                 "all bounded lifecycle stages are registered"
                 if not missing_stages else "stage descriptors are incomplete")

    verify_provenance(manifest, evidence, checks, invalid)

    app_path = path_from(evidence, evidence_map.get("appRuntime", ""))
    contract_path = path_from(evidence, evidence_map.get("contract", ""))
    resolver_path = path_from(evidence, evidence_map.get("resolver", ""))
    app_records, app_errors = read_jsonl(app_path)
    contract_events, contract_errors = read_jsonl(contract_path)
    resolver_text = read_text(resolver_path)
    if resolver_text is None:
        resolver_text = ""
        invalid.append("native resolver ledger is unreadable")
    for error in app_errors + contract_errors:
        invalid.append(error)
    append_check(checks, "jsonl-syntax",
                 PASS if not app_errors and not contract_errors else INVALID,
                 "AppA and Java contract JSONL parse cleanly"
                 if not app_errors and not contract_errors
                 else "AppA or Java contract JSONL contains malformed records")

    for event in contract_events:
        if event.get("schema") != CONTRACT_SCHEMA:
            invalid.append("contract event has unexpected schema")
            break
    append_check(checks, "contract-schema",
                 PASS if contract_events and not any(
                     event.get("schema") != CONTRACT_SCHEMA for event in contract_events)
                 else INVALID,
                 "Java UidAttributionContract schema is durable"
                 if contract_events and not any(
                     event.get("schema") != CONTRACT_SCHEMA for event in contract_events)
                 else "contract JSONL is absent or has the wrong schema")

    resolver_lines = resolver_text.splitlines()
    native_observations, native_stale_fields = parse_native(resolver_text)
    append_check(checks, "native-resolver-ledger", PASS if native_observations else INCONCLUSIVE,
                 "native resolver emitted tuple observations"
                 if native_observations else "native resolver tuple observations are absent")
    if not native_observations:
        inconclusive.append("native resolver did not emit a decisive tuple observation")

    stage_dir = evidence_map.get("stageDir", "stages")
    stage_docs: Dict[str, Dict[str, Any]] = {}
    for stage_id in EXPECTED_STAGES:
        descriptor = stage_map.get(stage_id)
        if descriptor is None:
            continue
        stage_file = path_from(evidence, Path(str(stage_dir)) / f"{stage_id}.json")
        stage_doc, stage_error = read_json(stage_file)
        if stage_doc is None:
            invalid.append(f"stage boundary {stage_id} missing: {stage_error}")
            continue
        if stage_doc.get("schema") != STAGE_SCHEMA or stage_doc.get("stage_id") != stage_id:
            invalid.append(f"stage boundary {stage_id} has wrong schema/id")
            continue
        stage_docs[stage_id] = stage_doc
    append_check(checks, "stage-boundaries",
                 PASS if len(stage_docs) == len([x for x in EXPECTED_STAGES if x in stage_map])
                 else INVALID,
                 "durable stage boundaries or metadata identity files are available"
                 if len(stage_docs) == len([x for x in EXPECTED_STAGES if x in stage_map])
                 else "one or more stage boundaries are missing/invalid")

    app_by_stage: Dict[str, List[Dict[str, Any]]] = {}
    key_by_stage: Dict[str, str] = {}
    for record in app_records:
        stage_id = str(record.get("stage_id", ""))
        if not stage_id.startswith("A2-4-"):
            continue
        app_by_stage.setdefault(stage_id, []).append(record)
        key = app_key(record)
        if key is None:
            invalid.append(f"AppA record {stage_id} lacks a canonical tuple")
            continue
        key_by_stage.setdefault(stage_id, key)
        if record.get("schema") != APP_SCHEMA:
            invalid.append(f"AppA record {stage_id} has wrong schema")
        if record.get("package") != app_package and record.get("app_package") != app_package:
            failures.append(f"AppA package mismatch in {stage_id}")
        if as_int(record.get("uid")) != expected_uid:
            failures.append(f"AppA UID mismatch in {stage_id}")
        if record.get("family") != family or str(record.get("protocol", "")).lower() != protocol:
            failures.append(f"AppA family/protocol mismatch in {stage_id}")
        if record.get("bind_result") != "bound" or record.get("tuple_attempted") is not True:
            failures.append(f"AppA VPN bind/tuple admission failed in {stage_id}")
        if record.get("send_connect_outcome") != "udp_datagram_sent":
            failures.append(f"AppA UDP send failed in {stage_id}")
        if as_int(record.get("vpn_network_handle")) is None \
                or as_int(record.get("vpn_network_handle")) <= 0:
            failures.append(f"AppA VPN network handle missing in {stage_id}")
        adapter_key = app_adapter_key(record)
        if adapter_key is None or str(record.get("canonical_key", "")) != adapter_key:
            failures.append(f"AppA TrafficAdapter canonical_key mismatch in {stage_id}")

    native_by_port = {item["source_port"]: [] for item in native_observations}
    for item in native_observations:
        native_by_port.setdefault(item["source_port"], []).append(item)

    baseline_handles = {
        as_int(item.get("vpn_network_handle"))
        for item in app_by_stage.get("A2-4-baseline", [])
        if as_int(item.get("vpn_network_handle")) is not None
    }
    restart_handles = {
        as_int(item.get("vpn_network_handle"))
        for item in app_by_stage.get("A2-4-network-restart", [])
        if as_int(item.get("vpn_network_handle")) is not None
    }
    network_handle_changed = bool(baseline_handles and restart_handles
                                  and baseline_handles.isdisjoint(restart_handles))
    append_check(checks, "vpn-network-handle-restart",
                 PASS if network_handle_changed else INCONCLUSIVE,
                 "VPN restart produced a distinct Network handle"
                 if network_handle_changed
                 else "baseline and post-restart Network handles are not decisively distinct")
    if not network_handle_changed:
        inconclusive.append("VPN restart did not prove a distinct Network handle")

    for stage_id in EXPECTED_STAGES:
        descriptor = stage_map.get(stage_id)
        stage_doc = stage_docs.get(stage_id)
        if descriptor is None or stage_doc is None:
            continue
        contract_slice, contract_error = stage_slice(contract_events, stage_doc, "contract")
        native_raw_slice, native_error = stage_slice(resolver_lines, stage_doc, "resolver")
        native_slice, _ = parse_native("\n".join(native_raw_slice))
        app_slice, app_error = stage_slice(app_records, stage_doc, "app")
        if contract_error or native_error or app_error:
            invalid.append(f"{stage_id}: " + "; ".join(
                error for error in (contract_error, native_error, app_error) if error))
            continue
        if manifest.get("javaStageJoinRequired", True):
            tagged_contract = [event for event in contract_slice
                               if event.get("stage_id") == stage_id]
            if not tagged_contract:
                inconclusive.append(f"{stage_id}: Java contract stage_id join is absent")
            else:
                append_check(checks, f"java-stage-join-{stage_id}", PASS,
                             "Java contract event carries the registered stage_id")
        kind = str(descriptor.get("kind", ""))
        expected_outcomes = descriptor.get("contractOutcomes", [])
        if not isinstance(expected_outcomes, list):
            invalid.append(f"{stage_id}: contractOutcomes is not a list")
            continue
        key = key_by_stage.get(stage_id)
        for outcome in expected_outcomes:
            outcome_text = str(outcome)
            outcome_key = key
            if outcome_text in ("SCOPE_REFRESH", "LOOKUP_PROVIDER_AVAILABLE",
                                "LOOKUP_UNAVAILABLE"):
                outcome_key = None
            if kind == "runtime-stale" and outcome_text == "COMPLETION_STALE":
                outcome_key = key
            found = event_for(contract_slice, outcome_text, outcome_key)
            if not found:
                inconclusive.append(f"{stage_id}: missing {outcome_text}")
        if stage_id != "A2-4-runtime-stale" and not app_by_stage.get(stage_id):
            inconclusive.append(f"{stage_id}: AppA EMIT record is absent")
        if stage_id != "A2-4-runtime-stale" and not app_slice:
            inconclusive.append(f"{stage_id}: AppA record is outside its stage boundary")

        if kind == "refresh":
            reasons = [str(event.get("reason", "")) for event in contract_slice
                       if event.get("outcome") == "SCOPE_REFRESH"]
            if not any("app-refresh=intent" in reason for reason in reasons):
                inconclusive.append("A2-4-refresh: app epoch refresh marker missing")
            lookup_events = [event for event in contract_slice
                             if event.get("outcome") in ("MISS_SUBMITTED", "COMPLETION_ACCEPTED")]
            if not lookup_events or any(
                    (as_int(event.get("app_epoch")) or 0) < 2
                    for event in lookup_events):
                inconclusive.append("A2-4-refresh: post-app-refresh lookup epoch is not decisive")

        if kind == "network-restart":
            reasons = [str(event.get("reason", "")) for event in contract_slice
                       if event.get("outcome") == "SCOPE_REFRESH"]
            if not any("network-refresh=intent" in reason for reason in reasons):
                inconclusive.append("A2-4-network-restart: network epoch refresh marker missing")

        if kind == "runtime-stale":
            stale_events = [event for event in contract_slice
                            if event.get("outcome") == "COMPLETION_STALE"
                            and event.get("key") == key]
            generation_refresh = [event for event in contract_slice
                                  if event.get("outcome") == "SCOPE_REFRESH"
                                  and "runtime-generation=intent" in
                                  str(event.get("reason", ""))]
            if not stale_events:
                inconclusive.append("A2-4-runtime-stale: real stale completion is absent")
            if not generation_refresh:
                inconclusive.append("A2-4-runtime-stale: generation refresh marker is absent")

        native_mode = str(descriptor.get("nativeObservation", "none"))
        source_port = as_int(descriptor.get("sourcePort"))
        if native_mode != "none":
            observations = [item for item in native_slice
                            if item.get("protocol") == 17
                            and (source_port is None or item.get("source_port") == source_port)]
            if manifest.get("nativeStageJoinRequired", True):
                tagged_native = [item for item in observations
                                 if item.get("stage_id") == stage_id]
                if not tagged_native:
                    inconclusive.append(f"{stage_id}: native resolver stage join is absent")
                else:
                    observations = tagged_native
            if not observations:
                inconclusive.append(f"{stage_id}: native {native_mode} observation is absent")
            elif key and not any(item.get("key") == key for item in observations):
                failures.append(f"{stage_id}: native resolver tuple does not join AppA key")
            elif native_mode in ("miss", "unavailable", "stale") \
                    and not any(item.get("uid") == -1 for item in observations):
                failures.append(f"{stage_id}: native resolver miss sentinel is not -1")
            elif native_mode == "sequence":
                ordered = sorted(observations, key=lambda item: item.get("query", 0))
                miss_indexes = [index for index, item in enumerate(ordered)
                                if item.get("uid") == -1]
                hit_indexes = [index for index, item in enumerate(ordered)
                               if item.get("uid") == expected_uid]
                if not miss_indexes:
                    failures.append(f"{stage_id}: native sequence lacks uid=-1 miss")
                elif not any(index > miss_indexes[0] for index in hit_indexes):
                    failures.append(f"{stage_id}: native sequence lacks post-miss AppA UID")
                else:
                    append_check(checks, f"native-{stage_id}", PASS,
                                 "native resolver observed miss then AppA UID sequence")
            elif native_mode == "hit":
                if any(item.get("uid") == expected_uid for item in observations):
                    append_check(checks, f"native-{stage_id}", PASS,
                                 "native resolver cache UID joins the AppA tuple")
                elif any(item.get("uid", -1) >= 0 for item in observations):
                    failures.append(f"{stage_id}: native resolver returned the wrong UID")
                else:
                    inconclusive.append(f"{stage_id}: native cache hit UID is absent")
            elif native_mode in ("miss", "unavailable", "stale"):
                append_check(checks, f"native-{stage_id}", PASS,
                             "native resolver observed the expected miss sentinel")

        if key and any(event_for(contract_slice, outcome, key)
                       for outcome in ("COMPLETION_ACCEPTED", "CACHE_HIT")):
            append_check(checks, f"contract-app-join-{stage_id}", PASS,
                         "Java contract canonical key joins the AppA record")

    refresh_events = [event for event in contract_events
                      if event.get("outcome") == "SCOPE_REFRESH"]
    refresh_epochs_ok = (any("app-refresh=intent" in str(event.get("reason", ""))
                             for event in refresh_events)
                         and any("network-refresh=intent" in str(event.get("reason", ""))
                                 for event in refresh_events))
    append_check(checks, "app-network-refresh-epochs",
                 PASS if refresh_epochs_ok else INCONCLUSIVE,
                 "app and network scope refresh markers are durable"
                 if refresh_epochs_ok else "app/network refresh epoch evidence is incomplete")
    if not refresh_epochs_ok:
        inconclusive.append("app/network refresh epoch evidence is incomplete")

    replay_events = [event for event in contract_events
                     if event.get("outcome") == "REPLAY_ASSERTION"]
    java_stale_ok = any(
        event.get("stage_id") == "A2-4-runtime-stale"
        and event.get("outcome") == "COMPLETION_STALE"
        and "not-live-pending" in str(event.get("reason", ""))
        for event in contract_events
    ) and any(
        event.get("stage_id") == "A2-4-runtime-stale"
        and event.get("outcome") == "SCOPE_REFRESH"
        and "runtime-generation=intent" in str(event.get("reason", ""))
        for event in contract_events
    )
    append_check(checks, "java-generation-stale-replay",
                 PASS if java_stale_ok else INCONCLUSIVE,
                 "Java contract records wrong-generation and stale replay outcomes"
                 if java_stale_ok else "Java runtime-generation/stale replay is not decisive")
    if not java_stale_ok:
        inconclusive.append("Java runtime-generation/stale replay evidence is incomplete")
    runtime_refresh_ok = any(event.get("outcome") == "RUNTIME_REFRESH"
                             and (as_int(event.get("generation")) or 0) >= 2
                             for event in contract_events)
    append_check(checks, "runtime-generation-refresh", PASS if runtime_refresh_ok else INCONCLUSIVE,
                 "contract runtime generation advanced at startup"
                 if runtime_refresh_ok else "runtime generation refresh marker is absent")
    if not runtime_refresh_ok:
        inconclusive.append("runtime generation refresh marker is absent")

    native_stale_required = bool(manifest.get("staleNativeJoinRequired", False))
    native_stale_join_ok = native_stale_fields and any(
        item.get("stage_id") == "A2-4-runtime-stale" and item.get("stale")
        for item in native_observations)
    # Resolver sees the original request, while Java owns stale completion;
    # A2-4 does not claim a native stale state that the plugin does not expose.
    append_check(checks, "native-stale-join", INCONCLUSIVE,
                 "native stale completion is outside the registered claim; Java late completion is joined")
    if native_stale_required and native_stale_join_ok:
        append_check(checks, "native-stale-join-observed", PASS,
                     "native resolver emitted an explicit stale-generation marker")

    cleanup_path = path_from(evidence, evidence_map.get("cleanup", "cleanup-wait.json"))
    cleanup, cleanup_error = read_json(cleanup_path)
    cleanup_ok = (cleanup is not None
                  and cleanup.get("cleanupObservedBeforeForceStop") is True
                  and cleanup.get("forceStopFallback") is False)
    append_check(checks, "cleanup-settlement", PASS if cleanup_ok else INVALID,
                 "cleanup settled before force-stop"
                 if cleanup_ok else f"cleanup settlement is not durable: {cleanup_error}")
    if not cleanup_ok:
        invalid.append("cleanup did not settle before force-stop")
    cleanup_events = [event for event in contract_events
                      if event.get("outcome") == "CLEANUP"]
    cleanup_contract_ok = any(as_int(event.get("pending")) == 0
                              and as_int(event.get("cache")) == 0
                              for event in cleanup_events)
    append_check(checks, "contract-cleanup", PASS if cleanup_contract_ok else INVALID,
                 "Java contract cleanup has zero pending/cache state"
                 if cleanup_contract_ok else "Java contract cleanup event is absent/incomplete")
    if not cleanup_contract_ok:
        invalid.append("Java contract cleanup did not prove zero pending/cache")

    generic_cleanup_path = path_from(evidence, evidence_map.get("cleanupLedger", "cleanup.txt"))
    generic_cleanup = read_text(generic_cleanup_path) or ""
    generic_cleanup_ok = ("cleanup_no_vpp=true" in generic_cleanup
                          and "cleanup_no_tun=true" in generic_cleanup
                          and "transport_failures=0" in generic_cleanup)
    append_check(checks, "native-cleanup-ledger",
                 PASS if generic_cleanup_ok else INVALID,
                 "native process/TUN cleanup and transport failure gate are recorded"
                 if generic_cleanup_ok else "native cleanup ledger is incomplete")
    if not generic_cleanup_ok:
        invalid.append("native cleanup/transport gate is incomplete")

    status = FAIL if failures else INVALID if invalid else INCONCLUSIVE if inconclusive else PASS
    reasons = failures + invalid + inconclusive
    return {
        "schema": RESULT_SCHEMA,
        "profile": "a2-4",
        "cellId": "A2-4",
        "status": status,
        "reason": "; ".join(reasons) if reasons else "A2-4 lifecycle/native join passed",
        "checks": checks,
        "claims": {
            "baselineRegistered": not missing_stages,
            "appNetworkRefreshEpoch": refresh_epochs_ok,
            "providerUnavailableRestore": all(
                any(event_for(contract_events, outcome))
                for outcome in ("LOOKUP_UNAVAILABLE", "LOOKUP_PROVIDER_AVAILABLE")),
            "restoreMissCompletionHit": all(
                event_for(contract_events, outcome, key_by_stage.get(stage_id))
                for stage_id, outcome in (
                    ("A2-4-restore-miss", "MISS_SUBMITTED"),
                    ("A2-4-restore-miss", "COMPLETION_ACCEPTED"),
                    ("A2-4-restore-hit", "CACHE_HIT"),
                )),
            "javaGenerationStaleReplay": java_stale_ok,
            "nativeStaleJoin": native_stale_join_ok,
            "cleanupObservedBeforeForceStop": cleanup_ok,
        },
        "architecture_interruption": False,
        "staleNativeJoinGap": not native_stale_join_ok,
        "failureReasons": failures,
        "invalidReasons": invalid,
        "inconclusiveReasons": inconclusive,
    }


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(list(argv) if argv is not None else None)

    manifest, error = read_json(args.manifest)
    if manifest is None:
        result: Dict[str, Any] = {
            "schema": RESULT_SCHEMA,
            "profile": "a2-4",
            "cellId": "A2-4",
            "status": INVALID,
            "reason": "manifest " + error,
            "checks": [],
            "architecture_interruption": False,
        }
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
