#!/usr/bin/env python3
"""Manifest-driven verifier tracer for the revised SAKAMOTO-139 A2 cells.

The shell runners retain raw device evidence; this program only correlates it
and writes ``result.json``.  ``a2-0`` is intentionally the first profile, but
the dispatch table is an extension seam for A2-1..A2-6 readers.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


VERIFIER_SCHEMA = "s139-a2-verifier/v1"
MANIFEST_SCHEMA = "s139-a2-0-manifest/v1"
PROFILE_A20 = "a2-0"
MANIFEST_SCHEMA_A21 = "s139-a2-1-manifest/v1"
PROFILE_A21 = "a2-1"
PASS = "PASS"
FAIL = "FAIL"
INVALID = "INVALID"
INCONCLUSIVE = "INCONCLUSIVE"

DEFAULT_REQUIRED_FILES = (
    "package-list-packages-U.txt",
    "apk-provenance.tsv",
    "vpn-session-provenance.json",
    "vpp-start-provenance.json",
    "uid-attribution-contract.jsonl",
    "runtime-udp-traffic-probe.properties",
    "vpp-cli.log",
    "vpp-owner-resolver.log",
    "device-build.properties",
    "source-provenance.properties",
    "cleanup.txt",
)


def read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def parse_properties(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def package_snapshot(text: str) -> Dict[str, int]:
    result: Dict[str, int] = {}
    pattern = re.compile(r"^\s*package:(\S+)\s+uid:(\d+)\s*$")
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            result[match.group(1)] = int(match.group(2))
    return result


def expected_packages(manifest: Dict[str, Any]) -> List[str]:
    raw = manifest.get("allowedPackage", "")
    if not isinstance(raw, str):
        return []
    return sorted({part.strip() for part in raw.split(",") if part.strip()})


def append_check(checks: List[Dict[str, str]], name: str, status: str,
                 detail: str) -> None:
    checks.append({"name": name, "status": status, "detail": detail})


def canonical_config(receipt: Dict[str, Any]) -> str:
    profile = receipt.get("addressRouteProfile", {})
    ipv4 = profile.get("ipv4", {}) if isinstance(profile, dict) else {}
    ipv6 = profile.get("ipv6", {}) if isinstance(profile, dict) else {}

    def values(section: Dict[str, Any], key: str) -> Sequence[str]:
        value = section.get(key, [])
        return value if isinstance(value, list) else []

    allowed = receipt.get("normalizedAllowedPackages", [])
    if not isinstance(allowed, list):
        allowed = []
    lines = [
        "mode=" + str(receipt.get("mode", "")),
        "mtu=" + str(receipt.get("mtu", "")),
        "allowedPackages=" + ",".join(str(value) for value in allowed),
        "disallowedPackage=" + str(receipt.get("normalizedDisallowedPackage", "")),
        "ipv4Addresses=" + ",".join(str(value) for value in values(ipv4, "addresses")),
        "ipv4Routes=" + ",".join(str(value) for value in values(ipv4, "routes")),
        "ipv6Addresses=" + ",".join(str(value) for value in values(ipv6, "addresses")),
        "ipv6Routes=" + ",".join(str(value) for value in values(ipv6, "routes")),
    ]
    return "\n".join(lines) + "\n"


def verify_cleanup(text: str) -> Tuple[bool, str]:
    sections: Dict[str, List[str]] = {}
    current: Optional[str] = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        if line.endswith(":") and line[:-1] in ("processes", "tun0", "vpn"):
            current = line[:-1]
            sections[current] = []
            continue
        if current is not None and line.strip():
            sections[current].append(line.strip())
    if "processes" not in sections or "tun0" not in sections:
        return False, "cleanup markers missing"
    if sections["processes"]:
        return False, "VPP/service processes remain: " + "; ".join(sections["processes"])
    if sections["tun0"]:
        return False, "tun0 residue remains: " + "; ".join(sections["tun0"])
    return True, "process and tun0 sections are empty"


def resolver_lines(text: str, host: str, source_port: int, port: int,
                   uid: int, protocol: int, family: str) -> Tuple[bool, bool]:
    """Return (matching UID line, wrong UID line) for the exact tuple."""
    escaped_host = re.escape(host)
    host_pattern = escaped_host
    if family == "ip6":
        host_pattern = r"\[?" + escaped_host + r"\]?"
    pattern = re.compile(
        r"resolver\s+query=\d+\s+proto=" + str(protocol)
        + r"\s+.*:" + str(source_port) + r"\s+->\s+"
        + host_pattern + r":" + str(port) + r"\s+uid=(-?\d+)"
    )
    matching = False
    wrong = False
    for line in text.splitlines():
        match = pattern.search(line)
        if not match:
            continue
        if int(match.group(1)) == uid:
            matching = True
        elif int(match.group(1)) >= 0:
            wrong = True
    return matching, wrong


def resolver_verdict(text: str, host: str, source_port: int, port: int,
                     uid: int, protocol: int, family: str) -> str:
    """Classify exact resolver evidence without treating the -1 miss as wrong UID."""
    matching, wrong = resolver_lines(text, host, source_port, port, uid, protocol, family)
    if wrong:
        return FAIL
    if matching:
        return PASS
    return INCONCLUSIVE


def verify_vpp_start(receipt: Any, expected_mode: str, expected_vpp_mode: int,
                     expected_artifact_sha256: str) -> Tuple[str, str]:
    """Validate the native-start instrumentation gate for an A2 VPP cell."""
    if not isinstance(receipt, dict):
        return INVALID, "native-start receipt is not an object"
    errors: List[str] = []
    if receipt.get("schema") != "vpp-start-provenance/v1":
        errors.append("schema")
    if receipt.get("receiptType") != "native-start-outcome":
        errors.append("receiptType")
    if receipt.get("mode") != expected_mode:
        errors.append("mode")
    vpp_mode = receipt.get("vppMode")
    if not isinstance(vpp_mode, int) or isinstance(vpp_mode, bool):
        errors.append("vppMode")
    elif vpp_mode != expected_vpp_mode:
        errors.append("vppMode-mismatch")
    rc = receipt.get("rc")
    if not isinstance(rc, int) or isinstance(rc, bool):
        errors.append("rc")
    success = receipt.get("success")
    if not isinstance(success, bool):
        errors.append("success")
    elif isinstance(rc, int) and not isinstance(rc, bool) and success != (rc == 0):
        errors.append("success-rc-mismatch")
    marker = receipt.get("monotonicNs")
    if not isinstance(marker, int) or isinstance(marker, bool) or marker <= 0:
        errors.append("monotonicNs")
    required = receipt.get("requiredArtifact")
    if expected_vpp_mode == 5 and required != "libtun_poc_plugin.so|tun_poc_plugin.so":
        errors.append("requiredArtifact")
    if receipt.get("artifactPresent") is not True:
        errors.append("artifactPresent")
    if receipt.get("artifactName") not in ("libtun_poc_plugin.so", "tun_poc_plugin.so"):
        errors.append("artifactName")
    digest = receipt.get("artifactSha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        errors.append("artifactSha256")
    elif digest != expected_artifact_sha256:
        errors.append("artifactSha256-mismatch")
    if isinstance(rc, int) and not isinstance(rc, bool) and rc != 0:
        errors.append("nativeStartRc=" + str(rc))
    if errors:
        return INVALID, ",".join(errors)
    return PASS, ("native start rc=0 vppMode=" + str(expected_vpp_mode)
                  + " artifact=" + str(receipt.get("artifactName"))
                  + " sha256=" + str(digest))


def vpp_tuple_lines(text: str, family: str, protocol: int, source: str,
                    source_port: int, host: str, port: int) -> bool:
    escaped_source = re.escape(source)
    escaped_host = re.escape(host)
    if family == "ip6":
        source_pattern = r"\[?" + escaped_source + r"\]?"
        host_pattern = r"\[?" + escaped_host + r"\]?"
    else:
        source_pattern = escaped_source
        host_pattern = escaped_host
    pattern = re.compile(
        r"last-tuple\s+" + re.escape(family) + r"\s+proto\s+" + str(protocol)
        + r"\s+" + source_pattern + r":" + str(source_port)
        + r"\s+->\s+" + host_pattern + r":" + str(port)
    )
    return any(pattern.search(line) for line in text.splitlines())


def read_json_object(path: Path) -> Tuple[Optional[Dict[str, Any]], str]:
    text = read_text(path)
    if text is None or not text.strip():
        return None, "missing or empty"
    try:
        value = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        return None, "malformed JSON: " + str(error)
    if not isinstance(value, dict):
        return None, "JSON value is not an object"
    return value, ""


def read_json_lines(path: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
    text = read_text(path)
    if text is None:
        return [], ["unreadable"]
    records: List[Dict[str, Any]] = []
    errors: List[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            errors.append("line " + str(number) + ": " + str(error))
            continue
        if not isinstance(value, dict):
            errors.append("line " + str(number) + " is not an object")
            continue
        records.append(value)
    return records, errors


def addresses_equal(left: Any, right: Any) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        return ipaddress.ip_address(left.split("%", 1)[0]) == ipaddress.ip_address(
            right.split("%", 1)[0])
    except ValueError:
        return left == right


def verify_a21(manifest: Dict[str, Any], evidence: Path) -> Dict[str, Any]:
    checks: List[Dict[str, str]] = []
    invalid: List[str] = []
    failures: List[str] = []
    inconclusive: List[str] = []

    if manifest.get("schema") != MANIFEST_SCHEMA_A21:
        invalid.append("manifest schema is not " + MANIFEST_SCHEMA_A21)
    if manifest.get("profile") != PROFILE_A21:
        invalid.append("manifest profile is not a2-1")
    if manifest.get("cellId") != "A2-1":
        invalid.append("manifest cellId is not A2-1")
    for field in ("vpnPackage", "expectedVpnUid", "expectedVpnApkSha256",
                  "expectedTunPocPluginSha256", "allowedPackages",
                  "expectedAllowedUids", "expectedAppApkSha256", "runtimeFiles",
                  "mode", "vppMode", "tuples"):
        if field not in manifest:
            invalid.append("manifest field missing: " + field)
    if manifest.get("installOk") is not True:
        invalid.append("traffic APK installation did not complete")

    required = manifest.get("requiredFiles", [])
    if not isinstance(required, list) or not all(isinstance(name, str) for name in required):
        invalid.append("requiredFiles is not a string array")
        required = []
    missing = [name for name in required if not (evidence / name).is_file()]
    if missing:
        invalid.append("required raw evidence missing: " + ",".join(missing))
    append_check(checks, "manifest-and-required-raw",
                 INVALID if invalid or missing else PASS,
                 "; ".join(invalid) if invalid else "manifest and required raw files are present")

    vpn_package = manifest.get("vpnPackage")
    allowed = manifest.get("allowedPackages")
    uid_map = manifest.get("expectedAllowedUids")
    app_hashes = manifest.get("expectedAppApkSha256")
    runtime_files = manifest.get("runtimeFiles")
    apps_valid = (
        isinstance(vpn_package, str) and bool(vpn_package)
        and isinstance(allowed, list) and len(allowed) == 2
        and all(isinstance(name, str) and name for name in allowed)
        and len(set(allowed)) == 2
        and isinstance(uid_map, dict) and set(uid_map) == set(allowed)
        and all(isinstance(uid_map.get(name), int) and not isinstance(uid_map.get(name), bool)
                and uid_map[name] > 0 for name in allowed)
        and len({uid_map[name] for name in allowed}) == 2
        and isinstance(app_hashes, dict) and set(app_hashes) == set(allowed)
        and all(isinstance(app_hashes.get(name), str)
                and re.fullmatch(r"[0-9a-f]{64}", app_hashes[name]) for name in allowed)
        and isinstance(runtime_files, dict) and set(runtime_files) == set(allowed)
        and all(isinstance(runtime_files.get(name), str) and runtime_files[name]
                for name in allowed)
    )
    if not apps_valid:
        invalid.append("two-App manifest identity/hash/runtime mapping is invalid")
        append_check(checks, "two-app-registration", INVALID,
                     "requires two distinct packages, UIDs, hashes, and runtime files")
        allowed = allowed if isinstance(allowed, list) else []
        uid_map = uid_map if isinstance(uid_map, dict) else {}
        app_hashes = app_hashes if isinstance(app_hashes, dict) else {}
        runtime_files = runtime_files if isinstance(runtime_files, dict) else {}
    else:
        append_check(checks, "two-app-registration", PASS,
                     ", ".join(name + "=" + str(uid_map[name]) for name in allowed))

    tuple_fields = ("stageId", "package", "family", "protocol", "protocolName",
                    "sourceAddress", "sourcePort", "destinationAddress",
                    "destinationPort")
    tuples = manifest.get("tuples")
    matrix_errors: List[str] = []
    if not isinstance(tuples, list) or len(tuples) != 8:
        matrix_errors.append("matrix must contain exactly eight tuples")
        tuples = []
    registered: set = set()
    stage_ids: set = set()
    source_ports: set = set()
    for item in tuples:
        if not isinstance(item, dict) or any(field not in item for field in tuple_fields):
            matrix_errors.append("tuple entry is missing registered fields")
            continue
        family = item.get("family")
        protocol = item.get("protocol")
        protocol_name = item.get("protocolName")
        package = item.get("package")
        if package not in allowed or family not in ("ip4", "ip6"):
            matrix_errors.append("tuple has unknown package or family")
        if (protocol, protocol_name) not in ((6, "tcp"), (17, "udp")):
            matrix_errors.append("tuple protocol number/name mismatch")
        stage_id = item.get("stageId")
        source_port = item.get("sourcePort")
        destination_port = item.get("destinationPort")
        if not isinstance(stage_id, str) or not stage_id or stage_id in stage_ids:
            matrix_errors.append("stageId is empty or duplicated")
        if not isinstance(source_port, int) or isinstance(source_port, bool) \
                or not 1 <= source_port <= 65535 or source_port in source_ports:
            matrix_errors.append("sourcePort is invalid or duplicated")
        if not isinstance(destination_port, int) or isinstance(destination_port, bool) \
                or not 1 <= destination_port <= 65535:
            matrix_errors.append("destinationPort is invalid")
        if not isinstance(item.get("sourceAddress"), str) \
                or not isinstance(item.get("destinationAddress"), str):
            matrix_errors.append("tuple address is invalid")
        stage_ids.add(stage_id)
        source_ports.add(source_port)
        registered.add((package, family, protocol_name))
    expected_matrix = {(name, family, protocol)
                       for name in allowed
                       for family in ("ip4", "ip6")
                       for protocol in ("tcp", "udp")}
    if registered != expected_matrix:
        matrix_errors.append("matrix does not cover two Apps x ip4/ip6 x tcp/udp exactly once")
    if matrix_errors:
        invalid.append("registered tuple matrix is invalid")
        append_check(checks, "registered-eight-tuple-matrix", INVALID,
                     "; ".join(sorted(set(matrix_errors))))
    else:
        append_check(checks, "registered-eight-tuple-matrix", PASS,
                     "two Apps x two families x two protocols with unique source ports")

    package_text = read_text(evidence / "package-list-packages-U.txt")
    packages = package_snapshot(package_text or "")
    expected_vpn_uid = manifest.get("expectedVpnUid")
    package_errors: List[str] = []
    if not isinstance(expected_vpn_uid, int) or isinstance(expected_vpn_uid, bool) \
            or expected_vpn_uid <= 0:
        package_errors.append("expectedVpnUid")
    for name in ([vpn_package] if isinstance(vpn_package, str) else []) + list(allowed):
        if name not in packages:
            package_errors.append("missing " + name)
    if isinstance(vpn_package, str) and packages.get(vpn_package) != expected_vpn_uid:
        package_errors.append("VpnLite UID mismatch")
    for name in allowed:
        if packages.get(name) != uid_map.get(name):
            package_errors.append(name + " UID mismatch")
    if package_errors:
        invalid.append("package-to-UID snapshot is invalid")
        append_check(checks, "package-uid-snapshot", INVALID, ",".join(package_errors))
    else:
        append_check(checks, "package-uid-snapshot", PASS,
                     "VpnLite and two distinct App UIDs match the device snapshot")

    apk_text = read_text(evidence / "apk-provenance.tsv")
    apk_rows: Dict[str, List[str]] = {}
    apk_errors: List[str] = []
    if apk_text is None:
        apk_errors.append("unreadable")
    else:
        for line in apk_text.splitlines():
            fields = line.split("\t")
            if len(fields) != 3:
                if line.strip():
                    apk_errors.append("malformed row")
                continue
            name, path, digest = fields
            if name not in ([vpn_package] if isinstance(vpn_package, str) else []) + list(allowed):
                continue
            if not path.startswith("/") or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
                apk_errors.append("invalid path/hash for " + name)
            else:
                apk_rows.setdefault(name, []).append(digest.lower())
    vpn_hash = manifest.get("expectedVpnApkSha256")
    plugin_hash = manifest.get("expectedTunPocPluginSha256")
    if not isinstance(vpn_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", vpn_hash):
        apk_errors.append("expectedVpnApkSha256")
    elif isinstance(vpn_package, str) and vpn_hash not in apk_rows.get(vpn_package, []):
        apk_errors.append("installed VpnLite APK hash mismatch")
    if not isinstance(plugin_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", plugin_hash):
        apk_errors.append("expectedTunPocPluginSha256")
    for name in allowed:
        if app_hashes.get(name) not in apk_rows.get(name, []):
            apk_errors.append("installed traffic APK hash mismatch for " + name)
    if apk_errors:
        invalid.append("installed APK provenance is invalid")
        append_check(checks, "apk-paths-and-hashes", INVALID, "; ".join(apk_errors))
    else:
        append_check(checks, "apk-paths-and-hashes", PASS,
                     "installed VpnLite and both traffic APK hashes match local builds")

    source_props = parse_properties(read_text(evidence / "source-provenance.properties") or "")
    source_errors: List[str] = []
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                        source_props.get("captureUtc", "")):
        source_errors.append("captureUtc")
    for key in ("captureEpoch", "deviceEpoch"):
        try:
            if int(source_props.get(key, "-1")) <= 0:
                source_errors.append(key)
        except ValueError:
            source_errors.append(key)
    if not re.fullmatch(r"[0-9a-fA-F]{40}", source_props.get("gitHead", "")):
        source_errors.append("gitHead")
    if source_props.get("gitDirty") != "false":
        source_errors.append("gitDirty")
    expected_source_hashes = {
        "vpnApkSha256": vpn_hash,
        "tunPocPluginSha256": plugin_hash,
    }
    if len(allowed) == 2:
        expected_source_hashes["appAApkSha256"] = app_hashes.get(allowed[0])
        expected_source_hashes["appBApkSha256"] = app_hashes.get(allowed[1])
    for key, expected in expected_source_hashes.items():
        if source_props.get(key) != expected:
            source_errors.append(key + "-mismatch")
    if source_errors:
        invalid.append("source provenance is invalid")
        append_check(checks, "source-provenance", INVALID, ",".join(source_errors))
    else:
        append_check(checks, "source-provenance", PASS,
                     "clean Git checkpoint and all three APK/plugin hashes retained")

    receipt, receipt_error = read_json_object(evidence / "vpn-session-provenance.json")
    receipt_errors: List[str] = []
    receipt_mismatches: List[str] = []
    if receipt is None:
        receipt_errors.append(receipt_error)
    else:
        if receipt.get("schema") != "vpn-session-provenance/v1" \
                or receipt.get("receiptType") != "success":
            receipt_errors.append("schema/receiptType")
        for key in ("builderSuccess", "addAllowedApplicationSuccess",
                    "establishSuccess", "tunFdDetached"):
            if receipt.get(key) is not True:
                receipt_errors.append(key)
        normalized = receipt.get("normalizedAllowedPackages")
        resolved = receipt.get("resolvedAllowedUids")
        if not isinstance(normalized, list):
            receipt_errors.append("normalizedAllowedPackages")
        elif sorted(normalized) != sorted(allowed):
            receipt_mismatches.append("normalizedAllowedPackages")
        if not isinstance(resolved, list) or any(not isinstance(uid, int) for uid in resolved):
            receipt_errors.append("resolvedAllowedUids")
        elif sorted(resolved) != sorted(uid_map.values()):
            receipt_mismatches.append("resolvedAllowedUids")
        if receipt.get("mode") != manifest.get("mode"):
            receipt_mismatches.append("mode")
        if receipt.get("vpnLitePackage") != vpn_package \
                or receipt.get("vpnLiteProcessUid") != expected_vpn_uid:
            receipt_mismatches.append("VpnLite identity")
        digest = receipt.get("configDigest")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            receipt_errors.append("configDigest")
        elif hashlib.sha256(canonical_config(receipt).encode("utf-8")).hexdigest() != digest:
            receipt_mismatches.append("configDigest")
        profile = receipt.get("addressRouteProfile")
        if not isinstance(profile, dict):
            receipt_errors.append("addressRouteProfile")
        else:
            for family_name in ("ipv4", "ipv6"):
                part = profile.get(family_name)
                if not isinstance(part, dict) or not isinstance(part.get("addresses"), list) \
                        or not isinstance(part.get("routes"), list):
                    receipt_errors.append("addressRouteProfile." + family_name)
            for family, family_name in (("ip4", "ipv4"), ("ip6", "ipv6")):
                expected_sources = {item.get("sourceAddress") for item in tuples
                                    if isinstance(item, dict)
                                    and item.get("family") == family}
                part = profile.get(family_name, {})
                receipt_addresses = part.get("addresses", []) \
                    if isinstance(part, dict) else []
                for source in expected_sources:
                    if not any(addresses_equal(source, str(value).split("/", 1)[0])
                               for value in receipt_addresses):
                        receipt_mismatches.append(
                            "addressRouteProfile." + family_name + "." + str(source))
        start_ns = receipt.get("monotonicStartNs")
        established_ns = receipt.get("monotonicEstablishedNs")
        elapsed_ns = receipt.get("elapsedMonotonicNs")
        if not all(isinstance(value, int) for value in (start_ns, established_ns, elapsed_ns)) \
                or established_ns < start_ns or elapsed_ns != established_ns - start_ns:
            receipt_errors.append("monotonic markers")
    if receipt_errors:
        invalid.append("durable VPN session receipt is invalid")
        append_check(checks, "vpn-session-receipt", INVALID, ",".join(receipt_errors))
    elif receipt_mismatches:
        failures.append("durable VPN session receipt disagrees with the registered run")
        append_check(checks, "vpn-session-receipt", FAIL, ",".join(receipt_mismatches))
    else:
        append_check(checks, "vpn-session-receipt", PASS,
                     "builder/config digest and both allowed App identities agree")

    failure_text = read_text(evidence / "vpn-session-provenance-failure.json")
    if failure_text is not None and failure_text.strip():
        invalid.append("durable VPN startup failure receipt is present")
        append_check(checks, "vpn-session-failure-diagnostic", INVALID,
                     "failure receipt is non-empty")

    vpp_start, vpp_start_error = read_json_object(evidence / "vpp-start-provenance.json")
    if vpp_start is None:
        invalid.append("native VPP start receipt is invalid")
        append_check(checks, "native-vpp-start", INVALID, vpp_start_error)
    else:
        vpp_mode = manifest.get("vppMode")
        if not isinstance(vpp_mode, int) or isinstance(vpp_mode, bool):
            start_status, start_detail = INVALID, "manifest vppMode is invalid"
        else:
            start_status, start_detail = verify_vpp_start(
                vpp_start, str(manifest.get("mode", "")), vpp_mode, str(plugin_hash))
        append_check(checks, "native-vpp-start", start_status, start_detail)
        if start_status != PASS:
            invalid.append("native VPP start instrumentation is invalid")

    contract_records, contract_json_errors = read_json_lines(
        evidence / "uid-attribution-contract.jsonl")
    scope: Optional[List[int]] = None
    scope_errors = list(contract_json_errors)
    for event in contract_records:
        if event.get("outcome") != "ALLOWED_UID_SCOPE":
            continue
        reason = str(event.get("reason", ""))
        match = re.search(r"uids=\[([^]]*)\]", reason)
        if not match or "enforced=true" not in reason:
            scope_errors.append("malformed or unenforced ALLOWED_UID_SCOPE")
            break
        try:
            scope = [int(value.strip()) for value in match.group(1).split(",")
                     if value.strip()]
        except ValueError:
            scope_errors.append("non-numeric ALLOWED_UID_SCOPE")
        break
    if scope is None:
        scope_errors.append("ALLOWED_UID_SCOPE missing")
    if scope_errors:
        invalid.append("allowed UID scope contract is invalid")
        append_check(checks, "allowed-uid-scope-contract", INVALID,
                     "; ".join(scope_errors))
    elif sorted(scope) != sorted(uid_map.values()):
        failures.append("allowed UID scope differs from the two registered App UIDs")
        append_check(checks, "allowed-uid-scope-contract", FAIL,
                     "contract=" + str(scope) + " expected=" + str(sorted(uid_map.values())))
    else:
        append_check(checks, "allowed-uid-scope-contract", PASS,
                     "durable two-App UID scope=" + str(sorted(scope)))

    runtime_by_package: Dict[str, List[Dict[str, Any]]] = {}
    for name in allowed:
        filename = runtime_files.get(name)
        if not isinstance(filename, str):
            continue
        records, json_errors = read_json_lines(evidence / filename)
        if json_errors:
            invalid.append("runtime JSONL is malformed for " + name)
            append_check(checks, "runtime-" + name, INVALID, "; ".join(json_errors))
        elif any(record.get("schema") != "s139-a2-1-runtime/v1" for record in records):
            invalid.append("runtime schema is invalid for " + name)
            append_check(checks, "runtime-" + name, INVALID,
                         "every non-empty record must use s139-a2-1-runtime/v1")
        else:
            runtime_by_package[name] = records
            append_check(checks, "runtime-" + name, PASS,
                         str(len(records)) + " durable runtime records parsed")

    resolver_text = read_text(evidence / "vpp-owner-resolver.log")
    if resolver_text is None:
        invalid.append("native resolver log is unreadable")
        resolver_text = ""
    runtime_handles: set = set()
    tuple_passes = 0
    for item in tuples:
        if not isinstance(item, dict):
            continue
        stage_id = str(item.get("stageId", "unknown"))
        package = item.get("package")
        expected_uid = uid_map.get(package)
        records = [record for record in runtime_by_package.get(package, [])
                   if record.get("stage_id", record.get("stageId")) == stage_id]
        runtime_status = PASS
        runtime_detail = ""
        if not records:
            runtime_status = INCONCLUSIVE
            runtime_detail = "no durable runtime record for the registered stage"
        elif any(record.get("app_package", record.get("appPackage")) != package
                 or record.get("process_uid", record.get("uid")) != expected_uid
                 for record in records):
            runtime_status = FAIL
            runtime_detail = "runtime package or process UID differs from the registered App"
        else:
            valid_records = []
            for record in records:
                protocol_name = record.get("protocol")
                destination = record.get("destination_address", record.get("destinationHost"))
                local = record.get("actual_local_address", record.get("localAddress"))
                handle = record.get("vpn_network_handle", record.get("vpnNetworkHandle"))
                if (record.get("family") == item.get("family")
                        and protocol_name == item.get("protocolName")
                        and record.get("source_port", record.get("sourcePort")) == item.get("sourcePort")
                        and addresses_equal(destination, item.get("destinationAddress"))
                        and record.get("destination_port", record.get("destinationPort")) == item.get("destinationPort")
                        and addresses_equal(local, item.get("sourceAddress"))
                        and record.get("bind_result", record.get("vpnBindResult")) == "bound"
                        and isinstance(handle, int) and not isinstance(handle, bool) and handle > 0
                        and record.get("tuple_attempted") is True):
                    valid_records.append(record)
                    runtime_handles.add(handle)
            if not valid_records:
                runtime_status = INCONCLUSIVE
                runtime_detail = "stage ran but no record proves the fixed VPN-bound tuple attempt"
            else:
                runtime_detail = str(len(valid_records)) + " matching VPN-bound operation record(s)"

        protocol = item.get("protocol")
        source_port = item.get("sourcePort")
        host = item.get("destinationAddress")
        port = item.get("destinationPort")
        family = item.get("family")
        resolver_status = INCONCLUSIVE
        if isinstance(expected_uid, int) and isinstance(protocol, int) \
                and isinstance(source_port, int) and isinstance(host, str) \
                and isinstance(port, int) and isinstance(family, str):
            resolver_status = resolver_verdict(
                resolver_text, host, source_port, port, expected_uid, protocol, family)

        tuple_status = PASS
        if runtime_status == FAIL or resolver_status == FAIL:
            tuple_status = FAIL
            failures.append(stage_id + " has a wrong App UID")
        elif runtime_status != PASS or resolver_status != PASS:
            tuple_status = INCONCLUSIVE
            inconclusive.append(stage_id + " lacks a decisive runtime/resolver join")
        else:
            tuple_passes += 1
        append_check(checks, "tuple-" + stage_id, tuple_status,
                     "runtime=" + runtime_status + " (" + runtime_detail
                     + "); resolver=" + resolver_status + "; connect/reply not required")

    if len(runtime_handles) > 1:
        failures.append("runtime records refer to more than one VPN network handle")
        append_check(checks, "runtime-vpn-handle", FAIL,
                     "handles=" + str(sorted(runtime_handles)))
    elif len(runtime_handles) == 1:
        append_check(checks, "runtime-vpn-handle", PASS,
                     "all decisive records use VPN handle=" + str(next(iter(runtime_handles))))
    else:
        inconclusive.append("no decisive runtime VPN handle was retained")
        append_check(checks, "runtime-vpn-handle", INCONCLUSIVE,
                     "no positive handle on a matching tuple record")

    cleanup_text = read_text(evidence / "cleanup.txt")
    clean, cleanup_detail = verify_cleanup(cleanup_text or "")
    if cleanup_text is None or not clean:
        invalid.append("cleanup is missing or not clean")
        append_check(checks, "cleanup", INVALID, cleanup_detail)
    else:
        append_check(checks, "cleanup", PASS, cleanup_detail)

    if invalid:
        status = INVALID
        reasons = invalid
    elif failures:
        status = FAIL
        reasons = failures
    elif inconclusive:
        status = INCONCLUSIVE
        reasons = inconclusive
    else:
        status = PASS
        reasons = ["all eight deterministic App/family/protocol tuples resolve to their registered UID"]

    return {
        "schema": VERIFIER_SCHEMA,
        "profile": PROFILE_A21,
        "cellId": "A2-1",
        "status": status,
        "reason": "; ".join(reasons),
        "checks": checks,
        "summary": {"registeredTuples": len(tuples), "passedTuples": tuple_passes},
        "rawEvidence": {
            "evidenceDirectory": str(evidence),
            "retained": True,
            "files": sorted(path.name for path in evidence.iterdir() if path.is_file())
                     if evidence.is_dir() else [],
            "logcatDiagnosticOnly": True,
            "logcatCaptured": (evidence / "logcat-diagnostic.log").is_file(),
        },
        "claims": [
            "two deterministic App UIDs each produced exact IPv4/IPv6 TCP/UDP tuples",
            "each registered tuple was joined to its App UID at the native VPP owner-resolver seam",
        ],
        "nonClaims": [
            "external TCP connect, UDP reply, Internet reachability, or protected Direct Egress",
            "concurrency, cache bounds, lifecycle invalidation, or controlled reverse traffic",
            "B1/B2 whole-device forwarding behavior",
        ],
    }


def verify_a20(manifest: Dict[str, Any], evidence: Path) -> Dict[str, Any]:
    checks: List[Dict[str, str]] = []
    invalid: List[str] = []
    failures: List[str] = []
    inconclusive: List[str] = []

    if manifest.get("schema") != MANIFEST_SCHEMA:
        invalid.append("manifest schema is not s139-a2-0-manifest/v1")
    if manifest.get("profile") != PROFILE_A20:
        invalid.append("unsupported profile: " + str(manifest.get("profile")))
    if manifest.get("cellId") != "A2-0":
        invalid.append("manifest cellId is not A2-0")
    for field in ("vpnPackage", "allowedPackage", "mode", "vppMode",
                  "expectedVpnApkSha256", "expectedTunPocPluginSha256", "host", "port",
                  "sourcePort"):
        if field not in manifest:
            invalid.append("manifest field missing: " + field)

    required = manifest.get("requiredFiles", list(DEFAULT_REQUIRED_FILES))
    if not isinstance(required, list):
        invalid.append("requiredFiles is not an array")
        required = list(DEFAULT_REQUIRED_FILES)
    missing = [name for name in required if not (evidence / str(name)).is_file()]
    if missing:
        invalid.append("required raw evidence missing: " + ",".join(missing))
    append_check(checks, "manifest-and-required-raw", INVALID if missing or invalid else PASS,
                 "; ".join(invalid + (["missing=" + ",".join(missing)] if missing else []))
                 or "manifest and required raw files are present")

    package_text = read_text(evidence / "package-list-packages-U.txt")
    packages = package_snapshot(package_text or "")
    allowed_names = expected_packages(manifest)
    vpn_package = str(manifest.get("vpnPackage", ""))
    expected_uid = manifest.get("expectedAllowedUid")
    expected_vpn_uid = manifest.get("expectedVpnUid")
    if not isinstance(expected_uid, int):
        expected_uid = packages.get(allowed_names[0]) if len(allowed_names) == 1 else None
    if not isinstance(expected_vpn_uid, int):
        expected_vpn_uid = packages.get(vpn_package)
    if package_text is None or not packages:
        invalid.append("package-to-UID snapshot is empty or unreadable")
        append_check(checks, "package-uid-snapshot", INVALID,
                     "package-list-packages-U.txt did not yield package UID records")
    elif any(name not in packages for name in [vpn_package] + allowed_names):
        invalid.append("expected package is absent from package-to-UID snapshot")
        append_check(checks, "package-uid-snapshot", INVALID,
                     "missing one of " + ",".join([vpn_package] + allowed_names))
    else:
        snapshot_uids = {packages[name] for name in allowed_names}
        if expected_uid is None or expected_uid not in snapshot_uids:
            invalid.append("expected allowed UID is not in package snapshot")
            append_check(checks, "package-uid-snapshot", INVALID,
                         "expectedAllowedUid does not match the allowed package")
        else:
            append_check(checks, "package-uid-snapshot", PASS,
                         "allowed=" + str(sorted(snapshot_uids))
                         + " vpn=" + str(packages.get(vpn_package)))

    apk_text = read_text(evidence / "apk-provenance.tsv")
    apk_rows: Dict[str, List[str]] = {}
    apk_invalid = []
    if apk_text is None:
        apk_invalid.append("APK provenance is unreadable")
    else:
        for line in apk_text.splitlines():
            fields = line.split("\t")
            if len(fields) != 3:
                if line.strip():
                    apk_invalid.append("malformed APK row")
                continue
            package, path, digest = fields
            if package not in (vpn_package, *allowed_names):
                continue
            if not path.startswith("/") or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
                apk_invalid.append("invalid path/hash for " + package)
            else:
                apk_rows.setdefault(package, []).append(digest.lower())
    for package in (vpn_package, *allowed_names):
        if not apk_rows.get(package):
            apk_invalid.append("no APK path/hash for " + package)
    expected_vpn_apk = manifest.get("expectedVpnApkSha256")
    if not isinstance(expected_vpn_apk, str) or not re.fullmatch(
            r"[0-9a-f]{64}", expected_vpn_apk):
        apk_invalid.append("expectedVpnApkSha256 is invalid")
    elif expected_vpn_apk not in apk_rows.get(vpn_package, []):
        apk_invalid.append("installed VpnLite APK hash differs from local build")
    if apk_invalid:
        invalid.append("APK path/hash provenance invalid")
        append_check(checks, "apk-paths-and-hashes", INVALID, "; ".join(apk_invalid))
    else:
        append_check(checks, "apk-paths-and-hashes", PASS,
                     "path/hash rows retained for " + ",".join(sorted(apk_rows)))

    source_text = read_text(evidence / "source-provenance.properties")
    source_props = parse_properties(source_text or "")
    source_errors: List[str] = []
    if source_text is None:
        source_errors.append("source provenance is unreadable")
    capture_utc = source_props.get("captureUtc", "")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", capture_utc):
        source_errors.append("captureUtc")
    try:
        if int(source_props.get("captureEpoch", "-1")) <= 0:
            source_errors.append("captureEpoch")
    except ValueError:
        source_errors.append("captureEpoch")
    try:
        if int(source_props.get("deviceEpoch", "-1")) <= 0:
            source_errors.append("deviceEpoch")
    except ValueError:
        source_errors.append("deviceEpoch")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", source_props.get("gitHead", "")):
        source_errors.append("gitHead")
    if source_props.get("gitDirty") not in ("true", "false"):
        source_errors.append("gitDirty")
    for key in ("vpnApkSha256", "tunPocPluginSha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", source_props.get(key, "")):
            source_errors.append(key)
    if source_props.get("vpnApkSha256") != manifest.get("expectedVpnApkSha256"):
        source_errors.append("vpnApkSha256-mismatch")
    if source_props.get("tunPocPluginSha256") != manifest.get(
            "expectedTunPocPluginSha256"):
        source_errors.append("tunPocPluginSha256-mismatch")
    if source_errors:
        invalid.append("source provenance invalid")
        append_check(checks, "source-provenance", INVALID, ",".join(source_errors))
    else:
        append_check(checks, "source-provenance", PASS,
                     "UTC capture, device epoch, git HEAD, and dirty state retained")

    receipt: Dict[str, Any] = {}
    receipt_text = read_text(evidence / "vpn-session-provenance.json")
    if receipt_text is None:
        invalid.append("success receipt is missing")
        append_check(checks, "vpn-session-receipt", INVALID,
                     "no durable success receipt; failure cannot be promoted")
    else:
        try:
            parsed = json.loads(receipt_text)
            if isinstance(parsed, dict):
                receipt = parsed
            else:
                raise ValueError("receipt is not an object")
        except (ValueError, json.JSONDecodeError) as error:
            invalid.append("success receipt is not valid JSON")
            append_check(checks, "vpn-session-receipt", INVALID, str(error))
    if receipt:
        receipt_errors: List[str] = []
        receipt_mismatches: List[str] = []
        if receipt.get("schema") != "vpn-session-provenance/v1":
            receipt_errors.append("schema")
        if receipt.get("receiptType") != "success":
            receipt_errors.append("receiptType")
        for key in ("builderSuccess", "addAllowedApplicationSuccess",
                    "establishSuccess", "tunFdDetached"):
            if receipt.get(key) is not True:
                receipt_errors.append(key)
        normalized = receipt.get("normalizedAllowedPackages")
        if not isinstance(normalized, list):
            receipt_errors.append("normalizedAllowedPackages")
        elif normalized != allowed_names:
            receipt_mismatches.append("normalizedAllowedPackages")
        resolved_uids = receipt.get("resolvedAllowedUids")
        if not isinstance(resolved_uids, list) or any(not isinstance(uid, int)
                                                       for uid in resolved_uids):
            receipt_errors.append("resolvedAllowedUids")
        elif expected_uid is not None and sorted(resolved_uids) != sorted(
                {packages[name] for name in allowed_names if name in packages}):
            receipt_mismatches.append("resolvedAllowedUids")
        if receipt.get("mode") != manifest.get("mode"):
            receipt_mismatches.append("mode")
        if receipt.get("vpnLitePackage") != vpn_package:
            receipt_mismatches.append("vpnLitePackage")
        process_uid = receipt.get("vpnLiteProcessUid")
        if not isinstance(process_uid, int):
            receipt_errors.append("vpnLiteProcessUid")
        elif expected_vpn_uid is not None and process_uid != expected_vpn_uid:
            receipt_mismatches.append("vpnLiteProcessUid")
        if not isinstance(receipt.get("vpnLitePid"), int) or receipt.get("vpnLitePid", -1) <= 0:
            receipt_errors.append("vpnLitePid")
        mtu = receipt.get("mtu")
        if not isinstance(mtu, int) or isinstance(mtu, bool) or mtu <= 0:
            receipt_errors.append("mtu")
        requested_disallowed = manifest.get("disallowedPackage", "")
        if not isinstance(requested_disallowed, str):
            receipt_errors.append("manifest.disallowedPackage")
            requested_disallowed = ""
        normalized_disallowed = receipt.get("normalizedDisallowedPackage")
        if not isinstance(normalized_disallowed, str):
            receipt_errors.append("normalizedDisallowedPackage")
        elif normalized_disallowed != requested_disallowed.strip():
            receipt_mismatches.append("normalizedDisallowedPackage")
        start_ns = receipt.get("monotonicStartNs")
        established_ns = receipt.get("monotonicEstablishedNs")
        elapsed_ns = receipt.get("elapsedMonotonicNs")
        if not all(isinstance(value, int) for value in (start_ns, established_ns, elapsed_ns)):
            receipt_errors.append("monotonic-markers")
        elif established_ns < start_ns or elapsed_ns != established_ns - start_ns:
            receipt_errors.append("monotonic-order")
        digest = receipt.get("configDigest", "")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            receipt_errors.append("configDigest-format")
        else:
            computed = hashlib.sha256(canonical_config(receipt).encode("utf-8"))
            if computed.hexdigest() != digest:
                receipt_mismatches.append("configDigest")
        profile = receipt.get("addressRouteProfile")
        if not isinstance(profile, dict) or not all(
                isinstance(profile.get(family), dict) for family in ("ipv4", "ipv6")):
            receipt_errors.append("addressRouteProfile")
        else:
            for family_name in ("ipv4", "ipv6"):
                family_profile = profile[family_name]
                for key in ("addresses", "routes"):
                    if not isinstance(family_profile.get(key), list):
                        receipt_errors.append("addressRouteProfile." + family_name
                                              + "." + key)
        if receipt_errors:
            invalid.append("durable receipt fields invalid: " + ",".join(receipt_errors))
            append_check(checks, "vpn-session-receipt", INVALID, ",".join(receipt_errors))
        if receipt_mismatches:
            detail = ",".join(receipt_mismatches)
            failures.append("receipt trusted fields mismatch: " + detail)
            append_check(checks, "vpn-session-receipt", FAIL, detail)
        if not receipt_errors and not receipt_mismatches:
            append_check(checks, "vpn-session-receipt", PASS,
                         "builder, allowed scope, establish, detach, digest, and monotonic markers agree")

    failure_receipt_text = read_text(evidence / "vpn-session-provenance-failure.json")
    if failure_receipt_text is not None and failure_receipt_text.strip():
        try:
            failure_receipt = json.loads(failure_receipt_text)
            reason = str(failure_receipt.get("failureReason", "")) \
                if isinstance(failure_receipt, dict) else "non-object failure receipt"
        except (ValueError, json.JSONDecodeError) as error:
            reason = "malformed failure receipt: " + str(error)
        invalid.append("durable startup failure diagnostic is present")
        append_check(checks, "vpn-session-failure-diagnostic", INVALID, reason)

    vpp_start_text = read_text(evidence / "vpp-start-provenance.json")
    if vpp_start_text is None or not vpp_start_text.strip():
        invalid.append("native VPP start receipt is missing")
        append_check(checks, "native-vpp-start", INVALID,
                     "vpp-start-provenance.json is empty or unreadable")
    else:
        try:
            vpp_start_receipt = json.loads(vpp_start_text)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            invalid.append("native VPP start receipt is malformed")
            append_check(checks, "native-vpp-start", INVALID, str(error))
        else:
            expected_vpp_mode = manifest.get("vppMode")
            if not isinstance(expected_vpp_mode, int) or isinstance(expected_vpp_mode, bool):
                invalid.append("manifest vppMode is invalid")
                append_check(checks, "native-vpp-start", INVALID,
                             "manifest vppMode is not an integer")
            else:
                start_status, start_detail = verify_vpp_start(
                    vpp_start_receipt, str(manifest.get("mode", "")), expected_vpp_mode,
                    str(manifest.get("expectedTunPocPluginSha256", "")))
                append_check(checks, "native-vpp-start", start_status, start_detail)
                if start_status != PASS:
                    invalid.append("native VPP start instrumentation invalid: "
                                   + start_detail)

    contract_text = read_text(evidence / "uid-attribution-contract.jsonl")
    scope_uids: Optional[List[int]] = None
    contract_errors: List[str] = []
    if contract_text is None:
        contract_errors.append("contract raw is unreadable")
    else:
        for line in contract_text.splitlines():
            try:
                event = json.loads(line)
            except (ValueError, json.JSONDecodeError):
                continue
            if not isinstance(event, dict):
                continue
            if event.get("outcome") != "ALLOWED_UID_SCOPE":
                continue
            reason = str(event.get("reason", ""))
            match = re.search(r"uids=\[([^]]*)\]", reason)
            if match:
                try:
                    scope_uids = [int(value.strip()) for value in match.group(1).split(",")
                                  if value.strip()]
                except ValueError:
                    scope_uids = []
                    contract_errors.append("ALLOWED_UID_SCOPE contains non-numeric UID")
            if "enforced=true" not in reason:
                contract_errors.append("ALLOWED_UID_SCOPE is not enforced")
            break
        if scope_uids is None:
            contract_errors.append("ALLOWED_UID_SCOPE event missing")
    if contract_errors:
        invalid.append("allowed UID scope contract invalid")
        append_check(checks, "allowed-uid-scope-contract", INVALID, "; ".join(contract_errors))
    elif receipt and sorted(scope_uids or []) != sorted(receipt.get("resolvedAllowedUids", [])):
        failures.append("ALLOWED_UID_SCOPE differs from receipt resolvedAllowedUids")
        append_check(checks, "allowed-uid-scope-contract", FAIL,
                     "contract=" + str(scope_uids) + " receipt="
                     + str(receipt.get("resolvedAllowedUids")))
    else:
        append_check(checks, "allowed-uid-scope-contract", PASS,
                     "durable ALLOWED_UID_SCOPE=" + str(scope_uids))

    runtime_text = read_text(evidence / "runtime-udp-traffic-probe.properties")
    runtime = parse_properties(runtime_text or "")
    runtime_errors: List[str] = []
    if runtime_text is None:
        runtime_errors.append("runtime probe is unreadable")
    for key in ("uid", "bindResult", "bindNetworkHandle", "result"):
        if key not in runtime:
            runtime_errors.append("missing " + key)
    if runtime_errors:
        invalid.append("runtime probe instrumentation invalid")
        append_check(checks, "runtime-probe", INVALID, "; ".join(runtime_errors))
    else:
        try:
            runtime_uid = int(runtime["uid"])
            network_handle = int(runtime["bindNetworkHandle"])
        except ValueError:
            runtime_uid = -1
            network_handle = -1
            runtime_errors.append("uid or bindNetworkHandle is not numeric")
        if expected_uid is not None and runtime_uid != expected_uid:
            failures.append("runtime probe UID disagrees with package snapshot")
            append_check(checks, "runtime-probe", FAIL,
                         "runtime uid=" + str(runtime_uid) + " expected=" + str(expected_uid))
        elif runtime.get("bindResult") != "bound" or network_handle <= 0:
            inconclusive.append("runtime probe did not bind to an active VPN network")
            append_check(checks, "runtime-probe", INCONCLUSIVE,
                         "bindResult=" + runtime.get("bindResult", "")
                         + " handle=" + str(network_handle))
        elif runtime.get("result") != "udp_datagram_sent":
            inconclusive.append("runtime probe did not emit the registered tuple")
            append_check(checks, "runtime-probe", INCONCLUSIVE,
                         "result=" + runtime.get("result", ""))
        else:
            append_check(checks, "runtime-probe", PASS,
                         "UID and active VPN network handle are durable in the probe")

    family = str(manifest.get("family", "ip4"))
    protocol = int(manifest.get("protocol", 17))
    host = str(manifest.get("host", ""))
    port = int(manifest.get("port", -1))
    source_port = int(manifest.get("sourcePort", -1))
    source = str(manifest.get("sourceAddress", ""))
    if not source and receipt:
        profile = receipt.get("addressRouteProfile", {})
        ipv4 = profile.get("ipv4", {}) if isinstance(profile, dict) else {}
        addresses = ipv4.get("addresses", []) if isinstance(ipv4, dict) else []
        if addresses:
            source = str(addresses[0]).split("/", 1)[0]
    vpp_text = read_text(evidence / "vpp-cli.log")
    resolver_text = read_text(evidence / "vpp-owner-resolver.log")
    if vpp_text is None or resolver_text is None:
        invalid.append("VPP tuple/resolver raw is unreadable")
        append_check(checks, "exact-vpp-tuple", INVALID, "VPP raw file missing")
    elif expected_uid is None or not source:
        invalid.append("exact tuple lacks a source UID/address expectation")
        append_check(checks, "exact-vpp-tuple", INVALID, "source address or expected UID missing")
    else:
        tuple_match = vpp_tuple_lines(vpp_text, family, protocol, source, source_port,
                                       host, port)
        resolver_status = resolver_verdict(
            resolver_text, host, source_port, port, expected_uid, protocol, family)
        if resolver_status == FAIL:
            failures.append("exact resolver tuple has a wrong UID")
            append_check(checks, "exact-vpp-tuple", FAIL,
                         "vpp=" + str(tuple_match) + " resolver=FAIL")
        elif resolver_status != PASS:
            inconclusive.append("exact VPP tuple and UID completion were not both observed")
            detail = "vpp=" + str(tuple_match) + " resolver=" + resolver_status
            append_check(checks, "exact-vpp-tuple", resolver_status,
                         detail)
        elif not tuple_match:
            inconclusive.append("exact VPP tuple was not observed")
            append_check(checks, "exact-vpp-tuple", INCONCLUSIVE,
                         "vpp=False resolver=PASS")
        else:
            append_check(checks, "exact-vpp-tuple", PASS,
                         family + " proto=" + str(protocol) + " " + source + ":"
                         + str(source_port) + " -> " + host + ":" + str(port)
                         + " uid=" + str(expected_uid))

    cleanup_text = read_text(evidence / "cleanup.txt")
    if cleanup_text is None:
        invalid.append("cleanup raw is unreadable")
        append_check(checks, "cleanup", INVALID, "cleanup.txt missing")
    else:
        clean, detail = verify_cleanup(cleanup_text)
        if not clean:
            invalid.append("cleanup is not clean")
            append_check(checks, "cleanup", INVALID, detail)
        else:
            append_check(checks, "cleanup", PASS, detail)

    status = PASS
    reasons: List[str] = []
    if invalid:
        status = INVALID
        reasons.extend(invalid)
    elif failures:
        status = FAIL
        reasons.extend(failures)
    elif inconclusive:
        status = INCONCLUSIVE
        reasons.extend(inconclusive)
    else:
        reasons.append("all registered A2-0 provenance joins and cleanup checks passed")

    logcat_path = evidence / "logcat-diagnostic.log"
    return {
        "schema": VERIFIER_SCHEMA,
        "profile": PROFILE_A20,
        "cellId": "A2-0",
        "status": status,
        "reason": "; ".join(reasons),
        "checks": checks,
        "rawEvidence": {
            "evidenceDirectory": str(evidence),
            "retained": True,
            "files": sorted(path.name for path in evidence.iterdir()
                             if path.is_file()) if evidence.is_dir() else [],
            "logcatDiagnosticOnly": True,
            "logcatCaptured": logcat_path.is_file(),
        },
        "claims": [
            "one durable VpnService builder/establish session is joined to the exact A2-0 tuple",
            "the registered allowed package UID scope is consistent with the session receipt",
        ],
        "nonClaims": [
            "UID correctness beyond the captured tuple",
            "external connect, forwarding, reply, or B1/B2 whole-device behavior",
            "production cache sizing or long-lifecycle capacity",
        ],
    }


def invalid_result(reason: str, evidence: Path) -> Dict[str, Any]:
    return {
        "schema": VERIFIER_SCHEMA,
        "profile": "unknown",
        "cellId": "unknown",
        "status": INVALID,
        "reason": reason,
        "checks": [],
        "rawEvidence": {"evidenceDirectory": str(evidence), "retained": True,
                         "logcatDiagnosticOnly": True},
        "claims": [],
        "nonClaims": [],
    }


def write_result(path: Path, result: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    output = args.output or (args.evidence_dir / "result.json")
    manifest_text = read_text(args.manifest)
    if manifest_text is None:
        result = invalid_result("manifest is unreadable", args.evidence_dir)
    else:
        try:
            manifest = json.loads(manifest_text)
            if not isinstance(manifest, dict):
                raise ValueError("manifest is not an object")
            profile = manifest.get("profile")
            if profile == PROFILE_A20:
                result = verify_a20(manifest, args.evidence_dir)
            elif profile == PROFILE_A21:
                result = verify_a21(manifest, args.evidence_dir)
            else:
                result = invalid_result("unsupported profile: " + str(profile), args.evidence_dir)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            result = invalid_result("manifest JSON error: " + str(error), args.evidence_dir)
    try:
        write_result(output, result)
    except OSError as error:
        print("verifier: unable to write result.json: " + str(error), file=sys.stderr)
        return 2
    print(str(result.get("cellId", "A2")) + " status="
          + str(result.get("status")) + " result=" + str(output))
    return 0 if result.get("status") == PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
