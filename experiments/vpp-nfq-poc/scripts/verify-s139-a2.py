#!/usr/bin/env python3
"""Manifest-driven verifier tracer for the revised SAKAMOTO-139 A2 cells.

The shell runners retain raw device evidence; this program only correlates it
and writes ``result.json``.  ``a2-0`` is intentionally the first profile, but
the dispatch table is an extension seam for A2-1..A2-6 readers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


VERIFIER_SCHEMA = "s139-a2-verifier/v1"
MANIFEST_SCHEMA = "s139-a2-0-manifest/v1"
PROFILE_A20 = "a2-0"
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


def verify_vpp_start(receipt: Any, expected_mode: str,
                     expected_vpp_mode: int) -> Tuple[str, str]:
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
    for field in ("vpnPackage", "allowedPackage", "mode", "vppMode", "host", "port",
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
    apk_rows: Dict[str, int] = {}
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
                apk_rows[package] = apk_rows.get(package, 0) + 1
    for package in (vpn_package, *allowed_names):
        if apk_rows.get(package, 0) == 0:
            apk_invalid.append("no APK path/hash for " + package)
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
                    vpp_start_receipt, str(manifest.get("mode", "")), expected_vpp_mode)
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
            else:
                result = invalid_result("unsupported profile: " + str(profile), args.evidence_dir)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            result = invalid_result("manifest JSON error: " + str(error), args.evidence_dir)
    try:
        write_result(output, result)
    except OSError as error:
        print("verifier: unable to write result.json: " + str(error), file=sys.stderr)
        return 2
    print("A2-0 status=" + str(result.get("status")) + " result=" + str(output))
    return 0 if result.get("status") == PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
