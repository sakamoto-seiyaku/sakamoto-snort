#!/usr/bin/env python3
"""Regression tests for the revised A2 verifier profiles."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1]
VERIFIER_PATH = SCRIPT_DIR / "verify-s139-a2.py"
SPEC = importlib.util.spec_from_file_location("verify_s139_a2", VERIFIER_PATH)
if SPEC is None or SPEC.loader is None:
    raise ImportError("unable to load A2-0 verifier")
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class ResolverVerdictTest(unittest.TestCase):
    HOST = "198.51.100.7"
    SOURCE_PORT = 40000
    PORT = 9
    EXPECTED_UID = 12629

    def verdict(self, *uid_lines: int) -> str:
        resolver = "\n".join(
            "resolver query=1 proto=17 src=10.111.0.2:{} -> {}:{} uid={} "
            "cell=A2-1 stage=A2-1-appa-ip4-udp request=1"
            .format(self.SOURCE_PORT, self.HOST, self.PORT, uid)
            for uid in uid_lines
        )
        return VERIFIER.resolver_verdict(
            resolver,
            self.HOST,
            self.SOURCE_PORT,
            self.PORT,
            self.EXPECTED_UID,
            17,
            "ip4",
        )

    def test_tuple_only_resolver_row_is_inconclusive(self) -> None:
        resolver = (
            "resolver query=1 proto=17 src=10.111.0.2:{} -> {}:{} uid={}"
            .format(self.SOURCE_PORT, self.HOST, self.PORT, self.EXPECTED_UID)
        )
        self.assertEqual(
            VERIFIER.INCONCLUSIVE,
            VERIFIER.resolver_verdict(
                resolver,
                self.HOST,
                self.SOURCE_PORT,
                self.PORT,
                self.EXPECTED_UID,
                17,
                "ip4",
                "A2-1",
                "A2-1-appa-ip4-udp",
            ),
        )

    def test_startup_resolver_row_does_not_satisfy_a21_stage(self) -> None:
        resolver = (
            "resolver query=1 proto=17 src=10.111.0.2:{} -> {}:{} uid={} "
            "cell=A2-4 stage=startup"
            .format(self.SOURCE_PORT, self.HOST, self.PORT, self.EXPECTED_UID)
        )
        self.assertEqual(
            VERIFIER.INCONCLUSIVE,
            VERIFIER.resolver_verdict(
                resolver,
                self.HOST,
                self.SOURCE_PORT,
                self.PORT,
                self.EXPECTED_UID,
                17,
                "ip4",
                "A2-1",
                "A2-1-appa-ip4-udp",
            ),
        )

    def test_other_cell_resolver_row_does_not_satisfy_a21_stage(self) -> None:
        resolver = (
            "resolver query=1 proto=17 src=10.111.0.2:{} -> {}:{} uid={} "
            "cell=A2-4 stage=A2-1-appa-ip4-udp request=1"
            .format(self.SOURCE_PORT, self.HOST, self.PORT, self.EXPECTED_UID)
        )
        self.assertEqual(
            VERIFIER.INCONCLUSIVE,
            VERIFIER.resolver_verdict(
                resolver,
                self.HOST,
                self.SOURCE_PORT,
                self.PORT,
                self.EXPECTED_UID,
                17,
                "ip4",
                "A2-1",
                "A2-1-appa-ip4-udp",
            ),
        )

    def test_cell_stage_without_request_is_inconclusive(self) -> None:
        resolver = (
            "resolver query=1 proto=17 src=10.111.0.2:{} -> {}:{} uid={} "
            "cell=A2-1 stage=A2-1-appa-ip4-udp"
            .format(self.SOURCE_PORT, self.HOST, self.PORT, self.EXPECTED_UID)
        )
        self.assertEqual(
            VERIFIER.INCONCLUSIVE,
            VERIFIER.resolver_verdict(
                resolver,
                self.HOST,
                self.SOURCE_PORT,
                self.PORT,
                self.EXPECTED_UID,
                17,
                "ip4",
                "A2-1",
                "A2-1-appa-ip4-udp",
            ),
        )

    def test_initial_miss_then_expected_uid_is_pass(self) -> None:
        self.assertEqual(
            VERIFIER.PASS,
            self.verdict(-1, self.EXPECTED_UID),
        )

    def test_any_wrong_positive_uid_is_fail(self) -> None:
        # Policy is deliberately strict: a wrong non-negative completion
        # remains FAIL even when a later line reports the expected UID.
        self.assertEqual(
            VERIFIER.FAIL,
            self.verdict(10180, self.EXPECTED_UID),
        )

    def test_only_initial_miss_is_inconclusive(self) -> None:
        self.assertEqual(VERIFIER.INCONCLUSIVE, self.verdict(-1))

    def test_non_numeric_allowed_scope_uid_is_invalid(self) -> None:
        manifest = {
            "schema": VERIFIER.MANIFEST_SCHEMA,
            "profile": VERIFIER.PROFILE_A20,
            "cellId": "A2-0",
            "vpnPackage": "com.example.vpn",
            "allowedPackage": "com.example.allowed",
            "mode": "vpp",
            "host": self.HOST,
            "port": self.PORT,
            "sourcePort": self.SOURCE_PORT,
            "requiredFiles": ["uid-attribution-contract.jsonl"],
        }
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            (evidence / "uid-attribution-contract.jsonl").write_text(
                '{"outcome":"ALLOWED_UID_SCOPE",'
                '"reason":"uids=[not-a-number] enforced=true"}\n',
                encoding="utf-8",
            )
            result = VERIFIER.verify_a20(manifest, evidence)
        scope_checks = [
            check for check in result["checks"]
            if check["name"] == "allowed-uid-scope-contract"
        ]
        self.assertEqual(1, len(scope_checks))
        self.assertEqual(VERIFIER.INVALID, scope_checks[0]["status"])

    def test_main_turns_manifest_type_error_into_result(self) -> None:
        manifest = {
            "schema": VERIFIER.MANIFEST_SCHEMA,
            "profile": VERIFIER.PROFILE_A20,
            "cellId": "A2-0",
            "vpnPackage": "com.example.vpn",
            "allowedPackage": "com.example.allowed",
            "mode": "vpp",
            "host": self.HOST,
            "port": self.PORT,
            "sourcePort": self.SOURCE_PORT,
            "protocol": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = root / "manifest.json"
            evidence = root / "evidence"
            evidence.mkdir()
            output = evidence / "result.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            rc = VERIFIER.main([
                "--manifest", str(manifest_path),
                "--evidence-dir", str(evidence),
                "--output", str(output),
            ])
            self.assertNotEqual(0, rc)
            self.assertEqual(VERIFIER.INVALID, json.loads(
                output.read_text(encoding="utf-8"))["status"])


class NativeVppStartVerdictTest(unittest.TestCase):
    def receipt(self, rc: int = 0, artifact_present: bool = True) -> dict:
        return {
            "schema": "vpp-start-provenance/v1",
            "receiptType": "native-start-outcome",
            "mode": "vpp-hev-owner-resolver",
            "vppMode": 5,
            "rc": rc,
            "success": rc == 0,
            "monotonicNs": 123456789,
            "requiredArtifact": "libtun_poc_plugin.so|tun_poc_plugin.so",
            "artifactPresent": artifact_present,
            "artifactName": "libtun_poc_plugin.so" if artifact_present else "",
            "artifactSha256": "a" * 64 if artifact_present else "",
        }

    def verdict(self, receipt: dict) -> str:
        status, _ = VERIFIER.verify_vpp_start(
            receipt, "vpp-hev-owner-resolver", 5, "a" * 64)
        return status

    def test_native_start_success_with_hashed_artifact_is_pass(self) -> None:
        self.assertEqual(VERIFIER.PASS, self.verdict(self.receipt()))

    def test_native_start_nonzero_rc_is_invalid_fixture(self) -> None:
        self.assertEqual(VERIFIER.INVALID, self.verdict(self.receipt(rc=-3)))

    def test_native_start_missing_artifact_is_invalid_fixture(self) -> None:
        self.assertEqual(
            VERIFIER.INVALID,
            self.verdict(self.receipt(artifact_present=False)),
        )


class A21MatrixVerdictTest(unittest.TestCase):
    VPN_PACKAGE = "com.example.vpn"
    APP_A = "com.example.appa"
    APP_B = "com.example.appb"
    VPN_UID = 12000
    UID_A = 12001
    UID_B = 12002
    VPN_HASH = "1" * 64
    APP_A_HASH = "2" * 64
    APP_B_HASH = "3" * 64
    PLUGIN_HASH = "4" * 64
    FIXTURE_HASH = "5" * 64

    def tuples(self) -> list:
        result = []
        port = 46000
        for package in (self.APP_A, self.APP_B):
            for family, source, destination in (
                    ("ip4", "10.111.0.2", "1.1.1.1"),
                    ("ip6", "fd00:111:111::2", "2606:4700:4700::1111")):
                for protocol_number, protocol_name, destination_port in (
                        (6, "tcp", 443), (17, "udp", 53)):
                    port += 1
                    result.append({
                        "stageId": "A2-1-{}-{}-{}".format(
                            package.rsplit(".", 1)[-1], family, protocol_name),
                        "package": package,
                        "family": family,
                        "protocol": protocol_number,
                        "protocolName": protocol_name,
                    "sourceAddress": source,
                    "sourcePort": port,
                    "destinationHost": destination,
                    "destinationAddress": destination,
                    "destinationPort": destination_port,
                    "uidContractStage": "A2-1-{}-{}-{}".format(
                        package.rsplit(".", 1)[-1], family, protocol_name),
                    "repeat": 2,
                    })
        return result

    def manifest(self) -> dict:
        required = [
            "package-list-packages-U.txt",
            "apk-provenance.tsv",
            "vpn-session-provenance.json",
            "vpp-start-provenance.json",
            "uid-attribution-contract.jsonl",
            "a2-1-runtime-appa.jsonl",
            "a2-1-runtime-appb.jsonl",
            "vpp-owner-resolver.log",
            "source-provenance.properties",
            "cleanup.txt",
        ]
        return {
            "schema": VERIFIER.MANIFEST_SCHEMA_A21,
            "profile": VERIFIER.PROFILE_A21,
            "cellId": "A2-1",
            "vpnPackage": self.VPN_PACKAGE,
            "allowedPackages": [self.APP_A, self.APP_B],
            "expectedVpnUid": self.VPN_UID,
            "expectedAllowedUids": {
                self.APP_A: self.UID_A,
                self.APP_B: self.UID_B,
            },
            "expectedVpnApkSha256": self.VPN_HASH,
            "expectedAppApkSha256": {
                self.APP_A: self.APP_A_HASH,
                self.APP_B: self.APP_B_HASH,
            },
            "expectedTunPocPluginSha256": self.PLUGIN_HASH,
            "fixture": {
                "schema": "s152-a2-1-fixture/v1",
                "host4": "192.0.2.10",
                "host6": "2001:db8::10",
                "tcpPort": 55443,
                "udpPort": 55553,
                "scriptSha256": self.FIXTURE_HASH,
                "publicInternetClaim": False,
            },
            "mode": "vpp-hev-owner-resolver",
            "vppMode": 5,
            "uidContractCellId": "A2-1",
            "resolverCorrelationSchema": "a2-1-resolver-cell-stage-request/v1",
            "installOk": True,
            "runtimeFiles": {
                self.APP_A: "a2-1-runtime-appa.jsonl",
                self.APP_B: "a2-1-runtime-appb.jsonl",
            },
            "tuples": self.tuples(),
            "requiredFiles": required,
        }

    def write_fixture(self, root: Path, manifest: dict,
                      only_miss_stage: str = "", wrong_stage: str = "") -> None:
        (root / "package-list-packages-U.txt").write_text(
            "package:{} uid:{}\npackage:{} uid:{}\npackage:{} uid:{}\n".format(
                self.VPN_PACKAGE, self.VPN_UID,
                self.APP_A, self.UID_A,
                self.APP_B, self.UID_B),
            encoding="utf-8",
        )
        (root / "apk-provenance.tsv").write_text(
            "{}\t/data/app/vpn/base.apk\t{}\n"
            "{}\t/data/app/appa/base.apk\t{}\n"
            "{}\t/data/app/appb/base.apk\t{}\n".format(
                self.VPN_PACKAGE, self.VPN_HASH,
                self.APP_A, self.APP_A_HASH,
                self.APP_B, self.APP_B_HASH),
            encoding="utf-8",
        )
        (root / "source-provenance.properties").write_text(
            "captureUtc=2026-08-23T08:00:00Z\n"
            "captureEpoch=1787472000\n"
            "deviceEpoch=1787472001\n"
            "gitHead={}\n"
            "gitDirty=false\n"
            "vpnApkSha256={}\n"
            "appAApkSha256={}\n"
            "appBApkSha256={}\n"
            "tunPocPluginSha256={}\n".format(
                "a" * 40, self.VPN_HASH, self.APP_A_HASH,
                self.APP_B_HASH, self.PLUGIN_HASH),
            encoding="utf-8",
        )
        source_props = (root / "source-provenance.properties").read_text(
            encoding="utf-8")
        (root / "source-provenance.properties").write_text(
            source_props + "fixtureScriptSha256={}\n".format(self.FIXTURE_HASH),
            encoding="utf-8",
        )
        receipt = {
            "schema": "vpn-session-provenance/v1",
            "receiptType": "success",
            "mode": "vpp-hev-owner-resolver",
            "normalizedDisallowedPackage": "",
            "normalizedAllowedPackages": [self.APP_A, self.APP_B],
            "resolvedAllowedUids": [self.UID_A, self.UID_B],
            "builderSuccess": True,
            "addAllowedApplicationSuccess": True,
            "establishSuccess": True,
            "tunFdDetached": True,
            "mtu": 1500,
            "addressRouteProfile": {
                "ipv4": {"addresses": ["10.111.0.2/32"], "routes": ["0.0.0.0/0"]},
                "ipv6": {"addresses": ["fd00:111:111::2/128"], "routes": ["::/0"]},
            },
            "monotonicStartNs": 100,
            "monotonicEstablishedNs": 150,
            "elapsedMonotonicNs": 50,
            "vpnLitePackage": self.VPN_PACKAGE,
            "vpnLiteProcessUid": self.VPN_UID,
            "vpnLitePid": 1234,
        }
        receipt["configDigest"] = VERIFIER.hashlib.sha256(
            VERIFIER.canonical_config(receipt).encode("utf-8")).hexdigest()
        (root / "vpn-session-provenance.json").write_text(
            json.dumps(receipt), encoding="utf-8")
        start = {
            "schema": "vpp-start-provenance/v1",
            "receiptType": "native-start-outcome",
            "mode": "vpp-hev-owner-resolver",
            "vppMode": 5,
            "rc": 0,
            "success": True,
            "monotonicNs": 200,
            "requiredArtifact": "libtun_poc_plugin.so|tun_poc_plugin.so",
            "artifactPresent": True,
            "artifactName": "libtun_poc_plugin.so",
            "artifactSha256": self.PLUGIN_HASH,
        }
        (root / "vpp-start-provenance.json").write_text(
            json.dumps(start), encoding="utf-8")
        contract = [{
                "schema": "uid-attribution-contract/v1",
                "outcome": "ALLOWED_UID_SCOPE",
                "cell_id": "A2-1",
                "stage_id": "A2-1-start",
                "key": "-",
                "uid": -1,
                "pending": 0,
                "cache": 0,
                "token": -1,
                "flow_id": -1,
                "reason": "uids=[{}, {}] enforced=true".format(
                    self.UID_A, self.UID_B),
            }]
        for item in manifest["tuples"]:
            key = VERIFIER.canonical_tuple_key(item)
            contract.extend([
                {
                    "schema": "uid-attribution-contract/v1",
                    "outcome": "MISS_SUBMITTED",
                    "cell_id": "A2-1",
                    "stage_id": item["stageId"],
                    "key": key,
                    "uid": -1,
                    "pending": 1,
                    "cache": 0,
                    "token": 1,
                    "flow_id": 1,
                },
                {
                    "schema": "uid-attribution-contract/v1",
                    "outcome": "COMPLETION_ACCEPTED",
                    "cell_id": "A2-1",
                    "stage_id": item["stageId"],
                    "key": key,
                    "uid": manifest["expectedAllowedUids"][item["package"]],
                    "pending": 0,
                    "cache": 1,
                    "token": 1,
                    "flow_id": 1,
                },
            ])
        (root / "uid-attribution-contract.jsonl").write_text(
            "".join(json.dumps(event) + "\n" for event in contract),
            encoding="utf-8",
        )

        runtime = {self.APP_A: [], self.APP_B: []}
        resolver = []
        for item in manifest["tuples"]:
            uid = manifest["expectedAllowedUids"][item["package"]]
            runtime[item["package"]].append({
                "schema": "s139-a2-1-runtime/v1",
                "stage_id": item["stageId"],
                "app_package": item["package"],
                "process_uid": uid,
                "family": item["family"],
                "protocol": item["protocolName"],
                "source_port": item["sourcePort"],
                "destination_address": item["destinationAddress"],
                "destination_port": item["destinationPort"],
                "actual_local_address": item["sourceAddress"],
                "bind_result": "bound",
                "vpn_network_handle": 987654321,
                "tuple_attempted": True,
                "send_connect_outcome": "tcp_connect_timeout"
                    if item["protocolName"] == "tcp" else "udp_datagram_sent",
            })
            resolver.append(
                "resolver query=1 proto={} {}:{} -> {}:{} uid=-1 "
                "cell=A2-1 stage={} request={}".format(
                    item["protocol"], item["sourceAddress"], item["sourcePort"],
                    item["destinationAddress"], item["destinationPort"],
                    item["stageId"], item["sourcePort"] * 10 + 1))
            if item["stageId"] == wrong_stage:
                resolver.append(
                    "resolver query=2 proto={} {}:{} -> {}:{} uid=19999 "
                    "cell=A2-1 stage={} request={}".format(
                        item["protocol"], item["sourceAddress"], item["sourcePort"],
                        item["destinationAddress"], item["destinationPort"],
                        item["stageId"], item["sourcePort"] * 10 + 2))
            if item["stageId"] != only_miss_stage:
                resolver.append(
                "resolver query=3 proto={} {}:{} -> {}:{} uid={} "
                    "cell=A2-1 stage={} request={}".format(
                        item["protocol"], item["sourceAddress"], item["sourcePort"],
                    item["destinationAddress"], item["destinationPort"], uid,
                    item["stageId"], item["sourcePort"] * 10 + 3))
        for package, filename in manifest["runtimeFiles"].items():
            (root / filename).write_text(
                "".join(json.dumps(record) + "\n" for record in runtime[package]),
                encoding="utf-8",
            )
        (root / "vpp-owner-resolver.log").write_text(
            "\n".join(resolver) + "\n", encoding="utf-8")
        (root / "cleanup.txt").write_text(
            "processes:\ntun0:\nvpn:\n", encoding="utf-8")
        (root / "fixture-readiness.properties").write_text(
            "schema=s152-a2-1-fixture-readiness/v1\n"
            "publicInternetClaim=false\n"
            "fixtureHost4=192.0.2.10\n"
            "fixtureHost6=2001:db8::10\n"
            "tcpPort=55443\n"
            "udpPort=55553\n"
            "readyEvents=4\n",
            encoding="utf-8",
        )
        (root / "s152-a2-1-fixture.jsonl").write_text(
            "{\"event\": \"ready\"}\n" * 4
            + "{\"event\": \"fixture_ready\"}\n",
            encoding="utf-8",
        )

    def verdict(self, mutate=None, only_miss_stage: str = "",
                wrong_stage: str = "") -> dict:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.manifest()
            if mutate is not None:
                mutate(manifest, root)
            self.write_fixture(root, manifest, only_miss_stage, wrong_stage)
            return VERIFIER.verify_a21(manifest, root)

    def test_complete_eight_tuple_matrix_is_pass(self) -> None:
        result = self.verdict()
        self.assertEqual(VERIFIER.PASS, result["status"])
        self.assertEqual(8, result["summary"]["passedTuples"])

    def test_wrong_positive_uid_is_fail_even_with_later_expected_uid(self) -> None:
        stage = self.tuples()[0]["stageId"]
        self.assertEqual(VERIFIER.FAIL, self.verdict(wrong_stage=stage)["status"])

    def test_only_initial_miss_for_one_tuple_is_inconclusive(self) -> None:
        stage = self.tuples()[0]["stageId"]
        self.assertEqual(
            VERIFIER.INCONCLUSIVE,
            self.verdict(only_miss_stage=stage)["status"],
        )

    def test_duplicate_app_uid_is_invalid(self) -> None:
        def duplicate_uid(manifest, _root):
            manifest["expectedAllowedUids"][self.APP_B] = self.UID_A

        self.assertEqual(VERIFIER.INVALID, self.verdict(duplicate_uid)["status"])

    def test_missing_native_start_provenance_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.manifest()
            self.write_fixture(root, manifest)
            (root / "vpp-start-provenance.json").unlink()
            self.assertEqual(
                VERIFIER.INVALID,
                VERIFIER.verify_a21(manifest, root)["status"],
            )


if __name__ == "__main__":
    unittest.main()
