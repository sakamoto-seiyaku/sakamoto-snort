import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/android-run-s178-b1-final-dualstack-dns.sh"


class VerifyS178B1FinalDualstackDnsTest(unittest.TestCase):
    def setUp(self):
        self.runner = RUNNER.read_text(encoding="utf-8")

    def test_runner_targets_final_vpnlite_and_appa_artifacts(self):
        self.assertIn("snort-vpn-lite-debug.apk", self.runner)
        self.assertIn("com-sakamoto-snort-poc-appa-debug.apk", self.runner)
        self.assertIn('VPN_PACKAGE="${VPN_PACKAGE:-com.sakamoto.snort.vpnlite}"',
                      self.runner)
        self.assertIn('APP_PACKAGE="${APP_PACKAGE:-com.sakamoto.snort.poc.appa}"',
                      self.runner)
        self.assertIn("sha256sum \"$APK\"", self.runner)
        self.assertIn("expected_hash_policy=current-artifact-by-default-no-static-historical-hashes",
                      self.runner)
        self.assertNotIn("cb921108", self.runner)
        self.assertNotIn("b1a2f018", self.runner)
        self.assertNotIn("96726f", self.runner)

    def test_runner_uses_b1_probe_action_component_and_exact_extras(self):
        self.assertIn("com.sakamoto.snort.a2traffic.B1_PROBE", self.runner)
        self.assertIn("com.sakamoto.snort.poc.appa/com.sakamoto.snort.a2traffic.TrafficAdapterActivity",
                      self.runner)
        for extra in (
            "b1StageId",
            "b1Family",
            "b1Protocol",
            "b1SourcePort",
            "b1DestinationHost",
            "b1DestinationPort",
            "b1TimeoutMillis",
            "b1Dns",
            "b1PayloadHex",
            "b1TcpWriteMode",
        ):
            self.assertIn(extra, self.runner)
        self.assertIn("123401000001000000000000076578616d706c6503636f6d0000010001",
                      self.runner)

    def test_runner_declares_full_dualstack_dns_matrix(self):
        for cell in (
            "ip4-udp-dns|ip4|udp|1.1.1.1|separate",
            "ip4-tcp-dns-separate|ip4|tcp|1.1.1.1|separate",
            "ip4-tcp-dns-coalesced|ip4|tcp|1.1.1.1|coalesced",
            "ip6-udp-dns|ip6|udp|2606:4700:4700::1111|separate",
            "ip6-tcp-dns-separate|ip6|tcp|2606:4700:4700::1111|separate",
            "ip6-tcp-dns-coalesced|ip6|tcp|2606:4700:4700::1111|coalesced",
        ):
            self.assertIn(cell, self.runner)
        self.assertIn('CELLS="${CELLS:-all}"', self.runner)

    def test_runner_avoids_default_tcp_source_port_reuse_across_reruns(self):
        self.assertIn('if [[ -z "${SOURCE_PORT_BASE:-}" ]]; then',
                      self.runner)
        self.assertIn('SOURCE_PORT_BASE="$((46000 + ($(date +%s) % 1500) * 10))"',
                      self.runner)
        self.assertNotIn('SOURCE_PORT_BASE="${SOURCE_PORT_BASE:-46320}"',
                         self.runner)

    def test_runner_starts_final_oi3_multi_topology_for_appa(self):
        self.assertIn('VPN_MODE="${VPN_MODE:-vpp-oi3-multi}"', self.runner)
        self.assertIn('--es mode "$VPN_MODE"', self.runner)
        self.assertIn('--es allowedPackage "$APP_PACKAGE"', self.runner)
        self.assertIn('--ez enableIpv6 "$ENABLE_IPV6"', self.runner)
        self.assertIn("owners=4", self.runner)

    def test_runner_uses_bounded_adb_read_and_nonblocking_remote_log_capture(self):
        self.assertIn('ADB_READ_RETRY_ATTEMPTS="${ADB_READ_RETRY_ATTEMPTS:-3}"',
                      self.runner)
        self.assertIn("adb_read retry attempt=", self.runner)
        self.assertIn("adb_read_once()", self.runner)
        self.assertIn("had_errexit", self.runner)
        self.assertIn("safe_capture_remote_tail()", self.runner)
        self.assertIn("wait_stop_cleanup_marker()", self.runner)
        self.assertIn("WAIT_STOP_CLEANUP_ATTEMPTS", self.runner)
        self.assertIn("POST_B1_NATIVE_SETTLE_SECONDS", self.runner)
        self.assertIn('sleep "$POST_B1_NATIVE_SETTLE_SECONDS"', self.runner)
        self.assertIn("grep -E 'oi3_cleanup result='", self.runner)
        self.assertIn("if [ -f '$remote_path' ]; then tail -n '$REMOTE_LOG_TAIL_LINES'",
                      self.runner)
        self.assertIn("[ -f \\\"\\$f\\\" ]", self.runner)
        self.assertNotIn("grep -E 'oi4 multi enabled|oi3 multi enabled' '$REMOTE_STDOUT_LOG' '$REMOTE_CLI_LOG'",
                         self.runner)
        self.assertIn("tun0_after_output=", self.runner)
        self.assertIn('[[ "$tun0_after_output" == *"tun0:"* ]]',
                      self.runner)
        self.assertNotIn("ip link show tun0 >/dev/null 2>&1 && tun0_after=1",
                         self.runner)

    def test_runner_keeps_cleanup_marker_separate_from_dataplane_validity(self):
        self.assertIn("PASS_DATAPLANE_CLEANUP_MARKER_MISSING", self.runner)
        self.assertIn("PASS_DATAPLANE_WITH_CLEANUP_MARKER_GAPS", self.runner)
        self.assertIn("app_valid", self.runner)
        self.assertIn("native_valid", self.runner)
        self.assertIn("direct_preflight=not-run-current-AppA-B1-helper-requires-active-VPN",
                      self.runner)
        self.assertIn("full PASS requires app DNS response, native direct/broker/tun-output markers, zero residue, and cleanup marker",
                      self.runner)
        self.assertIn("dataplane PASS allows cleanup marker gap", self.runner)
        self.assertIn("oi3 direct-send length=", self.runner)
        self.assertIn("oi3 direct-recv length=", self.runner)
        self.assertIn("oi3 tun-output length=", self.runner)
        self.assertIn("broker-completion result=SUCCESS", self.runner)
        self.assertIn("underlay-available=1", self.runner)

    def test_runner_writes_expected_evidence_files(self):
        self.assertIn('CSV="$RESULT_DIR/cells-$RUN_ID.csv"', self.runner)
        self.assertIn('MANIFEST="$RESULT_DIR/run-$RUN_ID-manifest.json"',
                      self.runner)
        self.assertIn('VALIDITY="$RESULT_DIR/run-validity-$RUN_ID.txt"',
                      self.runner)
        for evidence_name in (
            "app-b1-runtime.jsonl",
            "vpn-session-provenance.json",
            "vpp-start-provenance.json",
            "vpp-cli.log",
            "vpp-stdout.log",
            "vpp-hev.log",
            "vpp-protect.log",
            "vpp-oi3-broker.log",
            "connectivity.txt",
            "baseline-ip-rules.txt",
            "after-ip-rules.txt",
            "processes-before.txt",
            "processes-after-stop.txt",
            "cleanup.log",
            "tun0-after.txt",
        ):
            self.assertIn(evidence_name, self.runner)


if __name__ == "__main__":
    unittest.main()
