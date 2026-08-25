#!/usr/bin/env python3
"""Regression tests for the A2-3 raw return-packet gate."""

import importlib.util
import ipaddress
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1]
VERIFIER_PATH = SCRIPT_DIR / "verify-s139-a2-3.py"
RUNNER_PATH = SCRIPT_DIR / "android-run-s139-a2-3-controlled-return.sh"
MAIN_ACTIVITY_PATH = (SCRIPT_DIR.parent / "android" / "vpn-lite" / "src" /
                      "main" / "java" / "com" / "sakamoto" / "snort" /
                      "vpnlite" / "MainActivity.java")
SPEC = importlib.util.spec_from_file_location("verify_s139_a2_3", VERIFIER_PATH)
if SPEC is None or SPEC.loader is None:
    raise ImportError("unable to load A2-3 verifier")
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


def udp6_packet(source: str, destination: str, source_port: int,
                destination_port: int, payload: bytes) -> bytes:
    packet = bytearray(40 + 8 + len(payload))
    packet[0] = 0x60
    packet[4:6] = (8 + len(payload)).to_bytes(2, "big")
    packet[6] = 17
    packet[7] = 64
    packet[8:24] = ipaddress.ip_address(source).packed
    packet[24:40] = ipaddress.ip_address(destination).packed
    packet[40:42] = source_port.to_bytes(2, "big")
    packet[42:44] = destination_port.to_bytes(2, "big")
    packet[44:46] = (8 + len(payload)).to_bytes(2, "big")
    packet[48:] = payload
    return bytes(packet)


class RawOutputGateTest(unittest.TestCase):
    PAYLOAD = b"s139-a2-3|A2-3-udp6-return"

    def app(self) -> dict:
        return {
            "family": "ip6",
            "source_address": "fd00:200::2",
            "source_port": 45843,
            "destination_address": "fd00:200::1",
            "destination_port": 42083,
            "payload_hex": self.PAYLOAD.hex(),
        }

    def line(self, packet: bytes) -> str:
        return "oi3 tun-output-raw length={} hex={}\n".format(
            len(packet), packet.hex())

    def test_exact_ipv6_tuple_and_payload_pass(self) -> None:
        packet = udp6_packet("fd00:200::1", "fd00:200::2", 42083, 45843,
                             self.PAYLOAD)
        status, _ = VERIFIER.verify_raw_output(self.line(packet), self.app())
        self.assertEqual(VERIFIER.PASS, status)

    def test_zero_source_from_old_state_bug_fails(self) -> None:
        packet = udp6_packet("::", "fd00:200::2", 0, 45843, self.PAYLOAD)
        status, detail = VERIFIER.verify_raw_output(self.line(packet), self.app())
        self.assertEqual(VERIFIER.FAIL, status)
        self.assertIn("raw TUN output differs", detail)

    def test_missing_raw_line_is_invalid(self) -> None:
        status, _ = VERIFIER.verify_raw_output("oi3 tun-output length=74\n",
                                                self.app())
        self.assertEqual(VERIFIER.INVALID, status)


class A23CleanupControlTest(unittest.TestCase):
    def test_runner_drives_oi3_cleanup_before_product_stop(self) -> None:
        runner = RUNNER_PATH.read_text(encoding="utf-8")
        oi3_stop = 'am start -n "$VPN_PACKAGE/.MainActivity" --es oi3Control stop'
        product_stop = 'am start -n "$VPN_PACKAGE/.MainActivity" --ez stop true'
        self.assertIn(oi3_stop, runner)
        self.assertIn(product_stop, runner)
        self.assertLess(runner.index(oi3_stop), runner.index(product_stop))

    def test_main_activity_bridges_oi3_control_without_vpn_prepare(self) -> None:
        source = MAIN_ACTIVITY_PATH.read_text(encoding="utf-8")
        branch = "startLegacyOi3Control(intent);"
        self.assertIn(branch, source)
        self.assertIn("copyStringExtra(source, serviceIntent, SnortVpnService.EXTRA_OI3_CONTROL);",
                      source)
        self.assertLess(source.index(branch),
                        source.index("EXTRA_UID_CONTRACT_REFRESH_APP"))


if __name__ == "__main__":
    unittest.main()
