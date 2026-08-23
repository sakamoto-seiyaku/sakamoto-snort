#!/usr/bin/env python3
"""Regression tests for the A2-3 raw return-packet gate."""

import importlib.util
import ipaddress
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1]
VERIFIER_PATH = SCRIPT_DIR / "verify-s139-a2-3.py"
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


if __name__ == "__main__":
    unittest.main()
