import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "verify-s139-a2-5.py"
SPEC = importlib.util.spec_from_file_location("verify_s139_a2_5", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VERIFIER)


class VerifyA25Tests(unittest.TestCase):
    def test_s156_guardrails_accept_controlled_fixture(self):
        invalid = []
        VERIFIER.verify_s156_guardrails({
            "uidContractCellId": "A2-5",
            "resolverCorrelationSchema": VERIFIER.RESOLVER_CORRELATION_SCHEMA,
            "destinationHost": "192.168.4.5",
            "destinationPort": 55553,
            "fixture": {
                "schema": "s152-a2-1-fixture/v1",
                "host4": "192.168.4.5",
                "host6": "fd76:d462:c4e3::1",
                "tcpPort": 55443,
                "udpPort": 55553,
                "publicInternetClaim": False,
            },
        }, invalid)
        self.assertEqual([], invalid)

    def test_s156_guardrails_reject_public_destination(self):
        invalid = []
        VERIFIER.verify_s156_guardrails({
            "uidContractCellId": "A2-5",
            "resolverCorrelationSchema": VERIFIER.RESOLVER_CORRELATION_SCHEMA,
            "destinationHost": "1.1.1.1",
            "destinationPort": 53,
            "fixture": {
                "schema": "s152-a2-1-fixture/v1",
                "host4": "192.168.4.5",
                "host6": "fd76:d462:c4e3::1",
                "tcpPort": 55443,
                "udpPort": 55553,
                "publicInternetClaim": False,
            },
        }, invalid)
        self.assertIn("destinationHost uses public resolver endpoint", invalid)


if __name__ == "__main__":
    unittest.main()
