#!/usr/bin/env python3
"""Keep Product vocabulary independent without fabricating external identities."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "docs/reference"


class ReferenceNamingTest(unittest.TestCase):
    def test_mainline_does_not_define_terms_through_fork_names(self):
        for name in ("CONTEXT.md", "docs/adr/0003-vpp-owned-packet-parsing.md",
                     "docs/product/ANDROID_L4_PRODUCT_PLAN.md"):
            text = (ROOT / name).read_text()
            self.assertNotRegex(text, r"(?i)\bstellar[-_]")
            self.assertNotIn("The protocol-identification baseline reads", text)
            self.assertNotIn("The protocol-identification baseline is", text)

    def test_external_control_names_match_the_existing_probe_contract(self):
        record = (REFERENCE / "PROTOCOL_IDENTIFICATION_VPP_LPI_CONTROL_AND_RUNNER_CONTRACT.md").read_text()
        for identifier in ("stellar_lpi_enable_disable", "set stellar-lpi interface",
                           "VPP_STELLAR_LPI_ROOT", "stellar-tcp-session", "stellar-udp-session"):
            self.assertIn(identifier, record)
        probe = (ROOT / "tools/protocol_identification/vpp_stellar_lpi_wrapper_inventory.sh").read_text()
        self.assertIn("VPP_STELLAR_LPI_ROOT", probe)
        self.assertIn("stellar_lpi_core.c", probe)
        self.assertIn("stellar_lpi.api", probe)

    def test_reference_records_keep_exact_identifiers_and_abstract_only_root(self):
        paths = list(REFERENCE.glob("PROTOCOL_IDENTIFICATION*.md"))
        paths.append(REFERENCE / "FORK_VPP_APPID_NUMBER_ORIGIN.md")
        for path in paths:
            with self.subTest(path=path.name):
                text = path.read_text()
                self.assertNotIn("/home/js/backup/backup/Git/vpp", text)
                self.assertNotRegex(text, r"\breference[-_](?:lpi|session_manager|acl|qdpi_detector)\b")
                self.assertNotIn("<wrapper-inventory-probe>", text)
                self.assertNotIn("<wrapper-host-payload-probe>", text)
                self.assertNotIn("<wrapper-host-pcap-probe>", text)

    def test_neutral_document_name_has_a_stable_redirect(self):
        old = REFERENCE / "PROTOCOL_IDENTIFICATION_STELLAR_LPI_WRAPPER_INVENTORY.md"
        new = REFERENCE / "PROTOCOL_IDENTIFICATION_REFERENCE_LPI_WRAPPER_INVENTORY.md"
        self.assertTrue(new.is_file())
        self.assertIn(f"]({new.name})", old.read_text())
        text = new.read_text()
        self.assertTrue(text.startswith("# Protocol Identification Reference Wrapper Inventory\n"))
        self.assertIn("stellar_lpi_core.h", text)


if __name__ == "__main__":
    unittest.main()
