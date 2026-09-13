#!/usr/bin/env python3
"""Check active navigation and test registration, not historical document links."""

from pathlib import Path
import re
import subprocess
import unittest
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[2]
ENTRIES = (
    "README.md",
    "docs/README.md",
    "docs/reference/README.md",
    "docs/reference/NAMING_AND_PROVENANCE.md",
    "docs/current/README.md",
    "docs/INTERFACE_SPECIFICATION.md",
    "docs/agents/domain.md",
    "docs/agents/doc-maintenance.md",
    "docs/decisions/README.md",
    "docs/decisions/SNORT_10_MAINLINE_RECONSTRUCTION.md",
    "docs/decisions/RESETALL_RUNTIME_CONCURRENCY.md",
    "docs/decisions/DOMAIN_POLICY_OBSERVABILITY.md",
    "docs/reference/PROTOCOL_IDENTIFICATION_STELLAR_LPI_WRAPPER_INVENTORY.md",
    "docs/archived/pre-vpp/README.md",
    "docs/testing/README.md",
    "docs/tooling/README.md",
    "docs/tooling/NDK_DAEMON_BUILD.md",
    "docs/tooling/VSCODE_CMAKE_WORKFLOW.md",
    "dev/README.md",
    "tests/README.md",
    "tests/host/README.md",
    "tests/integration/README.md",
    "tests/archive/README.md",
    "tests/archive/pre-vpp/README.md",
    "tests/archive/retired-contracts/README.md",
    "docs/maintenance/2026-09-13_REPOSITORY_ORGANIZATION.md",
)
RETIRED_CONTRACTS = (
    "s176-root-nfqueue-output", "s189-root-network-gate",
    "s190-vpn-network-gate", "s191-root-tcp4-l4",
)


class RepositoryNavigationTest(unittest.TestCase):
    def test_active_local_markdown_links_exist(self):
        count = 0
        for entry in ENTRIES:
            path = ROOT / entry
            text = re.sub(r"\x60{3}.*?\x60{3}", "", path.read_text(), flags=re.S)
            for target in re.findall(r"\[[^\]\n]+\]\(([^)\s]+)\)", text):
                parsed = urlsplit(target)
                if parsed.scheme or parsed.netloc or not parsed.path:
                    continue
                count += 1
                destination = (path.parent / unquote(parsed.path)).resolve()
                with self.subTest(entry=entry, target=target):
                    self.assertTrue(destination.is_relative_to(ROOT), "link escapes repository")
                    self.assertTrue(destination.exists(), "missing local link target")
        self.assertGreater(count, 50, "link scan unexpectedly empty")

    def test_default_entry_is_short_current_map(self):
        self.assertIn("(docs/current/README.md)", (ROOT / "README.md").read_text())
        self.assertLess(len((ROOT / "docs/current/README.md").read_text().splitlines()), 100)

    def test_registered_current_paths_exist_and_exclude_archive(self):
        cmake = (ROOT / "CMakeLists.txt").read_text()
        paths = re.findall(r'\$\{CMAKE_CURRENT_SOURCE_DIR\}/([^"]+)', cmake)
        self.assertGreater(len(paths), 20)
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).exists())
                self.assertNotIn("/archive/", path)
        for name in RETIRED_CONTRACTS:
            self.assertNotIn(name + "-contract-test.sh", cmake)

    def test_retired_scripts_are_not_active_or_executable(self):
        for name in RETIRED_CONTRACTS:
            self.assertFalse((ROOT / f"tests/android/{name}-contract-test.sh").exists())
        for directory in ("tests/archive/pre-vpp", "tests/archive/retired-contracts"):
            for path in (ROOT / directory).rglob("*"):
                if path.is_file() and path.suffix in (".sh", ".py"):
                    with self.subTest(path=str(path.relative_to(ROOT))):
                        self.assertEqual(path.stat().st_mode & 0o111, 0)
        for directory in ("ip", "dx", "diagnostics", "telemetry"):
            # Ignored local raw records/build outputs stay intact after archiving.
            candidates = subprocess.check_output(
                ["git", "ls-files", "--cached", "--others", "--exclude-standard",
                 "-z", "--", f"tests/device/{directory}"], cwd=ROOT,
            ).decode().split("\0")
            self.assertFalse(any(path and (ROOT / path).is_file() for path in candidates))


if __name__ == "__main__":
    unittest.main()
