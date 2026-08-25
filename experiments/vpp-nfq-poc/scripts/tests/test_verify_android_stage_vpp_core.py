import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
STAGE_SCRIPT = ROOT / "scripts/android-stage-vpp-core.sh"


class VerifyAndroidStageVppCoreTest(unittest.TestCase):
    def setUp(self):
        self.script = STAGE_SCRIPT.read_text(encoding="utf-8")

    def test_conditional_wake_guard_scans_selected_plugin_closure(self):
        self.assertIn("conditional_wake_pattern=", self.script)
        self.assertIn("--glob '!**/plugins/**'", self.script)
        self.assertIn('plugin_dir_name="${plugin%.so}"', self.script)
        self.assertIn('plugin_dir_name="${plugin_dir_name#lib}"', self.script)
        self.assertIn('plugin_dir_name="${plugin_dir_name%_plugin}"', self.script)
        self.assertIn('plugin_dir="$VPP_DIR/src/plugins/$plugin_dir_name"', self.script)
        self.assertIn('"${rg_conditional_wake[@]}" "$conditional_wake_pattern"', self.script)

    def test_binary_guard_still_checks_staged_vpp_binaries(self):
        self.assertIn('for artifact in "$STAGE_DIR/bin/vpp" "$STAGE_DIR/bin/vppctl"; do', self.script)
        self.assertIn("Rejected P6 conditional-wake symbols found in staged binary", self.script)


if __name__ == "__main__":
    unittest.main()
