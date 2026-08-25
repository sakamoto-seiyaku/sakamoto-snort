import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MAIN_ACTIVITY = (
    ROOT
    / "android/vpn-lite/src/main/java/com/sakamoto/snort/vpnlite/MainActivity.java"
)


class VerifyVpnLiteLegacyStartTest(unittest.TestCase):
    def setUp(self):
        self.main_activity = MAIN_ACTIVITY.read_text(encoding="utf-8")

    def _method(self, name, next_name):
        start = self.main_activity.index(name)
        end = self.main_activity.index(next_name, start)
        return self.main_activity[start:end]

    def test_legacy_poc_intent_dispatch_is_deferred_until_activity_resume(self):
        self.assertIn("private Intent pendingProductIntent;", self.main_activity)
        self.assertIn("private boolean resumed;", self.main_activity)
        self.assertIn("protected void onResume()", self.main_activity)
        self.assertIn("flushPendingProductIntent();", self.main_activity)

        on_new_intent = self._method("protected void onNewIntent", "private LinearLayout buildUi")
        self.assertIn("enqueueProductIntent(intent);", on_new_intent)
        self.assertNotIn("applyProductIntent(intent);", on_new_intent)

    def test_legacy_vpn_service_start_uses_foreground_compatible_entry(self):
        self.assertIn("import android.os.Build;", self.main_activity)
        self.assertIn("private void startLegacyServiceIntent(Intent serviceIntent)",
                      self.main_activity)
        helper = self._method(
            "private void startLegacyServiceIntent",
            "private static void copyStringExtra",
        )
        self.assertIn("Build.VERSION.SDK_INT >= Build.VERSION_CODES.O", helper)
        self.assertIn("startForegroundService(serviceIntent);", helper)
        self.assertIn("startService(serviceIntent);", helper)

        start_legacy = self._method(
            "private void startLegacyVpnService",
            "@Override\n    protected void onActivityResult",
        )
        self.assertIn("startLegacyServiceIntent(serviceIntent);", start_legacy)
        self.assertNotIn("startService(serviceIntent);", start_legacy)


if __name__ == "__main__":
    unittest.main()
