import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
NATIVE_PROBE = ROOT / "android/vpn-lite/native/vpn_fd_probe.c"
BUILD_DEBUG_APK = ROOT / "android/vpn-lite/scripts/build-debug-apk.sh"


class VerifyVpnLitePluginStagingTest(unittest.TestCase):
    def setUp(self):
        self.native_probe = NATIVE_PROBE.read_text(encoding="utf-8")
        self.build_debug_apk = BUILD_DEBUG_APK.read_text(encoding="utf-8")

    def test_vpp_plugins_are_loaded_from_native_dir_with_name_filter(self):
        write_start = self.native_probe.index("static int write_vpp_files")
        write_end = self.native_probe.index("JNIEXPORT jint JNICALL", write_start)
        write_vpp_files = self.native_probe[write_start:write_end]

        self.assertIn("char plugin_name[64]", write_vpp_files)
        self.assertIn("char plugin_path[PATH_BUF_SIZE];", write_vpp_files)
        self.assertIn("path_exists(plugin_path)", write_vpp_files)

        conf_start = write_vpp_files.index('"plugins {\\n"')
        conf = write_vpp_files[conf_start:]
        self.assertIn('"  path %s\\n"', conf)
        self.assertIn('"  name-filter %s\\n"', conf)
        self.assertIn("runtime_dir, runtime_dir, native_dir, plugin_name", conf)
        self.assertNotIn("plugin default { disable }", conf)
        self.assertNotIn("plugin %s { enable }", conf)

    def test_plugin_loader_no_longer_uses_default_disable_whitelist(self):
        self.assertNotIn("plugin default { disable }", self.native_probe)
        self.assertNotIn("plugin %s { enable }", self.native_probe)

    def test_vpp_monitor_uses_mode_specific_show_command(self):
        self.assertIn("g_vpp_monitor_show_command", self.native_probe)

        monitor_start = self.native_probe.index("static void *vpp_monitor_thread")
        monitor_end = self.native_probe.index("static int write_vpp_files", monitor_start)
        monitor = self.native_probe[monitor_start:monitor_end]
        self.assertIn('run_cli_command(sock_path, "show plugins", file);', monitor)
        self.assertIn("run_cli_command(sock_path, show_command, file);", monitor)
        self.assertNotIn('run_cli_command(sock_path, "show tun-poc", file);', monitor)
        self.assertNotIn('run_cli_command(sock_path, "show s124-vpn-tun", file);',
                         monitor)

        start = self.native_probe.index("g_vpp_underlay_epoch = 0;")
        start_block = self.native_probe[start:self.native_probe.index("g_oi5_mode = use_oi5;",
                                                                      start)]
        self.assertIn("if (use_oi3_multi)", start_block)
        self.assertIn('"show sakamoto-oi3 multi"', start_block)
        self.assertIn("else if (use_oi3)", start_block)
        self.assertIn('"show sakamoto-oi3"', start_block)
        self.assertIn("else if (use_oi2)", start_block)
        self.assertIn('"show sakamoto-oi2"', start_block)
        self.assertIn("else if (use_s124_tun)", start_block)
        self.assertIn('"show s124-vpn-tun"', start_block)
        self.assertIn('"show tun-poc"', start_block)

    def test_oi3_apk_packaging_requires_owner_context_hev_symbols(self):
        self.assertIn("has_dynamic_symbol()", self.build_debug_apk)
        self.assertIn("libhev_external_driver_poc_plugin.so", self.build_debug_apk)
        self.assertIn("OI3 plugin requires HEV owner-context library",
                      self.build_debug_apk)
        self.assertIn("required_oi3_hev_symbols=(", self.build_debug_apk)

        for symbol in (
            "hev_socks5_owner_config_default",
            "flow_stack_owner_create_with_config",
            "flow_stack_owner_configure_sessions",
            "flow_stack_owner_start",
            "flow_stack_owner_submit",
            "flow_stack_owner_stop",
            "flow_stack_owner_destroy",
            "flow_stack_owner_identity",
            "flow_stack_owner_runtime_identity",
        ):
            self.assertIn(symbol, self.build_debug_apk)


if __name__ == "__main__":
    unittest.main()
