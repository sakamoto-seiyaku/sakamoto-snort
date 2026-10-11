#!/usr/bin/env python3
"""Exercise the VPP packet graph's process mode getters as compiled C."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODE_SOURCE = ROOT / "src/product/vpp/product_vpn_tun_mode.c"

HARNESS = r"""
#include <stdlib.h>

void product_vpn_tun_mode_init(void);
int product_vpn_tun_product_mode(void);
int product_vpn_tun_enabled(void);

static int getenv_calls;
char *__real_getenv(const char *name);
char *__wrap_getenv(const char *name) {
  ++getenv_calls;
  return __real_getenv(name);
}

int main(int argc, char **argv) {
  if (argc != 3) return 10;
  product_vpn_tun_mode_init();
  const int calls_after_init = getenv_calls;
  if (calls_after_init < 1 || calls_after_init > 3) return 11;
  if (setenv("SAKAMOTO_RUNTIME_PROFILE", "root", 1) ||
      unsetenv("SAKAMOTO_PRODUCT_VPN_PRODUCT") ||
      unsetenv("SAKAMOTO_PRODUCT_VPN_GRAPH_VALIDATION")) return 12;
  product_vpn_tun_mode_init(); /* An accidental second init cannot change this process. */
  if (getenv_calls != calls_after_init) return 15;
  for (int i = 0; i < 100000; ++i) {
    if (product_vpn_tun_product_mode() != atoi(argv[1]) ||
        product_vpn_tun_enabled() != atoi(argv[2])) return 13;
  }
  return getenv_calls == calls_after_init ? 0 : 14;
}
"""


class VppRuntimeModeTest(unittest.TestCase):
    def test_process_modes_and_packet_getters(self):
        cases = (
            ("root", "1", "1", 0, 0),
            ("vpn", "1", None, 1, 1),
            ("vpn", None, "1", 0, 1),
            ("vpn", "1", "1", 1, 1),
            ("vpn", "0", "0", 0, 0),
            ("vpn", "true", "true", 0, 0),
            ("invalid", "1", "1", 0, 0),
            (None, "1", "1", 0, 0),
        )
        with tempfile.TemporaryDirectory() as directory:
            harness = Path(directory) / "runtime_mode_test.c"
            binary = Path(directory) / "runtime_mode_test"
            harness.write_text(HARNESS)
            subprocess.run(["cc", "-std=c11", "-D_POSIX_C_SOURCE=200809L",
                            "-Wall", "-Wextra", "-Werror", "-O2",
                            str(harness), str(MODE_SOURCE),
                            "-Wl,--wrap=getenv", "-o", str(binary)],
                           check=True, capture_output=True, text=True)
            for profile, product, validation, expected_product, expected_enabled in cases:
                with self.subTest(profile=profile, product=product, validation=validation):
                    env = os.environ.copy()
                    for key, value in (("SAKAMOTO_RUNTIME_PROFILE", profile),
                                       ("SAKAMOTO_PRODUCT_VPN_PRODUCT", product),
                                       ("SAKAMOTO_PRODUCT_VPN_GRAPH_VALIDATION", validation)):
                        if value is None:
                            env.pop(key, None)
                        else:
                            env[key] = value
                    subprocess.run([str(binary), str(expected_product),
                                    str(expected_enabled)], env=env,
                                   check=True, capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
