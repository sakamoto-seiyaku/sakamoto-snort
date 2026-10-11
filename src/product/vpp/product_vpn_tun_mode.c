/* SPDX-License-Identifier: Apache-2.0 */
/* RuntimeService selects the profile before spawning VPP. A profile switch
 * starts another process, so the packet graph reads one process-lifetime mode. */
#include <stdlib.h>
#include <string.h>

enum {
  MODE_UNINITIALIZED = -1,
  MODE_DISABLED = 0,
  MODE_GRAPH_VALIDATION = 1,
  MODE_PRODUCT_VPN = 2,
};

/* product_core_init publishes this before VPP starts workers or adapters. */
static int mode = MODE_UNINITIALIZED;

void product_vpn_tun_mode_init(void) {
  if (mode != MODE_UNINITIALIZED) return;
  int selected = MODE_DISABLED;
  const char *profile = getenv("SAKAMOTO_RUNTIME_PROFILE");
  if (profile && strcmp(profile, "vpn") == 0) {
    const char *product = getenv("SAKAMOTO_PRODUCT_VPN_PRODUCT");
    if (product && strcmp(product, "1") == 0) {
      selected = MODE_PRODUCT_VPN;
    } else {
      const char *validation = getenv("SAKAMOTO_PRODUCT_VPN_GRAPH_VALIDATION");
      if (validation && strcmp(validation, "1") == 0)
        selected = MODE_GRAPH_VALIDATION;
    }
  }
  mode = selected;
}

int product_vpn_tun_product_mode(void) { return mode == MODE_PRODUCT_VPN; }
int product_vpn_tun_enabled(void) { return mode > MODE_DISABLED; }
