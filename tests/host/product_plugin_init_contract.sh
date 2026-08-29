#!/usr/bin/env bash
set -euo pipefail

# Compile the production plugin translation unit against a deliberately tiny
# VPP-shaped seam. The fake generated API controls setup_message_id_table(),
# while the test calls the real VLIB init function registered by the plugin.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="$(mktemp -d /tmp/sakamoto-product-plugin-init.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
mkdir -p "$work_dir/vlib" "$work_dir/vlibapi" "$work_dir/vlibmemory" \
  "$work_dir/vnet/plugin" "$work_dir/vnet" "$work_dir/vpp/app"

cat >"$work_dir/vlib/vlib.h" <<'EOF'
#ifndef SAKAMOTO_TEST_VLIB_H
#define SAKAMOTO_TEST_VLIB_H
#include <stdint.h>
#include <stdarg.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint64_t u64;
typedef struct { int unused; } vlib_main_t;
typedef struct { const char *message; } clib_error_t;
extern clib_error_t sakamoto_test_error;
static inline clib_error_t *
sakamoto_test_error_return (int ignored, const char *format, ...)
{
  (void) ignored;
  (void) format;
  sakamoto_test_error.message = "message-id-table unavailable";
  return &sakamoto_test_error;
}
#define clib_error_return(...) sakamoto_test_error_return (__VA_ARGS__)
#define clib_memset memset
#define clib_memcpy memcpy
#define clib_host_to_net_u64 value_identity_u64
static inline u64 value_identity_u64 (u64 value) { return value; }
#define VLIB_INIT_FUNCTION(fn) \
  clib_error_t *(*sakamoto_test_init)(vlib_main_t *) = fn
#endif
EOF

cat >"$work_dir/vlibapi/api.h" <<'EOF'
#ifndef SAKAMOTO_TEST_VLIBAPI_H
#define SAKAMOTO_TEST_VLIBAPI_H
#endif
EOF
cat >"$work_dir/vlibmemory/api.h" <<'EOF'
#ifndef SAKAMOTO_TEST_VLIBMEMORY_H
#define SAKAMOTO_TEST_VLIBMEMORY_H
#endif
EOF
cat >"$work_dir/vnet/vnet.h" <<'EOF'
#ifndef SAKAMOTO_TEST_VNET_H
#define SAKAMOTO_TEST_VNET_H
#endif
EOF
cat >"$work_dir/vpp/app/version.h" <<'EOF'
#ifndef SAKAMOTO_TEST_VPP_VERSION_H
#define SAKAMOTO_TEST_VPP_VERSION_H
#define VPP_BUILD_VER "test-vpp"
#endif
EOF
cat >"$work_dir/vnet/plugin/plugin.h" <<'EOF'
#ifndef SAKAMOTO_TEST_VNET_PLUGIN_H
#define SAKAMOTO_TEST_VNET_PLUGIN_H
typedef struct {
  const char *version;
  const char *description;
} vlib_plugin_registration_t;
#define VLIB_PLUGIN_REGISTER() vlib_plugin_registration_t vlib_plugin_registration
#endif
EOF
cat >"$work_dir/vlibapi/api_helper_macros.h" <<'EOF'
#ifndef SAKAMOTO_TEST_API_HELPERS_H
#define SAKAMOTO_TEST_API_HELPERS_H
#define REPLY_MACRO2(message_id, body) \
  do { \
    (void) (message_id); \
    rmp = (void *) (uintptr_t) 1U; \
    body; \
  } while (0)
#endif
EOF

cat >"$work_dir/product_core.api_enum.h" <<'EOF'
#ifndef SAKAMOTO_TEST_PRODUCT_CORE_ENUM_H
#define SAKAMOTO_TEST_PRODUCT_CORE_ENUM_H
#define VL_API_PRODUCT_CORE_STATUS_REPLY 1
#endif
EOF
cat >"$work_dir/product_core.api_types.h" <<'EOF'
#ifndef SAKAMOTO_TEST_PRODUCT_CORE_TYPES_H
#define SAKAMOTO_TEST_PRODUCT_CORE_TYPES_H
typedef struct {
  int32_t retval;
  uint32_t abi_version;
  uint32_t api_version;
  uint64_t generation;
  u8 core_ready;
  u8 adapter_available;
  u8 protection_running;
  u8 artifact_id[96];
  u8 api_identity[96];
  u8 vpp_revision[48];
} vl_api_product_core_status_reply_t;
typedef struct { int unused; } vl_api_product_core_status_t;
#endif
EOF
cat >"$work_dir/product_core_identity.h" <<'EOF'
#ifndef SAKAMOTO_TEST_PRODUCT_CORE_IDENTITY_H
#define SAKAMOTO_TEST_PRODUCT_CORE_IDENTITY_H
#define SAKAMOTO_PRODUCT_ABI_VERSION 1
#define SAKAMOTO_PRODUCT_API_VERSION 1
#define SAKAMOTO_PRODUCT_ARTIFACT_ID "test-artifact"
#define SAKAMOTO_PRODUCT_API_IDENTITY "test-api"
#define SAKAMOTO_PRODUCT_MANIFEST_VPP_REVISION "test-revision"
#endif
EOF
cat >"$work_dir/product_core.api.c" <<'EOF'
extern u16 sakamoto_test_message_id_base;
static u16
setup_message_id_table (void)
{
  (void) vl_api_product_core_status_t_handler;
  return sakamoto_test_message_id_base;
}
EOF

cat >"$work_dir/harness.c" <<EOF
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "vlib/vlib.h"

clib_error_t sakamoto_test_error;
u16 sakamoto_test_message_id_base;

#define SAKAMOTO_PRODUCT_VPP_REVISION "test-revision"
#include "$repo_root/src/product/vpp/product_core_plugin.c"

int
main (void)
{
  vlib_main_t vm = {0};
  sakamoto_test_message_id_base = UINT16_MAX;
  sakamoto_test_error.message = NULL;
  clib_error_t *error = sakamoto_test_init (&vm);
  if (error == NULL || product_core_main.core_ready != 0U
      || product_core_main.msg_id_base != UINT16_MAX
      || strstr (error->message, "unavailable") == NULL)
    {
      fprintf (stderr, "message-id setup failure was not fail-closed\\n");
      return 1;
    }

  sakamoto_test_message_id_base = 42U;
  sakamoto_test_error.message = NULL;
  error = sakamoto_test_init (&vm);
  if (error != NULL || product_core_main.core_ready == 0U
      || product_core_main.msg_id_base != 42U)
    {
      fprintf (stderr, "available message-id setup did not reach ready\\n");
      return 1;
    }
  return 0;
}
EOF

cc -std=c11 -Wall -Wextra -Werror \
  -I"$work_dir" -I"$repo_root/src/product/include" \
  "$work_dir/harness.c" -o "$work_dir/plugin-init-contract"
"$work_dir/plugin-init-contract"
echo "sakamoto production VPP plugin init contract: PASS"
