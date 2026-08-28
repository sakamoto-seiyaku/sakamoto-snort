/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_WIRE_H
#define SAKAMOTO_PRODUCT_WIRE_H

#include <stdint.h>

/*
 * This is the narrow Host test transport used when a real VPP/VAPI build is
 * not linked into the C bridge.  It is deliberately not a product protocol:
 * the production build uses the generated VAPI client instead.  Keeping the
 * fixture wire format here makes semantic tests deterministic without
 * allowing a test server to masquerade as a VPP artifact.
 */
#define SAKAMOTO_PRODUCT_WIRE_MAGIC UINT32_C(0x534b5043)
#define SAKAMOTO_PRODUCT_WIRE_VERSION UINT16_C(1)
#define SAKAMOTO_PRODUCT_WIRE_OP_CONNECT UINT16_C(1)
#define SAKAMOTO_PRODUCT_WIRE_OP_QUERY UINT16_C(2)

#define SAKAMOTO_PRODUCT_WIRE_CORE_READY UINT32_C(1 << 0)
#define SAKAMOTO_PRODUCT_WIRE_ADAPTER_AVAILABLE UINT32_C(1 << 1)
#define SAKAMOTO_PRODUCT_WIRE_PROTECTION_RUNNING UINT32_C(1 << 2)
#define SAKAMOTO_PRODUCT_WIRE_PLUGIN_LOADED UINT32_C(1 << 3)
#define SAKAMOTO_PRODUCT_WIRE_VAPI_HANDLE_LIVE UINT32_C(1 << 4)
#define SAKAMOTO_PRODUCT_WIRE_GENERATION_LIVE UINT32_C(1 << 5)

typedef struct __attribute__((packed)) {
  uint32_t magic;
  uint16_t version;
  uint16_t operation;
  uint64_t generation;
} sakamoto_product_wire_request_t;

typedef struct __attribute__((packed)) {
  uint32_t magic;
  uint16_t version;
  uint16_t reserved;
  uint32_t status_code;
  uint64_t generation;
  uint32_t flags;
  char artifact_id[96];
  char api_identity[96];
  char vpp_revision[48];
  char error_detail[128];
} sakamoto_product_wire_response_t;

_Static_assert (sizeof (sakamoto_product_wire_request_t) == 16U,
                "Host fixture request framing changed");
_Static_assert (sizeof (sakamoto_product_wire_response_t) == 392U,
                "Host fixture response framing changed");

#endif
