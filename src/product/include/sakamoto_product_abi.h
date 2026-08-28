/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_ABI_H
#define SAKAMOTO_PRODUCT_ABI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* This is a deliberately small, fixed-width, non-unwinding seam. */
#define SAKAMOTO_PRODUCT_ABI_VERSION UINT32_C(1)
#define SAKAMOTO_PRODUCT_API_VERSION UINT32_C(1)
#define SAKAMOTO_PRODUCT_ARTIFACT_ID_MAX UINT32_C(96)
#define SAKAMOTO_PRODUCT_API_IDENTITY_MAX UINT32_C(96)
#define SAKAMOTO_PRODUCT_VPP_REVISION_MAX UINT32_C(48)
#define SAKAMOTO_PRODUCT_ERROR_DETAIL_MAX UINT32_C(128)

typedef struct {
  const uint8_t *data;
  uint32_t length;
} sakamoto_product_bytes_t;

/* Keep values as integer tags.  Do not model these as a fieldless Rust enum. */
#define SAKAMOTO_PRODUCT_OK UINT32_C(0)
#define SAKAMOTO_PRODUCT_INVALID_ARGUMENT UINT32_C(1)
#define SAKAMOTO_PRODUCT_ALLOCATION_FAILED UINT32_C(2)
#define SAKAMOTO_PRODUCT_CONNECT_FAILED UINT32_C(3)
#define SAKAMOTO_PRODUCT_DISCONNECTED UINT32_C(4)
#define SAKAMOTO_PRODUCT_STALE_HANDLE UINT32_C(5)
#define SAKAMOTO_PRODUCT_API_UNAVAILABLE UINT32_C(6)
#define SAKAMOTO_PRODUCT_QUERY_FAILED UINT32_C(7)
#define SAKAMOTO_PRODUCT_PROTOCOL_MISMATCH UINT32_C(8)
#define SAKAMOTO_PRODUCT_INTERNAL_ERROR UINT32_C(9)
#define SAKAMOTO_PRODUCT_UNKNOWN_TAG UINT32_C(10)

typedef struct {
  uint32_t abi_version;
  uint32_t api_version;
  uint32_t status_code;
  uint32_t reserved;
  uint64_t generation;
  uint32_t core_ready;
  uint32_t adapter_available;
  uint32_t protection_running;
  uint32_t plugin_loaded;
  uint32_t vapi_handle_live;
  uint32_t generation_live;
  uint32_t reserved_flags;
  char artifact_id[SAKAMOTO_PRODUCT_ARTIFACT_ID_MAX];
  char api_identity[SAKAMOTO_PRODUCT_API_IDENTITY_MAX];
  char vpp_revision[SAKAMOTO_PRODUCT_VPP_REVISION_MAX];
  char error_detail[SAKAMOTO_PRODUCT_ERROR_DETAIL_MAX];
} sakamoto_product_status_t;

/* Compile every consumer against the same layout, not just the bridge. */
#if defined(__cplusplus)
static_assert(sizeof(sakamoto_product_bytes_t) == 16U,
              "product bytes ABI changed");
static_assert(offsetof(sakamoto_product_status_t, generation) == 16U,
              "product status generation ABI changed");
static_assert(offsetof(sakamoto_product_status_t, artifact_id) == 52U,
              "product status identity ABI changed");
static_assert(sizeof(sakamoto_product_status_t) == 424U,
              "product status ABI changed");
#else
_Static_assert(sizeof(sakamoto_product_bytes_t) == 16U,
               "product bytes ABI changed");
_Static_assert(offsetof(sakamoto_product_status_t, generation) == 16U,
               "product status generation ABI changed");
_Static_assert(offsetof(sakamoto_product_status_t, artifact_id) == 52U,
               "product status identity ABI changed");
_Static_assert(sizeof(sakamoto_product_status_t) == 424U,
               "product status ABI changed");
#endif

/* Opaque to Rust and to all callers except the bridge implementation. */
typedef struct sakamoto_product_session sakamoto_product_session_t;

uint32_t sakamoto_product_abi_version(void);
uint32_t sakamoto_product_api_version(void);

uint32_t sakamoto_product_session_connect(
    sakamoto_product_bytes_t api_socket, uint64_t expected_generation,
    sakamoto_product_session_t **out_session,
    sakamoto_product_status_t *out_status);

uint32_t sakamoto_product_session_query(
    sakamoto_product_session_t *session, uint64_t expected_generation,
    sakamoto_product_status_t *out_status);

/* Retires transport state but keeps a tombstone so stale use is explicit. */
uint32_t sakamoto_product_session_disconnect(
    sakamoto_product_session_t *session);

/* Frees the tombstone; callers must not use the pointer afterward. */
uint32_t sakamoto_product_session_destroy(
    sakamoto_product_session_t *session);

#ifdef __cplusplus
}
#endif

#endif
