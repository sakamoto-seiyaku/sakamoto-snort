/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_CORE_FFI_H
#define SAKAMOTO_PRODUCT_CORE_FFI_H

#include "sakamoto_product_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The handle is allocated and owned by the Rust Product Core cdylib. */
typedef struct sakamoto_product_core_handle sakamoto_product_core_handle_t;

uint32_t sakamoto_product_core_connect(
    sakamoto_product_bytes_t api_socket, uint64_t generation,
    sakamoto_product_core_handle_t **out_handle,
    sakamoto_product_status_t *out_status);

uint32_t sakamoto_product_core_query(
    sakamoto_product_core_handle_t *handle, uint64_t generation,
    sakamoto_product_status_t *out_status);

uint32_t sakamoto_product_core_disconnect(
    sakamoto_product_core_handle_t *handle);

uint32_t sakamoto_product_core_destroy(
    sakamoto_product_core_handle_t *handle);

#ifdef __cplusplus
}
#endif

#endif
