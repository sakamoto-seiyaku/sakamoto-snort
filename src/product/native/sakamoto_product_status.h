/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_STATUS_H
#define SAKAMOTO_PRODUCT_STATUS_H

#include "sakamoto_product_abi.h"

#include <stddef.h>
#include <string.h>

/*
 * Transport-neutral status hygiene shared by the Host fixture and the real
 * generated-VAPI bridge.  The framing, socket, and VAPI ownership remain in
 * their separate translation units; these helpers only keep the public ABI
 * initialized and copy bounded identity text safely.
 */
static inline void
sakamoto_product_status_reset (sakamoto_product_status_t *status,
                                uint64_t generation)
{
  if (status == NULL)
    return;
  memset (status, 0, sizeof (*status));
  status->abi_version = SAKAMOTO_PRODUCT_ABI_VERSION;
  status->api_version = SAKAMOTO_PRODUCT_API_VERSION;
  status->generation = generation;
}

static inline void
sakamoto_product_status_error (sakamoto_product_status_t *status,
                               uint32_t code, const char *detail)
{
  if (status == NULL)
    return;
  status->status_code = code;
  if (detail == NULL)
    return;
  strncpy (status->error_detail, detail, sizeof (status->error_detail) - 1U);
  status->error_detail[sizeof (status->error_detail) - 1U] = '\0';
}

static inline void
sakamoto_product_status_copy_text (char *destination, size_t destination_size,
                                   const void *source, size_t source_size)
{
  if (destination == NULL || destination_size == 0U)
    return;
  const uint8_t *bytes = source;
  size_t count = 0U;
  if (bytes != NULL)
    while (count < source_size && bytes[count] != '\0')
      ++count;
  if (count >= destination_size)
    count = destination_size - 1U;
  if (count != 0U)
    memcpy (destination, bytes, count);
  destination[count] = '\0';
}

#endif
