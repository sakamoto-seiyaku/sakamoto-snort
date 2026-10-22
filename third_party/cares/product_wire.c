/* SPDX-License-Identifier: Apache-2.0 */
#include "product_cares.h"
/* Compile the unmodified pinned parser once in this translation unit. Its
 * buffer parser is static upstream; this narrow export adds exact-consumption
 * checking without patching the parser or importing resolver-channel code. */
#include "upstream/src/lib/record/ares_dns_parse.c"

ares_status_t product_cares_parse (const uint8_t *wire, size_t length,
                                  ares_dns_record_t **record)
{
  *record = NULL;
  ares_buf_t *buffer = ares_buf_create_const (wire, length);
  if (!buffer) return ARES_ENOMEM;
  ares_status_t status = ares_dns_parse_buf (buffer, 0, record);
  if (status == ARES_SUCCESS && ares_buf_len (buffer))
    {
      ares_dns_record_destroy (*record);
      *record = NULL;
      status = ARES_EBADRESP;
    }
  ares_buf_destroy (buffer);
  return status;
}
