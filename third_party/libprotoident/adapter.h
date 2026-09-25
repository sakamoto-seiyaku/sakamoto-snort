/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_LPI_ADAPTER_H
#define SAKAMOTO_LPI_ADAPTER_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Initialize once on main before workers; registry immutable thereafter. */
int sakamoto_lpi_init (void);
/* Borrowed scalar features. Returns a static catalog provider alias or NULL for a temporary miss; empty string for an unmapped result.
 * No heap allocation, threads, packet/Flow pointers or retained query state. */
const char *sakamoto_lpi_guess (const uint32_t payload[2], const uint32_t lengths[2],
                              const uint32_t observed[2], const uint32_t ips[2],
                              uint16_t client, uint16_t server, uint8_t transport);
#ifdef __cplusplus
}
#endif
#endif
