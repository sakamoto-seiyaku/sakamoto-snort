/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_LPI_H
#define SAKAMOTO_PRODUCT_LPI_H
#include <stdint.h>
#define PRODUCT_LPI_MAX_ATTEMPTS 20U
#define PRODUCT_LPI_MAX_BYTES 32768U

typedef enum {
  PRODUCT_LPI_RUNNING = 0,
  PRODUCT_LPI_STOP_PACKET_BUDGET,
  PRODUCT_LPI_STOP_BYTE_BUDGET,
  PRODUCT_LPI_STOP_FLOW_END,
  PRODUCT_LPI_STOP_UNSUPPORTED
} product_lpi_stop_t;
typedef enum {
  PRODUCT_LPI_NO_ATTEMPT = 0,
  PRODUCT_LPI_MISS,
  PRODUCT_LPI_UNMAPPED,
  PRODUCT_LPI_MAPPED
} product_lpi_outcome_t;
/* Owner-local values only, embedded in FlowEntry. No heap/packet ownership. */
typedef struct {
  uint64_t protocols;
  uint32_t payload[2], lengths[2], observed[2], ips[2];
  uint32_t bytes;
  uint16_t client_port, server_port;
  uint8_t attempts, available, stop_reason, last_outcome;
  /* Direction is the existing ORIG/REPLY observation, never inferred from port. */
  uint8_t mail_pending, mail_side, ftps_stage, ftps_side;
  uint8_t socks_version, socks_side, socks_methods[32];
  uint8_t wg_stage, wg_side;
  uint32_t wg_index[2];
  uint8_t ovpn_session[2][8], ovpn_count[2], ovpn_reset[2];
  uint8_t rdp_pending, rdp_side;
  uint32_t rdp_sequence;
} product_lpi_state_t;
static inline const char *product_lpi_stop_name (unsigned reason)
{
  switch (reason) {
    case PRODUCT_LPI_RUNNING: return "running";
    case PRODUCT_LPI_STOP_PACKET_BUDGET: return "packet_budget";
    case PRODUCT_LPI_STOP_BYTE_BUDGET: return "byte_budget";
    case PRODUCT_LPI_STOP_FLOW_END: return "flow_end";
    case PRODUCT_LPI_STOP_UNSUPPORTED: return "unsupported";
    default: return "invalid";
  }
}
/* Main-thread initialization before owner admission, exactly once per process. */
int product_lpi_init (void);
#endif
