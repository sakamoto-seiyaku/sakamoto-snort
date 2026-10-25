/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_ROOT_DNS_ADAPTER_H
#define SAKAMOTO_PRODUCT_ROOT_DNS_ADAPTER_H
#include <vlib/vlib.h>
#include "product_packet_completion.h"
#include "product_root_dns_admission.h"

int product_root_dns_adapter_start (vlib_main_t *, uint64_t generation, unsigned owners);
void product_root_dns_adapter_changed (void);
/* Existing main-thread lifecycle barrier; cancel upstream work first and keep
 * raw reply resources until native return/completion buffers have drained. */
void product_root_dns_adapter_quiesce (vlib_main_t *);
void product_root_dns_adapter_stop (vlib_main_t *);
int product_root_dns_adapter_ready (void);
uint32_t product_root_dns_adapter_pending (unsigned owner);
/* Configuration authority only: true while Root ordinary-query replacement is
 * selected. Admission uses this to prevent a resource bypass to the original
 * resolver before the complete-message proxy can take ownership. */
int product_root_dns_adapter_enabled (void);
void product_root_dns_adapter_admission_observe (vlib_main_t *, uint64_t token,
  const product_platform_packet_facts_t *,
  const product_root_dns_admission_facts_t *, uint8_t coverage,
  uint8_t delivery);
uint64_t product_root_dns_adapter_deadline (unsigned owner);
void product_root_dns_adapter_expire (vlib_main_t *, uint64_t now_us);
void product_root_dns_reply_complete (vlib_main_t *, uint32_t buffer,
  const product_packet_completion_frame_t *);
void product_root_dns_reply_freed (vlib_main_t *, uint32_t buffer,
  const product_packet_completion_frame_t *);
int product_root_dns_vpn_return_known(vlib_main_t *, uint32_t buffer);
int product_root_dns_vpn_authorized(vlib_main_t *, uint64_t generation, uint64_t cookie,
  unsigned error, uint64_t epoch, uint32_t context, int known);
void product_root_dns_vpn_invalidate(vlib_main_t *, uint64_t generation, uint64_t epoch);
void product_root_dns_vpn_session_end(vlib_main_t *, uint64_t generation, uint64_t session);
void product_root_dns_vpn_return_admit(vlib_main_t *, uint32_t buffer,
  const product_adapter_obligation_t *, const product_platform_packet_facts_t *);
void product_root_dns_vpn_reply_complete(vlib_main_t *, uint32_t buffer,
  const product_packet_completion_frame_t *, uint8_t delivery);
void product_root_dns_vpn_reply_freed(vlib_main_t *, uint32_t buffer,
  const product_packet_completion_frame_t *);
#endif
