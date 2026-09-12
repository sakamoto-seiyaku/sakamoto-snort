/* SPDX-License-Identifier: MIT */
#ifndef SAKAMOTO_HEV_LWIP_HOOKS_H
#define SAKAMOTO_HEV_LWIP_HOOKS_H
#include "hev-lwip-context.h"
/* No packet reparse. lwIP has already selected its transport PCB. */
#define LWIP_HOOK_TCP_INPACKET_PCB(pcb, hdr, optlen, opt1len, opt2, p) \
  hev_lwip_tcp_input_guard(pcb)
#endif
