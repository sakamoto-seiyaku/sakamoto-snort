/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_PACKET_COMPLETION_H
#define SAKAMOTO_PRODUCT_PACKET_COMPLETION_H

#include "product_packet.h"

/* After terminal, this value replaces PacketFacts in opaque2. The native
 * frame carries the existing buffer index; no packet or platform facts are
 * copied into completion ownership. */
typedef struct
{
  product_adapter_obligation_t obligation;
  uint16_t producer_thread;
  uint8_t terminal_intent;
  uint8_t runtime_drop_reason;
  uint8_t flags;
  uint8_t reserved[3];
} product_packet_completion_frame_t;

enum
{
  PRODUCT_COMPLETION_TRACE = 1 << 0,
  PRODUCT_COMPLETION_REPLAY_PROBE = 1 << 1,
};

_Static_assert (sizeof (product_packet_completion_frame_t) == 32,
                "bounded completion frame contract");
_Static_assert (offsetof (product_packet_completion_frame_t, producer_thread) == 24,
                "completion has only obligation and terminal operation fields");
#endif
