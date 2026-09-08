/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_PACKET_COMPLETION_H
#define SAKAMOTO_PRODUCT_PACKET_COMPLETION_H

#include "product_packet.h"

/* Current bounded configuration; capacity qualification remains separate. */
#define PRODUCT_ROOT_COMPLETION_CAPACITY 64
#define PRODUCT_ROOT_COMPLETION_MAX_LANES 4
#define PRODUCT_GRAPH_INJECTION_CAPACITY 32

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
  uint8_t processing_bypass_reason;
  uint8_t reserved[2];
} product_packet_completion_frame_t;

enum
{
  PRODUCT_COMPLETION_TRACE = 1 << 0,
  PRODUCT_COMPLETION_REPLAY_PROBE = 1 << 1,
  PRODUCT_COMPLETION_FRAGMENT_MEMBER = 1 << 2,
  PRODUCT_COMPLETION_FRAGMENT_PINNED = 1 << 3,
  /* Derived from shared PacketFacts before their terminal lifetime ends. */
  PRODUCT_COMPLETION_TRANSPORT_UNSUPPORTED = 1 << 4,
};

_Static_assert (sizeof (product_packet_completion_frame_t) == 32,
                "bounded completion frame contract");
_Static_assert (offsetof (product_packet_completion_frame_t, producer_thread) == 24,
                "completion has only obligation and terminal operation fields");
#endif
