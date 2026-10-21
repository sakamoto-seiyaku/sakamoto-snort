/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_PACKET_COMPLETION_H
#define SAKAMOTO_PRODUCT_PACKET_COMPLETION_H

#include "product_packet.h"

/* A bank has 64 slots; two banks support the default 128-slot Root pool.
 * The 64-slot diagnostic configuration and capacity qualification are separate. */
#define PRODUCT_ROOT_COMPLETION_CAPACITY 64
#define PRODUCT_ROOT_COMPLETION_MAX_CAPACITY 128
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
  /* Zero = no admission; otherwise Product Flow Stack input result + 1. */
  uint8_t flow_stack_result;
  uint8_t reserved;
} product_packet_completion_frame_t;

enum
{
  PRODUCT_COMPLETION_TRACE = 1 << 0,
  PRODUCT_COMPLETION_REPLAY_PROBE = 1 << 1,
  PRODUCT_COMPLETION_FRAGMENT_MEMBER = 1 << 2,
  PRODUCT_COMPLETION_FRAGMENT_PINNED = 1 << 3,
  /* Derived from shared PacketFacts before their terminal lifetime ends. */
  PRODUCT_COMPLETION_TRANSPORT_UNSUPPORTED = 1 << 4,
  PRODUCT_COMPLETION_FLOW_STACK_RETURN = 1 << 5,
  /* Ordinary Root packet: complete policy decision, not capacity bypass. */
  PRODUCT_COMPLETION_POLICY_QUALIFIED = 1 << 6,
  /* Qualified packet with a complete rule winner at its decision cutoff. */
  PRODUCT_COMPLETION_POLICY_QUALIFIED_MATCHED = 1 << 7,
};

_Static_assert (sizeof (product_packet_completion_frame_t) == 32,
                "bounded completion frame contract");
_Static_assert (offsetof (product_packet_completion_frame_t, producer_thread) == 24,
                "completion has only obligation and terminal operation fields");
#endif
