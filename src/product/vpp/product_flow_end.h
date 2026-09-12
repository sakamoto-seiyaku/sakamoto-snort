/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_FLOW_END_H
#define SAKAMOTO_PRODUCT_FLOW_END_H

#include <vlib/vlib.h>
#include "product_flow_entry.h"

/* Pinned vlib resets the entire first-cacheline template (including flags and
 * opaque) BEFORE the pool free callback. The discriminant must survive there.
 * opaque2 byte 55 bit 7 is reserved across the Product packet, fragment and
 * completion overlays. Upstream vnet_buffer2 places it in unused[4]; no enabled
 * upstream consumer owns it. Alloc always clears it, including non-Product
 * buffers. This does not enlarge vlib_buffer_t or reserve any packet payload.
 * See the S225 metadata audit for the pinned VLIB/VNET flag allocation. */
#define PRODUCT_FLOW_END_DISCRIMINANT_OFFSET 55
#define PRODUCT_FLOW_END_DISCRIMINANT UINT8_C (0x80)

typedef struct
{
  u64 generation;
  u64 incarnation;
  u32 flow_index;
  u16 owner;
  u8 end_reason;
  u8 trace;
  u8 early_free; /* bounded controlled-close evidence; normal delivery is zero */
  u8 reserved[30];
  u8 is_flow_end;
} product_flow_end_metadata_t;

_Static_assert (sizeof (product_flow_end_metadata_t) == 56, "FlowEnd overlay");
_Static_assert (offsetof (product_flow_end_metadata_t, is_flow_end) ==
                  PRODUCT_FLOW_END_DISCRIMINANT_OFFSET, "FlowEnd discriminant");
_Static_assert (sizeof (product_flow_end_metadata_t) ==
                  sizeof (((vlib_buffer_t *) 0)->opaque2), "native opaque2 size");

static_always_inline int
product_buffer_is_flow_end (const vlib_buffer_t *buffer)
{
  return (((const u8 *) buffer->opaque2)[PRODUCT_FLOW_END_DISCRIMINANT_OFFSET]
          & PRODUCT_FLOW_END_DISCRIMINANT) != 0;
}

/* One registration at plugin initialization; a conflict fails initialization.
 * Runtime/profile restart only rebinds drained owner-local state. */
clib_error_t *product_flow_end_init (vlib_main_t *vm);
int product_flow_end_start (u64 generation, product_flow_runtime_t **runtimes,
                            u32 worker_count);
void product_flow_end_unbind (void);
u32 product_flow_end_buffer_debt (void);
void product_flow_end_quiesce (vlib_main_t *vm);

/* Shared packet/END consumer and terminal branch. Return 1 from consume only
 * when the controlled early-free case has already returned the signal buffer.
 * Neither branch performs Adapter Completion or direct FlowEntry release. */
int product_flow_end_consume (vlib_main_t *vm, vlib_node_runtime_t *node,
                              u32 buffer_index);
void product_flow_end_terminal (vlib_main_t *vm, vlib_node_runtime_t *node,
                                u32 buffer_index);
void product_flow_end_before_observe (vlib_main_t *vm);

#endif
