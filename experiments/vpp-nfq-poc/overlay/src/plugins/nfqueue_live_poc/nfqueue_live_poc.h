/* SPDX-License-Identifier: Apache-2.0 */

#ifndef included_nfqueue_live_poc_h
#define included_nfqueue_live_poc_h

#include <vlib/vlib.h>

/* This is deliberately the only packet-obligation carrier in the probe.
 * It fits exactly in VPP's fixed opaque area; no side lease table exists.
 * The fixed rings below transport indices and completion identities only;
 * they do not own a second reference or lease for a packet. */
typedef struct
{
  u32 generation_lo;
  u32 generation_hi;
  u32 packet_id;
  u32 obligation_nonce;
  u32 datagram_length;
  u32 payload_offset;
  u32 payload_length;
  u32 original_length;
  u32 uid;
  u8 hook;
  u8 ip_version;
  u8 flags;
  u8 completion_refs;
} nfqueue_live_meta_t;

_Static_assert (sizeof (nfqueue_live_meta_t) == sizeof (((vlib_buffer_t *) 0)->opaque),
                "SAKAMOTO-73 metadata must fit VPP opaque inline");

typedef struct
{
  u32 buffer_index;
  u32 generation_lo;
  u32 generation_hi;
  u32 packet_id;
  u32 obligation_nonce;
  u32 verdict;
  u8 reference_held;
} nfqueue_live_completion_t;

typedef struct
{
  u32 head;
  u32 tail;
  u32 indices[128];
} nfqueue_live_index_ring_t;

typedef struct
{
  u32 head;
  u32 tail;
  nfqueue_live_completion_t entries[128];
} nfqueue_live_completion_ring_t;

typedef struct
{
  u8 enabled;
  u8 quiescing;
  u8 inject_stale;
  u8 inject_duplicate;
  u8 family;
  u8 origin_lane;
  u16 queue_num;
  u64 generation;
  u32 worker_thread;
  u32 frame_queue_index;
  u32 next_obligation_nonce;
  u32 netlink_file_index;
  u32 completion_file_index;
  int netlink_fd;
  int completion_fd;
  struct nfq_handle *handle;
  struct nfq_q_handle *queue;
  vlib_main_t *vm;
  void *active_datagram;
  nfqueue_live_index_ring_t ingress;
  nfqueue_live_completion_ring_t completion;
  u32 completion_push_lock;
  u32 outstanding;
  u32 last_buffer_index;
  uword last_buffer_base;
  u32 last_datagram_length;
  u32 last_payload_offset;
  u32 last_payload_length;
  u32 last_original_length;
  u32 last_captured_length;
  u32 last_worker_thread;
  u32 last_hook;
  u32 last_uid;
  u8 last_uid_known;
  u32 last_ip_version;
  u64 datagrams;
  u64 callbacks;
  u64 live_buffer_receives;
  u64 inline_metadata_writes;
  u64 payload_pointer_projections;
  u64 payload_span_checks;
  u64 payload_span_failures;
  u64 multiple_message_datagrams;
  u64 multiple_message_rejects;
  u64 missing_ingress_identity;
  u64 malformed_payloads;
  u64 cap_len_missing;
  u64 truncated_datagrams;
  u64 fail_open_settlements;
  u64 identity_unrecoverable;
  u64 ingress_alloc_failures;
  u64 ingress_overload;
  u64 handoff_count;
  u64 owner_mismatch_count;
  u64 owner_invalid_state;
  u64 completion_frames;
  u64 completion_stale;
  u64 completion_duplicate;
  u64 completion_ring_overflow;
  u64 completion_wake_writes;
  u64 completion_wake_errors;
  u64 verdict_attempts;
  u64 verdict_send_success;
  u64 verdict_send_failures;
  u64 completion_outcome_unknown;
  u64 native_buffer_returns;
  u32 last_verdict_errno;
} nfqueue_live_main_t;

extern nfqueue_live_main_t nfqueue_live_main;

#endif /* included_nfqueue_live_poc_h */
