/* SPDX-License-Identifier: Apache-2.0 */

#ifndef included_nfqueue_live_poc_h
#define included_nfqueue_live_poc_h

#include <vlib/vlib.h>

#define NFQUEUE_LIVE_MAX_LANES 4u
#define NFQUEUE_LIVE_MAX_WORKER_SLOTS 2u

struct nfq_handle;
struct nfq_q_handle;

typedef struct nfqueue_live_main_s nfqueue_live_main_t;

/* One native NFQUEUE I/O lane.  S75 uses four independent lanes (IPv4/IPv6
 * x INPUT/OUTPUT) in one runtime; S73/S74 continue to use one lane. */
typedef struct
{
  nfqueue_live_main_t *nm;
  u8 lane_index;
  u8 family;
  u8 hook;
  u8 enabled;
  u16 queue_num;
  u32 origin_lane;
  u64 generation;
  int netlink_fd;
  u32 netlink_file_index;
  struct nfq_handle *handle;
  struct nfq_q_handle *queue;
  u64 datagrams;
  u64 callbacks;
  u64 message_obligations;
  u64 verdict_attempts;
  u64 native_buffer_returns;
} nfqueue_live_lane_t;

typedef struct
{
  nfqueue_live_main_t *nm;
  u8 lane_index;
} nfqueue_live_reader_t;

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
  /* The accepted contiguous envelope is bounded by the patched 9000-byte
   * VPP data span, so these byte offsets/lengths fit without sacrificing the
   * full u32 original NFQA length below. */
  u16 datagram_length;
  u16 payload_offset;
  u16 payload_length;
  u16 captured_length;
  u32 original_length;
  u32 uid;
  u8 hook;
  u8 ip_version;
  u8 flags;
  u8 completion_refs;
  /* The low seven bits carry the origin lane.  S76 uses the high bit as the
   * bounded completion-credit marker so the complete identity still fits in
   * VPP's fixed opaque area. */
  u8 origin_lane;
  /* S76 keeps execution placement and canonical-owner identity in the same
   * fixed opaque metadata as the completion identity. */
  u8 initial_worker;
  u8 canonical_worker;
  u8 handoff_stage;
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
  u8 origin_lane;
  u32 verdict;
  u8 terminal;
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

/* Evidence is bounded and owned by the worker slot that records it.  The
 * lock protects every field so the origin CLI can take a coherent sample
 * while workers are still processing packets.  These fields never participate
 * in ownership or completion; packet proof uses the receiving buffer's inline
 * metadata/tag directly. */
typedef struct
{
  u32 lock;
  u8 before_valid;
  u8 after_valid;
  u16 reserved;
  u32 before_worker;
  u32 after_worker;
  u32 before_buffer_index;
  u32 after_buffer_index;
  uword before_buffer_base;
  uword after_buffer_base;
  u32 before_packet_id;
  u32 after_packet_id;
  u32 before_payload_offset;
  u32 after_payload_offset;
  u32 before_payload_length;
  u32 after_payload_length;
  u64 before_generation;
  u64 after_generation;
  u32 before_origin_lane;
  u32 after_origin_lane;
  u32 before_obligation_nonce;
  u32 after_obligation_nonce;
  u8 before_stage;
  u8 after_stage;
} nfqueue_live_handoff_sample_t;

struct nfqueue_live_main_s
{
  u8 enabled;
  u8 quiescing;
  u8 inject_stale;
  u8 inject_duplicate;
  u8 inject_completion_overflow;
  u8 family;
  u8 origin_lane;
  u16 queue_num;
  u64 generation;
  u32 worker_thread;
  u32 worker_count;
  u32 first_worker_thread;
  u32 second_worker_thread;
  u32 frame_queue_index;
  u32 next_obligation_nonce;
  u32 netlink_file_index;
  u32 completion_file_index;
  int netlink_fd;
  int completion_fd;
  struct nfq_handle *handle;
  struct nfq_q_handle *queue;
  nfqueue_live_lane_t lanes[NFQUEUE_LIVE_MAX_LANES];
  nfqueue_live_reader_t readers[NFQUEUE_LIVE_MAX_LANES];
  u8 lane_count;
  u8 dual_mode;
  u8 inject_missing_packet_id;
  u8 inject_missing_generation;
  u8 inject_uid_unknown;
  u8 inject_owner_queue_full;
  u8 inject_completion_credit_exhaustion;
  u8 owner_mode;
  vlib_main_t *vm;
  void *active_datagram;
  nfqueue_live_index_ring_t ingress;
  nfqueue_live_completion_ring_t completion;
  nfqueue_live_completion_ring_t origin_return;
  u32 completion_push_lock;
  u32 origin_return_push_lock;
  u32 outstanding;
  u32 last_buffer_index;
  uword last_buffer_base;
  u32 last_datagram_length;
  u32 last_payload_offset;
  u32 last_payload_length;
  u32 last_original_length;
  u32 last_captured_length;
  u32 last_packet_id;
  u64 last_queue_generation;
  u32 last_origin_lane;
  u8 last_device_direction;
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
  u64 envelope_message_count;
  u64 envelope_valid_message_count;
  u64 envelope_recoverable_message_count;
  u64 envelope_rejected_messages;
  u64 envelope_recovery_attempts;
  u64 envelope_recoveries;
  u64 envelope_malformed_rejects;
  u64 envelope_oversize_rejects;
  u64 envelope_boundary_passes;
  u64 envelope_exact_boundary_passes;
  u64 envelope_netlink_header_bytes;
  u64 envelope_attribute_bytes;
  u64 envelope_attribute_aligned_bytes;
  u64 envelope_payload_offset;
  u64 envelope_usable_l3_bytes;
  u64 envelope_parsed_bytes;
  u64 message_obligations;
  u64 message_rejections;
  u64 multiple_message_datagrams;
  u64 multiple_message_rejects;
  u64 missing_ingress_identity;
  u64 missing_packet_id;
  u64 missing_queue_generation;
  u64 uid_known_packets;
  u64 uid_unknown_fast_path;
  u64 uid_waits;
  u64 uid_cache_reads;
  u64 uid_replays;
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
  u64 origin_return_overflow;
  u64 completion_wake_writes;
  u64 completion_wake_errors;
  u64 verdict_attempts;
  u64 verdict_send_success;
  u64 verdict_send_failures;
  u64 completion_outcome_unknown;
  u64 native_buffer_returns;
  /* S76 independent worker/credit/residue ledgers. */
  u64 owner_local_obligations;
  u64 owner_remote_obligations;
  u64 owner_remote_handoffs;
  u64 owner_queue_full;
  u64 owner_terminal_intents;
  u64 ingress_queue_full;
  u64 completion_credit_acquired;
  u64 completion_credit_released;
  u64 completion_credit_exhausted;
  u32 completion_credits_held;
  u32 completion_credit_capacity;
  u64 identity_proof_checks;
  u64 identity_proof_matches;
  u64 identity_proof_failures;
  nfqueue_live_handoff_sample_t
    handoff_samples[NFQUEUE_LIVE_MAX_WORKER_SLOTS];
  u32 last_verdict_errno;
};

extern nfqueue_live_main_t nfqueue_live_main;

#endif /* included_nfqueue_live_poc_h */
