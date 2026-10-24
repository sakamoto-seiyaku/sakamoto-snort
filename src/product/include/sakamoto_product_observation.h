/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_OBSERVATION_H
#define SAKAMOTO_PRODUCT_OBSERVATION_H
#include <stdint.h>
#include <stddef.h>
#include "sakamoto_product_limits.h"

#define PRODUCT_OBSERVATION_VERSION 8
/* Storage bound follows the pinned VPP worker limit; live channels are 2*N. */
#define PRODUCT_OBSERVATION_OWNERS SAKAMOTO_PRODUCT_MAX_FLOW_OWNERS
#define PRODUCT_OBSERVATION_CHANNELS (2 * PRODUCT_OBSERVATION_OWNERS)
#define PRODUCT_OBSERVATION_END 1
#define PRODUCT_OBSERVATION_CREATE 2
#define PRODUCT_OBSERVATION_CLOCK_CHANGED 4
#define PRODUCT_OBSERVATION_BLOCKED 8
#define PRODUCT_OBSERVATION_DNS 16
#define PRODUCT_OBSERVATION_END_IDLE 2 /* blocked END shares Flow EXPIRED value */
#define PRODUCT_OBSERVATION_MAX_RECORD 704
#define PRODUCT_DNS_PROXY_RECORD 1U
#define PRODUCT_DNS_PROXY_TRUNCATED 2U
#define PRODUCT_DNS_PROXY_UPSTREAM_ANSWER 4U
#define PRODUCT_DNS_PROXY_ADMISSION_RESOURCE 8U
enum {
  PRODUCT_DNS_DELIVERY_UNKNOWN, PRODUCT_DNS_DELIVERY_GRAPH_ACCEPTED,
  PRODUCT_DNS_DELIVERY_KERNEL_ACCEPTED, PRODUCT_DNS_DELIVERY_POLICY_DROP,
  PRODUCT_DNS_DELIVERY_WRITE_FAILED, PRODUCT_DNS_DELIVERY_ADMISSION_FAILED,
  PRODUCT_DNS_DELIVERY_RESOURCE_DROP, PRODUCT_DNS_DELIVERY_OUTCOME_UNKNOWN,
};

/* Direction-local provenance; no pointers, source conditions or packet bytes.
 * A segment starts at the counters immediately preceding its first packet. */
typedef struct {
  uint64_t segment, start_packets, start_bytes, activity_utc_us;
  uint64_t policy_generation, policy_revision, policy_hash, winner;
  uint32_t uid, network;
  uint8_t declared_action, actual_action, mode, valid;
  uint8_t name[64], padding[4];
  /* Stable catalog bits at the time this segment's packets were counted.
   * Availability distinguishes no published label from no recognition fact. */
  uint64_t protocol_set;
  uint8_t protocols_available, protocol_padding[7];
} product_observation_attribution_t;
_Static_assert (sizeof (product_observation_attribution_t) == 160, "attribution ABI");

/* Local little-endian x86-64/ARM64 wire ABI; no pointer or packet payload.
 * IPv4 omits the final 24 bytes and places its two addresses in address[0..8]. */
typedef struct {
  uint16_t length;
  uint8_t version, flags;
  uint16_t owner, reserved;
  uint32_t slot, uid;
  uint64_t generation, incarnation, sequence;
  uint64_t first_seen, last_seen;
  uint64_t packets[2], bytes[2];
  uint64_t policy_revision, winner;
  uint32_t network;
  uint16_t ports[2];
  uint8_t family, protocol, origin_direction, last_direction, flow_direction,
    end_reason, padding[2];
  uint64_t activity_utc_us;
  product_observation_attribution_t attribution[2];
  uint8_t address[32];
} product_observation_record_t;
_Static_assert (sizeof (product_observation_record_t) == 480, "observation record ABI");
_Static_assert (offsetof (product_observation_record_t, address) == 448, "record addresses");

/* DNS query decisions share the existing owner channel and storage budget.
 * The original-path policy intent is recorded before Adapter Completion;
 * delivery=0 explicitly means this record does not prove wire delivery. */
typedef struct {
  uint16_t length;
  uint8_t version, flags;
  uint16_t owner, reserved;
  uint64_t generation, token, incarnation, mono_us, activity_utc_us;
  uint64_t policy_generation, policy_revision, policy_hash, winner;
  uint32_t uid, network, ifindex, codec_peak_bytes, slot;
  uint16_t id, query_flags, qtype, qclass, source_port, resolver_port, name_length;
  uint8_t family, protocol, direction, availability, caller, coverage;
  uint8_t declared_action, actual_action, mode, domain_available, stage, delivery;
  uint8_t name_index, chain_status;
  uint8_t source_address[16], resolver_address[16], rule_name[64], name[256];
  uint64_t query_token, query_policy_generation, query_policy_revision, query_policy_hash;
  uint64_t query_winner, network_revision, transport_session, underlay_epoch, query_incarnation;
  uint16_t matched_requests, retransmits;
  uint8_t candidate_count, name_source, correlation, packet_availability;
  uint64_t domain_lists;
  uint16_t rcode;
  uint8_t adapter_profile, reserved_extension2;
  uint32_t packet_uid;
  /* Per-direction framed identity prevents coalesced messages sharing one
   * packet token from replacing each other in the normal history store.
   * Continuation uses retained real DNS facts on a later original packet. */
  uint64_t message_sequence;
  uint32_t tcp_sequence;
  uint8_t tcp_continuation, packet_direction, tcp_reserved[2];
  uint64_t route_revision, request_attempt, upstream_session;
  uint8_t upstream_address[16];
  uint16_t upstream_port;
  uint8_t upstream_family, upstream_transport, proxy_result, proxy_reserved;
  uint16_t reply_rcode, client_udp_capacity, reply_capacity;
  uint32_t output_bytes, proxy_flags, proxy_reserved2;
  uint64_t return_token;
  uint64_t return_policy_generation, return_policy_revision, return_policy_hash, return_winner;
  uint8_t return_declared_action, return_actual_action, return_mode, return_provenance;
  uint32_t return_packet_uid;
} product_dns_observation_record_t;
_Static_assert (sizeof (product_dns_observation_record_t) == 704, "DNS observation ABI");
_Static_assert (offsetof (product_dns_observation_record_t, name) == 224, "DNS name ABI");
_Static_assert (offsetof (product_dns_observation_record_t, return_token) == 656, "DNS return identity ABI");

typedef struct {
  uint64_t attempted, published, full, oversize, consumed, notify_errors;
  uint64_t allocation_lost;
  uint64_t pending, notifications;
  uint64_t basic_packets[3], basic_bytes[3]; /* ALLOW, policy DROP, runtime failure */
  uint32_t occupancy, capacity;
} product_observation_channel_status_t;
typedef struct {
  uint64_t generation, mapping_bytes;
  uint32_t version, owners, flow_capacity, connected;
  uint32_t blocked_capacity, blocked_active[PRODUCT_OBSERVATION_OWNERS];
  uint64_t blocked_capacity_misses[PRODUCT_OBSERVATION_OWNERS];
  uint64_t blocked_retired[PRODUCT_OBSERVATION_OWNERS];
  product_observation_channel_status_t channels[PRODUCT_OBSERVATION_CHANNELS];
} product_observation_status_t;

typedef struct product_observation_transport product_observation_transport_t;
/* Caller owns one producer per channel; lifecycle calls require all producers
 * quiesced. Consumers use a separate process-local handle on one thread. */
product_observation_transport_t *product_observation_transport_create (
  uint64_t generation, uint32_t flow_capacity);
product_observation_transport_t *product_observation_transport_create_for_owners (
  uint64_t generation, uint32_t flow_capacity, uint32_t owner_count);
void product_observation_transport_destroy (product_observation_transport_t *);
int product_observation_publish (product_observation_transport_t *, unsigned channel,
                                 const void *, uint32_t length);
void product_observation_account (product_observation_transport_t *, unsigned owner,
                                  unsigned outcome, uint32_t bytes);
void product_observation_allocation_lost (product_observation_transport_t *, unsigned channel);
void product_observation_transport_status (product_observation_transport_t *,
                                           product_observation_status_t *);
/* Nonblocking first-claim server handshake, with producers quiesced. Validates
 * application-created descriptors, preserves all queued records/counters while
 * adopting their mapping, and replies before the consumer may touch queues. */
int product_observation_offer (product_observation_transport_t *, int socket_fd);
void product_observation_connected (product_observation_transport_t *, int);

/* Consumer opens only a negotiated generation. It owns received descriptors
 * and mapping; close only after all consumer access has stopped. */
product_observation_transport_t *product_observation_connect (
  const char *socket_path, uint64_t generation);
product_observation_transport_t *product_observation_connect_for_owners (
  const char *socket_path, uint64_t generation, uint32_t owner_count);
int product_observation_receive (product_observation_transport_t *, unsigned channel,
                                 void *, uint32_t capacity);
int product_observation_wait (product_observation_transport_t *, int timeout_ms);
/* A duplicated local interrupt fd may cross to the service owner solely to
 * wake shutdown/pause. The mapping handle remains on the consumer thread. */
int product_observation_interrupt_fd (product_observation_transport_t *);
void product_observation_interrupt (int fd);
void product_observation_close_fd (int fd);
#endif
