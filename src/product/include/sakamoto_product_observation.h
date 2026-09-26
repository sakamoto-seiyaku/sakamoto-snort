/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_OBSERVATION_H
#define SAKAMOTO_PRODUCT_OBSERVATION_H
#include <stdint.h>
#include <stddef.h>

#define PRODUCT_OBSERVATION_VERSION 1
#define PRODUCT_OBSERVATION_OWNERS 2
#define PRODUCT_OBSERVATION_CHANNELS 4
#define PRODUCT_OBSERVATION_END 1
#define PRODUCT_OBSERVATION_CREATE 2
#define PRODUCT_OBSERVATION_MAX_RECORD 152

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
  uint8_t address[32];
} product_observation_record_t;
_Static_assert (sizeof (product_observation_record_t) == 152, "observation record ABI");
_Static_assert (offsetof (product_observation_record_t, address) == 120, "record addresses");

typedef struct {
  uint64_t attempted, published, full, oversize, consumed, notify_errors;
  uint64_t pending, notifications;
  uint64_t basic_packets[3], basic_bytes[3]; /* ALLOW, policy DROP, runtime failure */
  uint32_t occupancy, capacity;
} product_observation_channel_status_t;
typedef struct {
  uint64_t generation, mapping_bytes;
  uint32_t version, owners, flow_capacity, connected;
  product_observation_channel_status_t channels[PRODUCT_OBSERVATION_CHANNELS];
} product_observation_status_t;

typedef struct product_observation_transport product_observation_transport_t;
/* Caller owns one producer per channel; lifecycle calls require all producers
 * quiesced. Consumers use a separate process-local handle on one thread. */
product_observation_transport_t *product_observation_transport_create (
  uint64_t generation, uint32_t flow_capacity);
void product_observation_transport_destroy (product_observation_transport_t *);
int product_observation_publish (product_observation_transport_t *, unsigned channel,
                                 const void *, uint32_t length);
void product_observation_account (product_observation_transport_t *, unsigned owner,
                                  unsigned outcome, uint32_t bytes);
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
int product_observation_receive (product_observation_transport_t *, unsigned channel,
                                 product_observation_record_t *);
int product_observation_wait (product_observation_transport_t *, int timeout_ms);
/* A duplicated local interrupt fd may cross to the service owner solely to
 * wake shutdown/pause. The mapping handle remains on the consumer thread. */
int product_observation_interrupt_fd (product_observation_transport_t *);
void product_observation_interrupt (int fd);
void product_observation_close_fd (int fd);
#endif
