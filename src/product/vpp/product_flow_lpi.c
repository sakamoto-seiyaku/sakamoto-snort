/* SPDX-License-Identifier: Apache-2.0 */
#include "product_flow_entry.h"
#include "product_protocol_catalog.h"
#include "../../../third_party/libprotoident/adapter.h"
#include <string.h>

int product_lpi_init (void) { return sakamoto_lpi_init (); }

/* RFC 9000 16/17.2.2, RFC 9369 3.2. Header recognition only: authentication
 * and CRYPTO/SNI assembly belong to the later QUIC producer. Never use ports
 * alone or promote a malformed/truncated version probe to a protocol fact. */
static int quic_varint (const uint8_t *p, uint32_t n, uint32_t *at, uint64_t *value)
{
  if (*at >= n) return 0;
  unsigned bytes = 1U << (p[*at] >> 6);
  if (bytes > n - *at) return 0;
  uint64_t v = p[(*at)++] & 63;
  for (unsigned i = 1; i < bytes; ++i) v = (v << 8) | p[(*at)++];
  *value = v;
  return 1;
}
static int quic_initial (const uint8_t *p, uint32_t n)
{
  if (n < 1200 || (p[0] & 0xc0) != 0xc0) return 0;
  uint32_t version = (uint32_t)p[1]<<24 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<8 | p[4];
  unsigned type = (p[0] >> 4) & 3;
  if (!((version == 1 && type == 0) || (version == UINT32_C(0x6b3343cf) && type == 1))) return 0;
  uint32_t at = 5;
  for (unsigned i = 0; i < 2; ++i) {
    if (at >= n) return 0;
    unsigned length = p[at++];
    if (length > 20 || length > n - at) return 0;
    at += length;
  }
  uint64_t token, length;
  if (!quic_varint (p,n,&at,&token) || token > n-at) return 0;
  at += (uint32_t)token;
  if (!quic_varint (p,n,&at,&length) || length < 20 || length > n-at) return 0;
  return 1;
}

product_flow_entry_status_t product_flow_entry_identify (
  product_flow_runtime_t *pool, uint32_t slot, uint64_t generation,
  uint64_t incarnation, const product_packet_facts_t *facts,
  const uint8_t *payload, uint32_t length)
{
  if (!pool || !facts || (length && !payload)) return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  product_flow_runtime_snapshot_t runtime = product_flow_runtime_snapshot (pool);
  if (runtime.generation != generation) return PRODUCT_FLOW_ENTRY_STATUS_WRONG_GENERATION;
  const product_flow_entry_t *borrowed = product_flow_runtime_entry (pool,slot);
  if (!borrowed || !borrowed->linked || borrowed->incarnation != incarnation)
    return PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE;
  /* Entry is allocated mutable storage; the public query is const to prevent
   * accidental mutation. Only this identity-validated owner operation writes. */
  product_flow_entry_t *entry = (product_flow_entry_t *) borrowed;
  product_lpi_state_t *state = &entry->lpi;
  if (entry->key.protocol != 6 && entry->key.protocol != 17) {
    state->stop_reason = PRODUCT_LPI_STOP_UNSUPPORTED;
    return PRODUCT_FLOW_ENTRY_STATUS_OK;
  }
  unsigned source_is_a = entry->last_flow_direction == PRODUCT_FLOW_DIRECTION_ORIG
    ? entry->origin_is_endpoint_a : !entry->origin_is_endpoint_a;
  const uint8_t *source = source_is_a ? entry->key.address_a : entry->key.address_b;
  const uint8_t *destination = source_is_a ? entry->key.address_b : entry->key.address_a;
  if (facts->protocol != entry->key.protocol || facts->ip_family != entry->key.ip_family
      || facts->l4_status != PRODUCT_PACKET_L4_COMPLETE
      || facts->transport_length < facts->l4_header_length
      || length != (uint32_t)facts->transport_length - facts->l4_header_length
      || memcmp (facts->source_address, source, 16)
      || memcmp (facts->destination_address, destination, 16)
      || facts->source_port != (source_is_a ? entry->key.transport.ports.a : entry->key.transport.ports.b)
      || facts->destination_port != (source_is_a ? entry->key.transport.ports.b : entry->key.transport.ports.a))
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_PACKET;
  if (state->stop_reason || !length) return PRODUCT_FLOW_ENTRY_STATUS_OK;
  if (length > PRODUCT_LPI_MAX_BYTES - state->bytes) {
    state->stop_reason = PRODUCT_LPI_STOP_BYTE_BUDGET;
    return PRODUCT_FLOW_ENTRY_STATUS_OK;
  }
  unsigned side = entry->last_flow_direction == PRODUCT_FLOW_DIRECTION_REPLY;
  if (!state->attempts) {
    state->client_port = side ? facts->destination_port : facts->source_port;
    state->server_port = side ? facts->source_port : facts->destination_port;
    if (facts->ip_family == 4) {
      memcpy (&state->ips[side],facts->source_address,4);
      memcpy (&state->ips[!side],facts->destination_address,4);
    }
  }
  state->payload[side] = 0;
  memcpy (&state->payload[side],payload,length < 4 ? length : 4);
  state->lengths[side] = length;
  state->observed[side] += length;
  state->bytes += length;
  ++state->attempts;
  const char *alias = sakamoto_lpi_guess (state->payload,state->lengths,state->observed,
    state->ips,state->client_port,state->server_port,facts->protocol);
  uint64_t result = product_protocol_bit (product_protocol_provider_id (alias));
  if (facts->protocol == 17 && quic_initial(payload,length))
    result |= product_protocol_bit (1004);
  state->last_outcome = result ? PRODUCT_LPI_MAPPED : alias ? PRODUCT_LPI_UNMAPPED : PRODUCT_LPI_MISS;
  state->protocols |= result;
  state->available = state->protocols != 0;
  if (state->attempts == PRODUCT_LPI_MAX_ATTEMPTS)
    state->stop_reason = PRODUCT_LPI_STOP_PACKET_BUDGET;
  else if (state->bytes == PRODUCT_LPI_MAX_BYTES)
    state->stop_reason = PRODUCT_LPI_STOP_BYTE_BUDGET;
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
}
