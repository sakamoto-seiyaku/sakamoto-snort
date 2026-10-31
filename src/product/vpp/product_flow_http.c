/* SPDX-License-Identifier: Apache-2.0 */
#include "product_flow_entry.h"
#include <string.h>

/* Cleartext HTTP/1.x request targets of one TCP flow. Runs on the owner thread
 * immediately after SNI recognition saw the same packet. A flow whose first
 * payload byte is an upper-case letter is an HTTP candidate: TLS cannot start
 * that way, so SNI is stopped and its reserved storage is handed over. Any
 * other first byte leaves the flow alone for good. */
_Static_assert (sizeof (product_http_flow_t) <= sizeof (product_tcp_byte_cache_t),
  "HTTP state shares the TCP-owned reserved storage without growing the Flow");

static void remember (product_http_flow_t *h, const product_http_request_t *request)
{
  h->current = *request; h->has_current = 1;
  h->pending[h->pending_count++] = *request;   /* callers stop feeding before the batch is full */
  if (h->completed_in_packet < UINT16_MAX) ++h->completed_in_packet;
}

/* A stop other than entering a tunnel leaves later requests without a known target. */
static void stopped (product_http_flow_t *h, unsigned stop, unsigned tunnel)
{ if (stop && stop != tunnel) h->unavailable = 1; }

/* In-order bytes of one direction: 1 with payload and length trimmed to the new bytes,
 * 0 for a pure retransmission, -1 when bytes were lost to us. The caller advances
 * *next by what it actually consumed. */
static int in_order (uint32_t *next, uint8_t *valid, uint32_t sequence, const uint8_t **payload, uint32_t *length)
{
  if (!*valid) { *valid = 1; *next = sequence; }
  int32_t delta = (int32_t) (sequence - *next);
  if (delta > 0) return -1;
  if (delta < 0)
    {
      uint32_t overlap = (uint32_t) -delta;
      if (overlap >= *length) return 0;
      *payload += overlap; *length -= overlap;
    }
  return 1;
}

void product_flow_http_observe (product_flow_entry_t *entry, const product_packet_facts_t *facts,
  const uint8_t *payload, uint32_t length)
{
  if (entry->key.protocol != 6 || facts->protocol != 6 || entry->http_mode == PRODUCT_HTTP_NOT_HTTP) return;
  unsigned side = entry->last_flow_direction == PRODUCT_FLOW_DIRECTION_REPLY;
  if (entry->http_mode == PRODUCT_HTTP_UNDECIDED)
    {
      /* Only the connection's first client bytes decide. TLS starts with 0x16, so neither an upper-case
       * HTTP method nor a SOCKS version byte can be a ClientHello. */
      if (!length || side) return;
      unsigned first = payload[0];
      unsigned mode = first >= 'A' && first <= 'Z' ? PRODUCT_HTTP_ACTIVE
                    : first == 4 || first == 5 ? PRODUCT_HTTP_SOCKS : PRODUCT_HTTP_NOT_HTTP;
      if (mode == PRODUCT_HTTP_NOT_HTTP) { entry->http_mode = PRODUCT_HTTP_NOT_HTTP; return; }
      product_flow_sni_stop (entry, PRODUCT_SNI_UNSUPPORTED);   /* also clears the shared storage */
      memset (&entry->http, 0, sizeof (entry->http));
      if (mode == PRODUCT_HTTP_ACTIVE) product_http_target_init (&entry->http.parser);
      else product_socks_target_init (&entry->http.socks, first);
      entry->http.side = (uint8_t) side;
      entry->http_mode = (uint8_t) mode;
    }
  product_http_flow_t *h = &entry->http;
  h->pending_count = 0; h->overflow = 0; h->completed_in_packet = 0; h->more = 0;
  if (!length) return;
  uint32_t sequence = facts->tcp_sequence + !!(facts->tcp_flags & 2);
  if (entry->http_mode == PRODUCT_HTTP_SOCKS)
    {
      product_http_request_t request;
      int result;
      if (side != h->side)
        {
          int order = in_order (&h->server_next_sequence, &h->server_seq_valid, sequence, &payload, &length);
          if (order < 0) { product_socks_target_lost (&h->socks); stopped (h, h->socks.stop, PRODUCT_SOCKS_STOP_TUNNEL); return; }
          if (!order) return;
          h->server_next_sequence += length;
          result = product_socks_target_server (&h->socks, payload, length, &request);
        }
      else
        {
          int order = in_order (&h->next_sequence, &h->seq_valid, sequence, &payload, &length);
          if (order < 0) { product_socks_target_lost (&h->socks); stopped (h, h->socks.stop, PRODUCT_SOCKS_STOP_TUNNEL); return; }
          if (!order || h->socks.stop) return;
          h->next_sequence += length;
          size_t consumed;
          result = product_socks_target_client (&h->socks, payload, length, &consumed, &request);
        }
      if (result == PRODUCT_HTTP_FEED_REQUEST) remember (h, &request);
      stopped (h, h->socks.stop, PRODUCT_SOCKS_STOP_TUNNEL);
      return;
    }
  if (side != h->side || h->parser.stop) return;
  int order = in_order (&h->next_sequence, &h->seq_valid, sequence, &payload, &length);
  if (order < 0) { product_http_target_lost (&h->parser); stopped (h, h->parser.stop, PRODUCT_HTTP_STOP_TUNNEL); return; }
  if (!order) return;
  /* Only consumed bytes advance the stream. A full batch leaves the rest of this packet
   * for product_flow_http_resume, or for its retransmission if the packet is refused. */
  while (length)
    {
      if (h->pending_count == PRODUCT_HTTP_PENDING) { h->more = 1; h->overflow = 1; break; }
      size_t consumed = 0;
      product_http_request_t request;
      int result = product_http_target_feed (&h->parser, h->head, payload, length, &consumed, &request);
      if (result == PRODUCT_HTTP_FEED_REQUEST) remember (h, &request);
      if (result == PRODUCT_HTTP_FEED_STOPPED) consumed = length;   /* nothing after a stop is parsed */
      h->next_sequence += (uint32_t) consumed;
      payload += consumed; length -= (uint32_t) consumed;
      if (result == PRODUCT_HTTP_FEED_STOPPED || !consumed) break;
    }
  stopped (h, h->parser.stop, PRODUCT_HTTP_STOP_TUNNEL);
}

product_flow_entry_status_t product_flow_http_resume (product_flow_runtime_t *pool, uint32_t slot,
  uint64_t generation, uint64_t incarnation, const product_packet_facts_t *facts,
  const uint8_t *payload, uint32_t length, int give_up)
{
  if (!pool || !facts || (length && !payload)) return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  product_flow_runtime_snapshot_t runtime = product_flow_runtime_snapshot (pool);
  if (runtime.generation != generation) return PRODUCT_FLOW_ENTRY_STATUS_WRONG_GENERATION;
  const product_flow_entry_t *borrowed = product_flow_runtime_entry (pool, slot);
  if (!borrowed || !borrowed->linked || borrowed->incarnation != incarnation
      || borrowed->http_mode != PRODUCT_HTTP_ACTIVE || !borrowed->http.more)
    return PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE;
  product_flow_entry_t *entry = (product_flow_entry_t *) borrowed;
  if (give_up)
    {
      product_http_target_lost (&entry->http.parser);
      entry->http.parser.stop = PRODUCT_HTTP_STOP_HEAD_LIMIT;
      entry->http.unavailable = 1; entry->http.more = 0; entry->http.pending_count = 0;
      return PRODUCT_FLOW_ENTRY_STATUS_OK;
    }
  /* The same packet: in-order trimming skips what the previous batch consumed. */
  product_flow_http_observe (entry, facts, payload, length);
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
}

product_flow_entry_status_t product_flow_http_deny (product_flow_runtime_t *pool, uint32_t slot,
  uint64_t generation, uint64_t incarnation, const product_http_request_t *target)
{
  if (!pool || !target) return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  product_flow_runtime_snapshot_t runtime = product_flow_runtime_snapshot (pool);
  if (runtime.generation != generation) return PRODUCT_FLOW_ENTRY_STATUS_WRONG_GENERATION;
  const product_flow_entry_t *borrowed = product_flow_runtime_entry (pool, slot);
  if (!borrowed || !borrowed->linked || borrowed->incarnation != incarnation
      || !product_flow_direct_target (borrowed))
    return PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE;
  product_flow_entry_t *entry = (product_flow_entry_t *) borrowed;
  /* The latest refused target is what the rest of the connection is evaluated against. */
  entry->http.denied = *target; entry->http.has_denied = 1;
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
}
