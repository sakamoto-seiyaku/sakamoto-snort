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
  if (h->pending_count < PRODUCT_HTTP_PENDING) h->pending[h->pending_count++] = *request;
  else h->overflow = 1;
  if (h->completed_in_packet < UINT16_MAX) ++h->completed_in_packet;
}

void product_flow_http_observe (product_flow_entry_t *entry, const product_packet_facts_t *facts,
  const uint8_t *payload, uint32_t length)
{
  if (entry->key.protocol != 6 || facts->protocol != 6 || entry->http_mode == PRODUCT_HTTP_NOT_HTTP) return;
  unsigned side = entry->last_flow_direction == PRODUCT_FLOW_DIRECTION_REPLY;
  if (entry->http_mode == PRODUCT_HTTP_UNDECIDED)
    {
      if (!length) return;
      if (payload[0] < 'A' || payload[0] > 'Z') { entry->http_mode = PRODUCT_HTTP_NOT_HTTP; return; }
      product_flow_sni_stop (entry, PRODUCT_SNI_UNSUPPORTED);   /* also clears the shared storage */
      memset (&entry->http, 0, sizeof (entry->http));
      product_http_target_init (&entry->http.parser);
      entry->http.side = (uint8_t) side;
      entry->http_mode = PRODUCT_HTTP_ACTIVE;
    }
  product_http_flow_t *h = &entry->http;
  h->pending_count = 0; h->overflow = 0; h->completed_in_packet = 0;
  if (!length || side != h->side || h->parser.stop) return;
  uint32_t sequence = facts->tcp_sequence + !!(facts->tcp_flags & 2);
  if (!h->seq_valid) { h->seq_valid = 1; h->next_sequence = sequence; }
  int32_t delta = (int32_t) (sequence - h->next_sequence);
  if (delta > 0) { product_http_target_lost (&h->parser); return; }   /* bytes were lost to us */
  if (delta < 0)
    {
      uint32_t overlap = (uint32_t) -delta;
      if (overlap >= length) return;                                  /* pure retransmission */
      payload += overlap; length -= overlap;
    }
  h->next_sequence += length;
  while (length)
    {
      size_t consumed = 0;
      product_http_request_t request;
      int result = product_http_target_feed (&h->parser, h->head, payload, length, &consumed, &request);
      if (result == PRODUCT_HTTP_FEED_REQUEST) remember (h, &request);
      payload += consumed; length -= (uint32_t) consumed;
      if (result == PRODUCT_HTTP_FEED_STOPPED || !consumed) break;
    }
}

product_flow_entry_status_t product_flow_http_deny (product_flow_runtime_t *pool, uint32_t slot,
  uint64_t generation, uint64_t incarnation, const product_http_request_t *target)
{
  if (!pool || !target) return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  product_flow_runtime_snapshot_t runtime = product_flow_runtime_snapshot (pool);
  if (runtime.generation != generation) return PRODUCT_FLOW_ENTRY_STATUS_WRONG_GENERATION;
  const product_flow_entry_t *borrowed = product_flow_runtime_entry (pool, slot);
  if (!borrowed || !borrowed->linked || borrowed->incarnation != incarnation
      || borrowed->http_mode != PRODUCT_HTTP_ACTIVE)
    return PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE;
  product_flow_entry_t *entry = (product_flow_entry_t *) borrowed;
  /* The latest refused target is what the rest of the connection is evaluated against. */
  entry->http.denied = *target; entry->http.has_denied = 1;
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
}
