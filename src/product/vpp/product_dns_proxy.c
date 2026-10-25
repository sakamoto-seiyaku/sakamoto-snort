/* SPDX-License-Identifier: Apache-2.0 */
#include "product_dns_proxy.h"
#include "product_cares.h"
#include "product_dns_route.h"
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

typedef struct {
  product_dns_proxy_event_t event;
  uint8_t *wire;
  size_t length;
  uint64_t deadline, retry_at;
  uint8_t retried, waiting_tcp;
} proxy_request_t;

struct product_dns_proxy {
  uint64_t generation, next_attempt;
  product_dns_proxy_route_t route;
  product_dns_proxy_callbacks_t callbacks;
  void *context;
  proxy_request_t requests[PRODUCT_DNS_PROXY_TRANSACTIONS];
  product_dns_proxy_resources_t resources;
  uint64_t other_bytes;
  uint64_t id_deadline[65536];
  uint16_t next_id;
};

product_dns_proxy_resources_t product_dns_proxy_resources (const product_dns_proxy_t *proxy)
{ return proxy ? proxy->resources : (product_dns_proxy_resources_t) {0}; }

void product_dns_proxy_other_bytes (product_dns_proxy_t *proxy, uint64_t bytes)
{ if (proxy) proxy->other_bytes = bytes; }

static void error_reply (product_dns_proxy_t *, product_dns_proxy_event_t *);

static proxy_request_t *find_request (product_dns_proxy_t *proxy, const product_dns_proxy_key_t *key)
{
  if (!proxy || !key) return NULL;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
    if (proxy->requests[i].wire && !memcmp (&proxy->requests[i].event.key, key, sizeof (*key)))
      return &proxy->requests[i];
  ++proxy->resources.stale;
  return NULL;
}

static void release_request (product_dns_proxy_t *proxy, proxy_request_t *request)
{
  product_dns_proxy_key_t key = request->event.key;
  uint8_t *wire = request->wire;
  proxy->resources.owned_bytes -= request->length;
  --proxy->resources.active; ++proxy->resources.completed;
  /* Retire identity before an Adapter callback can close a socket or cause
   * another ready event. No callback can complete this obligation twice. */
  memset (request, 0, sizeof (*request));
  if (proxy->callbacks.cancel) proxy->callbacks.cancel (proxy->context, &key);
  free (wire);
}

static void finish_failure (product_dns_proxy_t *proxy, proxy_request_t *request,
  uint64_t now, unsigned result, int reply)
{
  product_dns_proxy_event_t event = request->event;
  event.input.identity.now_us = now; event.stage = 3; event.result = result; event.rcode = 2;
  event.match = (product_l4_policy_match_result_t) {0}; event.policy = (product_dns_policy_identity_t) {0};
  release_request (proxy, request);
  if (result == PRODUCT_DNS_PROXY_CANCELLED || result == PRODUCT_DNS_PROXY_STOPPED)
    ++proxy->resources.cancelled;
  if (reply) error_reply (proxy, &event);
  else if (proxy->callbacks.observe) proxy->callbacks.observe (proxy->context, &event);
}

uint64_t product_dns_proxy_deadline (const product_dns_proxy_t *proxy)
{
  uint64_t next = UINT64_MAX;
  if (!proxy) return next;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
    {
      const proxy_request_t *request = &proxy->requests[i];
      if (!request->wire) continue;
      uint64_t due = request->event.transport == PRODUCT_DNS_PROXY_UDP && !request->retried
        ? request->retry_at : request->deadline;
      if (due < next) next = due;
    }
  return next;
}

void product_dns_proxy_cancel (product_dns_proxy_t *proxy, const product_dns_proxy_key_t *key, uint64_t now)
{
  proxy_request_t *request = find_request (proxy, key);
  if (request) finish_failure (proxy, request, now, PRODUCT_DNS_PROXY_CANCELLED, 0);
}

void product_dns_proxy_session_end (product_dns_proxy_t *proxy, uint64_t generation,
  uint64_t session, uint64_t now)
{
  if (!proxy || !session || generation != proxy->generation) return;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
    if (proxy->requests[i].wire && proxy->requests[i].event.input.identity.transport_session == session)
      finish_failure (proxy, &proxy->requests[i], now, PRODUCT_DNS_PROXY_CANCELLED, 0);
}

void product_dns_proxy_end (product_dns_proxy_t *proxy, uint64_t generation, uint64_t incarnation, uint64_t now)
{
  if (!proxy || !incarnation || generation != proxy->generation) return;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
    if (proxy->requests[i].wire && proxy->requests[i].event.key.incarnation == incarnation)
      finish_failure (proxy, &proxy->requests[i], now, PRODUCT_DNS_PROXY_CANCELLED, 0);
}

void product_dns_proxy_fail (product_dns_proxy_t *proxy, const product_dns_proxy_key_t *key, uint64_t now)
{
  proxy_request_t *request = find_request (proxy, key);
  if (request) finish_failure (proxy, request, now, PRODUCT_DNS_PROXY_SERVFAIL, 1);
}

void product_dns_proxy_advance (product_dns_proxy_t *proxy, uint64_t now, uint64_t network, uint64_t route)
{
  if (!proxy) return;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
    {
      proxy_request_t *request = &proxy->requests[i];
      if (!request->wire) continue;
      if (request->event.key.network_revision != network || request->event.key.route_revision != route)
        { finish_failure (proxy, request, now, PRODUCT_DNS_PROXY_VIEW_CHANGED, 1); continue; }
      if (request->deadline <= now)
        { finish_failure (proxy, request, now, PRODUCT_DNS_PROXY_SERVFAIL, 1); continue; }
      int send = 0;
      if (request->event.transport == PRODUCT_DNS_PROXY_UDP && !request->retried && request->retry_at <= now)
        { request->retried = 1; send = 1; }
      if (request->waiting_tcp) send = 1;
      if (send)
        {
          int result = proxy->callbacks.send (proxy->context, &request->event.key,
            request->event.transport, request->wire, request->length, request->deadline);
          request->waiting_tcp = request->event.transport == PRODUCT_DNS_PROXY_TCP && result == 0;
          if (result < 0 || (!result && request->event.transport == PRODUCT_DNS_PROXY_UDP))
            finish_failure (proxy, request, now, PRODUCT_DNS_PROXY_SERVFAIL, 1);
        }
    }
}

void product_dns_proxy_stop (product_dns_proxy_t *proxy, uint64_t now)
{
  if (!proxy) return;
  proxy->resources.accepting = 0;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
    if (proxy->requests[i].wire)
      finish_failure (proxy, &proxy->requests[i], now, PRODUCT_DNS_PROXY_STOPPED, 0);
}

product_dns_proxy_t *product_dns_proxy_open (uint64_t generation,
  const product_dns_proxy_route_t *route, const product_dns_proxy_callbacks_t *callbacks, void *context)
{
  if (!generation || !product_dns_route_valid (route) || !callbacks || !callbacks->reply || !callbacks->send) return NULL;
  product_dns_proxy_t *proxy = calloc (1, sizeof (*proxy));
  if (!proxy) return NULL;
  proxy->generation = generation; proxy->route = *route;
  proxy->callbacks = *callbacks; proxy->context = context;
  if (getrandom (&proxy->next_id, sizeof (proxy->next_id), GRND_NONBLOCK) != sizeof (proxy->next_id))
    { free (proxy); return NULL; }
  proxy->resources.accepting = !!route->enabled;
  proxy->resources.owned_bytes = proxy->resources.high_water_bytes = sizeof (*proxy);
  return proxy;
}

void product_dns_proxy_close (product_dns_proxy_t *proxy)
{
  if (!proxy) return;
  product_dns_proxy_stop (proxy, 0);
  free (proxy);
}

static void generated_reply (const product_dns_proxy_callbacks_t *callbacks, void *context,
  product_dns_proxy_event_t *event)
{
  if (event->result == PRODUCT_DNS_PROXY_NO_REPLY_IDENTITY)
    { if (callbacks->observe) callbacks->observe (context, event); return; }
  event->delivery = 2; /* an attempted local response, until graph acceptance */
  if (product_cares_memory_begin (PRODUCT_DNS_CODEC_BYTES))
    { if (callbacks->observe) callbacks->observe (context, event); return; }
  ares_dns_record_t *record = NULL;
  unsigned char *answer = NULL;
  size_t length = 0;
  uint8_t encoded[PRODUCT_DNS_PROXY_REPLY_BYTES];
  ares_status_t status = ares_dns_record_create (&record, event->query.id,
    ARES_FLAG_QR | ARES_FLAG_RA | (event->truncated ? ARES_FLAG_TC : 0)
      | ((event->query.flags & 0x0100) ? ARES_FLAG_RD : 0)
      | ((event->query.flags & 0x0010) ? ARES_FLAG_CD : 0),
    ARES_OPCODE_QUERY, event->rcode);
  if (status == ARES_SUCCESS && event->query.name_length)
    status = ares_dns_record_query_add (record,
      strcmp (event->query.name, ".") ? event->query.name : "",
      event->query.qtype, event->query.qclass);
  if (status == ARES_SUCCESS && event->query.edns_present)
    {
      ares_dns_rr_t *opt = NULL;
      status = ares_dns_record_rr_add (&opt, record, ARES_SECTION_ADDITIONAL, "", ARES_REC_TYPE_OPT, ARES_CLASS_IN, 0);
      if (status == ARES_SUCCESS)
        status = ares_dns_rr_set_u16 (opt, ARES_RR_OPT_UDP_SIZE, event->client_capacity);
      if (status == ARES_SUCCESS)
        status = ares_dns_rr_set_u16 (opt, ARES_RR_OPT_FLAGS, event->query.edns_flags & 0x8000);
    }
  if (status == ARES_SUCCESS) status = ares_dns_write (record, &answer, &length);
  if (status == ARES_SUCCESS)
    {
      /* The narrow codec deliberately rejects unknown opcodes. NOTIMP must
       * nevertheless echo all four original opcode bits in its DNS header. */
      answer[2] = (answer[2] & ~0x78U) | ((event->query.flags >> 8) & 0x78U);
      if (length > sizeof (encoded)) status = ARES_ENOMEM;
      else memcpy (encoded, answer, length);
    }
  ares_free_string (answer); ares_dns_record_destroy (record);
  size_t unreleased = 0; (void) product_cares_memory_end (&unreleased);
  if (status == ARES_SUCCESS && !unreleased)
    {
      event->output_bytes = length;
      event->delivery = callbacks->reply (context, event, encoded, length) ? 1 : 2;
    }
  if (callbacks->observe) callbacks->observe (context, event);
}
static void error_reply (product_dns_proxy_t *proxy, product_dns_proxy_event_t *event)
{ generated_reply (&proxy->callbacks, proxy->context, event); }

static int reserve_id (product_dns_proxy_t *proxy, uint64_t now, uint16_t *id)
{
  if (now > UINT64_MAX - PRODUCT_DNS_PROXY_ATTEMPT_US - PRODUCT_DNS_REQUEST_US) return 0;
  for (unsigned i = 0; i < 65536; ++i)
    {
      uint16_t candidate = proxy->next_id++;
      if (proxy->id_deadline[candidate] > now) continue;
      /* A completed/cancelled ID remains unavailable for the entire bounded
       * request window after its original attempt deadline. Reuse never
       * aliases an active request, even after the 16-bit counter wraps. */
      proxy->id_deadline[candidate] = now + PRODUCT_DNS_PROXY_ATTEMPT_US + PRODUCT_DNS_REQUEST_US;
      *id = candidate; return 1;
    }
  return 0;
}

void product_dns_proxy_answer (product_dns_proxy_t *proxy, const product_dns_proxy_key_t *key,
  unsigned transport, const uint8_t *wire, size_t length, uint64_t now_us)
{
  proxy_request_t *request = find_request (proxy, key);
  if (!request || !wire || !proxy->callbacks.acquire) return;
  if (request->deadline <= now_us)
    { finish_failure (proxy, request, now_us, PRODUCT_DNS_PROXY_SERVFAIL, 1); return; }
  if (length < 12 || length > PRODUCT_DNS_MESSAGE_MAX)
    { finish_failure (proxy, request, now_us, PRODUCT_DNS_PROXY_SERVFAIL, 1); return; }
    {
      if (transport != request->event.transport) return;
      product_dns_proxy_snapshot_t snapshot = {0};
      if (!proxy->callbacks.acquire (proxy->context, &request->event.input, &snapshot))
        { finish_failure (proxy, request, now_us, PRODUCT_DNS_PROXY_SERVFAIL, 1); return; }
      if (snapshot.network_revision != key->network_revision || snapshot.route_revision != key->route_revision ||
          snapshot.identity.generation != key->generation)
        {
          if (proxy->callbacks.release) proxy->callbacks.release (proxy->context, &snapshot);
          finish_failure (proxy, request, now_us, PRODUCT_DNS_PROXY_VIEW_CHANGED, 1); return;
        }
      product_dns_query_t expected = request->event.query;
      expected.id = ((uint16_t) request->wire[0] << 8) | request->wire[1];
      product_dns_response_t response;
      product_dns_inspect_answer (wire, length, &snapshot.context, &expected, &response);
      if (transport == PRODUCT_DNS_PROXY_UDP && response.correlation == PRODUCT_DNS_CORRELATED &&
          response.question.coverage == PRODUCT_DNS_COPY_GAP && (response.question.flags & 0x0200))
        {
          request->event.transport = PRODUCT_DNS_PROXY_TCP;
          int sent = proxy->callbacks.send (proxy->context, key, PRODUCT_DNS_PROXY_TCP,
            request->wire, request->length, request->deadline);
          request->waiting_tcp = sent == 0;
          if (proxy->callbacks.release) proxy->callbacks.release (proxy->context, &snapshot);
          if (sent < 0) finish_failure (proxy, request, now_us, PRODUCT_DNS_PROXY_SERVFAIL, 1);
          return;
        }
      if (response.correlation == PRODUCT_DNS_CORRELATED &&
          response.question.coverage == PRODUCT_DNS_QUERY_COMPLETE)
        {
          product_dns_proxy_event_t event = request->event;
          event.input.identity.now_us = now_us; event.stage = 2;
          event.policy = snapshot.identity; event.result = PRODUCT_DNS_PROXY_UPSTREAM;
          event.rcode = response.rcode; event.response = &response; event.transport = transport;
          if (!product_dns_response_match (snapshot.view, &snapshot.context.packet, &response,
                PRODUCT_L4_POLICY_POSITION_ALL, &event.match))
            {
              event.policy.winner = event.match.rule_id;
              if (event.match.actual_action == PRODUCT_L4_POLICY_ACTION_DROP)
                {
                  event.result = PRODUCT_DNS_PROXY_REFUSED; event.rcode = 5;
                  release_request (proxy, request);
                  error_reply (proxy, &event);
                }
              else if (length > event.client_capacity)
                {
                  event.truncated = 1;
                  release_request (proxy, request);
                  error_reply (proxy, &event);
                }
              else
                {
                  uint8_t *answer = malloc (length);
                  if (answer)
                    {
                      memcpy (answer, wire, length);
                      answer[0] = event.query.id >> 8; answer[1] = event.query.id;
                      event.output_bytes = length;
                      release_request (proxy, request);
                      event.delivery = proxy->callbacks.reply (proxy->context, &event, answer, length) ? 1 : 2;
                      if (proxy->callbacks.observe) proxy->callbacks.observe (proxy->context, &event);
                      free (answer);
                    }
                  else
                    {
                      release_request (proxy, request);
                      event.result = PRODUCT_DNS_PROXY_CAPACITY; event.rcode = 2; event.stage = 3;
                      ++proxy->resources.capacity;
                      error_reply (proxy, &event);
                    }
                }
            }
        }
      if (proxy->callbacks.release) proxy->callbacks.release (proxy->context, &snapshot);
      return;
    }
}

static int prepare_request (const product_dns_proxy_input_t *input, const uint8_t *wire, size_t length,
  const product_dns_proxy_snapshot_t *snapshot, const product_dns_proxy_route_t *route,
  uint64_t attempt, product_dns_proxy_event_t *out)
{
  product_dns_proxy_event_t event = {
    .input = *input, .route = *route, .query_policy = snapshot->identity,
    .policy = snapshot->identity, .client_capacity = 512, .stage = 1,
    .transport = PRODUCT_DNS_PROXY_UDP,
    .key = {.generation = input->identity.generation, .token = input->token,
      .incarnation = input->identity.incarnation, .attempt = attempt,
      .network_revision = input->identity.network_revision, .route_revision = input->route_revision},
  };
  event.input.context.domains = NULL;
  product_dns_inspect_query (wire, length, &snapshot->context, &event.query);
  event.client_capacity = event.query.udp_capacity < PRODUCT_DNS_PROXY_REPLY_BYTES
    ? event.query.udp_capacity : PRODUCT_DNS_PROXY_REPLY_BYTES;
  if (event.client_capacity < 512) event.client_capacity = 512;
  if (wire && length >= 4 && (event.query.flags & 0x8000)) return 0;
  if (!wire || length < 2)
    {
      event.result = PRODUCT_DNS_PROXY_NO_REPLY_IDENTITY;
      *out = event; return 1;
    }
  event.query.id = ((uint16_t) wire[0] << 8) | wire[1];
  if (length >= 4) event.query.flags = ((uint16_t) wire[2] << 8) | wire[3];
  if (event.query.coverage == PRODUCT_DNS_CAPACITY)
    {
      event.stage = 3; event.result = PRODUCT_DNS_PROXY_CAPACITY; event.rcode = 2;
      *out = event; return 1;
    }
  if ((event.query.flags & 0x7800) || event.query.coverage != PRODUCT_DNS_QUERY_COMPLETE)
    {
      event.result = (event.query.flags & 0x7800) ? PRODUCT_DNS_PROXY_NOTIMP : PRODUCT_DNS_PROXY_FORMERR;
      event.rcode = event.result == PRODUCT_DNS_PROXY_NOTIMP ? 4 : 1;
      *out = event; return 1;
    }
  if (product_l4_policy_match (snapshot->view, &event.query.packet, &event.match))
    { event.stage = 3; event.result = PRODUCT_DNS_PROXY_SERVFAIL; event.rcode = 2; *out = event; return 1; }
  event.policy.winner = event.query_policy.winner = event.match.rule_id;
  if (event.match.actual_action == PRODUCT_L4_POLICY_ACTION_DROP)
    { event.result = PRODUCT_DNS_PROXY_REFUSED; event.rcode = 5; *out = event; return 1; }
  *out = event; return 2;
}

int product_dns_proxy_unavailable (const product_dns_proxy_input_t *input, const uint8_t *wire, size_t length,
  const product_dns_proxy_snapshot_t *snapshot, const product_dns_proxy_route_t *route,
  const product_dns_proxy_callbacks_t *callbacks, void *context, product_dns_proxy_result_t result)
{
  if (!input || !snapshot || !snapshot->view || !route || !callbacks || !callbacks->reply) return 0;
  product_dns_proxy_event_t event;
  int prepared = prepare_request (input, wire, length, snapshot, route, input->token, &event);
  if (!prepared) return 0;
  if (prepared == 2)
    {
      if (callbacks->observe) callbacks->observe (context, &event);
      event.stage = 3; event.result = result; event.rcode = 2;
      event.match = (product_l4_policy_match_result_t) {0}; event.policy = (product_dns_policy_identity_t) {0};
    }
  generated_reply (callbacks, context, &event); return 1;
}

int product_dns_proxy_submit (product_dns_proxy_t *proxy, const product_dns_proxy_input_t *input,
  const uint8_t *wire, size_t length, const product_dns_proxy_snapshot_t *snapshot)
{
  if (!proxy || !input || !snapshot || !snapshot->view || !proxy->resources.accepting || !proxy->route.enabled ||
      !input->token || input->identity.generation != proxy->generation) return 0;
  if (proxy->next_attempt == UINT64_MAX)
    return product_dns_proxy_unavailable (input, wire, length, snapshot, &proxy->route,
      &proxy->callbacks, proxy->context, PRODUCT_DNS_PROXY_CAPACITY);
  product_dns_proxy_event_t event;
  int prepared = prepare_request (input, wire, length, snapshot, &proxy->route, ++proxy->next_attempt, &event);
  if (!prepared) return 0;
  if (prepared == 1)
    {
      if (event.result == PRODUCT_DNS_PROXY_CAPACITY) ++proxy->resources.capacity;
      error_reply (proxy, &event); return 1;
    }
    {
      if (proxy->callbacks.observe) proxy->callbacks.observe (proxy->context, &event);
      const uint64_t scratch = PRODUCT_DNS_CODEC_BYTES + 2U * PRODUCT_DNS_MESSAGE_MAX +
        sizeof (product_dns_response_t) + 2U * sizeof (product_dns_proxy_event_t);
      if (proxy->other_bytes > PRODUCT_DNS_WORK_BYTES - scratch ||
          proxy->resources.owned_bytes > PRODUCT_DNS_WORK_BYTES - scratch - proxy->other_bytes ||
          length > PRODUCT_DNS_WORK_BYTES - scratch - proxy->other_bytes - proxy->resources.owned_bytes)
        goto capacity;
      for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
        if (!proxy->requests[i].wire)
          {
            proxy_request_t *request = &proxy->requests[i];
            uint16_t upstream_id;
            if (!reserve_id (proxy, input->identity.now_us, &upstream_id)) goto capacity;
            uint8_t *copy = malloc (length);
            if (!copy) goto capacity;
            memcpy (copy, wire, length);
            copy[0] = upstream_id >> 8; copy[1] = upstream_id;
            request->event = event; request->wire = copy; request->length = length;
            request->deadline = input->identity.now_us + PRODUCT_DNS_PROXY_ATTEMPT_US;
            request->retry_at = input->identity.now_us + PRODUCT_DNS_PROXY_RETRY_US;
            ++proxy->resources.active; proxy->resources.owned_bytes += length;
            if (proxy->resources.active > proxy->resources.high_water)
              proxy->resources.high_water = proxy->resources.active;
            if (proxy->resources.owned_bytes > proxy->resources.high_water_bytes)
              proxy->resources.high_water_bytes = proxy->resources.owned_bytes;
            int sent = proxy->callbacks.send (proxy->context, &event.key,
              PRODUCT_DNS_PROXY_UDP, copy, length, request->deadline);
            if (sent != 1) finish_failure (proxy, request, input->identity.now_us, PRODUCT_DNS_PROXY_SERVFAIL, 1);
            return 1;
          }
capacity:
      ++proxy->resources.capacity;
      event.stage = 3; event.result = PRODUCT_DNS_PROXY_CAPACITY; event.rcode = 2;
      error_reply (proxy, &event);
      return 1;
    }
}
