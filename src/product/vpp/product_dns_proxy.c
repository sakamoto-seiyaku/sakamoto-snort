/* SPDX-License-Identifier: Apache-2.0 */
#include "product_dns_proxy.h"
#include "product_cares.h"
#include "product_dns_route.h"
#include "product_dns_assoc.h"
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include "product_dns_cache.inc"

typedef struct {
  product_dns_proxy_key_t key;
  uint8_t *wire;
  size_t length;
  uint64_t deadline, total_deadline, retry_at, underlay_epoch;
  uint32_t network_context_id;
  uint16_t resolver_port;
  uint8_t resolver_address[16], family, profile, network_context_known;
  uint32_t waiters;
  uint32_t resolution_route, position, resolver_id;
  sakamoto_product_dns_endpoint_t endpoint;
  dns_cache_view_t view;
  product_dns_proxy_io_event_t io;
  uint8_t transport, retried, waiting_tcp, stored, answering, probe, retirement_owed, attempt_started;
} proxy_exchange_t;
typedef struct {
  product_dns_proxy_event_t event;
  proxy_exchange_t *exchange;
  uint64_t deadline;
} proxy_request_t;

struct product_dns_proxy {
  uint64_t generation, next_attempt, network_revision, route_revision;
  uint8_t view_known;
  product_dns_proxy_route_t route;
  product_dns_proxy_callbacks_t callbacks;
  void *context;
  proxy_request_t requests[PRODUCT_DNS_PROXY_WAITERS];
  proxy_exchange_t exchanges[PRODUCT_DNS_PROXY_TRANSACTIONS];
  product_dns_proxy_resources_t resources;
  dns_cache_t cache;
  product_dns_assoc_t *assoc; /* domain-IP facts; owner-local, never shared */
  uint64_t other_bytes;
  uint64_t id_deadline[65536];
  uint16_t next_id;
};

product_dns_proxy_resources_t product_dns_proxy_resources (const product_dns_proxy_t *proxy)
{
  if (!proxy) return (product_dns_proxy_resources_t) {0};
  product_dns_proxy_resources_t result = proxy->resources;
  result.cache_bytes = sizeof (proxy->cache) + proxy->cache.bytes;
  result.cache_high_water_bytes = sizeof (proxy->cache) + proxy->cache.high_water_bytes;
  result.cache_entries = proxy->cache.count; result.cache_high_water = proxy->cache.high_water;
  result.cache_hits = proxy->cache.hits; result.cache_misses = proxy->cache.misses;
  result.cache_evictions = proxy->cache.evictions; result.cache_skipped = proxy->cache.skipped;
  result.assoc = product_dns_assoc_stats (proxy->assoc);
  result.assoc_bytes = proxy->assoc ? product_dns_assoc_bytes () : 0;
  return result;
}

void product_dns_proxy_other_bytes (product_dns_proxy_t *proxy, uint64_t bytes)
{ if (proxy) proxy->other_bytes = bytes; }

static void error_reply (product_dns_proxy_t *, product_dns_proxy_event_t *);
static void next_candidate (product_dns_proxy_t *, proxy_exchange_t *, uint64_t, int);
static int reserve_id (product_dns_proxy_t *, uint64_t, uint16_t *);

static sakamoto_product_dns_endpoint_t legacy_endpoint (const product_dns_proxy_route_t *config)
{
  sakamoto_product_dns_endpoint_t endpoint = {.transport = PRODUCT_DNS_PROXY_UDP,
    .family = config->family, .port = config->port};
  memcpy (endpoint.address, config->address, 16);
  return endpoint;
}

static int local_resolver (const product_l4_policy_packet_t *packet)
{
  const uint8_t *a = packet->destination_address;
  if (packet->family == 4)
    return a[0] == 10 || a[0] == 127 || (a[0] == 172 && a[1] >= 16 && a[1] <= 31) ||
      (a[0] == 192 && a[1] == 168) || (a[0] == 169 && a[1] == 254);
  if (packet->family == 6)
    return (a[0] & 0xfe) == 0xfc || (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) ||
      !memcmp (a, (uint8_t[16]) {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}, 16);
  return 0;
}

/* Match whole labels against the actual query. Escaped/binary names cannot
 * accidentally become configured dotted names. Exact beats every suffix. */
static uint32_t resolution_route (const product_dns_proxy_route_t *config,
  const product_dns_proxy_input_t *input, const product_dns_query_t *query)
{
  const sakamoto_product_dns_exception_t *selected = NULL;
  size_t length = strlen (query->name);
  for (unsigned i = 0; i < config->exception_count; ++i)
    {
      const sakamoto_product_dns_exception_t *e = &config->exceptions[i];
      if (length < e->length || (!e->match && length != e->length) ||
          (length > e->length && query->name[length - e->length - 1] != '.')) continue;
      if (length > e->length)
        {
          size_t boundary = length - e->length - 1, escapes = 0;
          while (boundary && query->name[--boundary] == '\\') ++escapes;
          if (escapes & 1U) continue;
        }
      int equal = 1;
      for (unsigned j = 0; j < e->length; ++j)
        {
          unsigned c = (uint8_t) query->name[length - e->length + j];
          if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
          if (c != e->name[j]) { equal = 0; break; }
        }
      if (equal && (!selected || e->match < selected->match ||
            (e->match == selected->match && e->length > selected->length))) selected = e;
    }
  if (selected) return selected->target ? selected->route : UINT32_MAX;
  /* Preserve explicitly addressed local resolvers; this says nothing about
   * undiscovered internal names or a network's search-domain list. */
  return local_resolver (&input->context.packet) ? UINT32_MAX : 0;
}

static sakamoto_product_dns_endpoint_t first_endpoint (const product_dns_proxy_route_t *config,
  const product_dns_proxy_input_t *input, uint32_t route, uint32_t *resolver_id)
{
  *resolver_id = 0;
  if (route == UINT32_MAX)
    {
      sakamoto_product_dns_endpoint_t endpoint = {.transport = PRODUCT_DNS_PROXY_UDP,
        .family = input->context.packet.family, .port = input->context.packet.destination_port};
      memcpy (endpoint.address, input->context.packet.destination_address, 16);
      return endpoint;
    }
  if (!config->endpoint_count) return legacy_endpoint (config);
  unsigned index = config->routes[route].candidates[0];
  *resolver_id = index + 1;
  return config->endpoints[index];
}

static dns_cache_view_t cache_view (const proxy_exchange_t *exchange)
{
  dns_cache_view_t view = {.network = exchange->key.network_revision, .route = exchange->key.route_revision,
    .underlay = exchange->underlay_epoch, .resolution_route = exchange->resolution_route,
    .resolver_id = exchange->resolver_id, .family = exchange->endpoint.family, .port = exchange->endpoint.port,
    .profile = exchange->profile, .network_context_known = exchange->network_context_known,
    .network_context = exchange->network_context_id};
  memcpy (view.address, exchange->endpoint.address, 16);
  return view;
}

static void select_endpoint (product_dns_proxy_t *proxy, proxy_exchange_t *exchange, unsigned position)
{
  exchange->io = (product_dns_proxy_io_event_t){0};
  exchange->position = position;
  if (exchange->resolution_route != UINT32_MAX && proxy->route.endpoint_count)
    {
      unsigned index = proxy->route.routes[exchange->resolution_route].candidates[position];
      exchange->endpoint = proxy->route.endpoints[index]; exchange->resolver_id = index + 1;
    }
  exchange->transport = exchange->endpoint.transport;
  exchange->view = cache_view (exchange);
  exchange->key.resolver_id = exchange->resolver_id;
  exchange->key.resolution_route = exchange->resolution_route;
  exchange->key.resolver_family = exchange->endpoint.family;
  exchange->key.resolver_port = exchange->endpoint.port;
  memcpy (exchange->key.resolver_address, exchange->endpoint.address, 16);
}

static void event_endpoint (product_dns_proxy_event_t *event, const proxy_exchange_t *exchange)
{
  event->route = exchange->endpoint; event->resolution_route = exchange->resolution_route;
  event->transport = exchange->transport;
  event->io = exchange->io;
  event->resolver_id = exchange->resolver_id;
  event->upstream_attempt = !event->cached && exchange->attempt_started &&
    (exchange->resolver_id || exchange->resolution_route == UINT32_MAX) ? exchange->key.attempt : 0;
}

static int observe_attempt (product_dns_proxy_t *proxy, proxy_exchange_t *exchange, uint64_t now, unsigned result)
{
  if (!proxy->route.endpoint_count || !proxy->callbacks.observe) return 1;
  product_dns_proxy_key_t key = exchange->key;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_WAITERS; ++i)
    if (proxy->requests[i].exchange == exchange && !memcmp (&exchange->key, &key, sizeof (key)))
      {
        product_dns_proxy_event_t event = proxy->requests[i].event;
        event.cached = 0; event_endpoint (&event, exchange);
        event.stage = 5; event.result = result; event.transport = exchange->transport;
        event.input.identity.now_us = now; event.rcode = 0; event.delivery = event.truncated = 0;
        event.output_bytes = 0; event.response = NULL;
        event.match = (product_l4_policy_match_result_t) {0}; event.policy = (product_dns_policy_identity_t) {0};
        proxy->callbacks.observe (proxy->context, &event);
      }
  return exchange->wire && !memcmp (&exchange->key, &key, sizeof (key));
}

static proxy_request_t *find_request (product_dns_proxy_t *proxy, const product_dns_proxy_key_t *key)
{
  if (!proxy || !key) return NULL;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_WAITERS; ++i)
    if (proxy->requests[i].exchange)
      {
        const product_dns_proxy_key_t *owned = &proxy->requests[i].event.key;
        if (owned->generation == key->generation && owned->token == key->token &&
            owned->incarnation == key->incarnation && owned->attempt == key->attempt &&
            owned->network_revision == key->network_revision && owned->route_revision == key->route_revision)
          return &proxy->requests[i];
      }
  ++proxy->resources.stale;
  return NULL;
}

static proxy_exchange_t *find_exchange (product_dns_proxy_t *proxy, const product_dns_proxy_key_t *key)
{
  if (!proxy || !key) return NULL;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
    if (proxy->exchanges[i].wire && !memcmp (&proxy->exchanges[i].key, key, sizeof (*key)))
      return &proxy->exchanges[i];
  ++proxy->resources.stale;
  return NULL;
}

static void retire_attempt (product_dns_proxy_t *proxy, proxy_exchange_t *exchange)
{
  if (!exchange->retirement_owed) return;
  exchange->retirement_owed = 0;
  if (proxy->callbacks.cancel) proxy->callbacks.cancel (proxy->context, &exchange->key);
}

static void release_request (product_dns_proxy_t *proxy, proxy_request_t *request)
{
  proxy_exchange_t *exchange = request->exchange;
  --proxy->resources.active; ++proxy->resources.completed;
  /* Retire this delivery before callbacks; the exchange remains owned until
   * its last independent waiter settles, even if its first caller cancels. */
  memset (request, 0, sizeof (*request));
  if (--exchange->waiters) return;
  if (exchange->probe && exchange->resolver_id)
    proxy->resources.health[exchange->resolver_id - 1].probing = 0;
  retire_attempt (proxy, exchange);
  uint8_t *wire = exchange->wire;
  proxy->resources.owned_bytes -= exchange->length;
  memset (exchange, 0, sizeof (*exchange));
  --proxy->resources.exchanges;
  free (wire);
}

static void finish_failure (product_dns_proxy_t *proxy, proxy_request_t *request,
  uint64_t now, unsigned result, int reply)
{
  product_dns_proxy_event_t event = request->event;
  event_endpoint (&event, request->exchange);
  event.transport = request->exchange->transport;
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
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_WAITERS; ++i)
    if (proxy->requests[i].exchange && proxy->requests[i].deadline < next)
      next = proxy->requests[i].deadline;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
    {
      const proxy_exchange_t *exchange = &proxy->exchanges[i];
      if (!exchange->wire) continue;
      uint64_t due = exchange->transport == PRODUCT_DNS_PROXY_UDP && !exchange->retried
        ? exchange->retry_at : exchange->deadline;
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
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_WAITERS; ++i)
    if (proxy->requests[i].exchange && proxy->requests[i].event.input.identity.transport_session == session)
      finish_failure (proxy, &proxy->requests[i], now, PRODUCT_DNS_PROXY_CANCELLED, 0);
}

void product_dns_proxy_end (product_dns_proxy_t *proxy, uint64_t generation, uint64_t incarnation, uint64_t now)
{
  if (!proxy || !incarnation || generation != proxy->generation) return;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_WAITERS; ++i)
    if (proxy->requests[i].exchange && proxy->requests[i].event.key.incarnation == incarnation)
      finish_failure (proxy, &proxy->requests[i], now, PRODUCT_DNS_PROXY_CANCELLED, 0);
}

static void fail_exchange (product_dns_proxy_t *proxy, proxy_exchange_t *exchange,
  uint64_t now, unsigned result)
{
  product_dns_proxy_key_t key = exchange->key;
  exchange->answering = 1;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_WAITERS; ++i)
    if (proxy->requests[i].exchange == exchange &&
        !memcmp (&exchange->key, &key, sizeof (key)))
      finish_failure (proxy, &proxy->requests[i], now, result, 1);
}

static int choose_candidate (product_dns_proxy_t *proxy, proxy_exchange_t *exchange,
  unsigned start, uint64_t now, dns_cache_entry_t **cached)
{
  unsigned count = exchange->resolution_route == UINT32_MAX || !proxy->route.endpoint_count
    ? 1 : proxy->route.routes[exchange->resolution_route].count;
  *cached = NULL;
  for (unsigned position = start; position < count; ++position)
    {
      proxy_exchange_t candidate = *exchange;
      select_endpoint (proxy, &candidate, position);
      *cached = cache_lookup (&proxy->cache, candidate.wire, candidate.length, now, &candidate.view);
      if (*cached) { *exchange = candidate; return 1; }
      if (candidate.resolver_id)
        {
          const product_dns_proxy_health_t *health = &proxy->resources.health[candidate.resolver_id - 1];
          if (health->cooldown_until > now || health->probing) continue;
        }
      *exchange = candidate; return 1;
    }
  return 0;
}

static int cached_exchange (product_dns_proxy_t *proxy, proxy_exchange_t *exchange,
  dns_cache_entry_t *cached, uint64_t now)
{
  size_t length = cached->answer_length;
  uint8_t *answer = malloc (length);
  if (!answer) { fail_exchange (proxy, exchange, now, PRODUCT_DNS_PROXY_CAPACITY); return 1; }
  memcpy (answer, cached->data + cached->query_length, length);
  uint64_t age = now - cached->inserted;
  uint32_t elapsed = age / UINT64_C(1000000) + !!(age % UINT64_C(1000000)), lifetime;
  int valid = cache_answer_ttls (answer, length, elapsed, NULL, answer, &lifetime);
  if (valid)
    {
      answer[0] = exchange->wire[0]; answer[1] = exchange->wire[1];
      exchange->transport = cached->transport;
      if(cached->transport==PRODUCT_DNS_PROXY_DOT||cached->transport==PRODUCT_DNS_PROXY_DOH)
        exchange->io=(product_dns_proxy_io_event_t){.tls=PRODUCT_DNS_TLS_CACHED_DATA};
      for (unsigned i = 0; i < PRODUCT_DNS_PROXY_WAITERS; ++i)
        if (proxy->requests[i].exchange == exchange) proxy->requests[i].event.cached = 1;
      product_dns_proxy_key_t key = exchange->key;
      product_dns_proxy_answer (proxy, &key, cached->transport, answer, length, now);
      free (answer);
      if (!exchange->wire || memcmp (&exchange->key, &key, sizeof (key))) return 1;
    }
  else free (answer);
  cache_drop (&proxy->cache, cached, 0);
  --proxy->cache.hits; ++proxy->cache.misses;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_WAITERS; ++i)
    if (proxy->requests[i].exchange == exchange) proxy->requests[i].event.cached = 0;
  exchange->transport = exchange->endpoint.transport;
  exchange->io = (product_dns_proxy_io_event_t){0};
  return 0;
}

static void send_candidate (product_dns_proxy_t *proxy, proxy_exchange_t *exchange, uint64_t now)
{
  if (exchange->resolver_id)
    {
      const product_dns_proxy_health_t *health = &proxy->resources.health[exchange->resolver_id - 1];
      if (health->cooldown_until > now || (health->probing && !exchange->probe))
        { next_candidate (proxy, exchange, now, 0); return; }
    }
  if (exchange->resolver_id && proxy->resources.health[exchange->resolver_id - 1].failures)
    {
      proxy->resources.health[exchange->resolver_id - 1].probing = 1;
      exchange->probe = 1;
    }
  exchange->retirement_owed = 1;
  if (!exchange->attempt_started)
    {
      exchange->attempt_started = 1;
      if (!observe_attempt (proxy, exchange, now, PRODUCT_DNS_PROXY_ATTEMPT)) return;
    }
  int result = proxy->callbacks.send (proxy->context, &exchange->key, exchange->transport,
    exchange->wire, exchange->length, exchange->deadline);
  exchange->waiting_tcp = exchange->transport != PRODUCT_DNS_PROXY_UDP && result == 0;
  if (result < 0) next_candidate (proxy, exchange, now, PRODUCT_DNS_PROXY_ATTEMPT_FAILED);
  else if (!result && exchange->transport == PRODUCT_DNS_PROXY_UDP)
    { ++proxy->resources.capacity; fail_exchange (proxy, exchange, now, PRODUCT_DNS_PROXY_CAPACITY); }
}

static void next_candidate (product_dns_proxy_t *proxy, proxy_exchange_t *exchange, uint64_t now, int fault)
{
  if (fault)
    {
      ++proxy->resources.failed_attempts;
      if (exchange->resolver_id)
        {
          product_dns_proxy_health_t *health = &proxy->resources.health[exchange->resolver_id - 1];
          if (health->failures < 4) ++health->failures;
          uint64_t cooldown = health->failures < 4 ? UINT64_C(5000000) << (health->failures - 1) : UINT64_C(30000000);
          health->cooldown_until = now > UINT64_MAX - cooldown ? UINT64_MAX : now + cooldown;
          health->probing = 0;
        }
      if (!observe_attempt (proxy, exchange, now, fault)) return;
    }
  if (exchange->probe && exchange->resolver_id)
    proxy->resources.health[exchange->resolver_id - 1].probing = 0;
  exchange->probe = 0; exchange->answering = 0;
  retire_attempt (proxy, exchange);
  dns_cache_entry_t *cached;
  if (now >= exchange->total_deadline || proxy->next_attempt == UINT64_MAX ||
      !choose_candidate (proxy, exchange, exchange->position + 1, now, &cached))
    { fail_exchange (proxy, exchange, now, PRODUCT_DNS_PROXY_SERVFAIL); return; }
  uint16_t id;
  if (!reserve_id (proxy, now, &id))
    { ++proxy->resources.capacity; fail_exchange (proxy, exchange, now, PRODUCT_DNS_PROXY_CAPACITY); return; }
  exchange->key.attempt = ++proxy->next_attempt;
  exchange->retirement_owed = 1;
  exchange->attempt_started = 0;
  exchange->wire[0] = id >> 8; exchange->wire[1] = id;
  exchange->deadline = exchange->total_deadline - now < PRODUCT_DNS_PROXY_ATTEMPT_US
    ? exchange->total_deadline : now + PRODUCT_DNS_PROXY_ATTEMPT_US;
  exchange->retry_at = now + PRODUCT_DNS_PROXY_RETRY_US;
  exchange->retried = exchange->waiting_tcp = exchange->stored = 0;
  ++proxy->resources.failovers;
  if (cached && cached_exchange (proxy, exchange, cached, now)) return;
  send_candidate (proxy, exchange, now);
}

void product_dns_proxy_fail (product_dns_proxy_t *proxy, const product_dns_proxy_key_t *key, uint64_t now)
{
  proxy_exchange_t *exchange = find_exchange (proxy, key);
  if (exchange) next_candidate (proxy, exchange, now, PRODUCT_DNS_PROXY_ATTEMPT_FAILED);
}

void product_dns_proxy_io_event(product_dns_proxy_t *proxy,const product_dns_proxy_key_t *key,
  const product_dns_proxy_io_event_t *event)
{
  proxy_exchange_t *exchange=find_exchange(proxy,key);
  if(!exchange||!event||(exchange->transport!=PRODUCT_DNS_PROXY_DOT&&exchange->transport!=PRODUCT_DNS_PROXY_DOH)||
     event->tls>PRODUCT_DNS_TLS_FAILED||
     event->bootstrap>PRODUCT_DNS_BOOTSTRAP_FAILED||event->authorization>PRODUCT_DNS_AUTHORIZATION_FAILED||
     event->trust_source<1||event->trust_source>2)return;
  if(event->connection_family){
    if(!product_dns_address_valid(event->connection_family,event->connection_port,event->connection_address)||
       event->connection_port!=exchange->key.resolver_port)return;
  }else if(event->connection_port||memcmp(event->connection_address,(uint8_t[16]){0},16))return;
  if(event->bootstrap_family){
    int address=product_dns_address_valid(event->bootstrap_family,event->bootstrap_port,event->bootstrap_address);
    if(event->bootstrap_family==6&&event->bootstrap_address[0]==0xfe&&
       (event->bootstrap_address[1]&0xc0)==0x80)address=1;
    if(!address||event->bootstrap_port!=53||!event->bootstrap_ifindex)return;
  }else if(event->bootstrap_port||event->bootstrap_ifindex||
    memcmp(event->bootstrap_address,(uint8_t[16]){0},16))return;
  if((event->bootstrap==PRODUCT_DNS_BOOTSTRAP_NONE&&event->bootstrap_family)||
     ((event->bootstrap==PRODUCT_DNS_BOOTSTRAP_PENDING||event->bootstrap==PRODUCT_DNS_BOOTSTRAP_RESOLVED)&&
       !event->bootstrap_family))return;
  if(event->tls==PRODUCT_DNS_TLS_AUTHENTICATED&&
     (!event->connection_family||event->authorization!=PRODUCT_DNS_AUTHORIZATION_GRANTED||event->error))return;
  if(exchange->transport==PRODUCT_DNS_PROXY_DOH){
    if(event->http_status>599||event->alpn>PRODUCT_DNS_ALPN_REFUSED||event->http_error>PRODUCT_DNS_HTTP_ERROR_ALPN)return;
  }else if(event->http_status||event->http_age||event->http_error||event->alpn)return;
  exchange->io=*event;
}

void product_dns_proxy_advance (product_dns_proxy_t *proxy, uint64_t now, uint64_t network, uint64_t route)
{
  if (!proxy) return;
  if (proxy->view_known && (proxy->network_revision != network || proxy->route_revision != route))
    memset (proxy->resources.health, 0, sizeof (proxy->resources.health));
  proxy->network_revision = network; proxy->route_revision = route; proxy->view_known = 1;
  cache_prune (&proxy->cache, now, network, route);
  product_dns_assoc_advance (proxy->assoc, now, network, route);
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_WAITERS; ++i)
    {
      proxy_request_t *request = &proxy->requests[i];
      if (!request->exchange) continue;
      if (request->event.key.network_revision != network || request->event.key.route_revision != route)
        { finish_failure (proxy, request, now, PRODUCT_DNS_PROXY_VIEW_CHANGED, 1); continue; }
    }
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
    {
      proxy_exchange_t *exchange = &proxy->exchanges[i];
      if (!exchange->wire) continue;
      if (exchange->deadline <= now)
        { next_candidate (proxy, exchange, now, PRODUCT_DNS_PROXY_ATTEMPT_TIMEOUT); continue; }
      int send = 0;
      if (exchange->transport == PRODUCT_DNS_PROXY_UDP && !exchange->retried && exchange->retry_at <= now)
        { exchange->retried = 1; send = 1; }
      if (exchange->waiting_tcp) send = 1;
      if (send)
        {
          send_candidate (proxy, exchange, now);
        }
    }
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_WAITERS; ++i)
    if (proxy->requests[i].exchange && proxy->requests[i].deadline <= now)
      finish_failure (proxy, &proxy->requests[i], now, PRODUCT_DNS_PROXY_SERVFAIL, 1);
}

void product_dns_proxy_stop (product_dns_proxy_t *proxy, uint64_t now)
{
  if (!proxy) return;
  proxy->resources.accepting = 0;
  cache_clear (&proxy->cache);
  product_dns_assoc_clear (proxy->assoc);
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_WAITERS; ++i)
    if (proxy->requests[i].exchange)
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
  proxy->assoc = product_dns_assoc_open ();
  if (!proxy->assoc) { free (proxy); return NULL; }
  proxy->resources.accepting = !!route->enabled;
  proxy->resources.owned_bytes = proxy->resources.high_water_bytes =
    sizeof (*proxy) - sizeof (proxy->cache) + product_dns_assoc_bytes ();
  return proxy;
}

void product_dns_proxy_close (product_dns_proxy_t *proxy)
{
  if (!proxy) return;
  product_dns_proxy_stop (proxy, 0);
  product_dns_assoc_close (proxy->assoc);
  free (proxy);
}

static void generated_reply (const product_dns_proxy_callbacks_t *callbacks, void *context,
  product_dns_proxy_event_t *event)
{
  event->output_bytes = 0;
  if (event->result == PRODUCT_DNS_PROXY_NO_REPLY_IDENTITY)
    {
      if (callbacks->abandon) callbacks->abandon (context, event);
      if (callbacks->observe) callbacks->observe (context, event);
      return;
    }
  event->delivery = 2; /* an attempted local response, until graph acceptance */
  if (product_cares_memory_begin (PRODUCT_DNS_CODEC_BYTES))
    {
      if (callbacks->abandon) callbacks->abandon (context, event);
      if (callbacks->observe) callbacks->observe (context, event);
      return;
    }
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
      event->delivery = callbacks->reply (context, event, encoded, length) == PRODUCT_DNS_REPLY_ACCEPTED ? 1 : 2;
    }
  if (event->delivery != 1 && callbacks->abandon) callbacks->abandon (context, event);
  if (callbacks->observe) callbacks->observe (context, event);
}
static void error_reply (product_dns_proxy_t *proxy, product_dns_proxy_event_t *event)
{ generated_reply (&proxy->callbacks, proxy->context, event); }

static int reserve_id (product_dns_proxy_t *proxy, uint64_t now, uint16_t *id)
{
  uint64_t lifetime = proxy->route.endpoint_count ? 2U * PRODUCT_DNS_REQUEST_US
    : PRODUCT_DNS_PROXY_ATTEMPT_US + PRODUCT_DNS_REQUEST_US;
  if (now > UINT64_MAX - lifetime) return 0;
  for (unsigned i = 0; i < 65536; ++i)
    {
      uint16_t candidate = proxy->next_id++;
      if (proxy->id_deadline[candidate] > now) continue;
      /* A completed/cancelled ID remains unavailable for the entire bounded
       * request window after its original attempt deadline. Reuse never
       * aliases an active request, even after the 16-bit counter wraps. */
      proxy->id_deadline[candidate] = now + lifetime;
      *id = candidate; return 1;
    }
  return 0;
}

static void answer_waiter (product_dns_proxy_t *proxy, proxy_request_t *request,
  unsigned transport, const uint8_t *wire, size_t length, uint64_t now_us,
  const uint8_t *aged, uint32_t age_seconds)
{
  if (!request || !proxy->callbacks.acquire) return;
  const product_dns_proxy_key_t *key = &request->event.key;
  if (request->deadline <= now_us)
    { finish_failure (proxy, request, now_us, PRODUCT_DNS_PROXY_SERVFAIL, 1); return; }
  if (!wire || length < 12 || length > PRODUCT_DNS_MESSAGE_MAX)
    { next_candidate (proxy, request->exchange, now_us, PRODUCT_DNS_PROXY_ATTEMPT_INVALID); return; }
    {
      if (transport != request->exchange->transport) return;
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
      expected.id = ((uint16_t) request->exchange->wire[0] << 8) | request->exchange->wire[1];
      product_dns_response_t response;
      product_dns_inspect_answer (wire, length, &snapshot.context, &expected, &response);
      if (transport == PRODUCT_DNS_PROXY_UDP && response.correlation == PRODUCT_DNS_CORRELATED &&
          response.question.coverage == PRODUCT_DNS_COPY_GAP && (response.question.flags & 0x0200))
        {
          request->exchange->transport = PRODUCT_DNS_PROXY_TCP;
          if (proxy->callbacks.release) proxy->callbacks.release (proxy->context, &snapshot);
          send_candidate (proxy, request->exchange, now_us);
          return;
        }
      if (response.correlation == PRODUCT_DNS_CORRELATED &&
          response.question.coverage == PRODUCT_DNS_QUERY_COMPLETE)
        {
          product_dns_proxy_event_t event = request->event;
          event_endpoint (&event, request->exchange);
          event.input.identity.now_us = now_us; event.stage = 2;
          event.policy = snapshot.identity;
          event.result = event.cached ? PRODUCT_DNS_PROXY_CACHE : PRODUCT_DNS_PROXY_UPSTREAM;
          if (!event.cached && request->exchange->resolver_id)
            {
              proxy->resources.health[request->exchange->resolver_id - 1] = (product_dns_proxy_health_t) {0};
              request->exchange->probe = 0;
            }
          if (!event.cached && !request->exchange->stored)
            {
              request->exchange->stored = 1;
              cache_store (&proxy->cache, request->exchange->wire, request->exchange->length, wire, length,
                transport, now_us, &request->exchange->view, &response, age_seconds);
            }
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
                      memcpy (answer, aged ? aged : wire, length);
                      answer[0] = event.query.id >> 8; answer[1] = event.query.id;
                      event.output_bytes = length;
                      uint64_t underlay = request->exchange->view.underlay;
                      release_request (proxy, request);
                      int queued = proxy->callbacks.reply (proxy->context, &event, answer, length);
                      if (queued == PRODUCT_DNS_REPLY_CAPACITY && event.input.context.packet.protocol == 6)
                        {
                          event.stage = 3; event.result = PRODUCT_DNS_PROXY_CAPACITY; event.rcode = 2;
                          ++proxy->resources.capacity;
                          error_reply (proxy, &event);
                        }
                      else
                        {
                          event.delivery = queued == PRODUCT_DNS_REPLY_ACCEPTED ? 1 : 2;
                          /* Policy allowed this complete answer. Admission records the
                           * output result as its own evidence, never as App receipt. It reads
                           * the proxy's own copy: the caller's receive buffer may already be
                           * reused once the reply callback has run. */
                          product_dns_assoc_source_t source = {.generation = proxy->generation,
                            .network_revision = event.key.network_revision, .route_revision = event.key.route_revision,
                            .underlay_epoch = underlay, .token = event.input.token,
                            .resolver_id = event.resolver_id, .resolution_route = event.resolution_route,
                            .qtype = event.query.qtype, .rcode = response.rcode, .caller = event.query.caller,
                            .transport = (uint8_t) transport, .cached = event.cached, .delivery = event.delivery};
                          product_dns_assoc_admit (proxy->assoc, answer, length, &response, &source, now_us, &event.assoc);
                          if (event.delivery != 1 && proxy->callbacks.abandon)
                            proxy->callbacks.abandon (proxy->context, &event);
                          if (proxy->callbacks.observe) proxy->callbacks.observe (proxy->context, &event);
                        }
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
      else
        {
          if (proxy->callbacks.release) proxy->callbacks.release (proxy->context, &snapshot);
          /* Retained data can fail the mature codec after its lightweight
           * TTL walk. cached_exchange drops it and starts this candidate's
           * real request; it is not a resolver failure or a terminal reply. */
          if (!request->event.cached)
            next_candidate (proxy, request->exchange, now_us, PRODUCT_DNS_PROXY_ATTEMPT_INVALID);
          return;
        }
      if (proxy->callbacks.release) proxy->callbacks.release (proxy->context, &snapshot);
      return;
    }
}

void product_dns_proxy_answer (product_dns_proxy_t *proxy, const product_dns_proxy_key_t *key,
  unsigned transport, const uint8_t *wire, size_t length, uint64_t now_us)
{
  proxy_exchange_t *exchange = find_exchange (proxy, key);
  if (!exchange || exchange->answering) return;
  int encrypted=exchange->transport==PRODUCT_DNS_PROXY_DOT||exchange->transport==PRODUCT_DNS_PROXY_DOH;
  if(encrypted&&exchange->io.tls!=PRODUCT_DNS_TLS_AUTHENTICATED&&
     exchange->io.tls!=PRODUCT_DNS_TLS_CACHED_DATA){
    next_candidate(proxy,exchange,now_us,PRODUCT_DNS_PROXY_ATTEMPT_INVALID);return;
  }
  if (exchange->deadline <= now_us)
    { next_candidate (proxy, exchange, now_us, PRODUCT_DNS_PROXY_ATTEMPT_TIMEOUT); return; }
  product_dns_proxy_key_t expected = exchange->key;
  /* HTTP Age is time the answer already spent upstream. Delivery and cache both see
   * TTLs reduced by it (floor zero); data with no ageable RR is unchanged. */
  uint32_t age = exchange->transport == PRODUCT_DNS_PROXY_DOH ? exchange->io.http_age : 0;
  uint8_t *aged = NULL;
  if (age && wire && length >= 12 && length <= PRODUCT_DNS_MESSAGE_MAX && (aged = malloc (length)))
    {
      uint32_t ignored;
      memcpy (aged, wire, length);
      if (!cache_answer_ttls (aged, length, age, NULL, aged, &ignored)) { free (aged); aged = NULL; }
    }
  exchange->answering = 1;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_WAITERS; ++i)
    if (proxy->requests[i].exchange == exchange &&
        !memcmp (&exchange->key, &expected, sizeof (expected)))
      answer_waiter (proxy, &proxy->requests[i], transport, wire, length, now_us, aged, age);
  if (!memcmp (&exchange->key, &expected, sizeof (expected))) exchange->answering = 0;
  free (aged);
}

static int prepare_request (const product_dns_proxy_input_t *input, const uint8_t *wire, size_t length,
  const product_dns_proxy_snapshot_t *snapshot, const product_dns_proxy_route_t *route,
  uint64_t attempt, product_dns_proxy_event_t *out)
{
  product_dns_proxy_event_t event = {
    .input = *input, .query_policy = snapshot->identity,
    .policy = snapshot->identity, .client_capacity = 512, .stage = 1,
    .transport = PRODUCT_DNS_PROXY_UDP,
    .key = {.generation = input->identity.generation, .token = input->token,
      .incarnation = input->identity.incarnation, .attempt = attempt,
      .network_revision = input->identity.network_revision, .route_revision = input->route_revision},
  };
  event.route = first_endpoint (route, input, 0, &event.resolver_id);
  event.transport = event.route.transport;
  event.input.context.domains = NULL;
  product_dns_inspect_query (wire, length, &snapshot->context, &event.query);
  event.client_capacity = event.query.udp_capacity < PRODUCT_DNS_PROXY_REPLY_BYTES
    ? event.query.udp_capacity : PRODUCT_DNS_PROXY_REPLY_BYTES;
  if (event.client_capacity < 512) event.client_capacity = 512;
  if (input->context.packet.protocol == 6) event.client_capacity = PRODUCT_DNS_MESSAGE_MAX;
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
  event.resolution_route = resolution_route (route, input, &event.query);
  event.route = first_endpoint (route, input, event.resolution_route, &event.resolver_id);
  event.transport = event.route.transport;
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
  if (snapshot->identity.generation != proxy->generation ||
      snapshot->network_revision != input->identity.network_revision || snapshot->route_revision != input->route_revision)
    return product_dns_proxy_unavailable (input, wire, length, snapshot, &proxy->route,
      &proxy->callbacks, proxy->context, PRODUCT_DNS_PROXY_VIEW_CHANGED);
  if (proxy->view_known && (proxy->network_revision != input->identity.network_revision ||
      proxy->route_revision != input->route_revision))
    product_dns_proxy_advance (proxy, input->identity.now_us, input->identity.network_revision, input->route_revision);
  else {
    proxy->network_revision = input->identity.network_revision; proxy->route_revision = input->route_revision;
    proxy->view_known = 1;
  }
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
  const uint64_t scratch = PRODUCT_DNS_CODEC_BYTES + 2U * PRODUCT_DNS_MESSAGE_MAX +
    sizeof (product_dns_response_t) + 2U * sizeof (product_dns_proxy_event_t);
  if (input->identity.now_us > UINT64_MAX - 2U * PRODUCT_DNS_REQUEST_US ||
      proxy->other_bytes > PRODUCT_DNS_WORK_BYTES - scratch ||
      proxy->resources.owned_bytes > PRODUCT_DNS_WORK_BYTES - scratch - proxy->other_bytes ||
      length > PRODUCT_DNS_WORK_BYTES - scratch - proxy->other_bytes - proxy->resources.owned_bytes)
    goto capacity;

  proxy_exchange_t selected = {.key = event.key, .wire = (uint8_t *) wire, .length = length,
    .deadline = input->identity.now_us + PRODUCT_DNS_PROXY_ATTEMPT_US,
    .total_deadline = input->identity.now_us + PRODUCT_DNS_REQUEST_US,
    .retry_at = input->identity.now_us + PRODUCT_DNS_PROXY_RETRY_US,
    .underlay_epoch = input->identity.underlay_epoch, .profile = input->identity.profile,
    .family = input->context.packet.family, .resolver_port = input->context.packet.destination_port,
    .network_context_known = input->context.packet.network_context_known,
    .network_context_id = input->context.packet.network_context_id,
    .resolution_route = event.resolution_route, .resolver_id = event.resolver_id, .endpoint = event.route};
  memcpy (selected.resolver_address, input->context.packet.destination_address, 16);
  dns_cache_entry_t *cached;
  if (!choose_candidate (proxy, &selected, 0, input->identity.now_us, &cached))
    {
      if (proxy->callbacks.observe) proxy->callbacks.observe (proxy->context, &event);
      event.stage = 3; event.result = PRODUCT_DNS_PROXY_SERVFAIL; event.rcode = 2;
      event.match = (product_l4_policy_match_result_t) {0}; event.policy = (product_dns_policy_identity_t) {0};
      error_reply (proxy, &event); return 1;
    }
  event_endpoint (&event, &selected); event.key = selected.key; event.upstream_attempt = 0;
  if (proxy->callbacks.observe) proxy->callbacks.observe (proxy->context, &event);

  proxy_exchange_t *shared = NULL, *free_exchange = NULL;
  size_t question_end;
  int reusable = !cached && cache_question (wire, length, &question_end);
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
    {
      proxy_exchange_t *exchange = &proxy->exchanges[i];
      if (!exchange->wire) { if (!free_exchange) free_exchange = exchange; continue; }
      if (reusable && !exchange->answering && exchange->deadline > input->identity.now_us &&
          exchange->family == selected.family && exchange->resolver_port == selected.resolver_port &&
          !memcmp (exchange->resolver_address, selected.resolver_address, 16) &&
          cache_same_view (&exchange->view, &selected.view) && exchange->length == length &&
          !memcmp (exchange->wire + 2, wire + 2, length - 2))
        { shared = exchange; break; }
    }
  if (!shared && !free_exchange) goto capacity_observed;
  proxy_request_t *request = NULL;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_WAITERS; ++i)
    if (!proxy->requests[i].exchange) { request = &proxy->requests[i]; break; }
  if (!request) goto capacity_observed;

  if (!shared)
    {
      uint16_t upstream_id;
      if (!reserve_id (proxy, input->identity.now_us, &upstream_id)) goto capacity_observed;
      uint8_t *copy = malloc (length);
      if (!copy) goto capacity_observed;
      memcpy (copy, wire, length); copy[0] = upstream_id >> 8; copy[1] = upstream_id;
      *free_exchange = selected; free_exchange->wire = copy; free_exchange->retirement_owed = 1;
      shared = free_exchange;
      ++proxy->resources.exchanges; proxy->resources.owned_bytes += length;
      if (proxy->resources.exchanges > proxy->resources.exchange_high_water)
        proxy->resources.exchange_high_water = proxy->resources.exchanges;
      if (proxy->resources.owned_bytes > proxy->resources.high_water_bytes)
        proxy->resources.high_water_bytes = proxy->resources.owned_bytes;
    }
  else ++proxy->resources.coalesced;
  *request = (proxy_request_t) {.event = event, .exchange = shared,
    .deadline = input->identity.now_us + PRODUCT_DNS_REQUEST_US};
  ++shared->waiters; ++proxy->resources.active;
  if (proxy->resources.active > proxy->resources.high_water) proxy->resources.high_water = proxy->resources.active;
  if (shared != free_exchange) return 1;
  if (cached && cached_exchange (proxy, shared, cached, input->identity.now_us)) return 1;
  send_candidate (proxy, shared, input->identity.now_us);
  return 1;

capacity:
  if (proxy->callbacks.observe) proxy->callbacks.observe (proxy->context, &event);
capacity_observed:
  ++proxy->resources.capacity;
  event.stage = 3; event.result = PRODUCT_DNS_PROXY_CAPACITY; event.rcode = 2;
  error_reply (proxy, &event);
  return 1;
}
