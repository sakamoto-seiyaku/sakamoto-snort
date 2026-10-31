/* SPDX-License-Identifier: Apache-2.0 */
/* Private owned-wire data cache. Its caller has already validated the complete
 * correlated message with the bounded codec. No policy or caller is retained. */
#define DNS_CACHE_ENTRIES 512U
#define DNS_CACHE_BYTES (2U * 1024U * 1024U)
typedef struct {
  uint64_t network, route, underlay;
  uint32_t resolution_route, resolver_id, family, port, network_context;
  uint8_t address[16], profile, network_context_known;
} dns_cache_view_t;
static int cache_same_view (const dns_cache_view_t *a, const dns_cache_view_t *b)
{
  return a->network == b->network && a->route == b->route && a->underlay == b->underlay &&
    a->resolution_route == b->resolution_route && a->resolver_id == b->resolver_id &&
    a->family == b->family && a->port == b->port && a->profile == b->profile &&
    a->network_context_known == b->network_context_known &&
    (!a->network_context_known || a->network_context == b->network_context) &&
    !memcmp (a->address, b->address, 16);
}
typedef struct {
  uint8_t *data;
  dns_cache_view_t view;
  uint64_t inserted, used;
  uint32_t lifetime;
  uint16_t query_length, answer_length;
  uint8_t transport;
} dns_cache_entry_t;
typedef struct {
  dns_cache_entry_t entries[DNS_CACHE_ENTRIES];
  uint64_t bytes, high_water_bytes, hits, misses, evictions, skipped, serial;
  uint32_t count, high_water;
} dns_cache_t;

static unsigned cache_u16 (const uint8_t *p)
{ return ((unsigned) p[0] << 8) | p[1]; }
static uint32_t cache_u32 (const uint8_t *p)
{ return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | p[3]; }

/* Restrict only data-cache eligibility to unambiguous ordinary textual
 * labels. The codec/forwarding path still preserves binary and escaped names.
 * A literal dot, NUL or backslash inside a label must never become a dotted
 * string separator, terminator or escape in SOA ancestor qualification. */
static int cache_label_char (unsigned c)
{ return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
    (c >= '0' && c <= '9') || c == '-' || c == '_'; }
static int cache_candidate_names (const product_dns_response_t *response)
{
  for (unsigned i = 0; i < response->name_count; ++i)
    {
      const char *name = response->names[i].name;
      if (!strcmp (name, ".")) continue;
      unsigned label = 0;
      for (size_t j = 0; name[j]; ++j)
        if (name[j] == '.')
          { if (!label || label > 63) return 0; label = 0; }
        else
          { if (!cache_label_char ((unsigned char) name[j])) return 0; ++label; }
      if (!label || label > 63) return 0;
    }
  return 1;
}

/* The codec already validates DNS semantics. Cache eligibility additionally
 * requires every compression target to be a previously visited name boundary.
 * Only 14-bit offsets can be referenced; the bitmap is bounded stack scratch.
 * TTL/header/label-interior/opaque bytes never become name anchors. */
#define DNS_CACHE_NAME_ANCHORS (16384U / 8U)
static int cache_name (const uint8_t *wire, size_t length, size_t *offset, char *name,
  uint8_t anchors[DNS_CACHE_NAME_ANCHORS])
{
  size_t at = *offset, end = 0, written = 0;
  unsigned steps = 0;
  while (at < length && ++steps <= 128)
    {
      size_t boundary = at;
      unsigned n = wire[at++];
      if ((n & 0xc0) == 0xc0)
        {
          if (at >= length) return 0;
          size_t target = ((n & 63U) << 8) | wire[at++];
          if (target >= boundary || !(anchors[target / 8] & (1U << (target % 8)))) return 0;
          if (boundary < 16384) anchors[boundary / 8] |= 1U << (boundary % 8);
          if (!end) end = at;
          at = target; continue;
        }
      if (n & 0xc0 || n > length - at || written + n + 1 > 255) return 0;
      if (boundary < 16384) anchors[boundary / 8] |= 1U << (boundary % 8);
      if (!n)
        {
          *offset = end ? end : at;
          if (name) { if (!written) name[written++] = '.'; name[written] = 0; }
          return 1;
        }
      if (written && name) name[written] = '.';
      if (written) ++written;
      for (unsigned i = 0; i < n; ++i)
        {
          unsigned c = wire[at++];
          if (!cache_label_char (c)) return 0;
          if (name) name[written] = c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
          ++written;
        }
    }
  return 0;
}

/* Visit name fields supported by the existing codec, without decoding their
 * other data. Unknown RDATA remains opaque: a possible compression octet makes
 * it ineligible, and it can never supply anchors to later records. */
static int cache_rdata_names (const uint8_t *wire, size_t length, size_t data,
  size_t bytes, unsigned type, uint8_t anchors[DNS_CACHE_NAME_ANCHORS])
{
  size_t at = data, end = data + bytes;
  unsigned names = 0, prefix = 0, tail = 0;
  switch (type)
    {
    case 2: case 5: case 12: names = 1; break; /* NS, CNAME, PTR */
    case 6: names = 2; tail = 20; break; /* SOA */
    case 15: prefix = 2; names = 1; break; /* MX */
    case 24: prefix = 18; names = 1; break; /* SIG */
    case 33: prefix = 6; names = 1; break; /* SRV */
    case 35: /* NAPTR: order/preference and three character strings */
      if (bytes < 4) return 0;
      at += 4;
      for (unsigned i = 0; i < 3; ++i)
        { if (at == end || wire[at] >= end - at) return 0; at += wire[at] + 1U; }
      names = 1; break;
    case 64: case 65: prefix = 2; names = 1; break; /* SVCB, HTTPS */
    case 1: case 13: case 16: case 28: case 41: case 52: case 256: case 257:
      return 1; /* codec-supported data without DNS name fields */
    default:
      for (size_t i = data; i < end; ++i) if ((wire[i] & 0xc0) == 0xc0) return 0;
      return 1;
    }
  if (prefix > end - at) return 0;
  at += prefix;
  for (unsigned i = 0; i < names; ++i)
    if (!cache_name (wire, length, &at, NULL, anchors) || at > end) return 0;
  if (type == 24 || type == 64 || type == 65) return 1; /* opaque trailing data */
  return end - at == tail;
}

/* Be conservative about options which can bind an answer to a client, a
 * nonce, server state or an undisclosed view. Empty EDNS0 (including DO) is
 * safe when the entire query bytes participate in the key. */
static int cache_question (const uint8_t *wire, size_t length, size_t *end)
{
  if (length < 17 || cache_u16 (wire + 4) != 1 || cache_u16 (wire + 6) ||
      cache_u16 (wire + 8) || cache_u16 (wire + 10) > 1 ||
      (cache_u16 (wire + 2) & ~0x0130U)) return 0;
  size_t at = 12;
  while (at < length && wire[at])
    {
      unsigned n = wire[at++];
      if (n > 63 || n > length - at) return 0;
      for (unsigned i = 0; i < n; ++i) if (!cache_label_char (wire[at + i])) return 0;
      at += n;
    }
  if (at >= length || length - ++at < 4) return 0;
  at += 4; *end = at;
  if (!cache_u16 (wire + 10)) return at == length;
  return length - at == 11 && wire[at] == 0 && cache_u16 (wire + at + 1) == 41 &&
    !(cache_u32 (wire + at + 5) & ~0x8000U) /* EDNS0 and DO only */ &&
    !cache_u16 (wire + at + 9);
}

static int cache_zone (const char *name, const char *zone)
{
  size_t n = strlen (name), z = strlen (zone);
  if (!strcmp (zone, ".")) return 1;
  return n >= z && !memcmp (name + n - z, zone, z) && (n == z || name[n - z - 1] == '.');
}

/* Every actual RR TTL ages, even when this product has no type-specific
 * extractor. OPT TTL is protocol metadata. The whole answer expires at its
 * shortest reusable TTL, with RFC2308's min(SOA TTL, MINIMUM) for negatives. */
static int cache_answer_ttls (const uint8_t *wire, size_t length, uint32_t elapsed,
  const product_dns_response_t *response, uint8_t *aged, uint32_t *lifetime)
{
  if (length < 12 || (cache_u16 (wire + 2) & 0x0200) ||
      cache_u16 (wire + 4) != 1 || (response && ((response->rcode != 0 && response->rcode != 3) ||
      !response->name_count || response->chain_status || !cache_candidate_names (response)))) return 0;
  uint8_t anchors[DNS_CACHE_NAME_ANCHORS] = {0};
  size_t at = 12;
  if (!cache_name (wire, length, &at, NULL, anchors) || length - at < 4) return 0;
  at += 4;
  uint32_t minimum = UINT32_MAX, negative = UINT32_MAX;
  unsigned positive = 0, soa_count = 0, seen = 0;
  char terminal[256];
  const char *original = response ? response->names[response->question.qtype == 5 ? 0 : response->name_count - 1].name : ".";
  size_t terminal_length = strlen (original);
  for (size_t i = 0; i <= terminal_length; ++i)
    terminal[i] = original[i] >= 'A' && original[i] <= 'Z' ? original[i] + ('a' - 'A') : original[i];
  for (unsigned section = 0; section < 3; ++section)
    for (unsigned i = 0, count = cache_u16 (wire + 6 + section * 2); i < count; ++i)
      {
        char owner[256];
        if (!cache_name (wire, length, &at, owner, anchors) || length - at < 10) return 0;
        unsigned type = cache_u16 (wire + at), klass = cache_u16 (wire + at + 2);
        uint32_t ttl = cache_u32 (wire + at + 4);
        size_t bytes = cache_u16 (wire + at + 8), data = at + 10;
        if (bytes > length - data || !cache_rdata_names (wire, length, data, bytes, type, anchors)) return 0;
        if (type == 41)
          { if (section != 2 || bytes || (ttl & ~0x8000U)) return 0; }
        else
          {
            /* RFC2181's reserved high TTL bit has zero cache lifetime. */
            if (ttl & UINT32_C(0x80000000)) return 0;
            ++seen;
            if (ttl < minimum) minimum = ttl;
            if (response && !section && (response->question.qtype == 255 || type == response->question.qtype) &&
                (response->question.qclass == 255 || klass == response->question.qclass) &&
                !strcmp (owner, terminal)) positive = 1;
            if (response && section == 1 && type == 6 && klass == response->question.qclass && cache_zone (terminal, owner))
              {
                size_t soa = data;
                if (!cache_name (wire, length, &soa, NULL, anchors) || !cache_name (wire, length, &soa, NULL, anchors) ||
                    soa > data + bytes || data + bytes - soa != 20) return 0;
                uint32_t limit = cache_u32 (wire + soa + 16);
                if (ttl < limit) limit = ttl;
                if (limit < negative) negative = limit;
                if (response->rcode == 3 || !positive) ttl = limit;
                ++soa_count;
              }
            uint32_t remaining = ttl > elapsed ? ttl - elapsed : 0;
            if (aged) {
              aged[at + 4] = remaining >> 24; aged[at + 5] = remaining >> 16;
              aged[at + 6] = remaining >> 8; aged[at + 7] = remaining;
            }
          }
        at = data + bytes;
      }
  if (at != length || !seen) return 0;
  if (!response) return 1;
  if (response->rcode == 3 || !positive)
    { if (soa_count != 1) return 0; if (negative < minimum) minimum = negative; }
  *lifetime = minimum;
  return minimum != 0;
}

static void cache_drop (dns_cache_t *cache, dns_cache_entry_t *entry, int evicted)
{
  if (!entry->data) return;
  cache->bytes -= (size_t) entry->query_length + entry->answer_length;
  --cache->count; cache->evictions += !!evicted;
  free (entry->data); memset (entry, 0, sizeof (*entry));
}
static void cache_clear (dns_cache_t *cache)
{ for (unsigned i = 0; i < DNS_CACHE_ENTRIES; ++i) cache_drop (cache, &cache->entries[i], 0); }
static int cache_expired (const dns_cache_entry_t *entry, uint64_t now)
{ return now < entry->inserted || (now - entry->inserted) / UINT64_C(1000000) >= entry->lifetime; }
static void cache_prune (dns_cache_t *cache, uint64_t now, uint64_t network, uint64_t route)
{
  for (unsigned i = 0; i < DNS_CACHE_ENTRIES; ++i)
    {
      dns_cache_entry_t *e = &cache->entries[i];
      if (e->data && (e->view.network != network || e->view.route != route || cache_expired (e, now)))
        cache_drop (cache, e, 1);
    }
}
static dns_cache_entry_t *cache_lookup (dns_cache_t *cache, const uint8_t *query, size_t length,
  uint64_t now, const dns_cache_view_t *view)
{
  size_t end;
  cache_prune (cache, now, view->network, view->route);
  if (cache->serial == UINT64_MAX) { cache_clear (cache); cache->serial = 0; }
  if (!cache_question (query, length, &end)) { ++cache->skipped; return NULL; }
  for (unsigned i = 0; i < DNS_CACHE_ENTRIES; ++i)
    {
      dns_cache_entry_t *e = &cache->entries[i];
      if (e->data && cache_same_view (&e->view, view) && e->query_length == length &&
          !memcmp (e->data + 2, query + 2, length - 2))
        { e->used = ++cache->serial; ++cache->hits; return e; }
    }
  ++cache->misses; return NULL;
}
/* age_seconds is HTTP Age already spent upstream (DoH). It reduces the reusable
 * lifetime and every stored RR TTL before local elapsed time starts counting. */
static void cache_store (dns_cache_t *cache, const uint8_t *query, size_t query_length,
  const uint8_t *answer, size_t answer_length, unsigned transport, uint64_t now,
  const dns_cache_view_t *view, const product_dns_response_t *response, uint32_t age_seconds)
{
  size_t end;
  if (!cache_question (query, query_length, &end) || answer_length < end ||
      memcmp (query + 12, answer + 12, end - 12)) { ++cache->skipped; return; }
  size_t bytes = query_length + answer_length;
  if (bytes > DNS_CACHE_BYTES - sizeof (*cache)) { ++cache->skipped; return; }
  uint32_t lifetime;
  /* Validate directly from the synchronous input first. Retire enough old
   * owned data before allocating its replacement: the bound applies to live
   * memory throughout insertion, not just the final container state. */
  if (!cache_answer_ttls (answer, answer_length, 0, response, NULL, &lifetime) || lifetime <= age_seconds)
    { ++cache->skipped; return; }
  lifetime -= age_seconds;
  cache_prune (cache, now, view->network, view->route);
  if (cache->serial == UINT64_MAX) { cache_clear (cache); cache->serial = 0; }
  for (unsigned i = 0; i < DNS_CACHE_ENTRIES; ++i)
    {
      dns_cache_entry_t *e = &cache->entries[i];
      if (e->data && cache_same_view (&e->view, view) && e->query_length == query_length &&
          !memcmp (e->data + 2, query + 2, query_length - 2))
        cache_drop (cache, e, 0);
    }
  while (cache->count == DNS_CACHE_ENTRIES || cache->bytes + bytes > DNS_CACHE_BYTES - sizeof (*cache))
    {
      dns_cache_entry_t *oldest = NULL;
      for (unsigned i = 0; i < DNS_CACHE_ENTRIES; ++i)
        if (cache->entries[i].data && (!oldest || cache->entries[i].used < oldest->used)) oldest = &cache->entries[i];
      if (!oldest) { ++cache->skipped; return; }
      cache_drop (cache, oldest, 1);
    }
  uint8_t *copy = malloc (bytes);
  if (!copy) { ++cache->skipped; return; }
  memcpy (copy, query, query_length); memcpy (copy + query_length, answer, answer_length);
  (void) cache_answer_ttls (copy + query_length, answer_length, age_seconds, response,
    copy + query_length, &lifetime);
  lifetime = lifetime > age_seconds ? lifetime - age_seconds : 0;
  for (unsigned i = 0; i < DNS_CACHE_ENTRIES; ++i)
    if (!cache->entries[i].data)
      {
        cache->entries[i] = (dns_cache_entry_t) {.data = copy, .view = *view,
          .inserted = now, .used = ++cache->serial, .lifetime = lifetime, .query_length = query_length,
          .answer_length = answer_length, .transport = transport};
        ++cache->count; cache->bytes += bytes;
        if (cache->count > cache->high_water) cache->high_water = cache->count;
        if (cache->bytes > cache->high_water_bytes) cache->high_water_bytes = cache->bytes;
        return;
      }
  free (copy);
}
