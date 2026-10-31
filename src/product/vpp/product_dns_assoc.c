/* SPDX-License-Identifier: Apache-2.0 */
#include "product_dns_assoc.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef struct {
  char name[256];
  uint8_t address[16], family, via_cname;
  uint64_t expires, refreshed;
  product_dns_assoc_source_t source;
  uint8_t used;
} assoc_entry_t;

struct product_dns_assoc {
  assoc_entry_t entries[PRODUCT_DNS_ASSOC_ENTRIES];
  product_dns_assoc_stats_t stats;
};

size_t product_dns_assoc_bytes (void) { return sizeof (product_dns_assoc_t); }

product_dns_assoc_t *product_dns_assoc_open (void)
{ return calloc (1, sizeof (product_dns_assoc_t)); }
void product_dns_assoc_close (product_dns_assoc_t *table) { free (table); }
void product_dns_assoc_clear (product_dns_assoc_t *table)
{
  if (!table) return;
  memset (table->entries, 0, sizeof (table->entries));
  table->stats.count = 0;
}

static unsigned u16 (const uint8_t *p) { return ((unsigned) p[0] << 8) | p[1]; }

static int same_view (const product_dns_assoc_source_t *s, uint64_t network, uint64_t route)
{ return s->network_revision == network && (!s->route_revision || !route || s->route_revision == route); }

/* Decode one possibly compressed name into lower-case dotted form without a
 * trailing dot ("" is the root). The codec already accepted this message; the
 * walk is still bounded and refuses forward or looping pointers. */
static int wire_name (const uint8_t *wire, size_t length, size_t *offset, char out[256])
{
  size_t at = *offset, end = 0, written = 0;
  unsigned steps = 0;
  while (at < length && ++steps <= 128)
    {
      unsigned n = wire[at++];
      if ((n & 0xc0) == 0xc0)
        {
          if (at >= length) return 0;
          size_t target = ((n & 63U) << 8) | wire[at++];
          if (target >= at - 2) return 0;
          if (!end) end = at;
          at = target; continue;
        }
      if (n & 0xc0 || n > length - at) return 0;
      if (!n) { out[written] = 0; *offset = end ? end : at; return 1; }
      if (written + n + 1 > 254) return 0;
      if (written) out[written++] = '.';
      for (unsigned i = 0; i < n; ++i)
        {
          unsigned c = wire[at++];
          out[written++] = (char) (c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
        }
    }
  return 0;
}

static int chain_name (const char *wire_form, const char *chain_form)
{
  size_t n = strlen (chain_form);
  if (n && chain_form[n - 1] == '.') --n;
  if (!strcmp (chain_form, ".")) n = 0;
  return strlen (wire_form) == n && !strncasecmp (wire_form, chain_form, n);
}

static int usable (unsigned family, const uint8_t *a)
{
  if (family == 4) return a[0] && a[0] != 127 && a[0] < 224;
  static const uint8_t zero[16];
  if (!memcmp (a, zero, 16) || a[0] == 0xff) return 0;
  for (unsigned i = 0; i < 15; ++i) if (a[i]) return 1;
  return a[15] != 1;
}

typedef struct { uint8_t address[16], family, name_index; } found_t;

static unsigned entry_slot (product_dns_assoc_t *table, uint64_t now, int *evicted)
{
  unsigned oldest = 0;
  *evicted = 0;
  for (unsigned i = 0; i < PRODUCT_DNS_ASSOC_ENTRIES; ++i)
    {
      assoc_entry_t *e = &table->entries[i];
      if (!e->used) return i;
      if (e->expires <= now)
        { memset (e, 0, sizeof (*e)); --table->stats.count; ++table->stats.expired; return i; }
      if (e->expires < table->entries[oldest].expires) oldest = i;
    }
  memset (&table->entries[oldest], 0, sizeof (table->entries[oldest]));
  --table->stats.count; ++table->stats.evicted; *evicted = 1;
  return oldest;
}

unsigned product_dns_assoc_admit (product_dns_assoc_t *table, const uint8_t *wire, size_t length,
  const product_dns_response_t *response, const product_dns_assoc_source_t *source, uint64_t now_us,
  product_dns_assoc_admission_t *result)
{
  product_dns_assoc_admission_t none = {0};
  if (result) *result = none;
  if (!table || !wire || !response || !source) return 0;
  if (length < 12 || response->rcode != 0 || response->chain_status || !response->name_count ||
      response->correlation != PRODUCT_DNS_CORRELATED || (u16 (wire + 2) & 0x0200) ||
      u16 (wire + 4) != 1)
    {
      ++table->stats.rejected;
      if (result) result->reason = PRODUCT_DNS_ASSOC_NOT_ELIGIBLE;
      return 0;
    }
  size_t at = 12;
  char name[256];
  if (!wire_name (wire, length, &at, name) || length - at < 4)
    {
      ++table->stats.rejected;
      if (result) result->reason = PRODUCT_DNS_ASSOC_NOT_ELIGIBLE;
      return 0;
    }
  at += 4;
  /* Answer section only: authority/additional records can never be reliable
   * association evidence, so they are not even visited. */
  found_t found[PRODUCT_DNS_ASSOC_PER_ANSWER + 1];
  unsigned found_count = 0, unusable = 0, addresses = 0, pairs = 0;
  for (unsigned i = 0, count = u16 (wire + 6); i < count; ++i)
    {
      if (!wire_name (wire, length, &at, name) || length - at < 10) break;
      unsigned type = u16 (wire + at), klass = u16 (wire + at + 2), bytes = u16 (wire + at + 8);
      size_t data = at + 10;
      if (bytes > length - data) break;
      at = data + bytes;
      if (klass != 1 || (type != 1 && type != 28) || bytes != (type == 1 ? 4U : 16U)) continue;
      int index = -1;
      for (unsigned n = 0; n < response->name_count && index < 0; ++n)
        if (chain_name (name, response->names[n].name)) index = (int) n;
      if (index < 0) continue;                    /* unrelated owner */
      unsigned family = type == 1 ? 4 : 6;
      ++addresses;
      if (!usable (family, wire + data)) { ++unusable; continue; }
      if (found_count == PRODUCT_DNS_ASSOC_PER_ANSWER || pairs + (unsigned) index + 1 > PRODUCT_DNS_ASSOC_PER_ANSWER)
        {
          ++table->stats.rejected;
          if (result) result->reason = PRODUCT_DNS_ASSOC_OVER_LIMIT;
          return 0;
        }
      pairs += (unsigned) index + 1;
      found_t *f = &found[found_count++];
      memset (f, 0, sizeof (*f));
      f->family = (uint8_t) family; f->name_index = (uint8_t) index;
      memcpy (f->address, wire + data, family == 4 ? 4 : 16);
    }
  if (!found_count)
    {
      if (result)
        {
          result->reason = addresses ? PRODUCT_DNS_ASSOC_UNUSABLE_ONLY : PRODUCT_DNS_ASSOC_NO_ADDRESS;
          result->skipped = unusable > 255 ? 255 : (uint8_t) unusable;
        }
      table->stats.skipped += unusable;
      return 0;
    }
  unsigned touched = 0;
  for (unsigned f = 0; f < found_count; ++f)
    /* The chain is linear: an address owned by names[k] is reached from every
     * name before it (QName first), and from nothing after it. */
    for (unsigned n = 0; n <= found[f].name_index; ++n)
      {
        const char *chain = response->names[n].name;
        size_t chain_length = strlen (chain);
        if (!strcmp (chain, ".")) chain_length = 0;
        else if (chain_length && chain[chain_length - 1] == '.') --chain_length;
        char lowered[256];
        for (size_t k = 0; k < chain_length; ++k)
          lowered[k] = (char) (chain[k] >= 'A' && chain[k] <= 'Z' ? chain[k] + ('a' - 'A') : chain[k]);
        lowered[chain_length] = 0;
        assoc_entry_t *entry = NULL;
        for (unsigned i = 0; i < PRODUCT_DNS_ASSOC_ENTRIES && !entry; ++i)
          {
            assoc_entry_t *e = &table->entries[i];
            if (e->used && e->expires > now_us && e->family == found[f].family &&
                !memcmp (e->address, found[f].address, 16) && !strcmp (e->name, lowered)) entry = e;
          }
        int fresh = !entry, evicted = 0;
        if (fresh)
          {
            entry = &table->entries[entry_slot (table, now_us, &evicted)];
            entry->used = 1;
            memcpy (entry->name, lowered, chain_length + 1);
            memcpy (entry->address, found[f].address, 16);
            entry->family = found[f].family;
            if (++table->stats.count > table->stats.high_water) table->stats.high_water = table->stats.count;
            ++table->stats.admitted;
          }
        else ++table->stats.refreshed;
        entry->via_cname = response->names[n].source;
        entry->source = *source;
        entry->refreshed = now_us; entry->expires = now_us + PRODUCT_DNS_ASSOC_WINDOW_US;
        ++touched;
        if (result)
          {
            if (fresh) { if (result->admitted < 255) ++result->admitted; }
            else if (result->refreshed < 255) ++result->refreshed;
            if (evicted && result->evicted < 255) ++result->evicted;
          }
      }
  if (result) result->skipped = unusable > 255 ? 255 : (uint8_t) unusable;
  table->stats.skipped += unusable;
  return touched;
}

void product_dns_assoc_advance (product_dns_assoc_t *table, uint64_t now_us,
  uint64_t network_revision, uint64_t route_revision)
{
  if (!table) return;
  for (unsigned i = 0; i < PRODUCT_DNS_ASSOC_ENTRIES; ++i)
    {
      assoc_entry_t *e = &table->entries[i];
      if (!e->used) continue;
      if (e->expires <= now_us) ++table->stats.expired;
      else if (!same_view (&e->source, network_revision, route_revision))
        ++table->stats.view_dropped;
      else continue;
      memset (e, 0, sizeof (*e)); --table->stats.count;
    }
}

void product_dns_assoc_qualify (const product_dns_assoc_t *table, uint64_t now_us,
  uint64_t network_revision, uint64_t route_revision, unsigned family,
  const uint8_t address[16], product_dns_assoc_qualification_t *out)
{
  if (!out) return;
  memset (out, 0, sizeof (*out));
  if (!table || !address || (family != 4 && family != 6)) return;
  const assoc_entry_t *first = NULL;
  for (unsigned i = 0; i < PRODUCT_DNS_ASSOC_ENTRIES; ++i)
    {
      const assoc_entry_t *e = &table->entries[i];
      if (!e->used || e->expires <= now_us || e->family != family ||
          !same_view (&e->source, network_revision, route_revision) ||
          memcmp (e->address, address, 16)) continue;
      if (!first) first = e;
      ++out->candidates;
    }
  out->status = !out->candidates ? PRODUCT_DNS_ASSOC_NO_CANDIDATE :
    out->candidates == 1 ? PRODUCT_DNS_ASSOC_ONE_CANDIDATE : PRODUCT_DNS_ASSOC_MANY_CANDIDATES;
  if (out->candidates == 1)
    {
      memcpy (out->name, first->name, sizeof (out->name));
      out->caller = first->source.caller; out->delivery = first->source.delivery;
      out->via_cname = first->via_cname;
      out->expires_us = first->expires; out->refreshed_us = first->refreshed;
    }
}

product_dns_assoc_stats_t product_dns_assoc_stats (const product_dns_assoc_t *table)
{ return table ? table->stats : (product_dns_assoc_stats_t) {0}; }
