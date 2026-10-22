/* SPDX-License-Identifier: Apache-2.0 */
#include "product_dns.h"
#include "product_cares.h"
#include <string.h>

static uint16_t read_u16 (const uint8_t *wire)
{
  return (uint16_t) (((uint16_t) wire[0] << 8) | wire[1]);
}

product_dns_resources_t product_dns_resources (void)
{
  size_t bytes, operations;
  product_cares_memory_status (&bytes, &operations);
  return (product_dns_resources_t) { bytes, operations };
}

void product_dns_inspect_query (const uint8_t *wire, size_t length,
                                const product_dns_context_t *context,
                                product_dns_query_t *out)
{
  if (!out) return;
  memset (out, 0, sizeof (*out));
  if (!context) return;
  out->packet = context->packet;
  out->caller = context->caller == PRODUCT_DNS_CALLER_PLATFORM_APP &&
    context->packet.uid_known && context->packet.uid != UINT32_MAX
      ? PRODUCT_DNS_CALLER_PLATFORM_APP : PRODUCT_DNS_CALLER_UNKNOWN;
  out->packet.domain_source = PRODUCT_POLICY_DOMAIN_DNS_QNAME;
  out->packet.domain_available = 0;
  out->packet.domain_lists = 0;
  if (!wire || length < 4)
    { out->coverage = PRODUCT_DNS_MALFORMED; return; }
  out->id = read_u16 (wire);
  out->flags = read_u16 (wire + 2);
  out->wire_hash = UINT64_C(14695981039346656037);
  for (size_t i = 0; i < length; ++i)
    out->wire_hash = (out->wire_hash ^ wire[i]) * UINT64_C(1099511628211);
  if (out->flags & 0x8000) return;
  if (length < 12 || length > PRODUCT_DNS_MESSAGE_MAX)
    { out->coverage = PRODUCT_DNS_MALFORMED; return; }
  if ((out->flags & 0x7800) || read_u16 (wire + 4) != 1)
    { out->coverage = PRODUCT_DNS_UNSUPPORTED; return; }
  if (product_cares_memory_begin (PRODUCT_DNS_CODEC_BYTES))
    { out->coverage = PRODUCT_DNS_CAPACITY; return; }
  ares_dns_record_t *record = NULL;
  ares_status_t status = product_cares_parse (wire, length, &record);
  out->coverage = status == ARES_ENOMEM ? PRODUCT_DNS_CAPACITY : PRODUCT_DNS_MALFORMED;
  if (status == ARES_SUCCESS && ares_dns_record_query_cnt (record) == 1)
    {
      const char *name = NULL;
      ares_dns_rec_type_t type;
      ares_dns_class_t dnsclass;
      status = ares_dns_record_query_get (record, 0, &name, &type, &dnsclass);
      if (status == ARES_SUCCESS && name && strlen (name) < sizeof (out->name))
        {
          out->qtype = type;
          out->qclass = dnsclass;
          out->name_length = strlen (name);
          memcpy (out->name, name, out->name_length + 1);
          /* c-ares represents the valid DNS root as an empty string. Keep an
           * explicit root QName distinct from missing/unrepresentable facts. */
          if (!out->name_length)
            { out->name[0] = '.'; out->name[1] = 0; out->name_length = 1; }
          out->coverage = PRODUCT_DNS_QUERY_COMPLETE;
          if (out->caller == PRODUCT_DNS_CALLER_PLATFORM_APP && context->domains_available)
            {
              out->packet.domain_available = !product_domains_lookup_dns (
                context->domains, (const uint8_t *) out->name, out->name_length,
                &out->packet.domain_lists);
            }
        }
      else if (status == ARES_SUCCESS) out->coverage = PRODUCT_DNS_UNSUPPORTED;
    }
  ares_dns_record_destroy (record);
  size_t unreleased = 0;
  out->codec_peak_bytes = product_cares_memory_end (&unreleased);
  if (unreleased)
    {
      out->coverage = PRODUCT_DNS_MALFORMED;
      out->packet.domain_available = 0;
      out->packet.domain_lists = 0;
    }
}


static unsigned char dns_lower (unsigned char c)
{ return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c; }

static int same_name (const char *left, const char *right)
{
  if (!left || !right) return 0;
  if (!*left) left = ".";
  if (!*right) right = ".";
  while (*left && *right)
    if (dns_lower ((unsigned char) *left++) != dns_lower ((unsigned char) *right++)) return 0;
  return !*left && !*right;
}

void product_dns_owner_start (product_dns_owner_t *owner, uint64_t generation)
{
  if (!owner) return;
  memset (owner, 0, sizeof (*owner));
  owner->generation = generation;
  owner->accepting = generation != 0;
}

void product_dns_owner_stop (product_dns_owner_t *owner)
{
  if (!owner) return;
  memset (owner->requests, 0, sizeof (owner->requests));
  owner->accepting = 0;
  owner->overflow_until = 0;
}

uint64_t product_dns_owner_deadline (const product_dns_owner_t *owner)
{
  uint64_t next = UINT64_MAX;
  if (!owner || !owner->accepting) return next;
  if (owner->overflow_until) next = owner->overflow_until;
  for (unsigned i = 0; i < PRODUCT_DNS_REQUESTS; ++i)
    if (owner->requests[i].active && owner->requests[i].deadline < next)
      next = owner->requests[i].deadline;
  return next;
}

unsigned product_dns_owner_active (product_dns_owner_t *owner, uint64_t now)
{
  if (!owner) return 0;
  unsigned active = 0;
  for (unsigned i = 0; i < PRODUCT_DNS_REQUESTS; ++i)
    {
      product_dns_request_t *request = &owner->requests[i];
      if (request->active && request->deadline <= now)
        { memset (request, 0, sizeof (*request)); ++owner->expired; }
      active += request->active;
    }
  if (owner->overflow_until <= now) owner->overflow_until = 0;
  return active;
}

static int same_context (const product_l4_policy_packet_t *a,
                         const product_l4_policy_packet_t *b, int reverse)
{
  return a->family == b->family && a->protocol == b->protocol &&
    a->source_port == (reverse ? b->destination_port : b->source_port) &&
    a->destination_port == (reverse ? b->source_port : b->destination_port) &&
    !memcmp (a->source_address, reverse ? b->destination_address : b->source_address, 16) &&
    !memcmp (a->destination_address, reverse ? b->source_address : b->destination_address, 16);
}

static int same_identity (const product_dns_identity_t *a, const product_dns_identity_t *b)
{
  return a->generation == b->generation && a->incarnation == b->incarnation &&
    a->network_revision == b->network_revision && a->profile == b->profile;
}

static int same_platform_context (const product_l4_policy_packet_t *a,
                                  const product_l4_policy_packet_t *b)
{
  return a->network_context_known == b->network_context_known &&
    (!a->network_context_known || a->network_context_id == b->network_context_id) &&
    a->ifindex_known == b->ifindex_known && (!a->ifindex_known || a->ifindex == b->ifindex);
}

static int same_question (const product_dns_query_t *a, const product_dns_query_t *b)
{
  return a->id == b->id && a->qtype == b->qtype && a->qclass == b->qclass &&
    same_name (a->name, b->name);
}

product_dns_correlation_t product_dns_remember (product_dns_owner_t *owner,
  const product_dns_query_t *query, const product_dns_identity_t *identity,
  uint64_t token, const product_dns_policy_identity_t *policy)
{
  if (!owner || !query || !identity || !policy || !token || !owner->accepting ||
      owner->generation != identity->generation ||
      (!identity->incarnation && !(query->packet.protocol == 6 && query->message_sequence)) ||
      query->coverage != PRODUCT_DNS_QUERY_COMPLETE || query->packet.direction != 3)
    return PRODUCT_DNS_UNMATCHED;
  unsigned active = product_dns_owner_active (owner, identity->now_us);
  product_dns_request_t *empty = NULL;
  for (unsigned i = 0; i < PRODUCT_DNS_REQUESTS; ++i)
    {
      product_dns_request_t *request = &owner->requests[i];
      if (!request->active) { if (!empty) empty = request; continue; }
      if (!same_identity (&request->identity, identity) ||
          !same_question (&request->query, query) ||
          !same_context (&request->query.packet, &query->packet, 0) ||
          !same_platform_context (&request->query.packet, &query->packet)) continue;
      /* TCP retransmission is resolved by the byte observer. A subsequent
       * framed request may legitimately reuse an ID after its answer, while
       * two simultaneous identical Questions remain ambiguous. UDP keeps its
       * finite datagram tombstone/retransmission contract. */
      if (query->packet.protocol == 6 && request->replied)
        { memset (request, 0, sizeof (*request)); --active; if (!empty) empty = request; continue; }
      request->transport_token = token;
      ++owner->retransmits;
      if (request->retransmits < UINT16_MAX) ++request->retransmits;
      if (request->replied ||
          (query->packet.protocol == 6 && request->query.message_sequence != query->message_sequence) ||
          request->query.wire_hash != query->wire_hash ||
          request->policy.generation != policy->generation ||
          request->policy.revision != policy->revision || request->policy.hash != policy->hash ||
          request->policy.winner != policy->winner ||
          request->query.caller != query->caller ||
          request->query.packet.uid_known != query->packet.uid_known ||
          request->query.packet.uid != query->packet.uid)
        {
          if (!request->ambiguous) ++owner->ambiguous;
          request->ambiguous = 1;
          if (request->requests < UINT16_MAX) ++request->requests;
        }
      return request->ambiguous ? PRODUCT_DNS_AMBIGUOUS : PRODUCT_DNS_CORRELATED;
    }
  if (!empty)
    {
      ++owner->capacity;
      owner->overflow_until = identity->now_us + PRODUCT_DNS_REQUEST_US;
      return PRODUCT_DNS_REQUEST_CAPACITY;
    }
  *empty = (product_dns_request_t) {.query = *query, .identity = *identity,
    .policy = *policy, .token = token, .transport_token = token, .deadline = identity->now_us + PRODUCT_DNS_REQUEST_US,
    .requests = 1, .active = 1};
  if (owner->high_water < active + 1) owner->high_water = active + 1;
  return PRODUCT_DNS_CORRELATED;
}

void product_dns_request_transport (product_dns_owner_t *owner, uint64_t generation,
  uint64_t token, uint64_t incarnation, uint64_t session, uint64_t epoch,
  uint32_t context, int known)
{
  if (!owner || !owner->accepting || owner->generation != generation || !session) return;
  for (unsigned i = 0; i < PRODUCT_DNS_REQUESTS; ++i)
    {
      product_dns_request_t *r = &owner->requests[i];
      if (!r->active || (r->token != token && r->transport_token != token) || r->identity.incarnation != incarnation ||
          r->identity.profile != 2) continue;
      if (r->identity.transport_session && r->identity.transport_session != session)
        { r->ambiguous = 1; ++owner->ambiguous; continue; }
      r->identity.transport_session = session;
      r->identity.underlay_epoch = epoch;
      r->bound_context = context;
      r->bound_context_known = !!known;
    }
}

void product_dns_transport_bound (product_dns_owner_t *owner, uint64_t generation,
  uint64_t session, uint64_t epoch, uint32_t context, int known)
{
  if (!owner || !owner->accepting || owner->generation != generation || !session || !epoch) return;
  for (unsigned i = 0; i < PRODUCT_DNS_REQUESTS; ++i)
    {
      product_dns_request_t *r = &owner->requests[i];
      if (!r->active || r->identity.profile != 2 ||
          r->identity.transport_session != session || r->identity.underlay_epoch) continue;
      r->identity.underlay_epoch = epoch;
      r->bound_context = context;
      r->bound_context_known = !!known;
    }
}

static int add_name (product_dns_response_t *out, const char *name, unsigned source)
{
  if (!name || strlen (name) >= sizeof (out->names[0].name)) return 0;
  if (out->name_count == PRODUCT_DNS_NAMES) return 0;
  product_dns_name_t *candidate = &out->names[out->name_count++];
  candidate->source = source;
  candidate->length = strlen (name);
  memcpy (candidate->name, name, candidate->length + 1);
  if (!candidate->length)
    { candidate->name[0] = '.'; candidate->name[1] = 0; candidate->length = 1; }
  return 1;
}

static void prepare_chain (ares_dns_record_t *record, product_dns_response_t *out)
{
  (void) add_name (out, out->question.name, 0);
  unsigned chain_class = out->question.qclass;
  for (;;)
    {
      const char *current = out->names[out->name_count - 1].name, *target = NULL;
      for (size_t i = 0; i < ares_dns_record_rr_cnt (record, ARES_SECTION_ANSWER); ++i)
        {
          const ares_dns_rr_t *rr = ares_dns_record_rr_get_const (record, ARES_SECTION_ANSWER, i);
          if (ares_dns_rr_get_type (rr) != ARES_REC_TYPE_CNAME ||
              (out->question.qclass != ARES_CLASS_ANY &&
               ares_dns_rr_get_class (rr) != out->question.qclass) ||
              !same_name (ares_dns_rr_get_name (rr), current)) continue;
          unsigned rr_class = ares_dns_rr_get_class (rr);
          if (out->question.qclass == ARES_CLASS_ANY && out->name_count > 1 &&
              rr_class != chain_class) continue;
          if (target && rr_class != chain_class)
            { out->question.coverage = PRODUCT_DNS_UNSUPPORTED; out->chain_status = 2; return; }
          const char *next = ares_dns_rr_get_str (rr, ARES_RR_CNAME_CNAME);
          if (target && !same_name (target, next))
            { out->question.coverage = PRODUCT_DNS_MALFORMED; out->chain_status = 2; return; }
          target = next;
          chain_class = rr_class;
        }
      if (!target) return;
      for (unsigned i = 0; i < out->name_count; ++i)
        if (same_name (out->names[i].name, *target ? target : "."))
          { out->question.coverage = PRODUCT_DNS_MALFORMED; out->chain_status = 1; return; }
      if (!add_name (out, target, 1))
        { out->question.coverage = PRODUCT_DNS_CAPACITY; out->chain_status = 3; return; }
    }
}

void product_dns_inspect_response (const uint8_t *wire, size_t length,
  const product_dns_context_t *context, const product_dns_identity_t *identity,
  product_dns_owner_t *owner, product_dns_response_t *out)
{
  if (!out) return;
  memset (out, 0, sizeof (*out));
  if (!context || !identity) return;
  out->question.packet = context->packet;
  out->question.packet.domain_source = PRODUCT_POLICY_DOMAIN_DNS_QNAME;
  out->question.packet.domain_available = 0;
  out->question.packet.domain_lists = 0;
  out->query_uid = UINT32_MAX;
  out->correlation = PRODUCT_DNS_UNMATCHED;
  if (!wire || length < 4) { out->question.coverage = PRODUCT_DNS_MALFORMED; return; }
  out->question.id = read_u16 (wire);
  out->question.flags = read_u16 (wire + 2);
  if (!(out->question.flags & 0x8000)) return;
  out->question.coverage = PRODUCT_DNS_MALFORMED;
  if (length < 12 || length > PRODUCT_DNS_MESSAGE_MAX) return;
  if ((out->question.flags & 0x7800) || read_u16 (wire + 4) != 1)
    { out->question.coverage = PRODUCT_DNS_UNSUPPORTED; return; }
  if (product_cares_memory_begin (PRODUCT_DNS_CODEC_BYTES))
    { out->question.coverage = PRODUCT_DNS_CAPACITY; return; }
  ares_dns_record_t *record = NULL;
  ares_status_t status = product_cares_parse (wire, length, &record);
  if (status == ARES_ENOMEM) out->question.coverage = PRODUCT_DNS_CAPACITY;
  if (status == ARES_SUCCESS)
    {
      out->rcode = ares_dns_record_get_rcode (record);
      const char *name = NULL;
      ares_dns_rec_type_t type;
      ares_dns_class_t dnsclass;
      status = ares_dns_record_query_get (record, 0, &name, &type, &dnsclass);
      if (status == ARES_SUCCESS && name && strlen (name) < sizeof (out->question.name))
        {
          out->question.name_length = strlen (name);
          memcpy (out->question.name, name, out->question.name_length + 1);
          if (!out->question.name_length)
            { strcpy (out->question.name, "."); out->question.name_length = 1; }
          out->question.qtype = type; out->question.qclass = dnsclass;
          out->question.coverage = PRODUCT_DNS_QUERY_COMPLETE;
          prepare_chain (record, out);
          if (out->question.flags & 0x0200) out->question.coverage = PRODUCT_DNS_COPY_GAP;
        }
      else out->question.coverage = PRODUCT_DNS_UNSUPPORTED;
    }
  ares_dns_record_destroy (record);
  size_t unreleased = 0;
  out->question.codec_peak_bytes = product_cares_memory_end (&unreleased);
  if (unreleased) out->question.coverage = PRODUCT_DNS_MALFORMED;
  if (!owner || !owner->accepting || identity->generation != owner->generation ||
      context->packet.direction != 1 || !identity->incarnation || !out->question.name_length) return;
  (void) product_dns_owner_active (owner, identity->now_us);
  if (owner->overflow_until)
    { out->correlation = PRODUCT_DNS_REQUEST_CAPACITY; return; }
  for (unsigned i = 0; i < PRODUCT_DNS_REQUESTS; ++i)
    {
      product_dns_request_t *r = &owner->requests[i];
      if (!r->active || !same_identity (&r->identity, identity) ||
          !same_question (&r->query, &out->question) ||
          !same_context (&r->query.packet, &context->packet, 1)) continue;
      if (identity->profile == 1 && !same_platform_context (&r->query.packet, &context->packet)) continue;
      out->matched_requests = r->requests; out->retransmits = r->retransmits;
      if (r->ambiguous)
        { out->correlation = PRODUCT_DNS_AMBIGUOUS; return; }
      if (identity->profile == 2 && (!r->identity.transport_session || !r->identity.underlay_epoch ||
          r->identity.transport_session != identity->transport_session ||
          r->identity.underlay_epoch != identity->underlay_epoch))
        { out->correlation = PRODUCT_DNS_BINDING_UNAVAILABLE; return; }
      int known = identity->profile == 2 ? r->bound_context_known : r->query.packet.network_context_known;
      uint32_t network = identity->profile == 2 ? r->bound_context : r->query.packet.network_context_id;
      if (known != context->packet.network_context_known ||
          (known && network != context->packet.network_context_id)) continue;
      out->correlation = PRODUCT_DNS_CORRELATED;
      out->query_token = r->token; out->query_policy = r->policy;
      out->query_incarnation = r->identity.incarnation;
      out->query_uid = r->query.packet.uid;
      out->query_uid_known = r->query.packet.uid_known;
      out->question.caller = r->query.caller;
      out->transport_session = r->identity.transport_session;
      out->underlay_epoch = r->identity.underlay_epoch;
      r->replied = 1;
      ++owner->matched;
      break;
    }
  if (out->correlation != PRODUCT_DNS_CORRELATED) ++owner->unmatched;
  /* No candidate is evaluated until the complete connected name set and all
   * current-snapshot memberships have been prepared. Incomplete coverage never
   * becomes a confident negative or a cross-name membership union. */
  if (out->correlation == PRODUCT_DNS_CORRELATED &&
      out->question.caller == PRODUCT_DNS_CALLER_PLATFORM_APP &&
      out->question.coverage == PRODUCT_DNS_QUERY_COMPLETE && context->domains_available)
    for (unsigned i = 0; i < out->name_count; ++i)
      out->names[i].available = !product_domains_lookup_dns (context->domains,
        (const uint8_t *) out->names[i].name, out->names[i].length, &out->names[i].lists);
}

product_l4_policy_status_t product_dns_response_match (
  const product_l4_policy_view_t *view, const product_l4_policy_packet_t *packet,
  const product_dns_response_t *response, product_l4_policy_position_t position,
  product_l4_policy_match_result_t *result)
{
  if (!view || !packet || !response || !result) return PRODUCT_L4_POLICY_STATUS_INVALID_ARGUMENT;
  product_l4_policy_packet_t candidate = *packet;
  candidate.domain_source = PRODUCT_POLICY_DOMAIN_DNS_QNAME;
  if (response->correlation == PRODUCT_DNS_CORRELATED &&
      response->question.caller == PRODUCT_DNS_CALLER_PLATFORM_APP)
    { candidate.uid = response->query_uid; candidate.uid_known = 1; }
  unsigned count = response->name_count ? response->name_count : 1;
  for (unsigned i = 0; i < count; ++i)
    {
      candidate.domain_available = response->names[i].available;
      candidate.domain_lists = response->names[i].lists;
      product_l4_policy_match_result_t match;
      product_l4_policy_status_t status = product_l4_policy_match_position (view, &candidate, position, &match);
      if (status != PRODUCT_L4_POLICY_STATUS_OK) return status;
      if (!i || (match.evaluation && (!result->evaluation || match.winner_rank < result->winner_rank)))
        *result = match;
    }
  return PRODUCT_L4_POLICY_STATUS_OK;
}
