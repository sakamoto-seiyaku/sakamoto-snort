/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Production transport for the Host Product Core.  This translation unit is
 * selected only by the pinned-VPP build; ordinary semantic tests use the
 * explicitly named fixture transport in sakamoto_product_host_fixture_abi.c.
 * The two implementations share the public ABI but never share a packet or
 * VPP buffer.  VAPI is blocking and the session lock is the one serialized
 * owner.
 */

#include "sakamoto_product_abi.h"
#include "sakamoto_product_status.h"
#include "sakamoto_product_observation.h"

#include <stdbool.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wsign-compare"
#endif
#include <vapi/memclnt.api.vapi.h>
#include <vapi/vapi.h>
#include <vapi/vlib.api.vapi.h>
#include <vapi/product_core.api.vapi.h>
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

DEFINE_VAPI_MSG_IDS_MEMCLNT_API_JSON;
DEFINE_VAPI_MSG_IDS_VLIB_API_JSON;
DEFINE_VAPI_MSG_IDS_PRODUCT_CORE_API_JSON;

struct sakamoto_product_session {
  vapi_ctx_t context;
  uint64_t generation;
  int connected;
  uint32_t policy_mutation_fault_mode;
  pthread_mutex_t mutex;
};

typedef struct {
  uint32_t transport_code;
  bool callback_called;
  sakamoto_product_status_t *status;
} status_call_t;

typedef struct {
  uint32_t transport_code;
  bool callback_called;
  sakamoto_product_status_t *status;
} apply_call_t;

typedef struct {
  bool called;
  uint32_t code;
} network_call_t;

static void
release_unsent_request (sakamoto_product_session_t *session, vapi_error_e rv,
                        bool callback_called, void *message)
{
  /* This mutex-owned blocking UDS context has one outstanding slot. A
   * failed generated call with no callback and no stored request failed
   * before ownership transfer; vapi.h requires the caller to free it.
   * A failed dispatch with a stored request already consumed the message. */
  if (rv != VAPI_OK && !callback_called
      && vapi_get_request_count (session->context) == 0)
    vapi_msg_free (session->context, message);
}

typedef struct {
  bool called, invalid;
  uint32_t code, worker, slot;
  uint64_t generation, incarnation;
  sakamoto_product_sni_status_t *out;
} sni_call_t;

typedef struct {
  bool called, invalid;
  uint32_t code;
  uint64_t generation;
  product_observation_status_t *out;
} observation_call_t;
static vapi_error_e observation_reply (vapi_ctx_t context, void *opaque, vapi_error_e rv,
  bool last, vapi_payload_product_core_observation_query_reply *reply)
{
  (void) context; (void) last;
  observation_call_t *call = opaque; call->called = true;
  if (rv != VAPI_OK || !reply) { call->invalid = true; return VAPI_OK; }
  if (reply->retval) { call->code = SAKAMOTO_PRODUCT_STALE_HANDLE; return VAPI_OK; }
  if (reply->generation != call->generation || reply->owners > 2
      || (reply->version != 0 && reply->version != PRODUCT_OBSERVATION_VERSION)
      || reply->flow_capacity > 65536 || reply->connected > 1) {
    call->invalid = true; return VAPI_OK;
  }
#define COPY(field) call->out->field = reply->field
  COPY (generation); COPY (mapping_bytes); COPY (version); COPY (owners);
  COPY (flow_capacity); COPY (connected);
  COPY (blocked_capacity);
  for (unsigned i = 0; i < PRODUCT_OBSERVATION_OWNERS; i++) {
    call->out->blocked_active[i] = reply->blocked_active[i];
    call->out->blocked_capacity_misses[i] = reply->blocked_capacity_misses[i];
    call->out->blocked_retired[i] = reply->blocked_retired[i];
  }
#undef COPY
  for (unsigned i = 0; i < PRODUCT_OBSERVATION_CHANNELS; i++) {
#define COPY(field) call->out->channels[i].field = reply->channels[i].field
    COPY (attempted); COPY (published); COPY (full); COPY (oversize); COPY (consumed);
    COPY (allocation_lost);
    COPY (notify_errors); COPY (pending); COPY (notifications); COPY (occupancy); COPY (capacity);
#undef COPY
    for (unsigned j = 0; j < 3; j++) {
      call->out->channels[i].basic_packets[j] = reply->channels[i].basic_packets[j];
      call->out->channels[i].basic_bytes[j] = reply->channels[i].basic_bytes[j];
    }
  }
  call->code = SAKAMOTO_PRODUCT_OK; return VAPI_OK;
}
uint32_t sakamoto_product_session_observation_query (sakamoto_product_session_t *session,
  uint64_t generation, product_observation_status_t *out)
{
  if (out) memset (out, 0, sizeof (*out));
  if (!session || !generation || !out) return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (pthread_mutex_lock (&session->mutex)) return SAKAMOTO_PRODUCT_INTERNAL_ERROR;
  uint32_t code = SAKAMOTO_PRODUCT_STALE_HANDLE;
  if (!session->connected || generation != session->generation) goto done;
  code = SAKAMOTO_PRODUCT_API_UNAVAILABLE;
  if (!vapi_is_msg_available (session->context, vapi_msg_id_product_core_observation_query)
      || !vapi_is_msg_available (session->context, vapi_msg_id_product_core_observation_query_reply)) goto done;
  vapi_msg_product_core_observation_query *message = vapi_alloc_product_core_observation_query (session->context);
  code = SAKAMOTO_PRODUCT_ALLOCATION_FAILED; if (!message) goto done;
  message->payload.generation = generation;
  observation_call_t call = { .code = SAKAMOTO_PRODUCT_QUERY_FAILED, .generation = generation, .out = out };
  vapi_error_e rv = vapi_product_core_observation_query (session->context, message, observation_reply, &call);
  release_unsent_request (session, rv, call.called, message);
  if (rv != VAPI_OK || !call.called || call.invalid) {
    session->connected = 0; memset (out, 0, sizeof (*out)); code = SAKAMOTO_PRODUCT_QUERY_FAILED;
  } else code = call.code;
done:
  (void) pthread_mutex_unlock (&session->mutex); return code;
}

typedef struct {
  bool called, invalid;
  uint32_t code, cursor;
  uint64_t generation;
  sakamoto_product_flow_page_t *out;
} flow_call_t;

static vapi_error_e flow_reply (vapi_ctx_t context, void *opaque, vapi_error_e rv,
  bool last, vapi_payload_product_core_flow_query_reply *reply)
{
  (void) context; (void) last;
  flow_call_t *call = opaque;
  call->called = true;
  if (rv != VAPI_OK || !reply) { call->invalid = true; return VAPI_OK; }
  if (reply->retval) {
    call->code = reply->retval == -1 ? SAKAMOTO_PRODUCT_INVALID_ARGUMENT
                                     : SAKAMOTO_PRODUCT_STALE_HANDLE;
    return VAPI_OK;
  }
  uint64_t total = (uint64_t)reply->capacity[0] + reply->capacity[1];
  if (reply->generation != call->generation || reply->cursor != call->cursor
      || reply->count > SAKAMOTO_FLOW_QUERY_PAGE
      || reply->scanned > SAKAMOTO_FLOW_QUERY_SCAN
      || reply->done > 1 || total > 131072
      || (uint64_t)call->cursor + reply->scanned > total
      || (reply->done ? reply->next_cursor != 0
                      : reply->next_cursor != call->cursor + reply->scanned
                        || reply->scanned == 0)
      || reply->count > reply->scanned) {
    call->invalid = true; return VAPI_OK;
  }
  sakamoto_product_flow_page_t *out = call->out;
  out->generation = reply->generation;
  out->cursor = reply->cursor; out->next_cursor = reply->next_cursor;
  out->scanned = reply->scanned; out->count = reply->count;
  out->done = reply->done;
  for (unsigned worker = 0; worker < 2; worker++) {
    out->allocated_bytes[worker] = reply->allocated_bytes[worker];
    out->capacity_misses[worker] = reply->capacity_misses[worker];
    out->capacity[worker] = reply->capacity[worker];
    out->active[worker] = reply->active[worker];
    out->high_watermark[worker] = reply->high_watermark[worker];
    if (out->active[worker] > out->capacity[worker]
        || out->high_watermark[worker] > out->capacity[worker]) {
      call->invalid = true; return VAPI_OK;
    }
  }
  for (unsigned i = 0; i < reply->count; i++) {
    const vapi_type_product_flow_query_entry *in = &reply->entries[i];
    sakamoto_product_flow_entry_t *entry = &out->entries[i];
    if (in->worker >= 2 || in->slot >= out->capacity[in->worker]
        || !in->incarnation || (in->family != 4 && in->family != 6)
        || in->protocols_available > 1 || (!in->protocols_available && in->protocols)
        || in->last_seen < in->first_seen) {
      call->invalid = true; return VAPI_OK;
    }
#define COPY_FLOW(field) entry->field = in->field
    COPY_FLOW (incarnation); COPY_FLOW (first_seen); COPY_FLOW (last_seen);
    COPY_FLOW (policy_generation); COPY_FLOW (policy_revision);
    COPY_FLOW (policy_hash); COPY_FLOW (winner); COPY_FLOW (protocols);
    COPY_FLOW (worker); COPY_FLOW (slot); COPY_FLOW (uid); COPY_FLOW (network);
    COPY_FLOW (query_class); COPY_FLOW (sni_result); COPY_FLOW (sni_stop);
    COPY_FLOW (lpi_stop); COPY_FLOW (family); COPY_FLOW (protocol);
    COPY_FLOW (kind); COPY_FLOW (origin_is_a);
    COPY_FLOW (flow_origin_direction); COPY_FLOW (last_device_direction);
    COPY_FLOW (last_flow_direction); COPY_FLOW (protocols_available);
#undef COPY_FLOW
    for (unsigned side = 0; side < 2; side++) {
      entry->packets[side] = in->packets[side];
      entry->bytes[side] = in->bytes[side];
      entry->ports[side] = in->ports[side];
    }
    memcpy(entry->addresses, in->addresses, sizeof entry->addresses);
    for (unsigned side = 0; side < 2; side++) {
      const vapi_type_product_flow_query_attribution *a = &in->attribution[side];
      product_observation_attribution_t *b = &entry->attribution[side];
      if (a->valid > 1 || a->protocols_available > 1
          || (!a->protocols_available && a->protocol_set)
          || !memchr (a->name, 0, sizeof a->name)) {
        call->invalid = true; return VAPI_OK;
      }
      b->segment = a->segment; b->start_packets = a->start_packets;
      b->start_bytes = a->start_bytes; b->activity_utc_us = a->activity_utc_us;
      b->policy_generation = a->policy_generation;
      b->policy_revision = a->policy_revision;
      b->policy_hash = a->policy_hash; b->winner = a->winner;
      b->uid = a->uid; b->network = a->network;
      b->declared_action = a->declared_action;
      b->actual_action = a->actual_action;
      b->mode = a->mode; b->valid = a->valid;
      memcpy (b->name, a->name, sizeof b->name);
      b->protocol_set = a->protocol_set;
      b->protocols_available = a->protocols_available;
    }
  }
  call->code = SAKAMOTO_PRODUCT_OK;
  return VAPI_OK;
}

uint32_t sakamoto_product_session_flow_query (sakamoto_product_session_t *session,
  uint64_t generation, uint32_t cursor, sakamoto_product_flow_page_t *out)
{
  if (out) memset (out, 0, sizeof (*out));
  if (!session || !generation || !out) return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (pthread_mutex_lock (&session->mutex)) return SAKAMOTO_PRODUCT_INTERNAL_ERROR;
  uint32_t code = SAKAMOTO_PRODUCT_STALE_HANDLE;
  if (!session->connected || generation != session->generation) goto done;
  code = SAKAMOTO_PRODUCT_API_UNAVAILABLE;
  if (!vapi_is_msg_available (session->context, vapi_msg_id_product_core_flow_query)
      || !vapi_is_msg_available (session->context, vapi_msg_id_product_core_flow_query_reply)) goto done;
  vapi_msg_product_core_flow_query *message = vapi_alloc_product_core_flow_query (session->context);
  code = SAKAMOTO_PRODUCT_ALLOCATION_FAILED;
  if (!message) goto done;
  message->payload.generation = generation;
  message->payload.cursor = cursor;
  flow_call_t call = {.code = SAKAMOTO_PRODUCT_QUERY_FAILED,
                      .generation = generation, .cursor = cursor, .out = out};
  vapi_error_e rv = vapi_product_core_flow_query (session->context, message, flow_reply, &call);
  release_unsent_request (session, rv, call.called, message);
  if (rv != VAPI_OK || !call.called || call.invalid) {
    session->connected = 0;
    memset (out, 0, sizeof (*out));
    code = SAKAMOTO_PRODUCT_QUERY_FAILED;
  } else code = call.code;
done:
  (void) pthread_mutex_unlock (&session->mutex);
  return code;
}

static vapi_error_e sni_reply(vapi_ctx_t context, void *opaque, vapi_error_e rv,
  bool last, vapi_payload_product_core_sni_query_reply *reply)
{
  (void)context;(void)last;
  sni_call_t *call=opaque;call->called=true;
  if(rv!=VAPI_OK || !reply) {call->invalid=true;return VAPI_OK;}
  if(reply->retval) {call->code=SAKAMOTO_PRODUCT_STALE_HANDLE;return VAPI_OK;}
  if(reply->generation!=call->generation || reply->incarnation!=call->incarnation
     || reply->worker!=call->worker || reply->slot!=call->slot
     || reply->result>2 || reply->stop>12 || reply->name_length>=254
     || (reply->result==1 ? !reply->name_length : reply->name_length!=0)
     || reply->name[reply->name_length]) {call->invalid=true;return VAPI_OK;}
#define COPY(field) call->out->field=reply->field
  COPY(generation);COPY(incarnation);COPY(protocols);COPY(worker);COPY(slot);
  COPY(result);COPY(stop);COPY(attempts);COPY(bytes);COPY(work);COPY(cache_bytes);
  COPY(name_length);COPY(protocols_available);
#undef COPY
  memcpy(call->out->name,reply->name,sizeof call->out->name);
  call->code=SAKAMOTO_PRODUCT_OK;return VAPI_OK;
}
uint32_t sakamoto_product_session_sni_query(sakamoto_product_session_t *session,
  uint64_t generation,uint32_t worker,uint32_t slot,uint64_t incarnation,
  sakamoto_product_sni_status_t *out)
{
  if(out) memset(out,0,sizeof *out);
  if(!session || !generation || !incarnation || !out) return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if(pthread_mutex_lock(&session->mutex)) return SAKAMOTO_PRODUCT_INTERNAL_ERROR;
  uint32_t code=SAKAMOTO_PRODUCT_STALE_HANDLE;
  if(!session->connected || generation!=session->generation) goto done;
  code=SAKAMOTO_PRODUCT_API_UNAVAILABLE;
  if(!vapi_is_msg_available(session->context,vapi_msg_id_product_core_sni_query)
     || !vapi_is_msg_available(session->context,vapi_msg_id_product_core_sni_query_reply)) goto done;
  vapi_msg_product_core_sni_query *message=vapi_alloc_product_core_sni_query(session->context);
  code=SAKAMOTO_PRODUCT_ALLOCATION_FAILED;if(!message) goto done;
  message->payload.generation=generation;message->payload.incarnation=incarnation;
  message->payload.worker=worker;message->payload.slot=slot;
  sni_call_t call={.code=SAKAMOTO_PRODUCT_QUERY_FAILED,.worker=worker,.slot=slot,
    .generation=generation,.incarnation=incarnation,.out=out};
  vapi_error_e rv=vapi_product_core_sni_query(session->context,message,sni_reply,&call);
  release_unsent_request(session,rv,call.called,message);
  if(rv!=VAPI_OK || !call.called || call.invalid) {
    session->connected=0;memset(out,0,sizeof *out);code=SAKAMOTO_PRODUCT_QUERY_FAILED;
  } else code=call.code;
done:
  (void)pthread_mutex_unlock(&session->mutex);return code;
}

typedef struct {
  bool called;
  bool invalid_reply;
  uint32_t code;
  uint64_t generation;
  sakamoto_product_rule_config_status_t *status;
} rule_config_call_t;

static vapi_error_e
rule_config_reply (vapi_ctx_t context, void *opaque, vapi_error_e rv,
                   bool is_last, vapi_payload_product_core_rule_config_reply *reply)
{
  (void) context; (void) is_last;
  rule_config_call_t *call = opaque;
  call->called = true;
  if (rv != VAPI_OK || !reply)
    { call->invalid_reply = true; call->code = SAKAMOTO_PRODUCT_INTERNAL_ERROR; }
  else if (reply->generation != call->generation || reply->retval == -5)
    call->code = SAKAMOTO_PRODUCT_STALE_HANDLE;
  else if (reply->retval) call->code = SAKAMOTO_PRODUCT_PROTOCOL_MISMATCH;
  else
    {
      sakamoto_product_rule_config_status_t *s = call->status;
      s->generation = reply->generation;
      s->saved_revision = reply->saved_revision;
      s->active_revision = reply->active_revision;
      s->saved_rule_version = reply->saved_rule_version;
      s->active_rule_version = reply->active_rule_version;
      s->result = reply->result;
      s->save_error = reply->save_error;
      s->compile_error = reply->compile_error;
#define COPY_RULE(field) s->rule.field = reply->rule.field
      COPY_RULE (present); COPY_RULE (uid); COPY_RULE (protocol); COPY_RULE (direction);
      COPY_RULE (action); COPY_RULE (source_port); COPY_RULE (destination_port); COPY_RULE (reserved);
#undef COPY_RULE
      memcpy (s->rule.source_address, reply->rule.source_address, 4);
      memcpy (s->rule.destination_address, reply->rule.destination_address, 4);
      if (reply->count > SAKAMOTO_RULE_CONFIG_MAX_RULES || reply->active_count > SAKAMOTO_RULE_CONFIG_MAX_RULES ||
          reply->graph.group_count > SAKAMOTO_RULE_CONFIG_MAX_GROUPS || reply->graph.edge_count > SAKAMOTO_RULE_CONFIG_MAX_EDGES || reply->graph.binding_count > SAKAMOTO_RULE_CONFIG_MAX_BINDINGS ||
          reply->domains.list_count > SAKAMOTO_DOMAIN_MAX_LISTS || reply->domains.entry_count > SAKAMOTO_DOMAIN_MAX_ENTRIES)
        { call->invalid_reply = true; call->code = SAKAMOTO_PRODUCT_PROTOCOL_MISMATCH; return VAPI_OK; }
      s->count = reply->count; s->active_count = reply->active_count;
      s->error_index = reply->error_index; s->compiler_status = reply->compiler_status;
      for (unsigned i = 0; i < s->count; ++i)
        {
          s->rules[i].version = reply->rules[i].version;
          s->rules[i].base_version = reply->rules[i].base_version;
          s->rules[i].uid = reply->rules[i].uid;
          s->rules[i].network_context = reply->rules[i].network_context;
          s->rules[i].ifindex = reply->rules[i].ifindex;
          s->rules[i].priority = reply->rules[i].priority;
          s->rules[i].order = reply->rules[i].order;
          s->rules[i].family = reply->rules[i].family;
          s->rules[i].protocol = reply->rules[i].protocol;
          s->rules[i].direction = reply->rules[i].direction;
          s->rules[i].action = reply->rules[i].action;
          s->rules[i].source_prefix = reply->rules[i].source_prefix;
          s->rules[i].destination_prefix = reply->rules[i].destination_prefix;
          s->rules[i].source_port_first = reply->rules[i].source_port_first;
          s->rules[i].source_port_last = reply->rules[i].source_port_last;
          s->rules[i].destination_port_first = reply->rules[i].destination_port_first;
          s->rules[i].destination_port_last = reply->rules[i].destination_port_last;
          s->rules[i].reserved = reply->rules[i].reserved;
          s->rules[i].expression_length = reply->rules[i].expression_length;
          memcpy(s->rules[i].expression, reply->rules[i].expression, 64);
          memcpy (s->rules[i].source_address, reply->rules[i].source_address, 16);
          memcpy (s->rules[i].destination_address, reply->rules[i].destination_address, 16);
        }
      s->graph.group_count = reply->graph.group_count;
      s->graph.edge_count = reply->graph.edge_count;
      s->graph.binding_count = reply->graph.binding_count;
      for (unsigned i = 0; i < s->graph.group_count && i < SAKAMOTO_RULE_CONFIG_MAX_GROUPS; ++i) {
      s->graph.groups[i] = reply->graph.groups[i];
      }
      for (unsigned i = 0; i < s->graph.edge_count && i < SAKAMOTO_RULE_CONFIG_MAX_EDGES; ++i) {
      s->graph.edges[i].group = reply->graph.edges[i].group;
      s->graph.edges[i].kind = reply->graph.edges[i].kind;
      s->graph.edges[i].target = reply->graph.edges[i].target;
      }
      for (unsigned i = 0; i < s->graph.binding_count && i < SAKAMOTO_RULE_CONFIG_MAX_BINDINGS; ++i) {
      s->graph.bindings[i].id = reply->graph.bindings[i].id;
      s->graph.bindings[i].uid = reply->graph.bindings[i].uid;
      s->graph.bindings[i].kind = reply->graph.bindings[i].kind;
      s->graph.bindings[i].target = reply->graph.bindings[i].target;
      s->graph.bindings[i].mode = reply->graph.bindings[i].mode;
      }
      s->domains.list_count = reply->domains.list_count;
      _Static_assert(sizeof s->metadata == sizeof reply->metadata, "metadata wire layout");
      memcpy (&s->metadata, &reply->metadata, sizeof s->metadata);
      s->domains.entry_count = reply->domains.entry_count;
      for (unsigned i = 0; i < s->domains.entry_count; ++i) {
        if (reply->domains.entries[i].list >= s->domains.list_count ||
            reply->domains.entries[i].mode > 1 || reply->domains.entries[i].length > 253) {
          call->invalid_reply = true; call->code = SAKAMOTO_PRODUCT_PROTOCOL_MISMATCH; return VAPI_OK;
        }
        s->domains.entries[i].list = reply->domains.entries[i].list;
        s->domains.entries[i].mode = reply->domains.entries[i].mode;
        s->domains.entries[i].length = reply->domains.entries[i].length;
        memcpy(s->domains.entries[i].name, reply->domains.entries[i].name, SAKAMOTO_DOMAIN_NAME_BYTES);
      }
      for (unsigned i = 0; i < s->active_count; ++i) s->active_versions[i] = reply->active_versions[i];
      call->code = SAKAMOTO_PRODUCT_OK;
    }
  return VAPI_OK;
}

uint32_t
sakamoto_product_session_rule_config (
  sakamoto_product_session_t *session, uint64_t generation,
  const sakamoto_product_rule_config_request_t *request,
  sakamoto_product_rule_config_status_t *status)
{
  if (status) memset (status, 0, sizeof (*status));
  if (!session || !generation || !request || !status || request->count > SAKAMOTO_RULE_CONFIG_MAX_RULES ||
      request->graph.group_count > SAKAMOTO_RULE_CONFIG_MAX_GROUPS || request->graph.edge_count > SAKAMOTO_RULE_CONFIG_MAX_EDGES || request->graph.binding_count > SAKAMOTO_RULE_CONFIG_MAX_BINDINGS ||
      request->domains.list_count > SAKAMOTO_DOMAIN_MAX_LISTS || request->domains.entry_count > SAKAMOTO_DOMAIN_MAX_ENTRIES)
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (pthread_mutex_lock (&session->mutex) != 0) return SAKAMOTO_PRODUCT_INTERNAL_ERROR;
  uint32_t code = SAKAMOTO_PRODUCT_STALE_HANDLE;
  if (!session->connected || session->generation != generation) goto done;
  code = SAKAMOTO_PRODUCT_API_UNAVAILABLE;
  if (!vapi_is_msg_available (session->context, vapi_msg_id_product_core_rule_config)
      || !vapi_is_msg_available (session->context, vapi_msg_id_product_core_rule_config_reply))
    goto done;
  vapi_msg_product_core_rule_config *message = vapi_alloc_product_core_rule_config (session->context);
  code = SAKAMOTO_PRODUCT_ALLOCATION_FAILED;
  if (!message) goto done;
  message->payload.generation = generation;
  message->payload.schema = request->schema;
  message->payload.operation = request->operation;
  message->payload.expected_saved_revision = request->expected_saved_revision;
#define COPY_RULE(field) message->payload.rule.field = request->rule.field
  COPY_RULE (present); COPY_RULE (uid); COPY_RULE (protocol); COPY_RULE (direction);
  COPY_RULE (action); COPY_RULE (source_port); COPY_RULE (destination_port); COPY_RULE (reserved);
#undef COPY_RULE
  memcpy (message->payload.rule.source_address, request->rule.source_address, 4);
  memcpy (message->payload.rule.destination_address, request->rule.destination_address, 4);
  message->payload.count = request->count; message->payload.reserved = request->reserved;
  for (unsigned i = 0; i < request->count; ++i)
    {
      message->payload.rules[i].version = request->rules[i].version;
      message->payload.rules[i].base_version = request->rules[i].base_version;
      message->payload.rules[i].uid = request->rules[i].uid;
      message->payload.rules[i].network_context = request->rules[i].network_context;
      message->payload.rules[i].ifindex = request->rules[i].ifindex;
      message->payload.rules[i].priority = request->rules[i].priority;
      message->payload.rules[i].order = request->rules[i].order;
      message->payload.rules[i].family = request->rules[i].family;
      message->payload.rules[i].protocol = request->rules[i].protocol;
      message->payload.rules[i].direction = request->rules[i].direction;
      message->payload.rules[i].action = request->rules[i].action;
      message->payload.rules[i].source_prefix = request->rules[i].source_prefix;
      message->payload.rules[i].destination_prefix = request->rules[i].destination_prefix;
      message->payload.rules[i].source_port_first = request->rules[i].source_port_first;
      message->payload.rules[i].source_port_last = request->rules[i].source_port_last;
      message->payload.rules[i].destination_port_first = request->rules[i].destination_port_first;
      message->payload.rules[i].destination_port_last = request->rules[i].destination_port_last;
      message->payload.rules[i].reserved = request->rules[i].reserved;
      message->payload.rules[i].expression_length = request->rules[i].expression_length;
      memcpy(message->payload.rules[i].expression, request->rules[i].expression, 64);
      memcpy (message->payload.rules[i].source_address, request->rules[i].source_address, 16);
      memcpy (message->payload.rules[i].destination_address, request->rules[i].destination_address, 16);
    }
  message->payload.graph.group_count = request->graph.group_count;
  message->payload.graph.edge_count = request->graph.edge_count;
  message->payload.graph.binding_count = request->graph.binding_count;
  for (unsigned i = 0; i < message->payload.graph.group_count && i < SAKAMOTO_RULE_CONFIG_MAX_GROUPS; ++i) {
    message->payload.graph.groups[i] = request->graph.groups[i];
  }
  for (unsigned i = 0; i < message->payload.graph.edge_count && i < SAKAMOTO_RULE_CONFIG_MAX_EDGES; ++i) {
    message->payload.graph.edges[i].group = request->graph.edges[i].group;
    message->payload.graph.edges[i].kind = request->graph.edges[i].kind;
    message->payload.graph.edges[i].target = request->graph.edges[i].target;
  }
  for (unsigned i = 0; i < message->payload.graph.binding_count && i < SAKAMOTO_RULE_CONFIG_MAX_BINDINGS; ++i) {
    message->payload.graph.bindings[i].id = request->graph.bindings[i].id;
    message->payload.graph.bindings[i].uid = request->graph.bindings[i].uid;
    message->payload.graph.bindings[i].kind = request->graph.bindings[i].kind;
    message->payload.graph.bindings[i].target = request->graph.bindings[i].target;
    message->payload.graph.bindings[i].mode = request->graph.bindings[i].mode;
  }
  message->payload.domains.list_count = request->domains.list_count;
  _Static_assert(sizeof request->metadata == sizeof message->payload.metadata, "metadata wire layout");
  memcpy (&message->payload.metadata, &request->metadata, sizeof request->metadata);
  message->payload.domains.entry_count = request->domains.entry_count;
  for (unsigned i = 0; i < request->domains.entry_count; ++i) {
    message->payload.domains.entries[i].list = request->domains.entries[i].list;
    message->payload.domains.entries[i].mode = request->domains.entries[i].mode;
    message->payload.domains.entries[i].length = request->domains.entries[i].length;
    memcpy(message->payload.domains.entries[i].name, request->domains.entries[i].name, SAKAMOTO_DOMAIN_NAME_BYTES);
  }
  rule_config_call_t call = { .generation = generation, .status = status,
                             .code = SAKAMOTO_PRODUCT_INTERNAL_ERROR };
  vapi_error_e rv = vapi_product_core_rule_config (session->context, message, rule_config_reply, &call);
  release_unsent_request (session, rv, call.called, message);
  /* Never let a stack callback survive a failed dispatch; never replay a
   * mutation. The next generation/session queries VPP's saved/active state. */
  if (rv != VAPI_OK || !call.called || call.invalid_reply
      || call.code == SAKAMOTO_PRODUCT_STALE_HANDLE) session->connected = 0;
  code = rv == VAPI_OK && call.called && !call.invalid_reply ? call.code
    : request->operation != SAKAMOTO_RULE_CONFIG_QUERY
      ? SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN : SAKAMOTO_PRODUCT_QUERY_FAILED;
done:
  (void) pthread_mutex_unlock (&session->mutex);
  return code;
}

static vapi_error_e
network_publish_reply (vapi_ctx_t context, void *opaque, vapi_error_e rv,
                       bool is_last,
                       vapi_payload_product_core_network_publish_reply *reply)
{
  (void) context;
  (void) is_last;
  network_call_t *call = opaque;
  call->called = true;
  call->code = rv == VAPI_OK && reply && reply->retval == 0
    ? SAKAMOTO_PRODUCT_OK : SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  return VAPI_OK;
}

uint32_t
sakamoto_product_session_publish_network (
  sakamoto_product_session_t *session, uint64_t generation,
  const sakamoto_product_network_snapshot_t *snapshot)
{
  if (!session || !snapshot || !generation || !snapshot->revision
      || snapshot->reserved
      || snapshot->count > SAKAMOTO_PRODUCT_NETWORK_MAX_INTERFACES)
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (pthread_mutex_lock (&session->mutex) != 0)
    return SAKAMOTO_PRODUCT_INTERNAL_ERROR;
  uint32_t code = SAKAMOTO_PRODUCT_STALE_HANDLE;
  if (!session->connected || session->generation != generation) goto done;
  code = SAKAMOTO_PRODUCT_API_UNAVAILABLE;
  if (!vapi_is_msg_available (session->context,
                             vapi_msg_id_product_core_network_publish)
      || !vapi_is_msg_available (session->context,
                                vapi_msg_id_product_core_network_publish_reply))
    goto done;
  vapi_msg_product_core_network_publish *message =
    vapi_alloc_product_core_network_publish (session->context);
  code = SAKAMOTO_PRODUCT_ALLOCATION_FAILED;
  if (!message) goto done;
  message->payload.generation = generation;
  message->payload.revision = snapshot->revision;
  message->payload.event_elapsed_ns = snapshot->event_elapsed_ns;
  message->payload.count = snapshot->count;
  message->payload.reserved = snapshot->reserved;
  for (uint32_t i = 0; i < SAKAMOTO_PRODUCT_NETWORK_MAX_INTERFACES; ++i)
    {
      message->payload.entries[i].linux_ifindex = snapshot->entries[i].linux_ifindex;
      message->payload.entries[i].network_context = snapshot->entries[i].context;
    }
  network_call_t call = { .called = false, .code = SAKAMOTO_PRODUCT_INTERNAL_ERROR };
  vapi_error_e rv = vapi_product_core_network_publish (
    session->context, message, network_publish_reply, &call);
  release_unsent_request (session, rv, call.called, message);
  /* A failed blocking dispatch can leave its stack callback registered.
   * Fence all further requests before that callback storage goes out of
   * scope. The UDS disconnect path drains without dispatching callbacks;
   * explicit close still owns the context and its outstanding request. */
  if (rv != VAPI_OK || !call.called) session->connected = 0;
  code = rv == VAPI_OK && call.called ? call.code : SAKAMOTO_PRODUCT_INTERNAL_ERROR;
done:
  (void) pthread_mutex_unlock (&session->mutex);
  return code;
}

typedef struct {
  bool called;
  uint64_t generation;
  uint32_t stopped;
  uint32_t code;
} root_stop_call_t;

static vapi_error_e
root_stop_reply (vapi_ctx_t context, void *opaque, vapi_error_e rv,
                 bool is_last, vapi_payload_product_core_root_stop_reply *reply)
{
  (void) context;
  (void) is_last;
  root_stop_call_t *call = opaque;
  call->called = true;
  if (rv != VAPI_OK || !reply)
    call->code = SAKAMOTO_PRODUCT_INTERNAL_ERROR;
  else if (reply->generation != call->generation)
    call->code = SAKAMOTO_PRODUCT_STALE_HANDLE;
  else if (reply->retval != 0 || reply->stopped > 1)
    call->code = SAKAMOTO_PRODUCT_PROTOCOL_MISMATCH;
  else
    {
      call->code = SAKAMOTO_PRODUCT_OK;
      call->stopped = reply->stopped;
    }
  return VAPI_OK;
}

uint32_t
sakamoto_product_session_stop_root (sakamoto_product_session_t *session,
                                     uint64_t generation, uint32_t *out_stopped)
{
  if (out_stopped) *out_stopped = 0;
  if (!session || !generation || !out_stopped)
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (pthread_mutex_lock (&session->mutex) != 0)
    return SAKAMOTO_PRODUCT_INTERNAL_ERROR;
  uint32_t code = SAKAMOTO_PRODUCT_STALE_HANDLE;
  if (!session->connected || generation != session->generation) goto done;
  code = SAKAMOTO_PRODUCT_API_UNAVAILABLE;
  if (!vapi_is_msg_available (session->context, vapi_msg_id_product_core_root_stop)
      || !vapi_is_msg_available (session->context,
                                vapi_msg_id_product_core_root_stop_reply))
    goto done;
  vapi_msg_product_core_root_stop *message =
    vapi_alloc_product_core_root_stop (session->context);
  code = SAKAMOTO_PRODUCT_ALLOCATION_FAILED;
  if (!message) goto done;
  message->payload.generation = generation;
  root_stop_call_t call = { .generation = generation,
                            .code = SAKAMOTO_PRODUCT_INTERNAL_ERROR };
  vapi_error_e rv = vapi_product_core_root_stop (
    session->context, message, root_stop_reply, &call);
  release_unsent_request (session, rv, call.called, message);
  /* As with status/network callbacks, an incomplete dispatch must fence the
   * context before this stack callback retires. No retry on that context. */
  if (rv != VAPI_OK || !call.called) session->connected = 0;
  code = rv == VAPI_OK && call.called ? call.code : SAKAMOTO_PRODUCT_INTERNAL_ERROR;
  if (code == SAKAMOTO_PRODUCT_OK) *out_stopped = call.stopped;
done:
  (void) pthread_mutex_unlock (&session->mutex);
  return code;
}

static bool
product_core_api_available (vapi_ctx_t context)
{
  return vapi_is_msg_available (context, vapi_msg_id_product_core_status)
         && vapi_is_msg_available (context,
                                   vapi_msg_id_product_core_status_reply)
         && vapi_is_msg_available (context,
                                   vapi_msg_id_product_core_policy_apply)
         && vapi_is_msg_available (
           context, vapi_msg_id_product_core_policy_apply_reply);
}

static bool
product_core_policy_bundle_api_available (vapi_ctx_t context)
{
  return product_core_api_available (context)
         && vapi_is_msg_available (
           context, vapi_msg_id_product_core_policy_bundle_apply)
         && vapi_is_msg_available (
           context, vapi_msg_id_product_core_policy_bundle_apply_reply);
}

static bool
policy_bundle_identity_valid (const sakamoto_product_policy_bundle_t *bundle)
{
  size_t length = 0U;
  while (length < SAKAMOTO_PRODUCT_POLICY_IDENTITY_MAX
         && bundle->snapshot_identity[length] != '\0')
    ++length;
  if (length == 0U || length == SAKAMOTO_PRODUCT_POLICY_IDENTITY_MAX)
    return false;
  for (size_t index = length + 1U;
       index < SAKAMOTO_PRODUCT_POLICY_IDENTITY_MAX; ++index)
    if (bundle->snapshot_identity[index] != '\0')
      return false;
  for (size_t index = 0U; index < length; ++index)
    if (bundle->snapshot_identity[index] == '\n'
        || bundle->snapshot_identity[index] == '\r'
        || bundle->snapshot_identity[index] == '=')
      return false;
  return true;
}

static bool
policy_bundle_rule_valid (const sakamoto_product_policy_rule_entry_t *entry,
                          uint32_t kind)
{
  if (entry->subject_uid == UINT32_MAX || entry->network_context == 0U
      || entry->rule_kind != kind
      || (entry->action != SAKAMOTO_PRODUCT_POLICY_ACTION_PASS_NEXT
          && entry->action != SAKAMOTO_PRODUCT_POLICY_ACTION_DROP)
      || entry->enabled > 1U || entry->rule_id == 0U
      || entry->reason_id == 0U || entry->reserved != 0U)
    return false;
  if (kind == SAKAMOTO_PRODUCT_POLICY_RULE_KIND_GATE)
    {
      sakamoto_product_policy_rule_entry_t zero = {0};
      return entry->ip_family == 0U && entry->ip_protocol == 0U
        && entry->direction == 0U && entry->source_prefix_len == 0U
        && entry->destination_prefix_len == 0U
        && entry->source_port_first == 0U && entry->source_port_last == 0U
        && entry->destination_port_first == 0U
        && entry->destination_port_last == 0U && entry->priority == 0U
        && entry->order == 0U
        && memcmp (entry->source_address, zero.source_address,
                   sizeof entry->source_address) == 0
        && memcmp (entry->destination_address, zero.destination_address,
                   sizeof entry->destination_address) == 0;
    }
  uint32_t max_prefix = entry->ip_family
    == SAKAMOTO_PRODUCT_POLICY_IP_FAMILY_IPV4 ? 32U : 128U;
  if (entry->ip_family == SAKAMOTO_PRODUCT_POLICY_IP_FAMILY_IPV4)
    for (size_t index = 4U; index < 16U; ++index)
      if (entry->source_address[index] != 0U
          || entry->destination_address[index] != 0U)
        return false;
  return (entry->ip_family == SAKAMOTO_PRODUCT_POLICY_IP_FAMILY_IPV4
          || entry->ip_family == SAKAMOTO_PRODUCT_POLICY_IP_FAMILY_IPV6)
    && (entry->ip_protocol == SAKAMOTO_PRODUCT_POLICY_IP_PROTOCOL_TCP
        || entry->ip_protocol == SAKAMOTO_PRODUCT_POLICY_IP_PROTOCOL_UDP)
    && (entry->direction == SAKAMOTO_PRODUCT_POLICY_DIRECTION_INPUT
        || entry->direction == SAKAMOTO_PRODUCT_POLICY_DIRECTION_OUTPUT)
    && entry->source_prefix_len <= max_prefix
    && entry->destination_prefix_len <= max_prefix
    && entry->source_port_first <= entry->source_port_last
    && entry->destination_port_first <= entry->destination_port_last
    && entry->source_port_last <= UINT16_MAX
    && entry->destination_port_last <= UINT16_MAX;
}

static bool
policy_bundle_valid (const sakamoto_product_policy_bundle_t *bundle)
{
  if (bundle->abi_version != SAKAMOTO_PRODUCT_POLICY_BUNDLE_ABI_VERSION
      || bundle->struct_size != sizeof (*bundle)
      || bundle->requested_revision == 0U || bundle->snapshot_hash == 0U
      || bundle->gate_entry_count
           > SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_GATE_ENTRIES
      || bundle->l4_rule_count
           > SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_L4_ENTRIES
      || bundle->gate_entry_count + bundle->l4_rule_count
           > SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_RULE_ENTRIES
      || bundle->default_pass > 1U || bundle->reserved != 0U
      || !policy_bundle_identity_valid (bundle))
    return false;
  sakamoto_product_policy_rule_entry_t zero = {0};
  uint64_t rule_ids[SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_RULE_ENTRIES];
  uint32_t rule_id_count = 0U;
  for (uint32_t index = 0U;
       index < SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_GATE_ENTRIES; ++index)
    {
      const sakamoto_product_policy_rule_entry_t *entry =
        &bundle->gate_entries[index];
      if (index < bundle->gate_entry_count)
        {
          if (!policy_bundle_rule_valid (entry,
                                         SAKAMOTO_PRODUCT_POLICY_RULE_KIND_GATE))
            return false;
          for (uint32_t prior = 0U; prior < rule_id_count; ++prior)
            if (rule_ids[prior] == entry->rule_id)
              return false;
          rule_ids[rule_id_count++] = entry->rule_id;
        }
      else if (memcmp (entry, &zero, sizeof zero) != 0)
        return false;
    }
  for (uint32_t index = 0U;
       index < SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_L4_ENTRIES; ++index)
    {
      const sakamoto_product_policy_rule_entry_t *entry =
        &bundle->l4_entries[index];
      if (index < bundle->l4_rule_count)
        {
          if (!policy_bundle_rule_valid (entry,
                                         SAKAMOTO_PRODUCT_POLICY_RULE_KIND_L4))
            return false;
          for (uint32_t prior = 0U; prior < rule_id_count; ++prior)
            if (rule_ids[prior] == entry->rule_id)
              return false;
          rule_ids[rule_id_count++] = entry->rule_id;
        }
      else if (memcmp (entry, &zero, sizeof zero) != 0)
        return false;
    }
  return true;
}

static vapi_error_e
status_reply (vapi_ctx_t context, void *callback_context, vapi_error_e rv,
              bool is_last, vapi_payload_product_core_status_reply *reply)
{
  (void) context;
  (void) is_last;
  status_call_t *call = callback_context;
  if (call == NULL)
    return VAPI_EINVAL;
  call->callback_called = true;
  if (rv != VAPI_OK || reply == NULL)
    {
      const char *detail = rv != VAPI_OK
        ? "VAPI status callback failed"
        : "VAPI status callback returned a null reply";
      call->transport_code = SAKAMOTO_PRODUCT_QUERY_FAILED;
      sakamoto_product_status_error (call->status, call->transport_code,
                                     detail);
      return VAPI_OK;
    }
  call->status->status_code = SAKAMOTO_PRODUCT_OK;
  call->status->abi_version = reply->abi_version;
  call->status->api_version = reply->api_version;
  call->status->generation = reply->generation;
  call->status->core_ready = reply->core_ready != 0;
  call->status->adapter_available = reply->adapter_available != 0;
  call->status->protection_running = reply->protection_running != 0;
  call->status->root_nfqueue_queue_id = reply->root_nfqueue_queue_id;
  call->status->root_nfqueue_queue_last = reply->root_nfqueue_queue_last;
  call->status->root_nfqueue_lane_count = reply->root_nfqueue_lane_count;
  call->status->root_nfqueue_ready_lane_mask =
    reply->root_nfqueue_ready_lane_mask;
  call->status->root_nfqueue_generation = reply->root_nfqueue_generation;
  call->status->root_nfqueue_verdict_attempts =
    reply->root_nfqueue_verdict_attempts;
  call->status->root_nfqueue_internal_settlements =
    reply->root_nfqueue_internal_settlements;
  call->status->root_nfqueue_buffer_returns =
    reply->root_nfqueue_buffer_returns;
  call->status->root_nfqueue_origin_local_completions =
    reply->root_nfqueue_origin_local_completions;
  call->status->root_nfqueue_origin_remote_completions =
    reply->root_nfqueue_origin_remote_completions;
  call->status->root_nfqueue_lane0_verdict_attempts =
    reply->root_nfqueue_lane0_verdict_attempts;
  call->status->root_nfqueue_lane1_verdict_attempts =
    reply->root_nfqueue_lane1_verdict_attempts;
  call->status->root_nfqueue_input_packets =
    reply->root_nfqueue_input_packets;
  call->status->root_nfqueue_output_packets =
    reply->root_nfqueue_output_packets;
  call->status->root_nfqueue_ipv4_packets =
    reply->root_nfqueue_ipv4_packets;
  call->status->root_nfqueue_ipv6_packets =
    reply->root_nfqueue_ipv6_packets;
  call->status->root_nfqueue_tcp_packets = reply->root_nfqueue_tcp_packets;
  call->status->root_nfqueue_udp_packets = reply->root_nfqueue_udp_packets;
  call->status->root_nfqueue_uid_known_packets =
    reply->root_nfqueue_uid_known_packets;
  call->status->root_nfqueue_uid_unknown_packets =
    reply->root_nfqueue_uid_unknown_packets;
  call->status->root_nfqueue_last_ip_family =
    reply->root_nfqueue_last_ip_family;
  call->status->root_nfqueue_last_protocol =
    reply->root_nfqueue_last_protocol;
  call->status->root_nfqueue_last_hook = reply->root_nfqueue_last_hook;
  call->status->root_nfqueue_last_uid_known =
    reply->root_nfqueue_last_uid_known;
  call->status->root_nfqueue_last_uid = reply->root_nfqueue_last_uid;
  call->status->root_nfqueue_last_queue_id =
    reply->root_nfqueue_last_queue_id;
  call->status->root_nfqueue_last_packet_id =
    reply->root_nfqueue_last_packet_id;
  call->status->root_nfqueue_verdict_succeeded =
    reply->root_nfqueue_verdict_succeeded;
  call->status->root_nfqueue_verdict_failed_definite =
    reply->root_nfqueue_verdict_failed_definite;
  call->status->root_nfqueue_verdict_outcome_unknown =
    reply->root_nfqueue_verdict_outcome_unknown;
  call->status->root_nfqueue_ingress_identity_missing =
    reply->root_nfqueue_ingress_identity_missing;
  call->status->root_nfqueue_graph_submit_fail_opens =
    reply->root_nfqueue_graph_submit_fail_opens;
  call->status->root_nfqueue_non_owner_bypasses =
    reply->root_nfqueue_non_owner_bypasses;
  call->status->root_nfqueue_duplicate_completion_drops =
    reply->root_nfqueue_duplicate_completion_drops;
  call->status->root_nfqueue_stale_completion_drops =
    reply->root_nfqueue_stale_completion_drops;
  call->status->vpn_tun_fd_attached = reply->vpn_tun_fd_attached;
  call->status->vpn_direct_udp4_socket_attached =
    reply->vpn_direct_udp4_socket_attached;
  call->status->vpn_direct_udp4_protect_succeeded =
    reply->vpn_direct_udp4_protect_succeeded;
  call->status->vpn_direct_udp4_bind_succeeded =
    reply->vpn_direct_udp4_bind_succeeded;
  call->status->vpn_tun_ingress_packets =
    reply->vpn_tun_ingress_packets;
  call->status->vpn_tun_udp4_tun_origin_packets =
    reply->vpn_tun_udp4_tun_origin_packets;
  call->status->vpn_flow_stack_admissions =
    reply->vpn_flow_stack_admissions;
  call->status->vpn_direct_udp4_send_succeeded =
    reply->vpn_direct_udp4_send_succeeded;
  call->status->vpn_direct_udp4_transport_failed =
    reply->vpn_direct_udp4_transport_failed;
  call->status->vpn_flow_stack_return_packets =
    reply->vpn_flow_stack_return_packets;
  call->status->vpn_flow_stack_return_provenance_packets =
    reply->vpn_flow_stack_return_provenance_packets;
  call->status->vpn_tun_write_completions =
    reply->vpn_tun_write_completions;
  call->status->vpn_infrastructure_faults =
    reply->vpn_infrastructure_faults;
  call->status->vpn_duplicate_or_stale_drops =
    reply->vpn_duplicate_or_stale_drops;
  call->status->product_graph_worker_count =
    reply->product_graph_worker_count;
  call->status->product_graph_hash_seed =
    reply->product_graph_hash_seed;
  call->status->product_graph_handoff_credits =
    reply->product_graph_handoff_credits;
  call->status->product_graph_vpp_worker_count =
    reply->product_graph_vpp_worker_count;
  call->status->product_graph_vpp_main_core =
    reply->product_graph_vpp_main_core;
  call->status->product_graph_vpp_worker0_thread_index =
    reply->product_graph_vpp_worker0_thread_index;
  call->status->product_graph_vpp_worker0_core =
    reply->product_graph_vpp_worker0_core;
  call->status->product_graph_vpp_worker1_thread_index =
    reply->product_graph_vpp_worker1_thread_index;
  call->status->product_graph_vpp_worker1_core =
    reply->product_graph_vpp_worker1_core;
  call->status->product_graph_enabled = reply->product_graph_enabled;
  call->status->product_graph_accepting = reply->product_graph_accepting;
  call->status->product_graph_worker_layout_ready =
    reply->product_graph_worker_layout_ready;
  call->status->product_graph_obligation_debt =
    reply->product_graph_obligation_debt;
  call->status->product_graph_buffer_debt =
    reply->product_graph_buffer_debt;
  call->status->product_graph_handoff_debt =
    reply->product_graph_handoff_debt;
  call->status->policy_requested_revision =
    reply->policy_requested_revision;
  call->status->policy_active_revision = reply->policy_active_revision;
  call->status->policy_generation = reply->policy_generation;
  call->status->policy_snapshot_hash = reply->policy_snapshot_hash;
  call->status->policy_worker0_revision = reply->policy_worker0_revision;
  call->status->policy_worker1_revision = reply->policy_worker1_revision;
  call->status->policy_snapshot_empty = reply->policy_snapshot_empty;
  call->status->policy_default_pass = reply->policy_default_pass;
  call->status->policy_gate_claim_count = reply->policy_gate_claim_count;
  call->status->policy_l4_rule_count = reply->policy_l4_rule_count;
  call->status->policy_last_apply_status_code =
    reply->policy_last_apply_status_code;
  call->status->policy_mixed_revision = reply->policy_mixed_revision;
  call->status->policy_artifact_match = reply->policy_artifact_match;
  call->status->policy_generation_match = reply->policy_generation_match;
  call->status->policy_gate_subject_uid = reply->policy_gate_subject_uid;
  call->status->policy_gate_network_context =
    reply->policy_gate_network_context;
  call->status->policy_gate_blocked = reply->policy_gate_blocked;
  call->status->policy_gate_reason_id = reply->policy_gate_reason_id;
  call->status->policy_gate_rule_id = reply->policy_gate_rule_id;
  call->status->policy_drop_records = reply->policy_drop_records;
  call->status->policy_last_drop_revision = reply->policy_last_drop_revision;
  call->status->policy_last_drop_rule_id = reply->policy_last_drop_rule_id;
  call->status->policy_last_drop_completion_attempts =
    reply->policy_last_drop_completion_attempts;
  call->status->policy_last_drop_uid = reply->policy_last_drop_uid;
  call->status->policy_last_drop_network_context =
    reply->policy_last_drop_network_context;
  call->status->policy_last_drop_reason_id = reply->policy_last_drop_reason_id;
  call->status->policy_last_drop_verdict = reply->policy_last_drop_verdict;
  call->status->policy_last_drop_winner = reply->policy_last_drop_winner;
  call->status->policy_last_drop_uid_known =
    reply->policy_last_drop_uid_known;
  call->status->policy_last_drop_device_direction =
    reply->policy_last_drop_device_direction;
  call->status->policy_l4_active_revision = reply->policy_l4_active_revision;
  call->status->policy_l4_rule_id = reply->policy_l4_rule_id;
  call->status->policy_l4_match_records = reply->policy_l4_match_records;
  call->status->policy_l4_no_match_records = reply->policy_l4_no_match_records;
  call->status->policy_l4_last_match_revision =
    reply->policy_l4_last_match_revision;
  call->status->policy_l4_last_match_rule_id =
    reply->policy_l4_last_match_rule_id;
  call->status->policy_l4_subject_uid = reply->policy_l4_subject_uid;
  call->status->policy_l4_network_context = reply->policy_l4_network_context;
  call->status->policy_l4_ip_family = reply->policy_l4_ip_family;
  call->status->policy_l4_ip_protocol = reply->policy_l4_ip_protocol;
  call->status->policy_l4_direction = reply->policy_l4_direction;
  call->status->policy_l4_action = reply->policy_l4_action;
  call->status->policy_l4_priority = reply->policy_l4_priority;
  call->status->policy_l4_order = reply->policy_l4_order;
  call->status->policy_l4_reason_id = reply->policy_l4_reason_id;
  call->status->policy_l4_last_match_uid = reply->policy_l4_last_match_uid;
  call->status->policy_l4_last_match_network_context =
    reply->policy_l4_last_match_network_context;
  call->status->policy_l4_last_match_reason_id =
    reply->policy_l4_last_match_reason_id;
  call->status->policy_l4_last_match_verdict =
    reply->policy_l4_last_match_verdict;
  call->status->policy_l4_last_match_winner = reply->policy_l4_last_match_winner;
  call->status->policy_l4_last_match_uid_known =
    reply->policy_l4_last_match_uid_known;
  call->status->policy_l4_last_match_device_direction =
    reply->policy_l4_last_match_device_direction;
  call->status->policy_l4_last_match_action = reply->policy_l4_last_match_action;
  call->status->policy_l4_last_evaluation_result =
    reply->policy_l4_last_evaluation_result;
  call->status->policy_l4_last_evaluation_verdict =
    reply->policy_l4_last_evaluation_verdict;
  call->status->policy_l4_last_evaluation_device_direction =
    reply->policy_l4_last_evaluation_device_direction;
  call->status->policy_l4_view_active = reply->policy_l4_view_active;
  call->status->policy_l4_view_rule_count = reply->policy_l4_view_rule_count;
  call->status->policy_l4_view_max_probes = reply->policy_l4_view_max_probes;
  call->status->policy_l4_view_last_match_winner_rank =
    reply->policy_l4_view_last_match_winner_rank;
  call->status->policy_l4_view_last_match_probes =
    reply->policy_l4_view_last_match_probes;
  call->status->policy_l4_view_last_match_candidate_count =
    reply->policy_l4_view_last_match_candidate_count;
  call->status->policy_l4_view_last_no_match_reason =
    reply->policy_l4_view_last_no_match_reason;
  call->status->policy_l4_typed_match_policy_key =
    reply->policy_l4_typed_match_policy_key;
  call->status->policy_l4_typed_match_probe_key =
    reply->policy_l4_typed_match_probe_key;
  call->status->policy_l4_last_evaluation_probe_key =
    reply->policy_l4_last_evaluation_probe_key;
  call->status->plugin_loaded = 1U;
  call->status->vapi_handle_live = 1U;
  call->status->generation_live = 1U;
  sakamoto_product_status_copy_text (
    call->status->artifact_id, sizeof (call->status->artifact_id),
    reply->artifact_id, sizeof (reply->artifact_id));
  sakamoto_product_status_copy_text (
    call->status->api_identity, sizeof (call->status->api_identity),
    reply->api_identity, sizeof (reply->api_identity));
  sakamoto_product_status_copy_text (
    call->status->vpp_revision, sizeof (call->status->vpp_revision),
    reply->vpp_revision, sizeof (reply->vpp_revision));
  sakamoto_product_status_copy_text (
    call->status->policy_snapshot_identity,
    sizeof (call->status->policy_snapshot_identity),
    reply->policy_snapshot_identity, sizeof (reply->policy_snapshot_identity));
  if (reply->retval != 0)
    {
      char detail[SAKAMOTO_PRODUCT_ERROR_DETAIL_MAX];
      call->transport_code = SAKAMOTO_PRODUCT_QUERY_FAILED;
      (void) snprintf (detail, sizeof (detail),
                       "VPP status request returned retval=%d",
                       (int) reply->retval);
      sakamoto_product_status_error (call->status, call->transport_code,
                                     detail);
    }
  return VAPI_OK;
}

static vapi_error_e
policy_apply_reply (vapi_ctx_t context, void *callback_context,
                    vapi_error_e rv, bool is_last,
                    vapi_payload_product_core_policy_apply_reply *reply)
{
  (void) context;
  (void) is_last;
  apply_call_t *call = callback_context;
  if (call == NULL)
    return VAPI_EINVAL;
  call->callback_called = true;
  if (rv != VAPI_OK || reply == NULL)
    {
      const char *detail = rv != VAPI_OK
        ? "VAPI policy apply callback failed"
        : "VAPI policy apply callback returned a null reply";
      call->transport_code = SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN;
      sakamoto_product_status_error (call->status, call->transport_code,
                                     detail);
      return VAPI_OK;
    }
  if (reply->retval != 0)
    {
      char detail[SAKAMOTO_PRODUCT_ERROR_DETAIL_MAX];
      call->transport_code = SAKAMOTO_PRODUCT_POLICY_APPLY_FAILED;
      (void) snprintf (detail, sizeof (detail),
                       "VPP policy apply returned retval=%d",
                       (int) reply->retval);
      sakamoto_product_status_error (call->status, call->transport_code,
                                     detail);
    }
  return VAPI_OK;
}

static vapi_error_e
policy_bundle_apply_reply (
  vapi_ctx_t context, void *callback_context, vapi_error_e rv, bool is_last,
  vapi_payload_product_core_policy_bundle_apply_reply *reply)
{
  (void) context;
  (void) is_last;
  apply_call_t *call = callback_context;
  if (call == NULL)
    return VAPI_EINVAL;
  call->callback_called = true;
  if (rv != VAPI_OK || reply == NULL)
    {
      const char *detail = rv != VAPI_OK
        ? "VAPI policy bundle apply callback failed"
        : "VAPI policy bundle apply callback returned a null reply";
      call->transport_code = SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN;
      sakamoto_product_status_error (call->status, call->transport_code,
                                     detail);
      return VAPI_OK;
    }
  if (reply->retval != 0)
    {
      char detail[SAKAMOTO_PRODUCT_ERROR_DETAIL_MAX];
      call->transport_code = SAKAMOTO_PRODUCT_POLICY_APPLY_FAILED;
      (void) snprintf (detail, sizeof (detail),
                       "VPP policy bundle apply returned retval=%d",
                       (int) reply->retval);
      sakamoto_product_status_error (call->status, call->transport_code,
                                     detail);
    }
  return VAPI_OK;
}

/* The public ABI is naturally aligned while generated VAPI types are packed. */
static void
policy_bundle_rule_to_vapi (
  const sakamoto_product_policy_rule_entry_t *source,
  vapi_type_product_policy_rule_entry *destination)
{
  destination->subject_uid = source->subject_uid;
  destination->network_context = source->network_context;
  destination->ifindex = source->ifindex;
  destination->rule_kind = source->rule_kind;
  destination->ip_family = source->ip_family;
  destination->ip_protocol = source->ip_protocol;
  destination->direction = source->direction;
  destination->action = source->action;
  destination->enabled = source->enabled;
  destination->source_prefix_len = source->source_prefix_len;
  destination->destination_prefix_len = source->destination_prefix_len;
  destination->source_port_first = source->source_port_first;
  destination->source_port_last = source->source_port_last;
  destination->destination_port_first = source->destination_port_first;
  destination->destination_port_last = source->destination_port_last;
  destination->priority = source->priority;
  destination->order = source->order;
  destination->reason_id = source->reason_id;
  destination->reserved = source->reserved;
  destination->rule_id = source->rule_id;
  memcpy (destination->source_address, source->source_address,
          sizeof (destination->source_address));
  memcpy (destination->destination_address, source->destination_address,
          sizeof (destination->destination_address));
}

static uint32_t
query_status (sakamoto_product_session_t *session,
              sakamoto_product_status_t *status)
{
  if (!product_core_api_available (session->context))
    {
      sakamoto_product_status_error (
        status, SAKAMOTO_PRODUCT_API_UNAVAILABLE,
        "required Product Core VAPI messages are unavailable");
      return SAKAMOTO_PRODUCT_API_UNAVAILABLE;
    }
  vapi_msg_product_core_status *message =
    vapi_alloc_product_core_status (session->context);
  if (message == NULL)
    {
      sakamoto_product_status_error (status, SAKAMOTO_PRODUCT_ALLOCATION_FAILED,
                                     "cannot allocate VAPI status request");
      return SAKAMOTO_PRODUCT_ALLOCATION_FAILED;
    }
  status_call_t call = {.transport_code = SAKAMOTO_PRODUCT_OK,
                        .callback_called = false,
                        .status = status};
  vapi_error_e rv = vapi_product_core_status (
    session->context, message, status_reply, &call);
  release_unsent_request (session, rv, call.callback_called, message);
  if (rv != VAPI_OK || !call.callback_called) session->connected = 0;
  if (rv == VAPI_OK && !call.callback_called)
    {
      sakamoto_product_status_error (status, SAKAMOTO_PRODUCT_QUERY_FAILED,
                                     "VAPI status callback was not invoked");
      return SAKAMOTO_PRODUCT_QUERY_FAILED;
    }
  if (rv != VAPI_OK && call.transport_code == SAKAMOTO_PRODUCT_OK)
    {
      sakamoto_product_status_error (status, SAKAMOTO_PRODUCT_QUERY_FAILED,
                                     "VAPI status request send failed");
      return SAKAMOTO_PRODUCT_QUERY_FAILED;
    }
  return call.transport_code != SAKAMOTO_PRODUCT_OK ? call.transport_code
                                                    : status->status_code;
}

static uint32_t
apply_policy_snapshot (sakamoto_product_session_t *session,
                       const sakamoto_product_policy_snapshot_t *snapshot,
                       sakamoto_product_status_t *status)
{
  if (!product_core_api_available (session->context))
    {
      sakamoto_product_status_error (
        status, SAKAMOTO_PRODUCT_API_UNAVAILABLE,
        "required Product Core VAPI messages are unavailable");
      return SAKAMOTO_PRODUCT_API_UNAVAILABLE;
    }
  vapi_msg_product_core_policy_apply *message =
    vapi_alloc_product_core_policy_apply (session->context);
  if (message == NULL)
    {
      sakamoto_product_status_error (
        status, SAKAMOTO_PRODUCT_ALLOCATION_FAILED,
        "cannot allocate VAPI policy apply request");
      return SAKAMOTO_PRODUCT_ALLOCATION_FAILED;
    }
  message->payload.generation = session->generation;
  message->payload.requested_revision = snapshot->requested_revision;
  message->payload.snapshot_hash = snapshot->snapshot_hash;
  message->payload.snapshot_empty = snapshot->snapshot_empty != 0U;
  message->payload.default_pass = snapshot->default_pass != 0U;
  message->payload.gate_claim_count = snapshot->gate_claim_count;
  message->payload.l4_rule_count = snapshot->l4_rule_count;
  message->payload.gate_subject_uid = snapshot->gate_subject_uid;
  message->payload.gate_network_context = snapshot->gate_network_context;
  message->payload.gate_blocked = snapshot->gate_blocked != 0U;
  message->payload.gate_reason_id = snapshot->gate_reason_id;
  message->payload.gate_rule_id = snapshot->gate_rule_id;
  message->payload.l4_subject_uid = snapshot->l4_subject_uid;
  message->payload.l4_network_context = snapshot->l4_network_context;
  message->payload.l4_ip_family = snapshot->l4_ip_family;
  message->payload.l4_ip_protocol = snapshot->l4_ip_protocol;
  message->payload.l4_direction = snapshot->l4_direction;
  message->payload.l4_action = snapshot->l4_action;
  message->payload.l4_source_prefix_len = snapshot->l4_source_prefix_len;
  message->payload.l4_destination_prefix_len =
    snapshot->l4_destination_prefix_len;
  message->payload.l4_source_port_first = snapshot->l4_source_port_first;
  message->payload.l4_source_port_last = snapshot->l4_source_port_last;
  message->payload.l4_destination_port_first =
    snapshot->l4_destination_port_first;
  message->payload.l4_destination_port_last =
    snapshot->l4_destination_port_last;
  message->payload.l4_priority = snapshot->l4_priority;
  message->payload.l4_order = snapshot->l4_order;
  message->payload.l4_reason_id = snapshot->l4_reason_id;
  message->payload.l4_reserved = snapshot->l4_reserved;
  message->payload.l4_rule_id = snapshot->l4_rule_id;
  memcpy (message->payload.l4_source_address, snapshot->l4_source_address,
          sizeof (snapshot->l4_source_address));
  memcpy (message->payload.l4_destination_address,
          snapshot->l4_destination_address,
          sizeof (snapshot->l4_destination_address));
  memset (message->payload.snapshot_identity, 0,
          sizeof (message->payload.snapshot_identity));
  memcpy (message->payload.snapshot_identity, snapshot->snapshot_identity,
          sizeof (snapshot->snapshot_identity));

  apply_call_t call = {.transport_code = SAKAMOTO_PRODUCT_OK,
                       .callback_called = false,
                       .status = status};
  vapi_error_e rv = vapi_product_core_policy_apply (
    session->context, message, policy_apply_reply, &call);
  release_unsent_request (session, rv, call.callback_called, message);
  if (rv != VAPI_OK || !call.callback_called) session->connected = 0;
  if (rv == VAPI_OK && !call.callback_called)
    {
      sakamoto_product_status_error (
        status, SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN,
        "VAPI policy apply callback was not invoked");
      return SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN;
    }
  if (rv != VAPI_OK && call.transport_code == SAKAMOTO_PRODUCT_OK)
    {
      sakamoto_product_status_error (status,
                                     SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN,
                                     "VAPI policy apply request send failed");
      return SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN;
    }
  if (call.transport_code != SAKAMOTO_PRODUCT_OK)
    return call.transport_code;
  return query_status (session, status);
}

uint32_t
sakamoto_product_abi_version (void)
{
  return SAKAMOTO_PRODUCT_ABI_VERSION;
}

uint32_t
sakamoto_product_api_version (void)
{
  return SAKAMOTO_PRODUCT_API_VERSION;
}

uint32_t
sakamoto_product_session_connect (sakamoto_product_bytes_t api_socket,
                                   uint64_t expected_generation,
                                   sakamoto_product_session_t **out_session,
                                   sakamoto_product_status_t *out_status)
{
  if (out_session != NULL)
    *out_session = NULL;
  sakamoto_product_status_reset (out_status, expected_generation);
  if (out_session == NULL || out_status == NULL || api_socket.data == NULL
      || api_socket.length == 0U || api_socket.length >= sizeof (((struct sockaddr_un *) 0)->sun_path)
      || expected_generation == 0U)
    {
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_INVALID_ARGUMENT,
        "socket path and non-zero generation are required");
      return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
    }
  for (uint32_t index = 0U; index < api_socket.length; ++index)
    if (api_socket.data[index] == 0U)
      {
        sakamoto_product_status_error (
          out_status, SAKAMOTO_PRODUCT_INVALID_ARGUMENT,
          "socket path contains an embedded NUL");
        return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
      }
  char *socket_path = calloc ((size_t) api_socket.length + 1U, sizeof (*socket_path));
  if (socket_path == NULL)
    {
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_ALLOCATION_FAILED,
        "cannot allocate VAPI socket path");
      return SAKAMOTO_PRODUCT_ALLOCATION_FAILED;
    }
  memcpy (socket_path, api_socket.data, api_socket.length);
  vapi_ctx_t context = NULL;
  vapi_error_e rv = vapi_ctx_alloc (&context);
  if (rv != VAPI_OK)
    {
      free (socket_path);
      sakamoto_product_status_error (out_status,
                                     SAKAMOTO_PRODUCT_ALLOCATION_FAILED,
                                     "cannot allocate VAPI context");
      return SAKAMOTO_PRODUCT_ALLOCATION_FAILED;
    }
  rv = vapi_connect_ex (context, "sakamoto-product-core", socket_path, 1, 1,
                        VAPI_MODE_BLOCKING, true, true);
  free (socket_path);
  if (rv != VAPI_OK)
    {
      vapi_ctx_free (context);
      sakamoto_product_status_error (out_status,
                                     SAKAMOTO_PRODUCT_CONNECT_FAILED,
                                     "cannot connect to VPP VAPI");
      return SAKAMOTO_PRODUCT_CONNECT_FAILED;
    }
  if (!product_core_api_available (context))
    {
      vapi_disconnect (context);
      vapi_ctx_free (context);
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_API_UNAVAILABLE,
        "required Product Core VAPI messages are unavailable");
      return SAKAMOTO_PRODUCT_API_UNAVAILABLE;
    }
  sakamoto_product_session_t *session = calloc (1U, sizeof (*session));
  if (session == NULL || pthread_mutex_init (&session->mutex, NULL) != 0)
    {
      if (session != NULL)
        free (session);
      vapi_disconnect (context);
      vapi_ctx_free (context);
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_ALLOCATION_FAILED,
        "cannot initialize VAPI session");
      return SAKAMOTO_PRODUCT_ALLOCATION_FAILED;
    }
  session->context = context;
  session->generation = expected_generation;
  session->connected = 1;
  uint32_t code = query_status (session, out_status);
  if (code != SAKAMOTO_PRODUCT_OK
      || out_status->generation != expected_generation)
    {
      if (code == SAKAMOTO_PRODUCT_OK)
        sakamoto_product_status_error (
          out_status, SAKAMOTO_PRODUCT_STALE_HANDLE,
          "VPP generation does not match the active generation");
      vapi_disconnect (context);
      vapi_ctx_free (context);
      pthread_mutex_destroy (&session->mutex);
      free (session);
      return out_status->status_code;
    }
  *out_session = session;
  return SAKAMOTO_PRODUCT_OK;
}

uint32_t
sakamoto_product_session_query (sakamoto_product_session_t *session,
                                 uint64_t expected_generation,
                                 sakamoto_product_status_t *out_status)
{
  if (out_status == NULL)
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  sakamoto_product_status_reset (out_status, expected_generation);
  if (session == NULL || expected_generation == 0U)
    {
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_INVALID_ARGUMENT,
        "session and non-zero generation are required");
      return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
    }
  if (pthread_mutex_lock (&session->mutex) != 0)
    {
      sakamoto_product_status_error (out_status,
                                     SAKAMOTO_PRODUCT_INTERNAL_ERROR,
                                     "cannot lock VAPI session");
      return SAKAMOTO_PRODUCT_INTERNAL_ERROR;
    }
  uint32_t code;
  if (!session->connected || expected_generation != session->generation)
    {
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_STALE_HANDLE,
        "session is retired or belongs to another generation");
      code = SAKAMOTO_PRODUCT_STALE_HANDLE;
    }
  else
    {
      code = query_status (session, out_status);
      if (code == SAKAMOTO_PRODUCT_OK
          && out_status->generation != expected_generation)
        {
          sakamoto_product_status_error (
            out_status, SAKAMOTO_PRODUCT_STALE_HANDLE,
            "VPP generation does not match the active generation");
          code = SAKAMOTO_PRODUCT_STALE_HANDLE;
        }
    }
  pthread_mutex_unlock (&session->mutex);
  return code;
}

uint32_t
sakamoto_product_session_apply_policy (
  sakamoto_product_session_t *session, uint64_t expected_generation,
  const sakamoto_product_policy_snapshot_t *snapshot,
  sakamoto_product_status_t *out_status)
{
  if (out_status == NULL)
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  sakamoto_product_status_reset (out_status, expected_generation);
  if (session == NULL || snapshot == NULL || expected_generation == 0U)
    {
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_INVALID_ARGUMENT,
        "session, snapshot and non-zero generation are required");
      return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
    }
  if (pthread_mutex_lock (&session->mutex) != 0)
    {
      sakamoto_product_status_error (out_status,
                                     SAKAMOTO_PRODUCT_INTERNAL_ERROR,
                                     "cannot lock VAPI session");
      return SAKAMOTO_PRODUCT_INTERNAL_ERROR;
    }
  uint32_t code;
  if (!session->connected || expected_generation != session->generation)
    {
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_STALE_HANDLE,
        "session is retired or belongs to another generation");
      code = SAKAMOTO_PRODUCT_STALE_HANDLE;
    }
  else
    {
      code = apply_policy_snapshot (session, snapshot, out_status);
      if (code == SAKAMOTO_PRODUCT_OK
          && out_status->generation != expected_generation)
        {
          sakamoto_product_status_error (
            out_status, SAKAMOTO_PRODUCT_STALE_HANDLE,
            "VPP generation does not match the active generation");
          code = SAKAMOTO_PRODUCT_STALE_HANDLE;
        }
    }
  pthread_mutex_unlock (&session->mutex);
  return code;
}

/* One complete successor is sent through the generated typed VAPI message. */
uint32_t
sakamoto_product_session_apply_policy_bundle (
  sakamoto_product_session_t *session, uint64_t expected_generation,
  const sakamoto_product_policy_bundle_t *bundle,
  sakamoto_product_status_t *out_status)
{
  if (out_status == NULL)
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  sakamoto_product_status_reset (out_status, expected_generation);
  if (session == NULL || bundle == NULL || expected_generation == 0U)
    {
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_INVALID_ARGUMENT,
        "session, bundle and non-zero generation are required");
      return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
    }
  if (!policy_bundle_valid (bundle))
    {
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_INVALID_ARGUMENT,
        "policy bundle ABI, identity, or bounded counts are invalid");
      return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
    }
  if (pthread_mutex_lock (&session->mutex) != 0)
    {
      sakamoto_product_status_error (out_status,
                                     SAKAMOTO_PRODUCT_INTERNAL_ERROR,
                                     "cannot lock VAPI session");
      return SAKAMOTO_PRODUCT_INTERNAL_ERROR;
    }
  uint32_t code = SAKAMOTO_PRODUCT_OK;
  if (!session->connected || expected_generation != session->generation)
    {
      sakamoto_product_status_reset (out_status, session->generation);
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_STALE_HANDLE,
        "session is retired or belongs to another generation");
      code = SAKAMOTO_PRODUCT_STALE_HANDLE;
    }
  else
    {
      if (!product_core_policy_bundle_api_available (session->context))
        {
          sakamoto_product_status_error (
            out_status, SAKAMOTO_PRODUCT_API_UNAVAILABLE,
            "Product Core typed policy bundle VAPI messages are unavailable");
          code = SAKAMOTO_PRODUCT_API_UNAVAILABLE;
        }
      else
        {
          /* Consume a pre-submit fault before allocating or handing a
           * message to generated VAPI.  This is a definite failure: the
           * request is known not to have been submitted, so Product Core may
           * discard the temp file and let an explicit retry proceed. */
          uint32_t fault_mode = session->policy_mutation_fault_mode;
          if (fault_mode
              == SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_PRE_SUBMIT_NOT_SENT)
            {
              session->policy_mutation_fault_mode =
                SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_NONE;
              sakamoto_product_status_error (
                out_status, SAKAMOTO_PRODUCT_POLICY_APPLY_FAILED,
                "debug policy bundle apply was not submitted");
              code = SAKAMOTO_PRODUCT_POLICY_APPLY_FAILED;
            }
          else
            {
              vapi_msg_product_core_policy_bundle_apply *message =
                vapi_alloc_product_core_policy_bundle_apply (session->context);
              if (message == NULL)
                {
                  sakamoto_product_status_error (
                    out_status, SAKAMOTO_PRODUCT_ALLOCATION_FAILED,
                    "cannot allocate VAPI policy bundle apply request");
                  code = SAKAMOTO_PRODUCT_ALLOCATION_FAILED;
                  goto policy_bundle_apply_done;
                }
              message->payload.generation = session->generation;
              message->payload.abi_version = bundle->abi_version;
              message->payload.struct_size = bundle->struct_size;
              message->payload.requested_revision = bundle->requested_revision;
              message->payload.snapshot_hash = bundle->snapshot_hash;
              message->payload.gate_entry_count = bundle->gate_entry_count;
              message->payload.l4_rule_count = bundle->l4_rule_count;
              message->payload.default_pass = bundle->default_pass;
              message->payload.reserved = bundle->reserved;
              memcpy (message->payload.snapshot_identity,
                      bundle->snapshot_identity,
                      sizeof (message->payload.snapshot_identity));
              for (uint32_t index = 0U;
                   index < SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_GATE_ENTRIES;
                   ++index)
                policy_bundle_rule_to_vapi (
                  &bundle->gate_entries[index],
                  &message->payload.gate_entries[index]);
              for (uint32_t index = 0U;
                   index < SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_L4_ENTRIES;
                   ++index)
                policy_bundle_rule_to_vapi (
                  &bundle->l4_entries[index],
                  &message->payload.l4_entries[index]);

              apply_call_t call = {.transport_code = SAKAMOTO_PRODUCT_OK,
                                   .callback_called = false,
                                   .status = out_status};
              /* The debug fault is consumed at the generated typed-call
               * boundary.  The request is still sent once; only its reply is
               * made untrusted so Product Core must fence and reconcile. */
              session->policy_mutation_fault_mode =
                SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_NONE;
              vapi_error_e rv = vapi_product_core_policy_bundle_apply (
                session->context, message, policy_bundle_apply_reply, &call);
              release_unsent_request (session, rv, call.callback_called, message);
              if (rv != VAPI_OK || !call.callback_called) session->connected = 0;
              if (fault_mode
                  == SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_OMIT_CALLBACK)
                {
                  call.callback_called = false;
                  call.transport_code = SAKAMOTO_PRODUCT_OK;
                  sakamoto_product_status_error (
                    out_status, SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN,
                    "VAPI policy bundle apply callback was not invoked");
                  code = SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN;
                }
              else if (rv == VAPI_OK && !call.callback_called)
                {
                  sakamoto_product_status_error (
                    out_status, SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN,
                    "VAPI policy bundle apply callback was not invoked");
                  code = SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN;
                }
              else if (rv != VAPI_OK
                       && call.transport_code == SAKAMOTO_PRODUCT_OK)
                {
                  sakamoto_product_status_error (
                    out_status, SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN,
                    "VAPI policy bundle apply request send failed");
                  code = SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN;
                }
              else if (call.transport_code != SAKAMOTO_PRODUCT_OK)
                code = call.transport_code;
              else
                {
                  code = query_status (session, out_status);
                  if (code == SAKAMOTO_PRODUCT_OK
                      && out_status->generation != expected_generation)
                    {
                      sakamoto_product_status_error (
                        out_status, SAKAMOTO_PRODUCT_STALE_HANDLE,
                        "VPP generation does not match the active generation");
                      code = SAKAMOTO_PRODUCT_STALE_HANDLE;
                    }
                  }
            }
        }
    }
policy_bundle_apply_done:
  (void) pthread_mutex_unlock (&session->mutex);
  return code;
}

uint32_t
sakamoto_product_session_set_policy_mutation_fault (
  sakamoto_product_session_t *session, uint64_t expected_generation,
  uint32_t fault_mode)
{
  if (session == NULL || expected_generation == 0U
      || (fault_mode != SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_NONE
          && fault_mode != SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_OMIT_CALLBACK
          && fault_mode
               != SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_PRE_SUBMIT_NOT_SENT))
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (pthread_mutex_lock (&session->mutex) != 0)
    return SAKAMOTO_PRODUCT_INTERNAL_ERROR;
  uint32_t code = SAKAMOTO_PRODUCT_OK;
  if (!session->connected || expected_generation != session->generation)
    code = SAKAMOTO_PRODUCT_STALE_HANDLE;
  else
    session->policy_mutation_fault_mode = fault_mode;
  (void) pthread_mutex_unlock (&session->mutex);
  return code;
}

uint32_t
sakamoto_product_session_disconnect (sakamoto_product_session_t *session)
{
  if (session == NULL)
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (pthread_mutex_lock (&session->mutex) != 0)
    return SAKAMOTO_PRODUCT_INTERNAL_ERROR;
  vapi_error_e rv = VAPI_OK;
  if (session->context != NULL)
    {
      session->connected = 0;
      rv = vapi_disconnect (session->context);
      vapi_ctx_free (session->context);
      session->context = NULL;
    }
  pthread_mutex_unlock (&session->mutex);
  return rv == VAPI_OK ? SAKAMOTO_PRODUCT_OK
                       : SAKAMOTO_PRODUCT_DISCONNECT_FAILED;
}

uint32_t
sakamoto_product_session_destroy (sakamoto_product_session_t *session)
{
  if (session == NULL)
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  uint32_t code = sakamoto_product_session_disconnect (session);
  if (code != SAKAMOTO_PRODUCT_OK)
    return code;
  pthread_mutex_destroy (&session->mutex);
  free (session);
  return SAKAMOTO_PRODUCT_OK;
}
