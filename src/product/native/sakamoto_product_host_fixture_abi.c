/* SPDX-License-Identifier: Apache-2.0 */

#include "sakamoto_product_abi.h"

/* Fixture transports cannot supply platform event/packet evidence. */
uint32_t
sakamoto_product_session_publish_network (
  sakamoto_product_session_t *session, uint64_t generation,
  const sakamoto_product_network_snapshot_t *snapshot)
{
  (void) session;
  (void) generation;
  (void) snapshot;
  return SAKAMOTO_PRODUCT_API_UNAVAILABLE;
}
#include "product_wire.h"
#include "sakamoto_product_status.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef SAKAMOTO_PRODUCT_HOST_FIXTURE
#error "The fixture transport is Host-test-only; production must compile sakamoto_product_vapi.c"
#endif

#define SAKAMOTO_PRODUCT_SOCKET_TIMEOUT_MS 2000
#define SAKAMOTO_PRODUCT_SOCKET_PATH_MAX 108

struct sakamoto_product_session {
  int fd;
  uint64_t generation;
  int connected;
  int policy_active;
  sakamoto_product_policy_snapshot_t policy_snapshot;
  pthread_mutex_t mutex;
};

_Static_assert (offsetof (sakamoto_product_status_t, generation) == 16U,
                "product status generation offset is part of the ABI");
_Static_assert (offsetof (sakamoto_product_status_t, artifact_id) == 52U,
                "product status identity offset is part of the ABI");
_Static_assert (sizeof (sakamoto_product_policy_snapshot_t) == 264U,
                "product policy snapshot size is part of the ABI");
_Static_assert (sizeof (sakamoto_product_policy_rule_entry_t) == 120U,
                "typed product policy rule size is part of the ABI");
_Static_assert (sizeof (sakamoto_product_policy_bundle_t) == 15496U,
                "typed product policy bundle size is part of the ABI");
_Static_assert (sizeof (sakamoto_product_status_t) == 1304U,
                "product status size is part of the ABI");

static void
fixture_identity (sakamoto_product_status_t *status)
{
  if (status == NULL)
    return;
  status->status_code = SAKAMOTO_PRODUCT_OK;
  status->core_ready = 1U;
  status->plugin_loaded = 1U;
  status->vapi_handle_live = 1U;
  status->generation_live = 1U;
  sakamoto_product_status_copy_text (status->artifact_id,
                                     sizeof (status->artifact_id),
                                     "host-fixture-v1", 15U);
  sakamoto_product_status_copy_text (status->api_identity,
                                     sizeof (status->api_identity),
                                     "product_core.api/1.0.0@fixture", 30U);
  sakamoto_product_status_copy_text (status->vpp_revision,
                                     sizeof (status->vpp_revision),
                                     "fixture1", 8U);
}

static void
copy_session_policy (const sakamoto_product_session_t *session,
                     sakamoto_product_status_t *status)
{
  if (session == NULL || status == NULL || !session->policy_active)
    return;
  const sakamoto_product_policy_snapshot_t *snapshot =
    &session->policy_snapshot;
  status->policy_requested_revision = snapshot->requested_revision;
  status->policy_active_revision = snapshot->requested_revision;
  status->policy_generation = session->generation;
  status->policy_snapshot_hash = snapshot->snapshot_hash;
  status->policy_worker0_revision = snapshot->requested_revision;
  status->policy_worker1_revision = snapshot->requested_revision;
  status->policy_snapshot_empty = snapshot->snapshot_empty;
  status->policy_default_pass = snapshot->default_pass;
  status->policy_gate_claim_count = snapshot->gate_claim_count;
  status->policy_l4_rule_count = snapshot->l4_rule_count;
  status->policy_last_apply_status_code = SAKAMOTO_PRODUCT_OK;
  status->policy_mixed_revision = 0U;
  status->policy_artifact_match = 1U;
  status->policy_generation_match = 1U;
  status->policy_gate_subject_uid = snapshot->gate_subject_uid;
  status->policy_gate_network_context = snapshot->gate_network_context;
  status->policy_gate_blocked = snapshot->gate_blocked;
  status->policy_gate_reason_id = snapshot->gate_reason_id;
  status->policy_gate_rule_id = snapshot->gate_rule_id;
  if (snapshot->l4_rule_count == 1U)
    {
      status->policy_l4_active_revision = snapshot->requested_revision;
      status->policy_l4_rule_id = snapshot->l4_rule_id;
      status->policy_l4_subject_uid = snapshot->l4_subject_uid;
      status->policy_l4_network_context = snapshot->l4_network_context;
      status->policy_l4_ip_family = snapshot->l4_ip_family;
      status->policy_l4_ip_protocol = snapshot->l4_ip_protocol;
      status->policy_l4_direction = snapshot->l4_direction;
      status->policy_l4_action = snapshot->l4_action;
      status->policy_l4_priority = snapshot->l4_priority;
      status->policy_l4_order = snapshot->l4_order;
      status->policy_l4_reason_id = snapshot->l4_reason_id;
    }
  sakamoto_product_status_copy_text (status->policy_snapshot_identity,
                                     sizeof (status->policy_snapshot_identity),
                                     snapshot->snapshot_identity,
                                     sizeof (snapshot->snapshot_identity));
}

static int
wait_fd (int fd, short events)
{
  struct pollfd poll_fd = {.fd = fd, .events = events, .revents = 0};
  int result;
  do
    {
      result = poll (&poll_fd, 1U, SAKAMOTO_PRODUCT_SOCKET_TIMEOUT_MS);
    }
  while (result < 0 && errno == EINTR);
  if (result <= 0)
    return result;
  if ((poll_fd.revents & POLLNVAL) != 0
      || (poll_fd.revents & POLLERR) != 0
      || ((events & POLLIN) == 0 && (poll_fd.revents & POLLHUP) != 0)
      || ((events & POLLIN) != 0 && (poll_fd.revents & POLLIN) == 0
          && (poll_fd.revents & POLLHUP) != 0))
    return -1;
  return 1;
}

static int
write_all (int fd, const void *buffer, size_t length)
{
  const unsigned char *cursor = (const unsigned char *) buffer;
  while (length != 0U)
    {
      if (wait_fd (fd, POLLOUT) <= 0)
        return -1;
      ssize_t written = write (fd, cursor, length);
      if (written < 0 && errno == EINTR)
        continue;
      if (written <= 0)
        return -1;
      cursor += (size_t) written;
      length -= (size_t) written;
    }
  return 0;
}

static int
read_all (int fd, void *buffer, size_t length)
{
  unsigned char *cursor = (unsigned char *) buffer;
  while (length != 0U)
    {
      if (wait_fd (fd, POLLIN) <= 0)
        return -1;
      ssize_t read_count = read (fd, cursor, length);
      if (read_count < 0 && errno == EINTR)
        continue;
      if (read_count <= 0)
        return -1;
      cursor += (size_t) read_count;
      length -= (size_t) read_count;
    }
  return 0;
}

static uint32_t
map_transport_error (void)
{
  if (errno == ETIMEDOUT)
    return SAKAMOTO_PRODUCT_QUERY_FAILED;
  return SAKAMOTO_PRODUCT_CONNECT_FAILED;
}

static uint32_t
copy_response (const sakamoto_product_wire_response_t *response,
               uint64_t expected_generation,
               sakamoto_product_status_t *status)
{
  if (response->magic != SAKAMOTO_PRODUCT_WIRE_MAGIC
      || response->version != SAKAMOTO_PRODUCT_WIRE_VERSION)
    {
      sakamoto_product_status_error (status, SAKAMOTO_PRODUCT_PROTOCOL_MISMATCH,
                                      "VAPI response identity mismatch");
      return SAKAMOTO_PRODUCT_PROTOCOL_MISMATCH;
    }
  status->status_code = response->status_code;
  status->generation = response->generation;
  status->core_ready =
    (response->flags & SAKAMOTO_PRODUCT_WIRE_CORE_READY) != 0U;
  status->adapter_available =
    (response->flags & SAKAMOTO_PRODUCT_WIRE_ADAPTER_AVAILABLE) != 0U;
  status->protection_running =
    (response->flags & SAKAMOTO_PRODUCT_WIRE_PROTECTION_RUNNING) != 0U;
  status->plugin_loaded =
    (response->flags & SAKAMOTO_PRODUCT_WIRE_PLUGIN_LOADED) != 0U;
  status->vapi_handle_live =
    (response->flags & SAKAMOTO_PRODUCT_WIRE_VAPI_HANDLE_LIVE) != 0U;
  status->generation_live =
    (response->flags & SAKAMOTO_PRODUCT_WIRE_GENERATION_LIVE) != 0U;
  sakamoto_product_status_copy_text (status->artifact_id,
                                     sizeof (status->artifact_id),
                                     response->artifact_id,
                                     sizeof (response->artifact_id));
  sakamoto_product_status_copy_text (status->api_identity,
                                     sizeof (status->api_identity),
                                     response->api_identity,
                                     sizeof (response->api_identity));
  sakamoto_product_status_copy_text (status->vpp_revision,
                                     sizeof (status->vpp_revision),
                                     response->vpp_revision,
                                     sizeof (response->vpp_revision));
  sakamoto_product_status_copy_text (status->error_detail,
                                     sizeof (status->error_detail),
                                     response->error_detail,
                                     sizeof (response->error_detail));
  if (response->generation != expected_generation)
    {
      sakamoto_product_status_error (
        status, SAKAMOTO_PRODUCT_STALE_HANDLE,
        "VAPI generation does not match the active generation");
      return SAKAMOTO_PRODUCT_STALE_HANDLE;
    }
  return status->status_code;
}

static uint32_t
exchange (sakamoto_product_session_t *session, uint16_t operation,
          sakamoto_product_status_t *status)
{
  sakamoto_product_wire_request_t request = {
    .magic = SAKAMOTO_PRODUCT_WIRE_MAGIC,
    .version = SAKAMOTO_PRODUCT_WIRE_VERSION,
    .operation = operation,
    .generation = session->generation,
  };
  sakamoto_product_wire_response_t response;
  if (write_all (session->fd, &request, sizeof (request)) != 0
      || read_all (session->fd, &response, sizeof (response)) != 0)
    {
      sakamoto_product_status_error (status, map_transport_error (),
                                     "VAPI transport failed");
      return status->status_code;
    }
  return copy_response (&response, session->generation, status);
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
      || api_socket.length == 0U || api_socket.length >= SAKAMOTO_PRODUCT_SOCKET_PATH_MAX
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
  struct sockaddr_un address;
  memset (&address, 0, sizeof (address));
  address.sun_family = AF_UNIX;
  memcpy (address.sun_path, api_socket.data, api_socket.length);
  address.sun_path[api_socket.length] = '\0';

  int fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    {
      sakamoto_product_status_error (out_status,
                                     SAKAMOTO_PRODUCT_CONNECT_FAILED,
                                     "cannot create VAPI socket");
      return SAKAMOTO_PRODUCT_CONNECT_FAILED;
    }
  if (connect (fd, (const struct sockaddr *) &address, sizeof (address)) != 0)
    {
      close (fd);
      sakamoto_product_status_error (out_status,
                                     SAKAMOTO_PRODUCT_CONNECT_FAILED,
                                     "cannot connect to VAPI socket");
      return SAKAMOTO_PRODUCT_CONNECT_FAILED;
    }
  sakamoto_product_session_t *session = calloc (1U, sizeof (*session));
  if (session == NULL)
    {
      close (fd);
      sakamoto_product_status_error (out_status,
                                     SAKAMOTO_PRODUCT_ALLOCATION_FAILED,
                                     "cannot allocate VAPI session");
      return SAKAMOTO_PRODUCT_ALLOCATION_FAILED;
    }
  session->fd = fd;
  session->generation = expected_generation;
  session->connected = 1;
  if (pthread_mutex_init (&session->mutex, NULL) != 0)
    {
      close (fd);
      free (session);
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_ALLOCATION_FAILED,
        "cannot initialize VAPI session lock");
      return SAKAMOTO_PRODUCT_ALLOCATION_FAILED;
    }
  uint32_t code = exchange (session, SAKAMOTO_PRODUCT_WIRE_OP_CONNECT,
                            out_status);
  if (code != SAKAMOTO_PRODUCT_OK)
    {
      pthread_mutex_destroy (&session->mutex);
      close (fd);
      free (session);
      return code;
    }
  *out_session = session;
  return SAKAMOTO_PRODUCT_OK;
}

uint32_t
sakamoto_product_session_query (sakamoto_product_session_t *session,
                                 uint64_t expected_generation,
                                 sakamoto_product_status_t *out_status)
{
  sakamoto_product_status_reset (out_status, expected_generation);
  if (session == NULL || out_status == NULL || expected_generation == 0U)
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
      sakamoto_product_status_reset (out_status, session->generation);
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_STALE_HANDLE,
        "session is retired or belongs to another generation");
      code = SAKAMOTO_PRODUCT_STALE_HANDLE;
    }
  else
    {
      code = exchange (session, SAKAMOTO_PRODUCT_WIRE_OP_QUERY, out_status);
      if (code == SAKAMOTO_PRODUCT_OK)
        copy_session_policy (session, out_status);
    }
  (void) pthread_mutex_unlock (&session->mutex);
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
      int valid_empty =
        snapshot->snapshot_empty != 0U && snapshot->default_pass != 0U
        && snapshot->gate_claim_count == 0U && snapshot->l4_rule_count == 0U
        && snapshot->gate_subject_uid == 0U
        && snapshot->gate_network_context == 0U
        && snapshot->gate_blocked == 0U && snapshot->gate_reason_id == 0U
        && snapshot->gate_rule_id == 0U;
      int valid_gate_block =
        snapshot->snapshot_empty == 0U && snapshot->default_pass != 0U
        && snapshot->gate_claim_count == 1U && snapshot->l4_rule_count == 0U
        && snapshot->gate_subject_uid != UINT32_MAX
        && snapshot->gate_network_context != 0U
        && snapshot->gate_blocked != 0U && snapshot->gate_reason_id != 0U
        && snapshot->gate_rule_id != 0U;
      int valid_gate_open =
        snapshot->snapshot_empty == 0U && snapshot->default_pass != 0U
        && snapshot->gate_claim_count == 0U && snapshot->l4_rule_count == 0U
        && snapshot->gate_subject_uid != UINT32_MAX
        && snapshot->gate_network_context != 0U
        && snapshot->gate_blocked == 0U && snapshot->gate_reason_id != 0U
        && snapshot->gate_rule_id != 0U;
      int valid_l4 =
        snapshot->snapshot_empty == 0U && snapshot->default_pass != 0U
        && snapshot->gate_claim_count == 0U && snapshot->l4_rule_count == 1U
        && snapshot->gate_subject_uid == 0U
        && snapshot->gate_network_context == 0U
        && snapshot->gate_blocked == 0U && snapshot->gate_reason_id == 0U
        && snapshot->gate_rule_id == 0U
        && snapshot->l4_subject_uid != UINT32_MAX
        && snapshot->l4_network_context != 0U
        && snapshot->l4_ip_family == 4U && snapshot->l4_ip_protocol == 6U
        && (snapshot->l4_direction == 1U || snapshot->l4_direction == 2U)
        && (snapshot->l4_action == 1U || snapshot->l4_action == 2U)
        && snapshot->l4_source_prefix_len <= 32U
        && snapshot->l4_destination_prefix_len <= 32U
        && snapshot->l4_source_port_first <= UINT16_MAX
        && snapshot->l4_source_port_last <= UINT16_MAX
        && snapshot->l4_destination_port_first <= UINT16_MAX
        && snapshot->l4_destination_port_last <= UINT16_MAX
        && snapshot->l4_source_port_first <= snapshot->l4_source_port_last
        && snapshot->l4_destination_port_first
             <= snapshot->l4_destination_port_last
        && snapshot->l4_rule_id != 0U && snapshot->l4_reason_id != 0U;
      if (snapshot->schema_version != 1U || snapshot->requested_revision == 0U
          || snapshot->snapshot_hash == 0U || snapshot->default_pass == 0U
          || (!valid_empty && !valid_gate_block && !valid_gate_open
              && !valid_l4))
        {
          out_status->policy_requested_revision =
            snapshot->requested_revision;
          out_status->policy_snapshot_hash = snapshot->snapshot_hash;
          out_status->policy_snapshot_empty = snapshot->snapshot_empty;
          out_status->policy_default_pass = snapshot->default_pass;
          out_status->policy_gate_claim_count = snapshot->gate_claim_count;
          out_status->policy_l4_rule_count = snapshot->l4_rule_count;
          out_status->policy_last_apply_status_code =
            SAKAMOTO_PRODUCT_POLICY_APPLY_FAILED;
          sakamoto_product_status_error (
            out_status, SAKAMOTO_PRODUCT_POLICY_APPLY_FAILED,
            "only empty default-pass, one Root Network Gate policy snapshot, or one Root IPv4 TCP L4 policy snapshot is supported");
          code = SAKAMOTO_PRODUCT_POLICY_APPLY_FAILED;
        }
      else
        {
          session->policy_snapshot = *snapshot;
          session->policy_active = 1;
          fixture_identity (out_status);
          copy_session_policy (session, out_status);
        }
    }
  (void) pthread_mutex_unlock (&session->mutex);
  return code;
}

static int
policy_bundle_identity_valid (const sakamoto_product_policy_bundle_t *bundle)
{
  size_t length = 0U;
  while (length < SAKAMOTO_PRODUCT_POLICY_IDENTITY_MAX
         && bundle->snapshot_identity[length] != '\0')
    ++length;
  if (length == 0U || length == SAKAMOTO_PRODUCT_POLICY_IDENTITY_MAX)
    return 0;
  for (size_t index = length + 1U;
       index < SAKAMOTO_PRODUCT_POLICY_IDENTITY_MAX; ++index)
    if (bundle->snapshot_identity[index] != '\0')
      return 0;
  for (size_t index = 0U; index < length; ++index)
    if (bundle->snapshot_identity[index] == '\n'
        || bundle->snapshot_identity[index] == '\r'
        || bundle->snapshot_identity[index] == '=')
      return 0;
  return 1;
}

static int
policy_bundle_rule_valid (const sakamoto_product_policy_rule_entry_t *entry,
                          uint32_t kind)
{
  if (entry->subject_uid == UINT32_MAX || entry->network_context == 0U
      || entry->rule_kind != kind
      || (entry->action != SAKAMOTO_PRODUCT_POLICY_ACTION_PASS_NEXT
          && entry->action != SAKAMOTO_PRODUCT_POLICY_ACTION_DROP)
      || entry->enabled > 1U || entry->rule_id == 0U
      || entry->reason_id == 0U || entry->reserved != 0U)
    return 0;
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
        return 0;
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

static int
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
    return 0;
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
            return 0;
          for (uint32_t prior = 0U; prior < rule_id_count; ++prior)
            if (rule_ids[prior] == entry->rule_id)
              return 0;
          rule_ids[rule_id_count++] = entry->rule_id;
        }
      else if (memcmp (entry, &zero, sizeof zero) != 0)
        return 0;
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
            return 0;
          for (uint32_t prior = 0U; prior < rule_id_count; ++prior)
            if (rule_ids[prior] == entry->rule_id)
              return 0;
          rule_ids[rule_id_count++] = entry->rule_id;
        }
      else if (memcmp (entry, &zero, sizeof zero) != 0)
        return 0;
    }
  return 1;
}

/* The Host fixture exposes the same one-call bundle seam as production.  Its
 * current wire peer is deliberately S191-only, so it refuses a bundle rather
 * than simulating one with repeated legacy messages. */
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
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_API_UNAVAILABLE,
        "policy bundle requires regenerated Product Core VAPI artifact");
      code = SAKAMOTO_PRODUCT_API_UNAVAILABLE;
    }
  (void) pthread_mutex_unlock (&session->mutex);
  return code;
}

/* The Host fixture has no generated VAPI transport to fault.  Keep the
 * append-only control ABI callable so Rust Host builds remain link-complete;
 * production VAPI owns the actual one-shot callback omission behavior. */
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
  if (!session->connected)
    {
      (void) pthread_mutex_unlock (&session->mutex);
      return SAKAMOTO_PRODUCT_OK;
    }
  session->connected = 0;
  int fd = session->fd;
  session->fd = -1;
  (void) shutdown (fd, SHUT_RDWR);
  (void) close (fd);
  (void) pthread_mutex_unlock (&session->mutex);
  return SAKAMOTO_PRODUCT_OK;
}

uint32_t
sakamoto_product_session_destroy (sakamoto_product_session_t *session)
{
  if (session == NULL)
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  uint32_t code = sakamoto_product_session_disconnect (session);
  if (code != SAKAMOTO_PRODUCT_OK)
    return code;
  (void) pthread_mutex_destroy (&session->mutex);
  free (session);
  return SAKAMOTO_PRODUCT_OK;
}
