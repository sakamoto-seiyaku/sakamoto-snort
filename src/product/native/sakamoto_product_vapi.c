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
  pthread_mutex_t mutex;
};

typedef struct {
  uint32_t transport_code;
  bool callback_called;
  sakamoto_product_status_t *status;
} status_call_t;

static bool
product_core_api_available (vapi_ctx_t context)
{
  return vapi_is_msg_available (context, vapi_msg_id_product_core_status)
         && vapi_is_msg_available (context,
                                   vapi_msg_id_product_core_status_reply);
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
sakamoto_product_session_disconnect (sakamoto_product_session_t *session)
{
  if (session == NULL)
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (pthread_mutex_lock (&session->mutex) != 0)
    return SAKAMOTO_PRODUCT_INTERNAL_ERROR;
  vapi_error_e rv = VAPI_OK;
  if (session->connected)
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
