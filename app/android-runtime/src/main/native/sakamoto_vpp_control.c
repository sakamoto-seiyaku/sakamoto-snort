/* SPDX-License-Identifier: Apache-2.0 */

#include "sakamoto_vpp_control.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <vapi/memclnt.api.vapi.h>
#include <vapi/vapi.h>
#include <vapi/vlib.api.vapi.h>
#include <vapi/vpe.api.vapi.h>

#ifndef SAKAMOTO_VPP_CONTROL_API_IDENTITY
#error "SAKAMOTO_VPP_CONTROL_API_IDENTITY must come from generated VPE VAPI"
#endif

DEFINE_VAPI_MSG_IDS_MEMCLNT_API_JSON;
DEFINE_VAPI_MSG_IDS_VLIB_API_JSON;
DEFINE_VAPI_MSG_IDS_VPE_API_JSON;

enum
{
  SAKAMOTO_VPP_CONTROL_EINVAL = -1,
  SAKAMOTO_VPP_CONTROL_EALLOC = -2,
  SAKAMOTO_VPP_CONTROL_ECONNECT = -3,
  SAKAMOTO_VPP_CONTROL_ECALL = -4,
  SAKAMOTO_VPP_CONTROL_ENOREPLY = -5,
  SAKAMOTO_VPP_CONTROL_EDISCONNECT = -6,
};

typedef struct
{
  int called;
  vapi_error_e rv;
  vapi_payload_show_version_reply reply;
} sakamoto_show_version_call_t;

static void
copy_text(char *destination, size_t destination_size, const uint8_t *source,
          size_t source_size)
{
  size_t length = 0;

  if (destination == NULL || destination_size == 0)
    return;
  if (source != NULL)
    {
      while (length < source_size && source[length] != '\0')
        ++length;
      if (length >= destination_size)
        length = destination_size - 1;
      memcpy(destination, source, length);
    }
  destination[length] = '\0';
}

static vapi_error_e
show_version_reply_cb(vapi_ctx_t ctx, void *callback_ctx, vapi_error_e rv,
                      bool is_last, vapi_payload_show_version_reply *reply)
{
  sakamoto_show_version_call_t *call = callback_ctx;

  (void)ctx;
  (void)is_last;
  call->rv = rv;
  if (rv != VAPI_OK)
    return rv;
  if (reply == NULL)
    return VAPI_OK;
  call->reply = *reply;
  call->called = 1;
  return VAPI_OK;
}

uint32_t
sakamoto_vpp_control_abi_version(void)
{
  return SAKAMOTO_VPP_CONTROL_ABI_VERSION;
}

const char *
sakamoto_vpp_control_api_identity(void)
{
  return SAKAMOTO_VPP_CONTROL_API_IDENTITY;
}

int
sakamoto_vpp_core_status_get(const char *api_socket,
                             sakamoto_vpp_core_status_t *out)
{
  vapi_ctx_t ctx = NULL;
  sakamoto_show_version_call_t call;
  vapi_msg_show_version *message;
  vapi_error_e rv;
  int result = 0;

  if (api_socket == NULL || out == NULL)
    return SAKAMOTO_VPP_CONTROL_EINVAL;

  memset(out, 0, sizeof(*out));
  out->control_abi_version = SAKAMOTO_VPP_CONTROL_ABI_VERSION;
  copy_text(out->api_identity, sizeof(out->api_identity),
            (const uint8_t *)SAKAMOTO_VPP_CONTROL_API_IDENTITY,
            strlen(SAKAMOTO_VPP_CONTROL_API_IDENTITY));

  rv = vapi_ctx_alloc(&ctx);
  if (rv != VAPI_OK)
    {
      out->transport_rc = SAKAMOTO_VPP_CONTROL_EALLOC;
      return out->transport_rc;
    }
  rv = vapi_connect_ex(ctx, "sakamoto-core-runtime", api_socket, 64, 32,
                       VAPI_MODE_BLOCKING, true, true);
  if (rv != VAPI_OK)
    {
      out->transport_rc = SAKAMOTO_VPP_CONTROL_ECONNECT;
      vapi_ctx_free(ctx);
      return out->transport_rc;
    }

  message = vapi_alloc_show_version(ctx);
  if (message == NULL)
    {
      result = SAKAMOTO_VPP_CONTROL_EALLOC;
      goto disconnect;
    }
  memset(&call, 0, sizeof(call));
  rv = vapi_show_version(ctx, message, show_version_reply_cb, &call);
  if (rv != VAPI_OK)
    {
      result = SAKAMOTO_VPP_CONTROL_ECALL;
      goto disconnect;
    }
  if (!call.called)
    {
      result = SAKAMOTO_VPP_CONTROL_ENOREPLY;
      goto disconnect;
    }

  out->vpp_retval = call.reply.retval;
  copy_text(out->program, sizeof(out->program), call.reply.program,
            sizeof(call.reply.program));
  copy_text(out->version, sizeof(out->version), call.reply.version,
            sizeof(call.reply.version));
  copy_text(out->build_date, sizeof(out->build_date), call.reply.build_date,
            sizeof(call.reply.build_date));
  copy_text(out->build_directory, sizeof(out->build_directory),
            call.reply.build_directory, sizeof(call.reply.build_directory));

disconnect:
  rv = vapi_disconnect(ctx);
  vapi_ctx_free(ctx);
  if (result == 0 && rv != VAPI_OK)
    result = SAKAMOTO_VPP_CONTROL_EDISCONNECT;
  out->transport_rc = result;
  return result;
}
