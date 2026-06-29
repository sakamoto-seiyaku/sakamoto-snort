/* SPDX-License-Identifier: Apache-2.0 */

#include "tun_poc_control_shim.h"

#include <stdbool.h>
#include <string.h>
#include <endian.h>

#include <vapi/memclnt.api.vapi.h>
#include <vapi/vapi.h>
#include <vapi/vlib.api.vapi.h>

#include <tun_poc.api.vapi.h>

DEFINE_VAPI_MSG_IDS_MEMCLNT_API_JSON;
DEFINE_VAPI_MSG_IDS_VLIB_API_JSON;
DEFINE_VAPI_MSG_IDS_TUN_POC_API_JSON;

enum
{
  TUN_POC_SHIM_EINVAL = -1,
  TUN_POC_SHIM_ECTX = -2,
  TUN_POC_SHIM_ECONNECT = -3,
  TUN_POC_SHIM_EALLOC = -4,
  TUN_POC_SHIM_ECALL = -5,
  TUN_POC_SHIM_ENOREPLY = -6,
  TUN_POC_SHIM_EDISCONNECT = -7,
};

typedef struct
{
  int called;
  vapi_error_e rv;
  vapi_payload_tun_poc_status_reply reply;
} tun_poc_status_call_t;

typedef struct
{
  int called;
  vapi_error_e rv;
  vapi_payload_tun_poc_owner_policy_set_reply reply;
} tun_poc_policy_set_call_t;

uint32_t
tun_poc_control_shim_abi_version (void)
{
  return TUN_POC_CONTROL_SHIM_ABI_VERSION;
}

static vapi_error_e
tun_poc_status_reply_cb (vapi_ctx_t ctx, void *callback_ctx, vapi_error_e rv,
			 bool is_last,
			 vapi_payload_tun_poc_status_reply *reply)
{
  tun_poc_status_call_t *call = callback_ctx;

  (void) ctx;
  call->rv = rv;
  if (rv != VAPI_OK)
    return rv;
  if (reply == NULL)
    return VAPI_OK;

  (void) is_last;
  call->reply = *reply;
  call->called = 1;
  return VAPI_OK;
}

static vapi_error_e
tun_poc_policy_set_reply_cb (
  vapi_ctx_t ctx, void *callback_ctx, vapi_error_e rv, bool is_last,
  vapi_payload_tun_poc_owner_policy_set_reply *reply)
{
  tun_poc_policy_set_call_t *call = callback_ctx;

  (void) ctx;
  call->rv = rv;
  if (rv != VAPI_OK)
    return rv;
  if (reply == NULL)
    return VAPI_OK;

  (void) is_last;
  call->reply = *reply;
  call->called = 1;
  return VAPI_OK;
}

static int
tun_poc_call_status (vapi_ctx_t ctx, tun_poc_status_call_t *call)
{
  vapi_msg_tun_poc_status *msg = vapi_alloc_tun_poc_status (ctx);
  vapi_error_e rv;

  if (msg == NULL)
    return TUN_POC_SHIM_EALLOC;

  memset (call, 0, sizeof (*call));
  rv = vapi_tun_poc_status (ctx, msg, tun_poc_status_reply_cb, call);
  if (rv != VAPI_OK)
    return TUN_POC_SHIM_ECALL;
  if (!call->called)
    return TUN_POC_SHIM_ENOREPLY;

  return 0;
}

static int
tun_poc_call_policy_set (vapi_ctx_t ctx, const tun_poc_owner_policy_t *policy,
			 tun_poc_policy_set_call_t *call)
{
  vapi_msg_tun_poc_owner_policy_set *msg =
    vapi_alloc_tun_poc_owner_policy_set (ctx);
  vapi_error_e rv;

  if (msg == NULL)
    return TUN_POC_SHIM_EALLOC;

  msg->payload.owner_cache_enabled = policy->owner_cache_enabled != 0;
  msg->payload.block_owner_uid_set = policy->block_owner_uid_set != 0;
  msg->payload.block_owner_uid = policy->block_owner_uid;

  memset (call, 0, sizeof (*call));
  rv = vapi_tun_poc_owner_policy_set (ctx, msg, tun_poc_policy_set_reply_cb,
				      call);
  if (rv != VAPI_OK)
    return TUN_POC_SHIM_ECALL;
  if (!call->called)
    return TUN_POC_SHIM_ENOREPLY;

  return 0;
}

static void
tun_poc_copy_status (tun_poc_status_out_t *out,
		     const vapi_payload_tun_poc_status_reply *reply)
{
  memset (out, 0, sizeof (*out));
  out->retval = reply->retval;
  out->enabled = reply->enabled;
  out->owner_cache_enabled = reply->owner_cache_enabled;
  out->block_owner_uid_set = reply->block_owner_uid_set;
  out->mode = reply->mode;
  out->rx_packets = reply->rx_packets;
  out->tx_packets = reply->tx_packets;
  out->shim_tx_packets = reply->shim_tx_packets;
  out->blocked_packets = reply->blocked_packets;
  out->resolver_queries = reply->resolver_queries;
  out->resolver_hits = reply->resolver_hits;
  out->owner_cache_hits = reply->owner_cache_hits;
  out->uid_blocked_packets = reply->uid_blocked_packets;
  out->block_owner_uid = reply->block_owner_uid;
  out->last_owner_uid = reply->last_owner_uid;
}

int
tun_poc_status_get (const char *api_sock, tun_poc_status_out_t *out)
{
  tun_poc_status_call_t call;
  vapi_ctx_t ctx;
  vapi_error_e rv;
  int rc;

  if (api_sock == NULL || out == NULL)
    return TUN_POC_SHIM_EINVAL;

  rv = vapi_ctx_alloc (&ctx);
  if (rv != VAPI_OK)
    return TUN_POC_SHIM_ECTX;

  rv = vapi_connect_ex (ctx, "tun-poc-control-shim", api_sock, 64, 32,
			VAPI_MODE_BLOCKING, true, true);
  if (rv != VAPI_OK)
    {
      vapi_ctx_free (ctx);
      return TUN_POC_SHIM_ECONNECT;
    }

  rc = tun_poc_call_status (ctx, &call);
  if (rc == 0)
    tun_poc_copy_status (out, &call.reply);

  rv = vapi_disconnect (ctx);
  vapi_ctx_free (ctx);
  if (rv != VAPI_OK)
    return TUN_POC_SHIM_EDISCONNECT;

  return rc;
}

int
tun_poc_owner_policy_set (const char *api_sock,
			  const tun_poc_owner_policy_t *policy,
			  int32_t *vpp_retval)
{
  tun_poc_policy_set_call_t call;
  vapi_ctx_t ctx;
  vapi_error_e rv;
  int rc;

  if (api_sock == NULL || policy == NULL)
    return TUN_POC_SHIM_EINVAL;
  if (vpp_retval != NULL)
    *vpp_retval = 0;

  rv = vapi_ctx_alloc (&ctx);
  if (rv != VAPI_OK)
    return TUN_POC_SHIM_ECTX;

  rv = vapi_connect_ex (ctx, "tun-poc-control-shim", api_sock, 64, 32,
			VAPI_MODE_BLOCKING, true, true);
  if (rv != VAPI_OK)
    {
      vapi_ctx_free (ctx);
      return TUN_POC_SHIM_ECONNECT;
    }

  rc = tun_poc_call_policy_set (ctx, policy, &call);
  if (rc == 0 && vpp_retval != NULL)
    *vpp_retval = call.reply.retval;

  rv = vapi_disconnect (ctx);
  vapi_ctx_free (ctx);
  if (rv != VAPI_OK)
    return TUN_POC_SHIM_EDISCONNECT;

  return rc;
}
