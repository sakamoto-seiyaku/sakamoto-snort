/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>

#include <vapi/memclnt.api.vapi.h>
#include <vapi/vapi.h>
#include <vapi/vlib.api.vapi.h>

#include <tun_poc.api.vapi.h>

DEFINE_VAPI_MSG_IDS_MEMCLNT_API_JSON;
DEFINE_VAPI_MSG_IDS_VLIB_API_JSON;
DEFINE_VAPI_MSG_IDS_TUN_POC_API_JSON;

typedef struct
{
  int called;
  vapi_error_e rv;
  vapi_payload_tun_poc_status_reply reply;
} status_call_t;

static vapi_error_e
status_reply_cb (vapi_ctx_t ctx, void *callback_ctx, vapi_error_e rv,
		 bool is_last, vapi_payload_tun_poc_status_reply *reply)
{
  status_call_t *call = callback_ctx;

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
call_status (vapi_ctx_t ctx, status_call_t *call)
{
  vapi_msg_tun_poc_status *msg = vapi_alloc_tun_poc_status (ctx);
  vapi_error_e rv;

  if (msg == NULL)
    {
      fprintf (stderr, "vapi_alloc_tun_poc_status failed\n");
      return 1;
    }

  memset (call, 0, sizeof (*call));
  rv = vapi_tun_poc_status (ctx, msg, status_reply_cb, call);
  if (rv != VAPI_OK)
    {
      fprintf (stderr, "vapi_tun_poc_status failed: %d\n", rv);
      return 1;
    }
  if (!call->called)
    {
      fprintf (stderr, "tun_poc_status callback was not called\n");
      return 1;
    }
  if (call->reply.retval != 0)
    {
      fprintf (stderr, "tun_poc_status retval=%d\n", call->reply.retval);
      return 1;
    }

  return 0;
}

int
main (int argc, char **argv)
{
  const char *api_sock = argc > 1 ? argv[1] : "/run/vpp/api.sock";
  vapi_ctx_t ctx;
  vapi_error_e rv;
  status_call_t status;
  int rc = 1;

  rv = vapi_ctx_alloc (&ctx);
  if (rv != VAPI_OK)
    {
      fprintf (stderr, "vapi_ctx_alloc failed: %d\n", rv);
      return 1;
    }

  rv = vapi_connect_ex (ctx, "tun-poc-vapi-status", api_sock, 64, 32,
			VAPI_MODE_BLOCKING, true, true);
  if (rv != VAPI_OK)
    {
      fprintf (stderr, "vapi_connect_ex failed: %d socket=%s\n", rv, api_sock);
      goto out_free;
    }

  if (call_status (ctx, &status) != 0)
    goto out_disconnect;

  printf ("tun_poc_status via VAPI C:\n");
  printf ("  enabled=%u mode=%u retval=%d\n", status.reply.enabled,
	  status.reply.mode, status.reply.retval);
  printf ("  counters rx=%lu tx=%lu shim_tx=%lu blocked=%lu\n",
	  status.reply.rx_packets, status.reply.tx_packets,
	  status.reply.shim_tx_packets, status.reply.blocked_packets);
  printf ("  owner cache_enabled=%u block_uid_set=%u block_uid=%d last_uid=%d\n",
	  status.reply.owner_cache_enabled, status.reply.block_owner_uid_set,
	  status.reply.block_owner_uid, status.reply.last_owner_uid);
  rc = 0;

out_disconnect:
  rv = vapi_disconnect (ctx);
  if (rv != VAPI_OK)
    {
      fprintf (stderr, "vapi_disconnect failed: %d\n", rv);
      rc = 1;
    }
out_free:
  vapi_ctx_free (ctx);
  return rc;
}
