/* SPDX-License-Identifier: Apache-2.0 */

#include <tun_poc/tun_poc.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <tun_poc/tun_poc.api_enum.h>
#include <tun_poc/tun_poc.api_types.h>

static u16 tun_poc_msg_id_base;

#define REPLY_MSG_ID_BASE tun_poc_msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
tun_poc_apply_owner_policy (tun_poc_main_t *tm, u8 owner_cache_enabled,
			    u8 block_owner_uid_set, i32 block_owner_uid)
{
  tm->owner_cache_enabled = owner_cache_enabled;
  if (!tm->owner_cache_enabled)
    tm->owner_cache_valid = 0;

  tm->block_owner_uid_set = block_owner_uid_set;
  tm->block_owner_uid = tm->block_owner_uid_set ? block_owner_uid : -1;
}

static void
vl_api_tun_poc_owner_policy_set_t_handler (
  vl_api_tun_poc_owner_policy_set_t *mp)
{
  tun_poc_main_t *tm = &tun_poc_main;
  vl_api_tun_poc_owner_policy_set_reply_t *rmp;
  int rv = 0;

  tun_poc_apply_owner_policy (
    tm, mp->owner_cache_enabled, mp->block_owner_uid_set,
    (i32) clib_net_to_host_u32 (mp->block_owner_uid));

  REPLY_MACRO (VL_API_TUN_POC_OWNER_POLICY_SET_REPLY);
}

static void
vl_api_tun_poc_owner_policy_stage_t_handler (
  vl_api_tun_poc_owner_policy_stage_t *mp)
{
  tun_poc_main_t *tm = &tun_poc_main;
  vl_api_tun_poc_owner_policy_stage_reply_t *rmp;
  int rv = 0;

  tm->pending_owner_policy_valid = 1;
  tm->pending_owner_cache_enabled = mp->owner_cache_enabled;
  tm->pending_block_owner_uid_set = mp->block_owner_uid_set;
  tm->pending_block_owner_uid =
    tm->pending_block_owner_uid_set ?
      (i32) clib_net_to_host_u32 (mp->block_owner_uid) :
      -1;

  REPLY_MACRO (VL_API_TUN_POC_OWNER_POLICY_STAGE_REPLY);
}

static void
vl_api_tun_poc_owner_policy_commit_t_handler (
  vl_api_tun_poc_owner_policy_commit_t *mp)
{
  tun_poc_main_t *tm = &tun_poc_main;
  vl_api_tun_poc_owner_policy_commit_reply_t *rmp;
  int rv = 0;

  if (!tm->pending_owner_policy_valid)
    rv = -1;
  else
    {
      tun_poc_apply_owner_policy (tm, tm->pending_owner_cache_enabled,
				  tm->pending_block_owner_uid_set,
				  tm->pending_block_owner_uid);
      tm->pending_owner_policy_valid = 0;
      tm->pending_owner_cache_enabled = 0;
      tm->pending_block_owner_uid_set = 0;
      tm->pending_block_owner_uid = -1;
    }

  REPLY_MACRO (VL_API_TUN_POC_OWNER_POLICY_COMMIT_REPLY);
}

static void
vl_api_tun_poc_owner_policy_rollback_t_handler (
  vl_api_tun_poc_owner_policy_rollback_t *mp)
{
  tun_poc_main_t *tm = &tun_poc_main;
  vl_api_tun_poc_owner_policy_rollback_reply_t *rmp;
  int rv = 0;

  tm->pending_owner_policy_valid = 0;
  tm->pending_owner_cache_enabled = 0;
  tm->pending_block_owner_uid_set = 0;
  tm->pending_block_owner_uid = -1;

  REPLY_MACRO (VL_API_TUN_POC_OWNER_POLICY_ROLLBACK_REPLY);
}

static void
vl_api_tun_poc_status_t_handler (vl_api_tun_poc_status_t *mp)
{
  tun_poc_main_t *tm = &tun_poc_main;
  vl_api_tun_poc_status_reply_t *rmp;
  int rv = 0;

  REPLY_MACRO2 (VL_API_TUN_POC_STATUS_REPLY, ({
		  rmp->enabled = tm->enabled;
		  rmp->mode = clib_host_to_net_u32 (tm->mode);
		  rmp->rx_packets = clib_host_to_net_u64 (tm->rx_packets);
		  rmp->tx_packets = clib_host_to_net_u64 (tm->tx_packets);
		  rmp->shim_tx_packets =
		    clib_host_to_net_u64 (tm->shim_tx_packets);
		  rmp->blocked_packets =
		    clib_host_to_net_u64 (tm->blocked_packets);
		  rmp->tuple_parsed_packets =
		    clib_host_to_net_u64 (tm->tuple_parsed_packets);
		  rmp->resolver_queries =
		    clib_host_to_net_u64 (tm->resolver_queries);
		  rmp->resolver_hits =
		    clib_host_to_net_u64 (tm->resolver_hits);
		  rmp->resolver_errors =
		    clib_host_to_net_u64 (tm->resolver_errors);
		  rmp->owner_cache_enabled = tm->owner_cache_enabled;
		  rmp->owner_cache_hits =
		    clib_host_to_net_u64 (tm->owner_cache_hits);
		  rmp->owner_cache_misses =
		    clib_host_to_net_u64 (tm->owner_cache_misses);
		  rmp->owner_cache_stores =
		    clib_host_to_net_u64 (tm->owner_cache_stores);
		  rmp->block_owner_uid_set = tm->block_owner_uid_set;
		  rmp->block_owner_uid =
		    clib_host_to_net_u32 ((u32) tm->block_owner_uid);
		  rmp->uid_blocked_packets =
		    clib_host_to_net_u64 (tm->uid_blocked_packets);
		  rmp->last_owner_uid =
		    clib_host_to_net_u32 ((u32) tm->last_owner_uid);
		}));
}

/* API definitions */
#include <tun_poc/tun_poc.api.c>

static clib_error_t *
tun_poc_api_hookup (vlib_main_t *vm)
{
  (void) vm;
  tun_poc_msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (tun_poc_api_hookup);
