/* SPDX-License-Identifier: Apache-2.0 */

/*
 * The first product VPP plugin intentionally has no packet nodes, adapters,
 * queues, pools, workers, or Flow Stack.  Its only runtime responsibility is
 * to publish the coarse identity/readiness needed by the Host Product Core.
 */

#include <errno.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include <vlib/vlib.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>
#include <vpp/app/version.h>

#include "product_core.api_enum.h"
#include "product_core.api_types.h"
#include "product_core_identity.h"

#ifndef SAKAMOTO_PRODUCT_VPP_REVISION
#error "the product plugin must be compiled with the pinned VPP revision"
#endif

typedef struct
{
  vlib_main_t *vlib_main;
  u16 msg_id_base;
  u64 generation;
  u8 core_ready;
} product_core_main_t;

product_core_main_t product_core_main;

#define REPLY_MSG_ID_BASE product_core_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static u64
product_core_generation (void)
{
  const char *value = getenv ("SAKAMOTO_PRODUCT_GENERATION");
  if (value == NULL || *value == '\0')
    return 1;
  errno = 0;
  char *end = 0;
  unsigned long long generation = strtoull (value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || generation == 0)
    return 1;
  return (u64) generation;
}

static void
vl_api_product_core_status_t_handler (vl_api_product_core_status_t *mp)
{
  product_core_main_t *pcm = &product_core_main;
  vl_api_product_core_status_reply_t *rmp;
  int rv = 0;
  (void) mp;

  REPLY_MACRO2 (VL_API_PRODUCT_CORE_STATUS_REPLY,
                ({
                  rmp->retval = htonl (rv);
                  rmp->abi_version = htonl (SAKAMOTO_PRODUCT_ABI_VERSION);
                  rmp->api_version = htonl (SAKAMOTO_PRODUCT_API_VERSION);
                  rmp->generation = clib_host_to_net_u64 (pcm->generation);
                  rmp->core_ready = pcm->core_ready;
                  /* Adapter and protection are separate capabilities. */
                  rmp->adapter_available = 0;
                  rmp->protection_running = 0;
                  clib_memset (rmp->artifact_id, 0, sizeof (rmp->artifact_id));
                  clib_memset (rmp->api_identity, 0, sizeof (rmp->api_identity));
                  clib_memset (rmp->vpp_revision, 0, sizeof (rmp->vpp_revision));
                  clib_memcpy (rmp->artifact_id,
                               SAKAMOTO_PRODUCT_ARTIFACT_ID,
                               sizeof (SAKAMOTO_PRODUCT_ARTIFACT_ID));
                  clib_memcpy (rmp->api_identity,
                               SAKAMOTO_PRODUCT_API_IDENTITY,
                               sizeof (SAKAMOTO_PRODUCT_API_IDENTITY));
                  clib_memcpy (rmp->vpp_revision,
                               SAKAMOTO_PRODUCT_MANIFEST_VPP_REVISION,
                               sizeof (SAKAMOTO_PRODUCT_MANIFEST_VPP_REVISION));
                }));
}

#include "product_core.api.c"

static clib_error_t *
product_core_init (vlib_main_t *vm)
{
  product_core_main_t *pcm = &product_core_main;
  pcm->vlib_main = vm;
  pcm->generation = product_core_generation ();
  pcm->core_ready = 1;
  pcm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_INIT_FUNCTION (product_core_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Sakamoto product control identity (Host spine only)",
};
