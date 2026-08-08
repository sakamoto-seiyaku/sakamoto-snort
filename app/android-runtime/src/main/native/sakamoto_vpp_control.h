/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SAKAMOTO_VPP_CONTROL_H
#define SAKAMOTO_VPP_CONTROL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* This is the product/native boundary. It is deliberately independent of
 * packet Adapter state: the only status query in SAKAMOTO-67 is VPP's core
 * show_version binary API message. */
#define SAKAMOTO_VPP_CONTROL_ABI_VERSION 1u
#define SAKAMOTO_VPP_CONTROL_API_IDENTITY_MAX 64u
#define SAKAMOTO_VPP_CONTROL_PROGRAM_MAX 32u
#define SAKAMOTO_VPP_CONTROL_VERSION_MAX 32u
#define SAKAMOTO_VPP_CONTROL_DATE_MAX 32u
#define SAKAMOTO_VPP_CONTROL_DIRECTORY_MAX 256u

typedef struct
{
  uint32_t control_abi_version;
  int32_t transport_rc;
  int32_t vpp_retval;
  char api_identity[SAKAMOTO_VPP_CONTROL_API_IDENTITY_MAX];
  char program[SAKAMOTO_VPP_CONTROL_PROGRAM_MAX];
  char version[SAKAMOTO_VPP_CONTROL_VERSION_MAX];
  char build_date[SAKAMOTO_VPP_CONTROL_DATE_MAX];
  char build_directory[SAKAMOTO_VPP_CONTROL_DIRECTORY_MAX];
} sakamoto_vpp_core_status_t;

uint32_t sakamoto_vpp_control_abi_version(void);
const char *sakamoto_vpp_control_api_identity(void);
int sakamoto_vpp_core_status_get(const char *api_socket,
                                 sakamoto_vpp_core_status_t *out);

#ifdef __cplusplus
}
#endif

#endif
