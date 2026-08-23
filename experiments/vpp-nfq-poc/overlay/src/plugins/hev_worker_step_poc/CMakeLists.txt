# SPDX-License-Identifier: Apache-2.0

add_vpp_plugin(hev_worker_step_poc
  SOURCES
  plugin.c
  hev_worker_step_poc.c

  LINK_LIBRARIES
  vlib
  vppinfra
  dl

  SUPPORTED_OS_LIST Linux Android
)
