# SPDX-License-Identifier: Apache-2.0

add_vpp_plugin(hev_external_driver_poc
  SOURCES
  plugin.c
  hev_external_driver_poc.c
  hev_packet_path_poc.c
  s122_packet_path_perf.c
  s124_vpn_tun_owner.c
  owner_inline_oi1.c
  owner_inline_oi2.c
  owner_inline_oi3.c

  LINK_LIBRARIES
  vlib
  vppinfra
  dl

  SUPPORTED_OS_LIST Linux Android
)
