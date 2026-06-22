# SPDX-License-Identifier: Apache-2.0

add_vpp_plugin(tun_poc
  SOURCES
  plugin.c
  tun_poc.c

  INSTALL_HEADERS
  tun_poc.h

  LINK_LIBRARIES
  vlib
  vppinfra

  SUPPORTED_OS_LIST Linux
)
