# SPDX-License-Identifier: Apache-2.0

add_vpp_plugin(handoff_perf_poc
  SOURCES
  plugin.c
  handoff_perf_poc.c

  LINK_LIBRARIES
  vlib
  vppinfra

  SUPPORTED_OS_LIST Linux Android
)

target_compile_definitions(handoff_perf_poc_plugin PRIVATE HANDOFF_PERF_WAKE_PATCH=1)
