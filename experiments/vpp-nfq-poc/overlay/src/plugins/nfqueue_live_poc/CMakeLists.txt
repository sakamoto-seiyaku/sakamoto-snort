# SPDX-License-Identifier: Apache-2.0
# Throwaway SAKAMOTO-73 source-owned VPP-native NFQUEUE live-buffer probe.

set(LIVE_POC_NETFILTER_ROOT "${SAKAMOTO_NETFILTER_ROOT}" CACHE PATH
    "Vendored libnetfilter_queue source root for the live-buffer probe")

if(NOT EXISTS "${LIVE_POC_NETFILTER_ROOT}/libnetfilter_queue/include/libnetfilter_queue/libnetfilter_queue.h")
  message(FATAL_ERROR "SAKAMOTO_NETFILTER_ROOT must point at checked-in netfilter sources")
endif()

set(LIVE_POC_CONFIG_DIR "${CMAKE_CURRENT_BINARY_DIR}/nfqueue_live_poc_config")
file(MAKE_DIRECTORY "${LIVE_POC_CONFIG_DIR}/libnfnetlink")
file(WRITE "${LIVE_POC_CONFIG_DIR}/config.h"
     "#pragma once\n#define HAVE_VISIBILITY_HIDDEN 1\n")
file(WRITE "${LIVE_POC_CONFIG_DIR}/libnfnetlink/linux_nfnetlink.h"
     "#pragma once\n#include <linux/netfilter/nfnetlink.h>\n")

add_library(nfqueue_live_poc_mnl STATIC
  "${LIVE_POC_NETFILTER_ROOT}/libmnl/src/socket.c"
  "${LIVE_POC_NETFILTER_ROOT}/libmnl/src/callback.c"
  "${LIVE_POC_NETFILTER_ROOT}/libmnl/src/nlmsg.c"
  "${LIVE_POC_NETFILTER_ROOT}/libmnl/src/attr.c"
)
target_include_directories(nfqueue_live_poc_mnl
  PUBLIC "${LIVE_POC_NETFILTER_ROOT}/libmnl/include"
  PRIVATE
    "${LIVE_POC_NETFILTER_ROOT}/cmake_config/libmnl"
    "${LIVE_POC_NETFILTER_ROOT}/libmnl/src"
)

add_library(nfqueue_live_poc_nfnetlink STATIC
  "${LIVE_POC_NETFILTER_ROOT}/libnfnetlink/src/libnfnetlink.c"
  "${LIVE_POC_NETFILTER_ROOT}/libnfnetlink/src/iftable.c"
  "${LIVE_POC_NETFILTER_ROOT}/libnfnetlink/src/rtnl.c"
)
target_include_directories(nfqueue_live_poc_nfnetlink
  PUBLIC
    "${LIVE_POC_CONFIG_DIR}"
    "${LIVE_POC_NETFILTER_ROOT}/libnfnetlink/include"
  PRIVATE
    "${LIVE_POC_NETFILTER_ROOT}/libnfnetlink/src"
)
target_compile_definitions(nfqueue_live_poc_nfnetlink PUBLIC NFNL_EXPORT=)

add_library(nfqueue_live_poc_queue STATIC
  "${LIVE_POC_NETFILTER_ROOT}/libnetfilter_queue/src/libnetfilter_queue.c"
  "${LIVE_POC_NETFILTER_ROOT}/libnetfilter_queue/src/nlmsg.c"
)
target_include_directories(nfqueue_live_poc_queue
  PUBLIC "${LIVE_POC_NETFILTER_ROOT}/libnetfilter_queue/include"
  PRIVATE
    "${LIVE_POC_CONFIG_DIR}"
    "${LIVE_POC_NETFILTER_ROOT}/libnetfilter_queue/src"
)
target_link_libraries(nfqueue_live_poc_queue
  PUBLIC nfqueue_live_poc_mnl nfqueue_live_poc_nfnetlink
)

foreach(target nfqueue_live_poc_mnl nfqueue_live_poc_nfnetlink nfqueue_live_poc_queue)
  set_target_properties(${target} PROPERTIES
    C_EXTENSIONS ON
    POSITION_INDEPENDENT_CODE ON
  )
endforeach()

add_vpp_plugin(nfqueue_live_poc
  SOURCES
    plugin.c
    nfqueue_live_poc.c
  LINK_LIBRARIES
    vlib
    vppinfra
    nfqueue_live_poc_queue
    nfqueue_live_poc_mnl
    nfqueue_live_poc_nfnetlink
  SUPPORTED_OS_LIST Linux Android
)
