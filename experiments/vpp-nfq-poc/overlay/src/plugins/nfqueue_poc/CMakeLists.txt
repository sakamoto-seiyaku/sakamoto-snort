# SPDX-License-Identifier: Apache-2.0

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Android")
  set(SAKAMOTO_NETFILTER_ROOT "" CACHE PATH "Vendored netfilter userspace source root")
  if(NOT EXISTS "${SAKAMOTO_NETFILTER_ROOT}/libnetfilter_queue/include/libnetfilter_queue/libnetfilter_queue.h")
    message(WARNING "-- SAKAMOTO_NETFILTER_ROOT is missing libnetfilter_queue headers - nfqueue_poc plugin disabled")
    return()
  endif()
  set(NFQUEUE_POC_NETFILTER_CONFIG_DIR "${CMAKE_CURRENT_BINARY_DIR}/netfilter_config")
  file(MAKE_DIRECTORY "${NFQUEUE_POC_NETFILTER_CONFIG_DIR}")
  file(MAKE_DIRECTORY "${NFQUEUE_POC_NETFILTER_CONFIG_DIR}/libnfnetlink")
  file(WRITE "${NFQUEUE_POC_NETFILTER_CONFIG_DIR}/config.h" "#pragma once\n#define HAVE_VISIBILITY_HIDDEN 1\n")
  file(WRITE "${NFQUEUE_POC_NETFILTER_CONFIG_DIR}/libnfnetlink/linux_nfnetlink.h" "#pragma once\n#include <linux/netfilter/nfnetlink.h>\n")

  add_library(nfqueue_poc_mnl STATIC
    "${SAKAMOTO_NETFILTER_ROOT}/libmnl/src/socket.c"
    "${SAKAMOTO_NETFILTER_ROOT}/libmnl/src/callback.c"
    "${SAKAMOTO_NETFILTER_ROOT}/libmnl/src/nlmsg.c"
    "${SAKAMOTO_NETFILTER_ROOT}/libmnl/src/attr.c"
  )
  target_include_directories(nfqueue_poc_mnl
    PUBLIC "${SAKAMOTO_NETFILTER_ROOT}/libmnl/include"
    PRIVATE
      "${SAKAMOTO_NETFILTER_ROOT}/cmake_config/libmnl"
      "${SAKAMOTO_NETFILTER_ROOT}/libmnl/src"
  )

  add_library(nfqueue_poc_nfnetlink STATIC
    "${SAKAMOTO_NETFILTER_ROOT}/libnfnetlink/src/libnfnetlink.c"
    "${SAKAMOTO_NETFILTER_ROOT}/libnfnetlink/src/iftable.c"
    "${SAKAMOTO_NETFILTER_ROOT}/libnfnetlink/src/rtnl.c"
  )
  target_include_directories(nfqueue_poc_nfnetlink
    PUBLIC
      "${NFQUEUE_POC_NETFILTER_CONFIG_DIR}"
      "${SAKAMOTO_NETFILTER_ROOT}/libnfnetlink/include"
    PRIVATE
      "${SAKAMOTO_NETFILTER_ROOT}/libnfnetlink/include"
      "${SAKAMOTO_NETFILTER_ROOT}/libnfnetlink/src"
  )
  target_compile_definitions(nfqueue_poc_nfnetlink PUBLIC NFNL_EXPORT=)

  add_library(nfqueue_poc_netfilter_queue STATIC
    "${SAKAMOTO_NETFILTER_ROOT}/libnetfilter_queue/src/libnetfilter_queue.c"
    "${SAKAMOTO_NETFILTER_ROOT}/libnetfilter_queue/src/nlmsg.c"
  )
  target_include_directories(nfqueue_poc_netfilter_queue
    PUBLIC
      "${SAKAMOTO_NETFILTER_ROOT}/libnetfilter_queue/include"
    PRIVATE
      "${NFQUEUE_POC_NETFILTER_CONFIG_DIR}"
      "${SAKAMOTO_NETFILTER_ROOT}/libnetfilter_queue/src"
  )
  target_link_libraries(nfqueue_poc_netfilter_queue
    PUBLIC nfqueue_poc_mnl nfqueue_poc_nfnetlink
  )

  foreach(target nfqueue_poc_mnl nfqueue_poc_nfnetlink nfqueue_poc_netfilter_queue)
    set_target_properties(${target}
      PROPERTIES
        C_EXTENSIONS ON
        POSITION_INDEPENDENT_CODE ON
    )
  endforeach()

  set(NFQUEUE_LINK_LIBRARIES
    nfqueue_poc_netfilter_queue
    nfqueue_poc_mnl
    nfqueue_poc_nfnetlink
  )
  include_directories(
    "${SAKAMOTO_NETFILTER_ROOT}/libnetfilter_queue/include"
  )
else()
  vpp_find_path(NFQUEUE_INCLUDE_DIR NAMES libnetfilter_queue/libnetfilter_queue.h)
  if (NOT NFQUEUE_INCLUDE_DIR)
    message(WARNING "-- libnetfilter_queue headers not found - nfqueue_poc plugin disabled")
    return()
  endif()

  vpp_plugin_find_library(nfqueue_poc NFQUEUE_LIB libnetfilter_queue.so)
  if (NOT NFQUEUE_LIB)
    message(WARNING "-- libnetfilter_queue library not found - nfqueue_poc plugin disabled")
    return()
  endif()

  set(NFQUEUE_LINK_LIBRARIES ${NFQUEUE_LIB})
  include_directories(${NFQUEUE_INCLUDE_DIR})
endif()

add_vpp_plugin(nfqueue_poc
  SOURCES
  plugin.c
  nfqueue_poc.c

  INSTALL_HEADERS
  nfqueue_poc.h

  LINK_LIBRARIES
  vlib
  vppinfra
  ${NFQUEUE_LINK_LIBRARIES}

  SUPPORTED_OS_LIST Linux Android
)
