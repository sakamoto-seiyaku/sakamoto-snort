# SPDX-License-Identifier: Apache-2.0

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

include_directories(${NFQUEUE_INCLUDE_DIR})

add_vpp_plugin(nfqueue_poc
  SOURCES
  plugin.c
  nfqueue_poc.c

  INSTALL_HEADERS
  nfqueue_poc.h

  LINK_LIBRARIES
  ${NFQUEUE_LIB}

  SUPPORTED_OS_LIST Linux
)
