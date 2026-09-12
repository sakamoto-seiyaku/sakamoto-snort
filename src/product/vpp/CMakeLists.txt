# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.18)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/../NOTICE.tcp" DESTINATION share/licenses/sakamoto)
project(sakamoto_product_core_plugin LANGUAGES C)

include(GNUInstallDirs)

if(NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/lib")
endif()

if(NOT DEFINED VPP_SOURCE_DIR)
  message(FATAL_ERROR "VPP_SOURCE_DIR must point at the pinned official VPP source")
endif()
get_filename_component(VPP_SOURCE_DIR "${VPP_SOURCE_DIR}" REALPATH)
if(NOT EXISTS "${VPP_SOURCE_DIR}/src/cmake/VPPConfig.cmake")
  message(FATAL_ERROR "VPP_SOURCE_DIR does not contain the official VPP CMake integration")
endif()

# VPPConfig exposes add_vpp_plugin and its generated API pipeline for an
# external plugin.  The runtime itself is never copied into this repository.
set(VPP_INCLUDE_DIR "${VPP_INCLUDE_DIR}" CACHE PATH "Pinned VPP generated/include root")
set(VPP_APIGEN "${VPP_APIGEN}" CACHE FILEPATH "Pinned VPP API generator")
set(VPP_VAPI_C_GEN "${VPP_VAPI_C_GEN}" CACHE FILEPATH "Pinned VPP VAPI C generator")
set(VPP_VAPI_CPP_GEN "${VPP_VAPI_CPP_GEN}" CACHE FILEPATH "Pinned VPP VAPI C++ generator")
if(NOT VPP_INCLUDE_DIR)
  message(FATAL_ERROR "VPP_INCLUDE_DIR must point at the built pinned VPP headers")
endif()
if(NOT EXISTS "${VPP_APIGEN}" OR NOT EXISTS "${VPP_VAPI_C_GEN}"
   OR NOT EXISTS "${VPP_VAPI_CPP_GEN}")
  message(FATAL_ERROR "VPP API generators are required; do not use a hand-written API header")
endif()

if(ANDROID)
  # Android's dynamic linker does not make the VPP runtime's TLS state
  # available to an unlisted plugin dependency. Require the exact staged
  # runtime library directory so the plugin records its VPP closure directly.
  set(VPP_LIBRARY_DIR "${VPP_LIBRARY_DIR}" CACHE PATH
    "Exact staged VPP shared-library directory")
  if(NOT VPP_LIBRARY_DIR OR NOT IS_ABSOLUTE "${VPP_LIBRARY_DIR}")
    message(FATAL_ERROR
      "Android product builds require an absolute VPP_LIBRARY_DIR")
  endif()
  if(NOT IS_DIRECTORY "${VPP_LIBRARY_DIR}")
    message(FATAL_ERROR
      "Android product VPP_LIBRARY_DIR does not exist: ${VPP_LIBRARY_DIR}")
  endif()
  set(SAKAMOTO_PRODUCT_VPP_LINK_LIBRARIES)
  foreach(vpp_library IN ITEMS
      libvlibapi.so
      libvlibmemory.so
      libvnet.so
      libvlib.so
      libvppinfra.so)
    set(vpp_library_path "${VPP_LIBRARY_DIR}/${vpp_library}")
    if(NOT EXISTS "${vpp_library_path}" OR
       IS_DIRECTORY "${vpp_library_path}")
      message(FATAL_ERROR
        "Android product VPP library is missing: ${vpp_library_path}")
    endif()
    list(APPEND SAKAMOTO_PRODUCT_VPP_LINK_LIBRARIES
      "${vpp_library_path}")
  endforeach()
endif()
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/pinned-vpp-revision.txt"
  SAKAMOTO_PRODUCT_VPP_REVISION LIMIT_COUNT 1)
string(STRIP "${SAKAMOTO_PRODUCT_VPP_REVISION}"
  SAKAMOTO_PRODUCT_VPP_REVISION)
string(LENGTH "${SAKAMOTO_PRODUCT_VPP_REVISION}" revision_length)
if(NOT revision_length EQUAL 40)
  message(FATAL_ERROR "pinned-vpp-revision.txt must contain one 40-character commit")
endif()
if(NOT SAKAMOTO_PRODUCT_VPP_REVISION MATCHES "^[0-9a-fA-F]+$")
  message(FATAL_ERROR "pinned-vpp-revision.txt must contain a hexadecimal commit")
endif()
if(NOT EXISTS "${VPP_SOURCE_DIR}/.git")
  message(FATAL_ERROR "VPP_SOURCE_DIR must be an auditable Git checkout")
endif()
execute_process(
  COMMAND git -C "${VPP_SOURCE_DIR}" rev-parse HEAD
  OUTPUT_VARIABLE VPP_SOURCE_HEAD
  OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE VPP_SOURCE_HEAD_RESULT)
if(NOT VPP_SOURCE_HEAD_RESULT EQUAL 0
   OR NOT "${VPP_SOURCE_HEAD}" STREQUAL "${SAKAMOTO_PRODUCT_VPP_REVISION}")
  message(FATAL_ERROR "VPP_SOURCE_DIR is not at the pinned product revision")
endif()
execute_process(
  COMMAND git -C "${VPP_SOURCE_DIR}" status --porcelain
  OUTPUT_VARIABLE VPP_SOURCE_STATUS
  OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE VPP_SOURCE_STATUS_RESULT)
if(NOT VPP_SOURCE_STATUS_RESULT EQUAL 0)
  message(FATAL_ERROR "VPP_SOURCE_DIR status cannot be inspected")
endif()
if(NOT "${VPP_SOURCE_STATUS}" STREQUAL "")
  set(SAKAMOTO_PRODUCT_VPP_SOURCE_TREE_SHA256
    "${SAKAMOTO_PRODUCT_VPP_SOURCE_TREE_SHA256}" CACHE STRING
    "Verified Product VPP patch-tree SHA-256")
  string(LENGTH "${SAKAMOTO_PRODUCT_VPP_SOURCE_TREE_SHA256}"
    source_tree_sha256_length)
  if(NOT source_tree_sha256_length EQUAL 64 OR
     NOT SAKAMOTO_PRODUCT_VPP_SOURCE_TREE_SHA256 MATCHES "^[0-9a-fA-F]+$")
    message(FATAL_ERROR
      "patched VPP_SOURCE_DIR requires its verified source-tree SHA-256")
  endif()
  set(VPP_SOURCE_DIFF_FILE
    "${CMAKE_CURRENT_BINARY_DIR}/product-vpp-source-tree.diff")
  execute_process(
    COMMAND git -C "${VPP_SOURCE_DIR}" diff --binary HEAD
    OUTPUT_FILE "${VPP_SOURCE_DIFF_FILE}"
    RESULT_VARIABLE VPP_SOURCE_DIFF_RESULT)
  if(NOT VPP_SOURCE_DIFF_RESULT EQUAL 0)
    message(FATAL_ERROR "patched VPP_SOURCE_DIR diff cannot be inspected")
  endif()
  file(SHA256 "${VPP_SOURCE_DIFF_FILE}" VPP_SOURCE_TREE_SHA256)
  file(REMOVE "${VPP_SOURCE_DIFF_FILE}")
  if(NOT "${VPP_SOURCE_TREE_SHA256}" STREQUAL
      "${SAKAMOTO_PRODUCT_VPP_SOURCE_TREE_SHA256}")
    message(FATAL_ERROR "patched VPP_SOURCE_DIR tree identity mismatch")
  endif()
endif()

set(SAKAMOTO_PRODUCT_MANIFEST
  "${CMAKE_CURRENT_SOURCE_DIR}/product-vpp-artifact.properties")
if(NOT EXISTS "${SAKAMOTO_PRODUCT_MANIFEST}")
  message(FATAL_ERROR "the product artifact source manifest is required")
endif()
file(STRINGS "${SAKAMOTO_PRODUCT_MANIFEST}" SAKAMOTO_PRODUCT_MANIFEST_LINES)
foreach(line IN LISTS SAKAMOTO_PRODUCT_MANIFEST_LINES)
  if(line MATCHES "^artifact\\.id=(.*)$")
    set(SAKAMOTO_PRODUCT_ARTIFACT_ID "${CMAKE_MATCH_1}")
  elseif(line MATCHES "^product\\.api\\.identity=(.*)$")
    set(SAKAMOTO_PRODUCT_API_IDENTITY "${CMAKE_MATCH_1}")
  elseif(line MATCHES "^vpp\\.revision=(.*)$")
    set(SAKAMOTO_PRODUCT_MANIFEST_VPP_REVISION "${CMAKE_MATCH_1}")
  elseif(line MATCHES "^product\\.abi\\.version=(.*)$")
    set(SAKAMOTO_PRODUCT_ABI_VERSION "${CMAKE_MATCH_1}")
  elseif(line MATCHES "^product\\.api\\.version=(.*)$")
    set(SAKAMOTO_PRODUCT_API_VERSION "${CMAKE_MATCH_1}")
  elseif(line MATCHES "^product\\.plugin=(.*)$")
    set(SAKAMOTO_PRODUCT_PLUGIN "${CMAKE_MATCH_1}")
endif()
endforeach()
foreach(required_value IN ITEMS
    SAKAMOTO_PRODUCT_ARTIFACT_ID
    SAKAMOTO_PRODUCT_API_IDENTITY
    SAKAMOTO_PRODUCT_MANIFEST_VPP_REVISION
    SAKAMOTO_PRODUCT_ABI_VERSION
    SAKAMOTO_PRODUCT_API_VERSION
    SAKAMOTO_PRODUCT_PLUGIN)
  if(NOT DEFINED ${required_value} OR "${${required_value}}" STREQUAL "")
    message(FATAL_ERROR "missing ${required_value} in product-vpp-artifact.properties")
  endif()
endforeach()
if(NOT "${SAKAMOTO_PRODUCT_MANIFEST_VPP_REVISION}"
   STREQUAL "${SAKAMOTO_PRODUCT_VPP_REVISION}")
  message(FATAL_ERROR
    "artifact manifest VPP revision does not match pinned-vpp-revision.txt")
endif()
if(NOT "${SAKAMOTO_PRODUCT_ABI_VERSION}" STREQUAL "1"
   OR NOT "${SAKAMOTO_PRODUCT_API_VERSION}" STREQUAL "1")
  message(FATAL_ERROR "the Host Product Core ABI/API version is not version 1")
endif()
if(NOT "${SAKAMOTO_PRODUCT_PLUGIN}" STREQUAL "product_core_plugin.so")
  message(FATAL_ERROR "the product manifest must allow exactly product_core_plugin.so")
endif()
string(LENGTH "${SAKAMOTO_PRODUCT_ARTIFACT_ID}" artifact_id_length)
string(LENGTH "${SAKAMOTO_PRODUCT_API_IDENTITY}" api_identity_length)
if(artifact_id_length GREATER 95 OR api_identity_length GREATER 95)
  message(FATAL_ERROR "product identity text exceeds the fixed VAPI reply fields")
endif()

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/product_core_identity.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/product_core_identity.h"
  @ONLY)

include("${VPP_SOURCE_DIR}/src/cmake/VPPConfig.cmake")
include_directories("${CMAKE_CURRENT_BINARY_DIR}")

# Offline source-pinned HEV fork. Its public Product adapter exposes no
# dependency types, and no experiment artifact enters this link closure.
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../../../third_party/hev"
                 "${CMAKE_CURRENT_BINARY_DIR}/hev")

option(SAKAMOTO_PRODUCT_HOST_EVIDENCE
  "Build the Host-only installed Product graph evidence seam" OFF)
set(SAKAMOTO_PRODUCT_PACKET_GRAPH_SOURCE product_packet_graph.c)
if(SAKAMOTO_PRODUCT_HOST_EVIDENCE)
  if(ANDROID)
    message(FATAL_ERROR
      "SAKAMOTO_PRODUCT_HOST_EVIDENCE is forbidden for Android Product builds")
  endif()
  set(SAKAMOTO_PRODUCT_PACKET_GRAPH_SOURCE
    product_packet_graph_host_evidence.c)
else()
  file(READ "${CMAKE_CURRENT_SOURCE_DIR}/product_packet_graph.c"
    SAKAMOTO_PRODUCT_PACKET_GRAPH_TEXT)
  foreach(host_evidence_token IN ITEMS
      "s174-valid-dual-stack-v1"
      "product packet-graph run-fixture")
    string(FIND "${SAKAMOTO_PRODUCT_PACKET_GRAPH_TEXT}"
      "${host_evidence_token}" host_evidence_offset)
    if(NOT host_evidence_offset EQUAL -1)
      message(FATAL_ERROR
        "Android/default Product source closure contains Host evidence: ${host_evidence_token}")
    endif()
  endforeach()
endif()

add_vpp_plugin(product_core
  SOURCES
    product_core_plugin.c
    product_packet.c
    product_fragment.c
    product_l4_policy.c
    product_flow_entry.c
    product_flow_udp.c
    product_flow_tcp.c
    product_root_nfqueue_adapter.c
    product_vpn_tun_adapter.c
    product_vpn_flow_stack_hev.c
    product_vpn_flow_stack.c
    product_vpn_socket_broker.c
    product_network_snapshot.c
    ${SAKAMOTO_PRODUCT_PACKET_GRAPH_SOURCE}
  API_FILES
    product_core.api
  VAT_AUTO_TEST
    OFF
  COMPONENT
    vpp-plugin-core
)
target_include_directories(product_core_plugin PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../include")
target_compile_definitions(product_core_plugin PRIVATE
  SAKAMOTO_PRODUCT_VPP_REVISION="${SAKAMOTO_PRODUCT_VPP_REVISION}"
)
target_link_libraries(product_core_plugin sakamoto_hev_owner)
if(SAKAMOTO_PRODUCT_HOST_EVIDENCE)
  target_compile_definitions(product_core_plugin PRIVATE
    SAKAMOTO_PRODUCT_HOST_EVIDENCE=1)
endif()
if(ANDROID)
  # Inline native timer scheduling must use the same 1 ms tick as the
  # allowlisted Android VPP stage, not the upstream 10 us host default.
  target_compile_definitions(product_core_plugin PRIVATE
    SAKAMOTO_VPP_ANDROID_IDLE_PROFILE=1)
  # Keep these as direct NEEDED entries. bionic must load the VPP libraries
  # before resolving the plugin's vlibapi TLS symbol (my_api_main).
  target_link_libraries(product_core_plugin
    "-Wl,--no-as-needed"
    ${SAKAMOTO_PRODUCT_VPP_LINK_LIBRARIES})
  # VPP resolves plugin entry points from the host process at load time. The
  # Android NDK toolchain adds --no-undefined by default, which is correct for
  # app libraries but rejects this loadable VPP plugin's host-owned symbols.
  target_link_options(product_core_plugin PRIVATE
    "-Wl,--allow-shlib-undefined"
    "-Wl,--unresolved-symbols=ignore-all")
endif()

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/product_core.api"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/vpp/api/plugins"
  COMPONENT vpp-plugin-core)
