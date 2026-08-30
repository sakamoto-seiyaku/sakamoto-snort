# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.18)
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
if(NOT VPP_SOURCE_STATUS_RESULT EQUAL 0 OR NOT "${VPP_SOURCE_STATUS}" STREQUAL "")
  message(FATAL_ERROR "VPP_SOURCE_DIR must be a clean checkout")
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

add_vpp_plugin(product_core
  SOURCES
    product_core_plugin.c
    product_packet.c
  API_FILES
    product_core.api
  VAT_AUTO_TEST
    OFF
  COMPONENT
    vpp-plugin-core
)
target_compile_definitions(product_core_plugin PRIVATE
  SAKAMOTO_PRODUCT_VPP_REVISION="${SAKAMOTO_PRODUCT_VPP_REVISION}"
)
if(ANDROID)
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
