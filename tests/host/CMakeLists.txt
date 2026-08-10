cmake_minimum_required(VERSION 3.18)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(sucre_snort_host_tests LANGUAGES CXX)
  include(CTest)
endif()

include(FetchContent)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
  URL_HASH SHA256=7b42b4d6ed48810c5362c265a17faebe90dc2373c885e5216439d37927f02926
)
FetchContent_MakeAvailable(googletest)

include(GoogleTest)

get_filename_component(SUCRE_SNORT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
set(HOST_TEST_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(RAPIDJSON_INCLUDE_DIR "${SUCRE_SNORT_ROOT}/third_party/rapidjson/include")
set(
  SUCRE_SNORT_MAINLINE_INCLUDE_DIRS
  "${SUCRE_SNORT_ROOT}/src"
  "${SUCRE_SNORT_ROOT}/src/main"
  "${SUCRE_SNORT_ROOT}/src/control/vnext"
  "${SUCRE_SNORT_ROOT}/src/platform/android"
  "${SUCRE_SNORT_ROOT}/src/datapath/nfqueue"
  "${SUCRE_SNORT_ROOT}/src/core/flow"
  "${SUCRE_SNORT_ROOT}/src/core/packet"
  "${SUCRE_SNORT_ROOT}/src/core/policy"
  "${SUCRE_SNORT_ROOT}/src/core/metrics"
  "${SUCRE_SNORT_ROOT}/src/app"
  "${SUCRE_SNORT_ROOT}/src/config"
)

set(SUCRE_SNORT_HOST_TEST_LANE "H")
set(SUCRE_SNORT_HOST_TEST_LABELS "host")

function(add_sucre_snort_host_test target)
  add_executable(${target} ${ARGN})
  target_include_directories(
    ${target}
    PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}"
      "${HOST_TEST_INCLUDE_DIR}"
      ${SUCRE_SNORT_MAINLINE_INCLUDE_DIRS}
  )
  target_include_directories(${target} SYSTEM PRIVATE "${RAPIDJSON_INCLUDE_DIR}")
  target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  target_link_libraries(${target} PRIVATE GTest::gtest_main)
  set_property(GLOBAL APPEND PROPERTY SUCRE_SNORT_HOST_TEST_TARGETS ${target})
  add_test(NAME "${SUCRE_SNORT_HOST_TEST_LANE}.${target}" COMMAND ${target})
  set_tests_properties(
    "${SUCRE_SNORT_HOST_TEST_LANE}.${target}"
    PROPERTIES LABELS "${SUCRE_SNORT_HOST_TEST_LABELS}"
  )
endfunction()

function(add_sucre_snort_host_tool target)
  add_executable(${target} ${ARGN})
  target_include_directories(
    ${target}
    PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}"
      "${HOST_TEST_INCLUDE_DIR}"
      ${SUCRE_SNORT_MAINLINE_INCLUDE_DIRS}
  )
  target_include_directories(${target} SYSTEM PRIVATE "${RAPIDJSON_INCLUDE_DIR}")
  target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
endfunction()

add_sucre_snort_host_tool(
  sucre-snort-ctl
  sucre_snort_ctl.cpp
  sucre_snort_ctl_session.cpp
  "${SUCRE_SNORT_ROOT}/src/control/vnext/ControlVNextCodec.cpp"
)

add_sucre_snort_host_test(package_state_tests package_state_tests.cpp)
add_sucre_snort_host_test(reason_metrics_tests reason_metrics_tests.cpp)
add_sucre_snort_host_test(ipv6_l4_walker_tests ipv6_l4_walker_tests.cpp)
add_sucre_snort_host_test(nfqueue_topology_tests nfqueue_topology_tests.cpp)
add_sucre_snort_host_test(
  packet_policy_tests
  packet_policy_tests.cpp
  "${SUCRE_SNORT_ROOT}/src/core/flow/FlowSteering.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/policy/PacketPolicy.cpp"
)
add_sucre_snort_host_test(
  flow_steering_tests
  flow_steering_tests.cpp
  "${SUCRE_SNORT_ROOT}/src/core/flow/FlowSteering.cpp"
)
add_sucre_snort_host_test(
  nfqueue_flow_adapter_tests
  nfqueue_flow_adapter_tests.cpp
  "${SUCRE_SNORT_ROOT}/src/datapath/nfqueue/NfqueueFlowAdapter.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/flow/FlowSteering.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/flow/FlowGraphIngress.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/flow/FlowGraphFragmentIngress.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/flow/FlowGraphInjection.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/flow/FragmentSteering.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/policy/PacketPolicy.cpp"
  "${SUCRE_SNORT_ROOT}/src/datapath/nfqueue/NfqueueFragmentLeaseBook.cpp"
  "${SUCRE_SNORT_ROOT}/src/datapath/nfqueue/NfqueuePacketLeaseAdapter.cpp"
)
target_compile_definitions(
  nfqueue_flow_adapter_tests
  PRIVATE
    "SUCRE_SNORT_SOURCE_ROOT=\"${SUCRE_SNORT_ROOT}\""
)
add_sucre_snort_host_test(
  vpp_graph_injection_tests
  vpp_graph_injection_tests.cpp
  "${SUCRE_SNORT_ROOT}/src/core/flow/FlowGraphInjection.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/flow/FlowSteering.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/policy/PacketPolicy.cpp"
)
add_sucre_snort_host_test(
  flow_graph_fragment_ingress_tests
  flow_graph_fragment_ingress_tests.cpp
  "${SUCRE_SNORT_ROOT}/src/core/flow/FlowGraphFragmentIngress.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/flow/FlowGraphIngress.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/flow/FlowGraphInjection.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/flow/FragmentSteering.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/flow/FlowSteering.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/policy/PacketPolicy.cpp"
)
add_sucre_snort_host_test(
  packet_capture_adapter_tests
  packet_capture_adapter_tests.cpp
  "${SUCRE_SNORT_ROOT}/src/core/flow/PacketCaptureAdapter.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/flow/FlowGraphIngress.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/flow/FlowSteering.cpp"
)
add_sucre_snort_host_test(
  fragment_steering_tests
  fragment_steering_tests.cpp
  "${SUCRE_SNORT_ROOT}/src/core/flow/FragmentSteering.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/flow/FlowSteering.cpp"
)
add_sucre_snort_host_test(
  nfqueue_packet_lease_adapter_tests
  nfqueue_packet_lease_adapter_tests.cpp
  "${SUCRE_SNORT_ROOT}/src/datapath/nfqueue/NfqueuePacketLeaseAdapter.cpp"
)
add_sucre_snort_host_test(
  nfqueue_fragment_lease_book_tests
  nfqueue_fragment_lease_book_tests.cpp
  "${SUCRE_SNORT_ROOT}/src/datapath/nfqueue/NfqueueFragmentLeaseBook.cpp"
  "${SUCRE_SNORT_ROOT}/src/datapath/nfqueue/NfqueuePacketLeaseAdapter.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/flow/FlowSteering.cpp"
)
add_sucre_snort_host_test(
  nfqueue_ipv4_pass_through_tests
  nfqueue_ipv4_pass_through_tests.cpp
  "${SUCRE_SNORT_ROOT}/src/datapath/nfqueue/NfqueueHookInstaller.cpp"
  "${SUCRE_SNORT_ROOT}/src/datapath/nfqueue/NfqueueHookPlan.cpp"
  "${SUCRE_SNORT_ROOT}/src/datapath/nfqueue/NfqueuePassThrough.cpp"
)
add_sucre_snort_host_test(
  control_vnext_codec_tests
  control_vnext_codec_tests.cpp
  "${SUCRE_SNORT_ROOT}/src/control/vnext/ControlVNextCodec.cpp"
)
add_sucre_snort_host_test(
  runtime_profile_tests
  runtime_profile_tests.cpp
  "${SUCRE_SNORT_ROOT}/src/main/RuntimeFactoryPlan.cpp"
  "${SUCRE_SNORT_ROOT}/src/main/RuntimeProfile.cpp"
)
add_sucre_snort_host_test(
  control_server_contract_tests
  control_server_contract_tests.cpp
  "${SUCRE_SNORT_ROOT}/src/control/vnext/ControlServer.cpp"
  "${SUCRE_SNORT_ROOT}/src/control/vnext/ControlVNextCodec.cpp"
  "${SUCRE_SNORT_ROOT}/src/main/DaemonRuntime.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/flow/FlowSteering.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/policy/PacketPolicy.cpp"
)
add_sucre_snort_host_test(
  control_server_init_socket_tests
  control_server_init_socket_tests.cpp
  "${SUCRE_SNORT_ROOT}/src/control/vnext/ControlServer.cpp"
  "${SUCRE_SNORT_ROOT}/src/control/vnext/ControlVNextCodec.cpp"
  "${SUCRE_SNORT_ROOT}/src/main/DaemonRuntime.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/flow/FlowSteering.cpp"
  "${SUCRE_SNORT_ROOT}/src/core/policy/PacketPolicy.cpp"
)
