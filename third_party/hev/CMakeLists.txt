# SPDX-License-Identifier: MIT
cmake_minimum_required(VERSION 3.18)
project(sakamoto_hev LANGUAGES C ASM)

find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_package(Threads REQUIRED)
get_filename_component(SAKAMOTO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
# Staged sources are immutable snapshots. Editing the fork must re-run staging
# even when a persistent build reuses its CMake command-line identity.
file(GLOB_RECURSE HEV_FORK_INPUTS CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/product/*"
  "${CMAKE_CURRENT_SOURCE_DIR}/patches/*")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  ${HEV_FORK_INPUTS} "${CMAKE_CURRENT_SOURCE_DIR}/upstream-manifest.json"
  "${SAKAMOTO_ROOT}/tools/product/stage-hev.py"
  "${SAKAMOTO_ROOT}/tools/product/vendor-hev.py")
execute_process(
  COMMAND "${Python3_EXECUTABLE}" "${SAKAMOTO_ROOT}/tools/product/stage-hev.py"
          --output-root "${CMAKE_CURRENT_BINARY_DIR}/staged"
  OUTPUT_VARIABLE HEV_SOURCE OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE HEV_STAGE_RESULT)
if(NOT HEV_STAGE_RESULT EQUAL 0)
  message(FATAL_ERROR "The offline HEV source/patch manifest failed verification")
endif()
execute_process(COMMAND "${Python3_EXECUTABLE}" "${SAKAMOTO_ROOT}/tools/product/hev-notices.py"
  --output "${CMAKE_CURRENT_BINARY_DIR}/hev-notices.txt" RESULT_VARIABLE HEV_NOTICE_RESULT)
if(NOT HEV_NOTICE_RESULT EQUAL 0)
  message(FATAL_ERROR "Pinned HEV dependency notice packaging failed")
endif()
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/hev-notices.txt"
  DESTINATION "share/licenses/sakamoto")

set(HEV_TASK "${HEV_SOURCE}/third-part/hev-task-system")
file(GLOB_RECURSE HEV_TASK_C CONFIGURE_DEPENDS "${HEV_TASK}/src/*.c")
add_library(sakamoto_hev_task STATIC ${HEV_TASK_C}
  "${HEV_TASK}/src/kern/task/hev-task-execute.S")
set_target_properties(sakamoto_hev_task PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_features(sakamoto_hev_task PRIVATE c_std_11)
target_include_directories(sakamoto_hev_task PUBLIC "${HEV_TASK}/include"
  PRIVATE "${HEV_TASK}/src")
target_compile_definitions(sakamoto_hev_task PRIVATE
  CONFIG_STACK_BACKEND=STACK_MMAP
  CONFIG_STACK_OVERFLOW_DETECTION=1 CONFIG_MEMALLOC_SLICE_ALIGN=16
  CONFIG_MEMALLOC_SLICE_MAX_SIZE=4096 CONFIG_MEMALLOC_SLICE_MAX_COUNT=1000
  CONFIG_SCHED_CLOCK=CLOCK_NONE)
target_compile_options(sakamoto_hev_task PRIVATE -Wall -fvisibility=hidden)
target_link_libraries(sakamoto_hev_task PUBLIC Threads::Threads)

set(HEV_LWIP "${HEV_SOURCE}/third-part/lwip/src")
add_library(sakamoto_hev_lwip STATIC
  "${HEV_SOURCE}/sakamoto/hev-lwip-context.c"
  "${HEV_LWIP}/core/init.c" "${HEV_LWIP}/core/def.c"
  "${HEV_LWIP}/core/inet_chksum.c" "${HEV_LWIP}/core/ip.c"
  "${HEV_LWIP}/core/mem.c" "${HEV_LWIP}/core/memp.c"
  "${HEV_LWIP}/core/netif.c" "${HEV_LWIP}/core/pbuf.c"
  "${HEV_LWIP}/core/tcp.c" "${HEV_LWIP}/core/tcp_in.c"
  "${HEV_LWIP}/core/tcp_out.c"
  "${HEV_LWIP}/core/udp.c" "${HEV_LWIP}/core/ipv4/ip4.c"
  "${HEV_LWIP}/core/ipv4/ip4_addr.c"
  "${HEV_LWIP}/core/ipv6/ip6.c" "${HEV_LWIP}/core/ipv6/ip6_addr.c"
  "${HEV_LWIP}/core/ipv6/nd6.c" "${HEV_LWIP}/core/ipv6/icmp6.c")
set_target_properties(sakamoto_hev_lwip PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_features(sakamoto_hev_lwip PRIVATE c_std_11)
target_include_directories(sakamoto_hev_lwip PUBLIC
  "${HEV_SOURCE}/sakamoto" "${HEV_LWIP}/include"
  "${HEV_LWIP}/ports/include")
target_compile_options(sakamoto_hev_lwip PRIVATE -Wall -fvisibility=hidden)
option(SAKAMOTO_PRODUCT_VPN_LARGE_SEGMENT_EXPERIMENT
  "Enable a larger inner TCP packet profile (legacy option name)" ON)
set(vpn_tun_mtu_default 1500)
if(SAKAMOTO_PRODUCT_VPN_LARGE_SEGMENT_EXPERIMENT)
  set(vpn_tun_mtu_default 10000)
endif()
set(SAKAMOTO_PRODUCT_VPN_TUN_MTU "${vpn_tun_mtu_default}" CACHE STRING
  "Inner VPN MTU: 1500, or experimental 3000/10000")
if((SAKAMOTO_PRODUCT_VPN_LARGE_SEGMENT_EXPERIMENT AND
    NOT SAKAMOTO_PRODUCT_VPN_TUN_MTU MATCHES "^(3000|10000)$") OR
   (NOT SAKAMOTO_PRODUCT_VPN_LARGE_SEGMENT_EXPERIMENT AND
    NOT SAKAMOTO_PRODUCT_VPN_TUN_MTU STREQUAL "1500"))
  message(FATAL_ERROR "VPN MTU does not match the selected packet profile")
endif()
target_compile_definitions(sakamoto_hev_lwip PUBLIC
  SAKAMOTO_PRODUCT_VPN_TUN_MTU=${SAKAMOTO_PRODUCT_VPN_TUN_MTU})
if(SAKAMOTO_PRODUCT_VPN_LARGE_SEGMENT_EXPERIMENT)
  target_compile_definitions(sakamoto_hev_lwip PUBLIC
    SAKAMOTO_PRODUCT_VPN_LARGE_SEGMENT_EXPERIMENT=1)
endif()
option(SAKAMOTO_PRODUCT_VPN_TCP_BUFFER_EXPERIMENT
  "Use 65528-byte owner-local TCP sndbuf/ring with unchanged receive window" OFF)
if(SAKAMOTO_PRODUCT_VPN_TCP_BUFFER_EXPERIMENT)
  target_compile_definitions(sakamoto_hev_lwip PUBLIC
    SAKAMOTO_PRODUCT_VPN_TCP_BUFFER_EXPERIMENT=1)
endif()

# Product allocator is separate so lower-level fault fixtures can substitute
# their own heap without replacing real lwIP pbuf/PCB implementations.
add_library(sakamoto_hev_memory STATIC
  "${HEV_SOURCE}/sakamoto/hev-lwip-memory.c")
set_target_properties(sakamoto_hev_memory PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_features(sakamoto_hev_memory PRIVATE c_std_11)
target_link_libraries(sakamoto_hev_memory PUBLIC sakamoto_hev_lwip)
target_compile_options(sakamoto_hev_memory PRIVATE -Wall -Wextra -Werror
  -fvisibility=hidden)

# The actual upstream session implementation, including its Direct fork.
# A static archive build alone is not an end-to-end transport witness.
add_library(sakamoto_hev_session STATIC
  "${HEV_SOURCE}/src/hev-socks5-session-tcp.c"
  "${HEV_SOURCE}/src/misc/hev-ring-buffer.c"
  "${HEV_SOURCE}/src/hev-socks5-session-udp.c"
  "${HEV_SOURCE}/src/hev-socks5-session.c"
  "${HEV_SOURCE}/src/core/src/hev-socks5.c"
  "${HEV_SOURCE}/src/core/src/hev-socks5-client.c"
  "${HEV_SOURCE}/src/core/src/hev-socks5-client-tcp.c"
  "${HEV_SOURCE}/src/core/src/hev-socks5-tcp.c"
  "${HEV_SOURCE}/src/core/src/hev-socks5-client-udp.c"
  "${HEV_SOURCE}/src/core/src/hev-socks5-udp.c")
set_target_properties(sakamoto_hev_session PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_features(sakamoto_hev_session PRIVATE c_std_11)
target_compile_definitions(sakamoto_hev_session PRIVATE SAKAMOTO_HEV_DIRECT_ONLY=1 _GNU_SOURCE)
option(SAKAMOTO_PRODUCT_VPN_UDP_BATCH_EXPERIMENT
  "Send bounded ready UDP datagrams in one owner-local syscall" OFF)
if(SAKAMOTO_PRODUCT_VPN_UDP_BATCH_EXPERIMENT)
  target_compile_definitions(sakamoto_hev_session PUBLIC
    SAKAMOTO_PRODUCT_VPN_UDP_BATCH_EXPERIMENT=1)
endif()
option(SAKAMOTO_PRODUCT_VPN_TCP_BATCH_EXPERIMENT
  "Bound ready TCP splice work and aggregate native VPN graph frames" OFF)
if(SAKAMOTO_PRODUCT_VPN_TCP_BATCH_EXPERIMENT)
  target_compile_definitions(sakamoto_hev_session PUBLIC
    SAKAMOTO_PRODUCT_VPN_TCP_BATCH_EXPERIMENT=1)
endif()
option(SAKAMOTO_PRODUCT_VPN_TCP_PROGRESS_EXPERIMENT
  "Gate socket readiness by the owner-local TCP ring and pending writes" OFF)
if(SAKAMOTO_PRODUCT_VPN_TCP_PROGRESS_EXPERIMENT)
  target_compile_definitions(sakamoto_hev_session PUBLIC
    SAKAMOTO_PRODUCT_VPN_TCP_PROGRESS_EXPERIMENT=1)
endif()
target_include_directories(sakamoto_hev_session PUBLIC
  "${HEV_SOURCE}/src" "${HEV_SOURCE}/src/core/src"
  "${HEV_SOURCE}/src/misc")
target_link_libraries(sakamoto_hev_session PUBLIC sakamoto_hev_task sakamoto_hev_lwip)
target_compile_options(sakamoto_hev_session PRIVATE -Wall -fvisibility=hidden
  -ffunction-sections -fdata-sections)

add_library(sakamoto_hev_owner STATIC "${HEV_SOURCE}/sakamoto/hev-owner.c")
set_target_properties(sakamoto_hev_owner PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_features(sakamoto_hev_owner PRIVATE c_std_11)
target_include_directories(sakamoto_hev_owner SYSTEM PRIVATE "${HEV_TASK}/src")
target_link_libraries(sakamoto_hev_owner PUBLIC sakamoto_hev_session
  "-Wl,--start-group" sakamoto_hev_memory sakamoto_hev_lwip "-Wl,--end-group")
target_compile_options(sakamoto_hev_owner PRIVATE -Wall -Wextra -Werror
  -fvisibility=hidden)

option(SAKAMOTO_HEV_TESTS "Build standalone real-dependency seam tests" OFF)
if(SAKAMOTO_HEV_TESTS)
  enable_testing()
  add_executable(sakamoto-hev-owner-underlay-test "${SAKAMOTO_ROOT}/tests/host/hev_owner_underlay_test.c")
  target_link_libraries(sakamoto-hev-owner-underlay-test PRIVATE sakamoto_hev_owner)
  target_compile_options(sakamoto-hev-owner-underlay-test PRIVATE -Wall -Wextra -Werror)
  target_link_options(sakamoto-hev-owner-underlay-test PRIVATE -Wl,--gc-sections)
  foreach(family IN ITEMS ipv4 ipv6)
    add_test(NAME sakamoto-hev-owner-${family}-udp-underlay-test COMMAND sh
      "${SAKAMOTO_ROOT}/tests/host/run-hev-tcp-test.sh" $<TARGET_FILE:sakamoto-hev-owner-underlay-test> ${family})
    set_tests_properties(sakamoto-hev-owner-${family}-udp-underlay-test PROPERTIES TIMEOUT 10)
  endforeach()
  add_executable(sakamoto-hev-owner-capacity-test "${SAKAMOTO_ROOT}/tests/host/hev_owner_capacity_test.c")
  target_link_libraries(sakamoto-hev-owner-capacity-test PRIVATE sakamoto_hev_owner)
  target_compile_options(sakamoto-hev-owner-capacity-test PRIVATE -Wall -Wextra -Werror)
  target_link_options(sakamoto-hev-owner-capacity-test PRIVATE -Wl,--gc-sections)
  foreach(family IN ITEMS ipv4 ipv6)
    add_test(NAME sakamoto-hev-owner-${family}-udp-capacity-test COMMAND sh
      "${SAKAMOTO_ROOT}/tests/host/run-hev-tcp-test.sh" $<TARGET_FILE:sakamoto-hev-owner-capacity-test> ${family})
    set_tests_properties(sakamoto-hev-owner-${family}-udp-capacity-test PROPERTIES TIMEOUT 20)
  endforeach()
  add_executable(sakamoto-hev-owner-tcp-test "${SAKAMOTO_ROOT}/tests/host/hev_owner_tcp_test.c")
  target_link_libraries(sakamoto-hev-owner-tcp-test PRIVATE sakamoto_hev_owner)
  target_compile_definitions(sakamoto-hev-owner-tcp-test PRIVATE _GNU_SOURCE)
  target_compile_options(sakamoto-hev-owner-tcp-test PRIVATE -Wall -Wextra -Werror)
  target_link_options(sakamoto-hev-owner-tcp-test PRIVATE -Wl,--gc-sections)
  set(HEV_TCP_TEST_COMMAND sh "${SAKAMOTO_ROOT}/tests/host/run-hev-tcp-test.sh" $<TARGET_FILE:sakamoto-hev-owner-tcp-test>)
  add_test(NAME sakamoto-hev-owner-tcp4-test COMMAND ${HEV_TCP_TEST_COMMAND})
  add_test(NAME sakamoto-hev-owner-tcp6-test COMMAND ${HEV_TCP_TEST_COMMAND} ipv6)
  set_tests_properties(sakamoto-hev-owner-tcp4-test sakamoto-hev-owner-tcp6-test PROPERTIES TIMEOUT 30)
  foreach(family IN ITEMS ipv4 ipv6)
    foreach(mode IN ITEMS refusal unreachable reset remote-fin underlay hold-ack session-capacity pcb-capacity
                           socket-capacity packet-credit pbuf-capacity)
      add_test(NAME sakamoto-hev-owner-${family}-${mode}-test COMMAND ${HEV_TCP_TEST_COMMAND} ${family} ${mode})
      set_tests_properties(sakamoto-hev-owner-${family}-${mode}-test PROPERTIES TIMEOUT 30)
    endforeach()
  endforeach()
  add_executable(sakamoto-product-socket-broker-test
    "${SAKAMOTO_ROOT}/src/product/vpp/product_vpn_socket_broker.c"
    "${SAKAMOTO_ROOT}/tests/host/product_vpn_socket_broker_test.c")
  target_include_directories(sakamoto-product-socket-broker-test PRIVATE
    "${SAKAMOTO_ROOT}/src/product/vpp")
  target_compile_options(sakamoto-product-socket-broker-test PRIVATE -Wall -Wextra -Werror)
  add_test(NAME sakamoto-product-socket-broker-test COMMAND sakamoto-product-socket-broker-test)
  set_tests_properties(sakamoto-product-socket-broker-test PROPERTIES TIMEOUT 5)
  add_executable(sakamoto-product-flow-stack-test
    "${SAKAMOTO_ROOT}/src/product/vpp/product_vpn_flow_stack_hev.c"
    "${SAKAMOTO_ROOT}/tests/host/product_vpn_flow_stack_test.c")
  target_include_directories(sakamoto-product-flow-stack-test PRIVATE
    "${SAKAMOTO_ROOT}/src/product/vpp")
  target_link_libraries(sakamoto-product-flow-stack-test PRIVATE sakamoto_hev_owner)
  target_link_options(sakamoto-product-flow-stack-test PRIVATE -Wl,--gc-sections)
  target_compile_options(sakamoto-product-flow-stack-test PRIVATE -Wall -Wextra -Werror)
  add_test(NAME sakamoto-product-flow-stack-test COMMAND sakamoto-product-flow-stack-test)
  add_test(NAME sakamoto-product-flow-stack-ipv6-test COMMAND sakamoto-product-flow-stack-test ipv6)
  add_test(NAME sakamoto-product-flow-stack-ipv6-extension-test COMMAND sakamoto-product-flow-stack-test ipv6-extension)
  set_tests_properties(sakamoto-product-flow-stack-ipv6-extension-test PROPERTIES TIMEOUT 5)
  set_tests_properties(sakamoto-product-flow-stack-ipv6-test PROPERTIES TIMEOUT 5)
  set_tests_properties(sakamoto-product-flow-stack-test PROPERTIES TIMEOUT 5)
  add_executable(sakamoto-hev-owner-transport-test
    "${SAKAMOTO_ROOT}/tests/host/hev_owner_transport_test.c")
  target_link_libraries(sakamoto-hev-owner-transport-test PRIVATE sakamoto_hev_owner)
  target_link_options(sakamoto-hev-owner-transport-test PRIVATE -Wl,--gc-sections)
  target_compile_options(sakamoto-hev-owner-transport-test PRIVATE -Wall -Wextra -Werror)
  add_test(NAME sakamoto-hev-owner-transport-test COMMAND sakamoto-hev-owner-transport-test)
  set_tests_properties(sakamoto-hev-owner-transport-test PROPERTIES TIMEOUT 5)
  add_executable(sakamoto-hev-scheduler-test
    "${SAKAMOTO_ROOT}/tests/host/hev_owner_scheduler_test.c")
  target_include_directories(sakamoto-hev-scheduler-test SYSTEM PRIVATE "${HEV_TASK}/src")
  target_link_libraries(sakamoto-hev-scheduler-test PRIVATE sakamoto_hev_task)
  target_compile_options(sakamoto-hev-scheduler-test PRIVATE -Wall -Wextra -Werror)
  add_test(NAME sakamoto-hev-scheduler-test COMMAND sakamoto-hev-scheduler-test)
  add_executable(sakamoto-hev-lwip-test
    "${SAKAMOTO_ROOT}/tests/host/hev_owner_lwip_test.c")
  target_link_libraries(sakamoto-hev-lwip-test PRIVATE sakamoto_hev_lwip)
  target_compile_options(sakamoto-hev-lwip-test PRIVATE -Wall -Wextra -Werror)
  add_test(NAME sakamoto-hev-lwip-test COMMAND sakamoto-hev-lwip-test)
  set_tests_properties(sakamoto-hev-lwip-test PROPERTIES TIMEOUT 5)
  add_executable(sakamoto-hev-memory-test
    "${SAKAMOTO_ROOT}/tests/host/hev_owner_memory_test.c")
  target_link_libraries(sakamoto-hev-memory-test PRIVATE sakamoto_hev_memory)
  target_compile_options(sakamoto-hev-memory-test PRIVATE -Wall -Wextra -Werror)
  add_test(NAME sakamoto-hev-memory-test COMMAND sakamoto-hev-memory-test)
  set_tests_properties(sakamoto-hev-memory-test PROPERTIES TIMEOUT 5)
  add_executable(sakamoto-hev-direct-receive-test
    "${SAKAMOTO_ROOT}/tests/host/hev_direct_receive_test.c")
  target_link_libraries(sakamoto-hev-direct-receive-test PRIVATE sakamoto_hev_session)
  target_link_options(sakamoto-hev-direct-receive-test PRIVATE -Wl,--gc-sections)
  target_compile_options(sakamoto-hev-direct-receive-test PRIVATE -Wall -Wextra -Werror)
  add_test(NAME sakamoto-hev-direct-receive-test COMMAND sakamoto-hev-direct-receive-test)
  set_tests_properties(sakamoto-hev-direct-receive-test PROPERTIES TIMEOUT 5)
  find_program(HEV_READELF NAMES llvm-readelf readelf REQUIRED)
  add_test(NAME sakamoto-hev-lwip-state-audit
    COMMAND "${Python3_EXECUTABLE}"
      "${SAKAMOTO_ROOT}/tests/host/hev_lwip_state_audit.py"
      --readelf "${HEV_READELF}" "$<TARGET_FILE:sakamoto_hev_lwip>")
endif()
