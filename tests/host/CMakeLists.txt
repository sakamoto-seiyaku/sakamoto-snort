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

set(SUCRE_SNORT_HOST_TEST_LANE "H")
set(SUCRE_SNORT_HOST_TEST_LABELS "host")

set(_sucre_snort_host_has_asan OFF)
if(
  CMAKE_CXX_FLAGS MATCHES "-fsanitize=address"
  OR CMAKE_C_FLAGS MATCHES "-fsanitize=address"
  OR CMAKE_EXE_LINKER_FLAGS MATCHES "-fsanitize=address"
)
  set(_sucre_snort_host_has_asan ON)
endif()

set(_sucre_snort_host_has_coverage OFF)
if(
  CMAKE_CXX_FLAGS MATCHES "-fprofile-instr-generate"
  OR CMAKE_C_FLAGS MATCHES "-fprofile-instr-generate"
  OR CMAKE_EXE_LINKER_FLAGS MATCHES "-fprofile-instr-generate"
)
  set(_sucre_snort_host_has_coverage ON)
endif()

if(_sucre_snort_host_has_asan)
  set(SUCRE_SNORT_HOST_TEST_LANE "H.ASAN")
  set(SUCRE_SNORT_HOST_TEST_LABELS "${SUCRE_SNORT_HOST_TEST_LABELS};asan")
elseif(_sucre_snort_host_has_coverage)
  set(SUCRE_SNORT_HOST_TEST_LANE "H.COV")
  set(SUCRE_SNORT_HOST_TEST_LABELS "${SUCRE_SNORT_HOST_TEST_LABELS};coverage")
endif()

function(add_sucre_snort_host_test target)
  add_executable(${target} "${SUCRE_SNORT_ROOT}/src/Saver.cpp" ${ARGN})
  target_include_directories(
    ${target}
    PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}"
      "${SUCRE_SNORT_ROOT}/src"
  )
  target_include_directories(${target} PRIVATE "${HOST_TEST_INCLUDE_DIR}")
  target_include_directories(${target} SYSTEM PRIVATE "${RAPIDJSON_INCLUDE_DIR}")
  target_compile_options(${target} PRIVATE -Wall -Wextra -Werror)
  target_link_libraries(${target} PRIVATE GTest::gtest_main)
  set_property(GLOBAL APPEND PROPERTY SUCRE_SNORT_HOST_TEST_TARGETS ${target})
  gtest_discover_tests(
    ${target}
    DISCOVERY_TIMEOUT 60
    DISCOVERY_MODE PRE_TEST
    TEST_PREFIX "${SUCRE_SNORT_HOST_TEST_LANE}.${target}."
    PROPERTIES LABELS "${SUCRE_SNORT_HOST_TEST_LABELS}"
  )
endfunction()

function(add_sucre_snort_host_tool target)
  add_executable(${target} ${ARGN})
  target_include_directories(
    ${target}
    PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}"
      "${SUCRE_SNORT_ROOT}/src"
  )
  target_include_directories(${target} PRIVATE "${HOST_TEST_INCLUDE_DIR}")
  target_include_directories(${target} SYSTEM PRIVATE "${RAPIDJSON_INCLUDE_DIR}")
  target_compile_options(${target} PRIVATE -Wall -Wextra -Werror)
endfunction()

add_sucre_snort_host_tool(
  sucre-snort-ctl
  sucre_snort_ctl.cpp
  sucre_snort_ctl_session.cpp
  "${SUCRE_SNORT_ROOT}/src/ControlVNextCodec.cpp"
)

add_sucre_snort_host_test(package_state_tests package_state_tests.cpp)
add_sucre_snort_host_test(perf_metrics_tests perf_metrics_tests.cpp)
add_sucre_snort_host_test(reset_epoch_tests reset_epoch_tests.cpp "${SUCRE_SNORT_ROOT}/src/SnortRuntime.cpp")
add_sucre_snort_host_test(reason_metrics_tests reason_metrics_tests.cpp)
add_sucre_snort_host_test(conntrack_tests conntrack_tests.cpp "${SUCRE_SNORT_ROOT}/src/Conntrack.cpp")
target_compile_definitions(conntrack_tests PRIVATE SUCRE_SNORT_TESTING=1)
add_sucre_snort_host_test(ip_rules_engine_tests ip_rules_engine_tests.cpp "${SUCRE_SNORT_ROOT}/src/IpRulesEngine.cpp")
add_sucre_snort_host_test(ip_rules_engine_tests_nocache ip_rules_engine_tests.cpp "${SUCRE_SNORT_ROOT}/src/IpRulesEngine.cpp")
target_compile_definitions(ip_rules_engine_tests_nocache PRIVATE SUCRE_SNORT_IPRULES_DECISION_CACHE=0)
add_sucre_snort_host_test(rule_tests rule_tests.cpp "${SUCRE_SNORT_ROOT}/src/Rule.cpp")
add_sucre_snort_host_test(settings_tests settings_tests.cpp "${SUCRE_SNORT_ROOT}/src/Settings.cpp")
add_sucre_snort_host_test(stats_tests stats_tests.cpp "${SUCRE_SNORT_ROOT}/src/Stats.cpp" "${SUCRE_SNORT_ROOT}/src/AppStats.cpp" "${SUCRE_SNORT_ROOT}/src/DomainStats.cpp")
add_sucre_snort_host_test(
  domain_policy_sources_tests
  domain_policy_sources_tests.cpp
  "${SUCRE_SNORT_ROOT}/src/Address.cpp"
  "${SUCRE_SNORT_ROOT}/src/App.cpp"
  "${SUCRE_SNORT_ROOT}/src/AppStats.cpp"
  "${SUCRE_SNORT_ROOT}/src/BlockingList.cpp"
  "${SUCRE_SNORT_ROOT}/src/CustomList.cpp"
  "${SUCRE_SNORT_ROOT}/src/CustomRules.cpp"
  "${SUCRE_SNORT_ROOT}/src/Domain.cpp"
  "${SUCRE_SNORT_ROOT}/src/DomainList.cpp"
  "${SUCRE_SNORT_ROOT}/src/DomainManager.cpp"
  "${SUCRE_SNORT_ROOT}/src/DomainStats.cpp"
  "${SUCRE_SNORT_ROOT}/src/Rule.cpp"
  "${SUCRE_SNORT_ROOT}/src/RulesManager.cpp"
  "${SUCRE_SNORT_ROOT}/src/Settings.cpp"
  "${SUCRE_SNORT_ROOT}/src/Stats.cpp"
)

add_sucre_snort_host_test(
  control_vnext_codec_tests
  control_vnext_codec_tests.cpp
  "${SUCRE_SNORT_ROOT}/src/ControlVNextCodec.cpp"
)

add_sucre_snort_host_test(
  control_vnext_ctl_roundtrip_tests
  control_vnext_ctl_roundtrip_tests.cpp
  sucre_snort_ctl_session.cpp
  "${SUCRE_SNORT_ROOT}/src/ControlVNextCodec.cpp"
)

add_sucre_snort_host_test(
  control_vnext_daemon_session_tests
  control_vnext_daemon_session_tests.cpp
  control_vnext_daemon_stub_commands.cpp
  "${SUCRE_SNORT_ROOT}/src/Address.cpp"
  "${SUCRE_SNORT_ROOT}/src/ControlVNextSession.cpp"
  "${SUCRE_SNORT_ROOT}/src/ControlVNextCodec.cpp"
  "${SUCRE_SNORT_ROOT}/src/ControlVNextStreamManager.cpp"
  "${SUCRE_SNORT_ROOT}/src/ControlVNextStreamJson.cpp"
  "${SUCRE_SNORT_ROOT}/src/Domain.cpp"
  "${SUCRE_SNORT_ROOT}/src/DomainStats.cpp"
  "${SUCRE_SNORT_ROOT}/src/Host.cpp"
  "${SUCRE_SNORT_ROOT}/src/Settings.cpp"
  "${SUCRE_SNORT_ROOT}/src/Stats.cpp"
)

add_sucre_snort_host_test(
  control_vnext_stream_surface_tests
  control_vnext_stream_surface_tests.cpp
  control_vnext_daemon_stub_commands.cpp
  "${SUCRE_SNORT_ROOT}/src/Address.cpp"
  "${SUCRE_SNORT_ROOT}/src/ControlVNextSession.cpp"
  "${SUCRE_SNORT_ROOT}/src/ControlVNextCodec.cpp"
  "${SUCRE_SNORT_ROOT}/src/ControlVNextStreamManager.cpp"
  "${SUCRE_SNORT_ROOT}/src/ControlVNextStreamJson.cpp"
  "${SUCRE_SNORT_ROOT}/src/Domain.cpp"
  "${SUCRE_SNORT_ROOT}/src/DomainStats.cpp"
  "${SUCRE_SNORT_ROOT}/src/Host.cpp"
  "${SUCRE_SNORT_ROOT}/src/Settings.cpp"
  "${SUCRE_SNORT_ROOT}/src/Stats.cpp"
)

add_sucre_snort_host_test(
  control_vnext_domain_surface_tests
  control_vnext_domain_surface_tests.cpp
  "${SUCRE_SNORT_ROOT}/src/Address.cpp"
  "${SUCRE_SNORT_ROOT}/src/App.cpp"
  "${SUCRE_SNORT_ROOT}/src/AppStats.cpp"
  "${SUCRE_SNORT_ROOT}/src/BlockingList.cpp"
  "${SUCRE_SNORT_ROOT}/src/BlockingListManager.cpp"
  "${SUCRE_SNORT_ROOT}/src/ControlVNextCodec.cpp"
  "${SUCRE_SNORT_ROOT}/src/ControlVNextSessionCommandsDomain.cpp"
  "${SUCRE_SNORT_ROOT}/src/CustomList.cpp"
  "${SUCRE_SNORT_ROOT}/src/CustomRules.cpp"
  "${SUCRE_SNORT_ROOT}/src/Domain.cpp"
  "${SUCRE_SNORT_ROOT}/src/DomainList.cpp"
  "${SUCRE_SNORT_ROOT}/src/DomainManager.cpp"
  "${SUCRE_SNORT_ROOT}/src/DomainStats.cpp"
  "${SUCRE_SNORT_ROOT}/src/Rule.cpp"
  "${SUCRE_SNORT_ROOT}/src/RulesManager.cpp"
  "${SUCRE_SNORT_ROOT}/src/Settings.cpp"
  "${SUCRE_SNORT_ROOT}/src/Stats.cpp"
)

add_sucre_snort_host_test(
  control_vnext_iprules_surface_tests
  control_vnext_iprules_surface_tests.cpp
  "${SUCRE_SNORT_ROOT}/src/Address.cpp"
  "${SUCRE_SNORT_ROOT}/src/App.cpp"
  "${SUCRE_SNORT_ROOT}/src/AppStats.cpp"
  "${SUCRE_SNORT_ROOT}/src/BlockingList.cpp"
  "${SUCRE_SNORT_ROOT}/src/BlockingListManager.cpp"
  "${SUCRE_SNORT_ROOT}/src/Conntrack.cpp"
  "${SUCRE_SNORT_ROOT}/src/ControlVNextCodec.cpp"
  "${SUCRE_SNORT_ROOT}/src/ControlVNextSessionCommandsIpRules.cpp"
  "${SUCRE_SNORT_ROOT}/src/CustomList.cpp"
  "${SUCRE_SNORT_ROOT}/src/CustomRules.cpp"
  "${SUCRE_SNORT_ROOT}/src/Domain.cpp"
  "${SUCRE_SNORT_ROOT}/src/DomainList.cpp"
  "${SUCRE_SNORT_ROOT}/src/DomainManager.cpp"
  "${SUCRE_SNORT_ROOT}/src/DomainStats.cpp"
  "${SUCRE_SNORT_ROOT}/src/IpRulesEngine.cpp"
  "${SUCRE_SNORT_ROOT}/src/Rule.cpp"
  "${SUCRE_SNORT_ROOT}/src/RulesManager.cpp"
  "${SUCRE_SNORT_ROOT}/src/Settings.cpp"
  "${SUCRE_SNORT_ROOT}/src/Stats.cpp"
)

add_sucre_snort_host_test(
  control_vnext_metrics_surface_tests
  control_vnext_metrics_surface_tests.cpp
  "${SUCRE_SNORT_ROOT}/src/Address.cpp"
  "${SUCRE_SNORT_ROOT}/src/App.cpp"
  "${SUCRE_SNORT_ROOT}/src/AppStats.cpp"
  "${SUCRE_SNORT_ROOT}/src/BlockingList.cpp"
  "${SUCRE_SNORT_ROOT}/src/BlockingListManager.cpp"
  "${SUCRE_SNORT_ROOT}/src/Conntrack.cpp"
  "${SUCRE_SNORT_ROOT}/src/ControlVNextCodec.cpp"
  "${SUCRE_SNORT_ROOT}/src/ControlVNextSessionCommandsMetrics.cpp"
  "${SUCRE_SNORT_ROOT}/src/CustomList.cpp"
  "${SUCRE_SNORT_ROOT}/src/CustomRules.cpp"
  "${SUCRE_SNORT_ROOT}/src/Domain.cpp"
  "${SUCRE_SNORT_ROOT}/src/DomainList.cpp"
  "${SUCRE_SNORT_ROOT}/src/DomainManager.cpp"
  "${SUCRE_SNORT_ROOT}/src/DomainStats.cpp"
  "${SUCRE_SNORT_ROOT}/src/IpRulesEngine.cpp"
  "${SUCRE_SNORT_ROOT}/src/Rule.cpp"
  "${SUCRE_SNORT_ROOT}/src/RulesManager.cpp"
  "${SUCRE_SNORT_ROOT}/src/Settings.cpp"
  "${SUCRE_SNORT_ROOT}/src/Stats.cpp"
)

add_sucre_snort_host_test(
  host_gap_tests
  host_gap_tests.cpp
  "${SUCRE_SNORT_ROOT}/src/Activity.cpp"
  "${SUCRE_SNORT_ROOT}/src/ActivityManager.cpp"
  "${SUCRE_SNORT_ROOT}/src/Address.cpp"
  "${SUCRE_SNORT_ROOT}/src/App.cpp"
  "${SUCRE_SNORT_ROOT}/src/AppManager.cpp"
  "${SUCRE_SNORT_ROOT}/src/AppStats.cpp"
  "${SUCRE_SNORT_ROOT}/src/BlockingList.cpp"
  "${SUCRE_SNORT_ROOT}/src/CmdLine.cpp"
  "${SUCRE_SNORT_ROOT}/src/CustomList.cpp"
  "${SUCRE_SNORT_ROOT}/src/CustomRules.cpp"
  "${SUCRE_SNORT_ROOT}/src/DnsRequest.cpp"
  "${SUCRE_SNORT_ROOT}/src/Domain.cpp"
  "${SUCRE_SNORT_ROOT}/src/DomainList.cpp"
  "${SUCRE_SNORT_ROOT}/src/DomainManager.cpp"
  "${SUCRE_SNORT_ROOT}/src/DomainStats.cpp"
  "${SUCRE_SNORT_ROOT}/src/Host.cpp"
  "${SUCRE_SNORT_ROOT}/src/HostManager.cpp"
  "${SUCRE_SNORT_ROOT}/src/Packet.cpp"
  "${SUCRE_SNORT_ROOT}/src/PacketManager.cpp"
  "${SUCRE_SNORT_ROOT}/src/Rule.cpp"
  "${SUCRE_SNORT_ROOT}/src/RulesManager.cpp"
  "${SUCRE_SNORT_ROOT}/src/Settings.cpp"
  "${SUCRE_SNORT_ROOT}/src/SocketIO.cpp"
  "${SUCRE_SNORT_ROOT}/src/SnortIo.cpp"
  "${SUCRE_SNORT_ROOT}/src/Stats.cpp"
  "${SUCRE_SNORT_ROOT}/src/Streamable.cpp"
  "${SUCRE_SNORT_ROOT}/src/Timer.cpp"
)
