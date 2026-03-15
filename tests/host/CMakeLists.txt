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

function(add_sucre_snort_host_test target)
  add_executable(${target} ${ARGN})
  target_include_directories(${target} PRIVATE "${HOST_TEST_INCLUDE_DIR}" "${SUCRE_SNORT_ROOT}/src")
  target_compile_options(${target} PRIVATE -Wall -Wextra -Werror)
  target_link_libraries(${target} PRIVATE GTest::gtest_main)
  set_property(GLOBAL APPEND PROPERTY SUCRE_SNORT_HOST_TEST_TARGETS ${target})
  gtest_discover_tests(
    ${target}
    DISCOVERY_TIMEOUT 60
    PROPERTIES LABELS "p0;host"
  )
endfunction()

add_sucre_snort_host_test(package_state_tests package_state_tests.cpp)
add_sucre_snort_host_test(perf_metrics_tests perf_metrics_tests.cpp)
add_sucre_snort_host_test(reason_metrics_tests reason_metrics_tests.cpp)
add_sucre_snort_host_test(ip_rules_engine_tests ip_rules_engine_tests.cpp "${SUCRE_SNORT_ROOT}/src/IpRulesEngine.cpp")
add_sucre_snort_host_test(rule_tests rule_tests.cpp "${SUCRE_SNORT_ROOT}/src/Rule.cpp")
add_sucre_snort_host_test(settings_tests settings_tests.cpp "${SUCRE_SNORT_ROOT}/src/Settings.cpp")
add_sucre_snort_host_test(stats_tests stats_tests.cpp "${SUCRE_SNORT_ROOT}/src/Stats.cpp" "${SUCRE_SNORT_ROOT}/src/AppStats.cpp" "${SUCRE_SNORT_ROOT}/src/DomainStats.cpp")
