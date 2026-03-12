cmake_minimum_required(VERSION 3.18)

project(sucre_snort_host_tests LANGUAGES CXX)

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

enable_testing()
include(GoogleTest)

get_filename_component(SUCRE_SNORT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)

add_executable(package_state_tests package_state_tests.cpp)
target_include_directories(package_state_tests PRIVATE "${SUCRE_SNORT_ROOT}/src")
target_compile_options(package_state_tests PRIVATE -Wall -Wextra -Werror)
target_link_libraries(package_state_tests PRIVATE GTest::gtest_main)

gtest_discover_tests(package_state_tests)
