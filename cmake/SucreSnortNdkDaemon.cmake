include("${CMAKE_CURRENT_LIST_DIR}/SucreSnortDaemonSources.cmake")

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
  message(FATAL_ERROR "SNORT_ENABLE_NDK_DAEMON requires the Android NDK CMake toolchain")
endif()

if(NOT CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
  message(FATAL_ERROR "sucre-snort NDK daemon supports only arm64-v8a in this change")
endif()

if(DEFINED ANDROID_PLATFORM AND NOT ANDROID_PLATFORM STREQUAL "android-31")
  message(FATAL_ERROR "sucre-snort NDK daemon requires android-31")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(SNORT_NETFILTER_ROOT "${CMAKE_SOURCE_DIR}/third_party/netfilter")

add_library(
  snort_netfilter_mnl
  STATIC
  "${SNORT_NETFILTER_ROOT}/libmnl/src/socket.c"
  "${SNORT_NETFILTER_ROOT}/libmnl/src/callback.c"
  "${SNORT_NETFILTER_ROOT}/libmnl/src/nlmsg.c"
  "${SNORT_NETFILTER_ROOT}/libmnl/src/attr.c"
)
target_include_directories(
  snort_netfilter_mnl
  PUBLIC "${SNORT_NETFILTER_ROOT}/libmnl/include"
  PRIVATE
    "${SNORT_NETFILTER_ROOT}/cmake_config/libmnl"
    "${SNORT_NETFILTER_ROOT}/libmnl/src"
)
set_target_properties(snort_netfilter_mnl PROPERTIES C_EXTENSIONS ON)

add_library(
  snort_netfilter_nfnetlink
  STATIC
  "${SNORT_NETFILTER_ROOT}/libnfnetlink/src/libnfnetlink.c"
  "${SNORT_NETFILTER_ROOT}/libnfnetlink/src/iftable.c"
  "${SNORT_NETFILTER_ROOT}/libnfnetlink/src/rtnl.c"
)
target_include_directories(
  snort_netfilter_nfnetlink
  PUBLIC "${SNORT_NETFILTER_ROOT}/libnfnetlink/include"
  PRIVATE
    "${SNORT_NETFILTER_ROOT}/libnfnetlink/include"
    "${SNORT_NETFILTER_ROOT}/libnfnetlink/src"
)
target_compile_definitions(snort_netfilter_nfnetlink PUBLIC NFNL_EXPORT=)
set_target_properties(snort_netfilter_nfnetlink PROPERTIES C_EXTENSIONS ON)

add_library(
  snort_netfilter_queue
  STATIC
  "${SNORT_NETFILTER_ROOT}/libnetfilter_queue/src/nlmsg.c"
)
target_include_directories(
  snort_netfilter_queue
  PUBLIC
    "${SNORT_NETFILTER_ROOT}/cmake_config/libnetfilter_queue"
    "${SNORT_NETFILTER_ROOT}/libnetfilter_queue/include"
  PRIVATE
    "${SNORT_NETFILTER_ROOT}/libnetfilter_queue/src"
)
target_link_libraries(
  snort_netfilter_queue
  PUBLIC snort_netfilter_mnl snort_netfilter_nfnetlink
)
set_target_properties(snort_netfilter_queue PROPERTIES C_EXTENSIONS ON)

set(
  SNORT_DAEMON_BUILD_ID
  ""
  CACHE STRING
  "Build identity exposed through vNext HELLO"
)
if(SNORT_DAEMON_BUILD_ID STREQUAL "")
  execute_process(
    COMMAND git rev-parse --short=12 HEAD
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    RESULT_VARIABLE SNORT_GIT_REV_RESULT
    OUTPUT_VARIABLE SNORT_GIT_REV
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
  )
  if(SNORT_GIT_REV_RESULT EQUAL 0 AND NOT SNORT_GIT_REV STREQUAL "")
    set(SNORT_DAEMON_BUILD_ID "ndk-r29-${SNORT_GIT_REV}")
  else()
    set(SNORT_DAEMON_BUILD_ID "ndk-r29-unknown")
  endif()
endif()

find_library(SNORT_ANDROID_LOG_LIBRARY log REQUIRED)
find_package(Threads REQUIRED)

add_executable(sucre-snort-ndk ${SUCRE_SNORT_DAEMON_SOURCES})
set_target_properties(
  sucre-snort-ndk
  PROPERTIES
    OUTPUT_NAME "sucre-snort-ndk"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/build-output"
)
target_include_directories(
  sucre-snort-ndk
  PRIVATE "${CMAKE_SOURCE_DIR}/src"
)
target_include_directories(
  sucre-snort-ndk
  SYSTEM PRIVATE "${CMAKE_SOURCE_DIR}/third_party/rapidjson/include"
)
target_compile_features(sucre-snort-ndk PRIVATE cxx_std_20)
target_compile_definitions(
  sucre-snort-ndk
  PRIVATE
    "SUCRE_SNORT_DAEMON_BUILD_ID=\"${SNORT_DAEMON_BUILD_ID}\""
    "SUCRE_SNORT_ARTIFACT_ABI=\"arm64-v8a\""
)
target_compile_options(
  sucre-snort-ndk
  PRIVATE
    -fexceptions
    -Wall
    -Wextra
    -Werror
    -Wno-unused-parameter
    -Wno-unused-variable
    -Wno-unused-private-field
    -Wno-missing-designated-field-initializers
)
target_link_libraries(
  sucre-snort-ndk
  PRIVATE
    snort_netfilter_queue
    snort_netfilter_mnl
    snort_netfilter_nfnetlink
    "${SNORT_ANDROID_LOG_LIBRARY}"
    Threads::Threads
)

set(SNORT_NDK_APK_LIB_DIR "${CMAKE_SOURCE_DIR}/build-output/apk-native/lib/arm64-v8a")
add_custom_target(
  sucre-snort-ndk-apk-lib
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${SNORT_NDK_APK_LIB_DIR}"
  COMMAND
    "${CMAKE_COMMAND}" -E copy "$<TARGET_FILE:sucre-snort-ndk>"
    "${SNORT_NDK_APK_LIB_DIR}/libsucre_snortd.so"
  DEPENDS sucre-snort-ndk
  COMMENT "Stage APK native daemon artifact as lib/arm64-v8a/libsucre_snortd.so"
  VERBATIM
)

message(STATUS "NDK daemon target enabled: build-output/sucre-snort-ndk")
message(STATUS "NDK APK-native staging target: build-output/apk-native/lib/arm64-v8a/libsucre_snortd.so")
message(STATUS "NDK daemon build id: ${SNORT_DAEMON_BUILD_ID}")
