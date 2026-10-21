# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.18)
project(sakamoto_runtime_control LANGUAGES C)

if(NOT ANDROID OR NOT EXISTS "${SAKAMOTO_PRODUCT_CORE_LIBRARY}")
  message(FATAL_ERROR "Android JNI requires the compiled Product Core library")
endif()
get_filename_component(product_core_dir "${SAKAMOTO_PRODUCT_CORE_LIBRARY}" DIRECTORY)
add_library(sakamoto_runtime_control SHARED sakamoto_product_core_jni.c)
set_target_properties(sakamoto_runtime_control PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO
  SKIP_BUILD_RPATH TRUE LINK_DEPENDS "${SAKAMOTO_PRODUCT_CORE_LIBRARY}")
target_compile_options(sakamoto_runtime_control PRIVATE -Wall -Wextra -Werror)
target_include_directories(sakamoto_runtime_control PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/product/include")
# Link by name as before: do not put the compilation-cache path in DT_NEEDED.
target_link_directories(sakamoto_runtime_control PRIVATE "${product_core_dir}")
target_link_libraries(sakamoto_runtime_control PRIVATE
  "-Wl,--no-as-needed" sakamoto_product_core)
