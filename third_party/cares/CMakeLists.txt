# Verify the offline pin and generated closure whenever an input changes.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
file(GLOB_RECURSE cares_inputs CONFIGURE_DEPENDS "upstream/*")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  ${cares_inputs} upstream-manifest.json namespace.h onion-helper.c sources.cmake
  "${CMAKE_CURRENT_SOURCE_DIR}/../../tools/product/vendor-cares.py")
execute_process(COMMAND "${Python3_EXECUTABLE}"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../tools/product/vendor-cares.py" --verify
  RESULT_VARIABLE cares_verify OUTPUT_VARIABLE cares_verify_output
  ERROR_VARIABLE cares_verify_error)
if(NOT cares_verify EQUAL 0)
  message(FATAL_ERROR "Pinned c-ares verification failed: ${cares_verify_output}${cares_verify_error}")
endif()
include(sources.cmake)
configure_file(upstream/include/ares_build.h.dist ares_build.h COPYONLY)
add_library(sakamoto_dns_wire STATIC ${cares_sources})
target_include_directories(sakamoto_dns_wire PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/upstream/include" "${CMAKE_CURRENT_BINARY_DIR}"
  PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/upstream/src/lib"
  "${CMAKE_CURRENT_SOURCE_DIR}/upstream/src/lib/include")
target_compile_options(sakamoto_dns_wire PRIVATE
  -include "${CMAKE_CURRENT_SOURCE_DIR}/namespace.h")
target_compile_definitions(sakamoto_dns_wire PRIVATE HAVE_CONFIG_H=1)
target_compile_features(sakamoto_dns_wire PRIVATE c_std_11)
set_target_properties(sakamoto_dns_wire PROPERTIES
  POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
