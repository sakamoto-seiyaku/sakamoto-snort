cmake_minimum_required(VERSION 3.18)

project(sucre_snort_workspace LANGUAGES NONE)

find_program(BASH_EXECUTABLE bash REQUIRED)
find_program(PYTHON3_EXECUTABLE python3 REQUIRED)

set(
  SNORT_BUILD_SCRIPT
  "${CMAKE_SOURCE_DIR}/dev/dev-build.sh"
  CACHE FILEPATH
  "Delegated Android build entrypoint for sucre-snort"
)

option(
  SNORT_ENABLE_DELEGATED_BUILD_TARGETS
  "Expose delegated Android build targets in the repo-root CMake workspace"
  ON
)
option(
  SNORT_ENABLE_HOST_TESTS
  "Expose host-side gtest/CTest targets in the repo-root CMake workspace"
  ON
)
option(
  SNORT_ENABLE_DEVICE_TESTS
  "Expose real-device integration/smoke CTest lanes in the repo-root CMake workspace"
  ON
)

if(SNORT_ENABLE_DELEGATED_BUILD_TARGETS)
  add_custom_target(
    snort-build
    COMMAND "${BASH_EXECUTABLE}" "${SNORT_BUILD_SCRIPT}"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Delegated Android build via dev/dev-build.sh"
    USES_TERMINAL
    VERBATIM
  )

  add_custom_target(
    snort-build-clean
    COMMAND "${BASH_EXECUTABLE}" "${SNORT_BUILD_SCRIPT}" --clean
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Delegated Android clean build via dev/dev-build.sh --clean"
    USES_TERMINAL
    VERBATIM
  )

  add_custom_target(
    snort-build-regen-graph
    COMMAND "${BASH_EXECUTABLE}" "${SNORT_BUILD_SCRIPT}" --regen-graph
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Delegated Android build with graph regeneration"
    USES_TERMINAL
    VERBATIM
  )

  add_custom_target(
    snort-deploy-stage
    COMMAND "${BASH_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/dev/dev-deploy.sh" --stage-only
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Stage sucre-snort binary onto the real device without starting daemon"
    USES_TERMINAL
    VERBATIM
  )

  add_custom_target(
    snort-debug-run-workflow
    COMMAND "${PYTHON3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/dev/dev-vscode-debug-task.py" workflow run
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Prepare VS Code / LLDB run workflow for the real device"
    USES_TERMINAL
    VERBATIM
  )

  add_custom_target(
    snort-debug-attach-workflow
    COMMAND "${PYTHON3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/dev/dev-vscode-debug-task.py" workflow attach
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Prepare VS Code / LLDB attach workflow for the real device"
    USES_TERMINAL
    VERBATIM
  )

  add_custom_target(
    snort-debug-cleanup
    COMMAND "${PYTHON3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/dev/dev-vscode-debug-task.py" cleanup
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Cleanup VS Code / LLDB real-device debug residue"
    USES_TERMINAL
    VERBATIM
  )

  add_custom_target(
    snort-debug-status
    COMMAND "${PYTHON3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/dev/dev-vscode-debug-task.py" status
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Show VS Code / LLDB real-device debug helper status"
    USES_TERMINAL
    VERBATIM
  )
endif()

if(SNORT_ENABLE_HOST_TESTS OR SNORT_ENABLE_DEVICE_TESTS)
  include(CTest)
endif()

if(SNORT_ENABLE_HOST_TESTS)
  enable_language(CXX)
  add_subdirectory(tests/host)

  get_property(SNORT_HOST_TEST_TARGETS GLOBAL PROPERTY SUCRE_SNORT_HOST_TEST_TARGETS)
  add_custom_target(
    snort-host-tests
    COMMAND "${CMAKE_CTEST_COMMAND}" --output-on-failure -L p0
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "Run sucre-snort host-side gtest lane via CTest"
    USES_TERMINAL
    VERBATIM
  )
  if(SNORT_HOST_TEST_TARGETS)
    add_dependencies(snort-host-tests ${SNORT_HOST_TEST_TARGETS})
  endif()
endif()

if(SNORT_ENABLE_DEVICE_TESTS)
  add_subdirectory(tests/integration)
endif()

message(STATUS "sucre-snort repo-root workflow workspace configured")
message(STATUS "Delegated build/debug targets: snort-build, snort-build-clean, snort-build-regen-graph, snort-deploy-stage, snort-debug-run-workflow, snort-debug-attach-workflow, snort-debug-cleanup, snort-debug-status")
if(SNORT_ENABLE_HOST_TESTS)
  message(STATUS "Host test target: snort-host-tests")
else()
  message(STATUS "Host tests disabled: SNORT_ENABLE_HOST_TESTS=OFF")
endif()
if(SNORT_ENABLE_DEVICE_TESTS)
  message(STATUS "Device test targets: snort-p1-tests, snort-p2-tests")
else()
  message(STATUS "Device tests disabled: SNORT_ENABLE_DEVICE_TESTS=OFF")
endif()
