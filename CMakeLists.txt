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
  OFF
)
option(
  SNORT_ENABLE_NDK_DAEMON
  "Configure the Android NDK arm64 root daemon target"
  OFF
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
    snort-build-ndk
    COMMAND "${BASH_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/dev/dev-build-ndk.sh"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Build sucre-snort daemon through Android NDK r29"
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

if(SNORT_ENABLE_NDK_DAEMON)
  enable_language(C CXX)
  include(cmake/SucreSnortNdkDaemon.cmake)
endif()

if(SNORT_ENABLE_HOST_TESTS)
  enable_language(CXX)
  add_subdirectory(tests/host)

  get_property(SNORT_HOST_TEST_TARGETS GLOBAL PROPERTY SUCRE_SNORT_HOST_TEST_TARGETS)
  set(SNORT_HOST_TEST_ENV)
  if(
    CMAKE_CXX_FLAGS MATCHES "-fsanitize=address"
    OR CMAKE_C_FLAGS MATCHES "-fsanitize=address"
    OR CMAKE_EXE_LINKER_FLAGS MATCHES "-fsanitize=address"
  )
    # LeakSanitizer can fail under ptrace (common in CI/harnesses). Keep the
    # ASAN lane stable by disabling leak detection by default.
    list(APPEND SNORT_HOST_TEST_ENV "ASAN_OPTIONS=detect_leaks=0")
  endif()
  if(
    CMAKE_CXX_FLAGS MATCHES "-fsanitize=thread"
    OR CMAKE_C_FLAGS MATCHES "-fsanitize=thread"
    OR CMAKE_EXE_LINKER_FLAGS MATCHES "-fsanitize=thread"
  )
    list(APPEND SNORT_HOST_TEST_ENV "TSAN_OPTIONS=halt_on_error=1")
  endif()
  if(
    CMAKE_CXX_FLAGS MATCHES "-fsanitize=undefined"
    OR CMAKE_C_FLAGS MATCHES "-fsanitize=undefined"
    OR CMAKE_EXE_LINKER_FLAGS MATCHES "-fsanitize=undefined"
  )
    list(APPEND SNORT_HOST_TEST_ENV "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1")
  endif()
  add_custom_target(
    snort-host-tests
    COMMAND "${CMAKE_COMMAND}" -E env ${SNORT_HOST_TEST_ENV} "${CMAKE_CTEST_COMMAND}" --output-on-failure -L host
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "Run sucre-snort host-side gtest lane via CTest"
    USES_TERMINAL
    VERBATIM
  )
  if(SNORT_HOST_TEST_TARGETS)
    add_dependencies(snort-host-tests ${SNORT_HOST_TEST_TARGETS})
  endif()

  add_custom_target(
    snort-host-tests-asan
    COMMAND "${CMAKE_COMMAND}" --preset host-asan-clang
    COMMAND "${CMAKE_COMMAND}" --build --preset host-asan-clang --target snort-host-tests
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Run sucre-snort host-side gtest lane with ASAN via a dedicated preset"
    USES_TERMINAL
    VERBATIM
  )

  add_custom_target(
    snort-host-tests-ubsan
    COMMAND "${CMAKE_COMMAND}" --preset host-ubsan-clang
    COMMAND "${CMAKE_COMMAND}" --build --preset host-ubsan-clang --target snort-host-tests
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Run sucre-snort host-side gtest lane with UBSAN via a dedicated preset"
    USES_TERMINAL
    VERBATIM
  )

  find_program(SNORT_SETARCH_EXECUTABLE setarch)
  set(SNORT_TSAN_CONNTRACK_TEST "${CMAKE_SOURCE_DIR}/build-output/cmake/host-tsan-clang/tests/host/conntrack_tests")
  if(SNORT_SETARCH_EXECUTABLE)
    set(
      SNORT_TSAN_CONNTRACK_COMMAND
      "${SNORT_SETARCH_EXECUTABLE}" "${CMAKE_SYSTEM_PROCESSOR}" "-R"
      "${CMAKE_COMMAND}" "-E" "env" "TSAN_OPTIONS=halt_on_error=1"
      "${SNORT_TSAN_CONNTRACK_TEST}"
    )
  else()
    set(
      SNORT_TSAN_CONNTRACK_COMMAND
      "${CMAKE_COMMAND}" "-E" "env" "TSAN_OPTIONS=halt_on_error=1"
      "${SNORT_TSAN_CONNTRACK_TEST}"
    )
  endif()
  add_custom_target(
    snort-host-tests-tsan
    COMMAND "${CMAKE_COMMAND}" --preset host-tsan-clang
    COMMAND "${CMAKE_COMMAND}" --build --preset host-tsan-clang --target conntrack_tests
    COMMAND ${SNORT_TSAN_CONNTRACK_COMMAND}
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Run Conntrack host stress tests with ThreadSanitizer"
    USES_TERMINAL
    VERBATIM
  )

  add_custom_target(
    snort-host-tests-gate
    COMMAND "${CMAKE_COMMAND}" -E echo "=== Host tests (normal) ==="
    COMMAND "${CMAKE_COMMAND}" -E chdir "${CMAKE_BINARY_DIR}" "${CMAKE_CTEST_COMMAND}" --output-on-failure -L host
    COMMAND "${CMAKE_COMMAND}" -E echo "=== Host tests (ASAN) ==="
    COMMAND "${CMAKE_COMMAND}" --preset host-asan-clang
    COMMAND "${CMAKE_COMMAND}" --build --preset host-asan-clang --target snort-host-tests
    COMMAND "${CMAKE_COMMAND}" -E echo "=== Host tests (UBSAN) ==="
    COMMAND "${CMAKE_COMMAND}" --preset host-ubsan-clang
    COMMAND "${CMAKE_COMMAND}" --build --preset host-ubsan-clang --target snort-host-tests
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Run sucre-snort host-side unit-test gate (normal + ASAN + UBSAN)"
    USES_TERMINAL
    VERBATIM
  )
  if(SNORT_HOST_TEST_TARGETS)
    add_dependencies(snort-host-tests-gate ${SNORT_HOST_TEST_TARGETS})
  endif()

  find_program(LLVM_PROFDATA_EXECUTABLE llvm-profdata)
  find_program(LLVM_COV_EXECUTABLE llvm-cov)
  if(LLVM_PROFDATA_EXECUTABLE AND LLVM_COV_EXECUTABLE)
    set(SNORT_HOST_COVERAGE_OBJECTS)
    foreach(target IN LISTS SNORT_HOST_TEST_TARGETS)
      list(APPEND SNORT_HOST_COVERAGE_OBJECTS "$<TARGET_FILE:${target}>")
    endforeach()

    string(
      CONCAT
      SNORT_HOST_COVERAGE_RESET_SCRIPT
      "file(REMOVE_RECURSE \"${CMAKE_BINARY_DIR}/coverage\")\n"
      "file(MAKE_DIRECTORY \"${CMAKE_BINARY_DIR}/coverage\")\n"
    )
    file(
      GENERATE
      OUTPUT "${CMAKE_BINARY_DIR}/snort_host_coverage_reset.cmake"
      CONTENT "${SNORT_HOST_COVERAGE_RESET_SCRIPT}"
    )

    string(
      CONCAT
      SNORT_HOST_COVERAGE_REPORT_SCRIPT
      "set(COV_OBJECTS \"${SNORT_HOST_COVERAGE_OBJECTS}\")\n"
      "if(NOT COV_OBJECTS)\n"
      "  message(FATAL_ERROR \"No coverage objects configured\")\n"
      "endif()\n"
      "list(GET COV_OBJECTS 0 COV_MAIN_OBJECT)\n"
      "list(REMOVE_AT COV_OBJECTS 0)\n"
      "set(COV_OBJECT_ARGS \"\${COV_MAIN_OBJECT}\")\n"
      "foreach(obj IN LISTS COV_OBJECTS)\n"
      "  list(APPEND COV_OBJECT_ARGS \"--object=\${obj}\")\n"
      "endforeach()\n"
      "file(GLOB PROFRAWS LIST_DIRECTORIES false \"${CMAKE_BINARY_DIR}/coverage/*.profraw\")\n"
      "if(NOT PROFRAWS)\n"
      "  message(FATAL_ERROR \"No .profraw files found under: ${CMAKE_BINARY_DIR}/coverage\")\n"
      "endif()\n"
      "execute_process(\n"
      "  COMMAND \"${LLVM_PROFDATA_EXECUTABLE}\" merge -sparse \${PROFRAWS} -o \"${CMAKE_BINARY_DIR}/coverage/coverage.profdata\"\n"
      "  RESULT_VARIABLE MERGE_RES\n"
      ")\n"
      "if(NOT MERGE_RES EQUAL 0)\n"
      "  message(FATAL_ERROR \"llvm-profdata merge failed\")\n"
      "endif()\n"
      "execute_process(\n"
      "  COMMAND \"${LLVM_COV_EXECUTABLE}\" report \${COV_OBJECT_ARGS} -instr-profile \"${CMAKE_BINARY_DIR}/coverage/coverage.profdata\" --ignore-filename-regex \".*(tests/host|_deps|third_party).*\"\n"
      "  OUTPUT_FILE \"${CMAKE_BINARY_DIR}/coverage/summary.txt\"\n"
      "  RESULT_VARIABLE REPORT_RES\n"
      ")\n"
      "if(NOT REPORT_RES EQUAL 0)\n"
      "  message(FATAL_ERROR \"llvm-cov report failed\")\n"
      "endif()\n"
      "execute_process(\n"
      "  COMMAND \"${LLVM_COV_EXECUTABLE}\" export \${COV_OBJECT_ARGS} -instr-profile \"${CMAKE_BINARY_DIR}/coverage/coverage.profdata\" --ignore-filename-regex \".*(tests/host|_deps|third_party).*\"\n"
      "  OUTPUT_FILE \"${CMAKE_BINARY_DIR}/coverage/coverage.json\"\n"
      "  RESULT_VARIABLE EXPORT_RES\n"
      ")\n"
      "if(NOT EXPORT_RES EQUAL 0)\n"
      "  message(FATAL_ERROR \"llvm-cov export failed\")\n"
      "endif()\n"
      "message(STATUS \"Coverage: ${CMAKE_BINARY_DIR}/coverage/summary.txt\")\n"
      "message(STATUS \"Coverage: ${CMAKE_BINARY_DIR}/coverage/coverage.json\")\n"
    )
    file(
      GENERATE
      OUTPUT "${CMAKE_BINARY_DIR}/snort_host_coverage_report.cmake"
      CONTENT "${SNORT_HOST_COVERAGE_REPORT_SCRIPT}"
    )

    add_custom_target(
      snort-host-coverage
      COMMAND "${CMAKE_COMMAND}" -P "${CMAKE_BINARY_DIR}/snort_host_coverage_reset.cmake"
      COMMAND "${CMAKE_COMMAND}" -E env "LLVM_PROFILE_FILE=${CMAKE_BINARY_DIR}/coverage/%m_%p.profraw" "${CMAKE_CTEST_COMMAND}" --output-on-failure -L host
      COMMAND "${CMAKE_COMMAND}" -P "${CMAKE_BINARY_DIR}/snort_host_coverage_report.cmake"
      WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMMENT "Generate LLVM source-based coverage artifacts for host tests"
      USES_TERMINAL
      VERBATIM
    )
    if(SNORT_HOST_TEST_TARGETS)
      add_dependencies(snort-host-coverage ${SNORT_HOST_TEST_TARGETS})
    endif()
  else()
    message(STATUS "llvm-profdata/llvm-cov not found: snort-host-coverage target unavailable")
  endif()
endif()

if(SNORT_ENABLE_DEVICE_TESTS)
  add_subdirectory(tests/integration)
endif()

message(STATUS "sucre-snort repo-root workflow workspace configured")
message(STATUS "Delegated build/debug targets: snort-build, snort-build-clean, snort-build-ndk, snort-build-regen-graph, snort-deploy-stage, snort-debug-run-workflow, snort-debug-attach-workflow, snort-debug-cleanup, snort-debug-status")
if(SNORT_ENABLE_HOST_TESTS)
  message(STATUS "Host test targets: snort-host-tests, snort-host-tests-asan, snort-host-tests-ubsan, snort-host-tests-tsan, snort-host-tests-gate")
  if(TARGET snort-host-coverage)
    message(STATUS "Host coverage target: snort-host-coverage")
  endif()
else()
  message(STATUS "Host tests disabled: SNORT_ENABLE_HOST_TESTS=OFF")
endif()
if(SNORT_ENABLE_DEVICE_TESTS)
  message(STATUS "Device test targets: snort-dx-smoke, snort-dx-smoke-platform, snort-dx-smoke-control, snort-dx-smoke-datapath, snort-dx-casebook-other")
else()
  message(STATUS "Device tests disabled: SNORT_ENABLE_DEVICE_TESTS=OFF")
endif()
