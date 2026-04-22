cmake_minimum_required(VERSION 3.18)

set(SUCRE_SNORT_INTEGRATION_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(SUCRE_SNORT_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(SUCRE_SNORT_SKIP_REGEX_COMMON "未找到 adb/adb.exe|未检测到已连接的 Android 真机|检测到多台 Android 真机|无法通过 su 获取 root 权限|目标设备未返回 root 身份|错误: 真机 preflight 失败|SKIP: perf-network-load.*")

function(add_sucre_snort_shell_test name script labels)
  add_test(
    NAME ${name}
    COMMAND "${BASH_EXECUTABLE}" "${script}" ${ARGN}
  )
  set_tests_properties(
    ${name}
    PROPERTIES
      LABELS "${labels}"
      SKIP_REGULAR_EXPRESSION "${SUCRE_SNORT_SKIP_REGEX_COMMON}"
      WORKING_DIRECTORY "${SUCRE_SNORT_REPO_ROOT}"
  )
endfunction()

add_sucre_snort_shell_test(
  p1-baseline
  "${SUCRE_SNORT_INTEGRATION_ROOT}/run.sh"
  "p1;device;root-required;baseline"
)

add_sucre_snort_shell_test(
  p1-vnext-baseline
  "${SUCRE_SNORT_INTEGRATION_ROOT}/vnext-baseline.sh"
  "p1;device;root-required;baseline;vnext"
)

add_sucre_snort_shell_test(
  p1-iprules
  "${SUCRE_SNORT_INTEGRATION_ROOT}/iprules.sh"
  "p1;device;root-required;iprules"
)

add_sucre_snort_shell_test(
  p2-device-smoke
  "${SUCRE_SNORT_INTEGRATION_ROOT}/device-smoke.sh"
  "p2;device;root-required;smoke"
)

add_sucre_snort_shell_test(
  ip-smoke
  "${SUCRE_SNORT_REPO_ROOT}/tests/device-modules/ip/run.sh"
  "device;root-required;ip-smoke"
  --profile smoke --case iprules_smoke
)

add_sucre_snort_shell_test(
  perf-network-load
  "${SUCRE_SNORT_INTEGRATION_ROOT}/perf-network-load.sh"
  "perf;device;root-required;baseline"
)

add_custom_target(
  snort-p1-tests
  COMMAND "${CMAKE_CTEST_COMMAND}" --output-on-failure -L p1
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
  COMMENT "Run sucre-snort real-device baseline lane via CTest"
  USES_TERMINAL
  VERBATIM
)

add_custom_target(
  snort-p2-tests
  COMMAND "${CMAKE_CTEST_COMMAND}" --output-on-failure -L p2
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
  COMMENT "Run sucre-snort real-device platform smoke lane via CTest"
  USES_TERMINAL
  VERBATIM
)

add_custom_target(
  snort-ip-smoke-tests
  COMMAND "${CMAKE_CTEST_COMMAND}" --output-on-failure -L ip-smoke
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
  COMMENT "Run sucre-snort IP device-module smoke via CTest"
  USES_TERMINAL
  VERBATIM
)

if(TARGET sucre-snort-ctl)
  add_dependencies(snort-p1-tests sucre-snort-ctl)
  add_dependencies(snort-p2-tests sucre-snort-ctl)
  add_dependencies(snort-ip-smoke-tests sucre-snort-ctl)
endif()
