cmake_minimum_required(VERSION 3.18)

set(SUCRE_SNORT_INTEGRATION_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(SUCRE_SNORT_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(SUCRE_SNORT_SKIP_REGEX_COMMON "未找到 adb/adb.exe|未检测到已连接的 Android 真机|检测到多台 Android 真机|无法通过 su 获取 root 权限|目标设备未返回 root 身份|错误: 真机 preflight 失败|SKIP: dx-diagnostics-perf-network-load.*|SKIP: dx-casebook-other.*")

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
      SKIP_RETURN_CODE 77
      WORKING_DIRECTORY "${SUCRE_SNORT_REPO_ROOT}"
  )
endfunction()

add_sucre_snort_shell_test(
  dx-smoke
  "${SUCRE_SNORT_INTEGRATION_ROOT}/dx-smoke.sh"
  "dx-smoke;device;root-required;smoke"
)

add_sucre_snort_shell_test(
  dx-smoke-platform
  "${SUCRE_SNORT_INTEGRATION_ROOT}/dx-smoke-platform.sh"
  "dx-smoke-platform;device;root-required;smoke"
)

add_sucre_snort_shell_test(
  dx-smoke-control
  "${SUCRE_SNORT_INTEGRATION_ROOT}/dx-smoke-control.sh"
  "dx-smoke-control;device;root-required;smoke"
)

add_sucre_snort_shell_test(
  dx-smoke-datapath
  "${SUCRE_SNORT_INTEGRATION_ROOT}/dx-smoke-datapath.sh"
  "dx-smoke-datapath;device;root-required;smoke"
)

add_sucre_snort_shell_test(
  dx-diagnostics
  "${SUCRE_SNORT_REPO_ROOT}/tests/device/diagnostics/dx-diagnostics.sh"
  "dx-diagnostics;device;root-required;diagnostics"
)

add_sucre_snort_shell_test(
  dx-diagnostics-perf-network-load
  "${SUCRE_SNORT_REPO_ROOT}/tests/device/diagnostics/dx-diagnostics-perf-network-load.sh"
  "dx-diagnostics-perf-network-load;device;root-required;diagnostics;perf"
)

add_sucre_snort_shell_test(
  dx-casebook-other
  "${SUCRE_SNORT_REPO_ROOT}/tests/device/diagnostics/dx-casebook-other.sh"
  "dx-casebook-other;device;root-required;casebook;optional"
)

add_custom_target(
  snort-dx-smoke
  COMMAND "${CMAKE_CTEST_COMMAND}" --output-on-failure -R ^dx-smoke$
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
  COMMENT "Run sucre-snort DX smoke gate via CTest"
  USES_TERMINAL
  VERBATIM
)

add_custom_target(
  snort-dx-smoke-platform
  COMMAND "${CMAKE_CTEST_COMMAND}" --output-on-failure -R ^dx-smoke-platform$
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
  COMMENT "Run sucre-snort DX smoke platform gate via CTest"
  USES_TERMINAL
  VERBATIM
)

add_custom_target(
  snort-dx-smoke-control
  COMMAND "${CMAKE_CTEST_COMMAND}" --output-on-failure -R ^dx-smoke-control$
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
  COMMENT "Run sucre-snort DX smoke control gate via CTest"
  USES_TERMINAL
  VERBATIM
)

add_custom_target(
  snort-dx-smoke-datapath
  COMMAND "${CMAKE_CTEST_COMMAND}" --output-on-failure -R ^dx-smoke-datapath$
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
  COMMENT "Run sucre-snort DX smoke datapath gate via CTest"
  USES_TERMINAL
  VERBATIM
)

add_custom_target(
  snort-dx-casebook-other
  COMMAND "${CMAKE_CTEST_COMMAND}" --output-on-failure -R ^dx-casebook-other$
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
  COMMENT "Run optional sucre-snort DX other casebook checks via CTest"
  USES_TERMINAL
  VERBATIM
)

if(TARGET sucre-snort-ctl)
  add_dependencies(snort-dx-smoke sucre-snort-ctl)
  add_dependencies(snort-dx-smoke-platform sucre-snort-ctl)
  add_dependencies(snort-dx-smoke-control sucre-snort-ctl)
  add_dependencies(snort-dx-smoke-datapath sucre-snort-ctl)
  add_dependencies(snort-dx-casebook-other sucre-snort-ctl)
endif()
