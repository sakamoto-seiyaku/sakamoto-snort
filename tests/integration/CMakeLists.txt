cmake_minimum_required(VERSION 3.18)

set(SUCRE_SNORT_INTEGRATION_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(SUCRE_SNORT_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(SUCRE_SNORT_SKIP_REGEX_COMMON "未找到 adb/adb.exe|未检测到已连接的 Android 真机|检测到多台 Android 真机|无法通过 su 获取 root 权限|目标设备未返回 root 身份|错误: 真机 preflight 失败|BLOCKED: .*")

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
  dx-snort10-base
  "${SUCRE_SNORT_INTEGRATION_ROOT}/dx-snort10-base.sh"
  "dx-snort10-base;device;root-required;smoke"
)

add_custom_target(
  snort-dx-snort10-base
  COMMAND "${CMAKE_CTEST_COMMAND}" --output-on-failure -R ^dx-snort10-base$
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
  COMMENT "Run SNORT-10 base real-device smoke via CTest"
  USES_TERMINAL
  VERBATIM
)

if(TARGET sucre-snort-ctl)
  add_dependencies(snort-dx-snort10-base sucre-snort-ctl)
endif()

if(TARGET snort-build-ndk)
  add_dependencies(snort-dx-snort10-base snort-build-ndk)
endif()
