cmake_minimum_required(VERSION 3.18)

project(sakamoto_snort_workspace LANGUAGES C)

# The former C++ sucre-snort daemon, its host model, and its NDK/APK staging
# target were deliberately removed. The first product seam is the small,
# packet-free Host ABI; the real VPP plugin is built by
# tools/product/build-host-artifact.sh against a pinned external VPP checkout.
add_library(sakamoto_product_host_fixture_abi STATIC
  src/product/native/sakamoto_product_host_fixture_abi.c
)
target_include_directories(sakamoto_product_host_fixture_abi PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src/product/include"
)
target_compile_features(sakamoto_product_host_fixture_abi PRIVATE c_std_11)
target_compile_options(sakamoto_product_host_fixture_abi PRIVATE -Wall -Wextra -Werror)
target_compile_definitions(sakamoto_product_host_fixture_abi PRIVATE SAKAMOTO_PRODUCT_HOST_FIXTURE=1)
set_target_properties(sakamoto_product_host_fixture_abi PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(sakamoto_product_host_fixture_abi PUBLIC pthread)

# The stateless L4 policy view is a VPP-native C module with a standalone Host
# semantic seam.  It deliberately does not depend on VPP, Android, or the
# public Product ABI so the shared rule semantics can be tested independently.
add_library(sakamoto_product_l4_policy STATIC
  src/product/vpp/product_l4_policy.c
)
target_include_directories(sakamoto_product_l4_policy PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src/product/vpp"
)
target_compile_features(sakamoto_product_l4_policy PRIVATE c_std_11)
target_compile_options(sakamoto_product_l4_policy PRIVATE -Wall -Wextra -Werror)

add_executable(sakamoto-product-l4-policy-test
  tests/host/product_l4_policy_test.c
)
target_include_directories(sakamoto-product-l4-policy-test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src/product/vpp"
)
target_compile_features(sakamoto-product-l4-policy-test PRIVATE c_std_11)
target_compile_options(sakamoto-product-l4-policy-test PRIVATE
  -Wall -Wextra -Werror -pedantic)
target_link_libraries(sakamoto-product-l4-policy-test PRIVATE
  sakamoto_product_l4_policy)

add_executable(sakamoto-product-host-fixture-abi-test
  tests/host/product_host_fixture_abi_test.c
)
target_include_directories(sakamoto-product-host-fixture-abi-test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src/product/include"
)
target_compile_features(sakamoto-product-host-fixture-abi-test PRIVATE c_std_11)
target_compile_options(sakamoto-product-host-fixture-abi-test PRIVATE -Wall -Wextra -Werror)
target_link_libraries(sakamoto-product-host-fixture-abi-test PRIVATE
  sakamoto_product_host_fixture_abi pthread)

enable_testing()
add_test(NAME sakamoto-product-host-fixture-abi-test
  COMMAND sakamoto-product-host-fixture-abi-test)
add_test(NAME sakamoto-product-l4-policy-test
  COMMAND sakamoto-product-l4-policy-test)
add_test(NAME sakamoto-product-l4-policy-contract
  COMMAND bash
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_l4_policy_contract.sh")
add_test(NAME sakamoto-product-vpp-contract
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_vpp_contract.sh")
add_test(NAME sakamoto-s174-product-packet-kernel-contract
  COMMAND bash
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/s174-product-packet-kernel-contract.sh")
add_test(NAME sakamoto-s175-product-packet-kernel-contract
  COMMAND bash
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/s175-product-packet-kernel-contract.sh")
add_test(NAME sakamoto-s175-vpp-core-patch-contract
  COMMAND bash
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/s175-vpp-core-patch-contract.sh")
add_test(NAME sakamoto-s175-host-vpp-core-stage-contract
  COMMAND bash
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/s175-host-vpp-core-stage-contract.sh")
add_test(NAME sakamoto-s175-android-vpp-core-profile-contract
  COMMAND bash
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/android/s175-android-vpp-core-profile-contract-test.sh")
add_test(NAME sakamoto-product-host-query-identity-contract
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_query_identity_contract.sh")
add_test(NAME sakamoto-product-host-residue-contract
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_residue_contract.sh")
add_test(NAME sakamoto-product-vapi-callback-contract
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_vapi_callback_contract.sh")
add_test(NAME sakamoto-product-host-vapi-build-contract
  COMMAND bash
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_host_vapi_build_contract.sh")
add_test(NAME sakamoto-product-plugin-init-contract
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_plugin_init_contract.sh")
add_test(NAME sakamoto-product-path-contract
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_path_contract.sh")
add_test(NAME sakamoto-product-core-profile-contract
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_core_profile_contract.sh")

add_custom_target(sakamoto-vpp-mainline-pending
  COMMAND "${CMAKE_COMMAND}" -E echo
          "Build the real VPP-native artifact with tools/product/build-host-artifact.sh."
  VERBATIM
)

message(STATUS "Snort C++ implementation removed; see ADR-0008 and the Android/VPP handoff.")
