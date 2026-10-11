cmake_minimum_required(VERSION 3.18)

project(sakamoto_snort_workspace LANGUAGES C CXX)
add_subdirectory(third_party/libprotoident)
add_subdirectory(third_party/mbedtls)

# The former C++ sucre-snort daemon, its host model, and its NDK/APK staging
# target were deliberately removed. This workspace tests standalone C semantics
# and the packet-free Host ABI; the real VPP plugin is built by
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
add_library(sakamoto_product_domains STATIC
  src/product/vpp/product_domains.c
  src/product/vpp/product_domains_memory.c
  src/product/vpp/product_domains_rax.c)
target_include_directories(sakamoto_product_domains PUBLIC src/product/include src/product/vpp)
target_compile_features(sakamoto_product_domains PRIVATE c_std_11)
target_compile_options(sakamoto_product_domains PRIVATE -Wall -Wextra -Werror)
target_link_libraries(sakamoto_product_domains PUBLIC m)

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

# The first stateful seam is a fixed-capacity, worker-private FlowEntry pool.
# It has no VPP/Android/Rust dependency so its bounded semantics stay host
# testable before graph integration.
add_library(sakamoto_product_flow_entry STATIC
  src/product/vpp/product_flow_entry.c
  src/product/vpp/product_flow_lpi.c
  src/product/vpp/product_flow_sni.c
  src/product/vpp/product_flow_quic.c
  src/product/vpp/product_flow_udp.c
  src/product/vpp/product_flow_tcp.c
  src/product/vpp/product_flow_icmp.c
)
target_include_directories(sakamoto_product_flow_entry PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src/product/vpp"
)
target_link_libraries(sakamoto_product_flow_entry PUBLIC sakamoto_lpi sakamoto_quic_crypto)
target_compile_features(sakamoto_product_flow_entry PRIVATE c_std_11)
target_compile_options(sakamoto_product_flow_entry PRIVATE -Wall -Wextra -Werror)

add_executable(sakamoto-product-flow-entry-test
  tests/host/product_flow_entry_test.c
  src/product/vpp/product_packet.c
)
target_include_directories(sakamoto-product-flow-entry-test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src/product/vpp"
)
target_compile_features(sakamoto-product-flow-entry-test PRIVATE c_std_11)
target_compile_options(sakamoto-product-flow-entry-test PRIVATE
  -Wall -Wextra -Werror -pedantic)
target_link_libraries(sakamoto-product-flow-entry-test PRIVATE
  sakamoto_product_flow_entry)

add_executable(sakamoto-product-blocked-observation-test
  tests/host/product_blocked_observation_test.c
  src/product/vpp/product_blocked_observation.c)
target_include_directories(sakamoto-product-blocked-observation-test PRIVATE
  src/product/include src/product/vpp)
target_compile_features(sakamoto-product-blocked-observation-test PRIVATE c_std_11)
target_compile_options(sakamoto-product-blocked-observation-test PRIVATE -Wall -Wextra -Werror)

add_executable(sakamoto-product-host-fixture-abi-test
  tests/host/product_host_fixture_abi_test.c
)

add_executable(sakamoto-product-flow-udp-test
  tests/host/product_flow_udp_test.c
  src/product/vpp/product_packet.c
)
target_compile_features(sakamoto-product-flow-udp-test PRIVATE c_std_11)
target_compile_options(sakamoto-product-flow-udp-test PRIVATE
  -Wall -Wextra -Werror -pedantic)
target_link_libraries(sakamoto-product-flow-udp-test PRIVATE sakamoto_product_flow_entry)
target_include_directories(sakamoto-product-host-fixture-abi-test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src/product/include"
)
target_compile_features(sakamoto-product-host-fixture-abi-test PRIVATE c_std_11)
target_compile_options(sakamoto-product-host-fixture-abi-test PRIVATE -Wall -Wextra -Werror)
target_link_libraries(sakamoto-product-host-fixture-abi-test PRIVATE
  sakamoto_product_host_fixture_abi pthread)

enable_testing()
add_test(NAME sakamoto-product-blocked-observation-test COMMAND sakamoto-product-blocked-observation-test)
add_executable(sakamoto-product-vpn-return-credit-test
  tests/host/product_vpn_return_credit_test.c)
target_include_directories(sakamoto-product-vpn-return-credit-test PRIVATE src/product/vpp)
target_compile_options(sakamoto-product-vpn-return-credit-test PRIVATE -Wall -Wextra -Werror)
target_link_libraries(sakamoto-product-vpn-return-credit-test PRIVATE pthread)
add_test(NAME sakamoto-product-vpn-return-credit-test COMMAND sakamoto-product-vpn-return-credit-test)
add_executable(sakamoto-product-domains-test tests/host/product_domains_test.c)
target_link_libraries(sakamoto-product-domains-test PRIVATE sakamoto_product_domains)
target_link_options(sakamoto-product-domains-test PRIVATE -Wl,--wrap=product_domains_memory_alloc -Wl,--wrap=product_domains_memory_free)
target_compile_options(sakamoto-product-domains-test PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME sakamoto-product-domains-test COMMAND sakamoto-product-domains-test)
add_executable(sakamoto-product-flow-quic-test tests/host/product_flow_quic_test.c src/product/vpp/product_packet.c)
target_link_libraries(sakamoto-product-flow-quic-test PRIVATE sakamoto_product_flow_entry sakamoto_product_l4_policy sakamoto_product_domains)
target_compile_options(sakamoto-product-flow-quic-test PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME sakamoto-product-flow-quic-test COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/quic_initial_vectors.py" $<TARGET_FILE:sakamoto-product-flow-quic-test>)
add_test(NAME sakamoto-product-quic-assembly-test COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/quic_crypto_sequences.py" $<TARGET_FILE:sakamoto-product-flow-quic-test>)
add_executable(sakamoto-product-policy-cache-test tests/host/product_policy_cache_test.c src/product/vpp/product_packet.c)
target_link_libraries(sakamoto-product-policy-cache-test PRIVATE sakamoto_product_l4_policy sakamoto_product_flow_entry)
target_compile_options(sakamoto-product-policy-cache-test PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME sakamoto-product-policy-cache-test COMMAND sakamoto-product-policy-cache-test)
add_executable(sakamoto-product-ct-policy-test
  tests/host/product_ct_policy_test.c src/product/vpp/product_packet.c)
target_link_libraries(sakamoto-product-ct-policy-test PRIVATE
  sakamoto_product_l4_policy sakamoto_product_flow_entry)
target_compile_options(sakamoto-product-ct-policy-test PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME sakamoto-product-ct-policy-test COMMAND sakamoto-product-ct-policy-test)
add_test(NAME sakamoto-product-static-reference-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_static_reference_test.py")
add_executable(sakamoto-product-rule-config-test
  tests/host/product_rule_config_test.c
  src/product/vpp/product_rule_config.c
  src/product/vpp/product_l4_policy.c)
target_include_directories(sakamoto-product-rule-config-test PRIVATE
  src/product/include src/product/vpp)
target_compile_features(sakamoto-product-rule-config-test PRIVATE c_std_11)
target_compile_options(sakamoto-product-rule-config-test PRIVATE -Wall -Wextra -Werror)
target_link_libraries(sakamoto-product-rule-config-test PRIVATE sakamoto_product_domains)
target_link_options(sakamoto-product-rule-config-test PRIVATE -Wl,--wrap=getrandom -Wl,--wrap=fsync -Wl,--wrap=malloc -Wl,--wrap=calloc
  -Wl,--wrap=product_domains_memory_alloc -Wl,--wrap=product_domains_memory_free)
add_test(NAME sakamoto-product-rule-config-test COMMAND sakamoto-product-rule-config-test)
add_test(NAME sakamoto-rule-config-android-contract
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/android/t01-rule-configuration-test.sh")
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_executable(sakamoto-product-linux-network-test tests/host/product_linux_network_test.c)
  target_include_directories(sakamoto-product-linux-network-test PRIVATE src/product/include)
  target_compile_features(sakamoto-product-linux-network-test PRIVATE c_std_11)
  target_compile_options(sakamoto-product-linux-network-test PRIVATE -Wall -Wextra -Werror)
  add_test(NAME sakamoto-product-linux-network-test COMMAND sakamoto-product-linux-network-test)
endif()
add_executable(sakamoto-product-flow-icmp-test tests/host/product_flow_icmp_test.c src/product/vpp/product_packet.c)
target_link_libraries(sakamoto-product-flow-icmp-test PRIVATE sakamoto_product_flow_entry)
target_compile_options(sakamoto-product-flow-icmp-test PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME sakamoto-product-flow-icmp-test COMMAND sakamoto-product-flow-icmp-test)

add_executable(sakamoto-product-flow-timeout-test tests/host/product_flow_timeout_test.c)
target_include_directories(sakamoto-product-flow-timeout-test PRIVATE src/product/vpp)
target_compile_options(sakamoto-product-flow-timeout-test PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME sakamoto-product-flow-timeout-test COMMAND sakamoto-product-flow-timeout-test)

add_executable(sakamoto-product-diagnostic-hex-test tests/host/product_diagnostic_hex_test.c)
target_include_directories(sakamoto-product-diagnostic-hex-test PRIVATE src/product/vpp)
target_compile_options(sakamoto-product-diagnostic-hex-test PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME sakamoto-product-diagnostic-hex-test COMMAND sakamoto-product-diagnostic-hex-test)

add_executable(sakamoto-product-flow-end-test tests/host/product_flow_end_test.c src/product/vpp/product_packet.c)
target_link_libraries(sakamoto-product-flow-end-test PRIVATE sakamoto_product_flow_entry)
target_compile_options(sakamoto-product-flow-end-test PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME sakamoto-product-flow-end-test COMMAND sakamoto-product-flow-end-test)

add_executable(sakamoto-product-flow-expiry-test tests/host/product_flow_expiry_test.c src/product/vpp/product_packet.c)
target_link_libraries(sakamoto-product-flow-expiry-test PRIVATE sakamoto_product_flow_entry)
target_compile_options(sakamoto-product-flow-expiry-test PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME sakamoto-product-flow-expiry-test COMMAND sakamoto-product-flow-expiry-test)
add_executable(sakamoto-product-root-receive-pool-test tests/host/product_root_receive_pool_test.c)
target_include_directories(sakamoto-product-root-receive-pool-test PRIVATE src/product/vpp)
target_compile_options(sakamoto-product-root-receive-pool-test PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME sakamoto-product-root-receive-pool-test COMMAND sakamoto-product-root-receive-pool-test)
add_executable(sakamoto-product-flow-tcp-test tests/host/product_flow_tcp_test.c src/product/vpp/product_packet.c)
target_link_libraries(sakamoto-product-flow-tcp-test PRIVATE sakamoto_product_flow_entry)
target_compile_options(sakamoto-product-flow-tcp-test PRIVATE -Wall -Wextra -Werror -pedantic)
add_test(NAME sakamoto-product-flow-tcp-test COMMAND sakamoto-product-flow-tcp-test)
add_test(NAME sakamoto-product-flow-udp-test COMMAND sakamoto-product-flow-udp-test)
add_test(NAME sakamoto-product-host-fixture-abi-test
  COMMAND sakamoto-product-host-fixture-abi-test)
add_test(NAME sakamoto-product-l4-policy-test
  COMMAND sakamoto-product-l4-policy-test)
add_test(NAME sakamoto-product-flow-entry-test
  COMMAND sakamoto-product-flow-entry-test)
add_test(NAME sakamoto-product-flow-entry-contract
  COMMAND bash
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_flow_entry_contract.sh")
add_test(NAME sakamoto-s209-policy-snapshot-contract
  COMMAND python3
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/s209-policy-snapshot-contract.py")
add_test(NAME sakamoto-s210-capacity-bypass-contract
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/s210-capacity-bypass-contract.sh")
add_test(NAME sakamoto-product-l4-policy-contract
  COMMAND bash
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_l4_policy_contract.sh")
add_test(NAME sakamoto-product-vpp-contract
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_vpp_contract.sh")
add_test(NAME sakamoto-product-external-graph-ownership-contract
  COMMAND bash
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_external_graph_ownership_contract.sh")
add_test(NAME sakamoto-s174-product-packet-kernel-contract
  COMMAND bash
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/s174-product-packet-kernel-contract.sh")
add_test(NAME sakamoto-s192-product-packet-graph-policy-contract
  COMMAND bash
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/s192-product-packet-graph-policy-contract.sh")
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
add_test(NAME sakamoto-android-runtime-contract
  COMMAND bash
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/android/android-runtime-contract-test.sh")
add_test(NAME sakamoto-s187-worker-core-guardrails-contract
  COMMAND bash
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/android/s187-worker-core-guardrails-contract-test.sh")

add_test(NAME sakamoto-product-platform-boundary-contract
  COMMAND python3
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_platform_boundary_test.py")
add_test(NAME sakamoto-vpp-runtime-mode-test
  COMMAND python3
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/vpp_runtime_mode_test.py")

add_test(NAME sakamoto-android-runtime-teardown-contract
  COMMAND bash
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/android/s196-runtime-instance-teardown-contract-test.sh")
add_test(NAME sakamoto-repository-navigation-contract
  COMMAND python3
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/repository_navigation_test.py")
add_test(NAME sakamoto-reference-naming-contract
  COMMAND python3
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/reference_naming_test.py")
add_test(NAME sakamoto-experiment-catalog-contract
  COMMAND python3
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/experiment_catalog_test.py")
add_test(NAME sakamoto-product-host-query-identity-contract
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_query_identity_contract.sh")
add_test(NAME sakamoto-product-host-residue-contract
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_residue_contract.sh")
add_test(NAME sakamoto-product-vapi-callback-contract
  COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_vapi_callback_contract.sh")
add_test(NAME sakamoto-s242-packet-identity-contract
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/s242_packet_identity_test.py")
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

message(STATUS "VPP-native C Product: standalone Host tests here; see docs/current/README.md for artifact builds and limits.")

add_executable(sakamoto-product-flow-lpi-test tests/host/product_flow_lpi_test.c
  src/product/vpp/product_packet.c)
target_compile_options(sakamoto-product-flow-lpi-test PRIVATE -Wall -Wextra -Werror -pedantic)
target_link_libraries(sakamoto-product-flow-lpi-test PRIVATE sakamoto_product_flow_entry sakamoto_product_l4_policy)
add_test(NAME sakamoto-product-flow-lpi-test COMMAND sakamoto-product-flow-lpi-test)
add_test(NAME sakamoto-product-protocol-catalog-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/catalog/application_protocol_catalog_contract_test.py")

add_executable(sakamoto-product-flow-sni-test tests/host/product_flow_sni_test.c
  src/product/vpp/product_packet.c)
target_compile_options(sakamoto-product-flow-sni-test PRIVATE -Wall -Wextra -Werror -pedantic)
target_link_libraries(sakamoto-product-flow-sni-test PRIVATE sakamoto_product_flow_entry sakamoto_product_l4_policy sakamoto_product_domains)
add_test(NAME sakamoto-product-flow-sni-test COMMAND sakamoto-product-flow-sni-test)
