cmake_minimum_required(VERSION 3.18)

project(sakamoto_snort_workspace LANGUAGES C CXX)
option(SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT
  "Build the Root whole-path batch implementation" ON)
option(SAKAMOTO_PRODUCT_POLICY_QUALIFICATION_COUNTERS
  "Record policy completion coupled to successful Root verdicts" OFF)
add_subdirectory(third_party/libprotoident)
add_subdirectory(third_party/mbedtls)
add_subdirectory(third_party/cares)

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
if(SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT)
  target_compile_definitions(sakamoto_product_l4_policy PUBLIC
    SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT=1)
endif()

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

add_library(sakamoto_product_dns STATIC src/product/vpp/product_dns.c src/product/vpp/product_dns_tcp.c
  src/product/vpp/product_dns_proxy.c src/product/vpp/product_dns_tls.c
  src/product/vpp/product_dns_bootstrap.c src/product/vpp/product_dns_http.c)
target_link_libraries(sakamoto_product_dns PUBLIC
  sakamoto_product_l4_policy sakamoto_product_domains PRIVATE sakamoto_dns_wire sakamoto_quic_crypto)
target_compile_features(sakamoto_product_dns PRIVATE c_std_11)
target_compile_options(sakamoto_product_dns PRIVATE -Wall -Wextra -Werror)
add_executable(sakamoto-product-dns-query-test tests/host/product_dns_query_test.c
  src/product/vpp/product_packet.c)
target_link_libraries(sakamoto-product-dns-query-test PRIVATE sakamoto_product_dns)
add_test(NAME sakamoto-product-dns-query-test COMMAND sakamoto-product-dns-query-test)
add_executable(sakamoto-product-dns-response-test tests/host/product_dns_response_test.c)
target_link_libraries(sakamoto-product-dns-response-test PRIVATE sakamoto_product_dns)
target_compile_options(sakamoto-product-dns-response-test PRIVATE -Wall -Wextra -Werror)
add_test(NAME sakamoto-product-dns-response-test COMMAND sakamoto-product-dns-response-test)
add_executable(sakamoto-product-dns-tcp-test tests/host/product_dns_tcp_test.c)
target_link_libraries(sakamoto-product-dns-tcp-test PRIVATE sakamoto_product_dns)
target_compile_options(sakamoto-product-dns-tcp-test PRIVATE -Wall -Wextra -Werror)
add_test(NAME sakamoto-product-dns-tcp-test COMMAND sakamoto-product-dns-tcp-test)
add_executable(sakamoto-product-dns-proxy-test tests/host/product_dns_proxy_test.c)
target_link_libraries(sakamoto-product-dns-proxy-test PRIVATE sakamoto_product_dns sakamoto_dns_wire)
target_compile_options(sakamoto-product-dns-proxy-test PRIVATE -Wall -Wextra -Werror)
add_test(NAME sakamoto-hev-stage-cache-test COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/hev_stage_cache_test.py")
add_test(NAME sakamoto-product-dns-proxy-test COMMAND sakamoto-product-dns-proxy-test)
add_executable(sakamoto-product-dns-routing-test tests/host/product_dns_routing_test.c)
target_link_libraries(sakamoto-product-dns-routing-test PRIVATE sakamoto_product_dns)
target_compile_options(sakamoto-product-dns-routing-test PRIVATE -Wall -Wextra -Werror)
add_test(NAME sakamoto-product-dns-routing-test COMMAND sakamoto-product-dns-routing-test)
add_executable(sakamoto-product-dns-coalescing-test tests/host/product_dns_coalescing_test.c)
target_link_libraries(sakamoto-product-dns-coalescing-test PRIVATE sakamoto_product_dns)
target_compile_options(sakamoto-product-dns-coalescing-test PRIVATE -Wall -Wextra -Werror)
target_link_options(sakamoto-product-dns-coalescing-test PRIVATE -Wl,--wrap=malloc)
add_test(NAME sakamoto-product-dns-coalescing-test COMMAND sakamoto-product-dns-coalescing-test)
add_executable(sakamoto-product-dns-coalescing-io-test tests/host/product_dns_coalescing_io_test.c
  src/product/vpp/product_root_dns_io.c)
target_link_libraries(sakamoto-product-dns-coalescing-io-test PRIVATE sakamoto_product_dns)
target_compile_options(sakamoto-product-dns-coalescing-io-test PRIVATE -Wall -Wextra -Werror)
add_test(NAME sakamoto-product-dns-coalescing-io-test COMMAND sakamoto-product-dns-coalescing-io-test)
add_executable(sakamoto-product-dns-cache-test tests/host/product_dns_cache_test.c)
target_link_libraries(sakamoto-product-dns-cache-test PRIVATE sakamoto_product_dns)
target_compile_options(sakamoto-product-dns-cache-test PRIVATE -Wall -Wextra -Werror)
add_test(NAME sakamoto-product-dns-cache-test COMMAND sakamoto-product-dns-cache-test)
add_executable(sakamoto-product-dns-cache-names-test tests/host/product_dns_cache_names_test.c)
target_link_libraries(sakamoto-product-dns-cache-names-test PRIVATE sakamoto_product_dns)
target_compile_options(sakamoto-product-dns-cache-names-test PRIVATE -Wall -Wextra -Werror)
add_test(NAME sakamoto-product-dns-cache-names-test COMMAND sakamoto-product-dns-cache-names-test)
foreach(cache_case compression fallback)
  add_executable(sakamoto-product-dns-cache-${cache_case}-test tests/host/product_dns_cache_${cache_case}_test.c)
  target_link_libraries(sakamoto-product-dns-cache-${cache_case}-test PRIVATE sakamoto_product_dns sakamoto_dns_wire)
  target_compile_options(sakamoto-product-dns-cache-${cache_case}-test PRIVATE -Wall -Wextra -Werror)
  add_test(NAME sakamoto-product-dns-cache-${cache_case}-test COMMAND sakamoto-product-dns-cache-${cache_case}-test)
endforeach()
add_executable(sakamoto-product-dns-cache-allocation-test tests/host/product_dns_cache_allocation_test.c)
target_link_libraries(sakamoto-product-dns-cache-allocation-test PRIVATE sakamoto_product_dns)
target_compile_options(sakamoto-product-dns-cache-allocation-test PRIVATE -Wall -Wextra -Werror)
target_link_options(sakamoto-product-dns-cache-allocation-test PRIVATE
  -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc -Wl,--wrap=free)
add_test(NAME sakamoto-product-dns-cache-allocation-test COMMAND sakamoto-product-dns-cache-allocation-test)
add_executable(sakamoto-product-root-dns-io-test tests/host/product_root_dns_io_test.c
  src/product/vpp/product_root_dns_io.c)
target_link_libraries(sakamoto-product-root-dns-io-test PRIVATE sakamoto_product_dns)
target_compile_options(sakamoto-product-root-dns-io-test PRIVATE -Wall -Wextra -Werror)
add_test(NAME sakamoto-product-root-dns-io-test COMMAND sakamoto-product-root-dns-io-test)
add_executable(sakamoto-product-dns-routing-io-test tests/host/product_dns_routing_io_test.c
  src/product/vpp/product_root_dns_io.c)
target_link_libraries(sakamoto-product-dns-routing-io-test PRIVATE sakamoto_product_dns)
target_compile_options(sakamoto-product-dns-routing-io-test PRIVATE -Wall -Wextra -Werror)
add_test(NAME sakamoto-product-dns-routing-io-test COMMAND sakamoto-product-dns-routing-io-test)
add_executable(sakamoto-product-dns-route-doh-test tests/host/product_dns_route_doh_test.c)
target_include_directories(sakamoto-product-dns-route-doh-test PRIVATE src/product/vpp src/product/include)
target_compile_options(sakamoto-product-dns-route-doh-test PRIVATE -Wall -Wextra -Werror)
add_test(NAME sakamoto-product-dns-route-doh-test COMMAND sakamoto-product-dns-route-doh-test)
add_executable(sakamoto-product-dns-http-test tests/host/product_dns_http_test.c)
target_link_libraries(sakamoto-product-dns-http-test PRIVATE sakamoto_product_dns)
target_compile_options(sakamoto-product-dns-http-test PRIVATE -Wall -Wextra -Werror)
add_test(NAME sakamoto-product-dns-http-test COMMAND sakamoto-product-dns-http-test)
add_executable(sakamoto-product-dns-doh-io-test tests/host/product_dns_doh_io_test.c
  src/product/vpp/product_root_dns_io.c)
target_link_libraries(sakamoto-product-dns-doh-io-test PRIVATE sakamoto_product_dns)
target_compile_options(sakamoto-product-dns-doh-io-test PRIVATE -Wall -Wextra -Werror)
add_test(NAME sakamoto-product-dns-doh-io-test COMMAND python3
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_dns_doh_io_test.py"
  $<TARGET_FILE:sakamoto-product-dns-doh-io-test>)
add_executable(sakamoto-product-dns-dot-io-test tests/host/product_dns_dot_io_test.c
  src/product/vpp/product_root_dns_io.c)
target_link_libraries(sakamoto-product-dns-dot-io-test PRIVATE sakamoto_product_dns)
target_link_options(sakamoto-product-dns-dot-io-test PRIVATE "LINKER:--wrap=getrandom")
target_compile_options(sakamoto-product-dns-dot-io-test PRIVATE -Wall -Wextra -Werror)
add_test(NAME sakamoto-product-dns-dot-io-test COMMAND python3
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_dns_dot_io_test.py"
  $<TARGET_FILE:sakamoto-product-dns-dot-io-test>)
add_executable(sakamoto-product-root-dns-tcp-io-test tests/host/product_root_dns_tcp_io_test.c
  src/product/vpp/product_root_dns_tcp_io.c)
target_link_libraries(sakamoto-product-root-dns-tcp-io-test PRIVATE sakamoto_product_dns)
target_link_options(sakamoto-product-root-dns-tcp-io-test PRIVATE -Wl,--wrap=malloc)
target_compile_definitions(sakamoto-product-root-dns-tcp-io-test PRIVATE _GNU_SOURCE)
target_compile_options(sakamoto-product-root-dns-tcp-io-test PRIVATE -Wall -Wextra -Werror)
add_test(NAME sakamoto-product-root-dns-tcp-io-test COMMAND sakamoto-product-root-dns-tcp-io-test)
add_test(NAME sakamoto-product-root-dns-tcp-partial-fin-test COMMAND sakamoto-product-root-dns-tcp-io-test 1)
add_test(NAME sakamoto-product-root-dns-tcp-backpressure-test COMMAND sakamoto-product-root-dns-tcp-io-test 2)
add_test(NAME sakamoto-product-root-dns-tcp-watch-failure-test COMMAND sakamoto-product-root-dns-tcp-io-test 3)
add_test(NAME sakamoto-product-root-dns-tcp-fin-rst-test COMMAND sakamoto-product-root-dns-tcp-io-test 5)
add_test(NAME sakamoto-product-root-dns-tcp-resume-test COMMAND sakamoto-product-root-dns-tcp-io-test 6)
add_test(NAME sakamoto-product-root-dns-tcp-resource-bounds-test COMMAND sakamoto-product-root-dns-tcp-io-test 7)
add_test(NAME sakamoto-product-root-dns-tcp-pending-bounds-test COMMAND sakamoto-product-root-dns-tcp-io-test 8)
add_test(NAME sakamoto-product-root-dns-tcp-pending-rst-test COMMAND sakamoto-product-root-dns-tcp-io-test 9)
add_test(NAME sakamoto-product-root-dns-tcp-pending-multiclient-test COMMAND sakamoto-product-root-dns-tcp-io-test 10)
add_test(NAME sakamoto-product-root-dns-tcp-pending-stop-test COMMAND sakamoto-product-root-dns-tcp-io-test 11)
add_test(NAME sakamoto-product-root-dns-tcp-output-malloc-test COMMAND sakamoto-product-root-dns-tcp-io-test 12)
add_test(NAME sakamoto-product-root-dns-tcp-output-abandon-test COMMAND sakamoto-product-root-dns-tcp-io-test 13)
add_test(NAME sakamoto-product-dns-authorization-test COMMAND sakamoto-product-root-dns-io-test authorization)
add_test(NAME sakamoto-product-dns-idle-authorization-test COMMAND sakamoto-product-root-dns-io-test idle-authorization)
add_test(NAME sakamoto-dns-wire-observation-test COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/dns_wire_observation_test.py")
add_test(NAME sakamoto-dns-peer-gate-test COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/dns_peer_gate_test.py")
add_test(NAME sakamoto-product-vpn-stopped-tcp-wire-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_device_vpn_tcp_stop_wire_test.py")
add_test(NAME sakamoto-product-dns-readiness-contract
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_dns_readiness_test.py")
add_test(NAME sakamoto-product-dns-history-qualification-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_dns_history_qualification_test.py")
add_test(NAME sakamoto-product-dns-dispatch-qualification-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_dns_dispatch_qualification_test.py")
add_test(NAME sakamoto-product-root-dns-adapter-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_root_dns_adapter_test.py"
    $<TARGET_FILE:sakamoto_product_dns> $<TARGET_FILE:sakamoto_product_l4_policy>
    $<TARGET_FILE:sakamoto_product_domains> $<TARGET_FILE:sakamoto_dns_wire>)
add_test(NAME sakamoto-product-dns-cache-adapter-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_root_dns_adapter_test.py"
    $<TARGET_FILE:sakamoto_product_dns> $<TARGET_FILE:sakamoto_product_l4_policy>
    $<TARGET_FILE:sakamoto_product_domains> $<TARGET_FILE:sakamoto_dns_wire> --case cache)
add_test(NAME sakamoto-product-root-dns-tcp-adapter-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_root_dns_adapter_test.py"
    $<TARGET_FILE:sakamoto_product_dns> $<TARGET_FILE:sakamoto_product_l4_policy>
    $<TARGET_FILE:sakamoto_product_domains> $<TARGET_FILE:sakamoto_dns_wire> --case tcp-proxy)
add_test(NAME sakamoto-product-root-dns-tcp-unknown-caller-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_root_dns_adapter_test.py"
    $<TARGET_FILE:sakamoto_product_dns> $<TARGET_FILE:sakamoto_product_l4_policy>
    $<TARGET_FILE:sakamoto_product_domains> $<TARGET_FILE:sakamoto_dns_wire> --case tcp-unknown)
add_test(NAME sakamoto-product-vpn-dns-authority-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_root_dns_adapter_test.py"
    $<TARGET_FILE:sakamoto_product_dns> $<TARGET_FILE:sakamoto_product_l4_policy>
    $<TARGET_FILE:sakamoto_product_domains> $<TARGET_FILE:sakamoto_dns_wire> --case vpn-authority)
foreach(vpn_tcp_case off view)
  add_test(NAME "sakamoto-product-vpn-dns-tcp-${vpn_tcp_case}-test"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_root_dns_adapter_test.py"
      $<TARGET_FILE:sakamoto_product_dns> $<TARGET_FILE:sakamoto_product_l4_policy>
      $<TARGET_FILE:sakamoto_product_domains> $<TARGET_FILE:sakamoto_dns_wire> --case "vpn-tcp-${vpn_tcp_case}")
endforeach()
add_test(NAME sakamoto-product-dns-idle-readiness-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_root_dns_adapter_test.py"
    $<TARGET_FILE:sakamoto_product_dns> $<TARGET_FILE:sakamoto_product_l4_policy>
    $<TARGET_FILE:sakamoto_product_domains> $<TARGET_FILE:sakamoto_dns_wire> --case idle-health)
add_test(NAME sakamoto-product-vpn-dns-return-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_root_dns_adapter_test.py"
    $<TARGET_FILE:sakamoto_product_dns> $<TARGET_FILE:sakamoto_product_l4_policy>
    $<TARGET_FILE:sakamoto_product_domains> $<TARGET_FILE:sakamoto_dns_wire> --case vpn-return)
add_test(NAME sakamoto-product-root-dns-generation-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_root_dns_adapter_test.py"
    $<TARGET_FILE:sakamoto_product_dns> $<TARGET_FILE:sakamoto_product_l4_policy>
    $<TARGET_FILE:sakamoto_product_domains> $<TARGET_FILE:sakamoto_dns_wire> --case generation)
foreach(dns_transition_case crossover reverse-crossover)
  add_test(NAME "sakamoto-product-root-dns-${dns_transition_case}-test"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_root_dns_adapter_test.py"
      $<TARGET_FILE:sakamoto_product_dns> $<TARGET_FILE:sakamoto_product_l4_policy>
      $<TARGET_FILE:sakamoto_product_domains> $<TARGET_FILE:sakamoto_dns_wire> --case "${dns_transition_case}")
endforeach()
add_test(NAME sakamoto-product-dns-tcp-graph-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_dns_tcp_graph_test.py"
    $<TARGET_FILE:sakamoto_product_dns> $<TARGET_FILE:sakamoto_product_l4_policy>
    $<TARGET_FILE:sakamoto_product_domains> $<TARGET_FILE:sakamoto_dns_wire>)
add_test(NAME sakamoto-product-dns-graph-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_dns_graph_test.py")
add_test(NAME sakamoto-product-vpn-uid-dns-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_vpn_uid_dns_test.py")

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
if(SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT)
  target_compile_definitions(sakamoto_product_flow_entry PUBLIC
    SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT=1)
endif()

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
add_executable(sakamoto-product-vpn-tun-write-test
  tests/host/product_vpn_tun_write_test.c)
target_include_directories(sakamoto-product-vpn-tun-write-test PRIVATE src/product/vpp)
target_compile_features(sakamoto-product-vpn-tun-write-test PRIVATE c_std_11)
target_compile_options(sakamoto-product-vpn-tun-write-test PRIVATE -Wall -Wextra -Werror)
add_test(NAME sakamoto-product-vpn-tun-write-test COMMAND sakamoto-product-vpn-tun-write-test)
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
add_test(NAME sakamoto-vpn-packet-profile-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/vpn_packet_profile_test.py")
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/build-output/pinned-vpp-clean/src/vlib/buffer.c")
  add_test(NAME sakamoto-vpp-virtual-buffer-test
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/vpp_virtual_buffer_test.py")
endif()
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
add_test(NAME sakamoto-product-external-batch-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_external_batch_test.py")
add_test(NAME sakamoto-product-vpn-capture-batch-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_vpn_capture_batch_test.py")
add_test(NAME sakamoto-product-vpn-return-batch-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_vpn_return_batch_test.py")
add_test(NAME sakamoto-product-packet-batch-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_packet_batch_test.py")
add_test(NAME sakamoto-product-policy-batch-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_policy_batch_test.py")
add_test(NAME sakamoto-product-nfqueue-verdict-batch-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_nfqueue_verdict_batch_test.py")
add_test(NAME sakamoto-product-root-pending-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_root_pending_test.py")
add_test(NAME product_root_io
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_root_io_test.py")
add_test(NAME product_root_dns_admission
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_root_dns_admission_test.py")
add_test(NAME product_root_dns_reassembly_admission
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_root_dns_reassembly_admission_test.py")
add_test(NAME product_root_dns_receiver
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_root_dns_receiver_test.py")
add_test(NAME product_root_capacity
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_root_capacity_test.py")
add_test(NAME sakamoto-product-root-defaults-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_root_defaults_test.py")
add_test(NAME sakamoto-product-build-cache-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_build_cache_test.py")
add_test(NAME sakamoto-product-l4-match-evidence-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_l4_match_evidence_test.py")
add_test(NAME sakamoto-product-stop-before-start-test
  COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_stop_before_start_test.py")
add_test(NAME sakamoto-s174-product-packet-kernel-contract
  COMMAND bash
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/s174-product-packet-kernel-contract.sh")
# The S192 Host-only graph CLI cannot be built on the current VPP pin. Exercise
# the installed Product RuleConfig path instead; packet decisions also have
# the separate policy-cache, CT-policy and policy-batch executable tests.
add_test(NAME sakamoto-product-unified-rule-runtime-contract
  COMMAND bash
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/host/product_unified_rule_runtime_contract.sh")
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
