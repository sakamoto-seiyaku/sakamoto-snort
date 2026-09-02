/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Host-only installed Product evidence seam. Android never compiles this
 * translation unit; its source closure contains product_packet_graph.c only.
 */
#define SAKAMOTO_PRODUCT_HOST_EVIDENCE 1
#define PRODUCT_GRAPH_FIXTURE "s174-valid-dual-stack-v1"
#define PRODUCT_GRAPH_RUN_FIXTURE_COMMAND "product packet-graph run-fixture"
#define PRODUCT_GRAPH_RUN_FIXTURE_HELP PRODUCT_GRAPH_RUN_FIXTURE_COMMAND " "
#define PRODUCT_GRAPH_CONGESTION_FIXTURE "s175-handoff-congestion-v1"
#define PRODUCT_GRAPH_FRAGMENT_FIXTURE                                    \
  "s175-official-full-reassembly-v1"
#define PRODUCT_GRAPH_RUN_FRAGMENT_FIXTURE_COMMAND                        \
  "product packet-graph run-fragment-fixture"
#define PRODUCT_GRAPH_LIFECYCLE_FIXTURE "s175-bounded-drain-generation-v1"
#define PRODUCT_GRAPH_RUN_LIFECYCLE_FIXTURE_COMMAND                       \
  "product packet-graph run-lifecycle-fixture"
#define PRODUCT_GRAPH_RUN_CONGESTION_FIXTURE_COMMAND                         \
  "product packet-graph run-congestion-fixture"
#define PRODUCT_GRAPH_POLICY_FIXTURE_UID UINT32_C (10001)
#define PRODUCT_GRAPH_POLICY_FIXTURE_CONTEXT UINT32_C (1)
#define PRODUCT_GRAPH_POLICY_FIXTURE "s192-typed-l4-bundle-v1"
#define PRODUCT_GRAPH_RUN_POLICY_FIXTURE_COMMAND \
  "product packet-graph run-policy-fixture"
#define PRODUCT_GRAPH_RUN_POLICY_ASSOCIATION_FIXTURE_COMMAND \
  "product packet-graph run-policy-association-fixture"
#define PRODUCT_GRAPH_RUN_GATE_TABLE_FIXTURE_COMMAND \
  "product packet-graph run-gate-table-fixture"

#include "product_packet_graph.c"
