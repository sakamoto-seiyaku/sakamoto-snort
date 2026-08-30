/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Host-only installed Product evidence seam. Android never compiles this
 * translation unit; its source closure contains product_packet_graph.c only.
 */
#define SAKAMOTO_PRODUCT_HOST_EVIDENCE 1
#define PRODUCT_GRAPH_FIXTURE "s174-valid-dual-stack-v1"
#define PRODUCT_GRAPH_RUN_FIXTURE_COMMAND "product packet-graph run-fixture"
#define PRODUCT_GRAPH_RUN_FIXTURE_HELP PRODUCT_GRAPH_RUN_FIXTURE_COMMAND " "

#include "product_packet_graph.c"
