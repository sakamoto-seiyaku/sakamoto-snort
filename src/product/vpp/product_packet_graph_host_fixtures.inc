/* SPDX-License-Identifier: Apache-2.0 */

/* Private Host fixtures; included in the graph's original translation unit. */
static u32
product_ipv4_fixture (u8 *packet, u8 protocol, u32 source, u16 source_port,
                      u32 destination, u16 destination_port)
{
  clib_memset (packet, 0, 64);
  packet[0] = 0x45;
  packet[3] = protocol == 6 ? 40 : 28;
  packet[8] = 64;
  packet[9] = protocol;
  packet[12] = (u8) (source >> 24);
  packet[13] = (u8) (source >> 16);
  packet[14] = (u8) (source >> 8);
  packet[15] = (u8) source;
  packet[16] = (u8) (destination >> 24);
  packet[17] = (u8) (destination >> 16);
  packet[18] = (u8) (destination >> 8);
  packet[19] = (u8) destination;
  packet[20] = (u8) (source_port >> 8);
  packet[21] = (u8) source_port;
  packet[22] = (u8) (destination_port >> 8);
  packet[23] = (u8) destination_port;
  if (protocol == 6)
    packet[32] = 0x50;
  else
    packet[25] = 8;
  return protocol == 6 ? 40 : 28;
}

static u32
product_ipv6_fixture (u8 *packet, u8 protocol, const u8 source[16],
                      u16 source_port, const u8 destination[16],
                      u16 destination_port)
{
  u16 payload_length = protocol == 6 ? 20 : 8;
  clib_memset (packet, 0, 80);
  packet[0] = 0x60;
  packet[4] = (u8) (payload_length >> 8);
  packet[5] = (u8) payload_length;
  packet[6] = protocol;
  packet[7] = 64;
  clib_memcpy_fast (packet + 8, source, 16);
  clib_memcpy_fast (packet + 24, destination, 16);
  packet[40] = (u8) (source_port >> 8);
  packet[41] = (u8) source_port;
  packet[42] = (u8) (destination_port >> 8);
  packet[43] = (u8) destination_port;
  if (protocol == 6)
    packet[52] = 0x50;
  else
    packet[45] = 8;
  return 40 + payload_length;
}

static u32
product_materialize_fixture (u8 fixture_index, u8 *packet)
{
  static const u8 ip6_a[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                0,    0,    0,    0,    0, 0, 0, 1 };
  static const u8 ip6_b[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                0,    0,    0,    0,    0, 0, 0, 2 };
  switch (fixture_index)
    {
    case 0:
      return product_ipv4_fixture (packet, 6, 0x0a000001, 12345,
                                   0x0a000002, 443);
    case 1:
      return product_ipv4_fixture (packet, 6, 0x0a000002, 443,
                                   0x0a000001, 12345);
    case 2:
      return product_ipv4_fixture (packet, 17, 0xc0000201, 5353,
                                   0xc6336402, 53);
    case 3:
      return product_ipv4_fixture (packet, 17, 0xc6336402, 53,
                                   0xc0000201, 5353);
    case 4:
      return product_ipv6_fixture (packet, 6, ip6_a, 2222, ip6_b, 8443);
    case 5:
      return product_ipv6_fixture (packet, 6, ip6_b, 8443, ip6_a, 2222);
    case 6:
      return product_ipv6_fixture (packet, 17, ip6_a, 60000, ip6_b, 443);
    default:
      return product_ipv6_fixture (packet, 17, ip6_b, 443, ip6_a, 60000);
    }
}

static clib_error_t *
product_packet_graph_configure_cli (vlib_main_t *vm, unformat_input_t *input,
                                    vlib_cli_command_t *command)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u32 workers = 0;
  u8 *fixture = 0;
  (void) command;

  if (!unformat (input, "workers %u fixture %s", &workers, &fixture)
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      vec_free (fixture);
      return clib_error_return (0, "expected: workers 2 fixture %s",
                                PRODUCT_GRAPH_FIXTURE);
    }
  if (workers != PRODUCT_GRAPH_WORKERS || vlib_num_workers () != workers
      || (strcmp ((char *) fixture, PRODUCT_GRAPH_FIXTURE) != 0
          && strcmp ((char *) fixture, PRODUCT_GRAPH_FRAGMENT_FIXTURE) != 0)
      || clib_atomic_load_acq_n (&graph->enabled)
      || clib_atomic_load_acq_n (&graph->buffer_debt) != 0
      || clib_atomic_load_acq_n (&graph->handoff_credit_debt) != 0
      || clib_atomic_load_acq_n (&graph->obligation_debt) != 0)
    {
      vec_free (fixture);
      return clib_error_return (0, "graph configuration rejected");
    }
  vec_free (fixture);
  graph->configured = 1;
  vlib_cli_output (vm, "graph.configure=ok");
  vlib_cli_output (vm, "graph.workers=2");
  vlib_cli_output (vm, "graph.fixture=%s", PRODUCT_GRAPH_FIXTURE);
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_configure_command, static) = {
  .path = "product packet-graph configure",
  .short_help = "product packet-graph configure workers 2 fixture "
                PRODUCT_GRAPH_FIXTURE,
  .function = product_packet_graph_configure_cli,
};

static clib_error_t *
product_packet_graph_policy_fixture_cli (vlib_main_t *vm,
                                         unformat_input_t *input,
                                         vlib_cli_command_t *command)
{
  static const u8 matrix_ip6_a[16] = {
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
  };
  static const u8 matrix_ip6_b[16] = {
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
  };
  u8 *fixture = 0;
  product_l4_policy_rule_t matrix_rules[5];
  product_l4_policy_rule_t l4_rule = {
    .rule_id = UINT64_C (192002),
    .uid = PRODUCT_GRAPH_POLICY_FIXTURE_UID,
    .network_context_id = PRODUCT_GRAPH_POLICY_FIXTURE_CONTEXT,
    .ifindex = PRODUCT_L4_POLICY_IFINDEX_ANY,
    .priority = 100,
    .order = 1,
    .reason_id = UINT32_C (19202),
    .source_port_first = 12345,
    .source_port_last = 12345,
    .destination_port_first = 443,
    .destination_port_last = 443,
    .family = PRODUCT_L4_POLICY_FAMILY_IPV4,
    .protocol = PRODUCT_L4_POLICY_PROTOCOL_TCP,
    .direction = PRODUCT_L4_POLICY_DIRECTION_OUTPUT,
    .source_prefix_length = 32,
    .destination_prefix_length = 32,
    .action = PRODUCT_L4_POLICY_ACTION_DROP,
    .source_address = { 0x0a, 0, 0, 1 },
    .destination_address = { 0x0a, 0, 0, 2 },
  };
  product_packet_graph_gate_entry_t gate_entry = {
    .rule_id = UINT64_C (192001),
    .uid = PRODUCT_GRAPH_POLICY_FIXTURE_UID,
    .network_context_id = PRODUCT_GRAPH_POLICY_FIXTURE_CONTEXT,
    .ifindex = PRODUCT_L4_POLICY_IFINDEX_ANY,
    .source_port_first = PRODUCT_L4_POLICY_PORT_FIRST_ANY,
    .source_port_last = PRODUCT_L4_POLICY_PORT_LAST_ANY,
    .destination_port_first = PRODUCT_L4_POLICY_PORT_FIRST_ANY,
    .destination_port_last = PRODUCT_L4_POLICY_PORT_LAST_ANY,
    .action = PRODUCT_L4_POLICY_ACTION_DROP,
    .reason_id = UINT32_C (19201),
  };
  product_packet_graph_policy_bundle_t bundle = { 0 };
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  (void) command;

  /* Keep the matrix in the same normalized native rule shape as production. */
  matrix_rules[0] = l4_rule;
  matrix_rules[0].rule_id = UINT64_C (192201);
  matrix_rules[0].reason_id = UINT32_C (19221);
  matrix_rules[0].priority = 10;
  matrix_rules[1] = l4_rule;
  matrix_rules[1].rule_id = UINT64_C (192202);
  matrix_rules[1].reason_id = UINT32_C (19222);
  matrix_rules[1].priority = 20;
  matrix_rules[1].protocol = PRODUCT_L4_POLICY_PROTOCOL_UDP;
  matrix_rules[1].source_address[0] = 0xc0;
  matrix_rules[1].source_address[1] = 0x00;
  matrix_rules[1].source_address[2] = 0x02;
  matrix_rules[1].source_address[3] = 0x01;
  matrix_rules[1].destination_address[0] = 0xc6;
  matrix_rules[1].destination_address[1] = 0x33;
  matrix_rules[1].destination_address[2] = 0x64;
  matrix_rules[1].destination_address[3] = 0x02;
  matrix_rules[1].source_port_first = 5353;
  matrix_rules[1].source_port_last = 5353;
  matrix_rules[1].destination_port_first = 53;
  matrix_rules[1].destination_port_last = 53;
  matrix_rules[1].action = PRODUCT_L4_POLICY_ACTION_ALLOW;
  matrix_rules[2] = l4_rule;
  matrix_rules[2].rule_id = UINT64_C (192203);
  matrix_rules[2].reason_id = UINT32_C (19223);
  matrix_rules[2].priority = 30;
  matrix_rules[2].family = PRODUCT_L4_POLICY_FAMILY_IPV6;
  clib_memcpy_fast (matrix_rules[2].source_address, matrix_ip6_a, 16);
  clib_memcpy_fast (matrix_rules[2].destination_address, matrix_ip6_b, 16);
  matrix_rules[2].source_port_first = 2222;
  matrix_rules[2].source_port_last = 2222;
  matrix_rules[2].destination_port_first = 8443;
  matrix_rules[2].destination_port_last = 8443;
  matrix_rules[2].action = PRODUCT_L4_POLICY_ACTION_ALLOW;
  matrix_rules[3] = l4_rule;
  matrix_rules[3].rule_id = UINT64_C (192204);
  matrix_rules[3].reason_id = UINT32_C (19224);
  matrix_rules[3].priority = 40;
  matrix_rules[3].family = PRODUCT_L4_POLICY_FAMILY_IPV6;
  matrix_rules[3].protocol = PRODUCT_L4_POLICY_PROTOCOL_UDP;
  clib_memcpy_fast (matrix_rules[3].source_address, matrix_ip6_a, 16);
  clib_memcpy_fast (matrix_rules[3].destination_address, matrix_ip6_b, 16);
  matrix_rules[3].source_port_first = 60000;
  matrix_rules[3].source_port_last = 60000;
  matrix_rules[3].destination_port_first = 443;
  matrix_rules[3].destination_port_last = 443;
  matrix_rules[3].action = PRODUCT_L4_POLICY_ACTION_ALLOW;
  matrix_rules[4] = l4_rule;
  matrix_rules[4].rule_id = UINT64_C (192205);
  matrix_rules[4].reason_id = UINT32_C (19225);
  matrix_rules[4].priority = 100;
  matrix_rules[4].source_prefix_length = 0;
  matrix_rules[4].destination_prefix_length = 0;
  matrix_rules[4].source_port_first = PRODUCT_L4_POLICY_PORT_FIRST_ANY;
  matrix_rules[4].source_port_last = PRODUCT_L4_POLICY_PORT_LAST_ANY;
  matrix_rules[4].destination_port_first = PRODUCT_L4_POLICY_PORT_FIRST_ANY;
  matrix_rules[4].destination_port_last = PRODUCT_L4_POLICY_PORT_LAST_ANY;
  matrix_rules[4].action = PRODUCT_L4_POLICY_ACTION_ALLOW;
  clib_memset (matrix_rules[4].source_address, 0, 16);
  clib_memset (matrix_rules[4].destination_address, 0, 16);

  if (!unformat (input, "%s", &fixture)
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || !clib_atomic_load_acq_n (&graph->enabled))
    {
      vec_free (fixture);
      return clib_error_return (0, "policy fixture setup rejected");
    }

  bundle.generation = graph->generation;
  if (strcmp ((char *) fixture, "gate-drop") == 0)
    {
      bundle.revision = UINT64_C (19201);
      bundle.snapshot_hash = UINT64_C (0x19201);
      bundle.gate_entries = &gate_entry;
      bundle.gate_entry_count = 1;
    }
  else if (strcmp ((char *) fixture, "l4-drop") == 0
           || strcmp ((char *) fixture, "l4-allow") == 0
           || strcmp ((char *) fixture, "l4-no-match") == 0)
    {
      if (strcmp ((char *) fixture, "l4-allow") == 0)
        l4_rule.action = PRODUCT_L4_POLICY_ACTION_ALLOW;
      if (strcmp ((char *) fixture, "l4-no-match") == 0)
        l4_rule.source_address[3] = 0x99;
      bundle.revision = UINT64_C (19202);
      bundle.snapshot_hash = UINT64_C (0x19202);
      bundle.l4_rules = &l4_rule;
      bundle.l4_rule_count = 1;
    }
  else if (strcmp ((char *) fixture, "empty") == 0)
    {
      /* A valid empty typed view is default-pass, not an invalid envelope. */
      bundle.revision = UINT64_C (19204);
      bundle.snapshot_hash = UINT64_C (0x19204);
    }
  else if (strcmp ((char *) fixture, "l4-matrix") == 0)
    {
      bundle.revision = UINT64_C (19205);
      bundle.snapshot_hash = UINT64_C (0x19205);
      bundle.l4_rules = matrix_rules;
      bundle.l4_rule_count = 5;
    }
  else if (strcmp ((char *) fixture, "clear") == 0)
    {
      product_packet_graph_clear_gate_policy (UINT64_C (19203),
                                              UINT64_C (0x19203));
      bundle.revision = 0;
    }
  else
    {
      vec_free (fixture);
      return clib_error_return (
        0, "expected gate-drop, l4-drop, l4-allow, l4-no-match, empty, "
           "l4-matrix, or clear");
    }
  if (bundle.revision != 0
      && product_packet_graph_publish_policy_bundle (&bundle)
           != PRODUCT_PACKET_OK)
    {
      vec_free (fixture);
      return clib_error_return (0, "typed policy bundle publication rejected");
    }
  vlib_cli_output (vm, "policy.fixture=%s", fixture);
  vec_free (fixture);
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_policy_fixture_command, static) = {
  .path = PRODUCT_GRAPH_RUN_POLICY_FIXTURE_COMMAND,
  .short_help = PRODUCT_GRAPH_RUN_POLICY_FIXTURE_COMMAND " "
                "gate-drop|l4-drop|l4-allow|l4-no-match|empty|l4-matrix|clear",
  .function = product_packet_graph_policy_fixture_cli,
  .is_mp_safe = 1,
};

static clib_error_t *
product_packet_graph_enable_cli (vlib_main_t *vm, unformat_input_t *input,
                                 vlib_cli_command_t *command)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  vlib_thread_main_t *thread_main = vlib_get_thread_main ();
  vlib_frame_queue_main_t *ingress_fqm = vec_elt_at_index (
    thread_main->frame_queue_mains, graph->ingress_frame_queue);
  vlib_frame_queue_main_t *owner_fqm = vec_elt_at_index (
    thread_main->frame_queue_mains, graph->owner_guard_frame_queue);
  u32 worker;
  (void) input;
  (void) command;
  if (!graph->configured || clib_atomic_load_acq_n (&graph->enabled))
    return clib_error_return (0, "graph is not configured or is already enabled");
  if (graph->generation == UINT16_MAX
      || clib_atomic_load_acq_n (&graph->lifecycle_obligations) != 0
      || clib_atomic_load_acq_n (&graph->lifecycle_buffers) != 0
      || product_flow_end_buffer_debt () != 0
      || clib_atomic_load_acq_n (&graph->lifecycle_handoffs) != 0)
    return clib_error_return (0, "graph lifecycle is not clean");
  graph->generation++;
  if (!product_packet_graph_flow_pools_reset (graph))
    return clib_error_return (0, "failed to initialize graph FlowEntry pools");
  /* Enabling starts a new generation; no reader may inherit an older bank. */
  clib_memset (graph->l4_policy_banks, 0, sizeof (graph->l4_policy_banks));
  clib_atomic_store_rel_n (&graph->l4_policy_active_bank, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_bank_readers[0], 0);
  clib_atomic_store_rel_n (&graph->l4_policy_bank_readers[1], 0);
  clib_atomic_store_rel_n (&graph->policy_publish_sequence, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_view_active, 0);
  clib_memset (graph->results, 0, sizeof (graph->results));
  clib_memset (graph->ingress, 0, sizeof (graph->ingress));
  clib_memset (graph->result_ready, 0, sizeof (graph->result_ready));
  clib_memset (graph->reject_buffer_indices, 0,
               sizeof (graph->reject_buffer_indices));
  graph->congestion_fixture = 0;
  clib_atomic_store_rel_n (&graph->completed, 0);
  clib_atomic_store_rel_n (&graph->ingress_vectors, 0);
  clib_atomic_store_rel_n (&graph->admit_vectors, 0);
  clib_atomic_store_rel_n (&graph->guard_vectors, 0);
  clib_atomic_store_rel_n (&graph->policy_vectors, 0);
  clib_atomic_store_rel_n (&graph->terminal_vectors, 0);
  clib_atomic_store_rel_n (&graph->admitted, 0);
  clib_atomic_store_rel_n (&graph->local_packets, 0);
  clib_atomic_store_rel_n (&graph->remote_packets, 0);
  clib_atomic_store_rel_n (&graph->primary_enqueues, 0);
  clib_atomic_store_rel_n (&graph->primary_enqueue_max_per_packet, 0);
  clib_atomic_store_rel_n (&graph->terminal_intents, 0);
  clib_atomic_store_rel_n (&graph->ledger_settlements, 0);
  clib_atomic_store_rel_n (&graph->buffer_returns, 0);
  clib_atomic_store_rel_n (&graph->duplicate_terminals, 0);
  clib_atomic_store_rel_n (&graph->duplicate_settlements, 0);
  clib_atomic_store_rel_n (&graph->lost_buffers, 0);
  clib_atomic_store_rel_n (&graph->congestion_rejections, 0);
  clib_atomic_store_rel_n (&graph->runtime_drop_settlements, 0);
  clib_atomic_store_rel_n (&graph->policy_stage_evaluations, 0);
  clib_atomic_store_rel_n (&graph->policy_gate_evaluations, 0);
  clib_atomic_store_rel_n (&graph->policy_l4_evaluations, 0);
  clib_atomic_store_rel_n (&graph->policy_stage_pass_next, 0);
  clib_atomic_store_rel_n (&graph->policy_stage_drops, 0);
  clib_atomic_store_rel_n (&graph->policy_last_stage, 0);
  clib_atomic_store_rel_n (&graph->policy_last_verdict, 0);
  clib_atomic_store_rel_n (&graph->policy_last_matched, 0);
  clib_atomic_store_rel_n (&graph->policy_last_terminal_preserved, 0);
  clib_atomic_store_rel_n (&graph->policy_last_winner, 0);
  clib_atomic_store_rel_n (&graph->policy_last_revision, 0);
  clib_atomic_store_rel_n (&graph->policy_last_rule_id, 0);
  clib_atomic_store_rel_n (&graph->policy_last_reason_id, 0);
  clib_atomic_store_rel_n (&graph->gate_policy_revision, 0);
  clib_atomic_store_rel_n (&graph->gate_policy_snapshot_hash, 0);
  clib_atomic_store_rel_n (&graph->gate_policy_rule_id, 0);
  clib_atomic_store_rel_n (&graph->gate_policy_subject_uid, UINT32_MAX);
  clib_atomic_store_rel_n (&graph->gate_policy_network_context_id, 0);
  clib_atomic_store_rel_n (&graph->gate_policy_blocked, 0);
  clib_atomic_store_rel_n (&graph->gate_policy_reason_id, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_match_revision, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_match_rule_id, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_winner_rank, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_probes, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_candidate_count, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_no_match_reason,
                           PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_NO_RULE);
  clib_atomic_store_rel_n (&graph->gate_table_last_match_action, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_match_reason_id, 0);
  clib_atomic_store_rel_n (&graph->l4_match_records, 0);
  clib_atomic_store_rel_n (&graph->l4_no_match_records, 0);
  clib_atomic_store_rel_n (&graph->l4_last_match_revision, 0);
  clib_atomic_store_rel_n (&graph->l4_last_match_rule_id, 0);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_revision, 0);
  clib_atomic_store_rel_n (&graph->l4_last_match_uid, 0);
  clib_atomic_store_rel_n (&graph->l4_last_match_network_context, 0);
  clib_atomic_store_rel_n (&graph->l4_last_match_reason_id, 0);
  clib_atomic_store_rel_n (&graph->l4_last_match_verdict, 0);
  clib_atomic_store_rel_n (&graph->l4_last_match_winner, 0);
  clib_atomic_store_rel_n (&graph->l4_last_match_uid_known, 0);
  clib_atomic_store_rel_n (&graph->l4_last_match_device_direction, 0);
  clib_atomic_store_rel_n (&graph->l4_last_match_action, 0);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_result, 0);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_verdict, 0);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_device_direction, 0);
  clib_atomic_store_rel_n (&graph->l4_typed_match_policy_key, 0);
  clib_atomic_store_rel_n (&graph->l4_typed_match_probe_key, 0);
  clib_atomic_store_rel_n (&graph->l4_typed_match_subject_key, 0);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_probe_key, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_view_match_records, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_view_no_match_records, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_revision, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_rule_id, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_winner_rank, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_probes, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_candidate_count, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_no_match_reason, 0);
  clib_atomic_store_rel_n (&graph->policy_drop_records, 0);
  clib_atomic_store_rel_n (&graph->policy_last_drop_revision, 0);
  clib_atomic_store_rel_n (&graph->policy_last_drop_rule_id, 0);
  clib_atomic_store_rel_n (&graph->policy_last_drop_completion_attempts, 0);
  clib_atomic_store_rel_n (&graph->policy_last_drop_uid, 0);
  clib_atomic_store_rel_n (&graph->policy_last_drop_network_context, 0);
  clib_atomic_store_rel_n (&graph->policy_last_drop_reason_id, 0);
  clib_atomic_store_rel_n (&graph->policy_last_drop_verdict, 0);
  clib_atomic_store_rel_n (&graph->policy_last_drop_winner, 0);
  clib_atomic_store_rel_n (&graph->policy_last_drop_uid_known, 0);
  clib_atomic_store_rel_n (&graph->policy_last_drop_device_direction, 0);
  for (worker = 0; worker < PRODUCT_GRAPH_WORKERS; worker++)
    {
      u32 thread = vlib_get_worker_thread_index (worker);
      graph->ingress_fq_head_start[worker] =
        ingress_fqm->vlib_frame_queues[thread]->head;
      graph->ingress_fq_tail_start[worker] =
        ingress_fqm->vlib_frame_queues[thread]->tail;
      graph->owner_fq_head_start[worker] =
        owner_fqm->vlib_frame_queues[thread]->head;
      graph->owner_fq_tail_start[worker] =
        owner_fqm->vlib_frame_queues[thread]->tail;
    }
  clib_atomic_store_rel_n (&graph->enabled, 1);
  clib_atomic_store_rel_n (&graph->accepting, 1);
  vlib_cli_output (vm, "graph.enable=ok");
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_enable_command, static) = {
  .path = "product packet-graph enable",
  .function = product_packet_graph_enable_cli,
};

static clib_error_t *
product_packet_graph_run_fixture_cli (vlib_main_t *vm,
                                      unformat_input_t *input,
                                      vlib_cli_command_t *command)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  vlib_node_runtime_t *ingress_runtime;
  u8 *fixture = 0;
  u32 buffer_indices[PRODUCT_GRAPH_VECTOR_COUNT];
  u16 thread_indices[PRODUCT_GRAPH_VECTOR_COUNT];
  u32 allocated;
  u32 index;
  (void) command;

  if (!unformat (input, "%s", &fixture)
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || strcmp ((char *) fixture, PRODUCT_GRAPH_FIXTURE) != 0
      || !clib_atomic_load_acq_n (&graph->enabled)
      || clib_atomic_load_acq_n (&graph->completed) != 0)
    {
      vec_free (fixture);
      return clib_error_return (0, "fixture run rejected");
    }
  vec_free (fixture);
  allocated = vlib_buffer_alloc (vm, buffer_indices,
                                 PRODUCT_GRAPH_VECTOR_COUNT);
  if (allocated != PRODUCT_GRAPH_VECTOR_COUNT)
    {
      if (allocated != 0)
        vlib_buffer_free (vm, buffer_indices, allocated);
      return clib_error_return (0, "cannot allocate fixture buffers");
    }
  ingress_runtime =
    vlib_node_get_runtime (vm, product_packet_test_ingress_node.index);
  for (index = 0; index < PRODUCT_GRAPH_VECTOR_COUNT; index++)
    {
      vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_indices[index]);
      product_buffer_metadata_t metadata;
      product_ingress_evidence_t *evidence = &graph->ingress[index];
      product_platform_packet_facts_t platform_facts;
      u32 packet_length;

      vlib_buffer_reset (buffer);
      clib_memset (buffer->opaque2, 0, sizeof (buffer->opaque2));
      packet_length = product_materialize_fixture (
        (u8) index, vlib_buffer_get_current (buffer));
      buffer->current_length = packet_length;
      clib_memset (&metadata, 0, sizeof (metadata));
      metadata.origin_obligation_id = UINT64_C (174001) + index;
      metadata.generation = graph->generation;
      product_metadata_store (buffer, &metadata);
      clib_memset (&platform_facts, 0, sizeof (platform_facts));
      platform_facts.availability = PRODUCT_PLATFORM_UID_KNOWN | PRODUCT_PLATFORM_CONTEXT_KNOWN;
      platform_facts.uid = PRODUCT_GRAPH_POLICY_FIXTURE_UID;
      platform_facts.network_context_id = PRODUCT_GRAPH_POLICY_FIXTURE_CONTEXT;
      platform_facts.direction = (index & 1) ?
                                  PRODUCT_PACKET_GRAPH_L4_DIRECTION_INPUT :
                                  PRODUCT_PACKET_GRAPH_L4_DIRECTION_OUTPUT;
      product_packet_graph_set_platform_facts (buffer, &platform_facts,
                                             graph->generation);

      evidence->buffer_index = buffer_indices[index];
      evidence->current_data = (u32) buffer->current_data;
      evidence->length = packet_length;
      evidence->arrival_worker = (u8) (index & 1);
      clib_sha256 (vlib_buffer_get_current (buffer), packet_length,
                   evidence->digest);
      thread_indices[index] =
        (u16) vlib_get_worker_thread_index (evidence->arrival_worker);
      if (vlib_trace_buffer (vm, ingress_runtime, 0, buffer, 1))
        product_add_trace (vm, ingress_runtime, buffer, PRODUCT_TRACE_FIXTURE,
                           metadata.origin_obligation_id);
    }
  clib_atomic_store_rel_n (&graph->buffer_debt, PRODUCT_GRAPH_VECTOR_COUNT);
  clib_atomic_store_rel_n (&graph->obligation_debt,
                           PRODUCT_GRAPH_VECTOR_COUNT);
  if (vlib_buffer_enqueue_to_thread (
        vm, ingress_runtime, graph->ingress_frame_queue, buffer_indices,
        thread_indices, PRODUCT_GRAPH_VECTOR_COUNT, 0)
      != PRODUCT_GRAPH_VECTOR_COUNT)
    return clib_error_return (0, "fixture ingress frame queue is full");

  {
    f64 deadline = vlib_time_now (vm) + 5.0;
    while (!product_all_results_ready (graph)
           && vlib_time_now (vm) < deadline)
      usleep (1000);
  }
  if (!product_all_results_ready (graph))
    {
      vlib_thread_main_t *thread_main = vlib_get_thread_main ();
      vlib_frame_queue_main_t *ingress_fqm = vec_elt_at_index (
        thread_main->frame_queue_mains, graph->ingress_frame_queue);
      return clib_error_return (
        0, "fixture graph completion timed out (ingress=%u admit=%u guard=%u "
           "terminal=%u completed=%u fq-node=%u q1=%llu/%llu/%llu "
           "q2=%llu/%llu/%llu)",
        clib_atomic_load_acq_n (&graph->ingress_vectors),
        clib_atomic_load_acq_n (&graph->admit_vectors),
        clib_atomic_load_acq_n (&graph->guard_vectors),
        clib_atomic_load_acq_n (&graph->terminal_vectors),
        clib_atomic_load_acq_n (&graph->completed), ingress_fqm->node_index,
        (unsigned long long) ingress_fqm->vlib_frame_queues[1]->head,
        (unsigned long long) ingress_fqm->vlib_frame_queues[1]->tail,
        (unsigned long long) vlib_get_main_by_index (1)->check_frame_queues,
        (unsigned long long) ingress_fqm->vlib_frame_queues[2]->head,
        (unsigned long long) ingress_fqm->vlib_frame_queues[2]->tail,
        (unsigned long long) vlib_get_main_by_index (2)->check_frame_queues);
    }

  vlib_cli_output (vm, "fixture.id=%s", PRODUCT_GRAPH_FIXTURE);
  vlib_cli_output (vm, "fixture.workers=2");
  vlib_cli_output (vm, "fixture.vector_count=8");
  for (index = 0; index < PRODUCT_GRAPH_VECTOR_COUNT; index++)
    {
      const product_fixture_result_t *result = &graph->results[index];
      const char *name = product_vector_names[index];
      vlib_cli_output (vm, "vector.%s.family=%u", name, result->family);
      vlib_cli_output (vm, "vector.%s.protocol=%u", name, result->protocol);
      vlib_cli_output (vm, "vector.%s.l3_status=complete", name);
      vlib_cli_output (vm, "vector.%s.l4_status=complete", name);
      vlib_cli_output (vm, "vector.%s.canonical_key=%u/%u/%U:%u-%U:%u",
                       name, result->canonical_key.ip_family,
                       result->canonical_key.protocol,
                       format_hex_bytes_no_wrap,
                       result->canonical_key.address_a, 16,
                       result->canonical_key.transport.ports.a,
                       format_hex_bytes_no_wrap,
                       result->canonical_key.address_b, 16,
                       result->canonical_key.transport.ports.b);
      vlib_cli_output (vm, "vector.%s.expected_owner=%u", name,
                       result->expected_owner);
      vlib_cli_output (vm, "vector.%s.origin_obligation_id=%llu", name,
                       (unsigned long long) result->origin_obligation_id);
      vlib_cli_output (vm, "vector.%s.arrival_worker=%u", name,
                       result->arrival_worker);
      vlib_cli_output (vm, "vector.%s.actual_admit_thread=%u", name,
                       result->admit_thread);
      vlib_cli_output (vm, "vector.%s.actual_guard_thread=%u", name,
                       result->guard_thread);
      vlib_cli_output (vm, "vector.%s.placement=%s", name,
                       result->primary_enqueues == 0 ? "local" : "remote");
      vlib_cli_output (vm, "vector.%s.primary_enqueues=%u", name,
                       result->primary_enqueues);
      vlib_cli_output (vm, "vector.%s.terminal_intents=%u", name,
                       result->terminal_intents);
      vlib_cli_output (vm, "vector.%s.terminal_intent=%s", name,
                       result->terminal_intent
                           == PRODUCT_PACKET_INTENT_PASS_ADAPTER
                         ? "pass-adapter"
                         : result->terminal_intent ==
                               PRODUCT_PACKET_INTENT_DROP_RUNTIME
                             ? "drop-runtime"
                             : "invalid");
      vlib_cli_output (vm, "vector.%s.runtime_drop_reason=%u", name,
                       result->runtime_drop_reason);
      vlib_cli_output (vm, "vector.%s.ledger_settlements=%u", name,
                       result->ledger_settlements);
      vlib_cli_output (vm, "vector.%s.buffer_returns=%u", name,
                       result->buffer_returns);
      vlib_cli_output (vm, "vector.%s.ingress_buffer_index=%u", name,
                       result->ingress_buffer_index);
      vlib_cli_output (vm, "vector.%s.terminal_buffer_index=%u", name,
                       result->terminal_buffer_index);
      vlib_cli_output (vm, "vector.%s.ingress_digest=%U", name,
                       format_hex_bytes_no_wrap, result->ingress_digest, 32);
      vlib_cli_output (vm, "vector.%s.terminal_digest=%U", name,
                       format_hex_bytes_no_wrap, result->terminal_digest, 32);
      vlib_cli_output (vm, "vector.%s.ingress_current_data=%u", name,
                       result->ingress_current_data);
      vlib_cli_output (vm, "vector.%s.terminal_current_data=%u", name,
                       result->terminal_current_data);
      vlib_cli_output (vm, "vector.%s.ingress_length=%u", name,
                       result->ingress_length);
      vlib_cli_output (vm, "vector.%s.terminal_length=%u", name,
                       result->terminal_length);
      vlib_cli_output (vm, "vector.%s.source_address=%U", name,
                       format_hex_bytes_no_wrap,
                       result->facts.source_address, 16);
      vlib_cli_output (vm, "vector.%s.destination_address=%U", name,
                       format_hex_bytes_no_wrap,
                       result->facts.destination_address, 16);
      vlib_cli_output (vm, "vector.%s.source_port=%u", name,
                       result->facts.source_port);
      vlib_cli_output (vm, "vector.%s.destination_port=%u", name,
                       result->facts.destination_port);
      vlib_cli_output (vm, "vector.%s.l3_header_length=%u", name,
                       result->facts.l3_header_length);
      vlib_cli_output (vm, "vector.%s.l4_header_length=%u", name,
                       result->facts.l4_header_length);
      vlib_cli_output (vm, "vector.%s.packet_length=%u", name,
                       result->facts.packet_length);
    }
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_run_fixture_command, static) = {
  .path = PRODUCT_GRAPH_RUN_FIXTURE_COMMAND,
  .short_help = PRODUCT_GRAPH_RUN_FIXTURE_HELP PRODUCT_GRAPH_FIXTURE,
  .function = product_packet_graph_run_fixture_cli,
  .is_mp_safe = 1,
};

static int
product_congestion_results_ready (const product_packet_graph_main_t *graph)
{
  return clib_atomic_load_acq_n (&graph->result_ready[0].value)
         && clib_atomic_load_acq_n (&graph->result_ready[1].value);
}

static clib_error_t *
product_packet_graph_run_congestion_fixture_cli (
  vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *command)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  vlib_node_runtime_t *ingress_runtime;
  u8 *fixture = 0;
  u32 buffer_indices[2];
  u16 thread_indices[2];
  u32 allocated;
  u32 index;
  (void) command;

  if (!unformat (input, "%s", &fixture)
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || strcmp ((char *) fixture, PRODUCT_GRAPH_CONGESTION_FIXTURE) != 0
      || !clib_atomic_load_acq_n (&graph->enabled)
      || clib_atomic_load_acq_n (&graph->completed) != 0)
    {
      vec_free (fixture);
      return clib_error_return (0, "congestion fixture run rejected");
    }
  vec_free (fixture);
  graph->congestion_fixture = 1;
  allocated = vlib_buffer_alloc (vm, buffer_indices, 2);
  if (allocated != 2)
    {
      if (allocated != 0)
        vlib_buffer_free (vm, buffer_indices, allocated);
      return clib_error_return (0, "cannot allocate congestion buffers");
    }

  ingress_runtime =
    vlib_node_get_runtime (vm, product_packet_test_ingress_node.index);
  for (index = 0; index < 2; index++)
    {
      vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_indices[index]);
      product_buffer_metadata_t metadata;
      product_packet_ingress_t ingress;
      product_packet_lease_t lease;
      product_worker_layout_t layout = {
        .worker_count = PRODUCT_GRAPH_WORKERS,
        .hash_seed = PRODUCT_GRAPH_HASH_SEED,
      };
      product_ingress_evidence_t *evidence = &graph->ingress[index];
      u32 packet_length;
      u16 arrival_worker;

      vlib_buffer_reset (buffer);
      clib_memset (buffer->opaque2, 0, sizeof (buffer->opaque2));
      packet_length = product_ipv4_fixture (
        vlib_buffer_get_current (buffer), index == 0 ? 6 : 17,
        index == 0 ? 0x0a000011 : 0xc0000211,
        index == 0 ? 31001 : 32001,
        index == 0 ? 0x0a000012 : 0xc6336412,
        index == 0 ? 443 : 53);
      buffer->current_length = packet_length;

      clib_memset (&ingress, 0, sizeof (ingress));
      ingress.data = vlib_buffer_get_current (buffer);
      ingress.length = packet_length;
      ingress.current_worker = 0;
      ingress.origin_obligation_id = UINT64_C (174001) + index;
      if (product_packet_admit (&layout, &ingress, &lease)
          != PRODUCT_PACKET_OK)
        {
          vlib_buffer_free (vm, buffer_indices, 2);
          return clib_error_return (0, "congestion vector admission failed");
        }
      arrival_worker = index == 0 ? (u16) (lease.assignment.execution_owner ^ 1)
                                  : lease.assignment.execution_owner;

      clib_memset (&metadata, 0, sizeof (metadata));
      metadata.origin_obligation_id = UINT64_C (174001) + index;
      metadata.generation = graph->generation;
      product_metadata_store (buffer, &metadata);
      evidence->buffer_index = buffer_indices[index];
      evidence->current_data = (u32) buffer->current_data;
      evidence->length = packet_length;
      evidence->arrival_worker = (u8) arrival_worker;
      clib_sha256 (vlib_buffer_get_current (buffer), packet_length,
                   evidence->digest);
      thread_indices[index] =
        (u16) vlib_get_worker_thread_index (arrival_worker);
    }

  clib_atomic_store_rel_n (&graph->buffer_debt, 2);
  clib_atomic_store_rel_n (&graph->obligation_debt, 2);
  if (vlib_buffer_enqueue_to_thread (
        vm, ingress_runtime, graph->ingress_frame_queue, buffer_indices,
        thread_indices, 2, 0)
      != 2)
    return clib_error_return (0, "congestion ingress frame queue is full");

  {
    f64 deadline = vlib_time_now (vm) + 1.0;
    while (!product_congestion_results_ready (graph)
           && vlib_time_now (vm) < deadline)
      usleep (1000);
  }
  if (!product_congestion_results_ready (graph))
    return clib_error_return (0, "congestion fixture completion timed out");

  vlib_cli_output (vm, "fixture.id=%s", PRODUCT_GRAPH_CONGESTION_FIXTURE);
  vlib_cli_output (vm, "fixture.vector_count=2");
  for (index = 0; index < 2; index++)
    {
      const product_fixture_result_t *result = &graph->results[index];
      const char *name = index == 0 ? "primary-credit-exhausted"
                                    : "corrective-queue-full";
      const char *reason;
      if (result->runtime_drop_reason
          == PRODUCT_PACKET_DROP_PRIMARY_HANDOFF_CONGESTION)
        reason = "primary-handoff-congestion";
      else if (result->runtime_drop_reason
               == PRODUCT_PACKET_DROP_CORRECTIVE_HANDOFF_CONGESTION)
        reason = "corrective-handoff-congestion";
      else
        return clib_error_return (0,
                                  "congestion result has no drop reason");
      if (result->terminal_intent != PRODUCT_PACKET_INTENT_DROP_RUNTIME)
        return clib_error_return (0,
                                  "congestion result is not runtime-drop");
      vlib_cli_output (vm, "vector.%s.handoff_stage=%s", name,
                       index == 0 ? "primary" : "corrective");
      vlib_cli_output (vm, "vector.%s.injected_fault=%s", name,
                       index == 0 ? "credit-exhausted" : "queue-full");
      vlib_cli_output (vm, "vector.%s.runtime_drop_reason=%s", name,
                       reason);
      vlib_cli_output (vm, "vector.%s.terminal_intent=%s", name,
                       result->terminal_intent
                           == PRODUCT_PACKET_INTENT_DROP_RUNTIME
                         ? "drop-runtime"
                         : "invalid");
      vlib_cli_output (vm, "vector.%s.terminal_intents=%u", name,
                       result->terminal_intents);
      vlib_cli_output (vm, "vector.%s.ledger_settlements=%u", name,
                       result->ledger_settlements);
      vlib_cli_output (vm, "vector.%s.buffer_returns=%u", name,
                       result->buffer_returns);
      vlib_cli_output (vm, "vector.%s.ingress_buffer_index=%u", name,
                       result->ingress_buffer_index);
      vlib_cli_output (vm, "vector.%s.reject_buffer_index=%u", name,
                       graph->reject_buffer_indices[index]);
      vlib_cli_output (vm, "vector.%s.terminal_buffer_index=%u", name,
                       result->terminal_buffer_index);
      vlib_cli_output (vm, "vector.%s.ingress_digest=%U", name,
                       format_hex_bytes_no_wrap, result->ingress_digest, 32);
      vlib_cli_output (vm, "vector.%s.terminal_digest=%U", name,
                       format_hex_bytes_no_wrap, result->terminal_digest, 32);
    }
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_run_congestion_fixture_command,
                  static) = {
  .path = PRODUCT_GRAPH_RUN_CONGESTION_FIXTURE_COMMAND,
  .short_help = PRODUCT_GRAPH_RUN_CONGESTION_FIXTURE_COMMAND " "
                PRODUCT_GRAPH_CONGESTION_FIXTURE,
  .function = product_packet_graph_run_congestion_fixture_cli,
  .is_mp_safe = 1,
};

static clib_error_t *product_packet_graph_disable_cli (
  vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *command);
static u64 product_packet_graph_frame_queue_occupancy (u32 frame_queue);

static int
product_lifecycle_enqueue_two_outstanding (vlib_main_t *vm)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  vlib_node_runtime_t *ingress_runtime =
    vlib_node_get_runtime (vm, product_packet_test_ingress_node.index);
  u32 buffers[2];
  u16 threads[2];
  u8 fragment_payload[32];
  product_buffer_metadata_t metadata;
  u32 allocated = vlib_buffer_alloc (vm, buffers, 2);
  if (allocated != 2)
    {
      if (allocated)
        vlib_buffer_free (vm, buffers, allocated);
      return 0;
    }
  product_fragment_payload (fragment_payload, 40001);
  for (u32 index = 0; index < 2; index++)
    {
      vlib_buffer_t *buffer = vlib_get_buffer (vm, buffers[index]);
      vlib_buffer_reset (buffer);
      clib_memset (buffer->opaque2, 0, sizeof (buffer->opaque2));
      if (index == 0)
        buffer->current_length = product_fragment_materialize_ip4 (
          vlib_buffer_get_current (buffer), 0x5f01, 0, 1,
          fragment_payload, 8);
      else
        buffer->current_length = product_ipv4_fixture (
          vlib_buffer_get_current (buffer), 17, 0xc0000231, 33001,
          0xc6336432, 53);
      vnet_buffer (buffer)->sw_if_index[VLIB_RX] = 0;
      vnet_buffer (buffer)->sw_if_index[VLIB_TX] = ~0;
      clib_memset (&metadata, 0, sizeof (metadata));
      metadata.origin_obligation_id = UINT64_C (1759001) + index;
      metadata.generation = graph->generation;
      product_metadata_store (buffer, &metadata);
      threads[index] = (u16) vlib_get_worker_thread_index (index);
      if (index == 1)
        {
          product_packet_ingress_t ingress;
          product_packet_lease_t lease;
          product_worker_layout_t layout = {
            .worker_count = PRODUCT_GRAPH_WORKERS,
            .hash_seed = PRODUCT_GRAPH_HASH_SEED,
          };
          clib_memset (&ingress, 0, sizeof (ingress));
          ingress.data = vlib_buffer_get_current (buffer);
          ingress.length = buffer->current_length;
          ingress.current_worker = 0;
          ingress.origin_obligation_id = metadata.origin_obligation_id;
          if (product_packet_admit (&layout, &ingress, &lease)
              != PRODUCT_PACKET_OK)
            return 0;
          threads[index] = (u16) vlib_get_worker_thread_index (
            (u16) (lease.assignment.execution_owner ^ 1));
        }
    }
  return vlib_buffer_enqueue_to_thread (
           vm, ingress_runtime, graph->ingress_frame_queue, buffers, threads,
           2, 0)
         == 2;
}

static int
product_lifecycle_enqueue_stale_events (vlib_main_t *vm, u16 generation)
{
  u32 buffers[2];
  u32 allocated = vlib_buffer_alloc (vm, buffers, 2);
  if (allocated != 2)
    {
      if (allocated)
        vlib_buffer_free (vm, buffers, allocated);
      return 0;
    }
  {
    vlib_buffer_t *buffer = vlib_get_buffer (vm, buffers[0]);
    product_packet_ingress_t ingress;
    product_packet_lease_t lease;
    product_buffer_metadata_t metadata;
    product_worker_layout_t layout = {
      .worker_count = PRODUCT_GRAPH_WORKERS,
      .hash_seed = PRODUCT_GRAPH_HASH_SEED,
    };
    vlib_buffer_reset (buffer);
    buffer->current_length = product_ipv4_fixture (
      vlib_buffer_get_current (buffer), 17, 0xc0000241, 34001,
      0xc6336442, 53);
    clib_memset (&ingress, 0, sizeof (ingress));
    ingress.data = vlib_buffer_get_current (buffer);
    ingress.length = buffer->current_length;
    ingress.current_worker = 0;
    ingress.origin_obligation_id = UINT64_C (1759001);
    if (product_packet_admit (&layout, &ingress, &lease)
        != PRODUCT_PACKET_OK)
      return 0;
    product_metadata_from_lease (&metadata, &lease, generation, buffer);
    product_metadata_store (buffer, &metadata);
  }
  {
    vlib_buffer_t *buffer = vlib_get_buffer (vm, buffers[1]);
    product_fragment_metadata_t metadata;
    vlib_buffer_reset (buffer);
    buffer->current_length = 1;
    clib_memset (&metadata, 0, sizeof (metadata));
    metadata.obligation_ids[0] = UINT64_C (1759002);
    metadata.final_owner = PRODUCT_FRAGMENT_FINAL_OWNER_UNKNOWN;
    metadata.fragment_worker = 0;
    metadata.obligation_count = 1;
    metadata.family = 4;
    metadata.fixture_vector = 0xff;
    metadata.flags = PRODUCT_FRAGMENT_META_FRAGMENT;
    metadata.magic = PRODUCT_FRAGMENT_METADATA_MAGIC;
    metadata.custom_error = PRODUCT_FRAGMENT_ERROR_TIMEOUT;
    metadata.generation = generation;
    product_fragment_metadata_store (buffer, &metadata);
  }
  for (u32 index = 0; index < 2; index++)
    {
      u32 node_index = index == 0 ? product_packet_terminal_node.index
                                  : product_packet_fragment_error_node.index;
      vlib_frame_t *frame = vlib_get_frame_to_node (vm, node_index);
      u32 *to = vlib_frame_vector_args (frame);
      to[0] = buffers[index];
      frame->n_vectors = 1;
      vlib_put_frame_to_node (vm, node_index, frame);
    }
  return 1;
}

static clib_error_t *
product_packet_graph_run_lifecycle_fixture_cli (
  vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *command)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u8 *fixture = 0;
  u32 terminal_start;
  u32 settlement_start;
  u32 returns_start;
  u32 stale_start;
  u16 stale_generation;
  f64 drain_start;
  f64 drain_end;
  clib_error_t *error;
  (void) command;
  if (!unformat (input, "%s", &fixture)
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || strcmp ((char *) fixture, PRODUCT_GRAPH_LIFECYCLE_FIXTURE) != 0
      || clib_atomic_load_acq_n (&graph->enabled))
    {
      vec_free (fixture);
      return clib_error_return (0, "lifecycle fixture run rejected");
    }
  vec_free (fixture);
  terminal_start =
    clib_atomic_load_acq_n (&graph->lifecycle_terminal_intents);
  settlement_start =
    clib_atomic_load_acq_n (&graph->lifecycle_settlements);
  returns_start = clib_atomic_load_acq_n (&graph->lifecycle_returns);
  stale_start = clib_atomic_load_acq_n (&graph->stale_events_rejected);
  graph->lifecycle_fixture = 1;

  error = product_packet_graph_enable_cli (vm, 0, 0);
  if (error)
    return error;
  stale_generation = graph->generation;
  if (!product_lifecycle_enqueue_two_outstanding (vm))
    return clib_error_return (0, "lifecycle outstanding injection failed");
  {
    f64 deadline = vlib_time_now (vm) + 0.05;
    while ((clib_atomic_load_acq_n (&graph->lifecycle_obligations) != 2
            || clib_atomic_load_acq_n (&graph->lifecycle_handoffs) != 1)
           && vlib_time_now (vm) < deadline)
      vlib_process_suspend (vm, 0.001);
  }
  if (clib_atomic_load_acq_n (&graph->lifecycle_obligations) != 2
      || clib_atomic_load_acq_n (&graph->lifecycle_handoffs) != 1)
    return clib_error_return (0, "lifecycle outstanding state not reached");
  drain_start = vlib_time_now (vm);
  error = product_packet_graph_disable_cli (vm, 0, 0);
  drain_end = vlib_time_now (vm);
  if (error)
    return error;

  graph->configured = 1;
  error = product_packet_graph_enable_cli (vm, 0, 0);
  if (error)
    return error;
  if (!product_lifecycle_enqueue_stale_events (vm, stale_generation))
    return clib_error_return (0, "lifecycle stale injection failed");
  {
    f64 deadline = vlib_time_now (vm) + 1.0;
    while (clib_atomic_load_acq_n (&graph->stale_events_rejected)
               - stale_start
             != 2
           && vlib_time_now (vm) < deadline)
      vlib_process_suspend (vm, 0.001);
  }
  if (clib_atomic_load_acq_n (&graph->stale_events_rejected) - stale_start
      != 2)
    return clib_error_return (0, "stale events were not fenced");
  error = product_packet_graph_disable_cli (vm, 0, 0);
  if (error)
    return error;

  graph->configured = 1;
  error = product_packet_graph_enable_cli (vm, 0, 0);
  if (error)
    return error;
  error = product_packet_graph_disable_cli (vm, 0, 0);
  if (error)
    return error;
  graph->lifecycle_fixture = 0;

  vlib_cli_output (vm, "fixture.id=%s", PRODUCT_GRAPH_LIFECYCLE_FIXTURE);
  vlib_cli_output (vm, "fixture.disable.admission_quiesced=1");
  vlib_cli_output (vm, "fixture.drain.fragment_outstanding=1");
  vlib_cli_output (vm, "fixture.drain.handoff_outstanding=1");
  vlib_cli_output (vm, "fixture.drain.input_obligations=2");
  vlib_cli_output (
    vm, "fixture.drain.terminal_intents=%u",
    clib_atomic_load_acq_n (&graph->lifecycle_terminal_intents)
      - terminal_start);
  vlib_cli_output (
    vm, "fixture.drain.ledger_settlements=%u",
    clib_atomic_load_acq_n (&graph->lifecycle_settlements)
      - settlement_start);
  vlib_cli_output (
    vm, "fixture.drain.buffer_returns=%u",
    clib_atomic_load_acq_n (&graph->lifecycle_returns) - returns_start);
  vlib_cli_output (vm, "fixture.drain.outstanding_obligations=0");
  vlib_cli_output (vm, "fixture.drain.elapsed_ms=%u",
                   (u32) ((drain_end - drain_start) * 1000.0));
  vlib_cli_output (vm,
                   "fixture.generation.stale_completion_after_reenable=1");
  vlib_cli_output (vm,
                   "fixture.generation.stale_timeout_after_reenable=1");
  vlib_cli_output (
    vm, "fixture.generation.stale_events_rejected=%u",
    clib_atomic_load_acq_n (&graph->stale_events_rejected) - stale_start);
  vlib_cli_output (
    vm, "fixture.generation.cross_generation_admissions=%u",
    clib_atomic_load_acq_n (&graph->cross_generation_admissions));
  vlib_cli_output (vm, "fixture.generation.late_verdicts=%u",
                   clib_atomic_load_acq_n (&graph->late_verdicts));
  vlib_cli_output (vm, "fixture.repeat.enable_disable_cycles=3");
  vlib_cli_output (vm, "fixture.fragment_contexts=0");
  vlib_cli_output (
    vm, "fixture.ingress_fqm_occupancy=%llu",
    (unsigned long long) product_packet_graph_frame_queue_occupancy (
      graph->ingress_frame_queue));
  vlib_cli_output (
    vm, "fixture.owner_fqm_occupancy=%llu",
    (unsigned long long) product_packet_graph_frame_queue_occupancy (
      graph->owner_guard_frame_queue));
  vlib_cli_output (vm, "fixture.fragment_context_debt=0");
  vlib_cli_output (vm, "fixture.handoff_credit_debt=0");
  vlib_cli_output (vm, "fixture.obligation_debt=0");
  vlib_cli_output (vm, "fixture.buffer_debt=0");
  vlib_cli_output (vm, "fixture.duplicate_settlements=0");
  vlib_cli_output (vm, "fixture.lost_buffers=0");
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_run_lifecycle_fixture_command,
                  static) = {
  .path = PRODUCT_GRAPH_RUN_LIFECYCLE_FIXTURE_COMMAND,
  .short_help = PRODUCT_GRAPH_RUN_LIFECYCLE_FIXTURE_COMMAND " "
                PRODUCT_GRAPH_LIFECYCLE_FIXTURE,
  .function = product_packet_graph_run_lifecycle_fixture_cli,
  .is_mp_safe = 1,
};

static clib_error_t *
product_packet_graph_show_cli (vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *command)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  vlib_thread_main_t *thread_main = vlib_get_thread_main ();
  vlib_frame_queue_main_t *ingress_fqm = vec_elt_at_index (
    thread_main->frame_queue_mains, graph->ingress_frame_queue);
  vlib_frame_queue_main_t *owner_fqm = vec_elt_at_index (
    thread_main->frame_queue_mains, graph->owner_guard_frame_queue);
  u64 ingress_head_delta = 0;
  u64 ingress_tail_delta = 0;
  u64 owner_head_delta = 0;
  u64 owner_tail_delta = 0;
  product_packet_graph_gate_status_t gate_status;
  product_packet_graph_l4_status_t l4_status;
  product_packet_graph_flow_status_t flow_status;
  u32 worker;
  (void) input;
  (void) command;
  product_packet_graph_gate_status (&gate_status);
  product_packet_graph_l4_status (&l4_status);
  product_packet_graph_flow_status (&flow_status);
  for (worker = 0; worker < PRODUCT_GRAPH_WORKERS; worker++)
    {
      u32 thread = vlib_get_worker_thread_index (worker);
      ingress_head_delta += ingress_fqm->vlib_frame_queues[thread]->head
                            - graph->ingress_fq_head_start[worker];
      ingress_tail_delta += ingress_fqm->vlib_frame_queues[thread]->tail
                            - graph->ingress_fq_tail_start[worker];
      owner_head_delta += owner_fqm->vlib_frame_queues[thread]->head
                          - graph->owner_fq_head_start[worker];
      owner_tail_delta += owner_fqm->vlib_frame_queues[thread]->tail
                          - graph->owner_fq_tail_start[worker];
    }
  vlib_cli_output (vm, "graph.workers=2");
  vlib_cli_output (vm, "graph.enabled=%u",
                   clib_atomic_load_acq_n (&graph->enabled));
  vlib_cli_output (vm, "graph.generation=%llu", (unsigned long long)graph->generation);
  vlib_cli_output (vm, "graph.fragment_context_debt=%u",
                   clib_atomic_load_acq_n (&graph->lifecycle_obligations));
  vlib_cli_output (vm, "graph.handoff_credit_debt=%u",
                   clib_atomic_load_acq_n (&graph->lifecycle_handoffs));
  vlib_cli_output (vm, "graph.obligation_debt=%u",
                   clib_atomic_load_acq_n (&graph->lifecycle_obligations));
  vlib_cli_output (vm, "graph.buffer_debt=%u",
                   clib_atomic_load_acq_n (&graph->lifecycle_buffers));
  vlib_cli_output (vm, "graph.admitted=%u",
                   clib_atomic_load_acq_n (&graph->admitted));
  vlib_cli_output (vm, "graph.local_packets=%u",
                   clib_atomic_load_acq_n (&graph->local_packets));
  vlib_cli_output (vm, "graph.remote_packets=%u",
                   clib_atomic_load_acq_n (&graph->remote_packets));
  vlib_cli_output (vm, "graph.policy_vectors=%u",
                   clib_atomic_load_acq_n (&graph->policy_vectors));
  vlib_cli_output (vm, "graph.primary_enqueues=%u",
                   clib_atomic_load_acq_n (&graph->primary_enqueues));
  vlib_cli_output (vm, "graph.primary_enqueue_max_per_packet=%u",
                   clib_atomic_load_acq_n (
                     &graph->primary_enqueue_max_per_packet));
  vlib_cli_output (vm, "graph.terminal_intents=%u",
                   clib_atomic_load_acq_n (&graph->terminal_intents));
  vlib_cli_output (vm, "graph.ledger_settlements=%u",
                   clib_atomic_load_acq_n (&graph->ledger_settlements));
  vlib_cli_output (vm, "graph.buffer_returns=%u",
                   clib_atomic_load_acq_n (&graph->buffer_returns));
  vlib_cli_output (vm, "graph.duplicate_terminals=%u",
                   clib_atomic_load_acq_n (&graph->duplicate_terminals));
  vlib_cli_output (vm, "graph.duplicate_settlements=%u",
                   clib_atomic_load_acq_n (&graph->duplicate_settlements));
  vlib_cli_output (vm, "graph.lost_buffers=%u",
                   clib_atomic_load_acq_n (&graph->lost_buffers));
  vlib_cli_output (vm, "graph.congestion_rejections=%u",
                   clib_atomic_load_acq_n (&graph->congestion_rejections));
  vlib_cli_output (
    vm, "graph.runtime_drop_settlements=%u",
    clib_atomic_load_acq_n (&graph->runtime_drop_settlements));
  vlib_cli_output (
    vm, "graph.policy_stage_evaluations=%llu",
    (unsigned long long) clib_atomic_load_acq_n (
      &graph->policy_stage_evaluations));
  vlib_cli_output (
    vm, "graph.policy_gate_evaluations=%llu",
    (unsigned long long) clib_atomic_load_acq_n (&graph->policy_gate_evaluations));
  vlib_cli_output (
    vm, "graph.policy_l4_evaluations=%llu",
    (unsigned long long) clib_atomic_load_acq_n (&graph->policy_l4_evaluations));
  vlib_cli_output (
    vm, "graph.policy_stage_pass_next=%llu",
    (unsigned long long) clib_atomic_load_acq_n (&graph->policy_stage_pass_next));
  vlib_cli_output (
    vm, "graph.policy_stage_drops=%llu",
    (unsigned long long) clib_atomic_load_acq_n (&graph->policy_stage_drops));
  vlib_cli_output (
    vm, "graph.policy_last_stage=%u",
    clib_atomic_load_acq_n (&graph->policy_last_stage));
  vlib_cli_output (
    vm, "graph.policy_last_verdict=%u",
    clib_atomic_load_acq_n (&graph->policy_last_verdict));
  vlib_cli_output (
    vm, "graph.policy_last_matched=%u",
    clib_atomic_load_acq_n (&graph->policy_last_matched));
  vlib_cli_output (
    vm, "graph.policy_last_terminal_preserved=%u",
    clib_atomic_load_acq_n (&graph->policy_last_terminal_preserved));
  vlib_cli_output (
    vm, "graph.policy_last_winner=%u",
    clib_atomic_load_acq_n (&graph->policy_last_winner));
  vlib_cli_output (
    vm, "graph.policy_last_revision=%llu",
    (unsigned long long) clib_atomic_load_acq_n (&graph->policy_last_revision));
  vlib_cli_output (
    vm, "graph.policy_last_rule_id=%llu",
    (unsigned long long) clib_atomic_load_acq_n (&graph->policy_last_rule_id));
  vlib_cli_output (
    vm, "graph.policy_last_reason_id=%u",
    clib_atomic_load_acq_n (&graph->policy_last_reason_id));
  vlib_cli_output (
    vm, "graph.policy_drop_records=%llu",
    (unsigned long long) clib_atomic_load_acq_n (&graph->policy_drop_records));
  vlib_cli_output (
    vm, "graph.policy_last_drop_completion_attempts=%llu",
    (unsigned long long) clib_atomic_load_acq_n (
      &graph->policy_last_drop_completion_attempts));
  vlib_cli_output (
    vm, "graph.policy_last_drop_reason_id=%u",
    clib_atomic_load_acq_n (&graph->policy_last_drop_reason_id));
  vlib_cli_output (
    vm, "graph.policy_last_drop_winner=%u",
    clib_atomic_load_acq_n (&graph->policy_last_drop_winner));
  vlib_cli_output (vm, "graph.gate_table_active_generation=%llu",
                   (unsigned long long) gate_status.active_generation);
  vlib_cli_output (vm, "graph.gate_table_active_revision=%llu",
                   (unsigned long long) gate_status.active_revision);
  vlib_cli_output (vm, "graph.gate_table_snapshot_hash=%llu",
                   (unsigned long long) gate_status.snapshot_hash);
  vlib_cli_output (vm, "graph.gate_table_active_entry_count=%u",
                   gate_status.active_entry_count);
  vlib_cli_output (vm, "graph.gate_table_max_probes=%u",
                   gate_status.max_probes);
  vlib_cli_output (vm, "graph.gate_table_last_match_revision=%llu",
                   (unsigned long long) gate_status.last_match_revision);
  vlib_cli_output (vm, "graph.gate_table_last_match_rule_id=%llu",
                   (unsigned long long) gate_status.last_match_rule_id);
  vlib_cli_output (vm, "graph.gate_table_last_winner_rank=%u",
                   gate_status.last_match_winner_rank);
  vlib_cli_output (vm, "graph.gate_table_last_probes=%u",
                   gate_status.last_match_probes);
  vlib_cli_output (vm, "graph.gate_table_last_candidate_count=%u",
                   gate_status.last_match_candidate_count);
  vlib_cli_output (vm, "graph.gate_table_last_no_match_reason=%u",
                   gate_status.last_no_match_reason);
  vlib_cli_output (vm, "graph.gate_table_last_match_action=%u",
                   gate_status.last_match_action);
  vlib_cli_output (vm, "graph.gate_table_last_match_reason_id=%u",
                   gate_status.last_match_reason_id);
  vlib_cli_output (
    vm, "graph.l4_match_records=%llu",
    (unsigned long long) clib_atomic_load_acq_n (&graph->l4_match_records));
  vlib_cli_output (
    vm, "graph.l4_no_match_records=%llu",
    (unsigned long long) clib_atomic_load_acq_n (&graph->l4_no_match_records));
  vlib_cli_output (vm, "graph.l4_policy_view_active=%u",
                   l4_status.view_active);
  vlib_cli_output (vm, "graph.l4_policy_view_generation=%llu",
                   (unsigned long long) l4_status.active_generation);
  vlib_cli_output (vm, "graph.l4_policy_view_revision=%llu",
                   (unsigned long long) l4_status.active_revision);
  vlib_cli_output (vm, "graph.l4_policy_view_rule_count=%u",
                   l4_status.view_rule_count);
  vlib_cli_output (vm, "graph.l4_policy_view_max_probes=%u",
                   l4_status.view_max_probes);
  vlib_cli_output (vm, "graph.l4_policy_view_match_records=%llu",
                   (unsigned long long) clib_atomic_load_acq_n (
                     &graph->l4_policy_view_match_records));
  vlib_cli_output (vm, "graph.l4_policy_view_no_match_records=%llu",
                   (unsigned long long) clib_atomic_load_acq_n (
                     &graph->l4_policy_view_no_match_records));
  vlib_cli_output (vm, "graph.l4_policy_view_last_winner_rank=%u",
                   l4_status.last_match_winner_rank);
  vlib_cli_output (vm, "graph.l4_policy_view_last_rule_id=%llu",
                   (unsigned long long) l4_status.last_match_rule_id);
  vlib_cli_output (vm, "graph.l4_policy_view_last_probes=%u",
                   l4_status.last_match_probes);
  vlib_cli_output (vm, "graph.l4_policy_view_last_candidate_count=%u",
                   l4_status.last_match_candidate_count);
  vlib_cli_output (vm, "graph.l4_policy_view_last_no_match_reason=%u",
                   l4_status.last_no_match_reason);
  vlib_cli_output (vm, "graph.l4_policy_view_typed_match_policy_key=%llu",
                   (unsigned long long) l4_status.typed_match_policy_key);
  vlib_cli_output (vm, "graph.l4_policy_view_typed_match_probe_key=%llu",
                   (unsigned long long) l4_status.typed_match_probe_key);
  vlib_cli_output (vm, "graph.l4_policy_view_last_evaluation_probe_key=%llu",
                   (unsigned long long) l4_status.last_evaluation_probe_key);
  vlib_cli_output (vm, "graph.flow_worker_count=%u",
                   flow_status.worker_count);
  vlib_cli_output (vm, "graph.flow_max_entries_per_worker=%u",
                   flow_status.max_entries_per_worker);
  vlib_cli_output (vm, "graph.flow_active_generation=%llu",
                   (unsigned long long) flow_status.active_generation);
  vlib_cli_output (vm, "graph.flow_active_revision=%llu",
                   (unsigned long long) flow_status.active_revision);
  vlib_cli_output (vm, "graph.flow_active_snapshot_hash=%llu",
                   (unsigned long long) flow_status.active_snapshot_hash);
  vlib_cli_output (vm, "graph.flow_active_entries=%u",
                   flow_status.active_entries);
  vlib_cli_output (vm, "graph.flow_allocation_count=%llu",
                   (unsigned long long) flow_status.allocation_count);
  vlib_cli_output (vm, "graph.flow_reuse_count=%llu",
                   (unsigned long long) flow_status.reuse_count);
  vlib_cli_output (vm, "graph.flow_early_drop_count=%llu",
                   (unsigned long long) flow_status.early_drop_count);
  vlib_cli_output (vm, "graph.flow_wrong_owner_count=%llu",
                   (unsigned long long) flow_status.wrong_owner_count);
  vlib_cli_output (vm, "graph.flow_capacity_rejection_count=%llu",
                   (unsigned long long) flow_status.capacity_rejection_count);
  vlib_cli_output (vm, "graph.flow_revision_invalidation_count=%llu",
                   (unsigned long long) flow_status.revision_invalidation_count);
  vlib_cli_output (vm, "graph.flow_revision_mismatch_count=%llu",
                   (unsigned long long) flow_status.revision_mismatch_count);
  vlib_cli_output (vm, "graph.flow_unavailable_count=%llu",
                   (unsigned long long) flow_status.unavailable_count);
  vlib_cli_output (vm, "graph.flow_pass_next_count=%llu",
                   (unsigned long long) flow_status.pass_next_count);
  vlib_cli_output (vm, "graph.flow_drop_count=%llu",
                   (unsigned long long) flow_status.drop_count);
  vlib_cli_output (vm, "graph.flow_flush_count=%llu",
                   (unsigned long long) flow_status.flush_count);
  vlib_cli_output (vm, "graph.ingress_frame_queue=%u",
                   graph->ingress_frame_queue);
  vlib_cli_output (vm, "graph.ingress_fq_node=%v",
                   vlib_get_node (vm, ingress_fqm->node_index)->name);
  vlib_cli_output (vm, "graph.ingress_fq_enqueued_frames=%llu",
                   (unsigned long long) ingress_tail_delta);
  vlib_cli_output (vm, "graph.ingress_fq_dequeued_frames=%llu",
                   (unsigned long long) ingress_head_delta);
  vlib_cli_output (vm, "graph.owner_guard_frame_queue=%u",
                   graph->owner_guard_frame_queue);
  vlib_cli_output (vm, "graph.owner_guard_fq_node=%v",
                   vlib_get_node (vm, owner_fqm->node_index)->name);
  vlib_cli_output (vm, "graph.owner_guard_fq_enqueued_frames=%llu",
                   (unsigned long long) owner_tail_delta);
  vlib_cli_output (vm, "graph.owner_guard_fq_dequeued_frames=%llu",
                   (unsigned long long) owner_head_delta);
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_show_command, static) = {
  .path = "show product packet-graph",
  .function = product_packet_graph_show_cli,
};

static product_packet_result_t
product_packet_graph_association_prepare_lease (
  const u8 *packet, u32 packet_length, const product_platform_packet_facts_t *platform,
  u64 origin_obligation_id, product_packet_lease_t *lease)
{
  product_packet_ingress_t ingress;
  product_worker_layout_t layout = {
    .worker_count = PRODUCT_GRAPH_WORKERS,
    .hash_seed = PRODUCT_GRAPH_HASH_SEED,
  };
  product_packet_result_t result;

  clib_memset (&ingress, 0, sizeof (ingress));
  ingress.data = packet;
  ingress.length = packet_length;
  ingress.current_worker = 0;
  ingress.origin_obligation_id = origin_obligation_id;
  ingress.platform = *platform;
  result = product_packet_admit (&layout, &ingress, lease);
  if (result != PRODUCT_PACKET_OK)
    return result;
  return product_packet_owner_guard (lease, lease->assignment.execution_owner);
}

static clib_error_t *
product_packet_graph_policy_association_fixture_cli (
  vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *command)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_packet_graph_l4_status_t drop_status;
  product_packet_graph_l4_status_t unrelated_status;
  product_packet_graph_l4_status_t same_probe_status;
  product_packet_graph_l4_status_t wrong_port_status;
  product_packet_graph_policy_evaluation_t evaluation;
  product_platform_packet_facts_t platform = {
    .uid = PRODUCT_GRAPH_POLICY_FIXTURE_UID,
    .availability = PRODUCT_PLATFORM_UID_KNOWN | PRODUCT_PLATFORM_IFINDEX_KNOWN | PRODUCT_PLATFORM_CONTEXT_KNOWN,
    .linux_ifindex = 0,
    .network_context_id = PRODUCT_GRAPH_POLICY_FIXTURE_CONTEXT,
    .direction = PRODUCT_PACKET_GRAPH_L4_DIRECTION_OUTPUT,
  };
  product_packet_lease_t lease;
  u8 packet[64];
  u32 packet_length;
  product_packet_result_t result;
  int drop_terminal;
  int l4_winner_kind;
  int drop_winner_kind;
  int unrelated_preserved;
  int same_probe_preserved;
  int wrong_port_visible;
  (void) input;
  (void) command;

  if (!clib_atomic_load_acq_n (&graph->enabled)
      || !product_packet_graph_l4_policy_view_active (graph))
    return clib_error_return (0,
                              "typed policy association fixture requires an "
                              "enabled view");

  /* First, exercise the real admit -> owner guard -> shared policy stage ->
   * terminal path with the fixture's typed DROP rule. */
  packet_length = product_ipv4_fixture (packet, 6, 0x0a000001, 12345,
                                        0x0a000002, 443);
  result = product_packet_graph_association_prepare_lease (
    packet, packet_length, &platform, UINT64_C (192601), &lease);
  if (result != PRODUCT_PACKET_OK)
    return clib_error_return (0, "drop association admission failed: %d",
                              result);
  result = product_packet_graph_policy_stage (&lease, &evaluation);
  drop_terminal = result == PRODUCT_PACKET_OK
                  && lease.terminal_intent == PRODUCT_PACKET_INTENT_DROP_RUNTIME;
  l4_winner_kind = evaluation.winner == PRODUCT_PACKET_GRAPH_L4_WINNER_RULE;
  drop_winner_kind = clib_atomic_load_acq_n (&graph->policy_last_drop_winner)
                     == PRODUCT_PACKET_GRAPH_L4_WINNER_RULE;
  if (!drop_terminal || product_packet_settle (&lease) != PRODUCT_PACKET_OK)
    return clib_error_return (0, "typed DROP did not settle exactly once");
  product_packet_graph_l4_status (&drop_status);
  l4_winner_kind = l4_winner_kind
                   && drop_status.last_match_winner
                        == PRODUCT_PACKET_GRAPH_L4_WINNER_RULE
                   && drop_status.last_match_winner_rank == 1;

  /* A different destination is background traffic for the same known UID.
   * It increments no-match counters but cannot erase the target DROP. */
  packet_length = product_ipv4_fixture (packet, 6, 0x0a000001, 12345,
                                        0x0a000099, 443);
  result = product_packet_graph_association_prepare_lease (
    packet, packet_length, &platform, UINT64_C (192602), &lease);
  if (result != PRODUCT_PACKET_OK)
    return clib_error_return (0, "unrelated admission failed: %d", result);
  result = product_packet_graph_policy_stage (&lease, &evaluation);
  if (result != PRODUCT_PACKET_OK
      || product_packet_set_terminal (&lease, PRODUCT_PACKET_INTENT_PASS_ADAPTER)
           != PRODUCT_PACKET_OK
      || product_packet_settle (&lease) != PRODUCT_PACKET_OK)
    return clib_error_return (0, "unrelated no-match lifecycle failed");
  product_packet_graph_l4_status (&unrelated_status);
  unrelated_preserved =
    unrelated_status.last_evaluation_result == PRODUCT_PACKET_GRAPH_L4_EVALUATION_MATCH
    && unrelated_status.last_evaluation_verdict == PRODUCT_POLICY_VERDICT_DROP
    && unrelated_status.last_match_rule_id == UINT64_C (192002);

  /* Keep destination port 443 but change the ephemeral source port.  This is
   * the bounded same-probe/retransmit case and must retain the DROP result. */
  packet_length = product_ipv4_fixture (packet, 6, 0x0a000001, 12346,
                                        0x0a000002, 443);
  result = product_packet_graph_association_prepare_lease (
    packet, packet_length, &platform, UINT64_C (192603), &lease);
  if (result != PRODUCT_PACKET_OK)
    return clib_error_return (0, "same-probe admission failed: %d", result);
  result = product_packet_graph_policy_stage (&lease, &evaluation);
  if (result != PRODUCT_PACKET_OK
      || product_packet_set_terminal (&lease, PRODUCT_PACKET_INTENT_PASS_ADAPTER)
           != PRODUCT_PACKET_OK
      || product_packet_settle (&lease) != PRODUCT_PACKET_OK)
    return clib_error_return (0, "same-probe no-match lifecycle failed");
  product_packet_graph_l4_status (&same_probe_status);
  same_probe_preserved =
    same_probe_status.last_evaluation_result == PRODUCT_PACKET_GRAPH_L4_EVALUATION_MATCH
    && same_probe_status.last_evaluation_verdict == PRODUCT_POLICY_VERDICT_DROP
    && same_probe_status.last_no_match_reason == PRODUCT_L4_POLICY_NO_MATCH_NONE
    && same_probe_status.last_match_rule_id == UINT64_C (192002);

  /* Changing only the destination port is an intentional wrong-port probe;
   * it shares the subject key but must remain visible as NO_MATCH. */
  packet_length = product_ipv4_fixture (packet, 6, 0x0a000001, 12345,
                                        0x0a000002, 444);
  result = product_packet_graph_association_prepare_lease (
    packet, packet_length, &platform, UINT64_C (192604), &lease);
  if (result != PRODUCT_PACKET_OK)
    return clib_error_return (0, "wrong-port admission failed: %d", result);
  result = product_packet_graph_policy_stage (&lease, &evaluation);
  if (result != PRODUCT_PACKET_OK
      || product_packet_set_terminal (&lease, PRODUCT_PACKET_INTENT_PASS_ADAPTER)
           != PRODUCT_PACKET_OK
      || product_packet_settle (&lease) != PRODUCT_PACKET_OK)
    return clib_error_return (0, "wrong-port no-match lifecycle failed");
  product_packet_graph_l4_status (&wrong_port_status);
  wrong_port_visible =
    wrong_port_status.last_evaluation_result
      == PRODUCT_PACKET_GRAPH_L4_EVALUATION_NO_MATCH
    && wrong_port_status.last_evaluation_verdict
         == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
    && wrong_port_status.last_no_match_reason
         == PRODUCT_L4_POLICY_NO_MATCH_NO_RULE
    && wrong_port_status.last_match_rule_id == UINT64_C (192002);

  vlib_cli_output (vm, "association.fixture=s192-typed-match-v1");
  vlib_cli_output (vm, "association.drop_terminal=%s",
                   drop_terminal ? "drop-runtime" : "invalid");
  vlib_cli_output (
    vm, "association.drop_completion_attempts=%llu",
    (unsigned long long) clib_atomic_load_acq_n (
      &graph->policy_last_drop_completion_attempts));
  vlib_cli_output (vm, "association.l4_last_match_winner=%u",
                   drop_status.last_match_winner);
  vlib_cli_output (vm, "association.policy_last_drop_winner=%u",
                   clib_atomic_load_acq_n (&graph->policy_last_drop_winner));
  vlib_cli_output (vm, "association.last_match_winner_rank=%u",
                   drop_status.last_match_winner_rank);
  vlib_cli_output (vm, "association.evaluation_winner=%u",
                   PRODUCT_PACKET_GRAPH_L4_WINNER_RULE);
  vlib_cli_output (vm, "association.winner_kind_valid=%u",
                   l4_winner_kind && drop_winner_kind);
  vlib_cli_output (vm, "association.unrelated_preserved=%u",
                   unrelated_preserved);
  vlib_cli_output (vm, "association.same_probe_preserved=%u",
                   same_probe_preserved);
  vlib_cli_output (vm, "association.wrong_port_visible=%u",
                   wrong_port_visible);
  vlib_cli_output (vm, "association.match_records=%llu",
                   (unsigned long long) wrong_port_status.match_records);
  vlib_cli_output (vm, "association.no_match_records=%llu",
                   (unsigned long long) wrong_port_status.no_match_records);
  vlib_cli_output (vm, "association.last_match_rule_id=%llu",
                   (unsigned long long) wrong_port_status.last_match_rule_id);
  vlib_cli_output (vm, "association.last_no_match_reason=%u",
                   wrong_port_status.last_no_match_reason);
  vlib_cli_output (vm, "association.typed_match_policy_key=%llu",
                   (unsigned long long) drop_status.typed_match_policy_key);
  vlib_cli_output (vm, "association.typed_match_probe_key=%llu",
                   (unsigned long long) drop_status.typed_match_probe_key);
  vlib_cli_output (vm, "association.last_evaluation_probe_key=%llu",
                   (unsigned long long)
                     wrong_port_status.last_evaluation_probe_key);
  vlib_cli_output (
    vm, "association.wrong_port_probe_key_distinct=%u",
    wrong_port_status.last_evaluation_probe_key
      != wrong_port_status.typed_match_probe_key);
  if (!unrelated_preserved || !same_probe_preserved || !wrong_port_visible
      || !l4_winner_kind || !drop_winner_kind)
    return clib_error_return (0, "typed match evidence association failed");
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_policy_association_fixture_command,
                  static) = {
  .path = PRODUCT_GRAPH_RUN_POLICY_ASSOCIATION_FIXTURE_COMMAND,
  .short_help = PRODUCT_GRAPH_RUN_POLICY_ASSOCIATION_FIXTURE_COMMAND,
  .function = product_packet_graph_policy_association_fixture_cli,
  .is_mp_safe = 1,
};

static int
product_packet_graph_gate_table_fixture_vector (
  const u8 *packet, u32 packet_length, const product_platform_packet_facts_t *platform,
  u64 origin_obligation_id,
  product_packet_graph_policy_evaluation_t *evaluation)
{
  product_packet_lease_t lease;
  product_packet_result_t result;

  result = product_packet_graph_association_prepare_lease (
    packet, packet_length, platform, origin_obligation_id, &lease);
  if (result != PRODUCT_PACKET_OK)
    return 0;
  result = product_packet_graph_policy_stage (&lease, evaluation);
  if (result != PRODUCT_PACKET_OK)
    return 0;
  if (lease.terminal_intent == PRODUCT_PACKET_INTENT_NONE)
    {
      result = product_packet_set_terminal (
        &lease, PRODUCT_PACKET_INTENT_PASS_ADAPTER);
      if (result != PRODUCT_PACKET_OK)
        return 0;
    }
  return product_packet_settle (&lease) == PRODUCT_PACKET_OK;
}

static clib_error_t *
product_packet_graph_gate_table_fixture_cli (
  vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *command)
{
  static const u8 ip6_a[16] = {
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
  };
  static const u8 ip6_b[16] = {
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
  };
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_packet_graph_gate_entry_t gate_rules[6];
  product_packet_graph_policy_bundle_t bundle;
  product_packet_graph_gate_status_t drop_status;
  product_packet_graph_gate_status_t range_status;
  product_packet_graph_gate_status_t ipv6_status;
  product_packet_graph_gate_status_t address_status;
  product_packet_graph_gate_status_t ifindex_status;
  product_packet_graph_gate_status_t unavailable_status;
  product_packet_graph_gate_status_t unknown_uid_status;
  product_packet_graph_gate_status_t unknown_context_status;
  product_packet_graph_gate_status_t wildcard_status;
  product_packet_graph_flow_status_t flow_status;
  product_packet_graph_policy_evaluation_t evaluation;
  product_platform_packet_facts_t platform = {
    .uid = PRODUCT_GRAPH_POLICY_FIXTURE_UID,
    .availability = PRODUCT_PLATFORM_UID_KNOWN | PRODUCT_PLATFORM_IFINDEX_KNOWN | PRODUCT_PLATFORM_CONTEXT_KNOWN,
    .linux_ifindex = 77,
    .network_context_id = PRODUCT_GRAPH_POLICY_FIXTURE_CONTEXT,
    .direction = PRODUCT_PACKET_GRAPH_L4_DIRECTION_OUTPUT,
  };
  u8 packet[80];
  u32 packet_length;
  int scalar_identity_empty;
  int drop_ok;
  int range_ok;
  int ipv6_ok;
  int address_ok;
  int ifindex_ok;
  int unavailable_ok;
  int unknown_uid_ok;
  int unknown_context_ok;
  int wildcard_ok;
  int lazy_revision_ok;
  (void) command;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || !clib_atomic_load_acq_n (&graph->enabled))
    return clib_error_return (0, "GateTable fixture requires an enabled graph");

  clib_memset (gate_rules, 0, sizeof (gate_rules));
  gate_rules[0] = (product_packet_graph_gate_entry_t) {
    .rule_id = UINT64_C (192301),
    .uid = PRODUCT_GRAPH_POLICY_FIXTURE_UID,
    .network_context_id = PRODUCT_GRAPH_POLICY_FIXTURE_CONTEXT,
    .ifindex = 77,
    .priority = 10,
    .order = 0,
    .reason_id = UINT32_C (19301),
    .source_port_first = 12345,
    .source_port_last = 12345,
    .destination_port_first = 443,
    .destination_port_last = 443,
    .family = PRODUCT_L4_POLICY_FAMILY_IPV4,
    .protocol = PRODUCT_L4_POLICY_PROTOCOL_TCP,
    .direction = PRODUCT_L4_POLICY_DIRECTION_OUTPUT,
    .source_prefix_length = 32,
    .destination_prefix_length = 32,
    .action = PRODUCT_L4_POLICY_ACTION_DROP,
  };
  gate_rules[0].source_address[0] = 0x0a;
  gate_rules[0].source_address[3] = 1;
  gate_rules[0].destination_address[0] = 0x0a;
  gate_rules[0].destination_address[3] = 2;
  gate_rules[1] = gate_rules[0];
  gate_rules[1].rule_id = UINT64_C (192302);
  gate_rules[1].order = 1;
  gate_rules[1].reason_id = UINT32_C (19302);
  gate_rules[1].action = PRODUCT_L4_POLICY_ACTION_ALLOW;
  gate_rules[2] = gate_rules[0];
  gate_rules[2].rule_id = UINT64_C (192303);
  gate_rules[2].priority = 20;
  gate_rules[2].order = 0;
  gate_rules[2].reason_id = UINT32_C (19303);
  gate_rules[2].family = PRODUCT_L4_POLICY_FAMILY_IPV6;
  gate_rules[2].protocol = PRODUCT_L4_POLICY_PROTOCOL_UDP;
  gate_rules[2].source_port_first = 60000;
  gate_rules[2].source_port_last = 60000;
  gate_rules[2].destination_port_first = 443;
  gate_rules[2].destination_port_last = 443;
  gate_rules[2].source_prefix_length = 128;
  gate_rules[2].destination_prefix_length = 128;
  clib_memcpy_fast (gate_rules[2].source_address, ip6_a, sizeof (ip6_a));
  clib_memcpy_fast (gate_rules[2].destination_address, ip6_b,
                    sizeof (ip6_b));
  gate_rules[2].action = PRODUCT_L4_POLICY_ACTION_ALLOW;
  gate_rules[3] = gate_rules[0];
  gate_rules[3].rule_id = UINT64_C (192304);
  gate_rules[3].priority = 30;
  gate_rules[3].reason_id = UINT32_C (19304);
  gate_rules[3].protocol = PRODUCT_L4_POLICY_PROTOCOL_UDP;
  gate_rules[3].source_prefix_length = 24;
  gate_rules[3].destination_prefix_length = 24;
  gate_rules[3].source_port_first = 1000;
  gate_rules[3].source_port_last = 2000;
  gate_rules[3].destination_port_first = 400;
  gate_rules[3].destination_port_last = 500;
  gate_rules[3].source_address[3] = 0;
  gate_rules[3].destination_address[3] = 0;
  gate_rules[4] = gate_rules[0];
  gate_rules[4].rule_id = UINT64_C (192305);
  gate_rules[4].priority = 40;
  gate_rules[4].reason_id = UINT32_C (19305);
  gate_rules[4].source_port_first = 10000;
  gate_rules[4].source_port_last = 20000;
  gate_rules[4].destination_port_first = 400;
  gate_rules[4].destination_port_last = 500;
  gate_rules[4].action = PRODUCT_L4_POLICY_ACTION_ALLOW;
  gate_rules[5] = gate_rules[0];
  gate_rules[5].rule_id = UINT64_C (192306);
  gate_rules[5].uid = UINT32_C (10002);
  gate_rules[5].priority = 50;
  gate_rules[5].order = 0;
  gate_rules[5].reason_id = UINT32_C (19306);
  gate_rules[5].ifindex = PRODUCT_L4_POLICY_IFINDEX_ANY;
  gate_rules[5].family = 0;
  gate_rules[5].protocol = 0;
  gate_rules[5].direction = PRODUCT_L4_POLICY_DIRECTION_ANY;
  gate_rules[5].source_address[0] = 0;
  gate_rules[5].source_address[3] = 0;
  gate_rules[5].destination_address[0] = 0;
  gate_rules[5].destination_address[3] = 0;
  gate_rules[5].source_prefix_length = 0;
  gate_rules[5].destination_prefix_length = 0;
  gate_rules[5].source_port_first = PRODUCT_L4_POLICY_PORT_FIRST_ANY;
  gate_rules[5].source_port_last = PRODUCT_L4_POLICY_PORT_LAST_ANY;
  gate_rules[5].destination_port_first = PRODUCT_L4_POLICY_PORT_FIRST_ANY;
  gate_rules[5].destination_port_last = PRODUCT_L4_POLICY_PORT_LAST_ANY;
  gate_rules[5].action = PRODUCT_L4_POLICY_ACTION_ALLOW;

  bundle = (product_packet_graph_policy_bundle_t) {
    .generation = graph->generation,
    .revision = UINT64_C (19206),
    .snapshot_hash = UINT64_C (0x19206),
    .gate_entries = gate_rules,
    .gate_entry_count = 6,
    .l4_rules = 0,
    .l4_rule_count = 0,
  };
  if (product_packet_graph_publish_policy_bundle (&bundle)
      != PRODUCT_PACKET_OK)
    return clib_error_return (0, "GateTable fixture publication rejected");

  packet_length = product_ipv4_fixture (packet, PRODUCT_L4_POLICY_PROTOCOL_TCP,
                                        0x0a000001, 12345, 0x0a000002, 443);
  drop_ok = product_packet_graph_gate_table_fixture_vector (
    packet, packet_length, &platform, UINT64_C (192701), &evaluation)
             && evaluation.stage == PRODUCT_PACKET_GRAPH_POLICY_STAGE_GATE
             && evaluation.verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_DROP
             && evaluation.rule_id == UINT64_C (192301);
  product_packet_graph_gate_status (&drop_status);

  packet_length = product_ipv4_fixture (packet, PRODUCT_L4_POLICY_PROTOCOL_TCP,
                                        0x0a000001, 15000, 0x0a000002, 444);
  range_ok = product_packet_graph_gate_table_fixture_vector (
    packet, packet_length, &platform, UINT64_C (192702), &evaluation)
              && evaluation.verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
              && evaluation.rule_id == 0;
  product_packet_graph_gate_status (&range_status);

  packet_length = product_ipv6_fixture (packet, PRODUCT_L4_POLICY_PROTOCOL_UDP,
                                        ip6_a, 60000, ip6_b, 443);
  ipv6_ok = product_packet_graph_gate_table_fixture_vector (
    packet, packet_length, &platform, UINT64_C (192703), &evaluation)
             && evaluation.verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
             && evaluation.rule_id == 0;
  product_packet_graph_gate_status (&ipv6_status);

  packet_length = product_ipv4_fixture (packet, PRODUCT_L4_POLICY_PROTOCOL_TCP,
                                        0x0a000001, 12345, 0x0a000099, 444);
  address_ok = product_packet_graph_gate_table_fixture_vector (
    packet, packet_length, &platform, UINT64_C (192704), &evaluation)
               && evaluation.verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
               && evaluation.rule_id == 0;
  product_packet_graph_gate_status (&address_status);

  platform.linux_ifindex = 78;
  packet_length = product_ipv4_fixture (packet, PRODUCT_L4_POLICY_PROTOCOL_TCP,
                                        0x0a000001, 12345, 0x0a000002, 443);
  ifindex_ok = product_packet_graph_gate_table_fixture_vector (
    packet, packet_length, &platform, UINT64_C (192705), &evaluation)
               && evaluation.verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
               && evaluation.rule_id == 0;
  product_packet_graph_gate_status (&ifindex_status);

  platform.linux_ifindex = 77;
  packet_length = product_ipv4_fixture (packet, PRODUCT_L4_POLICY_PROTOCOL_TCP,
                                        0x0a000001, 12345, 0x0a000002, 443);
  packet[2] = 0;
  packet[3] = 20;
  unavailable_ok = product_packet_graph_gate_table_fixture_vector (
    packet, 20, &platform, UINT64_C (192706), &evaluation)
                  && evaluation.verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
                  && evaluation.rule_id == 0;
  product_packet_graph_gate_status (&unavailable_status);

  platform.availability &= ~PRODUCT_PLATFORM_UID_KNOWN;
  packet_length = product_ipv4_fixture (packet, PRODUCT_L4_POLICY_PROTOCOL_TCP,
                                        0x0a000001, 12345, 0x0a000002, 443);
  unknown_uid_ok = product_packet_graph_gate_table_fixture_vector (
    packet, packet_length, &platform, UINT64_C (192707), &evaluation)
                   && evaluation.verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
                   && evaluation.rule_id == 0;
  product_packet_graph_gate_status (&unknown_uid_status);

  platform.availability |= PRODUCT_PLATFORM_UID_KNOWN;
  platform.uid = UINT32_C (10002);
  platform.availability |= PRODUCT_PLATFORM_CONTEXT_KNOWN;
  platform.network_context_id = PRODUCT_GRAPH_POLICY_FIXTURE_CONTEXT;
  packet_length = product_ipv4_fixture (packet, PRODUCT_L4_POLICY_PROTOCOL_TCP,
                                        0x0a000001, 12345, 0x0a000002, 443);
  wildcard_ok = product_packet_graph_gate_table_fixture_vector (
    packet, packet_length, &platform, UINT64_C (192709), &evaluation)
                && evaluation.verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
                && evaluation.rule_id == 0;
  product_packet_graph_gate_status (&wildcard_status);

  platform.uid = PRODUCT_GRAPH_POLICY_FIXTURE_UID;
  platform.availability &= ~PRODUCT_PLATFORM_CONTEXT_KNOWN;
  unknown_context_ok = product_packet_graph_gate_table_fixture_vector (
    packet, packet_length, &platform, UINT64_C (192708), &evaluation)
                       && evaluation.verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
                       && evaluation.rule_id == 0;
  product_packet_graph_gate_status (&unknown_context_status);

  /* Publish a successor view without flushing the worker pools.  Replaying
   * an existing PASS_NEXT tuple proves that revision invalidation remains
   * lazy and that the bounded entry is reused rather than reallocated. */
  bundle.revision = UINT64_C (19207);
  bundle.snapshot_hash = UINT64_C (0x19207);
  if (product_packet_graph_publish_policy_bundle (&bundle)
      != PRODUCT_PACKET_OK)
    return clib_error_return (0, "GateTable successor publication rejected");
  platform.uid = PRODUCT_GRAPH_POLICY_FIXTURE_UID;
  platform.availability |= PRODUCT_PLATFORM_CONTEXT_KNOWN;
  platform.network_context_id = PRODUCT_GRAPH_POLICY_FIXTURE_CONTEXT;
  platform.linux_ifindex = 77;
  packet_length = product_ipv4_fixture (packet, PRODUCT_L4_POLICY_PROTOCOL_TCP,
                                        0x0a000001, 15000, 0x0a000002, 444);
  lazy_revision_ok = product_packet_graph_gate_table_fixture_vector (
    packet, packet_length, &platform, UINT64_C (192710), &evaluation)
                     && evaluation.verdict
                          == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
                     && evaluation.rule_id == 0;
  product_packet_graph_flow_status (&flow_status);

  scalar_identity_empty = drop_status.active_entry_count == 6
                          && drop_status.max_probes == 6
                          && drop_status.rule_id == 0
                          && drop_status.active_revision == UINT64_C (19206)
                          && drop_status.snapshot_hash == UINT64_C (0x19206);
  if (!drop_ok || !range_ok || !ipv6_ok || !address_ok || !ifindex_ok
      || !unavailable_ok || !unknown_uid_ok || !wildcard_ok
      || !unknown_context_ok
      || !scalar_identity_empty
      || drop_status.last_match_rule_id != UINT64_C (192301)
      || drop_status.last_match_winner_rank != 1
      || drop_status.last_match_candidate_count != 3
      || drop_status.last_match_probes != 6
      || range_status.last_match_rule_id != UINT64_C (192305)
      || range_status.last_match_winner_rank != 5
      || range_status.last_match_candidate_count != 1
      || ipv6_status.last_match_rule_id != UINT64_C (192303)
      || ipv6_status.last_match_winner_rank != 3
      || address_status.last_match_rule_id != 0
      || address_status.last_no_match_reason
           != PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_ADDRESS
      || ifindex_status.last_match_rule_id != 0
      || ifindex_status.last_no_match_reason
           != PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_NO_RULE
      || unavailable_status.last_match_rule_id != 0
      || unavailable_status.last_no_match_reason
           != PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_PORTS_UNAVAILABLE
      || unknown_uid_status.last_match_rule_id != 0
      || unknown_uid_status.last_no_match_reason
           != PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_UNKNOWN_UID
      || wildcard_status.last_match_rule_id != UINT64_C (192306)
      || wildcard_status.last_match_winner_rank != 6
      || wildcard_status.last_match_action != PRODUCT_L4_POLICY_ACTION_ALLOW
      || unknown_context_status.last_match_rule_id != 0
      || unknown_context_status.last_no_match_reason
           != PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_UNKNOWN_CONTEXT
      || !lazy_revision_ok
      || flow_status.active_revision != UINT64_C (19207)
      || flow_status.active_snapshot_hash != UINT64_C (0x19207)
      || flow_status.active_entries != 4
      || flow_status.allocation_count != 4
      || flow_status.reuse_count != 4
      || flow_status.early_drop_count != 1
      || flow_status.revision_invalidation_count != 1)
    return clib_error_return (0, "GateTable fixture vector failed");

  vlib_cli_output (vm, "gate-table.fixture=s192-gate-table-v1");
  vlib_cli_output (vm, "gate-table.active_entry_count=%u",
                   drop_status.active_entry_count);
  vlib_cli_output (vm, "gate-table.max_probes=%u", drop_status.max_probes);
  vlib_cli_output (vm, "gate-table.scalar_rule_id=%llu",
                   (unsigned long long) drop_status.rule_id);
  vlib_cli_output (vm, "gate-table.drop_rule_id=%llu",
                   (unsigned long long) drop_status.last_match_rule_id);
  vlib_cli_output (vm, "gate-table.drop_winner_rank=%u",
                   drop_status.last_match_winner_rank);
  vlib_cli_output (vm, "gate-table.drop_candidate_count=%u",
                   drop_status.last_match_candidate_count);
  vlib_cli_output (vm, "gate-table.range_rule_id=%llu",
                   (unsigned long long) range_status.last_match_rule_id);
  vlib_cli_output (vm, "gate-table.ipv6_rule_id=%llu",
                   (unsigned long long) ipv6_status.last_match_rule_id);
  vlib_cli_output (vm, "gate-table.address_no_match_reason=%u",
                   address_status.last_no_match_reason);
  vlib_cli_output (vm, "gate-table.ifindex_no_match_reason=%u",
                   ifindex_status.last_no_match_reason);
  vlib_cli_output (vm, "gate-table.unavailable_no_match_reason=%u",
                   unavailable_status.last_no_match_reason);
  vlib_cli_output (vm, "gate-table.unknown_uid_no_match_reason=%u",
                   unknown_uid_status.last_no_match_reason);
  vlib_cli_output (vm, "gate-table.wildcard_rule_id=%llu",
                   (unsigned long long) wildcard_status.last_match_rule_id);
  vlib_cli_output (vm, "gate-table.wildcard_winner_rank=%u",
                   wildcard_status.last_match_winner_rank);
  vlib_cli_output (vm, "gate-table.unknown_context_no_match_reason=%u",
                   unknown_context_status.last_no_match_reason);
  vlib_cli_output (vm, "gate-table.drop_terminal=%u", drop_ok);
  vlib_cli_output (vm, "gate-table.open_pass_next=%u",
                   range_ok && ipv6_ok);
  vlib_cli_output (vm, "gate-table.scalar_identity_empty=%u",
                   scalar_identity_empty);
  vlib_cli_output (vm, "gate-table.lazy_revision=%llu",
                   (unsigned long long) flow_status.active_revision);
  vlib_cli_output (vm, "gate-table.lazy_revision_ok=%u", lazy_revision_ok);
  vlib_cli_output (vm, "gate-table.flow_active_entries=%u",
                   flow_status.active_entries);
  vlib_cli_output (vm, "gate-table.flow_allocation_count=%llu",
                   (unsigned long long) flow_status.allocation_count);
  vlib_cli_output (vm, "gate-table.flow_reuse_count=%llu",
                   (unsigned long long) flow_status.reuse_count);
  vlib_cli_output (vm, "gate-table.flow_early_drop_count=%llu",
                   (unsigned long long) flow_status.early_drop_count);
  vlib_cli_output (vm, "gate-table.flow_revision_invalidation_count=%llu",
                   (unsigned long long) flow_status.revision_invalidation_count);
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_gate_table_fixture_command, static) = {
  .path = PRODUCT_GRAPH_RUN_GATE_TABLE_FIXTURE_COMMAND,
  .short_help = PRODUCT_GRAPH_RUN_GATE_TABLE_FIXTURE_COMMAND,
  .function = product_packet_graph_gate_table_fixture_cli,
  .is_mp_safe = 1,
};

static u64
product_packet_graph_frame_queue_occupancy (u32 frame_queue)
{
  vlib_thread_main_t *thread_main = vlib_get_thread_main ();
  vlib_frame_queue_main_t *fqm =
    vec_elt_at_index (thread_main->frame_queue_mains, frame_queue);
  u64 occupancy = 0;
  for (u32 worker = 0; worker < PRODUCT_GRAPH_WORKERS; worker++)
    {
      u32 thread = vlib_get_worker_thread_index (worker);
      occupancy += fqm->vlib_frame_queues[thread]->tail
                   - fqm->vlib_frame_queues[thread]->head;
    }
  return occupancy;
}

static u64
product_packet_graph_all_frame_queue_occupancy (void)
{
  return product_packet_graph_frame_queue_occupancy (
           product_packet_graph_main.ingress_frame_queue)
         + product_packet_graph_frame_queue_occupancy (
           product_packet_graph_main.owner_guard_frame_queue)
         + product_packet_graph_frame_queue_occupancy (
           product_fragment_graph_main.steer_frame_queue)
         + product_packet_graph_frame_queue_occupancy (
           product_fragment_graph_main.final_frame_queue);
}

static clib_error_t *
product_packet_graph_disable_cli (vlib_main_t *vm, unformat_input_t *input,
                                  vlib_cli_command_t *command)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  (void) input;
  (void) command;
  f64 deadline;
  if (!clib_atomic_load_acq_n (&graph->enabled))
    return clib_error_return (0, "graph is not enabled");
  clib_atomic_store_rel_n (&graph->accepting, 0);
  product_flow_end_quiesce (vm);
  deadline = vlib_time_now (vm) + 2.0;
  while ((clib_atomic_load_acq_n (&graph->lifecycle_obligations) != 0
          || clib_atomic_load_acq_n (&graph->lifecycle_buffers) != 0
          || product_flow_end_buffer_debt () != 0
          || clib_atomic_load_acq_n (&graph->lifecycle_handoffs) != 0
          || product_packet_graph_all_frame_queue_occupancy () != 0)
         && vlib_time_now (vm) < deadline)
    vlib_process_suspend (vm, 0.001);
  if (clib_atomic_load_acq_n (&graph->lifecycle_obligations) != 0
      || clib_atomic_load_acq_n (&graph->lifecycle_buffers) != 0
      || product_flow_end_buffer_debt () != 0
      || clib_atomic_load_acq_n (&graph->lifecycle_handoffs) != 0
      || product_packet_graph_all_frame_queue_occupancy () != 0
      || clib_atomic_load_acq_n (&graph->buffer_debt) != 0
      || clib_atomic_load_acq_n (&graph->handoff_credit_debt) != 0
      || clib_atomic_load_acq_n (&graph->obligation_debt) != 0)
    return clib_error_return (0, "graph bounded drain timed out");
  clib_atomic_store_rel_n (&graph->enabled, 0);
  product_packet_graph_policy_writer_lock (graph);
  product_packet_graph_flow_pools_flush (graph);
  product_packet_graph_policy_writer_unlock (graph);
  graph->configured = 0;
  vlib_cli_output (vm, "graph.disable=ok");
  vlib_cli_output (vm, "graph.buffer_debt=0");
  vlib_cli_output (vm, "graph.handoff_credit_debt=0");
  vlib_cli_output (vm, "graph.obligation_debt=0");
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_disable_command, static) = {
  .path = "product packet-graph disable",
  .function = product_packet_graph_disable_cli,
};
