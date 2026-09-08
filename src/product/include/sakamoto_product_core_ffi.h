/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_CORE_FFI_H
#define SAKAMOTO_PRODUCT_CORE_FFI_H

#include "sakamoto_product_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The handle is allocated and owned by the Rust Product Core cdylib. */
typedef struct sakamoto_product_core_handle sakamoto_product_core_handle_t;

uint32_t sakamoto_product_core_connect(
    sakamoto_product_bytes_t api_socket, uint64_t generation,
    sakamoto_product_core_handle_t **out_handle,
    sakamoto_product_status_t *out_status);

uint32_t sakamoto_product_core_query(
    sakamoto_product_core_handle_t *handle, uint64_t generation,
    sakamoto_product_status_t *out_status);

uint32_t sakamoto_product_core_publish_network(
    sakamoto_product_core_handle_t *handle, uint64_t generation,
    const sakamoto_product_network_snapshot_t *snapshot);

uint32_t sakamoto_product_core_apply_empty_policy(
    sakamoto_product_core_handle_t *handle, uint64_t generation,
    sakamoto_product_bytes_t files_dir,
    sakamoto_product_status_t *out_status);

uint32_t sakamoto_product_core_apply_empty_policy_revision(
    sakamoto_product_core_handle_t *handle, uint64_t generation,
    sakamoto_product_bytes_t files_dir, uint64_t revision,
    sakamoto_product_status_t *out_status);

uint32_t sakamoto_product_core_apply_network_gate_policy(
    sakamoto_product_core_handle_t *handle, uint64_t generation,
    sakamoto_product_bytes_t files_dir, uint32_t subject_uid,
    uint32_t network_context, uint32_t blocked, uint64_t rule_id,
    uint32_t reason_id, sakamoto_product_status_t *out_status);

uint32_t sakamoto_product_core_apply_network_gate_policy_revision(
    sakamoto_product_core_handle_t *handle, uint64_t generation,
    sakamoto_product_bytes_t files_dir, uint64_t revision,
    uint32_t subject_uid, uint32_t network_context, uint32_t blocked,
    uint64_t rule_id, uint32_t reason_id,
    sakamoto_product_status_t *out_status);

uint32_t sakamoto_product_core_apply_l4_policy(
    sakamoto_product_core_handle_t *handle, uint64_t generation,
    sakamoto_product_bytes_t files_dir, uint32_t subject_uid,
    uint32_t network_context, uint32_t ip_family, uint32_t ip_protocol,
    uint32_t direction, uint32_t action, sakamoto_product_bytes_t source_cidr,
    sakamoto_product_bytes_t destination_cidr, uint32_t source_port_first,
    uint32_t source_port_last, uint32_t destination_port_first,
    uint32_t destination_port_last, uint32_t priority, uint32_t order,
    uint64_t rule_id, uint32_t reason_id,
    sakamoto_product_status_t *out_status);

uint32_t sakamoto_product_core_apply_l4_policy_revision(
    sakamoto_product_core_handle_t *handle, uint64_t generation,
    sakamoto_product_bytes_t files_dir, uint64_t revision,
    uint32_t subject_uid, uint32_t network_context, uint32_t ip_family,
    uint32_t ip_protocol, uint32_t direction, uint32_t action,
    sakamoto_product_bytes_t source_cidr,
    sakamoto_product_bytes_t destination_cidr, uint32_t source_port_first,
    uint32_t source_port_last, uint32_t destination_port_first,
    uint32_t destination_port_last, uint32_t priority, uint32_t order,
    uint64_t rule_id, uint32_t reason_id,
    sakamoto_product_status_t *out_status);

/* Validate, stage, and apply one complete successor Gate + L4 bundle.  The
 * implementation must never emulate this with repeated single-rule calls. */
uint32_t sakamoto_product_core_apply_policy_bundle(
    sakamoto_product_core_handle_t *handle, uint64_t generation,
    sakamoto_product_bytes_t files_dir,
    const sakamoto_product_policy_bundle_t *bundle,
    sakamoto_product_status_t *out_status);

/* Debug-only, one-shot fault arming for the typed bundle transport. */
uint32_t sakamoto_product_core_set_policy_mutation_fault(
    sakamoto_product_core_handle_t *handle, uint64_t generation,
    uint32_t fault_mode, sakamoto_product_status_t *out_status);

uint32_t sakamoto_product_core_reconcile_policy(
    sakamoto_product_core_handle_t *handle, uint64_t generation,
    sakamoto_product_bytes_t files_dir,
    sakamoto_product_status_t *out_status);

uint32_t sakamoto_product_core_reconcile_empty_policy(
    sakamoto_product_core_handle_t *handle, uint64_t generation,
    sakamoto_product_bytes_t files_dir,
    sakamoto_product_status_t *out_status);

uint32_t sakamoto_product_core_disconnect(
    sakamoto_product_core_handle_t *handle);

uint32_t sakamoto_product_core_destroy(
    sakamoto_product_core_handle_t *handle);

#ifdef __cplusplus
}
#endif

#endif
