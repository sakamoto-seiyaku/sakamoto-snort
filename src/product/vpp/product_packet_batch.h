/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_PACKET_BATCH_H
#define SAKAMOTO_PRODUCT_PACKET_BATCH_H

/* Execution windows, not additional packet credits or backlog capacity. */
#define PRODUCT_ROOT_INPUT_BATCH_SIZE 32U
#define PRODUCT_PACKET_BATCH_SIZE 16U
#define PRODUCT_PACKET_PREPARE_SIZE 4U
#define PRODUCT_POLICY_BATCH_SIZE 16U
#define PRODUCT_COMPLETION_BATCH_SIZE 64U

#endif
