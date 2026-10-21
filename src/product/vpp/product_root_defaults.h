/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_ROOT_DEFAULTS_H
#define SAKAMOTO_PRODUCT_ROOT_DEFAULTS_H

/* User-selected Root capacity/service defaults, 2026-10-13. These bound the
 * existing pools and native queues; they do not select a flow owner or promise
 * a particular distribution across kernel queues. */
#define PRODUCT_ROOT_DEFAULT_NORMAL_CAPACITY 128U
#define PRODUCT_ROOT_DEFAULT_HANDOFF_CREDITS 48U
#define PRODUCT_ROOT_DEFAULT_READ_BUDGET 16U
#define PRODUCT_ROOT_READ_BUDGET_LIMIT 64U
#define PRODUCT_ROOT_DEFAULT_RCVBUF_REQUEST (1024U * 1024U)
#define PRODUCT_ROOT_DEFAULT_QUEUE_MAXLEN 4096U

#endif
