/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_RULE_CONFIG_H
#define SAKAMOTO_PRODUCT_RULE_CONFIG_H

#include "sakamoto_product_rule_config.h"
#include "product_l4_policy.h"

/* Main-thread-only ownership. A publish callback borrows rule bytes for the
 * duration of the call and returns only after protected publication or failure.
 * It must preserve the preceding snapshot on failure. No worker sees this
 * mutable source object. */
typedef struct product_rule_config product_rule_config_t;
typedef uint32_t (*product_rule_config_publish_t) (
  void *, uint64_t revision, uint64_t hash,
  const product_l4_policy_rule_t *, uint32_t count);

product_rule_config_t *product_rule_config_open (const char *path);
void product_rule_config_close (product_rule_config_t *);
void product_rule_config_query (const product_rule_config_t *,
                               sakamoto_product_rule_config_status_t *);
uint32_t product_rule_config_activate (product_rule_config_t *,
                                     product_rule_config_publish_t, void *);
uint32_t product_rule_config_replace (
  product_rule_config_t *, const sakamoto_product_rule_config_request_t *,
  product_rule_config_publish_t, void *);

#endif
