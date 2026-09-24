/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_CORE_POLICY_H
#define SAKAMOTO_PRODUCT_CORE_POLICY_H
#include <stdint.h>
/* Called only during main-thread graph startup, before Adapter admission. */
int product_core_policy_start (uint64_t generation);
#endif
