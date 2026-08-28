/* SPDX-License-Identifier: Apache-2.0 */

#include "sakamoto_product_abi.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

_Static_assert (sizeof (sakamoto_product_bytes_t) == 16U,
                "bytes ABI changed");
_Static_assert (offsetof (sakamoto_product_status_t, generation) == 16U,
                "status generation ABI changed");
_Static_assert (offsetof (sakamoto_product_status_t, artifact_id) == 52U,
                "status identity ABI changed");
_Static_assert (sizeof (sakamoto_product_status_t) == 424U,
                "status ABI changed");

static int
expect_code (uint32_t actual, uint32_t expected, const char *case_name)
{
  if (actual == expected)
    return 0;
  fprintf (stderr, "%s: got %u, expected %u\n", case_name, actual, expected);
  return 1;
}

int
main (void)
{
  int failures = 0;
  failures += expect_code (sakamoto_product_abi_version (),
                           SAKAMOTO_PRODUCT_ABI_VERSION, "ABI version");
  failures += expect_code (sakamoto_product_api_version (),
                           SAKAMOTO_PRODUCT_API_VERSION, "API version");

  sakamoto_product_status_t status;
  sakamoto_product_session_t *session =
    (sakamoto_product_session_t *) (uintptr_t) 1U;
  sakamoto_product_bytes_t empty = {.data = NULL, .length = 0};
  failures += expect_code (sakamoto_product_session_connect (
                             empty, 0, &session, &status),
                           SAKAMOTO_PRODUCT_INVALID_ARGUMENT,
                           "invalid connect");
  if (session != NULL)
    {
      fprintf (stderr, "invalid connect left a stale session pointer\n");
      ++failures;
    }
  failures += expect_code (sakamoto_product_session_query (
                             NULL, 1, &status),
                           SAKAMOTO_PRODUCT_INVALID_ARGUMENT,
                           "invalid query");
  failures += expect_code (sakamoto_product_session_disconnect (NULL),
                           SAKAMOTO_PRODUCT_INVALID_ARGUMENT,
                           "invalid disconnect");
  return failures == 0 ? 0 : 1;
}
