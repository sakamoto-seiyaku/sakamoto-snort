/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_DIAGNOSTIC_HEX_H
#define SAKAMOTO_PRODUCT_DIAGNOSTIC_HEX_H

#include <stddef.h>
#include <stdio.h>

/* Formatting only. The caller retains its existing trace limit and stream
 * lock, and no packet storage or ownership survives this synchronous call. */
static inline void
product_diagnostic_write_hex (FILE *stream, const unsigned char *bytes,
                              size_t length)
{
  static const char digits[] = "0123456789abcdef";
  char output[128];
  while (length)
    {
      size_t count = length < sizeof (output) / 2 ? length : sizeof (output) / 2;
      for (size_t i = 0; i < count; i++)
        {
          output[2 * i] = digits[bytes[i] >> 4];
          output[2 * i + 1] = digits[bytes[i] & 15];
        }
      (void) fwrite (output, 2, count, stream);
      bytes += count;
      length -= count;
    }
}

#endif
