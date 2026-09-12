/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "product_diagnostic_hex.h"
#include <assert.h>
#include <string.h>
#include <sys/types.h>

struct sink
{
  unsigned char bytes[32768];
  size_t length, writes;
};

static ssize_t
write_sink (void *opaque, const char *bytes, size_t length)
{
  struct sink *sink = opaque;
  assert (length <= sizeof (sink->bytes) - sink->length);
  memcpy (sink->bytes + sink->length, bytes, length);
  sink->length += length;
  sink->writes++;
  return (ssize_t) length;
}

int
main (void)
{
  unsigned char input[8192];
  for (size_t i = 0; i < sizeof (input); i++) input[i] = (unsigned char) i;
  const size_t lengths[] = {0, 1, 16, 63, 64, 65, 255, 256, 257, 2048, 8192};
  for (size_t n = 0; n < sizeof (lengths) / sizeof (lengths[0]); n++)
    {
      struct sink sink = {0};
      FILE *stream = fopencookie (&sink, "w", (cookie_io_functions_t) {.write = write_sink});
      assert (stream);
      assert (setvbuf (stream, NULL, _IONBF, 0) == 0);
      product_diagnostic_write_hex (stream, input, lengths[n]);
      assert (fclose (stream) == 0);
      assert (sink.length == lengths[n] * 2);
      for (size_t i = 0; i < lengths[n]; i++)
        {
          char expected[3];
          assert (snprintf (expected, sizeof (expected), "%02x", input[i]) == 2);
          assert (memcmp (expected, sink.bytes + 2 * i, 2) == 0);
        }
      /* stderr is unbuffered. A 64-byte input chunk should produce at most
       * one sink write, not one syscall for every input octet under the
       * common worker trace lock. Exact full wire bytes remain present. */
      if (sink.writes > (lengths[n] + 63) / 64)
        {
          fprintf (stderr, "length=%zu sink_writes=%zu bound=%zu\n",
                   lengths[n], sink.writes, (lengths[n] + 63) / 64);
          return 1;
        }
    }
  return 0;
}
