/* MIT License
 *
 * Copyright (c) 2005, 2013 Dominick Meglio
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ares_private.h"

/* Determines if s1 ends with the string in s2 (case-insensitive) */
static char *ares_striendstr(const char *s1, const char *s2)
{
  const char *c1;
  const char *c2;
  const char *c1_begin;
  int         lo1;
  int         lo2;
  size_t      s1_len = ares_strlen(s1);
  size_t      s2_len = ares_strlen(s2);

  if (s1 == NULL || s2 == NULL) {
    return NULL;
  }

  /* If the substr is longer than the full str, it can't match */
  if (s2_len > s1_len) {
    return NULL;
  }

  /* Jump to the end of s1 minus the length of s2 */
  c1_begin = s1 + s1_len - s2_len;
  c1       = c1_begin;
  c2       = s2;
  while (c2 < s2 + s2_len) {
    lo1 = ares_tolower((unsigned char)*c1);
    lo2 = ares_tolower((unsigned char)*c2);
    if (lo1 != lo2) {
      return NULL;
    } else {
      c1++;
      c2++;
    }
  }
  /* Cast off const */
  return (char *)((size_t)c1_begin);
}

ares_bool_t ares_is_onion_domain(const char *name)
{
  if (ares_striendstr(name, ".onion")) {
    return ARES_TRUE;
  }

  if (ares_striendstr(name, ".onion.")) {
    return ARES_TRUE;
  }

  return ARES_FALSE;
}
