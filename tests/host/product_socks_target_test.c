/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "product_socks_target.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct { product_socks_target_t t; product_http_request_t r[4]; unsigned n; int last; } run_t;

static void client (run_t *x, const void *bytes, size_t length, size_t step)
{
  const uint8_t *p = bytes;
  for (size_t at = 0; at < length; at += step)
    {
      size_t n = length - at < step ? length - at : step, consumed = 0;
      product_http_request_t request;
      x->last = product_socks_target_client (&x->t, p + at, n, &consumed, &request);
      if (x->last == PRODUCT_HTTP_FEED_REQUEST) x->r[x->n++] = request;
      if (x->last == PRODUCT_HTTP_FEED_STOPPED) return;
    }
}
static void server (run_t *x, const void *bytes, size_t length)
{
  product_http_request_t request;
  for (size_t at = 0; at < length; ++at)
    {
      x->last = product_socks_target_server (&x->t, (const uint8_t *) bytes + at, 1, &request);
      if (x->last == PRODUCT_HTTP_FEED_REQUEST) x->r[x->n++] = request;
    }
}

static const uint8_t S4[] = {4, 1, 0x1f, 0x90, 192, 0, 2, 7, 'u', 's', 'e', 'r', 0};
static const uint8_t S4A[] = {4, 1, 0x00, 0x50, 0, 0, 0, 1, 0, 'W', 'w', 'w', '.', 'E', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'T', 'e', 's', 't', 0};
static const uint8_t S5_GREETING_NOAUTH[] = {5, 1, 0};
static const uint8_t S5_GREETING_BOTH[] = {5, 2, 0, 2};
static const uint8_t S5_AUTH[] = {1, 4, 'n', 'a', 'm', 'e', 6, 's', 'e', 'c', 'r', 'e', 't'};
static const uint8_t S5_DOMAIN[] = {5, 1, 0, 3, 14, 'p', 'r', 'o', 'x', 'i', 'e', 'd', '.', 'h', 't', 't', 'p', '.', 't', 0x01, 0xbb};
static const uint8_t S5_IPV6[] = {5, 1, 0, 4, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53, 0, 80};
static const uint8_t S5_IPV4[] = {5, 1, 0, 1, 198, 51, 100, 9, 0, 22};

static void socks4_and_4a (void)
{
  for (size_t step = 1; step <= sizeof (S4); ++step)
    {
      run_t x; product_socks_target_init (&x.t, 4); x.n = 0;
      client (&x, S4, sizeof (S4), step);
      assert (x.n == 1 && x.r[0].kind == PRODUCT_HTTP_TARGET_IPV4 && x.r[0].port == 8080 && x.r[0].connect);
      assert (x.r[0].address[0] == 192 && x.r[0].address[3] == 7 && x.t.stop == PRODUCT_SOCKS_STOP_TUNNEL && !x.t.socks4a);
      server (&x, "\x00\x5a\x00\x00\x00\x00\x00\x00", 8);
      assert (x.t.confirmed && x.n == 1);
    }
  for (size_t step = 1; step <= sizeof (S4A); ++step)
    {
      run_t x; product_socks_target_init (&x.t, 4); x.n = 0;
      client (&x, S4A, sizeof (S4A), step);
      assert (x.n == 1 && x.r[0].kind == PRODUCT_HTTP_TARGET_NAME && !strcmp (x.r[0].name, "www.example.test"));
      assert (x.r[0].port == 80 && x.t.socks4a);
    }
  /* BIND names the peer the client expects, not a connect target. */
  uint8_t bind[sizeof (S4)]; memcpy (bind, S4, sizeof (S4)); bind[1] = 2;
  run_t x; product_socks_target_init (&x.t, 4); x.n = 0;
  client (&x, bind, sizeof (bind), 3);
  assert (x.n == 1 && x.r[0].kind == PRODUCT_HTTP_TARGET_NONE && x.r[0].reason == PRODUCT_HTTP_TARGET_COMMAND && !x.r[0].connect);
  /* 0.0.0.0 is not a valid SOCKS4 destination. */
  uint8_t zero[sizeof (S4)]; memcpy (zero, S4, sizeof (S4)); memset (zero + 4, 0, 4);
  product_socks_target_init (&x.t, 4); x.n = 0;
  client (&x, zero, sizeof (zero), sizeof (zero));
  assert (x.n == 1 && x.r[0].reason == PRODUCT_HTTP_TARGET_BAD_AUTHORITY);
  /* Port 0 and an invalid 4a name are reported without a target. */
  uint8_t port0[sizeof (S4)]; memcpy (port0, S4, sizeof (S4)); port0[2] = port0[3] = 0;
  product_socks_target_init (&x.t, 4); x.n = 0;
  client (&x, port0, sizeof (port0), 5);
  assert (x.n == 1 && x.r[0].kind == PRODUCT_HTTP_TARGET_NONE && x.r[0].reason == PRODUCT_HTTP_TARGET_BAD_AUTHORITY);
  uint8_t bad[] = {4, 1, 0, 80, 0, 0, 0, 1, 0, 'b', 'a', 'd', ' ', 'h', 0};
  product_socks_target_init (&x.t, 4); x.n = 0;
  client (&x, bad, sizeof (bad), 2);
  assert (x.n == 1 && x.r[0].reason == PRODUCT_HTTP_TARGET_BAD_AUTHORITY);
  uint8_t hostport[] = {4, 1, 0, 80, 0, 0, 0, 1, 0, 'a', '.', 't', 'e', 's', 't', ':', '9', 0};
  product_socks_target_init (&x.t, 4); x.n = 0;
  client (&x, hostport, sizeof (hostport), 4);
  assert (x.n == 1 && x.r[0].reason == PRODUCT_HTTP_TARGET_BAD_AUTHORITY);
}

static void socks5_negotiation (void)
{
  /* No-auth: greeting, the server's selection, then the request with a domain name. */
  for (size_t step = 1; step <= sizeof (S5_DOMAIN); ++step)
    {
      run_t x; product_socks_target_init (&x.t, 5); x.n = 0;
      client (&x, S5_GREETING_NOAUTH, sizeof (S5_GREETING_NOAUTH), step);
      assert (!x.n && !x.t.confirmed);
      server (&x, "\x05\x00", 2);
      assert (x.t.confirmed && !x.n);
      client (&x, S5_DOMAIN, sizeof (S5_DOMAIN), step);
      assert (x.n == 1 && x.r[0].kind == PRODUCT_HTTP_TARGET_NAME && !strcmp (x.r[0].name, "proxied.http.t"));
      assert (x.r[0].port == 443 && x.t.stop == PRODUCT_SOCKS_STOP_TUNNEL);
    }
  /* Username/password: credentials are skipped and never kept. */
  run_t x; product_socks_target_init (&x.t, 5); x.n = 0;
  client (&x, S5_GREETING_BOTH, sizeof (S5_GREETING_BOTH), 1);
  server (&x, "\x05\x02", 2);
  client (&x, S5_AUTH, sizeof (S5_AUTH), 3);
  assert (!x.n && !memmem (x.t.buffer, sizeof (x.t.buffer), "secret", 6));
  server (&x, "\x01\x00", 2);
  client (&x, S5_IPV6, sizeof (S5_IPV6), 5);
  assert (x.n == 1 && x.r[0].kind == PRODUCT_HTTP_TARGET_IPV6 && x.r[0].address[15] == 0x53 && x.r[0].port == 80);
  /* An optimistic client sends greeting and request together: judged once the server selects. */
  product_socks_target_init (&x.t, 5); x.n = 0;
  uint8_t both[sizeof (S5_GREETING_NOAUTH) + sizeof (S5_IPV4)];
  memcpy (both, S5_GREETING_NOAUTH, sizeof (S5_GREETING_NOAUTH));
  memcpy (both + sizeof (S5_GREETING_NOAUTH), S5_IPV4, sizeof (S5_IPV4));
  client (&x, both, sizeof (both), sizeof (both));
  assert (!x.n);
  server (&x, "\x05\x00", 2);
  assert (x.n == 1 && x.r[0].kind == PRODUCT_HTTP_TARGET_IPV4 && x.r[0].address[0] == 198 && x.r[0].port == 22);
  /* The server's selection arriving before the greeting finishes is applied when it completes. */
  product_socks_target_init (&x.t, 5); x.n = 0;
  client (&x, S5_GREETING_NOAUTH, 1, 1);
  server (&x, "\x05\x00", 2);
  client (&x, S5_GREETING_NOAUTH + 1, 2, 1);
  assert (x.t.confirmed);
  client (&x, S5_IPV4, sizeof (S5_IPV4), 2);
  assert (x.n == 1);
  /* UDP ASSOCIATE names the client's own datagram address: no target. */
  product_socks_target_init (&x.t, 5); x.n = 0;
  client (&x, S5_GREETING_NOAUTH, 3, 3); server (&x, "\x05\x00", 2);
  uint8_t udp[sizeof (S5_IPV4)]; memcpy (udp, S5_IPV4, sizeof (udp)); udp[1] = 3;
  client (&x, udp, sizeof (udp), sizeof (udp));
  assert (x.n == 1 && x.r[0].kind == PRODUCT_HTTP_TARGET_NONE && x.r[0].reason == PRODUCT_HTTP_TARGET_COMMAND);
}

static void refusals_and_stops (void)
{
  run_t x;
  /* No acceptable method, or a method not offered, ends parsing without a target. */
  product_socks_target_init (&x.t, 5); x.n = 0;
  client (&x, S5_GREETING_NOAUTH, 3, 3); server (&x, "\x05\xff", 2);
  assert (x.t.stop == PRODUCT_SOCKS_STOP_METHOD && !x.n);
  product_socks_target_init (&x.t, 5); x.n = 0;
  client (&x, S5_GREETING_NOAUTH, 3, 3); server (&x, "\x05\x02", 2);
  assert (x.t.stop == PRODUCT_SOCKS_STOP_METHOD);
  product_socks_target_init (&x.t, 5); x.n = 0;
  client (&x, "\x05\x01\x01", 3, 3); server (&x, "\x05\x01", 2);   /* GSSAPI */
  assert (x.t.stop == PRODUCT_SOCKS_STOP_METHOD);
  /* A server that does not speak SOCKS5 never confirms. */
  product_socks_target_init (&x.t, 5); x.n = 0;
  client (&x, S5_GREETING_NOAUTH, 3, 3); server (&x, "HT", 2);
  assert (x.t.stop == PRODUCT_SOCKS_STOP_NOT_SOCKS);
  /* Malformed requests. */
  const uint8_t *bad[] = {(const uint8_t *) "\x05\x01\x01\x01\x01\x02\x03\x04\x00\x50", (const uint8_t *) "\x05\x01\x00\x09\x00",
                          (const uint8_t *) "\x05\x01\x00\x03\x00\x00\x50", (const uint8_t *) "\x04\x01\x00\x50\x01\x02\x03\x04",
                          (const uint8_t *) "\x05\x04\x00\x01\x01\x02\x03\x04\x00\x50"};
  const size_t sizes[] = {10, 5, 7, 8, 10};
  const unsigned stops[] = {PRODUCT_SOCKS_STOP_MALFORMED, PRODUCT_SOCKS_STOP_MALFORMED, PRODUCT_SOCKS_STOP_MALFORMED,
                            PRODUCT_SOCKS_RUNNING, PRODUCT_SOCKS_STOP_MALFORMED};
  for (unsigned i = 0; i < 5; ++i)
    {
      unsigned version = bad[i][0];
      product_socks_target_init (&x.t, version); x.n = 0;
      if (version == 5) { client (&x, S5_GREETING_NOAUTH, 3, 3); server (&x, "\x05\x00", 2); }
      client (&x, bad[i], sizes[i], 1);
      assert (!x.n && x.t.stop == stops[i]);
    }
  /* Version byte that is not SOCKS. */
  product_socks_target_init (&x.t, 4); x.n = 0;
  client (&x, "\x04\x09\x00\x50\x01\x02\x03\x04\x00", 9, 9);
  assert (x.t.stop == PRODUCT_SOCKS_STOP_NOT_SOCKS);
  /* A user id above its bound. */
  uint8_t big[8 + 300 + 1]; memcpy (big, S4, 8); memset (big + 8, 'u', 300); big[308] = 0;
  product_socks_target_init (&x.t, 4); x.n = 0;
  client (&x, big, sizeof (big), 50);
  assert (x.t.stop == PRODUCT_SOCKS_STOP_LIMIT && !x.n);
  /* Loss and anything after the request are terminal. */
  product_socks_target_init (&x.t, 4); x.n = 0;
  client (&x, S4, 4, 4); product_socks_target_lost (&x.t);
  assert (x.t.stop == PRODUCT_SOCKS_STOP_SEQUENCE);
  product_socks_target_init (&x.t, 4); x.n = 0;
  client (&x, S4, sizeof (S4), sizeof (S4));
  client (&x, S4, sizeof (S4), sizeof (S4));
  assert (x.n == 1 && x.last == PRODUCT_HTTP_FEED_STOPPED);
}

int main (void)
{
  socks4_and_4a ();
  socks5_negotiation ();
  refusals_and_stops ();
  puts ("SOCKS request target parser PASS");
  return 0;
}
