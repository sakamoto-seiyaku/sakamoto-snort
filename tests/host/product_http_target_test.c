/* SPDX-License-Identifier: Apache-2.0 */
#include "product_http_target.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { product_http_request_t r[16]; unsigned n; product_http_target_t t; uint8_t head[PRODUCT_HTTP_HEAD_BYTES]; } run_t;

/* Feed `text` in `step`-byte pieces, collecting every reported request. */
static void feed (run_t *run, const char *text, size_t length, size_t step)
{
  for (size_t at = 0; at < length;)
    {
      size_t n = length - at < step ? length - at : step;
      while (n)
        {
          size_t consumed = 0;
          product_http_request_t request;
          int result = product_http_target_feed (&run->t, run->head, (const uint8_t *) text + at, n, &consumed, &request);
          assert (consumed <= n);
          if (result == PRODUCT_HTTP_FEED_REQUEST) { assert (run->n < 16); run->r[run->n++] = request; }
          at += consumed; n -= consumed;
          if (result == PRODUCT_HTTP_FEED_STOPPED) { at = length; break; }
          if (!consumed && result != PRODUCT_HTTP_FEED_REQUEST) { at += n; break; }
        }
    }
}
static run_t *fresh (void) { run_t *run = calloc (1, sizeof (*run)); product_http_target_init (&run->t); return run; }

static void expect_names (const char *text, size_t step, unsigned count, const char *const names[], unsigned stop)
{
  run_t *run = fresh ();
  feed (run, text, strlen (text), step);
  assert (run->n == count);
  for (unsigned i = 0; i < count; ++i)
    {
      assert (run->r[i].index == i);
      assert (run->r[i].kind == PRODUCT_HTTP_TARGET_NAME && !strcmp (run->r[i].name, names[i]));
      assert (run->r[i].name_length == strlen (names[i]));
    }
  assert (run->t.stop == stop);
  free (run);
}

static void every_split (const char *text, unsigned count, const char *const names[], unsigned stop)
{
  size_t length = strlen (text);
  for (size_t step = 1; step <= length; step += step < 8 ? 1 : 13) expect_names (text, step, count, names, stop);
  expect_names (text, length, count, names, stop);
}

static void forms (void)
{
  every_split ("GET /a HTTP/1.1\r\nHost: Example.COM\r\n\r\n", 1, (const char *[]){"example.com"}, 0);
  every_split ("GET http://proxy.test/a?b=1 HTTP/1.1\r\nHost: ignored.test\r\n\r\n", 1, (const char *[]){"proxy.test"}, 0);
  every_split ("GET HTTP://UPPER.test:8080/ HTTP/1.0\r\n\r\n", 1, (const char *[]){"upper.test"}, 0);
  every_split ("OPTIONS * HTTP/1.1\r\nHost: star.test\r\n\r\n", 1, (const char *[]){"star.test"}, 0);
  every_split ("GET /x HTTP/1.1\r\nHost: dot.test.\r\n\r\n", 1, (const char *[]){"dot.test"}, 0);
  every_split ("GET /x HTTP/1.1\r\nHost: under_score.test:81\r\n\r\n", 1, (const char *[]){"under_score.test"}, 0);
  run_t *run = fresh ();
  const char *text = "GET /x HTTP/1.1\r\nHost: dot.test:81\r\n\r\n";
  feed (run, text, strlen (text), 3);
  assert (run->r[0].port == 81 && run->r[0].via_host_field);
  free (run);
  run = fresh ();
  text = "GET http://abs.test/ HTTP/1.1\r\nHost: other.test\r\n\r\n";
  feed (run, text, strlen (text), 100);
  assert (!run->r[0].via_host_field);
  free (run);
}

static void ip_targets (void)
{
  run_t *run = fresh ();
  const char *text = "GET /x HTTP/1.1\r\nHost: 192.0.2.7:8080\r\n\r\nGET http://[2001:db8::53]:81/ HTTP/1.1\r\n\r\n";
  feed (run, text, strlen (text), 5);
  assert (run->n == 2);
  assert (run->r[0].kind == PRODUCT_HTTP_TARGET_IPV4 && run->r[0].address[0] == 192 && run->r[0].address[3] == 7 && run->r[0].port == 8080);
  assert (run->r[1].kind == PRODUCT_HTTP_TARGET_IPV6 && run->r[1].address[0] == 0x20 && run->r[1].address[15] == 0x53 && run->r[1].port == 81);
  free (run);
}

static void unavailable (const char *text, unsigned reason, unsigned stop)
{
  run_t *run = fresh ();
  feed (run, text, strlen (text), 1);
  assert (run->n == 1 && run->r[0].kind == PRODUCT_HTTP_TARGET_NONE && run->r[0].reason == reason);
  assert (run->t.stop == stop);
  free (run);
}

static void targets_that_are_not_usable (void)
{
  unavailable ("GET /x HTTP/1.1\r\n\r\n", PRODUCT_HTTP_TARGET_NO_HOST, 0);
  unavailable ("GET /x HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\n\r\n", PRODUCT_HTTP_TARGET_DUPLICATE_HOST, 0);
  unavailable ("GET /x HTTP/1.1\r\nHost: bad host.test\r\n\r\n", PRODUCT_HTTP_TARGET_BAD_AUTHORITY, 0);
  unavailable ("GET /x HTTP/1.1\r\nHost: a.test:0\r\n\r\n", PRODUCT_HTTP_TARGET_BAD_AUTHORITY, 0);
  unavailable ("GET /x HTTP/1.1\r\nHost: a.test:99999\r\n\r\n", PRODUCT_HTTP_TARGET_BAD_AUTHORITY, 0);
  unavailable ("GET /x HTTP/1.1\r\nHost: user@a.test\r\n\r\n", PRODUCT_HTTP_TARGET_BAD_AUTHORITY, 0);
  unavailable ("GET /x HTTP/1.1\r\nHost: -a.test\r\n\r\n", PRODUCT_HTTP_TARGET_BAD_AUTHORITY, 0);
  unavailable ("GET /x HTTP/1.1\r\nHost: a..test\r\n\r\n", PRODUCT_HTTP_TARGET_BAD_AUTHORITY, 0);
  unavailable ("GET /x HTTP/1.1\r\nHost: 1.2.3\r\n\r\n", PRODUCT_HTTP_TARGET_BAD_AUTHORITY, 0);
  unavailable ("GET /x HTTP/1.1\r\nHost: 999.1.1.1\r\n\r\n", PRODUCT_HTTP_TARGET_BAD_AUTHORITY, 0);
  unavailable ("GET /x HTTP/1.1\r\nHost:\r\n\r\n", PRODUCT_HTTP_TARGET_BAD_AUTHORITY, 0);
  unavailable ("GET http://user:pw@a.test/ HTTP/1.1\r\n\r\n", PRODUCT_HTTP_TARGET_USERINFO, 0);
  unavailable ("GET https://a.test/ HTTP/1.1\r\n\r\n", PRODUCT_HTTP_TARGET_SCHEME, 0);
  unavailable ("GET ftp://a.test/ HTTP/1.1\r\n\r\n", PRODUCT_HTTP_TARGET_SCHEME, 0);
  unavailable ("GET a.test:80 HTTP/1.1\r\nHost: b.test\r\n\r\n", PRODUCT_HTTP_TARGET_FORM, 0);
  unavailable ("GET * HTTP/1.1\r\nHost: b.test\r\n\r\n", PRODUCT_HTTP_TARGET_FORM, 0);
}

static void each_request_has_its_own_target (void)
{
  /* Content-Length, chunked (with extension and trailer) and a body-less request, pipelined. */
  const char *text =
    "POST /a HTTP/1.1\r\nHost: one.test\r\nContent-Length: 5\r\n\r\nhello"
    "POST /b HTTP/1.1\r\nHost: two.test\r\nTransfer-Encoding: chunked\r\n\r\n"
    "5;ext=1\r\nhello\r\nA\r\n0123456789\r\n0\r\nX-Trailer: v\r\n\r\n"
    "\r\nGET /c HTTP/1.1\r\nHost: three.test\r\n\r\n"
    "GET http://four.test/ HTTP/1.1\r\n\r\n";
  every_split (text, 4, (const char *[]){"one.test", "two.test", "three.test", "four.test"}, 0);
  /* A body that merely looks like a request is skipped, never parsed. */
  text = "POST /a HTTP/1.1\r\nHost: one.test\r\nContent-Length: 38\r\n\r\nGET /evil HTTP/1.1\r\nHost: evil.test\r\n\r\n"
         "GET /b HTTP/1.1\r\nHost: two.test\r\n\r\n";
  every_split (text, 2, (const char *[]){"one.test", "two.test"}, 0);
}

static void stops (const char *text, unsigned count, unsigned stop)
{
  run_t *run = fresh ();
  feed (run, text, strlen (text), 1);
  assert (run->n == count && run->t.stop == stop);
  /* Later bytes never reopen a stopped connection. */
  size_t consumed = 0; product_http_request_t request;
  assert (product_http_target_feed (&run->t, run->head, (const uint8_t *) "GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n", 10, &consumed, &request) == PRODUCT_HTTP_FEED_STOPPED);
  assert (run->n == count);
  free (run);
}

static void connection_level_stops (void)
{
  stops ("\x16\x03\x01\x02\x00 not a request", 0, PRODUCT_HTTP_STOP_NOT_HTTP);
  stops ("SSH-2.0-OpenSSH_9\r\n", 0, PRODUCT_HTTP_STOP_NOT_HTTP);
  stops ("get /x HTTP/1.1\r\n\r\n", 0, PRODUCT_HTTP_STOP_NOT_HTTP);
  stops ("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 0, PRODUCT_HTTP_STOP_VERSION);
  stops ("GET /x HTTP/1.1\r\nbad field\r\n\r\n", 0, PRODUCT_HTTP_STOP_MALFORMED);
  stops ("GET /x HTTP/1.1\r\n folded: x\r\n\r\n", 0, PRODUCT_HTTP_STOP_MALFORMED);
  stops ("GET /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n", 1, PRODUCT_HTTP_STOP_FRAMING);
  stops ("POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n", 1, PRODUCT_HTTP_STOP_FRAMING);
  stops ("POST /x HTTP/1.1\r\nHost: a.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", 1, PRODUCT_HTTP_STOP_FRAMING);
  stops ("POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: +1\r\n\r\n", 1, PRODUCT_HTTP_STOP_FRAMING);
  stops ("POST /x HTTP/1.1\r\nHost: a.test\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", 1, PRODUCT_HTTP_STOP_FRAMING);
  stops ("POST /x HTTP/1.1\r\nHost: a.test\r\nTransfer-Encoding: chunked\r\n\r\n111111111\r\n", 1, PRODUCT_HTTP_STOP_FRAMING);
  stops ("POST /x HTTP/1.1\r\nHost: a.test\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nab", 1, PRODUCT_HTTP_STOP_FRAMING);
  stops ("CONNECT secure.test:443 HTTP/1.1\r\nHost: secure.test:443\r\n\r\n", 1, PRODUCT_HTTP_STOP_TUNNEL);
  stops ("GET /ws HTTP/1.1\r\nHost: a.test\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n", 1, PRODUCT_HTTP_STOP_TUNNEL);
  stops ("GET /x HTTP/1.1\r\nHost: a.test\r\n\r\nxyz", 1, PRODUCT_HTTP_STOP_MALFORMED);
  run_t *run = fresh ();
  const char *text = "CONNECT secure.test:443 HTTP/1.1\r\nHost: secure.test:443\r\n\r\n";
  feed (run, text, strlen (text), 7);
  assert (run->r[0].connect && run->r[0].kind == PRODUCT_HTTP_TARGET_NAME && !strcmp (run->r[0].name, "secure.test") && run->r[0].port == 443);
  free (run);
  run = fresh ();
  text = "GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n";
  feed (run, text, 10, 3);
  product_http_target_lost (&run->t);
  assert (run->t.stop == PRODUCT_HTTP_STOP_SEQUENCE);
  free (run);
}

static void bounds (void)
{
  char *text = malloc (PRODUCT_HTTP_HEAD_BYTES * 2);
  size_t at = (size_t) snprintf (text, PRODUCT_HTTP_HEAD_BYTES * 2, "GET /x HTTP/1.1\r\nHost: a.test\r\nX-Pad: ");
  memset (text + at, 'a', PRODUCT_HTTP_HEAD_BYTES); at += PRODUCT_HTTP_HEAD_BYTES;
  memcpy (text + at, "\r\n\r\n", 4); at += 4;
  run_t *run = fresh ();
  feed (run, text, at, 97);
  assert (run->n == 0 && run->t.stop == PRODUCT_HTTP_STOP_HEAD_LIMIT);
  free (run);
  at = (size_t) snprintf (text, PRODUCT_HTTP_HEAD_BYTES * 2, "GET /x HTTP/1.1\r\nHost: a.test\r\n");
  for (unsigned i = 0; i < PRODUCT_HTTP_FIELDS + 1; ++i) at += (size_t) snprintf (text + at, PRODUCT_HTTP_HEAD_BYTES * 2 - at, "X-%u: v\r\n", i);
  memcpy (text + at, "\r\n", 2); at += 2;
  run = fresh ();
  feed (run, text, at, at);
  assert (run->n == 0 && run->t.stop == PRODUCT_HTTP_STOP_HEAD_LIMIT);
  free (run);
  /* A long body costs no memory: the parser only counts it. */
  run = fresh ();
  const char *head = "POST /x HTTP/1.1\r\nHost: big.test\r\nContent-Length: 1000000\r\n\r\n";
  feed (run, head, strlen (head), 1000);
  static char filler[100000];
  memset (filler, 'x', sizeof (filler));
  for (unsigned i = 0; i < 10; ++i) feed (run, filler, sizeof (filler), sizeof (filler));
  const char *next = "GET /y HTTP/1.1\r\nHost: after.test\r\n\r\n";
  feed (run, next, strlen (next), 4);
  assert (run->n == 2 && !strcmp (run->r[0].name, "big.test") && !strcmp (run->r[1].name, "after.test") && !run->t.stop);
  free (run);
  free (text);
}

int main (void)
{
  forms ();
  ip_targets ();
  targets_that_are_not_usable ();
  each_request_has_its_own_target ();
  connection_level_stops ();
  bounds ();
  puts ("HTTP request target parser PASS");
  return 0;
}
