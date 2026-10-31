/* SPDX-License-Identifier: Apache-2.0 */
#include "product_socks_target.h"
#include <string.h>

/* RFC 1928 (SOCKS5), RFC 1929 (username/password), SOCKS4 and the SOCKS4a extension. */
enum { S4_REQUEST = 1, S5_GREETING, S5_METHOD, S5_AUTH, S5_REQUEST, S_DONE, S_STOPPED };

void product_socks_target_init (product_socks_target_t *t, unsigned version)
{
  memset (t, 0, sizeof (*t));
  t->version = (uint8_t) version;
  t->state = version == 4 ? S4_REQUEST : version == 5 ? S5_GREETING : S_STOPPED;
  if (t->state == S_STOPPED) t->stop = PRODUCT_SOCKS_STOP_NOT_SOCKS;
}

static int stop (product_socks_target_t *t, unsigned reason)
{
  if (!t->stop) t->stop = (uint8_t) reason;
  t->state = S_STOPPED;
  return PRODUCT_HTTP_FEED_STOPPED;
}

void product_socks_target_lost (product_socks_target_t *t)
{ if (t->state != S_STOPPED && t->state != S_DONE) (void) stop (t, PRODUCT_SOCKS_STOP_SEQUENCE); }

static void drop_front (product_socks_target_t *t, size_t n)
{
  memmove (t->buffer, t->buffer + n, t->length - n);
  t->length = (uint16_t) (t->length - n);
  memset (t->buffer + t->length, 0, n);   /* consumed bytes (including credentials) are not kept */
}

static unsigned port_of (const uint8_t *p) { return ((unsigned) p[0] << 8) | p[1]; }

/* The request names its target; it never comes from the outer proxy endpoint. */
static void finish (product_socks_target_t *t, product_http_request_t *r, unsigned command, unsigned reason)
{
  r->index = t->requests++;
  r->connect = command == 1;
  t->command = (uint8_t) command;
  if (command != 1) { r->kind = PRODUCT_HTTP_TARGET_NONE; r->reason = PRODUCT_HTTP_TARGET_COMMAND; }
  else if (reason) { r->kind = PRODUCT_HTTP_TARGET_NONE; r->reason = (uint8_t) reason; }
  else if (!r->port) { r->kind = PRODUCT_HTTP_TARGET_NONE; r->reason = PRODUCT_HTTP_TARGET_BAD_AUTHORITY; }
  t->state = S_DONE;
  if (!t->stop) t->stop = PRODUCT_SOCKS_STOP_TUNNEL;
  memset (t->buffer, 0, sizeof (t->buffer)); t->length = 0;
}

/* 0 more bytes needed, 1 request reported, or a stop result. */
static int socks4 (product_socks_target_t *t, product_http_request_t *r)
{
  const uint8_t *b = t->buffer;
  size_t n = t->length;
  if (n < 9) return 0;
  if (b[0] != 4) return stop (t, PRODUCT_SOCKS_STOP_NOT_SOCKS);
  unsigned command = b[1];
  if (command != 1 && command != 2) return stop (t, PRODUCT_SOCKS_STOP_NOT_SOCKS);
  size_t user_end = 8;
  while (user_end < n && b[user_end]) ++user_end;
  if (user_end == n) return user_end - 8 > PRODUCT_SOCKS_FIELD_BYTES ? stop (t, PRODUCT_SOCKS_STOP_LIMIT) : 0;
  if (user_end - 8 > PRODUCT_SOCKS_FIELD_BYTES) return stop (t, PRODUCT_SOCKS_STOP_LIMIT);
  memset (r, 0, sizeof (*r));
  r->port = (uint16_t) port_of (b + 2);
  unsigned reason = 0;
  if (!b[4] && !b[5] && !b[6] && b[7])
    {
      /* SOCKS4a: 0.0.0.x with x != 0 means a host name follows the user id. */
      size_t host_at = user_end + 1, host_end = host_at;
      while (host_end < n && b[host_end]) ++host_end;
      if (host_end == n) return host_end - host_at > PRODUCT_SOCKS_FIELD_BYTES ? stop (t, PRODUCT_SOCKS_STOP_LIMIT) : 0;
      if (host_end - host_at > PRODUCT_SOCKS_FIELD_BYTES) return stop (t, PRODUCT_SOCKS_STOP_LIMIT);
      t->socks4a = 1;
      uint16_t port = r->port;
      reason = host_end == host_at ? PRODUCT_HTTP_TARGET_BAD_AUTHORITY
             : product_http_target_authority (b + host_at, host_end - host_at, r);
      if (r->port != port && !reason) reason = PRODUCT_HTTP_TARGET_BAD_AUTHORITY; /* "host:port" inside the name */
      r->port = port;
    }
  else
    {
      r->kind = PRODUCT_HTTP_TARGET_IPV4;
      memcpy (r->address, b + 4, 4);
      if (!b[4] && !b[5] && !b[6] && !b[7]) reason = PRODUCT_HTTP_TARGET_BAD_AUTHORITY;
    }
  finish (t, r, command, reason);
  return PRODUCT_HTTP_FEED_REQUEST;
}

static int socks5 (product_socks_target_t *t, product_http_request_t *r)
{
  for (;;)
    {
      const uint8_t *b = t->buffer;
      size_t n = t->length;
      if (t->state == S5_GREETING)
        {
          if (n < 2) return 0;
          if (b[0] != 5 || !b[1]) return stop (t, PRODUCT_SOCKS_STOP_NOT_SOCKS);
          if (n < 2U + b[1]) return 0;
          for (unsigned i = 0; i < b[1]; ++i)
            {
              if (b[2 + i] == 0) t->offered_no_auth = 1;
              if (b[2 + i] == 2) t->offered_password = 1;
            }
          t->only_no_auth = t->offered_no_auth && b[1] == 1;
          drop_front (t, 2U + b[1]);
          t->state = S5_METHOD;
          if (t->server_bytes < 2) return 0;
          /* The selection may already be known when the greeting was split. */
          if (t->server_version != 5) return stop (t, PRODUCT_SOCKS_STOP_NOT_SOCKS);
          if (t->method == 0 && t->offered_no_auth) t->state = S5_REQUEST;
          else if (t->method == 2 && t->offered_password) t->state = S5_AUTH;
          else return stop (t, PRODUCT_SOCKS_STOP_METHOD);
          t->confirmed = 1;
          continue;
        }
      if (t->state == S5_METHOD) return 0;   /* client bytes wait for the server's selection */
      if (t->state == S5_AUTH)
        {
          if (n < 2) return 0;
          if (b[0] != 1 || !b[1]) return stop (t, PRODUCT_SOCKS_STOP_MALFORMED);
          if (n < 3U + b[1]) return 0;
          unsigned password = b[2U + b[1]];
          if (n < 3U + b[1] + password) return 0;
          drop_front (t, 3U + b[1] + password);   /* credentials are never retained */
          t->state = S5_REQUEST;
          continue;
        }
      if (t->state != S5_REQUEST) return 0;
      if (n < 5) return 0;
      if (b[0] != 5 || b[2] != 0 || !b[1] || b[1] > 3) return stop (t, PRODUCT_SOCKS_STOP_MALFORMED);
      size_t need;
      if (b[3] == 1) need = 4 + 4 + 2;
      else if (b[3] == 4) need = 4 + 16 + 2;
      else if (b[3] == 3) { if (!b[4]) return stop (t, PRODUCT_SOCKS_STOP_MALFORMED); need = 5U + b[4] + 2; }
      else return stop (t, PRODUCT_SOCKS_STOP_MALFORMED);
      if (n < need) return 0;
      memset (r, 0, sizeof (*r));
      unsigned reason = 0;
      if (b[3] == 1) { r->kind = PRODUCT_HTTP_TARGET_IPV4; memcpy (r->address, b + 4, 4); }
      else if (b[3] == 4) { r->kind = PRODUCT_HTTP_TARGET_IPV6; memcpy (r->address, b + 4, 16); }
      else
        {
          reason = product_http_target_authority (b + 5, b[4], r);
          if (!reason && r->port) reason = PRODUCT_HTTP_TARGET_BAD_AUTHORITY;   /* a port inside the name */
        }
      r->port = (uint16_t) port_of (b + need - 2);
      finish (t, r, b[1], reason);
      return PRODUCT_HTTP_FEED_REQUEST;
    }
}

static int process (product_socks_target_t *t, product_http_request_t *r)
{
  int result = t->version == 4 ? socks4 (t, r) : socks5 (t, r);
  if (result == 0) return PRODUCT_HTTP_FEED_MORE;
  return result;
}

int product_socks_target_client (product_socks_target_t *t, const uint8_t *bytes, size_t length,
  size_t *consumed, product_http_request_t *request)
{
  if (consumed) *consumed = length;
  if (!t || (!bytes && length) || !request) return PRODUCT_HTTP_FEED_STOPPED;
  if (t->state == S_STOPPED || t->state == S_DONE) return PRODUCT_HTTP_FEED_STOPPED;
  size_t room = PRODUCT_SOCKS_BUFFER_BYTES - t->length, take = length < room ? length : room;
  memcpy (t->buffer + t->length, bytes, take);
  t->length = (uint16_t) (t->length + take);
  int result = process (t, request);
  if (result == PRODUCT_HTTP_FEED_MORE && (take < length || t->length == PRODUCT_SOCKS_BUFFER_BYTES))
    return stop (t, PRODUCT_SOCKS_STOP_LIMIT);
  return result;
}

int product_socks_target_server (product_socks_target_t *t, const uint8_t *bytes, size_t length,
  product_http_request_t *request)
{
  if (!t || (!bytes && length) || !request) return PRODUCT_HTTP_FEED_STOPPED;
  for (size_t i = 0; i < length && t->server_bytes < 2; ++i, ++t->server_bytes)
    {
      if (!t->server_bytes) t->server_version = bytes[i];
      else if (t->version == 5) t->method = bytes[i];
      else t->reply = bytes[i];
    }
  if (t->server_bytes < 2) return PRODUCT_HTTP_FEED_MORE;
  if (t->version == 4)
    {
      /* Confirmation only: the request was already judged when it was sent. */
      if (t->server_version == 0 && t->reply >= 0x5a && t->reply <= 0x5d) t->confirmed = 1;
      return PRODUCT_HTTP_FEED_MORE;
    }
  if (t->confirmed || t->state == S_STOPPED || t->state == S_DONE) return PRODUCT_HTTP_FEED_MORE;
  if (t->server_version != 5) return stop (t, PRODUCT_SOCKS_STOP_NOT_SOCKS);
  if (t->state == S5_GREETING) return PRODUCT_HTTP_FEED_MORE;   /* resumed when the greeting completes */
  if (t->state != S5_METHOD) return PRODUCT_HTTP_FEED_MORE;
  if (t->method == 0 && t->offered_no_auth) t->state = S5_REQUEST;
  else if (t->method == 2 && t->offered_password) t->state = S5_AUTH;
  else return stop (t, PRODUCT_SOCKS_STOP_METHOD);
  t->confirmed = 1;
  return process (t, request);
}
