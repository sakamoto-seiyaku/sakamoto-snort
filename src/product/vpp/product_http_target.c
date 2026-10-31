/* SPDX-License-Identifier: Apache-2.0 */
#include "product_http_target.h"
#include <arpa/inet.h>
#include <string.h>
#include <strings.h>

enum { S_HEAD, S_BODY, S_CHUNK_SIZE, S_CHUNK_DATA, S_CHUNK_CRLF, S_TRAILERS, S_STOPPED };
#define CHUNK_LINE_BYTES 256U
#define METHOD_BYTES 16U

void product_http_target_init (product_http_target_t *t)
{ memset (t, 0, sizeof (*t)); t->state = S_HEAD; }

static int stop (product_http_target_t *t, unsigned reason)
{
  t->state = S_STOPPED;
  if (!t->stop) t->stop = (uint8_t) reason;
  return PRODUCT_HTTP_FEED_STOPPED;
}

void product_http_target_lost (product_http_target_t *t)
{ if (t->state != S_STOPPED) (void) stop (t, PRODUCT_HTTP_STOP_SEQUENCE); }

static int tchar (unsigned c)
{
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
    (c && strchr ("!#$%&'*+-.^_`|~", (int) c));
}

/* host [":" port], or "[" IPv6 "]" [":" port]. The bytes are not NUL terminated. */
static unsigned authority (const uint8_t *s, size_t n, product_http_request_t *r)
{
  size_t host_end = n, port_at = 0;
  if (!n) return PRODUCT_HTTP_TARGET_BAD_AUTHORITY;
  if (s[0] == '[')
    {
      size_t close = 1;
      while (close < n && s[close] != ']') ++close;
      if (close == n || close == 1 || close - 1 >= 46) return PRODUCT_HTTP_TARGET_BAD_AUTHORITY;
      char text[48];
      memcpy (text, s + 1, close - 1); text[close - 1] = 0;
      if (inet_pton (AF_INET6, text, r->address) != 1) return PRODUCT_HTTP_TARGET_BAD_AUTHORITY;
      r->kind = PRODUCT_HTTP_TARGET_IPV6;
      host_end = close + 1;
      if (host_end < n) { if (s[host_end] != ':') return PRODUCT_HTTP_TARGET_BAD_AUTHORITY; port_at = host_end + 1; }
    }
  else
    {
      for (size_t i = 0; i < n; ++i) if (s[i] == ':') { host_end = i; port_at = i + 1; break; }
      if (!host_end) return PRODUCT_HTTP_TARGET_BAD_AUTHORITY;
      size_t length = host_end;
      if (length && s[length - 1] == '.') --length;
      if (!length || length >= PRODUCT_HTTP_NAME_BYTES - 1) return PRODUCT_HTTP_TARGET_BAD_AUTHORITY;
      int numeric = 1, dots = 0;
      for (size_t i = 0; i < length; ++i)
        { if (s[i] == '.') ++dots; else if (s[i] < '0' || s[i] > '9') numeric = 0; }
      if (numeric && dots)
        {
          char text[20];
          if (length >= sizeof (text)) return PRODUCT_HTTP_TARGET_BAD_AUTHORITY;
          memcpy (text, s, length); text[length] = 0;
          if (dots != 3 || inet_pton (AF_INET, text, r->address) != 1) return PRODUCT_HTTP_TARGET_BAD_AUTHORITY;
          r->kind = PRODUCT_HTTP_TARGET_IPV4;
        }
      else
        {
          unsigned label = 0, previous = 0;
          for (size_t i = 0; i < length; ++i)
            {
              unsigned c = s[i];
              if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
              if (c == '.')
                { if (!label || previous == '-') return PRODUCT_HTTP_TARGET_BAD_AUTHORITY; label = 0; }
              else
                {
                  if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') ||
                      (!label && c == '-') || ++label > 63) return PRODUCT_HTTP_TARGET_BAD_AUTHORITY;
                }
              r->name[i] = (char) c; previous = c;
            }
          if (!label || previous == '-') return PRODUCT_HTTP_TARGET_BAD_AUTHORITY;
          r->name[length] = 0; r->name_length = (uint16_t) length;
          r->kind = PRODUCT_HTTP_TARGET_NAME;
        }
    }
  if (port_at)
    {
      size_t digits = n - port_at;
      unsigned value = 0;
      if (!digits || digits > 5) { r->kind = 0; return PRODUCT_HTTP_TARGET_BAD_AUTHORITY; }
      for (size_t i = port_at; i < n; ++i)
        {
          if (s[i] < '0' || s[i] > '9') { r->kind = 0; return PRODUCT_HTTP_TARGET_BAD_AUTHORITY; }
          value = value * 10 + (s[i] - '0');
        }
      if (!value || value > 65535) { r->kind = 0; return PRODUCT_HTTP_TARGET_BAD_AUTHORITY; }
      r->port = (uint16_t) value;
    }
  return PRODUCT_HTTP_TARGET_OK;
}

static int word_is (const uint8_t *s, size_t n, const char *word)
{ return strlen (word) == n && !strncasecmp ((const char *) s, word, n); }

/* Comma separated token list contains `word`. */
static int list_has (const uint8_t *s, size_t n, const char *word)
{
  size_t at = 0;
  while (at < n)
    {
      while (at < n && (s[at] == ' ' || s[at] == '\t' || s[at] == ',')) ++at;
      size_t start = at;
      while (at < n && s[at] != ',' && s[at] != ' ' && s[at] != '\t') ++at;
      if (at > start && word_is (s + start, at - start, word)) return 1;
    }
  return 0;
}

typedef struct {
  const uint8_t *host; size_t host_length;
  int hosts, has_length, chunked, upgrade, connection_upgrade, bad_framing;
  uint64_t length;
} fields_t;

/* One complete head, request-line through the blank line. */
static int parse_head (product_http_target_t *t, const uint8_t *h, size_t n, product_http_request_t *r)
{
  size_t line_end = 0;
  while (line_end + 1 < n && !(h[line_end] == '\r' && h[line_end + 1] == '\n')) ++line_end;
  size_t at = 0;
  while (at < line_end && tchar (h[at])) ++at;
  size_t method_length = at;
  if (!method_length || method_length > METHOD_BYTES || at >= line_end || h[at] != ' ')
    return stop (t, t->requests ? PRODUCT_HTTP_STOP_MALFORMED : PRODUCT_HTTP_STOP_NOT_HTTP);
  const uint8_t *method = h;
  ++at;
  size_t target_at = at;
  while (at < line_end && h[at] > 0x20 && h[at] < 0x7f) ++at;
  size_t target_length = at - target_at;
  if (!target_length || at >= line_end || h[at] != ' ' || line_end - at != 9 ||
      memcmp (h + at + 1, "HTTP/1.", 7))
    {
      if (line_end - at == 9 && at < line_end && h[at] == ' ' && !memcmp (h + at + 1, "HTTP/", 5))
        return stop (t, PRODUCT_HTTP_STOP_VERSION);
      return stop (t, t->requests ? PRODUCT_HTTP_STOP_MALFORMED : PRODUCT_HTTP_STOP_NOT_HTTP);
    }
  if (h[at + 8] != '0' && h[at + 8] != '1') return stop (t, PRODUCT_HTTP_STOP_VERSION);
  const uint8_t *target = h + target_at;

  fields_t f = {0};
  unsigned count = 0;
  size_t line = line_end + 2;
  while (line + 2 <= n && !(h[line] == '\r' && h[line + 1] == '\n'))
    {
      size_t end = line;
      while (end + 1 < n && !(h[end] == '\r' && h[end + 1] == '\n')) ++end;
      if (end + 1 >= n) return stop (t, PRODUCT_HTTP_STOP_MALFORMED);
      if (h[line] == ' ' || h[line] == '\t') return stop (t, PRODUCT_HTTP_STOP_MALFORMED); /* obs-fold */
      size_t colon = line;
      while (colon < end && h[colon] != ':') ++colon;
      if (colon == line || colon == end) return stop (t, PRODUCT_HTTP_STOP_MALFORMED);
      for (size_t i = line; i < colon; ++i) if (!tchar (h[i])) return stop (t, PRODUCT_HTTP_STOP_MALFORMED);
      for (size_t i = colon + 1; i < end; ++i)
        if ((h[i] < 0x20 && h[i] != '\t') || h[i] == 0x7f) return stop (t, PRODUCT_HTTP_STOP_MALFORMED);
      if (++count > PRODUCT_HTTP_FIELDS) return stop (t, PRODUCT_HTTP_STOP_HEAD_LIMIT);
      const uint8_t *name = h + line, *value = h + colon + 1;
      size_t name_length = colon - line, value_length = end - colon - 1;
      while (value_length && (*value == ' ' || *value == '\t')) { ++value; --value_length; }
      while (value_length && (value[value_length - 1] == ' ' || value[value_length - 1] == '\t')) --value_length;
      if (word_is (name, name_length, "host"))
        { ++f.hosts; f.host = value; f.host_length = value_length; }
      else if (word_is (name, name_length, "content-length"))
        {
          uint64_t v = 0;
          if (f.has_length || !value_length || value_length > 15) f.bad_framing = 1;
          for (size_t i = 0; i < value_length && !f.bad_framing; ++i)
            { if (value[i] < '0' || value[i] > '9') f.bad_framing = 1; else v = v * 10 + (value[i] - '0'); }
          f.has_length = 1; f.length = v;
        }
      else if (word_is (name, name_length, "transfer-encoding"))
        { if (f.chunked || !word_is (value, value_length, "chunked")) f.bad_framing = 1; f.chunked = 1; }
      else if (word_is (name, name_length, "connection"))
        { if (list_has (value, value_length, "upgrade")) f.connection_upgrade = 1; }
      else if (word_is (name, name_length, "upgrade"))
        f.upgrade = 1;
      line = end + 2;
    }

  memset (r, 0, sizeof (*r));
  r->index = t->requests++;
  r->connect = word_is (method, method_length, "CONNECT");
  if (r->connect)
    {
      unsigned why = authority (target, target_length, r);
      if (why) { r->kind = 0; r->reason = (uint8_t) why; }
      else if (!r->port) { r->kind = 0; r->reason = PRODUCT_HTTP_TARGET_BAD_AUTHORITY; }
    }
  else if (target[0] == '/' || (target_length == 1 && target[0] == '*'))
    {
      if (target[0] == '*' && !word_is (method, method_length, "OPTIONS")) r->reason = PRODUCT_HTTP_TARGET_FORM;
      else if (!f.hosts) r->reason = PRODUCT_HTTP_TARGET_NO_HOST;
      else if (f.hosts > 1) r->reason = PRODUCT_HTTP_TARGET_DUPLICATE_HOST;
      else
        {
          r->via_host_field = 1;
          unsigned why = authority (f.host, f.host_length, r);
          if (why) { r->kind = 0; r->reason = (uint8_t) why; }
        }
    }
  else
    {
      size_t scheme = 0;
      while (scheme < target_length && target[scheme] != ':' && target[scheme] != '/') ++scheme;
      if (scheme + 2 < target_length && target[scheme] == ':' && target[scheme + 1] == '/' && target[scheme + 2] == '/')
        {
          if (!word_is (target, scheme, "http")) r->reason = PRODUCT_HTTP_TARGET_SCHEME;
          else
            {
              size_t start = scheme + 3, end = start;
              while (end < target_length && target[end] != '/' && target[end] != '?' && target[end] != '#') ++end;
              int userinfo = 0;
              for (size_t i = start; i < end; ++i) if (target[i] == '@') userinfo = 1;
              unsigned why = userinfo ? PRODUCT_HTTP_TARGET_USERINFO : authority (target + start, end - start, r);
              if (why) { r->kind = 0; r->reason = (uint8_t) why; }
            }
        }
      else r->reason = PRODUCT_HTTP_TARGET_FORM;
    }

  if (f.bad_framing || (f.has_length && f.chunked)) { stop (t, PRODUCT_HTTP_STOP_FRAMING); return PRODUCT_HTTP_FEED_REQUEST; }
  if (r->connect || (f.upgrade && f.connection_upgrade)) { stop (t, PRODUCT_HTTP_STOP_TUNNEL); return PRODUCT_HTTP_FEED_REQUEST; }
  t->head_length = 0; t->line_length = 0; t->stray = 0;
  if (f.chunked) t->state = S_CHUNK_SIZE, t->body_remaining = 0;
  else if (f.has_length && f.length) t->state = S_BODY, t->body_remaining = f.length;
  else t->state = S_HEAD;
  return PRODUCT_HTTP_FEED_REQUEST;
}

int product_http_target_feed (product_http_target_t *t, uint8_t head[PRODUCT_HTTP_HEAD_BYTES],
  const uint8_t *bytes, size_t length, size_t *consumed, product_http_request_t *request)
{
  size_t at = 0;
  int result = PRODUCT_HTTP_FEED_MORE;
  if (consumed) *consumed = 0;
  if (!t || !head || (!bytes && length) || !request) return PRODUCT_HTTP_FEED_STOPPED;
  if (t->state == S_STOPPED) { if (consumed) *consumed = length; return PRODUCT_HTTP_FEED_STOPPED; }
  while (at < length && result == PRODUCT_HTTP_FEED_MORE)
    {
      unsigned c = bytes[at];
      switch (t->state)
        {
        case S_HEAD:
          if (!t->head_length)
            {
              /* A single stray CRLF may precede a request line (RFC 9112 2.2). */
              if ((c == '\r' || c == '\n') && t->requests && t->stray < PRODUCT_HTTP_STRAY_LINE_BYTES)
                { ++t->stray; ++at; continue; }
              if (!(c >= 'A' && c <= 'Z'))
                { result = stop (t, t->requests ? PRODUCT_HTTP_STOP_MALFORMED : PRODUCT_HTTP_STOP_NOT_HTTP); break; }
            }
          if (t->head_length == PRODUCT_HTTP_HEAD_BYTES)
            { result = stop (t, PRODUCT_HTTP_STOP_HEAD_LIMIT); break; }
          head[t->head_length++] = (uint8_t) c; ++at;
          if (c == '\n' && t->head_length >= 4 && !memcmp (head + t->head_length - 4, "\r\n\r\n", 4))
            result = parse_head (t, head, t->head_length, request);
          else if (c == '\n' && !t->line_length)
            {
              /* First line complete: refuse a non-HTTP stream before buffering any more of it. */
              t->line_length = t->head_length;
              if (t->head_length < 12 || head[t->head_length - 2] != '\r' || memcmp (head + t->head_length - 11, " HTTP/", 6))
                result = stop (t, t->requests ? PRODUCT_HTTP_STOP_MALFORMED : PRODUCT_HTTP_STOP_NOT_HTTP);
            }
          break;
        case S_BODY:
          {
            size_t take = length - at;
            if (take > t->body_remaining) take = (size_t) t->body_remaining;
            at += take; t->body_remaining -= take;
            if (!t->body_remaining) t->state = S_HEAD;
            break;
          }
        case S_CHUNK_SIZE:
          ++at;
          if (c == '\n')
            {
              if (!t->prev_cr || !t->chunk_digits) { result = stop (t, PRODUCT_HTTP_STOP_FRAMING); break; }
              t->line_length = 0; t->chunk_digits = 0; t->in_extension = 0; t->prev_cr = 0;
              t->trailer_bytes = 0;
              t->state = t->body_remaining ? S_CHUNK_DATA : S_TRAILERS;
              break;
            }
          if (++t->line_length > CHUNK_LINE_BYTES || t->prev_cr) { result = stop (t, PRODUCT_HTTP_STOP_FRAMING); break; }
          if (c == '\r') t->prev_cr = 1;
          else if (t->in_extension) { /* chunk extensions are skipped */ }
          else if (c == ';') t->in_extension = 1;
          else
            {
              int hex = c >= '0' && c <= '9' ? (int) (c - '0') : c >= 'a' && c <= 'f' ? (int) (c - 'a' + 10) :
                c >= 'A' && c <= 'F' ? (int) (c - 'A' + 10) : -1;
              if (hex < 0 || t->chunk_digits >= 8) { result = stop (t, PRODUCT_HTTP_STOP_FRAMING); break; }
              t->body_remaining = t->body_remaining * 16 + (unsigned) hex; ++t->chunk_digits;
            }
          break;
        case S_CHUNK_DATA:
          {
            size_t take = length - at;
            if (take > t->body_remaining) take = (size_t) t->body_remaining;
            at += take; t->body_remaining -= take;
            if (!t->body_remaining) { t->state = S_CHUNK_CRLF; t->line_length = 0; }
            break;
          }
        case S_CHUNK_CRLF:
          if ((t->line_length == 0 && c == '\r') || (t->line_length == 1 && c == '\n'))
            {
              ++at;
              if (++t->line_length == 2) { t->state = S_CHUNK_SIZE; t->line_length = 0; t->body_remaining = 0; }
            }
          else result = stop (t, PRODUCT_HTTP_STOP_FRAMING);
          break;
        case S_TRAILERS:
          /* Trailer fields are skipped up to the blank line. */
          ++at;
          if (++t->trailer_bytes > PRODUCT_HTTP_TRAILER_BYTES) { result = stop (t, PRODUCT_HTTP_STOP_FRAMING); break; }
          if (c == '\n')
            {
              if (t->line_length == 1 && t->prev_cr)
                { t->state = S_HEAD; t->head_length = 0; t->line_length = 0; t->trailer_bytes = 0; t->stray = 0; }
              else t->line_length = 0;
              t->prev_cr = 0;
            }
          else { t->prev_cr = c == '\r'; ++t->line_length; }
          break;
        default:
          result = PRODUCT_HTTP_FEED_STOPPED;
        }
    }
  if (consumed) *consumed = at;
  if (result == PRODUCT_HTTP_FEED_MORE && t->state == S_STOPPED) result = PRODUCT_HTTP_FEED_STOPPED;
  return result;
}
