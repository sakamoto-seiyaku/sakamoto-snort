/* SPDX-License-Identifier: Apache-2.0 */
#include "product_flow_entry.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
  product_flow_runtime_t *pool;
  product_owner_assignment_t owner;
  product_packet_facts_t f, reply;
  uint32_t seq, reply_seq;
  uint64_t clock;
  product_flow_entry_observation_t o;
} flow_t;

static void packet (flow_t *x, int reply, const void *bytes, unsigned size, uint32_t sequence);
static void open_flow (flow_t *x, unsigned port)
{
  memset (x, 0, sizeof (*x));
  assert (!product_flow_runtime_create (&x->pool, 0, 1, 7, 1));
  x->f = (product_packet_facts_t){.l3_status = 1, .l4_status = 1, .ip_family = 4, .protocol = 6,
    .source_port = 42000, .destination_port = (uint16_t) port, .l4_header_length = 20,
    .tcp_flags = 16, .tcp_window = 65535};
  x->f.source_address[0] = 10; x->f.destination_address[0] = 11;
  x->reply = x->f;
  x->reply.source_port = (uint16_t) port; x->reply.destination_port = 42000;
  memset (x->reply.source_address, 0, 16); memset (x->reply.destination_address, 0, 16);
  x->reply.source_address[0] = 11; x->reply.destination_address[0] = 10;
  x->seq = 1000; x->reply_seq = 5000; x->clock = 1;
  product_worker_layout_t layout = {1, 1};
  assert (!product_owner_assign (&layout, &x->f, &x->owner));
  x->f.tcp_flags = 2;                       /* the connection opens with the client SYN */
  packet (x, 0, NULL, 0, x->seq - 1);
  x->f.tcp_flags = 16;
}

static void packet (flow_t *x, int reply, const void *bytes, unsigned size, uint32_t sequence)
{
  product_packet_facts_t *f = reply ? &x->reply : &x->f;
  f->tcp_sequence = sequence;
  f->transport_length = (uint16_t) (20 + size); f->packet_length = (uint16_t) (20 + f->transport_length);
  product_worker_layout_t layout = {1, 1};
  assert (!product_owner_assign (&layout, f, &x->owner));
  product_flow_entry_packet_t input = {.facts = f, .policy = {7, 1, 1}, .uid = 17, .timestamp = x->clock++};
  assert (!product_flow_entry_observe (x->pool, &x->owner, &input, 0, &x->o));
  assert (x->o.entry);
  assert (!product_flow_entry_identify (x->pool, x->o.slot, 7, x->o.entry->incarnation, f, bytes, size));
}
static void send (flow_t *x, const char *text) { packet (x, 0, text, (unsigned) strlen (text), x->seq); x->seq += (uint32_t) strlen (text); }
static const product_http_flow_t *http (flow_t *x) { return &x->o.entry->http; }
static void close_flow (flow_t *x) { product_flow_runtime_destroy (x->pool); }

static product_packet_facts_t facts_at (flow_t *x, unsigned size, uint32_t sequence)
{
  product_packet_facts_t f = x->f;
  f.tcp_sequence = sequence;
  f.transport_length = (uint16_t) (20 + size); f.packet_length = (uint16_t) (20 + f.transport_length);
  return f;
}
static product_flow_entry_status_t resume_with (flow_t *x, const char *bytes, unsigned size, uint32_t sequence, int give_up)
{
  product_packet_facts_t f = facts_at (x, size, sequence);
  return product_flow_http_resume (x->pool, x->o.slot, 7, x->o.entry->incarnation, &f,
    (const uint8_t *) bytes, size, give_up);
}
static void resume (flow_t *x, const char *bytes, unsigned size, uint32_t sequence, int give_up)
{ assert (resume_with (x, bytes, size, sequence, give_up) == PRODUCT_FLOW_ENTRY_STATUS_OK); }
static product_flow_entry_status_t resume_status (flow_t *x, const char *bytes, unsigned size, uint32_t sequence)
{ return resume_with (x, bytes, size, sequence, 0); }
static product_flow_entry_status_t resume_give_up (flow_t *x, const char *bytes, unsigned size, uint32_t sequence)
{ return resume_with (x, bytes, size, sequence, 1); }

static const char REQUEST[] = "GET /index HTTP/1.1\r\nHost: Example.Test\r\nAccept: */*\r\n\r\n";

static void a_request_takes_the_flow_storage_from_sni (void)
{
  flow_t x; open_flow (&x, 80);
  send (&x, REQUEST);
  assert (x.o.entry->http_mode == PRODUCT_HTTP_ACTIVE);
  assert (x.o.entry->sni.stop == PRODUCT_SNI_UNSUPPORTED && !x.o.entry->sni.result);
  assert (http (&x)->pending_count == 1 && http (&x)->has_current && !http (&x)->has_denied);
  assert (!strcmp (http (&x)->pending[0].name, "example.test") && http (&x)->pending[0].index == 0);
  assert (http (&x)->completed_in_packet == 1 && !http (&x)->parser.stop);
  /* The next packet carries no head: nothing is pending, the current target stays. */
  packet (&x, 0, "", 0, x.seq);
  assert (http (&x)->pending_count == 0 && http (&x)->has_current && !strcmp (http (&x)->current.name, "example.test"));
  close_flow (&x);
}

static void a_head_split_across_packets_completes_on_its_last_fragment (void)
{
  size_t n = strlen (REQUEST);
  for (size_t split = 1; split < n; ++split)
    {
      flow_t x; open_flow (&x, 80);
      packet (&x, 0, REQUEST, (unsigned) split, x.seq); x.seq += (uint32_t) split;
      assert (x.o.entry->http_mode == PRODUCT_HTTP_ACTIVE && !http (&x)->pending_count && !http (&x)->has_current);
      packet (&x, 0, REQUEST + split, (unsigned) (n - split), x.seq); x.seq += (uint32_t) (n - split);
      assert (http (&x)->pending_count == 1 && !strcmp (http (&x)->current.name, "example.test"));
      close_flow (&x);
    }
}

static void pipelined_and_successive_requests_are_reported_in_order (void)
{
  flow_t x; open_flow (&x, 8080);
  send (&x, "GET /a HTTP/1.1\r\nHost: one.test\r\n\r\nGET http://two.test/b HTTP/1.1\r\n\r\nGET /c HTTP/1.1\r\nHost: three.test\r\n\r\n");
  assert (http (&x)->pending_count == 3 && http (&x)->completed_in_packet == 3);
  assert (!strcmp (http (&x)->pending[0].name, "one.test") && !strcmp (http (&x)->pending[1].name, "two.test")
          && !strcmp (http (&x)->pending[2].name, "three.test"));
  assert (!strcmp (http (&x)->current.name, "three.test"));
  send (&x, "GET /d HTTP/1.1\r\nHost: four.test\r\n\r\n");
  assert (http (&x)->pending_count == 1 && http (&x)->pending[0].index == 3);
  /* More heads than one batch in one packet: every head is still judged, batch by batch. */
  static const char five[] = "GET /1 HTTP/1.1\r\nHost: a.test\r\n\r\nGET /2 HTTP/1.1\r\nHost: b.test\r\n\r\n"
            "GET /3 HTTP/1.1\r\nHost: c.test\r\n\r\nGET /4 HTTP/1.1\r\nHost: d.test\r\n\r\nGET /5 HTTP/1.1\r\nHost: e.test\r\n\r\n";
  uint32_t start = x.seq;
  packet (&x, 0, five, sizeof (five) - 1, start);
  assert (http (&x)->pending_count == PRODUCT_HTTP_PENDING && http (&x)->more && http (&x)->completed_in_packet == 4);
  assert (!strcmp (http (&x)->pending[3].name, "d.test") && !strcmp (http (&x)->current.name, "d.test"));
  resume (&x, five, sizeof (five) - 1, start, 0);
  assert (http (&x)->pending_count == 1 && !http (&x)->more && !strcmp (http (&x)->pending[0].name, "e.test"));
  assert (resume_status (&x, five, sizeof (five) - 1, start) == PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE);   /* nothing left */
  x.seq = start + sizeof (five) - 1;
  /* A refused packet whose batch was not finished: its retransmission resumes where parsing stopped. */
  static const char six[] = "GET /1 HTTP/1.1\r\nHost: a.test\r\n\r\nGET /2 HTTP/1.1\r\nHost: b.test\r\n\r\n"
            "GET /3 HTTP/1.1\r\nHost: c.test\r\n\r\nGET /4 HTTP/1.1\r\nHost: d.test\r\n\r\nGET /5 HTTP/1.1\r\nHost: f.test\r\n\r\n";
  start = x.seq;
  packet (&x, 0, six, sizeof (six) - 1, start);
  assert (http (&x)->more);
  packet (&x, 0, six, sizeof (six) - 1, start);              /* retransmission */
  assert (http (&x)->pending_count == 1 && !strcmp (http (&x)->pending[0].name, "f.test") && !http (&x)->more);
  /* A batch limit gives up on the rest: later requests have no known target. */
  x.seq = start + sizeof (six) - 1;
  start = x.seq;
  packet (&x, 0, five, sizeof (five) - 1, start);
  assert (http (&x)->more);
  assert (resume_give_up (&x, five, sizeof (five) - 1, start) == PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert (http (&x)->unavailable && !http (&x)->more && http (&x)->parser.stop == PRODUCT_HTTP_STOP_HEAD_LIMIT);
  close_flow (&x);
}

static void retransmission_and_loss_are_handled_by_sequence (void)
{
  flow_t x; open_flow (&x, 80);
  size_t n = strlen (REQUEST);
  uint32_t start = x.seq;
  packet (&x, 0, REQUEST, 20, start);
  packet (&x, 0, REQUEST, 20, start);                       /* exact duplicate */
  packet (&x, 0, REQUEST + 10, 20, start + 10);             /* overlapping retransmission */
  assert (!http (&x)->pending_count && !http (&x)->parser.stop);
  packet (&x, 0, REQUEST + 20, (unsigned) (n - 20), start + 20);
  assert (http (&x)->pending_count == 1);
  packet (&x, 0, REQUEST, (unsigned) n, start);             /* whole request again */
  assert (http (&x)->pending_count == 0 && http (&x)->current.index == 0 && !http (&x)->parser.stop);
  close_flow (&x);
  open_flow (&x, 80);
  packet (&x, 0, REQUEST, 10, x.seq);
  packet (&x, 0, REQUEST + 30, 10, x.seq + 30);              /* bytes 10..29 never seen */
  assert (http (&x)->parser.stop == PRODUCT_HTTP_STOP_SEQUENCE && !http (&x)->pending_count);
  close_flow (&x);
}

static void only_the_request_direction_is_parsed (void)
{
  flow_t x; open_flow (&x, 80);
  send (&x, "GET /x HTTP/1.1\r\nHost: client.test\r\n");
  packet (&x, 1, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 38, x.reply_seq);
  assert (!http (&x)->pending_count && !http (&x)->parser.stop);
  send (&x, "\r\n");
  assert (http (&x)->pending_count == 1 && !strcmp (http (&x)->pending[0].name, "client.test"));
  close_flow (&x);
}

static void flows_that_are_not_http_are_never_taken (void)
{
  static const uint8_t hello[] = {22, 3, 1, 0, 45, 1, 0, 0, 41, 3, 3};
  flow_t x; open_flow (&x, 443);
  packet (&x, 0, hello, sizeof (hello), x.seq);
  assert (x.o.entry->http_mode == PRODUCT_HTTP_NOT_HTTP && !x.o.entry->sni.stop);   /* SNI keeps running */
  close_flow (&x);
  open_flow (&x, 22);
  send (&x, "SSH-2.0-OpenSSH_9\r\n");
  assert (x.o.entry->http_mode == PRODUCT_HTTP_ACTIVE && http (&x)->parser.stop == PRODUCT_HTTP_STOP_NOT_HTTP);
  assert (!http (&x)->has_current);
  close_flow (&x);
  open_flow (&x, 80);
  send (&x, "CONNECT secure.test:443 HTTP/1.1\r\nHost: secure.test:443\r\n\r\n");
  assert (http (&x)->pending_count == 1 && http (&x)->pending[0].connect && http (&x)->parser.stop == PRODUCT_HTTP_STOP_TUNNEL);
  send (&x, "\x16\x03\x01\x00\x10 tunnelled bytes");
  assert (!http (&x)->pending_count);
  close_flow (&x);
}

static void denial_is_sticky_and_validated (void)
{
  flow_t x; open_flow (&x, 80);
  send (&x, REQUEST);
  product_http_request_t target = http (&x)->pending[0];
  uint64_t incarnation = x.o.entry->incarnation;
  assert (product_flow_http_deny (x.pool, x.o.slot, 7, incarnation + 1, &target, NULL) == PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE);
  assert (product_flow_http_deny (x.pool, x.o.slot, 8, incarnation, &target, NULL) == PRODUCT_FLOW_ENTRY_STATUS_WRONG_GENERATION);
  assert (!http (&x)->has_denied);
  assert (!product_flow_http_deny (x.pool, x.o.slot, 7, incarnation, &target, NULL));
  assert (http (&x)->has_denied && !strcmp (http (&x)->denied.name, "example.test"));
  product_http_request_t other = target; strcpy (other.name, "other.test");
  product_observation_attribution_t denied_rule = { .valid = 1, .policy_generation = 7,
    .policy_revision = 19, .winner = 543, .actual_action = 2 };
  memcpy (denied_rule.name, "refused target rule", 20);
  assert (!product_flow_http_deny (x.pool, x.o.slot, 7, incarnation, &other, &denied_rule));
  assert (!strcmp (http (&x)->denied.name, "other.test"));            /* the latest refused target is kept */
  send (&x, "GET /y HTTP/1.1\r\nHost: later.test\r\n\r\n");
  assert (http (&x)->has_denied && !strcmp (http (&x)->denied.name, "other.test"));   /* parsing never clears a refusal */
  product_flow_names_t names;
  product_flow_names (x.o.entry, &names);
  assert (names.available && names.request_available);
  assert (!strcmp (names.request.name, "later.test") && !strcmp (names.denied.name, "other.test"));
  assert (names.request.source == PRODUCT_TARGET_HTTP_HOST);
  assert (names.denied_rule.valid && names.denied_rule.winner == 543 && names.denied_rule.policy_revision == 19);
  send (&x, "GET /unknown HTTP/1.1\r\n\r\n");
  product_flow_names (x.o.entry, &names);
  assert (!names.request_available && names.request_reason == PRODUCT_HTTP_TARGET_NO_HOST);
  assert (!strcmp (names.request.name, "later.test")); /* latest valid name remains, eligibility does not */

  close_flow (&x);
  open_flow (&x, 443);
  packet (&x, 0, "\x16\x03\x01", 3, x.seq);
  assert (product_flow_http_deny (x.pool, x.o.slot, 7, x.o.entry->incarnation, &target, NULL) == PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE);
  close_flow (&x);
}

static void sni_deadline_never_touches_the_http_state (void)
{
  flow_t x; open_flow (&x, 80);
  packet (&x, 0, "GE", 2, x.seq); x.seq += 2;                  /* SNI would still be waiting here */
  assert (x.o.entry->sni.stop == PRODUCT_SNI_UNSUPPORTED && !x.o.entry->sni.deadline_us);
  send (&x, "T /x HTTP/1.1\r\nHost: slow.test\r\n");
  assert (!http (&x)->pending_count);
  assert (!product_flow_runtime_set_deadline (x.pool, x.o.slot, 7, x.o.entry->incarnation, 60000000, PRODUCT_CT_TIMEOUT_TCP_ESTABLISHED));
  uint32_t closed = 0;
  assert (!product_flow_runtime_run_due (x.pool, 1 + PRODUCT_SNI_TIMEOUT_US + 10, 4, &closed));
  send (&x, "\r\n");
  assert (http (&x)->pending_count == 1 && !strcmp (http (&x)->current.name, "slow.test"));
  close_flow (&x);
}

static void socks_flows_report_the_requested_target (void)
{
  flow_t x; open_flow (&x, 1080);
  /* SOCKS5: greeting, the server's method selection, then a domain CONNECT. */
  packet (&x, 0, "\x05\x01\x00", 3, x.seq); x.seq += 3;
  assert (x.o.entry->http_mode == PRODUCT_HTTP_SOCKS && x.o.entry->sni.stop == PRODUCT_SNI_UNSUPPORTED);
  assert (!http (&x)->pending_count && !http (&x)->socks.confirmed);
  packet (&x, 1, "\x05\x00", 2, x.reply_seq); x.reply_seq += 2;
  assert (http (&x)->socks.confirmed && !http (&x)->pending_count);
  static const uint8_t request[] = {5, 1, 0, 3, 11, 's', 'o', 'c', 'k', 's', '.', 't', 'e', 's', 't', 's', 0, 80};
  packet (&x, 0, request, sizeof (request), x.seq); x.seq += sizeof (request);
  assert (http (&x)->pending_count == 1 && !strcmp (http (&x)->pending[0].name, "socks.tests") && http (&x)->pending[0].port == 80);
  assert (http (&x)->socks.stop == PRODUCT_SOCKS_STOP_TUNNEL);
  packet (&x, 0, "GET / HTTP/1.1\r\nHost: inner.test\r\n\r\n", 37, x.seq);  /* tunnel bytes are not parsed */
  assert (!http (&x)->pending_count && !strcmp (http (&x)->current.name, "socks.tests"));
  close_flow (&x);
  /* SOCKS4 IP and SOCKS4a name; a retransmitted request is not reported twice. */
  open_flow (&x, 1080);
  static const uint8_t s4[] = {4, 1, 0, 80, 203, 0, 113, 5, 0};
  packet (&x, 0, s4, sizeof (s4), x.seq);
  assert (http (&x)->pending_count == 1 && http (&x)->pending[0].kind == PRODUCT_HTTP_TARGET_IPV4 && http (&x)->pending[0].address[3] == 5);
  packet (&x, 0, s4, sizeof (s4), x.seq);
  assert (!http (&x)->pending_count);
  packet (&x, 1, "\x00\x5a\x00\x00\x00\x00\x00\x00", 8, x.reply_seq);
  assert (http (&x)->socks.confirmed);
  close_flow (&x);
  open_flow (&x, 1080);
  static const uint8_t s4a[] = {4, 1, 1, 187, 0, 0, 0, 9, 'u', 0, 'a', '.', 't', 'e', 's', 't', 0};
  packet (&x, 0, s4a, 5, x.seq);
  packet (&x, 0, s4a + 5, sizeof (s4a) - 5, x.seq + 5);
  assert (http (&x)->pending_count == 1 && !strcmp (http (&x)->pending[0].name, "a.test") && http (&x)->pending[0].port == 443);
  assert (!product_flow_http_deny (x.pool, x.o.slot, 7, x.o.entry->incarnation, &http (&x)->pending[0], NULL));
  assert (http (&x)->has_denied);
  close_flow (&x);
  /* Server-first bytes never decide the mode. */
  open_flow (&x, 21);
  packet (&x, 1, "220 FTP ready\r\n", 15, x.reply_seq);
  assert (x.o.entry->http_mode == PRODUCT_HTTP_UNDECIDED);
  close_flow (&x);
}

static void a_mid_connection_stop_leaves_no_known_target (void)
{
  flow_t x; open_flow (&x, 80);
  send (&x, REQUEST);
  assert (!http (&x)->unavailable);
  send (&x, "GET /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n");
  /* That head itself is reported; framing after it cannot be trusted, so later requests are unknown. */
  assert (http (&x)->pending_count == 1 && !strcmp (http (&x)->pending[0].name, "a.test"));
  assert (http (&x)->parser.stop == PRODUCT_HTTP_STOP_FRAMING && http (&x)->unavailable);
  close_flow (&x);
  open_flow (&x, 80);
  send (&x, REQUEST);
  packet (&x, 0, "GET", 3, x.seq + 40);                      /* lost bytes */
  assert (http (&x)->parser.stop == PRODUCT_HTTP_STOP_SEQUENCE && http (&x)->unavailable);
  close_flow (&x);
  /* A tunnel keeps its target: CONNECT names where the tunnel goes. */
  open_flow (&x, 80);
  send (&x, "CONNECT secure.test:443 HTTP/1.1\r\nHost: secure.test:443\r\n\r\n");
  assert (http (&x)->parser.stop == PRODUCT_HTTP_STOP_TUNNEL && !http (&x)->unavailable);
  close_flow (&x);
  /* SOCKS: a malformed request is unavailable, the tunnel after a request is not. */
  open_flow (&x, 1080);
  packet (&x, 0, "\x05\x01\x00", 3, x.seq); x.seq += 3;
  packet (&x, 1, "\x05\x00", 2, x.reply_seq); x.reply_seq += 2;
  packet (&x, 0, "\x05\x01\x00\x09\x00", 5, x.seq);
  assert (http (&x)->socks.stop == PRODUCT_SOCKS_STOP_MALFORMED && http (&x)->unavailable);
  close_flow (&x);
}

int main (void)
{
  assert (!product_lpi_init ());
  a_request_takes_the_flow_storage_from_sni ();
  a_head_split_across_packets_completes_on_its_last_fragment ();
  pipelined_and_successive_requests_are_reported_in_order ();
  retransmission_and_loss_are_handled_by_sequence ();
  only_the_request_direction_is_parsed ();
  flows_that_are_not_http_are_never_taken ();
  denial_is_sticky_and_validated ();
  sni_deadline_never_touches_the_http_state ();
  socks_flows_report_the_requested_target ();
  a_mid_connection_stop_leaves_no_known_target ();
  puts ("Flow HTTP request targets PASS");
  return 0;
}
