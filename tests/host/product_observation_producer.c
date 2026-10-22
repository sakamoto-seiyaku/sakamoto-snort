/* SPDX-License-Identifier: Apache-2.0 */
/* Separate-process transport fixture using the actual Product C transport.
 * It does not implement packet ownership or replace Product graph acceptance. */
#define _GNU_SOURCE
#include "sakamoto_product_observation.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <time.h>

/* Keep literal relative windows inside the real store retention horizon. */
static uint64_t activity_base;
#include <vppinfra/mem.h>
/* Literal oracle fixture: two independent directions, observe versus enforce,
 * a missing old boundary, a new application's NoMatch tail and duplicate END. */
static unsigned attribution_fixture (product_observation_transport_t *t) {
  product_observation_record_t r = {
    .length = 456, .version = PRODUCT_OBSERVATION_VERSION, .owner = 0, .slot = 7,
    .generation = 77, .incarnation = 30, .sequence = 1, .first_seen = 100, .last_seen = 101,
    .packets = {2, 1}, .bytes = {120, 80}, .activity_utc_us = (activity_base + 1000000),
    .family = 4, .protocol = 17, .address = {10, 1, 2, 3, 10, 4, 5, 6},
    .attribution = {
      {.segment=1, .activity_utc_us=(activity_base + 1000000), .policy_generation=77, .policy_revision=1,
       .policy_hash=101, .winner=65537, .uid=1001, .declared_action=2, .actual_action=1,
       .mode=1, .valid=1, .name="observe request"},
      {.segment=1, .activity_utc_us=(activity_base + 1000000), .policy_generation=77, .policy_revision=1,
       .policy_hash=101, .winner=131073, .uid=1001, .declared_action=1, .actual_action=1,
       .valid=1, .name="reply"}
    },
  };
  unsigned n = product_observation_publish (t, 0, &r, r.length) == 1;
  r.sequence=2; r.last_seen=102; r.packets[0]=3; r.bytes[0]=180;
  n += product_observation_publish (t, 0, &r, r.length) == 1;
  r.sequence=3; r.last_seen=103; r.packets[0]=4; r.bytes[0]=240;
  r.attribution[0] = (product_observation_attribution_t) {
    .segment=2, .start_packets=3, .start_bytes=180, .activity_utc_us=(activity_base + 1000000),
    .policy_generation=77, .policy_revision=2, .policy_hash=202, .winner=196609,
    .uid=1001, .declared_action=2, .actual_action=2, .valid=1, .name="enforce request"
  };
  n += product_observation_publish (t, 0, &r, r.length) == 1;
  r.sequence=5; r.last_seen=105; r.packets[0]=7; r.packets[1]=2;
  r.bytes[0]=420; r.bytes[1]=160; r.flags=PRODUCT_OBSERVATION_END;
  r.activity_utc_us=(activity_base + 61000000); r.attribution[1].activity_utc_us=(activity_base + 61000000);
  r.attribution[0] = (product_observation_attribution_t) {
    .segment=3, .start_packets=6, .start_bytes=360, .activity_utc_us=(activity_base + 61000000),
    .policy_generation=77, .policy_revision=3, .policy_hash=303, .uid=1002,
    .declared_action=1, .actual_action=1, .valid=1
  };
  n += product_observation_publish (t, 0, &r, r.length) == 1;
  n += product_observation_publish (t, 0, &r, r.length) == 1;
  return n;
}
static unsigned blocked_fixture (product_observation_transport_t *t) {
  product_observation_record_t flow = {
    .length = 456, .version = PRODUCT_OBSERVATION_VERSION,
    .owner = 0, .slot = 7, .generation = 77, .incarnation = 1, .sequence = 1,
    .first_seen = 100, .last_seen = 100, .activity_utc_us = (activity_base + 1000000),
    .family = 4, .protocol = 17, .packets = {1, 0}, .bytes = {60, 0},
    .attribution = {{.segment=1, .activity_utc_us=(activity_base + 1000000),
      .policy_generation=77, .policy_revision=1, .policy_hash=100,
      .uid=42, .declared_action=1, .actual_action=1, .valid=1}},
  };
  unsigned n = product_observation_publish (t, 0, &flow, flow.length) == 1;
  product_observation_record_t blocked = flow;
  blocked.flags = PRODUCT_OBSERVATION_BLOCKED | PRODUCT_OBSERVATION_CREATE;
  blocked.incarnation = 20;
  blocked.attribution[0].winner = 65537;
  blocked.attribution[0].declared_action = 2;
  blocked.attribution[0].actual_action = 2;
  memcpy (blocked.attribution[0].name, "first drop", 11);
  n += product_observation_publish (t, 1, &blocked, blocked.length) == 1;
  blocked.flags = PRODUCT_OBSERVATION_BLOCKED;
  blocked.sequence = 2; blocked.last_seen = 101;
  n += product_observation_publish (t, 1, &blocked, blocked.length) == 1;
  blocked.sequence = 3; blocked.last_seen = 102;
  blocked.packets[0] = 2; blocked.bytes[0] = 120;
  blocked.attribution[0] = (product_observation_attribution_t) {
    .segment=2, .start_packets=1, .start_bytes=60, .activity_utc_us=(activity_base + 1000000),
    .policy_generation=77, .policy_revision=2, .policy_hash=200,
    .winner=131073, .uid=42, .declared_action=2, .actual_action=2,
    .valid=1, .name="second drop" };
  n += product_observation_publish (t, 1, &blocked, blocked.length) == 1;
  blocked.flags = PRODUCT_OBSERVATION_BLOCKED | PRODUCT_OBSERVATION_END;
  blocked.end_reason = PRODUCT_OBSERVATION_END_IDLE;
  blocked.sequence = 4; blocked.last_seen = 103;
  blocked.packets[0] = 3; blocked.bytes[0] = 180;
  n += product_observation_publish (t, 1, &blocked, blocked.length) == 1;
  return n;
}
static unsigned protocol_fixture (product_observation_transport_t *t) {
  /* Bits 0 and 5 are stable catalog DNS and supplemental mDNS. The packet
   * producer uses the generated catalog; this transport fixture pins ABI. */
  product_observation_attribution_t a = {
    .segment=1, .activity_utc_us=(activity_base + 1000000), .policy_generation=77,
    .policy_revision=1, .policy_hash=88, .winner=65537, .uid=42,
    .declared_action=1, .actual_action=1, .valid=1, .name="same winner"
  };
  product_observation_record_t r = {
    .length=456, .version=PRODUCT_OBSERVATION_VERSION,
    .owner=0, .slot=11, .generation=77, .incarnation=1,
    .sequence=1, .first_seen=1, .last_seen=1,
    .activity_utc_us=(activity_base + 1000000), .family=4, .protocol=17,
    .packets={1,1}, .bytes={60,80},
    .address={10,1,2,3,10,4,5,6},
    .attribution={a,a},
  };
  r.attribution[1].protocols_available=1;
  r.attribution[1].protocol_set=UINT64_C(1);
  unsigned n = product_observation_publish (t, 0, &r, r.length) == 1;
  r.sequence=2; r.last_seen=2; r.packets[0]=3; r.bytes[0]=180;
  r.attribution[0].segment=2; r.attribution[0].start_packets=1;
  r.attribution[0].start_bytes=60; r.attribution[0].protocols_available=1;
  r.attribution[0].protocol_set=UINT64_C(1);
  n += product_observation_publish (t, 0, &r, r.length) == 1;
  r.sequence=3; r.last_seen=3; r.packets[0]=5; r.bytes[0]=300;
  r.attribution[0].segment=3; r.attribution[0].start_packets=3;
  r.attribution[0].start_bytes=180;
  r.attribution[0].protocol_set=UINT64_C(1) | (UINT64_C(1)<<5);
  n += product_observation_publish (t, 0, &r, r.length) == 1;
  r.sequence=4; r.last_seen=4; r.packets[1]=2; r.bytes[1]=160;
  r.attribution[1].segment=2; r.attribution[1].start_packets=1;
  r.attribution[1].start_bytes=80; r.attribution[1].protocol_set=0;
  r.flags=PRODUCT_OBSERVATION_END;
  n += product_observation_publish (t, 0, &r, r.length) == 1;
  n += product_observation_publish (t, 0, &r, r.length) == 1;
  return n;
}
static unsigned protocol_gap_fixture (product_observation_transport_t *t) {
  product_observation_record_t r = {
    .length=456, .version=PRODUCT_OBSERVATION_VERSION,
    .owner=0, .slot=12, .generation=77, .incarnation=1,
    .sequence=1, .first_seen=1, .last_seen=1,
    .activity_utc_us=(activity_base + 1000000), .family=4, .protocol=17,
    .packets={1,0}, .bytes={60,0}, .address={10,1,2,3,10,4,5,6},
    .attribution={{.segment=1,.activity_utc_us=(activity_base + 1000000),.policy_generation=77,
      .policy_revision=1,.policy_hash=88,.winner=65537,.uid=42,
      .declared_action=1,.actual_action=1,.valid=1,.name="same winner",
      .protocol_set=UINT64_C(1),.protocols_available=1}},
  };
  unsigned n = product_observation_publish (t, 0, &r, r.length) == 1;
  /* The sequence 2/3 boundary messages were lost. Only packets 4/5 are
   * provably covered by the current two-label set. */
  r.sequence=4; r.last_seen=5; r.packets[0]=5; r.bytes[0]=300;
  r.attribution[0].segment=3; r.attribution[0].start_packets=3;
  r.attribution[0].start_bytes=180;
  r.attribution[0].protocol_set=UINT64_C(1) | (UINT64_C(1)<<5);
  n += product_observation_publish (t, 0, &r, r.length) == 1;
  return n;
}
static unsigned dns_reply_fixture (product_observation_transport_t *t, unsigned tcp, unsigned profile) {
  product_dns_observation_record_t r = {
    .length=sizeof(r), .version=PRODUCT_OBSERVATION_VERSION, .flags=PRODUCT_OBSERVATION_DNS,
    .generation=77, .token=17, .incarnation=8, .mono_us=100, .activity_utc_us=(activity_base + 1000000),
    .policy_generation=77, .policy_revision=3, .policy_hash=123, .winner=310,
    .uid=10123, .network=UINT32_MAX, .slot=3, .id=0x1234, .query_flags=0x0100,
    .qtype=1, .qclass=1, .source_port=40000, .resolver_port=53, .name_length=11,
    .family=4, .protocol=17, .direction=3, .availability=9, .caller=1, .coverage=1,
    .declared_action=1, .actual_action=1, .domain_available=1, .stage=1,
    .source_address={192,0,2,2}, .resolver_address={192,0,2,53},
    .name="example.com", .rule_name="original allow", .network_revision=5, .adapter_profile=profile,
    .packet_uid=10123, .packet_availability=9,
  };
  if (tcp) {
    r.protocol=6; r.packet_direction=3; r.message_sequence=1; r.tcp_sequence=101;
  }
  unsigned n = product_observation_publish(t,0,&r,sizeof(r)) == 1;
  if (tcp) {
    r.message_sequence=2; r.tcp_sequence=132;
    n += product_observation_publish(t,0,&r,sizeof(r)) == 1;
    r.message_sequence=1; r.tcp_sequence=501; r.packet_direction=1;
  }
  r.token=18; r.stage=2; r.direction=1; r.query_flags=0x8180; r.packet_availability=1;
  r.policy_revision=9; r.policy_hash=456; r.winner=312;
  r.query_token=17; r.query_policy_generation=77; r.query_policy_revision=3;
  r.query_policy_hash=123; r.query_winner=310; r.query_incarnation=8;
  r.matched_requests=1; r.candidate_count=2; r.correlation=1;
  if (profile==2) { r.transport_session=71; r.underlay_epoch=9; }
  r.declared_action=r.actual_action=2;
  memset(r.rule_name,0,sizeof(r.rule_name)); memcpy(r.rule_name,"reply deny",10);
  n += product_observation_publish(t,0,&r,sizeof(r)) == 1;
  product_dns_observation_record_t continuation = r;
  r.name_index=r.name_source=1; r.name_length=10;
  memset(r.name,0,sizeof(r.name)); memcpy(r.name,"alias.test",10);
  n += product_observation_publish(t,0,&r,sizeof(r)) == 1;
  r.token=19; r.query_token=r.query_policy_generation=r.query_policy_revision=0;
  r.query_policy_hash=r.query_winner=r.query_incarnation=0;
  r.correlation=3; r.matched_requests=2; r.caller=0; r.availability=1;
  r.domain_available=0; r.declared_action=r.actual_action=1; r.winner=0;
  memset(r.rule_name,0,sizeof(r.rule_name));
  n += product_observation_publish(t,0,&r,sizeof(r)) == 1;
  r.name_index=r.name_source=0; r.name_length=11;
  memset(r.name,0,sizeof(r.name)); memcpy(r.name,"example.com",11);
  n += product_observation_publish(t,0,&r,sizeof(r)) == 1;
  /* Actual graph observations when a UDP53 return has no readable header,
   * followed by a chained-buffer copy gap. Do not invent a QR bit. */
  r.token=20; r.query_flags=r.qtype=r.qclass=r.id=0;
  r.name_length=r.candidate_count=r.matched_requests=0;
  r.correlation=2; r.coverage=2;
  memset(r.name,0,sizeof(r.name));
  n += product_observation_publish(t,0,&r,sizeof(r)) == 1;
  r.token=21; r.coverage=5;
  n += product_observation_publish(t,0,&r,sizeof(r)) == 1;
  if (tcp) {
    continuation.token=22; continuation.tcp_continuation=1; continuation.packet_direction=3;
    n += product_observation_publish(t,0,&continuation,sizeof(continuation)) == 1;
    /* Two complete malformed frames from one original packet retain separate
     * message identities, just as the actual Root graph producer does. */
    r.token=23; r.coverage=2; r.message_sequence=1; r.tcp_sequence=601;
    n += product_observation_publish(t,0,&r,sizeof(r)) == 1;
    r.message_sequence=2; r.tcp_sequence=606;
    n += product_observation_publish(t,0,&r,sizeof(r)) == 1;
  }
  return n;
}

int main (int argc, char **argv) {
  assert (argc == 2);
  struct timespec wall; assert (!clock_gettime (CLOCK_REALTIME, &wall));
  activity_base = ((uint64_t) wall.tv_sec / 60 - 2) * UINT64_C(60000000);
  assert (clib_mem_init (NULL, 4 * 1024 * 1024));
  product_observation_transport_t *t = product_observation_transport_create (77, 1024);
  assert (t);
  struct sockaddr_un address = { .sun_family = AF_UNIX };
  assert (strlen (argv[1]) < sizeof (address.sun_path));
  strcpy (address.sun_path, argv[1]);
  int listener = socket (AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  assert (listener >= 0 && !bind (listener, (void *) &address, sizeof (address)) && !listen (listener, 1));
  puts ("LISTEN"); fflush (stdout);
  int peer = accept (listener, NULL, NULL);
  assert (peer >= 0);
  int result;
  do { result = product_observation_offer (t, peer); if (result > 0) usleep (1000); } while (result > 0);
  assert (!result);
  product_observation_connected (t, 1);
  puts ("CONNECTED"); fflush (stdout);
  char command[128];
  while (fgets (command, sizeof (command), stdin)) {
    unsigned channel, count, length, end;
    unsigned long long base, incarnation;
    if (sscanf (command, "emit %u %u %u %llu %llu %u", &channel, &count, &length,
                &base, &incarnation, &end) == 6) {
      unsigned admitted = 0;
      for (unsigned i = 0; i < count; i++) {
        product_observation_record_t record = {
          .length = length, .version = PRODUCT_OBSERVATION_VERSION, .flags = end ? PRODUCT_OBSERVATION_END : 0,
          .owner = channel / 2, .slot = 3, .uid = 12345, .generation = 77,
          .incarnation = incarnation, .sequence = base + i,
          .activity_utc_us = (activity_base + 1000000) + base + i, .first_seen = 100, .last_seen = 100 + base + i,
          .packets = { base + i, 0 }, .bytes = { (base + i) * 60, 0 },
          .family = length == 456 ? 4 : 6, .protocol = 17,
          .address = { 10, 1, 2, 3, 10, 4, 5, 6 },
        };
        admitted += product_observation_publish (t, channel, &record, length) == 1;
        product_observation_account (t, channel / 2, 0, 60);
      }
      printf ("EMITTED %u\n", admitted);
    } else if (!strncmp (command, "dns-vpn-tcp", 11)) {
      printf ("DNS-TCP %u\n", dns_reply_fixture (t, 1, 2));
    } else if (!strncmp (command, "dns-tcp", 7)) {
      printf ("DNS-TCP %u\n", dns_reply_fixture (t, 1, 1));
    } else if (!strncmp (command, "dns-reply", 9)) {
      printf ("DNS-REPLY %u\n", dns_reply_fixture (t, 0, 1));
    } else if (!strncmp (command, "attribution", 11)) {
      printf ("ATTRIBUTION %u\n", attribution_fixture (t));
    } else if (!strncmp (command, "blocked", 7)) {
      printf ("BLOCKED %u\n", blocked_fixture (t));
    } else if (!strncmp (command, "protocol-gap", 12)) {
      printf ("PROTOCOL-GAP %u\n", protocol_gap_fixture (t));
    } else if (!strncmp (command, "protocol", 8)) {
      printf ("PROTOCOL %u\n", protocol_fixture (t));
    } else if (!strncmp (command, "status", 6)) {
      product_observation_status_t s;
      product_observation_transport_status (t, &s);
      for (unsigned i = 0; i < 4; i++)
        printf ("CHANNEL %u %llu %llu %llu %llu %u %llu\n", i,
          (unsigned long long) s.channels[i].attempted,
          (unsigned long long) s.channels[i].published,
          (unsigned long long) s.channels[i].full,
          (unsigned long long) s.channels[i].consumed,
          s.channels[i].occupancy, (unsigned long long) s.channels[i].basic_packets[0]);
    } else if (!strncmp (command, "quit", 4)) break;
    else abort ();
    fflush (stdout);
  }
  product_observation_connected (t, 0);
  close (peer); close (listener); unlink (argv[1]);
  product_observation_transport_destroy (t);
  return 0;
}
