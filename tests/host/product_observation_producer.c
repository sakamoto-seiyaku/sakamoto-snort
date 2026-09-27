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
#include <vppinfra/mem.h>
/* Literal oracle fixture: two independent directions, observe versus enforce,
 * a missing old boundary, a new application's NoMatch tail and duplicate END. */
static unsigned attribution_fixture (product_observation_transport_t *t) {
  product_observation_record_t r = {
    .length = 424, .version = PRODUCT_OBSERVATION_VERSION, .owner = 0, .slot = 7,
    .generation = 77, .incarnation = 30, .sequence = 1, .first_seen = 100, .last_seen = 101,
    .packets = {2, 1}, .bytes = {120, 80}, .activity_utc_us = 61000000,
    .family = 4, .protocol = 17, .address = {10, 1, 2, 3, 10, 4, 5, 6},
    .attribution = {
      {.segment=1, .activity_utc_us=61000000, .policy_generation=77, .policy_revision=1,
       .policy_hash=101, .winner=65537, .uid=1001, .declared_action=2, .actual_action=1,
       .mode=1, .valid=1, .name="observe request"},
      {.segment=1, .activity_utc_us=61000000, .policy_generation=77, .policy_revision=1,
       .policy_hash=101, .winner=131073, .uid=1001, .declared_action=1, .actual_action=1,
       .valid=1, .name="reply"}
    },
  };
  unsigned n = product_observation_publish (t, 0, &r, r.length) == 1;
  r.sequence=2; r.last_seen=102; r.packets[0]=3; r.bytes[0]=180;
  n += product_observation_publish (t, 0, &r, r.length) == 1;
  r.sequence=3; r.last_seen=103; r.packets[0]=4; r.bytes[0]=240;
  r.attribution[0] = (product_observation_attribution_t) {
    .segment=2, .start_packets=3, .start_bytes=180, .activity_utc_us=61000000,
    .policy_generation=77, .policy_revision=2, .policy_hash=202, .winner=196609,
    .uid=1001, .declared_action=2, .actual_action=2, .valid=1, .name="enforce request"
  };
  n += product_observation_publish (t, 0, &r, r.length) == 1;
  r.sequence=5; r.last_seen=105; r.packets[0]=7; r.packets[1]=2;
  r.bytes[0]=420; r.bytes[1]=160; r.flags=PRODUCT_OBSERVATION_END;
  r.activity_utc_us=121000000; r.attribution[1].activity_utc_us=121000000;
  r.attribution[0] = (product_observation_attribution_t) {
    .segment=3, .start_packets=6, .start_bytes=360, .activity_utc_us=121000000,
    .policy_generation=77, .policy_revision=3, .policy_hash=303, .uid=1002,
    .declared_action=1, .actual_action=1, .valid=1
  };
  n += product_observation_publish (t, 0, &r, r.length) == 1;
  n += product_observation_publish (t, 0, &r, r.length) == 1;
  return n;
}
int main (int argc, char **argv) {
  assert (argc == 2);
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
          .activity_utc_us = 1700000000000000ULL + base + i, .first_seen = 100, .last_seen = 100 + base + i,
          .packets = { base + i, 0 }, .bytes = { (base + i) * 60, 0 },
          .family = length == 424 ? 4 : 6, .protocol = 17,
          .address = { 10, 1, 2, 3, 10, 4, 5, 6 },
        };
        admitted += product_observation_publish (t, channel, &record, length) == 1;
        product_observation_account (t, channel / 2, 0, 60);
      }
      printf ("EMITTED %u\n", admitted);
    } else if (!strncmp (command, "attribution", 11)) {
      printf ("ATTRIBUTION %u\n", attribution_fixture (t));
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
