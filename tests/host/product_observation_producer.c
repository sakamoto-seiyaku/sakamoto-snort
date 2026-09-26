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
          .family = length == 136 ? 4 : 6, .protocol = 17,
          .address = { 10, 1, 2, 3, 10, 4, 5, 6 },
        };
        admitted += product_observation_publish (t, channel, &record, length) == 1;
        product_observation_account (t, channel / 2, 0, 60);
      }
      printf ("EMITTED %u\n", admitted);
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
