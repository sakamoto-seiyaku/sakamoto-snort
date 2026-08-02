/* SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define NFQB_MAGIC 0x4e465142u
#define NFQB_MAX_FLOWS 4096u
#define NFQB_BASE_PORT 20000u

/* Pixel 6a / Android 16 / queue-balance 70:71 / source port 19000.
 * Ordered as lane0-owner0, lane0-owner1, lane1-owner0, lane1-owner1. */
static const uint32_t p3_oracle_flows[] = { 0u, 224u, 1u, 226u };
static const uint32_t p4_remote_flows[] = { 224u, 1u };

typedef struct
{
  uint32_t magic;
  uint32_t epoch;
  uint32_t flow_id;
  uint32_t sequence;
} nfqb_payload_t;

static uint64_t
parse_u64 (const char *text, const char *name)
{
  char *end = NULL;
  unsigned long long value;

  errno = 0;
  value = strtoull (text, &end, 10);
  if (errno || !end || *end)
    {
      fprintf (stderr, "invalid %s: %s\n", name, text);
      exit (2);
    }
  return (uint64_t) value;
}

static uint64_t
monotonic_ns (void)
{
  struct timespec ts;

  if (clock_gettime (CLOCK_MONOTONIC, &ts) != 0)
    {
      perror ("clock_gettime");
      exit (2);
    }
  return (uint64_t) ts.tv_sec * 1000000000ull + (uint64_t) ts.tv_nsec;
}

static void
sleep_until_ns (uint64_t deadline)
{
  int rv;
  struct timespec ts = {
    .tv_sec = (time_t) (deadline / 1000000000ull),
    .tv_nsec = (long) (deadline % 1000000000ull),
  };

  do
    rv = clock_nanosleep (CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);
  while (rv == EINTR);
  if (rv != 0)
    {
      errno = rv;
      perror ("clock_nanosleep");
      exit (2);
    }
}

static uint32_t
choose_flow (const char *pattern, uint64_t packet_index, uint32_t flows)
{
  if (strcmp (pattern, "p3-oracle-four") == 0)
    return p3_oracle_flows[packet_index % 4];
  if (strcmp (pattern, "p4-all-remote") == 0)
    return p4_remote_flows[packet_index % 2];
  if (strcmp (pattern, "elephant-mice") == 0)
    {
      if (flows == 1 || packet_index % 10 < 8)
	return 0;
      return 1u + (uint32_t) ((packet_index / 10) % (flows - 1));
    }
  return (uint32_t) (packet_index % flows);
}

static void
choose_destination (const char *pattern, uint32_t flow,
		    struct sockaddr_in *destination)
{
  char address[INET_ADDRSTRLEN];

  memset (destination, 0, sizeof (*destination));
  destination->sin_family = AF_INET;
  destination->sin_port = htons ((uint16_t) (NFQB_BASE_PORT + flow));
  if (strcmp (pattern, "port-only") != 0)
    snprintf (address, sizeof (address), "127.0.%u.%u",
	      (flow / 250u) % 250u, 1u + flow % 250u);
  else
    snprintf (address, sizeof (address), "127.0.0.1");
  if (inet_pton (AF_INET, address, &destination->sin_addr) != 1)
    {
      fprintf (stderr, "invalid generated destination: %s\n", address);
      exit (2);
    }
}

int
main (int argc, char **argv)
{
  const char *pattern;
  uint32_t flows;
  uint64_t packets;
  uint64_t rate;
  uint32_t epoch;
  uint16_t source_port = 19000;
  uint32_t sequence[NFQB_MAX_FLOWS] = { 0 };
  uint64_t sent = 0;
  uint64_t errors = 0;
  uint64_t started;
  uint64_t finished;
  int fd;

  if (argc != 6 && argc != 7)
    {
      fprintf (stderr,
	       "usage: %s port-only|address-diverse|elephant-mice|p3-oracle-four|p4-all-remote flows "
	       "packets rate-pps epoch [source-port]\n",
	       argv[0]);
      return 2;
    }
  pattern = argv[1];
  if (strcmp (pattern, "port-only") != 0 &&
      strcmp (pattern, "address-diverse") != 0 &&
      strcmp (pattern, "elephant-mice") != 0 &&
      strcmp (pattern, "p3-oracle-four") != 0 &&
      strcmp (pattern, "p4-all-remote") != 0)
    {
      fprintf (stderr, "invalid pattern: %s\n", pattern);
      return 2;
    }
  flows = (uint32_t) parse_u64 (argv[2], "flows");
  packets = parse_u64 (argv[3], "packets");
  rate = parse_u64 (argv[4], "rate");
  epoch = (uint32_t) parse_u64 (argv[5], "epoch");
  if (argc == 7)
    source_port = (uint16_t) parse_u64 (argv[6], "source-port");
  if (flows == 0 || flows > NFQB_MAX_FLOWS || packets == 0)
    {
      fprintf (stderr, "flows must be 1..%u and packets must be nonzero\n",
	       NFQB_MAX_FLOWS);
      return 2;
    }
  if (strcmp (pattern, "p3-oracle-four") == 0 && flows != 4)
    {
      fprintf (stderr, "p3-oracle-four requires flows=4\n");
      return 2;
    }
  if (strcmp (pattern, "p4-all-remote") == 0 && flows != 2)
    {
      fprintf (stderr, "p4-all-remote requires flows=2\n");
      return 2;
    }

  fd = socket (AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    {
      perror ("socket");
      return 2;
    }
  {
    int reuse = 1;
    struct sockaddr_in source = {
      .sin_family = AF_INET,
      .sin_port = htons (source_port),
      .sin_addr.s_addr = htonl (INADDR_LOOPBACK),
    };

    if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof (reuse)) != 0 ||
	bind (fd, (struct sockaddr *) &source, sizeof (source)) != 0)
      {
	perror ("bind source-port");
	close (fd);
	return 2;
      }
  }

  started = monotonic_ns ();
  for (uint64_t i = 0; i < packets; i++)
    {
      struct sockaddr_in destination;
      uint32_t flow = choose_flow (pattern, i, flows);
      nfqb_payload_t payload = {
	.magic = htonl (NFQB_MAGIC),
	.epoch = htonl (epoch),
	.flow_id = htonl (flow),
	.sequence = htonl (sequence[flow]),
      };
      ssize_t rv;

      choose_destination (pattern, flow, &destination);
      rv = sendto (fd, &payload, sizeof (payload), 0,
		   (struct sockaddr *) &destination, sizeof (destination));
      if (rv == (ssize_t) sizeof (payload))
	{
	  sequence[flow]++;
	  sent++;
	}
      else
	errors++;

      if (rate && ((i + 1) % 32 == 0 || i + 1 == packets))
	{
	  uint64_t target = started + (i + 1) * 1000000000ull / rate;
	  if (monotonic_ns () < target)
	    sleep_until_ns (target);
	}
    }
  finished = monotonic_ns ();
  close (fd);

  printf ("pattern=%s flows=%u requested=%" PRIu64 " sent=%" PRIu64
	  " errors=%" PRIu64 " rate-target=%" PRIu64 " epoch=%u "
	  "elapsed-ns=%" PRIu64 " achieved-pps=%.3f\n",
	  pattern, flows, packets, sent, errors, rate, epoch, finished - started,
	  sent * 1000000000.0 / (double) (finished - started));
  return errors ? 1 : 0;
}
