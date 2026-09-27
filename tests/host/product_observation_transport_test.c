/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "sakamoto_product_observation.h"
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vppinfra/mem.h>

static unsigned fd_count (void) {
  DIR *directory = opendir ("/proc/self/fd"); assert (directory);
  unsigned count = 0;
  struct dirent *entry;
  while ((entry = readdir (directory))) if (entry->d_name[0] != '.') count++;
  closedir (directory); return count;
}
static void rejected_rights (product_observation_transport_t *transport, unsigned n, unsigned length) {
  int pair[2], fds[9];
  assert (!socketpair (AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair));
  for (unsigned i = 0; i < n; i++) { fds[i] = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC); assert (fds[i] >= 0); }
  unsigned before = fd_count ();
  uint8_t invalid[48] = {0};
  struct iovec iov = { invalid, length };
  union { struct cmsghdr alignment; char bytes[CMSG_SPACE (sizeof (fds))]; } control = {0};
  struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
    .msg_control = control.bytes, .msg_controllen = CMSG_SPACE (n * sizeof (int)) };
  struct cmsghdr *c = CMSG_FIRSTHDR (&msg);
  c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN (n * sizeof (int));
  memcpy (CMSG_DATA (c), fds, n * sizeof (int));
  assert (sendmsg (pair[0], &msg, MSG_NOSIGNAL) == (ssize_t) length);
  assert (product_observation_offer (transport, pair[1]) == -1);
  assert (fd_count () == before); /* received/truncated duplicates were settled */
  assert (product_observation_offer (transport, pair[1]) == 1); /* no-message EAGAIN is bounded */
  for (unsigned i = 0; i < n; i++) close (fds[i]);
  close (pair[0]); close (pair[1]);
}
int main (void) {
  assert (clib_mem_init (NULL, 4 * 1024 * 1024));
  unsigned before = fd_count ();
  product_observation_transport_t *t = product_observation_transport_create (77, 1024);
  assert (t);
  product_observation_record_t r = { .length = 456, .version = PRODUCT_OBSERVATION_VERSION, .family = 4 };
  assert (product_observation_publish (t, 0, &r, 456) == 1);
  rejected_rights (t, 3, 48);
  rejected_rights (t, 5, 0);
  rejected_rights (t, 9, 48);
  rejected_rights (t, 5, 48);
  for (unsigned i = 1; i < 512; i++) assert (product_observation_publish (t, 0, &r, 456) == 1);
  assert (product_observation_publish (t, 0, &r, 456) == 0);
  assert (product_observation_publish (t, 0, &r, PRODUCT_OBSERVATION_MAX_RECORD + 1) == -1);
  assert (product_observation_publish (t, 1, &r, 456) == 1);
  for (unsigned i = 0; i < 256; i++) assert (product_observation_publish (t, 2, &r, 480) == 1);
  assert (product_observation_publish (t, 2, &r, 480) == 0);
  assert (product_observation_publish (t, 2, &r, 456) == 1);
  for (unsigned outcome = 0; outcome < 3; outcome++) product_observation_account (t, 0, outcome, 60 + outcome);
  product_observation_status_t s;
  product_observation_transport_status (t, &s);
  assert (s.channels[0].published == 512 && s.channels[0].full == 1 && s.channels[0].oversize == 1);
  assert (s.channels[1].published == 1 && s.channels[1].full == 0);
  assert (s.channels[2].published == 257 && s.channels[2].full == 1);
  for (unsigned outcome = 0; outcome < 3; outcome++)
    assert (s.channels[0].basic_packets[outcome] == 1 && s.channels[0].basic_bytes[outcome] == 60 + outcome);
  product_observation_transport_destroy (t);
  assert (fd_count () == before);
  puts ("transport_capacity_fd_rejection_accounting=PASS");
  return 0;
}
