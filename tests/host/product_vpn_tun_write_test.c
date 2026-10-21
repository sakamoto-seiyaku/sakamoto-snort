/* SPDX-License-Identifier: Apache-2.0 */
/* Exercise the one-attempt VPN write seam against real nonblocking fds. */
#define _GNU_SOURCE
#include "product_vpn_tun_write.h"
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
  int fd[2];
  assert(pipe2(fd, O_NONBLOCK | O_CLOEXEC) == 0);
  char bytes[8192];
  memset(bytes, 'q', sizeof(bytes));
  product_vpn_tun_write_result_t result =
    product_vpn_tun_write_once(fd[1], bytes, 7);
  assert(result.kind == PRODUCT_VPN_TUN_WRITE_SUCCEEDED);
  assert(result.written == 7 && result.error == 0);
  char received[7];
  assert(read(fd[0], received, sizeof(received)) == 7);
  assert(memcmp(received, bytes, sizeof(received)) == 0);

  int capacity = fcntl(fd[1], F_GETPIPE_SZ);
  assert(capacity >= 8192);
  for (int left = capacity - 4096; left > 0;) {
    int amount = left < (int)sizeof(bytes) ? left : (int)sizeof(bytes);
    ssize_t written = write(fd[1], bytes, amount);
    assert(written > 0);
    left -= written;
  }
  result = product_vpn_tun_write_once(fd[1], bytes, sizeof(bytes));
  assert(result.kind == PRODUCT_VPN_TUN_WRITE_SHORT);
  assert(result.written == 4096 && result.error == 0);
  result = product_vpn_tun_write_once(fd[1], bytes, 1);
  assert(result.kind == PRODUCT_VPN_TUN_WRITE_EAGAIN);
  assert(result.written == -1 && result.error == EAGAIN);
  close(fd[0]); close(fd[1]);
  return 0;
}
