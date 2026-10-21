/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_VPN_TUN_WRITE_H
#define SAKAMOTO_PRODUCT_VPN_TUN_WRITE_H

#include <errno.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>

typedef enum {
  PRODUCT_VPN_TUN_WRITE_SUCCEEDED,
  PRODUCT_VPN_TUN_WRITE_SHORT,
  PRODUCT_VPN_TUN_WRITE_EAGAIN,
  PRODUCT_VPN_TUN_WRITE_ERROR,
} product_vpn_tun_write_kind_t;

typedef struct {
  product_vpn_tun_write_kind_t kind;
  ssize_t written;
  int error;
} product_vpn_tun_write_result_t;

static inline product_vpn_tun_write_result_t
product_vpn_tun_write_once(int fd, const void *bytes, size_t length)
{
  ssize_t written = write(fd, bytes, length);
  int error = written < 0 ? errno : 0;
  product_vpn_tun_write_kind_t kind;
  if (length && written == (ssize_t)length)
    kind = PRODUCT_VPN_TUN_WRITE_SUCCEEDED;
  else if (written >= 0)
    kind = PRODUCT_VPN_TUN_WRITE_SHORT;
  else if (error == EAGAIN || error == EWOULDBLOCK)
    kind = PRODUCT_VPN_TUN_WRITE_EAGAIN;
  else
    kind = PRODUCT_VPN_TUN_WRITE_ERROR;
  return (product_vpn_tun_write_result_t){kind, written, error};
}

#endif
