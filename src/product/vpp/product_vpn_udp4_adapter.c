/* SPDX-License-Identifier: Apache-2.0 */

/*
 * SAKAMOTO-180/181/182/183 minimal ProductCore VPN Direct Egress adapter.
 *
 * This is a deliberately narrow vertical slice: Android owns VpnService,
 * authorization, TUN creation, and Direct UDP socket protect/bind; this VPP
 * adapter owns the TUN fd, the already-protected UDP4/UDP6/TCP4/TCP6 socket fds, packet
 * graph admission, direct send/return, and TUN write completion evidence. It is
 * not a SOCKS path, not a retired C++ facade, and not a full TCP/IPv6 Flow
 * Stack.
 */

#include "product_vpn_udp4_adapter.h"

#include "product_packet_graph.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <vlib/file.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS 0
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING 43
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif
#ifndef IPPROTO_AH
#define IPPROTO_AH 51
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS 60
#endif

#define CONTROL_SOCKET_NAME "sucre-snort-control-vnext"
#define PRODUCT_VPN_CONTROL_BUFFER_BYTES 8192
#define PRODUCT_VPN_MAX_PACKET_BYTES 2048
#define PRODUCT_VPN_MAX_UDP4_FLOWS 64
#define PRODUCT_VPN_MAX_UDP6_FLOWS 64
#define PRODUCT_VPN_MAX_TCP4_FLOWS 16
#define PRODUCT_VPN_MAX_TCP6_FLOWS 16
#define PRODUCT_VPN_TCP4_PENDING_BYTES 2048
#define PRODUCT_VPN_TCP_FLAG_FIN 0x01
#define PRODUCT_VPN_TCP_FLAG_SYN 0x02
#define PRODUCT_VPN_TCP_FLAG_RST 0x04
#define PRODUCT_VPN_TCP_FLAG_PSH 0x08
#define PRODUCT_VPN_TCP_FLAG_ACK 0x10
#define PRODUCT_VPN_OBLIGATION_SEQUENCE_MASK UINT64_C (0x00ffffffffffffff)
#define PRODUCT_VPN_OBLIGATION_ORIGIN_SHIFT 56

typedef enum
{
  PRODUCT_VPN_PACKET_ORIGIN_TUN = 1,
  PRODUCT_VPN_PACKET_ORIGIN_FLOW_STACK = 2,
} product_vpn_packet_origin_t;

/*
 * VPN origin values belong to interface_id/provenance.  The policy matcher
 * consumes the normalized Device Packet Direction in profile_id: TUN-origin
 * inner traffic is OUTPUT, while flow-stack return traffic leaves profile_id
 * zero/unknown after hints initialization.
 */
_Static_assert (PRODUCT_L4_POLICY_DIRECTION_OUTPUT == 3,
                "VPN TUN policy direction must remain Device OUTPUT");
_Static_assert (PRODUCT_VPN_PACKET_ORIGIN_TUN == 1,
                "VPN TUN provenance value is part of the adapter contract");

typedef struct
{
  u32 source_address;
  u32 destination_address;
  u16 source_port;
  u16 destination_port;
  u16 ip_header_length;
  u16 udp_length;
  u16 payload_offset;
  u16 payload_length;
} product_vpn_udp4_packet_t;

typedef struct
{
  u8 source_address[16];
  u8 destination_address[16];
  u16 source_port;
  u16 destination_port;
  u16 transport_offset;
  u16 udp_length;
  u16 payload_offset;
  u16 payload_length;
} product_vpn_udp6_packet_t;

typedef struct
{
  u32 source_address;
  u32 destination_address;
  u16 source_port;
  u16 destination_port;
  u16 ip_header_length;
  u16 tcp_header_length;
  u16 payload_offset;
  u16 payload_length;
  u8 flags;
  u32 sequence_number;
  u32 acknowledgment_number;
} product_vpn_tcp4_packet_t;

typedef struct
{
  u8 source_address[16];
  u8 destination_address[16];
  u16 source_port;
  u16 destination_port;
  u16 transport_offset;
  u16 tcp_header_length;
  u16 payload_offset;
  u16 payload_length;
  u8 flags;
  u32 sequence_number;
  u32 acknowledgment_number;
} product_vpn_tcp6_packet_t;

typedef struct
{
  u32 client_address;
  u32 remote_address;
  u16 client_port;
  u16 remote_port;
  u8 active;
} product_vpn_udp4_flow_t;

typedef enum
{
  PRODUCT_VPN_TCP4_SOCKET_IDLE = 0,
  PRODUCT_VPN_TCP4_CONNECTING = 1,
  PRODUCT_VPN_TCP4_ESTABLISHED = 2,
  PRODUCT_VPN_TCP4_CLOSING = 3,
} product_vpn_tcp4_state_t;

typedef struct
{
  u32 client_address;
  u32 remote_address;
  u16 client_port;
  u16 remote_port;
  u32 client_next_sequence;
  u32 server_initial_sequence;
  u32 server_next_sequence;
  u16 pending_length;
  u16 pending_offset;
  u8 pending[PRODUCT_VPN_TCP4_PENDING_BYTES];
  int fd;
  uword file_index;
  product_vpn_tcp4_state_t state;
  u8 active;
  u8 client_fin_seen;
  u8 server_fin_sent;
} product_vpn_tcp4_flow_t;

typedef struct
{
  u8 client_address[16];
  u8 remote_address[16];
  u16 client_port;
  u16 remote_port;
  u32 client_next_sequence;
  u32 server_initial_sequence;
  u32 server_next_sequence;
  u16 pending_length;
  u16 pending_offset;
  u8 pending[PRODUCT_VPN_TCP4_PENDING_BYTES];
  int fd;
  uword file_index;
  product_vpn_tcp4_state_t state;
  u8 active;
  u8 client_fin_seen;
  u8 server_fin_sent;
} product_vpn_tcp6_flow_t;

typedef struct
{
  u8 client_address[16];
  u8 remote_address[16];
  u16 client_port;
  u16 remote_port;
  u8 active;
} product_vpn_udp6_flow_t;

typedef struct
{
  vlib_main_t *vlib_main;
  u64 generation;
  u64 next_obligation;
  int control_fd;
  int tun_fd;
  int udp_fd;
  int udp6_fd;
  uword control_file_index;
  uword tun_file_index;
  uword udp_file_index;
  uword udp6_file_index;
  product_vpn_udp4_flow_t last_flow;
  product_vpn_udp4_flow_t flows[PRODUCT_VPN_MAX_UDP4_FLOWS];
  product_vpn_udp6_flow_t last_udp6_flow;
  product_vpn_udp6_flow_t udp6_flows[PRODUCT_VPN_MAX_UDP6_FLOWS];
  product_vpn_tcp4_flow_t tcp4_flows[PRODUCT_VPN_MAX_TCP4_FLOWS];
  product_vpn_tcp6_flow_t tcp6_flows[PRODUCT_VPN_MAX_TCP6_FLOWS];
  u32 next_flow_slot;
  u32 udp6_next_flow_slot;
  u32 tcp4_next_sequence;
  u32 tcp6_next_sequence;
  u64 vpn_tun_fd_attached;
  u64 vpn_direct_udp4_socket_attached;
  u64 vpn_direct_udp4_protect_succeeded;
  u64 vpn_direct_udp4_bind_succeeded;
  u64 vpn_direct_udp6_socket_attached;
  u64 vpn_direct_udp6_protect_succeeded;
  u64 vpn_direct_udp6_bind_succeeded;
  u64 vpn_direct_tcp4_socket_attached;
  u64 vpn_direct_tcp4_protect_succeeded;
  u64 vpn_direct_tcp4_bind_succeeded;
  u64 vpn_direct_tcp6_socket_attached;
  u64 vpn_direct_tcp6_protect_succeeded;
  u64 vpn_direct_tcp6_bind_succeeded;
  u64 vpn_tun_ingress_packets;
  u64 vpn_tun_udp4_tun_origin_packets;
  u64 vpn_tun_udp6_tun_origin_packets;
  u64 vpn_tun_tcp4_tun_origin_packets;
  u64 vpn_tun_tcp6_tun_origin_packets;
  u64 vpn_flow_stack_admissions;
  u64 vpn_direct_udp4_send_succeeded;
  u64 vpn_direct_udp4_transport_failed;
  u64 vpn_direct_udp6_send_succeeded;
  u64 vpn_direct_udp6_transport_failed;
  u64 vpn_direct_udp6_return_packets;
  u64 vpn_direct_udp6_tun_write_completions;
  u64 vpn_direct_udp6_last_errno;
  u64 vpn_direct_tcp4_connect_attempts;
  u64 vpn_direct_tcp4_connect_succeeded;
  u64 vpn_direct_tcp4_payload_bytes_from_tun;
  u64 vpn_direct_tcp4_socket_write_completions;
  u64 vpn_direct_tcp4_socket_read_packets;
  u64 vpn_direct_tcp4_return_packets;
  u64 vpn_direct_tcp4_tun_write_completions;
  u64 vpn_direct_tcp4_transport_failed;
  u64 vpn_direct_tcp4_close_completions;
  u64 vpn_direct_tcp4_last_errno;
  u64 vpn_direct_tcp6_connect_attempts;
  u64 vpn_direct_tcp6_connect_succeeded;
  u64 vpn_direct_tcp6_payload_bytes_from_tun;
  u64 vpn_direct_tcp6_socket_write_completions;
  u64 vpn_direct_tcp6_socket_read_packets;
  u64 vpn_direct_tcp6_return_packets;
  u64 vpn_direct_tcp6_tun_write_completions;
  u64 vpn_direct_tcp6_transport_failed;
  u64 vpn_direct_tcp6_close_completions;
  u64 vpn_direct_tcp6_last_errno;
  u64 vpn_flow_stack_return_packets;
  u64 vpn_flow_stack_return_provenance_packets;
  u64 vpn_tun_write_completions;
  u64 vpn_infrastructure_faults;
  u64 vpn_duplicate_or_stale_drops;
  u32 policy_subject_uid;
  u64 policy_network_context_id;
  u8 control_ready;
  u8 tun_ready;
  u8 udp_ready;
  u8 udp6_ready;
  u8 tcp_ready;
  u8 tcp6_ready;
  u8 available;
} product_vpn_udp4_main_t;

static product_vpn_udp4_main_t product_vpn_udp4_main = {
  .control_fd = -1,
  .tun_fd = -1,
  .udp_fd = -1,
  .udp6_fd = -1,
  .control_file_index = ~0,
  .tun_file_index = ~0,
  .udp_file_index = ~0,
  .udp6_file_index = ~0,
};

static u16
product_vpn_read_be16 (const u8 *value)
{
  return (u16) (((u16) value[0] << 8) | value[1]);
}

static void
product_vpn_write_be16 (u8 *value, u16 number)
{
  value[0] = (u8) (number >> 8);
  value[1] = (u8) number;
}

static u32
product_vpn_read_be32 (const u8 *value)
{
  return ((u32) value[0] << 24) | ((u32) value[1] << 16)
         | ((u32) value[2] << 8) | value[3];
}

static void
product_vpn_write_be32 (u8 *value, u32 number)
{
  value[0] = (u8) (number >> 24);
  value[1] = (u8) (number >> 16);
  value[2] = (u8) (number >> 8);
  value[3] = (u8) number;
}

static u32
product_vpn_checksum_accumulate (const u8 *data, u32 length, u32 sum)
{
  u32 index;

  for (index = 0; index + 1 < length; index += 2)
    sum += product_vpn_read_be16 (data + index);
  if ((length & 1U) != 0)
    sum += (u16) ((u16) data[length - 1] << 8);
  return sum;
}

static u16
product_vpn_checksum_finish (u32 sum)
{
  while ((sum >> 16) != 0)
    sum = (sum & 0xffffU) + (sum >> 16);
  return (u16) ~sum;
}

static u16
product_vpn_ipv4_checksum (const u8 *packet, u16 header_length)
{
  u32 sum = 0;
  u16 index;

  for (index = 0; index < header_length; index += 2)
    sum += (u16) (((u16) packet[index] << 8) | packet[index + 1]);
  while ((sum >> 16) != 0)
    sum = (sum & 0xffffU) + (sum >> 16);
  return (u16) ~sum;
}

static u16
product_vpn_tcp4_checksum (u8 *packet, u16 ip_header_length, u16 tcp_length)
{
  u32 sum = 0;

  sum += product_vpn_read_be16 (packet + 12);
  sum += product_vpn_read_be16 (packet + 14);
  sum += product_vpn_read_be16 (packet + 16);
  sum += product_vpn_read_be16 (packet + 18);
  sum += IPPROTO_TCP;
  sum += tcp_length;
  sum = product_vpn_checksum_accumulate (packet + ip_header_length, tcp_length,
                                         sum);
  return product_vpn_checksum_finish (sum);
}

static u16
product_vpn_udp6_checksum (u8 *packet, u16 udp_length)
{
  u32 sum = 0;
  u16 checksum;

  sum = product_vpn_checksum_accumulate (packet + 8, 16, sum);
  sum = product_vpn_checksum_accumulate (packet + 24, 16, sum);
  sum += udp_length;
  sum += IPPROTO_UDP;
  sum = product_vpn_checksum_accumulate (packet + 40, udp_length, sum);
  checksum = product_vpn_checksum_finish (sum);
  return checksum == 0 ? UINT16_C (0xffff) : checksum;
}

static u16
product_vpn_tcp6_checksum (u8 *packet, u16 tcp_length)
{
  u32 sum = 0;
  u16 checksum;

  sum = product_vpn_checksum_accumulate (packet + 8, 16, sum);
  sum = product_vpn_checksum_accumulate (packet + 24, 16, sum);
  sum += tcp_length;
  sum += IPPROTO_TCP;
  sum = product_vpn_checksum_accumulate (packet + 40, tcp_length, sum);
  checksum = product_vpn_checksum_finish (sum);
  return checksum == 0 ? UINT16_C (0xffff) : checksum;
}

static int
product_vpn_set_nonblocking (int fd)
{
  int flags = fcntl (fd, F_GETFL, 0);
  if (flags < 0)
    return 0;
  return fcntl (fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static int
product_vpn_udp4_from_sockaddr (const struct sockaddr_storage *remote,
                                socklen_t remote_length, u32 *address,
                                u16 *port)
{
  if (remote == 0 || address == 0 || port == 0)
    return 0;
  if (remote->ss_family == AF_INET
      && remote_length >= sizeof (struct sockaddr_in))
    {
      const struct sockaddr_in *remote4 =
        (const struct sockaddr_in *) remote;
      *address = remote4->sin_addr.s_addr;
      *port = ntohs (remote4->sin_port);
      return 1;
    }
  if (remote->ss_family == AF_INET6
      && remote_length >= sizeof (struct sockaddr_in6))
    {
      const struct sockaddr_in6 *remote6 =
        (const struct sockaddr_in6 *) remote;
      if (!IN6_IS_ADDR_V4MAPPED (&remote6->sin6_addr))
        return 0;
      clib_memcpy_fast (address, &remote6->sin6_addr.s6_addr[12],
                        sizeof (*address));
      *port = ntohs (remote6->sin6_port);
      return 1;
    }
  return 0;
}

static int
product_vpn_udp6_from_sockaddr (const struct sockaddr_storage *remote,
                                socklen_t remote_length, u8 address[16],
                                u16 *port)
{
  const struct sockaddr_in6 *remote6;

  if (remote == 0 || address == 0 || port == 0
      || remote->ss_family != AF_INET6
      || remote_length < sizeof (struct sockaddr_in6))
    return 0;
  remote6 = (const struct sockaddr_in6 *) remote;
  if (IN6_IS_ADDR_V4MAPPED (&remote6->sin6_addr))
    return 0;
  clib_memcpy_fast (address, remote6->sin6_addr.s6_addr, 16);
  *port = ntohs (remote6->sin6_port);
  return 1;
}

static int
product_vpn_udp4_parse_tun_origin (const u8 *packet, u32 length,
                                   product_vpn_udp4_packet_t *out)
{
  u16 total_length;
  u16 fragment;
  u8 header_length;

  if (packet == 0 || out == 0 || length < 28 || (packet[0] >> 4) != 4)
    return 0;
  header_length = (u8) ((packet[0] & 0x0fU) * 4U);
  total_length = product_vpn_read_be16 (packet + 2);
  fragment = product_vpn_read_be16 (packet + 6);
  if (header_length < 20 || total_length < header_length + 8
      || total_length > length || packet[9] != IPPROTO_UDP
      || (fragment & UINT16_C (0x3fff)) != 0)
    return 0;

  clib_memset (out, 0, sizeof (*out));
  clib_memcpy_fast (&out->source_address, packet + 12,
                    sizeof (out->source_address));
  clib_memcpy_fast (&out->destination_address, packet + 16,
                    sizeof (out->destination_address));
  out->source_port = product_vpn_read_be16 (packet + header_length);
  out->destination_port = product_vpn_read_be16 (packet + header_length + 2);
  out->udp_length = product_vpn_read_be16 (packet + header_length + 4);
  if (out->udp_length < 8 || header_length + out->udp_length > total_length)
    return 0;
  out->ip_header_length = header_length;
  out->payload_offset = (u16) (header_length + 8);
  out->payload_length = (u16) (out->udp_length - 8);
  return 1;
}

static int
product_vpn_ipv6_extension_header (u8 protocol)
{
  return protocol == IPPROTO_HOPOPTS || protocol == IPPROTO_ROUTING
         || protocol == IPPROTO_FRAGMENT || protocol == IPPROTO_AH
         || protocol == IPPROTO_DSTOPTS;
}

static int
product_vpn_ipv6_transport_offset (const u8 *packet, u32 length,
                                   u8 expected_protocol,
                                   u16 *transport_offset,
                                   u16 *transport_payload_length)
{
  u16 payload_length;
  u32 total_length;
  u32 offset = 40;
  u8 protocol;

  if (packet == 0 || transport_offset == 0 || transport_payload_length == 0
      || length < 40 || (packet[0] >> 4) != 6)
    return 0;
  payload_length = product_vpn_read_be16 (packet + 4);
  total_length = 40U + payload_length;
  if (payload_length == 0 || total_length > length)
    return 0;
  protocol = packet[6];
  for (u32 extensions = 0; extensions < 8; ++extensions)
    {
      u32 header_length;

      if (protocol == expected_protocol)
        {
          if (total_length < offset)
            return 0;
          *transport_offset = (u16) offset;
          *transport_payload_length = (u16) (total_length - offset);
          return 1;
        }
      if (!product_vpn_ipv6_extension_header (protocol))
        return 0;
      if (offset + 2 > total_length)
        return 0;
      if (protocol == IPPROTO_FRAGMENT)
        {
          u16 fragment = product_vpn_read_be16 (packet + offset + 2);
          if (offset + 8 > total_length || (fragment & UINT16_C (0xfff9)) != 0)
            return 0;
          protocol = packet[offset];
          offset += 8;
          continue;
        }
      if (protocol == IPPROTO_AH)
        header_length = ((u32) packet[offset + 1] + 2U) * 4U;
      else
        header_length = ((u32) packet[offset + 1] + 1U) * 8U;
      if (header_length == 0 || offset + header_length > total_length)
        return 0;
      protocol = packet[offset];
      offset += header_length;
    }
  return 0;
}

static int
product_vpn_udp6_parse_tun_origin (const u8 *packet, u32 length,
                                   product_vpn_udp6_packet_t *out)
{
  u16 transport_offset;
  u16 transport_payload_length;
  u16 udp_length;

  if (packet == 0 || out == 0 || length < 48
      || !product_vpn_ipv6_transport_offset (
        packet, length, IPPROTO_UDP, &transport_offset,
        &transport_payload_length))
    return 0;
  if (transport_payload_length < 8)
    return 0;
  udp_length = product_vpn_read_be16 (packet + transport_offset + 4);
  if (udp_length < 8 || udp_length > transport_payload_length)
    return 0;

  clib_memset (out, 0, sizeof (*out));
  clib_memcpy_fast (out->source_address, packet + 8,
                    sizeof (out->source_address));
  clib_memcpy_fast (out->destination_address, packet + 24,
                    sizeof (out->destination_address));
  out->source_port = product_vpn_read_be16 (packet + transport_offset);
  out->destination_port = product_vpn_read_be16 (packet + transport_offset + 2);
  out->transport_offset = transport_offset;
  out->udp_length = udp_length;
  out->payload_offset = (u16) (transport_offset + 8);
  out->payload_length = (u16) (udp_length - 8);
  return 1;
}

static int
product_vpn_tcp6_parse_tun_origin (const u8 *packet, u32 length,
                                   product_vpn_tcp6_packet_t *out)
{
  u16 transport_offset;
  u16 transport_payload_length;
  u8 tcp_header_length;

  if (!product_vpn_ipv6_transport_offset (packet, length, IPPROTO_TCP,
                                          &transport_offset,
                                          &transport_payload_length)
      || out == 0 || transport_payload_length < 20)
    return 0;
  tcp_header_length = (u8) ((packet[transport_offset + 12] >> 4) * 4U);
  if (tcp_header_length < 20 || tcp_header_length > transport_payload_length)
    return 0;

  clib_memset (out, 0, sizeof (*out));
  clib_memcpy_fast (out->source_address, packet + 8,
                    sizeof (out->source_address));
  clib_memcpy_fast (out->destination_address, packet + 24,
                    sizeof (out->destination_address));
  out->source_port = product_vpn_read_be16 (packet + transport_offset);
  out->destination_port = product_vpn_read_be16 (packet + transport_offset + 2);
  out->sequence_number = product_vpn_read_be32 (packet + transport_offset + 4);
  out->acknowledgment_number =
    product_vpn_read_be32 (packet + transport_offset + 8);
  out->flags = packet[transport_offset + 13];
  out->transport_offset = transport_offset;
  out->tcp_header_length = tcp_header_length;
  out->payload_offset = (u16) (transport_offset + tcp_header_length);
  out->payload_length =
    (u16) (transport_payload_length - tcp_header_length);
  return 1;
}

static int
product_vpn_tcp4_parse_tun_origin (const u8 *packet, u32 length,
                                   product_vpn_tcp4_packet_t *out)
{
  u16 total_length;
  u16 fragment;
  u8 ip_header_length;
  u8 tcp_header_length;

  if (packet == 0 || out == 0 || length < 40 || (packet[0] >> 4) != 4)
    return 0;
  ip_header_length = (u8) ((packet[0] & 0x0fU) * 4U);
  total_length = product_vpn_read_be16 (packet + 2);
  fragment = product_vpn_read_be16 (packet + 6);
  if (ip_header_length < 20 || total_length < ip_header_length + 20
      || total_length > length || packet[9] != IPPROTO_TCP
      || (fragment & UINT16_C (0x3fff)) != 0)
    return 0;
  tcp_header_length = (u8) ((packet[ip_header_length + 12] >> 4) * 4U);
  if (tcp_header_length < 20
      || ip_header_length + tcp_header_length > total_length)
    return 0;

  clib_memset (out, 0, sizeof (*out));
  clib_memcpy_fast (&out->source_address, packet + 12,
                    sizeof (out->source_address));
  clib_memcpy_fast (&out->destination_address, packet + 16,
                    sizeof (out->destination_address));
  out->source_port = product_vpn_read_be16 (packet + ip_header_length);
  out->destination_port = product_vpn_read_be16 (packet + ip_header_length + 2);
  out->sequence_number = product_vpn_read_be32 (packet + ip_header_length + 4);
  out->acknowledgment_number =
    product_vpn_read_be32 (packet + ip_header_length + 8);
  out->flags = packet[ip_header_length + 13];
  out->ip_header_length = ip_header_length;
  out->tcp_header_length = tcp_header_length;
  out->payload_offset = (u16) (ip_header_length + tcp_header_length);
  out->payload_length = (u16) (total_length - out->payload_offset);
  return 1;
}

static u64
product_vpn_obligation_id (product_vpn_packet_origin_t origin)
{
  product_vpn_udp4_main_t *nm = &product_vpn_udp4_main;
  nm->next_obligation =
    (nm->next_obligation + 1) & PRODUCT_VPN_OBLIGATION_SEQUENCE_MASK;
  if (nm->next_obligation == 0)
    nm->next_obligation = 1;
  return (((u64) origin) << PRODUCT_VPN_OBLIGATION_ORIGIN_SHIFT)
         | nm->next_obligation;
}

static product_vpn_packet_origin_t
product_vpn_obligation_origin (u64 obligation)
{
  return (product_vpn_packet_origin_t) (obligation
                                       >> PRODUCT_VPN_OBLIGATION_ORIGIN_SHIFT);
}

static void
product_vpn_udp4_remember_flow (product_vpn_udp4_main_t *nm,
                                const product_vpn_udp4_packet_t *parsed)
{
  product_vpn_udp4_flow_t *flow;
  u32 index;

  if (nm == 0 || parsed == 0)
    return;

  for (index = 0; index < PRODUCT_VPN_MAX_UDP4_FLOWS; ++index)
    if (nm->flows[index].active
        && nm->flows[index].remote_address == parsed->destination_address
        && nm->flows[index].remote_port == parsed->destination_port)
      break;
  if (index == PRODUCT_VPN_MAX_UDP4_FLOWS)
    {
      index = nm->next_flow_slot++ % PRODUCT_VPN_MAX_UDP4_FLOWS;
      nm->flows[index].active = 0;
    }

  flow = &nm->flows[index];
  flow->client_address = parsed->source_address;
  flow->remote_address = parsed->destination_address;
  flow->client_port = parsed->source_port;
  flow->remote_port = parsed->destination_port;
  flow->active = 1;
  nm->last_flow = *flow;
}

static const product_vpn_udp4_flow_t *
product_vpn_udp4_find_flow (const product_vpn_udp4_main_t *nm,
                            u32 remote_address, u16 remote_port)
{
  u32 index;

  if (nm == 0)
    return 0;
  for (index = 0; index < PRODUCT_VPN_MAX_UDP4_FLOWS; ++index)
    if (nm->flows[index].active
        && nm->flows[index].remote_address == remote_address
        && nm->flows[index].remote_port == remote_port)
      return &nm->flows[index];
  return 0;
}

static void
product_vpn_udp6_remember_flow (product_vpn_udp4_main_t *nm,
                                const product_vpn_udp6_packet_t *parsed)
{
  product_vpn_udp6_flow_t *flow;
  u32 index;

  if (nm == 0 || parsed == 0)
    return;

  for (index = 0; index < PRODUCT_VPN_MAX_UDP6_FLOWS; ++index)
    if (nm->udp6_flows[index].active
        && memcmp (nm->udp6_flows[index].remote_address,
                   parsed->destination_address, 16) == 0
        && nm->udp6_flows[index].remote_port == parsed->destination_port)
      break;
  if (index == PRODUCT_VPN_MAX_UDP6_FLOWS)
    {
      index = nm->udp6_next_flow_slot++ % PRODUCT_VPN_MAX_UDP6_FLOWS;
      nm->udp6_flows[index].active = 0;
    }

  flow = &nm->udp6_flows[index];
  clib_memcpy_fast (flow->client_address, parsed->source_address,
                    sizeof (flow->client_address));
  clib_memcpy_fast (flow->remote_address, parsed->destination_address,
                    sizeof (flow->remote_address));
  flow->client_port = parsed->source_port;
  flow->remote_port = parsed->destination_port;
  flow->active = 1;
  nm->last_udp6_flow = *flow;
}

static const product_vpn_udp6_flow_t *
product_vpn_udp6_find_flow (const product_vpn_udp4_main_t *nm,
                            const u8 remote_address[16], u16 remote_port)
{
  u32 index;

  if (nm == 0 || remote_address == 0)
    return 0;
  for (index = 0; index < PRODUCT_VPN_MAX_UDP6_FLOWS; ++index)
    if (nm->udp6_flows[index].active
        && memcmp (nm->udp6_flows[index].remote_address, remote_address, 16)
             == 0
        && nm->udp6_flows[index].remote_port == remote_port)
      return &nm->udp6_flows[index];
  return 0;
}

static int product_vpn_udp4_send_direct (product_vpn_udp4_main_t *nm,
                                         const u8 *packet,
                                         const product_vpn_udp4_packet_t
                                           *parsed);
static int product_vpn_udp6_send_direct (product_vpn_udp4_main_t *nm,
                                         const u8 *packet,
                                         const product_vpn_udp6_packet_t
                                           *parsed);
static int product_vpn_tcp4_consume_from_tun (
  product_vpn_udp4_main_t *nm, const u8 *packet,
  const product_vpn_tcp4_packet_t *parsed);
static int product_vpn_tcp6_consume_from_tun (
  product_vpn_udp4_main_t *nm, const u8 *packet,
  const product_vpn_tcp6_packet_t *parsed);
static clib_error_t *product_vpn_tcp4_socket_read_ready (clib_file_t *file);
static clib_error_t *product_vpn_tcp4_socket_write_ready (clib_file_t *file);
static clib_error_t *product_vpn_tcp6_socket_read_ready (clib_file_t *file);
static clib_error_t *product_vpn_tcp6_socket_write_ready (clib_file_t *file);
static clib_error_t *product_vpn_udp6_read_ready (clib_file_t *file);

static u32
product_vpn_tcp4_flow_index (const product_vpn_udp4_main_t *nm,
                             const product_vpn_tcp4_flow_t *flow)
{
  return (u32) (flow - nm->tcp4_flows);
}

static product_vpn_tcp4_flow_t *
product_vpn_tcp4_find_flow (product_vpn_udp4_main_t *nm,
                            const product_vpn_tcp4_packet_t *parsed)
{
  u32 index;

  if (nm == 0 || parsed == 0)
    return 0;
  for (index = 0; index < PRODUCT_VPN_MAX_TCP4_FLOWS; ++index)
    {
      product_vpn_tcp4_flow_t *flow = &nm->tcp4_flows[index];
      if (flow->active && flow->client_address == parsed->source_address
          && flow->remote_address == parsed->destination_address
          && flow->client_port == parsed->source_port
          && flow->remote_port == parsed->destination_port)
        return flow;
    }
  return 0;
}

static product_vpn_tcp4_flow_t *
product_vpn_tcp4_allocate_flow (product_vpn_udp4_main_t *nm,
                                const product_vpn_tcp4_packet_t *parsed)
{
  u32 index;

  if (nm == 0 || parsed == 0)
    return 0;
  for (index = 0; index < PRODUCT_VPN_MAX_TCP4_FLOWS; ++index)
    {
      product_vpn_tcp4_flow_t *flow = &nm->tcp4_flows[index];
      if (!flow->active && flow->fd >= 0
          && flow->state == PRODUCT_VPN_TCP4_SOCKET_IDLE)
        {
          int fd = flow->fd;
          clib_memset (flow, 0, sizeof (*flow));
          flow->fd = fd;
          flow->file_index = ~0;
          flow->client_address = parsed->source_address;
          flow->remote_address = parsed->destination_address;
          flow->client_port = parsed->source_port;
          flow->remote_port = parsed->destination_port;
          flow->client_next_sequence = parsed->sequence_number + 1U;
          flow->server_initial_sequence =
            0x5a181000U + (++nm->tcp4_next_sequence * 0x101U);
          flow->server_next_sequence = flow->server_initial_sequence + 1U;
          flow->active = 1;
          return flow;
        }
    }
  return 0;
}

static u32
product_vpn_tcp6_flow_index (const product_vpn_udp4_main_t *nm,
                             const product_vpn_tcp6_flow_t *flow)
{
  return (u32) (flow - nm->tcp6_flows);
}

static product_vpn_tcp6_flow_t *
product_vpn_tcp6_find_flow (product_vpn_udp4_main_t *nm,
                            const product_vpn_tcp6_packet_t *parsed)
{
  u32 index;

  if (nm == 0 || parsed == 0)
    return 0;
  for (index = 0; index < PRODUCT_VPN_MAX_TCP6_FLOWS; ++index)
    {
      product_vpn_tcp6_flow_t *flow = &nm->tcp6_flows[index];
      if (flow->active
          && memcmp (flow->client_address, parsed->source_address, 16) == 0
          && memcmp (flow->remote_address, parsed->destination_address, 16)
               == 0
          && flow->client_port == parsed->source_port
          && flow->remote_port == parsed->destination_port)
        return flow;
    }
  return 0;
}

static product_vpn_tcp6_flow_t *
product_vpn_tcp6_allocate_flow (product_vpn_udp4_main_t *nm,
                                const product_vpn_tcp6_packet_t *parsed)
{
  u32 index;

  if (nm == 0 || parsed == 0)
    return 0;
  for (index = 0; index < PRODUCT_VPN_MAX_TCP6_FLOWS; ++index)
    {
      product_vpn_tcp6_flow_t *flow = &nm->tcp6_flows[index];
      if (!flow->active && flow->fd >= 0
          && flow->state == PRODUCT_VPN_TCP4_SOCKET_IDLE)
        {
          int fd = flow->fd;
          clib_memset (flow, 0, sizeof (*flow));
          flow->fd = fd;
          flow->file_index = ~0;
          clib_memcpy_fast (flow->client_address, parsed->source_address,
                            sizeof (flow->client_address));
          clib_memcpy_fast (flow->remote_address, parsed->destination_address,
                            sizeof (flow->remote_address));
          flow->client_port = parsed->source_port;
          flow->remote_port = parsed->destination_port;
          flow->client_next_sequence = parsed->sequence_number + 1U;
          flow->server_initial_sequence =
            0x5a183000U + (++nm->tcp6_next_sequence * 0x101U);
          flow->server_next_sequence = flow->server_initial_sequence + 1U;
          flow->active = 1;
          return flow;
        }
    }
  return 0;
}

static void
product_vpn_tcp4_update_write_interest (product_vpn_tcp4_flow_t *flow,
                                        int available)
{
  if (flow == 0 || flow->file_index == ~0)
    return;
  (void) clib_file_set_data_available_to_write (&file_main,
                                                (u32) flow->file_index,
                                                available != 0);
}

static void
product_vpn_tcp6_update_write_interest (product_vpn_tcp6_flow_t *flow,
                                        int available)
{
  if (flow == 0 || flow->file_index == ~0)
    return;
  (void) clib_file_set_data_available_to_write (&file_main,
                                                (u32) flow->file_index,
                                                available != 0);
}

static void
product_vpn_tcp4_release_flow (product_vpn_udp4_main_t *nm,
                               product_vpn_tcp4_flow_t *flow)
{
  if (nm == 0 || flow == 0)
    return;
  if (flow->file_index != ~0)
    {
      clib_file_del_by_index (&file_main, flow->file_index);
      flow->file_index = ~0;
    }
  else if (flow->fd >= 0)
    close (flow->fd);
  flow->fd = -1;
  flow->state = PRODUCT_VPN_TCP4_SOCKET_IDLE;
  flow->active = 0;
  flow->pending_length = 0;
  flow->pending_offset = 0;
  nm->vpn_direct_tcp4_close_completions++;
}

static void
product_vpn_tcp6_release_flow (product_vpn_udp4_main_t *nm,
                               product_vpn_tcp6_flow_t *flow)
{
  if (nm == 0 || flow == 0)
    return;
  if (flow->file_index != ~0)
    {
      clib_file_del_by_index (&file_main, flow->file_index);
      flow->file_index = ~0;
    }
  else if (flow->fd >= 0)
    close (flow->fd);
  flow->fd = -1;
  flow->state = PRODUCT_VPN_TCP4_SOCKET_IDLE;
  flow->active = 0;
  flow->pending_length = 0;
  flow->pending_offset = 0;
  nm->vpn_direct_tcp6_close_completions++;
}

static int
product_vpn_tcp4_submit_return (product_vpn_udp4_main_t *nm,
                                product_vpn_tcp4_flow_t *flow, u8 flags,
                                u32 sequence_number,
                                u32 acknowledgment_number,
                                const u8 *payload, u16 payload_length)
{
  u8 packet[PRODUCT_VPN_MAX_PACKET_BYTES];
  u16 total_length = (u16) (20U + 20U + payload_length);
  u16 tcp_length = (u16) (20U + payload_length);
  u32 buffer_index;
  vlib_buffer_t *buffer;
  product_packet_hints_t hints;
  u64 obligation_id;

  if (nm == 0 || flow == 0 || !flow->active || nm->vlib_main == 0
      || total_length > sizeof (packet)
      || (payload_length != 0 && payload == 0))
    return 0;

  clib_memset (packet, 0, total_length);
  packet[0] = 0x45;
  product_vpn_write_be16 (packet + 2, total_length);
  packet[8] = 64;
  packet[9] = IPPROTO_TCP;
  clib_memcpy_fast (packet + 12, &flow->remote_address,
                    sizeof (flow->remote_address));
  clib_memcpy_fast (packet + 16, &flow->client_address,
                    sizeof (flow->client_address));
  product_vpn_write_be16 (packet + 10, product_vpn_ipv4_checksum (packet, 20));

  product_vpn_write_be16 (packet + 20, flow->remote_port);
  product_vpn_write_be16 (packet + 22, flow->client_port);
  product_vpn_write_be32 (packet + 24, sequence_number);
  product_vpn_write_be32 (packet + 28, acknowledgment_number);
  packet[32] = (u8) (5U << 4);
  packet[33] = flags;
  product_vpn_write_be16 (packet + 34, 65535);
  if (payload_length != 0)
    clib_memcpy_fast (packet + 40, payload, payload_length);
  product_vpn_write_be16 (packet + 36,
                          product_vpn_tcp4_checksum (packet, 20, tcp_length));

  if (vlib_buffer_alloc (nm->vlib_main, &buffer_index, 1) != 1)
    return 0;
  buffer = vlib_get_buffer (nm->vlib_main, buffer_index);
  vlib_buffer_reset (buffer);
  clib_memset (buffer->opaque2, 0, sizeof (buffer->opaque2));
  buffer->current_length = total_length;
  clib_memcpy_fast (vlib_buffer_get_current (buffer), packet, total_length);

  clib_memset (&hints, 0, sizeof (hints));
  hints.uid = UINT32_MAX;
  hints.interface_id = PRODUCT_VPN_PACKET_ORIGIN_FLOW_STACK;
  hints.profile_id = PRODUCT_L4_POLICY_DIRECTION_ANY;
  obligation_id =
    product_vpn_obligation_id (PRODUCT_VPN_PACKET_ORIGIN_FLOW_STACK);
  if (!product_packet_graph_submit_external (nm->vlib_main, buffer_index,
                                             &hints, obligation_id, 0))
    {
      vlib_buffer_free (nm->vlib_main, &buffer_index, 1);
      return 0;
    }
  nm->vpn_flow_stack_return_packets++;
  nm->vpn_direct_tcp4_return_packets++;
  return 1;
}

static int
product_vpn_tcp6_submit_return (product_vpn_udp4_main_t *nm,
                                product_vpn_tcp6_flow_t *flow, u8 flags,
                                u32 sequence_number,
                                u32 acknowledgment_number,
                                const u8 *payload, u16 payload_length)
{
  u8 packet[PRODUCT_VPN_MAX_PACKET_BYTES];
  u16 tcp_length = (u16) (20U + payload_length);
  u16 total_length = (u16) (40U + tcp_length);
  u32 buffer_index;
  vlib_buffer_t *buffer;
  product_packet_hints_t hints;
  u64 obligation_id;

  if (nm == 0 || flow == 0 || !flow->active || nm->vlib_main == 0
      || total_length > sizeof (packet)
      || (payload_length != 0 && payload == 0))
    return 0;

  clib_memset (packet, 0, total_length);
  packet[0] = 0x60;
  product_vpn_write_be16 (packet + 4, tcp_length);
  packet[6] = IPPROTO_TCP;
  packet[7] = 64;
  clib_memcpy_fast (packet + 8, flow->remote_address,
                    sizeof (flow->remote_address));
  clib_memcpy_fast (packet + 24, flow->client_address,
                    sizeof (flow->client_address));

  product_vpn_write_be16 (packet + 40, flow->remote_port);
  product_vpn_write_be16 (packet + 42, flow->client_port);
  product_vpn_write_be32 (packet + 44, sequence_number);
  product_vpn_write_be32 (packet + 48, acknowledgment_number);
  packet[52] = (u8) (5U << 4);
  packet[53] = flags;
  product_vpn_write_be16 (packet + 54, 65535);
  if (payload_length != 0)
    clib_memcpy_fast (packet + 60, payload, payload_length);
  product_vpn_write_be16 (packet + 56,
                          product_vpn_tcp6_checksum (packet, tcp_length));

  if (vlib_buffer_alloc (nm->vlib_main, &buffer_index, 1) != 1)
    return 0;
  buffer = vlib_get_buffer (nm->vlib_main, buffer_index);
  vlib_buffer_reset (buffer);
  clib_memset (buffer->opaque2, 0, sizeof (buffer->opaque2));
  buffer->current_length = total_length;
  clib_memcpy_fast (vlib_buffer_get_current (buffer), packet, total_length);

  clib_memset (&hints, 0, sizeof (hints));
  hints.uid = UINT32_MAX;
  hints.interface_id = PRODUCT_VPN_PACKET_ORIGIN_FLOW_STACK;
  hints.profile_id = PRODUCT_L4_POLICY_DIRECTION_ANY;
  obligation_id =
    product_vpn_obligation_id (PRODUCT_VPN_PACKET_ORIGIN_FLOW_STACK);
  if (!product_packet_graph_submit_external (nm->vlib_main, buffer_index,
                                             &hints, obligation_id, 0))
    {
      vlib_buffer_free (nm->vlib_main, &buffer_index, 1);
      return 0;
    }
  nm->vpn_flow_stack_return_packets++;
  nm->vpn_direct_tcp6_return_packets++;
  return 1;
}

static int
product_vpn_tcp4_register_flow_file (product_vpn_udp4_main_t *nm,
                                     product_vpn_tcp4_flow_t *flow,
                                     int write_interest)
{
  clib_file_t template = { 0 };

  if (nm == 0 || flow == 0 || flow->fd < 0)
    return 0;
  if (flow->file_index != ~0)
    {
      product_vpn_tcp4_update_write_interest (flow, write_interest);
      return 1;
    }
  template.read_function = product_vpn_tcp4_socket_read_ready;
  template.write_function = product_vpn_tcp4_socket_write_ready;
  template.file_descriptor = (u32) flow->fd;
  template.private_data = product_vpn_tcp4_flow_index (nm, flow);
  template.flags = write_interest ? UNIX_FILE_DATA_AVAILABLE_TO_WRITE : 0;
  template.description = format (0, "sakamoto-vpn-direct-tcp4%c", 0);
  flow->file_index = clib_file_add (&file_main, &template);
  return 1;
}

static int
product_vpn_tcp6_register_flow_file (product_vpn_udp4_main_t *nm,
                                     product_vpn_tcp6_flow_t *flow,
                                     int write_interest)
{
  clib_file_t template = { 0 };

  if (nm == 0 || flow == 0 || flow->fd < 0)
    return 0;
  if (flow->file_index != ~0)
    {
      product_vpn_tcp6_update_write_interest (flow, write_interest);
      return 1;
    }
  template.read_function = product_vpn_tcp6_socket_read_ready;
  template.write_function = product_vpn_tcp6_socket_write_ready;
  template.file_descriptor = (u32) flow->fd;
  template.private_data = product_vpn_tcp6_flow_index (nm, flow);
  template.flags = write_interest ? UNIX_FILE_DATA_AVAILABLE_TO_WRITE : 0;
  template.description = format (0, "sakamoto-vpn-direct-tcp6%c", 0);
  flow->file_index = clib_file_add (&file_main, &template);
  return 1;
}

static int
product_vpn_tcp4_finish_connect (product_vpn_udp4_main_t *nm,
                                 product_vpn_tcp4_flow_t *flow)
{
  int value = 0;
  socklen_t value_length = sizeof (value);

  if (nm == 0 || flow == 0 || !flow->active)
    return 0;
  if (flow->state == PRODUCT_VPN_TCP4_ESTABLISHED
      || flow->state == PRODUCT_VPN_TCP4_CLOSING)
    return 1;
  if (flow->state != PRODUCT_VPN_TCP4_CONNECTING)
    return 0;
  if (getsockopt (flow->fd, SOL_SOCKET, SO_ERROR, &value, &value_length) != 0)
    return 0;
  if (value != 0)
    {
      errno = value;
      return 0;
    }
  flow->state = PRODUCT_VPN_TCP4_ESTABLISHED;
  nm->vpn_direct_tcp4_connect_succeeded++;
  if (flow->client_fin_seen)
    (void) shutdown (flow->fd, SHUT_WR);
  return 1;
}

static int
product_vpn_tcp4_flush_pending (product_vpn_udp4_main_t *nm,
                                product_vpn_tcp4_flow_t *flow)
{
  if (nm == 0 || flow == 0 || !flow->active || flow->fd < 0)
    return 0;
  if (!product_vpn_tcp4_finish_connect (nm, flow))
    return errno == EINPROGRESS || errno == EALREADY || errno == EWOULDBLOCK;
  while (flow->pending_offset < flow->pending_length)
    {
      ssize_t sent = send (flow->fd, flow->pending + flow->pending_offset,
                           flow->pending_length - flow->pending_offset,
                           MSG_DONTWAIT | MSG_NOSIGNAL);
      if (sent < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
              product_vpn_tcp4_update_write_interest (flow, 1);
              return 1;
            }
          return 0;
        }
      if (sent == 0)
        return 0;
      flow->pending_offset = (u16) (flow->pending_offset + sent);
      nm->vpn_direct_tcp4_socket_write_completions++;
    }
  flow->pending_length = 0;
  flow->pending_offset = 0;
  product_vpn_tcp4_update_write_interest (flow, 0);
  if (flow->client_fin_seen)
    {
      (void) shutdown (flow->fd, SHUT_WR);
      flow->state = PRODUCT_VPN_TCP4_CLOSING;
    }
  return 1;
}

static int
product_vpn_tcp4_start_connect (product_vpn_udp4_main_t *nm,
                                product_vpn_tcp4_flow_t *flow)
{
  struct sockaddr_storage local;
  socklen_t local_length = sizeof (local);
  struct sockaddr_in remote4;
  struct sockaddr_in6 remote6;
  const struct sockaddr *remote = 0;
  socklen_t remote_length = 0;
  int result;

  if (nm == 0 || flow == 0 || flow->fd < 0)
    return 0;
  clib_memset (&local, 0, sizeof (local));
  if (getsockname (flow->fd, (struct sockaddr *) &local, &local_length) != 0)
    return 0;
  if (local.ss_family == AF_INET6)
    {
      clib_memset (&remote6, 0, sizeof (remote6));
      remote6.sin6_family = AF_INET6;
      remote6.sin6_port = htons (flow->remote_port);
      remote6.sin6_addr.s6_addr[10] = 0xff;
      remote6.sin6_addr.s6_addr[11] = 0xff;
      clib_memcpy_fast (&remote6.sin6_addr.s6_addr[12],
                        &flow->remote_address, sizeof (flow->remote_address));
      remote = (const struct sockaddr *) &remote6;
      remote_length = sizeof (remote6);
    }
  else
    {
      clib_memset (&remote4, 0, sizeof (remote4));
      remote4.sin_family = AF_INET;
      remote4.sin_addr.s_addr = flow->remote_address;
      remote4.sin_port = htons (flow->remote_port);
      remote = (const struct sockaddr *) &remote4;
      remote_length = sizeof (remote4);
    }
  nm->vpn_direct_tcp4_connect_attempts++;
  result = connect (flow->fd, remote, remote_length);
  if (result == 0)
    {
      flow->state = PRODUCT_VPN_TCP4_ESTABLISHED;
      nm->vpn_direct_tcp4_connect_succeeded++;
      return product_vpn_tcp4_register_flow_file (nm, flow, 0);
    }
  if (errno == EINPROGRESS || errno == EALREADY || errno == EWOULDBLOCK)
    {
      flow->state = PRODUCT_VPN_TCP4_CONNECTING;
      return product_vpn_tcp4_register_flow_file (nm, flow, 1);
    }
  return 0;
}

static int
product_vpn_tcp4_accept_payload (product_vpn_udp4_main_t *nm,
                                 product_vpn_tcp4_flow_t *flow,
                                 const u8 *payload, u16 payload_length)
{
  u16 compact_length;

  if (nm == 0 || flow == 0 || payload == 0 || payload_length == 0)
    return 1;
  if (flow->pending_offset != 0)
    {
      compact_length = (u16) (flow->pending_length - flow->pending_offset);
      if (compact_length != 0)
        memmove (flow->pending, flow->pending + flow->pending_offset,
                 compact_length);
      flow->pending_length = compact_length;
      flow->pending_offset = 0;
    }
  if (payload_length > PRODUCT_VPN_TCP4_PENDING_BYTES - flow->pending_length)
    return 0;
  clib_memcpy_fast (flow->pending + flow->pending_length, payload,
                    payload_length);
  flow->pending_length = (u16) (flow->pending_length + payload_length);
  nm->vpn_direct_tcp4_payload_bytes_from_tun += payload_length;
  if (flow->state == PRODUCT_VPN_TCP4_ESTABLISHED
      || flow->state == PRODUCT_VPN_TCP4_CLOSING)
    return product_vpn_tcp4_flush_pending (nm, flow);
  product_vpn_tcp4_update_write_interest (flow, 1);
  return 1;
}

static int
product_vpn_tcp6_finish_connect (product_vpn_udp4_main_t *nm,
                                 product_vpn_tcp6_flow_t *flow)
{
  int value = 0;
  socklen_t value_length = sizeof (value);

  if (nm == 0 || flow == 0 || !flow->active)
    return 0;
  if (flow->state == PRODUCT_VPN_TCP4_ESTABLISHED
      || flow->state == PRODUCT_VPN_TCP4_CLOSING)
    return 1;
  if (flow->state != PRODUCT_VPN_TCP4_CONNECTING)
    return 0;
  if (getsockopt (flow->fd, SOL_SOCKET, SO_ERROR, &value, &value_length) != 0)
    return 0;
  if (value != 0)
    {
      errno = value;
      return 0;
    }
  flow->state = PRODUCT_VPN_TCP4_ESTABLISHED;
  nm->vpn_direct_tcp6_connect_succeeded++;
  if (flow->client_fin_seen)
    (void) shutdown (flow->fd, SHUT_WR);
  return 1;
}

static int
product_vpn_tcp6_flush_pending (product_vpn_udp4_main_t *nm,
                                product_vpn_tcp6_flow_t *flow)
{
  if (nm == 0 || flow == 0 || !flow->active || flow->fd < 0)
    return 0;
  if (!product_vpn_tcp6_finish_connect (nm, flow))
    return errno == EINPROGRESS || errno == EALREADY || errno == EWOULDBLOCK;
  while (flow->pending_offset < flow->pending_length)
    {
      ssize_t sent = send (flow->fd, flow->pending + flow->pending_offset,
                           flow->pending_length - flow->pending_offset,
                           MSG_DONTWAIT | MSG_NOSIGNAL);
      if (sent < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
              product_vpn_tcp6_update_write_interest (flow, 1);
              return 1;
            }
          return 0;
        }
      if (sent == 0)
        return 0;
      flow->pending_offset = (u16) (flow->pending_offset + sent);
      nm->vpn_direct_tcp6_socket_write_completions++;
    }
  flow->pending_length = 0;
  flow->pending_offset = 0;
  product_vpn_tcp6_update_write_interest (flow, 0);
  if (flow->client_fin_seen)
    {
      (void) shutdown (flow->fd, SHUT_WR);
      flow->state = PRODUCT_VPN_TCP4_CLOSING;
    }
  return 1;
}

static int
product_vpn_tcp6_start_connect (product_vpn_udp4_main_t *nm,
                                product_vpn_tcp6_flow_t *flow)
{
  struct sockaddr_storage local;
  socklen_t local_length = sizeof (local);
  struct sockaddr_in6 remote;
  int result;

  if (nm == 0 || flow == 0 || flow->fd < 0)
    return 0;
  clib_memset (&local, 0, sizeof (local));
  if (getsockname (flow->fd, (struct sockaddr *) &local, &local_length) != 0)
    return 0;
  if (local.ss_family != AF_INET6)
    {
      errno = EAFNOSUPPORT;
      return 0;
    }

  clib_memset (&remote, 0, sizeof (remote));
  remote.sin6_family = AF_INET6;
  remote.sin6_port = htons (flow->remote_port);
  clib_memcpy_fast (remote.sin6_addr.s6_addr, flow->remote_address,
                    sizeof (flow->remote_address));
  nm->vpn_direct_tcp6_connect_attempts++;
  result = connect (flow->fd, (const struct sockaddr *) &remote,
                    sizeof (remote));
  if (result == 0)
    {
      flow->state = PRODUCT_VPN_TCP4_ESTABLISHED;
      nm->vpn_direct_tcp6_connect_succeeded++;
      return product_vpn_tcp6_register_flow_file (nm, flow, 0);
    }
  if (errno == EINPROGRESS || errno == EALREADY || errno == EWOULDBLOCK)
    {
      flow->state = PRODUCT_VPN_TCP4_CONNECTING;
      return product_vpn_tcp6_register_flow_file (nm, flow, 1);
    }
  return 0;
}

static int
product_vpn_tcp6_accept_payload (product_vpn_udp4_main_t *nm,
                                 product_vpn_tcp6_flow_t *flow,
                                 const u8 *payload, u16 payload_length)
{
  u16 compact_length;

  if (nm == 0 || flow == 0 || payload == 0 || payload_length == 0)
    return 1;
  if (flow->pending_offset != 0)
    {
      compact_length = (u16) (flow->pending_length - flow->pending_offset);
      if (compact_length != 0)
        memmove (flow->pending, flow->pending + flow->pending_offset,
                 compact_length);
      flow->pending_length = compact_length;
      flow->pending_offset = 0;
    }
  if (payload_length > PRODUCT_VPN_TCP4_PENDING_BYTES - flow->pending_length)
    return 0;
  clib_memcpy_fast (flow->pending + flow->pending_length, payload,
                    payload_length);
  flow->pending_length = (u16) (flow->pending_length + payload_length);
  nm->vpn_direct_tcp6_payload_bytes_from_tun += payload_length;
  if (flow->state == PRODUCT_VPN_TCP4_ESTABLISHED
      || flow->state == PRODUCT_VPN_TCP4_CLOSING)
    return product_vpn_tcp6_flush_pending (nm, flow);
  product_vpn_tcp6_update_write_interest (flow, 1);
  return 1;
}

static void
product_vpn_udp4_complete_from_graph (
  vlib_main_t *vm, u32 buffer_index, const product_packet_lease_t *lease,
  u64 origin_obligation_id,
  product_packet_terminal_intent_t terminal_intent,
  product_packet_runtime_drop_reason_t runtime_drop_reason, void *opaque)
{
  product_vpn_udp4_main_t *nm = opaque;
  vlib_buffer_t *buffer;
  u8 *packet;
  product_vpn_udp4_packet_t parsed;
  product_vpn_packet_origin_t origin =
    product_vpn_obligation_origin (origin_obligation_id);
  (void) lease;
  (void) runtime_drop_reason;

  if (nm == 0 || vm == 0 || terminal_intent != PRODUCT_PACKET_INTENT_PASS_ADAPTER)
    return;
  buffer = vlib_get_buffer (vm, buffer_index);
  packet = vlib_buffer_get_current (buffer);
  if (origin == PRODUCT_VPN_PACKET_ORIGIN_TUN)
    {
      if (!product_vpn_udp4_parse_tun_origin (packet, buffer->current_length,
                                              &parsed))
        {
          product_vpn_tcp4_packet_t tcp4;
          if (!product_vpn_tcp4_parse_tun_origin (packet,
                                                  buffer->current_length,
                                                  &tcp4))
            {
              product_vpn_udp6_packet_t udp6;
              if (!product_vpn_udp6_parse_tun_origin (
                    packet, buffer->current_length, &udp6))
                {
                  product_vpn_tcp6_packet_t tcp6;
                  if (!product_vpn_tcp6_parse_tun_origin (
                        packet, buffer->current_length, &tcp6))
                    {
                      nm->vpn_duplicate_or_stale_drops++;
                      return;
                    }
                  nm->vpn_flow_stack_admissions++;
                  if (!product_vpn_tcp6_consume_from_tun (nm, packet, &tcp6))
                    {
                      nm->vpn_direct_tcp6_transport_failed++;
                      nm->vpn_infrastructure_faults++;
                    }
                  return;
                }
              nm->vpn_flow_stack_admissions++;
              if (!product_vpn_udp6_send_direct (nm, packet, &udp6))
                {
                  nm->vpn_direct_udp6_transport_failed++;
                  nm->vpn_direct_udp6_last_errno = errno;
                  nm->vpn_infrastructure_faults++;
                }
              return;
            }
          nm->vpn_flow_stack_admissions++;
          if (!product_vpn_tcp4_consume_from_tun (nm, packet, &tcp4))
            {
              nm->vpn_direct_tcp4_transport_failed++;
              nm->vpn_infrastructure_faults++;
            }
          return;
        }
      nm->vpn_flow_stack_admissions++;
      if (!product_vpn_udp4_send_direct (nm, packet, &parsed))
        {
          nm->vpn_direct_udp4_transport_failed++;
          nm->vpn_infrastructure_faults++;
        }
      return;
    }
  if (origin == PRODUCT_VPN_PACKET_ORIGIN_FLOW_STACK)
    {
      nm->vpn_flow_stack_return_provenance_packets++;
      if (nm->tun_fd >= 0 && nm->tun_ready
          && write (nm->tun_fd, packet, buffer->current_length)
               == (ssize_t) buffer->current_length)
        {
          nm->vpn_tun_write_completions++;
          if (buffer->current_length >= 20 && (packet[0] >> 4) == 4
              && packet[9] == IPPROTO_TCP)
            nm->vpn_direct_tcp4_tun_write_completions++;
          if (buffer->current_length >= 48 && (packet[0] >> 4) == 6
              && packet[6] == IPPROTO_UDP)
            nm->vpn_direct_udp6_tun_write_completions++;
          if (buffer->current_length >= 60 && (packet[0] >> 4) == 6
              && packet[6] == IPPROTO_TCP)
            nm->vpn_direct_tcp6_tun_write_completions++;
        }
      else
        nm->vpn_infrastructure_faults++;
    }
  else
    nm->vpn_duplicate_or_stale_drops++;
}

static int
product_vpn_udp4_send_direct (product_vpn_udp4_main_t *nm, const u8 *packet,
                              const product_vpn_udp4_packet_t *parsed)
{
  struct sockaddr_in remote;
  ssize_t sent;

  if (nm == 0 || packet == 0 || parsed == 0 || nm->udp_fd < 0
      || !nm->udp_ready)
    return 0;

  clib_memset (&remote, 0, sizeof (remote));
  remote.sin_family = AF_INET;
  remote.sin_addr.s_addr = parsed->destination_address;
  remote.sin_port = htons (parsed->destination_port);
  sent = sendto (nm->udp_fd, packet + parsed->payload_offset,
                 parsed->payload_length, MSG_DONTWAIT,
                 (const struct sockaddr *) &remote, sizeof (remote));
  if (sent != (ssize_t) parsed->payload_length)
    return 0;

  product_vpn_udp4_remember_flow (nm, parsed);
  nm->vpn_direct_udp4_send_succeeded++;
  return 1;
}

static int
product_vpn_udp6_send_direct (product_vpn_udp4_main_t *nm, const u8 *packet,
                              const product_vpn_udp6_packet_t *parsed)
{
  struct sockaddr_in6 remote;
  ssize_t sent;

  if (nm == 0 || packet == 0 || parsed == 0 || nm->udp6_fd < 0
      || !nm->udp6_ready)
    return 0;

  clib_memset (&remote, 0, sizeof (remote));
  remote.sin6_family = AF_INET6;
  clib_memcpy_fast (remote.sin6_addr.s6_addr, parsed->destination_address,
                    sizeof (parsed->destination_address));
  remote.sin6_port = htons (parsed->destination_port);
  sent = sendto (nm->udp6_fd, packet + parsed->payload_offset,
                 parsed->payload_length, MSG_DONTWAIT,
                 (const struct sockaddr *) &remote, sizeof (remote));
  if (sent != (ssize_t) parsed->payload_length)
    return 0;

  product_vpn_udp6_remember_flow (nm, parsed);
  nm->vpn_direct_udp6_send_succeeded++;
  return 1;
}

static u32
product_vpn_udp4_build_return_packet (const product_vpn_udp4_flow_t *flow,
                                      u32 remote_address, u16 remote_port,
                                      const u8 *payload, u16 payload_length,
                                      u8 *packet, u32 packet_capacity)
{
  u16 total_length = (u16) (20U + 8U + payload_length);
  u16 checksum;

  if (flow == 0 || payload == 0 || packet == 0 || !flow->active
      || packet_capacity < total_length)
    return 0;
  if (remote_address != flow->remote_address || remote_port != flow->remote_port)
    return 0;

  clib_memset (packet, 0, total_length);
  packet[0] = 0x45;
  product_vpn_write_be16 (packet + 2, total_length);
  packet[8] = 64;
  packet[9] = IPPROTO_UDP;
  clib_memcpy_fast (packet + 12, &flow->remote_address,
                    sizeof (flow->remote_address));
  clib_memcpy_fast (packet + 16, &flow->client_address,
                    sizeof (flow->client_address));
  checksum = product_vpn_ipv4_checksum (packet, 20);
  product_vpn_write_be16 (packet + 10, checksum);

  product_vpn_write_be16 (packet + 20, flow->remote_port);
  product_vpn_write_be16 (packet + 22, flow->client_port);
  product_vpn_write_be16 (packet + 24, (u16) (8U + payload_length));
  clib_memcpy_fast (packet + 28, payload, payload_length);
  return total_length;
}

static u32
product_vpn_udp6_build_return_packet (
  const product_vpn_udp6_flow_t *flow, const u8 remote_address[16],
  u16 remote_port, const u8 *payload, u16 payload_length, u8 *packet,
  u32 packet_capacity)
{
  u16 udp_length = (u16) (8U + payload_length);
  u16 total_length = (u16) (40U + udp_length);
  u16 checksum;

  if (flow == 0 || remote_address == 0 || payload == 0 || packet == 0
      || !flow->active || packet_capacity < total_length)
    return 0;
  if (memcmp (remote_address, flow->remote_address, 16) != 0
      || remote_port != flow->remote_port)
    return 0;

  clib_memset (packet, 0, total_length);
  packet[0] = 0x60;
  product_vpn_write_be16 (packet + 4, udp_length);
  packet[6] = IPPROTO_UDP;
  packet[7] = 64;
  clib_memcpy_fast (packet + 8, flow->remote_address,
                    sizeof (flow->remote_address));
  clib_memcpy_fast (packet + 24, flow->client_address,
                    sizeof (flow->client_address));

  product_vpn_write_be16 (packet + 40, flow->remote_port);
  product_vpn_write_be16 (packet + 42, flow->client_port);
  product_vpn_write_be16 (packet + 44, udp_length);
  product_vpn_write_be16 (packet + 46, 0);
  clib_memcpy_fast (packet + 48, payload, payload_length);
  checksum = product_vpn_udp6_checksum (packet, udp_length);
  product_vpn_write_be16 (packet + 46, checksum);
  return total_length;
}

static clib_error_t *
product_vpn_tun_read_ready (clib_file_t *file)
{
  product_vpn_udp4_main_t *nm = &product_vpn_udp4_main;
  vlib_main_t *vm = nm->vlib_main;
  u8 *packet;
  product_vpn_udp4_packet_t parsed;
  product_packet_hints_t hints;
  product_packet_graph_external_result_t graph_result;
  u32 buffer_index;
  vlib_buffer_t *buffer;
  ssize_t received;
  u64 obligation_id;
  int submitted;

  (void) file;
  if (vm == 0 || nm->tun_fd < 0 || !nm->tun_ready)
    return 0;

  while (1)
    {
      if (vlib_buffer_alloc (vm, &buffer_index, 1) != 1)
        {
          nm->vpn_infrastructure_faults++;
          return 0;
        }
      buffer = vlib_get_buffer (vm, buffer_index);
      vlib_buffer_reset (buffer);
      clib_memset (buffer->opaque2, 0, sizeof (buffer->opaque2));
      packet = vlib_buffer_get_current (buffer);
      received = read (nm->tun_fd, packet, vlib_buffer_get_default_data_size (vm));
      if (received < 0)
        {
          int saved_errno = errno;
          vlib_buffer_free (vm, &buffer_index, 1);
          if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK)
            return 0;
          nm->vpn_infrastructure_faults++;
          return 0;
        }
      if (received == 0)
        {
          vlib_buffer_free (vm, &buffer_index, 1);
          nm->vpn_infrastructure_faults++;
          return 0;
        }
      if (received > (ssize_t) vlib_buffer_get_default_data_size (vm))
        {
          vlib_buffer_free (vm, &buffer_index, 1);
          nm->vpn_infrastructure_faults++;
          continue;
        }

      nm->vpn_tun_ingress_packets++;
      buffer->current_length = (u16) received;
      if (!product_vpn_udp4_parse_tun_origin (packet, (u32) received,
                                              &parsed))
        {
          product_vpn_tcp4_packet_t tcp4;
          if (!product_vpn_tcp4_parse_tun_origin (packet, (u32) received,
                                                  &tcp4))
            {
              product_vpn_udp6_packet_t udp6;
              if (!product_vpn_udp6_parse_tun_origin (packet, (u32) received,
                                                       &udp6))
                {
                  product_vpn_tcp6_packet_t tcp6;
                  if (!product_vpn_tcp6_parse_tun_origin (
                        packet, (u32) received, &tcp6))
                    {
                      vlib_buffer_free (vm, &buffer_index, 1);
                      continue;
                    }
                  nm->vpn_tun_tcp6_tun_origin_packets++;
                }
              else
                {
                  nm->vpn_tun_udp6_tun_origin_packets++;
                }
            }
          else
            {
              nm->vpn_tun_tcp4_tun_origin_packets++;
            }
        }
      else
        {
          nm->vpn_tun_udp4_tun_origin_packets++;
        }

      clib_memset (&hints, 0, sizeof (hints));
      hints.uid = nm->policy_subject_uid;
      /* TUN origin is provenance, while the inner packet is device OUTPUT. */
      hints.interface_id = PRODUCT_VPN_PACKET_ORIGIN_TUN;
      hints.network_context_id = nm->policy_network_context_id;
      hints.profile_id = PRODUCT_L4_POLICY_DIRECTION_OUTPUT;
      obligation_id = product_vpn_obligation_id (PRODUCT_VPN_PACKET_ORIGIN_TUN);
      submitted = product_packet_graph_submit_external (
        vm, buffer_index, &hints, obligation_id, &graph_result);
      if (!submitted)
        {
          nm->vpn_infrastructure_faults++;
          vlib_buffer_free (vm, &buffer_index, 1);
          continue;
        }
    }
}

static clib_error_t *
product_vpn_udp_read_ready (clib_file_t *file)
{
  product_vpn_udp4_main_t *nm = &product_vpn_udp4_main;
  vlib_main_t *vm = nm->vlib_main;
  u8 payload[PRODUCT_VPN_MAX_PACKET_BYTES];
  u8 packet[PRODUCT_VPN_MAX_PACKET_BYTES];
  struct sockaddr_storage remote;
  socklen_t remote_length = sizeof (remote);
  u32 remote_address;
  u16 remote_port;
  ssize_t received;
  u32 packet_length;
  u32 buffer_index;
  vlib_buffer_t *buffer;
  product_packet_hints_t hints;
  const product_vpn_udp4_flow_t *flow;
  u64 obligation_id;
  int submitted;

  (void) file;
  if (vm == 0 || nm->udp_fd < 0 || !nm->udp_ready)
    return 0;

  while (1)
    {
      clib_memset (&remote, 0, sizeof (remote));
      remote_length = sizeof (remote);
      received = recvfrom (nm->udp_fd, payload, sizeof (payload),
                           MSG_DONTWAIT, (struct sockaddr *) &remote,
                           &remote_length);
      if (received < 0)
        {
          int saved_errno = errno;
          if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK)
            return 0;
          nm->vpn_direct_udp4_transport_failed++;
          nm->vpn_infrastructure_faults++;
          return 0;
        }
      if (received == 0 || received > UINT16_MAX - 28)
        {
          nm->vpn_duplicate_or_stale_drops++;
          continue;
        }

      if (!product_vpn_udp4_from_sockaddr (&remote, remote_length,
                                           &remote_address, &remote_port))
        {
          nm->vpn_duplicate_or_stale_drops++;
          continue;
        }
      flow = product_vpn_udp4_find_flow (nm, remote_address, remote_port);
      packet_length = product_vpn_udp4_build_return_packet (
        flow, remote_address, remote_port, payload, (u16) received, packet,
        sizeof (packet));
      if (packet_length == 0)
        {
          nm->vpn_duplicate_or_stale_drops++;
          continue;
        }
      nm->vpn_flow_stack_return_packets++;

      if (vlib_buffer_alloc (vm, &buffer_index, 1) != 1)
        {
          nm->vpn_infrastructure_faults++;
          return 0;
        }
      buffer = vlib_get_buffer (vm, buffer_index);
      vlib_buffer_reset (buffer);
      clib_memset (buffer->opaque2, 0, sizeof (buffer->opaque2));
      buffer->current_length = (u16) packet_length;
      clib_memcpy_fast (vlib_buffer_get_current (buffer), packet,
                        packet_length);

      clib_memset (&hints, 0, sizeof (hints));
      hints.uid = UINT32_MAX;
      hints.interface_id = PRODUCT_VPN_PACKET_ORIGIN_FLOW_STACK;
      hints.profile_id = PRODUCT_L4_POLICY_DIRECTION_ANY;
      obligation_id =
        product_vpn_obligation_id (PRODUCT_VPN_PACKET_ORIGIN_FLOW_STACK);
      submitted = product_packet_graph_submit_external (
        vm, buffer_index, &hints, obligation_id, 0);
      if (!submitted)
        {
          nm->vpn_infrastructure_faults++;
          vlib_buffer_free (vm, &buffer_index, 1);
          continue;
        }
    }
}

static clib_error_t *
product_vpn_udp6_read_ready (clib_file_t *file)
{
  product_vpn_udp4_main_t *nm = &product_vpn_udp4_main;
  vlib_main_t *vm = nm->vlib_main;
  u8 payload[PRODUCT_VPN_MAX_PACKET_BYTES];
  u8 packet[PRODUCT_VPN_MAX_PACKET_BYTES];
  struct sockaddr_storage remote;
  socklen_t remote_length = sizeof (remote);
  u8 remote_address[16];
  u16 remote_port;
  ssize_t received;
  u32 packet_length;
  u32 buffer_index;
  vlib_buffer_t *buffer;
  product_packet_hints_t hints;
  const product_vpn_udp6_flow_t *flow;
  u64 obligation_id;
  int submitted;

  (void) file;
  if (vm == 0 || nm->udp6_fd < 0 || !nm->udp6_ready)
    return 0;

  while (1)
    {
      clib_memset (&remote, 0, sizeof (remote));
      remote_length = sizeof (remote);
      received = recvfrom (nm->udp6_fd, payload, sizeof (payload),
                           MSG_DONTWAIT, (struct sockaddr *) &remote,
                           &remote_length);
      if (received < 0)
        {
          int saved_errno = errno;
          if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK)
            return 0;
          nm->vpn_direct_udp6_transport_failed++;
          nm->vpn_direct_udp6_last_errno = saved_errno;
          nm->vpn_infrastructure_faults++;
          return 0;
        }
      if (received == 0 || received > UINT16_MAX - 48)
        {
          nm->vpn_duplicate_or_stale_drops++;
          continue;
        }

      if (!product_vpn_udp6_from_sockaddr (&remote, remote_length,
                                           remote_address, &remote_port))
        {
          nm->vpn_duplicate_or_stale_drops++;
          continue;
        }
      flow = product_vpn_udp6_find_flow (nm, remote_address, remote_port);
      packet_length = product_vpn_udp6_build_return_packet (
        flow, remote_address, remote_port, payload, (u16) received, packet,
        sizeof (packet));
      if (packet_length == 0)
        {
          nm->vpn_duplicate_or_stale_drops++;
          continue;
        }
      nm->vpn_flow_stack_return_packets++;
      nm->vpn_direct_udp6_return_packets++;

      if (vlib_buffer_alloc (vm, &buffer_index, 1) != 1)
        {
          nm->vpn_infrastructure_faults++;
          return 0;
        }
      buffer = vlib_get_buffer (vm, buffer_index);
      vlib_buffer_reset (buffer);
      clib_memset (buffer->opaque2, 0, sizeof (buffer->opaque2));
      buffer->current_length = (u16) packet_length;
      clib_memcpy_fast (vlib_buffer_get_current (buffer), packet,
                        packet_length);

      clib_memset (&hints, 0, sizeof (hints));
      hints.uid = UINT32_MAX;
      hints.interface_id = PRODUCT_VPN_PACKET_ORIGIN_FLOW_STACK;
      hints.profile_id = PRODUCT_L4_POLICY_DIRECTION_ANY;
      obligation_id =
        product_vpn_obligation_id (PRODUCT_VPN_PACKET_ORIGIN_FLOW_STACK);
      submitted = product_packet_graph_submit_external (
        vm, buffer_index, &hints, obligation_id, 0);
      if (!submitted)
        {
          nm->vpn_infrastructure_faults++;
          vlib_buffer_free (vm, &buffer_index, 1);
          continue;
        }
    }
}

static clib_error_t *
product_vpn_tcp4_socket_write_ready (clib_file_t *file)
{
  product_vpn_udp4_main_t *nm = &product_vpn_udp4_main;
  u32 index;
  product_vpn_tcp4_flow_t *flow;

  if (file == 0)
    return 0;
  index = (u32) file->private_data;
  if (index >= PRODUCT_VPN_MAX_TCP4_FLOWS)
    return 0;
  flow = &nm->tcp4_flows[index];
  if (!flow->active || flow->fd < 0)
    return 0;
  if (!product_vpn_tcp4_flush_pending (nm, flow))
    {
      nm->vpn_direct_tcp4_transport_failed++;
      nm->vpn_infrastructure_faults++;
      nm->vpn_direct_tcp4_last_errno = errno;
      product_vpn_tcp4_release_flow (nm, flow);
    }
  return 0;
}

static clib_error_t *
product_vpn_tcp4_socket_read_ready (clib_file_t *file)
{
  product_vpn_udp4_main_t *nm = &product_vpn_udp4_main;
  u32 index;
  product_vpn_tcp4_flow_t *flow;
  u8 payload[PRODUCT_VPN_TCP4_PENDING_BYTES];

  if (file == 0)
    return 0;
  index = (u32) file->private_data;
  if (index >= PRODUCT_VPN_MAX_TCP4_FLOWS)
    return 0;
  flow = &nm->tcp4_flows[index];
  if (!flow->active || flow->fd < 0)
    return 0;

  if (flow->state == PRODUCT_VPN_TCP4_CONNECTING
      && !product_vpn_tcp4_finish_connect (nm, flow))
    {
      nm->vpn_direct_tcp4_transport_failed++;
      nm->vpn_infrastructure_faults++;
      nm->vpn_direct_tcp4_last_errno = errno;
      product_vpn_tcp4_release_flow (nm, flow);
      return 0;
    }

  while (1)
    {
      ssize_t received =
        recv (flow->fd, payload, sizeof (payload), MSG_DONTWAIT);
      if (received < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
          nm->vpn_direct_tcp4_transport_failed++;
          nm->vpn_infrastructure_faults++;
          nm->vpn_direct_tcp4_last_errno = errno;
          product_vpn_tcp4_release_flow (nm, flow);
          return 0;
        }
      if (received == 0)
        {
          if (!flow->server_fin_sent)
            {
              flow->server_fin_sent = 1;
              if (!product_vpn_tcp4_submit_return (
                    nm, flow, PRODUCT_VPN_TCP_FLAG_FIN | PRODUCT_VPN_TCP_FLAG_ACK,
                    flow->server_next_sequence, flow->client_next_sequence, 0,
                    0))
                nm->vpn_infrastructure_faults++;
              flow->server_next_sequence++;
            }
          product_vpn_tcp4_release_flow (nm, flow);
          return 0;
        }

      nm->vpn_direct_tcp4_socket_read_packets++;
      if (!product_vpn_tcp4_submit_return (
            nm, flow, PRODUCT_VPN_TCP_FLAG_PSH | PRODUCT_VPN_TCP_FLAG_ACK,
            flow->server_next_sequence, flow->client_next_sequence, payload,
            (u16) received))
        {
          nm->vpn_infrastructure_faults++;
          return 0;
        }
      flow->server_next_sequence = (u32) (flow->server_next_sequence + received);
    }
}

static int
product_vpn_tcp4_consume_from_tun (product_vpn_udp4_main_t *nm,
                                   const u8 *packet,
                                   const product_vpn_tcp4_packet_t *parsed)
{
  product_vpn_tcp4_flow_t *flow;

  if (nm == 0 || packet == 0 || parsed == 0)
    return 0;
  flow = product_vpn_tcp4_find_flow (nm, parsed);

  if ((parsed->flags & PRODUCT_VPN_TCP_FLAG_RST) != 0)
    {
      if (flow != 0)
        product_vpn_tcp4_release_flow (nm, flow);
      else
        nm->vpn_duplicate_or_stale_drops++;
      return 1;
    }

  if ((parsed->flags & PRODUCT_VPN_TCP_FLAG_SYN) != 0
      && (parsed->flags & PRODUCT_VPN_TCP_FLAG_ACK) == 0)
    {
      if (flow == 0)
        {
          flow = product_vpn_tcp4_allocate_flow (nm, parsed);
          if (flow == 0)
            {
              nm->vpn_duplicate_or_stale_drops++;
              return 1;
            }
          if (!product_vpn_tcp4_start_connect (nm, flow))
            {
              nm->vpn_direct_tcp4_last_errno = errno;
              product_vpn_tcp4_release_flow (nm, flow);
              return 0;
            }
        }
      return product_vpn_tcp4_submit_return (
        nm, flow, PRODUCT_VPN_TCP_FLAG_SYN | PRODUCT_VPN_TCP_FLAG_ACK,
        flow->server_initial_sequence, flow->client_next_sequence, 0, 0);
    }

  if (flow == 0)
    {
      nm->vpn_duplicate_or_stale_drops++;
      return 1;
    }

  if (parsed->payload_length != 0)
    {
      flow->client_next_sequence =
        (u32) (parsed->sequence_number + parsed->payload_length);
      if (!product_vpn_tcp4_accept_payload (
            nm, flow, packet + parsed->payload_offset,
            parsed->payload_length))
        return 0;
      if (!product_vpn_tcp4_submit_return (
            nm, flow, PRODUCT_VPN_TCP_FLAG_ACK, flow->server_next_sequence,
            flow->client_next_sequence, 0, 0))
        return 0;
    }

  if ((parsed->flags & PRODUCT_VPN_TCP_FLAG_FIN) != 0)
    {
      flow->client_fin_seen = 1;
      flow->client_next_sequence =
        (u32) (parsed->sequence_number + parsed->payload_length + 1U);
      if (flow->state == PRODUCT_VPN_TCP4_ESTABLISHED
          && flow->pending_length == flow->pending_offset)
        {
          (void) shutdown (flow->fd, SHUT_WR);
          flow->state = PRODUCT_VPN_TCP4_CLOSING;
        }
      return product_vpn_tcp4_submit_return (
        nm, flow, PRODUCT_VPN_TCP_FLAG_ACK, flow->server_next_sequence,
        flow->client_next_sequence, 0, 0);
    }

  if (flow->state == PRODUCT_VPN_TCP4_CONNECTING)
    {
      if (!product_vpn_tcp4_finish_connect (nm, flow))
        return 1;
      if (flow->pending_length != flow->pending_offset
          && !product_vpn_tcp4_flush_pending (nm, flow))
        return 0;
    }

  return 1;
}

static clib_error_t *
product_vpn_tcp6_socket_write_ready (clib_file_t *file)
{
  product_vpn_udp4_main_t *nm = &product_vpn_udp4_main;
  u32 index;
  product_vpn_tcp6_flow_t *flow;

  if (file == 0)
    return 0;
  index = (u32) file->private_data;
  if (index >= PRODUCT_VPN_MAX_TCP6_FLOWS)
    return 0;
  flow = &nm->tcp6_flows[index];
  if (!flow->active || flow->fd < 0)
    return 0;
  if (!product_vpn_tcp6_flush_pending (nm, flow))
    {
      nm->vpn_direct_tcp6_transport_failed++;
      nm->vpn_infrastructure_faults++;
      nm->vpn_direct_tcp6_last_errno = errno;
      product_vpn_tcp6_release_flow (nm, flow);
    }
  return 0;
}

static clib_error_t *
product_vpn_tcp6_socket_read_ready (clib_file_t *file)
{
  product_vpn_udp4_main_t *nm = &product_vpn_udp4_main;
  u32 index;
  product_vpn_tcp6_flow_t *flow;
  u8 payload[PRODUCT_VPN_TCP4_PENDING_BYTES];

  if (file == 0)
    return 0;
  index = (u32) file->private_data;
  if (index >= PRODUCT_VPN_MAX_TCP6_FLOWS)
    return 0;
  flow = &nm->tcp6_flows[index];
  if (!flow->active || flow->fd < 0)
    return 0;

  if (flow->state == PRODUCT_VPN_TCP4_CONNECTING
      && !product_vpn_tcp6_finish_connect (nm, flow))
    {
      nm->vpn_direct_tcp6_transport_failed++;
      nm->vpn_infrastructure_faults++;
      nm->vpn_direct_tcp6_last_errno = errno;
      product_vpn_tcp6_release_flow (nm, flow);
      return 0;
    }

  while (1)
    {
      ssize_t received =
        recv (flow->fd, payload, sizeof (payload), MSG_DONTWAIT);
      if (received < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
          nm->vpn_direct_tcp6_transport_failed++;
          nm->vpn_infrastructure_faults++;
          nm->vpn_direct_tcp6_last_errno = errno;
          product_vpn_tcp6_release_flow (nm, flow);
          return 0;
        }
      if (received == 0)
        {
          if (!flow->server_fin_sent)
            {
              flow->server_fin_sent = 1;
              if (!product_vpn_tcp6_submit_return (
                    nm, flow, PRODUCT_VPN_TCP_FLAG_FIN | PRODUCT_VPN_TCP_FLAG_ACK,
                    flow->server_next_sequence, flow->client_next_sequence, 0,
                    0))
                nm->vpn_infrastructure_faults++;
              flow->server_next_sequence++;
            }
          product_vpn_tcp6_release_flow (nm, flow);
          return 0;
        }

      nm->vpn_direct_tcp6_socket_read_packets++;
      if (!product_vpn_tcp6_submit_return (
            nm, flow, PRODUCT_VPN_TCP_FLAG_PSH | PRODUCT_VPN_TCP_FLAG_ACK,
            flow->server_next_sequence, flow->client_next_sequence, payload,
            (u16) received))
        {
          nm->vpn_infrastructure_faults++;
          return 0;
        }
      flow->server_next_sequence = (u32) (flow->server_next_sequence + received);
    }
}

static int
product_vpn_tcp6_consume_from_tun (product_vpn_udp4_main_t *nm,
                                   const u8 *packet,
                                   const product_vpn_tcp6_packet_t *parsed)
{
  product_vpn_tcp6_flow_t *flow;

  if (nm == 0 || packet == 0 || parsed == 0)
    return 0;
  flow = product_vpn_tcp6_find_flow (nm, parsed);

  if ((parsed->flags & PRODUCT_VPN_TCP_FLAG_RST) != 0)
    {
      if (flow != 0)
        product_vpn_tcp6_release_flow (nm, flow);
      else
        nm->vpn_duplicate_or_stale_drops++;
      return 1;
    }

  if ((parsed->flags & PRODUCT_VPN_TCP_FLAG_SYN) != 0
      && (parsed->flags & PRODUCT_VPN_TCP_FLAG_ACK) == 0)
    {
      if (flow == 0)
        {
          flow = product_vpn_tcp6_allocate_flow (nm, parsed);
          if (flow == 0)
            {
              nm->vpn_duplicate_or_stale_drops++;
              return 1;
            }
          if (!product_vpn_tcp6_start_connect (nm, flow))
            {
              nm->vpn_direct_tcp6_last_errno = errno;
              product_vpn_tcp6_release_flow (nm, flow);
              return 0;
            }
        }
      return product_vpn_tcp6_submit_return (
        nm, flow, PRODUCT_VPN_TCP_FLAG_SYN | PRODUCT_VPN_TCP_FLAG_ACK,
        flow->server_initial_sequence, flow->client_next_sequence, 0, 0);
    }

  if (flow == 0)
    {
      nm->vpn_duplicate_or_stale_drops++;
      return 1;
    }

  if (parsed->payload_length != 0)
    {
      flow->client_next_sequence =
        (u32) (parsed->sequence_number + parsed->payload_length);
      if (!product_vpn_tcp6_accept_payload (
            nm, flow, packet + parsed->payload_offset,
            parsed->payload_length))
        return 0;
      if (!product_vpn_tcp6_submit_return (
            nm, flow, PRODUCT_VPN_TCP_FLAG_ACK, flow->server_next_sequence,
            flow->client_next_sequence, 0, 0))
        return 0;
    }

  if ((parsed->flags & PRODUCT_VPN_TCP_FLAG_FIN) != 0)
    {
      flow->client_fin_seen = 1;
      flow->client_next_sequence =
        (u32) (parsed->sequence_number + parsed->payload_length + 1U);
      if (flow->state == PRODUCT_VPN_TCP4_ESTABLISHED
          && flow->pending_length == flow->pending_offset)
        {
          (void) shutdown (flow->fd, SHUT_WR);
          flow->state = PRODUCT_VPN_TCP4_CLOSING;
        }
      return product_vpn_tcp6_submit_return (
        nm, flow, PRODUCT_VPN_TCP_FLAG_ACK, flow->server_next_sequence,
        flow->client_next_sequence, 0, 0);
    }

  if (flow->state == PRODUCT_VPN_TCP4_CONNECTING)
    {
      if (!product_vpn_tcp6_finish_connect (nm, flow))
        return 1;
      if (flow->pending_length != flow->pending_offset
          && !product_vpn_tcp6_flush_pending (nm, flow))
        return 0;
    }

  return 1;
}

static int
product_vpn_parse_netstring_payload (u8 *frame, ssize_t received,
                                     char **payload, u32 *payload_length)
{
  ssize_t cursor = 0;
  unsigned long length = 0;

  if (frame == 0 || payload == 0 || payload_length == 0 || received <= 0)
    return 0;
  while (cursor < received && frame[cursor] >= '0' && frame[cursor] <= '9')
    {
      length = length * 10U + (unsigned long) (frame[cursor] - '0');
      if (length > PRODUCT_VPN_CONTROL_BUFFER_BYTES - 1)
        return 0;
      cursor++;
    }
  if (cursor == 0 || cursor >= received || frame[cursor] != ':')
    return 0;
  cursor++;
  if (cursor + (ssize_t) length >= received
      || frame[cursor + (ssize_t) length] != ',')
    return 0;
  frame[cursor + (ssize_t) length] = '\0';
  *payload = (char *) (frame + cursor);
  *payload_length = (u32) length;
  return 1;
}

static int
product_vpn_payload_has (const char *payload, const char *needle)
{
  return payload != 0 && needle != 0 && strstr (payload, needle) != 0;
}

static int
product_vpn_payload_u32 (const char *payload, const char *key, u32 *value)
{
  char pattern[64];
  const char *cursor;
  unsigned long long parsed = 0;
  int length;

  if (payload == 0 || key == 0 || value == 0)
    return 0;
  length = snprintf (pattern, sizeof (pattern), "\"%s\":", key);
  if (length <= 0 || (size_t) length >= sizeof (pattern))
    return 0;
  cursor = strstr (payload, pattern);
  if (cursor == 0)
    return 0;
  cursor += length;
  while (*cursor == ' ')
    cursor++;
  if (*cursor < '0' || *cursor > '9')
    return 0;
  while (*cursor >= '0' && *cursor <= '9')
    {
      parsed = parsed * 10ULL + (unsigned long long) (*cursor - '0');
      if (parsed > UINT32_MAX)
        return 0;
      cursor++;
    }
  *value = (u32) parsed;
  return 1;
}

static int
product_vpn_send_json_response (int fd, const char *json)
{
  char frame[PRODUCT_VPN_CONTROL_BUFFER_BYTES];
  int length;
  ssize_t sent;

  if (json == 0)
    json = "{\"ok\":false,\"error\":{\"code\":\"VPN_CONTROL_FAILED\"}}";
  length = snprintf (frame, sizeof (frame), "%zu:%s,", strlen (json), json);
  if (length <= 0 || (size_t) length >= sizeof (frame))
    return 0;
  sent = send (fd, frame, (size_t) length, MSG_NOSIGNAL);
  return sent == length;
}

static void
product_vpn_send_status_response (product_vpn_udp4_main_t *nm, int fd)
{
  char json[PRODUCT_VPN_CONTROL_BUFFER_BYTES];
  int length;

  if (nm == 0)
    {
      product_vpn_send_json_response (
        fd,
        "{\"ok\":false,\"error\":{\"code\":\"VPN_CONTROL_STATUS_FAILED\","
        "\"message\":\"VPN adapter state is unavailable\"}}");
      return;
    }

  length = snprintf (
    json, sizeof (json),
    "{\"ok\":true,\"result\":{\"adapter\":\"vpn-tun-hev-lwip\","
    "\"fdAttached\":%s,\"transportFdAttached\":%s,\"ipv6Enabled\":true,"
    "\"policySubjectUid\":%u,"
    "\"policyNetworkContext\":%llu,"
    "\"policyDropActivity\":{\"totalRecords\":0},"
    "\"allowedFlowActivity\":{\"totalRecords\":0},"
    "\"vpnTunFdAttached\":%llu,"
    "\"vpnDirectUdp4SocketAttached\":%llu,"
    "\"vpnDirectUdp4ProtectSucceeded\":%llu,"
    "\"vpnDirectUdp4BindSucceeded\":%llu,"
    "\"vpnDirectUdp6SocketAttached\":%llu,"
    "\"vpnDirectUdp6ProtectSucceeded\":%llu,"
    "\"vpnDirectUdp6BindSucceeded\":%llu,"
    "\"vpnDirectTcp4SocketAttached\":%llu,"
    "\"vpnDirectTcp4ProtectSucceeded\":%llu,"
    "\"vpnDirectTcp4BindSucceeded\":%llu,"
    "\"vpnDirectTcp6SocketAttached\":%llu,"
    "\"vpnDirectTcp6ProtectSucceeded\":%llu,"
    "\"vpnDirectTcp6BindSucceeded\":%llu,"
    "\"vpnTunIngressPackets\":%llu,"
    "\"vpnTunUdp4TunOriginPackets\":%llu,"
    "\"vpnTunUdp6TunOriginPackets\":%llu,"
    "\"vpnTunTcp4TunOriginPackets\":%llu,"
    "\"vpnTunTcp6TunOriginPackets\":%llu,"
    "\"vpnFlowStackAdmissions\":%llu,"
    "\"vpnDirectUdp4SendSucceeded\":%llu,"
    "\"vpnDirectUdp4TransportFailed\":%llu,"
    "\"vpnDirectUdp6SendSucceeded\":%llu,"
    "\"vpnDirectUdp6TransportFailed\":%llu,"
    "\"vpnDirectUdp6ReturnPackets\":%llu,"
    "\"vpnDirectUdp6TunWriteCompletions\":%llu,"
    "\"vpnDirectUdp6LastErrno\":%llu,"
    "\"vpnDirectTcp4ConnectAttempts\":%llu,"
    "\"vpnDirectTcp4ConnectSucceeded\":%llu,"
    "\"vpnDirectTcp4PayloadBytesFromTun\":%llu,"
    "\"vpnDirectTcp4SocketWriteCompletions\":%llu,"
    "\"vpnDirectTcp4SocketReadPackets\":%llu,"
    "\"vpnDirectTcp4ReturnPackets\":%llu,"
    "\"vpnDirectTcp4TunWriteCompletions\":%llu,"
    "\"vpnDirectTcp4TransportFailed\":%llu,"
    "\"vpnDirectTcp4CloseCompletions\":%llu,"
    "\"vpnDirectTcp4LastErrno\":%llu,"
    "\"vpnDirectTcp6ConnectAttempts\":%llu,"
    "\"vpnDirectTcp6ConnectSucceeded\":%llu,"
    "\"vpnDirectTcp6PayloadBytesFromTun\":%llu,"
    "\"vpnDirectTcp6SocketWriteCompletions\":%llu,"
    "\"vpnDirectTcp6SocketReadPackets\":%llu,"
    "\"vpnDirectTcp6ReturnPackets\":%llu,"
    "\"vpnDirectTcp6TunWriteCompletions\":%llu,"
    "\"vpnDirectTcp6TransportFailed\":%llu,"
    "\"vpnDirectTcp6CloseCompletions\":%llu,"
    "\"vpnDirectTcp6LastErrno\":%llu,"
    "\"vpnFlowStackReturnPackets\":%llu,"
    "\"vpnFlowStackReturnProvenancePackets\":%llu,"
    "\"vpnTunWriteCompletions\":%llu,"
    "\"vpnInfrastructureFaults\":%llu,"
    "\"vpnDuplicateOrStaleDrops\":%llu}}",
    nm->tun_ready ? "true" : "false",
    (nm->udp_ready || nm->udp6_ready || nm->tcp_ready || nm->tcp6_ready) ?
      "true" :
      "false",
    nm->policy_subject_uid,
    (unsigned long long) nm->policy_network_context_id,
    (unsigned long long) nm->vpn_tun_fd_attached,
    (unsigned long long) nm->vpn_direct_udp4_socket_attached,
    (unsigned long long) nm->vpn_direct_udp4_protect_succeeded,
    (unsigned long long) nm->vpn_direct_udp4_bind_succeeded,
    (unsigned long long) nm->vpn_direct_udp6_socket_attached,
    (unsigned long long) nm->vpn_direct_udp6_protect_succeeded,
    (unsigned long long) nm->vpn_direct_udp6_bind_succeeded,
    (unsigned long long) nm->vpn_direct_tcp4_socket_attached,
    (unsigned long long) nm->vpn_direct_tcp4_protect_succeeded,
    (unsigned long long) nm->vpn_direct_tcp4_bind_succeeded,
    (unsigned long long) nm->vpn_direct_tcp6_socket_attached,
    (unsigned long long) nm->vpn_direct_tcp6_protect_succeeded,
    (unsigned long long) nm->vpn_direct_tcp6_bind_succeeded,
    (unsigned long long) nm->vpn_tun_ingress_packets,
    (unsigned long long) nm->vpn_tun_udp4_tun_origin_packets,
    (unsigned long long) nm->vpn_tun_udp6_tun_origin_packets,
    (unsigned long long) nm->vpn_tun_tcp4_tun_origin_packets,
    (unsigned long long) nm->vpn_tun_tcp6_tun_origin_packets,
    (unsigned long long) nm->vpn_flow_stack_admissions,
    (unsigned long long) nm->vpn_direct_udp4_send_succeeded,
    (unsigned long long) nm->vpn_direct_udp4_transport_failed,
    (unsigned long long) nm->vpn_direct_udp6_send_succeeded,
    (unsigned long long) nm->vpn_direct_udp6_transport_failed,
    (unsigned long long) nm->vpn_direct_udp6_return_packets,
    (unsigned long long) nm->vpn_direct_udp6_tun_write_completions,
    (unsigned long long) nm->vpn_direct_udp6_last_errno,
    (unsigned long long) nm->vpn_direct_tcp4_connect_attempts,
    (unsigned long long) nm->vpn_direct_tcp4_connect_succeeded,
    (unsigned long long) nm->vpn_direct_tcp4_payload_bytes_from_tun,
    (unsigned long long) nm->vpn_direct_tcp4_socket_write_completions,
    (unsigned long long) nm->vpn_direct_tcp4_socket_read_packets,
    (unsigned long long) nm->vpn_direct_tcp4_return_packets,
    (unsigned long long) nm->vpn_direct_tcp4_tun_write_completions,
    (unsigned long long) nm->vpn_direct_tcp4_transport_failed,
    (unsigned long long) nm->vpn_direct_tcp4_close_completions,
    (unsigned long long) nm->vpn_direct_tcp4_last_errno,
    (unsigned long long) nm->vpn_direct_tcp6_connect_attempts,
    (unsigned long long) nm->vpn_direct_tcp6_connect_succeeded,
    (unsigned long long) nm->vpn_direct_tcp6_payload_bytes_from_tun,
    (unsigned long long) nm->vpn_direct_tcp6_socket_write_completions,
    (unsigned long long) nm->vpn_direct_tcp6_socket_read_packets,
    (unsigned long long) nm->vpn_direct_tcp6_return_packets,
    (unsigned long long) nm->vpn_direct_tcp6_tun_write_completions,
    (unsigned long long) nm->vpn_direct_tcp6_transport_failed,
    (unsigned long long) nm->vpn_direct_tcp6_close_completions,
    (unsigned long long) nm->vpn_direct_tcp6_last_errno,
    (unsigned long long) nm->vpn_flow_stack_return_packets,
    (unsigned long long) nm->vpn_flow_stack_return_provenance_packets,
    (unsigned long long) nm->vpn_tun_write_completions,
    (unsigned long long) nm->vpn_infrastructure_faults,
    (unsigned long long) nm->vpn_duplicate_or_stale_drops);
  if (length <= 0 || (size_t) length >= sizeof (json))
    {
      product_vpn_send_json_response (
        fd,
        "{\"ok\":false,\"error\":{\"code\":\"VPN_CONTROL_STATUS_FAILED\","
        "\"message\":\"VPN adapter status response is too large\"}}");
      return;
    }
  product_vpn_send_json_response (fd, json);
}

static void
product_vpn_close_tun_for_fault (product_vpn_udp4_main_t *nm)
{
  if (nm == 0)
    return;
  if (nm->tun_file_index != ~0)
    {
      clib_file_del_by_index (&file_main, nm->tun_file_index);
      nm->tun_file_index = ~0;
    }
  else if (nm->tun_fd >= 0)
    close (nm->tun_fd);
  nm->tun_fd = -1;
  nm->tun_ready = 0;
  nm->available = 0;
  nm->vpn_infrastructure_faults++;
}

static void
product_vpn_send_tun_fault_response (product_vpn_udp4_main_t *nm, int fd)
{
  char json[PRODUCT_VPN_CONTROL_BUFFER_BYTES];
  int length;

  if (nm == 0)
    {
      product_vpn_send_json_response (
        fd,
        "{\"ok\":false,\"error\":{\"code\":\"VPN_FAULT_CLOSE_TUN_FAILED\","
        "\"message\":\"VPN adapter state is unavailable\"}}");
      return;
    }
  length = snprintf (
    json, sizeof (json),
    "{\"ok\":true,\"result\":{\"adapter\":\"vpn-tun-hev-lwip\","
    "\"fault\":\"tun_abnormal_close\",\"tunReady\":%s,"
    "\"fdAttached\":%s,\"transportFdAttached\":%s,"
    "\"vpnTunFdAttached\":%llu,"
    "\"vpnInfrastructureFaults\":%llu,"
    "\"vpnDuplicateOrStaleDrops\":%llu}}",
    nm->tun_ready ? "true" : "false", nm->tun_ready ? "true" : "false",
    (nm->udp_ready || nm->udp6_ready || nm->tcp_ready || nm->tcp6_ready) ?
      "true" :
      "false",
    (unsigned long long) nm->vpn_tun_fd_attached,
    (unsigned long long) nm->vpn_infrastructure_faults,
    (unsigned long long) nm->vpn_duplicate_or_stale_drops);
  if (length <= 0 || (size_t) length >= sizeof (json))
    {
      product_vpn_send_json_response (
        fd,
        "{\"ok\":false,\"error\":{\"code\":\"VPN_FAULT_CLOSE_TUN_FAILED\","
        "\"message\":\"VPN TUN fault response is too large\"}}");
      return;
    }
  product_vpn_send_json_response (fd, json);
}

static void
product_vpn_attach_tun_fd (product_vpn_udp4_main_t *nm, int fd, int ipv6,
                           u32 policy_subject_uid,
                           u64 policy_network_context_id)
{
  clib_file_t template = { 0 };

  if (nm->tun_file_index != ~0)
    {
      clib_file_del_by_index (&file_main, nm->tun_file_index);
      nm->tun_file_index = ~0;
    }
  else if (nm->tun_fd >= 0)
    close (nm->tun_fd);
  nm->tun_fd = fd;
  nm->tun_ready = 0;
  if (fd < 0 || !product_vpn_set_nonblocking (fd))
    {
      nm->vpn_infrastructure_faults++;
      if (fd >= 0)
        close (fd);
      nm->tun_fd = -1;
      return;
    }
  (void) ipv6;
  nm->policy_subject_uid = policy_subject_uid;
  nm->policy_network_context_id = policy_network_context_id;
  template.read_function = product_vpn_tun_read_ready;
  template.file_descriptor = (u32) fd;
  template.private_data = pointer_to_uword (nm);
  template.description = format (0, "sakamoto-vpn-tun-udp4%c", 0);
  nm->tun_file_index = clib_file_add (&file_main, &template);
  nm->tun_ready = 1;
  nm->vpn_tun_fd_attached++;
}

static void
product_vpn_attach_udp_fd (product_vpn_udp4_main_t *nm, int fd)
{
  clib_file_t template = { 0 };

  if (nm->udp_file_index != ~0)
    {
      clib_file_del_by_index (&file_main, nm->udp_file_index);
      nm->udp_file_index = ~0;
    }
  else if (nm->udp_fd >= 0)
    close (nm->udp_fd);
  nm->udp_fd = fd;
  nm->udp_ready = 0;
  if (fd < 0 || !product_vpn_set_nonblocking (fd))
    {
      nm->vpn_infrastructure_faults++;
      if (fd >= 0)
        close (fd);
      nm->udp_fd = -1;
      return;
    }
  template.read_function = product_vpn_udp_read_ready;
  template.file_descriptor = (u32) fd;
  template.private_data = pointer_to_uword (nm);
  template.description = format (0, "sakamoto-vpn-direct-udp4%c", 0);
  nm->udp_file_index = clib_file_add (&file_main, &template);
  nm->udp_ready = 1;
  nm->vpn_direct_udp4_socket_attached++;
  nm->vpn_direct_udp4_protect_succeeded++;
  nm->vpn_direct_udp4_bind_succeeded++;
}

static void
product_vpn_attach_udp6_fd (product_vpn_udp4_main_t *nm, int fd)
{
  clib_file_t template = { 0 };

  if (nm->udp6_file_index != ~0)
    {
      clib_file_del_by_index (&file_main, nm->udp6_file_index);
      nm->udp6_file_index = ~0;
    }
  else if (nm->udp6_fd >= 0)
    close (nm->udp6_fd);
  nm->udp6_fd = fd;
  nm->udp6_ready = 0;
  if (fd < 0 || !product_vpn_set_nonblocking (fd))
    {
      nm->vpn_infrastructure_faults++;
      if (fd >= 0)
        close (fd);
      nm->udp6_fd = -1;
      return;
    }
  template.read_function = product_vpn_udp6_read_ready;
  template.file_descriptor = (u32) fd;
  template.private_data = pointer_to_uword (nm);
  template.description = format (0, "sakamoto-vpn-direct-udp6%c", 0);
  nm->udp6_file_index = clib_file_add (&file_main, &template);
  nm->udp6_ready = 1;
  nm->vpn_direct_udp6_socket_attached++;
  nm->vpn_direct_udp6_protect_succeeded++;
  nm->vpn_direct_udp6_bind_succeeded++;
}

static void
product_vpn_attach_tcp4_fd (product_vpn_udp4_main_t *nm, int fd)
{
  u32 index;

  if (nm == 0)
    {
      if (fd >= 0)
        close (fd);
      return;
    }
  if (fd < 0 || !product_vpn_set_nonblocking (fd))
    {
      nm->vpn_infrastructure_faults++;
      if (fd >= 0)
        close (fd);
      return;
    }
  for (index = 0; index < PRODUCT_VPN_MAX_TCP4_FLOWS; ++index)
    {
      product_vpn_tcp4_flow_t *flow = &nm->tcp4_flows[index];
      if (!flow->active && flow->fd < 0)
        {
          flow->fd = fd;
          flow->file_index = ~0;
          flow->state = PRODUCT_VPN_TCP4_SOCKET_IDLE;
          nm->tcp_ready = 1;
          nm->vpn_direct_tcp4_socket_attached++;
          nm->vpn_direct_tcp4_protect_succeeded++;
          nm->vpn_direct_tcp4_bind_succeeded++;
          return;
        }
    }
  close (fd);
  nm->vpn_infrastructure_faults++;
}

static void
product_vpn_attach_tcp6_fd (product_vpn_udp4_main_t *nm, int fd)
{
  u32 index;

  if (nm == 0)
    {
      if (fd >= 0)
        close (fd);
      return;
    }
  if (fd < 0 || !product_vpn_set_nonblocking (fd))
    {
      nm->vpn_infrastructure_faults++;
      if (fd >= 0)
        close (fd);
      return;
    }
  for (index = 0; index < PRODUCT_VPN_MAX_TCP6_FLOWS; ++index)
    {
      product_vpn_tcp6_flow_t *flow = &nm->tcp6_flows[index];
      if (!flow->active && flow->fd < 0)
        {
          flow->fd = fd;
          flow->file_index = ~0;
          flow->state = PRODUCT_VPN_TCP4_SOCKET_IDLE;
          nm->tcp6_ready = 1;
          nm->vpn_direct_tcp6_socket_attached++;
          nm->vpn_direct_tcp6_protect_succeeded++;
          nm->vpn_direct_tcp6_bind_succeeded++;
          return;
        }
    }
  close (fd);
  nm->vpn_infrastructure_faults++;
}

static int
product_vpn_recv_control_frame (int fd, u8 *buffer, size_t buffer_size,
                                int *received_fd)
{
  struct pollfd poll_fd = {.fd = fd, .events = POLLIN, .revents = 0};
  struct iovec iov = {.iov_base = buffer, .iov_len = buffer_size - 1U};
  char control[CMSG_SPACE (sizeof (int))];
  struct msghdr message;
  ssize_t received;

  if (received_fd != 0)
    *received_fd = -1;
  if (poll (&poll_fd, 1, 250) <= 0)
    return -1;
  clib_memset (&message, 0, sizeof (message));
  clib_memset (control, 0, sizeof (control));
  message.msg_iov = &iov;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = sizeof (control);
  received = recvmsg (fd, &message, 0);
  if (received <= 0)
    return -1;
  buffer[received] = '\0';
  for (struct cmsghdr *cmsg = CMSG_FIRSTHDR (&message); cmsg != 0;
       cmsg = CMSG_NXTHDR (&message, cmsg))
    if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS
        && cmsg->cmsg_len >= CMSG_LEN (sizeof (int)))
      {
        int passed_fd;
        clib_memcpy_fast (&passed_fd, CMSG_DATA (cmsg), sizeof (passed_fd));
        if (received_fd != 0)
          *received_fd = passed_fd;
        break;
      }
  return (int) received;
}

static void
product_vpn_process_control_connection (product_vpn_udp4_main_t *nm, int fd)
{
  u8 frame[PRODUCT_VPN_CONTROL_BUFFER_BYTES];
  char *payload = 0;
  u32 payload_length = 0;
  int passed_fd = -1;
  int received;

  received = product_vpn_recv_control_frame (fd, frame, sizeof (frame),
                                             &passed_fd);
  if (received <= 0
      || !product_vpn_parse_netstring_payload (frame, received, &payload,
                                               &payload_length))
    {
      nm->vpn_infrastructure_faults++;
      product_vpn_send_json_response (
        fd,
        "{\"ok\":false,\"error\":{\"code\":\"VPN_CONTROL_INVALID_FRAME\","
        "\"message\":\"invalid netstring control frame\"}}");
      if (passed_fd >= 0)
        close (passed_fd);
      return;
    }

  if (product_vpn_payload_has (payload, "\"cmd\":\"HELLO\"")
      || product_vpn_payload_has (payload, "\"cmd\": \"HELLO\""))
    {
      product_vpn_send_json_response (
        fd,
        "{\"ok\":true,\"result\":{\"capabilities\":["
        "\"vpn-tun-fd-handoff\","
        "\"vpn-tun-transport-fd-handoff\","
        "\"vpn-direct-udp4-protected-socket-handoff\","
        "\"vpn-direct-udp6-protected-socket-handoff\","
        "\"vpn-direct-tcp4-protected-socket-handoff\","
        "\"vpn-direct-tcp6-protected-socket-handoff\","
        "\"vpn-policy-hints-v1\","
        "\"vpn-fault-close-tun-debug\"]}}");
      if (passed_fd >= 0)
        close (passed_fd);
      return;
    }

  if (product_vpn_payload_has (payload, "\"cmd\":\"VPN_TUN.ATTACH\"")
      || product_vpn_payload_has (payload, "\"cmd\": \"VPN_TUN.ATTACH\""))
    {
      u32 policy_subject_uid = UINT32_MAX;
      u32 policy_network_context_id = 0;
      int ipv6 = product_vpn_payload_has (payload, "\"enableIpv6\":true")
                 || product_vpn_payload_has (payload, "\"enableIpv6\": true");
      (void) product_vpn_payload_u32 (payload, "policySubjectUid",
                                      &policy_subject_uid);
      (void) product_vpn_payload_u32 (payload, "networkContext",
                                      &policy_network_context_id);
      product_vpn_attach_tun_fd (nm, passed_fd, ipv6, policy_subject_uid,
                                 policy_network_context_id);
      passed_fd = -1;
      nm->available =
        nm->tun_ready && nm->udp_ready && nm->udp6_ready && nm->tcp_ready
        && nm->tcp6_ready;
      {
        char json[PRODUCT_VPN_CONTROL_BUFFER_BYTES];
        int length = snprintf (
          json, sizeof (json),
          "{\"ok\":true,\"result\":{\"adapter\":\"vpn-tun-hev-lwip\","
          "\"fdAttached\":true,\"transportFdAttached\":false,"
          "\"ipv6Enabled\":true,"
          "\"policySubjectUid\":%u,"
          "\"policyNetworkContext\":%u}}",
          policy_subject_uid, policy_network_context_id);
        product_vpn_send_json_response (
          fd,
          (length <= 0 || (size_t) length >= sizeof (json)) ?
            "{\"ok\":false,\"error\":{\"code\":\"VPN_TUN_ATTACH_FAILED\","
            "\"message\":\"VPN TUN attach response is too large\"}}" :
            json);
      }
      return;
    }

  if (product_vpn_payload_has (payload, "\"cmd\":\"VPN_TUN.STATUS\"")
      || product_vpn_payload_has (payload, "\"cmd\": \"VPN_TUN.STATUS\""))
    {
      product_vpn_send_status_response (nm, fd);
      if (passed_fd >= 0)
        close (passed_fd);
      return;
    }

  if (product_vpn_payload_has (payload, "\"cmd\":\"VPN_FAULT.CLOSE_TUN\"")
      || product_vpn_payload_has (payload, "\"cmd\": \"VPN_FAULT.CLOSE_TUN\""))
    {
      if (passed_fd >= 0)
        {
          close (passed_fd);
          passed_fd = -1;
        }
      product_vpn_close_tun_for_fault (nm);
      product_vpn_send_tun_fault_response (nm, fd);
      return;
    }

  if (product_vpn_payload_has (payload, "\"cmd\":\"VPN_TRANSPORT.ATTACH\"")
      || product_vpn_payload_has (payload,
                                  "\"cmd\": \"VPN_TRANSPORT.ATTACH\""))
    {
      product_vpn_attach_udp_fd (nm, passed_fd);
      passed_fd = -1;
      nm->available =
        nm->tun_ready && nm->udp_ready && nm->udp6_ready && nm->tcp_ready
        && nm->tcp6_ready;
      product_vpn_send_json_response (
        fd,
        "{\"ok\":true,\"result\":{\"adapter\":\"vpn-tun-hev-lwip\","
        "\"fdAttached\":true,\"transportFdAttached\":true,"
        "\"ipv6Enabled\":true}}");
      return;
    }

  if (product_vpn_payload_has (payload, "\"cmd\":\"VPN_UDP6_TRANSPORT.ATTACH\"")
      || product_vpn_payload_has (
        payload, "\"cmd\": \"VPN_UDP6_TRANSPORT.ATTACH\""))
    {
      product_vpn_attach_udp6_fd (nm, passed_fd);
      passed_fd = -1;
      nm->available =
        nm->tun_ready && nm->udp_ready && nm->udp6_ready && nm->tcp_ready
        && nm->tcp6_ready;
      product_vpn_send_json_response (
        fd,
        "{\"ok\":true,\"result\":{\"adapter\":\"vpn-tun-hev-lwip\","
        "\"fdAttached\":true,\"transportFdAttached\":true,"
        "\"ipv6Enabled\":true}}");
      return;
    }

  if (product_vpn_payload_has (payload, "\"cmd\":\"VPN_TCP_TRANSPORT.ATTACH\"")
      || product_vpn_payload_has (
        payload, "\"cmd\": \"VPN_TCP_TRANSPORT.ATTACH\""))
    {
      product_vpn_attach_tcp4_fd (nm, passed_fd);
      passed_fd = -1;
      nm->available =
        nm->tun_ready && nm->udp_ready && nm->udp6_ready && nm->tcp_ready
        && nm->tcp6_ready;
      product_vpn_send_json_response (
        fd,
        "{\"ok\":true,\"result\":{\"adapter\":\"vpn-tun-hev-lwip\","
        "\"fdAttached\":true,\"transportFdAttached\":true,"
        "\"ipv6Enabled\":true}}");
      return;
    }

  if (product_vpn_payload_has (payload, "\"cmd\":\"VPN_TCP6_TRANSPORT.ATTACH\"")
      || product_vpn_payload_has (
        payload, "\"cmd\": \"VPN_TCP6_TRANSPORT.ATTACH\""))
    {
      product_vpn_attach_tcp6_fd (nm, passed_fd);
      passed_fd = -1;
      nm->available =
        nm->tun_ready && nm->udp_ready && nm->udp6_ready && nm->tcp_ready
        && nm->tcp6_ready;
      product_vpn_send_json_response (
        fd,
        "{\"ok\":true,\"result\":{\"adapter\":\"vpn-tun-hev-lwip\","
        "\"fdAttached\":true,\"transportFdAttached\":true,"
        "\"ipv6Enabled\":true}}");
      return;
    }

  nm->vpn_infrastructure_faults++;
  product_vpn_send_json_response (
    fd,
    "{\"ok\":false,\"error\":{\"code\":\"VPN_CONTROL_UNKNOWN_COMMAND\","
    "\"message\":\"unknown VPN control command\"}}");
  if (passed_fd >= 0)
    close (passed_fd);
}

static clib_error_t *
product_vpn_control_accept_ready (clib_file_t *file)
{
  product_vpn_udp4_main_t *nm = &product_vpn_udp4_main;
  int listener = (int) file->file_descriptor;

  while (1)
    {
      int fd = accept (listener, 0, 0);
      if (fd < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
          nm->vpn_infrastructure_faults++;
          return 0;
        }
      (void) fcntl (fd, F_SETFD, FD_CLOEXEC);
      product_vpn_process_control_connection (nm, fd);
      close (fd);
    }
}

static int
product_vpn_open_control_socket (product_vpn_udp4_main_t *nm)
{
  struct sockaddr_un address;
  clib_file_t template = { 0 };
  size_t name_length = strlen (CONTROL_SOCKET_NAME);
  socklen_t address_length =
    (socklen_t) (offsetof (struct sockaddr_un, sun_path) + 1U + name_length);
  int fd;

  fd = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (fd < 0)
    return 0;
  clib_memset (&address, 0, sizeof (address));
  address.sun_family = AF_UNIX;
  address.sun_path[0] = '\0';
  clib_memcpy_fast (address.sun_path + 1, CONTROL_SOCKET_NAME, name_length);
  if (bind (fd, (const struct sockaddr *) &address, address_length) != 0
      || listen (fd, 4) != 0)
    {
      close (fd);
      return 0;
    }
  template.read_function = product_vpn_control_accept_ready;
  template.file_descriptor = (u32) fd;
  template.private_data = pointer_to_uword (nm);
  template.description = format (0, "sakamoto-vpn-control-vnext%c", 0);
  nm->control_file_index = clib_file_add (&file_main, &template);
  nm->control_fd = fd;
  nm->control_ready = 1;
  return 1;
}

int
product_vpn_udp4_adapter_start (vlib_main_t *vm, uint64_t generation)
{
  product_vpn_udp4_main_t *nm = &product_vpn_udp4_main;

  if (nm->control_ready)
    return 1;
  if (vm == 0 || generation == 0)
    return 0;

  nm->vlib_main = vm;
  nm->generation = generation;
  nm->next_obligation = 0;
  nm->tun_fd = -1;
  nm->udp_fd = -1;
  nm->udp6_fd = -1;
  nm->tun_file_index = ~0;
  nm->udp_file_index = ~0;
  nm->udp6_file_index = ~0;
  for (u32 index = 0; index < PRODUCT_VPN_MAX_TCP4_FLOWS; ++index)
    {
      clib_memset (&nm->tcp4_flows[index], 0, sizeof (nm->tcp4_flows[index]));
      nm->tcp4_flows[index].fd = -1;
      nm->tcp4_flows[index].file_index = ~0;
      nm->tcp4_flows[index].state = PRODUCT_VPN_TCP4_SOCKET_IDLE;
    }
  for (u32 index = 0; index < PRODUCT_VPN_MAX_TCP6_FLOWS; ++index)
    {
      clib_memset (&nm->tcp6_flows[index], 0, sizeof (nm->tcp6_flows[index]));
      nm->tcp6_flows[index].fd = -1;
      nm->tcp6_flows[index].file_index = ~0;
      nm->tcp6_flows[index].state = PRODUCT_VPN_TCP4_SOCKET_IDLE;
    }
  nm->vpn_tun_fd_attached = 0;
  nm->vpn_direct_udp4_socket_attached = 0;
  nm->vpn_direct_udp4_protect_succeeded = 0;
  nm->vpn_direct_udp4_bind_succeeded = 0;
  nm->vpn_direct_udp6_socket_attached = 0;
  nm->vpn_direct_udp6_protect_succeeded = 0;
  nm->vpn_direct_udp6_bind_succeeded = 0;
  nm->vpn_direct_tcp4_socket_attached = 0;
  nm->vpn_direct_tcp4_protect_succeeded = 0;
  nm->vpn_direct_tcp4_bind_succeeded = 0;
  nm->vpn_direct_tcp6_socket_attached = 0;
  nm->vpn_direct_tcp6_protect_succeeded = 0;
  nm->vpn_direct_tcp6_bind_succeeded = 0;
  nm->vpn_tun_ingress_packets = 0;
  nm->vpn_tun_udp4_tun_origin_packets = 0;
  nm->vpn_tun_udp6_tun_origin_packets = 0;
  nm->vpn_tun_tcp4_tun_origin_packets = 0;
  nm->vpn_tun_tcp6_tun_origin_packets = 0;
  nm->vpn_flow_stack_admissions = 0;
  nm->vpn_direct_udp4_send_succeeded = 0;
  nm->vpn_direct_udp4_transport_failed = 0;
  nm->vpn_direct_udp6_send_succeeded = 0;
  nm->vpn_direct_udp6_transport_failed = 0;
  nm->vpn_direct_udp6_return_packets = 0;
  nm->vpn_direct_udp6_tun_write_completions = 0;
  nm->vpn_direct_udp6_last_errno = 0;
  nm->vpn_direct_tcp4_connect_attempts = 0;
  nm->vpn_direct_tcp4_connect_succeeded = 0;
  nm->vpn_direct_tcp4_payload_bytes_from_tun = 0;
  nm->vpn_direct_tcp4_socket_write_completions = 0;
  nm->vpn_direct_tcp4_socket_read_packets = 0;
  nm->vpn_direct_tcp4_return_packets = 0;
  nm->vpn_direct_tcp4_tun_write_completions = 0;
  nm->vpn_direct_tcp4_transport_failed = 0;
  nm->vpn_direct_tcp4_close_completions = 0;
  nm->vpn_direct_tcp4_last_errno = 0;
  nm->vpn_direct_tcp6_connect_attempts = 0;
  nm->vpn_direct_tcp6_connect_succeeded = 0;
  nm->vpn_direct_tcp6_payload_bytes_from_tun = 0;
  nm->vpn_direct_tcp6_socket_write_completions = 0;
  nm->vpn_direct_tcp6_socket_read_packets = 0;
  nm->vpn_direct_tcp6_return_packets = 0;
  nm->vpn_direct_tcp6_tun_write_completions = 0;
  nm->vpn_direct_tcp6_transport_failed = 0;
  nm->vpn_direct_tcp6_close_completions = 0;
  nm->vpn_direct_tcp6_last_errno = 0;
  nm->vpn_flow_stack_return_packets = 0;
  nm->vpn_flow_stack_return_provenance_packets = 0;
  nm->vpn_tun_write_completions = 0;
  nm->vpn_infrastructure_faults = 0;
  nm->vpn_duplicate_or_stale_drops = 0;
  nm->policy_subject_uid = UINT32_MAX;
  nm->policy_network_context_id = 0;
  nm->tun_ready = 0;
  nm->udp_ready = 0;
  nm->udp6_ready = 0;
  nm->tcp_ready = 0;
  nm->tcp6_ready = 0;
  nm->available = 0;
  clib_memset (&nm->last_flow, 0, sizeof (nm->last_flow));
  clib_memset (nm->flows, 0, sizeof (nm->flows));
  clib_memset (&nm->last_udp6_flow, 0, sizeof (nm->last_udp6_flow));
  clib_memset (nm->udp6_flows, 0, sizeof (nm->udp6_flows));
  nm->next_flow_slot = 0;
  nm->udp6_next_flow_slot = 0;
  nm->tcp4_next_sequence = 0;
  nm->tcp6_next_sequence = 0;

  if (!product_packet_graph_start_external (vm, generation))
    return 0;
  product_packet_graph_register_external_completion (
    product_vpn_udp4_complete_from_graph, nm);
  if (!product_vpn_open_control_socket (nm))
    {
      product_packet_graph_register_external_completion (0, 0);
      product_packet_graph_stop_external (vm);
      return 0;
    }
  return 1;
}

void
product_vpn_udp4_adapter_stop (vlib_main_t *vm)
{
  product_vpn_udp4_main_t *nm = &product_vpn_udp4_main;
  (void) vm;

  nm->available = 0;
  nm->tun_ready = 0;
  nm->udp_ready = 0;
  nm->udp6_ready = 0;
  nm->tcp_ready = 0;
  nm->tcp6_ready = 0;
  product_packet_graph_stop_external (nm->vlib_main);
  product_packet_graph_register_external_completion (0, 0);
  if (nm->tun_file_index != ~0)
    {
      clib_file_del_by_index (&file_main, nm->tun_file_index);
      nm->tun_file_index = ~0;
    }
  else if (nm->tun_fd >= 0)
    close (nm->tun_fd);
  if (nm->udp_file_index != ~0)
    {
      clib_file_del_by_index (&file_main, nm->udp_file_index);
      nm->udp_file_index = ~0;
    }
  else if (nm->udp_fd >= 0)
    close (nm->udp_fd);
  if (nm->udp6_file_index != ~0)
    {
      clib_file_del_by_index (&file_main, nm->udp6_file_index);
      nm->udp6_file_index = ~0;
    }
  else if (nm->udp6_fd >= 0)
    close (nm->udp6_fd);
  for (u32 index = 0; index < PRODUCT_VPN_MAX_TCP4_FLOWS; ++index)
    {
      product_vpn_tcp4_flow_t *flow = &nm->tcp4_flows[index];
      if (flow->file_index != ~0)
        {
          clib_file_del_by_index (&file_main, flow->file_index);
          flow->file_index = ~0;
        }
      else if (flow->fd >= 0)
        close (flow->fd);
      flow->fd = -1;
      flow->active = 0;
      flow->state = PRODUCT_VPN_TCP4_SOCKET_IDLE;
    }
  for (u32 index = 0; index < PRODUCT_VPN_MAX_TCP6_FLOWS; ++index)
    {
      product_vpn_tcp6_flow_t *flow = &nm->tcp6_flows[index];
      if (flow->file_index != ~0)
        {
          clib_file_del_by_index (&file_main, flow->file_index);
          flow->file_index = ~0;
        }
      else if (flow->fd >= 0)
        close (flow->fd);
      flow->fd = -1;
      flow->active = 0;
      flow->state = PRODUCT_VPN_TCP4_SOCKET_IDLE;
    }
  if (nm->control_file_index != ~0)
    {
      clib_file_del_by_index (&file_main, nm->control_file_index);
      nm->control_file_index = ~0;
    }
  else if (nm->control_fd >= 0)
    close (nm->control_fd);
  nm->tun_fd = -1;
  nm->udp_fd = -1;
  nm->udp6_fd = -1;
  nm->control_fd = -1;
  nm->control_ready = 0;
}

int
product_vpn_udp4_adapter_available (void)
{
  const product_vpn_udp4_main_t *nm = &product_vpn_udp4_main;
  return nm->control_ready && nm->available && nm->tun_ready && nm->udp_ready
         && nm->udp6_ready && nm->tcp_ready && nm->tcp6_ready;
}

int
product_vpn_udp4_adapter_protection_running (void)
{
  return product_vpn_udp4_adapter_available ();
}

uint64_t
product_vpn_udp4_adapter_tun_fd_attached (void)
{
  return product_vpn_udp4_main.vpn_tun_fd_attached;
}

uint64_t
product_vpn_udp4_adapter_direct_socket_attached (void)
{
  return product_vpn_udp4_main.vpn_direct_udp4_socket_attached;
}

uint64_t
product_vpn_udp4_adapter_direct_protect_succeeded (void)
{
  return product_vpn_udp4_main.vpn_direct_udp4_protect_succeeded;
}

uint64_t
product_vpn_udp4_adapter_direct_bind_succeeded (void)
{
  return product_vpn_udp4_main.vpn_direct_udp4_bind_succeeded;
}

uint64_t
product_vpn_udp4_adapter_tun_ingress_packets (void)
{
  return product_vpn_udp4_main.vpn_tun_ingress_packets;
}

uint64_t
product_vpn_udp4_adapter_udp4_tun_origin_packets (void)
{
  return product_vpn_udp4_main.vpn_tun_udp4_tun_origin_packets;
}

uint64_t
product_vpn_udp4_adapter_flow_stack_admissions (void)
{
  return product_vpn_udp4_main.vpn_flow_stack_admissions;
}

uint64_t
product_vpn_udp4_adapter_direct_send_succeeded (void)
{
  return product_vpn_udp4_main.vpn_direct_udp4_send_succeeded;
}

uint64_t
product_vpn_udp4_adapter_direct_transport_failed (void)
{
  return product_vpn_udp4_main.vpn_direct_udp4_transport_failed;
}

uint64_t
product_vpn_udp4_adapter_flow_stack_return_packets (void)
{
  return product_vpn_udp4_main.vpn_flow_stack_return_packets;
}

uint64_t
product_vpn_udp4_adapter_flow_stack_return_provenance_packets (void)
{
  return product_vpn_udp4_main.vpn_flow_stack_return_provenance_packets;
}

uint64_t
product_vpn_udp4_adapter_tun_write_completions (void)
{
  return product_vpn_udp4_main.vpn_tun_write_completions;
}

uint64_t
product_vpn_udp4_adapter_infrastructure_faults (void)
{
  return product_vpn_udp4_main.vpn_infrastructure_faults;
}

uint64_t
product_vpn_udp4_adapter_duplicate_or_stale_drops (void)
{
  return product_vpn_udp4_main.vpn_duplicate_or_stale_drops;
}
