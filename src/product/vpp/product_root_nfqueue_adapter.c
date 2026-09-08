/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Root dual-stack INPUT/OUTPUT adapter.
 *
 * Scope is intentionally narrow: IPv4/IPv6 LOCAL_OUT and LOCAL_IN default PASS
 * through the Product Packet graph. Each configured NFQUEUE lane owns one
 * queue/socket for both receive and verdict; completion always routes back to
 * the origin lane. Policy and release capacity belong to later work items.
 */

#include "product_root_nfqueue_adapter.h"

#include "product_packet_graph.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include <vlib/file.h>

#define PRODUCT_ROOT_NFQUEUE_DEFAULT_QUEUE 176
#define PRODUCT_ROOT_NFQUEUE_DEFAULT_LANES 1
#define PRODUCT_ROOT_NFQUEUE_MAX_LANES 4
#define PRODUCT_ROOT_NFQUEUE_MAX_NETLINK 8192
#define PRODUCT_ROOT_NFQUEUE_OBLIGATION_PACKET_MASK UINT64_C (0xffffffff)
#define PRODUCT_ROOT_NFQUEUE_OBLIGATION_LANE_SHIFT 32

typedef enum
{
  PRODUCT_ROOT_NFQUEUE_FAULT_NONE,
  PRODUCT_ROOT_NFQUEUE_FAULT_MISSING_IDENTITY,
  PRODUCT_ROOT_NFQUEUE_FAULT_GRAPH_SUBMIT_FAIL_OPEN,
  PRODUCT_ROOT_NFQUEUE_FAULT_VERDICT_FAILED_DEFINITE,
  PRODUCT_ROOT_NFQUEUE_FAULT_VERDICT_OUTCOME_UNKNOWN,
  PRODUCT_ROOT_NFQUEUE_FAULT_DUPLICATE_COMPLETION,
  PRODUCT_ROOT_NFQUEUE_FAULT_STALE_COMPLETION,
} product_root_nfqueue_fault_mode_t;

typedef struct
{
  u32 packet_id;
  u32 uid;
  u8 hook;
  u8 ip_family;
  u8 protocol;
  u8 uid_present;
  u8 indev_present, outdev_present;
  u32 indev, outdev;
  u8 *payload;
  u32 payload_length;
} product_root_nfqueue_packet_t;

typedef struct
{
  int fd;
  uword clib_file_index;
  u32 queue_id;
  u32 lane_index;
  u64 packets_seen;
  u64 packets_submitted;
  u64 verdict_attempts;
  u64 verdict_succeeded;
  u64 verdict_failed;
  u64 duplicate_completion_drops;
  u64 internal_settlements;
  u64 buffer_returns;
  u64 origin_local_completions;
  u64 origin_remote_completions;
  u32 last_verdict_packet_id;
  u8 verdict_packet_id_known;
  u8 socket_ready;
  u8 listener_ready;
} product_root_nfqueue_lane_t;

typedef struct
{
  vlib_main_t *vlib_main;
  u32 queue_id;
  u32 queue_last;
  u32 lane_count;
  u32 uid_owner;
  u64 generation;
  u64 packets_seen;
  u64 packets_submitted;
  u64 verdict_attempts;
  u64 verdict_succeeded;
  u64 verdict_failed;
  u64 internal_settlements;
  u64 buffer_returns;
  u64 origin_local_completions;
  u64 origin_remote_completions;
  u64 input_packets;
  u64 output_packets;
  u64 ipv4_packets;
  u64 ipv6_packets;
  u64 tcp_packets;
  u64 udp_packets;
  u64 uid_known_packets;
  u64 uid_unknown_packets;
  u64 verdict_failed_definite;
  u64 verdict_outcome_unknown;
  u64 ingress_identity_missing;
  u64 graph_submit_fail_opens;
  u64 non_owner_bypasses;
  u32 last_packet_id;
  u32 last_queue_id;
  u32 last_uid;
  u32 last_ip_family;
  u32 last_protocol;
  u32 last_hook;
  u32 last_uid_known;
  u64 duplicate_completion_drops;
  u64 stale_completion_drops;
  u32 ready_lane_mask;
  product_root_nfqueue_fault_mode_t fault_mode;
  u8 hook_ready;
  u8 available;
  product_root_nfqueue_lane_t lanes[PRODUCT_ROOT_NFQUEUE_MAX_LANES];
} product_root_nfqueue_main_t;

static int product_root_nfqueue_last_errno;

static product_root_nfqueue_main_t product_root_nfqueue_main = {
  .queue_id = PRODUCT_ROOT_NFQUEUE_DEFAULT_QUEUE,
  .queue_last =
    PRODUCT_ROOT_NFQUEUE_DEFAULT_QUEUE + PRODUCT_ROOT_NFQUEUE_DEFAULT_LANES - 1,
  .lane_count = PRODUCT_ROOT_NFQUEUE_DEFAULT_LANES,
  .uid_owner = UINT32_MAX,
};

static u32
product_root_nfqueue_queue_from_env (void)
{
  const char *value = getenv ("SAKAMOTO_PRODUCT_ROOT_NFQUEUE_QUEUE");
  char *end = 0;
  unsigned long parsed;

  if (value == 0 || *value == '\0')
    return PRODUCT_ROOT_NFQUEUE_DEFAULT_QUEUE;

  errno = 0;
  parsed = strtoul (value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed == 0
      || parsed > UINT16_MAX)
    return PRODUCT_ROOT_NFQUEUE_DEFAULT_QUEUE;
  return (u32) parsed;
}

static u32
product_root_nfqueue_lanes_from_env (void)
{
  const char *value = getenv ("SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES");
  char *end = 0;
  unsigned long parsed;

  if (value == 0 || *value == '\0')
    return PRODUCT_ROOT_NFQUEUE_DEFAULT_LANES;

  errno = 0;
  parsed = strtoul (value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed == 0
      || parsed > PRODUCT_ROOT_NFQUEUE_MAX_LANES)
    return PRODUCT_ROOT_NFQUEUE_DEFAULT_LANES;
  return (u32) parsed;
}

static int
product_root_nfqueue_uid_from_env (u32 *uid_owner)
{
  const char *value = getenv ("SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID");
  char *end = 0;
  unsigned long parsed;

  if (uid_owner == 0 || value == 0 || *value == '\0')
    return 0;

  errno = 0;
  parsed = strtoul (value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed == 0
      || parsed > UINT32_MAX)
    return 0;
  *uid_owner = (u32) parsed;
  return 1;
}

static product_root_nfqueue_fault_mode_t
product_root_nfqueue_fault_mode_from_env (void)
{
  const char *value = getenv ("SAKAMOTO_PRODUCT_ROOT_NFQUEUE_FAULT_MODE");

  if (value == 0 || *value == '\0' || strcmp (value, "none") == 0)
    return PRODUCT_ROOT_NFQUEUE_FAULT_NONE;
  if (strcmp (value, "missing_identity") == 0)
    return PRODUCT_ROOT_NFQUEUE_FAULT_MISSING_IDENTITY;
  if (strcmp (value, "graph_submit_fail_open") == 0)
    return PRODUCT_ROOT_NFQUEUE_FAULT_GRAPH_SUBMIT_FAIL_OPEN;
  if (strcmp (value, "verdict_failed_definite") == 0)
    return PRODUCT_ROOT_NFQUEUE_FAULT_VERDICT_FAILED_DEFINITE;
  if (strcmp (value, "verdict_outcome_unknown") == 0)
    return PRODUCT_ROOT_NFQUEUE_FAULT_VERDICT_OUTCOME_UNKNOWN;
  if (strcmp (value, "duplicate_completion") == 0)
    return PRODUCT_ROOT_NFQUEUE_FAULT_DUPLICATE_COMPLETION;
  if (strcmp (value, "stale_completion") == 0)
    return PRODUCT_ROOT_NFQUEUE_FAULT_STALE_COMPLETION;
  return PRODUCT_ROOT_NFQUEUE_FAULT_NONE;
}

static u64
product_root_nfqueue_obligation_id (u32 lane_index, u32 packet_id)
{
  return (((u64) lane_index + 1) << PRODUCT_ROOT_NFQUEUE_OBLIGATION_LANE_SHIFT)
         | ((u64) packet_id & PRODUCT_ROOT_NFQUEUE_OBLIGATION_PACKET_MASK);
}

static int
product_root_nfqueue_decode_obligation (u64 obligation_id, u32 *lane_index,
                                        u32 *packet_id)
{
  u64 lane_tag =
    obligation_id >> PRODUCT_ROOT_NFQUEUE_OBLIGATION_LANE_SHIFT;
  u32 packet =
    (u32) (obligation_id & PRODUCT_ROOT_NFQUEUE_OBLIGATION_PACKET_MASK);

  if (lane_index == 0 || packet_id == 0 || lane_tag == 0
      || lane_tag > PRODUCT_ROOT_NFQUEUE_MAX_LANES || packet == 0)
    return 0;
  *lane_index = (u32) lane_tag - 1;
  *packet_id = packet;
  return 1;
}

static u16
product_nfnl_type (u16 message_type)
{
  return (u16) ((NFNL_SUBSYS_QUEUE << 8) | message_type);
}

static int
product_nfnl_addattr (struct nlmsghdr *nlh, size_t message_size, u16 type,
                      const void *data, u16 data_length)
{
  u16 attr_length = (u16) NFA_LENGTH (data_length);
  u16 aligned_length = (u16) NFA_ALIGN (attr_length);
  struct nfattr *attr;

  if ((size_t) nlh->nlmsg_len + aligned_length > message_size)
    return 0;

  attr = (struct nfattr *) ((u8 *) nlh + nlh->nlmsg_len);
  attr->nfa_len = attr_length;
  attr->nfa_type = type;
  if (data_length != 0)
    clib_memcpy_fast (NFA_DATA (attr), data, data_length);
  if (aligned_length > attr_length)
    clib_memset ((u8 *) attr + attr_length, 0,
                 aligned_length - attr_length);
  nlh->nlmsg_len += aligned_length;
  return 1;
}

static int
product_nfnl_send (int fd, const struct nlmsghdr *nlh)
{
  struct sockaddr_nl kernel;
  ssize_t sent;

  clib_memset (&kernel, 0, sizeof (kernel));
  kernel.nl_family = AF_NETLINK;
  product_root_nfqueue_last_errno = 0;
  sent = sendto (fd, nlh, nlh->nlmsg_len, 0,
                 (const struct sockaddr *) &kernel, sizeof (kernel));
  if (sent != (ssize_t) nlh->nlmsg_len)
    {
      product_root_nfqueue_last_errno = errno == 0 ? EIO : errno;
      return 0;
    }
  return 1;
}

static void
product_nfnl_fill_header (struct nlmsghdr *nlh, size_t message_size,
                          u16 message_type, u32 queue_id)
{
  struct nfgenmsg *nfgen;

  clib_memset (nlh, 0, message_size);
  nlh->nlmsg_len = NLMSG_LENGTH (sizeof (*nfgen));
  nlh->nlmsg_type = product_nfnl_type (message_type);
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  nfgen = (struct nfgenmsg *) NLMSG_DATA (nlh);
  nfgen->nfgen_family = AF_UNSPEC;
  nfgen->version = NFNETLINK_V0;
  nfgen->res_id = htons ((u16) queue_id);
}

static int
product_nfqueue_recv_ack (int fd)
{
  u8 buffer[512];
  int attempt;

  product_root_nfqueue_last_errno = 0;
  for (attempt = 0; attempt < 100; attempt++)
    {
      ssize_t received = recv (fd, buffer, sizeof (buffer), 0);
      struct nlmsghdr *nlh;
      int remaining;

      if (received < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
              usleep (1000);
              continue;
            }
          product_root_nfqueue_last_errno = errno == 0 ? EIO : errno;
          return 0;
        }
      if (received == 0)
        {
          product_root_nfqueue_last_errno = ECONNRESET;
          return 0;
        }

      remaining = (int) received;
      for (nlh = (struct nlmsghdr *) buffer; NLMSG_OK (nlh, remaining);
           nlh = NLMSG_NEXT (nlh, remaining))
        if (nlh->nlmsg_type == NLMSG_ERROR)
          {
            struct nlmsgerr *error = (struct nlmsgerr *) NLMSG_DATA (nlh);
            if (error->error != 0)
              product_root_nfqueue_last_errno = -error->error;
            return error->error == 0;
          }
    }
  product_root_nfqueue_last_errno = ETIMEDOUT;
  return 0;
}

static void
product_root_nfqueue_warn_errno (const char *step)
{
  int code =
    product_root_nfqueue_last_errno == 0 ? EIO : product_root_nfqueue_last_errno;
  clib_warning ("root nfqueue %s failed: errno=%d (%s)", step, code,
                strerror (code));
}

static int
product_nfqueue_send_config_command (int fd, u8 command, u32 queue_id,
                                     u16 pf)
{
  union
  {
    u8 bytes[NLMSG_SPACE (sizeof (struct nfgenmsg)) +
             NFA_SPACE (sizeof (struct nfqnl_msg_config_cmd))];
    struct nlmsghdr nlh;
  } request;
  struct nfqnl_msg_config_cmd cmd;

  product_nfnl_fill_header (&request.nlh, sizeof (request),
                            NFQNL_MSG_CONFIG, queue_id);
  clib_memset (&cmd, 0, sizeof (cmd));
  cmd.command = command;
  cmd.pf = htons (pf);
  if (!product_nfnl_addattr (&request.nlh, sizeof (request), NFQA_CFG_CMD,
                             &cmd, sizeof (cmd)))
    return 0;
  if (!product_nfnl_send (fd, &request.nlh))
    return 0;
  return product_nfqueue_recv_ack (fd);
}

static int
product_nfqueue_send_copy_packet (int fd, u32 queue_id)
{
  union
  {
    u8 bytes[NLMSG_SPACE (sizeof (struct nfgenmsg)) +
             NFA_SPACE (sizeof (struct nfqnl_msg_config_params))];
    struct nlmsghdr nlh;
  } request;
  struct nfqnl_msg_config_params params;

  product_nfnl_fill_header (&request.nlh, sizeof (request),
                            NFQNL_MSG_CONFIG, queue_id);
  clib_memset (&params, 0, sizeof (params));
  params.copy_range = htonl (UINT16_MAX);
  params.copy_mode = NFQNL_COPY_PACKET;
  if (!product_nfnl_addattr (&request.nlh, sizeof (request),
                             NFQA_CFG_PARAMS, &params, sizeof (params)))
    return 0;
  if (!product_nfnl_send (fd, &request.nlh))
    return 0;
  return product_nfqueue_recv_ack (fd);
}

static int
product_nfqueue_configure (int fd, u32 queue_id)
{
  if (!product_nfqueue_send_config_command (fd, NFQNL_CFG_CMD_PF_BIND, 0,
                                            AF_INET))
    {
      product_root_nfqueue_warn_errno ("PF_BIND AF_INET");
      return 0;
    }
  if (!product_nfqueue_send_config_command (fd, NFQNL_CFG_CMD_PF_BIND, 0,
                                            AF_INET6))
    {
      product_root_nfqueue_warn_errno ("PF_BIND AF_INET6");
      return 0;
    }
  if (!product_nfqueue_send_config_command (fd, NFQNL_CFG_CMD_BIND,
                                            queue_id, 0))
    {
      product_root_nfqueue_warn_errno ("BIND");
      return 0;
    }
  if (!product_nfqueue_send_copy_packet (fd, queue_id))
    {
      product_root_nfqueue_warn_errno ("COPY_PACKET");
      return 0;
    }
  return 1;
}

static int
product_nfqueue_send_verdict (int fd, u32 queue_id, u32 packet_id,
                              u32 verdict)
{
  union
  {
    u8 bytes[NLMSG_SPACE (sizeof (struct nfgenmsg)) +
             NFA_SPACE (sizeof (struct nfqnl_msg_verdict_hdr))];
    struct nlmsghdr nlh;
  } request;
  struct nfqnl_msg_verdict_hdr verdict_header;

  product_nfnl_fill_header (&request.nlh, sizeof (request),
                            NFQNL_MSG_VERDICT, queue_id);
  /* libnetfilter_queue sends verdicts with NLM_F_REQUEST only.  ACK is kept
   * for configuration commands, but verdict ACKs are delivered on the same
   * queue fd as packets and pollute the read-ready ingress stream. */
  request.nlh.nlmsg_flags = NLM_F_REQUEST;
  clib_memset (&verdict_header, 0, sizeof (verdict_header));
  verdict_header.verdict = htonl (verdict);
  verdict_header.id = htonl (packet_id);
  if (!product_nfnl_addattr (&request.nlh, sizeof (request),
                             NFQA_VERDICT_HDR, &verdict_header,
                             sizeof (verdict_header)))
    return 0;
  return product_nfnl_send (fd, &request.nlh);
}

static void
product_root_nfqueue_record_verdict_attempt (
  product_root_nfqueue_main_t *nm, product_root_nfqueue_lane_t *lane,
  u32 packet_id)
{
  lane->verdict_attempts++;
  nm->verdict_attempts++;
  lane->last_verdict_packet_id = packet_id;
  lane->verdict_packet_id_known = 1;
}

static int
product_root_nfqueue_send_counted_verdict (
  product_root_nfqueue_main_t *nm, product_root_nfqueue_lane_t *lane,
  u32 packet_id, u32 verdict)
{
  product_root_nfqueue_record_verdict_attempt (nm, lane, packet_id);
  if (product_nfqueue_send_verdict (lane->fd, lane->queue_id, packet_id,
                                    verdict))
    {
      lane->verdict_succeeded++;
      nm->verdict_succeeded++;
      return 1;
    }
  lane->verdict_failed++;
  nm->verdict_failed++;
  nm->verdict_failed_definite++;
  return 0;
}

static int
product_root_nfqueue_parse_packet (u8 *data, u32 length,
                                   product_root_nfqueue_packet_t *packet)
{
  struct nlmsghdr *nlh;
  int remaining = (int) length;

  clib_memset (packet, 0, sizeof (*packet));
  for (nlh = (struct nlmsghdr *) data; NLMSG_OK (nlh, remaining);
       nlh = NLMSG_NEXT (nlh, remaining))
    {
      struct nfgenmsg *nfgen;
      struct nfattr *attr;
      int attr_length;

      if (nlh->nlmsg_type == NLMSG_ERROR)
        return 0;
      if (NFNL_SUBSYS_ID (nlh->nlmsg_type) != NFNL_SUBSYS_QUEUE
          || NFNL_MSG_TYPE (nlh->nlmsg_type) != NFQNL_MSG_PACKET)
        continue;
      if (NLMSG_PAYLOAD (nlh, 0) < sizeof (*nfgen))
        return 0;

      nfgen = (struct nfgenmsg *) NLMSG_DATA (nlh);
      attr = NFM_NFA (nfgen);
      attr_length = NFM_PAYLOAD (nlh);
      for (; NFA_OK (attr, attr_length);
           attr = NFA_NEXT (attr, attr_length))
        {
          switch (NFA_TYPE (attr))
            {
            case NFQA_PACKET_HDR:
              if (NFA_PAYLOAD (attr) >=
                  (int) sizeof (struct nfqnl_msg_packet_hdr))
                {
                  const struct nfqnl_msg_packet_hdr *packet_header =
                    (const struct nfqnl_msg_packet_hdr *) NFA_DATA (attr);
                  packet->packet_id = ntohl (packet_header->packet_id);
                  packet->hook = packet_header->hook;
                }
              break;
            case NFQA_UID:
              if (NFA_PAYLOAD (attr) >= (int) sizeof (u32))
                {
                  u32 uid;
                  clib_memcpy_fast (&uid, NFA_DATA (attr), sizeof (uid));
                  packet->uid = ntohl (uid);
                  packet->uid_present = 1;
                }
              break;
            case NFQA_IFINDEX_INDEV:
            case NFQA_IFINDEX_OUTDEV:
              if (NFA_PAYLOAD (attr) >= (int) sizeof (u32))
                {
                  u32 ifindex;
                  clib_memcpy_fast (&ifindex, NFA_DATA (attr), sizeof (ifindex));
                  if (NFA_TYPE (attr) == NFQA_IFINDEX_INDEV)
                    { packet->indev = ntohl (ifindex); packet->indev_present = 1; }
                  else
                    { packet->outdev = ntohl (ifindex); packet->outdev_present = 1; }
                }
              break;
            case NFQA_PAYLOAD:
              packet->payload = (u8 *) NFA_DATA (attr);
              packet->payload_length = (u32) NFA_PAYLOAD (attr);
              break;
            default:
              break;
            }
        }
      if (packet->payload != 0 && packet->payload_length != 0)
        {
          u8 version = packet->payload[0] >> 4;
          if (version == 4)
            {
              packet->ip_family = 4;
              if (packet->payload_length >= 20)
                packet->protocol = packet->payload[9];
            }
          else if (version == 6)
            {
              packet->ip_family = 6;
              if (packet->payload_length >= 40)
                packet->protocol = packet->payload[6];
            }
        }
      return packet->packet_id != 0
             && (packet->hook == NF_INET_LOCAL_OUT
                 || packet->hook == NF_INET_LOCAL_IN)
             && (packet->ip_family == 4 || packet->ip_family == 6)
             && packet->payload != 0 && packet->payload_length != 0;
    }
  return 0;
}

static int
product_root_nfqueue_packet_id_seen (const u32 *packet_ids, u32 packet_count,
                                     u32 packet_id)
{
  u32 index;
  for (index = 0; index < packet_count; index++)
    if (packet_ids[index] == packet_id)
      return 1;
  return 0;
}

static void
product_root_nfqueue_accept_extra_messages (product_root_nfqueue_main_t *nm,
                                            product_root_nfqueue_lane_t *lane,
                                            u8 *data, u32 length,
                                            u32 primary_packet_id)
{
  struct nlmsghdr *nlh;
  int remaining = (int) length;
  u32 accepted_ids[64];
  u32 accepted_count = 0;

  for (nlh = (struct nlmsghdr *) data; NLMSG_OK (nlh, remaining);
       nlh = NLMSG_NEXT (nlh, remaining))
    {
      struct nfgenmsg *nfgen;
      struct nfattr *attr;
      int attr_length;
      u32 packet_id = 0;

      if (NFNL_SUBSYS_ID (nlh->nlmsg_type) != NFNL_SUBSYS_QUEUE
          || NFNL_MSG_TYPE (nlh->nlmsg_type) != NFQNL_MSG_PACKET
          || NLMSG_PAYLOAD (nlh, 0) < sizeof (*nfgen))
        continue;

      nfgen = (struct nfgenmsg *) NLMSG_DATA (nlh);
      attr = NFM_NFA (nfgen);
      attr_length = NFM_PAYLOAD (nlh);
      for (; NFA_OK (attr, attr_length);
           attr = NFA_NEXT (attr, attr_length))
        if (NFA_TYPE (attr) == NFQA_PACKET_HDR
            && NFA_PAYLOAD (attr)
                 >= (int) sizeof (struct nfqnl_msg_packet_hdr))
          {
            const struct nfqnl_msg_packet_hdr *packet_header =
              (const struct nfqnl_msg_packet_hdr *) NFA_DATA (attr);
            packet_id = ntohl (packet_header->packet_id);
            break;
          }

      if (packet_id == 0 || packet_id == primary_packet_id
          || product_root_nfqueue_packet_id_seen (accepted_ids,
                                                 accepted_count, packet_id))
        continue;
      if (accepted_count <
          sizeof (accepted_ids) / sizeof (accepted_ids[0]))
        accepted_ids[accepted_count++] = packet_id;
      nm->graph_submit_fail_opens++;
      product_root_nfqueue_send_counted_verdict (nm, lane, packet_id,
                                                 NF_ACCEPT);
    }
}

static void
product_root_nfqueue_complete_from_graph (
  vlib_main_t *vm, u32 buffer_index, const product_packet_lease_t *lease,
  u64 origin_obligation_id,
  product_packet_terminal_intent_t terminal_intent,
  product_packet_runtime_drop_reason_t runtime_drop_reason, void *opaque)
{
  product_root_nfqueue_main_t *nm = opaque;
  product_root_nfqueue_lane_t *lane;
  u32 lane_index;
  u32 packet_id;
  u32 verdict = terminal_intent == PRODUCT_PACKET_INTENT_PASS_ADAPTER
                  ? NF_ACCEPT
                  : NF_DROP;
  (void) buffer_index;
  (void) runtime_drop_reason;

  if (!product_root_nfqueue_decode_obligation (origin_obligation_id,
                                               &lane_index, &packet_id)
      || lane_index >= nm->lane_count)
    {
      nm->stale_completion_drops++;
      return;
    }
  lane = &nm->lanes[lane_index];
  if (!lane->listener_ready || !lane->socket_ready || lane->fd < 0)
    {
      nm->stale_completion_drops++;
      return;
    }
  if (lane->verdict_packet_id_known
      && lane->last_verdict_packet_id == packet_id)
    {
      lane->duplicate_completion_drops++;
      nm->duplicate_completion_drops++;
      return;
    }

  if (vm->thread_index != vlib_get_worker_thread_index (0))
    {
      nm->stale_completion_drops++;
      return;
    }
  lane->origin_local_completions++;
  nm->origin_local_completions++;
  lane->buffer_returns++;
  nm->buffer_returns++;
  lane->internal_settlements++;
  nm->internal_settlements++;
  product_root_nfqueue_record_verdict_attempt (nm, lane, packet_id);
  if (nm->fault_mode == PRODUCT_ROOT_NFQUEUE_FAULT_VERDICT_FAILED_DEFINITE)
    {
      lane->verdict_failed++;
      nm->verdict_failed++;
      nm->verdict_failed_definite++;
      return;
    }
  if (nm->fault_mode == PRODUCT_ROOT_NFQUEUE_FAULT_VERDICT_OUTCOME_UNKNOWN)
    {
      lane->verdict_failed++;
      nm->verdict_failed++;
      nm->verdict_outcome_unknown++;
      return;
    }
  if (nm->internal_settlements <= 64)
  fprintf(stderr, "s203 event=verdict source=NFQ_CAPTURED thread=%u lane=%u queue=%u packet=%u obligation=%llu generation=%llu verdict=%u owner=%u\n",
    vm->thread_index, lane_index, lane->queue_id, packet_id,
    (unsigned long long)origin_obligation_id, (unsigned long long)nm->generation,
    verdict, lease ? lease->expected_owner : UINT16_MAX);
  if (product_nfqueue_send_verdict (lane->fd, lane->queue_id, packet_id,
                                    verdict))
    {
      lane->verdict_succeeded++;
      nm->verdict_succeeded++;
    }
  else
    {
      lane->verdict_failed++;
      nm->verdict_failed++;
      nm->verdict_failed_definite++;
    }
}

static clib_error_t *
product_root_nfqueue_read_ready (clib_file_t *file)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  product_root_nfqueue_lane_t *lane =
    uword_to_pointer (file->private_data, product_root_nfqueue_lane_t *);
  vlib_main_t *vm = vlib_get_main ();

  if (lane == 0 || lane->lane_index >= nm->lane_count)
    return clib_error_return (0, "Root NFQUEUE lane identity missing");

  for (u32 budget = 0; budget < 64; budget++)
    {
      u32 buffer_index;
      vlib_buffer_t *buffer;
      u8 *base;
      u32 data_size;
      ssize_t received;
      product_root_nfqueue_packet_t packet;
      product_platform_packet_facts_t platform;
      product_packet_graph_external_result_t graph_result;
      u64 obligation_id;
      int submitted;

      if (vlib_buffer_alloc (vm, &buffer_index, 1) != 1)
        return 0;
      buffer = vlib_get_buffer (vm, buffer_index);
      vlib_buffer_reset (buffer);
      clib_memset (buffer->opaque2, 0, sizeof (buffer->opaque2));
      base = vlib_buffer_get_current (buffer);
      data_size = vlib_buffer_get_default_data_size (vm);
      received = recv ((int) file->file_descriptor, base, data_size,
                       MSG_DONTWAIT | MSG_TRUNC);
      if (received < 0)
        {
          int saved_errno = errno;
          vlib_buffer_free (vm, &buffer_index, 1);
          if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK)
            return 0;
          return clib_error_return_unix (0, "Root NFQUEUE recv");
        }
      if (received == 0 || received > (ssize_t) data_size)
        {
          vlib_buffer_free (vm, &buffer_index, 1);
          continue;
        }

      buffer->current_length = (u16) received;
      if (!product_root_nfqueue_parse_packet (base, (u32) received, &packet))
        {
          if (packet.packet_id != 0
              && (packet.hook == NF_INET_LOCAL_OUT
                  || packet.hook == NF_INET_LOCAL_IN))
            {
              product_root_nfqueue_accept_extra_messages (
                nm, lane, base, (u32) received, packet.packet_id);
              nm->graph_submit_fail_opens++;
              product_root_nfqueue_send_counted_verdict (
                nm, lane, packet.packet_id, NF_ACCEPT);
            }
          else
            nm->ingress_identity_missing++;
          vlib_buffer_free (vm, &buffer_index, 1);
          continue;
        }
      if (nm->fault_mode == PRODUCT_ROOT_NFQUEUE_FAULT_MISSING_IDENTITY)
        {
          nm->ingress_identity_missing++;
          vlib_buffer_free (vm, &buffer_index, 1);
          continue;
        }

      lane->packets_seen++;
      nm->packets_seen++;
      /* OUTPUT reaches this queue only through the supervisor's uid-owner rule. */
      if (packet.hook == NF_INET_LOCAL_OUT && !packet.uid_present)
        {
          packet.uid = nm->uid_owner;
          packet.uid_present = 1;
        }
      if (packet.hook == NF_INET_LOCAL_OUT && packet.uid_present
          && packet.uid != nm->uid_owner)
        {
          nm->non_owner_bypasses++;
          product_root_nfqueue_send_counted_verdict (
            nm, lane, packet.packet_id, NF_ACCEPT);
          vlib_buffer_free (vm, &buffer_index, 1);
          continue;
        }
      if (packet.hook == NF_INET_LOCAL_IN)
        nm->input_packets++;
      else if (packet.hook == NF_INET_LOCAL_OUT)
        nm->output_packets++;
      if (packet.ip_family == 4)
        nm->ipv4_packets++;
      else if (packet.ip_family == 6)
        nm->ipv6_packets++;
      if (packet.protocol == IPPROTO_TCP)
        nm->tcp_packets++;
      else if (packet.protocol == IPPROTO_UDP)
        nm->udp_packets++;
      if (packet.uid_present)
        nm->uid_known_packets++;
      else
        nm->uid_unknown_packets++;
      nm->last_packet_id = packet.packet_id;
      nm->last_queue_id = lane->queue_id;
      nm->last_uid = packet.uid_present ? packet.uid : UINT32_MAX;
      nm->last_ip_family = packet.ip_family;
      nm->last_protocol = packet.protocol;
      nm->last_hook = packet.hook;
      nm->last_uid_known = packet.uid_present ? 1 : 0;
      buffer->current_data =
        (i16) (buffer->current_data + (packet.payload - base));
      buffer->current_length = (u16) packet.payload_length;
      clib_memset (&platform, 0, sizeof (platform));
      platform.uid = packet.uid;
      platform.availability = packet.uid_present ? PRODUCT_PLATFORM_UID_KNOWN : 0;
      platform.provenance = PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE;
      platform.direction = packet.hook == NF_INET_LOCAL_OUT
        ? PRODUCT_PACKET_DIRECTION_OUTPUT : packet.hook == NF_INET_LOCAL_IN
        ? PRODUCT_PACKET_DIRECTION_INPUT : PRODUCT_PACKET_DIRECTION_UNKNOWN;
      if (packet.hook == NF_INET_LOCAL_OUT && packet.outdev_present)
        {
          platform.linux_ifindex = packet.outdev;
          platform.availability |= PRODUCT_PLATFORM_IFINDEX_KNOWN;
        }
      else if (packet.hook == NF_INET_LOCAL_IN && packet.indev_present)
        {
          platform.linux_ifindex = packet.indev;
          platform.availability |= PRODUCT_PLATFORM_IFINDEX_KNOWN;
        }
      /* No reliable per-interface classification snapshot yet. Context stays
       * unavailable, including for loopback. Never infer it from queue/lane. */

      obligation_id =
        product_root_nfqueue_obligation_id (lane->lane_index,
                                            packet.packet_id);
      if (nm->fault_mode == PRODUCT_ROOT_NFQUEUE_FAULT_GRAPH_SUBMIT_FAIL_OPEN)
        {
          product_root_nfqueue_accept_extra_messages (
            nm, lane, base, (u32) received, packet.packet_id);
          nm->graph_submit_fail_opens++;
          product_root_nfqueue_send_counted_verdict (
            nm, lane, packet.packet_id, NF_ACCEPT);
          vlib_buffer_free (vm, &buffer_index, 1);
          continue;
        }
      if (nm->packets_seen <= 64)
        fprintf(stderr, "s203 event=capture source=NFQ_CAPTURED thread=%u tls=%u polling_thread=%u lane=%u queue=%u packet=%u buffer=%u obligation=%llu\n",
          vm->thread_index, vlib_get_thread_index(), file->polling_thread_index,
          lane->lane_index, lane->queue_id, packet.packet_id, buffer_index,
          (unsigned long long)obligation_id);
      submitted = product_packet_graph_submit_external (
        vm, buffer_index, &platform,
        &(product_adapter_obligation_t) {
          .token = obligation_id, .queue_generation = nm->generation,
          .packet_id = packet.packet_id, .origin_lane = lane->lane_index,
          .kind = PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE,
        }, &graph_result);
      if (!submitted)
        {
          product_root_nfqueue_accept_extra_messages (
            nm, lane, base, (u32) received, packet.packet_id);
          nm->graph_submit_fail_opens++;
          product_root_nfqueue_send_counted_verdict (
            nm, lane, packet.packet_id, NF_ACCEPT);
          vlib_buffer_free (vm, &buffer_index, 1);
        }
      else
        {
          lane->packets_submitted++;
          nm->packets_submitted++;
          if (nm->packets_submitted <= 64)
          fprintf(stderr, "s203 event=frame_accept source=NFQ_CAPTURED thread=%u lane=%u queue=%u packet=%u buffer=%u obligation=%llu generation=%llu\n",
            vm->thread_index, lane->lane_index, lane->queue_id, packet.packet_id,
            buffer_index, (unsigned long long)obligation_id,
            (unsigned long long)nm->generation);
        }
    }
  return 0;
}

static void
product_root_nfqueue_reset_lane (product_root_nfqueue_lane_t *lane,
                                 u32 lane_index, u32 queue_id)
{
  clib_memset (lane, 0, sizeof (*lane));
  lane->fd = -1;
  lane->clib_file_index = ~0;
  lane->queue_id = queue_id;
  lane->lane_index = lane_index;
}

static int
product_root_nfqueue_open_lane (product_root_nfqueue_main_t *nm,
                                product_root_nfqueue_lane_t *lane)
{
  struct sockaddr_nl address;
  clib_file_t template = { 0 };
  int fd;

  fd = socket (AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
               NETLINK_NETFILTER);
  if (fd < 0)
    {
      product_root_nfqueue_last_errno = errno == 0 ? EIO : errno;
      product_root_nfqueue_warn_errno ("socket");
      return 0;
    }

  clib_memset (&address, 0, sizeof (address));
  address.nl_family = AF_NETLINK;
  if (bind (fd, (struct sockaddr *) &address, sizeof (address)) < 0)
    {
      product_root_nfqueue_last_errno = errno == 0 ? EIO : errno;
      product_root_nfqueue_warn_errno ("bind");
      close (fd);
      return 0;
    }
  lane->fd = fd;
  lane->socket_ready = 1;

  if (!product_nfqueue_configure (fd, lane->queue_id))
    {
      close (fd);
      lane->fd = -1;
      lane->socket_ready = 0;
      return 0;
    }

  template.read_function = product_root_nfqueue_read_ready;
  template.polling_thread_index = vlib_get_worker_thread_index (0);
  template.file_descriptor = (u32) fd;
  template.private_data = pointer_to_uword (lane);
  template.description =
    format (0, "sakamoto-root-nfqueue-%u%c", lane->queue_id, 0);
  lane->clib_file_index = clib_file_add (&file_main, &template);
  lane->listener_ready = 1;
  nm->ready_lane_mask |= 1U << lane->lane_index;
  return 1;
}

int
product_root_nfqueue_adapter_start (vlib_main_t *vm, u64 generation)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  u32 index;

  if (nm->available)
    return 1;
  if (vm == 0 || generation == 0)
    return 0;

  nm->vlib_main = vm;
  nm->queue_id = product_root_nfqueue_queue_from_env ();
  nm->lane_count = product_root_nfqueue_lanes_from_env ();
  if (nm->lane_count != 1 || vlib_num_workers () < 2)
    return 0;
  nm->queue_last = nm->queue_id + nm->lane_count - 1;
  if (!product_root_nfqueue_uid_from_env (&nm->uid_owner))
    {
      clib_warning ("root nfqueue start failed: missing app uid owner");
      return 0;
    }
  nm->generation = generation;
  nm->fault_mode = product_root_nfqueue_fault_mode_from_env ();
  if (nm->fault_mode == PRODUCT_ROOT_NFQUEUE_FAULT_DUPLICATE_COMPLETION
      || nm->fault_mode == PRODUCT_ROOT_NFQUEUE_FAULT_STALE_COMPLETION)
    return 0;
  nm->packets_seen = 0;
  nm->packets_submitted = 0;
  nm->verdict_attempts = 0;
  nm->verdict_succeeded = 0;
  nm->verdict_failed = 0;
  nm->internal_settlements = 0;
  nm->buffer_returns = 0;
  nm->origin_local_completions = 0;
  nm->origin_remote_completions = 0;
  nm->input_packets = 0;
  nm->output_packets = 0;
  nm->ipv4_packets = 0;
  nm->ipv6_packets = 0;
  nm->tcp_packets = 0;
  nm->udp_packets = 0;
  nm->uid_known_packets = 0;
  nm->uid_unknown_packets = 0;
  nm->verdict_succeeded = 0;
  nm->verdict_failed_definite = 0;
  nm->verdict_outcome_unknown = 0;
  nm->ingress_identity_missing = 0;
  nm->graph_submit_fail_opens = 0;
  nm->non_owner_bypasses = 0;
  nm->last_packet_id = 0;
  nm->last_queue_id = 0;
  nm->last_uid = UINT32_MAX;
  nm->last_ip_family = 0;
  nm->last_protocol = 0;
  nm->last_hook = 0;
  nm->last_uid_known = 0;
  nm->duplicate_completion_drops = 0;
  nm->stale_completion_drops = 0;
  nm->ready_lane_mask = 0;
  nm->hook_ready = 0;
  nm->available = 0;

  for (index = 0; index < PRODUCT_ROOT_NFQUEUE_MAX_LANES; index++)
    product_root_nfqueue_reset_lane (&nm->lanes[index], index,
                                     nm->queue_id + index);

  if (!product_packet_graph_start_external (vm, generation))
    {
      product_root_nfqueue_adapter_stop (vm);
      return 0;
    }
  product_packet_graph_register_external_completion (
    product_root_nfqueue_complete_from_graph, nm);

  for (index = 0; index < nm->lane_count; index++)
    if (!product_root_nfqueue_open_lane (nm, &nm->lanes[index]))
      {
        product_root_nfqueue_adapter_stop (vm);
        return 0;
      }

  /*
   * Android Runtime Supervisor installs/removes the platform INPUT/OUTPUT
   * hooks under KernelSU before launching Product VPP. VPP owns only the
   * NFQUEUE netlink sockets, VPP file listeners, and Product Packet completion
   * path.
   */
  nm->hook_ready = 1;
  nm->available = 1;
  return 1;
}

void
product_root_nfqueue_adapter_stop (vlib_main_t *vm)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  (void) vm;

  nm->available = 0;
  nm->hook_ready = 0;
  product_packet_graph_stop_external (nm->vlib_main);
  product_packet_graph_register_external_completion (0, 0);
  for (u32 index = 0; index < PRODUCT_ROOT_NFQUEUE_MAX_LANES; index++)
    {
      product_root_nfqueue_lane_t *lane = &nm->lanes[index];
      if (lane->listener_ready && lane->clib_file_index != ~0)
        {
          clib_file_del_by_index (&file_main, lane->clib_file_index);
          lane->clib_file_index = ~0;
        }
      else if (lane->fd >= 0 && lane->socket_ready)
        {
          close (lane->fd);
        }
      lane->fd = -1;
      lane->listener_ready = 0;
      lane->socket_ready = 0;
    }
  nm->ready_lane_mask = 0;
}

int
product_root_nfqueue_adapter_available (void)
{
  const product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  u32 ready = nm->lane_count >= 32 ? UINT32_MAX : ((1U << nm->lane_count) - 1);
  return nm->available && nm->lane_count >= 1
         && nm->ready_lane_mask == ready && nm->hook_ready;
}

uint32_t
product_root_nfqueue_adapter_queue_id (void)
{
  return product_root_nfqueue_main.queue_id;
}

uint32_t
product_root_nfqueue_adapter_queue_last (void)
{
  return product_root_nfqueue_main.queue_last;
}

uint32_t
product_root_nfqueue_adapter_lane_count (void)
{
  return product_root_nfqueue_main.lane_count;
}

uint32_t
product_root_nfqueue_adapter_ready_lane_mask (void)
{
  return product_root_nfqueue_main.ready_lane_mask;
}

uint64_t
product_root_nfqueue_adapter_generation (void)
{
  return product_root_nfqueue_main.generation;
}

uint64_t
product_root_nfqueue_adapter_verdict_attempts (void)
{
  return product_root_nfqueue_main.verdict_attempts;
}

uint64_t
product_root_nfqueue_adapter_verdict_succeeded (void)
{
  return product_root_nfqueue_main.verdict_succeeded;
}

uint64_t
product_root_nfqueue_adapter_verdict_failed_definite (void)
{
  return product_root_nfqueue_main.verdict_failed_definite;
}

uint64_t
product_root_nfqueue_adapter_verdict_outcome_unknown (void)
{
  return product_root_nfqueue_main.verdict_outcome_unknown;
}

uint64_t
product_root_nfqueue_adapter_ingress_identity_missing (void)
{
  return product_root_nfqueue_main.ingress_identity_missing;
}

uint64_t
product_root_nfqueue_adapter_graph_submit_fail_opens (void)
{
  return product_root_nfqueue_main.graph_submit_fail_opens;
}

uint64_t
product_root_nfqueue_adapter_non_owner_bypasses (void)
{
  return product_root_nfqueue_main.non_owner_bypasses;
}

uint64_t
product_root_nfqueue_adapter_duplicate_completion_drops (void)
{
  return product_root_nfqueue_main.duplicate_completion_drops;
}

uint64_t
product_root_nfqueue_adapter_stale_completion_drops (void)
{
  return product_root_nfqueue_main.stale_completion_drops;
}

uint64_t
product_root_nfqueue_adapter_internal_settlements (void)
{
  return product_root_nfqueue_main.internal_settlements;
}

uint64_t
product_root_nfqueue_adapter_buffer_returns (void)
{
  return product_root_nfqueue_main.buffer_returns;
}

uint64_t
product_root_nfqueue_adapter_origin_local_completions (void)
{
  return product_root_nfqueue_main.origin_local_completions;
}

uint64_t
product_root_nfqueue_adapter_origin_remote_completions (void)
{
  return product_root_nfqueue_main.origin_remote_completions;
}

uint64_t
product_root_nfqueue_adapter_lane_verdict_attempts (uint32_t lane_index)
{
  if (lane_index >= product_root_nfqueue_main.lane_count
      || lane_index >= PRODUCT_ROOT_NFQUEUE_MAX_LANES)
    return 0;
  return product_root_nfqueue_main.lanes[lane_index].verdict_attempts;
}

uint64_t
product_root_nfqueue_adapter_input_packets (void)
{
  return product_root_nfqueue_main.input_packets;
}

uint64_t
product_root_nfqueue_adapter_output_packets (void)
{
  return product_root_nfqueue_main.output_packets;
}

uint64_t
product_root_nfqueue_adapter_ipv4_packets (void)
{
  return product_root_nfqueue_main.ipv4_packets;
}

uint64_t
product_root_nfqueue_adapter_ipv6_packets (void)
{
  return product_root_nfqueue_main.ipv6_packets;
}

uint64_t
product_root_nfqueue_adapter_tcp_packets (void)
{
  return product_root_nfqueue_main.tcp_packets;
}

uint64_t
product_root_nfqueue_adapter_udp_packets (void)
{
  return product_root_nfqueue_main.udp_packets;
}

uint64_t
product_root_nfqueue_adapter_uid_known_packets (void)
{
  return product_root_nfqueue_main.uid_known_packets;
}

uint64_t
product_root_nfqueue_adapter_uid_unknown_packets (void)
{
  return product_root_nfqueue_main.uid_unknown_packets;
}

uint32_t
product_root_nfqueue_adapter_last_ip_family (void)
{
  return product_root_nfqueue_main.last_ip_family;
}

uint32_t
product_root_nfqueue_adapter_last_protocol (void)
{
  return product_root_nfqueue_main.last_protocol;
}

uint32_t
product_root_nfqueue_adapter_last_hook (void)
{
  return product_root_nfqueue_main.last_hook;
}

uint32_t
product_root_nfqueue_adapter_last_uid_known (void)
{
  return product_root_nfqueue_main.last_uid_known;
}

uint32_t
product_root_nfqueue_adapter_last_uid (void)
{
  return product_root_nfqueue_main.last_uid;
}

uint32_t
product_root_nfqueue_adapter_last_queue_id (void)
{
  return product_root_nfqueue_main.last_queue_id;
}

uint32_t
product_root_nfqueue_adapter_last_packet_id (void)
{
  return product_root_nfqueue_main.last_packet_id;
}

static clib_error_t *
product_root_nfqueue_exit (vlib_main_t *vm)
{
  product_root_nfqueue_adapter_stop (vm);
  return 0;
}

VLIB_MAIN_LOOP_EXIT_FUNCTION (product_root_nfqueue_exit);
