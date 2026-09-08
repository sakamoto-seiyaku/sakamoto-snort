/* SPDX-License-Identifier: Apache-2.0 */

/*
 * VPP-native Root packet I/O. Dual-stack Q2 per family maps each family
 * lane 0/1 to worker 0/1. The shared graph parses and selects its
 * owner; the origin Completion Frame consumer alone completes admitted NFQ
 * obligations. Wider hooks/protocols and queue-pressure qualification remain
 * separate acceptance work.
 */

#include "product_root_nfqueue_adapter.h"
#include "product_network_snapshot.h"

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
#include <sys/syscall.h>
#include <unistd.h>

#include <vlib/file.h>

#define PRODUCT_ROOT_NFQUEUE_DEFAULT_QUEUE 176
#define PRODUCT_ROOT_NFQUEUE_DEFAULT_LANES 4
#define PRODUCT_ROOT_NFQUEUE_MAX_LANES PRODUCT_ROOT_COMPLETION_MAX_LANES
#define PRODUCT_ROOT_NFQUEUE_MAX_NETLINK 8192
#define PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY PRODUCT_ROOT_COMPLETION_CAPACITY

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
  u32 skb_info, captured_length;
  u8 skb_info_present, captured_length_present;
  u8 *payload;
  u32 payload_length;
} product_root_nfqueue_packet_t;

/* Bounded adapter ledger only: no packet or platform facts. It remembers
 * completed identities until the slot is reused, preventing non-last replay. */
typedef struct
{
  product_packet_completion_frame_t completion;
  u32 buffer_index;
  u8 active;
} product_root_nfqueue_pending_t;

_Static_assert (sizeof (product_root_nfqueue_pending_t) == 40, "bounded completion identity ledger");

typedef struct
{
  int fd;
  uword clib_file_index;
  u32 queue_id;
  u32 lane_index;
  u32 family_lane;
  u32 worker_index;
  u32 ip_family;
  u64 generation;
  u64 next_obligation_token;
  u32 pending_count;
  u8 draining;
  u32 last_cpu, callback_thread, callback_tls;
  u32 last_packet_id, last_queue_id, last_uid, last_ip_family;
  u32 last_protocol, last_hook, last_uid_known;
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
  product_root_nfqueue_pending_t pending[PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY];
} product_root_nfqueue_lane_t;

typedef struct
{
  vlib_main_t *vlib_main;
  u32 queue_id;
  u32 queue_last;
  u32 lane_count;
  u32 uid_owner;
  u64 generation;
  u32 pending_count;
  u32 replay_count;
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
  u32 last_lane;
  u64 duplicate_completion_drops;
  u64 stale_completion_drops;
  u32 ready_lane_mask;
  product_root_nfqueue_fault_mode_t fault_mode;
  u32 facts_fault; /* Explicit CLI-only attribute fault; reset per generation. */
  u8 hook_ready;
  u8 available;
  product_root_nfqueue_lane_t lanes[PRODUCT_ROOT_NFQUEUE_MAX_LANES];
} product_root_nfqueue_main_t;

static __thread int product_root_nfqueue_last_errno;

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
  /* UID zero is a real Linux endpoint identity; UINT32_MAX is unknown. */
  if (errno != 0 || end == value || *end != '\0' || *value == '-'
      || parsed >= UINT32_MAX)
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

static product_root_nfqueue_pending_t *
product_root_nfqueue_reserve (product_root_nfqueue_main_t *nm,
                              product_root_nfqueue_lane_t *lane,
                              u32 packet_id, u32 buffer_index)
{
  product_root_nfqueue_pending_t *pending =
    &lane->pending[packet_id % PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY];
  if (pending->active || lane->next_obligation_token >=
      (UINT64_MAX - PRODUCT_ROOT_NFQUEUE_MAX_LANES) / PRODUCT_ROOT_NFQUEUE_MAX_LANES)
    return 0;
  clib_memset (pending, 0, sizeof (*pending));
  pending->completion.obligation = (product_adapter_obligation_t) {
    .token = (++lane->next_obligation_token * PRODUCT_ROOT_NFQUEUE_MAX_LANES)
             + lane->lane_index,
    .queue_generation = lane->generation,
    .packet_id = packet_id,
    .origin_lane = lane->lane_index,
    .origin_worker = lane->worker_index,
    .kind = PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE,
  };
  pending->buffer_index = buffer_index;
  pending->active = 1;
  lane->pending_count++;
  clib_atomic_fetch_add_relax (&nm->pending_count, 1);
  return pending;
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
             NFA_SPACE (sizeof (struct nfqnl_msg_config_params)) +
             2 * NFA_SPACE (sizeof (u32))];
    struct nlmsghdr nlh;
  } request;
  struct nfqnl_msg_config_params params;
  u32 uid_flags = htonl (NFQA_CFG_F_UID_GID);

  product_nfnl_fill_header (&request.nlh, sizeof (request),
                            NFQNL_MSG_CONFIG, queue_id);
  clib_memset (&params, 0, sizeof (params));
  params.copy_range = htonl (UINT16_MAX);
  params.copy_mode = NFQNL_COPY_PACKET;
  if (!product_nfnl_addattr (&request.nlh, sizeof (request),
                             NFQA_CFG_PARAMS, &params, sizeof (params)))
    return 0;
  if (!product_nfnl_addattr (&request.nlh, sizeof (request), NFQA_CFG_MASK,
                             &uid_flags, sizeof (uid_flags))
      || !product_nfnl_addattr (&request.nlh, sizeof (request), NFQA_CFG_FLAGS,
                                &uid_flags, sizeof (uid_flags)))
    return 0;
  if (!product_nfnl_send (fd, &request.nlh))
    return 0;
  return product_nfqueue_recv_ack (fd);
}

static int
product_nfqueue_configure (int fd, u32 queue_id, u32 family)
{
  if (!product_nfqueue_send_config_command (fd, NFQNL_CFG_CMD_PF_BIND, 0,
                                            family == 4 ? AF_INET : AF_INET6))
    {
      product_root_nfqueue_warn_errno ("PF_BIND");
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
  clib_atomic_fetch_add_relax (&nm->verdict_attempts, 1);
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
      clib_atomic_fetch_add_relax (&nm->verdict_succeeded, 1);
      return 1;
    }
  lane->verdict_failed++;
  clib_atomic_fetch_add_relax (&nm->verdict_failed, 1);
  clib_atomic_fetch_add_relax (&nm->verdict_failed_definite, 1);
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
            case NFQA_SKB_INFO:
            case NFQA_CAP_LEN:
              if (NFA_PAYLOAD (attr) >= (int) sizeof (u32))
                {
                  u32 value;
                  clib_memcpy_fast (&value, NFA_DATA (attr), sizeof (value));
                  if (NFA_TYPE (attr) == NFQA_SKB_INFO)
                    { packet->skb_info = ntohl (value); packet->skb_info_present = 1; }
                  else
                    { packet->captured_length = ntohl (value); packet->captured_length_present = 1; }
                }
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
      clib_atomic_fetch_add_relax (&nm->graph_submit_fail_opens, 1);
      product_root_nfqueue_send_counted_verdict (nm, lane, packet_id,
                                                 NF_ACCEPT);
    }
}

static void
product_root_nfqueue_complete_from_graph (
  vlib_main_t *vm, u32 buffer_index,
  const product_packet_completion_frame_t *completion, void *opaque)
{
  product_root_nfqueue_main_t *nm = opaque;
  const product_adapter_obligation_t *obligation = &completion->obligation;
  u32 lane_index = obligation->origin_lane;
  u32 packet_id = obligation->packet_id;
  product_root_nfqueue_lane_t *lane;
  product_root_nfqueue_pending_t *pending;
  const char *rejection = 0;
  int capacity_bypass =
    completion->terminal_intent == PRODUCT_PACKET_INTENT_PROCESSING_CAPACITY_BYPASS
    && completion->runtime_drop_reason == PRODUCT_PACKET_DROP_NONE
    && (completion->processing_bypass_reason == PRODUCT_PACKET_BYPASS_PRIMARY_CREDIT_EXHAUSTED
        || completion->processing_bypass_reason == PRODUCT_PACKET_BYPASS_PRIMARY_ENQUEUE_REJECTED
        || completion->processing_bypass_reason == PRODUCT_PACKET_BYPASS_REASSEMBLY_RESOURCE);
  u32 verdict = completion->terminal_intent == PRODUCT_PACKET_INTENT_PASS_ADAPTER || capacity_bypass
                  ? NF_ACCEPT : NF_DROP;

  if (obligation->queue_generation != nm->generation
      || lane_index >= nm->lane_count
      || obligation->origin_worker >= product_packet_graph_worker_count ())
    { rejection = "stale_generation_or_lane"; goto stale; }
  lane = &nm->lanes[lane_index];
  if (obligation->queue_generation != lane->generation
      || obligation->origin_worker != lane->worker_index
      || vm->thread_index != vlib_get_worker_thread_index (lane->worker_index))
    { rejection = "origin_worker_mismatch"; goto stale; }
  if (!lane->listener_ready || !lane->socket_ready || lane->fd < 0)
    { rejection = "closed_lane"; goto stale; }
  pending = &lane->pending[packet_id % PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY];
  if (pending->completion.obligation.token != obligation->token
      || pending->completion.obligation.queue_generation != obligation->queue_generation
      || pending->completion.obligation.packet_id != packet_id)
    { rejection = "stale_identity"; goto stale; }
  if (!pending->active)
    {
      lane->duplicate_completion_drops++;
      clib_atomic_fetch_add_relax (&nm->duplicate_completion_drops, 1);
      rejection = "duplicate";
      goto rejected;
    }
  if (pending->buffer_index != buffer_index
      || (completion->flags & PRODUCT_COMPLETION_REPLAY_PROBE)
      || (completion->terminal_intent != PRODUCT_PACKET_INTENT_PASS_ADAPTER
          && completion->terminal_intent != PRODUCT_PACKET_INTENT_DROP_RUNTIME
          && !capacity_bypass))
    { rejection = "stale_carrier_or_intent"; goto stale; }

  /* Commit identity consumption before the one native operation attempt. */
  pending->active = 0;
  lane->pending_count--;
  pending->completion = *completion;
  clib_atomic_fetch_sub_relax (&nm->pending_count, 1);
  if (completion->producer_thread == vm->thread_index)
    { lane->origin_local_completions++; clib_atomic_fetch_add_relax (&nm->origin_local_completions, 1); }
  else
    { lane->origin_remote_completions++; clib_atomic_fetch_add_relax (&nm->origin_remote_completions, 1); }
  lane->buffer_returns++; clib_atomic_fetch_add_relax (&nm->buffer_returns, 1);
  lane->internal_settlements++; clib_atomic_fetch_add_relax (&nm->internal_settlements, 1);
  product_root_nfqueue_record_verdict_attempt (nm, lane, packet_id);
  if (completion->flags & PRODUCT_COMPLETION_TRACE)
    fprintf (stderr, "s210 event=origin_completion thread=%u buffer=%u token=%llu generation=%llu packet=%u lane=%u intent=%u drop_reason=%u bypass_reason=%u verdict=%u\n",
      vm->thread_index, buffer_index, (unsigned long long) obligation->token,
      (unsigned long long) obligation->queue_generation, packet_id, lane_index,
      completion->terminal_intent, completion->runtime_drop_reason,
      completion->processing_bypass_reason, verdict);
  if (nm->fault_mode == PRODUCT_ROOT_NFQUEUE_FAULT_VERDICT_FAILED_DEFINITE)
    {
      lane->verdict_failed++; clib_atomic_fetch_add_relax (&nm->verdict_failed, 1); clib_atomic_fetch_add_relax (&nm->verdict_failed_definite, 1);
      return;
    }
  if (nm->fault_mode == PRODUCT_ROOT_NFQUEUE_FAULT_VERDICT_OUTCOME_UNKNOWN)
    {
      lane->verdict_failed++; clib_atomic_fetch_add_relax (&nm->verdict_failed, 1); clib_atomic_fetch_add_relax (&nm->verdict_outcome_unknown, 1);
      return;
    }
  if (lane->internal_settlements <= product_packet_graph_trace_limit () / PRODUCT_ROOT_NFQUEUE_MAX_LANES)
    fprintf (stderr, "s203 event=verdict source=NFQ_CAPTURED thread=%u lane=%u queue=%u packet=%u obligation=%llu generation=%llu verdict=%u owner=%u\n",
      vm->thread_index, lane_index, lane->queue_id, packet_id,
      (unsigned long long) obligation->token, (unsigned long long) obligation->queue_generation,
      verdict, completion->producer_thread
        ? vlib_get_worker_index (completion->producer_thread)
        : PRODUCT_EXECUTION_OWNER_UNKNOWN);
  if (product_nfqueue_send_verdict (lane->fd, lane->queue_id, packet_id, verdict))
    { lane->verdict_succeeded++; clib_atomic_fetch_add_relax (&nm->verdict_succeeded, 1); }
  else
    { lane->verdict_failed++; clib_atomic_fetch_add_relax (&nm->verdict_failed, 1); clib_atomic_fetch_add_relax (&nm->verdict_failed_definite, 1); }
  return;

stale:
  clib_atomic_fetch_add_relax (&nm->stale_completion_drops, 1);
rejected:
  if (completion->flags & PRODUCT_COMPLETION_TRACE)
    fprintf (stderr, "s204 event=completion_reject source=%s thread=%u token=%llu generation=%llu packet=%u lane=%u reason=%s duplicate=%llu stale=%llu\n",
      (completion->flags & PRODUCT_COMPLETION_REPLAY_PROBE) ? "COMPLETION_REPLAY" : "NFQ_CAPTURED",
      vm->thread_index, (unsigned long long) obligation->token,
      (unsigned long long) obligation->queue_generation, packet_id, lane_index, rejection,
      (unsigned long long) nm->duplicate_completion_drops,
      (unsigned long long) nm->stale_completion_drops);
}

static clib_error_t *
product_root_nfqueue_read_ready (clib_file_t *file)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  product_root_nfqueue_lane_t *lane =
    uword_to_pointer (file->private_data, product_root_nfqueue_lane_t *);
  vlib_main_t *vm = vlib_get_main ();

  if (lane == 0 || lane->lane_index >= nm->lane_count
      || vm->thread_index != vlib_get_worker_thread_index (lane->worker_index)
      || file->file_descriptor != (u32) lane->fd)
    return clib_error_return (0, "Root NFQUEUE lane identity missing");
  if (lane->draining)
    return 0;

  for (u32 budget = 0; budget < 64; budget++)
    {
      u32 buffer_index;
      vlib_buffer_t *buffer;
      u8 *base;
      u32 data_size;
      ssize_t received;
      product_root_nfqueue_packet_t packet;
      product_platform_packet_facts_t platform;
      const sakamoto_product_network_snapshot_t *network = product_network_snapshot_current ();
      product_root_nfqueue_pending_t *pending;
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
              clib_atomic_fetch_add_relax (&nm->graph_submit_fail_opens, 1);
              product_root_nfqueue_send_counted_verdict (
                nm, lane, packet.packet_id, NF_ACCEPT);
            }
          else
            clib_atomic_fetch_add_relax (&nm->ingress_identity_missing, 1);
          vlib_buffer_free (vm, &buffer_index, 1);
          continue;
        }
      if (nm->fault_mode == PRODUCT_ROOT_NFQUEUE_FAULT_MISSING_IDENTITY)
        {
          clib_atomic_fetch_add_relax (&nm->ingress_identity_missing, 1);
          vlib_buffer_free (vm, &buffer_index, 1);
          continue;
        }

      lane->callback_thread = vm->thread_index;
      lane->callback_tls = vlib_get_thread_index ();
      if (lane->packets_seen < product_packet_graph_trace_limit () / PRODUCT_ROOT_NFQUEUE_MAX_LANES)
        {
          lane->last_cpu = UINT32_MAX;
          syscall (SYS_getcpu, &lane->last_cpu, 0, 0);
        }
      lane->packets_seen++;
      clib_atomic_fetch_add_relax (&nm->packets_seen, 1);
      product_root_nfqueue_packet_t observed = packet;
      /* Capture scope belongs to the supervisor's kernel rules. A configured
       * subject is not a packet identity, including across user namespaces.
       * Faults alter only parsed attribute evidence after real ingress.
       * Packet bytes and NFQUEUE completion identity are real.
       * They never run unless explicitly selected by the diagnostic CLI. */
      switch (nm->facts_fault)
        {
        case 1: packet.uid_present = 0; packet.uid = 0; break;
        case 2: packet.uid_present = 1; packet.uid = 0; break;
        case 3: packet.indev_present = packet.outdev_present = 0; break;
        case 4: packet.indev = packet.outdev = 0; break;
        case 5:
          if (packet.hook == NF_INET_LOCAL_OUT)
            { packet.indev_present = 1; packet.indev = 33333; }
          else if (packet.hook == NF_INET_LOCAL_IN)
            { packet.outdev_present = 1; packet.outdev = 33334; }
          break;
        case 6: packet.hook = UINT8_MAX; break;
        default: break;
        }
      if (packet.hook == NF_INET_LOCAL_IN)
        clib_atomic_fetch_add_relax (&nm->input_packets, 1);
      else if (packet.hook == NF_INET_LOCAL_OUT)
        clib_atomic_fetch_add_relax (&nm->output_packets, 1);
      if (packet.ip_family == 4)
        clib_atomic_fetch_add_relax (&nm->ipv4_packets, 1);
      else if (packet.ip_family == 6)
        clib_atomic_fetch_add_relax (&nm->ipv6_packets, 1);
      if (packet.protocol == IPPROTO_TCP)
        clib_atomic_fetch_add_relax (&nm->tcp_packets, 1);
      else if (packet.protocol == IPPROTO_UDP)
        clib_atomic_fetch_add_relax (&nm->udp_packets, 1);
      if (packet.uid_present)
        clib_atomic_fetch_add_relax (&nm->uid_known_packets, 1);
      else
        clib_atomic_fetch_add_relax (&nm->uid_unknown_packets, 1);
      lane->last_packet_id = packet.packet_id;
      lane->last_queue_id = lane->queue_id;
      lane->last_uid = packet.uid_present ? packet.uid : UINT32_MAX;
      lane->last_ip_family = packet.ip_family;
      lane->last_protocol = packet.protocol;
      lane->last_hook = packet.hook;
      lane->last_uid_known = packet.uid_present ? 1 : 0;
      clib_atomic_store_rel_n (&nm->last_lane, lane->lane_index);
      buffer->current_data =
        (i16) (buffer->current_data + (packet.payload - base));
      buffer->current_length = (u16) packet.payload_length;
      clib_memset (&platform, 0, sizeof (platform));
      platform.uid = packet.uid_present ? packet.uid : 0;
      platform.availability = packet.uid_present ? PRODUCT_PLATFORM_UID_KNOWN : 0;
      platform.provenance = PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE;
      platform.direction = packet.hook == NF_INET_LOCAL_OUT
        ? PRODUCT_PACKET_DIRECTION_OUTPUT : packet.hook == NF_INET_LOCAL_IN
        ? PRODUCT_PACKET_DIRECTION_INPUT : PRODUCT_PACKET_DIRECTION_UNKNOWN;
      if (packet.hook == NF_INET_LOCAL_OUT && packet.outdev_present
          && packet.outdev && packet.outdev <= INT32_MAX)
        {
          platform.linux_ifindex = packet.outdev;
          platform.availability |= PRODUCT_PLATFORM_IFINDEX_KNOWN;
        }
      else if (packet.hook == NF_INET_LOCAL_IN && packet.indev_present
               && packet.indev && packet.indev <= INT32_MAX)
        {
          platform.linux_ifindex = packet.indev;
          platform.availability |= PRODUCT_PLATFORM_IFINDEX_KNOWN;
        }
      if (platform.availability & PRODUCT_PLATFORM_IFINDEX_KNOWN)
        for (u32 i = 0; i < network->count; ++i)
          if (network->entries[i].linux_ifindex
              == platform.linux_ifindex)
            {
              platform.network_context_id =
                network->entries[i].context;
              platform.availability |= PRODUCT_PLATFORM_CONTEXT_KNOWN;
              break;
            }

      if (nm->fault_mode == PRODUCT_ROOT_NFQUEUE_FAULT_GRAPH_SUBMIT_FAIL_OPEN)
        {
          product_root_nfqueue_accept_extra_messages (
            nm, lane, base, (u32) received, packet.packet_id);
          clib_atomic_fetch_add_relax (&nm->graph_submit_fail_opens, 1);
          product_root_nfqueue_send_counted_verdict (
            nm, lane, packet.packet_id, NF_ACCEPT);
          vlib_buffer_free (vm, &buffer_index, 1);
          continue;
        }
      pending = product_root_nfqueue_reserve (nm, lane, packet.packet_id, buffer_index);
      if (!pending)
        {
          clib_atomic_fetch_add_relax (&nm->graph_submit_fail_opens, 1);
          product_root_nfqueue_send_counted_verdict (nm, lane, packet.packet_id, NF_ACCEPT);
          vlib_buffer_free (vm, &buffer_index, 1);
          continue;
        }
      obligation_id = pending->completion.obligation.token;
      if (lane->packets_seen <= product_packet_graph_trace_limit () / PRODUCT_ROOT_NFQUEUE_MAX_LANES)
        {
        fprintf (stderr, "s232 event=packet_snapshot generation=%llu token=%llu revision=%llu event_elapsed_ns=%llu ifindex=%u context=%u availability=%u\n",
          (unsigned long long) nm->generation, (unsigned long long) obligation_id,
          (unsigned long long) network->revision,
          (unsigned long long) network->event_elapsed_ns,
          platform.linux_ifindex, platform.network_context_id, platform.availability);
        fprintf (stderr, "s217 event=nfq_facts source=NFQ_CAPTURED thread=%u lane=%u token=%llu generation=%llu packet=%u fault=%u raw_hook=%u raw_uid_present=%u raw_uid=%u raw_indev_present=%u raw_indev=%u raw_outdev_present=%u raw_outdev=%u hook=%u uid_present=%u uid=%u indev_present=%u indev=%u outdev_present=%u outdev=%u normalized_uid=%u normalized_ifindex=%u availability=%u direction=%u context=%u provenance=%u\n",
          vm->thread_index, lane->lane_index, (unsigned long long) obligation_id,
          (unsigned long long) nm->generation, packet.packet_id, nm->facts_fault,
          observed.hook, observed.uid_present, observed.uid,
          observed.indev_present, observed.indev, observed.outdev_present, observed.outdev,
          packet.hook, packet.uid_present, packet.uid, packet.indev_present, packet.indev,
          packet.outdev_present, packet.outdev, platform.uid, platform.linux_ifindex,
          platform.availability, platform.direction, platform.network_context_id,
          platform.provenance);
        fprintf(stderr, "s203 event=capture source=NFQ_CAPTURED thread=%u tls=%u polling_thread=%u lane=%u queue=%u packet=%u buffer=%u obligation=%llu\n",
          vm->thread_index, vlib_get_thread_index(), file->polling_thread_index,
          lane->lane_index, lane->queue_id, packet.packet_id, buffer_index,
          (unsigned long long)obligation_id);
        /* Adapter observation only: preserve absent NFQA attributes as unknown.
         * Neither these fields nor this bounded wire trace classify packets. */
        flockfile (stderr);
        fprintf (stderr, "s217 event=netlink_message source=NFQ_CAPTURED thread=%u token=%llu generation=%llu bytes=%u raw=",
          vm->thread_index, (unsigned long long) obligation_id,
          (unsigned long long) nm->generation, (u32) received);
        for (u32 octet = 0; octet < (u32) received; octet++)
          fprintf (stderr, "%02x", base[octet]);
        fprintf (stderr, "\n");
        fprintf (stderr, "s231 event=nfq_payload source=NFQ_CAPTURED thread=%u lane=%u queue=%u packet=%u buffer=%u token=%llu generation=%llu hook=%u family=%u payload_bytes=%u cap_len_known=%u cap_len=%u skb_info_known=%u skb_info=%u raw=",
          vm->thread_index, lane->lane_index, lane->queue_id, packet.packet_id,
          buffer_index, (unsigned long long) obligation_id,
          (unsigned long long) nm->generation, packet.hook, packet.ip_family,
          packet.payload_length, packet.captured_length_present,
          packet.captured_length, packet.skb_info_present, packet.skb_info);
        for (u32 octet = 0; octet < packet.payload_length; octet++)
          fprintf (stderr, "%02x", packet.payload[octet]);
        fprintf (stderr, "\n");
        funlockfile (stderr);
        }
      submitted = product_packet_graph_submit_external (
        vm, buffer_index, &platform,
        &pending->completion.obligation, &graph_result);
      if (!submitted)
        {
          pending->active = 0;
          lane->pending_count--;
          clib_atomic_fetch_sub_relax (&nm->pending_count, 1);
          product_root_nfqueue_accept_extra_messages (
            nm, lane, base, (u32) received, packet.packet_id);
          clib_atomic_fetch_add_relax (&nm->graph_submit_fail_opens, 1);
          product_root_nfqueue_send_counted_verdict (
            nm, lane, packet.packet_id, NF_ACCEPT);
          vlib_buffer_free (vm, &buffer_index, 1);
        }
      else
        {
          lane->packets_submitted++;
          clib_atomic_fetch_add_relax (&nm->packets_submitted, 1);
          if (lane->packets_submitted <= product_packet_graph_trace_limit () / PRODUCT_ROOT_NFQUEUE_MAX_LANES)
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
  lane->family_lane = lane_index % 2;
  lane->worker_index = lane->family_lane;
  lane->ip_family = lane_index < 2 ? 4 : 6;
  lane->last_uid = UINT32_MAX;
  lane->last_cpu = UINT32_MAX;
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

  if (!product_nfqueue_configure (fd, lane->queue_id, lane->ip_family))
    {
      close (fd);
      lane->fd = -1;
      lane->socket_ready = 0;
      return 0;
    }

  template.read_function = product_root_nfqueue_read_ready;
  template.polling_thread_index = vlib_get_worker_thread_index (lane->worker_index);
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
  if (nm->lane_count != PRODUCT_ROOT_NFQUEUE_MAX_LANES
      || nm->queue_id > UINT16_MAX - (nm->lane_count - 1)
      || vlib_num_workers () != 2)
    return 0;
  nm->queue_last = nm->queue_id + nm->lane_count - 1;
  if (!product_root_nfqueue_uid_from_env (&nm->uid_owner))
    {
      clib_warning ("root nfqueue start failed: missing app uid owner");
      return 0;
    }
  nm->generation = generation;
  product_network_snapshot_start (generation);
  nm->last_lane = 0;
  nm->facts_fault = 0;
  nm->pending_count = 0;
  nm->replay_count = 0;
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
  nm->duplicate_completion_drops = 0;
  nm->stale_completion_drops = 0;
  nm->ready_lane_mask = 0;
  nm->hook_ready = 0;
  nm->available = 0;

  for (index = 0; index < PRODUCT_ROOT_NFQUEUE_MAX_LANES; index++)
    {
      product_root_nfqueue_reset_lane (&nm->lanes[index], index, nm->queue_id + index);
      nm->lanes[index].generation = generation;
    }

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
  product_network_snapshot_stop ();
}

int
product_root_nfqueue_adapter_available (void)
{
  const product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  /* A diagnostic lane closure degrades the ready mask without stopping the
   * independent listeners. The full Q2/W2 mask remains explicit in status. */
  return nm->available && nm->lane_count >= 1
         && nm->ready_lane_mask != 0 && nm->hook_ready;
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
  return product_root_nfqueue_main.lanes[product_root_nfqueue_main.last_lane].last_ip_family;
}

uint32_t
product_root_nfqueue_adapter_last_protocol (void)
{
  return product_root_nfqueue_main.lanes[product_root_nfqueue_main.last_lane].last_protocol;
}

uint32_t
product_root_nfqueue_adapter_last_hook (void)
{
  return product_root_nfqueue_main.lanes[product_root_nfqueue_main.last_lane].last_hook;
}

uint32_t
product_root_nfqueue_adapter_last_uid_known (void)
{
  return product_root_nfqueue_main.lanes[product_root_nfqueue_main.last_lane].last_uid_known;
}

uint32_t
product_root_nfqueue_adapter_last_uid (void)
{
  return product_root_nfqueue_main.lanes[product_root_nfqueue_main.last_lane].last_uid;
}

uint32_t
product_root_nfqueue_adapter_last_queue_id (void)
{
  return product_root_nfqueue_main.lanes[product_root_nfqueue_main.last_lane].last_queue_id;
}

uint32_t
product_root_nfqueue_adapter_last_packet_id (void)
{
  return product_root_nfqueue_main.lanes[product_root_nfqueue_main.last_lane].last_packet_id;
}

#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
static clib_error_t *
product_root_facts_fault_cli (vlib_main_t *vm, unformat_input_t *input,
                             vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  u32 mode;
  (void) command;
  if (!unformat (input, "%u", &mode) || mode > 6
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || !nm->available || nm->pending_count
      || product_packet_graph_buffer_debt ())
    return clib_error_return (0, "expected mode 0..6 on an active empty graph");
  nm->facts_fault = mode;
  vlib_cli_output (vm, "root.facts_fault=%u generation=%llu", mode,
                    (unsigned long long) nm->generation);
  return 0;
}
VLIB_CLI_COMMAND (product_root_facts_fault_command, static) = {
  .path = "product root facts-fault",
  .short_help = "product root facts-fault <0 off|1 missing-uid|2 uid-zero|3 missing-ifindex|4 zero-ifindex|5 opposite-ifindex|6 unknown-hook>",
  .function = product_root_facts_fault_cli,
};

/* Default CLI execution holds the VPP worker barrier. First request quiesces
 * ingress; the same lane keeps its fd until every admitted identity returns.
 * A busy response requires retry after workers resume, never a wait under the
 * barrier. Other lanes continue receiving throughout this bounded drain. */
static clib_error_t *
product_root_lane_close_cli (vlib_main_t *vm, unformat_input_t *input,
                             vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  u32 index;
  (void) command;
  if (!unformat (input, "%u", &index) || index >= nm->lane_count
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "expected configured global lane index");
  product_root_nfqueue_lane_t *lane = &nm->lanes[index];
  lane->draining = 1;
  if (lane->pending_count)
    {
      vlib_cli_output (vm, "root.lane_close lane=%u state=draining pending=%u",
                       index, lane->pending_count);
      return 0;
    }
  if (lane->listener_ready && lane->clib_file_index != ~0)
    clib_file_del_by_index (&file_main, lane->clib_file_index);
  else if (lane->socket_ready && lane->fd >= 0)
    close (lane->fd);
  lane->clib_file_index = ~0;
  lane->fd = -1;
  lane->listener_ready = lane->socket_ready = 0;
  nm->ready_lane_mask &= ~(1U << index);
  vlib_cli_output (vm, "root.lane_close lane=%u state=closed pending=0", index);
  return 0;
}
VLIB_CLI_COMMAND (product_root_lane_close_command, static) = {
  .path = "product root lane close", .function = product_root_lane_close_cli,
  .short_help = "product root lane close <global lane index>; retry if draining",
};

/* A nonblocking stop under the normal CLI worker barrier. Quiesce first;
 * retained obligations keep their origin descriptors until a later retry. */
static clib_error_t *
product_root_stop_cli (vlib_main_t *vm, unformat_input_t *input,
                       vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  (void) input; (void) command;
  for (u32 i = 0; i < nm->lane_count; i++) nm->lanes[i].draining = 1;
  product_packet_graph_quiesce_reassembly (vm);
  if (nm->pending_count || product_packet_graph_buffer_debt ()
      || product_packet_graph_obligation_debt () || product_packet_graph_handoff_debt ()
      || product_packet_graph_completion_frame_debt ())
    {
      vlib_cli_output (vm, "root.stop=draining pending=%u", nm->pending_count);
      return 0;
    }
  product_root_nfqueue_adapter_stop (vm);
  vlib_cli_output (vm, "root.stop=ok queues=0 buffers=0 obligations=0");
  return 0;
}
VLIB_CLI_COMMAND (product_root_stop_command, static) = {
  .path = "product root stop", .function = product_root_stop_cli,
  .short_help = "product root stop; retry if draining",
};

static clib_error_t *
product_root_lanes_cli (vlib_main_t *vm, unformat_input_t *input,
                        vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  (void) input; (void) command;
  for (u32 index = 0; index < nm->lane_count; index++)
    {
      product_root_nfqueue_lane_t *lane = &nm->lanes[index];
      vlib_cli_output (vm, "root.lane lane=%u family=%u family_lane=%u worker=%u thread=%u callback_thread=%u callback_tls=%u cpu=%u queue=%u fd=%d generation=%llu ready=%u draining=%u pending=%u captured=%llu submitted=%llu verdicts=%llu succeeded=%llu failed=%llu local=%llu remote=%llu returns=%llu duplicate=%llu",
        index, lane->ip_family, lane->family_lane, lane->worker_index,
        vlib_get_worker_thread_index (lane->worker_index), lane->callback_thread,
        lane->callback_tls, lane->last_cpu, lane->queue_id, lane->fd,
        (unsigned long long) lane->generation, lane->listener_ready, lane->draining,
        lane->pending_count, (unsigned long long) lane->packets_seen,
        (unsigned long long) lane->packets_submitted,
        (unsigned long long) lane->verdict_attempts,
        (unsigned long long) lane->verdict_succeeded,
        (unsigned long long) lane->verdict_failed,
        (unsigned long long) lane->origin_local_completions,
        (unsigned long long) lane->origin_remote_completions,
        (unsigned long long) lane->buffer_returns,
        (unsigned long long) lane->duplicate_completion_drops);
    }
  return 0;
}
VLIB_CLI_COMMAND (product_root_lanes_command, static) = {
  .path = "show product root lanes", .function = product_root_lanes_cli,
};

static clib_error_t *
product_completion_replay_cli (vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  u32 packet_id = 0;
  u8 *mode = 0;
  (void) command;
  if (!unformat (input, "%u %s", &packet_id, &mode) || !packet_id
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || !nm->available || nm->replay_count >= 8)
    { vec_free (mode); return clib_error_return (0, "completion replay rejected"); }
  int stale = strcmp ((char *) mode, "stale") == 0;
  if (!stale && strcmp ((char *) mode, "duplicate") != 0)
    { vec_free (mode); return clib_error_return (0, "expected duplicate or stale"); }
  product_root_nfqueue_pending_t *pending =
    &nm->lanes[0].pending[packet_id % PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY];
  if (pending->active || pending->completion.obligation.packet_id != packet_id
      || !pending->completion.obligation.token
      || pending->completion.terminal_intent == PRODUCT_PACKET_INTENT_NONE)
    { vec_free (mode); return clib_error_return (0, "completed identity unavailable"); }
  product_packet_completion_frame_t completion = pending->completion;
  completion.flags |= PRODUCT_COMPLETION_REPLAY_PROBE | PRODUCT_COMPLETION_TRACE;
  if (stale)
    completion.obligation.queue_generation ^= UINT64_C (0x100000000);
  if (!product_packet_graph_replay_completion (vm, &completion))
    { vec_free (mode); return clib_error_return (0, "completion replay enqueue rejected"); }
  clib_atomic_fetch_add_relax (&nm->replay_count, 1);
  vlib_cli_output (vm, "completion.replay=accepted source=COMPLETION_REPLAY mode=%s token=%llu packet=%u generation=%llu original_generation=%llu",
    mode, (unsigned long long) completion.obligation.token, packet_id,
    (unsigned long long) completion.obligation.queue_generation,
    (unsigned long long) nm->generation);
  vec_free (mode);
  return 0;
}
VLIB_CLI_COMMAND (product_completion_replay_command, static) = {
  .path = "product completion replay",
  .short_help = "product completion replay <completed packet ID> duplicate|stale",
  .function = product_completion_replay_cli,
};

static clib_error_t *
product_completion_status_cli (vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  (void) input; (void) command;
  vlib_cli_output (vm, "completion.status generation=%llu pending=%u frames=%llu buffers=%llu obligations=%llu verdicts=%llu duplicate=%llu stale=%llu local=%llu remote=%llu frame_bytes=%u capacity=%u",
    (unsigned long long) nm->generation, clib_atomic_load_acq_n (&nm->pending_count),
    (unsigned long long) product_packet_graph_completion_frame_debt (),
    (unsigned long long) product_packet_graph_buffer_debt (),
    (unsigned long long) product_packet_graph_obligation_debt (),
    (unsigned long long) nm->verdict_attempts,
    (unsigned long long) nm->duplicate_completion_drops,
    (unsigned long long) nm->stale_completion_drops,
    (unsigned long long) nm->origin_local_completions,
    (unsigned long long) nm->origin_remote_completions,
    (u32) sizeof (product_packet_completion_frame_t), PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY);
  return 0;
}
VLIB_CLI_COMMAND (product_completion_status_command, static) = {
  .path = "show product completion", .function = product_completion_status_cli,
};
#endif

static clib_error_t *
product_root_nfqueue_exit (vlib_main_t *vm)
{
  product_root_nfqueue_adapter_stop (vm);
  return 0;
}

VLIB_MAIN_LOOP_EXIT_FUNCTION (product_root_nfqueue_exit);
