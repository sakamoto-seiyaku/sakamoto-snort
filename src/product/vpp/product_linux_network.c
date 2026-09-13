/* SPDX-License-Identifier: Apache-2.0 */
#include "product_linux_network.h"
#include <errno.h>
#include <limits.h>
#include <linux/ethtool.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/wireless.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

enum { NETWORK_DATAGRAM_BYTES = 32768, NETWORK_READ_BUDGET = 64,
       NETWORK_LINK_MODE_WORDS = 127 };

/* A driver must report both a physical connector and its supported medium.
 * ARPHRD_ETHER, a zero/default port, speed, and an interface name are NOT
 * evidence of Wired. In particular virtual links never reach this probe. */
static int
wired_medium (unsigned port, uint32_t supported)
{
  unsigned bit;
  switch (port)
    {
    case PORT_TP: bit = ETHTOOL_LINK_MODE_TP_BIT; break;
    case PORT_AUI: bit = ETHTOOL_LINK_MODE_AUI_BIT; break;
    case PORT_MII: bit = ETHTOOL_LINK_MODE_MII_BIT; break;
    case PORT_FIBRE: bit = ETHTOOL_LINK_MODE_FIBRE_BIT; break;
    case PORT_BNC: bit = ETHTOOL_LINK_MODE_BNC_BIT; break;
    default: return 0;
    }
  return !!(supported & (1U << bit));
}

static uint32_t
classify (int fd, const char *name, const char *kind, unsigned flags,
          unsigned hardware_type, int ifindex)
{
  if (!(flags & IFF_UP) || !(flags & IFF_RUNNING) || (flags & IFF_LOOPBACK))
    return 0;
  if (!strcmp (kind, "wireguard")) return SAKAMOTO_PRODUCT_NETWORK_VPN;
  if (!strcmp (kind, "wwan")) return SAKAMOTO_PRODUCT_NETWORK_MOBILE;
  if (*kind || hardware_type != ARPHRD_ETHER || fd < 0) return 0;

  struct ifreq identity = {0};
  memcpy (identity.ifr_name, name, IFNAMSIZ);
  if (ioctl (fd, SIOCGIFINDEX, &identity) || identity.ifr_ifindex != ifindex)
    return 0;
  struct iwreq wireless = {0};
  memcpy (wireless.ifr_name, name, IFNAMSIZ);
  uint32_t context = 0;
  if (!ioctl (fd, SIOCGIWNAME, &wireless))
    {
      if (!strncmp (wireless.u.name, "IEEE 802.11", 11))
        context = SAKAMOTO_PRODUCT_NETWORK_WIFI;
      /* Other wireless protocols must not fall through to Wired. */
    }
  else
    {
      /* Fixed maximum (signed s8 ABI), no allocation and no legacy guessing. */
      struct {
        struct ethtool_link_settings settings;
        uint32_t masks[3 * NETWORK_LINK_MODE_WORDS];
      } link = {0};
      struct ifreq request = {0};
      memcpy (request.ifr_name, name, IFNAMSIZ);
      request.ifr_data = (void *) &link;
      link.settings.cmd = ETHTOOL_GLINKSETTINGS;
      link.settings.port = PORT_OTHER;
      if (!ioctl (fd, SIOCETHTOOL, &request)
          && link.settings.link_mode_masks_nwords < 0)
        {
          int words = -link.settings.link_mode_masks_nwords;
          if (words <= NETWORK_LINK_MODE_WORDS)
            {
              link.settings.link_mode_masks_nwords = words;
              link.settings.port = PORT_OTHER;
              if (!ioctl (fd, SIOCETHTOOL, &request)
                  && link.settings.link_mode_masks_nwords == words
                  && wired_medium (link.settings.port, link.masks[0]))
                context = SAKAMOTO_PRODUCT_NETWORK_WIRED;
            }
        }
    }
  /* Rename/delete while a driver query was running invalidates that result.
   * RTNL notifications also invalidate the entire in-flight dump below. */
  if (ioctl (fd, SIOCGIFINDEX, &identity) || identity.ifr_ifindex != ifindex)
    return 0;
  return context;
}

static uint64_t
monotonic_ns (void)
{
  struct timespec now;
  if (clock_gettime (CLOCK_MONOTONIC, &now)) return 0;
  return (uint64_t) now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static void
emit (product_linux_network_t *state,
      const sakamoto_product_network_snapshot_t *value, const char *reason)
{
  sakamoto_product_network_snapshot_t snapshot = {0};
  if (value) snapshot = *value;
  snapshot.revision = ++state->revision;
  snapshot.event_elapsed_ns = monotonic_ns ();
  state->publications++;
  state->publish (state->opaque, &snapshot, reason);
}

static void
timer (product_linux_network_t *state, unsigned seconds)
{
  struct itimerspec value = {0};
  value.it_value.tv_sec = seconds;
  if (timerfd_settime (state->timer_fd, 0, &value, NULL))
    {
      state->invalid = 1;
      emit (state, NULL, "timer_unavailable");
    }
}

static void
invalidate (product_linux_network_t *state, const char *reason)
{
  if (!state->invalid) emit (state, NULL, reason);
  state->invalid = 1;
  state->completed = 0;
}

static void
request_dump (product_linux_network_t *state)
{
  struct {
    struct nlmsghdr header;
    struct ifinfomsg link;
  } request = {0};
  struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
  if (++state->sequence == 0) ++state->sequence;
  request.header.nlmsg_len = sizeof (request);
  request.header.nlmsg_type = RTM_GETLINK;
  request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  request.header.nlmsg_seq = state->sequence;
  request.link.ifi_family = AF_UNSPEC;
  memset (&state->candidate, 0, sizeof (state->candidate));
  state->completed = state->overflow = 0;
  ssize_t sent = sendto (state->route_fd, &request, sizeof (request),
                        MSG_DONTWAIT, (void *) &kernel, sizeof (kernel));
  state->dumping = sent == sizeof (request);
  state->invalid = !state->dumping;
  state->resyncs++;
  /* One-shot watchdog/retry, never an idle polling timer. */
  timer (state, 1);
}

static int
attribute_string (const struct rtattr *attribute, char *target, size_t capacity)
{
  size_t length = RTA_PAYLOAD (attribute);
  if (!length || length > capacity
      || ((const char *) RTA_DATA (attribute))[length - 1] != 0
      || strnlen (RTA_DATA (attribute), length) != length - 1)
    return 0;
  memcpy (target, RTA_DATA (attribute), length);
  return 1;
}

static int
link_record (product_linux_network_t *state, const struct nlmsghdr *header)
{
  if (header->nlmsg_len < NLMSG_LENGTH (sizeof (struct ifinfomsg))) return 0;
  const struct ifinfomsg *link = NLMSG_DATA (header);
  char name[IFNAMSIZ] = {0}, kind[32] = {0};
  int remaining = IFLA_PAYLOAD (header);
  for (struct rtattr *attribute = IFLA_RTA (link);
       RTA_OK (attribute, remaining); attribute = RTA_NEXT (attribute, remaining))
    {
      unsigned type = attribute->rta_type & NLA_TYPE_MASK;
      if (type == IFLA_IFNAME && !attribute_string (attribute, name, sizeof (name)))
        return 0;
      if (type == IFLA_LINKINFO)
        {
          int nested = RTA_PAYLOAD (attribute);
          for (struct rtattr *info = RTA_DATA (attribute); RTA_OK (info, nested);
               info = RTA_NEXT (info, nested))
            if ((info->rta_type & NLA_TYPE_MASK) == IFLA_INFO_KIND
                && !attribute_string (info, kind, sizeof (kind))) return 0;
          if (nested) return 0;
        }
    }
  if (remaining || !*name || link->ifi_index <= 0) return 0;
  uint32_t context = classify (state->query_fd, name, kind, link->ifi_flags,
                               link->ifi_type, link->ifi_index);
  if (!context) return 1;
  for (uint32_t i = 0; i < state->candidate.count; ++i)
    if (state->candidate.entries[i].linux_ifindex == (uint32_t) link->ifi_index)
      return 0; /* duplicate/reuse in an inconsistent dump */
  if (state->candidate.count == SAKAMOTO_PRODUCT_NETWORK_MAX_INTERFACES)
    {
      state->overflow = 1;
      return 1;
    }
  state->candidate.entries[state->candidate.count++] =
    (sakamoto_product_network_entry_t) {link->ifi_index, context};
  return 1;
}

static void
consume (product_linux_network_t *state, void *bytes, int length, int multicast)
{
  for (struct nlmsghdr *header = bytes; NLMSG_OK (header, length);
       header = NLMSG_NEXT (header, length))
    {
      if (header->nlmsg_type == NLMSG_OVERRUN)
        { invalidate (state, "overrun"); continue; }
      /* Address notifications can retain the requesting process's sequence
       * and nlmsg_pid. The kernel sockaddr/group, NOT a zero header sequence,
       * distinguishes multicast events from replies to our dump. */
      if (multicast)
        {
          if (header->nlmsg_type == RTM_NEWLINK || header->nlmsg_type == RTM_DELLINK
              || header->nlmsg_type == RTM_NEWADDR || header->nlmsg_type == RTM_DELADDR)
            {
              state->events++;
              invalidate (state, "link_or_address_event");
            }
          continue;
        }
      if (header->nlmsg_seq != state->sequence || !state->dumping) continue;
      if (header->nlmsg_flags & NLM_F_DUMP_INTR) invalidate (state, "dump_interrupted");
      if (header->nlmsg_type == NLMSG_DONE)
        {
          int error = 0;
          if (header->nlmsg_len >= NLMSG_LENGTH (sizeof (error)))
            memcpy (&error, NLMSG_DATA (header), sizeof (error));
          if (error) invalidate (state, "dump_error");
          state->dumping = 0;
          state->completed = !state->invalid;
        }
      else if (header->nlmsg_type == NLMSG_ERROR)
        {
          invalidate (state, "netlink_error");
          state->dumping = 0;
        }
      else if (header->nlmsg_type == RTM_NEWLINK && !state->invalid
               && !link_record (state, header)) invalidate (state, "malformed_link");
    }
  if (length) invalidate (state, "malformed_datagram");
}

void
product_linux_network_read (product_linux_network_t *state)
{
  union { struct nlmsghdr align; unsigned char bytes[NETWORK_DATAGRAM_BYTES]; } data;
  if (state->route_fd < 0) return;
  for (unsigned batch = 0; batch < NETWORK_READ_BUDGET; ++batch)
    {
      struct sockaddr_nl sender = {0};
      struct iovec vector = {data.bytes, sizeof (data.bytes)};
      struct msghdr message = { .msg_name = &sender, .msg_namelen = sizeof (sender),
                               .msg_iov = &vector, .msg_iovlen = 1 };
      ssize_t length = recvmsg (state->route_fd, &message, MSG_DONTWAIT);
      if (length < 0)
        {
          if (errno == EINTR) continue;
          if (errno != EAGAIN && errno != EWOULDBLOCK)
            { invalidate (state, "receive_loss"); timer (state, 1); return; }
          /* Only publish after draining all currently queued notifications. */
          if (state->completed && !state->invalid)
            {
              emit (state, state->overflow ? NULL : &state->candidate,
                    state->overflow ? "map_overflow_unknown" : "kernel_dump");
              state->completed = 0;
              timer (state, 0);
            }
          else if (state->invalid && !state->dumping) request_dump (state);
          return;
        }
      if (message.msg_namelen != sizeof (sender) || sender.nl_pid != 0) continue;
      if (!length || message.msg_flags & (MSG_TRUNC | MSG_CTRUNC))
        { invalidate (state, "truncated_datagram"); timer (state, 1); continue; }
      consume (state, data.bytes, (int) length, sender.nl_groups != 0);
    }
  /* LT readiness schedules another bounded read. Do not publish a partial dump. */
}

void
product_linux_network_retry (product_linux_network_t *state)
{
  uint64_t expirations;
  if (read (state->timer_fd, &expirations, sizeof (expirations)) != sizeof (expirations))
    return;
  invalidate (state, "dump_timeout_or_retry");
  state->dumping = 0;
  request_dump (state);
}

void
product_linux_network_close (product_linux_network_t *state)
{
  if (state->route_fd >= 0) close (state->route_fd);
  if (state->query_fd >= 0) close (state->query_fd);
  if (state->timer_fd >= 0) close (state->timer_fd);
  memset (state, 0, sizeof (*state));
  state->route_fd = state->query_fd = state->timer_fd = -1;
}

int
product_linux_network_open (product_linux_network_t *state,
                           product_linux_network_publish_fn publish, void *opaque)
{
  memset (state, 0, sizeof (*state));
  state->route_fd = state->query_fd = state->timer_fd = -1;
  state->publish = publish;
  state->opaque = opaque;
  state->route_fd = socket (AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
                            NETLINK_ROUTE);
  struct sockaddr_nl address = {
    .nl_family = AF_NETLINK,
    .nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR,
  };
  if (state->route_fd < 0 || bind (state->route_fd, (void *) &address, sizeof (address)))
    goto failed;
  state->query_fd = socket (AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  /* Query failure still permits trustworthy rtnl kinds; hardware stays Unknown. */
  state->timer_fd = timerfd_create (CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
  if (state->timer_fd < 0) goto failed;
  emit (state, NULL, "start_unknown");
  request_dump (state);
  return 1;
failed:
  emit (state, NULL, "subscription_unavailable");
  product_linux_network_close (state);
  return 0;
}
