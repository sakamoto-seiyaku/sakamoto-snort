/* SPDX-License-Identifier: Apache-2.0 */
/* Controlled syscall/parser tests, NOT real platform-category evidence. */
#include <assert.h>
#include <stdarg.h>
#include <sys/ioctl.h>
static int test_ioctl (int, unsigned long, ...);
#define ioctl test_ioctl
#include "../../src/product/vpp/product_linux_network.c"
#undef ioctl

static int wireless_ok, link_ok, current_ifindex = 7, change_index;
static unsigned port = PORT_OTHER;
static uint32_t supported;
static unsigned identity_calls, driver_calls, emitted;
static sakamoto_product_network_snapshot_t last;
static char last_reason[80];

static int test_ioctl (int fd, unsigned long command, ...)
{
  (void) fd;
  va_list arguments;
  va_start (arguments, command);
  void *argument = va_arg (arguments, void *);
  va_end (arguments);
  if (command == SIOCGIFINDEX) {
    struct ifreq *request = argument;
    request->ifr_ifindex = current_ifindex + (change_index && identity_calls++);
    return 0;
  }
  driver_calls++;
  if (command == SIOCGIWNAME) {
    if (!wireless_ok) return -1;
    struct iwreq *request = argument;
    strcpy (request->u.name, wireless_ok == 1 ? "IEEE 802.11" : "Other wireless");
    return 0;
  }
  assert (command == SIOCETHTOOL);
  if (!link_ok) return -1;
  struct ifreq *request = argument;
  struct ethtool_link_settings *settings = (void *) request->ifr_data;
  if (!settings->link_mode_masks_nwords) settings->link_mode_masks_nwords = -3;
  else {
    settings->port = port;
    settings->link_mode_masks[0] = supported;
  }
  return 0;
}

static void published (void *opaque, const sakamoto_product_network_snapshot_t *value,
                       const char *reason)
{
  (void) opaque;
  assert (value->revision > last.revision);
  assert (value->event_elapsed_ns);
  last = *value;
  snprintf (last_reason, sizeof (last_reason), "%s", reason);
  ++emitted;
}

static product_linux_network_t state (void)
{
  product_linux_network_t value = { .query_fd = 42, .publish = published,
                                  .sequence = 31, .dumping = 1 };
  memset (&last, 0, sizeof (last));
  emitted = 0;
  return value;
}

static unsigned add_attribute (unsigned char *bytes, unsigned type,
                               const void *value, unsigned size)
{
  struct rtattr *attribute = (void *) bytes;
  attribute->rta_len = RTA_LENGTH (size);
  attribute->rta_type = type;
  memcpy (RTA_DATA (attribute), value, size);
  return RTA_ALIGN (attribute->rta_len);
}

static void link_message (unsigned char *bytes, unsigned ifindex, const char *kind)
{
  memset (bytes, 0, 256);
  struct nlmsghdr *header = (void *) bytes;
  struct ifinfomsg *link = NLMSG_DATA (header);
  header->nlmsg_len = NLMSG_LENGTH (sizeof (*link));
  header->nlmsg_type = RTM_NEWLINK;
  header->nlmsg_seq = 31;
  link->ifi_index = ifindex;
  link->ifi_flags = IFF_UP | IFF_RUNNING;
  link->ifi_type = ARPHRD_ETHER;
  header->nlmsg_len += add_attribute (bytes + header->nlmsg_len, IFLA_IFNAME, "test0", 6);
  unsigned char nested[64] = {0};
  unsigned size = add_attribute (nested, IFLA_INFO_KIND, kind, strlen (kind) + 1);
  header->nlmsg_len += add_attribute (bytes + header->nlmsg_len, IFLA_LINKINFO, nested, size);
}

int main (void)
{
  const char name[IFNAMSIZ] = "eth-looking";
  unsigned flags = IFF_UP | IFF_RUNNING;
  assert (classify (-1, name, "wireguard", flags, ARPHRD_NONE, 7) == 4);
  assert (classify (-1, name, "wwan", flags, ARPHRD_RAWIP, 7) == 2);
  for (unsigned i = 0; i < 5; ++i) {
    const char *kind[] = {"tun", "veth", "bridge", "dummy", "ipip"};
    assert (!classify (42, name, kind[i], flags, ARPHRD_ETHER, 7));
  }
  assert (!driver_calls);
  assert (!classify (42, name, "wireguard", IFF_UP, ARPHRD_NONE, 7));
  assert (!classify (42, name, "wireguard", flags | IFF_LOOPBACK, ARPHRD_NONE, 7));
  assert (!classify (42, name, "", flags, ARPHRD_ETHER, 7));
  wireless_ok = 1;
  assert (classify (42, name, "", flags, ARPHRD_ETHER, 7) == 1);
  wireless_ok = 0; link_ok = 1; port = PORT_TP;
  assert (!classify (42, name, "", flags, ARPHRD_ETHER, 7));
  supported = 1U << ETHTOOL_LINK_MODE_TP_BIT;
  assert (classify (42, name, "", flags, ARPHRD_ETHER, 7) == 8);
  wireless_ok = 2;
  assert (!classify (42, name, "", flags, ARPHRD_ETHER, 7));
  wireless_ok = 0; port = PORT_OTHER;
  assert (!classify (42, name, "", flags, ARPHRD_ETHER, 7));
  port = PORT_FIBRE;
  assert (!classify (42, name, "", flags, ARPHRD_ETHER, 7));
  supported = 1U << ETHTOOL_LINK_MODE_FIBRE_BIT;
  assert (classify (42, name, "", flags, ARPHRD_ETHER, 7) == 8);
  change_index = 1;
  assert (!classify (42, name, "", flags, ARPHRD_ETHER, 7));
  change_index = 0; current_ifindex = 8;
  assert (!classify (42, name, "", flags, ARPHRD_ETHER, 7));

  union { struct nlmsghdr alignment; unsigned char bytes[256]; } packet;
  struct nlmsghdr *header = (void *) packet.bytes;
  product_linux_network_t value = state ();
  for (unsigned i = 1; i <= 33; ++i) {
    link_message (packet.bytes, i, "wireguard");
    consume (&value, packet.bytes, header->nlmsg_len, 0);
  }
  assert (value.candidate.count == 32 && value.overflow && !value.invalid);
  link_message (packet.bytes, 1, "wireguard");
  consume (&value, packet.bytes, header->nlmsg_len, 0);
  assert (value.invalid && emitted == 1 && last.count == 0);
  assert (!strcmp (last_reason, "malformed_link"));

  value = state ();
  link_message (packet.bytes, 7, "wireguard");
  header->nlmsg_seq = 30;
  consume (&value, packet.bytes, header->nlmsg_len, 0);
  assert (!value.candidate.count && !value.invalid); /* stale dump */
  header->nlmsg_seq = 31;
  consume (&value, packet.bytes, header->nlmsg_len, 0);
  assert (value.candidate.count == 1);
  header->nlmsg_type = RTM_DELLINK; header->nlmsg_seq = 0;
  consume (&value, packet.bytes, header->nlmsg_len, 1);
  assert (value.invalid && value.events == 1 && last.count == 0);
  link_message (packet.bytes, 7, "wireguard");
  consume (&value, packet.bytes, header->nlmsg_len, 0);
  assert (value.candidate.count == 1 && value.invalid); /* cannot revive deleted ifindex */

  for (unsigned event = RTM_NEWADDR; event <= RTM_DELADDR; ++event) {
    value = state ();
    memset (packet.bytes, 0, sizeof (packet.bytes));
    header->nlmsg_len = sizeof (*header); header->nlmsg_type = event;
    /* Real IPv4 address events retain the ip command's sequence and pid. */
    header->nlmsg_seq = 1789269045; header->nlmsg_pid = 1198217;
    consume (&value, packet.bytes, header->nlmsg_len, 1);
    assert (value.invalid && value.events == 1 && last.count == 0);
  }
  value = state ();
  header->nlmsg_type = NLMSG_DONE; header->nlmsg_seq = 31;
  header->nlmsg_flags = NLM_F_DUMP_INTR;
  consume (&value, packet.bytes, header->nlmsg_len, 0);
  assert (value.invalid && !value.completed && !value.dumping && last.count == 0);
  value = state ();
  header->nlmsg_flags = 0;
  consume (&value, packet.bytes, header->nlmsg_len, 0);
  assert (!value.invalid && value.completed && !value.dumping && !emitted);
  header->nlmsg_seq = 0; header->nlmsg_type = RTM_NEWLINK;
  consume (&value, packet.bytes, header->nlmsg_len, 1);
  assert (value.invalid && !value.completed); /* event following DONE */

  value = state ();
  link_message (packet.bytes, 7, "wireguard");
  header->nlmsg_len -= 1;
  consume (&value, packet.bytes, header->nlmsg_len, 0);
  assert (value.invalid && !value.candidate.count);
  value = state ();
  link_message (packet.bytes, 7, "wireguard");
  struct rtattr *attribute = IFLA_RTA ((struct ifinfomsg *) NLMSG_DATA (header));
  ((char *) RTA_DATA (attribute))[5] = 'X';
  consume (&value, packet.bytes, header->nlmsg_len, 0);
  assert (value.invalid && !value.candidate.count);
  puts ("PASS: controlled Linux classifier/parser: four classes, missing metadata, virtual non-inference, disconnect, reuse, loss, address events, overflow, malformed/stale dumps");
  return 0;
}
