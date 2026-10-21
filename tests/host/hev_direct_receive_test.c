/* SPDX-License-Identifier: MIT */
#include "hev-lwip-context.h"
#include "hev-socks5-session-udp.h"
#include <hev-task-mutex.h>
#include <hev-task-system.h>
#include <lwip/init.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Real session constructor/queue/destructor, UDP socket and lwIP output.
 * Socket setup and PCB admission are fixture-controlled: this does not prove
 * broker authorization, owner admission, or Product integration. */
static unsigned allocations, outputs;
static int fail_alloc;
static err_t output_error;
void *hev_lwip_malloc(size_t size)
{
  if (fail_alloc) { fail_alloc = 0; return NULL; }
  void *p = malloc(size); if (p) ++allocations; return p;
}
void *hev_lwip_calloc(size_t count, size_t size)
{
  if (fail_alloc) { fail_alloc = 0; return NULL; }
  void *p = calloc(count, size); if (p) ++allocations; return p;
}
void hev_lwip_free(void *p)
{ if (p) { assert(allocations); --allocations; free(p); } }
unsigned int lwip_port_rand(void) { return 1234; }

static err_t output(struct netif *netif, struct pbuf *p, const ip4_addr_t *dest)
{
  unsigned char bytes[32];
  (void)netif;
  assert(ip4_addr4(dest) == 2);
  assert(p->tot_len == 28 || p->tot_len == 31);
  assert(pbuf_copy_partial(p, bytes, p->tot_len, 0) == p->tot_len);
  assert(bytes[9] == 17 && bytes[15] == 1 && bytes[19] == 2);
  assert(bytes[20] == 0x23 && bytes[21] == 0x28); /* origin port 9000 */
  assert(bytes[22] == 0x30 && bytes[23] == 0x39); /* application port */
  if (p->tot_len == 31) assert(!memcmp(bytes + 28, "abc", 3));
  ++outputs;
  return output_error;
}
static err_t interface_init(struct netif *netif)
{
  netif->name[0] = 'h'; netif->name[1] = 'v'; netif->mtu = 1500;
  netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP | NETIF_FLAG_PRETEND;
  netif->output = output;
  return ERR_OK;
}

static int receive_ready(HevSocks5SessionUDP *session, void *scratch, int *result)
{
  struct pollfd ready = { .fd = session->base.fd, .events = POLLIN };
  assert(poll(&ready, 1, 1000) == 1 && (ready.revents & POLLIN));
  int status = hev_socks5_session_udp_direct_receive(session, scratch, 4, result);
  if (status != 1)
    fprintf(stderr, "receive status=%d errno=%d fd=%d limit=%u\n",
            status, errno, session->base.fd, session->direct_frame_limit);
  return status;
}

static void run(void *unused)
{
  hev_lwip_context_t context;
  struct netif netif = { 0 };
  HevSocks5SessionUDP *session;
  struct udp_pcb *pcb;
  HevTaskMutex mutex;
  struct sockaddr_in address = { .sin_family = AF_INET };
  socklen_t address_size = sizeof(address);
  ip4_addr_t ip, mask, gateway;
  char scratch[4];
  int sender, result = 123;
  unsigned baseline;
  (void)unused;
  hev_lwip_context_init(&context); hev_lwip_context_bind(&context); lwip_init();
  IP4_ADDR(&ip, 10, 0, 0, 1); IP4_ADDR(&mask, 255, 255, 255, 0);
  IP4_ADDR(&gateway, 0, 0, 0, 0);
  assert(netif_add(&netif, &ip, &mask, &gateway, NULL, interface_init, ip4_input));
  netif_set_default(&netif);
  pcb = udp_new(); assert(pcb);
  IP_ADDR4(&pcb->local_ip, 192, 0, 2, 1);
  IP_ADDR4(&pcb->remote_ip, 10, 0, 0, 2);
  pcb->local_port = 9000; pcb->remote_port = 12345;
  pcb->netif_idx = netif_get_index(&netif);
  assert(!hev_task_mutex_init(&mutex));
  session = hev_socks5_session_udp_direct_new(pcb, &mutex, 1); assert(session);
  assert(!strcmp(HEV_OBJECT(session)->klass->name, "HevSocks5SessionUDP"));
  assert(session->base.fd == -1 && HEV_SOCKS5(session)->fd == -1);
  hev_socks5_session_set_task(HEV_SOCKS5_SESSION(session), hev_task_self());
  session->base.fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
  sender = socket(AF_INET, SOCK_DGRAM, 0);
  assert(session->base.fd >= 0 && sender >= 0);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  assert(!bind(session->base.fd, (struct sockaddr *)&address, sizeof(address)));
  assert(!getsockname(session->base.fd, (struct sockaddr *)&address, &address_size));
  assert(!connect(sender, (struct sockaddr *)&address, sizeof(address)));
  assert(!getsockname(sender, (struct sockaddr *)&address, &address_size));
  assert(!connect(session->base.fd, (struct sockaddr *)&address, sizeof(address)));
  baseline = allocations;
  assert(!hev_socks5_session_udp_direct_receive(session, scratch, 4, &result));
  assert(result == 123);
  const err_t errors[] = { ERR_OK, ERR_MEM, ERR_OK, ERR_IF, ERR_OK };
  for (unsigned i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
    output_error = errors[i];
    assert(send(sender, "abc", 3, 0) == 3);
    assert(receive_ready(session, scratch, &result) == 1);
    assert(result == errors[i] && allocations == baseline);
  }
  assert(outputs == 5);
  assert(send(sender, "abcde", 5, 0) == 5);
  assert(receive_ready(session, scratch, &result) == 1);
  assert(result == ERR_BUF && outputs == 5 && allocations == baseline);
  assert(send(sender, "abc", 3, 0) == 3); fail_alloc = 1;
  assert(receive_ready(session, scratch, &result) == 1);
  assert(result == ERR_MEM && outputs == 5 && allocations == baseline);
  assert(send(sender, "", 0, 0) == 0);
  assert(receive_ready(session, scratch, &result) == 1);
  assert(result == ERR_OK && outputs == 6 && allocations == baseline);
  /* Controlled chain shape: exercise the actual HEV queue callback and send
   * every span, plus reject-at-capacity and drain-on-destruction. */
  struct pbuf *head = pbuf_alloc(PBUF_RAW, 3, PBUF_RAM);
  struct pbuf *tail = pbuf_alloc(PBUF_RAW, 3, PBUF_RAM);
  assert(head && tail);
  assert(pbuf_take(head, "abc", 3) == ERR_OK);
  assert(pbuf_take(tail, "def", 3) == ERR_OK);
  pbuf_cat(head, tail);
  pcb->recv(pcb->recv_arg, pcb, head, &pcb->remote_ip, pcb->remote_port);
  assert(session->frames == 1);
  unsigned full = allocations;
  tail = pbuf_alloc(PBUF_RAW, 1, PBUF_RAM); assert(tail);
  pcb->recv(pcb->recv_arg, pcb, tail, &pcb->remote_ip, pcb->remote_port);
  assert(session->frames == 1 && allocations == full);
  assert(hev_socks5_session_udp_direct_send(session) == 1);
  struct pollfd ready = { .fd = sender, .events = POLLIN };
  assert(poll(&ready, 1, 1000) == 1 && (ready.revents & POLLIN));
  char sent[8]; assert(recv(sender, sent, sizeof(sent), 0) == 6);
  assert(!memcmp(sent, "abcdef", 6));
  assert(!session->frames && allocations == baseline);
  assert(hev_socks5_session_udp_direct_send(session) == 0);
  /* Datagram send backpressure is deterministic on a bounded local socket
   * pair. This proves the existing sendmsg splice's EAGAIN behavior, not an
   * Android or IP-underlay failure claim. Its retained HEV frame is unchanged. */
  int pair[2], old_fd = session->base.fd;
  assert(!socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair));
  session->base.fd = pair[0];
  unsigned filled = 0;
  while (filled < 4096 && send(pair[0], "x", 1, MSG_DONTWAIT) == 1) ++filled;
  assert(filled > 0 && filled < 4096 && (errno == EAGAIN || errno == EWOULDBLOCK));
  head = pbuf_alloc(PBUF_RAW, 3, PBUF_RAM); assert(head);
  assert(pbuf_take(head, "abc", 3) == ERR_OK);
  pcb->recv(pcb->recv_arg, pcb, head, &pcb->remote_ip, pcb->remote_port);
  unsigned retained = allocations;
  assert(session->frames == 1 && hev_socks5_session_udp_direct_send(session) == 0);
  assert(session->frames == 1 && allocations == retained);
  for (unsigned i = 0; i < filled; ++i) assert(recv(pair[1], sent, sizeof(sent), 0) == 1);
  assert(hev_socks5_session_udp_direct_send(session) == 1);
  assert(!session->frames && allocations == baseline);
  assert(recv(pair[1], sent, sizeof(sent), 0) == 3 && !memcmp(sent, "abc", 3));
  close(pair[0]); close(pair[1]); session->base.fd = old_fd;
  puts("real datagram sendmsg EAGAIN retained one frame and recovered");
#ifdef SAKAMOTO_PRODUCT_VPN_UDP_BATCH_EXPERIMENT
  /* A ready burst spans two bounded calls, preserving datagram boundaries,
   * order, chained storage and a zero-length datagram without payload copies. */
  session->direct_frame_limit = 16;
  for (unsigned i = 0; i < 12; ++i) {
    unsigned char value[2] = { (unsigned char)i, (unsigned char)(i + 16) };
    head = pbuf_alloc(PBUF_RAW, i == 3 ? 0 : 1, PBUF_RAM); assert(head);
    if (i != 3) assert(pbuf_take(head, value, 1) == ERR_OK);
    if (i == 4) {
      tail = pbuf_alloc(PBUF_RAW, 1, PBUF_RAM); assert(tail);
      assert(pbuf_take(tail, value + 1, 1) == ERR_OK); pbuf_cat(head, tail);
    }
    pcb->recv(pcb->recv_arg, pcb, head, &pcb->remote_ip, pcb->remote_port);
  }
  assert(session->frames == 12);
  assert(hev_socks5_session_udp_direct_send(session) == 8);
  assert(session->frames == 4);
  assert(hev_socks5_session_udp_direct_send(session) == 4);
  assert(!session->frames && allocations == baseline);
  for (unsigned i = 0; i < 12; ++i) {
    assert(poll(&ready, 1, 1000) == 1 && (ready.revents & POLLIN));
    ssize_t length = recv(sender, sent, sizeof(sent), 0);
    assert(length == (i == 3 ? 0 : i == 4 ? 2 : 1));
    if (length) assert((unsigned char)sent[0] == i);
    if (i == 4) assert((unsigned char)sent[1] == i + 16);
  }
  /* Descriptor budget is shared across the batch. A complete 64-span head
   * sends alone, leaving the following datagram for the next bounded call. */
  head = pbuf_alloc(PBUF_RAW, 1, PBUF_RAM); assert(head);
  for (unsigned i = 1; i < 64; ++i) {
    tail = pbuf_alloc(PBUF_RAW, 1, PBUF_RAM); assert(tail); pbuf_cat(head, tail);
  }
  pcb->recv(pcb->recv_arg, pcb, head, &pcb->remote_ip, pcb->remote_port);
  head = pbuf_alloc(PBUF_RAW, 1, PBUF_RAM); assert(head);
  pcb->recv(pcb->recv_arg, pcb, head, &pcb->remote_ip, pcb->remote_port);
  assert(session->frames == 2 && hev_socks5_session_udp_direct_send(session) == 1);
  assert(session->frames == 1 && session->direct_send_requested == 1);
  assert(hev_socks5_session_udp_direct_send(session) == 1);
  char chained[64];
  assert(recv(sender, chained, sizeof(chained), 0) == 64);
  assert(recv(sender, chained, sizeof(chained), 0) == 1);
  assert(!session->frames && allocations == baseline);
  assert(!socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair));
  session->base.fd = pair[0]; filled = 0;
  while (filled < 4096 && send(pair[0], "x", 1, MSG_DONTWAIT) == 1) ++filled;
  assert(filled > 2 && filled < 4096 && (errno == EAGAIN || errno == EWOULDBLOCK));
  for (unsigned i = 0; i < 8; ++i) {
    unsigned char value = (unsigned char)i;
    head = pbuf_alloc(PBUF_RAW, 1, PBUF_RAM); assert(head);
    assert(pbuf_take(head, &value, 1) == ERR_OK);
    pcb->recv(pcb->recv_arg, pcb, head, &pcb->remote_ip, pcb->remote_port);
  }
  retained = allocations;
  assert(hev_socks5_session_udp_direct_send(session) == 0);
  assert(session->frames == 8 && allocations == retained);
  /* Free precisely two skb slots: the real sendmmsg must consume only that
   * prefix, retaining all six unsent frames. A later turn resumes at packet 2. */
  for (unsigned i = 0; i < 2; ++i) assert(recv(pair[1], sent, sizeof(sent), 0) == 1);
  assert(hev_socks5_session_udp_direct_send(session) == 2);
  assert(session->frames == 6);
  for (unsigned i = 2; i < filled; ++i) assert(recv(pair[1], sent, sizeof(sent), 0) == 1 && sent[0] == 'x');
  for (unsigned i = 0; i < 2; ++i) assert(recv(pair[1], sent, sizeof(sent), 0) == 1 && (unsigned char)sent[0] == i);
  assert(hev_socks5_session_udp_direct_send(session) == 6);
  assert(!session->frames && allocations == baseline);
  for (unsigned i = 2; i < 8; ++i) assert(recv(pair[1], sent, sizeof(sent), 0) == 1 && (unsigned char)sent[0] == i);
  close(pair[0]); close(pair[1]); session->base.fd = old_fd;
  puts("bounded UDP batch, zero/chained datagrams and real positive-prefix backpressure passed");
#endif
  head = pbuf_alloc(PBUF_RAW, 3, PBUF_RAM); assert(head);
  pcb->recv(pcb->recv_arg, pcb, head, &pcb->remote_ip, pcb->remote_port);
  assert(session->frames == 1);
  /* A terminal socket error retains queue ownership for normal destruction;
   * neither the failed operation nor teardown retries the datagram. */
  assert(!socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair));
  session->base.fd = pair[0]; close(pair[1]);
  retained = allocations;
  assert(hev_socks5_session_udp_direct_send(session) == -1);
  assert(session->frames == 1 && allocations == retained);
  close(pair[0]); session->base.fd = old_fd;
  int original_fd = session->base.fd;
  hev_object_unref(HEV_OBJECT(session));
  assert(fcntl(original_fd, F_GETFD) == -1 && errno == EBADF);
  assert(!udp_pcbs);
  close(sender); netif_remove(&netif);
  hev_lwip_context_bind(NULL); assert(!allocations);
}
int main(void)
{
  alarm(5);
  assert(!hev_task_system_init());
  HevTask *task = hev_task_new(32768); assert(task);
  hev_task_run(task, run, NULL); hev_task_system_run(); hev_task_system_fini();
  return 0;
}
