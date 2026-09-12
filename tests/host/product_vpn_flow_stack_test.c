/* SPDX-License-Identifier: Apache-2.0 */
#include "product_vpn_flow_stack_private.h"
#include <arpa/inet.h>
#include <assert.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct { uint64_t session; int fd; unsigned outputs, ipv6; } fixture_t;
static int broker(void *opaque, uint64_t generation, uint64_t session, int fd)
{
  fixture_t *f = opaque;
  assert(generation == 9);
  f->session = session; f->fd = fd;
  return 0;
}
static product_vpn_flow_stack_output_result_t output(void *opaque,
    const product_vpn_flow_stack_span_t *spans, unsigned count, size_t total,
    const product_platform_packet_facts_t *platform,
    uint64_t generation, uint64_t serial, uint64_t epoch)
{
  fixture_t *f = opaque;
  assert(count && spans && total == (f->ipv6 ? 49U : 29U) && generation == 9 && serial && epoch == 13);
  unsigned char returned[49];
  size_t offset = 0;
  for (unsigned i = 0; i < count; ++i) {
    assert(spans[i].length <= total - offset);
    memcpy(returned + offset, spans[i].data, spans[i].length);
    offset += spans[i].length;
  }
  assert(offset == total && returned[total - 1] == 42);
  assert(returned[0] >> 4 == (f->ipv6 ? 6 : 4));
  if (f->ipv6) {
    const unsigned char source[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    const unsigned char destination[16] = {0xfd,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2};
    assert(!memcmp(returned + 8, source, 16));
    assert(!memcmp(returned + 24, destination, 16));
    assert(returned[6] == 17 && returned[4] == 0 && returned[5] == 9);
    assert(returned[46] || returned[47]); /* UDP6 cannot omit its checksum. */
    unsigned sum = 9 + 17;
    for (unsigned i = 8; i < 48; i += 2)
      sum += ((unsigned)returned[i] << 8) | returned[i + 1];
    sum += (unsigned)returned[48] << 8;
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    assert(sum == 65535);
  }
  assert(platform->provenance == PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN);
  assert(platform->direction == PRODUCT_PACKET_DIRECTION_INPUT);
  assert(platform->uid == 0 && platform->network_context_id == 0);
  assert(platform->availability == (PRODUCT_PLATFORM_UID_KNOWN | PRODUCT_PLATFORM_CONTEXT_KNOWN));
  assert(platform->linux_ifindex == 0);
  ++f->outputs;
  return PRODUCT_VPN_FLOW_STACK_OUTPUT_ACCEPTED;
}
static void step(product_vpn_flow_stack_t *stack)
{
  assert(product_vpn_flow_stack_step(stack, 4, 10000).quanta <= 4);
}
int main(int argc, char **argv)
{
  int malformed = argc == 2 && !strcmp(argv[1], "ipv6-malformed");
  int extension = malformed || (argc == 2 && !strcmp(argv[1], "ipv6-extension"));
  int ipv6 = extension || (argc == 2 && !strcmp(argv[1], "ipv6"));
  alarm(5);
  int endpoint = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  assert(endpoint >= 0);
  struct sockaddr_in address = {.sin_family = AF_INET,
    .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  struct sockaddr_in6 address6 = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
  struct sockaddr *bind_address = ipv6 ? (struct sockaddr *)&address6 : (struct sockaddr *)&address;
  socklen_t size = ipv6 ? sizeof(address6) : sizeof(address);
  assert(!bind(endpoint, bind_address, size));
  assert(!getsockname(endpoint, bind_address, &size));
  unsigned char packet[29] = {0x45,0,0,29,0,1,0,0,64,17,0,0,
    10,0,0,2,127,0,0,1,0x30,0x39,0,0,0,9,0,0,42};
  memcpy(packet + 22, &address.sin_port, 2);
  unsigned checksum = 0;
  for (unsigned i = 0; i < 20; i += 2) checksum += ((unsigned)packet[i] << 8) | packet[i+1];
  while (checksum >> 16) checksum = (checksum & 65535) + (checksum >> 16);
  checksum = ~checksum;
  packet[10] = checksum >> 8; packet[11] = checksum;
  unsigned char packet6[49] = {0x60,0,0,0,0,9,17,64};
  if (ipv6) {
    packet6[8] = 0xfd; packet6[23] = 2; packet6[39] = 1;
    packet6[40] = 0x30; packet6[41] = 0x39;
    memcpy(packet6 + 42, &address6.sin6_port, 2);
    packet6[45] = 9; packet6[48] = 42;
    unsigned sum = 9 + 17;
    for (unsigned i = 8; i < 48; i += 2)
      sum += ((unsigned)packet6[i] << 8) | packet6[i+1];
    sum += 42U << 8;
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    sum = (~sum) & 65535;
    if (!sum) sum = 65535;
    packet6[46] = sum >> 8; packet6[47] = sum;
  }
  unsigned char *input = ipv6 ? packet6 : packet;
  size_t input_length = ipv6 ? sizeof(packet6) : sizeof(packet);
  unsigned char packet6_extension[57] = {0};
  if (extension) {
    memcpy(packet6_extension, packet6, 40);
    packet6_extension[5] = 17;
    packet6_extension[6] = 0; /* Hop-by-Hop, then UDP; only Pad1 options. */
    packet6_extension[40] = 17;
    if (malformed) packet6_extension[41] = 2; /* Claims 24 bytes, only 17 remain. */
    memcpy(packet6_extension + 48, packet6 + 40, 9);
    input = packet6_extension;
    input_length = sizeof(packet6_extension);
  }
  fixture_t fixture = {.ipv6 = ipv6};
  product_vpn_flow_stack_config_t config = {.generation = 9, .max_sessions = 1,
    .max_input_packets = 2, .max_pbufs = 16, .max_packet_bytes = 1500,
    .task_stack_bytes = 32768, .broker_timeout_ms = 1000, .idle_timeout_ms = 1000,
    .output = output, .broker = broker, .opaque = &fixture};
  product_vpn_flow_stack_t *stack = product_vpn_flow_stack_create(&config);
  assert(stack);
  product_platform_packet_facts_t platform = {.uid = 0,
    .availability = PRODUCT_PLATFORM_UID_KNOWN,
    .direction = PRODUCT_PACKET_DIRECTION_INPUT,
    .provenance = PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN};
  assert(product_vpn_flow_stack_input_copy(stack, input, input_length, &platform, 9)
    == PRODUCT_VPN_FLOW_STACK_UNSUPPORTED);
  platform.direction = PRODUCT_PACKET_DIRECTION_OUTPUT;
  platform.provenance = PRODUCT_PACKET_PROVENANCE_VPN_TUN;
  assert(product_vpn_flow_stack_input_copy(stack, input, input_length, &platform, 8)
    == PRODUCT_VPN_FLOW_STACK_INVALID_GENERATION);
  product_vpn_flow_stack_input_result_t result =
    product_vpn_flow_stack_input_copy(stack, input, input_length, &platform, 9);
  if (malformed) {
    assert(result != PRODUCT_VPN_FLOW_STACK_ACCEPTED);
    product_vpn_flow_stack_quiesce(stack);
    step(stack);
    product_vpn_flow_stack_snapshot_t s = product_vpn_flow_stack_snapshot(stack);
    assert(s.stopped && !s.pbufs && !s.sessions && !s.input_packets);
    assert(!s.direct_sent && !fixture.session && !fixture.outputs);
    assert(!product_vpn_flow_stack_close(stack));
    close(endpoint);
    return 0;
  }
  assert(result == PRODUCT_VPN_FLOW_STACK_ACCEPTED);
  memset(input, 0, input_length); /* Borrow ended; copied packet must survive. */
  step(stack);
  assert(fixture.session && !product_vpn_flow_stack_snapshot(stack).direct_sent);
  assert(!product_vpn_flow_stack_broker_complete(stack, 9, fixture.session, 0, 13, 0, 1));
  step(stack);
  struct pollfd ready = {.fd = endpoint, .events = POLLIN};
  assert(poll(&ready, 1, 1000) == 1);
  unsigned char byte;
  struct sockaddr_storage peer;
  size = sizeof(peer);
  assert(recvfrom(endpoint, &byte, 1, 0, (struct sockaddr *)&peer, &size) == 1);
  assert(byte == 42 && sendto(endpoint, &byte, 1, 0, (struct sockaddr *)&peer, size) == 1);
  ready.fd = fixture.fd;
  assert(poll(&ready, 1, 1000) == 1);
  step(stack);
  assert(fixture.outputs == 1);
  product_vpn_flow_stack_quiesce(stack);
  step(stack);
  product_vpn_flow_stack_snapshot_t s = product_vpn_flow_stack_snapshot(stack);
  assert(s.stopped && !s.pbufs && !s.sessions && !s.input_packets);
  assert(s.direct_sent == 1 && s.direct_received == 1 && s.output_accepted == 1);
  assert(!product_vpn_flow_stack_close(stack));
  close(endpoint);
  return 0;
}
