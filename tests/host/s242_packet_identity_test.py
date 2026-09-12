#!/usr/bin/env python3
"""Compile the actual adapter parser: zero is an ID, not missing identity.

Only the production function and its packet record are extracted. These are
Host semantic vectors, not live NFQUEUE or kernel sequence-wrap evidence.
"""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT/'src/product/vpp/product_root_nfqueue_adapter.c').read_text()
record = re.search(r'typedef struct\n\{\n  u32 packet_id;.*?\} product_root_nfqueue_packet_t;', source, re.S)
function = re.search(r'static int\nproduct_root_nfqueue_parse_packet \(.*?\n\}\n', source, re.S)
assert record and function, 'actual adapter parser extraction failed'
prefix = r'''
#include <arpa/inet.h>
#include <assert.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
typedef uint32_t u32;
#define clib_memset memset
#define clib_memcpy_fast memcpy
'''
harness = r'''
static void attribute(struct nlmsghdr *header, unsigned kind, const void *data, unsigned length) {
  unsigned offset = NLMSG_ALIGN(header->nlmsg_len);
  struct nfattr *a = (void *)((unsigned char *)header + offset);
  a->nfa_type = kind;
  a->nfa_len = sizeof(*a) + length;
  memcpy(NFA_DATA(a), data, length);
  header->nlmsg_len = offset + NFA_ALIGN(a->nfa_len);
}
static void check(unsigned family, uint32_t id, unsigned hook, unsigned defect) {
  _Alignas(struct nlmsghdr) unsigned char message[256] = {0};
  struct nlmsghdr *header = (void *)message;
  header->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET;
  header->nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg));
  struct nfqnl_msg_packet_hdr identity = {.packet_id=htonl(id), .hook=hook};
  if (defect != 1) attribute(header, NFQA_PACKET_HDR, &identity, defect == 2 ? 2 : sizeof(identity));
  unsigned char payload[40] = {0};
  payload[0] = family == 4 ? 0x45 : 0x60;
  payload[family == 4 ? 9 : 6] = 17;
  if (defect != 3) attribute(header, NFQA_PAYLOAD, payload, family == 4 ? 20 : 40);
  product_root_nfqueue_packet_t packet;
  int result = product_root_nfqueue_parse_packet(message, header->nlmsg_len, &packet);
  assert(result == (defect == 0));
  if (result) assert(packet.identity_present && packet.packet_id == id && packet.hook == hook);
}
int main(void) {
  uint32_t ids[] = {0, 1, UINT32_MAX};
  for (unsigned family = 4; family <= 6; family += 2)
    for (unsigned hook = NF_INET_LOCAL_IN; hook <= NF_INET_LOCAL_OUT; hook += 2) {
      for (unsigned i = 0; i < 3; ++i) check(family, ids[i], hook, 0);
      for (unsigned defect = 1; defect <= 3; ++defect) check(family, 0, hook, defect);
    }
  puts("PASS: 12 valid NFQA identities including ID zero; 12 missing/truncated identity/payload rejections");
}
'''
with tempfile.TemporaryDirectory(prefix='s242-identity-') as temporary:
    work = Path(temporary)
    translation = work/'parser.c'
    translation.write_text(prefix+record[0]+'\n'+function[0]+harness)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    str(translation), '-o', str(work/'parser')], check=True)
    subprocess.run([str(work/'parser')], check=True)
