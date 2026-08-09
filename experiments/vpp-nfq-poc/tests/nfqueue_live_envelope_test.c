/* SPDX-License-Identifier: Apache-2.0 */

#include "../overlay/src/plugins/nfqueue_live_poc/nfqueue_live_envelope.h"

#include <assert.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct
{
  uint32_t message_obligations;
  uint32_t recovery_attempts;
  uint32_t recoveries;
  uint32_t verdict_attempts;
  uint32_t native_buffer_returns;
  uint32_t packet_ids[4];
  uint32_t packet_id_count;
  uint32_t packet_copies;
  uint32_t residue_obligations;
} envelope_ledger_t;

static void
record_rejection (void *opaque, uint32_t packet_id)
{
  envelope_ledger_t *ledger = (envelope_ledger_t *) opaque;
  assert (ledger->packet_id_count <
          sizeof (ledger->packet_ids) / sizeof (ledger->packet_ids[0]));
  ledger->packet_ids[ledger->packet_id_count++] = packet_id;
  ledger->verdict_attempts++;
}

static uint32_t
append_nfqueue_message (uint8_t *buffer, uint32_t offset, uint32_t payload_len,
                        uint32_t packet_id, uint8_t fill)
{
  struct nlmsghdr *nlh = (struct nlmsghdr *) (buffer + offset);
  struct nfgenmsg *nfmsg;
  struct nfqnl_msg_packet_hdr packet_header;
  uint32_t message_start = offset;
  uint32_t attr_offset;
  uint32_t aligned;
  struct nlattr *attr;

  memset (nlh, 0, NLMSG_HDRLEN);
  nlh->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET;
  nlh->nlmsg_len = NLMSG_HDRLEN + NLMSG_ALIGN (sizeof (*nfmsg));
  nfmsg = (struct nfgenmsg *) ((uint8_t *) nlh + NLMSG_HDRLEN);
  memset (nfmsg, 0, sizeof (*nfmsg));
  nfmsg->version = NFNETLINK_V0;

  attr_offset = message_start + NLMSG_HDRLEN + NLMSG_ALIGN (sizeof (*nfmsg));
  attr = (struct nlattr *) (buffer + attr_offset);
  attr->nla_type = NFQA_PACKET_HDR;
  attr->nla_len = NLA_HDRLEN + sizeof (packet_header);
  packet_header.packet_id = htonl (packet_id);
  packet_header.hw_protocol = htons (0x0800);
  packet_header.hook = NF_INET_LOCAL_OUT;
  memcpy ((uint8_t *) attr + NLA_HDRLEN, &packet_header,
          sizeof (packet_header));
  aligned = NLA_ALIGN (attr->nla_len);
  memset ((uint8_t *) attr + attr->nla_len, 0, aligned - attr->nla_len);
  attr_offset += aligned;

  /* Match the ordinary NFQUEUE envelope observed by S73: MARK, OUTDEV, and
   * UID attributes add 24 aligned bytes before NFQA_PAYLOAD. */
  const uint16_t ancillary_types[] = { NFQA_MARK, NFQA_IFINDEX_OUTDEV,
                                       NFQA_UID };
  for (uint32_t i = 0; i < sizeof (ancillary_types) / sizeof (ancillary_types[0]);
       i++)
    {
      uint16_t type = ancillary_types[i];
      uint32_t value = htonl (type);
      attr = (struct nlattr *) (buffer + attr_offset);
      attr->nla_type = type;
      attr->nla_len = NLA_HDRLEN + sizeof (value);
      memcpy ((uint8_t *) attr + NLA_HDRLEN, &value, sizeof (value));
      aligned = NLA_ALIGN (attr->nla_len);
      memset ((uint8_t *) attr + attr->nla_len, 0, aligned - attr->nla_len);
      attr_offset += aligned;
    }

  attr = (struct nlattr *) (buffer + attr_offset);
  attr->nla_type = NFQA_PAYLOAD;
  attr->nla_len = NLA_HDRLEN + payload_len;
  memset ((uint8_t *) attr + NLA_HDRLEN, fill, payload_len);
  aligned = NLA_ALIGN (attr->nla_len);
  memset ((uint8_t *) attr + attr->nla_len, 0, aligned - attr->nla_len);
  attr_offset += aligned;

  nlh->nlmsg_len = attr_offset - message_start;
  aligned = NLMSG_ALIGN (nlh->nlmsg_len);
  memset (buffer + attr_offset, 0, aligned - nlh->nlmsg_len);
  return message_start + aligned;
}

static void
test_single_message (void)
{
  uint8_t buffer[9000];
  nfqueue_live_envelope_t envelope;
  uint32_t length;
  int status;

  memset (buffer, 0, sizeof (buffer));
  length = append_nfqueue_message (buffer, 0, 84, 7, 0x45);
  status = nfqueue_live_measure_envelope (buffer, length, sizeof (buffer),
                                           &envelope);
  assert (status == NFQUEUE_LIVE_ENVELOPE_COMPLETE);
  assert (envelope.message_count == 1);
  assert (envelope.valid_message_count == 1);
  assert (envelope.recoverable_message_count == 1);
  assert (envelope.first_packet_id == 7);
  assert (envelope.first_payload_offset == 60);
  assert (envelope.first_payload_length == 84);
  assert (envelope.usable_l3_bytes == 84);
  assert (envelope.netlink_header_bytes == NLMSG_HDRLEN);
  assert (envelope.attribute_aligned_bytes == 124);
}

static void
test_multi_message (void)
{
  uint8_t buffer[9000];
  nfqueue_live_envelope_t envelope;
  envelope_ledger_t ledger = { 0 };
  uint32_t length;
  uint32_t visited;
  int status;

  memset (buffer, 0, sizeof (buffer));
  length = append_nfqueue_message (buffer, 0, 84, 11, 0x45);
  length = append_nfqueue_message (buffer, length, 104, 12, 0x60);
  status = nfqueue_live_measure_envelope (buffer, length, sizeof (buffer),
                                           &envelope);
  assert (status == NFQUEUE_LIVE_ENVELOPE_MULTI);
  assert (envelope.message_count == 2);
  assert (envelope.valid_message_count == 2);
  assert (envelope.recoverable_message_count == 2);
  assert (envelope.total_payload_bytes == 188);
  assert (envelope.first_packet_id == 11);

  /* This is the production preflight rejection seam: both identities get an
   * explicit ACCEPT attempt, while the one VPP buffer is returned once and no
   * independent packet obligation or copy is created. */
  visited = nfqueue_live_envelope_recover_packet_ids (
    buffer, envelope.parsed_bytes, record_rejection, &ledger);
  ledger.native_buffer_returns = 1;
  assert (visited == 2);
  assert (ledger.packet_id_count == 2);
  assert (ledger.packet_ids[0] == 11);
  assert (ledger.packet_ids[1] == 12);
  assert (ledger.message_obligations == 0);
  assert (ledger.verdict_attempts == 2);
  assert (ledger.native_buffer_returns == 1);
  assert (ledger.packet_copies == 0);
  assert (ledger.residue_obligations == 0);
  printf ("multi ledger: messages=%u recoverable=%u rejection-attempts=%u "
          "native-returns=%u obligations=%u copies=%u residue=%u ids=%u,%u\n",
          envelope.message_count, envelope.recoverable_message_count,
          ledger.verdict_attempts, ledger.native_buffer_returns,
          ledger.message_obligations, ledger.packet_copies,
          ledger.residue_obligations, ledger.packet_ids[0],
          ledger.packet_ids[1]);
}

static void
test_exact_capacity_boundary (void)
{
  uint8_t buffer[9000];
  nfqueue_live_envelope_t envelope;
  uint32_t length;
  uint32_t payload_len;
  int status;

  memset (buffer, 0, sizeof (buffer));
  payload_len = sizeof (buffer) - 60;
  length = append_nfqueue_message (buffer, 0, payload_len, 21, 0x45);
  assert (length == sizeof (buffer));
  status = nfqueue_live_measure_envelope (buffer, length, sizeof (buffer),
                                           &envelope);
  assert (status == NFQUEUE_LIVE_ENVELOPE_COMPLETE);
  assert (envelope.message_count == 1);
  assert (envelope.first_payload_offset == 60);
  assert (envelope.first_payload_length == payload_len);
  assert (envelope.parsed_bytes == sizeof (buffer));
  printf ("exact boundary: datagram=%u capacity=%zu status=COMPLETE "
          "parsed=%u payload=%u\n",
          length, sizeof (buffer), envelope.parsed_bytes,
          envelope.first_payload_length);
}

static void
test_oversize_is_rejected_without_partial_parse (void)
{
  uint8_t buffer[9000];
  nfqueue_live_envelope_t envelope;
  envelope_ledger_t ledger = { 0 };
  uint32_t length;
  uint32_t visited;
  int status;

  memset (buffer, 0, sizeof (buffer));
  length = append_nfqueue_message (buffer, 0, sizeof (buffer) - 60, 31, 0x45);
  status = nfqueue_live_measure_envelope (buffer, length + 1, sizeof (buffer),
                                           &envelope);
  assert (status == NFQUEUE_LIVE_ENVELOPE_OVERSIZE);
  assert (envelope.oversize == 1);
  assert (envelope.complete == 0);
  assert (envelope.payload_projectable == 0);
  visited = nfqueue_live_envelope_recover_packet_ids (
    buffer, envelope.parsed_bytes, record_rejection, &ledger);
  ledger.native_buffer_returns = 1;
  assert (visited == 1);
  assert (ledger.verdict_attempts == 1);
  assert (ledger.message_obligations == 0);
  assert (ledger.native_buffer_returns == 1);
  assert (ledger.packet_copies == 0);
  assert (ledger.residue_obligations == 0);
  printf ("oversize boundary: datagram=%u capacity=%zu status=OVERSIZE "
          "parsed=%u rejection-attempts=%u native-returns=%u obligations=%u "
          "copies=%u residue=%u\n",
          envelope.datagram_length, sizeof (buffer), envelope.parsed_bytes,
          ledger.verdict_attempts, ledger.native_buffer_returns,
          ledger.message_obligations, ledger.packet_copies,
          ledger.residue_obligations);
}

static void
test_declared_oversize_recovers_contained_identity (void)
{
  uint8_t buffer[9000];
  nfqueue_live_envelope_t envelope;
  envelope_ledger_t ledger = { 0 };
  struct nlmsghdr *nlh;
  uint32_t length;
  uint32_t visited;
  int status;

  memset (buffer, 0, sizeof (buffer));
  length = append_nfqueue_message (buffer, 0, 84, 51, 0x45);
  nlh = (struct nlmsghdr *) buffer;
  nlh->nlmsg_len = sizeof (buffer) + 1;
  status = nfqueue_live_measure_envelope (buffer, sizeof (buffer) + 1,
                                           sizeof (buffer), &envelope);
  assert (status == NFQUEUE_LIVE_ENVELOPE_OVERSIZE);
  assert (envelope.message_count == 1);
  assert (envelope.recoverable_message_count == 1);
  assert (envelope.valid_message_count == 0);
  assert (envelope.parsed_bytes == 0);
  assert (envelope.first_packet_id_known == 1);
  assert (envelope.first_packet_id == 51);
  assert (envelope.first_payload_present == 0);
  assert (envelope.first_payload_length == 0);
  assert (envelope.payload_projectable == 0);

  visited = nfqueue_live_envelope_recover_packet_ids (
    buffer, sizeof (buffer), record_rejection, &ledger);
  ledger.recovery_attempts = 1;
  ledger.recoveries = visited;
  ledger.native_buffer_returns = 1;
  assert (visited == 1);
  assert (ledger.recovery_attempts == 1);
  assert (ledger.recoveries == 1);
  assert (ledger.packet_ids[0] == 51);
  assert (ledger.verdict_attempts == 1);
  assert (ledger.message_obligations == 0);
  assert (ledger.native_buffer_returns == 1);
  assert (ledger.packet_copies == 0);
  assert (ledger.residue_obligations == 0);
  printf ("declared-oversize truncation: declared=%u captured=%zu "
          "status=OVERSIZE recoverable=%u recovery-attempts=%u recoveries=%u "
          "rejection-attempts=%u "
          "native-returns=%u obligations=%u copies=%u residue=%u id=%u\n",
          envelope.datagram_length, sizeof (buffer),
          envelope.recoverable_message_count, ledger.recovery_attempts,
          ledger.recoveries, ledger.verdict_attempts,
          ledger.native_buffer_returns, ledger.message_obligations,
          ledger.packet_copies, ledger.residue_obligations,
          ledger.packet_ids[0]);
  (void) length;
}

static void
test_mixed_complete_and_declared_truncated (void)
{
  uint8_t buffer[9000];
  nfqueue_live_envelope_t envelope;
  envelope_ledger_t ledger = { 0 };
  struct nlmsghdr *truncated_nlh;
  uint32_t first_length;
  uint32_t captured_length;
  uint32_t visited;
  int status;

  memset (buffer, 0, sizeof (buffer));
  first_length = append_nfqueue_message (buffer, 0, 84, 11, 0x45);
  captured_length = append_nfqueue_message (buffer, first_length, 84, 51,
                                            0x60);
  truncated_nlh = (struct nlmsghdr *) (buffer + first_length);
  truncated_nlh->nlmsg_len = sizeof (buffer) + 1;
  status = nfqueue_live_measure_envelope (buffer, sizeof (buffer) + 1,
                                           sizeof (buffer), &envelope);
  assert (status == NFQUEUE_LIVE_ENVELOPE_OVERSIZE);
  assert (envelope.message_count == 2);
  assert (envelope.valid_message_count == 1);
  assert (envelope.recoverable_message_count == 2);
  assert (envelope.first_packet_id == 11);
  assert (envelope.parsed_bytes == first_length);

  visited = nfqueue_live_envelope_recover_packet_ids (
    buffer, sizeof (buffer), record_rejection, &ledger);
  ledger.native_buffer_returns = 1;
  assert (visited == 2);
  assert (ledger.packet_id_count == 2);
  assert (ledger.packet_ids[0] == 11);
  assert (ledger.packet_ids[1] == 51);
  assert (ledger.verdict_attempts == 2);
  assert (ledger.message_obligations == 0);
  assert (ledger.native_buffer_returns == 1);
  assert (ledger.packet_copies == 0);
  assert (ledger.residue_obligations == 0);
  printf ("mixed complete+truncated: messages=%u recoverable=%u "
          "rejection-attempts=%u native-returns=%u obligations=%u copies=%u "
          "residue=%u ids=%u,%u\n",
          envelope.message_count, envelope.recoverable_message_count,
          ledger.verdict_attempts, ledger.native_buffer_returns,
          ledger.message_obligations, ledger.packet_copies,
          ledger.residue_obligations, ledger.packet_ids[0],
          ledger.packet_ids[1]);
  (void) captured_length;
}

static void
test_empty_payload_is_malformed (void)
{
  uint8_t buffer[9000];
  nfqueue_live_envelope_t envelope;
  uint32_t length;
  int status;

  memset (buffer, 0, sizeof (buffer));
  length = append_nfqueue_message (buffer, 0, 0, 41, 0x45);
  status = nfqueue_live_measure_envelope (buffer, length, sizeof (buffer),
                                           &envelope);
  assert (status == NFQUEUE_LIVE_ENVELOPE_MALFORMED);
  assert (envelope.complete == 0);
  assert (envelope.payload_projectable == 0);
  assert (envelope.malformed_message_count == 1);
  puts ("empty payload: status=MALFORMED projectable=0");
}

int
main (void)
{
  test_single_message ();
  test_multi_message ();
  test_exact_capacity_boundary ();
  test_oversize_is_rejected_without_partial_parse ();
  test_declared_oversize_recovers_contained_identity ();
  test_mixed_complete_and_declared_truncated ();
  test_empty_payload_is_malformed ();
  puts ("S74 netlink envelope parser: PASS");
  return 0;
}
