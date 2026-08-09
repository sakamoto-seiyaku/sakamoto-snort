/* SPDX-License-Identifier: Apache-2.0 */

#ifndef included_nfqueue_live_envelope_h
#define included_nfqueue_live_envelope_h

/*
 * SAKAMOTO-74 — bounded netlink-envelope measurement.
 *
 * This is deliberately a parser/proof seam, not a packet materialization
 * helper. It only reads the received VPP data span. The caller must reject
 * every result other than COMPLETE before invoking libnetfilter_queue; no
 * partial prefix is ever exposed as a usable L3 packet.
 */

#include <libnetfilter_queue/linux_nfnetlink_queue.h>
#include <linux/netlink.h>

#include <arpa/inet.h>
#include <stdint.h>

typedef enum
{
  NFQUEUE_LIVE_ENVELOPE_INVALID = -1,
  NFQUEUE_LIVE_ENVELOPE_COMPLETE = 0,
  NFQUEUE_LIVE_ENVELOPE_MULTI = 1,
  NFQUEUE_LIVE_ENVELOPE_OVERSIZE = 2,
  NFQUEUE_LIVE_ENVELOPE_MALFORMED = 3,
} nfqueue_live_envelope_status_t;

typedef struct
{
  uint32_t datagram_length;
  uint32_t data_capacity;
  uint32_t parsed_bytes;
  uint32_t message_count;
  uint32_t valid_message_count;
  uint32_t recoverable_message_count;
  uint32_t malformed_message_count;
  uint32_t netlink_header_bytes;
  uint32_t netlink_aligned_bytes;
  uint32_t nfgenmsg_bytes;
  uint32_t attribute_bytes;
  uint32_t attribute_aligned_bytes;
  uint32_t total_payload_bytes;
  uint32_t first_message_offset;
  uint32_t first_message_span;
  uint32_t first_payload_offset;
  uint32_t first_payload_length;
  uint32_t usable_l3_bytes;
  uint32_t first_packet_id;
  uint8_t first_packet_id_known;
  uint8_t first_payload_present;
  uint8_t complete;
  uint8_t oversize;
  uint8_t multi_message;
  uint8_t malformed;
  uint8_t payload_projectable;
} nfqueue_live_envelope_t;

typedef void (*nfqueue_live_envelope_packet_id_callback_t) (void *opaque,
                                                             uint32_t packet_id);

static inline uint32_t
nfqueue_live_envelope_min (uint32_t lhs, uint32_t rhs)
{
  return lhs < rhs ? lhs : rhs;
}

typedef struct
{
  uint32_t packet_id;
  uint8_t found;
} nfqueue_live_envelope_first_id_t;

static inline void
nfqueue_live_envelope_record_first_id (void *opaque, uint32_t packet_id)
{
  nfqueue_live_envelope_first_id_t *first =
    (nfqueue_live_envelope_first_id_t *) opaque;
  if (!first->found)
    {
      first->packet_id = packet_id;
      first->found = 1;
    }
}

/*
 * Recover identities from a captured prefix, including a later message whose
 * netlink header declares more bytes than were captured (MSG_TRUNC). The walk
 * clamps each declared message end to captured_length, requires every
 * attribute and NFQA_PACKET_HDR value it reads to be fully contained, and
 * stops after a truncated message because no following boundary is knowable.
 * Payload bytes are never exposed by this recovery path.
 */
static inline uint32_t
nfqueue_live_envelope_recover_packet_ids (
  const uint8_t *base, uint32_t captured_length,
  nfqueue_live_envelope_packet_id_callback_t callback, void *opaque)
{
  const uint32_t message_header_bytes =
    NLMSG_HDRLEN + NLMSG_ALIGN (sizeof (struct nfgenmsg));
  uint32_t offset = 0;
  uint32_t recovered = 0;

  if (!base || !callback)
    return 0;
  while (offset + NLMSG_HDRLEN <= captured_length)
    {
      const struct nlmsghdr *nlh = (const struct nlmsghdr *) (base + offset);
      uint32_t remaining = captured_length - offset;
      uint32_t declared_length = nlh->nlmsg_len;
      uint32_t bounded_length;
      uint32_t attr_offset;
      uint32_t attr_end;
      uint32_t aligned_length;
      uint32_t packet_id = 0;
      uint8_t packet_id_known = 0;

      if (declared_length < NLMSG_HDRLEN ||
          declared_length < message_header_bytes)
        break;
      bounded_length = nfqueue_live_envelope_min (declared_length, remaining);
      if (bounded_length < message_header_bytes)
        break;
      attr_offset = offset + message_header_bytes;
      attr_end = offset + bounded_length;
      while (attr_offset < attr_end)
        {
          const struct nlattr *attr;
          uint32_t attr_length;
          uint32_t aligned_attr_length;

          if (attr_end - attr_offset < NLA_HDRLEN)
            break;
          attr = (const struct nlattr *) (base + attr_offset);
          attr_length = attr->nla_len;
          if (attr_length < NLA_HDRLEN ||
              attr_length > attr_end - attr_offset)
            break;
          aligned_attr_length = NLA_ALIGN (attr_length);
          if (aligned_attr_length < attr_length ||
              aligned_attr_length > attr_end - attr_offset)
            break;
          if ((attr->nla_type & NLA_TYPE_MASK) == NFQA_PACKET_HDR &&
              attr_length - NLA_HDRLEN >= sizeof (struct nfqnl_msg_packet_hdr))
            {
              const struct nfqnl_msg_packet_hdr *header =
                (const struct nfqnl_msg_packet_hdr *)
                  ((const uint8_t *) attr + NLA_HDRLEN);
              packet_id = ntohl (header->packet_id);
              packet_id_known = 1;
            }
          attr_offset += aligned_attr_length;
        }
      if (packet_id_known)
        {
          callback (opaque, packet_id);
          recovered++;
        }
      if (declared_length > remaining)
        break;
      aligned_length = NLMSG_ALIGN (declared_length);
      if (aligned_length < declared_length || aligned_length > remaining)
        break;
      offset += aligned_length;
    }
  return recovered;
}

static inline uint8_t
nfqueue_live_envelope_recover_first_packet_id (const uint8_t *base,
                                                uint32_t captured_length,
                                                uint32_t *packet_id)
{
  nfqueue_live_envelope_first_id_t first = { 0 };
  if (!packet_id)
    return 0;
  if (nfqueue_live_envelope_recover_packet_ids (
        base, captured_length, nfqueue_live_envelope_record_first_id,
        &first) == 0)
    return 0;
  *packet_id = first.packet_id;
  return 1;
}

/* Parse one received datagram without copying or interpreting packet bytes. */
static inline int
nfqueue_live_measure_envelope (const uint8_t *base, uint32_t datagram_length,
                                uint32_t data_capacity,
                                nfqueue_live_envelope_t *out)
{
  const uint32_t nfgenmsg_aligned = NLMSG_ALIGN (sizeof (struct nfgenmsg));
  const uint32_t message_header_bytes = NLMSG_HDRLEN + nfgenmsg_aligned;
  uint32_t inspect_length;
  uint32_t offset = 0;

  if (!out)
    return NFQUEUE_LIVE_ENVELOPE_INVALID;
  *out = (nfqueue_live_envelope_t) {
    .datagram_length = datagram_length,
    .data_capacity = data_capacity,
  };
  if (!base || datagram_length == 0 || data_capacity == 0)
    {
      out->malformed = 1;
      return NFQUEUE_LIVE_ENVELOPE_INVALID;
    }

  inspect_length = nfqueue_live_envelope_min (datagram_length, data_capacity);
  out->oversize = datagram_length > data_capacity;

  while (offset < inspect_length)
    {
      const struct nlmsghdr *nlh;
      uint32_t remaining = inspect_length - offset;
      uint32_t message_length;
      uint32_t aligned_message_length;
      uint32_t attr_offset;
      uint32_t attr_end;
      uint8_t packet_id_known = 0;
      uint8_t payload_present = 0;
      uint32_t packet_id = 0;
      uint32_t payload_offset = 0;
      uint32_t payload_length = 0;
      uint32_t message_attribute_bytes = 0;
      uint32_t message_attribute_aligned_bytes = 0;
      uint32_t message_payload_bytes = 0;
      uint8_t message_malformed = 0;

      if (remaining < NLMSG_HDRLEN)
        {
          out->malformed = 1;
          out->malformed_message_count++;
          break;
        }

      nlh = (const struct nlmsghdr *) (base + offset);
      message_length = nlh->nlmsg_len;
      if (message_length < NLMSG_HDRLEN || message_length > remaining)
        {
          if (message_length >= NLMSG_HDRLEN &&
              message_length > remaining)
            {
              uint32_t recovered_packet_id;
              out->message_count++;
              if (out->message_count == 1)
                out->first_message_offset = offset;
              if (nfqueue_live_envelope_recover_first_packet_id (
                    base + offset, remaining, &recovered_packet_id))
                {
                  out->recoverable_message_count++;
                  if (out->message_count == 1)
                    {
                      out->first_packet_id = recovered_packet_id;
                      out->first_packet_id_known = 1;
                    }
                }
            }
          out->malformed = 1;
          out->malformed_message_count++;
          break;
        }
      aligned_message_length = NLMSG_ALIGN (message_length);
      if (aligned_message_length < message_length ||
          aligned_message_length > remaining)
        {
          out->malformed = 1;
          out->malformed_message_count++;
          break;
        }

      out->message_count++;
      if (out->message_count == 1)
        {
          out->first_message_offset = offset;
          out->first_message_span = aligned_message_length;
        }

      if (message_length < message_header_bytes)
        message_malformed = 1;
      else
        {
          attr_offset = offset + message_header_bytes;
          attr_end = offset + message_length;
          while (attr_offset < attr_end)
            {
              const struct nlattr *attr;
              uint32_t attribute_length;
              uint32_t aligned_attribute_length;
              uint32_t attribute_payload_length;

              if (attr_end - attr_offset < NLA_HDRLEN)
                {
                  message_malformed = 1;
                  break;
                }
              attr = (const struct nlattr *) (base + attr_offset);
              attribute_length = attr->nla_len;
              if (attribute_length < NLA_HDRLEN ||
                  attribute_length > attr_end - attr_offset)
                {
                  message_malformed = 1;
                  break;
                }
              aligned_attribute_length = NLA_ALIGN (attribute_length);
              if (aligned_attribute_length < attribute_length ||
                  aligned_attribute_length > attr_end - attr_offset)
                {
                  message_malformed = 1;
                  break;
                }

              attribute_payload_length = attribute_length - NLA_HDRLEN;
              message_attribute_bytes += attribute_length;
              message_attribute_aligned_bytes += aligned_attribute_length;
              if ((attr->nla_type & NLA_TYPE_MASK) == NFQA_PACKET_HDR &&
                  attribute_payload_length >=
                    sizeof (struct nfqnl_msg_packet_hdr))
                {
                  const struct nfqnl_msg_packet_hdr *header =
                    (const struct nfqnl_msg_packet_hdr *)
                      ((const uint8_t *) attr + NLA_HDRLEN);
                  packet_id = ntohl (header->packet_id);
                  packet_id_known = 1;
                }
              if ((attr->nla_type & NLA_TYPE_MASK) == NFQA_PAYLOAD)
                {
                  payload_offset = attr_offset + NLA_HDRLEN;
                  payload_length = attribute_payload_length;
                  payload_present = attribute_payload_length != 0;
                  if (!payload_present)
                    message_malformed = 1;
                  message_payload_bytes += attribute_payload_length;
                }
              attr_offset += aligned_attribute_length;
            }
        }

      if (message_malformed)
        {
          out->malformed = 1;
          out->malformed_message_count++;
        }
      else
        {
          out->netlink_header_bytes += NLMSG_HDRLEN;
          out->netlink_aligned_bytes += aligned_message_length;
          out->nfgenmsg_bytes += nfgenmsg_aligned;
          out->attribute_bytes += message_attribute_bytes;
          out->attribute_aligned_bytes += message_attribute_aligned_bytes;
          out->total_payload_bytes += message_payload_bytes;
          if (packet_id_known)
            out->recoverable_message_count++;
          if (packet_id_known && payload_present)
            out->valid_message_count++;
          if (out->message_count == 1)
            {
              out->first_packet_id = packet_id;
              out->first_packet_id_known = packet_id_known;
              out->first_payload_offset = payload_offset;
              out->first_payload_length = payload_length;
              out->usable_l3_bytes = payload_length;
              out->first_payload_present = payload_present;
            }
        }

      offset += aligned_message_length;
    }

  out->parsed_bytes = offset;
  out->multi_message = out->message_count > 1;
  out->complete = !out->oversize && !out->malformed &&
                  offset == datagram_length && out->message_count != 0;
  out->payload_projectable = out->complete &&
                             out->message_count == 1 &&
                             out->valid_message_count == 1 &&
                             out->first_payload_present;
  if (out->oversize)
    return NFQUEUE_LIVE_ENVELOPE_OVERSIZE;
  if (out->malformed || !out->complete)
    return NFQUEUE_LIVE_ENVELOPE_MALFORMED;
  if (out->message_count > 1)
    return NFQUEUE_LIVE_ENVELOPE_MULTI;
  if (!out->payload_projectable)
    return NFQUEUE_LIVE_ENVELOPE_MALFORMED;
  return NFQUEUE_LIVE_ENVELOPE_COMPLETE;
}

#endif /* included_nfqueue_live_envelope_h */
