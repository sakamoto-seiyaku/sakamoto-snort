/* SPDX-License-Identifier: BSD-2-Clause */
/*-
 * Copyright (c) 2001 Daniel Hartmeier
 * Copyright (c) 2002 - 2008 Henning Brauer
 * Copyright (c) 2012 Gleb Smirnoff <glebius@FreeBSD.org>
 * Copyright (c) 2015, 2016 Nicira, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Effort sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F30602-01-2-0537.
 *
 *      $OpenBSD: pf.c,v 1.634 2009/02/27 12:37:45 henning Exp $
 */

/* Adapted from OVS 3c2bea086ef8912d57331173af266f21d36740a0,
 * lib/conntrack-tcp.c (v3.1.0). Only the enabled sequence-check protocol
 * semantics are adapted: no OVS packet parser, table, lock, clock, NAT or
 * allocation. Invalid candidate mutations are deliberately not committed. */
#include "product_flow_tracker.h"

enum { FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08, ACK = 0x10, URG = 0x20 };
enum { SCALE_PRESENT = 0x80, SCALE_UNKNOWN = 0x40, SCALE_MASK = 0x0f, SCALE_MAX = 14 };
#define MAX_ACK_WINDOW UINT32_C(67035)

static uint32_t maximum (uint32_t a, uint32_t b) { return a > b ? a : b; }
static int seq_geq (uint32_t a, uint32_t b) { return a - b < UINT32_C(0x80000000); }
static int seq_gt (uint32_t a, uint32_t b) { return a != b && seq_geq(a, b); }

static int invalid_flags (uint8_t flags)
{
  return ((flags & SYN) && (flags & (RST | FIN)))
    || (!(flags & SYN) && !(flags & (ACK | RST)))
    || (!(flags & ACK) && (flags & (FIN | PSH | URG)));
}

static uint8_t scale (const product_packet_facts_t *packet)
{
  return packet->tcp_window_scale_known
    ? SCALE_PRESENT | (packet->tcp_window_scale > SCALE_MAX ? SCALE_MAX : packet->tcp_window_scale)
    : 0;
}

static product_tracker_result_t result_for (product_ct_update_t update,
  product_flow_direction_t direction, product_ct_timeout_t timeout, int refresh)
{
  return (product_tracker_result_t) {
    .facts = {update == PRODUCT_CT_UPDATE_INVALID ? PRODUCT_CT_INVALID :
              update == PRODUCT_CT_UPDATE_VALID ? PRODUCT_CT_ESTABLISHED : PRODUCT_CT_NEW,
              direction},
    .update = update, .timeout = timeout, .refresh_deadline = refresh,
  };
}

product_tracker_result_t product_tcp_update (product_tcp_state_t *state,
  const product_packet_facts_t *packet, product_flow_direction_t direction)
{
  product_tracker_result_t invalid = result_for(PRODUCT_CT_UPDATE_INVALID,
    direction, PRODUCT_CT_TIMEOUT_NONE, 0);
  if (!state || !packet || state->initialized > 1 ||
      (direction != PRODUCT_FLOW_DIRECTION_ORIG && direction != PRODUCT_FLOW_DIRECTION_REPLY) ||
      (!state->initialized && direction != PRODUCT_FLOW_DIRECTION_ORIG) ||
      packet->l3_status != PRODUCT_PACKET_L3_COMPLETE ||
      packet->l4_status != PRODUCT_PACKET_L4_COMPLETE ||
      (packet->ip_family != 4 && packet->ip_family != 6) || packet->protocol != 6 ||
      packet->l4_header_length < 20 || packet->l4_header_length > 60 ||
      packet->l4_header_length % 4 || packet->transport_length < packet->l4_header_length ||
      packet->tcp_window_scale_known > 1 || invalid_flags(packet->tcp_flags))
    return invalid;
  product_tcp_state_t candidate = *state;
  uint8_t flags = packet->tcp_flags;
  uint32_t payload = packet->transport_length - packet->l4_header_length;
  uint32_t seq = packet->tcp_sequence, ack = packet->tcp_acknowledgment;
  uint16_t window = packet->tcp_window;
  if (!candidate.initialized)
    {
      if ((flags & (SYN | ACK)) == (SYN | ACK)) return invalid;
      candidate = (product_tcp_state_t) {0};
      product_tcp_peer_t *src = &candidate.peer[0], *dst = &candidate.peer[1];
      src->seqlo = seq;
      src->seqhi = seq + payload + 1;
      if (flags & SYN) { ++src->seqhi; src->window_scale = scale(packet); }
      else src->window_scale = dst->window_scale = SCALE_UNKNOWN;
      src->max_window = maximum(window, 1);
      unsigned shift = src->window_scale & SCALE_MASK;
      if (shift) src->max_window = ((uint32_t)src->max_window + (1U << shift) - 1) >> shift;
      if (flags & FIN) ++src->seqhi;
      dst->seqhi = dst->max_window = 1;
      src->phase = PRODUCT_TCP_SYN_SENT;
      src->flags_history = flags;
      candidate.initialized = 1;
      candidate.timeout = PRODUCT_CT_TIMEOUT_TCP_FIRST_PACKET;
      *state = candidate;
      return result_for(PRODUCT_CT_UPDATE_VALID_NEW, direction, candidate.timeout, 1);
    }
  product_tcp_peer_t *src = &candidate.peer[direction == PRODUCT_FLOW_DIRECTION_REPLY];
  product_tcp_peer_t *dst = &candidate.peer[direction != PRODUCT_FLOW_DIRECTION_REPLY];
  if (src->phase > PRODUCT_TCP_TIME_WAIT || dst->phase > PRODUCT_TCP_TIME_WAIT)
    return invalid;
  if ((flags & (SYN | ACK)) == SYN)
    {
      if (src->phase >= PRODUCT_TCP_FIN_WAIT_2 && dst->phase >= PRODUCT_TCP_FIN_WAIT_2)
        {
          product_tracker_result_t replacement = result_for(PRODUCT_CT_UPDATE_NEW,
            direction, PRODUCT_CT_TIMEOUT_NONE, 0);
          replacement.close_old_instance = replacement.create_replacement = 1;
          return replacement;
        }
      if (src->phase <= PRODUCT_TCP_SYN_SENT)
        {
          src->phase = PRODUCT_TCP_SYN_SENT;
          src->flags_history |= flags;
          candidate.timeout = PRODUCT_CT_TIMEOUT_TCP_FIRST_PACKET;
          *state = candidate;
          return result_for(PRODUCT_CT_UPDATE_VALID_NEW, direction, candidate.timeout, 1);
        }
    }
  unsigned sws = 0, dws = 0;
  if (!(flags & SYN))
    {
      if ((src->window_scale & SCALE_PRESENT) && (dst->window_scale & SCALE_PRESENT))
        { sws = src->window_scale & SCALE_MASK; dws = dst->window_scale & SCALE_MASK; }
      else if ((src->window_scale & SCALE_UNKNOWN) && (dst->window_scale & SCALE_UNKNOWN))
        sws = dws = SCALE_MAX;
    }
  uint32_t original_seq = seq, end = seq + payload + !!(flags & SYN) + !!(flags & FIN);
  int check_ack_skew = 1;
  if (src->phase < PRODUCT_TCP_SYN_SENT)
    {
      if ((flags & SYN) && (dst->window_scale & SCALE_PRESENT))
        {
          src->window_scale = scale(packet);
          if (src->window_scale & SCALE_PRESENT)
            {
              sws = src->window_scale & SCALE_MASK;
              window = ((uint32_t)window + (1U << sws) - 1) >> sws;
              dws = dst->window_scale & SCALE_MASK;
            }
          else
            {
              dst->max_window = (uint16_t)(dst->max_window << (dst->window_scale & SCALE_MASK));
              dst->window_scale = 0;
            }
        }
      src->seqlo = seq;
      src->phase = PRODUCT_TCP_SYN_SENT;
      if (src->seqhi == 1 || seq_geq(end + maximum(1, (uint32_t)dst->max_window << dws), src->seqhi))
        {
          src->seqhi = end + maximum(1, (uint32_t)dst->max_window << dws);
          check_ack_skew = 0;
        }
      if (window > src->max_window) src->max_window = window;
    }
  if (!(flags & ACK) || (ack == 0 && (flags & (ACK | RST)) == (ACK | RST)))
    ack = dst->seqlo;
  if (seq == end) seq = end = src->seqlo;
  int64_t skew = check_ack_skew ? (uint32_t)(dst->seqlo - ack) : 0;
  if (skew >= INT64_C(0x80000000)) skew -= INT64_C(0x100000000);
  int normal = seq_geq(src->seqhi, end)
    && seq_geq(seq, src->seqlo - ((uint32_t)dst->max_window << dws))
    && skew >= -(int64_t)MAX_ACK_WINDOW && skew <= ((int64_t)MAX_ACK_WINDOW << sws)
    && (!(flags & RST) || original_seq == src->seqlo || original_seq == src->seqlo + 1 || original_seq + 1 == src->seqlo);
  int permissive = (dst->phase < PRODUCT_TCP_SYN_SENT || dst->phase >= PRODUCT_TCP_FIN_WAIT_2 || src->phase >= PRODUCT_TCP_FIN_WAIT_2)
    && seq_geq(src->seqhi + MAX_ACK_WINDOW, end)
    && seq_geq(seq, src->seqlo - MAX_ACK_WINDOW);
  if (!normal && !permissive) return invalid;
  if (window > src->max_window) src->max_window = window;
  if (seq_gt(end, src->seqlo)) src->seqlo = end;
  if (seq_geq(ack + ((uint32_t)window << sws), dst->seqhi))
    dst->seqhi = ack + maximum((uint32_t)window << sws, 1);
  if ((flags & FIN) && src->phase < PRODUCT_TCP_CLOSING) src->phase = PRODUCT_TCP_CLOSING;
  if (normal && (flags & ACK))
    {
      if (dst->phase == PRODUCT_TCP_SYN_SENT) dst->phase = PRODUCT_TCP_ESTABLISHED;
      else if (dst->phase == PRODUCT_TCP_CLOSING) dst->phase = PRODUCT_TCP_FIN_WAIT_2;
    }
  if (flags & RST) src->phase = dst->phase = PRODUCT_TCP_TIME_WAIT;
  if (normal)
    {
      candidate.timeout = src->phase >= PRODUCT_TCP_FIN_WAIT_2 && dst->phase >= PRODUCT_TCP_FIN_WAIT_2
        ? PRODUCT_CT_TIMEOUT_TCP_CLOSED : src->phase >= PRODUCT_TCP_CLOSING && dst->phase >= PRODUCT_TCP_CLOSING
        ? PRODUCT_CT_TIMEOUT_TCP_FIN_WAIT : src->phase < PRODUCT_TCP_ESTABLISHED || dst->phase < PRODUCT_TCP_ESTABLISHED
        ? PRODUCT_CT_TIMEOUT_TCP_OPENING : src->phase >= PRODUCT_TCP_CLOSING || dst->phase >= PRODUCT_TCP_CLOSING
        ? PRODUCT_CT_TIMEOUT_TCP_CLOSING : PRODUCT_CT_TIMEOUT_TCP_ESTABLISHED;
    }
  src->flags_history |= flags;
  *state = candidate;
  return result_for(PRODUCT_CT_UPDATE_VALID, direction, candidate.timeout, normal);
}
