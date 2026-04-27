/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <L4ParseResult.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// IPv6 L4 parsing helper:
// - walks extension headers up to a fixed budget
// - classifies terminal / fragment / invalid
// - parses ports only for known TCP/UDP
//
// NOTE: This is header-only to keep Android.bp stable (no new translation unit).
[[nodiscard]] inline L4ParseResult
parseIpv6L4(const std::uint8_t initialNext, const std::uint8_t *payload, const std::size_t payloadLen,
            const std::uint8_t **l4pOut = nullptr,
            std::uint16_t *l4PayloadLenOut = nullptr) noexcept {
    L4ParseResult out{};
    out.l4Status = L4Status::INVALID_OR_UNAVAILABLE_L4;
    out.proto = initialNext;
    out.srcPort = 0;
    out.dstPort = 0;
    out.portsAvailable = 0;
    if (l4pOut) {
        *l4pOut = nullptr;
    }
    if (l4PayloadLenOut) {
        *l4PayloadLenOut = 0;
    }

    const std::uint8_t *cur = payload;
    std::size_t rem = payloadLen;
    std::uint8_t next = initialNext;

    // Budget: max 8 headers / 256 bytes (extension headers only).
    std::uint32_t hdrs = 0;
    std::size_t walked = 0;

    auto budgetOk = [&]() noexcept -> bool {
        return hdrs <= 8 && walked <= 256;
    };

    for (;;) {
        if (!budgetOk()) {
            out.l4Status = L4Status::INVALID_OR_UNAVAILABLE_L4;
            out.proto = next;
            return out;
        }

        // Terminal known L4.
        if (next == IPPROTO_TCP) {
            out.proto = IPPROTO_TCP;
            if (rem < sizeof(tcphdr)) {
                out.l4Status = L4Status::INVALID_OR_UNAVAILABLE_L4;
                return out;
            }
            const auto tcp = reinterpret_cast<const tcphdr *>(cur);
            const std::uint32_t tcpHdrLen = static_cast<std::uint32_t>(tcp->doff) * 4u;
            if (tcp->doff < 5 || tcpHdrLen > rem) {
                out.l4Status = L4Status::INVALID_OR_UNAVAILABLE_L4;
                return out;
            }
            out.l4Status = L4Status::KNOWN_L4;
            out.srcPort = ntohs(tcp->source);
            out.dstPort = ntohs(tcp->dest);
            out.portsAvailable = 1;
            if (l4pOut) {
                *l4pOut = cur;
            }
            if (l4PayloadLenOut) {
                *l4PayloadLenOut = static_cast<std::uint16_t>(std::min<std::size_t>(rem, 0xFFFFu));
            }
            return out;
        }

        if (next == IPPROTO_UDP) {
            out.proto = IPPROTO_UDP;
            if (rem < sizeof(udphdr)) {
                out.l4Status = L4Status::INVALID_OR_UNAVAILABLE_L4;
                return out;
            }
            const auto udp = reinterpret_cast<const udphdr *>(cur);
            out.l4Status = L4Status::KNOWN_L4;
            out.srcPort = ntohs(udp->source);
            out.dstPort = ntohs(udp->dest);
            out.portsAvailable = 1;
            if (l4pOut) {
                *l4pOut = cur;
            }
            if (l4PayloadLenOut) {
                *l4PayloadLenOut = static_cast<std::uint16_t>(std::min<std::size_t>(rem, 0xFFFFu));
            }
            return out;
        }

        if (next == IPPROTO_ICMPV6) {
            out.proto = IPPROTO_ICMPV6;
            if (rem < sizeof(icmp6_hdr)) {
                out.l4Status = L4Status::INVALID_OR_UNAVAILABLE_L4;
                return out;
            }
            out.l4Status = L4Status::KNOWN_L4;
            if (l4pOut) {
                *l4pOut = cur;
            }
            if (l4PayloadLenOut) {
                *l4PayloadLenOut = static_cast<std::uint16_t>(std::min<std::size_t>(rem, 0xFFFFu));
            }
            return out;
        }

        if (next == IPPROTO_NONE) {
            out.l4Status = L4Status::OTHER_TERMINAL;
            out.proto = IPPROTO_NONE;
            if (l4PayloadLenOut) {
                *l4PayloadLenOut = static_cast<std::uint16_t>(std::min<std::size_t>(rem, 0xFFFFu));
            }
            return out;
        }

        // Fragment header: classify and stop (no reassembly).
        if (next == IPPROTO_FRAGMENT) {
            if (rem < sizeof(ip6_frag)) {
                out.l4Status = L4Status::INVALID_OR_UNAVAILABLE_L4;
                out.proto = IPPROTO_FRAGMENT;
                return out;
            }
            const auto frag = reinterpret_cast<const ip6_frag *>(cur);
            out.l4Status = L4Status::FRAGMENT;
            out.proto = frag->ip6f_nxt;
            if (l4pOut) {
                *l4pOut = cur;
            }
            if (l4PayloadLenOut) {
                *l4PayloadLenOut = static_cast<std::uint16_t>(std::min<std::size_t>(rem, 0xFFFFu));
            }
            return out;
        }

        // Skip selected extension headers.
        if (next == IPPROTO_HOPOPTS || next == IPPROTO_ROUTING || next == IPPROTO_DSTOPTS) {
            if (rem < sizeof(ip6_ext)) {
                out.l4Status = L4Status::INVALID_OR_UNAVAILABLE_L4;
                out.proto = next;
                return out;
            }
            const auto ext = reinterpret_cast<const ip6_ext *>(cur);
            const std::size_t hdrLen = static_cast<std::size_t>(ext->ip6e_len + 1u) * 8u;
            if (hdrLen > rem) {
                out.l4Status = L4Status::INVALID_OR_UNAVAILABLE_L4;
                out.proto = ext->ip6e_nxt;
                return out;
            }
            next = ext->ip6e_nxt;
            cur += hdrLen;
            rem -= hdrLen;
            hdrs++;
            walked += hdrLen;
            continue;
        }

        if (next == IPPROTO_AH) {
            if (rem < sizeof(ip6_ext)) {
                out.l4Status = L4Status::INVALID_OR_UNAVAILABLE_L4;
                out.proto = next;
                return out;
            }
            const auto ext = reinterpret_cast<const ip6_ext *>(cur);
            const std::size_t hdrLen = static_cast<std::size_t>(ext->ip6e_len + 2u) * 4u;
            if (hdrLen > rem) {
                out.l4Status = L4Status::INVALID_OR_UNAVAILABLE_L4;
                out.proto = ext->ip6e_nxt;
                return out;
            }
            next = ext->ip6e_nxt;
            cur += hdrLen;
            rem -= hdrLen;
            hdrs++;
            walked += hdrLen;
            continue;
        }

        // Anything else is treated as a legal terminal other-protocol.
        out.l4Status = L4Status::OTHER_TERMINAL;
        out.proto = next;
        if (l4pOut) {
            *l4pOut = cur;
        }
        if (l4PayloadLenOut) {
            *l4PayloadLenOut = static_cast<std::uint16_t>(std::min<std::size_t>(rem, 0xFFFFu));
        }
        return out;
    }
}

