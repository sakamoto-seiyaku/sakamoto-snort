/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <Settings.hpp>

struct IPv4 {
    using Addr = in_addr;
    using Header = iphdr;
    static constexpr uint32_t family = AF_INET;
    static constexpr uint32_t strLen = INET_ADDRSTRLEN;
    static constexpr const char *name = "ipv4";
    static constexpr const char *iptables = Settings::iptablesShell;

    static uint16_t hdrLen(const iphdr *ip) { return ip->ihl * 4; }

    static uint32_t payloadProto(const iphdr *ip) { return ip->protocol; }

    static void fillSockAddr(sockaddr_storage &sad, const uint8_t *rawAddress) {
        auto *sa = reinterpret_cast<sockaddr_in *>(&sad);
        sa->sin_family = family;
        std::memcpy(&sa->sin_addr, rawAddress, sizeof(in_addr));
    }
};

struct IPv6 {
    using Addr = in6_addr;
    using Header = ipv6hdr;
    static constexpr uint32_t family = AF_INET6;
    static constexpr uint32_t strLen = INET6_ADDRSTRLEN;
    static constexpr const char *name = "ipv6";
    static constexpr const char *iptables = Settings::ip6tablesShell;

    static uint16_t hdrLen(const ipv6hdr *ip) { return sizeof(ipv6hdr); }

    static uint32_t payloadProto(const ipv6hdr *ip) { return ip->nexthdr; }

    static void fillSockAddr(sockaddr_storage &sad, const uint8_t *rawAddress) {
        auto *sa = reinterpret_cast<sockaddr_in6 *>(&sad);
        sa->sin6_family = family;
        std::memcpy(&sa->sin6_addr, rawAddress, sizeof(in6_addr));
    }
};
