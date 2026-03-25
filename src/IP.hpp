/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <cstring>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <Settings.hpp>

#if defined(__has_include)
#if __has_include(<linux/ipv6.h>)
#include <linux/ipv6.h>
#define SUCRE_HAS_LINUX_IPV6HDR 1
#endif
#endif

#ifndef SUCRE_HAS_LINUX_IPV6HDR
#define SUCRE_HAS_LINUX_IPV6HDR 0
#endif

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
#if SUCRE_HAS_LINUX_IPV6HDR
    using Header = ipv6hdr;
#else
    using Header = ip6_hdr;
#endif
    static constexpr uint32_t family = AF_INET6;
    static constexpr uint32_t strLen = INET6_ADDRSTRLEN;
    static constexpr const char *name = "ipv6";
    static constexpr const char *iptables = Settings::ip6tablesShell;

    static uint16_t hdrLen(const Header *ip) { return sizeof(*ip); }

    static uint32_t payloadProto(const Header *ip) {
#if SUCRE_HAS_LINUX_IPV6HDR
        return ip->nexthdr;
#else
        return ip->ip6_nxt;
#endif
    }

    static void fillSockAddr(sockaddr_storage &sad, const uint8_t *rawAddress) {
        auto *sa = reinterpret_cast<sockaddr_in6 *>(&sad);
        sa->sin6_family = family;
        std::memcpy(&sa->sin6_addr, rawAddress, sizeof(in6_addr));
    }
};
