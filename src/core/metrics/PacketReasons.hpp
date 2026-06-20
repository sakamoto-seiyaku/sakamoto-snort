/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <array>
#include <cstdint>

enum class PacketReasonId : uint8_t {
    IFACE_BLOCK = 0,
    IP_LEAK_BLOCK = 1,
    ALLOW_DEFAULT = 2,
    IP_RULE_ALLOW = 3,
    IP_RULE_BLOCK = 4,
};

inline constexpr std::array<PacketReasonId, 5> kPacketReasonIds = {
    PacketReasonId::IFACE_BLOCK,
    PacketReasonId::IP_LEAK_BLOCK,
    PacketReasonId::ALLOW_DEFAULT,
    PacketReasonId::IP_RULE_ALLOW,
    PacketReasonId::IP_RULE_BLOCK,
};

inline constexpr const char *packetReasonIdStr(const PacketReasonId id) noexcept {
    switch (id) {
    case PacketReasonId::IFACE_BLOCK:
        return "IFACE_BLOCK";
    case PacketReasonId::IP_LEAK_BLOCK:
        return "IP_LEAK_BLOCK";
    case PacketReasonId::ALLOW_DEFAULT:
        return "ALLOW_DEFAULT";
    case PacketReasonId::IP_RULE_ALLOW:
        return "IP_RULE_ALLOW";
    case PacketReasonId::IP_RULE_BLOCK:
        return "IP_RULE_BLOCK";
    }
    return "UNKNOWN";
}

