/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <cstdint>

// Datapath L4 parse classification used to:
// - explain when ports are available/unavailable
// - drive IPRULES matching semantics (e.g. proto=other vs invalid/unavailable)
// - serialize stable vNext pkt stream fields
enum class L4Status : std::uint8_t {
    KNOWN_L4 = 0,
    OTHER_TERMINAL = 1,
    FRAGMENT = 2,
    INVALID_OR_UNAVAILABLE_L4 = 3,
};

// Small stack-only parse result shared by IPv4/IPv6 listener paths.
struct L4ParseResult {
    L4Status l4Status = L4Status::KNOWN_L4;
    // Terminal/declared proto for stream (`protocol`) purposes (IPv6: after ext-header walking).
    std::uint16_t proto = 0;
    std::uint16_t srcPort = 0;
    std::uint16_t dstPort = 0;
    // 1 only when ports were safely parsed (known-l4 TCP/UDP).
    std::uint8_t portsAvailable = 0;
};

