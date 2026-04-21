/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <charconv>
#include <cctype>
#include <cstdint>
#include <string_view>

namespace IpRulesContract {

// Apply contract: [A-Za-z0-9._:-]{1,64}
[[nodiscard]] inline bool isValidClientRuleId(const std::string_view id) noexcept {
    if (id.empty() || id.size() > 64) {
        return false;
    }
    for (const unsigned char ch : id) {
        if (std::isalnum(ch) != 0) {
            continue;
        }
        if (ch == '.' || ch == '_' || ch == ':' || ch == '-') {
            continue;
        }
        return false;
    }
    return true;
}

// IPv4 CIDR canonicalization helper (mask host bits to zero).
[[nodiscard]] inline std::uint32_t maskFromPrefix(const std::uint8_t prefix) noexcept {
    if (prefix == 0) {
        return 0u;
    }
    if (prefix >= 32) {
        return 0xFFFFFFFFu;
    }
    return 0xFFFFFFFFu << (32u - prefix);
}

template <class T> [[nodiscard]] inline bool parseDec(const std::string_view s, T &out) noexcept {
    if (s.empty()) {
        return false;
    }
    T v{};
    const char *begin = s.data();
    const char *end = s.data() + s.size();
    const auto res = std::from_chars(begin, end, v);
    if (res.ec != std::errc() || res.ptr != end) {
        return false;
    }
    out = v;
    return true;
}

} // namespace IpRulesContract

