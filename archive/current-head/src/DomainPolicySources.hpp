/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <array>
#include <cstdint>

// DomainPolicySource is a DNS-side attribution of which DomainPolicy branch produced the verdict.
// It is intentionally coarse-grained (no ruleId/listId attribution).
enum class DomainPolicySource : uint8_t {
    CUSTOM_WHITELIST = 0,
    CUSTOM_BLACKLIST = 1,
    CUSTOM_RULE_WHITE = 2,
    CUSTOM_RULE_BLACK = 3,
    // Domain-only device-wide logic (DomainManager authorized/blocked).
    // Historical name: "GLOBAL_*" (kept out of the interface to avoid semantic confusion).
    DOMAIN_DEVICE_WIDE_AUTHORIZED = 4,
    DOMAIN_DEVICE_WIDE_BLOCKED = 5,
    // Final fallback: app.blockMask & domain.blockMask.
    MASK_FALLBACK = 6,
};

inline constexpr std::array<DomainPolicySource, 7> kDomainPolicySources = {
    DomainPolicySource::CUSTOM_WHITELIST,  DomainPolicySource::CUSTOM_BLACKLIST,
    DomainPolicySource::CUSTOM_RULE_WHITE, DomainPolicySource::CUSTOM_RULE_BLACK,
    DomainPolicySource::DOMAIN_DEVICE_WIDE_AUTHORIZED, DomainPolicySource::DOMAIN_DEVICE_WIDE_BLOCKED,
    DomainPolicySource::MASK_FALLBACK,
};

inline constexpr const char *domainPolicySourceStr(const DomainPolicySource s) noexcept {
    switch (s) {
    case DomainPolicySource::CUSTOM_WHITELIST:
        return "CUSTOM_WHITELIST";
    case DomainPolicySource::CUSTOM_BLACKLIST:
        return "CUSTOM_BLACKLIST";
    case DomainPolicySource::CUSTOM_RULE_WHITE:
        return "CUSTOM_RULE_WHITE";
    case DomainPolicySource::CUSTOM_RULE_BLACK:
        return "CUSTOM_RULE_BLACK";
    case DomainPolicySource::DOMAIN_DEVICE_WIDE_AUTHORIZED:
        return "DOMAIN_DEVICE_WIDE_AUTHORIZED";
    case DomainPolicySource::DOMAIN_DEVICE_WIDE_BLOCKED:
        return "DOMAIN_DEVICE_WIDE_BLOCKED";
    case DomainPolicySource::MASK_FALLBACK:
        return "MASK_FALLBACK";
    }
    return "UNKNOWN";
}
