/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <IpRulesEngine.hpp>
#include <Rule.hpp>
#include <Stats.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace PolicyCheckpoint {

constexpr std::uint32_t kFormatVersion = 1;
constexpr std::uint32_t kSlotCount = 3;
constexpr std::uint64_t kMaxSlotBytes = 64ull * 1024ull * 1024ull;

struct Status {
    bool ok = false;
    std::string code;
    std::string message;
};

struct SlotMetadata {
    std::uint32_t slot = 0;
    bool present = false;
    std::uint32_t formatVersion = 0;
    std::uint64_t sizeBytes = 0;
    std::uint64_t createdAt = 0;
};

struct DeviceConfigSnapshot {
    bool blockEnabled = true;
    std::uint8_t blockMask = 0;
    std::uint8_t blockIface = 0;
    bool reverseDns = false;
    bool ipRulesEnabled = false;
};

struct AppConfigSnapshot {
    std::uint32_t uid = 0;
    std::uint8_t blockMask = 0;
    std::uint8_t blockIface = 0;
    bool useCustomList = false;
};

struct DomainRuleSnapshot {
    std::uint32_t ruleId = 0;
    Rule::Type type = Rule::DOMAIN;
    std::string pattern;
};

struct DomainRulesSnapshot {
    std::uint32_t nextRuleId = 0;
    std::vector<DomainRuleSnapshot> rules;
};

struct DomainPolicyScopeSnapshot {
    std::vector<std::string> allowDomains;
    std::vector<std::string> blockDomains;
    std::vector<std::uint32_t> allowRuleIds;
    std::vector<std::uint32_t> blockRuleIds;
};

struct AppDomainPolicySnapshot {
    std::uint32_t uid = 0;
    DomainPolicyScopeSnapshot policy;
};

struct DomainPolicySnapshot {
    DomainPolicyScopeSnapshot device;
    std::vector<AppDomainPolicySnapshot> apps;
};

struct DomainListSnapshot {
    std::string listId;
    Stats::Color color = Stats::BLACK;
    std::uint8_t mask = 0;
    bool enabled = false;
    std::string url;
    std::string name;
    std::string updatedAt;
    std::string etag;
    bool outdated = true;
    std::uint32_t domainsCount = 0;
    std::vector<std::string> domains;
};

struct Bundle {
    std::uint32_t formatVersion = kFormatVersion;
    std::uint64_t createdAt = 0;
    DeviceConfigSnapshot deviceConfig;
    std::vector<AppConfigSnapshot> appConfigs;
    DomainRulesSnapshot domainRules;
    DomainPolicySnapshot domainPolicy;
    std::vector<DomainListSnapshot> domainLists;
    IpRulesEngine::PolicySnapshot ipRules;
};

[[nodiscard]] bool isValidSlot(std::uint32_t slot) noexcept;
[[nodiscard]] std::array<SlotMetadata, kSlotCount> listSlots();
[[nodiscard]] Status clearSlot(std::uint32_t slot, SlotMetadata &metadata);
[[nodiscard]] Status saveCurrentPolicyToSlot(std::uint32_t slot, SlotMetadata &metadata);
[[nodiscard]] Status readSlot(std::uint32_t slot, Bundle &bundle, SlotMetadata &metadata);
[[nodiscard]] Status stageBundleForRestore(const Bundle &bundle);
[[nodiscard]] Status restoreBundleToLivePolicy(const Bundle &bundle);

[[nodiscard]] Bundle captureLivePolicy();
[[nodiscard]] Status validateBundle(const Bundle &bundle);
[[nodiscard]] Status encodeBundle(const Bundle &bundle, std::string &out);
[[nodiscard]] Status decodeBundle(const std::string &data, Bundle &out);

} // namespace PolicyCheckpoint
