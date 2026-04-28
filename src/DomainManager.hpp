/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <CustomList.hpp>
#include <DomainList.hpp>
#include <CustomRules.hpp>
#include <DomainPolicySourcesMetrics.hpp>
#include <Stats.hpp>
#include <BlockingList.hpp>
#include <vector>
#include <shared_mutex>
#include <mutex>
#include <ctime>
#include <optional>

class DomainManager {
private:
    using NamesMap = std::unordered_map<std::string, const Domain::Ptr>;
    using IPv4Map = std::unordered_map<Address<IPv4>, const Domain::Ptr>;
    using IPv6Map = std::unordered_map<Address<IPv6>, const Domain::Ptr>;

    Saver _saver{settings.saveDomains};

    NamesMap _byName;
    std::shared_mutex _mutexByName;
    IPv4Map _byIPv4;
    IPv6Map _byIPv6;
    std::shared_mutex _mutexByIP;

    DomainList _blacklist;
    DomainList _whitelist;
    CustomList _customBlacklist;
    CustomList _customWhitelist;
    CustomRules _blackRules;
    CustomRules _whiteRules;

    Domain::Ptr _anonymousDom{make("anonymous domains")};

    DomainPolicySourcesMetrics _domainSourcesMetrics;

public:
    DomainManager();

    ~DomainManager();

    DomainManager(const DomainManager &) = delete;

    const Domain::Ptr anonymousDom() { return _anonymousDom; }

    void start(std::vector<BlockingList> blockingLists);

    const Domain::Ptr make(const std::string &&name);

    const Domain::Ptr find(const std::string &name);

    template <class IP> const Domain::Ptr find(const Address<IP> &ip);

    void fixDomainsColors();

    bool blocked(const Domain::Ptr &domain);

    bool authorized(const Domain::Ptr &domain);

    // Optional per-rule attribution for device-wide allow/block decisions.
    // Returns nullopt when the decision came from device-wide custom list, or when no rule matched.
    std::optional<Rule::Id> authorizedRuleId(const Domain::Ptr &domain);
    std::optional<Rule::Id> blockedRuleId(const Domain::Ptr &domain);

    void observeDomainPolicySource(const DomainPolicySource source, const bool blocked) noexcept {
        _domainSourcesMetrics.observe(source, blocked);
    }

    DomainPolicySourcesSnapshot domainPolicySourcesSnapshot() const noexcept {
        return _domainSourcesMetrics.snapshot();
    }

    void resetDomainPolicySources() noexcept { _domainSourcesMetrics.reset(); }

    template <class IP> void addIP(const Domain::Ptr &domain, const Address<IP> &ip);

    // Atomically insert into domain IP set and global IP->Domain map under proper lock ordering
    // (Domain lock -> Global lock). Overloads provided for IPv4/IPv6 to avoid template
    // definitions in headers that would require additional includes.
    void addIPBoth(const Domain::Ptr &domain, const Address<IPv4> &ip);
    void addIPBoth(const Domain::Ptr &domain, const Address<IPv6> &ip);

    void removeIPs(const Domain::Ptr &domain);

    void addCustomDomain(const std::string &name, const Stats::Color color);

    void removeCustomDomain(const std::string &name, const Stats::Color color);

    // Snapshot custom allow/block domains. Order is unspecified (caller may sort if needed).
    std::vector<std::string> snapshotCustomDomains(const Stats::Color color) const;

    void printCustomDomains(std::ostream &out, const Stats::Color color);

    void addCustomRule(const Rule::Ptr rule, const bool compile, const Stats::Color color);

    void removeCustomRule(const Rule::Ptr rule, const bool compile, const Stats::Color color);

    // Snapshot custom allow/block ruleIds. Order is unspecified (caller may sort if needed).
    std::vector<Rule::Id> snapshotCustomRuleIds(const Stats::Color color) const;

    void buildCustomRules(const Stats::Color color);

    void printCustomRules(std::ostream &out, const Stats::Color color);

    void save();

    void restore();

    void reset();

    template <class... TypeStats>
    void printDomains(std::ostream &out, const std::string &subname, const Stats::Color cs,
                      const Stats::View view, const TypeStats... ts);

    void printBlackDomainsStats(std::ostream &out, const Stats::View view);

    uint32_t addDomainsToList(std::string listId, uint8_t blockMask, bool clear,
                          std::vector<std::string> domains, Stats::Color color);

    DomainList::ImportResult importDomainsToListAtomic(const std::string &listId, uint8_t blockMask,
                                                       bool clear,
                                                       const std::vector<std::string> &domains,
                                                       Stats::Color color, bool enabled);

    bool removeDomainList(std::string listId, Stats::Color color);

    void switchListColor(std::string listId, Stats::Color color);

    bool enableList(std::string listId, uint8_t blockMask, Stats::Color color);

    bool disableList(std::string listId, Stats::Color color);

    uint32_t getDomainsCount(Stats::Color color);

    void changeBlockMask(std::string listId, uint8_t blockMask, Stats::Color color);

    void printDomainsFromList(std::string listId, Stats::Color color, std::ostream &out);

private:
    CustomList &customList(const Stats::Color color) {
        return color == Stats::BLACK ? _customBlacklist : _customWhitelist;
    }

    const CustomList &customList(const Stats::Color color) const {
        return color == Stats::BLACK ? _customBlacklist : _customWhitelist;
    }

    CustomRules &customRules(const Stats::Color color) {
        return color == Stats::BLACK ? _blackRules : _whiteRules;
    }

    const CustomRules &customRules(const Stats::Color color) const {
        return color == Stats::BLACK ? _blackRules : _whiteRules;
    }

    void initDomain(const Domain::Ptr &domain);

    template <class IP> auto &byIP();

    const Domain::Ptr create(const std::string &&name);
};

template <class IP> auto &DomainManager::byIP() {
    if constexpr (std::is_same_v<IP, IPv4>) {
        return _byIPv4;
    } else {
        return _byIPv6;
    }
}

template <class IP> const Domain::Ptr DomainManager::find(const Address<IP> &ip) {
    const std::shared_lock<std::shared_mutex> lock(_mutexByIP);
    const auto it = byIP<IP>().find(ip);
    return it != byIP<IP>().end() ? it->second : nullptr;
}

template <class IP> void DomainManager::addIP(const Domain::Ptr &domain, const Address<IP> &ip) {
    const std::lock_guard lock(_mutexByIP);
    byIP<IP>().try_emplace(ip, domain);
}

/* template addIPBoth removed: keep single source of truth in .cpp IPv4/IPv6 overloads */

template <class... TypeStats>
void DomainManager::printDomains(std::ostream &out, const std::string &subname,
                                 const Stats::Color cs, const Stats::View view,
                                 const TypeStats... ts) {
    const std::lock_guard lock(_mutexByName);
    out << "[";
    bool first = true;
    for (const auto &[name, domain] : _byName) {
        if (domain->color() == cs && domain->stats().hasData(view) &&
            (subname.size() == 0 || name.find(subname) != std::string::npos)) {
            when(first, out << ",");
            domain->print(out, domain->stats(), view, ts...);
        }
    }
    out << "]";
}

extern DomainManager domManager;
