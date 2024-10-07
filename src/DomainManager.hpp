/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <CustomList.hpp>
#include <DomainList.hpp>
#include <CustomRules.hpp>
#include <Stats.hpp>
#include <BlockingList.hpp>
#include <vector>

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

    template <class IP> void addIP(const Domain::Ptr &domain, const Address<IP> &ip);

    void removeIPs(const Domain::Ptr &domain);

    void addCustomDomain(const std::string &name, const Stats::Color color);

    void removeCustomDomain(const std::string &name, const Stats::Color color);

    void printCustomDomains(std::ostream &out, const Stats::Color color);

    void addCustomRule(const Rule::Ptr rule, const bool compile, const Stats::Color color);

    void removeCustomRule(const Rule::Ptr rule, const bool compile, const Stats::Color color);

    void buildCustomRules(const Stats::Color color);

    void printCustomRules(std::ostream &out, const Stats::Color color);

    void save();

    void restore();

    void reset();

    template <class... TypeStats>
    void printDomains(std::ostream &out, const std::string &subname, const Stats::Color cs,
                      const Stats::View view, const TypeStats... ts);

    void printBlackDomainsStats(std::ostream &out, const Stats::View view);

    void addDomainsToList(std::string listId, uint8_t blockMask, bool clear,
                          std::vector<std::string> domains, Stats::Color color);

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

    CustomRules &customRules(const Stats::Color color) {
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
    const std::shared_lock_guard lock(_mutexByIP);
    const auto it = byIP<IP>().find(ip);
    return it != byIP<IP>().end() ? it->second : nullptr;
}

template <class IP> void DomainManager::addIP(const Domain::Ptr &domain, const Address<IP> &ip) {
    const std::lock_guard lock(_mutexByIP);
    byIP<IP>().try_emplace(ip, domain);
}

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
