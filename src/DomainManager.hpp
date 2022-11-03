/*
 * Copyright 2019 - 2022, iodé Technologies
 *
 * This file is part of the iode-snort project.
 *
 * iode-snort is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * iode-snort is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with iode-snort. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <CustomList.hpp>
#include <DomainList.hpp>

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
    CustomList _customBlacklist{[&](const std::string &name) { return find(name); }};
    CustomList _customWhitelist{[&](const std::string &name) { return find(name); }};

    Domain::Ptr _anonymousDom{make("anonymous domains")};

public:
    DomainManager();

    ~DomainManager();

    DomainManager(const DomainManager &) = delete;

    CustomList &customList(const Stats::Color color) {
        return color == Stats::BLACK ? _customBlacklist : _customWhitelist;
    }

    const Domain::Ptr anonymousDom() { return _anonymousDom; }

    void start();

    const Domain::Ptr make(const std::string &&name);

    const Domain::Ptr find(const std::string &name);

    template <class IP> const Domain::Ptr find(const Address<IP> &ip);

    void fixDomainsColors();

    bool blocked(const Domain::Ptr &domain);

    bool authorized(const Domain::Ptr &domain);

    template <class IP> void addIP(const Domain::Ptr &domain, const Address<IP> &ip);

    void removeIPs(const Domain::Ptr &domain);

    void save();

    void restore();

    void reset();

    template <class... TypeStats>
    void printDomains(std::ostream &out, const std::string &subname, const Stats::Color cs,
                      const Stats::View view, const TypeStats... ts);

    void printBlackDomainsStats(std::ostream &out, const Stats::View view);

private:
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
