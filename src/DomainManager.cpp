/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <thread>

#include <DomainManager.hpp>

DomainManager::DomainManager() {}

DomainManager::~DomainManager() {}

void DomainManager::start() {
    _blacklist.add(settings.defaultBlacklist);
    _whitelist.add(settings.defaultWhitelist);
}

const Domain::Ptr DomainManager::make(const std::string &&name) {
    Domain::Ptr domain = find(name) ?: create(std::move(name));
    initDomain(domain);
    return domain;
}

const Domain::Ptr DomainManager::find(const std::string &name) {
    const std::shared_lock_guard lock(_mutexByName);
    const auto it = _byName.find(name);
    return it != _byName.end() ? it->second : nullptr;
}

const Domain::Ptr DomainManager::create(const std::string &&name) {
    const std::lock_guard lock(_mutexByName);
    return _byName.try_emplace(name, std::make_shared<Domain>(std::move(name))).first->second;
}

void DomainManager::fixDomainsColors() {
    for (const auto &[_, domain] : _byName) {
        initDomain(domain);
    }
}

void DomainManager::initDomain(const Domain::Ptr &domain) {
    uint8_t blockMask = 0;
    auto cs = Stats::GREY;
    if (_whitelist.blockMask(domain->name()) == 0) {
        blockMask = _blacklist.blockMask(domain->name());
        if (blockMask & settings.standardListBit) {
            cs = Stats::BLACK;
        } else if (blockMask & settings.reinforcedListBit) {
            cs = Stats::WHITE;
        }
    }
    domain->color(cs);
    domain->blockMask(blockMask);
}

bool DomainManager::blocked(const Domain::Ptr &domain) { return _customBlacklist.exists(domain); }

bool DomainManager::authorized(const Domain::Ptr &domain) {
    return _customWhitelist.exists(domain);
}

void DomainManager::removeIPs(const Domain::Ptr &domain) {
    const std::lock_guard lock(_mutexByIP);
    for (const auto ip : domain->ips<IPv4>()) {
        byIP<IPv4>().erase(ip);
    }
    for (const auto ip : domain->ips<IPv6>()) {
        byIP<IPv6>().erase(ip);
    }
    domain->clearIPs();
}

void DomainManager::save() {
    _saver.save([&] {
        _saver.write<uint32_t>(_byName.size());
        for (const auto &[_, domain] : _byName) {
            domain->save(_saver);
        }
        _customBlacklist.save(_saver);
        _customWhitelist.save(_saver);
    });
}

void DomainManager::restore() {
    _saver.restore([&] {
        uint32_t nb = _saver.read<uint32_t>();
        for (uint32_t i = 0; i < nb; ++i) {
            std::string name;
            _saver.readDomName(name);
            const auto domain = create(std::move(name));
            domain->restore(_saver);
            for (const auto &ip : domain->ips<IPv4>()) {
                addIP<IPv4>(domain, ip);
            }
            for (const auto &ip : domain->ips<IPv6>()) {
                addIP<IPv6>(domain, ip);
            }
        }
        _customBlacklist.restore(_saver);
        _customWhitelist.restore(_saver);
    });
}

void DomainManager::reset() {
    _byIPv4.clear();
    _byIPv6.clear();
    _byName.clear();
    _customBlacklist.reset();
    _customWhitelist.reset();
}

void DomainManager::printBlackDomainsStats(std::ostream &out, const Stats::View view) {
    const std::shared_lock_guard lock(_mutexByName);
    uint32_t blackAccepted = 0;
    uint32_t blackBlocked = 0;
    for (const auto &[_, domain] : _byName) {
        if (domain->color() == Stats::BLACK && domain->stats().hasBlackAccepted(view)) {
            ++blackAccepted;
        }
        if (domain->stats().hasBlackBlocked(view)) {
            ++blackBlocked;
        }
    }
    out << "{" << JSF("blackBlocked") << blackBlocked << "," << JSF("blackAccepted")
        << blackAccepted << "}";
}
