/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <thread>
#include <dirent.h>

#include <RulesManager.hpp>
#include <DomainManager.hpp>
#include <Domain.hpp>

DomainManager::DomainManager() {}

DomainManager::~DomainManager() {}

void DomainManager::start(std::vector<BlockingList> blockingLists) {
    // Parse blockingLists.size() to string to log it
    for (auto it = blockingLists.begin(); it != blockingLists.end(); ++it) {
        if (it->isEnabled()) {
            if (it->getColor() == Stats::BLACK) {
                _blacklist.read(it->getId(), it->getBlockMask());
            } else if (it->getColor() == Stats::WHITE) {
                _whitelist.read(it->getId(), it->getBlockMask());
            }
        } else {
            if (it->getColor() == Stats::BLACK) {
                _blacklist.disable(it->getId());
            } else if (it->getColor() == Stats::WHITE) {
                _whitelist.disable(it->getId());
            }
        }
    }
}

const Domain::Ptr DomainManager::make(const std::string &&name) {
    Domain::Ptr domain = find(name);
    if (!domain) {
        domain = create(std::move(name));
    }
    initDomain(domain);
    return domain;
}

const Domain::Ptr DomainManager::find(const std::string &name) {
    const std::shared_lock<std::shared_mutex> lock(_mutexByName);
    const auto it = _byName.find(name);
    return it != _byName.end() ? it->second : nullptr;
}

const Domain::Ptr DomainManager::create(const std::string &&name) {
    const std::lock_guard lock(_mutexByName);
    return _byName.try_emplace(name, std::make_shared<Domain>(std::move(name))).first->second;
}

void DomainManager::fixDomainsColors() {
    const std::shared_lock<std::shared_mutex> lock(_mutexByName);
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

bool DomainManager::blocked(const Domain::Ptr &domain) {
    return _customBlacklist.exists(domain) ||
           (_blackRules.match(domain) && !_whiteRules.match(domain));
}

bool DomainManager::authorized(const Domain::Ptr &domain) {
    return _customWhitelist.exists(domain) || _whiteRules.match(domain);
}

std::optional<Rule::Id> DomainManager::authorizedRuleId(const Domain::Ptr &domain) {
    if (_customWhitelist.exists(domain)) {
        return std::nullopt;
    }
    // Deterministic attribution: pick the smallest matching ruleId.
    return _whiteRules.matchFirstRuleId(domain);
}

std::optional<Rule::Id> DomainManager::blockedRuleId(const Domain::Ptr &domain) {
    if (_customBlacklist.exists(domain)) {
        return std::nullopt;
    }
    // Only count/attribute block rules that actually win (white overrides black).
    if (!_blackRules.match(domain) || _whiteRules.match(domain)) {
        return std::nullopt;
    }
    return _blackRules.matchFirstRuleId(domain);
}

void DomainManager::removeIPs(const Domain::Ptr &domain) {
    // Strong consistency: hold domain lock first, then global IP map lock; delete mappings and
    // clear per-domain IP sets in the same critical section to avoid races.
    domain->withIPsLocked([&](auto &ipv4, auto &ipv6) {
        const std::lock_guard<std::shared_mutex> glock(_mutexByIP); // Domain -> Global lock order
        for (const auto &ip : ipv4) {
            _byIPv4.erase(ip);
        }
        for (const auto &ip : ipv6) {
            _byIPv6.erase(ip);
        }
        ipv4.clear();
        ipv6.clear();
    });
}

void DomainManager::addIPBoth(const Domain::Ptr &domain, const Address<IPv4> &ip) {
    domain->withAddedIPLocked<IPv4>(ip, [&]() {
        const std::lock_guard<std::shared_mutex> glock(_mutexByIP); // Domain -> Global
        _byIPv4.try_emplace(ip, domain);
    });
}

void DomainManager::addIPBoth(const Domain::Ptr &domain, const Address<IPv6> &ip) {
    domain->withAddedIPLocked<IPv6>(ip, [&]() {
        const std::lock_guard<std::shared_mutex> glock(_mutexByIP); // Domain -> Global
        _byIPv6.try_emplace(ip, domain);
    });
}

void DomainManager::addCustomDomain(const std::string &name, const Stats::Color color) {
    const auto domain = make(std::move(name));
    customList(color).add(domain);
}

void DomainManager::removeCustomDomain(const std::string &name, const Stats::Color color) {
    if (const auto domain = find(std::move(name))) {
        customList(color).remove(domain);
    }
}

std::vector<std::string> DomainManager::snapshotCustomDomains(const Stats::Color color) const {
    return customList(color).snapshotNames();
}

void DomainManager::printCustomDomains(std::ostream &out, const Stats::Color color) {
    customList(color).print(out);
}

void DomainManager::addCustomRule(const Rule::Ptr rule, const bool compile,
                                  const Stats::Color color) {
    customRules(color).add(rule, compile);
}

void DomainManager::removeCustomRule(const Rule::Ptr rule, const bool compile,
                                     const Stats::Color color) {
    customRules(color).remove(rule, compile);
}

std::vector<Rule::Id> DomainManager::snapshotCustomRuleIds(const Stats::Color color) const {
    return customRules(color).snapshotRuleIds();
}

std::vector<ControlVNextStreamExplain::DnsListEntrySnapshot>
DomainManager::matchingCustomListExplainSnapshots(const Domain::Ptr &domain, const Stats::Color color,
                                                  const std::string &scope,
                                                  const std::string &action) const {
    return customList(color).matchingExplainSnapshots(domain, scope, action);
}

std::vector<ControlVNextStreamExplain::DnsRuleSnapshot>
DomainManager::matchingCustomRuleExplainSnapshots(
    const Domain::Ptr &domain, const Stats::Color color, const std::string &scope,
    const std::string &action, const std::optional<Rule::Id> winningRuleId,
    bool &truncated, std::optional<std::uint32_t> &omittedCandidateCount) {
    return customRules(color).matchingExplainSnapshots(domain, scope, action, winningRuleId,
                                                       truncated, omittedCandidateCount);
}

void DomainManager::buildCustomRules(const Stats::Color color) { customRules(color).build(); }

void DomainManager::printCustomRules(std::ostream &out, const Stats::Color color) {
    customRules(color).print(out);
}

void DomainManager::save() {
    _saver.save([&] {
        const std::shared_lock<std::shared_mutex> lock(_mutexByName);
        _saver.write<uint32_t>(_byName.size());
        for (const auto &[_, domain] : _byName) {
            domain->save(_saver);
        }
        _customBlacklist.save(_saver);
        _customWhitelist.save(_saver);
        _blackRules.save(_saver);
        _whiteRules.save(_saver);
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
        rulesManager.restoreCustomRules(_saver, nullptr, Stats::BLACK);
        rulesManager.restoreCustomRules(_saver, nullptr, Stats::WHITE);
        // _blackRules->restore(_saver);
        // _whiteRules->restore(_saver);
    });
}

void DomainManager::reset() {
    _domainSourcesMetrics.reset();
    {
        const std::scoped_lock lock(_mutexByName, _mutexByIP);
        _byIPv4.clear();
        _byIPv6.clear();
        _byName.clear();
        // Keep the long-lived anonymous domain discoverable after a full reset.
        _byName.try_emplace(_anonymousDom->name(), _anonymousDom);
    }
    _customBlacklist.reset();
    _customWhitelist.reset();
    _blackRules.reset();
    _whiteRules.reset();
    _blacklist.reset();
    _whitelist.reset();
    if (auto dir = opendir(Settings::saveDirDomainListsPath().c_str())) {
        dirent *de;
        while ((de = readdir(dir)) != nullptr) {
            if (de->d_type == DT_REG) {
                std::remove((Settings::saveDirDomainListsPath() + de->d_name).c_str());
            }
        }
        closedir(dir);
    } else {
        LOG(ERROR) << Settings::saveDirDomainListsPath() << " dir not exists";
    }
}

void DomainManager::printBlackDomainsStats(std::ostream &out, const Stats::View view) {
    const std::shared_lock<std::shared_mutex> lock(_mutexByName);
    uint32_t blocked = 0;
    uint32_t stdLeaked = 0;
    uint32_t rfcLeaked = 0;
    for (const auto &[_, domain] : _byName) {
        if (domain->stats().hasBlocked(view)) {
            ++blocked;
        }
        if (domain->stats().hasAccepted(view)) {
            if (domain->color() == Stats::BLACK) {
                ++stdLeaked;
            } else if (domain->color() == Stats::WHITE) {
                ++rfcLeaked;
            }
        }
    }
    out << "{" << JSF("blocked") << blocked << "," << JSF("stdLeaked") << stdLeaked << ","
        << JSF("rfcLeaked") << rfcLeaked << "}";
}

uint32_t DomainManager::addDomainsToList(std::string listId, uint8_t blockMask, bool clear,
                                         std::vector<std::string> domains, Stats::Color color) {
    const std::shared_lock<std::shared_mutex> lock(_mutexByName);
    if (color == Stats::BLACK) {
        return _blacklist.write(listId, domains, blockMask, clear);
    } else if (color == Stats::WHITE) {
        return _whitelist.write(listId, domains, blockMask, clear);
    }
    return 0;
}

DomainList::ImportResult DomainManager::importDomainsToListAtomic(
    const std::string &listId, const uint8_t blockMask, const bool clear,
    const std::vector<std::string> &domains, const Stats::Color color, const bool enabled) {
    const std::shared_lock<std::shared_mutex> lock(_mutexByName);
    if (color == Stats::BLACK) {
        return _blacklist.importAtomic(listId, domains, blockMask, clear, enabled);
    }
    if (color == Stats::WHITE) {
        return _whitelist.importAtomic(listId, domains, blockMask, clear, enabled);
    }
    return {};
}

bool DomainManager::removeDomainList(std::string listId, Stats::Color color) {
    if (color == Stats::BLACK) {
        return _blacklist.remove(listId);
    } else if (color == Stats::WHITE) {
        return _whitelist.remove(listId);
    }
    return false;
}

void DomainManager::switchListColor(std::string listId, Stats::Color color) {
    if (color == Stats::BLACK) {
        _blacklist.set(listId, _whitelist.get(listId));
        _whitelist.erase(listId);
    } else if (color == Stats::WHITE) {
        _whitelist.set(listId, _blacklist.get(listId));
        _blacklist.erase(listId);
    }
}

bool DomainManager::enableList(std::string listId, uint8_t blockMask, Stats::Color color) {
    if (color == Stats::BLACK) {
        return _blacklist.enable(listId, blockMask);
    } else if (color == Stats::WHITE) {
        return _whitelist.enable(listId, blockMask);
    }
    return false;
}

bool DomainManager::disableList(std::string listId, Stats::Color color) {
    if (color == Stats::BLACK) {
        return _blacklist.disable(listId);
    } else if (color == Stats::WHITE) {
        return _whitelist.disable(listId);
    }
    return false;
}

uint32_t DomainManager::getDomainsCount(Stats::Color color) {
    if (color == Stats::BLACK) {
        return _blacklist.size();
    } else if (color == Stats::WHITE) {
        return _whitelist.size();
    }
    return 0;
}

void DomainManager::changeBlockMask(std::string listId, uint8_t blockMask, Stats::Color color) {
    if (color == Stats::BLACK) {
        _blacklist.changeBlockMask(listId, blockMask);
    } else if (color == Stats::WHITE) {
        _whitelist.changeBlockMask(listId, blockMask);
    }
}

void DomainManager::printDomainsFromList(std::string listId, Stats::Color color,
                                         std::ostream &out) {
    if (color == Stats::BLACK) {
        _blacklist.printDomains(listId, out);
    } else if (color == Stats::WHITE) {
        _whitelist.printDomains(listId, out);
    }
}
