/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "BlockingListManager.hpp"
#include <fstream>

#include <DomainList.hpp>

DomainList::DomainList() {}

DomainList::~DomainList() {}

DomainList::DomsSet DomainList::get(std::string listId) { return _domainsByListId[listId]; }

void DomainList::set(std::string listId, DomsSet domains) {
    std::unique_lock lock(_mutex);
    _domainsByListId[listId] = domains;
}

uint8_t DomainList::blockMask(const std::string &domain) {
    const std::shared_lock_guard lock(_mutex);
    for (const auto &[_, domains] : _domainsByListId) {
        auto it = domains.find(domain);
        if (it != domains.end()) {
            return it->second;
        }
        auto first = domain.find_first_of('.');
        auto last = domain.find_last_of('.');
        while (first != last) {
            auto it = domains.find(domain.substr(first + 1));
            if (it != domains.end()) {
                return it->second;
            }
            first = domain.find_first_of('.', first + 1);
        }
    }

    return 0;
}

void DomainList::read(std::string listId, uint8_t blockMask) {
    const std::shared_lock_guard lock(_mutex);
    if (auto in = std::ifstream(settings.saveDirDomainLists + listId, std::ifstream::in);
        in.is_open()) {
        std::string hostname;
        DomsSet domains;
        while (in >> hostname) {
            auto [it, inserted] = domains.emplace(std::move(hostname), blockMask);
            if (!inserted) {
                it->second |= blockMask;
            }
        }
        _domainsByListId.emplace(listId, domains);
        in.close();
    } else {
        LOG(ERROR) << " List read error for list: " << listId;
    }
}

uint32_t DomainList::write(const std::string listId, const std::vector<std::string> domains,
                           uint8_t blockMask, bool clear) {
    std::unique_lock lock(_mutex);

    if (clear) {
        _domainsByListId.erase(listId);
        // Clear file content
        std::ofstream(settings.saveDirDomainLists + listId,
                      std::ofstream::out | std::ofstream::trunc)
            .close();
    }

    // 1. Collect matching list IDs
    std::vector<std::string> matchingListIds; 
    for (const auto &[otherListId, _] : _domainsByListId) {
        BlockingList *bl = blockingListManager.findListById(otherListId);
        if (bl && bl->getBlockMask() <= blockMask) {
            matchingListIds.push_back(otherListId);
        }
    }

    auto &targetSet = _domainsByListId[listId];
    std::ofstream out(settings.saveDirDomainLists + listId, std::ofstream::app);
    if (!out.is_open()) {
        LOG(ERROR) << __FUNCTION__ << " List write error for list: " << listId;
        return 0;
    }

    uint32_t addedCount = 0;
    for (const auto &domain : domains) {
        bool exists = false;
        // 2. Check only lists with matching blockMask
        for (const auto &matchingId : matchingListIds) {
            const auto &set = _domainsByListId.at(matchingId);
            if (set.find(domain) != set.end()) {
                exists = true;
                break;
            }
        }
        if (exists)
            continue;

        auto [it, inserted] = targetSet.emplace(domain, blockMask);
        if (inserted) {
            out << domain << std::endl;
            ++addedCount;
            if (addedCount == 0)
                break; // uint8_t overflow
        }
    }

    out.close();
    return addedCount;
}

bool DomainList::erase(std::string listId) {
    std::unique_lock lock(_mutex);
    auto it = _domainsByListId.find(listId);
    if (it != _domainsByListId.end()) {
        _domainsByListId.erase(it);
        return true;
    }
    return false;
}

void DomainList::reset() {
    std::unique_lock lock(_mutex);
    _domainsByListId.clear();
}

bool DomainList::enable(std::string listId, uint8_t blockMask) {
    const std::shared_lock_guard lock(_mutex);
    const std::string oldName = settings.saveDirDomainLists + listId + ".disabled";
    const std::string newName = settings.saveDirDomainLists + listId;
    if (std::rename(oldName.c_str(), newName.c_str())) {
        return false;
    } else {
        read(listId, blockMask);
        return true;
    }
}

bool DomainList::disable(std::string listId) {
    const std::shared_lock_guard lock(_mutex);
    const std::string oldName = settings.saveDirDomainLists + listId;
    const std::string newName = settings.saveDirDomainLists + listId + ".disabled";
    if (std::rename(oldName.c_str(), newName.c_str())) {
        return false;
    } else {
        erase(listId);
        return true;
    }
}

void DomainList::changeBlockMask(std::string listId, uint8_t blockMask) {
    for (auto &it : _domainsByListId[listId]) {
        it.second = blockMask;
    }
}

void DomainList::printDomains(std::string listId, std::ostream &out) {
    for (auto it : _domainsByListId[listId]) {
        out << it.first << " " << std::to_string(it.second) << std::endl;
    }
}

bool DomainList::remove(std::string listId) {
    erase(listId);
    std::string filePathListEnabled = settings.saveDirDomainLists + "/" + listId;
    std::string filePathListDisabled = settings.saveDirDomainLists + "/" + listId + ".disabled";
    if (std::remove(filePathListEnabled.c_str()) == 0) {
        return true;
    } else if (std::remove(filePathListDisabled.c_str()) == 0) {
        return true;
    } else {
        return false;
    }
}
