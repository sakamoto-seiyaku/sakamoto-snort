/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <fstream>

#include <DomainList.hpp>

DomainList::DomainList() {}

DomainList::~DomainList() {}

DomainList::DomsSet DomainList::get(std::string listId) { return _domainsByListId[listId]; }

void DomainList::set(std::string listId, DomsSet domains) { _domainsByListId[listId] = domains; }

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
        throw std::runtime_error("Cannot read DomainList file");
    }
}

void DomainList::write(std::string listId, std::vector<std::string> domains, uint8_t blockMask,
                       bool clear) {
    // Acquire a lock on the mutex
    const std::shared_lock_guard lock(_mutex);
    if (auto out = std::ofstream(settings.saveDirDomainLists + listId.c_str(),
                                 std::ofstream::app | std::ofstream::out);
        out.is_open()) {
        if (clear) {
            _domainsByListId.erase(listId);
            out.clear();
        }
        // Iterate over the domains and write them to the file
        for (const auto &domain : domains) {
            _domainsByListId[listId].emplace(domain, blockMask);
            out << domain << std::endl;
        }
        out.close();
    } else {
        throw std::runtime_error("Cannot write DomainList file");
    }
}

void DomainList::erase(std::string listId) {
    const std::shared_lock_guard lock(_mutex);
    _domainsByListId.erase(listId);
}

void DomainList::reset() {
    const std::shared_lock_guard lock(_mutex);
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
