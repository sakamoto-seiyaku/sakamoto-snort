/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <fstream>

#include <DomainList.hpp>

DomainList::DomainList() {}

DomainList::~DomainList() {}

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

bool DomainList::read(std::string listId) {
    if (auto in = std::ifstream(settings.saveDomainLists + '/' + listId); in.is_open()) {
        std::string hostname;
        uint32_t mask;
        DomsSet domains;
        while (in >> hostname >> mask) {
            auto [it, inserted] = domains.emplace(std::move(hostname), mask);
            if (!inserted) {
                it->second |= mask;
            }
        }
        _domainsByListId.emplace(listId, domains);
        in.close();
        return true;
    } else {
        throw std::runtime_error("Cannot open list file for list" + listId);
    }
}

void DomainList::write(std::string listId, std::vector<std::string> domains, int8_t mask) {
    if (auto out = std::ofstream(settings.saveDomainLists + '/' + listId, std::ofstream::app);
        out.is_open()) {
        // Iterate over the domains and write them to the file
        for (auto &domain : domains) {
            out << domain << " " << mask << std::endl;
        }
        out.close();
    } else {
        throw std::runtime_error("Cannot open list file for list" + listId);
    }
}
