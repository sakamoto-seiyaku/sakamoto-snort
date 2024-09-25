/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <unordered_map>
#include <Settings.hpp>
#include <iode-snort.hpp>
#include <vector>

class DomainList {
private:
    using DomsSet = std::unordered_map<std::string, uint8_t>;
    using DomsMap = std::unordered_map<std::string, DomsSet>;

    DomsMap _domainsByListId;
    std::shared_mutex _mutex;

public:
    DomainList();

    ~DomainList();

    DomainList(const DomainList &) = delete;

    uint32_t size() const {
        int totalItems = 0;
        for (const auto &[_, domsSet] : _domainsByListId) {
            totalItems += domsSet.size();
        }
        return totalItems;
    }

    uint8_t blockMask(const std::string &domain);

    bool read(std::string listId);

    void write(std::string listId, std::vector<std::string> domains, int8_t mask);
};
