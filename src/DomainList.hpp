/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <unordered_map>
#include <memory>
#include <Settings.hpp>
#include <sucre-snort.hpp>
#include <vector>
class DomainList {
private:
    using DomsSet = std::unordered_map<std::string, uint8_t>;
    using DomsMap = std::unordered_map<std::string, DomsSet>;

    DomsMap _domainsByListId;                // all lists: listId -> (domain -> mask)
    mutable std::shared_mutex _mutex;        // protects _domainsByListId and snapshot rebuild

    // Aggregated read-only snapshot for fast lookups (domain -> merged mask)
    // Queried by blockMask() without taking _mutex.
    std::shared_ptr<DomsSet> _aggSnapshot;   

    // Internal helpers (call only under correct locking discipline)
    bool eraseUnlocked(const std::string &listId);
    void rebuildAggSnapshotLocked();

public:
    DomainList();

    ~DomainList();

    DomainList(const DomainList &) = delete;

    DomsSet get(std::string listId);

    void set(std::string listId, DomsSet domains);

    uint32_t size() const {
        const std::shared_lock<std::shared_mutex> lock(_mutex);
        uint32_t totalItems = 0;
        for (const auto &pair : _domainsByListId) {
            totalItems += static_cast<uint32_t>(pair.second.size());
        }
        return totalItems;
    }

    uint8_t blockMask(const std::string &domain);

    void read(std::string listId, uint8_t blockMask);

    uint32_t write(std::string listId, std::vector<std::string> domains, uint8_t blockMask,
                   bool clear = false);

    bool erase(std::string listId);

    bool enable(std::string listId, uint8_t blockMask);

    bool disable(std::string listId);

    void changeBlockMask(std::string listId, uint8_t blockMask);

    void reset();

    void printDomains(std::string listId, std::ostream &out);

    bool remove(std::string listId);
};
