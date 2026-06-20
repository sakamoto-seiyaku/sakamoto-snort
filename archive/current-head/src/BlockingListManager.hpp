/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <string>
#include <vector>
#include <shared_mutex>
#include <unordered_map>
#include <Settings.hpp>
#include <Stats.hpp>
#include <BlockingList.hpp>
#include <stdio.h>
#include <string>
#include <ctime>
#include <Saver.hpp>
#include <DomainManager.hpp>
class BlockingListManager {

private:
    std::unordered_map<std::string, BlockingList> _ByIds;
    Saver _saver{settings.saveBlockingLists};
    std::shared_mutex _mutex;

public:
    BlockingListManager();

    bool addBlockingList(std::string id, std::string url, std::string name, Stats::Color color,
                         std::uint8_t blockMask);

    bool removeBlockingList(std::string id);

    // Return a copy under shared lock to avoid data races.
    std::unordered_map<std::string, BlockingList> getAll();

    void restore();

    void printAll(std::ostream &out);

    void reset();

    void replaceAllForCheckpointRestore(std::unordered_map<std::string, BlockingList> lists);

    void save();

    std::vector<BlockingList> getLists();

    // ---- New atomic APIs (Scheme 3): no pointer exposure ----
    bool updateBlockingList(const std::string &id, const std::string &url, const std::string &name,
                            Stats::Color color, std::uint8_t blockMask, std::uint32_t domainsCount,
                            const std::string &updatedAtStr, const std::string &etag, bool enabled,
                            bool outdated);

    bool setEnabled(const std::string &id, bool enabled);

    bool markOutdated(const std::string &id);

    bool updateDomainsCount(const std::string &id, std::uint32_t domainsCount);

    // Return mask if present; false if id not found
    bool getBlockMask(const std::string &id, std::uint8_t &outMask);
    bool getColor(const std::string &id, Stats::Color &outColor);

    // Lightweight snapshots for read-mostly paths
    std::unordered_map<std::string, std::uint8_t> masksSnapshot();
    std::vector<BlockingList> listsSnapshot();
};

extern BlockingListManager blockingListManager;
