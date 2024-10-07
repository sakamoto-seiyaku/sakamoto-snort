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
#include <list>
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

    BlockingList *findListById(std::string id);

    bool removeBlockingList(std::string id);

    std::unordered_map<std::string, BlockingList> getAll();

    void restore();

    void printAll(std::ostream &out);

    void reset();

    void save();

    std::vector<BlockingList> getLists();
};

extern BlockingListManager blockingListManager;