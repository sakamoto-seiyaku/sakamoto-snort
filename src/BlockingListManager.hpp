#pragma once
#include <string>
#include <vector>
#include <shared_mutex>
#include <unordered_map>

#include <Saver.hpp>
#include <Settings.hpp>
#include <Stats.hpp>
#include <BlockingList.hpp>

class BlockingListManager {

private:
    std::unordered_map<std::string, BlockingList> _ByIds;
    Saver _saver{settings.saveBlobkingLists};
    std::shared_mutex _mutex;

public:
    BlockingListManager();

    bool addBlockingList(std::string id, std::string url, std::string name, Stats::Color color);

    BlockingList *findListById(std::string id);

    bool removeBlockingList(std::string id);

    std::unordered_map<std::string, BlockingList> getAll();

    void restore();

    void printAll(std::ostream &out);

    void reset();

    void save();
};

extern BlockingListManager blm;