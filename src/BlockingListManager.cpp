#include <list>
#include <string>
#include <ctime>
#include <Saver.hpp>
#include <BlockingList.hpp>
#include <BlockingListManager.hpp>
#include <Stats.hpp>
using namespace std;

BlockingListManager::BlockingListManager() {}

bool BlockingListManager::addBlockingList(string id, string url, string name, Stats::Color color,
                                          std::uint8_t blockMask) {
    auto it = _ByIds.find(id);
    if (it == _ByIds.end()) {
        BlockingList bl(id, name, url, color, blockMask, 0, true, "", true);
        const std::lock_guard lock(_mutex);
        return _ByIds.try_emplace(id, bl).second;
    }
    return false;
}

BlockingList *BlockingListManager::findListById(std::string id) {
    auto it = _ByIds.find(id);
    if (it != _ByIds.end()) {
        return &(it->second);
    }
    return nullptr;
}

bool BlockingListManager::removeBlockingList(std::string id) {
    auto it = _ByIds.find(id);
    if (it != _ByIds.end()) {
        _ByIds.erase(it);
        return true;
    }
    return false;
}

std::unordered_map<std::string, BlockingList> BlockingListManager::getAll() { return _ByIds; }

void BlockingListManager::restore() {
    _saver.restore([&] {
        uint32_t nb = _saver.read<uint32_t>();
        for (uint32_t i = 0; i < nb; ++i) {
            const lock_guard lock(_mutex);
            BlockingList blockingList;
            blockingList.restore(_saver);
            _ByIds.try_emplace(blockingList.getId(), blockingList);
        }
    });
}

void BlockingListManager::save() {
    _saver.save([&] {
        _saver.write<uint32_t>(_ByIds.size());
        for (const auto &[_, blockingList] : _ByIds) {
            blockingList.save(_saver);
        }
    });
}

void BlockingListManager::printAll(std::ostream &out) {
    const std::shared_lock_guard lock(_mutex);
    bool first = true;
    out << "{\"blockingLists\":[";
    for (auto &bl : _ByIds) {
        when(first, out << ",");
        string blString = bl.second.serialize();
        out << blString;
    }
    out << "]}";
}

void BlockingListManager::reset() {
    const std::lock_guard lock(_mutex);
    _ByIds.clear();
}

std::vector<BlockingList> BlockingListManager::getLists() {
    std::vector<BlockingList> lists;
    for (auto it = _ByIds.begin(); it != _ByIds.end(); ++it) {
        lists.push_back(it->second);
    }
    return lists;
}
