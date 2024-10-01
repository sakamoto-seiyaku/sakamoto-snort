#include <BlockingListManager.hpp>

using namespace std;

BlockingListManager::BlockingListManager() {}

bool BlockingListManager::addBlockingList(string id, string url, string name, Stats::Color color,
                                          uint8_t blockMask) {
    auto it = _ByIds.find(id);
    if (it == _ByIds.end()) {
        BlockingList bl(id, name, url, color, blockMask, 0, true, "", true, 0);
        const lock_guard lock(_mutex);
        return _ByIds.try_emplace(id, bl).second;
    }
    return false;
}

BlockingList *BlockingListManager::findListById(string id) {
    auto it = _ByIds.find(id);
    if (it != _ByIds.end()) {
        return &(it->second);
    }
    return nullptr;
}

bool BlockingListManager::removeBlockingList(string id) {
    auto it = _ByIds.find(id);
    if (it != _ByIds.end()) {
        string filePath =
            settings.saveDirDomainLists + "/" + id + (it->second.isEnabled() ? "" : ".disabled");
        if (std::remove(filePath.c_str()) == 0) {
            _ByIds.erase(it);
            return true;
        } else {
            return false;
        }
    }
    return false;
}

unordered_map<string, BlockingList> BlockingListManager::getAll() { return _ByIds; }

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

void BlockingListManager::printAll(ostream &out) {
    const shared_lock_guard lock(_mutex);
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
    const lock_guard lock(_mutex);
    _ByIds.clear();
}

vector<BlockingList> BlockingListManager::getLists() {
    vector<BlockingList> lists;
    const lock_guard lock(_mutex);
    for (auto it = _ByIds.begin(); it != _ByIds.end(); ++it) {
        lists.push_back(it->second);
    }
    return lists;
}
