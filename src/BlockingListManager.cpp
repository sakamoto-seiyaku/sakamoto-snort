/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <BlockingListManager.hpp>
#include <iomanip>
#include <sstream>

using namespace std;

BlockingListManager::BlockingListManager() {}

bool BlockingListManager::addBlockingList(string id, string url, string name, Stats::Color color,
                                          uint8_t blockMask) {
    const lock_guard lock(_mutex);
    auto it = _ByIds.find(id);
    if (it != _ByIds.end()) {
        return false;
    }
    BlockingList bl(id, name, url, color, blockMask, 0, true, "", true, 0);
    return _ByIds.try_emplace(id, bl).second;
}

bool BlockingListManager::removeBlockingList(string id) {
    const lock_guard lock(_mutex);
    auto it = _ByIds.find(id);
    if (it == _ByIds.end()) {
        return false;
    }
    _ByIds.erase(it);
    return true;
}

unordered_map<string, BlockingList> BlockingListManager::getAll() {
    const std::shared_lock_guard lock(_mutex);
    return _ByIds; // copy under shared lock
}

void BlockingListManager::restore() {
    _saver.restore([&] {
        uint32_t nb = _saver.read<uint32_t>();
        // Scheme B: deserialize without holding the mutex, then publish once
        std::unordered_map<std::string, BlockingList> tmp;
        tmp.reserve(nb);
        for (uint32_t i = 0; i < nb; ++i) {
            BlockingList blockingList;
            blockingList.restore(_saver);
            tmp.try_emplace(blockingList.getId(), blockingList);
        }
        {
            const lock_guard lock(_mutex);
            if (_ByIds.empty()) {
                _ByIds.swap(tmp);
            } else {
                for (auto &p : tmp) {
                    _ByIds.try_emplace(p.first, p.second);
                }
            }
        }
    });
}

void BlockingListManager::save() {
    // Snapshot first to avoid long-held locks and iterator invalidation
    auto lists = listsSnapshot();
    _saver.save([&] {
        _saver.write<uint32_t>(lists.size());
        for (const auto &blockingList : lists) {
            blockingList.save(_saver);
        }
    });
}

void BlockingListManager::printAll(ostream &out) {
    auto lists = listsSnapshot();
    bool first = true;
    out << "{\"blockingLists\":[";
    for (const auto &bl : lists) {
        if (!first) out << ",";
        first = false;
        out << bl.serialize();
    }
    out << "]}";
}

void BlockingListManager::reset() {
    const lock_guard lock(_mutex);
    _ByIds.clear();
}

vector<BlockingList> BlockingListManager::getLists() {
    return listsSnapshot();
}

bool BlockingListManager::updateBlockingList(const string &id, const string &url, const string &name,
                                             Stats::Color color, uint8_t blockMask,
                                             uint32_t domainsCount, const string &updatedAtStr,
                                             const string &etag, bool enabled, bool outdated) {
    // Strict time parsing (fix 8a): zero-init tm and check state
    std::tm tm{};
    std::istringstream ss(updatedAtStr);
    if (!(ss >> std::get_time(&tm, "%Y-%m-%d_%H:%M:%S"))) {
        return false; // refuse invalid time format
    }
    time_t updatedAt = mktime(&tm);

    const lock_guard lock(_mutex);
    auto it = _ByIds.find(id);
    if (it == _ByIds.end()) {
        return false;
    }
    it->second.updateList(name, color, url, static_cast<uint8_t>(blockMask), domainsCount,
                          updatedAt, etag, enabled, outdated);
    return true;
}

bool BlockingListManager::setEnabled(const string &id, bool enabled) {
    const lock_guard lock(_mutex);
    auto it = _ByIds.find(id);
    if (it == _ByIds.end()) return false;
    if (enabled) {
        it->second.enable();
    } else {
        it->second.disable();
    }
    return true;
}

bool BlockingListManager::markOutdated(const string &id) {
    const lock_guard lock(_mutex);
    auto it = _ByIds.find(id);
    if (it == _ByIds.end()) return false;
    it->second.setIsOutDated();
    return true;
}

bool BlockingListManager::getBlockMask(const string &id, uint8_t &outMask) {
    const std::shared_lock_guard lock(_mutex);
    auto it = _ByIds.find(id);
    if (it == _ByIds.end()) return false;
    outMask = it->second.getBlockMask();
    return true;
}

bool BlockingListManager::getColor(const string &id, Stats::Color &outColor) {
    const std::shared_lock_guard lock(_mutex);
    auto it = _ByIds.find(id);
    if (it == _ByIds.end()) return false;
    outColor = it->second.getColor();
    return true;
}

unordered_map<string, uint8_t> BlockingListManager::masksSnapshot() {
    const std::shared_lock_guard lock(_mutex);
    unordered_map<string, uint8_t> masks;
    masks.reserve(_ByIds.size());
    for (const auto &p : _ByIds) masks.emplace(p.first, p.second.getBlockMask());
    return masks;
}

vector<BlockingList> BlockingListManager::listsSnapshot() {
    const std::shared_lock_guard lock(_mutex);
    vector<BlockingList> lists;
    lists.reserve(_ByIds.size());
    for (const auto &p : _ByIds) lists.push_back(p.second);
    return lists;
}
