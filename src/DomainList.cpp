/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "BlockingListManager.hpp"
#include <fstream>
#include <memory>
#include <cctype>

#include <DomainList.hpp>

DomainList::DomainList() {}

DomainList::~DomainList() {}

DomainList::DomsSet DomainList::get(std::string listId) {
    const std::shared_lock<std::shared_mutex> lock(_mutex);
    auto it = _domainsByListId.find(listId);
    return it != _domainsByListId.end() ? it->second : DomsSet{};
}

void DomainList::set(std::string listId, DomsSet domains) {
    std::unique_lock lock(_mutex);
    _domainsByListId[listId] = domains;
    // Rebuild aggregated snapshot so subsequent queries observe the update.
    rebuildAggSnapshotLocked();
}

uint8_t DomainList::blockMask(const std::string &domain) {
    // Fast path: read aggregated snapshot without locking.
    auto snap = std::atomic_load(&_aggSnapshot);
    if (!snap) {
        return 0;
    }

    // Exact match first
    if (auto it = snap->find(domain); it != snap->end()) {
        return it->second;
    }

    // Suffix match: walk subdomains (a.b.c -> b.c -> c)
    auto first = domain.find_first_of('.');
    auto last = domain.find_last_of('.');
    while (first != last) {
        if (auto it2 = snap->find(domain.substr(first + 1)); it2 != snap->end()) {
            return it2->second;
        }
        first = domain.find_first_of('.', first + 1);
    }
    return 0;
}

void DomainList::read(std::string listId, uint8_t blockMask) {
    if (!validListId(listId)) {
        LOG(ERROR) << __FUNCTION__ << " - invalid list id";
        return;
    }
    // Phase 1: file I/O without holding the mutex
    DomsSet domains;
    if (auto in = std::ifstream(settings.saveDirDomainLists + listId, std::ifstream::in); in.is_open()) {
        std::string hostname;
        while (in >> hostname) {
            auto [it, inserted] = domains.emplace(std::move(hostname), blockMask);
            if (!inserted) {
                it->second |= blockMask;
            }
        }
        in.close();
    } else {
        LOG(ERROR) << " List read error for list: " << listId;
        return;
    }

    // Phase 2: short critical section to merge and rebuild snapshot
    {
        std::unique_lock lock(_mutex);
        _domainsByListId.emplace(listId, std::move(domains));
        rebuildAggSnapshotLocked();
    }
}

uint32_t DomainList::write(const std::string listId, const std::vector<std::string> domains,
                           uint8_t blockMask, bool clear) {
    if (!validListId(listId)) {
        LOG(ERROR) << __FUNCTION__ << " - invalid list id";
        return 0;
    }
    // Take a BLM masks snapshot BEFORE acquiring DL lock to avoid lock order inversion (BLM -> DL).
    const auto masks = blockingListManager.masksSnapshot();

    std::unique_lock lock(_mutex);

    if (clear) {
        _domainsByListId.erase(listId);
        // Clear file content
        std::ofstream(settings.saveDirDomainLists + listId,
                      std::ofstream::out | std::ofstream::trunc)
            .close();
    }

    // 1. Collect matching list IDs based on the pre-fetched masks snapshot
    //    Note: masks is a value snapshot to prevent cross-component locking while holding DL lock.
    std::vector<std::string> matchingListIds;
    for (const auto &[otherListId, _] : _domainsByListId) {
        auto itMask = masks.find(otherListId);
        if (itMask != masks.end() && itMask->second <= blockMask) {
            matchingListIds.push_back(otherListId);
        }
    }

    auto &targetSet = _domainsByListId[listId];
    std::ofstream out(settings.saveDirDomainLists + listId, std::ofstream::app);
    if (!out.is_open()) {
        LOG(ERROR) << __FUNCTION__ << " List write error for list: " << listId;
        return 0;
    }

    uint32_t addedCount = 0;
    for (const auto &domain : domains) {
        bool exists = false;
        // 2. Check only lists with matching blockMask
        for (const auto &matchingId : matchingListIds) {
            const auto &set = _domainsByListId.at(matchingId);
            if (set.find(domain) != set.end()) {
                exists = true;
                break;
            }
        }
        if (exists)
            continue;

        auto [it, inserted] = targetSet.emplace(domain, blockMask);
        if (inserted) {
            out << domain << std::endl;
            ++addedCount;
        }
    }

    out.close();

    // The underlying sets changed; rebuild aggregated snapshot.
    rebuildAggSnapshotLocked();
    return addedCount;
}

bool DomainList::erase(std::string listId) {
    if (!validListId(listId)) {
        LOG(ERROR) << __FUNCTION__ << " - invalid list id";
        return false;
    }
    std::unique_lock lock(_mutex);
    const bool erased = eraseUnlocked(listId);
    if (erased) {
        rebuildAggSnapshotLocked();
    }
    return erased;
}

void DomainList::reset() {
    std::unique_lock lock(_mutex);
    _domainsByListId.clear();
    rebuildAggSnapshotLocked();
}

bool DomainList::enable(std::string listId, uint8_t blockMask) {
    if (!validListId(listId)) {
        LOG(ERROR) << __FUNCTION__ << " - invalid list id";
        return false;
    }
    // 按方案A：全程持有独占锁，避免 enable() 与并发 disable() 的竞态窗口。
    std::unique_lock lock(_mutex);

    const std::string oldName = settings.saveDirDomainLists + listId + ".disabled";
    const std::string newName = settings.saveDirDomainLists + listId;
    if (std::rename(oldName.c_str(), newName.c_str())) {
        return false;
    }

    // 文件 I/O 低频，放在锁内以保证与 disable()/erase() 的一致性。
    DomsSet domains;
    if (auto in = std::ifstream(newName, std::ifstream::in); in.is_open()) {
        std::string hostname;
        while (in >> hostname) {
            auto [it, inserted] = domains.emplace(std::move(hostname), blockMask);
            if (!inserted) {
                it->second |= blockMask;
            }
        }
        in.close();
    } else {
        LOG(ERROR) << __FUNCTION__ << " List read error for list: " << listId;
        // 读取失败：视为启用但为空列表（与先前行为一致）。
    }

    _domainsByListId[listId] = std::move(domains);
    rebuildAggSnapshotLocked();
    return true;
}

bool DomainList::disable(std::string listId) {
    if (!validListId(listId)) {
        LOG(ERROR) << __FUNCTION__ << " - invalid list id";
        return false;
    }
    std::unique_lock lock(_mutex);
    const std::string oldName = settings.saveDirDomainLists + listId;
    const std::string newName = settings.saveDirDomainLists + listId + ".disabled";
    if (std::rename(oldName.c_str(), newName.c_str())) {
        return false;
    }
    eraseUnlocked(listId);
    rebuildAggSnapshotLocked();
    return true;
}

void DomainList::changeBlockMask(std::string listId, uint8_t blockMask) {
    std::unique_lock lock(_mutex);
    if (auto it = _domainsByListId.find(listId); it != _domainsByListId.end()) {
        for (auto &kv : it->second) {
            kv.second = blockMask;
        }
        rebuildAggSnapshotLocked();
    }
}

void DomainList::printDomains(std::string listId, std::ostream &out) {
    const std::shared_lock<std::shared_mutex> lock(_mutex);
    if (auto it = _domainsByListId.find(listId); it != _domainsByListId.end()) {
        for (const auto &kv : it->second) {
            out << kv.first << " " << std::to_string(kv.second) << std::endl;
        }
    }
}

bool DomainList::remove(std::string listId) {
    if (!validListId(listId)) {
        LOG(ERROR) << __FUNCTION__ << " - invalid list id";
        return false;
    }
    // Remove from in-memory map first; file deletion may fail due to filesystem state.
    // Returning false indicates that no on-disk file was removed, but the logical list
    // has already been erased from memory.
    erase(listId);
    // Avoid duplicate '/' since saveDirDomainLists already ends with '/'
    std::string filePathListEnabled = settings.saveDirDomainLists + listId;
    std::string filePathListDisabled = settings.saveDirDomainLists + listId + ".disabled";
    if (std::remove(filePathListEnabled.c_str()) == 0) {
        return true;
    } else if (std::remove(filePathListDisabled.c_str()) == 0) {
        return true;
    } else {
        return false;
    }
}

// ===== Internal helpers (no external locking) =====

bool DomainList::eraseUnlocked(const std::string &listId) {
    auto it = _domainsByListId.find(listId);
    if (it != _domainsByListId.end()) {
        _domainsByListId.erase(it);
        return true;
    }
    return false;
}

void DomainList::rebuildAggSnapshotLocked() {
    // Build a merged view of all lists: domain -> OR'ed mask.
    // Note: if allocation fails (std::bad_alloc), the exception will propagate and
    // the previously published snapshot remains intact, preserving reader safety.
    auto snap = std::make_shared<DomsSet>();
    // Pre-reserve to reduce rehashes.
    size_t total = 0;
    for (const auto &p : _domainsByListId) total += p.second.size();
    if (total > 0) snap->reserve(total);

    for (const auto &p : _domainsByListId) {
        for (const auto &kv : p.second) {
            auto it = snap->find(kv.first);
            if (it == snap->end()) {
                snap->emplace(kv.first, kv.second);
            } else {
                it->second |= kv.second;
            }
        }
    }
    std::atomic_store(&_aggSnapshot, std::move(snap));
}

// Accept only a restricted character set to prevent path traversal or directory injection.
// Current format is a GUID (hex + '-') with 36 chars, but allow up to 64 to decouple logic
// from exact formatting while keeping a strict whitelist.
bool DomainList::validListId(const std::string &listId) {
    if (listId.empty() || listId.size() > 64) return false;
    for (unsigned char ch : listId) {
        if (!(std::isxdigit(ch) || ch == '-')) {
            return false;
        }
    }
    return true;
}
