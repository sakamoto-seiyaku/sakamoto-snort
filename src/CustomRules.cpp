/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <sucre-snort.hpp>

#include <sstream>
#include <vector>

#include <Domain.hpp>
#include <Saver.hpp>
#include <CustomRules.hpp>
#include <RulesManager.hpp>

CustomRules::CustomRules()
    : _regexSnap(std::make_shared<std::regex>("")) {}

CustomRules::~CustomRules() {}

void CustomRules::add(const Rule::Ptr &rule, const bool compile) {
    const std::lock_guard lock(_mutex);
    _rules.insert(rule);
    _saved.store(false, std::memory_order_relaxed);
    if (compile) {
        rebuildRegexSnapshotLocked();
    }
}

void CustomRules::remove(const Rule::Ptr &rule, const bool compile) {
    const std::lock_guard lock(_mutex);
    _rules.erase(rule);
    _saved.store(false, std::memory_order_relaxed);
    if (compile) {
        rebuildRegexSnapshotLocked();
    }
}

void CustomRules::rebuildRegexSnapshotLocked() {
    // Precondition: _mutex is held exclusively by the caller.
    std::stringstream rules;
    bool first = true;
    for (const auto &rule : _rules) {
        if (rule->valid()) {
            when(first, rules << "|");
            rules << rule->regex();
        }
    }
    try {
        auto compiled = std::make_shared<std::regex>(rules.str(), std::regex::extended);
        std::atomic_store(&_regexSnap, std::move(compiled));
    } catch (...) {
        // On regex compilation failure, publish an empty regex which never matches.
        auto compiled = std::make_shared<std::regex>("");
        std::atomic_store(&_regexSnap, std::move(compiled));
    }
}

void CustomRules::build() {
    const std::lock_guard lock(_mutex);
    rebuildRegexSnapshotLocked();
}

bool CustomRules::match(const Domain::Ptr &domain) {
    // Lock-free fast path: read compiled regex snapshot atomically.
    const auto snap = std::atomic_load(&_regexSnap);
    if (!snap) {
        return false;
    }
    return std::regex_match(domain->name(), *snap);
}

void CustomRules::reset() {
    const std::lock_guard lock(_mutex);
    _saved.store(false, std::memory_order_relaxed);
    _rules.clear();
    rebuildRegexSnapshotLocked();
}

void CustomRules::save(Saver &saver) {
    // Snapshot rule ids under shared lock, write to disk without holding the mutex
    std::vector<Rule::Id> ids;
    {
        const std::shared_lock_guard lock(_mutex);
        ids.reserve(_rules.size());
        for (const auto &rule : _rules) ids.push_back(rule->id());
    }
    saver.write<uint32_t>(ids.size());
    for (const auto &id : ids) {
        saver.write<Rule::Id>(id);
    }
    _saved.store(true, std::memory_order_relaxed);
}

void CustomRules::restore(Saver &saver) {
    // Phase A: collect target rules without holding the mutex
    const uint32_t nb = saver.read<uint32_t>();
    std::vector<Rule::Ptr> toAdd;
    toAdd.reserve(nb);
    for (uint32_t i = 0; i < nb; ++i) {
        Rule::Id id = saver.read<Rule::Id>();
        const Rule::Ptr rule = rulesManager.findThreadSafe(id);
        if (rule != nullptr) {
            toAdd.push_back(rule);
        }
    }
    // Phase B: single lock; mutate _rules and publish one compiled snapshot
    const std::lock_guard lock(_mutex);
    for (const auto &r : toAdd) {
        _rules.insert(r);
    }
    _saved.store(false, std::memory_order_relaxed);
    rebuildRegexSnapshotLocked();
}

void CustomRules::print(std::ostream &out) {
    const std::shared_lock_guard lock(_mutex);
    bool first = true;
    out << "[";
    for (const auto &rule : _rules) {
        when(first, out << ",");
        out << rule->id();
    }
    out << "]";
}
