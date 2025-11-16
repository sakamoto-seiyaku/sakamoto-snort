/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <regex>
#include <memory>
#include <atomic>
#include <unordered_set>

#include <Rule.hpp>

class CustomRules {
private:
    std::unordered_set<Rule::Ptr> _rules;      // rules set; protected by _mutex
    std::shared_mutex _mutex;                  // protects _rules and rebuild operations
    // Atomically published compiled regex snapshot for lock-free reads in DNS path
    std::shared_ptr<std::regex> _regexSnap;
    std::atomic<bool> _saved{false};
    // Rebuild compiled regex snapshot under exclusive lock and publish atomically.
    void rebuildRegexSnapshotLocked();

public:
    CustomRules();

    ~CustomRules();

    CustomRules(const CustomRules &) = delete;

    bool saved() { return _saved.load(std::memory_order_relaxed); }

    void add(const Rule::Ptr &rule, const bool compile);

    void remove(const Rule::Ptr &rule, const bool compile);

    // Rebuild compiled regex and publish snapshot (acquires exclusive lock internally)
    void build();

    bool match(const Domain::Ptr &domain);

    void reset();

    void save(Saver &saver);

    void restore(Saver &saver);

    void print(std::ostream &out);
};
