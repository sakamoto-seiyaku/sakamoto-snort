/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <regex>
#include <memory>
#include <atomic>
#include <unordered_set>
#include <optional>
#include <shared_mutex>
#include <vector>

#include <Rule.hpp>

class CustomRules {
private:
    struct AttribEntry {
        Rule::Id ruleId = 0;
        std::regex regex;
    };

    std::unordered_set<Rule::Ptr> _rules;      // rules set; protected by _mutex
    mutable std::shared_mutex _mutex;          // protects _rules and rebuild operations
    // Atomically published compiled regex snapshot for lock-free reads in DNS path
    std::shared_ptr<std::regex> _regexSnap;
    // Atomically published per-rule compiled snapshot for lock-free attribution reads.
    std::shared_ptr<std::vector<AttribEntry>> _attribSnap;
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

    // Snapshot ruleIds. Order is unspecified (caller may sort if needed).
    std::vector<Rule::Id> snapshotRuleIds() const;

    bool match(const Domain::Ptr &domain);

    // Return the deterministic attributed ruleId (min ruleId) when any rule matches.
    // Lock-free read path via atomic snapshot load.
    std::optional<Rule::Id> matchFirstRuleId(const Domain::Ptr &domain);

    void reset();

    void save(Saver &saver);

    void restore(Saver &saver);

    void print(std::ostream &out);
};
