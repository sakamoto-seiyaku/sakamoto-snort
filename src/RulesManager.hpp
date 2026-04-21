/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <map>
#include <regex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <sucre-snort.hpp>
#include <App.hpp>
#include <CustomRules.hpp>
#include <Saver.hpp>

class RulesManager {
private:
    struct Custom {
        Stats::Color color = Stats::ALLC;
        std::unordered_set<App::Ptr> blacklist;
        std::unordered_set<App::Ptr> whitelist;
        std::unordered_set<App::Ptr> &list(Stats::Color color) {
            return color == Stats::BLACK ? blacklist : whitelist;
        }
    };

    std::map<uint32_t, const Rule::Ptr> _rules;
    std::unordered_map<Rule::Ptr, Custom> _customs;
    std::shared_mutex _mutex;
    uint32_t _idCount = 0;

    Saver _saver{settings.saveRules};

public:
    struct BaselineRule {
        uint32_t ruleId = 0;
        Rule::Type type = Rule::DOMAIN;
        std::string pattern;
    };

    struct CustomRuleConflict {
        uint32_t ruleId = 0;
        bool device = false;
        std::vector<uint32_t> appUids;
    };

    RulesManager();

    ~RulesManager();

    RulesManager(const RulesManager &) = delete;

    const Rule::Ptr find(const uint32_t ruleId);
    // Thread-safe lookup for contexts without external locking. Do not call
    // this while already holding _mutex to avoid lock reentrancy.
    const Rule::Ptr findThreadSafe(const uint32_t ruleId);

    // Snapshot of the current rules baseline (id/type/pattern) under shared lock.
    std::vector<BaselineRule> snapshotBaseline();

    // Bump the next allocated ruleId to at least nextId (no-op when already larger).
    void ensureNextRuleIdAtLeast(uint32_t nextId);

    // Upsert a rule with a fixed ruleId (create if missing; update if present).
    void upsertRuleWithId(uint32_t ruleId, Rule::Type type, const std::string &ruleRaw);

    // Compute referential-integrity conflicts for removing the given ruleIds.
    std::vector<CustomRuleConflict> conflictsForRemoval(const std::vector<uint32_t> &ruleIds);

    Rule::Id addRule(const Rule::Type type, const std::string &ruleRaw);

    void removeRule(const uint32_t ruleId);

    void updateRule(const uint32_t ruleId, const Rule::Type type, const std::string &ruleRaw);

    void addCustom(const uint32_t ruleId, const Stats::Color color, bool compile);

    void addCustom(const App::Ptr &app, const uint32_t ruleId, const Stats::Color color,
                   bool compile);

    void removeCustom(const uint32_t ruleId, const Stats::Color color);

    void removeCustom(const App::Ptr &app, const uint32_t ruleId, const Stats::Color color);

    void reset();

    void save();

    void restore();

    void restoreCustomRules(Saver &saver, App::Ptr app, Stats::Color color);

    void print(std::ostream &out);

private:
    const Rule::Ptr make(const uint32_t id, const Rule::Type type, const std::string &rule);
};

extern RulesManager rulesManager;
