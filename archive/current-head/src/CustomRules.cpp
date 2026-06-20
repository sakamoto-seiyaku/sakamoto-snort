/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <sucre-snort.hpp>

#include <algorithm>
#include <sstream>
#include <vector>

#include <Domain.hpp>
#include <Saver.hpp>
#include <CustomRules.hpp>
#include <RulesManager.hpp>

namespace {

[[nodiscard]] std::string ruleTypeStr(const Rule::Type type) {
    switch (type) {
    case Rule::DOMAIN:
        return "domain";
    case Rule::WILDCARD:
        return "wildcard";
    case Rule::REGEX:
        return "regex";
    }
    return "regex";
}

} // namespace

CustomRules::CustomRules()
    : _regexSnap(std::make_shared<std::regex>(""))
    , _attribSnap(std::make_shared<std::vector<AttribEntry>>()) {}

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

    std::vector<AttribEntry> attrib;
    attrib.reserve(_rules.size());

    for (const auto &rule : _rules) {
        if (!rule->valid()) {
            continue;
        }
        when(first, rules << "|");
        rules << rule->regex();
        try {
            attrib.push_back(AttribEntry{.ruleId = rule->id(),
                                         .regex = std::regex(rule->regex(), std::regex::extended)});
        } catch (...) {
            // Should not happen for rule->valid()==true, but keep attribution best-effort.
        }
    }
    std::sort(attrib.begin(), attrib.end(),
              [](const AttribEntry &a, const AttribEntry &b) { return a.ruleId < b.ruleId; });

    try {
        auto compiled = std::make_shared<std::regex>(rules.str(), std::regex::extended);
        std::atomic_store(&_regexSnap, std::move(compiled));
    } catch (...) {
        // On regex compilation failure, publish an empty regex which never matches.
        auto compiled = std::make_shared<std::regex>("");
        std::atomic_store(&_regexSnap, std::move(compiled));
    }

    std::atomic_store(&_attribSnap, std::make_shared<std::vector<AttribEntry>>(std::move(attrib)));
}

void CustomRules::build() {
    const std::lock_guard lock(_mutex);
    rebuildRegexSnapshotLocked();
}

std::vector<Rule::Id> CustomRules::snapshotRuleIds() const {
    const std::shared_lock<std::shared_mutex> lock(_mutex);
    std::vector<Rule::Id> out;
    out.reserve(_rules.size());
    for (const auto &rule : _rules) {
        out.push_back(rule->id());
    }
    return out;
}

bool CustomRules::match(const Domain::Ptr &domain) {
    // Lock-free fast path: read compiled regex snapshot atomically.
    const auto snap = std::atomic_load(&_regexSnap);
    if (!snap) {
        return false;
    }
    return std::regex_match(domain->name(), *snap);
}

std::optional<Rule::Id> CustomRules::matchFirstRuleId(const Domain::Ptr &domain) {
    const auto snap = std::atomic_load(&_attribSnap);
    if (!snap || snap->empty()) {
        return std::nullopt;
    }
    const std::string &name = domain->name();
    for (const auto &entry : *snap) {
        if (std::regex_match(name, entry.regex)) {
            return entry.ruleId;
        }
    }
    return std::nullopt;
}

std::vector<ControlVNextStreamExplain::DnsRuleSnapshot>
CustomRules::matchingExplainSnapshots(const Domain::Ptr &domain, const std::string &scope,
                                      const std::string &action,
                                      const std::optional<Rule::Id> winningRuleId,
                                      bool &truncated,
                                      std::optional<std::uint32_t> &omittedCandidateCount) {
    truncated = false;
    omittedCandidateCount.reset();
    const auto snap = std::atomic_load(&_attribSnap);
    if (!snap || snap->empty() || domain == nullptr) {
        return {};
    }

    const std::string &name = domain->name();
    std::vector<ControlVNextStreamExplain::DnsRuleSnapshot> out;
    for (const auto &entry : *snap) {
        if (!std::regex_match(name, entry.regex)) {
            continue;
        }
        const Rule::Ptr rule = rulesManager.findThreadSafe(entry.ruleId);
        if (rule == nullptr) {
            continue;
        }
        out.push_back(ControlVNextStreamExplain::DnsRuleSnapshot{
            .ruleId = rule->id(),
            .type = ruleTypeStr(rule->type()),
            .pattern = rule->rule(),
            .scope = scope,
            .action = action,
        });
    }

    std::sort(out.begin(), out.end(), [](const auto &a, const auto &b) {
        return a.ruleId < b.ruleId;
    });
    ControlVNextStreamExplain::capCandidateSnapshots(
        out, winningRuleId, [](const auto &snapshot) { return snapshot.ruleId; }, truncated,
        omittedCandidateCount);
    return out;
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
        const std::shared_lock<std::shared_mutex> lock(_mutex);
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
    const std::shared_lock<std::shared_mutex> lock(_mutex);
    bool first = true;
    out << "[";
    for (const auto &rule : _rules) {
        when(first, out << ",");
        out << rule->id();
    }
    out << "]";
}
