/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <sucre-snort.hpp>

#include <sstream>

#include <Domain.hpp>
#include <Saver.hpp>
#include <CustomRules.hpp>
#include <RulesManager.hpp>

CustomRules::CustomRules() {}

CustomRules::~CustomRules() {}

void CustomRules::add(const Rule::Ptr &rule, const bool compile) {
    const std::lock_guard lock(_mutex);
    _rules.insert(rule);
    _saved = false;
    if (compile) {
        build();
    }
}

void CustomRules::remove(const Rule::Ptr &rule, const bool compile) {
    const std::lock_guard lock(_mutex);
    _rules.erase(rule);
    _saved = false;
    if (compile) {
        build();
    }
}

void CustomRules::build() {
    std::stringstream rules;
    bool first = true;
    for (const auto &rule : _rules) {
        if (rule->valid()) {
            when(first, rules << "|");
            rules << rule->regex();
        }
    }
    try {
        _regex = std::regex(rules.str(), std::regex::extended);
    } catch (...) {
        _regex = std::regex("");
    }
}

bool CustomRules::match(const Domain::Ptr &domain) {
    const std::shared_lock_guard lock(_mutex);
    return std::regex_match(domain->name(), _regex);
}

void CustomRules::reset() {
    const std::lock_guard lock(_mutex);
    _saved = false;
    _rules.clear();
    build();
}

void CustomRules::save(Saver &saver) {
    saver.write<uint32_t>(_rules.size());
    for (const auto &rule : _rules) {
        saver.write<Rule::Id>(rule->id());
    }
    _saved = true;
}

void CustomRules::restore(Saver &saver) {
    uint32_t nb = saver.read<uint32_t>();
    for (uint32_t i = 0; i < nb; ++i) {
        Rule::Id id = saver.read<Rule::Id>();
        const Rule::Ptr &rule = rulesManager.find(id);
        if (rule != nullptr) {
            add(rule, false);
        }
    }
    build();
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
