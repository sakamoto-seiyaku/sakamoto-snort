/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <sstream>

#include <sucre-snort.hpp>
#include <Saver.hpp>
#include <RulesManager.hpp>

RulesManager::RulesManager() {}

RulesManager::~RulesManager() {}

Rule::Id RulesManager::addRule(const Rule::Type type, const std::string &ruleRaw) {
    const std::lock_guard lock(_mutex);
    const auto &rule = make(_idCount, type, ruleRaw);
    return ++_idCount - 1;
}

const Rule::Ptr RulesManager::make(const Rule::Id id, const Rule::Type type,
                                   const std::string &rule) {
    return _rules.try_emplace(id, std::make_shared<Rule>(type, id, rule)).first->second;
}

const Rule::Ptr RulesManager::find(const Rule::Id ruleId) {
    const auto it = _rules.find(ruleId);
    return it != _rules.end() ? it->second : nullptr;
}

void RulesManager::removeRule(const Rule::Id ruleId) {
    const std::lock_guard lock(_mutex);
    if (const auto &rule = find(ruleId)) {
        Custom &custom = _customs[rule];
        if (custom.color != Stats::ALLC) {
            domManager.removeCustomRule(rule, true, custom.color);
        }
        for (const auto &app : custom.blacklist) {
            app->removeCustomRule(rule, true, Stats::BLACK);
        }
        for (const auto &app : custom.whitelist) {
            app->removeCustomRule(rule, true, Stats::WHITE);
        }
        _rules.erase(rule->id());
        _customs.erase(rule);
    }
}

void RulesManager::updateRule(const uint32_t ruleId, const Rule::Type type,
                              const std::string &ruleRaw) {
    const std::lock_guard lock(_mutex);
    if (const auto &rule = find(ruleId)) {
        rule->update(type, ruleRaw);
        Custom &custom = _customs[rule];
        if (custom.color != Stats::ALLC) {
            domManager.buildCustomRules(custom.color);
        }
        for (const auto &app : custom.blacklist) {
            app->buildCustomRules(Stats::BLACK);
        }
        for (const auto &app : custom.whitelist) {
            app->buildCustomRules(Stats::WHITE);
        }
    }
}

void RulesManager::reset() {
    const std::lock_guard lock(_mutex);
    _rules.clear();
    _customs.clear();
    _idCount = 0;
}

void RulesManager::addCustom(const Rule::Id ruleId, const Stats::Color color, bool compile) {
    addCustom(nullptr, ruleId, color, compile);
}

void RulesManager::addCustom(const App::Ptr &app, const Rule::Id ruleId, const Stats::Color color,
                             bool compile) {
    const std::shared_lock_guard lock(_mutex);
    if (const auto &rule = find(ruleId)) {
        if (app == nullptr) {
            _customs[rule].color = color;
            domManager.addCustomRule(rule, compile, color);
        } else {
            _customs[rule].list(color).insert(app);
            app->addCustomRule(rule, compile, color);
        }
    }
}

void RulesManager::removeCustom(const Rule::Id ruleId, const Stats::Color color) {
    removeCustom(nullptr, ruleId, color);
}

void RulesManager::removeCustom(const App::Ptr &app, const Rule::Id ruleId,
                                const Stats::Color color) {
    const std::shared_lock_guard lock(_mutex);
    if (const auto &rule = find(ruleId)) {
        Custom &custom = _customs[rule];
        if (app == nullptr) {
            custom.color = Stats::ALLC;
            domManager.removeCustomRule(rule, true, color);
        } else {
            app->removeCustomRule(rule, true, color);
            custom.list(color).erase(app);
        }
        if (custom.color == Stats::ALLC && custom.blacklist.empty() && custom.whitelist.empty()) {
            _customs.erase(rule);
        }
    }
}

void RulesManager::save() {
    _saver.save([&] {
        _saver.write<uint32_t>(_idCount);
        _saver.write<uint32_t>(_rules.size());
        for (const auto &[id, rule] : _rules) {
            rule->save(_saver);
        }
    });
}

void RulesManager::restore() {
    _saver.restore([&] {
        _idCount = _saver.read<uint32_t>();
        uint32_t nb = _saver.read<uint32_t>();
        for (uint32_t i = 0; i < nb; ++i) {
            Rule::Id id = _saver.read<Rule::Id>();
            Rule::Type type = static_cast<Rule::Type>(_saver.read<Rule::Id>());
            std::string rule;
            _saver.read(rule);
            make(id, type, rule);
        }
    });
}

void RulesManager::restoreCustomRules(Saver &saver, App::Ptr app, Stats::Color color) {
    uint32_t nb = saver.read<uint32_t>();
    for (uint32_t i = 0; i < nb; ++i) {
        Rule::Id id = saver.read<Rule::Id>();
        const Rule::Ptr &rule = find(id);
        if (rule != nullptr) {
            addCustom(app, id, color, false);
        }
    }
    if (app == nullptr) {
        domManager.buildCustomRules(color);
    } else {
        app->buildCustomRules(color);
    }
}

void RulesManager::print(std::ostream &out) {
    const std::shared_lock_guard lock(_mutex);
    bool first = true;
    out << "[";
    for (const auto &[_, rule] : _rules) {
        auto &_custom = _customs[rule];
        std::stringstream tmp;
        for (const auto c : rule->rule()) {
            switch (c) {
            case '"':
                tmp << "\\\"";
                break;
            case '\\':
                tmp << "\\\\";
                break;
            default:
                tmp << c;
            }
        }
        when(first, out << ",");
        out << "{" << JSF("id") << JSS(rule->id()) << "," << JSF("type") << rule->type() << ","
            << JSF("rule") << JSS(tmp.str()) << "," << JSF("status")
            << JSS((_custom.color == Stats::ALLC    ? "none"
                    : _custom.color == Stats::BLACK ? "black"
                                                    : "white"))
            << "," << JSF("blacklist") << "[";
        bool first2 = true;
        for (const auto &app : _custom.blacklist) {
            when(first2, out << ",");
            out << JSS(app->name());
        }
        out << "]," << JSF("whitelist") << "[";
        first2 = true;
        for (const auto &app : _custom.whitelist) {
            when(first2, out << ",");
            out << JSS(app->name());
        }
        out << "]}";
    }
    out << "]";
}
