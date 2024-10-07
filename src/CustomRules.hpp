/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <regex>
#include <unordered_set>

#include <Rule.hpp>

class CustomRules {
private:
    std::unordered_set<Rule::Ptr> _rules;
    std::shared_mutex _mutex;
    std::regex _regex;
    bool _saved = false;

public:
    CustomRules();

    ~CustomRules();

    CustomRules(const CustomRules &) = delete;

    bool saved() { return _saved; }

    void add(const Rule::Ptr &rule, const bool compile);

    void remove(const Rule::Ptr &rule, const bool compile);

    void build();

    bool match(const Domain::Ptr &domain);

    void reset();

    void save(Saver &saver);

    void restore(Saver &saver);

    void print(std::ostream &out);
};
