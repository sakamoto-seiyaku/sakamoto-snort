/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <memory>

#include <Saver.hpp>

class Rule {
public:
    using Ptr = std::shared_ptr<Rule>;
    using Id = uint32_t;
    enum Type { DOMAIN, WILDCARD, REGEX };

private:
    const Id _id;
    Type _type;
    std::string _rule;
    std::string _regex;
    bool _valid;

public:
    Rule(const Type type, const Id id, const std::string &rule);

    ~Rule();

    Rule(const Rule &) = delete;

    Id id() { return _id; }

    Type type() { return _type; }

    const std::string rule() const { return _rule; }

    const std::string regex() const { return _regex; }

    bool valid() const { return _valid; }

    void update(const Type type, const std::string &rule);

    void save(Saver &saver);

    void restore(Saver &saver);

    void print(std::ostream &out) const;

private:
    void create(const Type type, const std::string &rule);
};
