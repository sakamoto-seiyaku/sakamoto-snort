/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <regex>
#include <sstream>

#include <sucre-snort.hpp>
#include <Rule.hpp>

using namespace std::string_literals;

namespace {

void appendEscapedRegexLiteral(std::stringstream &out, const char c) {
    if (std::string(".^$|()[]{}*+?\\").find(c) != std::string::npos) {
        out << '\\';
    }
    out << c;
}

std::string escapeRegexLiteral(const std::string &text) {
    std::stringstream out;
    for (const char c : text) {
        appendEscapedRegexLiteral(out, c);
    }
    return out.str();
}

} // namespace

Rule::Rule(const Type type, const Id id, const std::string &rule)
    : _id(id) {
    create(type, rule);
}

void Rule::update(const Type type, const std::string &rule) { create(type, rule); }

void Rule::create(const Type type, const std::string &rule) {
    _type = type;
    _rule = rule;
    if (type == Rule::WILDCARD) {
        std::stringstream tmp;
        for (const auto c : rule) {
            switch (c) {
            case '*':
                tmp << ".*";
                break;
            case '?':
                tmp << '.';
                break;
            default:
                // Treat WILDCARD as a pure glob: only '*' and '?' have special
                // meaning. All other regex meta characters must be escaped so
                // that user input cannot accidentally be interpreted as regex.
                appendEscapedRegexLiteral(tmp, c);
            }
        }
        _regex = tmp.str();
    } else if (type == Rule::DOMAIN) {
        _regex = escapeRegexLiteral(rule);
    } else {
        _regex = rule;
    }
    try {
        std::regex _(_regex, std::regex::extended);
        _valid = true;
    } catch (...) {
        _valid = false;
    }
}

Rule::~Rule() {}

void Rule::save(Saver &saver) {
    saver.write<Id>(_id);
    saver.write<Id>(_type);
    saver.write(_rule);
}

void Rule::print(std::ostream &out) const {
    out << "{" << JSF("id") << JSS(_id) << "," << JSF("type") << _type << "," << JSF("rule")
        << JSS(_rule) << "}";
}
