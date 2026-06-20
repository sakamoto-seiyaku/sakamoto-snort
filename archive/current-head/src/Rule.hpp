/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>

#include <Saver.hpp>

class Rule {
public:
    using Ptr = std::shared_ptr<Rule>;
    using Id = uint32_t;
    enum Type { DOMAIN, WILDCARD, REGEX };

    struct HitsSnapshot {
        std::uint64_t allowHits = 0;
        std::uint64_t blockHits = 0;
    };

private:
    const Id _id;
    Type _type;
    std::string _rule;
    std::string _regex;
    bool _valid;
    // Since-boot counters (not persisted). Thread-safe, lock-free.
    std::atomic<std::uint64_t> _allowHits{0};
    std::atomic<std::uint64_t> _blockHits{0};

public:
    Rule(const Type type, const Id id, const std::string &rule);

    ~Rule();

    Rule(const Rule &) = delete;

    Id id() { return _id; }

    Type type() { return _type; }

    const std::string rule() const { return _rule; }

    const std::string regex() const { return _regex; }

    bool valid() const { return _valid; }

    void observeAllowHit() noexcept { _allowHits.fetch_add(1, std::memory_order_relaxed); }

    void observeBlockHit() noexcept { _blockHits.fetch_add(1, std::memory_order_relaxed); }

    void resetHits() noexcept {
        _allowHits.store(0, std::memory_order_relaxed);
        _blockHits.store(0, std::memory_order_relaxed);
    }

    [[nodiscard]] HitsSnapshot hitsSnapshot() const noexcept {
        return HitsSnapshot{.allowHits = _allowHits.load(std::memory_order_relaxed),
                            .blockHits = _blockHits.load(std::memory_order_relaxed)};
    }

    void update(const Type type, const std::string &rule);

    void save(Saver &saver);

    void restore(Saver &saver);

    void print(std::ostream &out) const;

private:
    void create(const Type type, const std::string &rule);
};
