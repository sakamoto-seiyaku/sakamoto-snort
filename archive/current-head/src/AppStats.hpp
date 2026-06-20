/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <Stats.hpp>
#include <DomainStats.hpp>

class AppStats : public StatsTPL<uint64_t[Stats::nbTypes][Stats::nbColors][Stats::nbBlocks]> {
public:
    AppStats();

    ~AppStats();

    AppStats(const AppStats &) = delete;

    void update(const Type ts, const Color cs, const Block bs, const uint64_t val);

    uint64_t stat(const View view, const size_t ts, const size_t cs, const size_t bs) const;

    void migrateV4V5(DomainStats &domStats, const Color cs1, const Color cs2);

private:
    bool hasDataType(const View view, const Type ts) const;

    void printType(std::ostream &out, const View view, const Type ts) const;

    void printNotif(std::ostream &out) const;

    void resetDay(const View day);
};
