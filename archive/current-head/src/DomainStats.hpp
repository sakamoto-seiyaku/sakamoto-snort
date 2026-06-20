/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <Stats.hpp>

class DomainStats : public StatsTPL<uint64_t[Stats::nbTypes][Stats::nbBlocks]> {
public:
    DomainStats();

    ~DomainStats();

    DomainStats(const DomainStats &) = delete;

    void update(const Type ts, const Block bs, const uint64_t val);

    bool hasBlocked(const View view);

    bool hasAccepted(const View view);

    void migrateV1V2();

    void migrateV4V5(const DomainStats &oldStats);

    uint64_t stat(const View view, const size_t ts, const size_t bs) const;

private:
    bool hasDataType(const View view, const Type ts) const;

    void resetDay(const View view);

    void printType(std::ostream &out, const View view, const Type ts) const;

    void printNotif(std::ostream &out) const;
};
