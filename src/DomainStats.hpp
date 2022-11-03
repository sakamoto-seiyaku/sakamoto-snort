/*
 * Copyright 2019 - 2022, iodé Technologies
 *
 * This file is part of the iode-snort project.
 *
 * iode-snort is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * iode-snort is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with iode-snort. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <Stats.hpp>

class DomainStats : public StatsTPL<uint64_t[Stats::nbTypes][Stats::nbBlocks]> {
public:
    DomainStats();

    ~DomainStats();

    DomainStats(const DomainStats &) = delete;

    void update(const Type ts, const Block bs, const uint64_t val);

    bool hasBlackBlocked(const View view);

    bool hasBlackAccepted(const View view);

    void migrateV1V2();

private:
    uint64_t stat(const View view, const size_t ts, const size_t bs) const;

    bool hasDataType(const View view, const Type ts) const;

    void resetDay(const View view);

    void printType(std::ostream & out, const View view, const Type ts) const;
};
