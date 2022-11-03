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

#include <DomainStats.hpp>

DomainStats::DomainStats() {}

DomainStats::~DomainStats() {}

void DomainStats::update(const Type ts, const Block bs, const uint64_t val) {
    const std::lock_guard lock(_mutex);
    shift();
    _stats[DAY0][ts][bs] += val;
    _stats[DAY0][ts][ALLB] += val;
    _stats[ALL][ts][bs] += val;
    _stats[ALL][ts][ALLB] += val;
}

uint64_t DomainStats::stat(const View view, const size_t ts, const size_t bs) const {
    if (view == WEEK) {
        uint64_t total = 0;
        for (size_t i = 0; i < nbDays; ++i) {
            total += _stats[i][ts][bs];
        }
        return total;
    } else {
        return _stats[view][ts][bs];
    }
}

bool DomainStats::hasBlackBlocked(const View view) {
    const std::shared_lock_guard lock(_mutex);
    shift();
    return stat(view, DNS, BLOCK) != 0;
}

bool DomainStats::hasBlackAccepted(const View view) {
    const std::shared_lock_guard lock(_mutex);
    shift();
    return stat(view, DNS, AUTH) != 0;
}

bool DomainStats::hasDataType(const View view, const Type ts) const {
    return stat(view, ts, ALLB) != 0;
}

void DomainStats::resetDay(const View view) {
    for (size_t ts = 0; ts < nbTypes; ++ts) {
        for (size_t bs = 0; bs < nbBlocks; ++bs) {
            _stats[ALL][ts][bs] -= _stats[view][ts][bs];
            _stats[view][ts][bs] = 0;
        }
    }
}

void DomainStats::printType(std::ostream &out, const View view, const Type ts) const {
    out << "[";
    for (size_t bs = 0; bs < nbBlocks; ++bs) {
        if (bs > 0) {
            out << ",";
        }
        out << stat(view, ts, bs);
    }
    out << "]";
}

void DomainStats::migrateV1V2() {
    for (size_t vs = 0; vs < nbViews; ++vs) {
        for (size_t ts = 0; ts < nbTypes; ++ts) {
            _stats[vs][ts][AUTH] += _stats[vs][ts][BLOCK];
            _stats[vs][ts][BLOCK] = 0;
        }
    }
}
