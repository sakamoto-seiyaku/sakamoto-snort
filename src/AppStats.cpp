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

#include <AppStats.hpp>

AppStats::AppStats() {}

AppStats::~AppStats() {}

void AppStats::update(const Type ts, const Color cs, const Block bs, const uint64_t val) {
    const std::lock_guard lock(_mutex);
    shift();
    _stats[DAY0][ts][cs][bs] += val;
    _stats[DAY0][ts][ALLC][bs] += val;
    _stats[DAY0][ts][cs][ALLB] += val;
    _stats[DAY0][ts][ALLC][ALLB] += val;
    _stats[ALL][ts][cs][bs] += val;
    _stats[ALL][ts][ALLC][bs] += val;
    _stats[ALL][ts][cs][ALLB] += val;
    _stats[ALL][ts][ALLC][ALLB] += val;
}

uint64_t AppStats::stat(const View view, const size_t ts, const size_t cs, const size_t bs) const {
    if (view == WEEK) {
        uint64_t total = 0;
        for (size_t i = 0; i < nbDays; ++i) {
            total += _stats[i][ts][cs][bs];
        }
        return total;
    } else {
        return _stats[view][ts][cs][bs];
    }
}

bool AppStats::hasDataType(const View view, const Type ts) const {
    return stat(view, ts, ALLC, ALLB) != 0;
}

void AppStats::resetDay(const View day) {
    for (size_t ts = 0; ts < nbTypes; ++ts) {
        for (size_t cs = 0; cs < nbColors; ++cs) {
            for (size_t bs = 0; bs < nbBlocks; ++bs) {
                _stats[ALL][ts][cs][bs] -= _stats[day][ts][cs][bs];
                _stats[day][ts][cs][bs] = 0;
            }
        }
    }
}

void AppStats::printType(std::ostream &out, const View view, const Type ts) const {
    out << "{";
    for (size_t cs = 0; cs < nbColors; ++cs) {
        if (cs > 0) {
            out << ",";
        }
        out << JSF(colorNames[cs]);
        out << "[";
        for (size_t bs = 0; bs < nbBlocks; ++bs) {
            if (bs > 0) {
                out << ",";
            }
            out << stat(view, ts, cs, bs);
        }
        out << "]";
    }
    out << "}";
}
