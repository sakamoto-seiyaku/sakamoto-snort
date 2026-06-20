/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
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

void AppStats::printNotif(std::ostream &out) const {
    out << "{";
    out << JSF("blackBlocked")
        << stat(Stats::DAY0, Stats::DNS, Stats::BLACK, Stats::BLOCK) +
               stat(Stats::DAY0, Stats::DNS, Stats::GREY, Stats::BLOCK);
    out << "," << JSF("whiteBlocked") << stat(Stats::DAY0, Stats::DNS, Stats::WHITE, Stats::BLOCK);
    out << "," << JSF("blackAuth") << stat(Stats::DAY0, Stats::DNS, Stats::BLACK, Stats::AUTH);
    out << "," << JSF("whiteAuth") << stat(Stats::DAY0, Stats::DNS, Stats::WHITE, Stats::AUTH);
    out << "," << JSF("authorized") << stat(Stats::DAY0, Stats::DNS, Stats::GREY, Stats::AUTH);
    out << "," << JSF("rx") << stat(Stats::DAY0, Stats::RXB, Stats::ALLC, Stats::AUTH);
    out << "," << JSF("tx") << stat(Stats::DAY0, Stats::TXB, Stats::ALLC, Stats::AUTH);
    out << "}";
}

void AppStats::migrateV4V5(DomainStats &domStats, const Color cs1, const Color cs2) {
    for (size_t vs = 0; vs < nbViews - 1; ++vs) {
        for (size_t ts = 0; ts < nbTypes; ++ts) {
            for (size_t bs = 0; bs < nbBlocks; ++bs) {
                auto val = domStats.stat(static_cast<View>(vs), ts, bs);
                _stats[vs][ts][cs1][bs] -= _stats[vs][ts][cs1][bs] >= val ? val : 0;
                _stats[vs][ts][cs2][bs] += val;
            }
        }
    }
}
