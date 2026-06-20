/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
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

bool DomainStats::hasBlocked(const View view) {
    // Exclusive lock to protect shift() writing to _stats
    const std::lock_guard<std::shared_mutex> lock(_mutex);
    shift();
    for (size_t ts = 0; ts < nbTypes; ++ts) {
        if (stat(view, static_cast<Type>(ts), BLOCK) != 0) {
            return true;
        }
    }
    return false;
}

bool DomainStats::hasAccepted(const View view) {
    const std::lock_guard<std::shared_mutex> lock(_mutex);
    shift();
    for (size_t ts = 0; ts < nbTypes; ++ts) {
        if (stat(view, static_cast<Type>(ts), AUTH) != 0) {
            return true;
        }
    }
    return false;
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

void DomainStats::printNotif(std::ostream &out) const { (void)out; }

void DomainStats::migrateV1V2() {
    for (size_t vs = 0; vs < nbViews; ++vs) {
        for (size_t ts = 0; ts < nbTypes; ++ts) {
            _stats[vs][ts][AUTH] += _stats[vs][ts][BLOCK];
            _stats[vs][ts][BLOCK] = 0;
        }
    }
}

void DomainStats::migrateV4V5(const DomainStats &oldStats) {
    for (size_t vs = 0; vs < nbViews - 1; ++vs) {
        for (size_t ts = 0; ts < nbTypes; ++ts) {
            for (size_t bs = 0; bs < nbBlocks; ++bs) {
                _stats[vs][ts][bs] +=
                    oldStats.stat(static_cast<Stats::View>(vs), static_cast<Stats::Type>(ts),
                                  static_cast<Stats::Block>(bs));
            }
        }
    }
}
