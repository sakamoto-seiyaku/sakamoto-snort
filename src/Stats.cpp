/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
 
#include <Saver.hpp>
#include <Stats.hpp>

Stats::Stats() {}

Stats::~Stats() {}

template <class T> StatsTPL<T>::StatsTPL() {
    _timestamp = timestamp();
    reset();
}

template <class T> StatsTPL<T>::~StatsTPL() {}

template <class T> void StatsTPL<T>::save(Saver &saver) const {
    saver.write<time_t>(_timestamp);
    saver.write(_stats);
}

template <class T> void StatsTPL<T>::restore(Saver &saver) {
    _timestamp = saver.read<time_t>();
    saver.read(_stats);
}

template <class T> time_t StatsTPL<T>::timestamp() {
    auto t = std::time(nullptr);
    struct tm loctime;
    return timegm(localtime_r(&t, &loctime)) / _timeStep;
}

template <class T> void StatsTPL<T>::shift() {
    const std::lock_guard lock(_mutexTimestamp);
    const time_t update = timestamp();
    if (update > _timestamp) {
        const time_t diff = update - _timestamp;
        _timestamp = update;
        ssize_t i;
        for (i = nbDays - 1; i - diff >= 0; i--) {
            std::memcpy(_stats[i], _stats[i - diff], sizeof(T));
        }
        for (; i >= 0; i--) {
            std::memset(_stats[i], 0, sizeof(T));
        }
    }
}

template <class T> bool StatsTPL<T>::hasData(const View view) {
    const std::shared_lock_guard lock(_mutex);
    shift();
    for (size_t ts = 0; ts < nbTypes; ++ts) {
        if (hasDataType(view, static_cast<Type>(ts))) {
            return true;
        }
    }
    return false;
}

template <class T> void StatsTPL<T>::reset(const View view) {
    const std::lock_guard lock(_mutex);
    shift();
    switch (view) {
    case ALL:
        reset();
        break;
    case WEEK:
        for (size_t view = 0; view < nbDays; ++view) {
            resetDay(static_cast<View>(view));
        }
        break;
    default:
        resetDay(view);
        break;
    }
}

template <class T> void StatsTPL<T>::reset() { std::memset(_stats, 0, sizeof(_stats)); }

template <class T> void StatsTPL<T>::print(std::ostream &out) {
    const std::shared_lock_guard lock(_mutex);
    shift();
    printNotif(out);
}

template <class T> void StatsTPL<T>::print(std::ostream &out, const View view) {
    const std::shared_lock_guard lock(_mutex);
    shift();
    out << "{";
    for (size_t ts = 0; ts < nbTypes; ++ts) {
        if (ts > 0) {
            out << ",";
        }
        out << JSF(typeNames[ts]);
        printType(out, view, static_cast<Type>(ts));
    }
    out << "}";
}

template <class T> void StatsTPL<T>::print(std::ostream &out, const View view, const Type ts) {
    const std::shared_lock_guard lock(_mutex);
    shift();
    printType(out, view, ts);
}

template class StatsTPL<uint64_t[Stats::nbTypes][Stats::nbColors][Stats::nbBlocks]>;
template class StatsTPL<uint64_t[Stats::nbTypes][Stats::nbBlocks]>;
