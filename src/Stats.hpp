/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <iode-snort.hpp>
#include <Saver.hpp>

class ListColorException : public std::exception {};

class Stats {
public:
    enum View { DAY0, DAY1, DAY2, DAY3, DAY4, DAY5, DAY6, ALL, WEEK };
    enum Type { DNS, RXP, RXB, TXP, TXB };
    enum Color { ALLC, BLACK, WHITE, GREY };
    enum Block { ALLB, BLOCK, AUTH };

    static constexpr const char *colorNames[]{"total", "black", "white", "grey"};
    static constexpr const char *typeNames[]{"dns", "rxp", "rxb", "txp", "txb"};
    static constexpr const size_t nbViews = 9;
    static constexpr const size_t nbDays = 7;
    static constexpr const size_t nbTypes = 5;
    static constexpr const size_t nbColors = 4;
    static constexpr const size_t nbBlocks = 3;

protected:
    static constexpr const std::time_t _timeStep = 3600 * 24;

public:
    Stats();

    ~Stats();

    Stats(const Stats &) = delete;

    static inline std::string colorToString(Stats::Color color) {
        if (color == Stats::BLACK) {
            return "block";
        } else if (color == Stats::WHITE) {
            return "allow";
        } else {
            throw ListColorException();
        }
    }

    static inline Stats::Color colorFromString(std::string colorStr) {
        if (colorStr == "block") {
            return Stats::BLACK;
        } else if (colorStr == "allow") {
            return Stats::WHITE;
        } else {
            throw ListColorException();
        }
    }
};

template <class T> class StatsTPL : public Stats {
protected:
    T _stats[nbViews - 1];
    std::shared_mutex _mutex;

private:
    time_t _timestamp;
    std::mutex _mutexTimestamp;

public:
    StatsTPL();

    virtual ~StatsTPL();

    void save(Saver &saver) const;

    void restore(Saver &saver);

    bool hasData(const View view);

    void reset(const View view);

    void reset();

    void print(std::ostream &out);

    void print(std::ostream &out, const View view);

    void print(std::ostream &out, const View view, const Type ts);

protected:
    static time_t timestamp();

    void shift();

    virtual bool hasDataType(const View view, const Type ts) const = 0;

    virtual void resetDay(const View view) = 0;

    virtual void printType(std::ostream &out, const View view, const Type ts) const = 0;

    virtual void printNotif(std::ostream &out) const = 0;
};
