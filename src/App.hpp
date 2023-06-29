/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
 
#pragma once

#include <vector>

#include <AppStats.hpp>
#include <DomainManager.hpp>
#include <Settings.hpp>

class App {
public:
    using Ptr = std::shared_ptr<App>;
    using Uid = uint32_t;
    using NamesVec = std::vector<const std::string>;
    using FindDomainFun = std::function<const Domain::Ptr(const std::string &)>;

private:
    using DomStatsMap = std::unordered_map<Domain::Ptr, DomainStats>;
    using PrintFun = std::function<void(App &app)>;

    Saver _saver;

    const Uid _uid;
    const std::string _name;
    const NamesVec _names;
    std::atomic_bool _saved = false;
    AppStats _stats;
    std::pair<DomStatsMap, std::shared_mutex> _domStats[Stats::nbColors - 1];
    std::atomic_bool _tracked = true;
    std::atomic_uint8_t _blockMask;
    std::atomic_uint8_t _blockIface;
    std::atomic_bool _useCustomList;

    CustomList _customBlacklist;
    CustomList _customWhitelist;

public:
    App(const Uid uid, const FindDomainFun &&findDomain, const NamesVec &names = NamesVec());

    App(const Uid uid, const FindDomainFun &&findDomain, const std::string &name);

    App(const App &) = delete;

    CustomList &customListConst(const Stats::Color color) {
        return color == Stats::BLACK ? _customBlacklist : _customWhitelist;
    }

    CustomList &customList(const Stats::Color color) {
        _saved = false;
        return customListConst(color);
    }

    const std::string &name() const { return _name; }

    const NamesVec &names() const { return _names; }

    uint8_t blockMask() const { return _blockMask; }

    void blockMask(const uint8_t blockMask) {
        _saved = false;
        _blockMask = blockMask;
    }

    uint8_t blockIface() const { return _blockIface; }

    void blockIface(const uint8_t blockIface) {
        _saved = false;
        _blockIface = blockIface;
    }

    bool tracked() const { return _tracked; }

    void tracked(const bool tracked) {
        _saved = false;
        _tracked = tracked;
    }

    void useCustomList(const bool useCustomList) {
        _saved = false;
        _useCustomList = useCustomList;
    }

    bool useCustomList() const { return _useCustomList; }

    bool hasData(const Stats::View view);

    bool hasData(const Stats::Color cs, const Stats::View view);

    const std::pair<bool, Stats::Color> blocked(const Domain::Ptr &domain);

    void updateStats(const Domain::Ptr &domain, const Stats::Type ts, const Stats::Color cs,
                     const Stats::Block bs, const uint64_t val);

    void reset(const Stats::View vs);

    void save();

    void restore();

    void removeFile();

    void print(std::ostream &out);

    template <class... Args> void printAppStats(std::ostream &out, const Args... args);

    template <class... Args> void printAppNotif(std::ostream &out);

    template <class... Args> void printDomainStats(std::ostream &out, const Args... args);

    template <class... TypeStats>
    void printDomains(std::ostream &out, const Stats::Color cs, const Stats::View view,
                      const TypeStats... ts);

    void printCustomLists(std::ostream &out);

    void migrateV4V5(AppStats &globStats);

private:
    App(const Uid uid, const FindDomainFun &&findDomain, const std::string &name,
        const NamesVec &names, const std::string &&saveFile, const std::uint8_t blockMask,
        const std::uint8_t blockIface, const bool useCustomList);

    DomStatsMap &domStats(const size_t cs) { return _domStats[cs - 1].first; }

    std::shared_mutex &mutex(const Stats::Color cs) { return _domStats[cs - 1].second; }

    void print(std::ostream &out, const PrintFun &&print);
};

template <class... Args> void App::printAppStats(std::ostream &out, const Args... args) {
    print(out, [&](App &app) {
        out << "," << JSF("stats");
        app._stats.print(out, args...);
    });
}

template <class... Args> void App::printAppNotif(std::ostream &out) {
    print(out, [&](App &app) {
        out << "," << JSF("stats");
        app._stats.print(out);
    });
}

template <class... Args> void App::printDomainStats(std::ostream &out, const Args... args) {
    print(out, [&](App &app) {
        out << "," << JSF("domains");
        app.printDomains(out, args...);
    });
}

template <class... TypeStats>
void App::printDomains(std::ostream &out, const Stats::Color cs, const Stats::View view,
                       const TypeStats... ts) {
    out << "[";
    bool first = true;
    for (auto &[domain, stats] : domStats(cs)) {
        const std::shared_lock_guard lock(mutex(cs));
        if (stats.hasData(view)) {
            when(first, out << ",");
            domain->print(out, stats, view, ts...);
        }
    }
    out << "]";
}
