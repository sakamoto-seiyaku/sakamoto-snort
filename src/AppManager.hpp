/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <map>

#include <DomainManager.hpp>
#include <App.hpp>

class AppManager {
private:
    using NamesMap = std::map<std::string, const App::Ptr>;
    using UidMap = std::map<App::Uid, const App::Ptr>;
    using PrintFun = std::function<void(const App::Ptr &)>;
    using FilterFun = std::function<bool(const App::Ptr &)>;

    Saver _saver{settings.saveStatsTotal};
    AppStats _stats;
    UidMap _byUid;
    NamesMap _byName;
    std::shared_mutex _mutexByName;
    std::shared_mutex _mutexByUid;

public:
    AppManager();

    ~AppManager();

    AppManager(const AppManager &) = delete;

    const App::Ptr make(const App::Uid uid);

    const App::Ptr find(const App::Uid uid);

    const App::Ptr find(const std::string &name);

    void install(const App::Uid uid, const App::NamesVec &names);

    void remove(const App::Uid uid, const App::NamesVec &names);

    bool appBlocked(const Domain::Ptr &domain);

    void updateStats(const Domain::Ptr &domain, const App::Ptr &app, const bool blocked,
                     const Stats::Color cs, const Stats::Type ts, const uint64_t val);

    void reset(const Stats::View view);

    void reset();

    void save();

    void restore();

    void printAppsByUid(std::ostream &out, const std::string &subname);

    void printAppsByName(std::ostream &out, const std::string &subname);

    template <class... Args> void printStatsTotal(std::ostream &out, const Args... args);

    template <class... Args>
    void printApps(std::ostream &out, const std::string &subname, const Stats::View view,
                   const Args... args);

    template <class... TypeStats>
    void printDomains(std::ostream &out, const std::string &subname, const Stats::Color cs,
                      const Stats::View view, const TypeStats... ts);

    void migrateV4V5();

private:
    template <class... Names> App::Ptr create(const App::Uid uid, const Names &...names);

    template <class Map, class Arg> App::Ptr find(Map &map, Arg &arg);

    template <class MAP>
    void printAppList(MAP &map, std::ostream &out, const std::string &subname,
                      const PrintFun &&print);

    template <class MAP>
    void printAppList(MAP &map, std::ostream &out, const std::string &subname,
                      const PrintFun &&print, const FilterFun &&filter);
};

template <class... Args> void AppManager::printStatsTotal(std::ostream &out, const Args... args) {
    _stats.print(out, args...);
}

template <class... Args>
void AppManager::printApps(std::ostream &out, const std::string &subname, const Stats::View view,
                           const Args... args) {
    const std::shared_lock_guard lock(_mutexByUid);
    printAppList(
        _byUid, out, subname, [&](const App::Ptr &app) { app->printAppStats(out, view, args...); },
        [&](const App::Ptr &app) -> bool { return app->hasData(view); });
}

template <class... TypeStats>
void AppManager::printDomains(std::ostream &out, const std::string &subname, const Stats::Color cs,
                              const Stats::View view, const TypeStats... ts) {
    const std::shared_lock_guard lock(_mutexByUid);
    printAppList(
        _byUid, out, subname,
        [&](const App::Ptr &app) { app->printDomainStats(out, cs, view, ts...); },
        [&](const App::Ptr &app) -> bool { return app->hasData(cs, view); });
}

extern AppManager appManager;
