/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <dirent.h>
#include <sstream>

#include <ActivityManager.hpp>
#include <RulesManager.hpp>
#include <Settings.hpp>
#include <AppManager.hpp>

AppManager::AppManager() {}

AppManager::~AppManager() {}

const App::Ptr AppManager::find(const App::Uid uid) {
    const std::shared_lock<std::shared_mutex> lock(_mutexByUid);
    return find(_byUid, uid);
}

const App::Ptr AppManager::find(const std::string &name) {
    const std::shared_lock<std::shared_mutex> lock(_mutexByName);
    return find(_byName, name);
}

const App::Ptr AppManager::make(const App::Uid uid) {
    auto fuid = uid % 100000;
    if (const auto app = find(fuid)) {
        return app;
    } else {
        return create(fuid);
    }
}

template <class... Names> App::Ptr AppManager::create(const App::Uid uid, const Names &...names) {
    const std::scoped_lock lock(_mutexByUid, _mutexByName);
    const auto [it, inserted] = _byUid.emplace(uid, std::make_shared<App>(uid, names...));
    const auto app = it->second;
    if (inserted) {
        _byName.emplace(app->name(), app);
    }
    return app;
}

void AppManager::install(const App::Uid uid, const App::NamesVec &names) {
    if (names.size() == 1) {
        create(uid, names[0]);
    } else {
        create(uid, names);
    }
}

void AppManager::remove(const App::Uid uid, const App::NamesVec &names) {
    // Maintain index consistency even if names is empty or contains aliases.
    const std::scoped_lock lock(_mutexByUid, _mutexByName);
    auto it = _byUid.find(uid);
    if (it != _byUid.end()) {
        // Erase using the canonical name stored on the App object.
        const std::string canonical = it->second->name();
        // Remove persisted state for this app to keep on-disk data consistent.
        it->second->removeFile();
        _byUid.erase(it);
        _byName.erase(canonical);
    } else {
        // Do not attempt best-effort name-based deletion without a matching uid; avoid accidental
        // removal of unrelated entries. Let callers fix their uid/name mapping.
        LOG(WARNING) << __FUNCTION__ << " - remove: uid not found (" << uid
                     << "), skip names fallback";
    }
}

void AppManager::updateStats(const Domain::Ptr &domain, const App::Ptr &app, const bool blocked,
                             const Stats::Color cs, const Stats::Type ts, const uint64_t val) {
    const auto bs = blocked ? Stats::BLOCK : Stats::AUTH;
    _stats.update(ts, cs, bs, val);
    app->updateStats(domain ? domain : domManager.anonymousDom(), ts, cs, bs, val);
    activityManager.update(app, false);
}

void AppManager::reset(const Stats::View view) {
    const std::shared_lock<std::shared_mutex> lock(_mutexByUid);
    for (const auto &[_, app] : _byUid) {
        app->reset(view);
    }
}

void AppManager::reset() {
    // Simple coarse-grained locking: protect indexes during full reset
    const std::scoped_lock lock(_mutexByUid, _mutexByName);
    for (const auto &[_, app] : _byUid) {
        app->removeFile();
    }
    _stats.reset();
    _byUid.clear();
    _byName.clear();
}

void AppManager::save() {
    _saver.save([&] {
        _stats.save(_saver);
        for (const auto &[_, app] : _byUid) {
            app->save();
        }
    });
}

void AppManager::restore() {
    _saver.restore([&] {
        _stats.restore(_saver);
        if (auto dir = opendir(settings.saveDirSystem.c_str())) {
            dirent *de;
            while ((de = readdir(dir)) != nullptr) {
                if (de->d_type == DT_REG) {
                    try {
                        make(std::stoi(de->d_name));
                    } catch (const std::exception &e) {
                        std::remove((settings.saveDirPackages + de->d_name).c_str());
                    }
                }
            }
            closedir(dir);
        }
        for (const auto &[_, app] : _byUid) {
            app->restore(app);
        }
        if (auto dir = opendir(settings.saveDirPackages.c_str())) {
            dirent *de;
            while ((de = readdir(dir)) != nullptr) {
                if (de->d_type == DT_REG && find(de->d_name) == nullptr) {
                    LOG(ERROR) << "remove " << de->d_name;
                    std::remove((settings.saveDirPackages + de->d_name).c_str());
                }
            }
            closedir(dir);
        }
    });
}

void AppManager::printAppsByUid(std::ostream &out, const std::string &subname) {
    const std::shared_lock<std::shared_mutex> lock(_mutexByUid);
    printAppList(_byUid, out, subname, [&](const App::Ptr &app) { app->print(out); });
}

void AppManager::printAppsByName(std::ostream &out, const std::string &subname) {
    const std::shared_lock<std::shared_mutex> lock(_mutexByName);
    printAppList(_byName, out, subname, [&](const App::Ptr &app) { app->print(out); });
}

template <class Map, class Arg> App::Ptr AppManager::find(Map &map, Arg &arg) {
    auto it = map.find(arg);
    return it != map.end() ? it->second : nullptr;
}

template <class MAP>
void AppManager::printAppList(MAP &map, std::ostream &out, const std::string &subname,
                              const PrintFun &&print) {
    printAppList(map, out, subname, std::move(print),
                 [&](const App::Ptr &app) -> bool { return true; });
}

template <class MAP>
void AppManager::printAppList(MAP &map, std::ostream &out, const std::string &subname,
                              const PrintFun &&print, const FilterFun &&filter) {
    out << "[";
    bool first = true;
    for (const auto &[_, app] : map) {
        if (filter(app) &&
            (subname.size() == 0 || app->name().find(subname) != std::string::npos)) {
            when(first, out << ",");
            print(app);
        }
    }
    out << "]";
}

void AppManager::migrateV4V5() {
    for (const auto &[_, app] : _byUid) {
        app->migrateV4V5(_stats);
    }
}
