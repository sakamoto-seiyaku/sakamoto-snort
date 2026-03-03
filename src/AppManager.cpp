/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <dirent.h>
#include <cstring>
#include <sstream>
#include <vector>

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

const App::Ptr AppManager::findByName(const std::string &name, const uint32_t userId) {
    const std::shared_lock<std::shared_mutex> lock(_mutexByUid);
    for (const auto &[uid, app] : _byUid) {
        if (app->userId() == userId && app->name() == name) {
            return app;
        }
    }
    return nullptr;
}

const App::Ptr AppManager::make(const App::Uid uid) {
    if (const auto app = find(uid)) {
        return app;
    } else {
        return create(uid);
    }
}

template <class... Names> App::Ptr AppManager::create(const App::Uid uid, const Names &...names) {
    const std::scoped_lock lock(_mutexByUid, _mutexByName);
    const auto [it, inserted] = _byUid.emplace(uid, std::make_shared<App>(uid, names...));
    const auto app = it->second;
    if (inserted) {
        _byName.emplace(app->name(), app);
    } else {
        // UID already exists - check if we should upgrade from anonymous to named
        // This handles the case where traffic was observed before packages.list was parsed
        if constexpr (sizeof...(names) > 0) {
            const std::string oldName = app->name();
            // Try to upgrade - will only succeed if app is currently anonymous
            if (app->upgradeName(names...)) {
                // Update _byName index: remove old entry, add new entry
                _byName.erase(oldName);
                _byName.emplace(app->name(), app);
            }
        }
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

void AppManager::reset(const Stats::View view, const std::optional<uint32_t> userId) {
    const std::shared_lock<std::shared_mutex> lock(_mutexByUid);
    for (const auto &[_, app] : _byUid) {
        if (userId.has_value() && app->userId() != userId.value()) {
            continue;
        }
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
        std::vector<App::Ptr> apps;
        {
            const std::shared_lock<std::shared_mutex> lock(_mutexByUid);
            apps.reserve(_byUid.size());
            for (const auto &[_, app] : _byUid) {
                apps.push_back(app);
            }
        }
        for (const auto &app : apps) {
            app->save();
        }
    });
}

void AppManager::restore() {
    _saver.restore([&] {
        _stats.restore(_saver);
        // Restore state only for apps already in _byUid (created by PackageListener or runtime make()).
        // Do not create new Apps from persisted files - App lifecycle is driven by packages.list
        // and runtime UID discovery, not by saved state files.
        std::vector<App::Ptr> apps;
        {
            const std::shared_lock<std::shared_mutex> lock(_mutexByUid);
            apps.reserve(_byUid.size());
            for (const auto &[_, app] : _byUid) {
                apps.push_back(app);
            }
        }
        for (const auto &app : apps) {
            app->restore(app);
        }
        // Clean up orphan package save files for apps that no longer exist
        // Helper lambda to clean orphan files in a packages directory
        auto cleanOrphanFiles = [this](const std::string &packagesDir) {
            if (auto dir = opendir(packagesDir.c_str())) {
                dirent *de;
                while ((de = readdir(dir)) != nullptr) {
                    if (de->d_type == DT_REG && find(de->d_name) == nullptr) {
                        LOG(WARNING) << "remove orphan save file: " << de->d_name;
                        std::remove((packagesDir + de->d_name).c_str());
                    }
                }
                closedir(dir);
            }
        };
        // Clean user 0 packages directory
        cleanOrphanFiles(settings.saveDirPackages);
        // Clean per-user packages directories (user1, user2, ...)
        // Derive save directory from saveDirPackages by removing "packages/" suffix
        std::string saveDir = settings.saveDirPackages;
        auto pos = saveDir.rfind("packages/");
        if (pos != std::string::npos) {
            saveDir = saveDir.substr(0, pos);
            if (auto dir = opendir(saveDir.c_str())) {
                dirent *de;
                while ((de = readdir(dir)) != nullptr) {
                    // Look for directories named "user<N>" where N >= 1
                    if (de->d_type == DT_DIR &&
                        strncmp(de->d_name, "user", 4) == 0 &&
                        de->d_name[4] >= '1' && de->d_name[4] <= '9') {
                        cleanOrphanFiles(saveDir + de->d_name + "/packages/");
                    }
                }
                closedir(dir);
            }
        }
    });
}

void AppManager::printAppsByUid(std::ostream &out, const std::string &subname,
                                const std::optional<uint32_t> userId) {
    const std::shared_lock<std::shared_mutex> lock(_mutexByUid);
    printAppList(_byUid, out, subname, [&](const App::Ptr &app) { app->print(out); },
                 [&](const App::Ptr &app) -> bool {
                     // Filter by userId if specified (nullopt = all users)
                     if (userId.has_value() && app->userId() != userId.value()) {
                         return false;
                     }
                     return true;
                 });
}

void AppManager::printAppsByName(std::ostream &out, const std::string &subname,
                                 const std::optional<uint32_t> userId) {
    const std::shared_lock<std::shared_mutex> lock(_mutexByName);
    printAppList(_byName, out, subname, [&](const App::Ptr &app) { app->print(out); },
                 [&](const App::Ptr &app) -> bool {
                     // Filter by userId if specified (nullopt = all users)
                     if (userId.has_value() && app->userId() != userId.value()) {
                         return false;
                     }
                     return true;
                 });
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
