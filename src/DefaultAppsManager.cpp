/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <android-base/properties.h>
#include <dirent.h>
#include <fstream>
#include <sys/stat.h>
#include <thread>

#include <iode-snort.hpp>
#include <CmdLine.hpp>
#include <Settings.hpp>
#include <DefaultAppsManager.hpp>

DefaultAppsManager::DefaultAppsManager() {}

DefaultAppsManager::~DefaultAppsManager() {}

void DefaultAppsManager::start() {
    std::unordered_map<std::string, DefApp> defapps;

    try {
        std::ifstream in;
        in.exceptions(std::ifstream::failbit | std::ifstream::badbit);
        in.open(settings.defaultAppsFile);
        if (in.is_open()) {
            std::string app, dir;
            uint32_t status;
            bool removable;
            uint32_t category;
            while (in.peek() != EOF && in >> app >> dir >> status >> removable >> category) {
                defapps.try_emplace(app, dir, static_cast<Status>(status), removable, category);
                in.seekg(1, std::ios_base::cur);
            }
        }
    } catch (const std::ifstream::failure &_) {
        defapps.clear();
    }

    if (std::ifstream in(settings.defaultAppsFileEtc); in.is_open()) {
        std::string app, appdir;
        Status status;
        bool removable;
        uint32_t category;

        mkdir("/mnt/iode", 0700);
        mkdir("/mnt/iode/empty", 0700);

        while (in >> app >> appdir >> removable >> category) {
            auto it = defapps.find(app);
            std::string dir;
            bool found = false;
            if (it != defapps.end()) {
                if (const std::ifstream exists(it->second.dir); exists.is_open()) {
                    dir = it->second.dir;
                    found = true;
                }
            }
            if (!found) {
                for (const auto dir1 : {"/system", "/system_ext", "/system/product"}) {
                    for (const auto dir2 : {"/app/", "/priv-app/"}) {
                        dir = std::string(dir1) + dir2 + appdir;
                        if (const std::ifstream exists(dir); exists.is_open()) {
                            found = true;
                            break;
                        }
                    }
                    if (found) {
                        break;
                    }
                }
            }
            status = INSTALLED;
            if (found && it != defapps.end()) {
                const auto &app = it->first;
                status = it->second.status;
                if (status == REMOVED || status == TOBEREMOVED) {
                    if (removable) {
                        if (auto dirfd = opendir(dir.c_str())) {
                            bool empty = true;
                            dirent *de;
                            while ((de = readdir(dirfd)) != nullptr) {
                                if (de->d_type == DT_REG) {
                                    CmdLine(settings.mountShell, "-o", "bind",
                                            "/mnt/iode/empty", dir)
                                        .exec();
                                    break;
                                }
                            }
                        }
                        std::thread([=] {
                            if (android::base::WaitForProperty("sys.boot_completed", "1")) {
                                CmdLine(settings.pmShell, "disable", app).exec();
                                CmdLine(settings.pmShell, "hide", app).exec();
                            }
                        }).detach();
                    }
                    status = REMOVED;
                } else if (status == TOBEINSTALLED) {
                    std::thread([=] {
                        if (!settings.firstStart()) {
                            if (android::base::WaitForProperty("sys.boot_completed", "1")) {
                                CmdLine(settings.pmShell, "install", "-g",
                                        dir + "/" + appdir + ".apk")
                                    .exec();
                            }
                        }
                    }).detach();
                    status = INSTALLED;
                }
            }
            if (found) {
                _apps.try_emplace(app, dir, status, removable, category);
            }
        }
        save();
        settings.finishFirstStart();
    }
}

void DefaultAppsManager::install(const std::string &app) {
    if (auto it = _apps.find(app); it != _apps.end()) {
        auto &defapp = it->second;
        if (defapp.removable && defapp.status == REMOVED) {
            const std::lock_guard lock(_mutex);
            defapp.status = TOBEINSTALLED;
        } else {
            CmdLine(settings.pmShell, "unhide", app).exec();
            CmdLine(settings.pmShell, "enable", app).exec();
            const std::lock_guard lock(_mutex);
            defapp.status = INSTALLED;
        }
        save();
    }
}

void DefaultAppsManager::remove(const std::string &app) {
    if (auto it = _apps.find(app); it != _apps.end()) {
        auto &defapp = it->second;
        CmdLine(settings.pmShell, "disable", app).exec();
        CmdLine(settings.pmShell, "hide", app).exec();
        if (defapp.removable && defapp.status == INSTALLED) {
            CmdLine(settings.pmShell, "clear", app).exec();
            CmdLine(settings.pmShell, "uninstall-system-updates", app).exec();
            const std::lock_guard lock(_mutex);
            defapp.status = TOBEREMOVED;
        } else {
            const std::lock_guard lock(_mutex);
            defapp.status = REMOVED;
        }
        save();
    }
}

void DefaultAppsManager::save() {
    const std::shared_lock_guard lock(_mutex);
    if (auto out = std::ofstream(settings.defaultAppsFile + ".tmp")) {
        for (const auto &[app, defapp] : _apps) {
            out << app << " " << defapp.dir << " " << defapp.status << " " << defapp.removable
                << " " << defapp.category << "\n";
        }
        out.close();
        std::rename((settings.defaultAppsFile + ".tmp").c_str(), settings.defaultAppsFile.c_str());
    }
}

void DefaultAppsManager::print(std::ostream &out) {
    const std::shared_lock_guard lock(_mutex);
    bool first = true;
    out << "[";
    for (const auto &[app, defapp] : _apps) {
        when(first, out << ",");
        out << "{" << JSF("name") << JSS(app) << "," << JSF("status") << defapp.status << ","
            << JSF("removable") << defapp.removable << "," << JSF("category") << defapp.category
            << "}";
    }
    out << "]";
}
