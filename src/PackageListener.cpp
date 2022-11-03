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

#include <fstream>
#include <sys/inotify.h>
#include <thread>

#include <iode-snort.hpp>
#include <Settings.hpp>
#include <PackageListener.hpp>

PackageListener::PackageListener() {}

PackageListener::~PackageListener() {}

void PackageListener::start() {
    updatePackages();
    std::thread([=] { listen(); }).detach();
}

void PackageListener::reset() {
    _names.clear();
    updatePackages();
}

void PackageListener::listen() {
    char buf[sizeof(inotify_event)];
    for (;;) {
        if (int fd = inotify_init(); fd != -1) {
            for (;;) {
                if (inotify_add_watch(fd, settings.packagesList, IN_CLOSE_WRITE) != -1) {
                    if (read(fd, buf, sizeof(buf)) > 0) {
                        const std::shared_lock_guard lock(mutexListeners);
                        updatePackages();
                    } else {
                        close(fd);
                        break;
                    }
                }
            }
        }
    }
}

void PackageListener::updatePackages() {
    NamesMap old(std::move(_names));
    std::ifstream in;
    in.exceptions(std::ifstream::failbit | std::ifstream::badbit | std::ifstream::eofbit);
    bool finished = false;
    while (!finished) {
        try {
            std::string name;
            App::Uid uid;
            in = std::ifstream(settings.packagesList);
            while (in >> name >> uid) {
                in.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                _names[uid].push_back(name);
            }
            for (const auto &[uid, names] : _names) {
                if (const auto it = old.find(uid); it == old.end()) {
                    appManager.install(uid, names);
                } else {
                    old.erase(it);
                }
            }
            for (const auto &[uid, names] : old) {
                appManager.remove(uid, names);
            }
            finished = true;
        } catch (std::ifstream::failure _) {
            std::this_thread::sleep_for(settings.packagesListRetry);
        }
    }
}
