/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <fstream>
#include <sys/inotify.h>
#include <thread>
#include <unistd.h>
#include <errno.h>
#include <array>

#include <sucre-snort.hpp>
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
    // Robust inotify loop: add watch once per fd and drain variable-length events.
    for (;;) {
        int fd = inotify_init1(IN_CLOEXEC);
        if (fd == -1) {
            std::this_thread::sleep_for(settings.packagesListRetry);
            continue;
        }

        // Watch the file for writes; also detect inode replacement/deletion (atomic replace)
        int wd = inotify_add_watch(fd, settings.packagesList,
                                   IN_CLOSE_WRITE | IN_MOVE_SELF | IN_DELETE_SELF);
        if (wd == -1) {
            close(fd);
            std::this_thread::sleep_for(settings.packagesListRetry);
            continue;
        }

        std::array<char, 4096> buf{};
        for (;;) {
            ssize_t len = read(fd, buf.data(), buf.size());
            if (len > 0) {
                size_t i = 0;
                bool needRestart = false;
                while (i + sizeof(inotify_event) <= static_cast<size_t>(len)) {
                    const auto *ev = reinterpret_cast<const inotify_event *>(buf.data() + i);
                    if (ev->mask & IN_CLOSE_WRITE) {
                        // No need to hold mutexListeners here; updatePackages does not operate on
                        // listeners themselves and AppManager is internally synchronized.
                        updatePackages();
                    }
                    // If the watched file was moved/deleted (e.g., atomic rename), restart to reattach.
                    if ((ev->mask & IN_MOVE_SELF) || (ev->mask & IN_DELETE_SELF)) {
                        needRestart = true;
                    }
                    i += sizeof(inotify_event) + ev->len;
                }
                if (needRestart) {
                    close(fd);
                    break;
                }
            } else if (len == -1 && errno == EINTR) {
                continue; // retry
            } else {
                // fd closed or error; restart the inotify session
                close(fd);
                break;
            }
        }
    }
}

void PackageListener::updatePackages() {
    NamesMap old(std::move(_names));
    _names.clear();
    for (;;) {
        std::ifstream in(settings.packagesList);
        if (!in.is_open()) {
            std::this_thread::sleep_for(settings.packagesListRetry);
            continue;
        }
        std::string name;
        App::Uid uid;
        while (in >> name >> uid) {
            in.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            _names[uid].push_back(name);
        }
        // Apply delta: install new UIDs; remove ones missing from new snapshot
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
        break; // finished
    }
}
