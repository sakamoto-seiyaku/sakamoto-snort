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

namespace {
// App UIDs in Android are >= AID_APP_START (10000).
// UIDs below this threshold are system/root UIDs and should not be tracked as apps.
constexpr App::Uid AID_APP_START = 10000;

bool isAppUid(const App::Uid uid) { return uid >= AID_APP_START; }
} // namespace

void PackageListener::start() {
    updatePackages();
    std::thread([=, this] { listen(); }).detach();
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

            // Security validation 1: Filter non-app UIDs (system UIDs < 10000 are not tracked)
            if (!isAppUid(uid)) {
                continue;
            }

            // Security validation 2: userId range check (0 ≤ userId < 10000)
            const uint32_t userId = uid / 100000;
            if (userId >= 10000) {
                LOG(WARNING) << "packages.list: rejecting invalid userId " << userId
                             << " for uid " << uid;
                continue;
            }

            // Security validation 3: Package name validation
            // - Reject empty names
            // - Reject names with control characters (< 32), NUL, or high bytes that could be exploits
            // - Reject names with path traversal patterns
            // - Enforce reasonable length limit
            if (name.empty() || name.size() > 256) {
                LOG(WARNING) << "packages.list: rejecting invalid name length for uid " << uid;
                continue;
            }

            bool validName = true;
            for (unsigned char c : name) {
                // Reject control characters, NUL, DEL (127), and non-ASCII bytes
                if (c < 32 || c == 127) {
                    validName = false;
                    break;
                }
            }
            if (!validName) {
                LOG(WARNING) << "packages.list: rejecting name with invalid characters for uid " << uid;
                continue;
            }

            // Reject path traversal attempts
            if (name.find("..") != std::string::npos || name.find('/') != std::string::npos) {
                LOG(WARNING) << "packages.list: rejecting name with path traversal for uid " << uid;
                continue;
            }

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
