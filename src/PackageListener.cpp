/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <fstream>
#include <dirent.h>
#include <sys/inotify.h>
#include <thread>
#include <unistd.h>
#include <errno.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <string_view>
#include <unordered_set>

#include <sucre-snort.hpp>
#include <Settings.hpp>
#include <PackageState.hpp>
#include <PackageListener.hpp>

PackageListener::PackageListener() {}

PackageListener::~PackageListener() {}

namespace {
// App UIDs in Android are >= AID_APP_START (10000).
// UIDs below this threshold are system/root UIDs and should not be tracked as apps.
constexpr App::Uid AID_APP_START = 10000;
constexpr uint32_t AID_USER_OFFSET = 100000;

bool isAppUid(const App::Uid uid) { return uid >= AID_APP_START; }

bool isNumeric(const char *s) {
    if (s == nullptr || *s == '\0') {
        return false;
    }
    for (const unsigned char c : std::string_view{s}) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    return true;
}

bool tryParseUserId(const char *s, uint32_t &out) {
    if (!isNumeric(s)) {
        return false;
    }
    uint64_t value = 0;
    for (const unsigned char c : std::string_view{s}) {
        value = value * 10 + static_cast<uint64_t>(c - '0');
        if (value > std::numeric_limits<uint32_t>::max()) {
            return false;
        }
    }
    if (value >= 10000) {
        return false;
    }
    out = static_cast<uint32_t>(value);
    return true;
}

bool enumerateUserIds(std::vector<uint32_t> &outUserIds, std::string &error) {
    outUserIds.clear();
    DIR *dir = opendir(Settings::systemUsersDir);
    if (dir == nullptr) {
        error = std::string("opendir failed: ") + std::strerror(errno);
        return false;
    }

    std::unordered_set<uint32_t> uniq;
    dirent *de;
    while ((de = readdir(dir)) != nullptr) {
        if (std::strcmp(de->d_name, ".") == 0 || std::strcmp(de->d_name, "..") == 0) {
            continue;
        }
        uint32_t userId = 0;
        if (!tryParseUserId(de->d_name, userId)) {
            continue;
        }
        uniq.emplace(userId);
    }
    closedir(dir);

    if (uniq.empty()) {
        error = "no users found";
        return false;
    }

    outUserIds.assign(uniq.begin(), uniq.end());
    std::sort(outUserIds.begin(), outUserIds.end());
    return true;
}
} // namespace

void PackageListener::start() {
    updatePackages();
    std::thread([=, this] { listen(); }).detach();
}

void PackageListener::reset() {
    {
        const std::lock_guard lock(_mutexNames);
        _names.clear();
    }
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
    const auto retryDelay = std::chrono::milliseconds(100);

    for (;;) {
        PackageState::PackagesListSnapshot packages;
        std::string parseError;
        if (!PackageState::parsePackagesListFile(settings.packagesList, packages, &parseError)) {
            LOG(WARNING) << "packages.list: parse failed: " << parseError;
            std::this_thread::sleep_for(retryDelay);
            continue;
        }

        std::vector<uint32_t> userIds;
        std::string usersError;
        if (!enumerateUserIds(userIds, usersError)) {
            LOG(WARNING) << Settings::systemUsersDir << ": enumerate users failed: " << usersError;
            std::this_thread::sleep_for(retryDelay);
            continue;
        }

        NamesMap newNames;
        bool ok = true;
        for (const uint32_t userId : userIds) {
            const std::string path = Settings::packageRestrictionsPath(userId);
            PackageState::PackageRestrictionsSnapshot restrictions;
            std::string rerr;
            if (!PackageState::parsePackageRestrictionsFile(path.c_str(), restrictions, &rerr)) {
                LOG(WARNING) << path << ": parse failed: " << rerr;
                ok = false;
                break;
            }

            for (const auto &pkgName : restrictions.installedPackages) {
                const auto it = packages.packageToAppId.find(pkgName);
                if (it == packages.packageToAppId.end()) {
                    continue;
                }
                const uint32_t appId = it->second;
                const auto namesIt = packages.appIdToNames.find(appId);
                if (namesIt == packages.appIdToNames.end()) {
                    continue;
                }

                const uint64_t fullUid64 = static_cast<uint64_t>(userId) * AID_USER_OFFSET + appId;
                if (fullUid64 > std::numeric_limits<App::Uid>::max()) {
                    continue;
                }
                const App::Uid fullUid = static_cast<App::Uid>(fullUid64);
                if (!isAppUid(fullUid)) {
                    continue;
                }
                newNames[fullUid] = namesIt->second;
            }
        }

        if (!ok) {
            std::this_thread::sleep_for(retryDelay);
            continue;
        }

        std::vector<std::pair<App::Uid, App::NamesVec>> installs;
        std::vector<std::pair<App::Uid, App::NamesVec>> removes;

        NamesMap old;
        {
            const std::lock_guard lock(_mutexNames);
            old = std::move(_names);
            _names = std::move(newNames);

            for (auto &[uid, names] : _names) {
                if (const auto it = old.find(uid); it == old.end()) {
                    installs.emplace_back(uid, names);
                } else {
                    old.erase(it);
                }
            }
            for (auto &[uid, names] : old) {
                removes.emplace_back(uid, names);
            }
        }

        for (const auto &[uid, names] : installs) {
            appManager.install(uid, names);
        }
        for (const auto &[uid, names] : removes) {
            appManager.remove(uid, names);
        }
        break;
    }
}
