/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <fstream>
#include <dirent.h>
#include <poll.h>
#include <sys/inotify.h>
#include <thread>
#include <unistd.h>
#include <errno.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <string_view>
#include <unordered_map>
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
    const auto debounce = std::chrono::milliseconds(250);
    const auto retryDelay = std::chrono::seconds(1);

    enum class WatchKind { PackagesListFile, UsersDir, UserDir };
    struct WatchInfo {
        WatchKind kind;
        uint32_t userId;
    };

    auto isPackageRestrictionsName = [](const inotify_event *ev) -> bool {
        return ev->len > 0 && std::strcmp(ev->name, "package-restrictions.xml") == 0;
    };
    auto isUserlistName = [](const inotify_event *ev) -> bool {
        return ev->len > 0 && std::strcmp(ev->name, "userlist.xml") == 0;
    };

    for (;;) {
        int fd = inotify_init1(IN_CLOEXEC);
        if (fd == -1) {
            std::this_thread::sleep_for(retryDelay);
            continue;
        }

        std::unordered_map<int, WatchInfo> watches;
        const auto addWatch = [&](const std::string &path, const uint32_t mask,
                                  const WatchInfo info) -> bool {
            const int wd = inotify_add_watch(fd, path.c_str(), mask);
            if (wd == -1) {
                return false;
            }
            watches.emplace(wd, info);
            return true;
        };

        // Watch packages.list for writes + inode replacement.
        if (!addWatch(settings.packagesList, IN_CLOSE_WRITE | IN_MOVE_SELF | IN_DELETE_SELF,
                      WatchInfo{WatchKind::PackagesListFile, 0})) {
            close(fd);
            std::this_thread::sleep_for(retryDelay);
            continue;
        }

        // Watch /data/system/users for user add/remove + userlist.xml updates.
        constexpr uint32_t usersDirMask = IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM |
                                          IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF;
        if (!addWatch(Settings::systemUsersDir, usersDirMask, WatchInfo{WatchKind::UsersDir, 0})) {
            close(fd);
            std::this_thread::sleep_for(retryDelay);
            continue;
        }

        // Watch each user directory for package-restrictions.xml changes (robust across atomic replace).
        std::vector<uint32_t> userIds;
        std::string usersError;
        if (!enumerateUserIds(userIds, usersError)) {
            close(fd);
            std::this_thread::sleep_for(retryDelay);
            continue;
        }

        constexpr uint32_t userDirMask = IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM |
                                         IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF;
        bool ok = true;
        for (const uint32_t userId : userIds) {
            const std::string userDir = Settings::systemUserDir(userId);
            if (!addWatch(userDir, userDirMask, WatchInfo{WatchKind::UserDir, userId})) {
                ok = false;
                break;
            }
        }
        if (!ok) {
            close(fd);
            std::this_thread::sleep_for(retryDelay);
            continue;
        }

        bool updateQueued = false;
        auto updateDeadline = std::chrono::steady_clock::time_point{};

        std::array<char, 4096> buf{};
        for (;;) {
            const auto now = std::chrono::steady_clock::now();
            int timeoutMs = -1;
            if (updateQueued) {
                if (now >= updateDeadline) {
                    // updatePackages applies AppManager changes under mutexListeners so package
                    // updates cannot publish apps across a concurrent RESETALL boundary.
                    updatePackages();
                    updateQueued = false;
                } else {
                    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(updateDeadline - now);
                    timeoutMs = static_cast<int>(std::min<int64_t>(ms.count(), std::numeric_limits<int>::max()));
                }
            }

            pollfd pfd{fd, POLLIN, 0};
            const int pret = poll(&pfd, 1, timeoutMs);
            if (pret == 0) {
                continue; // timeout handled above
            }
            if (pret < 0) {
                if (errno == EINTR) {
                    continue;
                }
                close(fd);
                break;
            }

            const ssize_t len = read(fd, buf.data(), buf.size());
            if (len <= 0) {
                if (len == -1 && errno == EINTR) {
                    continue;
                }
                close(fd);
                break;
            }

            size_t i = 0;
            bool needRestart = false;
            while (i + sizeof(inotify_event) <= static_cast<size_t>(len)) {
                const auto *ev = reinterpret_cast<const inotify_event *>(buf.data() + i);

                if (ev->mask & IN_Q_OVERFLOW) {
                    updateQueued = true;
                    updateDeadline = std::chrono::steady_clock::now() + debounce;
                    needRestart = true;
                } else if (ev->mask & IN_IGNORED) {
                    updateQueued = true;
                    updateDeadline = std::chrono::steady_clock::now() + debounce;
                    needRestart = true;
                } else {
                    const auto it = watches.find(ev->wd);
                    if (it != watches.end()) {
                        const auto kind = it->second.kind;
                        if (kind == WatchKind::PackagesListFile) {
                            if (ev->mask & IN_CLOSE_WRITE) {
                                updateQueued = true;
                                updateDeadline = std::chrono::steady_clock::now() + debounce;
                            }
                            if ((ev->mask & IN_MOVE_SELF) || (ev->mask & IN_DELETE_SELF)) {
                                updateQueued = true;
                                updateDeadline = std::chrono::steady_clock::now() + debounce;
                                needRestart = true;
                            }
                        } else if (kind == WatchKind::UsersDir) {
                            if ((ev->mask & IN_DELETE_SELF) || (ev->mask & IN_MOVE_SELF)) {
                                updateQueued = true;
                                updateDeadline = std::chrono::steady_clock::now() + debounce;
                                needRestart = true;
                            }
                            if (isUserlistName(ev)) {
                                updateQueued = true;
                                updateDeadline = std::chrono::steady_clock::now() + debounce;
                                needRestart = true; // userlist.xml atomic replace or user set changed
                            }
                            if (ev->len > 0) {
                                uint32_t userId = 0;
                                if (tryParseUserId(ev->name, userId) &&
                                    (ev->mask & (IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM))) {
                                    updateQueued = true;
                                    updateDeadline = std::chrono::steady_clock::now() + debounce;
                                    needRestart = true; // need to rebuild per-user watches
                                }
                            }
                        } else if (kind == WatchKind::UserDir) {
                            if ((ev->mask & IN_DELETE_SELF) || (ev->mask & IN_MOVE_SELF)) {
                                updateQueued = true;
                                updateDeadline = std::chrono::steady_clock::now() + debounce;
                                needRestart = true;
                            }
                            if (isPackageRestrictionsName(ev) &&
                                (ev->mask & (IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_MOVED_FROM))) {
                                updateQueued = true;
                                updateDeadline = std::chrono::steady_clock::now() + debounce;
                            }
                        }
                    }
                }

                i += sizeof(inotify_event) + ev->len;
            }

            if (needRestart) {
                close(fd);
                if (updateQueued) {
                    const auto now = std::chrono::steady_clock::now();
                    if (now < updateDeadline) {
                        std::this_thread::sleep_for(updateDeadline - now);
                    }
                    updatePackages();
                }
                break;
            }
        }
    }
}

void PackageListener::updatePackages() {
    const auto start = std::chrono::steady_clock::now();
    const auto maxWait = std::chrono::seconds(5);
    auto nextLog = start;

    for (;;) {
        std::string error;
        PackageState::PackagesListSnapshot packages;
        std::string parseError;
        if (!PackageState::parsePackagesListFile(settings.packagesList, packages, &parseError)) {
            error = std::string("packages.list: parse failed: ") + parseError;
        } else {
            std::vector<uint32_t> userIds;
            std::string usersError;
            if (!enumerateUserIds(userIds, usersError)) {
                error = std::string(Settings::systemUsersDir) +
                        ": enumerate users failed: " + usersError;
            } else {
                NamesMap newNames;
                bool ok = true;
                for (const uint32_t userId : userIds) {
                    const std::string path = Settings::packageRestrictionsPath(userId);
                    PackageState::PackageRestrictionsSnapshot restrictions;
                    std::string rerr;
                    if (!PackageState::parsePackageRestrictionsFile(path.c_str(), restrictions,
                                                                   &rerr)) {
                        error = path + ": parse failed: " + rerr;
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

                        const uint64_t fullUid64 =
                            static_cast<uint64_t>(userId) * AID_USER_OFFSET + appId;
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

                if (ok) {
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

                    {
                        const std::shared_lock<std::shared_mutex> lock(mutexListeners);
                        for (const auto &[uid, names] : installs) {
                            appManager.install(uid, names);
                        }
                        for (const auto &[uid, names] : removes) {
                            appManager.remove(uid, names);
                        }
                    }
                    return;
                }
            }
        }

        const auto now = std::chrono::steady_clock::now();
        if (now >= nextLog) {
            LOG(WARNING) << __FUNCTION__ << ": " << error;
            nextLog = now + std::chrono::seconds(1);
        }
        if (now - start >= maxWait) {
            LOG(ERROR) << __FUNCTION__ << ": giving up after "
                       << std::chrono::duration_cast<std::chrono::seconds>(maxWait).count()
                       << "s (" << error << ")";
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}
