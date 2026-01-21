/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <android-base/properties.h>
#include <chrono>
#include <atomic>
#include <string>

#include <sucre-snort.hpp>
#include <Saver.hpp>

class Settings {
private:
    static constexpr const char *_saveFile = "/data/snort/settings";
    static constexpr const char *_firstStartProp = "sucre-snort.first_start";
    static inline const std::string _snortDir = "/data/snort/";
    static inline const std::string _saveDir = _snortDir + "save/";
    static inline const std::string _defaultDirEtc = "/system_ext/etc/sucre-snort/";
    static inline const std::string _telnetFile = _snortDir + "telnet";

public:
    const std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
    static constexpr auto saveInterval = std::chrono::minutes(60);
    static constexpr uint8_t standardListBit = 1;
    static constexpr uint8_t reinforcedListBit = 1 << 3;
    static constexpr uint8_t customListBit = 128;
    // Extra combinable chains for blocking lists (blacklists): 2/4/16/32/64.
    static constexpr uint8_t extraListBitsMask = 2 | 4 | 16 | 32 | 64;
    static constexpr uint8_t supportedListBitsMask = standardListBit | reinforcedListBit | extraListBitsMask;
    static constexpr uint8_t supportedAppBitsMask = supportedListBitsMask | customListBit;

    // BlockingList/DomainList masks must be single-bit selectors from the supported set.
    static constexpr bool isValidBlockingListMask(const uint32_t mask) {
        return mask == 1 || mask == 2 || mask == 4 || mask == 8 || mask == 16 || mask == 32 || mask == 64;
    }
    static constexpr bool isValidBlockingListMask(const uint8_t mask) {
        return isValidBlockingListMask(static_cast<uint32_t>(mask));
    }

    // App masks may combine multiple list bits + customListBit. Reinforced implies standard.
    static constexpr bool isValidAppBlockMask(const uint32_t mask) {
        if (mask > 255) return false;
        return (mask & ~static_cast<uint32_t>(supportedAppBitsMask)) == 0;
    }
    static constexpr uint8_t normalizeAppBlockMask(uint8_t mask) {
        if (mask & reinforcedListBit) {
            mask |= standardListBit;
        }
        return mask;
    }

    static constexpr const char *packagesList = "/data/system/packages.list";
    static constexpr auto packagesListRetry = std::chrono::milliseconds(1);

    static constexpr const char *systemUsersDir = "/data/system/users";
    static constexpr const char *systemUsersUserlist = "/data/system/users/userlist.xml";

    static std::string systemUserDir(uint32_t userId);

    static std::string packageRestrictionsPath(uint32_t userId);

    static inline const std::string saveDirPackages = _saveDir + "packages/";
    static inline const std::string saveDirSystem = _saveDir + "system/";
    static inline const std::string saveDirDomainLists = _saveDir + "domains_lists/";

    // Per-user directory helpers for userId > 0
    // User 0 continues to use the legacy paths (saveDirPackages/saveDirSystem).
    // For defense-in-depth, userId is range-checked and the resulting path is
    // validated to remain under the snort root directory.
    static std::string userSaveRoot(const uint32_t userId) {
        // Bound userId to a reasonable range (0 <= userId < 10000) to avoid
        // unbounded directory fan-out or accidental misuse.
        constexpr uint32_t maxUserId = 10000;
        const uint32_t safeUserId = userId < maxUserId ? userId : (maxUserId - 1);

        std::string root = _saveDir + "user" + std::to_string(safeUserId) + "/";

        // Prefix check: the computed per-user root must stay within the snort
        // directory tree. This guards against any future changes that might
        // accidentally construct an out-of-tree path.
        if (root.rfind(_snortDir, 0) != 0) {
            // Fall back to the main save directory to guarantee we never
            // escape /data/snort/.
            return _saveDir;
        }

        return root;
    }

    static std::string userSaveDirPackages(const uint32_t userId) {
        if (userId == 0) {
            return saveDirPackages;
        }
        return userSaveRoot(userId) + "packages/";
    }

    static std::string userSaveDirSystem(const uint32_t userId) {
        if (userId == 0) {
            return saveDirSystem;
        }
        return userSaveRoot(userId) + "system/";
    }

    static void ensureUserDirs(const uint32_t userId);

    static inline const std::string saveDomains = _saveDir + "stats_domains";
    static inline const std::string saveDnsStream = _saveDir + "dnsstream";
    static inline const std::string saveRules = _saveDir + "rules";
    static inline const std::string saveStatsTotal = _saveDir + "stats_total";
    static inline const std::string saveBlockingLists = _saveDir + "blocking_lists";

    static inline const std::string systemAppPrefix = "system_";

    static constexpr const char *netdSocketPath = "sucre-snort-netd";
    static constexpr const char *controlSocketPath = "sucre-snort-control";

    static constexpr const char *iptablesShell = "/system/bin/iptables";
    static constexpr const char *ip6tablesShell = "/system/bin/ip6tables";
    static constexpr const char *inputChain = "sucre-snort_INPUT";
    static constexpr const char *outputChain = "sucre-snort_OUTPUT";

    static constexpr const char *pmShell = "/system/bin/pm";
    static constexpr const char *mountShell = "/system/bin/mount";

    static constexpr uint32_t controlCmdLen = 20000;
    static constexpr uint32_t controlBindTrials = 10;
    static constexpr uint32_t controlClients = 1000;
    static constexpr uint32_t controlPort = 60606;

    static constexpr uint32_t dnsStreamMaxHorizon = 3600 * 24;
    static constexpr std::time_t dnsStreamDefaultHorizon = 600;
    static constexpr uint32_t dnsStreamMinSize = 500;
    static constexpr uint32_t pktStreamMaxHorizon = 3600 * 2;
    static constexpr std::time_t pktStreamDefaultHorizon = 600;
    static constexpr uint32_t pktStreamMinSize = 100;
    static constexpr uint32_t activityNotificationIntervalMs = 500;

private:
    Saver _saver{_saveFile};
    uint32_t _version = 7;
    uint32_t _savedVersion = 1;
    bool _firstStart = android::base::GetBoolProperty(_firstStartProp, true);
    bool _inetControl = std::ifstream(_telnetFile).is_open();
    std::shared_mutex _mutexPassword;

    std::atomic_bool _blockEnabled;
    std::atomic_uint8_t _blockMask;
    std::atomic_uint8_t _blockIface;
    std::atomic_bool _reverseDns;
    std::string _password;
    std::atomic_uint8_t _passState;
    std::atomic_bool _getBlackIPs;
    std::atomic_bool _blockIPLeaks;
    std::atomic<std::time_t> _maxAgeIP;

public:
    Settings();

    ~Settings();

    Settings(const Settings &) = delete;

    void reset() {
        _blockEnabled = true;
        _blockMask = standardListBit + customListBit;
        _blockIface = 0;
        _reverseDns = false;
        _password.clear();
        _passState = 0;
        _getBlackIPs = false;
        _blockIPLeaks = true;
        _maxAgeIP = 3600 * 4;
    }

    bool firstStart() { return _firstStart; }

    void finishFirstStart();

    uint32_t version() { return _version; }

    uint32_t savedVersion() { return _savedVersion; }

    bool inetControl() { return _inetControl; }

    std::string password() {
        const std::shared_lock<std::shared_mutex> lock(_mutexPassword);
        return _password;
    }

    void password(const std::string &password) {
        {
            const std::lock_guard lock(_mutexPassword);
            _password = password;
        }
        save();
    }

    uint8_t passState() { return _passState; }

    void passState(const uint8_t passState) {
        _passState = passState;
        save();
    }

    bool blockEnabled() const { return _blockEnabled; }

    void blockEnabled(const bool blockEnabled) {
        _blockEnabled = blockEnabled;
        save();
    }

    uint8_t blockMask() const { return _blockMask; }

    void blockMask(const uint8_t blockMask) {
        _blockMask = normalizeAppBlockMask(blockMask);
        save();
    }

    uint8_t blockIface() const { return _blockIface; }

    void blockIface(const uint8_t blockIface) {
        _blockIface = blockIface;
        save();
    }

    bool reverseDns() const { return _reverseDns; }

    void reverseDns(const bool rdns) {
        _reverseDns = rdns;
        save();
    }

    bool getBlackIPs() const { return _getBlackIPs; }

    void getBlackIPs(const bool getBlackIPs) {
        _getBlackIPs = getBlackIPs;
        save();
    }

    bool blockIPLeaks() const { return _blockIPLeaks; }

    void blockIPLeaks(const bool blockIPLeaks) {
        _blockIPLeaks = blockIPLeaks;
        save();
    }

    std::time_t maxAgeIP() const { return _maxAgeIP.load(std::memory_order_relaxed); }

    void maxAgeIP(const std::time_t maxAgeIP) {
        _maxAgeIP.store(maxAgeIP, std::memory_order_relaxed);
        save();
    }

    void start();

    void save();

    void restore();

    // Clear entire save tree for RESETALL, including all user<N> subdirectories
    static void clearSaveTreeForResetAll();
};

extern Settings settings;
