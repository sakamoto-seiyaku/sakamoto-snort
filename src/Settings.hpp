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

#pragma once

#include <android-base/properties.h>
#include <chrono>

#include <iode-snort.hpp>
#include <Saver.hpp>

class Settings {
private:
    static constexpr const char *_saveFile = "/data/snort/settings";
    static constexpr const char *_firstStartProp = "iode-snort.first_start";
    static constexpr const char *_snortDir2 = "/data/snort/";
    static constexpr const char *_snortDir3 = _snortDir2;
    static inline const std::string _snortDir = "/data/snort/";
    static inline const std::string _saveDir = _snortDir + "save/";
    static inline const std::string _defaultDirEtc = "/system_ext/etc/iode-snort/";
    static inline const std::string _telnetFile = _snortDir + "telnet";

public:
    std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
    static constexpr auto saveInterval = std::chrono::minutes(60);
    static constexpr uint8_t standardListBit = 1;
    static constexpr uint8_t customListBit = 128;

    static constexpr const char *packagesList = "/data/system/packages.list";
    static constexpr auto packagesListRetry = std::chrono::milliseconds(1);

    static inline const std::string saveDirPackages = _saveDir + "packages/";
    static inline const std::string saveDirSystem = _saveDir + "system/";
    static inline const std::string saveDomains = _saveDir + "stats_domains";
    static inline const std::string saveDnsStream = _saveDir + "dnsstream";
    static inline const std::string saveStatsTotal = _saveDir + "stats_total";
    static inline const std::string systemAppPrefix = "system_";

    static constexpr const char *netdSocketPath = "iode-snort-netd";
    static constexpr const char *controlSocketPath = "iode-snort-control";

    static inline const std::string defaultBlacklist = _defaultDirEtc + "domains-black";
    static inline const std::string defaultWhitelist = _defaultDirEtc + "domains-white";

    static constexpr const char *iptablesShell = "/system/bin/iptables";
    static constexpr const char *ip6tablesShell = "/system/bin/ip6tables";
    static constexpr const char *inputChain = "iode-snort_INPUT";
    static constexpr const char *outputChain = "iode-snort_OUTPUT";

    static inline const std::string defaultAppsFile = _snortDir + "default-apps";
    static inline const std::string defaultAppsFileEtc = _defaultDirEtc + "default-apps";
    static constexpr const char *pmShell = "/system/bin/pm";
    static constexpr const char *mountShell = "/system/bin/mount";

    static constexpr uint32_t controlCmdLen = 1000;
    static constexpr uint32_t controlBindTrials = 10;
    static constexpr uint32_t controlClients = 100;
    static constexpr uint32_t controlPort = 60606;

    static constexpr uint32_t dnsStreamMaxHorizon = 3600 * 24;
    static constexpr std::time_t dnsStreamDefaultHorizon = 600;
    static constexpr uint32_t dnsStreamMinSize = 500;
    static constexpr uint32_t pktStreamMaxHorizon = 3600 * 2;
    static constexpr std::time_t pktStreamDefaultHorizon = 600;
    static constexpr uint32_t pktStreamMinSize = 100;

private:
    Saver _saver{_saveFile};
    uint32_t _version = 4;
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
    std::time_t _maxAgeIP;

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
        const std::shared_lock_guard lock(_mutexPassword);
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
        _blockMask = blockMask;
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

    std::time_t maxAgeIP() const { return _maxAgeIP; }

    void maxAgeIP(const std::time_t maxAgeIP) {
        _maxAgeIP = maxAgeIP;
        save();
    }

    void start();

    void save();

    void restore();
};

extern Settings settings;
