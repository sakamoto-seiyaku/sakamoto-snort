/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>

#include <Settings.hpp>

namespace {
constexpr uint32_t kMaxUserId = 10000;
} // namespace

Settings::Settings() { reset(); }

Settings::~Settings() {}

void Settings::start() {
    mkdir(_saveDir.c_str(), 0700);
    mkdir(saveDirPackages.c_str(), 0700);
    mkdir(saveDirSystem.c_str(), 0700);
    mkdir(saveDirDomainLists.c_str(), 0700);
    mkdir(saveDirPolicyCheckpoints.c_str(), 0700);
    restore();
}

void Settings::ensureUserDirs(const uint32_t userId) {
    if (userId == 0) {
        // User 0 uses legacy paths which are created in start()
        return;
    }
    mkdir(userSaveRoot(userId).c_str(), 0700);
    mkdir(userSaveDirPackages(userId).c_str(), 0700);
    mkdir(userSaveDirSystem(userId).c_str(), 0700);
}

std::string Settings::systemUserDir(const uint32_t userId) {
    const uint32_t safeUserId = userId < kMaxUserId ? userId : (kMaxUserId - 1);
    return std::string(systemUsersDir) + "/" + std::to_string(safeUserId);
}

std::string Settings::packageRestrictionsPath(const uint32_t userId) {
    return systemUserDir(userId) + "/package-restrictions.xml";
}

void Settings::finishFirstStart() {}

void Settings::save() {
    _saver.save([&] {
        const std::shared_lock<std::shared_mutex> lock(_mutexPassword);
        _saver.write<bool>(_blockEnabled);
        _saver.write<uint32_t>(_version);
        _saver.write<uint8_t>(_blockMask);
        _saver.write<uint8_t>(_blockIface);
        _saver.write<uint8_t>(_passState);
        _saver.write(_password);
        _saver.write<bool>(legacyGetBlackIPsFrozenValue);
        _saver.write<bool>(legacyBlockIPLeaksFrozenValue);
        _saver.write<bool>(_ipRulesEnabled);
        _saver.write<std::time_t>(legacyMaxAgeIPFrozenValue);
    });
}

void Settings::restore() {
    _saver.restore([&] {
        _blockEnabled = _saver.read<bool>();
        _savedVersion = _saver.read<uint32_t>();
        if (_savedVersion == 1) {
            _saver.read<bool>();
        }
        _blockMask = _saver.read<uint8_t>();
        if (_savedVersion < 3) {
            _blockMask += customListBit;
        }
        _blockMask = normalizeAppBlockMask(_blockMask);
        _blockIface = _saver.read<uint8_t>();
        _passState = _saver.read<uint8_t>();
        std::string password;
        _saver.read(password);
        _password = password;
        // Legacy knobs are frozen: read to maintain wire compatibility but ignore values.
        (void)_saver.read<bool>(); // GETBLACKIPS
        (void)_saver.read<bool>(); // BLOCKIPLEAKS
        if (_savedVersion >= 8) {
            _ipRulesEnabled = _saver.read<bool>();
        } else {
            _ipRulesEnabled = false;
        }

        (void)_saver.read<std::time_t>(); // MAXAGEIP

        _getBlackIPs = legacyGetBlackIPsFrozenValue;
        _blockIPLeaks = legacyBlockIPLeaksFrozenValue;
        _maxAgeIP = legacyMaxAgeIPFrozenValue;
    });
}

void Settings::setSaveFileOverrideForTesting(std::string path) {
    if (path.empty()) {
        _saver = Saver(_saveFile);
        return;
    }
    _saver = Saver(std::move(path));
}

void Settings::applyCheckpointPolicyConfig(const bool blockEnabled, const uint8_t blockMask,
                                           const uint8_t blockIface, const bool reverseDns,
                                           const bool ipRulesEnabled) {
    _blockEnabled = blockEnabled;
    _blockMask = normalizeAppBlockMask(blockMask);
    _blockIface = blockIface;
    _reverseDns = reverseDns;
    _ipRulesEnabled = ipRulesEnabled;
    _getBlackIPs = legacyGetBlackIPsFrozenValue;
    _blockIPLeaks = legacyBlockIPLeaksFrozenValue;
    _maxAgeIP = legacyMaxAgeIPFrozenValue;
}

namespace {
// Recursively remove all files and subdirectories in the given path
void removeDirectoryContents(const std::string &path) {
    DIR *dir = opendir(path.c_str());
    if (dir == nullptr) {
        return;
    }

    dirent *de;
    while ((de = readdir(dir)) != nullptr) {
        // Skip . and ..
        if (std::strcmp(de->d_name, ".") == 0 || std::strcmp(de->d_name, "..") == 0) {
            continue;
        }

        std::string fullPath = path + "/" + de->d_name;
        if (de->d_type == DT_DIR) {
            // Recursively remove subdirectory contents, then remove the directory
            removeDirectoryContents(fullPath);
            rmdir(fullPath.c_str());
        } else {
            // Remove regular file
            std::remove(fullPath.c_str());
        }
    }
    closedir(dir);
}
} // namespace

void Settings::clearSaveTreeForResetAll() {
    // Clear contents of the main save directory including all user<N> subdirectories
    // This is called during RESETALL to ensure all per-user state is removed
    removeDirectoryContents(_saveDir);

    // Recreate the base directories for user 0
    mkdir(saveDirPackages.c_str(), 0700);
    mkdir(saveDirSystem.c_str(), 0700);
    mkdir(saveDirDomainLists.c_str(), 0700);
}
